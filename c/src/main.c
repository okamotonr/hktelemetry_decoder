#include "parser.h"
#include <err.h>
#include <hktelemetry_packet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_secondary_header(
    CFE_MSG_TelemetrySecondaryHeader_t const *s_header) {
  uint32 seconds = ((uint32)s_header->Time[0] << 24) |
                   ((uint32)s_header->Time[1] << 16) |
                   ((uint32)s_header->Time[2] << 8) | s_header->Time[3];
  uint16 subseconds = (uint16)s_header->Time[4] << 8 | s_header->Time[5];
  printf("Seconds: %u\n", seconds);
  printf("Subseconds: %u\n", subseconds);
}

bool print_primary_header(CCSDS_PrimaryHeader_t const *p_header) {
  uint16 stream_id =
      ((uint16)p_header->StreamId[0] << 8) | p_header->StreamId[1];
  uint16 application_id = stream_id & 0x07FF;
  printf("ApplicationID: %u\n", application_id);
  printf("HasSecondaryHeader: ");
  bool has_sec = has_secondary_header(p_header);
  if (has_sec) {
    printf("true\n");
  } else {
    printf("false\n");
  }

  uint16 packet_type = (stream_id & 0x1000) >> 12;
  printf("PacketType: ");
  if (packet_type == 0) {
    printf("TLM\n");
  } else if (packet_type == 1) {
    printf("CMD\n");
  } else {
    // NEVER OCCURED
    printf("UNKNOWN\n");
  }
  uint16 ccsds_v = (stream_id & 0xE000) >> 13;
  printf("CCSDSVersion: ");
  if (ccsds_v == 0) {
    printf("Ver1\n");
  } else if (ccsds_v == 1) {
    printf("Ver2\n");
  } else {
    printf("UnkownVersion\n");
  }
  uint16 sequence =
      ((uint16)p_header->Sequence[0] << 8) | p_header->Sequence[1];
  printf("Sequence: %u\n", sequence);

  uint16 sequence_count = sequence & 0x3FFF;
  printf("SequenceCount: %u\n", sequence_count);
  uint16 seg_flags = (sequence & 0xC000) >> 14;
  printf("SegmentationFlags: %u\n", seg_flags);
  uint16 length = ((uint16)p_header->Length[0] << 8) | p_header->Length[1];
  printf("Length: %u\n", length);
  return has_sec;
}

void print_header(CFE_MSG_TelemetryHeader_t const *header) {
  printf("PrimaryHeader:\n");
  if (print_primary_header(&header->Msg.CCSDS.Pri)) {
    printf("SecondaryHeader:\n");
    print_secondary_header(&header->Sec);
  } else {
    printf("No SecondaryHeader\n");
  }
}

void print_payload(DS_HkTlm_Payload_t const *payload) {
  printf("CmdAcceptedCounter: %u\n", payload->CmdAcceptedCounter);
  printf("CmdRejectedCounter: %u\n", payload->CmdRejectedCounter);
  printf("DestTblLoadCounter: %u\n", payload->DestTblLoadCounter);
  printf("DestTblErrCounter: %u\n", payload->DestTblErrCounter);
  printf("FilterTblLoadCounter: %u\n", payload->FilterTblLoadCounter);
  printf("FilterTblErrCounter: %u\n", payload->FilterTblErrCounter);
  printf("AppEnableState: %u\n", payload->AppEnableState);
  printf("FileWriteCounter: %u\n", payload->FileWriteCounter);
  printf("FileWriteErrCounter: %u\n", payload->FileWriteErrCounter);
  printf("FileUpdateCounter: %u\n", payload->FileUpdateCounter);
  printf("FileUpdateErrCounter: %u\n", payload->FileUpdateErrCounter);
  printf("DisabledPktCounter: %u\n", payload->DisabledPktCounter);
  printf("IgnoredPktCounter: %u\n", payload->IgnoredPktCounter);
  printf("FilteredPktCounter: %u\n", payload->FilteredPktCounter);
  printf("PassedPktCounter: %u\n", payload->PassedPktCounter);
  printf("FilterTblFilename: %s\n", payload->FilterTblFilename);
}

void print_packet(DS_HkPacket_t const *packet) {
  printf("TelemetryHeader:\n");
  print_header(&packet->TelemetryHeader);
  printf("Payload:\n");
  print_payload(&packet->Payload);
}

int main(int argv, char *argc[]) {
  long file_size = 0;

  if (argv < 2) {
    fprintf(stderr, "file path required\n");
    exit(EXIT_FAILURE);
  }

  FILE *fp = fopen(argc[1], "rb");
  if (fp == NULL) {
    perror("failed to opne file\n");
    exit(EXIT_FAILURE);
  }

  fseek(fp, 0L, SEEK_END);
  file_size = ftell(fp);
  if (file_size < 0) {
    perror("failed to get file_size\n");
    exit(EXIT_FAILURE);
    fclose(fp);
  }

  rewind(fp);

  uint8 *buffer = (uint8 *)malloc(file_size);
  if (buffer == NULL) {
    perror("failed to allocate memory\n");
    fclose(fp);
    exit(EXIT_FAILURE);
  }

  size_t bytes = fread(buffer, 1, file_size, fp);
  if (bytes != (size_t)file_size) {
    perror("failed to read file\n");
    fclose(fp);
    free(buffer);
    exit(EXIT_FAILURE);
  }

  Input_t input = {buffer, file_size, 0};

  for (;;) {
    DS_HkPacket_t packet;
    int ret = parse_ds_hk_packet(&input, &packet);
    printf("offset is %lu\n", input.offset);
    if (ret != 0) {
      fprintf(stderr, "failed to parse\n");
      exit(EXIT_FAILURE);
    }
    print_packet(&packet);
    if (input.offset == file_size) {
      break;
    }
    printf("\n");
  }

  fclose(fp);
  free(buffer);

  return 0;
}
