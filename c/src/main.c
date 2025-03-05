#include <err.h>
#include <hktelemetry_packet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_payload(const uint8 *buffer, off_t *offset,
                  DS_HkTlm_Payload_t *payload) {
  unsigned long payload_size = sizeof(DS_HkTlm_Payload_t);
  memcpy(payload, buffer + *offset, payload_size);
  // convert endian from big to little if need
  payload->FileWriteCounter = ntohs(payload->FileWriteCounter);
  payload->FileWriteErrCounter = ntohs(payload->FileWriteErrCounter);
  payload->FileUpdateCounter = ntohs(payload->FileUpdateCounter);
  payload->FileUpdateErrCounter = ntohs(payload->FileUpdateErrCounter);

  payload->DisabledPktCounter = ntohl(payload->DisabledPktCounter);
  payload->IgnoredPktCounter = ntohl(payload->IgnoredPktCounter);
  payload->FilteredPktCounter = ntohl(payload->FilteredPktCounter);
  payload->PassedPktCounter = ntohl(payload->PassedPktCounter);
  *offset += payload_size;
  return 0;
}

int parse_primary_header(const uint8 *buffer, off_t *offset,
                         CCSDS_PrimaryHeader_t *p_header) {
  unsigned long p_header_size = sizeof(CCSDS_PrimaryHeader_t);
  memcpy(p_header, buffer + *offset, p_header_size);
  *offset += p_header_size;
  return 0;
}

bool has_secondary_header(const CCSDS_PrimaryHeader_t *p_header) {
  return ((p_header->StreamId[0] & 0x08) == 0x08);
}

int parse_secondary_header(const uint8 *buffer, off_t *offset,
                           CFE_MSG_TelemetrySecondaryHeader_t *sec_header) {
  unsigned long sec_header_size = sizeof(CFE_MSG_TelemetrySecondaryHeader_t);
  memcpy(sec_header, buffer + *offset, sec_header_size);
  *offset += sec_header_size;
  return 0;
}

int parse_telemetry_header(const uint8 *buffer, off_t *offset,
                           CFE_MSG_TelemetryHeader_t *header) {
  int ret;
  if ((ret = parse_primary_header(buffer, offset, &header->Msg.CCSDS.Pri)) !=
      0) {
    return ret;
  }
  // TODO: check length
  if (has_secondary_header(&header->Msg.CCSDS.Pri)) {
    printf("has second header\n");
    if ((ret = parse_secondary_header(buffer, offset, &header->Sec)) != 0) {
      return ret;
    }
  }

  return 0;
}

int parse_ds_hk_packet(const uint8 *buffer, off_t *offset,
                       DS_HkPacket_t *packet) {
  int ret;
  if ((ret =
           parse_telemetry_header(buffer, offset, &packet->TelemetryHeader))) {
    return ret;
  }
  if ((ret = parse_payload(buffer, offset, &packet->Payload))) {
    return ret;
  }
  return 0;
}

int main(int argv, char *argc[]) {
  off_t offset = 0;
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

  for (;;) {
    DS_HkPacket_t packet;
    int ret = parse_ds_hk_packet(buffer, &offset, &packet);
    printf("offset is %lu\n", offset);
    if (ret != 0) {
      fprintf(stderr, "failed to parse\n");
      exit(EXIT_FAILURE);
    }
    if (offset == file_size) {
      break;
    }
  }

  fclose(fp);
  free(buffer);

  return 0;
}
