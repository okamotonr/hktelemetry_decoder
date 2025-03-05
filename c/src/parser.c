#include <netinet/in.h>
#include <parser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

bool has_secondary_header(const CCSDS_PrimaryHeader_t *p_header) {
  return ((p_header->StreamId[0] & 0x08) == 0x08);
}

int parse(Input_t *input, void *restrict target, size_t size) {
  if (input->buffer_size < input->offset + size) {
    fprintf(stderr, "not enough size\n");
    return -1;
  }
  memcpy(target, input->data + input->offset, size);
  input->offset += size;
  return 0;
}

int parse_payload(Input_t *input, DS_HkTlm_Payload_t *payload) {
  unsigned long payload_size = sizeof(DS_HkTlm_Payload_t);
  int ret = parse(input, payload, payload_size);

  if (ret != 0) {
    return ret;
  }
  // convert endian from big to little if need
  payload->FileWriteCounter = ntohs(payload->FileWriteCounter);
  payload->FileWriteErrCounter = ntohs(payload->FileWriteErrCounter);
  payload->FileUpdateCounter = ntohs(payload->FileUpdateCounter);
  payload->FileUpdateErrCounter = ntohs(payload->FileUpdateErrCounter);

  payload->DisabledPktCounter = ntohl(payload->DisabledPktCounter);
  payload->IgnoredPktCounter = ntohl(payload->IgnoredPktCounter);
  payload->FilteredPktCounter = ntohl(payload->FilteredPktCounter);
  payload->PassedPktCounter = ntohl(payload->PassedPktCounter);
  return 0;
}

int parse_primary_header(Input_t *input, CCSDS_PrimaryHeader_t *p_header) {
  unsigned long p_header_size = sizeof(CCSDS_PrimaryHeader_t);
  int ret = parse(input, p_header, p_header_size);
  if (ret != 0) {
    return ret;
  }
  return 0;
}

int parse_secondary_header(Input_t *input,
                           CFE_MSG_TelemetrySecondaryHeader_t *sec_header) {
  unsigned long sec_header_size = sizeof(CFE_MSG_TelemetrySecondaryHeader_t);
  int ret = parse(input, sec_header, sec_header_size);
  if (ret != 0) {
    return ret;
  }
  return 0;
}

int parse_telemetry_header(Input_t *input,
                           CFE_MSG_TelemetryHeader_t *header) {
  int ret;
  if ((ret = parse_primary_header(input, &header->Msg.CCSDS.Pri)) != 0) {
    return ret;
  }
  // TODO: check length
  if (has_secondary_header(&header->Msg.CCSDS.Pri)) {
    if ((ret = parse_secondary_header(input, &header->Sec)) != 0) {
      return ret;
    }
  }

  return 0;
}

int parse_ds_hk_packet(Input_t *input, DS_HkPacket_t *packet) {
  int ret;
  if ((ret = parse_telemetry_header(input, &packet->TelemetryHeader)) != 0) {
    return ret;
  }
  if ((ret = parse_payload(input, &packet->Payload)) != 0) {
    return ret;
  }
  return 0;
}
