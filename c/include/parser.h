#include <hktelemetry_packet.h>
#include <sys/types.h>
#include <stdbool.h>

typedef struct {
  const uint8 *data;
  size_t buffer_size;
  off_t offset;
} Input_t;

int parse_ds_hk_packet(Input_t *input, DS_HkPacket_t *packet);
bool has_secondary_header(const CCSDS_PrimaryHeader_t *p_header);

