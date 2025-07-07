#include "netgauge.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ADDRESS_SIZE 32

// struct libfabric_address {
//     uint8_t bytes[MAX_ADDRESS_SIZE];
// };

typedef {
    uint8_t bytes[MAX_ADDRESS_SIZE];
} libfabric_address_t;

inline static libfabric_address_t libfabric_address_from_bytes(uint8_t *bytes, size_t size) {
  libfabric_address_t addr = {0};

  memset(addr.bytes, 0, MAX_ADDRESS_SIZE);
  memcpy(addr.bytes, bytes, size);

  return addr;
}

/* information about peer node */
typedef struct {
    libfabric_address_t address;
} peer_info_t;

static int tcp_init(struct ng_options *global_opts);
static int tcp_sendto(int dst, void *buffer, int size);
static int tcp_recvfrom(int src, void *buffer, int size);
