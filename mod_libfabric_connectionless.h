#include "netgauge.h"

#ifdef NG_MOD_LIBFABRIC_CONNECTIONLESS

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ADDRESS_SIZE 32

typedef struct {
    uint8_t bytes[MAX_ADDRESS_SIZE];
} libfabric_cl_address_t;

inline static libfabric_cl_address_t libfabric_cl_address_from_bytes(uint8_t *bytes, size_t size) {
  libfabric_cl_address_t addr = {0};

  memset(addr.bytes, 0, MAX_ADDRESS_SIZE);
  memcpy(addr.bytes, bytes, size);

  return addr;
}

/* information about peer node */
typedef struct {
    libfabric_cl_address_t address;

    uint64_t buffer_address;
    uint64_t buffer_key;
} libfabric_cl_peer_info_t;

static int libfabric_cl_getopt(int argc, char **argv, struct ng_options *global_opts);
static void libfabric_cl_writemanpage(void);
static void libfabric_cl_usage(void);

static void *libfabric_cl_malloc(size_t size);

static int libfabric_cl_init(struct ng_options *global_opts);
static void libfabric_cl_shutdown(struct ng_options *global_opts);
static int libfabric_cl_sendto(int dst, void *buffer, int size);
static int libfabric_cl_recvfrom(int src, void *buffer, int size);
static int libfabric_cl_set_blocking(int do_block, int partner);

static int libfabric_cl_isendto(int dst, void *buffer, int size, NG_Request *req);
static int libfabric_cl_irecvfrom(int src, void *buffer, int size, NG_Request *req);
static int libfabric_cl_test(NG_Request *req);

#endif // NG_MOD_LIBFABRIC_CONNECTIONLESS
