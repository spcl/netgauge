#include "netgauge.h"
#ifdef NG_MOD_LIBFABRIC

#include "mod_libfabric.h"
#include "hrtimer/hrtimer.h"

#include <getopt.h>
#include <inttypes.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// To extract underlying queue pair parameters
#include "infiniband/verbs.h" /* OFED stuff */

#define CHECK(stmt)                                                   \
    do {                                                              \
        if (!(stmt)) {                                                \
            fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, #stmt); \
            exit(1);                                                  \
        }                                                             \
    } while (0)

#define FI_CHECK(stmt)                                                  \
    do {                                                                \
        int rc = (stmt);                                                \
        if (rc) {                                                       \
            fprintf(stderr, "%s:%d %s failed with %d (%s)\n", __FILE__, \
                    __LINE__, #stmt, rc, fi_strerror(-rc));             \
            exit(1);                                                    \
        }                                                               \
    } while (0)

#define RETRY_ON_EAGAIN(stmt)                                               \
    do {                                                                    \
        int rc;                                                             \
        while (true) {                                                      \
            rc = (stmt);                                                    \
            if (rc == -FI_EAGAIN) {                                         \
                fprintf(stderr, "%s:%d retrying with", __FILE__, __LINE__); \
                continue;                                                   \
            } else if (rc < 0) {                                            \
                fprintf(stderr, "%s:%d %s failed with %d (%s)\n", __FILE__, \
                        __LINE__, #stmt, rc, fi_strerror(-rc));             \
                exit(1);                                                    \
            }                                                               \
            break;                                                          \
        }                                                                   \
        if (rc) {                                                           \
            /* If we stop trying then report the last error */              \
            fprintf(stderr, "%s:%d %s failed with %d (%s)\n", __FILE__,     \
                    __LINE__, #stmt, rc, fi_strerror(-rc));                 \
            exit(1);                                                        \
        }                                                                   \
    } while (0)

#define PRINT_CQ_ERROR(cq, err_code)                                          \
    do {                                                                      \
        struct fi_cq_err_entry err;                                           \
        char err_buf[256];                                                    \
        int ret = fi_cq_readerr(cq, &err, 0);                                 \
        *err_code = err.err;                                                  \
        if (ret > 0) {                                                        \
            const char *err_str = fi_cq_strerror(cq, err.prov_errno,          \
                                                 err.err_data, err_buf, 256); \
            fprintf(stderr, "CQ error: %d (%s), provider error: %s\n",        \
                    err.err, fi_strerror(-err.err), err_str);                 \
        }                                                                     \
    } while (0)

#define VERBOSE_LOG(fmt, ...)                    \
    do {                                         \
        if (0) {                                 \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
        }                                        \
    } while (0)

#define VERBOSE_LOG_2(fmt, ...)                    \
    do {                                         \
        if (0) {                                 \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
        }                                        \
    } while (0)

HRT_TIMESTAMP_T benchmark_start_2;

uint64_t get_timestamp_ticks_2() {
  HRT_TIMESTAMP_T now;
  HRT_GET_TIMESTAMP(now);
  uint64_t ticks;
  HRT_GET_TIME(now, ticks);
  return ticks;
}

double get_timestamp_usec_2() {
  HRT_TIMESTAMP_T now;
  HRT_GET_TIMESTAMP(now);
  long long ticks;
  HRT_GET_ELAPSED_TICKS(benchmark_start_2, now, &ticks);
  double now_usec = HRT_GET_USEC(ticks);
  return now_usec;
}

struct ng_module libfabric_module = {
    .name = "libfabric",
    .desc = "This mod uses libfabric for data transmission.",
    .flags = NG_MOD_RELIABLE | NG_MOD_CHANNEL,
    .max_datasize = -1, /*  can send data of arbitrary size */
    .headerlen = 0,     /*  no extra space needed for header */
    .malloc = libfabric_malloc,
    .getopt = libfabric_getopt,
    .init = libfabric_init,
    .shutdown = libfabric_shutdown,
    .usage = libfabric_usage,
    .writemanpage = libfabric_writemanpage,
    .sendto = libfabric_sendto,
    .recvfrom = libfabric_recvfrom,
    .set_blocking = libfabric_set_blocking,
    .isendto = libfabric_isendto,
    .irecvfrom = libfabric_irecvfrom,
    .test = libfabric_test,
};

typedef struct {
    struct fi_info *fi;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
} libfabric_network_t;

typedef struct {
    struct fid_ep *ep;
    struct fid_cq *cq;
    struct fid_eq *eq;
} libfabric_connected_endpoint_t;

typedef struct {
    struct fid_pep *pep;
    struct fid_eq *eq;
    libfabric_address_t addr;
} libfabric_listening_endpoint_t;

typedef struct libfabric_memory_region_info_t {
    void *start; /* Start address of the memory region */
    size_t length; /* Length of the memory region */
    struct fid_mr *mr; /* Memory region handle */
    void *desc; /* Memory region descriptor */
    struct libfabric_memory_region_info_t *next; /* Pointer to the next memory region info */
} libfabric_memory_region_info_t;

/* module private data */
typedef struct {
    char *provider_name;
    char rdma_operation; /* 'r' for read, 'w' for write, 's' for send */

    size_t internal_buffer_size; /* size of local_buffer and  remote_operatio_buffer*/

    void *local_buffer; /* buffer for receiving data */
    struct fid_mr *local_mr; /* memory region for local_buffer */
    void *local_descriptor;

    void *remote_operation_buffer; /* buffer for remote operations (read/write) */
    struct fid_mr *remote_mr; /* memory region for remote_operation_buffer */
    void *remote_operation_descriptor;
    uint64_t remote_operation_buffer_key;

    libfabric_network_t network;
    libfabric_connected_endpoint_t *peer_connections;
    libfabric_memory_region_info_t *memory_regions; /* linked list of memory regions info */

    peer_info_t my_peer_info; /* info about this node to send to peers */
    size_t nodes_no;                 /* number of nodes in the benchmark */
    size_t my_node_id;               /* this node's id */
    peer_info_t *peer_info;   /* info about all nodes */


} libfabric_private_data_t;

static libfabric_private_data_t module_data;

// Returned by async operations as handle to check for completion
typedef struct {
    bool completed;
    struct fid_cq *cq;
} libfabric_completion_handle_t;

#define MAX_HANDLES 1024

libfabric_completion_handle_t* libfabric_get_completion_handle() {
    static libfabric_completion_handle_t handles[MAX_HANDLES];
    static int next_handle = 0;

    return &handles[next_handle++ % MAX_HANDLES];
}

static int libfabric_getopt(int argc, char **argv, struct ng_options *global_opts) {
    char *optchars = "-M:";
    int opt;

    extern char *optarg;
    extern int optind, opterr, optopt;

    module_data.rdma_operation = 's'; // Default to 's' if -T not provided

    VERBOSE_LOG("Parsing command-line options for libfabric module\n");
    VERBOSE_LOG("argc = %d\n", argc);
    for (int i = 0; i < argc; i++) {
        VERBOSE_LOG("argv[%d] = '%s'\n", i, argv[i]);
    }
    VERBOSE_LOG("optind = %d, opterr = %d, optopt = %d\n", optind, opterr, optopt);

    while ((opt = getopt(argc, argv, optchars)) >= 0) {
        VERBOSE_LOG("Processing option '-%c' with argument '%s'\n", opt, optarg ? optarg : "NULL");
        switch (opt) {
            case 'M':
                if (optarg && (optarg[0] == 'r' || optarg[0] == 'w' || optarg[0] == 's')) {
                    module_data.rdma_operation = optarg[0];
                } else {
                    fprintf(stderr, "Invalid value for -T. Use 'r', 'w', or 's'.\n");
                    exit(1);
                }
                break;
            case '?':
                // fprintf(stderr, "Unknown option '-%c'\n", optopt);
                continue; // Ignore unrecognized options
        }
    }

    VERBOSE_LOG("Final rdma_operation value: '%c'\n", module_data.rdma_operation);

    return 0;
}

static void libfabric_writemanpage(void) {
    return; // TODO: implement libfabric version
}

static void libfabric_usage(void) {
    return; // TODO: implement libfabric version
}

struct fi_info *libfabric_get_info(const char *provider_name) {
    struct fi_info *hints, *info;
    hints = fi_allocinfo();
    if (!hints) {
        fprintf(stderr, "fi_allocinfo failed\n");
        exit(1);
    }
    hints->ep_attr->type = FI_EP_MSG;
    hints->caps = FI_MSG | FI_RMA | FI_READ | FI_REMOTE_READ;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY;
    hints->fabric_attr->prov_name = strdup(provider_name);
    hints->tx_attr->op_flags |= FI_INJECT_COMPLETE;
    FI_CHECK(fi_getinfo(FI_VERSION(2, 0), NULL, NULL, 0, hints, &info));
    fi_freeinfo(hints);
    return info;
}

libfabric_network_t libfabric_open_network(struct fi_info *fi) {
    VERBOSE_LOG("Opening network with provider fi_info:\n");
    // print_fi_info(fi);

    VERBOSE_LOG("Opening fabric\n");
    struct fid_fabric *fabric;
    FI_CHECK(fi_fabric(fi->fabric_attr, &fabric, NULL));

    VERBOSE_LOG("Opening domain\n");
    struct fid_domain *domain;
    FI_CHECK(fi_domain(fabric, fi, &domain, NULL));

    libfabric_network_t network = {0};
    network.fi = fi;
    network.fabric = fabric;
    network.domain = domain;

    return network;
}

// Connect to the server using connected endpoint
libfabric_connected_endpoint_t libfabric_connect_to_server(
    libfabric_network_t *network, const libfabric_address_t *server_address) {
    VERBOSE_LOG("Connecting to server at address: ");
    for (size_t i = 0; i < MAX_ADDRESS_SIZE; i++) {
        VERBOSE_LOG("%02x", server_address->bytes[i]);
    }
    VERBOSE_LOG("\n");

    // Create connected endpoint
    struct fid_ep *ep;
    FI_CHECK(fi_endpoint(network->domain, network->fi, &ep, NULL));

    // Create and bind event queue
    struct fid_eq *eq;
    struct fi_eq_attr eq_attr = {.wait_obj = FI_WAIT_UNSPEC};
    FI_CHECK(fi_eq_open(network->fabric, &eq_attr, &eq, NULL));
    FI_CHECK(fi_ep_bind(ep, &eq->fid, 0));

    // Create and bind completion queue
    struct fid_cq *cq;
    struct fi_cq_attr cq_attr = {.format = FI_CQ_FORMAT_DATA};
    FI_CHECK(fi_cq_open(network->domain, &cq_attr, &cq, NULL));
    FI_CHECK(fi_ep_bind(ep, &cq->fid,
                        FI_TRANSMIT | FI_RECV));  // TODO: correct flags

    // Connect to the server
    FI_CHECK(fi_connect(ep, server_address->bytes, NULL, 0));

    VERBOSE_LOG(
        "Connection request sent to server, waiting for connected event\n");

    // Wait for connection completion
    struct fi_eq_cm_entry entry;
    ssize_t rd;
    uint32_t event;
    ssize_t ret = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);

    if (ret < 0) {
        fprintf(stderr, "fi_eq_sread failed: %ld (%s)\n", ret,
                fi_strerror(-ret));
        exit(1);
    }
    if (event == FI_CONNECTED) {
        VERBOSE_LOG("Connected to server successfully\n");
    } else {
        // Unexpected event
        fprintf(stderr, "Unexpected event: %d\n", event);
        exit(1);
    }

    VERBOSE_LOG("ep->fid.fclass = %u ?= %u\n", ep->fid.fclass, FI_CLASS_EP);

    // Create connected endpoint structure
    libfabric_connected_endpoint_t connected_ep;
    connected_ep.ep = ep;
    connected_ep.cq = cq;
    connected_ep.eq = eq;

    return connected_ep;
}

libfabric_listening_endpoint_t libfabric_create_listening_endpoint(
    libfabric_network_t *network) {
    VERBOSE_LOG("Creating listening endpoint\n");

    // Create passive endpoint
    struct fid_pep *pep;
    FI_CHECK(fi_passive_ep(network->fabric, network->fi, &pep, NULL));

    // Create and bind event queue
    struct fid_eq *eq;
    struct fi_eq_attr eq_attr = {.wait_obj = FI_WAIT_UNSPEC};
    FI_CHECK(fi_eq_open(network->fabric, &eq_attr, &eq, NULL));
    FI_CHECK(fi_pep_bind(pep, &eq->fid, 0));

    // Start listening for incoming connections
    FI_CHECK(fi_listen(pep));
    VERBOSE_LOG("Listening for incoming connections\n");

    // Get the address of the listening endpoint
    uint8_t addr[MAX_ADDRESS_SIZE];
    size_t addrlen = sizeof(addr);
    FI_CHECK(fi_getname(&pep->fid, addr, &addrlen));
    libfabric_address_t listening_addr =
        libfabric_address_from_bytes(addr, addrlen);

    VERBOSE_LOG("Listening address: ");
    for (size_t i = 0; i < MAX_ADDRESS_SIZE; i++) {
        VERBOSE_LOG("%02x", listening_addr.bytes[i]);
    }
    VERBOSE_LOG("\n");

    // Return the listening endpoint
    libfabric_listening_endpoint_t listening_ep;
    listening_ep.pep = pep;
    listening_ep.eq = eq;
    listening_ep.addr = listening_addr;

    VERBOSE_LOG("Listening endpoint created\n");

    return listening_ep;
}

void libfabric_close_listening_endpoint(
    libfabric_listening_endpoint_t *listening_ep) {
    if (listening_ep->pep) {
        FI_CHECK(fi_close(&listening_ep->pep->fid));
    }
    if (listening_ep->eq) {
        FI_CHECK(fi_close(&listening_ep->eq->fid));
    }
}

libfabric_connected_endpoint_t libfabric_accept_connection(
    libfabric_network_t *network,
    libfabric_listening_endpoint_t *listening_ep) {
    VERBOSE_LOG("Accepting client connection\n");

    // Wait for connection request
    struct fi_eq_cm_entry entry;
    ssize_t rd;
    uint32_t event;
    rd = fi_eq_sread(listening_ep->eq, &event, &entry, sizeof entry, -1, 0);
    if (rd < 0) {
        fprintf(stderr, "fi_eq_sread failed: %zd\n", rd);
        exit(1);
    }

    switch (event) {
        case FI_CONNREQ:
            VERBOSE_LOG("Client connection request received\n");
            // Create endpoint to accept the connection
            struct fid_ep *ep;
            FI_CHECK(fi_endpoint(network->domain, entry.info, &ep, NULL));

            // Create and bind completion queue
            struct fid_cq *cq;
            struct fi_cq_attr cq_attr = {.format = FI_CQ_FORMAT_DATA};
            FI_CHECK(fi_cq_open(network->domain, &cq_attr, &cq, NULL));
            FI_CHECK(fi_ep_bind(ep, &cq->fid,
                                FI_TRANSMIT | FI_RECV));  // TODO: correct flags

            // Create and bind event queue TODO: is this necessary?
            struct fid_eq *eq;
            struct fi_eq_attr eq_attr = {.wait_obj = FI_WAIT_UNSPEC};
            FI_CHECK(fi_eq_open(network->fabric, &eq_attr, &eq, NULL));
            FI_CHECK(fi_ep_bind(ep, &eq->fid, 0));

            // Accept the connection
            FI_CHECK(fi_accept(ep, NULL, 0));
            VERBOSE_LOG("Connection accepted\n");

            // Return the connected endpoint
            libfabric_connected_endpoint_t connected_ep;
            connected_ep.ep = ep;
            connected_ep.cq = cq;
            connected_ep.eq = eq;

            return connected_ep;

            break;
        case FI_CONNECTED:
            VERBOSE_LOG("Connected event received\n");
            break;
        default:
            fprintf(stderr, "Unknown event received: %d\n", event);
            exit(1);
    }
}

struct fid_mr *libfabric_register_memory_region(void *ptr, size_t size);

/* exchanges peer_info and sets nodes_no and my_node_id */
int MPI_data_exchange(struct ng_options *global_opts,
                      libfabric_private_data_t *module_data,
                      peer_info_t my_peer_info) {
    VERBOSE_LOG("Exchanging peer info using MPI\n");

    module_data->my_node_id = g_options.mpi_opts->worldrank;
    module_data->nodes_no = g_options.mpi_opts->worldsize;

    module_data->peer_info =
        malloc(sizeof(peer_info_t) * module_data->nodes_no);

    // Exchange peer_info using MPI
    MPI_Allgather(&my_peer_info, sizeof(peer_info_t), MPI_BYTE,
                  module_data->peer_info, sizeof(peer_info_t), MPI_BYTE,
                  MPI_COMM_WORLD);
}

static int libfabric_init(struct ng_options *global_opts) {
    VERBOSE_LOG("Initializing libfabric module\n");

    // setenv("FI_LOG_LEVEL", "INFO", 1);

    // Log value of FI_VERBS_MIN_RNR_TIMER env variable
    char *rnr_timer = getenv("FI_VERBS_MIN_RNR_TIMER");;
    if (rnr_timer) {
        VERBOSE_LOG("FI_VERBS_MIN_RNR_TIMER is set to %s\n", rnr_timer);
    } else {
        VERBOSE_LOG("FI_VERBS_MIN_RNR_TIMER is not set\n");
    }

    // For now hardcoded
    module_data.provider_name = "verbs";
    // module_data.provider_name = "TCP";

    // Initialize libfabric
    struct fi_info *info = libfabric_get_info(module_data.provider_name);
    module_data.network = libfabric_open_network(info);
    libfabric_listening_endpoint_t listening_endpoint =
        libfabric_create_listening_endpoint(&module_data.network);

    // Alloc internal buffers
    module_data.internal_buffer_size = 16777216;

    module_data.local_buffer = malloc(module_data.internal_buffer_size);
    module_data.local_mr = libfabric_register_memory_region(
        module_data.local_buffer, module_data.internal_buffer_size);
    module_data.local_descriptor = fi_mr_desc(module_data.local_mr);

    module_data.remote_operation_buffer = malloc(module_data.internal_buffer_size);
    module_data.remote_mr = libfabric_register_memory_region(
        module_data.remote_operation_buffer, module_data.internal_buffer_size);
    module_data.remote_operation_descriptor = fi_mr_desc(module_data.remote_mr);
    module_data.remote_operation_buffer_key = fi_mr_key(module_data.remote_mr);

    // Set my_peer_info
    peer_info_t my_peer_info;
    size_t addrlen = sizeof(my_peer_info.address);
    FI_CHECK(fi_getname(&listening_endpoint.pep->fid, my_peer_info.address.bytes, &addrlen));
    my_peer_info.buffer_address = (uint64_t)module_data.remote_operation_buffer;
    my_peer_info.buffer_key = module_data.remote_operation_buffer_key;

    MPI_data_exchange(global_opts, &module_data, my_peer_info);

    // Initialize connections with each peer
    module_data.peer_connections =
        malloc(sizeof(libfabric_connected_endpoint_t) * module_data.nodes_no);

    // Accept connections from peers with lower IDs
    for (size_t i = 0; i < module_data.my_node_id; i++) {
        libfabric_connected_endpoint_t connected_endpoint =
            libfabric_accept_connection(&module_data.network,
                                        &listening_endpoint);

        module_data.peer_connections[i] = connected_endpoint;
    }

    // Stop accepting connections
    libfabric_close_listening_endpoint(&listening_endpoint);

    // Connect to peers with higher IDs in reverse order
    for (size_t i = module_data.nodes_no - 1; i > module_data.my_node_id; i--) {
        libfabric_connected_endpoint_t connected_endpoint =
            libfabric_connect_to_server(&module_data.network,
                                        &module_data.peer_info[i].address);

        module_data.peer_connections[i] = connected_endpoint;
    }

    VERBOSE_LOG("libfabric module initialized successfully\n");

    HRT_GET_TIMESTAMP(benchmark_start_2);

    return 0;
}

void libfabric_add_memory_region(
    void *start,
    size_t length, 
    struct fid_mr *mr
) {
    libfabric_memory_region_info_t *new_info =
        malloc(sizeof(libfabric_memory_region_info_t));
    new_info->start = start;
    new_info->length = length;
    new_info->mr = mr;
    new_info->next = module_data.memory_regions;
    new_info->desc = fi_mr_desc(mr);  // Get the memory region descriptor

    module_data.memory_regions = new_info;
}

libfabric_memory_region_info_t *libfabric_get_memory_region_info(void *ptr) {
    VERBOSE_LOG("Looking up memory region for pointer %p\n", ptr);

    libfabric_memory_region_info_t *current = module_data.memory_regions;
    while (current) {
        VERBOSE_LOG("Checking memory region: start=%p, length=%zu\n", current->start, current->length);
        VERBOSE_LOG("%p <= %p <= %p\n", current->start, ptr, current->start + current->length);
        if (current->start <= ptr && ptr <= current->start + current->length) {
            return current;
        }
        current = current->next;
    }
    return NULL;  // Memory region not found
}

struct fid_mr *libfabric_register_memory_region(void *ptr, size_t size) {
    VERBOSE_LOG("Registering memory region at %p with size %zu\n", ptr, size);

    // Register memory with libfabric
    struct fid_mr *mr;
    struct fi_mr_attr mr_attr = {0};
    struct iovec iov = {.iov_base = ptr, .iov_len = size};
    mr_attr.mr_iov = &iov;
    mr_attr.iov_count = 1;
    mr_attr.access = FI_REMOTE_READ | FI_READ | FI_SEND | FI_RECV;

    uint64_t key = ((uint64_t)rand() << 32) | rand();
    mr_attr.requested_key = key;

    uint64_t flags = 0;
    FI_CHECK(fi_mr_regattr(module_data.network.domain, &mr_attr, flags, &mr));

    return mr;
}

void *libfabric_malloc(size_t size) {
    VERBOSE_LOG("Allocating %zu bytes of memory\n", size);

    void *ptr = malloc(size);
    
    struct fid_mr *mr = libfabric_register_memory_region(ptr, size);

    // Save the memory region info
    libfabric_add_memory_region(ptr, size, mr);

    VERBOSE_LOG("Memory allocated at %p with size %zu\n", ptr, size);
    return ptr;
}

void wait_for_completion(struct fid_cq *cq) {
    while (true) {
        struct fi_cq_data_entry comp;
        int ret;
        if (/*active_pooling*/ true) {
            ret = fi_cq_read(cq, &comp, 1);
        } else {
            ret = fi_cq_sread(cq, &comp, 1, NULL, -1);
        }
        if (ret > 0) {
            // Completion detected
            break;
        } else if (ret == -FI_EAGAIN) {
            // No completions available, retry polling
        } else if (ret == -FI_EAVAIL) {
            int err_code;
            PRINT_CQ_ERROR(cq, &err_code);
            exit(1);
        } else {
            fprintf(stderr, "fi_cq_read failed: %d (%s)\n", ret,
                    fi_strerror(-ret));
            exit(1);
        }
    }
}

// Reads all completions from the completion queue. Every completion is supposed
// to have a pointer to libfabric_completion_handle_t in a op_context field,
// this pointer is used to mark the operation as completed.
void read_all_completions(struct fid_cq *cq) {
    static int pools_no = 0;

    while (true) {
        struct fi_cq_data_entry comp;
        int ret = fi_cq_read(cq, &comp, 1);
        // VERBOSE_LOG_2("%d", module_data.my_node_id);
        pools_no++;
        if (ret > 0) {
            // Completion detected, continue reading

            libfabric_completion_handle_t *handle =
                (libfabric_completion_handle_t*)comp.op_context;

            //Mark comp as completed
            if (handle != NULL) {
                handle->completed = true;
                double time_stamp = get_timestamp_usec_2();
            VERBOSE_LOG_2("Read completion: "
                      "op_context=%p, flags=0x%lx, len=%lu, "
                      "buf=%p, data=%lu, pools_since_last=%d, time_stamp=%lu, node=%d\n",
                      comp.op_context, comp.flags, comp.len, comp.buf,
                      comp.data, pools_no, (unsigned long)time_stamp, module_data.my_node_id);
                pools_no = 0;
            } else {
                fprintf(stderr, "Completion handle is NULL\n");
                exit(1);
            }

            continue;
        } else if (ret == -FI_EAGAIN) {
            // No more completions available
            break;
        } else if (ret == -FI_EAVAIL) {
            int err_code;
            PRINT_CQ_ERROR(cq, &err_code);
            exit(1);
        } else {
            fprintf(stderr, "fi_cq_read failed: %d (%s)\n", ret,
                    fi_strerror(-ret));
            exit(1);
        }
    }
}

int libfabric_set_blocking(int fd, int blocking) {
    // Not supported in libfabric
    return 0;
}

static void libfabric_shutdown(struct ng_options *global_opts) {
    // TODO: Implement libfabric shutdown
    return;
}

static int libfabric_isendto(int dst, void *buffer, int size, int tag, NG_Request *req) {
    VERBOSE_LOG("Sending %d bytes to peer %d\n", size, dst);

    libfabric_completion_handle_t *handle = libfabric_get_completion_handle();
    handle->completed = false;
    handle->cq = module_data.peer_connections[dst].cq;

    *req = (NG_Request)handle;

    switch (module_data.rdma_operation) {
        case 's': // send (send/recv)
        {
            // Get the memory region descriptor
            // void *desc = libfabric_get_memory_region_info(buffer)->desc;

            RETRY_ON_EAGAIN(fi_send(
                module_data.peer_connections[dst].ep,
                // buffer,
                module_data.local_buffer,
                size,
                // desc,
                module_data.local_descriptor,
                FI_ADDR_UNSPEC,
                handle // context
            ));
            break;
        }
        case 'r': // RDMA read
            RETRY_ON_EAGAIN(fi_read(
                module_data.peer_connections[dst].ep,
                module_data.local_buffer,
                size,
                module_data.local_descriptor,
                /*peer_addres=*/0,
                module_data.peer_info[dst].buffer_address,
                module_data.peer_info[dst].buffer_key,
                handle // context
            ));
            break;
        case 'w': // RDMA write
            RETRY_ON_EAGAIN(fi_write(
                module_data.peer_connections[dst].ep,
                module_data.local_buffer,
                size,
                module_data.local_descriptor,
                /*peer_addres=*/0,
                module_data.peer_info[dst].buffer_address,
                module_data.peer_info[dst].buffer_key,
                handle // context
            ));
            break;
        default:
            // Impossible, would cause an error in module initialization
            exit(1);
    }

    // This is blocking and sends all data
    return size;
}

static int libfabric_irecvfrom(int src, void *buffer, int size, int tag, NG_Request *req) {
    VERBOSE_LOG("Receiving %d bytes from peer %d\n", size, src);

    libfabric_completion_handle_t *handle = libfabric_get_completion_handle();

    VERBOSE_LOG("Setting completion handle completed to false\n");
    handle->completed = false;

    VERBOSE_LOG("Setting completion cq pointer\n");
    handle->cq = module_data.peer_connections[src].cq;

    VERBOSE_LOG("Setting request handle for caller\n");    
    *req = (NG_Request)handle;

    switch (module_data.rdma_operation) {
        case 's': // receive (send/recv)
        {
            // Get the memory region descriptor
            VERBOSE_LOG("Getting memory region descriptor for buffer %p\n", buffer);
            // libfabric_memory_region_info_t *mr_info = libfabric_get_memory_region_info(buffer);
            // VERBOSE_LOG("mr_info=%p\n", mr_info);
            
            // void *desc = mr_info->desc;
            // VERBOSE_LOG("desc=%p\n", desc);

            VERBOSE_LOG("Retrieving endpoint for peer %d\n", src);
            struct fid_ep *ep = module_data.peer_connections[src].ep;

            VERBOSE_LOG("Posting fi_recv\n");
            VERBOSE_LOG("ep=%p\n", ep);
            VERBOSE_LOG("buffer=%p\n", buffer);
            VERBOSE_LOG("size=%d\n", size);
            // VERBOSE_LOG("desc=%p\n", desc);
            VERBOSE_LOG("handle=%p\n", handle);
            FI_CHECK(fi_recv(
                ep,
                // buffer,
                module_data.local_buffer,
                size,
                // desc,
                module_data.local_descriptor,
                FI_ADDR_UNSPEC,
                handle
            ));

            // wait_for_completion(module_data.peer_connections[src].cq);
            break;
        }
        case 'r': // RDMA read
            // Do nothing and mark as completed
            VERBOSE_LOG("Marking RDMA read as completed\n");
            handle->completed = true;
            break;
        case 'w': // RDMA write
            // Do nothing and mark as completed
            VERBOSE_LOG("Marking RDMA write as completed\n");
            handle->completed = true;
            break;
        default:
            // Impossible, would cause an error in module initialization
            exit(1);
    }

    return size;
}

static int libfabric_test(NG_Request *req) {
    libfabric_completion_handle_t *handle = (libfabric_completion_handle_t *)(*req);

    // // Read all completions from the CQ
    read_all_completions(handle->cq);

    if (handle->completed) {
        return 0; // completed
    } else {
        return 1; // not completed
    }

    return 0; // Always completed in blocking implementation
}

static int libfabric_sendto(int dst, void *buffer, int size, int tag) {
    NG_Request req;
    libfabric_isendto(dst, buffer, size, tag, &req);
    
    // Wait for completion
    while (libfabric_test(&req) != 0) {
        // Busy wait
    }

    return size;
}

static int libfabric_recvfrom(int src, void *buffer, int size, int tag) {
    NG_Request req;
    libfabric_irecvfrom(src, buffer, size, tag, &req);
    
    // Wait for completion
    while (libfabric_test(&req) != 0) {
        // Busy wait
    }

    return size;
}

/* module registration */
int register_libfabric(void) {
   ng_register_module(&libfabric_module);
   return 0;
}

#else

/* Don't register this module if NG_MOD_LIBFABRIC is not defined */
int register_libfabric(void) {
   return 0;
}

#endif // NG_MOD_LIBFABRIC
