#include "netgauge.h"
#ifdef NG_MOD_LIBFABRIC

#include "mod_libfabric.h"

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

#define VERBOSE_LOG(fmt, ...)                    \
    do {                                         \
        if (0) {                                 \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
        }                                        \
    } while (0)

struct ng_module libfabric_module = {
    .name = "libfabric",
    .desc = "This mod uses libfabric for data transmission.",
    .flags = NG_MOD_RELIABLE | NG_MOD_CHANNEL,
    .max_datasize = -1, /*  can send data of arbitrary size */
    .headerlen = 0,     /*  no extra space needed for header */
    .malloc = NULL,
    .getopt = tcp_getopt,  // TODO: implement libfabric version
    .init = libfabric_init,
    .shutdown = libfabric_shutdown,
    .usage = tcp_usage,                // TODO: implement libfabric version
    .writemanpage = tcp_writemanpage,  // TODO: implement libfabric version
    .sendto = libfabric_sendto,
    .recvfrom = libfabric_recvfrom,
    .set_blocking = libfabric_set_blocking,
    .isendto = tcp_isendto,            // TODO: implement libfabric version
    .irecvfrom = tcp_irecvfrom,        // TODO: implement libfabric version
    .test = tcp_test,                  // TODO: implement libfabric version
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

    libfabric_network_t network;
    libfabric_connected_endpoint_t *peer_connections;
    libfabric_memory_region_info_t *memory_regions; /* linked list of memory regions info */

    struct peer_info_t my_peer_info; /* info about this node to send to peers */
    size_t nodes_no;                 /* number of nodes in the benchmark */
    size_t my_node_id;               /* this node's id */
    struct peer_info_t *peer_info;   /* info about all nodes */
} libfabric_private_data_t;

libfabric_private_data_t module_data;

struct fi_info *libfabric_get_info(const char *provider_name) {
    struct fi_info *hints, *info;
    hints = fi_allocinfo();
    if (!hints) {
        fprintf(stderr, "fi_allocinfo failed\n");
        exit(1);
    }
    hints->ep_attr->type = FI_EP_RDM;
    hints->caps = FI_MSG | FI_RMA | FI_READ | FI_REMOTE_READ;
    hints->fabric_attr->prov_name = strdup(provider_name);
    FI_CHECK(fi_getinfo(FI_VERSION(2, 0), NULL, NULL, 0, hints, &info));
    fi_freeinfo(hints);
    return info;
}

libfabric_network_t libfabric_open_network(struct fi_info *fi) {
    VERBOSE_LOG("Opening network with provider fi_info:\n");
    print_fi_info(fi);

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

    // Create connected endpoint structure
    libfabric_connected_endpoint_t connected_ep;
    connected_ep.ep = ep;
    connected_ep.cq = cq;
    connected_ep.eq = eq;

    return connected_ep;
}

libfabric_listening_endpoint_t libfabric_create_listening_endpoint(
    struct Network *network) {
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
        VERBOSE_LOG("%02x", listening_addr[i]);
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

/* exchanges peer_info and sets nodes_no and my_node_id */
int MPI_data_exchange(struct ng_options *global_opts,
                      libfabric_private_data_t *module_data,
                      peer_info_t my_peer_info) {
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
    // Initialize libfabric
    struct fi_info *info = libfabric_get_info(global_opts->provider_name);
    module_data.network = libfabric_open_network(info);
    libfabric_listening_endpoint_t listening_endpoint =
        libfabric_create_listening_endpoint(&module_data.network);

    // Set my_peer_info
    peer_info_t my_peer_info;
    size_t addrlen = sizeof(my_peer_info.address);
    FI_CHECK(fi_getname(&ep->fid, my_peer_info.address, &addrlen));

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
    libfabric_memory_region_info_t *current = module_data.memory_regions;
    while (current) {
        if (current->start >= ptr && ptr <= current->start + current->length) {
            return current;
        }
        current = current->next;
    }
    return NULL;  // Memory region not found
}

void *libfabric_malloc(size_t size) {
    void *ptr = malloc(size);
    
    // Register memory with libfabric
    struct fid_mr *mr;
    struct fi_mr_attr mr_attr = {0};
    struct iovec iov = {.iov_base = ptr, .iov_len = size};
    mr_attr.mr_iov = &iov;
    mr_attr.iov_count = 1;
    mr_attr.access = FI_REMOTE_READ | FI_READ | FI_SEND | FI_RECV;

    // uint64_t key = ((uint64_t)rand() << 32) | rand();
    // mr_attr.requested_key = key;

    uint64_t flags = 0;
    FI_CHECK(fi_mr_regattr(module_data.network.domain, &mr_attr, flags, &mr));

    // Save the memory region info
    libfabric_add_memory_region(ptr, size, mr);

    return ptr;
}

void wait_for_completion(struct fi_cq *cq) {
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

static int libfabric_sendto(int dst, void *buffer, int size) {
    // ssize_t fi_send(struct fid_ep *ep, const void *buf, size_t len,
    // void *desc, fi_addr_t dest_addr, void *context);

    // Get the memory region descriptor
    void *desc = libfabric_get_memory_region_info(buffer)->desc;

    FI_CHECK(fi_send(
        module_data.peer_connections[dst].ep,
        buffer,
        size,
        desc,
        FI_ADDR_UNSPEC,
        NULL
    ));

    wait_for_completion(module_data.peer_connections[dst].cq);
}

static int libfabric_recvfrom(int src, void *buffer, int size) {
    // ssize_t fi_recv(struct fid_ep *ep, void * buf, size_t len,
    // void *desc, fi_addr_t src_addr, void *context);

    // Get the memory region descriptor
    void *desc = libfabric_get_memory_region_info(buffer)->desc;

    FI_CHECK(fi_recv(
        module_data.peer_connections[src].ep,
        buffer,
        size,
        desc,
        FI_ADDR_UNSPEC,
        NULL
    ));

    wait_for_completion(module_data.peer_connections[src].cq);
}

int libfabric_set_blocking(int fd, int blocking) {
    // Not supported in libfabric
    return 0;
}

static void libfabric_shutdown(struct ng_options *global_opts) {
    // TODO: Implement libfabric shutdown
    return;
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

#endif
