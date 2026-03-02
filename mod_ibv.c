/*
 * Copyright (c) 2009 The Trustees of Indiana University and Indiana
 *                    University Research and Technology
 *                    Corporation.  All rights reserved.
 *
 * Author(s): Torsten Hoefler <htor@cs.indiana.edu>
 *
 */

/* A new implementation of the Infiniband module of netgauge by oere
 * which uses the OpenIB/OpenFabrics verbs API 
 */

#include "netgauge.h"

#if defined NG_MPI && defined NG_OFED && defined NG_MOD_IBV /* do we want a build with openib stuff */

#include "infiniband/verbs.h" /* OFED stuff */
#include "mod_ibv.h"

#include <string.h>
#include <stdbool.h>

#define VERBOSE_LOG(fmt, ...)                    \
    do {                                         \
        if (0) {                                 \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
        }                                        \
    } while (0)

extern struct ng_options g_options;

/* module registration data structure */
static struct ng_module ibv_module = {
   .name           = "ibv",
   .desc           = "Mode ibv uses Infiniband 1:1 communication for data transmission.",
   .max_datasize   = 256 * 1024 * 1024,      /* can send data of arbitrary size */
   // .max_datasize   = 16777216,      /* can send data of arbitrary size */
   .headerlen      = 0,       /* no extra space needed for header */
   .flags          = NG_MOD_MEMREG | NG_MOD_RELIABLE | NG_MOD_CHANNEL, /* UD??? */
   .malloc         = NULL, /* TODO: implement */
   .getopt         = ibv_getopt,
   .init           = ibv_init,
   .shutdown       = ibv_shutdown,
   .usage          = ibv_usage,
   .sendto         = ibv_sendto,
   .recvfrom       = ibv_recvfrom,
   .writemanpage   = ibv_writemanpage,
   .isendto        = ibv_isendto,
   .irecvfrom      = ibv_irecvfrom,
   .test           = ibv_test,
};

// Returned by async operations as handle to check for completion
typedef struct {
    bool completed;
    int peer;
} ibv_completion_handle_t;

#define MAX_HANDLES 1024

ibv_completion_handle_t* ibv_get_completion_handle() {
    static ibv_completion_handle_t handles[MAX_HANDLES];
    static int next_handle = 0;

    return &handles[next_handle++ % MAX_HANDLES];
}

/* parses the module specific options and set some values in module_data
 * return 0 on success and 1 otherwise
 */
static int 
ibv_getopt(int argc, char **argv, struct ng_options *global_opts) {
   int c;
   char *optchars = "-T:M:";
   extern char *optarg;
   extern int optind, opterr, optopt;

    int tran_mode_set = 0, tran_type_set = 0;

   /* currently we only support the ibv module in conjunction with MPI to
    * exchange the connection parameters between the peers
    * an other way is to use common tcp/ip sockets but this is not 
    * implemented yet :)
    */
   if (!global_opts->mpi) {
      ng_error("Mode %s requires the global option '-p' (execution via MPI)",
         global_opts->mode);
      return 1;
   }
   
   /* set the parameter struct to zero to get a good point to begin */
   memset(&module_data, 0, sizeof(module_data));

   /* parsing the options and set some parameters */
   while ((c = getopt(argc, argv, optchars)) >= 0) {
      ng_info(NG_VLEV2, "Processing option '-%c' with argument '%s'", c, optarg ? optarg : "NULL");
      switch (c) {
      case '?': /* unrecognized or badly used option */
         continue;
         if (!strchr(optchars, optopt))
            continue; /* unrecognized */
         ng_error("ibv: option %c requires an argument", optopt);
         return 1;
      case 'T':   /* set transport type:
                   * see verbs.h -> enum ibv_qp_type
                   * r = reliable connection (IBV_QPT_RC)
                   * u = unreliable connection (IBV_QPT_UC)
                   * U = unreliable datagram (IBV_QPT_UD)
                   * R = reliable datagram (IBV_QPT_RD) (currently not supported) 
                   */
         switch (optarg[0]) {
         case 'r': /* reliable connection */
            module_data.tran_type = IBV_QPT_RC;
            tran_type_set = 1;
            ng_info(NG_VLEV2, "Setting transport type to reliable connection");
            break;
         case 'u': /* unreliable connection */
            module_data.tran_type = IBV_QPT_UC;
            tran_type_set = 1;
            ng_info(NG_VLEV2, "Setting transport type to unreliable connection");
            break;
         case 'U': /* unreliable datagram */
            module_data.tran_type = IBV_QPT_UD;
            tran_type_set = 1;
            ng_info(NG_VLEV2, "Setting transport type to unreliable datagram");
            break;
         default: /* wrong argument for -T */
            ng_error("Only 'r', 'u' and 'U' are possible arguments for ibv option -T");
            return 1;
         } /* -T switch */
         break; /* case 'T' */
      case 'M':   /* set transport mode:
                   * s = normal send mode (IBV_WR_SEND)
                   * w = RDMA write (IBV_WR_RDMA_WRITE)
                   * r = RDMA read (IBV_WR_RDMA_READ)
                   */
         switch (optarg[0]) {
         case 's': /* send */ 
            module_data.tran_mode = IBV_WR_SEND;
            tran_mode_set = 1;
            ng_info(NG_VLEV2, "Setting transport mode to send");
            break;
         case 'w': /* RDMA write */
            module_data.tran_mode = IBV_WR_RDMA_WRITE;
            tran_mode_set = 1;
            ng_info(NG_VLEV2, "Setting transport mode to RDMA write");
            break;
         case 'r': /* RDMA read */
            module_data.tran_mode = IBV_WR_RDMA_READ;
            tran_mode_set = 1;
            ng_info(NG_VLEV2, "Setting transport mode to RDMA read");
            break;
         default:  /* wrong argument for -M */
            ng_error("Only 's', 'w' and 'r' are possible arguments for ibv option -M");
            return 1;
         } /* -M switch */
         break; /* case 'M' */
      default:
         continue;
         ng_error("We got an unspecified argument in %s", __func__);
         return 1;
      } /* outer switch */                     
   } /* getopt loop */
  
   /* setting some default values if we got no commandline arguments for these */
   if (!tran_type_set) {
      module_data.tran_type = IBV_QPT_RC;
      ng_info(NG_VLEV2, "Setting transport type to default value reliable connection");
   }
   if (!tran_mode_set) {
      module_data.tran_mode = IBV_WR_SEND;
      ng_info(NG_VLEV2, "Setting transport mode to default value normal send");
   }
  
   return 0;
}

/* first steps for using the hca i.e. get the handle, the protection domain,
 * register some memory and create the queue pairs 
 */

static int
ibv_init (struct ng_options *global_opts) {
   
   int retval;
   
   /* structs for setting up the queue pair */
   struct ibv_qp_init_attr initattr;
   struct ibv_qp_attr attr;
   memset(&initattr, 0, sizeof(struct ibv_qp_init_attr));
   memset(&attr, 0, sizeof(struct ibv_qp_attr));
   
   /* get some supplied options from the main program for further use
    * when "global_opts" is not available
    */
   module_data.mpi_partner  = (global_opts->mpi_opts->worldrank+1)%2 ;
   module_data.mpi_comm     = MPI_COMM_WORLD; // global_opts->mpi_opts->comm;
   module_data.max_datasize = 256 * 1024 * 1024;
   // module_data.max_datasize = 16777216 * 2; /* 16 MB max data size */
   module_data.mpi_size     = global_opts->mpi_opts->worldsize;
   module_data.mpi_rank     = global_opts->mpi_opts->worldrank;
               
   /* FIXME size of the transmission queue */
   module_data.tx_depth = 100;
  
   /* get the list with the available hcas */
   module_data.dev_list = ibv_get_device_list(NULL);

   /* FIXME
    * at the moment we choose the first one, because we need some mechanism 
    * to set the correct hca if we run netgauge with mpi and we can't set a 
    * cli parameter for each peer if the hcas are different for each
    */
   module_data.ib_dev = module_data.dev_list[0];
   if (!module_data.ib_dev) {
      ng_error("No HCA found! (%s/%s/%d)", __FILE__, __func__, __LINE__);
      return 1;
   }

   /* now we open the first device we've found */
   module_data.context = ibv_open_device(module_data.ib_dev);
   if (!module_data.context) {
      ng_error("Couldn't get context for %s (%s/%s/%d)", 
         ibv_get_device_name(module_data.ib_dev), __FILE__, __func__, __LINE__);
      return 1;
   }
   ng_info(NG_VLEV2, "Got context for %s", 
      ibv_get_device_name(module_data.ib_dev));

   /* we free the device list because we don't need it any longer and memory is rare */
   ibv_free_device_list(module_data.dev_list);

   /* the next task is to acquire the protection domain */
   module_data.pd = ibv_alloc_pd(module_data.context);
   if (!module_data.pd) {
      ng_error("Couldn't allocate PD");
      return 1;
   }

   /* now create we allocate some memory in an aligned manner 
    * which we use for sending and receiving, but first
    * we get the page size with a GLIBC function
    * see chapter 13.7 Memory-mapped I/O
    */
   module_data.page_size = (size_t) sysconf (_SC_PAGESIZE);
   
   /* FIXME do we really need max_datasize * 2 */ 
   if (module_data.tran_type == IBV_QPT_UD) {
      module_data.buf = memalign(module_data.page_size, (module_data.max_datasize + 40) * 2);
   } else {
      module_data.buf = memalign(module_data.page_size, module_data.max_datasize * 2);
   }
   if (!module_data.buf) {
      ng_error("Couldn't allocate the work buffer (%s/%s/%d)", 
                  __FILE__, __func__, __LINE__);
      return 1;
   }
   if (module_data.tran_type == IBV_QPT_UD) {
      memset(module_data.buf, 0, (module_data.max_datasize + 40) * 2);
      /* we register the memory region */
      module_data.mr = ibv_reg_mr(module_data.pd, module_data.buf, 
                                 (module_data.max_datasize + 40) * 2,
                                 IBV_ACCESS_REMOTE_WRITE | 
                                 IBV_ACCESS_LOCAL_WRITE |
                                 IBV_ACCESS_REMOTE_READ);
   } else {
      memset(module_data.buf, 0, module_data.max_datasize * 2);
      /* we register the memory region */
      module_data.mr = ibv_reg_mr(module_data.pd, module_data.buf, 
                                 module_data.max_datasize * 2,
                                 IBV_ACCESS_REMOTE_WRITE | 
                                 IBV_ACCESS_LOCAL_WRITE |
                                 IBV_ACCESS_REMOTE_READ);
   }
  if (!module_data.mr) {
      ng_error("Couldn't register the memory region");
      return 1;
   }

   // Allocate memory for completion queues and queue pairs
   module_data.cq = malloc(sizeof(struct ibv_cq*) * module_data.mpi_size);
   module_data.qp = malloc(sizeof(struct ibv_qp*) * module_data.mpi_size);

   // Create a queue pair for each peer node
   for (int i = 0; i < module_data.mpi_size; i++) {
      // Skip creating a QP for ourselves
      if (0) {
         continue;
      }

      struct ibv_cq *cq;
      struct ibv_qp *qp;

      /* create the completion queue */
      cq = ibv_create_cq(module_data.context, 
                                       module_data.tx_depth,
                                       NULL,
                                       NULL,
                                       0);
      if (!cq) {
         ng_error("Couldn't create the completion queue");
         return 1;
      }

      /* set initial values for the queue pair */
      initattr.send_cq = cq;
      initattr.recv_cq = cq;
      initattr.cap.max_send_wr = module_data.tx_depth;
      /* Work around from OFED perftest write_bw:  
       * driver doesnt support
       * recv_wr = 0 */
      initattr.cap.max_recv_wr  = 100;
      initattr.cap.max_send_sge = 1;
      initattr.cap.max_recv_sge = 1;
      initattr.cap.max_inline_data = MAX_INLINE;
      initattr.qp_type = module_data.tran_type;

      /* create the queue pair */
      qp = ibv_create_qp(module_data.pd,
                                     &initattr);
      if (!qp) {
         ng_error("Couldn't create the queue pair");
         return 1;
      }

      /* modify the queue pair to an initial state */
      attr.qp_state        = IBV_QPS_INIT;
      attr.pkey_index      = 0;
      attr.port_num        = 1;              /* FIXME: no static port */
      if (module_data.tran_type == IBV_QPT_UD) {
         attr.qkey            = 0x11111111;
         retval = ibv_modify_qp(qp, &attr, 
                                 IBV_QP_STATE              |
                                 IBV_QP_PKEY_INDEX         |
                                 IBV_QP_PORT               |
                                 IBV_QP_QKEY);
      } else {
         attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | 
                                IBV_ACCESS_LOCAL_WRITE  |
                                IBV_ACCESS_REMOTE_READ;
         retval = ibv_modify_qp(qp, &attr,
                                 IBV_QP_STATE              |
                                 IBV_QP_PKEY_INDEX         |
                                 IBV_QP_PORT               |
                                 IBV_QP_ACCESS_FLAGS);
      }
      if (retval) {
         ng_error("Couldn't modify the queue pair to INIT state");
         return 1;
      }

      // Save CQ and QP in module data
      module_data.cq[i] = cq;
      module_data.qp[i] = qp;
   }

   /* TODO: merge functions! */
   return ibv_setup_channels();                                                                                                                               
}


/* Transition from INIT to ReadyToReceive and ReadyToSend */
static int ibv_setup_channels(void) {
   MPI_Status status;
   
   /* attr struct to gather the lid */
   struct ibv_port_attr pattr;
   memset(&pattr, 0 , sizeof(struct ibv_port_attr));

   /* FIXME don't use a static port */
   if (!ibv_query_port(module_data.context, 1, &pattr) && !pattr.lid) {
      ng_error("Local LID 0x0 detected. Maybe there is no SM running?");
      return 1;
   }
   module_data.llid = pattr.lid;

   // Allocate memory for LIDS of all nodes 
   module_data.rlid = malloc(sizeof(uint16_t) * module_data.mpi_size);

   /* Exchange LIDs between all nodes using MPI_Allgather */
   if(MPI_Allgather(&module_data.llid, 1, MPI_UNSIGNED_SHORT,
                    module_data.rlid, 1, MPI_UNSIGNED_SHORT,
                    module_data.mpi_comm) != MPI_SUCCESS) {
      ng_error("Couldn't exchange LIDs between nodes");
      return 1;
   }

   /* setting the psn to a random value for every qp */
   srand48(getpid() * time(NULL)); // Inint RNG
   module_data.lpsn = malloc(sizeof(uint32_t) * module_data.mpi_size);
   for (int i = 0; i < module_data.mpi_size; i++) {
      module_data.lpsn[i] = lrand48() & 0xffffff;
   }

   module_data.rpsn = malloc(sizeof(uint32_t) * module_data.mpi_size);

   /* exchange the packet sequence number (uint32_t) with with all other nodes */
   for (int i = 0; i < module_data.mpi_size; i++) {
      if (i == module_data.mpi_rank) {
         continue; // Skip self
      }
      if(MPI_Sendrecv(&module_data.lpsn[i], 1, MPI_UNSIGNED, i, 22,
                      &module_data.rpsn[i], 1, MPI_UNSIGNED, i, 22,
                      module_data.mpi_comm, &status)
          != MPI_SUCCESS) {
         ng_error("Couldn't send and receive the packet sequence numbers to/from %d",
            i);
         return 1;
      }
   }
   
   module_data.rbuf = malloc(sizeof(unsigned long long) * module_data.mpi_size);

   /* exchange the memory addresses of the buffers */
   if(MPI_Allgather(&module_data.buf, 1, MPI_UNSIGNED_LONG_LONG,
                     module_data.rbuf, 1, MPI_UNSIGNED_LONG_LONG,
                     module_data.mpi_comm) != MPI_SUCCESS) {
      ng_error("Couldn't exchange the memory addresses between nodes");
      return 1;
   }  
   
   module_data.rrkey = malloc(sizeof(uint32_t) * module_data.mpi_size);

   /* get the rkey (uint32_t) from the partner and send the own */
   if (MPI_Allgather(&module_data.mr->rkey, 1, MPI_UNSIGNED,
                    module_data.rrkey, 1, MPI_UNSIGNED,
                    module_data.mpi_comm) != MPI_SUCCESS) {
      ng_error("Couldn't exchange remote keys between nodes");
      return 1;
   }
   
   module_data.rqp_num = malloc(sizeof(uint32_t) * module_data.mpi_size);

   /* send and receive the queue pair num */
   for (int i = 0; i < module_data.mpi_size; i++) {
      if (i == module_data.mpi_rank) {
         continue; // Skip self
      }
      if (MPI_Sendrecv(&module_data.qp[i]->qp_num, 1, MPI_UNSIGNED, i, 55,
                       &module_data.rqp_num[i], 1, MPI_UNSIGNED, i, 55,
                       module_data.mpi_comm, &status)
          != MPI_SUCCESS) {
         ng_error("Couldn't send and receive the queue pair numbers to/from %d",
            module_data.mpi_partner);
         return 1;
      }
   }

   // /* print some debug infos to the exchanged ib parameters */
   // ng_info(NG_VLEV2 | NG_VPALL,"local information:  LID %#04x, QPN %#06x, PSN %#06x "
   //                  "RKey %#08x VAddr %#016Lx",
   //                  module_data.llid, module_data.qp->qp_num, module_data.lpsn,
   //                  module_data.mr->rkey, module_data.buf);
   // ng_info(NG_VLEV2 | NG_VPALL,"remote information: LID %#04x, QPN %#06x, PSN %#06x "
   //                  "RKey %#08x VAddr %#016Lx",
   //                  module_data.rlid, module_data.rqp_num, module_data.rpsn,
   //                  module_data.rrkey, module_data.rbuf);

   module_data.ah = malloc(sizeof(struct ibv_ah*) * module_data.mpi_size);

   for (int i = 0; i < module_data.mpi_size; i++) {
      if (i == module_data.mpi_rank) {
         continue; // Skip self
      }

      /* parameter struct for state transitions */
      struct ibv_qp_attr qpattr;
      memset(&qpattr, 0, sizeof(struct ibv_qp_attr));

      /* transit the queue pair to ReadyToReceive state */
      qpattr.qp_state = IBV_QPS_RTR;
      qpattr.path_mtu = IBV_MTU_2048; /* FIXME: add this as a parameter */
      qpattr.dest_qp_num = module_data.rqp_num[i];
      qpattr.rq_psn = module_data.rpsn[i];

      qpattr.ah_attr.is_global  = 0;
      qpattr.ah_attr.dlid       = module_data.rlid[i];
      qpattr.ah_attr.sl         = 0;
      qpattr.ah_attr.src_path_bits = 0;
      qpattr.ah_attr.port_num   = 1; /* FIXME no static port */

      if (module_data.tran_type == IBV_QPT_RC) {
         qpattr.max_dest_rd_atomic     = 1;
         qpattr.min_rnr_timer          = 12;
         if(ibv_modify_qp(module_data.qp[i], &qpattr,
                           IBV_QP_STATE               |
                           IBV_QP_AV                  |
                           IBV_QP_PATH_MTU            |
                           IBV_QP_DEST_QPN            |
                           IBV_QP_RQ_PSN              |
                           IBV_QP_MIN_RNR_TIMER       |
                           IBV_QP_MAX_DEST_RD_ATOMIC)) {
            ng_error("Failed to modify RC QP to RTR");
            return 1;
         }
         ng_info(NG_VLEV2, "Modified RC QP to RTR");
      } else if (module_data.tran_type == IBV_QPT_UC) {
         if(ibv_modify_qp(module_data.qp[i], &qpattr,
                           IBV_QP_STATE               |
                           IBV_QP_AV                  |
                           IBV_QP_PATH_MTU            |
                           IBV_QP_DEST_QPN            |
                           IBV_QP_RQ_PSN)) {
            ng_error("Failed to modify UC QP to RTR");
            return 1;
         }
         ng_info(NG_VLEV2, "Modified UC QP to RTR");
      } else {
         if(ibv_modify_qp(module_data.qp[i], &qpattr,
                           IBV_QP_STATE)) {
            ng_error("Failed to modify UD QP to RTR");
            return 1;
         }
         ng_info(NG_VLEV2, "Modified UD QP to RTR");
      }

      /* transit the queue pair to ReadyToSend state */
      qpattr.qp_state = IBV_QPS_RTS;
      qpattr.sq_psn = module_data.lpsn[i];
      if (module_data.tran_type == IBV_QPT_RC) {
         qpattr.timeout       = 14;
         qpattr.retry_cnt     = 7;
         qpattr.rnr_retry     = 7;
         qpattr.max_rd_atomic = 1;
         if(ibv_modify_qp(module_data.qp[i], &qpattr,
                           IBV_QP_STATE              |
                           IBV_QP_SQ_PSN             |
                           IBV_QP_TIMEOUT            |
                           IBV_QP_RETRY_CNT          |
                           IBV_QP_RNR_RETRY          |
                           IBV_QP_MAX_QP_RD_ATOMIC)) {
            ng_error("Failed to modify RC QP to RTS");
            return 1;
         }
         ng_info(NG_VLEV2, "Modified RC QP to RTS");
      } else {
         if(ibv_modify_qp(module_data.qp[i], &qpattr,
                           IBV_QP_STATE              |
                           IBV_QP_SQ_PSN)) {
            ng_error("Failed to modify UC/UD to RTS");
            return 1;
         }
         ng_info(NG_VLEV2, "Modified UC/UD to RTS");
      }
      if (module_data.tran_type == IBV_QPT_UD) {
         module_data.ah[i] = ibv_create_ah(module_data.pd, &qpattr.ah_attr);
         if (!module_data.ah[i]) {
            ng_error("Failed to create AH for UD");
            return 1;
         }
         ng_info(NG_VLEV2, "Created AH for UD");
      }
   } /* for all peers */

   if (module_data.mpi_rank != 1) {
      return 0;
   }

   struct ibv_qp_attr attr;
   struct ibv_qp_init_attr init_attr;
   int attr_mask = IBV_QP_QKEY 
             | IBV_QP_RQ_PSN 
             | IBV_QP_SQ_PSN 
             | IBV_QP_DEST_QPN 
             | IBV_QP_PKEY_INDEX 
             | IBV_QP_EN_SQD_ASYNC_NOTIFY 
             | IBV_QP_MAX_QP_RD_ATOMIC 
             | IBV_QP_MAX_DEST_RD_ATOMIC 
             | IBV_QP_MIN_RNR_TIMER 
             | IBV_QP_PORT 
             | IBV_QP_TIMEOUT 
             | IBV_QP_RETRY_CNT 
             | IBV_QP_RNR_RETRY 
             | IBV_QP_ALT_PATH // Covers alt_pkey, alt_port, alt_timeout
             | IBV_QP_STATE;
   int rc = ibv_query_qp(module_data.qp[0], &attr, IBV_QP_STATE, &init_attr);
   if (rc) {
       fprintf(stderr, "ibv_query_qp failed: %d\n", rc);
   } else {
       VERBOSE_LOG("QP attributes:\n");
       VERBOSE_LOG("  qkey: %u\n", attr.qkey);
       VERBOSE_LOG("  rq_psn: %u\n", attr.rq_psn);
       VERBOSE_LOG("  sq_psn: %u\n", attr.sq_psn);
       VERBOSE_LOG("  dest_qp_num: %u\n", attr.dest_qp_num);
       VERBOSE_LOG("  pkey_index: %u\n", attr.pkey_index);
       VERBOSE_LOG("  alt_pkey_index: %u\n", attr.alt_pkey_index);
       VERBOSE_LOG("  en_sqd_async_notify: %d\n", attr.en_sqd_async_notify);
       VERBOSE_LOG("  sq_draining: %d\n", attr.sq_draining);
       VERBOSE_LOG("  max_rd_atomic: %d\n", attr.max_rd_atomic);
       VERBOSE_LOG("  max_dest_rd_atomic: %d\n", attr.max_dest_rd_atomic);
       VERBOSE_LOG("  min_rnr_timer: %d\n", attr.min_rnr_timer);
       VERBOSE_LOG("  port_num: %d\n", attr.port_num);
       VERBOSE_LOG("  timeout: %d\n", attr.timeout);
       VERBOSE_LOG("  retry_cnt: %d\n", attr.retry_cnt);
       VERBOSE_LOG("  rnr_retry: %d\n", attr.rnr_retry);
       VERBOSE_LOG("  alt_port_num: %d\n", attr.alt_port_num);
       VERBOSE_LOG("  alt_timeout: %d\n", attr.alt_timeout);
   }

   return 0;
}
 
/* send data of size 'size' to the partner :) */
static int
ibv_sendto(int dst, void *buffer, int size) {
   ng_info(NG_VLEV2, "ibv_sendto: sending %d bytes to peer %d", size, dst);
   
   struct ibv_send_wr *bad_wr;
   struct ibv_wc wc;
   int ne;
   /* at the moment we have to copy buffer content to the registered 
    * buffer of the hca --> a nice mess 
    * FIXME this is a hard operation for benchmarking 
    * memcpy(module_data.buf, buffer, size); 
    */
   
   module_data.send_list.addr          = (uintptr_t) module_data.buf;
   module_data.send_list.length        = size;
   module_data.send_list.lkey          = module_data.mr->lkey;
   module_data.wr.wr_id                = NULL;
   module_data.wr.sg_list              = &module_data.send_list;
   module_data.wr.num_sge              = 1;
   module_data.wr.opcode               = module_data.tran_mode;
   module_data.wr.send_flags           = IBV_SEND_SIGNALED;
   module_data.wr.next                 = NULL;
   /* set some extra stuff for RDMA mode */
   if (module_data.tran_mode != IBV_WR_SEND && 
       module_data.tran_type != IBV_QPT_UD) {
      module_data.wr.wr.rdma.remote_addr  = module_data.rbuf; // TODO: fix this
      module_data.wr.wr.rdma.rkey         = module_data.rrkey; // TODO: fix this
   }
   ng_info(NG_VLEV2, "ibv_sendto: before UD settings");
   if (module_data.tran_type == IBV_QPT_UD) {
      module_data.send_list.addr       = (uintptr_t) module_data.buf + 40;
      module_data.wr.wr.ud.ah          = module_data.ah[dst];
      module_data.wr.wr.ud.remote_qpn  = module_data.rqp_num[dst];
      module_data.wr.wr.ud.remote_qkey = 0x11111111;
   }
   ng_info(NG_VLEV2, "ibv_sendto: posting send");
   if(ibv_post_send(module_data.qp[dst], &module_data.wr, &bad_wr)) {
      ng_error("Couldn't post send in %s", __func__);
      return -1;
   }
   ng_info(NG_VLEV2, "ibv_sendto: posted send, polling cq");
   
   do {
      ne = ibv_poll_cq(module_data.cq[dst], 1, &wc);
   } while (ne == 0);
   
   if (ne < 0) {
      ng_error("Couldn*t poll completion queue");
      return -1;
   }
   if (wc.status != IBV_WC_SUCCESS) {
      ng_error("Completion with error: status %d and wr_id %d",
               wc.status, (int)wc.wr_id);
      return -1;
   }

   return size;
}

static int
ibv_recvfrom(int src, void *buffer, int size) {
   ng_info(NG_VLEV2, "ibv_recvfrom: posting recv for %d bytes from peer %d", size, src);

   struct ibv_recv_wr *bad_rwr;
   struct ibv_wc wc;
   int ne;
   
   /* we only need to post a receive if we use the normal send mode 
    * because only in this case the receiving peer have to do
    * something ;) 
    */
   if (module_data.tran_mode == IBV_WR_SEND) {
      
      module_data.recv_list.addr          = (uintptr_t) module_data.buf;
      module_data.recv_list.length        = size;
      module_data.recv_list.lkey          = module_data.mr->lkey;
      module_data.rwr.wr_id               = NULL;
      module_data.rwr.sg_list             = &module_data.recv_list;
      module_data.rwr.num_sge             = 1; 
      module_data.rwr.next                = NULL;
      if (module_data.tran_type == IBV_QPT_UD) {
         module_data.recv_list.addr       = (uintptr_t) module_data.buf + 40;
      }
      if(ibv_post_recv(module_data.qp[src], &module_data.rwr, &bad_rwr)) {
         ng_error("Couldn't post recv in %s", __func__);
         return -1;
      }
      
      do {
         ne = ibv_poll_cq(module_data.cq[src], 1, &wc);
      } while (ne == 0);
      
      if (ne < 0) {
         ng_error("Couldn*t poll completion queue");
         return -1;
      }
      if (wc.status != IBV_WC_SUCCESS) {
         ng_error("Completion with error: status %d and wr_id %d",
                  wc.status, (int)wc.wr_id);
         return -1;
      }
   }

   return size;
}

/* send data of size 'size' to the partner :) */
static int
ibv_isendto(int dst, void *buffer, int size, NG_Request *req) {
   ng_info(NG_VLEV2, "ibv_isendto: queued isend %d bytes to %d", size, dst);
   
   struct ibv_send_wr *bad_wr;
   struct ibv_wc wc;
   int ne;
   /* at the moment we have to copy buffer content to the registered 
    * buffer of the hca --> a nice mess 
    * FIXME this is a hard operation for benchmarking 
    * memcpy(module_data.buf, buffer, size); 
    */

   ibv_completion_handle_t* completion_handle = ibv_get_completion_handle();
   completion_handle->completed = false;
   completion_handle->peer = dst;

   *req = (NG_Request)completion_handle;
   
   module_data.send_list.addr          = (uintptr_t) module_data.buf;
   module_data.send_list.length        = size;
   module_data.send_list.lkey          = module_data.mr->lkey;
   module_data.wr.wr_id                = (int64_t)completion_handle;
   module_data.wr.sg_list              = &module_data.send_list;
   module_data.wr.num_sge              = 1;
   module_data.wr.opcode               = module_data.tran_mode;
   module_data.wr.send_flags           = IBV_SEND_SIGNALED;
   module_data.wr.next                 = NULL;
   /* set some extra stuff for RDMA mode */
   if (module_data.tran_mode != IBV_WR_SEND && 
       module_data.tran_type != IBV_QPT_UD) {
      module_data.wr.wr.rdma.remote_addr  = module_data.rbuf; // TODO: fix
      module_data.wr.wr.rdma.rkey         = module_data.rrkey; // TODO: fix
   }
   
   if (module_data.tran_type == IBV_QPT_UD) {
      module_data.send_list.addr       = (uintptr_t) module_data.buf + 40;
      module_data.wr.wr.ud.ah          = module_data.ah[dst];
      module_data.wr.wr.ud.remote_qpn  = module_data.rqp_num[dst];
      module_data.wr.wr.ud.remote_qkey = 0x11111111;
   }
   if(ibv_post_send(module_data.qp[dst], &module_data.wr, &bad_wr)) {
      ng_error("Couldn't post send in %s", __func__);
      return -1;
   }

   return size;
}

static int
ibv_irecvfrom(int src, void *buffer, int size, NG_Request *req) {
   ng_info(NG_VLEV2, "ibv_irecvfrom: posted irecv %d bytes from %d", size, src);

   struct ibv_recv_wr *bad_rwr;
   struct ibv_wc wc;
   int ne;

   ibv_completion_handle_t* completion_handle = ibv_get_completion_handle();
   completion_handle->completed = false;
   completion_handle->peer = src;

   if (completion_handle == NULL) {
       ng_error("Couldn't get completion handle in %s", __func__);
   } else {
       ng_info(NG_VLEV2, "Got completion handle %p in %s", (void*)completion_handle, __func__);
   }

   ng_info(NG_VLEV2, "Setting compleated flag to false, completion_handle=%p", (void*)completion_handle);
   completion_handle->completed = false;

   if (req == NULL) {
       ng_error("NULL request pointer passed to %s", __func__);
       return -1;
   }

   ng_info(NG_VLEV2, "Setting request handle for caller");
   *req = (NG_Request)completion_handle;

   ng_info(NG_VLEV2, "Posting receive");
   /* we only need to post a receive if we use the normal send mode 
    * because only in this case the receiving peer have to do
    * something ;) 
    */
   if (module_data.tran_mode == IBV_WR_SEND) {
      
      module_data.recv_list.addr          = (uintptr_t) module_data.buf;
      module_data.recv_list.length        = size;
      module_data.recv_list.lkey          = module_data.mr->lkey;
      module_data.rwr.wr_id               = (int64_t)completion_handle;
      module_data.rwr.sg_list             = &module_data.recv_list;
      module_data.rwr.num_sge             = 1; 
      module_data.rwr.next                = NULL;
      if (module_data.tran_type == IBV_QPT_UD) {
         module_data.recv_list.addr       = (uintptr_t) module_data.buf + 40;
      }
      if(ibv_post_recv(module_data.qp[src], &module_data.rwr, &bad_rwr)) {
         ng_error("Couldn't post recv in %s", __func__);
         return -1;
      }

   }

   return size;
}

int ibv_test(NG_Request *req) {
   // ng_info(NG_VLEV2, "ibv_test: testing request %p", (void*)(req ? *req : NULL));

   if (req == NULL || *req == NULL) {
       ng_error("NULL request pointer passed to %s", __func__);
       return -1;
   }

   ibv_completion_handle_t* request_completion_handle = (ibv_completion_handle_t*)(*req);

   int peer = request_completion_handle->peer;

   while (true) {
      struct ibv_wc wc;
      int ne;

      ne = ibv_poll_cq(module_data.cq[peer], 1, &wc);

      // ng_info(NG_VLEV2, "ibv_test: poll returned ne=%d status=%d wr_id=0x%016llx", ne, wc.status, (unsigned long long)wc.wr_id);

      if (ne == 0) {
         // Nothing new in completion queue.
         break;
      }
      
      if (ne < 0) {
         ng_error("Couldn*t poll completion queue");
         return -1;
      }
      if (wc.status != IBV_WC_SUCCESS) {
         ng_error("Completion with error: status %d and wr_id %d",
                  wc.status, (int)wc.wr_id);
         return -1;
      }

      ibv_completion_handle_t* completion_handle = (ibv_completion_handle_t*)wc.wr_id;
      if (completion_handle != NULL) {
         completion_handle->completed = true;
      } else {
         ng_info(NG_VLEV2, "ibv_test: WARNING: NULL completion handle in wr_id");
      }
   }
   
   if (request_completion_handle->completed) {
      return 0; // completed
   } else {
      return 1; // not completed
   }
}

/* do some cleanup */
static void
ibv_shutdown(struct ng_options *global_opts) {
   
   /* we need this barrier because the receiving peer is gone
    * away before we have finished sending in RDMA mode :)
    */
   MPI_Barrier(module_data.mpi_comm);
   
   // ng_info(NG_VLEV1, "Beginning to release all IB data structures...");

   // if(ibv_destroy_qp(module_data.qp))
   //    ng_error("Couldn't destroy queue pair");
   
   // if(ibv_destroy_cq(module_data.cq))
   //    ng_error("Couldn't destroy completion queue");
   
   // if(ibv_dereg_mr(module_data.mr))
   //    ng_error("Couldn't release memory region");

   // if(ibv_dealloc_pd(module_data.pd))
   //    ng_error("Couldn't dealloc protection domain");

   // if(ibv_close_device(module_data.context))
   //    ng_error("Couldn't close device");
      
   // ng_info(NG_VLEV1, "... finished releasing the IB stuff!");
}

/* getopt long options for ibv */
static struct option long_options_ibv[]={
        {"transtype",	required_argument, 0, 'T'},
        {"transmode",	required_argument, 0, 'M'},
        {0, 0, 0, 0}
};

/* array of descriptions for ibv */
static struct option_info long_option_infos_ibv[]={
         {"transport type [u]n/[r]eliable connection, "
          "[U]nreliable datagram", "[u]|[r]|[U]"},
         {"transport mode normal [s]end, RDMA [w]rite or " 
          "[r]read", "[s]|[w]|[r]"},
         {0, 0}
};

/* module specific usage information */
void ibv_usage(void) {
   	int i;
	
	for(i=0; long_options_ibv[i].name != NULL; i++) {
	ng_longoption_usage(
		long_options_ibv[i].val,
		long_options_ibv[i].name,
		long_option_infos_ibv[i].desc,
		long_option_infos_ibv[i].param
	);
  }
}

/* module specific manpage information */
void ibv_writemanpage(void) {
   	int i;
	
	for(i=0; long_options_ibv[i].name != NULL; i++) {
	ng_manpage_module(
		long_options_ibv[i].val,
		long_options_ibv[i].name,
		long_option_infos_ibv[i].desc,
		long_option_infos_ibv[i].param
	);
  }
}

/* module registration */
int register_ibv(void) {
    ng_register_module(&ibv_module);
    return 0;
}

#else /* NOT NG_MPI */

/* module registration */
int register_ibv(void) {
   return 0;
}

#endif /* NG_MPI */
