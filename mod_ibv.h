/*
 * Copyright (c) 2009 The Trustees of Indiana University and Indiana
 *                    University Research and Technology
 *                    Corporation.  All rights reserved.
 *
 * Author(s): Torsten Hoefler <htor@cs.indiana.edu>
 *
 */

#ifndef MOD_IB_H_
#define MOD_IB_H_

#include <unistd.h>
#include "netgauge.h"
#include <stdlib.h>
#include <malloc.h>
/* some imports */
extern struct ng_options g_options;

/* module function prototypes */
static int  ibv_getopt(int argc, char **argv, struct ng_options *global_opts);
static int  ibv_init(struct ng_options *global_opts);
static void ibv_shutdown(struct ng_options *global_opts);
static int  ibv_setup_channels(void);
static int  ibv_sendto(int dst, void *buffer, int size);
static int  ibv_recvfrom(int src, void *buffer, int size);
static int  ibv_select(int count, int *clients, unsigned long timeout);
static void ibv_usage(void);
static void ibv_writemanpage(void);
static int  ibv_isendto(int dst, void *buffer, int size, NG_Request *req);
static int  ibv_irecvfrom(int src, void *buffer, int size, NG_Request *req);
static int  ibv_test(NG_Request *req);

static struct ibv_private_data {
   struct ibv_device    **dev_list;    /* pointer to list of hcas */
   struct ibv_device    *ib_dev;       /* pointer to an element of this list */
   struct ibv_context   *context;      /* handle for hca */
   struct ibv_pd        *pd;           /* protection domain */
   struct ibv_mr        *mr;           /* memory region */
   struct ibv_cq        **cq;          /* completion queue for every peer */
   struct ibv_qp        **qp;          /* queue pair for every peer */
   struct ibv_sge       send_list;     /* scatter gather list for sending */
   struct ibv_sge       recv_list;     /* scatter gather list for receiving */
   struct ibv_send_wr   wr;            /* send work request */
   struct ibv_recv_wr   rwr;           /* receive work request */
   enum ibv_qp_type     tran_type;     /* transport type e.g. reliable connection*/
   enum ibv_wr_opcode   tran_mode;     /* transport mode e.g. RDMA write */
   struct ibv_ah        **ah;           /* address handle for IBV_QPT_UD for every peer */
   size_t               page_size;     /* for memalign -> sys/mman.h (glibc) */
   uint16_t             llid;          /* local LID */
   uint16_t             *rlid;         /* list of LIDs of all nodes */
   uint32_t             *lpsn;          /* local packet sequence number for every qp */
   uint32_t             *rpsn;         /* remote packet sequence number for every qp */
   uint32_t             *rrkey;        /* remote rkey for every peer */
   uint32_t             *rqp_num;      /* the queue pair num for every peer */
   void                 *buf;          /* pointer to buffer */
   unsigned long long   *rbuf;         /* address of the remote memory for every peer */
   MPI_Comm             mpi_comm;      /* MPI communicator */
   int                  mpi_size;      /* number of MPI nodes */
   int                  mpi_partner;   /* MPI rank of the partner */
   int                  mpi_rank;      /* MPI rank of this node */
   unsigned long        max_datasize;  /* maximum size of data we'll transfer */
   int                  tx_depth;      /* number of elements in the completion queue */
} module_data;

#define MAX_INLINE 400                 /* FIXME: Where or what is the right value for this? */
                                       /* we use it for setting the initial attributes of the qp */
#endif
/* vim: set expandtab tabstop=3 shiftwidth=3 autoindent smartindent: */
