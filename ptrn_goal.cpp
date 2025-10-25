/*
 * Copyright (c) 2009 The Trustees of Indiana University and Indiana
 *                    University Research and Technology
 *                    Corporation.  All rights reserved.
 *
 * Author(s): Torsten Hoefler <htor@cs.indiana.edu>
 *
 */

#include "netgauge.h"
#ifdef NG_PTRN_ONE_ONE
#include "hrtimer/hrtimer.h"
#include <vector>
#include <time.h>
#include <algorithm>
#include "fullresult.h"
#include "statistics.h"
#include "ng_tools.hpp"

#include <ctype.h>

#include "Parser.hpp"

constexpr size_t BUFFER_SIZE = 2048;


extern "C" {

extern struct ng_options g_options;

/* internal function prototypes */
static void goal_do_benchmarks(struct ng_module *module);

/**
 * comm. pattern description and function pointer table
 */
static struct ng_comm_pattern pattern_goal = {
   pattern_goal.name = "goal",
   pattern_goal.desc = "Perform communication patterns as specified in a GOAL schedule file",
   pattern_goal.flags = 0,
   pattern_goal.do_benchmarks = goal_do_benchmarks
};

/**
 * register this comm. pattern for usage in main
 * program
 */
int register_pattern_goal() {
   ng_register_pattern(&pattern_goal);
   return 0;
}

// Operation types for GOAL schedule
#define OPTYPE_SEND 1
#define OPTYPE_RECV 2

FILE* output_file = nullptr;

/** 
 * Struct to keep information about an operation, including its type,
 * peer, offset, size, and timing information.
 */
struct OperationInfo {
  int type;           // Operation type (e.g., OPTYPE_SEND, OPTYPE_RECV, etc.)
  int peer;           // Peer rank involved in the operation
  size_t offset;      // Offset in the buffer
  size_t size;        // Size of the data
  double start_usec;  // Start time in microseconds
  double end_usec;    // End time in microseconds
};

void print_operation_type(int type) {
  FILE *out = output_file ? output_file : stdout;
  switch(type) {
    case OPTYPE_SEND:
      fprintf(out, "SEND");
      break;
    case OPTYPE_RECV:
      fprintf(out, "RECV");
      break;
    case OPTYPE_CALC:
      fprintf(out, "LOCAL_CALC");
      break;
    default:
      fprintf(out, "UNKNOWN");
      break;
  }
}

void print_operation_info(struct OperationInfo* info) {
  FILE *out = output_file ? output_file : stdout;
  print_operation_type(info->type);
  fprintf(out, ",%d,%zu,%zu,%.2f,%.2f\n", info->peer, info->offset, info->size, info->start_usec, info->end_usec);
}

void print_operation_info_header() {
  FILE *out = output_file ? output_file : stdout;
  fprintf(out, "type,peer,offset,size,start_usec,end_usec\n");
}

static void goal_do_benchmarks(struct ng_module *module) {
  /** for collecting statistics */
  struct ng_statistics statistics;

  /** currently tested packet size and maximum */
  long data_size;

  /** number of times to test the current datasize */
  long test_count = g_options.testcount;

  /** counts up to test_count */
  int test_round = 0;

  /** how long does the test run? */
  time_t test_time, cur_test_time;

  /** number of tests run */
  int ovr_tests=0, ovr_bytes=0;

  long max_data_size = ng_min(g_options.max_datasize + module->headerlen, module->max_datasize);

  int rank = g_options.mpi_opts->worldrank;

  // GOAL CODE

  char *schedule_file = nullptr; // will be set from --trace in g_options.ptrnopts if provided

  /* Minimal parsing of pattern-specific options string stored in g_options.ptrnopts
   * Accept the forms "--trace FILENAME" (space-separated) and "-o FILENAME". */
  if (g_options.ptrnopts) {
    char *opts_copy = strdup(g_options.ptrnopts);
    if (opts_copy) {
      char *p = opts_copy;
      while (*p) {
        /* skip spaces */
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        /* find token start/end */
        char *tok_start = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        char saved = *p;
        *p = '\0';

        if (strcmp(tok_start, "--trace") == 0) {
          /* restore and advance to next token for filename */
          *p = saved;
          while (*p && isspace((unsigned char)*p)) p++;
          if (*p) {
            char *fname_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t len = p - fname_start;
            schedule_file = (char*)malloc(len + 1);
            if (schedule_file) {
              memcpy(schedule_file, fname_start, len);
              schedule_file[len] = '\0';
            }
          }
          continue;
        }

        if (strcmp(tok_start, "-o") == 0) {
          /* restore and advance to next token for output filename */
          *p = saved;
          while (*p && isspace((unsigned char)*p)) p++;
          if (*p) {
            char *fname_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t len = p - fname_start;
            char *outname = (char*)malloc(len + 1);
            if (outname) {
              memcpy(outname, fname_start, len);
              outname[len] = '\0';
              {
                char suffix[32];
                snprintf(suffix, sizeof(suffix), "/%d.out", rank);
                size_t suf_len = strlen(suffix);
                char *new_out = (char*)malloc(len + suf_len + 1);
                if (new_out) {
                  memcpy(new_out, outname, len);
                  memcpy(new_out + len, suffix, suf_len);
                  new_out[len + suf_len] = '\0';
                  free(outname);
                  outname = new_out;
                }
              }
              FILE *f = fopen(outname, "w+");
              if (f) {
                output_file = f;
              } else {
                fprintf(stderr, "Warning: could not open output file '%s' for writing\n", outname);
              }
              free(outname);
            }
          }
          continue;
        }

        /* restore and continue scanning */
        *p = saved;
      }
      free(opts_copy);
    }
  }

  if (!schedule_file) {
    // ng_abort("GOAL pattern requires a schedule file specified with --trace=FILENAME");
    printf("GOAL pattern requires a schedule file specified with --trace=FILENAME\n");
    return;
  }
  ng_info(NG_VLEV1, "Using schedule file: %s", schedule_file);

  // Parse the schedule file (schedule_file may be NULL)
  Parser parser(schedule_file, false);
  fprintf(stderr, "Parsed schedule file successfully\n");

  // Use the first schedule
  SerializedGraph schedule = parser.schedules[rank];

  // Print graph representation to file for debugging purposes
  // schedule.write_as_dot("/home/tkubica/graph.txt");

  // Alloc the buffer. In GOAL address is specified as a single integer,
  // a possition in a buffer.
  ng_info(NG_VLEV1, "Allocating %d bytes data buffer", BUFFER_SIZE);
  char *buffer;
  NG_MALLOC(module, char*, BUFFER_SIZE, buffer);

  ng_info(NG_VLEV2, "Initializing data buffer (make sure it's really allocated)");
  for (int i = 0; i < BUFFER_SIZE; i++) buffer[i] = 0xff;

  // int p = g_options.mpi_opts->worldsize; 
  // if(p % 2 != 0) {
  //   ng_abort("this pattern needs an even number of ranks\n");
  // }
  // if(rank % 2 == 0) g_options.mpi_opts->partner = rank+1;
  // else g_options.mpi_opts->partner = rank-1;

  // TODO: replace with some other input suitable for the new pattern

  HRT_TIMESTAMP_T becnchmark_start;
  HRT_GET_TIMESTAMP(becnchmark_start);

  HRT_TIMESTAMP_T start, end;

  struct OperationInfo *op_info = (struct OperationInfo*) malloc(sizeof(struct OperationInfo) * schedule.GetNumNodes());
  int op_info_count = 0;

  std::vector<DeserializedNode> executable_nodes;
  
  executable_nodes = schedule.GetExecutableNodes_DSN();
  ng_info(NG_VLEV2, "Found %zu executable nodes", executable_nodes.size());
  if (executable_nodes.size() == 0) {
    ng_info(NG_VLEV1, "No executable nodes found.");
  }

  while (executable_nodes.size() > 0) {
    DeserializedNode node_to_execute = executable_nodes.back();
    executable_nodes.pop_back();
    schedule.MarkNodeAsStarted_DSN(node_to_execute);

    ng_info(NG_VLEV2, "[rank %d] Executing node offset=%d type=%d peer=%d size=%zu proc=%d\n",
            rank, node_to_execute.offset, node_to_execute.Type,
            node_to_execute.Peer, node_to_execute.Size,
            node_to_execute.Proc);

    // [Turns out proc is something else than node]
    // If this is not operation for this node, skip it and mark as done.
    // if (node_to_execute.Proc != rank) {
    //   schedule.MarkNodeAsDone_DSN(node_to_execute);
    //   ng_info(NG_VLEV2, "Node %d is for proc %d, skipping on proc %d.",
    //           node_to_execute.offset, node_to_execute.Proc, rank);
    //   continue;
    // }

    struct OperationInfo this_op_info;

    bool log_operation = false;

    HRT_GET_TIMESTAMP(start);

    switch (node_to_execute.Type) {
      case OPTYPE_SEND:
        module->sendto(node_to_execute.Peer, buffer + node_to_execute.offset, node_to_execute.Size);
        log_operation = true;
        this_op_info.type = OPTYPE_SEND;
        break;
      case OPTYPE_RECV:
        module->recvfrom(node_to_execute.Peer, buffer + node_to_execute.offset, node_to_execute.Size);
        log_operation = true;
        this_op_info.type = OPTYPE_RECV;
        break;
      case OPTYPE_CALC:
        // Asume that calculation length is given in microseconds.
        usleep(node_to_execute.Size);
        log_operation = true;
        this_op_info.type = OPTYPE_CALC;
        break;
      default:
        // Unknown operation type
        printf("Unknown operation type %d\n", node_to_execute.Type);
        // ng_abort("Unknown operation type");
        break;
    }

    HRT_GET_TIMESTAMP(end);

    if (log_operation) {
      long long start_ticks;
      HRT_GET_ELAPSED_TICKS(becnchmark_start, start, &start_ticks);
      double start_usec = HRT_GET_USEC(start_ticks);
      this_op_info.start_usec = start_usec;

      long long end_ticks;
      HRT_GET_ELAPSED_TICKS(becnchmark_start, end, &end_ticks);
      double end_usec = HRT_GET_USEC(end_ticks);
      this_op_info.end_usec = end_usec;

      op_info[op_info_count++] = this_op_info;
    }
    
    // Mark operation as finished.
    schedule.MarkNodeAsDone_DSN(node_to_execute);

    if (executable_nodes.size() == 0) {
      executable_nodes = schedule.GetExecutableNodes_DSN();
      ng_info(NG_VLEV2, "After executing, found %zu executable nodes", executable_nodes.size());
    }
  }

  // Print collected operation info
  print_operation_info_header();
  for (int i = 0; i < op_info_count; i++) {
    print_operation_info(&op_info[i]);
  }
  /* cleanup */
  if (op_info) free(op_info);
  if (schedule_file) free(schedule_file);
  if (buffer) free(buffer);
}

} /* extern C */

#else
extern "C" {
int register_pattern_goal(void) {return 0;};
}
#endif
