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
#include <deque>
#include <time.h>
#include <algorithm>
#include "fullresult.h"
#include "statistics.h"
#include "ng_tools.hpp"

#include <ctype.h>

#include "Parser.hpp"

constexpr size_t BUFFER_SIZE = 16777216 * 2; // x2 for safety margin


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
#define OPTYPE_PATTERN_START 41
#define OPTYPE_PATTERN_END 42

// Handle for output file
FILE* output_file = nullptr;

// Benchmark start timestamp, used to calculate timestamps for loging operations.
HRT_TIMESTAMP_T benchmark_start;

// Global node shift value set by --shift flag (default 0)
int node_shift = 0;

uint64_t get_timestamp_ticks() {
  HRT_TIMESTAMP_T now;
  HRT_GET_TIMESTAMP(now);
  uint64_t ticks;
  HRT_GET_TIME(now, ticks);
  return ticks;
}

double get_timestamp_usec() {
  HRT_TIMESTAMP_T now;
  HRT_GET_TIMESTAMP(now);
  long long ticks;
  HRT_GET_ELAPSED_TICKS(benchmark_start, now, &ticks);
  double now_usec = HRT_GET_USEC(ticks);
  return now_usec;
}

/** 
 * Struct to keep information about an operation, including its type,
 * peer, offset, size, and timing information.
 */
struct OperationInfo {
  int type;            // Operation type (e.g., OPTYPE_SEND, OPTYPE_RECV, etc.)
  int peer;            // Peer rank involved in the operation
  size_t offset;       // Offset in the buffer
  size_t size;         // Size of the data
  double start_usec;   // Start time in microseconds
  double end_usec;     // End time in microseconds
  uint64_t start_ticks; // Start time in ticks
  uint64_t end_ticks;   // End time in ticks
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
    case OPTYPE_PATTERN_START:
      fprintf(out, "PATTERN_START");
      break;
    case OPTYPE_PATTERN_END:
      fprintf(out, "PATTERN_END");
      break;
    default:
      fprintf(out, "UNKNOWN");
      break;
  }
}

void print_operation_info(struct OperationInfo* info) {
  FILE *out = output_file ? output_file : stdout;
  print_operation_type(info->type);
  fprintf(out, ",%d,%zu,%zu,%.2f,%.2f,%llu,%llu\n", info->peer, info->offset, info->size, info->start_usec, info->end_usec, info->start_ticks, info->end_ticks);
}

void print_operation_info_header() {
  FILE *out = output_file ? output_file : stdout;
  fprintf(out, "type,peer,offset,size,start_usec,end_usec,start_ticks,end_ticks\n");
}

struct StartedOperation {
  struct OperationInfo info; // Recorded inf about the operation.
  NG_Request request; // Non-blocking request handle from communication module.
  double usec_time; // Time that the simulated calculation should take. In microseconds.
  DeserializedNode node; // The original node from the schedule.
  bool finished = false; // Whether the operation has finished.
};

bool check_if_operation_finished(struct StartedOperation* op, struct ng_module *module) {
  if (op->info.type == OPTYPE_CALC) {
    // Check if specified number of microseconds has passed since start.
    double now_usec = get_timestamp_usec();
    double elapsed = now_usec - op->info.start_usec;
    return elapsed >= op->usec_time;
  } else if (op->info.type == OPTYPE_SEND || op->info.type == OPTYPE_RECV) {
    // Use handle and module function to check if operation has finished.
    return module->test(&op->request) == 0;
  } else if (op->info.type == OPTYPE_PATTERN_START || op->info.type == OPTYPE_PATTERN_END) {
    ng_abort("PATTERN_START and PATTERN_END are not real operations, they are only used in logs and are not actually performed.");
  } else {
    ng_abort("Unknown operation type in check_if_operation_finished");
  }
}

int shift_rank(int rank) {
  // Example shift function that shifts ranks in a round-robin fashion based on the iteration number
  int size = g_options.mpi_opts->worldsize;
  int shifted = rank + node_shift;
  /* ensure result in [0,size-1] even if node_shift is negative */
  shifted %= size;
  if (shifted < 0) shifted += size;
  return shifted;
}

// Same as shift_rank but uses negative node_shift
int shift_peer_rank(int peer_rank) {
  // Shift the peer rank using the same logic as shift_rank
  int size = g_options.mpi_opts->worldsize;
  int shifted = peer_rank - node_shift;
  /* ensure result in [0,size-1] even if node_shift is negative */
  shifted %= size;
  if (shifted < 0) shifted += size;
  return shifted;
}

static void goal_do_benchmarks(struct ng_module *module) {
  /** for collecting statistics */
  struct ng_statistics statistics;

  /** currently tested packet size and maximum */
  long data_size;

  /** number of times to test the current datasize */
  long test_count = g_options.testcount;

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

        /* --shift <N>  or --shift=N : global node shift */
        if (strncmp(tok_start, "--shift", 7) == 0) {
          /* check for --shift=N form */
          if (tok_start[7] == '=') {
            int val = atoi(tok_start + 8);
            node_shift = val;
          } else {
            /* restore and advance to next token for value */
            *p = saved;
            while (*p && isspace((unsigned char)*p)) p++;
            if (*p) {
              char *val_start = p;
              while (*p && !isspace((unsigned char)*p)) p++;
              size_t len = p - val_start;
              char tmp[64];
              if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
              memcpy(tmp, val_start, len);
              tmp[len] = '\0';
              node_shift = atoi(tmp);
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

  MPI_Barrier(MPI_COMM_WORLD);
  HRT_GET_TIMESTAMP(benchmark_start);

  HRT_TIMESTAMP_T start, end;

  std::vector<struct OperationInfo> op_info;

  ng_info(NG_VLEV1, "Starting GOAL benchmark wit %d iterations", test_count);
  for (int i = 0; i < test_count; i++) {

    // Parse the schedule file (schedule_file may be NULL)
    Parser parser(schedule_file, false);
    ng_info(NG_VLEV2, "Parsed schedule file successfully\n");

    // Use the first schedule
    SerializedGraph schedule = parser.schedules[shift_rank(rank)];
    
    std::vector<DeserializedNode> executable_nodes;
    std::deque<struct StartedOperation> ongoing_operations;
    
    // Synch all ranks before starting the benchmark using MPI barrier.
    MPI_Barrier(MPI_COMM_WORLD);

    // if (rank == 1) {
    //   ng_info(NG_VLEV2, "Rank 1 sleeping for 5 usec before starting the pattern");
    //   struct timespec ts;
    //   ts.tv_sec = 0;
    //   ts.tv_nsec = 500;
    //   nanosleep(&ts, NULL);
    // }

    // Log pattern start
    struct OperationInfo pattern_start_info;
    pattern_start_info.type = OPTYPE_PATTERN_START;
    pattern_start_info.peer = -1; // N/A
    pattern_start_info.offset = 0; // N/A
    pattern_start_info.size = 0; // N/A
    double start_timestamp = get_timestamp_usec();
    pattern_start_info.start_usec = start_timestamp;
    pattern_start_info.end_usec = start_timestamp;
    uint64_t start_ticks = get_timestamp_ticks();
    pattern_start_info.start_ticks = start_ticks;
    pattern_start_info.end_ticks = start_ticks;
    op_info.push_back(pattern_start_info);
    
    executable_nodes = schedule.GetExecutableNodes_DSN();
    ng_info(NG_VLEV2, "Found %zu executable nodes", executable_nodes.size());
    if (executable_nodes.size() == 0) {
      ng_info(NG_VLEV1, "No executable nodes found.");
    }

    while (executable_nodes.size() > 0 || ongoing_operations.size() > 0) {
      // Available operations must be proceeds in a specific order based on their type.
      for (char current_type : {OPTYPE_RECV, OPTYPE_SEND, OPTYPE_CALC}) {
        for (DeserializedNode node_to_execute : executable_nodes) {

          if (node_to_execute.Type != current_type) {
            // Nodes of this type were already processed in past iterations
            // or will be processed in future iterations.
            continue;
          }

          schedule.MarkNodeAsStarted_DSN(node_to_execute);
        
          ng_info(NG_VLEV2, "[rank %d] Executing node offset=%d type=%d peer=%d size=%zu proc=%d\n",
                  rank, node_to_execute.offset, node_to_execute.Type,
                  shift_peer_rank(node_to_execute.Peer), node_to_execute.Size,
                  node_to_execute.Proc);
          
          struct StartedOperation started_op;
          
          switch (node_to_execute.Type) {
            case OPTYPE_SEND:
              module->isendto(shift_peer_rank(node_to_execute.Peer), buffer + node_to_execute.offset, node_to_execute.Size, 0, &started_op.request);
              started_op.info.type = OPTYPE_SEND;
              started_op.info.peer = shift_peer_rank(node_to_execute.Peer);
              started_op.info.offset = node_to_execute.offset;
              started_op.info.size = node_to_execute.Size;
              break;
            case OPTYPE_RECV:
              module->irecvfrom(shift_peer_rank(node_to_execute.Peer), buffer + node_to_execute.offset, node_to_execute.Size, 0, &started_op.request);
              started_op.info.type = OPTYPE_RECV;
              started_op.info.peer = shift_peer_rank(node_to_execute.Peer);
              started_op.info.offset = node_to_execute.offset;
              started_op.info.size = node_to_execute.Size;
              break;
            case OPTYPE_CALC:
              // Assume that calculation length is given in microseconds.
              started_op.usec_time = (double)node_to_execute.Size;
              started_op.info.type = OPTYPE_CALC;
              started_op.info.peer = -1; // N/A
              started_op.info.offset = 0; // N/A
              started_op.info.size = node_to_execute.Size; // Time in microseconds
              break;
            default:
              // Unknown operation type
              printf("Unknown operation type %d\n", node_to_execute.Type);
              // ng_abort("Unknown operation type");
              continue;
              break;
          }

          // Save operation start timestamp after starting the operation.
          started_op.info.start_usec = get_timestamp_usec();
          started_op.info.start_ticks = get_timestamp_ticks();

          started_op.node = node_to_execute;

          ongoing_operations.push_back(started_op);
        
        } // for (DeserializedNode node_to_execute : executable_nodes)

        // Barrier after each operation type to simplify debugging.
        // MPI_Barrier(MPI_COMM_WORLD);

      } // for (char current_type : {OPTYPE_RECV, OPTYPE_SEND, OPTYPE_CALC})

      for (struct StartedOperation& this_op : ongoing_operations) {
        if (this_op.finished) {
          // This is a record for an already finished operation, skip it.
          continue;
        }

        if (!check_if_operation_finished(&this_op, module)) {
          // This operation is not finished yet, skip it for now.
          // It will be checked again later.
          continue;
        }

        this_op.info.end_usec = get_timestamp_usec();
        this_op.info.end_ticks = get_timestamp_ticks();

        this_op.finished = true;

        op_info.push_back(this_op.info);

        // Mark operation as finished.
        schedule.MarkNodeAsDone_DSN(this_op.node);
      }

      // Clean up finished operations from the front of the queue.
      while (ongoing_operations.size() > 0 && ongoing_operations.front().finished) {
        ongoing_operations.pop_front();
      }

      executable_nodes = schedule.GetExecutableNodes_DSN();
      // ng_info(NG_VLEV2, "After executing, found %zu executable nodes", executable_nodes.size());
    }

    // Synch all ranks after finsing the pattern using MPI barrier.
    MPI_Barrier(MPI_COMM_WORLD);

    // Log pattern end
    struct OperationInfo pattern_end_info;
    pattern_end_info.type = OPTYPE_PATTERN_END;
    pattern_end_info.peer = -1; // N/A
    pattern_end_info.offset = 0; // N/A
    pattern_end_info.size = 0; // N/A
    double end_timestamp = get_timestamp_usec();
    pattern_end_info.start_usec = end_timestamp;
    pattern_end_info.end_usec = end_timestamp;
    uint64_t end_ticks = get_timestamp_ticks();
    pattern_end_info.start_ticks = end_ticks;
    pattern_end_info.end_ticks = end_ticks;
    op_info.push_back(pattern_end_info);

  } // Pattern repetition loop

  // Print collected operation info
  print_operation_info_header();
  for (struct OperationInfo &info : op_info) {
    print_operation_info(&info);
  }

  /* cleanup */
  if (schedule_file) free(schedule_file);
  if (buffer) free(buffer);
}

} /* extern C */

#else
extern "C" {
int register_pattern_goal(void) {return 0;};
}
#endif
