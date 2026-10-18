#ifndef PAPI_SIMPLE_H
#define PAPI_SIMPLE_H

#include <stdio.h>
#include <stdlib.h>
#include <papi.h>

#define PAPI_SIMPLE_MAX_MEASUREMENTS 100000

static int papi_simple_event_set = PAPI_NULL;
static long long papi_simple_buffer[PAPI_SIMPLE_MAX_MEASUREMENTS];
static char papi_simple_tags[PAPI_SIMPLE_MAX_MEASUREMENTS];
static int papi_simple_count = 0;
static int papi_simple_initialized = 0;
static int papi_simple_is_running = 0;

/* Initializes the library, creates an EventSet and prepares the buffer */
static inline void papi_simple_init(void) {
    if (papi_simple_initialized) return;

    if (!PAPI_is_initialized()) {
        if (PAPI_library_init(PAPI_VER_CURRENT) != PAPI_VER_CURRENT) {
            fprintf(stderr, "Error: PAPI_library_init\n");
            exit(1);
        }
    }

    if (PAPI_create_eventset(&papi_simple_event_set) != PAPI_OK) {
        fprintf(stderr, "Error: PAPI_create_eventset\n");
        exit(1);
    }

    if (PAPI_add_event(papi_simple_event_set, PAPI_TOT_CYC) != PAPI_OK) {
        fprintf(stderr, "Error: PAPI_add_event (PAPI_TOT_CYC)\n");
        exit(1);
    }

    papi_simple_count = 0;
    papi_simple_initialized = 1;
    papi_simple_is_running = 0;
}

/* Stops counting and ignores the result */
static inline void papi_simple_stop_and_ignore(void) {
    long long cycles = 0;

    if (!papi_simple_initialized || !papi_simple_is_running) return;
    
    if (PAPI_stop(papi_simple_event_set, &cycles) != PAPI_OK) {
        fprintf(stderr, "Error: PAPI_stop\n");
        exit(1);
    }
    papi_simple_is_running = 0;
}

/* Starts counting cycles */
static inline void papi_simple_start(void) {
    if (!papi_simple_initialized) return;

    if (papi_simple_is_running) {
        papi_simple_stop_and_ignore();
    }

    if (PAPI_start(papi_simple_event_set) != PAPI_OK) {
        fprintf(stderr, "Error: PAPI_start\n");
        exit(1);
    }
    papi_simple_is_running = 1;
}

/* Stops counting and saves the result and tag to the internal buffer */
static inline void papi_simple_stop_and_save(char tag) {
    long long cycles = 0;

    if (!papi_simple_initialized || !papi_simple_is_running) return;
    
    if (PAPI_stop(papi_simple_event_set, &cycles) != PAPI_OK) {
        fprintf(stderr, "Error: PAPI_stop\n");
        exit(1);
    }
    
    if (papi_simple_count < PAPI_SIMPLE_MAX_MEASUREMENTS) {
        papi_simple_buffer[papi_simple_count] = cycles;
        papi_simple_tags[papi_simple_count] = tag;
        papi_simple_count++;
    } else {
        fprintf(stderr, "Warning: Measurement buffer full\n");
    }
    papi_simple_is_running = 0;
}

/* Prints the saved measurements in CSV format to the provided file and clears the buffer */
static inline void papi_simple_print_and_clear(const char *filename) {
    int i;
    FILE *file;
    
    if (!papi_simple_initialized) return;
    
    file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        return;
    }
    
    fprintf(file, "#,tag,cycles_no\n");
    for (i = 0; i < papi_simple_count; i++) {
        fprintf(file, "%d,%c,%lld\n", i, papi_simple_tags[i], papi_simple_buffer[i]);
    }
    
    fclose(file);
    papi_simple_count = 0;
}

#endif /* PAPI_SIMPLE_H */