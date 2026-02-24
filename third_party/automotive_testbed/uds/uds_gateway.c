/*
 * UDS Gateway - Main Entry Point
 *
 * Unified Diagnostic Services (UDS) Gateway for automotive pentesting.
 * Listens on both TCP (port 9556) and CAN (vcan0) interfaces.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#include "uds_engine.h"
#include "tcp_listener.h"
#include "can_listener.h"

#define LOG_FILE "/var/log/automotive-pentest/uds.log"

static volatile int running = 1;
static FILE *log_fp = NULL;
static pthread_t can_thread;
static int can_thread_started = 0;
static uds_state_t uds_state;
static pthread_mutex_t uds_state_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(const char *format, ...) {
    if (log_fp) {
        va_list args;
        va_start(args, format);
        vfprintf(log_fp, format, args);
        va_end(args);
        fflush(log_fp);
    }
}

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
    tcp_listener_stop();
    can_listener_stop();
}

static int init_logging(void) {
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        /* Try stderr if log file can't be opened */
        log_fp = stderr;
        fprintf(stderr, "Warning: Could not open %s, using stderr\n", LOG_FILE);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int ret;
    static can_listener_args_t can_args;

    (void)argc;
    (void)argv;

    printf("UDS Gateway starting...\n");

    /* Initialize logging */
    init_logging();
    log_message("UDS Gateway initialized\n");

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize UDS engine state */
    uds_engine_init(&uds_state);

    /* Initialize TCP listener */
    ret = tcp_listener_init();
    if (ret < 0) {
        log_message("Failed to initialize TCP listener\n");
        return 1;
    }

    /* Initialize and start CAN listener in separate thread */
    ret = can_listener_init();
    if (ret < 0) {
        log_message("Warning: CAN listener init failed (vcan0 may not be available)\n");
    } else {
        can_args.state = &uds_state;
        can_args.state_mutex = &uds_state_mutex;
        ret = pthread_create(&can_thread, NULL, can_listener_thread, &can_args);
        if (ret != 0) {
            log_message("Failed to create CAN listener thread\n");
        } else {
            can_thread_started = 1;
        }
    }

    log_message("UDS Gateway ready - TCP:%d, CAN:vcan0\n", TCP_PORT);
    printf("UDS Gateway ready - TCP:%d, CAN:vcan0\n", TCP_PORT);

    /* Run TCP listener in main thread */
    tcp_listener_run(&uds_state, &uds_state_mutex);

    /* Cleanup */
    log_message("UDS Gateway shutting down\n");
    if (can_thread_started) {
        pthread_join(can_thread, NULL);
    }

    if (log_fp && log_fp != stderr) {
        fclose(log_fp);
    }

    return 0;
}
