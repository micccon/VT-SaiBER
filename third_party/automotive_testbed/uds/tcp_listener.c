/*
 * TCP Listener - TCP server on port 9556 for UDS protocol
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "tcp_listener.h"
#include "uds_engine.h"

static int server_fd = -1;
static volatile int tcp_running = 1;

/* External declaration for logging */
extern void log_message(const char *format, ...);

int tcp_listener_init(void) {
    struct sockaddr_in addr;
    int opt = 1;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log_message("TCP: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message("TCP: setsockopt() failed: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(TCP_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_message("TCP: bind() failed: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, TCP_BACKLOG) < 0) {
        log_message("TCP: listen() failed: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }

    log_message("TCP: Listening on port %d\n", TCP_PORT);
    return 0;
}

int tcp_listener_run(uds_state_t *state, pthread_mutex_t *state_mutex) {
    struct sockaddr_in client_addr;
    socklen_t client_len;
    int client_fd;
    uint8_t buffer[TCP_BUFFER_SIZE];
    uint8_t response[TCP_BUFFER_SIZE];
    ssize_t bytes_read;
    size_t resp_len;

    while (tcp_running) {
        client_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd < 0) {
            if (tcp_running) {
                log_message("TCP: accept() failed: %s\n", strerror(errno));
            }
            continue;
        }

        log_message("TCP: Connection from %s:%d\n",
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        /* Handle client requests */
        while (tcp_running) {
            bytes_read = recv(client_fd, buffer, TCP_BUFFER_SIZE, 0);
            if (bytes_read <= 0) {
                break;
            }

            /* Process UDS request (thread-safe) */
            resp_len = 0;
            pthread_mutex_lock(state_mutex);
            uds_engine_process(state, buffer, (size_t)bytes_read, response, &resp_len);
            uds_engine_check_timeout(state);
            pthread_mutex_unlock(state_mutex);

            /* Send response */
            if (resp_len > 0) {
                send(client_fd, response, resp_len, 0);
            }
        }

        log_message("TCP: Client disconnected\n");
        close(client_fd);
    }

    return 0;
}


void tcp_listener_stop(void) {
    tcp_running = 0;
    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }
}
