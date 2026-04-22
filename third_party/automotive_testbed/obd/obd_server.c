/*
 * OBD-II Simulator Server
 * TCP server on port 9555 simulating an OBD-II interface
 *
 * Supports:
 * - Mode 01: Current Data (PIDs for RPM, speed, etc.)
 * - Mode 09: Vehicle Information (VIN request)
 *
 * Part of the Automotive Pentesting Testbed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#define PORT 9555
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024

// Log file for exploit detection
#define LOG_FILE "/var/log/automotive-pentest/obd.log"

// Global flag for graceful shutdown
volatile sig_atomic_t running = 1;

// Log function
void log_message(const char *message) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        time_t now = time(NULL);
        char *timestamp = ctime(&now);
        timestamp[strlen(timestamp) - 1] = '\0';  // Remove newline
        fprintf(log, "[%s] %s\n", timestamp, message);
        fflush(log);
        fclose(log);
    }
    printf("%s\n", message);
    fflush(stdout);
}

// Signal handler for graceful shutdown
void handle_signal(int sig) {
    (void)sig;  // Unused parameter
    running = 0;
}

// Mode 01: Current Data - returns simulated sensor values
void handle_mode_01(int client_fd, unsigned char pid) {
    unsigned char response[8];
    int response_len = 0;

    switch (pid) {
        case 0x00:  // PIDs supported [01-20]
            response[0] = 0x41;  // Response: Mode + 0x40
            response[1] = 0x00;  // PID
            response[2] = 0xBE;  // Supported PIDs bitmap
            response[3] = 0x3E;
            response[4] = 0xB8;
            response[5] = 0x13;
            response_len = 6;
            break;

        case 0x0C:  // Engine RPM
            response[0] = 0x41;
            response[1] = 0x0C;
            // RPM = ((A*256)+B)/4 - simulate ~2500 RPM
            response[2] = 0x27;  // A = 39
            response[3] = 0x10;  // B = 16 -> (39*256+16)/4 = 2500
            response_len = 4;
            break;

        case 0x0D:  // Vehicle Speed
            response[0] = 0x41;
            response[1] = 0x0D;
            response[2] = 0x3C;  // 60 km/h
            response_len = 3;
            break;

        case 0x05:  // Engine Coolant Temperature
            response[0] = 0x41;
            response[1] = 0x05;
            response[2] = 0x6E;  // 70C (value - 40)
            response_len = 3;
            break;

        case 0x0F:  // Intake Air Temperature
            response[0] = 0x41;
            response[1] = 0x0F;
            response[2] = 0x41;  // 25C (value - 40)
            response_len = 3;
            break;

        default:
            // Unknown PID - return no data
            response[0] = 0x7F;  // Negative response
            response[1] = 0x01;  // Mode
            response[2] = 0x12;  // SubFunction not supported
            response_len = 3;
            break;
    }

    send(client_fd, response, response_len, 0);
}

// VULNERABILITY: VIN Write Handler (V8 Buffer Overflow)
// This is an INTENTIONALLY VULNERABLE function for educational purposes
// It demonstrates a classic stack buffer overflow vulnerability
//
// WARNING: This code is intentionally insecure!
// - Uses fixed 17-byte buffer for VIN (standard VIN length)
// - Uses strcpy() with no bounds checking
// - Compiled with -fno-stack-protector and -z execstack
// - Input larger than 17 bytes will overflow the buffer and overwrite the return address
void handle_vin_write(int client_fd, unsigned char *request, int request_len) {
    // VULNERABLE: Fixed-size buffer for VIN (17 characters)
    // Standard VIN is exactly 17 characters, but we don't validate input length
    char vin_buffer[17];

    // Data starts at offset 2 (after mode and pid bytes)
    // Null-terminate the input for strcpy
    char *vin_data = (char *)&request[2];

    // Calculate actual VIN data length
    int vin_len = request_len - 2;

    // Log the attempt
    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "OBD: VIN write request received, data length: %d bytes", vin_len);
    log_message(log_buf);

    // Check for buffer overflow attempt and log it
    if (vin_len > 17) {
        log_message("BUFFER_OVERFLOW_DETECTED: Oversized VIN data received");
        snprintf(log_buf, sizeof(log_buf), "OBD: Potential buffer overflow - received %d bytes for 17-byte buffer", vin_len);
        log_message(log_buf);
    }

    // VULNERABLE: strcpy with no bounds checking
    // This allows buffer overflow if vin_data > 17 bytes
    // The attacker can overwrite the return address on the stack
    strcpy(vin_buffer, vin_data);

    // Send acknowledgment
    unsigned char response[4];
    response[0] = 0x49;  // Response: Mode + 0x40
    response[1] = 0x0A;  // PID
    response[2] = 0x00;  // Success status
    response[3] = '\0';
    send(client_fd, response, 3, 0);

    snprintf(log_buf, sizeof(log_buf), "OBD: VIN updated to: %.17s", vin_buffer);
    log_message(log_buf);
}

// Mode 09: Vehicle Information Request
// NOTE: This function contains an intentional vulnerability for educational purposes
void handle_mode_09(int client_fd, unsigned char *request, int request_len) {
    unsigned char pid = request[1];

    if (pid == 0x02) {
        // VIN Request - return vehicle identification number
        unsigned char vin_response[20];
        vin_response[0] = 0x49;  // Response: Mode + 0x40
        vin_response[1] = 0x02;  // PID
        vin_response[2] = 0x01;  // Number of data items
        // Default VIN: "1HGBH41JXMN109186"
        memcpy(&vin_response[3], "1HGBH41JXMN109186", 17);
        send(client_fd, vin_response, 20, 0);
        log_message("OBD: VIN request processed");
    }
    else if (pid == 0x0A) {
        // VULNERABILITY: VIN Write/Update Request (V8 Buffer Overflow)
        // This is an intentionally vulnerable function for educational purposes
        // WARNING: Fixed 17-byte buffer with no bounds checking
        handle_vin_write(client_fd, request, request_len);
    }
    else if (pid == 0x00) {
        // PIDs supported [01-20] for Mode 09
        unsigned char response[6];
        response[0] = 0x49;
        response[1] = 0x00;
        response[2] = 0x55;  // Supports 02, 04, 06, 0A
        response[3] = 0x40;
        response[4] = 0x00;
        response[5] = 0x00;
        send(client_fd, response, 6, 0);
    }
    else {
        // Unknown PID
        unsigned char response[3] = {0x7F, 0x09, 0x12};
        send(client_fd, response, 3, 0);
    }
}

// Handle client connection
void handle_client(int client_fd) {
    unsigned char buffer[BUFFER_SIZE];
    int bytes_read;
    char log_buf[256];

    // Set receive timeout to prevent a single client from blocking the server
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    snprintf(log_buf, sizeof(log_buf), "OBD: Client connected");
    log_message(log_buf);

    while (running && (bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';

        snprintf(log_buf, sizeof(log_buf), "OBD: Received %d bytes", bytes_read);
        log_message(log_buf);

        // Parse OBD-II request
        // Format: Mode (1 byte) + PID (1 byte) + optional data
        if (bytes_read < 2) {
            // Invalid request
            unsigned char error_response[3] = {0x7F, 0x00, 0x13};  // Incorrect message length
            send(client_fd, error_response, 3, 0);
            continue;
        }

        unsigned char mode = buffer[0];

        switch (mode) {
            case 0x01:  // Mode 01: Current Data
                handle_mode_01(client_fd, buffer[1]);
                break;

            case 0x09:  // Mode 09: Vehicle Information
                handle_mode_09(client_fd, buffer, bytes_read);
                break;

            default:
                // Unsupported mode
                snprintf(log_buf, sizeof(log_buf), "OBD: Unsupported mode 0x%02X", mode);
                log_message(log_buf);
                unsigned char error_response[3] = {0x7F, mode, 0x11};  // Service not supported
                send(client_fd, error_response, 3, 0);
                break;
        }
    }

    log_message("OBD: Client disconnected");
    close(client_fd);
}

int main(int argc, char *argv[]) {
    (void)argc;  // Unused parameter
    (void)argv;  // Unused parameter
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    log_message("OBD Server starting...");

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options for address reuse
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    char log_buf[128];
    snprintf(log_buf, sizeof(log_buf), "OBD Server listening on port %d", PORT);
    log_message(log_buf);

    // Main server loop
    while (running) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (running) {
                perror("Accept failed");
            }
            continue;
        }

        // Handle client (single-threaded for simplicity)
        handle_client(client_fd);
    }

    log_message("OBD Server shutting down...");
    close(server_fd);
    return 0;
}
