/*
 * UDS Services - Individual service implementations
 *
 * This file will contain the implementations for:
 * - 0x10 DiagnosticSessionControl
 * - 0x11 ECUReset
 * - 0x19 ReadDTCInformation
 * - 0x22 ReadDataByIdentifier
 * - 0x27 SecurityAccess
 * - 0x2E WriteDataByIdentifier
 * - 0x34 RequestDownload
 * - 0x36 TransferData
 * - 0x37 RequestTransferExit
 * - 0x3E TesterPresent
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uds_engine.h"

/* External declaration for logging */
extern void log_message(const char *format, ...);

/*
 * Data storage for DIDs (Data Identifiers)
 * In a real ECU, these would be in EEPROM/Flash
 */
static char did_vin[UDS_VIN_SIZE + 1] = "1HGCM82633A004352";  /* Sample VIN (17 chars) */
static char did_system_name[UDS_SYSTEM_NAME_SIZE + 1] = "UDS Gateway v1.0";
static uint8_t did_calibration_data[UDS_CALIBRATION_DATA_SIZE] = {0};
static uint8_t did_config_block[UDS_CONFIG_BLOCK_SIZE] = {0};

/* Helper function to send negative response */
static void send_negative_response(uint8_t sid, uint8_t nrc,
                                   uint8_t *response, size_t *resp_len) {
    response[0] = UDS_NEGATIVE_RESPONSE;
    response[1] = sid;
    response[2] = nrc;
    *resp_len = 3;
}

/*
 * Service 0x10 - DiagnosticSessionControl
 *
 * Request format: [0x10] [session_type]
 * Positive response: [0x50] [session_type] [P2_hi] [P2_lo] [P2*_hi] [P2*_lo]
 * P2 = 50ms (server response time)
 * P2* = 5000ms (extended response time)
 */
int uds_service_diagnostic_session_control(uds_state_t *state,
                                            const uint8_t *request, size_t req_len,
                                            uint8_t *response, size_t *resp_len) {
    uint8_t requested_session;
    uint8_t current_session;

    /* Check minimum length: SID + sub-function */
    if (req_len < 2) {
        send_negative_response(UDS_SID_DIAGNOSTIC_SESSION_CONTROL,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    requested_session = request[1] & 0x7F;  /* Mask suppress positive response bit */
    current_session = state->session_type;

    log_message("DiagnosticSessionControl: current=0x%02X, requested=0x%02X\n",
                current_session, requested_session);

    /* Validate requested session type */
    switch (requested_session) {
        case UDS_SESSION_DEFAULT:
        case UDS_SESSION_PROGRAMMING:
        case UDS_SESSION_EXTENDED:
            /* Valid session types */
            break;
        default:
            /* Invalid session type */
            send_negative_response(UDS_SID_DIAGNOSTIC_SESSION_CONTROL,
                                   UDS_NRC_SUBFUNCTION_NOT_SUPPORTED, response, resp_len);
            return -1;
    }

    /*
     * Session transition rules:
     * - Default -> Default: OK
     * - Default -> Extended: OK
     * - Default -> Programming: OK (normally requires security, but allowed here for testing)
     * - Extended -> Default: OK
     * - Extended -> Extended: OK
     * - Extended -> Programming: OK
     * - Programming -> Default: OK
     * - Programming -> Programming: OK
     * - Programming -> Extended: OK
     *
     * For V9 vulnerability: Track if Extended is entered without proper initialization
     * The vulnerability trigger: requesting Extended session as the FIRST command
     * after initialization (without first establishing a proper Default session).
     * This represents an unusual protocol usage that requires stateful fuzzing to discover.
     */

    /* Check for V9 vulnerability trigger condition:
     * If requesting Extended session when no session has been explicitly established yet,
     * this is an "invalid" transition pattern that enables the hidden bypass.
     */
    if (requested_session == UDS_SESSION_EXTENDED && !state->session_established) {
        /* Unusual: Extended requested without establishing Default first */
        state->invalid_session_transition = 1;
        log_message("DiagnosticSessionControl: Invalid session transition detected (bypass enabled)\n");
    } else if (requested_session == UDS_SESSION_DEFAULT) {
        /* Establishing Default session properly clears the vulnerability condition */
        state->invalid_session_transition = 0;
    }

    /* Mark that a session has been explicitly established */
    state->session_established = 1;

    /* Update session state */
    state->session_type = requested_session;
    state->last_activity = time(NULL);

    /* Reset security when changing sessions */
    if (requested_session != current_session) {
        state->security_state = UDS_SECURITY_LOCKED;
        state->security_attempts = 0;
        log_message("DiagnosticSessionControl: Security reset due to session change\n");
    }

    /* Build positive response */
    response[0] = UDS_SID_DIAGNOSTIC_SESSION_CONTROL + 0x40;  /* Positive response SID */
    response[1] = requested_session;
    /* P2 timing (50ms = 0x0032) - server response time */
    response[2] = 0x00;
    response[3] = 0x32;
    /* P2* timing (5000ms = 0x1388) - extended response time */
    response[4] = 0x13;
    response[5] = 0x88;
    *resp_len = 6;

    log_message("DiagnosticSessionControl: Switched to session 0x%02X\n", requested_session);

    return 0;
}

/*
 * Service 0x27 - SecurityAccess
 *
 * Sub-function 0x01 - Request Seed:
 *   Request format: [0x27] [0x01]
 *   Positive response: [0x67] [0x01] [seed_b3] [seed_b2] [seed_b1] [seed_b0]
 *
 * Sub-function 0x02 - Send Key:
 *   Request format: [0x27] [0x02] [key_b3] [key_b2] [key_b1] [key_b0]
 *   Positive response: [0x67] [0x02]
 *
 * Key algorithm: key = seed XOR 0xCAFEBABE
 */
int uds_service_security_access(uds_state_t *state,
                                 const uint8_t *request, size_t req_len,
                                 uint8_t *response, size_t *resp_len) {
    uint8_t sub_function;
    uint32_t seed;
    uint32_t expected_key;
    uint32_t received_key;
    time_t now;

    /* Check minimum length: SID + sub-function */
    if (req_len < 2) {
        send_negative_response(UDS_SID_SECURITY_ACCESS,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    sub_function = request[1] & 0x7F;  /* Mask suppress positive response bit */
    now = time(NULL);

    log_message("SecurityAccess: sub-function=0x%02X, session=0x%02X, security=%s\n",
                sub_function, state->session_type,
                state->security_state == UDS_SECURITY_UNLOCKED ? "UNLOCKED" : "LOCKED");

    /* Check if in lockout period */
    if (state->lockout_until > 0 && now < state->lockout_until) {
        log_message("SecurityAccess: Locked out for %ld more seconds\n",
                    (long)(state->lockout_until - now));
        send_negative_response(UDS_SID_SECURITY_ACCESS,
                               UDS_NRC_EXCEEDED_ATTEMPTS, response, resp_len);
        return -1;
    }

    /* Clear lockout if expired */
    if (state->lockout_until > 0 && now >= state->lockout_until) {
        state->lockout_until = 0;
        state->security_attempts = 0;
    }

    /* Security Access requires Extended Session (0x03) */
    if (state->session_type != UDS_SESSION_EXTENDED &&
        state->session_type != UDS_SESSION_PROGRAMMING) {
        log_message("SecurityAccess: Wrong session (need Extended or Programming)\n");
        send_negative_response(UDS_SID_SECURITY_ACCESS,
                               UDS_NRC_CONDITIONS_NOT_CORRECT, response, resp_len);
        return -1;
    }

    switch (sub_function) {
        case UDS_SA_REQUEST_SEED:  /* 0x01 - Request Seed */
            /* If already unlocked, return zero seed */
            if (state->security_state == UDS_SECURITY_UNLOCKED) {
                log_message("SecurityAccess: Already unlocked, returning zero seed\n");
                response[0] = UDS_SID_SECURITY_ACCESS + 0x40;
                response[1] = sub_function;
                response[2] = 0x00;
                response[3] = 0x00;
                response[4] = 0x00;
                response[5] = 0x00;
                *resp_len = 6;
                return 0;
            }

            /* Generate pseudo-random seed */
            seed = (uint32_t)now ^ 0xDEADBEEF ^ ((uint32_t)rand() << 16) ^ (uint32_t)rand();

            /* Ensure non-zero seed */
            if (seed == 0) {
                seed = 0x12345678;
            }

            state->current_seed = seed;
            log_message("SecurityAccess: Generated seed=0x%08X\n", seed);

            /* Build positive response with seed */
            response[0] = UDS_SID_SECURITY_ACCESS + 0x40;
            response[1] = sub_function;
            response[2] = (seed >> 24) & 0xFF;
            response[3] = (seed >> 16) & 0xFF;
            response[4] = (seed >> 8) & 0xFF;
            response[5] = seed & 0xFF;
            *resp_len = 6;
            return 0;

        case UDS_SA_SEND_KEY:  /* 0x02 - Send Key */
            /* Check that we have a pending seed (sequence check) */
            if (state->current_seed == 0) {
                log_message("SecurityAccess: No seed pending (request seed first)\n");
                send_negative_response(UDS_SID_SECURITY_ACCESS,
                                       UDS_NRC_REQUEST_SEQUENCE_ERROR, response, resp_len);
                return -1;
            }

            /* Check key length */
            if (req_len < 6) {
                send_negative_response(UDS_SID_SECURITY_ACCESS,
                                       UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
                return -1;
            }

            /* Extract received key (big-endian) */
            received_key = ((uint32_t)request[2] << 24) |
                           ((uint32_t)request[3] << 16) |
                           ((uint32_t)request[4] << 8) |
                           (uint32_t)request[5];

            /* Calculate expected key: seed XOR 0xCAFEBABE */
            expected_key = state->current_seed ^ UDS_SECURITY_XOR_KEY;

            log_message("SecurityAccess: received_key=0x%08X, expected_key=0x%08X\n",
                        received_key, expected_key);

            if (received_key == expected_key) {
                /* Key valid - unlock security */
                state->security_state = UDS_SECURITY_UNLOCKED;
                state->security_attempts = 0;
                state->current_seed = 0;  /* Clear seed */
                log_message("SecurityAccess: Key valid - UNLOCKED\n");

                response[0] = UDS_SID_SECURITY_ACCESS + 0x40;
                response[1] = sub_function;
                *resp_len = 2;
                return 0;
            } else {
                /* Key invalid - increment attempts */
                state->security_attempts++;
                state->current_seed = 0;  /* Clear seed - must request new one */
                log_message("SecurityAccess: Invalid key - attempt %d/%d\n",
                            state->security_attempts, UDS_SECURITY_MAX_ATTEMPTS);

                if (state->security_attempts >= UDS_SECURITY_MAX_ATTEMPTS) {
                    /* Lock out for configured duration */
                    state->lockout_until = now + UDS_SECURITY_LOCKOUT_SEC;
                    log_message("SecurityAccess: Max attempts reached - locked out for %d seconds\n",
                                UDS_SECURITY_LOCKOUT_SEC);
                    send_negative_response(UDS_SID_SECURITY_ACCESS,
                                           UDS_NRC_EXCEEDED_ATTEMPTS, response, resp_len);
                } else {
                    send_negative_response(UDS_SID_SECURITY_ACCESS,
                                           UDS_NRC_INVALID_KEY, response, resp_len);
                }
                return -1;
            }

        case UDS_SA_HIDDEN_BYPASS:  /* 0x05 - V9 VULNERABILITY: Hidden bypass */
            /*
             * V9 Vulnerability - State Machine Bypass
             *
             * This hidden sub-function bypasses seed-key authentication
             * but ONLY when triggered after an invalid session transition.
             * The sequence required is:
             *   1. Send 0x10 0x03 (Extended Session) WITHOUT first establishing Default
             *   2. Send 0x27 0x05 (this hidden sub-function)
             *
             * This requires stateful fuzzing to discover because:
             * - Sub-function 0x05 is not documented
             * - It only works after specific invalid protocol usage
             * - Standard fuzzing of just the Security Access service won't work
             */
            log_message("SecurityAccess: Hidden sub-function 0x05 received\n");

            if (state->invalid_session_transition) {
                /* Vulnerability triggered! Bypass authentication */
                state->security_state = UDS_SECURITY_UNLOCKED;
                state->security_attempts = 0;
                state->current_seed = 0;

                log_message("UDS_SECURITY_BYPASS_DETECTED\n");
                log_message("SecurityAccess: BYPASSED via state machine vulnerability - UNLOCKED\n");

                /* Return positive response */
                response[0] = UDS_SID_SECURITY_ACCESS + 0x40;
                response[1] = sub_function;
                *resp_len = 2;
                return 0;
            } else {
                /* Invalid session transition not detected - bypass fails */
                log_message("SecurityAccess: Bypass attempt failed (no invalid transition)\n");
                send_negative_response(UDS_SID_SECURITY_ACCESS,
                                       UDS_NRC_CONDITIONS_NOT_CORRECT, response, resp_len);
                return -1;
            }

        default:
            /* Unknown sub-function */
            log_message("SecurityAccess: Unknown sub-function 0x%02X\n", sub_function);
            send_negative_response(UDS_SID_SECURITY_ACCESS,
                                   UDS_NRC_SUBFUNCTION_NOT_SUPPORTED, response, resp_len);
            return -1;
    }
}

/*
 * Service 0x22 - ReadDataByIdentifier
 *
 * Request format: [0x22] [DID_hi] [DID_lo]
 * Positive response: [0x62] [DID_hi] [DID_lo] [data...]
 *
 * Supported DIDs:
 *   0xF190 - VIN (Vehicle Identification Number) - read-only
 *   0xF195 - System Name - read-only
 *   0x0100 - Calibration Data - read/write (requires security)
 *   0x0200 - Configuration Block - read/write (requires security)
 */
int uds_service_read_data_by_id(uds_state_t *state,
                                 const uint8_t *request, size_t req_len,
                                 uint8_t *response, size_t *resp_len) {
    uint16_t did;
    size_t data_len;

    /* Check minimum length: SID + DID (2 bytes) */
    if (req_len < 3) {
        send_negative_response(UDS_SID_READ_DATA_BY_ID,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    /* Extract DID (big-endian) */
    did = ((uint16_t)request[1] << 8) | (uint16_t)request[2];

    log_message("ReadDataByIdentifier: DID=0x%04X\n", did);

    /* Build response header */
    response[0] = UDS_SID_READ_DATA_BY_ID + 0x40;  /* Positive response SID */
    response[1] = request[1];  /* DID high byte */
    response[2] = request[2];  /* DID low byte */

    switch (did) {
        case UDS_DID_VIN:  /* 0xF190 - VIN */
            data_len = strlen(did_vin);
            memcpy(&response[3], did_vin, data_len);
            *resp_len = 3 + data_len;
            log_message("ReadDataByIdentifier: Returning VIN=%s\n", did_vin);
            return 0;

        case UDS_DID_SYSTEM_NAME:  /* 0xF195 - System Name */
            data_len = strlen(did_system_name);
            memcpy(&response[3], did_system_name, data_len);
            *resp_len = 3 + data_len;
            log_message("ReadDataByIdentifier: Returning SystemName=%s\n", did_system_name);
            return 0;

        case UDS_DID_CALIBRATION_DATA:  /* 0x0100 - Calibration Data (requires security) */
            if (state->security_state != UDS_SECURITY_UNLOCKED) {
                log_message("ReadDataByIdentifier: Security access required for DID 0x%04X\n", did);
                send_negative_response(UDS_SID_READ_DATA_BY_ID,
                                       UDS_NRC_SECURITY_ACCESS_DENIED, response, resp_len);
                return -1;
            }
            memcpy(&response[3], did_calibration_data, UDS_CALIBRATION_DATA_SIZE);
            *resp_len = 3 + UDS_CALIBRATION_DATA_SIZE;
            log_message("ReadDataByIdentifier: Returning Calibration Data (%d bytes)\n",
                        UDS_CALIBRATION_DATA_SIZE);
            return 0;

        case UDS_DID_CONFIG_BLOCK:  /* 0x0200 - Configuration Block (requires security) */
            if (state->security_state != UDS_SECURITY_UNLOCKED) {
                log_message("ReadDataByIdentifier: Security access required for DID 0x%04X\n", did);
                send_negative_response(UDS_SID_READ_DATA_BY_ID,
                                       UDS_NRC_SECURITY_ACCESS_DENIED, response, resp_len);
                return -1;
            }
            memcpy(&response[3], did_config_block, UDS_CONFIG_BLOCK_SIZE);
            *resp_len = 3 + UDS_CONFIG_BLOCK_SIZE;
            log_message("ReadDataByIdentifier: Returning Config Block (%d bytes)\n",
                        UDS_CONFIG_BLOCK_SIZE);
            return 0;

        default:
            log_message("ReadDataByIdentifier: Unknown DID 0x%04X\n", did);
            send_negative_response(UDS_SID_READ_DATA_BY_ID,
                                   UDS_NRC_REQUEST_OUT_OF_RANGE, response, resp_len);
            return -1;
    }
}

/*
 * Service 0x2E - WriteDataByIdentifier
 *
 * Request format: [0x2E] [DID_hi] [DID_lo] [data...]
 * Positive response: [0x6E] [DID_hi] [DID_lo]
 *
 * Writable DIDs (require security access):
 *   0x0100 - Calibration Data
 *   0x0200 - Configuration Block
 *
 * Read-only DIDs (cannot be written):
 *   0xF190 - VIN
 *   0xF195 - System Name
 *
 * V11 VULNERABILITY: Integer overflow in length calculation
 * When req_len is 1 or 2, the uint8_t subtraction wraps around to 254/255,
 * causing a heap buffer overflow when copying data.
 */
int uds_service_write_data_by_id(uds_state_t *state,
                                  const uint8_t *request, size_t req_len,
                                  uint8_t *response, size_t *resp_len) {
    uint16_t did;
    size_t data_len;
    uint8_t *temp_buffer;

    /*
     * V11 VULNERABILITY: Integer Overflow in Length Calculation
     *
     * The vulnerable pattern uses uint8_t for length calculation:
     *   uint8_t len = (uint8_t)(req_len - 3);
     *
     * When req_len is 1: len = (uint8_t)(1 - 3) = (uint8_t)(-2) = 254
     * When req_len is 2: len = (uint8_t)(2 - 3) = (uint8_t)(-1) = 255
     *
     * This requires fuzzing with malformed short requests to discover.
     * Normal requests (req_len >= 4) work correctly.
     */

    /* V11 vulnerable code path: Process request even with short length */
    if (req_len >= 1 && req_len <= 2) {
        /* VULNERABLE: Integer overflow in uint8_t subtraction */
        uint8_t vuln_len = (uint8_t)(req_len - 3);  /* Wraps to 254 or 255! */

        log_message("WriteDataByIdentifier: V11 OVERFLOW - req_len=%zu, vuln_len=%u\n",
                    req_len, vuln_len);
        log_message("UDS_INTEGER_OVERFLOW_DETECTED\n");

        /* Allocate small buffer on heap */
        temp_buffer = (uint8_t *)malloc(32);
        if (temp_buffer == NULL) {
            send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                                   UDS_NRC_GENERAL_REJECT, response, resp_len);
            return -1;
        }

        /*
         * VULNERABILITY: Copy vuln_len (254 or 255) bytes into 32-byte buffer
         * This causes heap buffer overflow, potentially corrupting heap metadata
         * or adjacent allocations.
         */
        memcpy(temp_buffer, request, vuln_len);

        /* The overflow has already occurred - free buffer and crash or continue */
        free(temp_buffer);

        /* Return generic error (if we haven't crashed) */
        send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    /* Normal length check for non-vulnerable requests */
    if (req_len < 4) {
        send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    /* Extract DID (big-endian) */
    did = ((uint16_t)request[1] << 8) | (uint16_t)request[2];
    data_len = req_len - 3;  /* Data length = total length - SID - DID */

    log_message("WriteDataByIdentifier: DID=0x%04X, data_len=%zu\n", did, data_len);

    switch (did) {
        case UDS_DID_VIN:  /* 0xF190 - VIN (read-only) */
        case UDS_DID_SYSTEM_NAME:  /* 0xF195 - System Name (read-only) */
            log_message("WriteDataByIdentifier: DID 0x%04X is read-only\n", did);
            send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                                   UDS_NRC_CONDITIONS_NOT_CORRECT, response, resp_len);
            return -1;

        case UDS_DID_CALIBRATION_DATA:  /* 0x0100 - Calibration Data */
            /* Check security access */
            if (state->security_state != UDS_SECURITY_UNLOCKED) {
                log_message("WriteDataByIdentifier: Security access required for DID 0x%04X\n", did);
                send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                                       UDS_NRC_SECURITY_ACCESS_DENIED, response, resp_len);
                return -1;
            }

            /* Check data length */
            if (data_len > UDS_CALIBRATION_DATA_SIZE) {
                log_message("WriteDataByIdentifier: Data too large for Calibration Data\n");
                send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                                       UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
                return -1;
            }

            /* Write data */
            memset(did_calibration_data, 0, UDS_CALIBRATION_DATA_SIZE);
            memcpy(did_calibration_data, &request[3], data_len);
            log_message("WriteDataByIdentifier: Written %zu bytes to Calibration Data\n", data_len);

            /* Build positive response */
            response[0] = UDS_SID_WRITE_DATA_BY_ID + 0x40;
            response[1] = request[1];
            response[2] = request[2];
            *resp_len = 3;
            return 0;

        case UDS_DID_CONFIG_BLOCK:  /* 0x0200 - Configuration Block */
            /* Check security access */
            if (state->security_state != UDS_SECURITY_UNLOCKED) {
                log_message("WriteDataByIdentifier: Security access required for DID 0x%04X\n", did);
                send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                                       UDS_NRC_SECURITY_ACCESS_DENIED, response, resp_len);
                return -1;
            }

            /* Check data length */
            if (data_len > UDS_CONFIG_BLOCK_SIZE) {
                log_message("WriteDataByIdentifier: Data too large for Config Block\n");
                send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                                       UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
                return -1;
            }

            /* Write data */
            memset(did_config_block, 0, UDS_CONFIG_BLOCK_SIZE);
            memcpy(did_config_block, &request[3], data_len);
            log_message("WriteDataByIdentifier: Written %zu bytes to Config Block\n", data_len);

            /* Build positive response */
            response[0] = UDS_SID_WRITE_DATA_BY_ID + 0x40;
            response[1] = request[1];
            response[2] = request[2];
            *resp_len = 3;
            return 0;

        default:
            log_message("WriteDataByIdentifier: Unknown DID 0x%04X\n", did);
            send_negative_response(UDS_SID_WRITE_DATA_BY_ID,
                                   UDS_NRC_REQUEST_OUT_OF_RANGE, response, resp_len);
            return -1;
    }
}

/*
 * Service 0x34 - RequestDownload
 *
 * Request format: [0x34] [dataFormatId] [addressAndLengthFormatId] [address...] [size...]
 * - dataFormatId: compression/encryption (0x00 = none)
 * - addressAndLengthFormatId: high nibble = address bytes, low nibble = size bytes
 *   Example: 0x44 = 4 byte address, 4 byte size
 *
 * Positive response: [0x74] [lengthFormatId] [maxBlockLength...]
 *
 * This service initiates a firmware download transfer.
 * Requires Programming Session (0x02) and Security Access unlocked.
 */
int uds_service_request_download(uds_state_t *state,
                                  const uint8_t *request, size_t req_len,
                                  uint8_t *response, size_t *resp_len) {
    uint8_t data_format;
    uint8_t addr_len_format;
    uint8_t addr_bytes;
    uint8_t size_bytes;
    uint32_t address = 0;
    uint32_t size = 0;
    size_t i;
    size_t offset;

    /* Check minimum length: SID + dataFormatId + addrLenFormatId = 3 bytes minimum */
    if (req_len < 3) {
        send_negative_response(UDS_SID_REQUEST_DOWNLOAD,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    log_message("RequestDownload: session=0x%02X, security=%s, transfer_active=%d\n",
                state->session_type,
                state->security_state == UDS_SECURITY_UNLOCKED ? "UNLOCKED" : "LOCKED",
                state->transfer_active);

    /* Require Programming Session (0x02) */
    if (state->session_type != UDS_SESSION_PROGRAMMING) {
        log_message("RequestDownload: Requires Programming Session\n");
        send_negative_response(UDS_SID_REQUEST_DOWNLOAD,
                               UDS_NRC_CONDITIONS_NOT_CORRECT, response, resp_len);
        return -1;
    }

    /* Require Security Access unlocked */
    if (state->security_state != UDS_SECURITY_UNLOCKED) {
        log_message("RequestDownload: Security access required\n");
        send_negative_response(UDS_SID_REQUEST_DOWNLOAD,
                               UDS_NRC_SECURITY_ACCESS_DENIED, response, resp_len);
        return -1;
    }

    /* Check if transfer already in progress */
    if (state->transfer_active == UDS_TRANSFER_STATE_DOWNLOAD) {
        log_message("RequestDownload: Transfer already in progress\n");
        send_negative_response(UDS_SID_REQUEST_DOWNLOAD,
                               UDS_NRC_CONDITIONS_NOT_CORRECT, response, resp_len);
        return -1;
    }

    /* Parse dataFormatId (compression/encryption) */
    data_format = request[1];
    if (data_format != 0x00) {
        /* Only uncompressed/unencrypted supported */
        log_message("RequestDownload: Unsupported data format 0x%02X\n", data_format);
        send_negative_response(UDS_SID_REQUEST_DOWNLOAD,
                               UDS_NRC_REQUEST_OUT_OF_RANGE, response, resp_len);
        return -1;
    }

    /* Parse addressAndLengthFormatIdentifier */
    addr_len_format = request[2];
    addr_bytes = (addr_len_format >> 4) & 0x0F;
    size_bytes = addr_len_format & 0x0F;

    log_message("RequestDownload: addr_bytes=%d, size_bytes=%d\n", addr_bytes, size_bytes);

    /* Validate format (support 1-4 byte addresses and sizes) */
    if (addr_bytes < 1 || addr_bytes > 4 || size_bytes < 1 || size_bytes > 4) {
        log_message("RequestDownload: Invalid addressAndLengthFormatId\n");
        send_negative_response(UDS_SID_REQUEST_DOWNLOAD,
                               UDS_NRC_REQUEST_OUT_OF_RANGE, response, resp_len);
        return -1;
    }

    /* Check message length */
    if (req_len < (size_t)(3 + addr_bytes + size_bytes)) {
        send_negative_response(UDS_SID_REQUEST_DOWNLOAD,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    /* Extract address (big-endian) */
    offset = 3;
    for (i = 0; i < addr_bytes; i++) {
        address = (address << 8) | request[offset + i];
    }

    /* Extract size (big-endian) */
    offset = 3 + addr_bytes;
    for (i = 0; i < size_bytes; i++) {
        size = (size << 8) | request[offset + i];
    }

    log_message("RequestDownload: address=0x%08X, size=%u\n", address, size);

    /* Validate transfer size */
    if (size == 0 || size > UDS_TRANSFER_MAX_SIZE) {
        log_message("RequestDownload: Invalid transfer size\n");
        send_negative_response(UDS_SID_REQUEST_DOWNLOAD,
                               UDS_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED, response, resp_len);
        return -1;
    }

    /* Initialize transfer state */
    state->transfer_active = UDS_TRANSFER_STATE_DOWNLOAD;
    state->transfer_address = address;
    state->transfer_size = size;
    state->transfer_seq = 0;  /* Start sequence counter at 0, first TransferData will be 1 */

    log_message("RequestDownload: Transfer initiated\n");

    /* Build positive response */
    /* Response: [0x74] [lengthFormatIdentifier] [maxNumberOfBlockLength...] */
    response[0] = UDS_SID_REQUEST_DOWNLOAD + 0x40;  /* 0x74 */
    /* lengthFormatIdentifier: 0x20 = 2 bytes for maxBlockLength */
    response[1] = 0x20;
    /* maxNumberOfBlockLength (2 bytes, big-endian) = block size + 2 (for SID and seq counter) */
    response[2] = ((UDS_TRANSFER_BLOCK_SIZE + 2) >> 8) & 0xFF;
    response[3] = (UDS_TRANSFER_BLOCK_SIZE + 2) & 0xFF;
    *resp_len = 4;

    return 0;
}

/*
 * Service 0x36 - TransferData
 *
 * Request format: [0x36] [blockSequenceCounter] [data...]
 * - blockSequenceCounter: 0x01-0xFF, wraps at 0xFF to 0x00
 *
 * Positive response: [0x76] [blockSequenceCounter]
 *
 * This service transfers firmware data blocks.
 * Must be called after RequestDownload (0x34).
 *
 * V12 VULNERABILITY: First block (sequence 0x01) is treated as firmware header.
 * Header format: [4-byte magic][2-byte version][2-byte name_len][name...]
 * The name_len field is not validated, causing a stack buffer overflow
 * when copying the name into a fixed 32-byte buffer.
 */

/* Firmware header magic number */
#define UDS_FIRMWARE_MAGIC      0x55444346  /* "UDCF" in hex */
#define UDS_FIRMWARE_NAME_BUF   32          /* Fixed buffer size for V12 vulnerability */

/*
 * V12 Vulnerable firmware header parsing
 *
 * This function parses the firmware header from the first TransferData block.
 * It contains an intentional buffer overflow vulnerability:
 * - The name_len field from the header is trusted without bounds checking
 * - When name_len > 32, the strcpy/memcpy overflows the stack buffer
 *
 * This vulnerability requires fuzzing the firmware header format to discover.
 */
static int parse_firmware_header(const uint8_t *data, size_t data_len) {
    uint32_t magic;
    uint16_t version;
    uint16_t name_len;
    char name_buffer[UDS_FIRMWARE_NAME_BUF];  /* V12: Fixed 32-byte stack buffer */

    /* Check minimum header size: magic(4) + version(2) + name_len(2) = 8 bytes */
    if (data_len < 8) {
        log_message("FirmwareHeader: Header too short (%zu bytes)\n", data_len);
        return -1;
    }

    /* Parse magic (big-endian) */
    magic = ((uint32_t)data[0] << 24) |
            ((uint32_t)data[1] << 16) |
            ((uint32_t)data[2] << 8) |
            (uint32_t)data[3];

    /* Parse version (big-endian) */
    version = ((uint16_t)data[4] << 8) | (uint16_t)data[5];

    /* Parse name_len (big-endian) */
    name_len = ((uint16_t)data[6] << 8) | (uint16_t)data[7];

    log_message("FirmwareHeader: magic=0x%08X, version=%u, name_len=%u\n",
                magic, version, name_len);

    /* Validate magic number */
    if (magic != UDS_FIRMWARE_MAGIC) {
        log_message("FirmwareHeader: Invalid magic (expected 0x%08X)\n", UDS_FIRMWARE_MAGIC);
        return -1;
    }

    /* Check if we have enough data for the name */
    if (data_len < 8 + name_len) {
        log_message("FirmwareHeader: Incomplete name (have %zu, need %u)\n",
                    data_len - 8, name_len);
        return -1;
    }

    /*
     * V12 VULNERABILITY: Buffer Overflow in Firmware Header Name Parsing
     *
     * The name_len field is read from the firmware header but NOT validated
     * against the buffer size. When name_len > 32, the memcpy below overflows
     * the stack buffer, potentially allowing code execution.
     *
     * This vulnerability requires:
     * 1. Fuzzing the firmware format to discover the header structure
     * 2. Crafting a header with valid magic and oversized name_len
     * 3. Understanding that first TransferData block is parsed as header
     *
     * Detection: Log marker is written BEFORE the overflow occurs.
     */
    if (name_len > UDS_FIRMWARE_NAME_BUF) {
        /* Log the vulnerability detection BEFORE the overflow */
        log_message("UDS_FIRMWARE_OVERFLOW_DETECTED\n");
        log_message("FirmwareHeader: V12 OVERFLOW - name_len=%u exceeds buffer=%d\n",
                    name_len, UDS_FIRMWARE_NAME_BUF);
    }

    /* Initialize buffer */
    memset(name_buffer, 0, sizeof(name_buffer));

    /*
     * VULNERABLE CODE: Copy name without bounds checking
     * When name_len > 32, this overflows the stack buffer
     */
    memcpy(name_buffer, &data[8], name_len);

    /* Null-terminate (may write past buffer end if overflowed) */
    name_buffer[name_len < UDS_FIRMWARE_NAME_BUF ? name_len : UDS_FIRMWARE_NAME_BUF - 1] = '\0';

    log_message("FirmwareHeader: Firmware name: %s\n", name_buffer);
    log_message("FirmwareHeader: Header parsed successfully\n");

    return 0;
}

int uds_service_transfer_data(uds_state_t *state,
                               const uint8_t *request, size_t req_len,
                               uint8_t *response, size_t *resp_len) {
    uint8_t block_seq;
    uint8_t expected_seq;
    size_t data_len;
    const uint8_t *data;

    /* Check minimum length: SID + blockSequenceCounter = 2 bytes */
    if (req_len < 2) {
        send_negative_response(UDS_SID_TRANSFER_DATA,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    log_message("TransferData: transfer_active=%d, expected_seq=%d\n",
                state->transfer_active, (state->transfer_seq + 1) & 0xFF);

    /* Check if transfer is active */
    if (state->transfer_active != UDS_TRANSFER_STATE_DOWNLOAD) {
        log_message("TransferData: No active transfer\n");
        send_negative_response(UDS_SID_TRANSFER_DATA,
                               UDS_NRC_REQUEST_SEQUENCE_ERROR, response, resp_len);
        return -1;
    }

    /* Parse block sequence counter */
    block_seq = request[1];
    expected_seq = (state->transfer_seq + 1) & 0xFF;  /* Expected next sequence (wraps at 255) */
    if (expected_seq == 0) expected_seq = 1;  /* First block is always 1, not 0 */

    log_message("TransferData: block_seq=0x%02X, expected=0x%02X\n", block_seq, expected_seq);

    /* Validate sequence counter */
    if (block_seq != expected_seq) {
        log_message("TransferData: Wrong sequence counter\n");
        send_negative_response(UDS_SID_TRANSFER_DATA,
                               UDS_NRC_REQUEST_SEQUENCE_ERROR, response, resp_len);
        return -1;
    }

    /* Calculate data length and pointer */
    data_len = req_len - 2;  /* Total length - SID - blockSeq */
    data = &request[2];      /* Data starts after SID and blockSeq */

    log_message("TransferData: Received %zu bytes of data\n", data_len);

    /* Check block size */
    if (data_len > UDS_TRANSFER_BLOCK_SIZE) {
        log_message("TransferData: Block too large\n");
        send_negative_response(UDS_SID_TRANSFER_DATA,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    /*
     * V12 VULNERABILITY: First block (sequence 0x01) is treated as firmware header
     *
     * The first TransferData block contains the firmware header which includes
     * metadata about the firmware being downloaded. This header is parsed
     * by parse_firmware_header() which contains a buffer overflow vulnerability.
     *
     * To exploit:
     * 1. RequestDownload (0x34) to initiate transfer
     * 2. TransferData (0x36) with block sequence 0x01 and crafted header:
     *    - Magic: 0x55444346 ("UDCF")
     *    - Version: any 2-byte value
     *    - name_len: value > 32 to trigger overflow
     *    - name: name_len bytes of data (overflows into stack)
     */
    if (block_seq == 0x01 && data_len > 0) {
        log_message("TransferData: First block - parsing firmware header\n");
        if (parse_firmware_header(data, data_len) != 0) {
            /* Header parsing failed - but we continue anyway (vulnerable behavior) */
            log_message("TransferData: Invalid firmware header (continuing anyway)\n");
        }
    } else {
        /*
         * Non-header blocks: In a real ECU, the data would be written
         * to flash/memory at address + current offset.
         * For this simulation, we just log that we received the data.
         */
        log_message("TransferData: Block %d received, %zu bytes\n", block_seq, data_len);
    }

    /* Update sequence counter for next expected block */
    state->transfer_seq = block_seq;

    /* Build positive response */
    response[0] = UDS_SID_TRANSFER_DATA + 0x40;  /* 0x76 */
    response[1] = block_seq;
    *resp_len = 2;

    return 0;
}

/*
 * Service 0x37 - RequestTransferExit
 *
 * Request format: [0x37] [optional_data...]
 *
 * Positive response: [0x77] [optional_data...]
 *
 * This service completes a firmware transfer.
 * Must be called after all TransferData blocks have been sent.
 */
int uds_service_request_transfer_exit(uds_state_t *state,
                                       const uint8_t *request, size_t req_len,
                                       uint8_t *response, size_t *resp_len) {
    (void)request;  /* Optional data not used in this implementation */

    /* Check minimum length: just SID */
    if (req_len < 1) {
        send_negative_response(UDS_SID_REQUEST_TRANSFER_EXIT,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    log_message("RequestTransferExit: transfer_active=%d\n", state->transfer_active);

    /* Check if transfer is active */
    if (state->transfer_active != UDS_TRANSFER_STATE_DOWNLOAD) {
        log_message("RequestTransferExit: No active transfer\n");
        send_negative_response(UDS_SID_REQUEST_TRANSFER_EXIT,
                               UDS_NRC_REQUEST_SEQUENCE_ERROR, response, resp_len);
        return -1;
    }

    /*
     * In a real ECU, this would:
     * - Verify the transferred data (checksum/CRC)
     * - Commit the firmware to permanent storage
     * - Optionally schedule a reboot
     *
     * For this simulation, we just reset the transfer state.
     */
    log_message("RequestTransferExit: Transfer complete after %d blocks\n", state->transfer_seq);

    /* Reset transfer state */
    state->transfer_active = UDS_TRANSFER_STATE_COMPLETE;
    state->transfer_address = 0;
    state->transfer_size = 0;
    state->transfer_seq = 0;

    /* Build positive response */
    response[0] = UDS_SID_REQUEST_TRANSFER_EXIT + 0x40;  /* 0x77 */
    *resp_len = 1;

    log_message("RequestTransferExit: Transfer state reset, ready for new transfer\n");

    /* Return to idle state for next transfer */
    state->transfer_active = UDS_TRANSFER_STATE_IDLE;

    return 0;
}

/*
 * Service 0x3E - TesterPresent
 *
 * Request format: [0x3E] [sub-function]
 * - sub-function: 0x00 = normal, 0x80 = suppress positive response
 *
 * Positive response: [0x7E] [sub-function]
 *
 * This service is used to keep the diagnostic session alive.
 * It resets the session timeout counter without changing session state.
 */
int uds_service_tester_present(uds_state_t *state,
                                const uint8_t *request, size_t req_len,
                                uint8_t *response, size_t *resp_len) {
    uint8_t sub_function;
    int suppress_response;

    /* Check minimum length: SID + sub-function */
    if (req_len < 2) {
        send_negative_response(UDS_SID_TESTER_PRESENT,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    sub_function = request[1];
    suppress_response = (sub_function & 0x80) != 0;  /* Bit 7 = suppress positive response */
    sub_function &= 0x7F;  /* Mask off suppress bit */

    log_message("TesterPresent: sub_function=0x%02X, suppress=%d, session=0x%02X\n",
                sub_function, suppress_response, state->session_type);

    /* Only sub-function 0x00 is supported */
    if (sub_function != 0x00) {
        send_negative_response(UDS_SID_TESTER_PRESENT,
                               UDS_NRC_SUBFUNCTION_NOT_SUPPORTED, response, resp_len);
        return -1;
    }

    /* Reset session timeout (last_activity already updated by uds_engine_process) */
    state->last_activity = time(NULL);
    log_message("TesterPresent: Session timeout reset\n");

    /* Check if positive response should be suppressed */
    if (suppress_response) {
        log_message("TesterPresent: Positive response suppressed\n");
        *resp_len = 0;
        return 0;
    }

    /* Build positive response */
    response[0] = UDS_SID_TESTER_PRESENT + 0x40;  /* 0x7E */
    response[1] = sub_function;
    *resp_len = 2;

    return 0;
}

/*
 * Service 0x11 - ECUReset
 *
 * Request format: [0x11] [reset_type]
 * - reset_type: 0x01 = hard reset, 0x02 = key off/on, 0x03 = soft reset
 *
 * Positive response: [0x51] [reset_type] [powerDownTime (optional)]
 *
 * This service simulates an ECU reset.
 * Requires security access to be unlocked.
 * Resets all UDS state back to initial values.
 */
int uds_service_ecu_reset(uds_state_t *state,
                           const uint8_t *request, size_t req_len,
                           uint8_t *response, size_t *resp_len) {
    uint8_t reset_type;

    /* Check minimum length: SID + reset_type */
    if (req_len < 2) {
        send_negative_response(UDS_SID_ECU_RESET,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    reset_type = request[1] & 0x7F;  /* Mask suppress positive response bit */

    log_message("ECUReset: reset_type=0x%02X, session=0x%02X, security=%s\n",
                reset_type, state->session_type,
                state->security_state == UDS_SECURITY_UNLOCKED ? "UNLOCKED" : "LOCKED");

    /* Validate reset type */
    switch (reset_type) {
        case UDS_RESET_HARD:
        case UDS_RESET_KEY_OFF_ON:
        case UDS_RESET_SOFT:
            /* Valid reset types */
            break;
        default:
            log_message("ECUReset: Unknown reset type 0x%02X\n", reset_type);
            send_negative_response(UDS_SID_ECU_RESET,
                                   UDS_NRC_SUBFUNCTION_NOT_SUPPORTED, response, resp_len);
            return -1;
    }

    /* Require security access unlocked for ECU reset */
    if (state->security_state != UDS_SECURITY_UNLOCKED) {
        log_message("ECUReset: Security access required\n");
        send_negative_response(UDS_SID_ECU_RESET,
                               UDS_NRC_SECURITY_ACCESS_DENIED, response, resp_len);
        return -1;
    }

    log_message("ECUReset: Performing %s reset\n",
                reset_type == UDS_RESET_HARD ? "HARD" :
                reset_type == UDS_RESET_KEY_OFF_ON ? "KEY_OFF_ON" : "SOFT");

    /*
     * Build positive response BEFORE resetting state
     * In a real ECU, the response would be sent and then the reset would occur.
     */
    response[0] = UDS_SID_ECU_RESET + 0x40;  /* 0x51 */
    response[1] = reset_type;
    *resp_len = 2;

    /*
     * Simulate ECU reset by reinitializing all state
     * This resets session to Default, locks security, clears transfer state, etc.
     */
    state->session_type = UDS_SESSION_DEFAULT;
    state->security_state = UDS_SECURITY_LOCKED;
    state->security_attempts = 0;
    state->current_seed = 0;
    state->lockout_until = 0;
    state->transfer_active = UDS_TRANSFER_STATE_IDLE;
    state->transfer_address = 0;
    state->transfer_size = 0;
    state->transfer_seq = 0;
    state->last_activity = time(NULL);
    state->invalid_session_transition = 0;
    state->session_established = 0;

    log_message("ECUReset: All state reset to defaults\n");

    return 0;
}

/*
 * Simulated DTC storage
 *
 * In a real ECU, DTCs would be stored in non-volatile memory.
 * For this simulation, we use a static array with some pre-populated DTCs.
 */
typedef struct {
    uint32_t dtc_id;      /* 3-byte DTC code (e.g., P0100 = 0x000100) */
    uint8_t status;       /* DTC status mask */
} dtc_entry_t;

#define MAX_DTCS 10

static dtc_entry_t dtc_storage[MAX_DTCS] = {
    { 0x000100, UDS_DTC_STATUS_CONFIRMED | UDS_DTC_STATUS_TEST_FAILED },      /* P0100 - Mass Air Flow */
    { 0x000300, UDS_DTC_STATUS_PENDING | UDS_DTC_STATUS_TEST_FAILED },        /* P0300 - Random Misfire */
    { 0x000420, UDS_DTC_STATUS_CONFIRMED },                                    /* P0420 - Catalyst Efficiency */
    { 0xC00100, UDS_DTC_STATUS_CONFIRMED | UDS_DTC_STATUS_WARNING_INDICATOR }, /* U0100 - Lost Comm ECM */
    { 0, 0 },  /* Empty slots follow */
};

/*
 * Service 0x19 - ReadDTCInformation
 *
 * Request format: [0x19] [sub-function] [additional_params...]
 *
 * Supported sub-functions:
 *   0x01 - reportNumberOfDTCByStatusMask [statusMask]
 *   0x02 - reportDTCByStatusMask [statusMask]
 *   0x0A - reportSupportedDTC
 *
 * Response formats vary by sub-function.
 */
int uds_service_read_dtc_info(uds_state_t *state,
                               const uint8_t *request, size_t req_len,
                               uint8_t *response, size_t *resp_len) {
    uint8_t sub_function;
    uint8_t status_mask;
    int i;
    int count;
    size_t offset;

    (void)state;  /* State not used for DTC reading */

    /* Check minimum length: SID + sub-function */
    if (req_len < 2) {
        send_negative_response(UDS_SID_READ_DTC_INFO,
                               UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    sub_function = request[1] & 0x7F;  /* Mask suppress positive response bit */

    log_message("ReadDTCInformation: sub_function=0x%02X\n", sub_function);

    switch (sub_function) {
        case UDS_DTC_REPORT_NUMBER_BY_STATUS_MASK:  /* 0x01 */
            /*
             * reportNumberOfDTCByStatusMask
             * Request: [0x19] [0x01] [statusMask]
             * Response: [0x59] [0x01] [DTCStatusAvailabilityMask] [DTCFormatId] [DTCCountHigh] [DTCCountLow]
             */
            if (req_len < 3) {
                send_negative_response(UDS_SID_READ_DTC_INFO,
                                       UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
                return -1;
            }

            status_mask = request[2];
            log_message("ReadDTCInformation: Counting DTCs with status mask 0x%02X\n", status_mask);

            /* Count DTCs matching status mask */
            count = 0;
            for (i = 0; i < MAX_DTCS && dtc_storage[i].dtc_id != 0; i++) {
                if (dtc_storage[i].status & status_mask) {
                    count++;
                }
            }

            log_message("ReadDTCInformation: Found %d DTCs matching mask\n", count);

            /* Build response */
            response[0] = UDS_SID_READ_DTC_INFO + 0x40;  /* 0x59 */
            response[1] = sub_function;
            response[2] = 0xFF;  /* DTCStatusAvailabilityMask - all bits supported */
            response[3] = 0x01;  /* DTCFormatIdentifier - ISO 15031-6 */
            response[4] = (count >> 8) & 0xFF;  /* DTC count high byte */
            response[5] = count & 0xFF;         /* DTC count low byte */
            *resp_len = 6;
            return 0;

        case UDS_DTC_REPORT_BY_STATUS_MASK:  /* 0x02 */
            /*
             * reportDTCByStatusMask
             * Request: [0x19] [0x02] [statusMask]
             * Response: [0x59] [0x02] [DTCStatusAvailabilityMask] [DTC1_hi] [DTC1_mid] [DTC1_lo] [DTC1_status] ...
             */
            if (req_len < 3) {
                send_negative_response(UDS_SID_READ_DTC_INFO,
                                       UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
                return -1;
            }

            status_mask = request[2];
            log_message("ReadDTCInformation: Reporting DTCs with status mask 0x%02X\n", status_mask);

            /* Build response header */
            response[0] = UDS_SID_READ_DTC_INFO + 0x40;  /* 0x59 */
            response[1] = sub_function;
            response[2] = 0xFF;  /* DTCStatusAvailabilityMask */
            offset = 3;

            /* Add matching DTCs */
            for (i = 0; i < MAX_DTCS && dtc_storage[i].dtc_id != 0; i++) {
                if (dtc_storage[i].status & status_mask) {
                    /* Each DTC is 4 bytes: 3-byte DTC code + 1-byte status */
                    response[offset++] = (dtc_storage[i].dtc_id >> 16) & 0xFF;
                    response[offset++] = (dtc_storage[i].dtc_id >> 8) & 0xFF;
                    response[offset++] = dtc_storage[i].dtc_id & 0xFF;
                    response[offset++] = dtc_storage[i].status;

                    log_message("ReadDTCInformation: DTC 0x%06X status 0x%02X\n",
                                dtc_storage[i].dtc_id, dtc_storage[i].status);
                }
            }

            *resp_len = offset;
            return 0;

        case UDS_DTC_REPORT_SUPPORTED_DTC:  /* 0x0A */
            /*
             * reportSupportedDTC
             * Request: [0x19] [0x0A]
             * Response: [0x59] [0x0A] [DTCStatusAvailabilityMask] [DTC1_hi] [DTC1_mid] [DTC1_lo] [DTC1_status] ...
             */
            log_message("ReadDTCInformation: Reporting all supported DTCs\n");

            /* Build response header */
            response[0] = UDS_SID_READ_DTC_INFO + 0x40;  /* 0x59 */
            response[1] = sub_function;
            response[2] = 0xFF;  /* DTCStatusAvailabilityMask */
            offset = 3;

            /* Add all stored DTCs */
            for (i = 0; i < MAX_DTCS && dtc_storage[i].dtc_id != 0; i++) {
                response[offset++] = (dtc_storage[i].dtc_id >> 16) & 0xFF;
                response[offset++] = (dtc_storage[i].dtc_id >> 8) & 0xFF;
                response[offset++] = dtc_storage[i].dtc_id & 0xFF;
                response[offset++] = dtc_storage[i].status;

                log_message("ReadDTCInformation: DTC 0x%06X status 0x%02X\n",
                            dtc_storage[i].dtc_id, dtc_storage[i].status);
            }

            *resp_len = offset;
            return 0;

        default:
            log_message("ReadDTCInformation: Unsupported sub-function 0x%02X\n", sub_function);
            send_negative_response(UDS_SID_READ_DTC_INFO,
                                   UDS_NRC_SUBFUNCTION_NOT_SUPPORTED, response, resp_len);
            return -1;
    }
}
