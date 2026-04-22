/*
 * UDS Engine - Core state machine and request routing
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "uds_engine.h"

#define SESSION_TIMEOUT_SEC 5

/* External declaration for logging */
extern void log_message(const char *format, ...);

void uds_engine_init(uds_state_t *state) {
    memset(state, 0, sizeof(uds_state_t));
    state->session_type = UDS_SESSION_DEFAULT;
    state->security_state = UDS_SECURITY_LOCKED;
    state->security_attempts = 0;
    state->current_seed = 0;
    state->lockout_until = 0;
    state->transfer_active = 0;
    state->last_activity = time(NULL);
    state->invalid_session_transition = 0;
    state->session_established = 0;  /* No explicit session established yet */
}

static void send_negative_response(uint8_t sid, uint8_t nrc,
                                   uint8_t *response, size_t *resp_len) {
    response[0] = UDS_NEGATIVE_RESPONSE;
    response[1] = sid;
    response[2] = nrc;
    *resp_len = 3;
}

int uds_engine_process(uds_state_t *state, const uint8_t *request, size_t req_len,
                       uint8_t *response, size_t *resp_len) {
    uint8_t sid;

    if (req_len < 1) {
        send_negative_response(0x00, UDS_NRC_INCORRECT_MSG_LENGTH, response, resp_len);
        return -1;
    }

    state->last_activity = time(NULL);
    sid = request[0];

    log_message("UDS Request: SID=0x%02X, len=%zu\n", sid, req_len);

    /* Route to appropriate service handler */
    switch (sid) {
        case UDS_SID_DIAGNOSTIC_SESSION_CONTROL:
            return uds_service_diagnostic_session_control(state, request, req_len,
                                                          response, resp_len);

        case UDS_SID_SECURITY_ACCESS:
            return uds_service_security_access(state, request, req_len,
                                                response, resp_len);

        case UDS_SID_READ_DATA_BY_ID:
            return uds_service_read_data_by_id(state, request, req_len,
                                                response, resp_len);

        case UDS_SID_WRITE_DATA_BY_ID:
            return uds_service_write_data_by_id(state, request, req_len,
                                                 response, resp_len);

        case UDS_SID_REQUEST_DOWNLOAD:
            return uds_service_request_download(state, request, req_len,
                                                 response, resp_len);

        case UDS_SID_TRANSFER_DATA:
            return uds_service_transfer_data(state, request, req_len,
                                              response, resp_len);

        case UDS_SID_REQUEST_TRANSFER_EXIT:
            return uds_service_request_transfer_exit(state, request, req_len,
                                                      response, resp_len);

        case UDS_SID_ECU_RESET:
            return uds_service_ecu_reset(state, request, req_len, response, resp_len);

        case UDS_SID_READ_DTC_INFO:
            return uds_service_read_dtc_info(state, request, req_len, response, resp_len);

        case UDS_SID_TESTER_PRESENT:
            return uds_service_tester_present(state, request, req_len, response, resp_len);

        default:
            send_negative_response(sid, UDS_NRC_SERVICE_NOT_SUPPORTED, response, resp_len);
            return -1;
    }

    return 0;
}

void uds_engine_check_timeout(uds_state_t *state) {
    time_t now = time(NULL);

    if (state->session_type != UDS_SESSION_DEFAULT) {
        if (now - state->last_activity > SESSION_TIMEOUT_SEC) {
            log_message("Session timeout - returning to Default Session\n");
            state->session_type = UDS_SESSION_DEFAULT;
            state->security_state = UDS_SECURITY_LOCKED;
            state->security_attempts = 0;
            state->invalid_session_transition = 0;
            state->session_established = 0;
        }
    }
}
