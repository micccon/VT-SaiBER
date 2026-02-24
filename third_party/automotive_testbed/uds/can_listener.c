/*
 * CAN Listener - CAN socket listener on vcan0 for UDS protocol
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <errno.h>

#include "can_listener.h"
#include "isotp.h"
#include "uds_engine.h"

static int can_fd = -1;
static volatile int can_running = 1;

/* External declaration for logging */
extern void log_message(const char *format, ...);

int can_listener_init(void) {
    struct sockaddr_can addr;
    struct ifreq ifr;

    can_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can_fd < 0) {
        log_message("CAN: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, CAN_INTERFACE, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(can_fd, SIOCGIFINDEX, &ifr) < 0) {
        log_message("CAN: ioctl() failed for %s: %s\n", CAN_INTERFACE, strerror(errno));
        close(can_fd);
        can_fd = -1;
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(can_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_message("CAN: bind() failed: %s\n", strerror(errno));
        close(can_fd);
        can_fd = -1;
        return -1;
    }

    log_message("CAN: Listening on %s\n", CAN_INTERFACE);
    return 0;
}

static int is_uds_request(canid_t can_id) {
    /* Check for UDS broadcast or ECU-specific request IDs */
    if (can_id == CAN_ID_UDS_BROADCAST) {
        return 1;
    }
    if (can_id >= CAN_ID_UDS_ECU_MIN && can_id <= CAN_ID_UDS_ECU_MAX) {
        return 1;
    }
    return 0;
}

static void send_can_frame(const struct can_frame *frame) {
    if (can_fd >= 0) {
        write(can_fd, frame, sizeof(*frame));
    }
}

static void send_flow_control(uint8_t status, uint8_t block_size, uint8_t stmin) {
    struct can_frame fc_frame;
    size_t fc_len;

    fc_frame.can_id = CAN_ID_UDS_RESPONSE;
    isotp_create_flow_control(status, block_size, stmin, fc_frame.data, &fc_len);
    fc_frame.can_dlc = (unsigned char)fc_len;

    log_message("CAN: Sending Flow Control status=%d BS=%d STmin=%d\n",
                status, block_size, stmin);
    send_can_frame(&fc_frame);
}

static void send_uds_response(isotp_session_t *tx_session, const uint8_t *response, size_t resp_len) {
    struct can_frame response_frame;
    uint8_t first_frame[CAN_MAX_DATA_LEN];
    size_t frame_len;
    int ret;

    response_frame.can_id = CAN_ID_UDS_RESPONSE;

    /* Start sending the response */
    ret = isotp_start_send(tx_session, response, resp_len, first_frame, &frame_len);

    if (ret == ISOTP_COMPLETE) {
        /* Single frame - send immediately */
        memcpy(response_frame.data, first_frame, frame_len);
        response_frame.can_dlc = (unsigned char)frame_len;
        send_can_frame(&response_frame);
    } else if (ret == ISOTP_OK) {
        /* Multi-frame - send first frame, will need to handle FC later */
        memcpy(response_frame.data, first_frame, frame_len);
        response_frame.can_dlc = (unsigned char)frame_len;
        send_can_frame(&response_frame);
        /* Note: In a full implementation, we would need to handle incoming FC
         * and send consecutive frames. For simplicity, we assume single-frame responses. */
    }
}

void *can_listener_thread(void *arg) {
    can_listener_args_t *args = (can_listener_args_t *)arg;
    uds_state_t *state = args->state;
    pthread_mutex_t *state_mutex = args->state_mutex;
    struct can_frame frame;
    isotp_session_t rx_session;
    isotp_session_t tx_session;
    uint8_t complete_msg[ISOTP_MAX_MSG_SIZE];
    size_t msg_len;
    uint8_t uds_response[ISOTP_MAX_MSG_SIZE];
    size_t uds_resp_len;
    ssize_t nbytes;
    int ret;

    isotp_init(&rx_session);
    isotp_init(&tx_session);

    while (can_running) {
        nbytes = read(can_fd, &frame, sizeof(frame));
        if (nbytes < 0) {
            if (can_running) {
                log_message("CAN: read() failed: %s\n", strerror(errno));
            }
            continue;
        }

        if ((size_t)nbytes < sizeof(frame)) {
            continue;
        }

        /* Only process UDS request CAN IDs */
        if (!is_uds_request(frame.can_id)) {
            continue;
        }

        log_message("CAN: Received frame ID=0x%03X len=%d\n",
                    frame.can_id, frame.can_dlc);

        /* Process through ISO-TP layer */
        ret = isotp_receive_frame(&rx_session, frame.data, frame.can_dlc,
                                  complete_msg, &msg_len);

        switch (ret) {
            case ISOTP_COMPLETE:
                /* Complete message received, process through UDS engine (thread-safe) */
                uds_resp_len = 0;
                pthread_mutex_lock(state_mutex);
                uds_engine_process(state, complete_msg, msg_len,
                                  uds_response, &uds_resp_len);
                pthread_mutex_unlock(state_mutex);

                /* Send response via ISO-TP */
                if (uds_resp_len > 0) {
                    send_uds_response(&tx_session, uds_response, uds_resp_len);
                }

                /* Reset ISO-TP session for next message */
                isotp_reset(&rx_session);
                break;

            case ISOTP_NEED_FC:
                /* Received First Frame, need to send Flow Control */
                /* Send CTS (Clear To Send) with no block limit and no delay */
                send_flow_control(ISOTP_FC_CTS, 0, 0);
                rx_session.fc_required = 0;
                break;

            case ISOTP_OK:
                /* Need more frames, continue waiting */
                break;

            case ISOTP_ERROR:
            default:
                /* Error occurred, reset session */
                log_message("CAN: ISO-TP error, resetting session\n");
                isotp_reset(&rx_session);
                break;
        }

        /* Check for ISO-TP timeout */
        if (isotp_check_timeout(&rx_session) == ISOTP_TIMEOUT) {
            log_message("CAN: ISO-TP timeout, resetting session\n");
            isotp_reset(&rx_session);
        }

        /* Check for UDS session timeout */
        pthread_mutex_lock(state_mutex);
        uds_engine_check_timeout(state);
        pthread_mutex_unlock(state_mutex);
    }

    return NULL;
}

void can_listener_stop(void) {
    can_running = 0;
    if (can_fd >= 0) {
        close(can_fd);
        can_fd = -1;
    }
}
