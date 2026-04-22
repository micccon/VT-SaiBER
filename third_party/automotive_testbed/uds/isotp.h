#ifndef ISOTP_H
#define ISOTP_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* ISO-TP Frame Types (PCI - Protocol Control Information) */
#define ISOTP_PCI_SF  0x00  /* Single Frame */
#define ISOTP_PCI_FF  0x10  /* First Frame */
#define ISOTP_PCI_CF  0x20  /* Consecutive Frame */
#define ISOTP_PCI_FC  0x30  /* Flow Control */

/* Flow Control Status */
#define ISOTP_FC_CTS      0x00  /* Clear To Send */
#define ISOTP_FC_WAIT     0x01  /* Wait */
#define ISOTP_FC_OVERFLOW 0x02  /* Overflow/Abort */

/* ISO-TP Timing Parameters (in milliseconds) */
#define ISOTP_N_As  1000  /* Transmitter: Time for transmission to CAN */
#define ISOTP_N_Ar  1000  /* Receiver: Time for transmission to CAN */
#define ISOTP_N_Bs  1000  /* Transmitter: Time until FC received */
#define ISOTP_N_Br  1000  /* Receiver: Time until FC sent */
#define ISOTP_N_Cs  1000  /* Transmitter: Time until next CF sent */
#define ISOTP_N_Cr  1000  /* Receiver: Time until next CF received */

/* Maximum message size */
#define ISOTP_MAX_MSG_SIZE 4095
#define CAN_MAX_DATA_LEN   8

/* ISO-TP Transfer State */
typedef enum {
    ISOTP_STATE_IDLE,
    ISOTP_STATE_RECEIVING,      /* Receiving multi-frame message */
    ISOTP_STATE_SENDING,        /* Sending multi-frame message */
    ISOTP_STATE_WAIT_FC,        /* Waiting for Flow Control */
    ISOTP_STATE_FC_WAIT         /* Received FC with Wait status */
} isotp_state_t;

/* ISO-TP Session Structure */
typedef struct {
    /* Receive buffer */
    uint8_t rx_buffer[ISOTP_MAX_MSG_SIZE];
    size_t rx_buffer_len;
    size_t rx_expected_len;
    uint8_t rx_next_seq;

    /* Transmit buffer */
    uint8_t tx_buffer[ISOTP_MAX_MSG_SIZE];
    size_t tx_buffer_len;
    size_t tx_offset;
    uint8_t tx_next_seq;

    /* Flow control parameters (received from peer) */
    uint8_t fc_block_size;       /* BS: 0 = no limit, >0 = max frames before FC */
    uint8_t fc_stmin;            /* STmin: separation time in ms (0-127) or us (0xF1-0xF9) */
    uint8_t fc_status;           /* Last received FC status */
    uint8_t blocks_sent;         /* Frames sent in current block */
    uint8_t fc_wait_count;       /* Number of consecutive FC Wait received */

    /* State machine */
    isotp_state_t state;
    int transfer_in_progress;
    int fc_required;             /* Need to send FC after FF */

    /* Timing (using time_t for simplicity) */
    time_t last_frame_time;
    time_t fc_wait_start;

    /* Legacy fields for compatibility */
    uint8_t buffer[ISOTP_MAX_MSG_SIZE];
    size_t buffer_len;
    size_t expected_len;
    uint8_t next_seq;
    uint8_t block_size;
    uint8_t stmin;
} isotp_session_t;

/* Maximum consecutive FC Wait frames before abort */
#define ISOTP_MAX_FC_WAIT 10

/* Return codes */
#define ISOTP_OK            0   /* Success, need more frames */
#define ISOTP_COMPLETE      1   /* Message complete */
#define ISOTP_ERROR        -1   /* Error occurred */
#define ISOTP_NEED_FC      -2   /* Need to send Flow Control */
#define ISOTP_FC_WAIT      -3   /* FC Wait received, retry later */
#define ISOTP_FC_OVERFLOW  -4   /* FC Overflow received, abort */
#define ISOTP_TIMEOUT      -5   /* Timeout occurred */

/* Function prototypes */
void isotp_init(isotp_session_t *session);

/* Receive a single CAN frame and reassemble */
int isotp_receive_frame(isotp_session_t *session, const uint8_t *frame, size_t frame_len,
                        uint8_t *complete_msg, size_t *msg_len);

/* Process received Flow Control frame (for sender side) */
int isotp_process_flow_control(isotp_session_t *session, const uint8_t *frame, size_t frame_len);

/* Segment a message into CAN frames (simple version) */
int isotp_send_message(const uint8_t *msg, size_t msg_len,
                       uint8_t *frames, size_t *num_frames);

/* Start sending a multi-frame message (stateful version) */
int isotp_start_send(isotp_session_t *session, const uint8_t *msg, size_t msg_len,
                     uint8_t *first_frame, size_t *frame_len);

/* Get next consecutive frame to send (checks FC parameters) */
int isotp_get_next_cf(isotp_session_t *session, uint8_t *frame, size_t *frame_len);

/* Create a Flow Control frame */
int isotp_create_flow_control(uint8_t status, uint8_t block_size, uint8_t stmin,
                              uint8_t *frame, size_t *frame_len);

/* Check for transfer timeout */
int isotp_check_timeout(isotp_session_t *session);

/* Get STmin value in microseconds */
uint32_t isotp_get_stmin_us(uint8_t stmin);

/* Check if session needs to send Flow Control */
int isotp_needs_flow_control(isotp_session_t *session);

/* Reset session state */
void isotp_reset(isotp_session_t *session);

#endif /* ISOTP_H */
