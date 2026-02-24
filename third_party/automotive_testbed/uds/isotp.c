/*
 * ISO-TP (ISO 15765-2) Transport Layer Implementation
 *
 * Handles segmentation and reassembly of UDS messages over CAN.
 * Implements full Flow Control with Block Size (BS) and Separation Time (STmin).
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "isotp.h"

/* External declaration for logging */
extern void log_message(const char *format, ...);

void isotp_init(isotp_session_t *session) {
    memset(session, 0, sizeof(isotp_session_t));
    session->rx_next_seq = 0;
    session->tx_next_seq = 1;
    session->fc_block_size = 0;  /* No limit */
    session->fc_stmin = 0;       /* No minimum separation time */
    session->state = ISOTP_STATE_IDLE;
    session->transfer_in_progress = 0;
    session->fc_required = 0;
    session->fc_wait_count = 0;

    /* Legacy fields */
    session->next_seq = 0;
    session->block_size = 0;
    session->stmin = 0;
}

void isotp_reset(isotp_session_t *session) {
    isotp_init(session);
}

uint32_t isotp_get_stmin_us(uint8_t stmin) {
    /*
     * STmin encoding per ISO 15765-2:
     * 0x00-0x7F: Separation time in milliseconds (0-127 ms)
     * 0x80-0xF0: Reserved
     * 0xF1-0xF9: Separation time in 100 microseconds (100-900 us)
     * 0xFA-0xFF: Reserved
     */
    if (stmin <= 0x7F) {
        return (uint32_t)stmin * 1000;  /* ms to us */
    } else if (stmin >= 0xF1 && stmin <= 0xF9) {
        return (uint32_t)(stmin - 0xF0) * 100;  /* 100us units */
    } else {
        /* Reserved values - use maximum allowed (127 ms) */
        return 127000;
    }
}

int isotp_needs_flow_control(isotp_session_t *session) {
    return session->fc_required;
}

int isotp_receive_frame(isotp_session_t *session, const uint8_t *frame, size_t frame_len,
                        uint8_t *complete_msg, size_t *msg_len) {
    uint8_t pci_type;
    size_t data_len;
    uint8_t seq_num;

    if (frame_len < 1) {
        return ISOTP_ERROR;
    }

    pci_type = frame[0] & 0xF0;

    switch (pci_type) {
        case ISOTP_PCI_SF:
            /* Single Frame - complete message in one frame */
            data_len = frame[0] & 0x0F;
            if (data_len > frame_len - 1 || data_len > ISOTP_MAX_MSG_SIZE) {
                return ISOTP_ERROR;
            }
            memcpy(complete_msg, &frame[1], data_len);
            *msg_len = data_len;
            session->state = ISOTP_STATE_IDLE;
            log_message("ISO-TP: Received Single Frame, len=%zu\n", data_len);
            return ISOTP_COMPLETE;  /* Complete message */

        case ISOTP_PCI_FF:
            /* First Frame - start of multi-frame message */
            if (frame_len < 2) {
                return ISOTP_ERROR;
            }
            session->rx_expected_len = ((frame[0] & 0x0F) << 8) | frame[1];
            if (session->rx_expected_len > ISOTP_MAX_MSG_SIZE) {
                log_message("ISO-TP: Message too large (%zu > %d)\n",
                           session->rx_expected_len, ISOTP_MAX_MSG_SIZE);
                return ISOTP_ERROR;
            }
            data_len = (frame_len > 2) ? frame_len - 2 : 0;
            if (data_len > 6) data_len = 6;  /* Max 6 bytes in FF */
            memcpy(session->rx_buffer, &frame[2], data_len);
            session->rx_buffer_len = data_len;
            session->rx_next_seq = 1;
            session->state = ISOTP_STATE_RECEIVING;
            session->transfer_in_progress = 1;
            session->fc_required = 1;  /* Need to send FC after receiving FF */
            session->last_frame_time = time(NULL);

            /* Legacy fields */
            session->expected_len = session->rx_expected_len;
            session->buffer_len = session->rx_buffer_len;
            memcpy(session->buffer, session->rx_buffer, session->rx_buffer_len);
            session->next_seq = 1;

            log_message("ISO-TP: Received First Frame, expected=%zu, need FC\n",
                       session->rx_expected_len);
            return ISOTP_NEED_FC;  /* Need to send Flow Control */

        case ISOTP_PCI_CF:
            /* Consecutive Frame */
            if (session->state != ISOTP_STATE_RECEIVING) {
                log_message("ISO-TP: Unexpected CF, not in receiving state\n");
                return ISOTP_ERROR;
            }
            if (!session->transfer_in_progress) {
                return ISOTP_ERROR;
            }
            seq_num = frame[0] & 0x0F;
            if (seq_num != session->rx_next_seq) {
                log_message("ISO-TP: Sequence error, expected=%d got=%d\n",
                           session->rx_next_seq, seq_num);
                session->state = ISOTP_STATE_IDLE;
                session->transfer_in_progress = 0;
                return ISOTP_ERROR;
            }
            data_len = frame_len - 1;
            if (session->rx_buffer_len + data_len > session->rx_expected_len) {
                data_len = session->rx_expected_len - session->rx_buffer_len;
            }
            memcpy(&session->rx_buffer[session->rx_buffer_len], &frame[1], data_len);
            session->rx_buffer_len += data_len;
            session->rx_next_seq = (session->rx_next_seq + 1) & 0x0F;
            session->last_frame_time = time(NULL);

            /* Update legacy fields */
            session->buffer_len = session->rx_buffer_len;
            memcpy(session->buffer, session->rx_buffer, session->rx_buffer_len);
            session->next_seq = session->rx_next_seq;

            if (session->rx_buffer_len >= session->rx_expected_len) {
                /* Complete message */
                memcpy(complete_msg, session->rx_buffer, session->rx_buffer_len);
                *msg_len = session->rx_buffer_len;
                session->state = ISOTP_STATE_IDLE;
                session->transfer_in_progress = 0;
                log_message("ISO-TP: Message complete, len=%zu\n", *msg_len);
                return ISOTP_COMPLETE;
            }
            return ISOTP_OK;  /* Need more frames */

        case ISOTP_PCI_FC:
            /* Flow Control - process on sender side */
            return isotp_process_flow_control(session, frame, frame_len);

        default:
            log_message("ISO-TP: Unknown PCI type 0x%02X\n", pci_type);
            return ISOTP_ERROR;
    }
}

int isotp_process_flow_control(isotp_session_t *session, const uint8_t *frame, size_t frame_len) {
    uint8_t fc_status;

    if (frame_len < 3) {
        log_message("ISO-TP: FC frame too short\n");
        return ISOTP_ERROR;
    }

    fc_status = frame[0] & 0x0F;
    session->fc_block_size = frame[1];
    session->fc_stmin = frame[2];
    session->fc_status = fc_status;

    switch (fc_status) {
        case ISOTP_FC_CTS:
            /* Clear To Send - continue transmission */
            session->blocks_sent = 0;
            session->fc_wait_count = 0;
            if (session->state == ISOTP_STATE_WAIT_FC || session->state == ISOTP_STATE_FC_WAIT) {
                session->state = ISOTP_STATE_SENDING;
            }
            log_message("ISO-TP: FC CTS received, BS=%d, STmin=%d\n",
                       session->fc_block_size, session->fc_stmin);
            return ISOTP_OK;

        case ISOTP_FC_WAIT:
            /* Wait - peer needs time, retry later */
            session->fc_wait_count++;
            if (session->fc_wait_count > ISOTP_MAX_FC_WAIT) {
                log_message("ISO-TP: Too many FC Wait frames, aborting\n");
                session->state = ISOTP_STATE_IDLE;
                session->transfer_in_progress = 0;
                return ISOTP_ERROR;
            }
            session->state = ISOTP_STATE_FC_WAIT;
            session->fc_wait_start = time(NULL);
            log_message("ISO-TP: FC Wait received (%d/%d)\n",
                       session->fc_wait_count, ISOTP_MAX_FC_WAIT);
            return ISOTP_FC_WAIT;

        case ISOTP_FC_OVERFLOW:
            /* Overflow - peer cannot receive message, abort */
            log_message("ISO-TP: FC Overflow received, aborting\n");
            session->state = ISOTP_STATE_IDLE;
            session->transfer_in_progress = 0;
            return ISOTP_FC_OVERFLOW;

        default:
            log_message("ISO-TP: Unknown FC status 0x%02X\n", fc_status);
            return ISOTP_ERROR;
    }
}

int isotp_start_send(isotp_session_t *session, const uint8_t *msg, size_t msg_len,
                     uint8_t *first_frame, size_t *frame_len) {
    size_t copy_len;

    if (msg_len > ISOTP_MAX_MSG_SIZE) {
        return ISOTP_ERROR;
    }

    /* Store message in TX buffer */
    memcpy(session->tx_buffer, msg, msg_len);
    session->tx_buffer_len = msg_len;

    if (msg_len <= 7) {
        /* Single Frame */
        first_frame[0] = (uint8_t)(ISOTP_PCI_SF | msg_len);
        memcpy(&first_frame[1], msg, msg_len);
        *frame_len = msg_len + 1;
        session->state = ISOTP_STATE_IDLE;
        log_message("ISO-TP: Sending Single Frame, len=%zu\n", msg_len);
        return ISOTP_COMPLETE;
    }

    /* First Frame - multi-frame transfer */
    first_frame[0] = ISOTP_PCI_FF | ((msg_len >> 8) & 0x0F);
    first_frame[1] = msg_len & 0xFF;
    copy_len = 6;
    if (copy_len > msg_len) copy_len = msg_len;
    memcpy(&first_frame[2], msg, copy_len);
    *frame_len = 8;  /* FF is always 8 bytes */

    session->tx_offset = copy_len;
    session->tx_next_seq = 1;
    session->blocks_sent = 0;
    session->state = ISOTP_STATE_WAIT_FC;
    session->transfer_in_progress = 1;
    session->last_frame_time = time(NULL);

    log_message("ISO-TP: Sending First Frame, total=%zu, waiting for FC\n", msg_len);
    return ISOTP_OK;  /* Wait for Flow Control */
}

int isotp_get_next_cf(isotp_session_t *session, uint8_t *frame, size_t *frame_len) {
    size_t copy_len;

    /* Check if we're in the right state */
    if (session->state != ISOTP_STATE_SENDING) {
        if (session->state == ISOTP_STATE_WAIT_FC) {
            return ISOTP_FC_WAIT;  /* Need to wait for FC */
        }
        return ISOTP_ERROR;
    }

    /* Check if transfer is complete */
    if (session->tx_offset >= session->tx_buffer_len) {
        session->state = ISOTP_STATE_IDLE;
        session->transfer_in_progress = 0;
        return ISOTP_COMPLETE;
    }

    /* Check Block Size limit */
    if (session->fc_block_size > 0 && session->blocks_sent >= session->fc_block_size) {
        /* Need another FC before continuing */
        session->state = ISOTP_STATE_WAIT_FC;
        session->last_frame_time = time(NULL);
        log_message("ISO-TP: Block complete (%d frames), waiting for FC\n", session->blocks_sent);
        return ISOTP_FC_WAIT;
    }

    /* Build Consecutive Frame */
    frame[0] = ISOTP_PCI_CF | session->tx_next_seq;
    copy_len = session->tx_buffer_len - session->tx_offset;
    if (copy_len > 7) copy_len = 7;
    memcpy(&frame[1], &session->tx_buffer[session->tx_offset], copy_len);
    *frame_len = copy_len + 1;

    session->tx_offset += copy_len;
    session->tx_next_seq = (session->tx_next_seq + 1) & 0x0F;
    session->blocks_sent++;
    session->last_frame_time = time(NULL);

    /* Check if transfer is now complete */
    if (session->tx_offset >= session->tx_buffer_len) {
        session->state = ISOTP_STATE_IDLE;
        session->transfer_in_progress = 0;
        log_message("ISO-TP: Send complete, total=%zu\n", session->tx_buffer_len);
        return ISOTP_COMPLETE;
    }

    return ISOTP_OK;
}

int isotp_send_message(const uint8_t *msg, size_t msg_len,
                       uint8_t *frames, size_t *num_frames) {
    size_t offset = 0;
    size_t frame_idx = 0;
    uint8_t *frame;
    size_t copy_len;
    uint8_t seq = 1;

    if (msg_len <= 7) {
        /* Single Frame */
        frame = &frames[frame_idx * CAN_MAX_DATA_LEN];
        frame[0] = (uint8_t)(ISOTP_PCI_SF | msg_len);
        memcpy(&frame[1], msg, msg_len);
        *num_frames = 1;
        return ISOTP_OK;
    }

    /* First Frame */
    frame = &frames[frame_idx * CAN_MAX_DATA_LEN];
    frame[0] = ISOTP_PCI_FF | ((msg_len >> 8) & 0x0F);
    frame[1] = msg_len & 0xFF;
    copy_len = 6;
    memcpy(&frame[2], msg, copy_len);
    offset = copy_len;
    frame_idx++;

    /* Consecutive Frames */
    while (offset < msg_len) {
        frame = &frames[frame_idx * CAN_MAX_DATA_LEN];
        frame[0] = ISOTP_PCI_CF | seq;
        copy_len = msg_len - offset;
        if (copy_len > 7) copy_len = 7;
        memcpy(&frame[1], &msg[offset], copy_len);
        offset += copy_len;
        seq = (seq + 1) & 0x0F;
        frame_idx++;
    }

    *num_frames = frame_idx;
    return ISOTP_OK;
}

int isotp_create_flow_control(uint8_t status, uint8_t block_size, uint8_t stmin,
                              uint8_t *frame, size_t *frame_len) {
    frame[0] = ISOTP_PCI_FC | status;
    frame[1] = block_size;
    frame[2] = stmin;
    /* Pad to 8 bytes for CAN frame */
    memset(&frame[3], 0xCC, 5);  /* 0xCC is common padding in CAN */
    *frame_len = 8;
    log_message("ISO-TP: Creating FC frame, status=%d, BS=%d, STmin=%d\n",
               status, block_size, stmin);
    return ISOTP_OK;
}

int isotp_check_timeout(isotp_session_t *session) {
    time_t now;
    time_t elapsed;

    if (!session->transfer_in_progress && session->state == ISOTP_STATE_IDLE) {
        return ISOTP_OK;
    }

    now = time(NULL);
    elapsed = now - session->last_frame_time;

    switch (session->state) {
        case ISOTP_STATE_RECEIVING:
            /* N_Cr timeout - waiting for next CF */
            if (elapsed > (ISOTP_N_Cr / 1000)) {
                log_message("ISO-TP: N_Cr timeout (%ld s > %d ms)\n",
                           (long)elapsed, ISOTP_N_Cr);
                session->state = ISOTP_STATE_IDLE;
                session->transfer_in_progress = 0;
                return ISOTP_TIMEOUT;
            }
            break;

        case ISOTP_STATE_SENDING:
            /* N_As timeout - waiting for frame transmission complete */
            if (elapsed > (ISOTP_N_As / 1000)) {
                log_message("ISO-TP: N_As timeout\n");
                session->state = ISOTP_STATE_IDLE;
                session->transfer_in_progress = 0;
                return ISOTP_TIMEOUT;
            }
            break;

        case ISOTP_STATE_WAIT_FC:
            /* N_Bs timeout - waiting for Flow Control */
            if (elapsed > (ISOTP_N_Bs / 1000)) {
                log_message("ISO-TP: N_Bs timeout waiting for FC\n");
                session->state = ISOTP_STATE_IDLE;
                session->transfer_in_progress = 0;
                return ISOTP_TIMEOUT;
            }
            break;

        case ISOTP_STATE_FC_WAIT:
            /* Waiting after FC Wait - use N_Bs as timeout */
            if (elapsed > (ISOTP_N_Bs / 1000)) {
                log_message("ISO-TP: Timeout after FC Wait\n");
                session->state = ISOTP_STATE_IDLE;
                session->transfer_in_progress = 0;
                return ISOTP_TIMEOUT;
            }
            break;

        default:
            break;
    }

    return ISOTP_OK;
}
