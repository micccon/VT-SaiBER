#ifndef UDS_ENGINE_H
#define UDS_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* UDS Session Types */
#define UDS_SESSION_DEFAULT     0x01
#define UDS_SESSION_PROGRAMMING 0x02
#define UDS_SESSION_EXTENDED    0x03

/* UDS Security States */
#define UDS_SECURITY_LOCKED     0x00
#define UDS_SECURITY_UNLOCKED   0x01

/* UDS Service IDs */
#define UDS_SID_DIAGNOSTIC_SESSION_CONTROL  0x10
#define UDS_SID_ECU_RESET                   0x11
#define UDS_SID_READ_DTC_INFO               0x19
#define UDS_SID_READ_DATA_BY_ID             0x22
#define UDS_SID_SECURITY_ACCESS             0x27
#define UDS_SID_WRITE_DATA_BY_ID            0x2E
#define UDS_SID_REQUEST_DOWNLOAD            0x34
#define UDS_SID_TRANSFER_DATA               0x36
#define UDS_SID_REQUEST_TRANSFER_EXIT       0x37
#define UDS_SID_TESTER_PRESENT              0x3E

/* UDS Negative Response Codes */
#define UDS_NRC_GENERAL_REJECT              0x10
#define UDS_NRC_SERVICE_NOT_SUPPORTED       0x11
#define UDS_NRC_SUBFUNCTION_NOT_SUPPORTED   0x12
#define UDS_NRC_INCORRECT_MSG_LENGTH        0x13
#define UDS_NRC_CONDITIONS_NOT_CORRECT      0x22
#define UDS_NRC_REQUEST_SEQUENCE_ERROR      0x24
#define UDS_NRC_REQUEST_OUT_OF_RANGE        0x31
#define UDS_NRC_SECURITY_ACCESS_DENIED      0x33
#define UDS_NRC_INVALID_KEY                 0x35
#define UDS_NRC_EXCEEDED_ATTEMPTS           0x36
#define UDS_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED 0x70

/* Negative response SID */
#define UDS_NEGATIVE_RESPONSE               0x7F

/* UDS Engine State Structure */
typedef struct {
    uint8_t session_type;
    uint8_t security_state;
    uint8_t security_attempts;
    uint32_t current_seed;
    time_t lockout_until;           /* Timestamp when lockout expires */
    uint8_t transfer_active;
    uint32_t transfer_address;
    uint32_t transfer_size;
    uint8_t transfer_seq;
    time_t last_activity;
    int invalid_session_transition;  /* For V9 vulnerability */
    int session_established;         /* Track if Default session was explicitly established */
} uds_state_t;

/* Function prototypes - UDS Engine */
void uds_engine_init(uds_state_t *state);
int uds_engine_process(uds_state_t *state, const uint8_t *request, size_t req_len,
                       uint8_t *response, size_t *resp_len);
void uds_engine_check_timeout(uds_state_t *state);

/* Security Access constants */
#define UDS_SECURITY_XOR_KEY        0xCAFEBABE
#define UDS_SECURITY_MAX_ATTEMPTS   3
#define UDS_SECURITY_LOCKOUT_SEC    10

/* Security Access sub-functions */
#define UDS_SA_REQUEST_SEED         0x01
#define UDS_SA_SEND_KEY             0x02
#define UDS_SA_HIDDEN_BYPASS        0x05  /* V9 vulnerability - hidden bypass */

/* Data Identifier (DID) definitions */
#define UDS_DID_VIN                 0xF190  /* Vehicle Identification Number (read-only) */
#define UDS_DID_SYSTEM_NAME         0xF195  /* System Name (read-only) */
#define UDS_DID_CALIBRATION_DATA    0x0100  /* Calibration Data (read/write, requires security) */
#define UDS_DID_CONFIG_BLOCK        0x0200  /* Configuration Block (read/write, requires security) */

/* DID data sizes */
#define UDS_VIN_SIZE                17      /* Standard VIN length */
#define UDS_SYSTEM_NAME_SIZE        32      /* Max system name length */
#define UDS_CALIBRATION_DATA_SIZE   64      /* Calibration data buffer size */
#define UDS_CONFIG_BLOCK_SIZE       128     /* Configuration block buffer size */

/* Transfer service constants */
#define UDS_TRANSFER_MAX_SIZE       0x10000 /* Max 64KB transfer */
#define UDS_TRANSFER_BLOCK_SIZE     4096    /* Max block size per TransferData */
#define UDS_TRANSFER_STATE_IDLE     0x00
#define UDS_TRANSFER_STATE_DOWNLOAD 0x01
#define UDS_TRANSFER_STATE_COMPLETE 0x02

/* Function prototypes - UDS Services (uds_services.c) */
int uds_service_diagnostic_session_control(uds_state_t *state,
                                            const uint8_t *request, size_t req_len,
                                            uint8_t *response, size_t *resp_len);

int uds_service_security_access(uds_state_t *state,
                                 const uint8_t *request, size_t req_len,
                                 uint8_t *response, size_t *resp_len);

int uds_service_read_data_by_id(uds_state_t *state,
                                 const uint8_t *request, size_t req_len,
                                 uint8_t *response, size_t *resp_len);

int uds_service_write_data_by_id(uds_state_t *state,
                                  const uint8_t *request, size_t req_len,
                                  uint8_t *response, size_t *resp_len);

int uds_service_request_download(uds_state_t *state,
                                  const uint8_t *request, size_t req_len,
                                  uint8_t *response, size_t *resp_len);

int uds_service_transfer_data(uds_state_t *state,
                               const uint8_t *request, size_t req_len,
                               uint8_t *response, size_t *resp_len);

int uds_service_request_transfer_exit(uds_state_t *state,
                                       const uint8_t *request, size_t req_len,
                                       uint8_t *response, size_t *resp_len);

int uds_service_tester_present(uds_state_t *state,
                                const uint8_t *request, size_t req_len,
                                uint8_t *response, size_t *resp_len);

int uds_service_ecu_reset(uds_state_t *state,
                           const uint8_t *request, size_t req_len,
                           uint8_t *response, size_t *resp_len);

int uds_service_read_dtc_info(uds_state_t *state,
                               const uint8_t *request, size_t req_len,
                               uint8_t *response, size_t *resp_len);

/* ECU Reset sub-functions */
#define UDS_RESET_HARD          0x01  /* Hard reset */
#define UDS_RESET_KEY_OFF_ON    0x02  /* Key off/on reset */
#define UDS_RESET_SOFT          0x03  /* Soft reset */

/* Read DTC Information sub-functions */
#define UDS_DTC_REPORT_NUMBER_BY_STATUS_MASK        0x01
#define UDS_DTC_REPORT_BY_STATUS_MASK               0x02
#define UDS_DTC_REPORT_SUPPORTED_DTC                0x0A
#define UDS_DTC_REPORT_FIRST_FAILED_DTC             0x0B
#define UDS_DTC_REPORT_MOST_RECENT_FAILED_DTC       0x0E

/* DTC Status Mask bits */
#define UDS_DTC_STATUS_TEST_FAILED                  0x01
#define UDS_DTC_STATUS_TEST_FAILED_THIS_CYCLE       0x02
#define UDS_DTC_STATUS_PENDING                      0x04
#define UDS_DTC_STATUS_CONFIRMED                    0x08
#define UDS_DTC_STATUS_TEST_NOT_COMPLETED_SINCE_CLEAR 0x10
#define UDS_DTC_STATUS_TEST_FAILED_SINCE_CLEAR      0x20
#define UDS_DTC_STATUS_TEST_NOT_COMPLETED_THIS_CYCLE 0x40
#define UDS_DTC_STATUS_WARNING_INDICATOR            0x80

#endif /* UDS_ENGINE_H */
