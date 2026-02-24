#ifndef CAN_LISTENER_H
#define CAN_LISTENER_H

#include <pthread.h>
#include "uds_engine.h"

/* CAN configuration */
#define CAN_INTERFACE "vcan0"

/* UDS CAN IDs */
#define CAN_ID_UDS_BROADCAST 0x7DF
#define CAN_ID_UDS_ECU_MIN   0x7E0
#define CAN_ID_UDS_ECU_MAX   0x7E7
#define CAN_ID_UDS_RESPONSE  0x7E8

/* Thread argument structure for passing state and mutex */
typedef struct {
    uds_state_t *state;
    pthread_mutex_t *state_mutex;
} can_listener_args_t;

/* Function prototypes */
int can_listener_init(void);
void *can_listener_thread(void *arg);
void can_listener_stop(void);

#endif /* CAN_LISTENER_H */
