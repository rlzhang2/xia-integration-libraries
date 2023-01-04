/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>

typedef enum {
    picoquic_newreno_alg_slow_start = 0,
    picoquic_newreno_alg_congestion_avoidance
} picoquic_newreno_alg_state_t;

#define NB_RTT_RENO 4

typedef struct st_picoquic_newreno_state_t {
    picoquic_newreno_alg_state_t alg_state;
    uint64_t residual_ack;
    uint64_t ssthresh;
    uint64_t recovery_start;
    uint64_t min_rtt;
    uint64_t last_rtt[NB_RTT_RENO];
    int nb_rtt;
} picoquic_newreno_state_t;

void picoquic_newreno_init(picoquic_path_t* path_x)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_newreno_state_t* nr_state = (picoquic_newreno_state_t*)malloc(sizeof(picoquic_newreno_state_t));

    if (nr_state != NULL) {
        memset(nr_state, 0, sizeof(picoquic_newreno_state_t));
        path_x->congestion_alg_state = (void*)nr_state;
        nr_state->alg_state = picoquic_newreno_alg_slow_start;
        nr_state->ssthresh = (uint64_t)((int64_t)-1);
        path_x->cwin = PICOQUIC_CWIN_INITIAL;
    }
    else {
        path_x->congestion_alg_state = NULL;
    }
}

/* The recovery state last 1 RTT, during which parameters will be frozen
 */
static void picoquic_newreno_enter_recovery(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_newreno_state_t* nr_state,
    uint64_t current_time)
{
    nr_state->ssthresh = path_x->cwin / 2;
    if (nr_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
        nr_state->ssthresh = PICOQUIC_CWIN_MINIMUM;
    }

    if (notification == picoquic_congestion_notification_timeout) {
        path_x->cwin = PICOQUIC_CWIN_MINIMUM;
        nr_state->alg_state = picoquic_newreno_alg_slow_start;
    } else {
        path_x->cwin = nr_state->ssthresh;
        nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
    }

    nr_state->recovery_start = current_time;

    nr_state->residual_ack = 0;


}

/*
 * Properly implementing New Reno requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
void picoquic_newreno_notify(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    uint64_t rtt_measurement,
    uint64_t nb_bytes_acknowledged,
    uint64_t lost_packet_number,
    uint64_t current_time)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(rtt_measurement);
    UNREFERENCED_PARAMETER(lost_packet_number);
#endif
    picoquic_newreno_state_t* nr_state = (picoquic_newreno_state_t*)path_x->congestion_alg_state;

    if (nr_state != NULL) {
        switch (notification) {
        case picoquic_congestion_notification_acknowledgement: {
            switch (nr_state->alg_state) {
            case picoquic_newreno_alg_slow_start:
                if (path_x->smoothed_rtt <= PICOQUIC_TARGET_RENO_RTT) {
                    path_x->cwin += nb_bytes_acknowledged;
                }
                else {
                    double delta = ((double)path_x->smoothed_rtt) / ((double)PICOQUIC_TARGET_RENO_RTT);
                    delta *= (double)nb_bytes_acknowledged;
                    path_x->cwin += (uint64_t)delta;
                }
                /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                if (path_x->cwin >= nr_state->ssthresh) {
                    nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
                }
                break;
            case picoquic_newreno_alg_congestion_avoidance:
            default: {
                uint64_t complete_delta = nb_bytes_acknowledged * path_x->send_mtu + nr_state->residual_ack;
                nr_state->residual_ack = complete_delta % path_x->cwin;
                path_x->cwin += complete_delta / path_x->cwin;
                break;
            }
            }
            break;
        }
        case picoquic_congestion_notification_ecn_ec:
        case picoquic_congestion_notification_repeat:
        case picoquic_congestion_notification_timeout:
            /* enter recovery */
            if (current_time - nr_state->recovery_start > path_x->smoothed_rtt) {
                picoquic_newreno_enter_recovery(path_x, notification, nr_state, current_time);
            }
            break;
        case picoquic_congestion_notification_spurious_repeat:
            if (current_time - nr_state->recovery_start < path_x->smoothed_rtt) {
                /* If spurious repeat of initial loss detected,
                 * exit recovery and reset threshold to pre-entry cwin.
                 */
                if (path_x->cwin < 2 * nr_state->ssthresh) {
                    path_x->cwin = 2 * nr_state->ssthresh;
                    nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
                }
            }
            break;
        case picoquic_congestion_notification_rtt_measurement:
            /* Using RTT increases as signal to get out of initial slow start */
            if (nr_state->alg_state == picoquic_newreno_alg_slow_start &&
                nr_state->ssthresh == (uint64_t)((int64_t)-1)) {
                uint64_t rolling_min;
                uint64_t delta_rtt;

                if (rtt_measurement < nr_state->min_rtt || nr_state->min_rtt == 0) {
                    nr_state->min_rtt = rtt_measurement;
                }

                if (nr_state->nb_rtt > NB_RTT_RENO) {
                    nr_state->nb_rtt = 0;
                }

                nr_state->last_rtt[nr_state->nb_rtt] = rtt_measurement;
                nr_state->nb_rtt++;

                rolling_min = nr_state->last_rtt[0];

                for (int i = 1; i < NB_RTT_RENO; i++) {
                    if (nr_state->last_rtt[i] == 0) {
                        break;
                    }
                    else if (nr_state->last_rtt[i] < rolling_min) {
                        rolling_min = nr_state->last_rtt[i];
                    }
                }

                delta_rtt = rolling_min - nr_state->min_rtt;
                if (delta_rtt * 4 > nr_state->min_rtt) {
                    /* RTT increased too much, get out of slow start! */
                    nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
                }
            }
            break;
        default:
            /* ignore */
            break;
        }
    }

    /* Compute pacing data */
    picoquic_update_pacing_data(path_x);
}

/* Release the state of the congestion control algorithm */
void picoquic_newreno_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

/* Definition record for the New Reno algorithm */

#define PICOQUIC_NEWRENO_ID 0x4E523838 /* NR88 */

picoquic_congestion_algorithm_t picoquic_newreno_algorithm_struct = {
    PICOQUIC_NEWRENO_ID,
    picoquic_newreno_init,
    picoquic_newreno_notify,
    picoquic_newreno_delete
};

picoquic_congestion_algorithm_t* picoquic_newreno_algorithm = &picoquic_newreno_algorithm_struct;
