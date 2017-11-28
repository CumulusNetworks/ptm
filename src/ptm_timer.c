/* Copyright 2013,2014,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 */

#include <sys/timerfd.h>
#include <time.h>
#include <stdint.h>
#include "kvec.h"
#include "ptm_event.h"
#include "ptm_timer.h"
#include "log.h"

//#define DEBUG_TIMER

#define PTM_MIN_TIMER_EXPIRY_NSECS (50 * NSEC_PER_MSEC)
#define PTM_TIMER_EXPIRY_SKID_NSECS (10 * NSEC_PER_MSEC)

/* timer internal flags */
#define T_SF_ARMED      (1 << 0)
#define T_SF_DELETED    (1 << 1)

static void _timer_setfd(cl_timer_t *timer);
static void _update_cached_interval(cl_timer_t *timer);
static void _arm_timer(cl_timer_t *timer);

/**
 * The main structure representing each user timer.
 *
 * @exp: Next expiration time
 * @interval: timer duration set by user in NSECS
 * @context: user context that should be passed to the callback
 *           upon timer expiry.
 * @cb: user callback function to be called upon timer expiry
 * @user_flags: user specified flags (PERIODIC or PERSIST_SSHOT)
 * @state_flags: internal state of timer (ARMED or DELETED)
 * @num_expiries: track # of expirations
 * @pos: position within the kvec_t array
 */
struct _cl_timer_t_ {
    struct timespec     exp;
    struct timespec     interval;
    void                *context;
    cl_timer_action_cb  cb;
    uint16_t            user_flags;
    uint16_t            state_flags;
    uint32_t            num_expiries;
    int                 pos;
};

typedef struct {
    int                     timer_fd;
    int                     in_timer_loop;
    struct timespec         next_timer;
    struct timespec         loop_start;
    struct timespec         cached_interval;
    ptm_globals_t           *g;
    kvec_t(cl_timer_t *)    run_queue;
} cl_timer_globals_t;

cl_timer_globals_t ptm_tg;

/*
 * cl_timer_arm
 * This routine arms the timer and programs the timer_fd appropriately
 * @interval - has to be specified (secs or nsecs)
 * @flags - T_UF_PERIODIC/T_UF_PERSIST_SSHOT/T_UF_NSEC
 */
int
cl_timer_arm (cl_timer_t *timer,
              cl_timer_action_cb cb,
              uint64_t    interval,
              uint32_t    flags)
{

    if (timer == NULL) {
        return (0);
    }

    if ((timer->state_flags & T_SF_DELETED) ||
        (cb == NULL) ||
        (interval == 0)) {
        return (0);
    }

    if ((flags == 0) ||
        ((flags & (T_UF_PERIODIC | T_UF_PERSIST_SSHOT)) ==
                            (T_UF_PERIODIC | T_UF_PERSIST_SSHOT))) {
        /* flags clear or both flags set */
        return (0);
    }


    if (flags & T_UF_NSEC) {
        timer->interval.tv_sec = timer->interval.tv_nsec = 0;
        cl_add_time(&timer->interval, interval);
    } else {
        timer->interval.tv_sec = interval;
        timer->interval.tv_nsec = 0;
    }

    timer->user_flags |= flags;
    timer->cb = cb;

    /*
     * If the timer is not in the run queue at all, add it.
     */
    if (timer->pos == -1) {
        timer->pos = kv_size(ptm_tg.run_queue);
        kv_push(cl_timer_t *, ptm_tg.run_queue, timer);
    }

    _arm_timer(timer);

    if (ptm_tg.in_timer_loop) {
        _update_cached_interval(timer);
    } else {
        _timer_setfd(timer);
    }

    return (0);
}

void
cl_timer_destroy (cl_timer_t *timer)
{
    if (timer == NULL) {
        return;
    }

#ifdef DEBUG_TIMER
    DLOG("%s TIMER DEL pos %d size %d)\n", __FUNCTION__,
         timer->pos, (int)kv_size(ptm_tg.run_queue));
#endif

    /* mark this object as deleted for now
     * we will clean up during timer loop
     */
    timer->state_flags = 0;
    timer->state_flags |= T_SF_DELETED;
}

cl_timer_t *
cl_timer_create ()
{
    cl_timer_t *timer;

    timer = calloc(1, sizeof(cl_timer_t));
    if (timer) {
        timer->pos = -1;
    }
    return (timer);
}

static void
_arm_timer(cl_timer_t *timer)
{
    timer->state_flags |= T_SF_ARMED;
    cl_cur_time(&timer->exp);
    cl_add_time_ts(&timer->exp, &timer->interval);
}

static void
_update_cached_interval(cl_timer_t *timer)
{
    if (((ptm_tg.cached_interval.tv_sec == 0) &&
        (ptm_tg.cached_interval.tv_nsec == 0)) ||
        (cl_comp_time(&ptm_tg.cached_interval, &timer->interval) > 0)) {
            cl_cp_time(&ptm_tg.cached_interval, &timer->interval);
    }

    return;
}

static void
_timer_setfd(cl_timer_t *timer)
{
    struct itimerspec curr;
    struct timespec exp, now;
    struct timespec new_interval;
    int rc, set_fd = 0;;

    /*
     * If the timerfd is currently running, find out how long it would
     * take to expire. If the timer requires expiration before
     * that, we would need to adjust the timerfd settings.
     */
    rc = timerfd_gettime(ptm_tg.timer_fd, &curr);
    if (rc < 0) {
        ERRLOG("timerfd_gettime error (%s)\n", strerror(errno));
        return;
    }

    /* if we are within 50ms of expiration - skip */
    if ((curr.it_value.tv_sec == 0) &&
        (curr.it_value.tv_nsec) &&
        (curr.it_value.tv_nsec <= PTM_MIN_TIMER_EXPIRY_NSECS)) {
        return;
    }

    cl_cur_time(&now);

    if (timer == NULL) {
        /* called from loop context - assume that timerfd is NULL */
        cl_cp_time(&exp, &ptm_tg.loop_start);
        cl_add_time_ts(&exp, &ptm_tg.cached_interval);
        if (cl_comp_time(&now, &exp) > 0) {
            /* loop has taken too much time - cache interval has elapsed */
            new_interval.tv_sec = 0;
            new_interval.tv_nsec = PTM_MIN_TIMER_EXPIRY_NSECS;
        } else {
            /* update cache interval minus loop time */
            cl_diff_time_ts(&exp, &now, &new_interval);
        }
        set_fd = 1;
    } else if ((curr.it_value.tv_sec == 0) &&
               (curr.it_value.tv_nsec == 0)) {
        /* special case where timer_fd has gone to zero */

        /* one scenario is that a previous timer obj has expired
         * but we have not yet called the select loop
         * if there is more than 1 element (including this one)
         * in the timer array - thats our clue.
         * set the timer to a min value
         */
	    if (kv_size(ptm_tg.run_queue) > 1) {
            new_interval.tv_sec = 0;
            new_interval.tv_nsec = PTM_MIN_TIMER_EXPIRY_NSECS;
        } else {
            /* calculate new expiration time for our timer */
            cl_diff_time_ts(&timer->exp, &now, &new_interval);
        }
        set_fd = 1;
    } else {
        /* find the min(timer_fd , current timer) */
        cl_cp_time(&exp, &now);
        cl_add_time_ts(&exp, &curr.it_value);
        if (cl_comp_time(&exp, &timer->exp) > 0) {
            cl_diff_time_ts(&timer->exp, &now, &new_interval);
            set_fd = 1;
        }
    }

    if (set_fd) {

        cl_cp_time(&curr.it_value, &new_interval);

        cl_add_time(&curr.it_value, PTM_TIMER_EXPIRY_SKID_NSECS);

        /* keep a copy for debug */
        cl_cp_time(&ptm_tg.next_timer, &curr.it_value);

        rc = timerfd_settime(ptm_tg.timer_fd, 0, &curr, 0);
        if (rc < 0) {
            ERRLOG("timerfd_settime error %lu s %llu ns (%s)\n",
             (unsigned long)curr.it_value.tv_sec,
             (unsigned long long)curr.it_value.tv_nsec,
             strerror(errno));
            return;
        }
#ifdef DEBUG_TIMER
        DLOG("Set TIMER FD expiration %lu s %llu ns\n",
             (unsigned long)curr.it_value.tv_sec,
             (unsigned long long)curr.it_value.tv_nsec);
#endif
    }
}

static int
ptm_event_timer(int fd,
		  ptm_sockevent_e event,
		  void *context)
{
    cl_timer_t *qitem, *top;
    int i;
    struct timespec now;
    ssize_t s;
    uint64_t exp;

    s = read(fd, &exp, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        ERRLOG("%s: read error(%s)\n", __FUNCTION__, strerror(errno));
        return (-1);
    }
#ifdef DEBUG_TIMERWHEEL
    DLOG("%s INIT(exp %llu, queue size=%u)\n", __FUNCTION__, (unsigned long long) exp,
	(int)kv_size(ptm_tg.run_queue));
#endif // DEBUG_TIMERWHEEL

    cl_cur_time(&now);
    cl_cp_time(&ptm_tg.loop_start, &now);
    ptm_tg.in_timer_loop = 1;
    cl_clear_time(&ptm_tg.cached_interval);

    /* Go through each timer in the run queue
     * we go last to first, so that when we delete a timer
     * we replace it with a timer that has already been processed
     */
    for (i = (kv_size(ptm_tg.run_queue) - 1); i >= 0; i--) {
        qitem = kv_A(ptm_tg.run_queue, i);

        if (qitem->state_flags & T_SF_DELETED) {
#ifdef DEBUG_TIMERWHEEL
            DLOG("%s TIMER CLEANUP pos %d size %d)\n", __FUNCTION__,
                 qitem->pos, (int)kv_size(ptm_tg.run_queue));
#endif // DEBUG_TIMERWHEEL

            top = kv_pop(ptm_tg.run_queue);

            if (top != qitem) {
                /* this timer will get a chance to run in the next loop */
                top->pos = i;
                kv_A(ptm_tg.run_queue, i) = top;
            }

            /* paranoia - clear out the memory */
            memset(qitem, 0x00, sizeof(*qitem));
            free(qitem);
            continue;
        }

        if ((qitem->state_flags & T_SF_ARMED) == 0) {
#ifdef DEBUG_TIMERWHEEL
            DLOG("%s TIMER Not Armed pos %d size %d)\n", __FUNCTION__,
                 qitem->pos, (int)kv_size(ptm_tg.run_queue));
#endif // DEBUG_TIMERWHEEL
            continue;
        }

        /*
         * If now >= qitem.exp, it has stayed long enough in the queue
         * and it's time for expiry.
         */
        if (cl_comp_time(&now, &qitem->exp) >= 0) {
            if ((qitem->user_flags & T_UF_PERIODIC) == 0) {
                qitem->state_flags &= ~T_SF_ARMED;
            }
            qitem->num_expiries++;
            qitem->cb(qitem, qitem->context);
            /* periodic timers are auto-re-armed */
            if (((qitem->state_flags & T_SF_DELETED) == 0) &&
                (qitem->user_flags & T_UF_PERIODIC)) {
                _arm_timer(qitem);
                _update_cached_interval(qitem);
            }
        } else {
            _update_cached_interval(qitem);
        }
    }

    /* we have completed one loop - set the timer fd (if needed)*/
    ptm_tg.in_timer_loop = 0;
    if (ptm_tg.cached_interval.tv_sec ||
        ptm_tg.cached_interval.tv_nsec)
        _timer_setfd(NULL);

    return (0);
}

int
ptm_init_timer(ptm_globals_t *g)
{
    int fd;

    PTM_MODULE_INITIALIZE(g, TIMER_MODULE);
    PTM_MODULE_PROCESSCB(g, TIMER_MODULE) = ptm_event_timer;

    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        ERRLOG("timerfd_create error (%s)\n", strerror(errno));
        return (-1);
    }
    ptm_tg.g = g;
    ptm_tg.timer_fd = fd;
    PTM_MODULE_SET_FD(ptm_tg.g, fd, TIMER_MODULE, 0);

    PTM_MODULE_SET_STATE(g, TIMER_MODULE, MOD_STATE_INITIALIZED);
    return (0);
}
