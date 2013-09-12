/*********************************************************************
 * Copyright 2013 Cumulus Networks, Inc.  All rights reserved.
 *
 * ptm_timer.[ch] implement small-scape timerfd timers for use within PTMD.
 */
#ifndef _PTM_TIMER_H_
#define _PTM_TIMER_H_

/**
 * Routines that can hang and manage a set of timers off one kernel timerfd. The
 * timers are currently kept in a kvec. Insertion=O(1), Deletion=O(1), Expiry can
 * be non-deterministic as the timers aren't sorted. Works well for a few timers.
 * You would need to convert to a timer wheel if you want lots of timers.
 *
 * Usage:
 *    timer = cl_timer_create(T_BACKOFF_MAX);
 *    ...
 *    cl_timer_arm(timer, cb, 10, 5, T_UF_BACKOFF | T_UF_PERIOIDIC);
 *
 *    cl_timer_t *cb (cl_timer_t *t, void *c)
 *    {
 *        if (t == NULL) {
 *            <upper bound on timer value reached>
 *            <declare failure>
 *        }
 *        ...
 *        if (<condition satisfied>) {
 *            cl_timer_destroy(t);
 *            return (NULL);
 *        } else {
 *            <return so that timer gets rearmed >
 *            return (t);
 *        }
 *    }
 */

typedef struct _cl_timer_t_ cl_timer_t;

#define T_BACKOFF_MAX    180

#define T_UF_BACKOFF     (1 << 0)
#define T_UF_PERIOIDIC   (1 << 1)

/**
 * prototype for user callback function on timer expiry.
 * The callback can return the same timer back:
 *   - if the timer is set to expire periodically, it will be rearmed.
 *   - if it was a oneshot timer, it will be destroyed.
 * The user can also choose to destroy the timer by calling ptm_timer_destroy()
 *  (e.g. when the timer was set to be periodic and the user's requirements are
 *   satisfied after a few attempts). In this case, the user returns NULL.
 */
typedef cl_timer_t * (*cl_timer_action_cb) (cl_timer_t *, void *context);

int
cl_timer_arm(cl_timer_t         *timer,
	     cl_timer_action_cb cb,
	     uint32_t           delay,
	     uint32_t           interval,
	     uint32_t           flags);

void
cl_timer_destroy(cl_timer_t *timer);

cl_timer_t *
cl_timer_create(uint32_t);

int
cl_timer_expired(int fd, ptm_sockevent_e event, void *context);

int
cl_timer_init(ptm_globals_t *g);

#endif
