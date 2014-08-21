/* Copyright 2013 Cumulus Networks, Inc.  All rights reserved. */

#ifndef _PTM_TIMER_H_
#define _PTM_TIMER_H_

/**
 * Routines that can hang and manage a set of timers off one kernel timerfd. The
 * timers are currently kept in a kvec. Insertion=O(1), Deletion=O(1), Expiry can
 * be non-deterministic as the timers aren't sorted. Works well for a few timers.
 * You would need to convert to a timer wheel if you want lots of timers.
 *
 * Usage:
 *    timer = cl_timer_create();
 *    ...
 *    cl_timer_arm(timer, cb, 5, T_UF_PERIOIDIC);
 *
 *    void cb (cl_timer_t *t, void *c)
 *    {
 *        if (<condition satisfied>) {
 *            cl_timer_destroy(t);
 *        }
 *    }
 */

typedef struct _cl_timer_t_ cl_timer_t;

#define T_UF_PERIOIDIC         (1 << 0)
#define T_UF_PERSIST_SSHOT     (1 << 1)
#define T_UF_NSEC              (1 << 2)

/**
 * prototype for user callback function on timer expiry.
 * The user destroy the timer by calling ptm_timer_destroy()
 *  (e.g. when the timer was set to be periodic and the user's requirements are
 *   satisfied after a few attempts). In this case, the user returns NULL.
 */
typedef void (*cl_timer_action_cb) (cl_timer_t *, void *context);

int
cl_timer_arm(cl_timer_t         *timer,
	     cl_timer_action_cb cb,
	     uint64_t           interval,
	     uint32_t           flags);

void
cl_timer_destroy(cl_timer_t *timer);

cl_timer_t *
cl_timer_create();

int
cl_timer_expired(int fd, ptm_sockevent_e event, void *context);

int
ptm_init_timer(ptm_globals_t *g);


/*-------------------------*/
/* some helper inlines */

/* Parameters used to convert the timespec values: */
#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL


static __always_inline uint32_t
__iter_div_u64_rem(uint64_t dividend, uint32_t divisor, uint64_t *remainder)
{
    uint32_t ret = 0;

    while (dividend >= divisor) {
        /* The following asm() prevents the compiler from
           optimising this loop into a modulo operation.  */
        asm("" : "+rm"(dividend));

        dividend -= divisor;
        ret++;
    }

    *remainder = dividend;

    return ret;
}

/**
 * timespec_add_ns - Adds nanoseconds to a timespec
 * @a:          pointer to timespec to be incremented
 * @ns:         unsigned nanoseconds value to be added
 *
 * This must always be inlined because its used from the x86-64 vdso,
 * which cannot call other kernel functions.
 */
static __always_inline void timespec_add_ns(struct timespec *a, uint64_t ns)
{
    a->tv_sec += __iter_div_u64_rem(a->tv_nsec + ns, NSEC_PER_SEC, &ns);
    a->tv_nsec = ns;
}

/**
 * timespec_to_ns - Convert timespec to nanoseconds
 * @ts:         pointer to the timespec variable to be converted
 *
 * Returns the scalar nanosecond representation of the timespec
 * parameter.
 */
static inline int64_t timespec_to_ns(const struct timespec *ts)
{
    return ((int64_t) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

/*
 * lhs < rhs:  return <0
 * lhs == rhs: return 0
 * lhs > rhs:  return >0
 */
static inline int timespec_compare(const struct timespec *lhs, const struct timespec *rhs)
{
    if (lhs->tv_sec < rhs->tv_sec)
        return -1;
    if (lhs->tv_sec > rhs->tv_sec)
        return 1;
    return lhs->tv_nsec - rhs->tv_nsec;
}


static inline void cl_cur_time(struct timespec *ts)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
    return;
}

static inline void cl_add_time(struct timespec *ts, uint64_t ns)
{
    return(timespec_add_ns(ts, ns));
}

static inline void cl_diff_time_ts(struct timespec *lhs, struct timespec *rhs,
                                   struct timespec *diff)
{
    diff->tv_sec = lhs->tv_sec - rhs->tv_sec;
    if (lhs->tv_nsec >= rhs->tv_nsec) {
        diff->tv_nsec = lhs->tv_nsec - rhs->tv_nsec;
    } else {
        --diff->tv_sec;
        diff->tv_nsec = (NSEC_PER_SEC - rhs->tv_nsec + lhs->tv_nsec);
    }
}

static inline void cl_add_time_ts(struct timespec *ts1, struct timespec *ts2)
{
    ts1->tv_sec += ts2->tv_sec;
    timespec_add_ns(ts1, ts2->tv_nsec);
}

static inline int cl_comp_time(struct timespec *ts1, struct timespec *ts2)
{
    return(timespec_compare(ts1, ts2));
}

static inline void cl_cp_time(struct timespec *ts1, struct timespec *ts2)
{
    ts1->tv_sec = ts2->tv_sec;
    ts1->tv_nsec = ts2->tv_nsec;
}

static inline void cl_clear_time(struct timespec *ts)
{
    ts->tv_sec = ts->tv_nsec = 0;
}

/*-------------------------*/
#endif
