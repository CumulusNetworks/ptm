#include <sys/timerfd.h>
#include <time.h>
#include <stdint.h>
#include "kvec.h"
#include "ptm_event.h"
#include "ptm_timer.h"
#include "log.h"

/*
 * addendum for exponential backoff - 1/2 * (2^c -1),
 * where c = #previous attempts
 */
#define T_BACKOFF_ELL(c)          (((1 << c) - 1) / 2)

#define T_NEXT_DELAY(t)                                  \
    ((((t)->user_flags & T_UF_BACKOFF) == 0) ?	         \
     (t)->interval :                                     \
     ((((t)->interval + T_BACKOFF_ELL((t)->num_expiries)) > (t)->maxsec) ?	\
      0 : ((t)->interval + T_BACKOFF_ELL((t)->num_expiries))))

#define T_ADJUST_DELAY(t, now)				\
    ((t)->delay - ((now).tv_sec - (t)->inq.tv_sec))

#define T_SF_ARMED (1 << 0)

/**
 * The main structure representing each user timer.
 *
 * @inq: how long has this timer been in the run queue?
 * @delay: the current set delay for the timer
 * @interval: if it's a periodic timer, what is the timer interval?
 * @context: user context that should be passed to the callback
 *           upon timer expiry.
 * @cb: user callback function to be called upon timer expiry
 * @user_flags: one or more of T_UF_* (ORed together).
 */
struct _cl_timer_t_ {
    struct timespec     inq;
    uint32_t            delay;
    uint32_t            interval;
    void                *context;
    cl_timer_action_cb  cb;
    uint16_t            user_flags;
    uint16_t            state_flags;
    uint32_t            num_expiries;
    int                 pos;
    uint32_t            maxsec;
};

typedef struct {
    int                  timer_fd;
    ptm_globals_t        *g;
    kvec_t(cl_timer_t *) run_queue;
} cl_timer_globals_t;

cl_timer_globals_t ptm_tg;

int
cl_timer_arm (cl_timer_t *timer,
	      cl_timer_action_cb cb,
	      uint32_t    delay,
	      uint32_t    interval,
	      uint32_t    flags)
{
    int rc;
    struct itimerspec curr, tobeset;

    if (timer == NULL) {
        return (0);
    }
    timer->delay = delay;
    timer->interval = interval;
    timer->user_flags |= flags;
    timer->cb = cb;

    /*
     * If the timer hasn't been armed -
     *   1) it has never been armed, or
     *   2) it expired and hasn't been armed back.
     * ARM it (set the flag) and take the current timestamp for inq.
     */
    if ((timer->state_flags & T_SF_ARMED) == 0) {
        DLOG("%s 1\n", __FUNCTION__);
        timer->state_flags |= T_SF_ARMED;
	clock_gettime(CLOCK_MONOTONIC, &timer->inq);
    }

    /*
     * If the timer is not in the run queue at all, add it.
     */
    if (timer->pos == -1) {
        timer->pos = kv_size(ptm_tg.run_queue);
        kv_push(cl_timer_t *, ptm_tg.run_queue, timer);
    }

    /*
     * If the timerfd is currently running, find out how long it would
     * take to expire. If the timer being added requires expiration before
     * that, we would need to adjust the timerfd settings.
     */
    rc = timerfd_gettime(ptm_tg.timer_fd, &curr);
    if (rc < 0) {
        ERRLOG("timerfd_gettime error (%s)\n", strerror(errno));
        return (-1);
    }

    /**
     * min(current timerfd expiry, init-delay for the timer being added.
     */
    memcpy(&tobeset, &curr, sizeof(struct itimerspec));
    tobeset.it_value.tv_sec = curr.it_value.tv_sec == 0 ? delay :
      (delay < curr.it_value.tv_sec ? delay : curr.it_value.tv_sec);
    rc = timerfd_settime(ptm_tg.timer_fd, 0, &tobeset, 0);
    if (rc < 0) {
        ERRLOG("timerfd_settime error (%s)\n", strerror(errno));
        return (-1);
    }
    return (0);
}

void
cl_timer_destroy (cl_timer_t *timer)
{
    cl_timer_t *repr;

    if (timer == NULL) {
        return;
    }
    DLOG("%s INIT(timer pos %d, queue size %d)\n", __FUNCTION__, timer->pos,
	(int)kv_size(ptm_tg.run_queue));

    /**
     * We need to remove this timer from run queue. Instead of creating a
     * hole in the vector, put the top item in its place.
     */
    if (timer->pos != -1) {
        repr = kv_pop(ptm_tg.run_queue);
	if (repr != timer) {
	    kv_A(ptm_tg.run_queue, timer->pos) = repr;
	    repr->pos = timer->pos;
	}
    }
    DLOG("%s END(queue size %d)\n", __FUNCTION__, (int)kv_size(ptm_tg.run_queue));
    free(timer);
}

cl_timer_t *
cl_timer_create (uint32_t maxsec)
{
    cl_timer_t *timer;

    timer = calloc(1, sizeof(cl_timer_t));
    if (timer) {
        timer->pos = -1;
	timer->maxsec = maxsec;
    }
    return (timer);
}

int
cl_timer_expired (int fd,
		  ptm_sockevent_e event,
		  void *context)
{
    cl_timer_t *qitem, *timer;
    int i;
    struct timespec now;
    ssize_t s;
    uint64_t exp;
    uint32_t delay;

    s = read(fd, &exp, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        ERRLOG("%s: read error(%s)\n", __FUNCTION__, strerror(errno));
        return (-1);
    }
    DLOG("%s INIT(exp %llu, queue size=%u)\n", __FUNCTION__, (unsigned long long) exp,
	(int)kv_size(ptm_tg.run_queue));
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Go through each timer in the run queue */
    for (i = (kv_size(ptm_tg.run_queue) - 1); i >= 0; i--) {
        qitem = kv_A(ptm_tg.run_queue, i);

	/*
	 * If (now - inqueue time) is greater than the timer's delay value,
	 * it has stayed long enough in the queue and it's time for expiry.
	 */
	if ((now.tv_sec - qitem->inq.tv_sec) >= qitem->delay) {
	    qitem->state_flags &= ~T_SF_ARMED;
	    qitem->num_expiries++;
	    timer = qitem->cb(qitem, qitem->context);
	    if (timer != NULL) {
	        if ((timer->user_flags & T_UF_PERIOIDIC) != 0) {
  		    delay = T_NEXT_DELAY(timer);
		    /*
		     * delay==0 means the timer has reached its upper bound.
		     * destroy it. Call the user callback so the user knows.
		     */
		    if (delay == 0) {
			DLOG("Destroying timer because delay == 0\n");
		        timer->cb(NULL, timer->context);
		        cl_timer_destroy(timer);
		    } else {
			DLOG("Arming with timer with delay %d\n", delay);
		        cl_timer_arm(timer, timer->cb, T_NEXT_DELAY(timer),
				     timer->interval, timer->user_flags);
		    }
		} else {
		    cl_timer_destroy(timer);
		}
	    }
	} else {
	    /*
	     * If it's not the timer's time yet..., readjust the new expiry
	     * time if we need to.
	     */
  	    cl_timer_arm(qitem, qitem->cb, T_ADJUST_DELAY(qitem, now),
			 qitem->interval, qitem->user_flags);
	}
	if (i == 0) {
	  break;
	}
    }
    return (0);
}

int
cl_timer_init (ptm_globals_t *g)
{
    int fd;

    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        ERRLOG("timerfd_create error (%s)\n", strerror(errno));
	return (-1);
    }
    ptm_tg.g = g;
    ptm_tg.timer_fd = fd;
    PTM_MODULE_SET_FD(ptm_tg.g, fd, TIMER_MODULE);
    return (0);
}
