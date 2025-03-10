/*
   Unix SMB/CIFS implementation.

   generalised event loop handling

   INTERNAL STRUCTS. THERE ARE NO API GUARANTEES.
   External users should only ever have to include this header when
   implementing new tevent backends.

   Copyright (C) Stefan Metzmacher 2005-2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

struct tevent_req {
	/**
	 * @brief What to do on completion
	 *
	 * This is used for the user of an async request, fn is called when
	 * the request completes, either successfully or with an error.
	 */
	struct {
		/**
		 * @brief Completion function
		 * Completion function, to be filled by the API user
		 */
		tevent_req_fn fn;
		/**
		 * @brief Private data for the completion function
		 */
		void *private_data;
		/**
		 * @brief  The completion function name, for flow tracing.
		 */
		const char *fn_name;
	} async;

	/**
	 * @brief Private state pointer for the actual implementation
	 *
	 * The implementation doing the work for the async request needs to
	 * keep around current data like for example a fd event. The user of
	 * an async request should not touch this.
	 */
	void *data;

	/**
	 * @brief A function to overwrite the default print function
	 *
	 * The implementation doing the work may want to implement a
	 * custom function to print the text representation of the async
	 * request.
	 */
	tevent_req_print_fn private_print;

	/**
	 * @brief A function to cancel the request
	 *
	 * The implementation might want to set a function
	 * that is called when the tevent_req_cancel() function
	 * was called.
	 */
	struct {
		tevent_req_cancel_fn fn;
		const char *fn_name;
	} private_cancel;

	/**
	 * @brief A function to cleanup the request
	 *
	 * The implementation might want to set a function
	 * that is called before the tevent_req_done() and tevent_req_error()
	 * trigger the callers callback function.
	 */
	struct {
		tevent_req_cleanup_fn fn;
		const char *fn_name;
		enum tevent_req_state state;
	} private_cleanup;

	/**
	 * @brief Internal state of the request
	 *
	 * Callers should only access this via functions and never directly.
	 */
	struct {
		/**
		 * @brief The talloc type of the data pointer
		 *
		 * This is filled by the tevent_req_create() macro.
		 *
		 * This for debugging only.
		 */
		const char *private_type;

		/**
		 * @brief The location where the request was created
		 *
		 * This uses the __location__ macro via the tevent_req_create()
		 * macro.
		 *
		 * This for debugging only.
		 */
		const char *create_location;

		/**
		 * @brief The location where the request was finished
		 *
		 * This uses the __location__ macro via the tevent_req_done(),
		 * tevent_req_error() or tevent_req_nomem() macro.
		 *
		 * This for debugging only.
		 */
		const char *finish_location;

		/**
		 * @brief The location where the request was canceled
		 *
		 * This uses the __location__ macro via the
		 * tevent_req_cancel() macro.
		 *
		 * This for debugging only.
		 */
		const char *cancel_location;

		/**
		 * @brief The external state - will be queried by the caller
		 *
		 * While the async request is being processed, state will remain in
		 * TEVENT_REQ_IN_PROGRESS. A request is finished if
		 * req->state>=TEVENT_REQ_DONE.
		 */
		enum tevent_req_state state;

		/**
		 * @brief status code when finished
		 *
		 * This status can be queried in the async completion function. It
		 * will be set to 0 when everything went fine.
		 */
		uint64_t error;

		/**
		 * @brief the immediate event used by tevent_req_post
		 *
		 */
		struct tevent_immediate *trigger;

		/**
		 * @brief An event context which will be used to
		 *        defer the _tevent_req_notify_callback().
		 */
		struct tevent_context *defer_callback_ev;

		/**
		 * @brief the timer event if tevent_req_set_endtime was used
		 *
		 */
		struct tevent_timer *timer;

		/**
		 * @brief The place where profiling data is kept
		 */
		struct tevent_req_profile *profile;

		size_t call_depth;
	} internal;
};

struct tevent_req_profile {
	struct tevent_req_profile *prev, *next;
	struct tevent_req_profile *parent;
	const char *req_name;
	pid_t pid;
	const char *start_location;
	struct timeval start_time;
	const char *stop_location;
	struct timeval stop_time;
	enum tevent_req_state state;
	uint64_t user_error;
	struct tevent_req_profile *subprofiles;
};

struct tevent_fd {
	struct tevent_fd *prev, *next;
	struct tevent_context *event_ctx;
	struct tevent_wrapper_glue *wrapper;
	bool busy;
	bool destroyed;
	int fd;
	uint16_t flags; /* see TEVENT_FD_* flags */
	tevent_fd_handler_t handler;
	tevent_fd_close_fn_t close_fn;
	/* this is private for the specific handler */
	void *private_data;
	/* this is for debugging only! */
	const char *handler_name;
	const char *location;
	/* this is private for the events_ops implementation */
	uint64_t additional_flags;
	void *additional_data;
	/* custom tag that can be set by caller */
	uint64_t tag;
	struct tevent_fd_mpx {
		struct tevent_fd_mpx *prev, *next;
		struct tevent_fd *fde;
		struct tevent_fd *primary;
		struct tevent_fd_mpx *list;
		uint16_t total_flags;
		bool has_mpx;
	} mpx;
};

struct tevent_timer {
	struct tevent_timer *prev, *next;
	struct tevent_context *event_ctx;
	struct tevent_wrapper_glue *wrapper;
	bool busy;
	bool destroyed;
	struct timeval next_event;
	tevent_timer_handler_t handler;
	/* this is private for the specific handler */
	void *private_data;
	/* this is for debugging only! */
	const char *handler_name;
	const char *location;
	/* this is private for the events_ops implementation */
	void *additional_data;
	/* custom tag that can be set by caller */
	uint64_t tag;
};

struct tevent_immediate {
	struct tevent_immediate *prev, *next;
	struct tevent_context *event_ctx;
	struct tevent_wrapper_glue *wrapper;
	bool busy;
	bool destroyed;
	struct tevent_context *detach_ev_ctx;
	tevent_immediate_handler_t handler;
	/* this is private for the specific handler */
	void *private_data;
	/* this is for debugging only! */
	const char *handler_name;
	const char *create_location;
	const char *schedule_location;
	/* this is private for the events_ops implementation */
	void (*cancel_fn)(struct tevent_immediate *im);
	void *additional_data;
	/* custom tag that can be set by caller */
	uint64_t tag;
};

struct tevent_signal {
	struct tevent_signal *prev, *next;
	struct tevent_context *event_ctx;
	struct tevent_wrapper_glue *wrapper;
	bool busy;
	bool destroyed;
	int signum;
	int sa_flags;
	tevent_signal_handler_t handler;
	/* this is private for the specific handler */
	void *private_data;
	/* this is for debugging only! */
	const char *handler_name;
	const char *location;
	/* this is private for the events_ops implementation */
	void *additional_data;
	/* custom tag that can be set by caller */
	uint64_t tag;
};

struct tevent_threaded_context {
	struct tevent_threaded_context *next, *prev;

#ifdef HAVE_PTHREAD
	pthread_mutex_t event_ctx_mutex;
#endif
	struct tevent_context *event_ctx;
};

struct tevent_debug_ops {
	enum tevent_debug_level max_level;
	void (*debug)(void *context, enum tevent_debug_level level,
		      const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3,0);
	void *context;
};

void tevent_debug(struct tevent_context *ev, enum tevent_debug_level level,
		  const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);
#define TEVENT_DEBUG(__ev, __level, __fmt, ...) do { \
	if (unlikely((__ev) != NULL && \
		     (__level) <= (__ev)->debug_ops.max_level)) \
	{ \
		tevent_debug((__ev), (__level), (__fmt), __VA_ARGS__); \
	} \
} while(0)

void tevent_abort(struct tevent_context *ev, const char *reason);

void tevent_common_check_double_free(TALLOC_CTX *ptr, const char *reason);

struct tevent_context {
	/* the specific events implementation */
	const struct tevent_ops *ops;

	/*
	 * The following three pointers are queried on every loop_once
	 * in the order in which they appear here. Not measured, but
	 * hopefully putting them at the top together with "ops"
	 * should make tevent a *bit* more cache-friendly than before.
	 */

	/* list of signal events - used by common code */
	struct tevent_signal *signal_events;

	/* List of threaded job indicators */
	struct tevent_threaded_context *threaded_contexts;

	/* list of immediate events - used by common code */
	struct tevent_immediate *immediate_events;

	/* list of fd events - used by common code */
	struct tevent_fd *fd_events;

	/* list of timed events - used by common code */
	struct tevent_timer *timer_events;

	/* List of scheduled immediates */
	pthread_mutex_t scheduled_mutex;
	struct tevent_immediate *scheduled_immediates;

	/* this is private for the events_ops implementation */
	void *additional_data;

	/* pipe hack used with signal handlers */
	struct tevent_fd *wakeup_fde;
	int wakeup_fd;		/* fd to write into */
#ifndef HAVE_EVENT_FD
	int wakeup_read_fd;
#endif

	/* debugging operations */
	struct tevent_debug_ops debug_ops;

	/* info about the nesting status */
	struct {
		bool allowed;
		uint32_t level;
		tevent_nesting_hook hook_fn;
		void *hook_private;
	} nesting;

	struct {
		struct {
			tevent_trace_callback_t callback;
			void *private_data;
		} point;

		struct {
			tevent_trace_fd_callback_t callback;
			void *private_data;
		} fde;

		struct {
			tevent_trace_signal_callback_t callback;
			void *private_data;
		} se;

		struct {
			tevent_trace_timer_callback_t callback;
			void *private_data;
		} te;

		struct {
			tevent_trace_immediate_callback_t callback;
			void *private_data;
		} im;

		struct {
			tevent_trace_queue_callback_t callback;
			void *private_data;
		} qe;
	} tracing;

	struct {
		/*
		 * This is used on the main event context
		 */
		struct tevent_wrapper_glue *list;

		/*
		 * This is used on the wrapper event context
		 */
		struct tevent_wrapper_glue *glue;
	} wrapper;

	/*
	 * an optimization pointer into timer_events
	 * used by used by common code via
	 * tevent_common_add_timer_v2()
	 */
	struct tevent_timer *last_zero_timer;
	struct timeval wait_timeout;

#ifdef HAVE_PTHREAD
	struct tevent_context *prev, *next;
#endif
};

int tevent_common_context_destructor(struct tevent_context *ev);
int tevent_common_loop_wait(struct tevent_context *ev,
			    const char *location);

struct tevent_common_fd_buf {
	char buf[128];
};

const char *tevent_common_fd_str(struct tevent_common_fd_buf *buf,
				 const char *description,
				 const struct tevent_fd *fde);

int tevent_common_fd_destructor(struct tevent_fd *fde);
struct tevent_fd *tevent_common_add_fd(struct tevent_context *ev,
				       TALLOC_CTX *mem_ctx,
				       int fd,
				       uint16_t flags,
				       tevent_fd_handler_t handler,
				       void *private_data,
				       const char *handler_name,
				       const char *location);
void tevent_common_fd_set_close_fn(struct tevent_fd *fde,
				   tevent_fd_close_fn_t close_fn);
uint16_t tevent_common_fd_get_flags(struct tevent_fd *fde);
void tevent_common_fd_set_flags(struct tevent_fd *fde, uint16_t flags);
int tevent_common_invoke_fd_handler(struct tevent_fd *fde, uint16_t flags,
				    bool *removed);

struct tevent_timer *tevent_common_add_timer(struct tevent_context *ev,
					     TALLOC_CTX *mem_ctx,
					     struct timeval next_event,
					     tevent_timer_handler_t handler,
					     void *private_data,
					     const char *handler_name,
					     const char *location);
struct tevent_timer *tevent_common_add_timer_v2(struct tevent_context *ev,
						TALLOC_CTX *mem_ctx,
					        struct timeval next_event,
					        tevent_timer_handler_t handler,
					        void *private_data,
					        const char *handler_name,
					        const char *location);
struct timeval tevent_common_loop_timer_delay(struct tevent_context *);

/* timeout values for poll(2) / epoll_wait(2) */
static inline bool tevent_common_no_timeout(const struct timeval *tv)
{
	if ((tv->tv_sec == 0) && (tv->tv_usec == INT32_MAX)) {
		/*
		 * This is special from
		 * tevent_context_set_wait_timeout(0)
		 */
		return true;
	}
	return false;
}
static inline int tevent_common_timeout_msec(const struct timeval *tv)
{
	if (tv->tv_sec == INT32_MAX) {
		return -1;
	}
	if (tevent_common_no_timeout(tv)) {
		/*
		 * This is special from
		 * tevent_context_set_wait_timeout(0)
		 */
		return 0;
	}
	return ((tv->tv_usec + 999) / 1000) + (tv->tv_sec * 1000);
}

int tevent_common_invoke_timer_handler(struct tevent_timer *te,
				       struct timeval current_time,
				       bool *removed);

void tevent_common_schedule_immediate(struct tevent_immediate *im,
				      struct tevent_context *ev,
				      tevent_immediate_handler_t handler,
				      void *private_data,
				      const char *handler_name,
				      const char *location);
int tevent_common_invoke_immediate_handler(struct tevent_immediate *im,
					   bool *removed);
bool tevent_common_loop_immediate(struct tevent_context *ev);
void tevent_common_threaded_activate_immediate(struct tevent_context *ev);

bool tevent_common_have_events(struct tevent_context *ev);
int tevent_common_wakeup_init(struct tevent_context *ev);
int tevent_common_wakeup_fd(int fd);
int tevent_common_wakeup(struct tevent_context *ev);

struct tevent_signal *tevent_common_add_signal(struct tevent_context *ev,
					       TALLOC_CTX *mem_ctx,
					       int signum,
					       int sa_flags,
					       tevent_signal_handler_t handler,
					       void *private_data,
					       const char *handler_name,
					       const char *location);
int tevent_common_check_signal(struct tevent_context *ev);
void tevent_cleanup_pending_signal_handlers(struct tevent_signal *se);
int tevent_common_invoke_signal_handler(struct tevent_signal *se,
					int signum, int count, void *siginfo,
					bool *removed);

struct tevent_context *tevent_wrapper_main_ev(struct tevent_context *ev);

struct tevent_wrapper_ops;

struct tevent_wrapper_glue {
	struct tevent_wrapper_glue *prev, *next;
	struct tevent_context *wrap_ev;
	struct tevent_context *main_ev;
	bool busy;
	bool destroyed;
	const struct tevent_wrapper_ops *ops;
	void *private_state;
};

void tevent_wrapper_push_use_internal(struct tevent_context *ev,
				      struct tevent_wrapper_glue *wrapper);
void tevent_wrapper_pop_use_internal(const struct tevent_context *__ev_ptr,
				     struct tevent_wrapper_glue *wrapper);

bool tevent_standard_init(void);
bool tevent_poll_init(void);
bool tevent_poll_event_add_fd_internal(struct tevent_context *ev,
				       struct tevent_fd *fde);
bool tevent_poll_mt_init(void);
#ifdef HAVE_EPOLL
bool tevent_epoll_init(void);
void tevent_epoll_set_panic_fallback(struct tevent_context *ev,
			bool (*panic_fallback)(struct tevent_context *ev,
					       bool replay));
#endif

static inline void tevent_thread_call_depth_notify(
			enum tevent_thread_call_depth_cmd cmd,
			struct tevent_req *req,
			size_t depth,
			const char *fname)
{
	if (tevent_thread_call_depth_state_g.cb != NULL) {
		tevent_thread_call_depth_state_g.cb(
			tevent_thread_call_depth_state_g.cb_private,
			cmd,
			req,
			depth,
			fname);
	}
}

void tevent_trace_point_callback(struct tevent_context *ev,
				 enum tevent_trace_point);

void tevent_trace_fd_callback(struct tevent_context *ev,
			      struct tevent_fd *fde,
			      enum tevent_event_trace_point);

void tevent_trace_signal_callback(struct tevent_context *ev,
				  struct tevent_signal *se,
				  enum tevent_event_trace_point);

void tevent_trace_timer_callback(struct tevent_context *ev,
				 struct tevent_timer *te,
				 enum tevent_event_trace_point);

void tevent_trace_immediate_callback(struct tevent_context *ev,
				     struct tevent_immediate *im,
				     enum tevent_event_trace_point);

void tevent_trace_queue_callback(struct tevent_context *ev,
				 struct tevent_queue_entry *qe,
				 enum tevent_event_trace_point);

#include "tevent_dlinklist.h"

static inline void tevent_common_fd_mpx_reinit(struct tevent_fd *fde)
{
	fde->mpx = (struct tevent_fd_mpx) { .fde = fde, };
}

static inline void tevent_common_fd_disarm(struct tevent_fd *fde)
{
	if (fde->event_ctx != NULL) {
		tevent_trace_fd_callback(fde->event_ctx, fde,
					 TEVENT_EVENT_TRACE_DETACH);
		DLIST_REMOVE(fde->event_ctx->fd_events, fde);
		fde->event_ctx = NULL;
	}
	tevent_common_fd_mpx_reinit(fde);
	fde->wrapper = NULL;
}

/*
 * tevent_common_fd_mpx_primary() returns the fde that is responsible
 * for the low level state.
 *
 * By default (when there's no multiplexing) it just returns 'any_fde'.
 *
 * Note it always returns a valid pointer.
 */
static inline
struct tevent_fd *tevent_common_fd_mpx_primary(struct tevent_fd *any_fde)
{
	struct tevent_fd *primary = NULL;

	if (any_fde->mpx.primary != NULL) {
		primary = any_fde->mpx.primary;
	} else {
		primary = any_fde;
	}

	return primary;
}

/*
 * tevent_common_fd_mpx_update_flags() needs to be called
 * if update_fde->flags has changed. It is needed in
 * order to let tevent_common_fd_mpx_flags() return a valid
 * result.
 */
static inline
void tevent_common_fd_mpx_update_flags(struct tevent_fd *update_fde)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(update_fde);
	struct tevent_fd_mpx *mpx = NULL;
	uint16_t new_total_flags = 0;

	if (!primary->mpx.has_mpx) {
		primary->mpx.total_flags = primary->flags;
		return;
	}

	for (mpx = primary->mpx.list; mpx != NULL; mpx = mpx->next) {
		struct tevent_fd *mpx_fde = mpx->fde;
		/* we don't care that mpx_fde might be == primary */
		new_total_flags |= mpx_fde->flags;
	}

	primary->mpx.total_flags = new_total_flags;
}

/*
 * tevent_common_fd_mpx_flags() return the effective flags
 * (TEVEND_FD_*) of the primary fde and all multiplexed fdes.
 *
 * Valid after tevent_common_fd_mpx_update_flags() was called
 */
static inline
uint16_t tevent_common_fd_mpx_flags(struct tevent_fd *any_fde)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(any_fde);

	return primary->mpx.total_flags;
}

/*
 * tevent_common_fd_mpx_clear_writeable() clears TEVENT_FD_WRITE
 * from all fdes belonging together.
 */
static inline
void tevent_common_fd_mpx_clear_writeable(struct tevent_fd *any_fde)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(any_fde);
	struct tevent_fd_mpx *mpx = NULL;

	primary->flags &= ~TEVENT_FD_WRITE;

	for (mpx = primary->mpx.list; mpx != NULL; mpx = mpx->next) {
		struct tevent_fd *mpx_fde = mpx->fde;
		/* we don't care that mpx_fde might be == primary */
		mpx_fde->flags &= ~TEVENT_FD_WRITE;
	}

	primary->mpx.total_flags &= ~TEVENT_FD_WRITE;
}

/*
 * tevent_common_fd_mpx_additional_flags() modifies
 * fde->additional_flags for all fdes belonging together.
 */
static inline
void tevent_common_fd_mpx_additional_flags(struct tevent_fd *any_fde,
					   uint64_t clear_flags,
					   uint64_t add_flags)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(any_fde);
	struct tevent_fd_mpx *mpx = NULL;

	primary->additional_flags &= ~clear_flags;
	primary->additional_flags |= add_flags;

	for (mpx = primary->mpx.list; mpx != NULL; mpx = mpx->next) {
		struct tevent_fd *mpx_fde = mpx->fde;
		/* we don't care that mpx_fde might be == primary */
		mpx_fde->additional_flags &= ~clear_flags;
		mpx_fde->additional_flags |= add_flags;
	}
}

/*
 * tevent_common_fd_mpx_disarm_all() detaches
 * all fdes currently belonging together from each other
 * and also from the tevent_context, which means their
 * handler will never be called again.
 */
static inline
void tevent_common_fd_mpx_disarm_all(struct tevent_fd *any_fde)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(any_fde);
	struct tevent_fd_mpx *mpx = NULL, *next = NULL;

	for (mpx = primary->mpx.list; mpx != NULL; mpx = next) {
		struct tevent_fd *mpx_fde = mpx->fde;

		next = mpx->next;
		DLIST_REMOVE(primary->mpx.list, mpx);

		if (mpx_fde == primary) {
			/* primary is handled below */
			continue;
		}

		tevent_common_fd_disarm(mpx_fde);
	}

	tevent_common_fd_disarm(primary);
}

/*
 * tevent_common_fd_mpx_select() selects the handler that
 * should be called for the given low level event.
 *
 * Note it's important to pass the primary fde!
 */
static inline
struct tevent_fd *tevent_common_fd_mpx_select(struct tevent_fd *primary,
					      uint16_t flags,
					      bool got_error)
{
	struct tevent_fd_mpx *mpx = NULL;
	struct tevent_fd *selected = NULL;

	/* optimize for the single event case. */
	if (!primary->mpx.has_mpx) {
		/*
		 * If we got an error, we won't report it if
		 * the caller only asked for TEVENT_FD_WRITE.
		 */
		if (got_error &&
		    !(primary->flags & (TEVENT_FD_READ|TEVENT_FD_ERROR)))
		{
			return NULL;
		}

		if (flags & primary->flags) {
			return primary;
		}

		return NULL;
	}

	for (mpx = primary->mpx.list; mpx != NULL; mpx = mpx->next) {
		struct tevent_fd *mpx_fde = mpx->fde;

		/*
		 * If we got an error, we won't report it if
		 * the caller only asked for TEVENT_FD_WRITE.
		 */
		if (got_error &&
		    !(mpx_fde->flags & (TEVENT_FD_READ|TEVENT_FD_ERROR)))
		{
			continue;
		}

		if (flags & mpx_fde->flags) {
			selected = mpx_fde;
			break;
		}
	}

	if (selected == NULL) {
		return NULL;
	}

	/*
	 * Maintain fairness and demote the just selected fde
	 */
	DLIST_DEMOTE_SHORT(primary->mpx.list, &selected->mpx);
	return selected;
}

/*
 * tevent_common_fd_mpx_add() searches for an existing (active) fde
 * for the same low level fd and adds the given 'add_fde'
 * as multiplexed to the found fde.
 *
 * If another fde was found it is returned.
 * NULL is returned to indicate no match
 */
static inline
struct tevent_fd *tevent_common_fd_mpx_add(struct tevent_fd *add_fde)
{
	struct tevent_context *ev = add_fde->event_ctx;
	struct tevent_fd *add_primary = tevent_common_fd_mpx_primary(add_fde);
	uint16_t add_flags = tevent_common_fd_mpx_flags(add_primary);
	struct tevent_fd *mpx_fde = NULL;
	struct tevent_fd *mpx_primary = NULL;
	struct tevent_fd_mpx *tmp = NULL;
	struct tevent_fd_mpx *next = NULL;

	/* Find the existing fde that caused the EEXIST error. */
	for (mpx_fde = ev->fd_events; mpx_fde; mpx_fde = mpx_fde->next) {
		mpx_primary = tevent_common_fd_mpx_primary(mpx_fde);

		if (mpx_primary->fd != add_primary->fd) {
			mpx_primary = NULL;
			continue;
		}

		if (mpx_primary == add_primary) {
			mpx_primary = NULL;
			continue;
		}

		if (add_flags != 0 &&
		    tevent_common_fd_mpx_flags(mpx_primary) == 0)
		{
			/*
			 * only active events should match
			 */
			mpx_primary = NULL;
			continue;
		}
		break;
	}
	if (mpx_primary == NULL) {
		tevent_debug(ev, TEVENT_DEBUG_FATAL,
			     "can't find multiplex fde for fd[%d]",
			     add_fde->fd);
		return NULL;
	}

	/*
	 * If add_primary is not in it's own list
	 * we add it in order to simplify the loop below.
	 */

	if (add_primary->mpx.prev == NULL && add_primary->mpx.next == NULL) {
		DLIST_ADD_END(add_primary->mpx.list, &add_primary->mpx);
	}

	/*
	 * Add the new mpx_primary to its own list before others,
	 * if it is not already added.
	 */
	if (mpx_primary->mpx.prev == NULL && mpx_primary->mpx.next == NULL) {
		DLIST_ADD_END(mpx_primary->mpx.list, &mpx_primary->mpx);
	}

	/*
	 * Now we clear all entries and move them to the
	 * new primary
	 */
	for (tmp = add_primary->mpx.list; tmp != NULL; tmp = next) {
		struct tevent_fd *tmp_fde = tmp->fde;

		next = tmp->next;

		DLIST_REMOVE(add_primary->mpx.list, tmp);
		tevent_common_fd_mpx_reinit(tmp_fde);
		DLIST_ADD_END(mpx_primary->mpx.list, tmp);
		tmp->primary = mpx_primary;
		tmp->has_mpx = true;
	}

	mpx_primary->mpx.has_mpx = true;
	return mpx_primary;
}

/*
 * tevent_common_fd_mpx_update() calls tevent_common_fd_mpx_update_flags()
 * and compares tevent_common_fd_mpx_flags() before and after.
 *
 * When there's a low level update needed the primary fde,
 * otherwise NULL is returned.
 */
static inline
struct tevent_fd *tevent_common_fd_mpx_update(struct tevent_fd *update_fde)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(update_fde);
	uint16_t old_total_flags;
	uint16_t new_total_flags;

	old_total_flags = primary->mpx.total_flags;
	tevent_common_fd_mpx_update_flags(primary);
	new_total_flags = primary->mpx.total_flags;

	if (old_total_flags == new_total_flags) {
		/* No update needed */
		return NULL;
	}

	return primary;
}

/*
 * tevent_common_fd_mpx_remove() removes remove_fde from its possible primary,
 * if remove_fde is a primary itself, a new primary is selected.
 *
 * The remaining primary or NULL is returned.
 */
static inline
struct tevent_fd *tevent_common_fd_mpx_remove(struct tevent_fd *remove_fde)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(remove_fde);
	struct tevent_fd_mpx *mpx = NULL, *next = NULL;
	struct tevent_fd *new_primary = NULL;

	DLIST_REMOVE(primary->mpx.list, &remove_fde->mpx);

	if (primary != remove_fde) {
		tevent_common_fd_mpx_reinit(remove_fde);
		return primary;
	}

	for (mpx = primary->mpx.list; mpx != NULL; mpx = next) {
		struct tevent_fd *mpx_fde = mpx->fde;

		next = mpx->next;

		DLIST_REMOVE(primary->mpx.list, &mpx_fde->mpx);
		tevent_common_fd_mpx_reinit(mpx_fde);
		mpx->primary = new_primary;
		if (new_primary == NULL) {
			/*
			 * Select the first one as the new primary and add
			 * itself as the first mpx-fde to the mpx list
			 */
			new_primary = mpx_fde;
			DLIST_ADD(new_primary->mpx.list, &mpx_fde->mpx);
			continue;
		}
		new_primary->mpx.has_mpx = true;
		mpx->has_mpx = true;
		DLIST_ADD_END(new_primary->mpx.list, &mpx_fde->mpx);
	}

	/* primary == remove_fde */
	tevent_common_fd_mpx_reinit(primary);
	return new_primary;
}
