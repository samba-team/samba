/* 
   Unix SMB/CIFS implementation.

   generalised event loop handling

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher 2005-2009
   Copyright (C) Volker Lendecke 2008

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

#ifndef __TEVENT_H__
#define __TEVENT_H__

#include <stdint.h>
#include <talloc.h>
#include <sys/time.h>

struct tevent_context;
struct tevent_ops;
struct tevent_fd;
struct tevent_timer;
struct tevent_signal;

/* event handler types */
typedef void (*tevent_fd_handler_t)(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data);
typedef void (*tevent_fd_close_fn_t)(struct tevent_context *ev,
				     struct tevent_fd *fde,
				     int fd,
				     void *private_data);
typedef void (*tevent_timer_handler_t)(struct tevent_context *ev,
				       struct tevent_timer *te,
				       struct timeval current_time,
				       void *private_data);
typedef void (*tevent_signal_handler_t)(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data);

struct tevent_context *tevent_context_init(TALLOC_CTX *mem_ctx);
struct tevent_context *tevent_context_init_byname(TALLOC_CTX *mem_ctx, const char *name);
const char **tevent_backend_list(TALLOC_CTX *mem_ctx);
void tevent_set_default_backend(const char *backend);

struct tevent_fd *_tevent_add_fd(struct tevent_context *ev,
				 TALLOC_CTX *mem_ctx,
				 int fd,
				 uint16_t flags,
				 tevent_fd_handler_t handler,
				 void *private_data,
				 const char *handler_name,
				 const char *location);
#define tevent_add_fd(ev, mem_ctx, fd, flags, handler, private_data) \
	_tevent_add_fd(ev, mem_ctx, fd, flags, handler, private_data, \
		       #handler, __location__)

struct tevent_timer *_tevent_add_timer(struct tevent_context *ev,
				       TALLOC_CTX *mem_ctx,
				       struct timeval next_event,
				       tevent_timer_handler_t handler,
				       void *private_data,
				       const char *handler_name,
				       const char *location);
#define tevent_add_timer(ev, mem_ctx, next_event, handler, private_data) \
	_tevent_add_timer(ev, mem_ctx, next_event, handler, private_data, \
			  #handler, __location__)

struct tevent_signal *_tevent_add_signal(struct tevent_context *ev,
					 TALLOC_CTX *mem_ctx,
					 int signum,
					 int sa_flags,
					 tevent_signal_handler_t handler,
					 void *private_data,
					 const char *handler_name,
					 const char *location);
#define tevent_add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data) \
	_tevent_add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data, \
			   #handler, __location__)

int tevent_loop_once(struct tevent_context *ev);
int tevent_loop_wait(struct tevent_context *ev);

void tevent_fd_set_close_fn(struct tevent_fd *fde,
			    tevent_fd_close_fn_t close_fn);
void tevent_fd_set_auto_close(struct tevent_fd *fde);
uint16_t tevent_fd_get_flags(struct tevent_fd *fde);
void tevent_fd_set_flags(struct tevent_fd *fde, uint16_t flags);

/* bits for file descriptor event flags */
#define TEVENT_FD_READ 1
#define TEVENT_FD_WRITE 2

#define TEVENT_FD_WRITEABLE(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) | TEVENT_FD_WRITE)
#define TEVENT_FD_READABLE(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) | TEVENT_FD_READ)

#define TEVENT_FD_NOT_WRITEABLE(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) & ~TEVENT_FD_WRITE)
#define TEVENT_FD_NOT_READABLE(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) & ~TEVENT_FD_READ)

/* DEBUG */
enum tevent_debug_level {
	TEVENT_DEBUG_FATAL,
	TEVENT_DEBUG_ERROR,
	TEVENT_DEBUG_WARNING,
	TEVENT_DEBUG_TRACE
};

int tevent_set_debug(struct tevent_context *ev,
		     void (*debug)(void *context,
				   enum tevent_debug_level level,
				   const char *fmt,
				   va_list ap) PRINTF_ATTRIBUTE(3,0),
		     void *context);
int tevent_set_debug_stderr(struct tevent_context *ev);

/**
 * An async request moves between the following 4 states:
 */
enum tevent_req_state {
	/**
	 * we are creating the request
	 */
	TEVENT_REQ_INIT,
	/**
	 * we are waiting the request to complete
	 */
	TEVENT_REQ_IN_PROGRESS,
	/**
	 * the request is finished
	 */
	TEVENT_REQ_DONE,
	/**
	 * A user error has occured
	 */
	TEVENT_REQ_USER_ERROR,
	/**
	 * Request timed out
	 */
	TEVENT_REQ_TIMED_OUT,
	/**
	 * No memory in between
	 */
	TEVENT_REQ_NO_MEMORY
};

/**
 * @brief An async request
 *
 * This represents an async request being processed by callbacks via an event
 * context. A user can issue for example a write request to a socket, giving
 * an implementation function the fd, the buffer and the number of bytes to
 * transfer. The function issuing the request will immediately return without
 * blocking most likely without having sent anything. The API user then fills
 * in req->async.fn and req->async.private_data, functions that are called
 * when the request is finished.
 *
 * It is up to the user of the async request to talloc_free it after it has
 * finished. This can happen while the completion function is called.
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
		void (*fn)(struct tevent_req *);
		/**
		 * @brief Private data for the completion function
		 */
		void *private_data;
	} async;

	/**
	 * @brief Private state pointer for the actual implementation
	 *
	 * The implementation doing the work for the async request needs a
	 * current state like for example a fd event. The user of an async
	 * request should not touch this.
	 */
	void *private_state;

	/**
	 * @brief Internal state of the request
	 *
	 * Callers should only access this via functions and never directly.
	 */
	struct {
		/**
		 * @brief The talloc type of the private_state pointer
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
		const char *location;

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
		 * @brief the timer event if tevent_req_post was used
		 *
		 */
		struct tevent_timer *trigger;

		/**
		 * @brief the timer event if tevent_req_set_timeout was used
		 *
		 */
		struct tevent_timer *timer;
	} internal;
};

char *tevent_req_print(TALLOC_CTX *mem_ctx, struct tevent_req *req);

struct tevent_req *_tevent_req_create(TALLOC_CTX *mem_ctx,
				      void *pstate,
				      size_t state_size,
				      const char *type,
				      const char *location);

#define tevent_req_create(_mem_ctx, _pstate, _type) \
	_tevent_req_create((_mem_ctx), (_pstate), sizeof(_type), \
			   #_type, __location__)

bool tevent_req_set_timeout(struct tevent_req *req,
			    struct tevent_context *ev,
			    struct timeval endtime);

void tevent_req_done(struct tevent_req *req);

bool tevent_req_error(struct tevent_req *req,
		      uint64_t error);

bool tevent_req_nomem(const void *p,
		      struct tevent_req *req);

struct tevent_req *tevent_req_post(struct tevent_req *req,
				   struct tevent_context *ev);

bool tevent_req_is_in_progress(struct tevent_req *req);

bool tevent_req_is_error(struct tevent_req *req,
			 enum tevent_req_state *state,
			 uint64_t *error);


int tevent_timeval_compare(const struct timeval *tv1,
			   const struct timeval *tv2);

struct timeval tevent_timeval_zero(void);

struct timeval tevent_timeval_current(void);

struct timeval tevent_timeval_set(uint32_t secs, uint32_t usecs);

struct timeval tevent_timeval_until(const struct timeval *tv1,
				    const struct timeval *tv2);

bool tevent_timeval_is_zero(const struct timeval *tv);

struct timeval tevent_timeval_add(const struct timeval *tv, uint32_t secs,
				  uint32_t usecs);

struct timeval tevent_timeval_current_ofs(uint32_t secs, uint32_t usecs);

#ifdef TEVENT_COMPAT_DEFINES

#define event_context	tevent_context
#define event_ops	tevent_ops
#define fd_event	tevent_fd
#define timed_event	tevent_timer
#define signal_event	tevent_signal

#define event_fd_handler_t	tevent_fd_handler_t
#define event_timed_handler_t	tevent_timer_handler_t
#define event_signal_handler_t	tevent_signal_handler_t

#define event_context_init(mem_ctx) \
	tevent_context_init(mem_ctx)

#define event_context_init_byname(mem_ctx, name) \
	tevent_context_init_byname(mem_ctx, name)

#define event_backend_list(mem_ctx) \
	tevent_backend_list(mem_ctx)

#define event_set_default_backend(backend) \
	tevent_set_default_backend(backend)

#define event_add_fd(ev, mem_ctx, fd, flags, handler, private_data) \
	tevent_add_fd(ev, mem_ctx, fd, flags, handler, private_data)

#define event_add_timed(ev, mem_ctx, next_event, handler, private_data) \
	tevent_add_timer(ev, mem_ctx, next_event, handler, private_data)

#define event_add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data) \
	tevent_add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data)

#define event_loop_once(ev) \
	tevent_loop_once(ev)

#define event_loop_wait(ev) \
	tevent_loop_wait(ev)

#define event_get_fd_flags(fde) \
	tevent_fd_get_flags(fde)

#define event_set_fd_flags(fde, flags) \
	tevent_fd_set_flags(fde, flags)

#define EVENT_FD_READ		TEVENT_FD_READ
#define EVENT_FD_WRITE		TEVENT_FD_WRITE

#define EVENT_FD_WRITEABLE(fde) \
	TEVENT_FD_WRITEABLE(fde)

#define EVENT_FD_READABLE(fde) \
	TEVENT_FD_READABLE(fde)

#define EVENT_FD_NOT_WRITEABLE(fde) \
	TEVENT_FD_NOT_WRITEABLE(fde)

#define EVENT_FD_NOT_READABLE(fde) \
	TEVENT_FD_NOT_READABLE(fde)

#define ev_debug_level		tevent_debug_level

#define EV_DEBUG_FATAL		TEVENT_DEBUG_FATAL
#define EV_DEBUG_ERROR		TEVENT_DEBUG_ERROR
#define EV_DEBUG_WARNING	TEVENT_DEBUG_WARNING
#define EV_DEBUG_TRACE		TEVENT_DEBUG_TRACE

#define ev_set_debug(ev, debug, context) \
	tevent_set_debug(ev, debug, context)

#define ev_set_debug_stderr(_ev) tevent_set_debug_stderr(ev)

#endif /* TEVENT_COMPAT_DEFINES */

#endif /* __TEVENT_H__ */
