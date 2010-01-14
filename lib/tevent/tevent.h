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
#include <stdbool.h>

struct tevent_context;
struct tevent_ops;
struct tevent_fd;
struct tevent_timer;
struct tevent_immediate;
struct tevent_signal;

/**
 * @defgroup tevent The tevent API
 *
 * The tevent low-level API
 *
 * @todo description
 *
 * @{
 */

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
typedef void (*tevent_immediate_handler_t)(struct tevent_context *ctx,
					   struct tevent_immediate *im,
					   void *private_data);
typedef void (*tevent_signal_handler_t)(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data);

/**
 * @brief Create a event_context structure.
 *
 * This must be the first events call, and all subsequent calls pass this
 * event_context as the first element. Event handlers also receive this as
 * their first argument.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @return              An allocated tevent context, NULL on error.
 *
 * @see tevent_context_init()
 */
struct tevent_context *tevent_context_init(TALLOC_CTX *mem_ctx);

/**
 * @brief Create a event_context structure and name it.
 *
 * This must be the first events call, and all subsequent calls pass this
 * event_context as the first element. Event handlers also receive this as
 * their first argument.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  name     The name for the tevent context.
 *
 * @return              An allocated tevent context, NULL on error.
 */
struct tevent_context *tevent_context_init_byname(TALLOC_CTX *mem_ctx, const char *name);

/**
 * @brief List available backends.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @return              A string vector with a terminating NULL element, NULL
 *                      on error.
 */
const char **tevent_backend_list(TALLOC_CTX *mem_ctx);

/**
 * @brief Set the default tevent backent.
 *
 * @param[in]  backend  The name of the backend to set.
 */
void tevent_set_default_backend(const char *backend);

#if DOXYGEN
/**
 * @brief Add a file descriptor based event.
 *
 * If flags contains TEVENT_FD_AUTOCLOSE then the fd will be closed when
 * the returned fd_event context is freed.
 *
 * @param[in]  ev       The event context to work on.
 *
 * @param[in]  mem_ctx  The talloc memory context to use.
 *
 * @param[in]  fd       The file descriptor to base the event on.
 *
 * @param[in]  flags
 *
 * @param[in]  handler  The callback handler for the event.
 *
 * @param[in]  private_data  The private data passed to the callback handler.
 *
 * @param[in]  handler_name  The name to identify the callback handler.
 *
 * @return              The file descriptor based event, NULL on error.
 *
 * @todo Document flags
 */
struct tevent_fd *tevent_add_fd(struct tevent_context *ev,
				TALLOC_CTX *mem_ctx,
				int fd,
				uint16_t flags,
				tevent_fd_handler_t handler,
				void *private_data,
				const char *handler_name);
#else
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
#endif

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

struct tevent_immediate *_tevent_create_immediate(TALLOC_CTX *mem_ctx,
						  const char *location);
#define tevent_create_immediate(mem_ctx) \
	_tevent_create_immediate(mem_ctx, __location__)

void _tevent_schedule_immediate(struct tevent_immediate *im,
				struct tevent_context *ctx,
				tevent_immediate_handler_t handler,
				void *private_data,
				const char *handler_name,
				const char *location);
#define tevent_schedule_immediate(im, ctx, handler, private_data) \
	_tevent_schedule_immediate(im, ctx, handler, private_data, \
				   #handler, __location__);

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

int _tevent_loop_once(struct tevent_context *ev, const char *location);
#define tevent_loop_once(ev) \
	_tevent_loop_once(ev, __location__) \

int _tevent_loop_wait(struct tevent_context *ev, const char *location);
#define tevent_loop_wait(ev) \
	_tevent_loop_wait(ev, __location__) \

void tevent_fd_set_close_fn(struct tevent_fd *fde,
			    tevent_fd_close_fn_t close_fn);
void tevent_fd_set_auto_close(struct tevent_fd *fde);
uint16_t tevent_fd_get_flags(struct tevent_fd *fde);
void tevent_fd_set_flags(struct tevent_fd *fde, uint16_t flags);

bool tevent_signal_support(struct tevent_context *ev);

void tevent_set_abort_fn(void (*abort_fn)(const char *reason));

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

/**
 * Debug level of tevent
 */
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
 * @}
 */

/**
 * @defgroup tevent_request The tevent request functions.
 * @ingroup tevent
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
 *
 * @{
 */

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
	 * A user error has occurred
	 */
	TEVENT_REQ_USER_ERROR,
	/**
	 * Request timed out
	 */
	TEVENT_REQ_TIMED_OUT,
	/**
	 * No memory in between
	 */
	TEVENT_REQ_NO_MEMORY,
	/**
	 * the request is already received by the caller
	 */
	TEVENT_REQ_RECEIVED
};

/**
 * @brief An async request
 */
struct tevent_req;

typedef void (*tevent_req_fn)(struct tevent_req *);

void tevent_req_set_callback(struct tevent_req *req, tevent_req_fn fn, void *pvt);

void *_tevent_req_callback_data(struct tevent_req *req);
#define tevent_req_callback_data(_req, _type) \
	talloc_get_type_abort(_tevent_req_callback_data(_req), _type)

#define tevent_req_callback_data_void(_req) \
	_tevent_req_callback_data(_req)

void *_tevent_req_data(struct tevent_req *req);
#define tevent_req_data(_req, _type) \
	talloc_get_type_abort(_tevent_req_data(_req), _type)

typedef char *(*tevent_req_print_fn)(struct tevent_req *, TALLOC_CTX *);

/**
 * @brief This function sets a print function for the given request.
 *
 * This function can be used to setup a print function for the given request.
 * This will be triggered if the tevent_req_print() function was
 * called on the given request.
 *
 * @param[in]  req      The request to use.
 *
 * @param[in]  fn       A pointer to the print function
 *
 * @note This function should only be used for debugging.
 */
void tevent_req_set_print_fn(struct tevent_req *req, tevent_req_print_fn fn);

/**
 * @brief The default print function for creating debug messages.
 *
 * The function should not be used by users of the async API,
 * but custom print function can use it and append custom text
 * to the string.
 *
 * @param[in]  req      The request to be printed.
 *
 * @param[in]  mem_ctx  The memory context for the result.
 *
 * @return              Text representation of request.
 *
 */
char *tevent_req_default_print(struct tevent_req *req, TALLOC_CTX *mem_ctx);

/**
 * @brief Print an tevent_req structure in debug messages.
 *
 * This function should be used by callers of the async API.
 *
 * @param[in]  mem_ctx  The memory context for the result.
 *
 * @param[in] req       The request to be printed.
 *
 * @return              Text representation of request.
 */
char *tevent_req_print(TALLOC_CTX *mem_ctx, struct tevent_req *req);

typedef bool (*tevent_req_cancel_fn)(struct tevent_req *);

/**
 * @brief This function sets a cancel function for the given tevent request.
 *
 * This function can be used to setup a cancel function for the given request.
 * This will be triggered if the tevent_req_cancel() function was
 * called on the given request.
 *
 * @param[in]  req      The request to use.
 *
 * @param[in]  fn       A pointer to the cancel function.
 */
void tevent_req_set_cancel_fn(struct tevent_req *req, tevent_req_cancel_fn fn);

#ifdef DOXYGEN
/**
 * @brief Try to cancel the given tevent request.
 *
 * This function can be used to cancel the given request.
 *
 * It is only possible to cancel a request when the implementation
 * has registered a cancel function via the tevent_req_set_cancel_fn().
 *
 * @param[in]  req      The request to use.
 *
 * @return              This function returns true is the request is cancelable,
 *                      othererwise false is returned.
 *
 * @note Even if the function returns true, the caller need to wait
 *       for the function to complete normally.
 *       Only the _recv() function of the given request indicates
 *       if the request was really canceled.
 */
bool tevent_req_cancel(struct tevent_req *req);
#else
bool _tevent_req_cancel(struct tevent_req *req, const char *location);
#define tevent_req_cancel(req) \
	_tevent_req_cancel(req, __location__)
#endif

#if DOXYGEN
/**
 * @brief Create an async tevent request.
 *
 * The new async request will be initialized in state ASYNC_REQ_IN_PROGRESS.
 *
 * @param[in] mem_ctx   The memory context for the result.
 *
 * @param[in] pstate    The private state of the request.
 *
 * @param[in] state_size  The size of the private state of the request.
 *
 * @param[in] type      The name of the request.
 *
 * @return              A new async request. NULL on error.
 */
struct tevent_req *tevent_req_create(TALLOC_CTX *mem_ctx,
				      void *pstate,
				      size_t state_size,
				      const char *type);
#else
struct tevent_req *_tevent_req_create(TALLOC_CTX *mem_ctx,
				      void *pstate,
				      size_t state_size,
				      const char *type,
				      const char *location);

#define tevent_req_create(_mem_ctx, _pstate, _type) \
	_tevent_req_create((_mem_ctx), (_pstate), sizeof(_type), \
			   #_type, __location__)
#endif

bool tevent_req_set_endtime(struct tevent_req *req,
			    struct tevent_context *ev,
			    struct timeval endtime);

void _tevent_req_notify_callback(struct tevent_req *req, const char *location);
#define tevent_req_notify_callback(req)		\
	_tevent_req_notify_callback(req, __location__)

#ifdef DOXYGEN
/**
 * @brief An async request has successfully finished.
 *
 * This function is to be used by implementors of async requests. When a
 * request is successfully finished, this function calls the user's completion
 * function.
 *
 * @param[in]  req       The finished request.
 */
void tevent_req_done(struct tevent_req *req);
#else
void _tevent_req_done(struct tevent_req *req,
		      const char *location);
#define tevent_req_done(req) \
	_tevent_req_done(req, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief An async request has seen an error.
 *
 * This function is to be used by implementors of async requests. When a
 * request can not successfully completed, the implementation should call this
 * function with the appropriate status code.
 *
 * If error is 0 the function returns false and does nothing more.
 *
 * @param[in]  req      The request with an error.
 *
 * @param[in]  error    The error code.
 *
 * @return              On success true is returned, false if error is 0.
 *
 * @code
 * int error = first_function();
 * if (tevent_req_error(req, error)) {
 *      return;
 * }
 *
 * error = second_function();
 * if (tevent_req_error(req, error)) {
 *      return;
 * }
 *
 * tevent_req_done(req);
 * return;
 * @endcode
 */
bool tevent_req_error(struct tevent_req *req,
		      uint64_t error);
#else
bool _tevent_req_error(struct tevent_req *req,
		       uint64_t error,
		       const char *location);
#define tevent_req_error(req, error) \
	_tevent_req_error(req, error, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Helper function for nomem check.
 *
 * Convenience helper to easily check alloc failure within a callback
 * implementing the next step of an async request.
 *
 * @param[in]  p        The pointer to be checked.
 *
 * @param[in]  req      The request being processed.
 *
 * @code
 * p = talloc(mem_ctx, bla);
 * if (tevent_req_nomem(p, req)) {
 *      return;
 * }
 * @endcode
 */
bool tevent_req_nomem(const void *p,
		      struct tevent_req *req);
#else
bool _tevent_req_nomem(const void *p,
		       struct tevent_req *req,
		       const char *location);
#define tevent_req_nomem(p, req) \
	_tevent_req_nomem(p, req, __location__)
#endif

/**
 * @brief Finish a request before the caller had the change to set the callback.
 *
 * An implementation of an async request might find that it can either finish
 * the request without waiting for an external event, or it can't even start
 * the engine. To present the illusion of a callback to the user of the API,
 * the implementation can call this helper function which triggers an
 * immediate timed event. This way the caller can use the same calling
 * conventions, independent of whether the request was actually deferred.
 *
 * @param[in]  req      The finished request.
 *
 * @param[in]  ev       The tevent_context for the timed event.
 *
 * @return              The given request will be returned.
 */
struct tevent_req *tevent_req_post(struct tevent_req *req,
				   struct tevent_context *ev);

/**
 * @brief Check if the given request is still in progress.
 *
 * It is typically used by sync wrapper functions.
 *
 * This function destroys the attached private data.
 *
 * @param[in]  req      The request to poll.
 *
 * @return              The boolean form of "is in progress".
 */
bool tevent_req_is_in_progress(struct tevent_req *req);

/**
 * @brief Actively poll for the given request to finish.
 *
 * This function is typically used by sync wrapper functions.
 *
 * @param[in]  req      The request to poll.
 *
 * @param[in]  ev       The tevent_context to be used.
 *
 * @return              On success true is returned. If a critical error has
 *                      happened in the tevent loop layer false is returned.
 *                      This is not the return value of the given request!
 *
 * @note This should only be used if the given tevent context was created by the
 * caller, to avoid event loop nesting.
 *
 * @code
 * req = tstream_writev_queue_send(mem_ctx,
 *                                 ev_ctx,
 *                                 tstream,
 *                                 send_queue,
 *                                 iov, 2);
 * ok = tevent_req_poll(req, tctx->ev);
 * rc = tstream_writev_queue_recv(req, &sys_errno);
 * TALLOC_FREE(req);
 * @endcode
 */
bool tevent_req_poll(struct tevent_req *req,
		     struct tevent_context *ev);

bool tevent_req_is_error(struct tevent_req *req,
			 enum tevent_req_state *state,
			 uint64_t *error);

/**
 * @brief Use as the last action of a _recv() function.
 *
 * This function destroys the attached private data.
 *
 * @param[in]  req      The finished request.
 */
void tevent_req_received(struct tevent_req *req);

struct tevent_req *tevent_wakeup_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct timeval wakeup_time);
bool tevent_wakeup_recv(struct tevent_req *req);

/* @} */

/**
 * @defgroup tevent_helpers The tevent helper functiions
 * @ingroup tevent
 *
 * @todo description
 *
 * @{
 */

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

/* @} */


/**
 * @defgroup tevent_queue The tevent queue functions
 * @ingroup tevent
 *
 * @{
 */

struct tevent_queue;

struct tevent_queue *_tevent_queue_create(TALLOC_CTX *mem_ctx,
					  const char *name,
					  const char *location);

#define tevent_queue_create(_mem_ctx, _name) \
	_tevent_queue_create((_mem_ctx), (_name), __location__)

typedef void (*tevent_queue_trigger_fn_t)(struct tevent_req *req,
					  void *private_data);
bool tevent_queue_add(struct tevent_queue *queue,
		      struct tevent_context *ev,
		      struct tevent_req *req,
		      tevent_queue_trigger_fn_t trigger,
		      void *private_data);
void tevent_queue_start(struct tevent_queue *queue);
void tevent_queue_stop(struct tevent_queue *queue);

size_t tevent_queue_length(struct tevent_queue *queue);

typedef int (*tevent_nesting_hook)(struct tevent_context *ev,
				   void *private_data,
				   uint32_t level,
				   bool begin,
				   void *stack_ptr,
				   const char *location);
#ifdef TEVENT_DEPRECATED
#ifndef _DEPRECATED_
#if (__GNUC__ >= 3) && (__GNUC_MINOR__ >= 1 )
#define _DEPRECATED_ __attribute__ ((deprecated))
#else
#define _DEPRECATED_
#endif
#endif
void tevent_loop_allow_nesting(struct tevent_context *ev) _DEPRECATED_;
void tevent_loop_set_nesting_hook(struct tevent_context *ev,
				  tevent_nesting_hook hook,
				  void *private_data) _DEPRECATED_;
int _tevent_loop_until(struct tevent_context *ev,
		       bool (*finished)(void *private_data),
		       void *private_data,
		       const char *location) _DEPRECATED_;
#define tevent_loop_until(ev, finished, private_data) \
	_tevent_loop_until(ev, finished, private_data, __location__)
#endif

int tevent_re_initialise(struct tevent_context *ev);

/* @} */

/**
 * @defgroup tevent_ops The tevent operation functions
 * @ingroup tevent
 *
 * The following structure and registration functions are exclusively
 * needed for people writing and pluggin a different event engine.
 * There is nothing useful for normal tevent user in here.
 * @{
 */

struct tevent_ops {
	/* context init */
	int (*context_init)(struct tevent_context *ev);

	/* fd_event functions */
	struct tevent_fd *(*add_fd)(struct tevent_context *ev,
				    TALLOC_CTX *mem_ctx,
				    int fd, uint16_t flags,
				    tevent_fd_handler_t handler,
				    void *private_data,
				    const char *handler_name,
				    const char *location);
	void (*set_fd_close_fn)(struct tevent_fd *fde,
				tevent_fd_close_fn_t close_fn);
	uint16_t (*get_fd_flags)(struct tevent_fd *fde);
	void (*set_fd_flags)(struct tevent_fd *fde, uint16_t flags);

	/* timed_event functions */
	struct tevent_timer *(*add_timer)(struct tevent_context *ev,
					  TALLOC_CTX *mem_ctx,
					  struct timeval next_event,
					  tevent_timer_handler_t handler,
					  void *private_data,
					  const char *handler_name,
					  const char *location);

	/* immediate event functions */
	void (*schedule_immediate)(struct tevent_immediate *im,
				   struct tevent_context *ev,
				   tevent_immediate_handler_t handler,
				   void *private_data,
				   const char *handler_name,
				   const char *location);

	/* signal functions */
	struct tevent_signal *(*add_signal)(struct tevent_context *ev,
					    TALLOC_CTX *mem_ctx,
					    int signum, int sa_flags,
					    tevent_signal_handler_t handler,
					    void *private_data,
					    const char *handler_name,
					    const char *location);

	/* loop functions */
	int (*loop_once)(struct tevent_context *ev, const char *location);
	int (*loop_wait)(struct tevent_context *ev, const char *location);
};

bool tevent_register_backend(const char *name, const struct tevent_ops *ops);

/* @} */

/**
 * @defgroup tevent_compat The tevent compatibility functions
 * @ingroup tevent
 *
 * The following definitions are usueful only for compatibility with the
 * implementation originally developed within the samba4 code and will be
 * soon removed. Please NEVER use in new code.
 *
 * @todo Ignore it?
 *
 * @{
 */

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

/* @} */

#endif /* __TEVENT_H__ */
