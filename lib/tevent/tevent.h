/* 
   Unix SMB/CIFS implementation.

   generalised event loop handling

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
