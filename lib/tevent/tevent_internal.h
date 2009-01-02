/* 
   Unix SMB/CIFS implementation.

   generalised event loop handling

   Internal structs

   Copyright (C) Stefan Metzmacher 2005
   
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

struct tevent_ops {
	/* conntext init */
	int (*context_init)(struct tevent_context *ev);

	/* fd_event functions */
	struct tevent_fd *(*add_fd)(struct tevent_context *ev,
				    TALLOC_CTX *mem_ctx,
				    int fd, uint16_t flags,
				    tevent_fd_handler_t handler,
				    void *private_data);
	uint16_t (*get_fd_flags)(struct tevent_fd *fde);
	void (*set_fd_flags)(struct tevent_fd *fde, uint16_t flags);

	/* timed_event functions */
	struct tevent_timer *(*add_timer)(struct tevent_context *ev,
					  TALLOC_CTX *mem_ctx,
					  struct timeval next_event,
					  tevent_timer_handler_t handler,
					  void *private_data);
	/* disk aio event functions */
	struct tevent_aio *(*add_aio)(struct tevent_context *ev,
				      TALLOC_CTX *mem_ctx,
				      struct iocb *iocb,
				      tevent_aio_handler_t handler,
				      void *private_data);
	/* signal functions */
	struct tevent_signal *(*add_signal)(struct tevent_context *ev,
					    TALLOC_CTX *mem_ctx,
					    int signum, int sa_flags,
					    tevent_signal_handler_t handler,
					    void *private_data);

	/* loop functions */
	int (*loop_once)(struct tevent_context *ev);
	int (*loop_wait)(struct tevent_context *ev);
};

struct tevent_fd {
	struct tevent_fd *prev, *next;
	struct tevent_context *event_ctx;
	int fd;
	uint16_t flags; /* see EVENT_FD_* flags */
	tevent_fd_handler_t handler;
	/* this is private for the specific handler */
	void *private_data;
	/* this is private for the events_ops implementation */
	uint16_t additional_flags;
	void *additional_data;
};

struct tevent_timer {
	struct tevent_timer *prev, *next;
	struct tevent_context *event_ctx;
	struct timeval next_event;
	tevent_timer_handler_t handler;
	/* this is private for the specific handler */
	void *private_data;
	/* this is private for the events_ops implementation */
	void *additional_data;
};

struct tevent_signal {
	struct tevent_signal *prev, *next;
	struct tevent_context *event_ctx;
	tevent_signal_handler_t handler;
	void *private_data;
	int signum;
	int sa_flags;
};

/* DEBUG */
enum ev_debug_level {EV_DEBUG_FATAL, EV_DEBUG_ERROR,
		      EV_DEBUG_WARNING, EV_DEBUG_TRACE};

struct ev_debug_ops {
	void (*debug)(void *context, enum ev_debug_level level,
		      const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3,0);
	void *context;
};

int ev_set_debug(struct tevent_context *ev,
		 void (*debug)(void *context, enum ev_debug_level level,
				const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3,0),
		 void *context);
int ev_set_debug_stderr(struct tevent_context *ev);
void ev_debug(struct tevent_context *ev, enum ev_debug_level level, const char *fmt, ...);

/* aio event is private to the aio backend */
struct tevent_aio;

struct tevent_context {
	/* the specific events implementation */
	const struct tevent_ops *ops;

	/* list of timed events - used by common code */
	struct tevent_timer *timer_events;

	/* this is private for the events_ops implementation */
	void *additional_data;

	/* number of signal event handlers */
	int num_signal_handlers;

	/* pipe hack used with signal handlers */
	struct tevent_fd *pipe_fde;

	/* debugging operations */
	struct ev_debug_ops debug_ops;
};


bool tevent_register_backend(const char *name, const struct tevent_ops *ops);

bool ev_timeval_is_zero(const struct timeval *tv);
struct tevent_timer *common_event_add_timed(struct tevent_context *,
					    TALLOC_CTX *,
					    struct timeval,
					    tevent_timer_handler_t,
					    void *);
struct timeval common_event_loop_timer_delay(struct tevent_context *);

struct tevent_signal *common_event_add_signal(struct tevent_context *ev,
					      TALLOC_CTX *mem_ctx,
					      int signum,
					      int sa_flags,
					      tevent_signal_handler_t handler,
					      void *private_data);
int common_event_check_signal(struct tevent_context *ev);


bool tevent_standard_init(void);
bool tevent_select_init(void);
#ifdef HAVE_EPOLL
bool tevent_epoll_init(void);
#endif
#ifdef HAVE_LINUX_AIO
bool tevent_aio_init(void);
#endif
