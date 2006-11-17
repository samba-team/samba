/* 
   Unix SMB/CIFS implementation.

   generalised event loop handling

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef __EVENTS_H__
#define __EVENTS_H__

struct event_context;
struct event_ops;
struct fd_event;
struct timed_event;

/* event handler types */
typedef void (*event_fd_handler_t)(struct event_context *, struct fd_event *, 
				   uint16_t , void *);
typedef void (*event_timed_handler_t)(struct event_context *, struct timed_event *, 
				      struct timeval , void *);

struct event_context *event_context_init(TALLOC_CTX *mem_ctx);
struct event_context *event_context_init_ops(TALLOC_CTX *mem_ctx, const struct event_ops *ops, void *private_data);

struct fd_event *event_add_fd(struct event_context *ev, TALLOC_CTX *mem_ctx,
			      int fd, uint16_t flags, event_fd_handler_t handler,
			      void *private);

struct timed_event *event_add_timed(struct event_context *ev, TALLOC_CTX *mem_ctx,
				    struct timeval next_event, 
				    event_timed_handler_t handler, 
				    void *private);

int event_loop_once(struct event_context *ev);
int event_loop_wait(struct event_context *ev);

uint16_t event_get_fd_flags(struct fd_event *fde);
void event_set_fd_flags(struct fd_event *fde, uint16_t flags);

struct event_context *event_context_find(TALLOC_CTX *mem_ctx);

/* bits for file descriptor event flags */
#define EVENT_FD_READ 1
#define EVENT_FD_WRITE 2

#define EVENT_FD_WRITEABLE(fde) \
	event_set_fd_flags(fde, event_get_fd_flags(fde) | EVENT_FD_WRITE)
#define EVENT_FD_READABLE(fde) \
	event_set_fd_flags(fde, event_get_fd_flags(fde) | EVENT_FD_READ)

#define EVENT_FD_NOT_WRITEABLE(fde) \
	event_set_fd_flags(fde, event_get_fd_flags(fde) & ~EVENT_FD_WRITE)
#define EVENT_FD_NOT_READABLE(fde) \
	event_set_fd_flags(fde, event_get_fd_flags(fde) & ~EVENT_FD_READ)

#endif /* __EVENTS_H__ */
