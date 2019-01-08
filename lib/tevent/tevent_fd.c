/*
   Unix SMB/CIFS implementation.

   common events code for fd events

   Copyright (C) Stefan Metzmacher 2009

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

#include "replace.h"
#define TEVENT_DEPRECATED 1
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

int tevent_common_fd_destructor(struct tevent_fd *fde)
{
	if (fde->destroyed) {
		tevent_common_check_double_free(fde, "tevent_fd double free");
		goto done;
	}
	fde->destroyed = true;

	if (fde->event_ctx) {
		DLIST_REMOVE(fde->event_ctx->fd_events, fde);
	}

	if (fde->close_fn) {
		fde->close_fn(fde->event_ctx, fde, fde->fd, fde->private_data);
		fde->fd = -1;
		fde->close_fn = NULL;
	}

	fde->event_ctx = NULL;
done:
	if (fde->busy) {
		return -1;
	}
	fde->wrapper = NULL;

	return 0;
}

struct tevent_fd *tevent_common_add_fd(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
				       int fd, uint16_t flags,
				       tevent_fd_handler_t handler,
				       void *private_data,
				       const char *handler_name,
				       const char *location)
{
	struct tevent_fd *fde;

	/* tevent will crash later on select() if we save
	 * a negative file descriptor. Better to fail here
	 * so that consumers will be able to debug it
	 */
	if (fd < 0) return NULL;

	fde = talloc(mem_ctx?mem_ctx:ev, struct tevent_fd);
	if (!fde) return NULL;

	*fde = (struct tevent_fd) {
		.event_ctx	= ev,
		.fd		= fd,
		.flags		= flags,
		.handler	= handler,
		.private_data	= private_data,
		.handler_name	= handler_name,
		.location	= location,
	};

	DLIST_ADD(ev->fd_events, fde);

	talloc_set_destructor(fde, tevent_common_fd_destructor);

	return fde;
}
uint16_t tevent_common_fd_get_flags(struct tevent_fd *fde)
{
	return fde->flags;
}

void tevent_common_fd_set_flags(struct tevent_fd *fde, uint16_t flags)
{
	if (fde->flags == flags) return;
	fde->flags = flags;
}

void tevent_common_fd_set_close_fn(struct tevent_fd *fde,
				   tevent_fd_close_fn_t close_fn)
{
	fde->close_fn = close_fn;
}

int tevent_common_invoke_fd_handler(struct tevent_fd *fde, uint16_t flags,
				    bool *removed)
{
	struct tevent_context *handler_ev = fde->event_ctx;

	if (removed != NULL) {
		*removed = false;
	}

	if (fde->event_ctx == NULL) {
		return 0;
	}

	fde->busy = true;
	if (fde->wrapper != NULL) {
		handler_ev = fde->wrapper->wrap_ev;

		tevent_wrapper_push_use_internal(handler_ev, fde->wrapper);
		fde->wrapper->ops->before_fd_handler(
					fde->wrapper->wrap_ev,
					fde->wrapper->private_state,
					fde->wrapper->main_ev,
					fde,
					flags,
					fde->handler_name,
					fde->location);
	}
	fde->handler(handler_ev, fde, flags, fde->private_data);
	if (fde->wrapper != NULL) {
		fde->wrapper->ops->after_fd_handler(
					fde->wrapper->wrap_ev,
					fde->wrapper->private_state,
					fde->wrapper->main_ev,
					fde,
					flags,
					fde->handler_name,
					fde->location);
		tevent_wrapper_pop_use_internal(handler_ev, fde->wrapper);
	}
	fde->busy = false;

	if (fde->destroyed) {
		talloc_set_destructor(fde, NULL);
		TALLOC_FREE(fde);
		if (removed != NULL) {
			*removed = true;
		}
	}

	return 0;
}
