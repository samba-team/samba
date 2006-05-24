/* 
   Unix SMB/CIFS implementation.

   testing of the events subsystem
   
   Copyright (C) Stefan Metzmacher
   
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

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "torture/torture.h"

const struct event_ops *event_standard_get_ops(void);
const struct event_ops *event_liboop_get_ops(void);
const struct event_ops *gtk_event_get_ops(void);

static int write_fd, read_fd;
static struct fd_event *fde;
static int te_count;
static int fde_count;
static BOOL ret = True;

static void fde_handler(struct event_context *ev_ctx, struct fd_event *f, 
			uint16_t flags, void *private)
{
	int *fd = private;

	printf("event[%d] fd[%d] events[0x%08X]", fde_count, *fd, flags);
	if (flags & EVENT_FD_READ) printf(" EVENT_FD_READ");
	if (flags & EVENT_FD_WRITE) printf(" EVENT_FD_WRITE");
	printf("\n");

	if (fde_count > 5) {
		printf("got more than fde 5 events - bug!\n");
		talloc_free(fde);
		fde = NULL;
		return;
	}

	event_set_fd_flags(fde, 0);
	fde_count++;
}

static void timed_handler(struct event_context *ev_ctx, struct timed_event *te,
			  struct timeval tval, void *private)
{
	printf("timed_handler called[%d]\n", te_count);
	if (te_count > 2) {
		close(write_fd);
		write_fd = -1;
	}
	if (te_count > 5) {
		printf("remove fd event!\n");
		talloc_free(fde);
		fde = NULL;
		return;
	}
	te_count++;
	event_add_timed(ev_ctx, ev_ctx, timeval_current_ofs(0,500), timed_handler, private);
}


static BOOL test_event_context(struct event_context *ev_ctx, const char *comment)
{
	int fd[2] = { -1, -1 };

	printf("Testing '%s'\n", comment);

	/* reset globals */
	write_fd = -1;
	read_fd = -1;
	fde = NULL;
	te_count = 0;
	fde_count = 0;
	ret = True;

	/* create a pipe */
	pipe(fd);
	read_fd = fd[0];
	write_fd = fd[1];

	fde = event_add_fd(ev_ctx, ev_ctx, read_fd, EVENT_FD_READ, fde_handler, &read_fd);

	event_add_timed(ev_ctx, ev_ctx, timeval_current_ofs(0,500), timed_handler, fde);

	event_loop_wait(ev_ctx);

	close(read_fd);
	close(write_fd);

	return ret;
}

BOOL torture_local_event(struct torture_context *torture) 
{
	struct event_context *ev_ctx;
	BOOL try_epoll;
	BOOL retv = True;

	try_epoll = False;
	ev_ctx = event_context_init_ops(NULL, event_standard_get_ops(), &try_epoll);
	retv &= test_event_context(ev_ctx, "standard with select");
	talloc_free(ev_ctx);

	try_epoll = True;
	ev_ctx = event_context_init_ops(NULL, event_standard_get_ops(), &try_epoll);
	retv &= test_event_context(ev_ctx, "standard try epool (or select)");
	talloc_free(ev_ctx);

	return retv;
}
