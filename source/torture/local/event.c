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

static int write_fd, read_fd;
static struct fd_event *fde;
static int te_count;
static int fde_count;
static struct torture_context *test;

static void fde_handler(struct event_context *ev_ctx, struct fd_event *f, 
			uint16_t flags, void *private)
{
	int *fd = private;

	torture_comment(test, "event[%d] fd[%d] events[0x%08X]%s%s\n", 
						fde_count, *fd, flags, 
					(flags & EVENT_FD_READ)?" EVENT_FD_READ":"", 
					(flags & EVENT_FD_WRITE)?" EVENT_FD_WRITE":"");

	if (fde_count > 5) {
		torture_result(test, TORTURE_FAIL, 
					   __location__": got more than fde 5 events - bug!");
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
	torture_comment(test, "timed_handler called[%d]\n", te_count);
	if (te_count > 2) {
		close(write_fd);
		write_fd = -1;
	}
	if (te_count > 5) {
		torture_comment(test, "remove fd event!\n");
		talloc_free(fde);
		fde = NULL;
		return;
	}
	te_count++;
	event_add_timed(ev_ctx, ev_ctx, timeval_current_ofs(0,500), timed_handler, private);
}

static bool test_event_context(struct torture_context *torture_ctx,
							   const void *test_data)
{
	struct event_context *ev_ctx;
	int fd[2] = { -1, -1 };
	const char *backend = (const char *)test_data;
	TALLOC_CTX *mem_ctx = torture_ctx;

	test = torture_ctx;

	ev_ctx = event_context_init_byname(mem_ctx, backend);
	if (ev_ctx == NULL) {
		torture_comment(test, "event backend '%s' not supported\n", backend);
		return true;
	}

	torture_comment(test, "Testing event backend '%s'\n", backend);

	/* reset globals */
	write_fd = -1;
	read_fd = -1;
	fde = NULL;
	te_count = 0;
	fde_count = 0;

	/* create a pipe */
	pipe(fd);
	read_fd = fd[0];
	write_fd = fd[1];

	fde = event_add_fd(ev_ctx, ev_ctx, read_fd, EVENT_FD_READ, 
			   fde_handler, &read_fd);

	event_add_timed(ev_ctx, ev_ctx, timeval_current_ofs(0,500), 
			timed_handler, fde);

	event_loop_wait(ev_ctx);

	close(read_fd);
	close(write_fd);
	
	talloc_free(ev_ctx);
	return true;
}

struct torture_suite *torture_local_event(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "EVENT");
	const char **list = event_backend_list(suite);
	int i;

	for (i=0;list && list[i];i++) {
		torture_suite_add_simple_tcase(suite, list[i],
					       test_event_context,
					       (const void *)list[i]);
	}

	return suite;
}
