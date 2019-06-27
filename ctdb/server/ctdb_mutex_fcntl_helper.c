/*
   CTDB mutex fcntl lock file helper

   Copyright (C) Martin Schwenke 2015

   wait_for_parent() code from ctdb_lock_helper.c:

   Copyright (C) Amitay Isaacs  2013

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"

#include <tevent.h>

#include "lib/util/sys_rw.h"
#include "lib/util/tevent_unix.h"

/* protocol.h is just needed for ctdb_sock_addr, which is used in system.h */
#include "protocol/protocol.h"
#include "common/system.h"

static char *progname = NULL;

static char fcntl_lock(const char *file, int *outfd)
{
	int fd;
	struct flock lock;

	fd = open(file, O_RDWR|O_CREAT, 0600);
	if (fd == -1) {
		fprintf(stderr, "%s: Unable to open %s - (%s)\n",
			progname, file, strerror(errno));
		return '3';
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 1;
	lock.l_pid = 0;

	if (fcntl(fd, F_SETLK, &lock) != 0) {
		int saved_errno = errno;
		close(fd);
		if (saved_errno == EACCES ||
		    saved_errno == EAGAIN) {
			/* Lock contention, fail silently */
			return '1';
		}

		/* Log an error for any other failure */
		fprintf(stderr,
			"%s: Failed to get lock on '%s' - (%s)\n",
			progname, file, strerror(saved_errno));
		return '3';
	}

	*outfd = fd;

	return '0';
}

/*
 * Wait and see if the parent exits
 */

struct wait_for_parent_state {
	struct tevent_context *ev;
	pid_t ppid;
};

static void wait_for_parent_check(struct tevent_req *subreq);

static struct tevent_req *wait_for_parent_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       pid_t ppid)
{
	struct tevent_req *req, *subreq;
	struct wait_for_parent_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wait_for_parent_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->ppid = ppid;

	if (ppid == 1) {
		fprintf(stderr, "parent == 1\n");
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = tevent_wakeup_send(state, ev,
				    tevent_timeval_current_ofs(5,0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wait_for_parent_check, req);

	return req;
}

static void wait_for_parent_check(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wait_for_parent_state *state = tevent_req_data(
		req, struct wait_for_parent_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		/* Ignore error */
		fprintf(stderr,
			"ctdb_mutex_fcntl_helper: "
			"tevent_wakeup_recv() failed\n");
	}

	if (kill(state->ppid, 0) == -1 && errno == ESRCH) {
		fprintf(stderr, "parent gone\n");
		tevent_req_done(req);
		return;
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(5,0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wait_for_parent_check, req);
}

static bool wait_for_parent_recv(struct tevent_req *req)
{
	if (tevent_req_is_unix_error(req, NULL)) {
		return false;
	}

	return true;
}

int main(int argc, char *argv[])
{
	struct tevent_context *ev;
	char result;
	int ppid;
	const char *file = NULL;
	int fd = -1;
	struct tevent_req *req;
	bool status;

	progname = argv[0];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", progname);
		exit(1);
	}

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "locking: tevent_context_init() failed\n");
		exit(1);
	}

	ppid = getppid();

	file = argv[1];

	result = fcntl_lock(file, &fd);
	sys_write(STDOUT_FILENO, &result, 1);

	if (result != '0') {
		return 0;
	}

	req = wait_for_parent_send(ev, ev, ppid);
	if (req == NULL) {
		fprintf(stderr,
			"%s: wait_for_parent_send() failed\n",
			progname);
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = wait_for_parent_recv(req);
	if (! status) {
		fprintf(stderr,
			"%s: wait_for_parent_recv() failed\n",
			progname);
	}

	if (fd != -1) {
		close(fd);
	}

	return 0;
}
