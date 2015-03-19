/*
   Unix SMB/CIFS implementation.
   Test for fd passing with messaging

   Copyright (C) Michael Adam 2014

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

#include "includes.h"
#include "torture/proto.h"
#include "lib/util/tevent_unix.h"
#include "messages.h"

/**
 * test fdpass1:
 *
 * Try to pass an fd to the sending process - fails.
 */
bool run_messaging_fdpass1(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	bool retval = false;
	int pipe_fds[2];
	int pass_fds[1] = { 0 };
	int ret;
	NTSTATUS status;
	struct server_id dst;
	TALLOC_CTX *frame = talloc_stackframe();

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}
	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}

	dst = messaging_server_id(msg_ctx);

	ret = pipe(pipe_fds);
	if (ret != 0) {
		perror("pipe failed");
		goto fail;
	}

	pass_fds[0] = pipe_fds[0];

	status = messaging_send_iov(msg_ctx, dst, MSG_PING, NULL, 0,
				    pass_fds, 1);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		fprintf(stderr,
			"messaging_send_iov gave: %s\n", nt_errstr(status));
		goto fail;
	}

	retval = true;

fail:
	TALLOC_FREE(frame);
	return retval;
}

/**
 * test fdpass2:
 *
 * - parent: create a child
 * - parent: create a two pipes in the parent: up and down
 * - parent: pass the up pipe's reading end and the down pipe's writing
 *   end to the child and close them
 * - parent: write a number into the up pipe's writing end
 * - child: read number from the passed reading fd (up)
 * - child: write the read number to the passed writing fd (down)
 * - parent: read number from the down pipe's reading end and compare with
 *   original number
 */

#define MSG_TORTURE_FDPASS2 0xF002

static bool fdpass2_filter(struct messaging_rec *rec, void *private_data)
{
	if (rec->msg_type != MSG_TORTURE_FDPASS2) {
		return false;
	}

	if (rec->num_fds != 2) {
		return false;
	}

	return true;
}

static bool fdpass2_child(int ready_fd)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	bool retval = false;
	uint8_t c = 1;
	struct tevent_req *subreq;
	int ret;
	ssize_t bytes;
	int up_fd, down_fd;
	struct messaging_rec *rec;
	bool ok;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		fprintf(stderr, "child: tevent_context_init failed\n");
		goto done;
	}

	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "child: messaging_init failed\n");
		goto done;
	}

	/* Tell the parent we are ready to receive mesages. */
	bytes = write(ready_fd, &c, 1);
	if (bytes != 1) {
		perror("child: failed to write to ready_fd");
		goto done;
	}

	subreq = messaging_filtered_read_send(frame, /* TALLOC_CTX */
					      ev, msg_ctx,
					      fdpass2_filter, NULL);
	if (subreq == NULL) {
		fprintf(stderr, "child: messaging_filtered_read_send failed\n");
		goto done;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		fprintf(stderr, "child: tevent_req_poll failed\n");
		goto done;
	}

	ret = messaging_filtered_read_recv(subreq, frame, &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		fprintf(stderr, "child: messaging_filtered_read_recv failed\n");
		goto done;
	}

	SMB_ASSERT(rec->num_fds == 2);

	/* Tell the parent we are done. */
	bytes = write(ready_fd, &c, 1);
	if (bytes != 1) {
		perror("child: failed to write to ready_fd");
		goto done;
	}

	up_fd = rec->fds[0];
	down_fd = rec->fds[1];

	bytes = read(up_fd, &c, 1);
	if (bytes != 1) {
		perror("child: read from up_fd failed");
		goto done;
	}

	bytes = write(down_fd, &c, 1);
	if (bytes != 1) {
		perror("child: write to down_fd failed");
	}

	printf("child: done\n");

	retval = true;

done:
	TALLOC_FREE(frame);
	return retval;
}

struct child_done_state {
	int fd;
	bool done;
};

static void child_done_cb(struct tevent_context *ev,
			  struct tevent_fd *fde,
			  uint16_t flags,
			  void *private_data)
{
	struct child_done_state *state =
			(struct child_done_state *)private_data;
	char c = 0;
	ssize_t bytes;

	bytes = read(state->fd, &c, 1);
	if (bytes != 1) {
		perror("parent: read from ready_fd failed");
	}

	state->done = true;
}

static bool fdpass2_parent(pid_t child_pid, int ready_fd, size_t payload_size)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	bool retval = false;
	int up_pipe[2];
	int down_pipe[2];
	int pass_fds[2] = { 0 };
	int ret;
	NTSTATUS status;
	struct server_id dst;
	TALLOC_CTX *frame = talloc_stackframe();
	uint8_t c1 = 1, c2, c;
	ssize_t bytes;
	struct iovec iov;
	DATA_BLOB blob;
	struct tevent_fd *child_done_fde;
	struct child_done_state child_state;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		fprintf(stderr, "parent: tevent_context_init failed\n");
		goto done;
	}

	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "parent: messaging_init failed\n");
		goto done;
	}

	/* wait util the child is ready to receive messages */
	bytes = read(ready_fd, &c, 1);
	if (bytes != 1) {
		perror("parent: read from ready_fd failed");
		goto done;
	}

	ret = pipe(up_pipe);
	if (ret != 0) {
		perror("parent: pipe failed for up_pipe");
		goto done;
	}

	ret = pipe(down_pipe);
	if (ret != 0) {
		perror("parent: pipe failed for down_pipe");
		goto done;
	}

	child_state.fd = ready_fd;
	child_state.done = false;

	child_done_fde = tevent_add_fd(ev, ev, ready_fd, TEVENT_FD_READ,
				       child_done_cb, &child_state);
	if (child_done_fde == NULL) {
		fprintf(stderr,
			"parent: failed tevent_add_fd for child done\n");
		goto done;
	}

	pass_fds[0] = up_pipe[0];
	pass_fds[1] = down_pipe[1];

	dst = messaging_server_id(msg_ctx);
	dst.pid = child_pid;

	/*
	 * Send a certain payload with the fds, to test to test
	 * that fd-passing works when we have fragmentation and
	 * re-assembly of the datagrams.
	 *
	 * Fragmentation/queuing is triggered by a certain payload
	 * size. Payloads below that size use the fast path.
	 */
	blob = data_blob_talloc_zero(frame, payload_size);
	iov.iov_base = blob.data;
	iov.iov_len  = blob.length;

	status = messaging_send_iov(msg_ctx, dst, MSG_TORTURE_FDPASS2, &iov, 1,
				    pass_fds, 2);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "parent: messaging_send_iov failed: %s\n",
			nt_errstr(status));
		goto done;
	}

	printf("parent: waiting for child to confirm\n");

	while (!child_state.done) {
		ret = tevent_loop_once(ev);
		if (ret != 0) {
			fprintf(stderr, "parent: tevent_loop_once failed\n");
			goto done;
		}
	}

	printf("parent: child confirmed\n");

	close(up_pipe[0]);
	close(down_pipe[1]);

	bytes = write(up_pipe[1], &c1, 1);
	if (bytes != 1) {
		perror("parent: write to up pipe failed");
		goto done;
	}

	bytes = read(down_pipe[0], &c2, 1);
	if (bytes != 1) {
		perror("parent: read from down pipe failed");
		goto done;
	}

	if (c1 != c2) {
		fprintf(stderr, "parent: c1[%d] != c2[%d]\n", c1, c2);
		goto done;
	}

	ret = waitpid(child_pid, NULL, 0);
	if (ret == -1) {
		perror("parent: waitpid failed");
		goto done;
	}

	retval = true;

done:
	TALLOC_FREE(frame);
	return retval;
}

static bool run_messaging_fdpass2_int(int dummy, size_t payload_size)
{
	bool retval = false;
	pid_t child_pid;
	int ready_pipe[2];
	int ret;

	ret = pipe(ready_pipe);
	if (ret != 0) {
		perror("parent: pipe failed for ready_pipe");
		return retval;
	}

	child_pid = fork();
	if (child_pid == -1) {
		perror("fork failed");
	} else if (child_pid == 0) {
		close(ready_pipe[0]);
		retval = fdpass2_child(ready_pipe[1]);
	} else {
		close(ready_pipe[1]);
		retval = fdpass2_parent(child_pid, ready_pipe[0], payload_size);
	}

	return retval;
}

bool run_messaging_fdpass2(int dummy)
{
	return run_messaging_fdpass2_int(dummy, 1000*1000);
}

/**
 * Variant of the FDPASS2 test that tests the non-queuing fast path
 * with a small payload.
 */
bool run_messaging_fdpass2a(int dummy)
{
	return run_messaging_fdpass2_int(dummy, 1);
}

/**
 * Variant of the FDPASS2 test that tests the non-queuing fast path
 * without a payload.
 */
bool run_messaging_fdpass2b(int dummy)
{
	return run_messaging_fdpass2_int(dummy, 0);
}
