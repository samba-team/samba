/*
   Unix SMB/CIFS implementation.
   Test for a messaging_read bug
   Copyright (C) Volker Lendecke 2014

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

struct msg_count_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	uint32_t msg_type;
	unsigned *count;
};

static void msg_count_done(struct tevent_req *subreq);

static struct tevent_req *msg_count_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct messaging_context *msg_ctx,
					 uint32_t msg_type,
					 unsigned *count)
{
	struct tevent_req *req, *subreq;
	struct msg_count_state *state;

	req = tevent_req_create(mem_ctx, &state, struct msg_count_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;
	state->msg_type = msg_type;
	state->count = count;

	subreq = messaging_read_send(state, state->ev, state->msg_ctx,
				     state->msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msg_count_done, req);
	return req;
}

static void msg_count_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct msg_count_state *state = tevent_req_data(
		req, struct msg_count_state);
	int ret;

	ret = messaging_read_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	*state->count += 1;

	subreq = messaging_read_send(state, state->ev, state->msg_ctx,
				     state->msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, msg_count_done, req);
}

bool run_messaging_read1(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct tevent_req *req1 = NULL;
	unsigned count1 = 0;
	struct tevent_req *req2 = NULL;
	unsigned count2 = 0;
	NTSTATUS status;
	bool retval = false;
	int i;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}
	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}

	req1 = msg_count_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY, &count1);
	if (req1 == NULL) {
		fprintf(stderr, "msg_count_send failed\n");
		goto fail;
	}
	req2 = msg_count_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY, &count2);
	if (req1 == NULL) {
		fprintf(stderr, "msg_count_send failed\n");
		goto fail;
	}
	status = messaging_send_buf(msg_ctx, messaging_server_id(msg_ctx),
				    MSG_SMB_NOTIFY, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "messaging_send_buf failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	for (i=0; i<2; i++) {
		if (tevent_loop_once(ev) != 0) {
			fprintf(stderr, "tevent_loop_once failed\n");
			goto fail;
		}
	}

	printf("%u/%u\n", count1, count2);

	if ((count1 != 1) || (count2 != 1)){
		fprintf(stderr, "Got %u/%u msgs, expected 1 each\n",
			count1, count2);
		goto fail;
	}

	retval = true;
fail:
	TALLOC_FREE(req1);
	TALLOC_FREE(req2);
	TALLOC_FREE(msg_ctx);
	TALLOC_FREE(ev);
	return retval;
}

struct msg_free_state {
	struct tevent_req **to_free;
};

static void msg_free_done(struct tevent_req *subreq);

static struct tevent_req *msg_free_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct messaging_context *msg_ctx,
					uint32_t msg_type,
					struct tevent_req **to_free)
{
	struct tevent_req *req, *subreq;
	struct msg_free_state *state;

	req = tevent_req_create(mem_ctx, &state, struct msg_free_state);
	if (req == NULL) {
		return NULL;
	}
	state->to_free = to_free;

	subreq = messaging_read_send(state, ev, msg_ctx, msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msg_free_done, req);
	return req;
}

static void msg_free_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct msg_free_state *state = tevent_req_data(
		req, struct msg_free_state);
	int ret;

	ret = messaging_read_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	TALLOC_FREE(*state->to_free);
	tevent_req_done(req);
}

bool run_messaging_read2(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct tevent_req *req1 = NULL;
	struct tevent_req *req2 = NULL;
	unsigned count = 0;
	NTSTATUS status;
	bool retval = false;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}
	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}

	req1 = msg_free_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY, &req2);
	if (req1 == NULL) {
		fprintf(stderr, "msg_count_send failed\n");
		goto fail;
	}
	req2 = msg_count_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY, &count);
	if (req1 == NULL) {
		fprintf(stderr, "msg_count_send failed\n");
		goto fail;
	}
	status = messaging_send_buf(msg_ctx, messaging_server_id(msg_ctx),
				    MSG_SMB_NOTIFY, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "messaging_send_buf failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	if (!tevent_req_poll(req1, ev) != 0) {
		fprintf(stderr, "tevent_req_poll failed\n");
		goto fail;
	}

	if (count != 0) {
		fprintf(stderr, "Got %u msgs, expected none\n", count);
		goto fail;
	}

	retval = true;
fail:
	TALLOC_FREE(req1);
	TALLOC_FREE(msg_ctx);
	TALLOC_FREE(ev);
	return retval;
}

struct msg_pingpong_state {
	uint8_t dummy;
};

static void msg_pingpong_done(struct tevent_req *subreq);

static struct tevent_req *msg_pingpong_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct messaging_context *msg_ctx,
					    struct server_id dst)
{
	struct tevent_req *req, *subreq;
	struct msg_pingpong_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct msg_pingpong_state);
	if (req == NULL) {
		return NULL;
	}

	status = messaging_send_buf(msg_ctx, dst, MSG_PING, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_error(req, map_errno_from_nt_status(status));
		return tevent_req_post(req, ev);
	}

	subreq = messaging_read_send(state, ev, msg_ctx, MSG_PONG);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msg_pingpong_done, req);
	return req;
}

static void msg_pingpong_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;

	ret = messaging_read_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}
	tevent_req_done(req);
}

static int msg_pingpong_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

static int msg_pingpong(struct messaging_context *msg_ctx,
			struct server_id dst)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	int ret = ENOMEM;

	ev = tevent_context_init(msg_ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = msg_pingpong_send(ev, ev, msg_ctx, dst);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		ret = errno;
		goto fail;
	}
	ret = msg_pingpong_recv(req);
fail:
	TALLOC_FREE(ev);
	return ret;
}

static void ping_responder_exit(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_data)
{
	bool *done = private_data;

	printf("Child: received write on exit-pipe\n");

	*done = true;
}

static void ping_responder(int ready_pipe, int exit_pipe)
{
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct tevent_fd *exit_handler;
	char c = 0;
	bool done = false;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "child tevent_context_init failed\n");
		exit(1);
	}
	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "child messaging_init failed\n");
		exit(1);
	}
	exit_handler = tevent_add_fd(ev, ev, exit_pipe, TEVENT_FD_READ,
				     ping_responder_exit, &done);
	if (exit_handler == NULL) {
		fprintf(stderr, "child tevent_add_fd failed\n");
		exit(1);
	}

	if (write(ready_pipe, &c, 1) != 1) {
		fprintf(stderr, "child messaging_init failed\n");
		exit(1);
	}

	while (!done) {
		int ret;
		ret = tevent_loop_once(ev);
		if (ret != 0) {
			fprintf(stderr, "child tevent_loop_once failed\n");
			exit(1);
		}
	}

	printf("Child: done, exiting...\n");

	TALLOC_FREE(msg_ctx);
	TALLOC_FREE(ev);
}

bool run_messaging_read3(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	bool retval = false;
	pid_t child;
	int ready_pipe[2];
	int exit_pipe[2];
	int ret;
	char c;
	struct server_id dst;
	ssize_t written;

	if ((pipe(ready_pipe) != 0) || (pipe(exit_pipe) != 0)) {
		perror("pipe failed");
		return false;
	}

	child = fork();
	if (child == -1) {
		perror("fork failed");
		return false;
	}

	if (child == 0) {
		close(ready_pipe[0]);
		close(exit_pipe[1]);
		ping_responder(ready_pipe[1], exit_pipe[0]);
		exit(0);
	}
	close(ready_pipe[1]);
	close(exit_pipe[0]);

	if (read(ready_pipe[0], &c, 1) != 1) {
		perror("read failed");
		return false;
	}

	ev = samba_tevent_context_init(talloc_tos());
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
	dst.pid = child;

	ret = msg_pingpong(msg_ctx, dst);
	if (ret != 0){
		fprintf(stderr, "msg_pingpong failed\n");
		goto fail;
	}

	printf("Parent: telling child to exit\n");

	written = write(exit_pipe[1], &c, 1);
	if (written != 1) {
		perror("write to exit_pipe failed");
		goto fail;
	}

	ret = waitpid(child, NULL, 0);
	if (ret == -1) {
		perror("waitpid failed");
		goto fail;
	}

	printf("Parent: child exited. Done\n");

	retval = true;
fail:
	TALLOC_FREE(msg_ctx);
	TALLOC_FREE(ev);
	return retval;
}

/**
 * read4:
 *
 * test transferring a big payload.
 */

#define MSG_TORTURE_READ4 0xF104

static bool read4_child(int ready_fd)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	bool retval = false;
	uint8_t c = 1;
	struct tevent_req *subreq;
	int ret;
	ssize_t bytes;
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

	printf("child: telling parent we're ready to receive messages\n");

	/* Tell the parent we are ready to receive mesages. */
	bytes = write(ready_fd, &c, 1);
	if (bytes != 1) {
		perror("child: failed to write to ready_fd");
		goto done;
	}

	printf("child: waiting for messages\n");

	subreq = messaging_read_send(frame, /* TALLOC_CTX */
				     ev, msg_ctx,
				     MSG_TORTURE_READ4);
	if (subreq == NULL) {
		fprintf(stderr, "child: messaging_read_send failed\n");
		goto done;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		fprintf(stderr, "child: tevent_req_poll failed\n");
		goto done;
	}

	printf("child: receiving message\n");

	ret = messaging_read_recv(subreq, frame, &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		fprintf(stderr, "child: messaging_read_recv failed\n");
		goto done;
	}

	printf("child: received message\n");

	/* Tell the parent we are done. */
	bytes = write(ready_fd, &c, 1);
	if (bytes != 1) {
		perror("child: failed to write to ready_fd");
		goto done;
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

static bool read4_parent(pid_t child_pid, int ready_fd)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	bool retval = false;
	int ret;
	NTSTATUS status;
	struct server_id dst;
	TALLOC_CTX *frame = talloc_stackframe();
	uint8_t c;
	ssize_t bytes;
	struct iovec iov;
	DATA_BLOB blob;
	struct tevent_fd *child_done_fde;
	struct child_done_state child_state;

	/* wait until the child is ready to receive messages */
	bytes = read(ready_fd, &c, 1);
	if (bytes != 1) {
		perror("parent: read from ready_fd failed");
		goto done;
	}

	printf("parent: child is ready to receive messages\n");

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

	child_state.fd = ready_fd;
	child_state.done = false;

	child_done_fde = tevent_add_fd(ev, ev, ready_fd, TEVENT_FD_READ,
				       child_done_cb, &child_state);
	if (child_done_fde == NULL) {
		fprintf(stderr,
			"parent: failed tevent_add_fd for child done\n");
		goto done;
	}

	/*
	 * Send a 1M payload with the message.
	 */
	blob = data_blob_talloc_zero(frame, 1000*1000);
	iov.iov_base = blob.data;
	iov.iov_len  = blob.length;

	dst = messaging_server_id(msg_ctx);
	dst.pid = child_pid;

	printf("parent: sending message to child\n");

	status = messaging_send_iov(msg_ctx, dst, MSG_TORTURE_READ4, &iov, 1,
				    NULL, 0);
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

	ret = waitpid(child_pid, NULL, 0);
	if (ret == -1) {
		perror("parent: waitpid failed");
		goto done;
	}

	printf("parent: done\n");

	retval = true;

done:
	TALLOC_FREE(frame);
	return retval;
}

bool run_messaging_read4(int dummy)
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
		retval = read4_child(ready_pipe[1]);
	} else {
		close(ready_pipe[1]);
		retval = read4_parent(child_pid, ready_pipe[0]);
	}

	return retval;
}
