/*
 * Unix SMB/CIFS implementation.
 * Samba internal messaging functions
 * Copyright (C) 2013 by Volker Lendecke
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "util/util.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "system/select.h"
#include "lib/util/debug.h"
#include "messages_dgm.h"
#include "lib/util/genrand.h"
#include "lib/util/dlinklist.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"
#include "lib/util/msghdr.h"
#include "lib/util/iov_buf.h"
#include "lib/util/blocking.h"
#include "lib/util/tevent_unix.h"

#define MESSAGING_DGM_FRAGMENT_LENGTH 1024

struct sun_path_buf {
	/*
	 * This will carry enough for a socket path
	 */
	char buf[sizeof(struct sockaddr_un)];
};

/*
 * We can only have one tevent_fd per dgm_context and per
 * tevent_context. Maintain a list of registered tevent_contexts per
 * dgm_context.
 */
struct messaging_dgm_fde_ev {
	struct messaging_dgm_fde_ev *prev, *next;

	/*
	 * Backreference to enable DLIST_REMOVE from our
	 * destructor. Also, set to NULL when the dgm_context dies
	 * before the messaging_dgm_fde_ev.
	 */
	struct messaging_dgm_context *ctx;

	struct tevent_context *ev;
	struct tevent_fd *fde;
};

struct messaging_dgm_out {
	struct messaging_dgm_out *prev, *next;
	struct messaging_dgm_context *ctx;

	pid_t pid;
	int sock;
	bool is_blocking;
	uint64_t cookie;

	struct tevent_queue *queue;
	struct tevent_timer *idle_timer;
};

struct messaging_dgm_in_msg {
	struct messaging_dgm_in_msg *prev, *next;
	struct messaging_dgm_context *ctx;
	size_t msglen;
	size_t received;
	pid_t sender_pid;
	int sender_sock;
	uint64_t cookie;
	uint8_t buf[];
};

struct messaging_dgm_context {
	struct tevent_context *ev;
	pid_t pid;
	struct sun_path_buf socket_dir;
	struct sun_path_buf lockfile_dir;
	int lockfile_fd;

	int sock;
	struct messaging_dgm_in_msg *in_msgs;

	struct messaging_dgm_fde_ev *fde_evs;
	void (*recv_cb)(struct tevent_context *ev,
			const uint8_t *msg,
			size_t msg_len,
			int *fds,
			size_t num_fds,
			void *private_data);
	void *recv_cb_private_data;

	bool *have_dgm_context;

	struct pthreadpool_tevent *pool;
	struct messaging_dgm_out *outsocks;
};

/* Set socket close on exec. */
static int prepare_socket_cloexec(int sock)
{
#ifdef FD_CLOEXEC
	int flags;

	flags = fcntl(sock, F_GETFD, 0);
	if (flags == -1) {
		return errno;
	}
	flags |= FD_CLOEXEC;
	if (fcntl(sock, F_SETFD, flags) == -1) {
		return errno;
	}
#endif
	return 0;
}

static void close_fd_array(int *fds, size_t num_fds)
{
	size_t i;

	for (i = 0; i < num_fds; i++) {
		if (fds[i] == -1) {
			continue;
		}

		close(fds[i]);
		fds[i] = -1;
	}
}

/*
 * The idle handler can free the struct messaging_dgm_out *,
 * if it's unused (qlen of zero) which closes the socket.
 */

static void messaging_dgm_out_idle_handler(struct tevent_context *ev,
					   struct tevent_timer *te,
					   struct timeval current_time,
					   void *private_data)
{
	struct messaging_dgm_out *out = talloc_get_type_abort(
		private_data, struct messaging_dgm_out);
	size_t qlen;

	out->idle_timer = NULL;

	qlen = tevent_queue_length(out->queue);
	if (qlen == 0) {
		TALLOC_FREE(out);
	}
}

/*
 * Setup the idle handler to fire afer 1 second if the
 * queue is zero.
 */

static void messaging_dgm_out_rearm_idle_timer(struct messaging_dgm_out *out)
{
	size_t qlen;

	qlen = tevent_queue_length(out->queue);
	if (qlen != 0) {
		TALLOC_FREE(out->idle_timer);
		return;
	}

	if (out->idle_timer != NULL) {
		tevent_update_timer(out->idle_timer,
				    tevent_timeval_current_ofs(1, 0));
		return;
	}

	out->idle_timer = tevent_add_timer(
		out->ctx->ev, out, tevent_timeval_current_ofs(1, 0),
		messaging_dgm_out_idle_handler, out);
	/*
	 * No NULL check, we'll come back here. Worst case we're
	 * leaking a bit.
	 */
}

static int messaging_dgm_out_destructor(struct messaging_dgm_out *dst);
static void messaging_dgm_out_idle_handler(struct tevent_context *ev,
					   struct tevent_timer *te,
					   struct timeval current_time,
					   void *private_data);

/*
 * Connect to an existing rendezvous point for another
 * pid - wrapped inside a struct messaging_dgm_out *.
 */

static int messaging_dgm_out_create(TALLOC_CTX *mem_ctx,
				    struct messaging_dgm_context *ctx,
				    pid_t pid, struct messaging_dgm_out **pout)
{
	struct messaging_dgm_out *out;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int ret = ENOMEM;
	int out_pathlen;
	char addr_buf[sizeof(addr.sun_path) + (3 * sizeof(unsigned) + 2)];

	out = talloc(mem_ctx, struct messaging_dgm_out);
	if (out == NULL) {
		goto fail;
	}

	*out = (struct messaging_dgm_out) {
		.pid = pid,
		.ctx = ctx,
		.cookie = 1
	};

	out_pathlen = snprintf(addr_buf, sizeof(addr_buf),
			       "%s/%u", ctx->socket_dir.buf, (unsigned)pid);
	if (out_pathlen < 0) {
		goto errno_fail;
	}
	if ((size_t)out_pathlen >= sizeof(addr.sun_path)) {
		ret = ENAMETOOLONG;
		goto fail;
	}

	memcpy(addr.sun_path, addr_buf, out_pathlen + 1);

	out->queue = tevent_queue_create(out, addr.sun_path);
	if (out->queue == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	out->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (out->sock == -1) {
		goto errno_fail;
	}

	DLIST_ADD(ctx->outsocks, out);
	talloc_set_destructor(out, messaging_dgm_out_destructor);

	do {
		ret = connect(out->sock,
			      (const struct sockaddr *)(const void *)&addr,
			      sizeof(addr));
	} while ((ret == -1) && (errno == EINTR));

	if (ret == -1) {
		goto errno_fail;
	}

	ret = set_blocking(out->sock, false);
	if (ret == -1) {
		goto errno_fail;
	}
	out->is_blocking = false;

	*pout = out;
	return 0;
errno_fail:
	ret = errno;
fail:
	TALLOC_FREE(out);
	return ret;
}

static int messaging_dgm_out_destructor(struct messaging_dgm_out *out)
{
	DLIST_REMOVE(out->ctx->outsocks, out);

	if ((tevent_queue_length(out->queue) != 0) &&
	    (getpid() == out->ctx->pid)) {
		/*
		 * We have pending jobs. We can't close the socket,
		 * this has been handed over to messaging_dgm_out_queue_state.
		 */
		return 0;
	}

	if (out->sock != -1) {
		close(out->sock);
		out->sock = -1;
	}
	return 0;
}

/*
 * Find the struct messaging_dgm_out * to talk to pid.
 * If we don't have one, create it. Set the timer to
 * delete after 1 sec.
 */

static int messaging_dgm_out_get(struct messaging_dgm_context *ctx, pid_t pid,
				 struct messaging_dgm_out **pout)
{
	struct messaging_dgm_out *out;
	int ret;

	for (out = ctx->outsocks; out != NULL; out = out->next) {
		if (out->pid == pid) {
			break;
		}
	}

	if (out == NULL) {
		ret = messaging_dgm_out_create(ctx, ctx, pid, &out);
		if (ret != 0) {
			return ret;
		}
	}

	/*
	 * shouldn't be possible, should be set if messaging_dgm_out_create
	 * succeeded. This check is to satisfy static checker
	 */
	if (out == NULL) {
		return EINVAL;
	}
	messaging_dgm_out_rearm_idle_timer(out);

	*pout = out;
	return 0;
}

/*
 * This function is called directly to send a message fragment
 * when the outgoing queue is zero, and from a pthreadpool
 * job thread when messages are being queued (qlen != 0).
 * Make sure *ONLY* thread-safe functions are called within.
 */

static ssize_t messaging_dgm_sendmsg(int sock,
				     const struct iovec *iov, int iovlen,
				     const int *fds, size_t num_fds,
				     int *perrno)
{
	struct msghdr msg;
	ssize_t fdlen, ret;

	/*
	 * Do the actual sendmsg syscall. This will be called from a
	 * pthreadpool helper thread, so be careful what you do here.
	 */

	msg = (struct msghdr) {
		.msg_iov = discard_const_p(struct iovec, iov),
		.msg_iovlen = iovlen
	};

	fdlen = msghdr_prep_fds(&msg, NULL, 0, fds, num_fds);
	if (fdlen == -1) {
		*perrno = EINVAL;
		return -1;
	}

	{
		uint8_t buf[fdlen];

		msghdr_prep_fds(&msg, buf, fdlen, fds, num_fds);

		do {
			ret = sendmsg(sock, &msg, 0);
		} while ((ret == -1) && (errno == EINTR));
	}

	if (ret == -1) {
		*perrno = errno;
	}
	return ret;
}

struct messaging_dgm_out_queue_state {
	struct tevent_context *ev;
	struct pthreadpool_tevent *pool;

	struct tevent_req *req;
	struct tevent_req *subreq;

	int sock;

	int *fds;
	uint8_t *buf;

	ssize_t sent;
	int err;
};

static int messaging_dgm_out_queue_state_destructor(
	struct messaging_dgm_out_queue_state *state);
static void messaging_dgm_out_queue_trigger(struct tevent_req *req,
					   void *private_data);
static void messaging_dgm_out_threaded_job(void *private_data);
static void messaging_dgm_out_queue_done(struct tevent_req *subreq);

/*
 * Push a message fragment onto a queue to be sent by a
 * threadpool job. Makes copies of data/fd's to be sent.
 * The running tevent_queue internally creates an immediate
 * event to schedule the write.
 */

static struct tevent_req *messaging_dgm_out_queue_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct messaging_dgm_out *out,
	const struct iovec *iov, int iovlen, const int *fds, size_t num_fds)
{
	struct tevent_req *req;
	struct messaging_dgm_out_queue_state *state;
	struct tevent_queue_entry *e;
	size_t i;
	ssize_t buflen;

	req = tevent_req_create(out, &state,
				struct messaging_dgm_out_queue_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->pool = out->ctx->pool;
	state->sock = out->sock;
	state->req = req;

	/*
	 * Go blocking in a thread
	 */
	if (!out->is_blocking) {
		int ret = set_blocking(out->sock, true);
		if (ret == -1) {
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}
		out->is_blocking = true;
	}

	buflen = iov_buflen(iov, iovlen);
	if (buflen == -1) {
		tevent_req_error(req, EMSGSIZE);
		return tevent_req_post(req, ev);
	}

	state->buf = talloc_array(state, uint8_t, buflen);
	if (tevent_req_nomem(state->buf, req)) {
		return tevent_req_post(req, ev);
	}
	iov_buf(iov, iovlen, state->buf, buflen);

	state->fds = talloc_array(state, int, num_fds);
	if (tevent_req_nomem(state->fds, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_fds; i++) {
		state->fds[i] = -1;
	}

	for (i=0; i<num_fds; i++) {

		state->fds[i] = dup(fds[i]);

		if (state->fds[i] == -1) {
			int ret = errno;

			close_fd_array(state->fds, num_fds);

			tevent_req_error(req, ret);
			return tevent_req_post(req, ev);
		}
	}

	talloc_set_destructor(state, messaging_dgm_out_queue_state_destructor);

	e = tevent_queue_add_entry(out->queue, ev, req,
				   messaging_dgm_out_queue_trigger, req);
	if (tevent_req_nomem(e, req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static int messaging_dgm_out_queue_state_destructor(
	struct messaging_dgm_out_queue_state *state)
{
	int *fds;
	size_t num_fds;

	if (state->subreq != NULL) {
		/*
		 * We're scheduled, but we're destroyed. This happens
		 * if the messaging_dgm_context is destroyed while
		 * we're stuck in a blocking send. There's nothing we
		 * can do but to leak memory.
		 */
		TALLOC_FREE(state->subreq);
		(void)talloc_reparent(state->req, NULL, state);
		return -1;
	}

	fds = state->fds;
	num_fds = talloc_array_length(fds);
	close_fd_array(fds, num_fds);
	return 0;
}

/*
 * tevent_queue callback that schedules the pthreadpool to actually
 * send the queued message fragment.
 */

static void messaging_dgm_out_queue_trigger(struct tevent_req *req,
					   void *private_data)
{
	struct messaging_dgm_out_queue_state *state = tevent_req_data(
		req, struct messaging_dgm_out_queue_state);

	tevent_req_reset_endtime(req);

	state->subreq = pthreadpool_tevent_job_send(
		state, state->ev, state->pool,
		messaging_dgm_out_threaded_job, state);
	if (tevent_req_nomem(state->subreq, req)) {
		return;
	}
	tevent_req_set_callback(state->subreq, messaging_dgm_out_queue_done,
				req);
}

/*
 * Wrapper function run by the pthread that calls
 * messaging_dgm_sendmsg() to actually do the sendmsg().
 */

static void messaging_dgm_out_threaded_job(void *private_data)
{
	struct messaging_dgm_out_queue_state *state = talloc_get_type_abort(
		private_data, struct messaging_dgm_out_queue_state);

	struct iovec iov = { .iov_base = state->buf,
			     .iov_len = talloc_get_size(state->buf) };
	size_t num_fds = talloc_array_length(state->fds);
	int msec = 1;

	while (true) {
		int ret;

		state->sent = messaging_dgm_sendmsg(state->sock, &iov, 1,
					    state->fds, num_fds, &state->err);

		if (state->sent != -1) {
			return;
		}
		if (state->err != ENOBUFS) {
			return;
		}

		/*
		 * ENOBUFS is the FreeBSD way of saying "Try
		 * again". We have to do polling.
		 */
		do {
			ret = poll(NULL, 0, msec);
		} while ((ret == -1) && (errno == EINTR));

		/*
		 * Exponential backoff up to once a second
		 */
		msec *= 2;
		msec = MIN(msec, 1000);
	}
}

/*
 * Pickup the results of the pthread sendmsg().
 */

static void messaging_dgm_out_queue_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct messaging_dgm_out_queue_state *state = tevent_req_data(
		req, struct messaging_dgm_out_queue_state);
	int ret;

	if (subreq != state->subreq) {
		abort();
	}

	ret = pthreadpool_tevent_job_recv(subreq);

	TALLOC_FREE(subreq);
	state->subreq = NULL;

	if (tevent_req_error(req, ret)) {
		return;
	}
	if (state->sent == -1) {
		tevent_req_error(req, state->err);
		return;
	}
	tevent_req_done(req);
}

static int messaging_dgm_out_queue_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static void messaging_dgm_out_sent_fragment(struct tevent_req *req);

/*
 * Core function to send a message fragment given a
 * connected struct messaging_dgm_out * destination.
 * If no current queue tries to send nonblocking
 * directly. If not, queues the fragment (which makes
 * a copy of it) and adds a 60-second timeout on the send.
 */

static int messaging_dgm_out_send_fragment(
	struct tevent_context *ev, struct messaging_dgm_out *out,
	const struct iovec *iov, int iovlen, const int *fds, size_t num_fds)
{
	struct tevent_req *req;
	size_t qlen;
	bool ok;

	qlen = tevent_queue_length(out->queue);
	if (qlen == 0) {
		ssize_t nsent;
		int err = 0;

		if (out->is_blocking) {
			int ret = set_blocking(out->sock, false);
			if (ret == -1) {
				return errno;
			}
			out->is_blocking = false;
		}

		nsent = messaging_dgm_sendmsg(out->sock, iov, iovlen, fds,
					      num_fds, &err);
		if (nsent >= 0) {
			return 0;
		}

		if (err == ENOBUFS) {
			/*
			 * FreeBSD's way of telling us the dst socket
			 * is full. EWOULDBLOCK makes us spawn a
			 * polling helper thread.
			 */
			err = EWOULDBLOCK;
		}

		if (err != EWOULDBLOCK) {
			return err;
		}
	}

	req = messaging_dgm_out_queue_send(out, ev, out, iov, iovlen,
					   fds, num_fds);
	if (req == NULL) {
		return ENOMEM;
	}
	tevent_req_set_callback(req, messaging_dgm_out_sent_fragment, out);

	ok = tevent_req_set_endtime(req, ev,
				    tevent_timeval_current_ofs(60, 0));
	if (!ok) {
		TALLOC_FREE(req);
		return ENOMEM;
	}

	return 0;
}

/*
 * Pickup the result of the fragment send. Reset idle timer
 * if queue empty.
 */

static void messaging_dgm_out_sent_fragment(struct tevent_req *req)
{
	struct messaging_dgm_out *out = tevent_req_callback_data(
		req, struct messaging_dgm_out);
	int ret;

	ret = messaging_dgm_out_queue_recv(req);
	TALLOC_FREE(req);

	if (ret != 0) {
		DBG_WARNING("messaging_out_queue_recv returned %s\n",
			    strerror(ret));
	}

	messaging_dgm_out_rearm_idle_timer(out);
}


struct messaging_dgm_fragment_hdr {
	size_t msglen;
	pid_t pid;
	int sock;
};

/*
 * Fragment a message into MESSAGING_DGM_FRAGMENT_LENGTH - 64-bit cookie
 * size chunks and send it.
 *
 * Message fragments are prefixed by a 64-bit cookie that
 * stays the same for all fragments. This allows the receiver
 * to recognise fragments of the same message and re-assemble
 * them on the other end.
 *
 * Note that this allows other message fragments from other
 * senders to be interleaved in the receive read processing,
 * the combination of the cookie and header info allows unique
 * identification of the message from a specific sender in
 * re-assembly.
 *
 * If the message is smaller than MESSAGING_DGM_FRAGMENT_LENGTH - cookie
 * then send a single message with cookie set to zero.
 *
 * Otherwise the message is fragmented into chunks and added
 * to the sending queue. Any file descriptors are passed only
 * in the last fragment.
 *
 * Finally the cookie is incremented (wrap over zero) to
 * prepare for the next message sent to this channel.
 *
 */

static int messaging_dgm_out_send_fragmented(struct tevent_context *ev,
					     struct messaging_dgm_out *out,
					     const struct iovec *iov,
					     int iovlen,
					     const int *fds, size_t num_fds)
{
	ssize_t msglen, sent;
	int ret = 0;
	struct iovec iov_copy[iovlen+2];
	struct messaging_dgm_fragment_hdr hdr;
	struct iovec src_iov;

	if (iovlen < 0) {
		return EINVAL;
	}

	msglen = iov_buflen(iov, iovlen);
	if (msglen == -1) {
		return EMSGSIZE;
	}
	if (num_fds > INT8_MAX) {
		return EINVAL;
	}

	if ((size_t) msglen <=
	    (MESSAGING_DGM_FRAGMENT_LENGTH - sizeof(uint64_t))) {
		uint64_t cookie = 0;

		iov_copy[0].iov_base = &cookie;
		iov_copy[0].iov_len = sizeof(cookie);
		if (iovlen > 0) {
			memcpy(&iov_copy[1], iov,
			       sizeof(struct iovec) * iovlen);
		}

		return messaging_dgm_out_send_fragment(
			ev, out, iov_copy, iovlen+1, fds, num_fds);

	}

	hdr = (struct messaging_dgm_fragment_hdr) {
		.msglen = msglen,
		.pid = getpid(),
		.sock = out->sock
	};

	iov_copy[0].iov_base = &out->cookie;
	iov_copy[0].iov_len = sizeof(out->cookie);
	iov_copy[1].iov_base = &hdr;
	iov_copy[1].iov_len = sizeof(hdr);

	sent = 0;
	src_iov = iov[0];

	/*
	 * The following write loop sends the user message in pieces. We have
	 * filled the first two iovecs above with "cookie" and "hdr". In the
	 * following loops we pull message chunks from the user iov array and
	 * fill iov_copy piece by piece, possibly truncating chunks from the
	 * caller's iov array. Ugly, but hopefully efficient.
	 */

	while (sent < msglen) {
		size_t fragment_len;
		size_t iov_index = 2;

		fragment_len = sizeof(out->cookie) + sizeof(hdr);

		while (fragment_len < MESSAGING_DGM_FRAGMENT_LENGTH) {
			size_t space, chunk;

			space = MESSAGING_DGM_FRAGMENT_LENGTH - fragment_len;
			chunk = MIN(space, src_iov.iov_len);

			iov_copy[iov_index].iov_base = src_iov.iov_base;
			iov_copy[iov_index].iov_len = chunk;
			iov_index += 1;

			src_iov.iov_base = (char *)src_iov.iov_base + chunk;
			src_iov.iov_len -= chunk;
			fragment_len += chunk;

			if (src_iov.iov_len == 0) {
				iov += 1;
				iovlen -= 1;
				if (iovlen == 0) {
					break;
				}
				src_iov = iov[0];
			}
		}
		sent += (fragment_len - sizeof(out->cookie) - sizeof(hdr));

		/*
		 * only the last fragment should pass the fd array.
		 * That simplifies the receiver a lot.
		 */
		if (sent < msglen) {
			ret = messaging_dgm_out_send_fragment(
				ev, out, iov_copy, iov_index, NULL, 0);
		} else {
			ret = messaging_dgm_out_send_fragment(
				ev, out, iov_copy, iov_index, fds, num_fds);
		}
		if (ret != 0) {
			break;
		}
	}

	out->cookie += 1;
	if (out->cookie == 0) {
		out->cookie += 1;
	}

	return ret;
}

static struct messaging_dgm_context *global_dgm_context;

static int messaging_dgm_context_destructor(struct messaging_dgm_context *c);

static int messaging_dgm_lockfile_create(struct messaging_dgm_context *ctx,
					 pid_t pid, int *plockfile_fd,
					 uint64_t *punique)
{
	char buf[64];
	int lockfile_fd;
	struct sun_path_buf lockfile_name;
	struct flock lck;
	uint64_t unique;
	int unique_len, ret;
	ssize_t written;

	ret = snprintf(lockfile_name.buf, sizeof(lockfile_name.buf),
		       "%s/%u", ctx->lockfile_dir.buf, (unsigned)pid);
	if (ret < 0) {
		return errno;
	}
	if ((unsigned)ret >= sizeof(lockfile_name.buf)) {
		return ENAMETOOLONG;
	}

	/* no O_EXCL, existence check is via the fcntl lock */

	lockfile_fd = open(lockfile_name.buf, O_NONBLOCK|O_CREAT|O_RDWR,
			   0644);

        if ((lockfile_fd == -1) &&
	    ((errno == ENXIO) /* Linux */ ||
	     (errno == ENODEV) /* Linux kernel bug */ ||
	     (errno == EOPNOTSUPP) /* FreeBSD */)) {
		/*
                 * Huh -- a socket? This might be a stale socket from
                 * an upgrade of Samba. Just unlink and retry, nobody
                 * else is supposed to be here at this time.
                 *
                 * Yes, this is racy, but I don't see a way to deal
                 * with this properly.
                 */
		unlink(lockfile_name.buf);

		lockfile_fd = open(lockfile_name.buf,
				   O_NONBLOCK|O_CREAT|O_WRONLY,
				   0644);
	}

	if (lockfile_fd == -1) {
		ret = errno;
		DEBUG(1, ("%s: open failed: %s\n", __func__, strerror(errno)));
		return ret;
	}

	lck = (struct flock) {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET
	};

	ret = fcntl(lockfile_fd, F_SETLK, &lck);
	if (ret == -1) {
		ret = errno;
		DEBUG(1, ("%s: fcntl failed: %s\n", __func__, strerror(ret)));
		goto fail_close;
	}

	/*
	 * Directly using the binary value for
	 * SERVERID_UNIQUE_ID_NOT_TO_VERIFY is a layering
	 * violation. But including all of ndr here just for this
	 * seems to be a bit overkill to me. Also, messages_dgm might
	 * be replaced sooner or later by something streams-based,
	 * where unique_id generation will be handled differently.
	 */

	do {
		generate_random_buffer((uint8_t *)&unique, sizeof(unique));
	} while (unique == UINT64_C(0xFFFFFFFFFFFFFFFF));

	unique_len = snprintf(buf, sizeof(buf), "%ju\n", (uintmax_t)unique);

	/* shorten a potentially preexisting file */

	ret = ftruncate(lockfile_fd, unique_len);
	if (ret == -1) {
		ret = errno;
		DEBUG(1, ("%s: ftruncate failed: %s\n", __func__,
			  strerror(ret)));
		goto fail_unlink;
	}

	written = write(lockfile_fd, buf, unique_len);
	if (written != unique_len) {
		ret = errno;
		DEBUG(1, ("%s: write failed: %s\n", __func__, strerror(ret)));
		goto fail_unlink;
	}

	*plockfile_fd = lockfile_fd;
	*punique = unique;
	return 0;

fail_unlink:
	unlink(lockfile_name.buf);
fail_close:
	close(lockfile_fd);
	return ret;
}

static void messaging_dgm_read_handler(struct tevent_context *ev,
				       struct tevent_fd *fde,
				       uint16_t flags,
				       void *private_data);

/*
 * Create the rendezvous point in the file system
 * that other processes can use to send messages to
 * this pid.
 */

int messaging_dgm_init(struct tevent_context *ev,
		       uint64_t *punique,
		       const char *socket_dir,
		       const char *lockfile_dir,
		       void (*recv_cb)(struct tevent_context *ev,
				       const uint8_t *msg,
				       size_t msg_len,
				       int *fds,
				       size_t num_fds,
				       void *private_data),
		       void *recv_cb_private_data)
{
	struct messaging_dgm_context *ctx;
	int ret;
	struct sockaddr_un socket_address;
	size_t len;
	static bool have_dgm_context = false;

	if (have_dgm_context) {
		return EEXIST;
	}

	ctx = talloc_zero(NULL, struct messaging_dgm_context);
	if (ctx == NULL) {
		goto fail_nomem;
	}
	ctx->ev = ev;
	ctx->pid = getpid();
	ctx->recv_cb = recv_cb;
	ctx->recv_cb_private_data = recv_cb_private_data;

	len = strlcpy(ctx->lockfile_dir.buf, lockfile_dir,
		      sizeof(ctx->lockfile_dir.buf));
	if (len >= sizeof(ctx->lockfile_dir.buf)) {
		TALLOC_FREE(ctx);
		return ENAMETOOLONG;
	}

	len = strlcpy(ctx->socket_dir.buf, socket_dir,
		      sizeof(ctx->socket_dir.buf));
	if (len >= sizeof(ctx->socket_dir.buf)) {
		TALLOC_FREE(ctx);
		return ENAMETOOLONG;
	}

	socket_address = (struct sockaddr_un) { .sun_family = AF_UNIX };
	len = snprintf(socket_address.sun_path,
		       sizeof(socket_address.sun_path),
		       "%s/%u", socket_dir, (unsigned)ctx->pid);
	if (len >= sizeof(socket_address.sun_path)) {
		TALLOC_FREE(ctx);
		return ENAMETOOLONG;
	}

	ret = messaging_dgm_lockfile_create(ctx, ctx->pid, &ctx->lockfile_fd,
					    punique);
	if (ret != 0) {
		DEBUG(1, ("%s: messaging_dgm_create_lockfile failed: %s\n",
			  __func__, strerror(ret)));
		TALLOC_FREE(ctx);
		return ret;
	}

	unlink(socket_address.sun_path);

	ctx->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ctx->sock == -1) {
		ret = errno;
		DBG_WARNING("socket failed: %s\n", strerror(ret));
		TALLOC_FREE(ctx);
		return ret;
	}

	ret = prepare_socket_cloexec(ctx->sock);
	if (ret == -1) {
		ret = errno;
		DBG_WARNING("prepare_socket_cloexec failed: %s\n",
			    strerror(ret));
		TALLOC_FREE(ctx);
		return ret;
	}

	ret = bind(ctx->sock, (struct sockaddr *)(void *)&socket_address,
		   sizeof(socket_address));
	if (ret == -1) {
		ret = errno;
		DBG_WARNING("bind failed: %s\n", strerror(ret));
		TALLOC_FREE(ctx);
		return ret;
	}

	talloc_set_destructor(ctx, messaging_dgm_context_destructor);

	ctx->have_dgm_context = &have_dgm_context;

	ret = pthreadpool_tevent_init(ctx, UINT_MAX, &ctx->pool);
	if (ret != 0) {
		DBG_WARNING("pthreadpool_tevent_init failed: %s\n",
			    strerror(ret));
		TALLOC_FREE(ctx);
		return ret;
	}

	global_dgm_context = ctx;
	return 0;

fail_nomem:
	TALLOC_FREE(ctx);
	return ENOMEM;
}

/*
 * Remove the rendezvous point in the filesystem
 * if we're the owner.
 */

static int messaging_dgm_context_destructor(struct messaging_dgm_context *c)
{
	while (c->outsocks != NULL) {
		TALLOC_FREE(c->outsocks);
	}
	while (c->in_msgs != NULL) {
		TALLOC_FREE(c->in_msgs);
	}
	while (c->fde_evs != NULL) {
		tevent_fd_set_flags(c->fde_evs->fde, 0);
		c->fde_evs->ctx = NULL;
		DLIST_REMOVE(c->fde_evs, c->fde_evs);
	}

	close(c->sock);

	if (getpid() == c->pid) {
		struct sun_path_buf name;
		int ret;

		ret = snprintf(name.buf, sizeof(name.buf), "%s/%u",
			       c->socket_dir.buf, (unsigned)c->pid);
		if ((ret < 0) || ((size_t)ret >= sizeof(name.buf))) {
			/*
			 * We've checked the length when creating, so this
			 * should never happen
			 */
			abort();
		}
		unlink(name.buf);

		ret = snprintf(name.buf, sizeof(name.buf), "%s/%u",
			       c->lockfile_dir.buf, (unsigned)c->pid);
		if ((ret < 0) || ((size_t)ret >= sizeof(name.buf))) {
			/*
			 * We've checked the length when creating, so this
			 * should never happen
			 */
			abort();
		}
		unlink(name.buf);
	}
	close(c->lockfile_fd);

	if (c->have_dgm_context != NULL) {
		*c->have_dgm_context = false;
	}

	return 0;
}

static void messaging_dgm_validate(struct messaging_dgm_context *ctx)
{
#ifdef DEVELOPER
	pid_t pid = getpid();
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	struct sockaddr_un *un_addr;
	struct sun_path_buf pathbuf;
	struct stat st1, st2;
	int ret;

	/*
	 * Protect against using the wrong messaging context after a
	 * fork without reinit_after_fork.
	 */

	ret = getsockname(ctx->sock, (struct sockaddr *)&addr, &addrlen);
	if (ret == -1) {
		DBG_ERR("getsockname failed: %s\n", strerror(errno));
		goto fail;
	}
	if (addr.ss_family != AF_UNIX) {
		DBG_ERR("getsockname returned family %d\n",
			(int)addr.ss_family);
		goto fail;
	}
	un_addr = (struct sockaddr_un *)&addr;

	ret = snprintf(pathbuf.buf, sizeof(pathbuf.buf),
		       "%s/%u", ctx->socket_dir.buf, (unsigned)pid);
	if (ret < 0) {
		DBG_ERR("snprintf failed: %s\n", strerror(errno));
		goto fail;
	}
	if ((size_t)ret >= sizeof(pathbuf.buf)) {
		DBG_ERR("snprintf returned %d chars\n", (int)ret);
		goto fail;
	}

	if (strcmp(pathbuf.buf, un_addr->sun_path) != 0) {
		DBG_ERR("sockname wrong: Expected %s, got %s\n",
			pathbuf.buf, un_addr->sun_path);
		goto fail;
	}

	ret = snprintf(pathbuf.buf, sizeof(pathbuf.buf),
		       "%s/%u", ctx->lockfile_dir.buf, (unsigned)pid);
	if (ret < 0) {
		DBG_ERR("snprintf failed: %s\n", strerror(errno));
		goto fail;
	}
	if ((size_t)ret >= sizeof(pathbuf.buf)) {
		DBG_ERR("snprintf returned %d chars\n", (int)ret);
		goto fail;
	}

	ret = stat(pathbuf.buf, &st1);
	if (ret == -1) {
		DBG_ERR("stat failed: %s\n", strerror(errno));
		goto fail;
	}
	ret = fstat(ctx->lockfile_fd, &st2);
	if (ret == -1) {
		DBG_ERR("fstat failed: %s\n", strerror(errno));
		goto fail;
	}

	if ((st1.st_dev != st2.st_dev) || (st1.st_ino != st2.st_ino)) {
		DBG_ERR("lockfile differs, expected (%d/%d), got (%d/%d)\n",
			(int)st2.st_dev, (int)st2.st_ino,
			(int)st1.st_dev, (int)st1.st_ino);
		goto fail;
	}

	return;
fail:
	abort();
#else
	return;
#endif
}

static void messaging_dgm_recv(struct messaging_dgm_context *ctx,
			       struct tevent_context *ev,
			       uint8_t *msg, size_t msg_len,
			       int *fds, size_t num_fds);

/*
 * Raw read callback handler - passes to messaging_dgm_recv()
 * for fragment reassembly processing.
 */

static void messaging_dgm_read_handler(struct tevent_context *ev,
				       struct tevent_fd *fde,
				       uint16_t flags,
				       void *private_data)
{
	struct messaging_dgm_context *ctx = talloc_get_type_abort(
		private_data, struct messaging_dgm_context);
	ssize_t received;
	struct msghdr msg;
	struct iovec iov;
	size_t msgbufsize = msghdr_prep_recv_fds(NULL, NULL, 0, INT8_MAX);
	uint8_t msgbuf[msgbufsize];
	uint8_t buf[MESSAGING_DGM_FRAGMENT_LENGTH];
	size_t num_fds;

	messaging_dgm_validate(ctx);

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}

	iov = (struct iovec) { .iov_base = buf, .iov_len = sizeof(buf) };
	msg = (struct msghdr) { .msg_iov = &iov, .msg_iovlen = 1 };

	msghdr_prep_recv_fds(&msg, msgbuf, msgbufsize, INT8_MAX);

#ifdef MSG_CMSG_CLOEXEC
	msg.msg_flags |= MSG_CMSG_CLOEXEC;
#endif

	received = recvmsg(ctx->sock, &msg, 0);
	if (received == -1) {
		if ((errno == EAGAIN) ||
		    (errno == EWOULDBLOCK) ||
		    (errno == EINTR) ||
		    (errno == ENOMEM)) {
			/* Not really an error - just try again. */
			return;
		}
		/* Problem with the socket. Set it unreadable. */
		tevent_fd_set_flags(fde, 0);
		return;
	}

	if ((size_t)received > sizeof(buf)) {
		/* More than we expected, not for us */
		return;
	}

	num_fds = msghdr_extract_fds(&msg, NULL, 0);
	if (num_fds == 0) {
		int fds[1];

		messaging_dgm_recv(ctx, ev, buf, received, fds, 0);
	} else {
		size_t i;
		int fds[num_fds];

		msghdr_extract_fds(&msg, fds, num_fds);

		for (i = 0; i < num_fds; i++) {
			int err;

			err = prepare_socket_cloexec(fds[i]);
			if (err != 0) {
				close_fd_array(fds, num_fds);
				num_fds = 0;
			}
		}

		messaging_dgm_recv(ctx, ev, buf, received, fds, num_fds);
	}
}

static int messaging_dgm_in_msg_destructor(struct messaging_dgm_in_msg *m)
{
	DLIST_REMOVE(m->ctx->in_msgs, m);
	return 0;
}

/*
 * Deal with identification of fragmented messages and
 * re-assembly into full messages sent, then calls the
 * callback.
 */

static void messaging_dgm_recv(struct messaging_dgm_context *ctx,
			       struct tevent_context *ev,
			       uint8_t *buf, size_t buflen,
			       int *fds, size_t num_fds)
{
	struct messaging_dgm_fragment_hdr hdr;
	struct messaging_dgm_in_msg *msg;
	size_t space;
	uint64_t cookie;

	if (buflen < sizeof(cookie)) {
		goto close_fds;
	}
	memcpy(&cookie, buf, sizeof(cookie));
	buf += sizeof(cookie);
	buflen -= sizeof(cookie);

	if (cookie == 0) {
		ctx->recv_cb(ev, buf, buflen, fds, num_fds,
			     ctx->recv_cb_private_data);
		return;
	}

	if (buflen < sizeof(hdr)) {
		goto close_fds;
	}
	memcpy(&hdr, buf, sizeof(hdr));
	buf += sizeof(hdr);
	buflen -= sizeof(hdr);

	for (msg = ctx->in_msgs; msg != NULL; msg = msg->next) {
		if ((msg->sender_pid == hdr.pid) &&
		    (msg->sender_sock == hdr.sock)) {
			break;
		}
	}

	if ((msg != NULL) && (msg->cookie != cookie)) {
		TALLOC_FREE(msg);
	}

	if (msg == NULL) {
		size_t msglen;
		msglen = offsetof(struct messaging_dgm_in_msg, buf) +
			hdr.msglen;

		msg = talloc_size(ctx, msglen);
		if (msg == NULL) {
			goto close_fds;
		}
		talloc_set_name_const(msg, "struct messaging_dgm_in_msg");

		*msg = (struct messaging_dgm_in_msg) {
			.ctx = ctx, .msglen = hdr.msglen,
			.sender_pid = hdr.pid, .sender_sock = hdr.sock,
			.cookie = cookie
		};
		DLIST_ADD(ctx->in_msgs, msg);
		talloc_set_destructor(msg, messaging_dgm_in_msg_destructor);
	}

	space = msg->msglen - msg->received;
	if (buflen > space) {
		goto close_fds;
	}

	memcpy(msg->buf + msg->received, buf, buflen);
	msg->received += buflen;

	if (msg->received < msg->msglen) {
		/*
		 * Any valid sender will send the fds in the last
		 * block. Invalid senders might have sent fd's that we
		 * need to close here.
		 */
		goto close_fds;
	}

	DLIST_REMOVE(ctx->in_msgs, msg);
	talloc_set_destructor(msg, NULL);

	ctx->recv_cb(ev, msg->buf, msg->msglen, fds, num_fds,
		     ctx->recv_cb_private_data);

	TALLOC_FREE(msg);
	return;

close_fds:
	close_fd_array(fds, num_fds);
}

void messaging_dgm_destroy(void)
{
	TALLOC_FREE(global_dgm_context);
}

int messaging_dgm_send(pid_t pid,
		       const struct iovec *iov, int iovlen,
		       const int *fds, size_t num_fds)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	struct messaging_dgm_out *out;
	int ret;
	unsigned retries = 0;

	if (ctx == NULL) {
		return ENOTCONN;
	}

	messaging_dgm_validate(ctx);

again:
	ret = messaging_dgm_out_get(ctx, pid, &out);
	if (ret != 0) {
		return ret;
	}

	DEBUG(10, ("%s: Sending message to %u\n", __func__, (unsigned)pid));

	ret = messaging_dgm_out_send_fragmented(ctx->ev, out, iov, iovlen,
						fds, num_fds);
	if (ret == ECONNREFUSED) {
		/*
		 * We cache outgoing sockets. If the receiver has
		 * closed and re-opened the socket since our last
		 * message, we get connection refused. Retry.
		 */

		TALLOC_FREE(out);

		if (retries < 5) {
			retries += 1;
			goto again;
		}
	}
	return ret;
}

static int messaging_dgm_read_unique(int fd, uint64_t *punique)
{
	char buf[25];
	ssize_t rw_ret;
	int error = 0;
	unsigned long long unique;
	char *endptr;

	rw_ret = pread(fd, buf, sizeof(buf)-1, 0);
	if (rw_ret == -1) {
		return errno;
	}
	buf[rw_ret] = '\0';

	unique = smb_strtoull(buf, &endptr, 10, &error, SMB_STR_STANDARD);
	if (error != 0) {
		return error;
	}

	if (endptr[0] != '\n') {
		return EINVAL;
	}
	*punique = unique;
	return 0;
}

int messaging_dgm_get_unique(pid_t pid, uint64_t *unique)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	struct sun_path_buf lockfile_name;
	int ret, fd;

	if (ctx == NULL) {
		return EBADF;
	}

	messaging_dgm_validate(ctx);

	if (pid == getpid()) {
		/*
		 * Protect against losing our own lock
		 */
		return messaging_dgm_read_unique(ctx->lockfile_fd, unique);
	}

	ret = snprintf(lockfile_name.buf, sizeof(lockfile_name.buf),
		       "%s/%u", ctx->lockfile_dir.buf, (int)pid);
	if (ret < 0) {
		return errno;
	}
	if ((size_t)ret >= sizeof(lockfile_name.buf)) {
		return ENAMETOOLONG;
	}

	fd = open(lockfile_name.buf, O_NONBLOCK|O_RDONLY, 0);
	if (fd == -1) {
		return errno;
	}

	ret = messaging_dgm_read_unique(fd, unique);
	close(fd);
	return ret;
}

int messaging_dgm_cleanup(pid_t pid)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	struct sun_path_buf lockfile_name, socket_name;
	int fd, len, ret;
	struct flock lck = {
		.l_pid = 0,
	};

	if (ctx == NULL) {
		return ENOTCONN;
	}

	len = snprintf(socket_name.buf, sizeof(socket_name.buf), "%s/%u",
		       ctx->socket_dir.buf, (unsigned)pid);
	if (len < 0) {
		return errno;
	}
	if ((size_t)len >= sizeof(socket_name.buf)) {
		return ENAMETOOLONG;
	}

	len = snprintf(lockfile_name.buf, sizeof(lockfile_name.buf), "%s/%u",
		       ctx->lockfile_dir.buf, (unsigned)pid);
	if (len < 0) {
		return errno;
	}
	if ((size_t)len >= sizeof(lockfile_name.buf)) {
		return ENAMETOOLONG;
	}

	fd = open(lockfile_name.buf, O_NONBLOCK|O_WRONLY, 0);
	if (fd == -1) {
		ret = errno;
		if (ret != ENOENT) {
			DEBUG(10, ("%s: open(%s) failed: %s\n", __func__,
				   lockfile_name.buf, strerror(ret)));
		}
		return ret;
	}

	lck.l_type = F_WRLCK;
	lck.l_whence = SEEK_SET;
	lck.l_start = 0;
	lck.l_len = 0;

	ret = fcntl(fd, F_SETLK, &lck);
	if (ret != 0) {
		ret = errno;
		if ((ret != EACCES) && (ret != EAGAIN)) {
			DEBUG(10, ("%s: Could not get lock: %s\n", __func__,
				   strerror(ret)));
		}
		close(fd);
		return ret;
	}

	DEBUG(10, ("%s: Cleaning up : %s\n", __func__, strerror(ret)));

	(void)unlink(socket_name.buf);
	(void)unlink(lockfile_name.buf);
	(void)close(fd);
	return 0;
}

static int messaging_dgm_wipe_fn(pid_t pid, void *private_data)
{
	pid_t *our_pid = (pid_t *)private_data;
	int ret;

	if (pid == *our_pid) {
		/*
		 * fcntl(F_GETLK) will succeed for ourselves, we hold
		 * that lock ourselves.
		 */
		return 0;
	}

	ret = messaging_dgm_cleanup(pid);
	DEBUG(10, ("messaging_dgm_cleanup(%lu) returned %s\n",
		   (unsigned long)pid, ret ? strerror(ret) : "ok"));

	return 0;
}

int messaging_dgm_wipe(void)
{
	pid_t pid = getpid();
	messaging_dgm_forall(messaging_dgm_wipe_fn, &pid);
	return 0;
}

int messaging_dgm_forall(int (*fn)(pid_t pid, void *private_data),
			 void *private_data)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	DIR *msgdir;
	struct dirent *dp;
	int error = 0;

	if (ctx == NULL) {
		return ENOTCONN;
	}

	messaging_dgm_validate(ctx);

	/*
	 * We scan the socket directory and not the lock directory. Otherwise
	 * we would race against messaging_dgm_lockfile_create's open(O_CREAT)
	 * and fcntl(SETLK).
	 */

	msgdir = opendir(ctx->socket_dir.buf);
	if (msgdir == NULL) {
		return errno;
	}

	while ((dp = readdir(msgdir)) != NULL) {
		unsigned long pid;
		int ret;

		pid = smb_strtoul(dp->d_name, NULL, 10, &error, SMB_STR_STANDARD);
		if ((pid == 0) || (error != 0)) {
			/*
			 * . and .. and other malformed entries
			 */
			continue;
		}

		ret = fn(pid, private_data);
		if (ret != 0) {
			break;
		}
	}
	closedir(msgdir);

	return 0;
}

struct messaging_dgm_fde {
	struct tevent_fd *fde;
};

static int messaging_dgm_fde_ev_destructor(struct messaging_dgm_fde_ev *fde_ev)
{
	if (fde_ev->ctx != NULL) {
		DLIST_REMOVE(fde_ev->ctx->fde_evs, fde_ev);
		fde_ev->ctx = NULL;
	}
	return 0;
}

/*
 * Reference counter for a struct tevent_fd messaging read event
 * (with callback function) on a struct tevent_context registered
 * on a messaging context.
 *
 * If we've already registered this struct tevent_context before
 * (so already have a read event), just increase the reference count.
 *
 * Otherwise create a new struct tevent_fd messaging read event on the
 * previously unseen struct tevent_context - this is what drives
 * the message receive processing.
 *
 */

struct messaging_dgm_fde *messaging_dgm_register_tevent_context(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	struct messaging_dgm_fde_ev *fde_ev;
	struct messaging_dgm_fde *fde;

	if (ctx == NULL) {
		return NULL;
	}

	fde = talloc(mem_ctx, struct messaging_dgm_fde);
	if (fde == NULL) {
		return NULL;
	}

	for (fde_ev = ctx->fde_evs; fde_ev != NULL; fde_ev = fde_ev->next) {
		if (tevent_fd_get_flags(fde_ev->fde) == 0) {
			/*
			 * If the event context got deleted,
			 * tevent_fd_get_flags() will return 0
			 * for the stale fde.
			 *
			 * In that case we should not
			 * use fde_ev->ev anymore.
			 */
			continue;
		}
		if (fde_ev->ev == ev) {
			break;
		}
	}

	if (fde_ev == NULL) {
		fde_ev = talloc(fde, struct messaging_dgm_fde_ev);
		if (fde_ev == NULL) {
			return NULL;
		}
		fde_ev->fde = tevent_add_fd(
			ev, fde_ev, ctx->sock, TEVENT_FD_READ,
			messaging_dgm_read_handler, ctx);
		if (fde_ev->fde == NULL) {
			TALLOC_FREE(fde);
			return NULL;
		}
		fde_ev->ev = ev;
		fde_ev->ctx = ctx;
		DLIST_ADD(ctx->fde_evs, fde_ev);
		talloc_set_destructor(
			fde_ev, messaging_dgm_fde_ev_destructor);
	} else {
		/*
		 * Same trick as with tdb_wrap: The caller will never
		 * see the talloc_referenced object, the
		 * messaging_dgm_fde_ev, so problems with
		 * talloc_unlink will not happen.
		 */
		if (talloc_reference(fde, fde_ev) == NULL) {
			TALLOC_FREE(fde);
			return NULL;
		}
	}

	fde->fde = fde_ev->fde;
	return fde;
}

bool messaging_dgm_fde_active(struct messaging_dgm_fde *fde)
{
	uint16_t flags;

	if (fde == NULL) {
		return false;
	}
	flags = tevent_fd_get_flags(fde->fde);
	return (flags != 0);
}
