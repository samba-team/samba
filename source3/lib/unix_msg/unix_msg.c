/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2013
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
#include "unix_msg.h"
#include "system/select.h"
#include "system/time.h"
#include "system/network.h"
#include "dlinklist.h"
#include "pthreadpool/pthreadpool.h"
#include <fcntl.h>

/*
 * This file implements two abstractions: The "unix_dgram" functions implement
 * queueing for unix domain datagram sockets. You can send to a destination
 * socket, and if that has no free space available, it will fall back to an
 * anonymous socket that will poll for writability. "unix_dgram" expects the
 * data size not to exceed the system limit.
 *
 * The "unix_msg" functions implement the fragmentation of large messages on
 * top of "unix_dgram". This is what is exposed to the user of this API.
 */

struct unix_dgram_msg {
	struct unix_dgram_msg *prev, *next;

	int sock;
	ssize_t sent;
	int sys_errno;
	size_t num_fds;
	struct msghdr msg;
	struct iovec iov;
};

struct unix_dgram_send_queue {
	struct unix_dgram_send_queue *prev, *next;
	struct unix_dgram_ctx *ctx;
	int sock;
	struct unix_dgram_msg *msgs;
	char path[];
};

struct unix_dgram_ctx {
	int sock;
	pid_t created_pid;
	const struct poll_funcs *ev_funcs;
	size_t max_msg;

	void (*recv_callback)(struct unix_dgram_ctx *ctx,
			      uint8_t *msg, size_t msg_len,
			      int *fds, size_t num_fds,
			      void *private_data);
	void *private_data;

	struct poll_watch *sock_read_watch;
	struct unix_dgram_send_queue *send_queues;

	struct pthreadpool *send_pool;
	struct poll_watch *pool_read_watch;

	uint8_t *recv_buf;
	char path[];
};

static ssize_t iov_buflen(const struct iovec *iov, int iovlen);
static void unix_dgram_recv_handler(struct poll_watch *w, int fd, short events,
				    void *private_data);

/* Set socket non blocking. */
static int prepare_socket_nonblock(int sock)
{
	int flags;
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

	flags = fcntl(sock, F_GETFL);
	if (flags == -1) {
		return errno;
	}
	flags |= FLAG_TO_SET;
	if (fcntl(sock, F_SETFL, flags) == -1) {
		return errno;
	}

#undef FLAG_TO_SET
	return 0;
}

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

/* Set socket non blocking and close on exec. */
static int prepare_socket(int sock)
{
	int ret = prepare_socket_nonblock(sock);

	if (ret) {
		return ret;
	}
	return prepare_socket_cloexec(sock);
}

static void extract_fd_array_from_msghdr(struct msghdr *msg, int **fds,
					 size_t *num_fds)
{
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	struct cmsghdr *cmsg;

	for(cmsg = CMSG_FIRSTHDR(msg);
	    cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg))
	{
		void *data = CMSG_DATA(cmsg);

		if (cmsg->cmsg_type != SCM_RIGHTS) {
			continue;
		}
		if (cmsg->cmsg_level != SOL_SOCKET) {
			continue;
		}

		*fds = (int *)data;
		*num_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof (int);
		break;
	}
#endif
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

static void close_fd_array_cmsg(struct msghdr *msg)
{
	int *fds = NULL;
	size_t num_fds = 0;

	extract_fd_array_from_msghdr(msg, &fds, &num_fds);

	/*
	 * TODO: caveat - side-effect - changing msg ???
	 */
	close_fd_array(fds, num_fds);
}

static int unix_dgram_init(const struct sockaddr_un *addr, size_t max_msg,
			   const struct poll_funcs *ev_funcs,
			   void (*recv_callback)(struct unix_dgram_ctx *ctx,
						 uint8_t *msg, size_t msg_len,
						 int *fds, size_t num_fds,
						 void *private_data),
			   void *private_data,
			   struct unix_dgram_ctx **result)
{
	struct unix_dgram_ctx *ctx;
	size_t pathlen;
	int ret;

	if (addr != NULL) {
		pathlen = strlen(addr->sun_path)+1;
	} else {
		pathlen = 1;
	}

	ctx = malloc(offsetof(struct unix_dgram_ctx, path) + pathlen);
	if (ctx == NULL) {
		return ENOMEM;
	}
	if (addr != NULL) {
		memcpy(ctx->path, addr->sun_path, pathlen);
	} else {
		ctx->path[0] = '\0';
	}

	*ctx = (struct unix_dgram_ctx) {
		.max_msg = max_msg,
		.ev_funcs = ev_funcs,
		.recv_callback = recv_callback,
		.private_data = private_data,
		.created_pid = (pid_t)-1
	};

	ctx->recv_buf = malloc(max_msg);
	if (ctx->recv_buf == NULL) {
		free(ctx);
		return ENOMEM;
	}

	ctx->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ctx->sock == -1) {
		ret = errno;
		goto fail_free;
	}

	/* Set non-blocking and close-on-exec. */
	ret = prepare_socket(ctx->sock);
	if (ret != 0) {
		goto fail_close;
	}

	if (addr != NULL) {
		ret = bind(ctx->sock,
			   (const struct sockaddr *)(const void *)addr,
			   sizeof(*addr));
		if (ret == -1) {
			ret = errno;
			goto fail_close;
		}

		ctx->created_pid = getpid();

		ctx->sock_read_watch = ctx->ev_funcs->watch_new(
			ctx->ev_funcs, ctx->sock, POLLIN,
			unix_dgram_recv_handler, ctx);

		if (ctx->sock_read_watch == NULL) {
			ret = ENOMEM;
			goto fail_close;
		}
	}

	*result = ctx;
	return 0;

fail_close:
	close(ctx->sock);
fail_free:
	free(ctx->recv_buf);
	free(ctx);
	return ret;
}

static void unix_dgram_recv_handler(struct poll_watch *w, int fd, short events,
				    void *private_data)
{
	struct unix_dgram_ctx *ctx = (struct unix_dgram_ctx *)private_data;
	ssize_t received;
	int flags = 0;
	struct msghdr msg;
	struct iovec iov;
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	char buf[CMSG_SPACE(sizeof(int)*INT8_MAX)] = { 0, };
#endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */
	int *fds = NULL;
	size_t i, num_fds = 0;

	iov = (struct iovec) {
		.iov_base = (void *)ctx->recv_buf,
		.iov_len = ctx->max_msg,
	};

	msg = (struct msghdr) {
		.msg_iov = &iov,
		.msg_iovlen = 1,
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
#endif
	};

#ifdef MSG_CMSG_CLOEXEC
	flags |= MSG_CMSG_CLOEXEC;
#endif

	received = recvmsg(fd, &msg, flags);
	if (received == -1) {
		if ((errno == EAGAIN) ||
		    (errno == EWOULDBLOCK) ||
		    (errno == EINTR) || (errno == ENOMEM)) {
			/* Not really an error - just try again. */
			return;
		}
		/* Problem with the socket. Set it unreadable. */
		ctx->ev_funcs->watch_update(w, 0);
		return;
	}
	if (received > ctx->max_msg) {
		/* More than we expected, not for us */
		return;
	}

	extract_fd_array_from_msghdr(&msg, &fds, &num_fds);

	for (i = 0; i < num_fds; i++) {
		int err;

		err = prepare_socket_cloexec(fds[i]);
		if (err != 0) {
			goto cleanup_fds;
		}
	}

	ctx->recv_callback(ctx, ctx->recv_buf, received,
			   fds, num_fds, ctx->private_data);

	/*
	 * Close those fds that the callback has not set to -1.
	 */
	close_fd_array(fds, num_fds);

	return;

cleanup_fds:
	close_fd_array(fds, num_fds);

	ctx->recv_callback(ctx, ctx->recv_buf, received,
			   NULL, 0, ctx->private_data);
}

static void unix_dgram_job_finished(struct poll_watch *w, int fd, short events,
				    void *private_data);

static int unix_dgram_init_pthreadpool(struct unix_dgram_ctx *ctx)
{
	int ret, signalfd;

	if (ctx->send_pool != NULL) {
		return 0;
	}

	ret = pthreadpool_init(0, &ctx->send_pool);
	if (ret != 0) {
		return ret;
	}

	signalfd = pthreadpool_signal_fd(ctx->send_pool);

	ctx->pool_read_watch = ctx->ev_funcs->watch_new(
		ctx->ev_funcs, signalfd, POLLIN,
		unix_dgram_job_finished, ctx);
	if (ctx->pool_read_watch == NULL) {
		pthreadpool_destroy(ctx->send_pool);
		ctx->send_pool = NULL;
		return ENOMEM;
	}

	return 0;
}

static int unix_dgram_send_queue_init(
	struct unix_dgram_ctx *ctx, const struct sockaddr_un *dst,
	struct unix_dgram_send_queue **result)
{
	struct unix_dgram_send_queue *q;
	size_t pathlen;
	int ret, err;

	pathlen = strlen(dst->sun_path)+1;

	q = malloc(offsetof(struct unix_dgram_send_queue, path) + pathlen);
	if (q == NULL) {
		return ENOMEM;
	}
	q->ctx = ctx;
	q->msgs = NULL;
	memcpy(q->path, dst->sun_path, pathlen);

	q->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (q->sock == -1) {
		err = errno;
		goto fail_free;
	}

	err = prepare_socket_cloexec(q->sock);
	if (err != 0) {
		goto fail_close;
	}

	do {
		ret = connect(q->sock,
			      (const struct sockaddr *)(const void *)dst,
			      sizeof(*dst));
	} while ((ret == -1) && (errno == EINTR));

	if (ret == -1) {
		err = errno;
		goto fail_close;
	}

	err = unix_dgram_init_pthreadpool(ctx);
	if (err != 0) {
		goto fail_close;
	}

	DLIST_ADD(ctx->send_queues, q);

	*result = q;
	return 0;

fail_close:
	close(q->sock);
fail_free:
	free(q);
	return err;
}

static void unix_dgram_send_queue_free(struct unix_dgram_send_queue *q)
{
	struct unix_dgram_ctx *ctx = q->ctx;

	while (q->msgs != NULL) {
		struct unix_dgram_msg *msg;
		msg = q->msgs;
		DLIST_REMOVE(q->msgs, msg);
		close_fd_array_cmsg(&msg->msg);
		free(msg);
	}
	close(q->sock);
	DLIST_REMOVE(ctx->send_queues, q);
	free(q);
}

static struct unix_dgram_send_queue *find_send_queue(
	struct unix_dgram_ctx *ctx, const char *dst_sock)
{
	struct unix_dgram_send_queue *s;

	for (s = ctx->send_queues; s != NULL; s = s->next) {
		if (strcmp(s->path, dst_sock) == 0) {
			return s;
		}
	}
	return NULL;
}

static int queue_msg(struct unix_dgram_send_queue *q,
		     const struct iovec *iov, int iovlen,
		     const int *fds, size_t num_fds)
{
	struct unix_dgram_msg *msg;
	ssize_t data_len;
	uint8_t *data_buf;
	size_t msglen = sizeof(struct unix_dgram_msg);
	int i;
	size_t tmp;
	int ret = -1;
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	size_t fds_size = sizeof(int) * MIN(num_fds, INT8_MAX);
	int fds_copy[MIN(num_fds, INT8_MAX)];
	size_t cmsg_len = CMSG_LEN(fds_size);
	size_t cmsg_space = CMSG_SPACE(fds_size);
	char *cmsg_buf;

	/*
	 * Note: No need to check for overflow here,
	 * since cmsg will store <= INT8_MAX fds.
	 */
	msglen += cmsg_space;

#endif /*  HAVE_STRUCT_MSGHDR_MSG_CONTROL */

	if (num_fds > INT8_MAX) {
		return EINVAL;
	}

#ifndef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (num_fds > 0) {
		return ENOSYS;
	}
#endif

	data_len = iov_buflen(iov, iovlen);
	if (data_len == -1) {
		return EINVAL;
	}

	tmp = msglen + data_len;
	if ((tmp < msglen) || (tmp < data_len)) {
		/* overflow */
		return EINVAL;
	}
	msglen = tmp;

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	for (i = 0; i < num_fds; i++) {
		fds_copy[i] = -1;
	}

	for (i = 0; i < num_fds; i++) {
		fds_copy[i] = dup(fds[i]);
		if (fds_copy[i] == -1) {
			ret = errno;
			goto fail;
		}
	}
#endif

	msg = malloc(msglen);
	if (msg == NULL) {
		ret = ENOMEM;
		goto fail;
	}

	msg->sock = q->sock;
	msg->num_fds = num_fds;

	data_buf = (uint8_t *)(msg + 1);

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (num_fds > 0) {
		cmsg_buf = (char *)data_buf;
		memset(cmsg_buf, 0, cmsg_space);
		data_buf += cmsg_space;
	} else {
		cmsg_buf = NULL;
		cmsg_space = 0;
	}
#endif

	msg->iov = (struct iovec) {
		.iov_base = (void *)data_buf,
		.iov_len = data_len,
	};

	msg->msg = (struct msghdr) {
		.msg_iov = &msg->iov,
		.msg_iovlen = 1,
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
		.msg_control = cmsg_buf,
		.msg_controllen = cmsg_space,
#endif
	};

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (num_fds > 0) {
		struct cmsghdr *cmsg;
		void *fdptr;

		cmsg = CMSG_FIRSTHDR(&msg->msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = cmsg_len;
		fdptr = CMSG_DATA(cmsg);
		memcpy(fdptr, fds_copy, fds_size);
		msg->msg.msg_controllen = cmsg->cmsg_len;
	}
#endif /*  HAVE_STRUCT_MSGHDR_MSG_CONTROL */

	for (i=0; i<iovlen; i++) {
		memcpy(data_buf, iov[i].iov_base, iov[i].iov_len);
		data_buf += iov[i].iov_len;
	}

	DLIST_ADD_END(q->msgs, msg, struct unix_dgram_msg);
	return 0;

fail:
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	close_fd_array(fds_copy, num_fds);
#endif
	return ret;
}

static void unix_dgram_send_job(void *private_data)
{
	struct unix_dgram_msg *dmsg = private_data;

	do {
		dmsg->sent = sendmsg(dmsg->sock, &dmsg->msg, 0);
	} while ((dmsg->sent == -1) && (errno == EINTR));

	if (dmsg->sent == -1) {
		dmsg->sys_errno = errno;
	}
}

static void unix_dgram_job_finished(struct poll_watch *w, int fd, short events,
				    void *private_data)
{
	struct unix_dgram_ctx *ctx = private_data;
	struct unix_dgram_send_queue *q;
	struct unix_dgram_msg *msg;
	int ret, job;

	ret = pthreadpool_finished_jobs(ctx->send_pool, &job, 1);
	if (ret != 1) {
		return;
	}

	for (q = ctx->send_queues; q != NULL; q = q->next) {
		if (job == q->sock) {
			break;
		}
	}

	if (q == NULL) {
		/* Huh? Should not happen */
		return;
	}

	msg = q->msgs;
	DLIST_REMOVE(q->msgs, msg);
	close_fd_array_cmsg(&msg->msg);
	free(msg);

	if (q->msgs != NULL) {
		ret = pthreadpool_add_job(ctx->send_pool, q->sock,
					  unix_dgram_send_job, q->msgs);
		if (ret == 0) {
			return;
		}
	}

	unix_dgram_send_queue_free(q);
}

static int unix_dgram_send(struct unix_dgram_ctx *ctx,
			   const struct sockaddr_un *dst,
			   const struct iovec *iov, int iovlen,
			   const int *fds, size_t num_fds)
{
	struct unix_dgram_send_queue *q;
	struct msghdr msg;
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	struct cmsghdr *cmsg;
	size_t fds_size = sizeof(int) * num_fds;
	size_t cmsg_len = CMSG_LEN(fds_size);
	size_t cmsg_space = CMSG_SPACE(fds_size);
	char cmsg_buf[cmsg_space];
#endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */
	int ret;
	int i;

	if (num_fds > INT8_MAX) {
		return EINVAL;
	}

#ifndef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (num_fds > 0) {
		return ENOSYS;
	}
#endif /* ! HAVE_STRUCT_MSGHDR_MSG_CONTROL */

	for (i = 0; i < num_fds; i++) {
		/*
		 * Make sure we only allow fd passing
		 * for communication channels,
		 * e.g. sockets, pipes, fifos, ...
		 */
		ret = lseek(fds[i], 0, SEEK_CUR);
		if (ret == -1 && errno == ESPIPE) {
			/* ok */
			continue;
		}

		/*
		 * Reject the message as we may need to call dup(),
		 * if we queue the message.
		 *
		 * That might result in unexpected behavior for the caller
		 * for files and broken posix locking.
		 */
		return EINVAL;
	}

	/*
	 * To preserve message ordering, we have to queue a message when
	 * others are waiting in line already.
	 */
	q = find_send_queue(ctx, dst->sun_path);
	if (q != NULL) {
		return queue_msg(q, iov, iovlen, fds, num_fds);
	}

	/*
	 * Try a cheap nonblocking send
	 */

	msg = (struct msghdr) {
		.msg_name = discard_const_p(struct sockaddr_un, dst),
		.msg_namelen = sizeof(*dst),
		.msg_iov = discard_const_p(struct iovec, iov),
		.msg_iovlen = iovlen
	};
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (num_fds > 0) {
		void *fdptr;

		memset(cmsg_buf, 0, cmsg_space);

		msg.msg_control = cmsg_buf;
		msg.msg_controllen = cmsg_space;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = cmsg_len;
		fdptr = CMSG_DATA(cmsg);
		memcpy(fdptr, fds, fds_size);
		msg.msg_controllen = cmsg->cmsg_len;
	}
#endif /*  HAVE_STRUCT_MSGHDR_MSG_CONTROL */

	ret = sendmsg(ctx->sock, &msg, 0);
	if (ret >= 0) {
		return 0;
	}
	if ((errno != EWOULDBLOCK) && (errno != EAGAIN) && (errno != EINTR)) {
		return errno;
	}

	ret = unix_dgram_send_queue_init(ctx, dst, &q);
	if (ret != 0) {
		return ret;
	}
	ret = queue_msg(q, iov, iovlen, fds, num_fds);
	if (ret != 0) {
		unix_dgram_send_queue_free(q);
		return ret;
	}
	ret = pthreadpool_add_job(ctx->send_pool, q->sock,
				  unix_dgram_send_job, q->msgs);
	if (ret != 0) {
		unix_dgram_send_queue_free(q);
		return ret;
	}
	return 0;
}

static int unix_dgram_sock(struct unix_dgram_ctx *ctx)
{
	return ctx->sock;
}

static int unix_dgram_free(struct unix_dgram_ctx *ctx)
{
	if (ctx->send_queues != NULL) {
		return EBUSY;
	}

	if (ctx->send_pool != NULL) {
		int ret = pthreadpool_destroy(ctx->send_pool);
		if (ret != 0) {
			return ret;
		}
		ctx->ev_funcs->watch_free(ctx->pool_read_watch);
	}

	ctx->ev_funcs->watch_free(ctx->sock_read_watch);

	close(ctx->sock);
	if (getpid() == ctx->created_pid) {
		/* If we created it, unlink. Otherwise someone else might
		 * still have it open */
		unlink(ctx->path);
	}

	free(ctx->recv_buf);
	free(ctx);
	return 0;
}

/*
 * Every message starts with a uint64_t cookie.
 *
 * A value of 0 indicates a single-fragment message which is complete in
 * itself. The data immediately follows the cookie.
 *
 * Every multi-fragment message has a cookie != 0 and starts with a cookie
 * followed by a struct unix_msg_header and then the data. The pid and sock
 * fields are used to assure uniqueness on the receiver side.
 */

struct unix_msg_hdr {
	size_t msglen;
	pid_t pid;
	int sock;
};

struct unix_msg {
	struct unix_msg *prev, *next;
	size_t msglen;
	size_t received;
	pid_t sender_pid;
	int sender_sock;
	uint64_t cookie;
	uint8_t buf[1];
};

struct unix_msg_ctx {
	struct unix_dgram_ctx *dgram;
	size_t fragment_len;
	uint64_t cookie;

	void (*recv_callback)(struct unix_msg_ctx *ctx,
			      uint8_t *msg, size_t msg_len,
			      int *fds, size_t num_fds,
			      void *private_data);
	void *private_data;

	struct unix_msg *msgs;
};

static void unix_msg_recv(struct unix_dgram_ctx *dgram_ctx,
			  uint8_t *buf, size_t buflen,
			  int *fds, size_t num_fds,
			  void *private_data);

int unix_msg_init(const struct sockaddr_un *addr,
		  const struct poll_funcs *ev_funcs,
		  size_t fragment_len, uint64_t cookie,
		  void (*recv_callback)(struct unix_msg_ctx *ctx,
					uint8_t *msg, size_t msg_len,
					int *fds, size_t num_fds,
					void *private_data),
		  void *private_data,
		  struct unix_msg_ctx **result)
{
	struct unix_msg_ctx *ctx;
	int ret;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		return ENOMEM;
	}

	*ctx = (struct unix_msg_ctx) {
		.fragment_len = fragment_len,
		.cookie = cookie,
		.recv_callback = recv_callback,
		.private_data = private_data
	};

	ret = unix_dgram_init(addr, fragment_len, ev_funcs,
			      unix_msg_recv, ctx, &ctx->dgram);
	if (ret != 0) {
		free(ctx);
		return ret;
	}

	*result = ctx;
	return 0;
}

int unix_msg_send(struct unix_msg_ctx *ctx, const struct sockaddr_un *dst,
		  const struct iovec *iov, int iovlen,
		  const int *fds, size_t num_fds)
{
	ssize_t msglen;
	size_t sent;
	int ret = 0;
	struct iovec iov_copy[iovlen+2];
	struct unix_msg_hdr hdr;
	struct iovec src_iov;

	if (iovlen < 0) {
		return EINVAL;
	}

	msglen = iov_buflen(iov, iovlen);
	if (msglen == -1) {
		return EINVAL;
	}

#ifndef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (num_fds > 0) {
		return ENOSYS;
	}
#endif /* ! HAVE_STRUCT_MSGHDR_MSG_CONTROL */

	if (num_fds > INT8_MAX) {
		return EINVAL;
	}

	if (msglen <= (ctx->fragment_len - sizeof(uint64_t))) {
		uint64_t cookie = 0;

		iov_copy[0].iov_base = &cookie;
		iov_copy[0].iov_len = sizeof(cookie);
		if (iovlen > 0) {
			memcpy(&iov_copy[1], iov,
			       sizeof(struct iovec) * iovlen);
		}

		return unix_dgram_send(ctx->dgram, dst, iov_copy, iovlen+1,
				       fds, num_fds);
	}

	hdr = (struct unix_msg_hdr) {
		.msglen = msglen,
		.pid = getpid(),
		.sock = unix_dgram_sock(ctx->dgram)
	};

	iov_copy[0].iov_base = &ctx->cookie;
	iov_copy[0].iov_len = sizeof(ctx->cookie);
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

		fragment_len = sizeof(ctx->cookie) + sizeof(hdr);

		while (fragment_len < ctx->fragment_len) {
			size_t space, chunk;

			space = ctx->fragment_len - fragment_len;
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
		sent += (fragment_len - sizeof(ctx->cookie) - sizeof(hdr));

		/*
		 * only the last fragment should pass the fd array.
		 * That simplifies the receiver a lot.
		 */
		if (sent < msglen) {
			ret = unix_dgram_send(ctx->dgram, dst,
					      iov_copy, iov_index,
					      NULL, 0);
		} else {
			ret = unix_dgram_send(ctx->dgram, dst,
					      iov_copy, iov_index,
					      fds, num_fds);
		}
		if (ret != 0) {
			break;
		}
	}

	ctx->cookie += 1;
	if (ctx->cookie == 0) {
		ctx->cookie += 1;
	}

	return ret;
}

static void unix_msg_recv(struct unix_dgram_ctx *dgram_ctx,
			  uint8_t *buf, size_t buflen,
			  int *fds, size_t num_fds,
			  void *private_data)
{
	struct unix_msg_ctx *ctx = (struct unix_msg_ctx *)private_data;
	struct unix_msg_hdr hdr;
	struct unix_msg *msg;
	size_t space;
	uint64_t cookie;

	if (buflen < sizeof(cookie)) {
		goto close_fds;
	}

	memcpy(&cookie, buf, sizeof(cookie));

	buf += sizeof(cookie);
	buflen -= sizeof(cookie);

	if (cookie == 0) {
		ctx->recv_callback(ctx, buf, buflen, fds, num_fds, ctx->private_data);
		return;
	}

	if (buflen < sizeof(hdr)) {
		goto close_fds;
	}
	memcpy(&hdr, buf, sizeof(hdr));

	buf += sizeof(hdr);
	buflen -= sizeof(hdr);

	for (msg = ctx->msgs; msg != NULL; msg = msg->next) {
		if ((msg->sender_pid == hdr.pid) &&
		    (msg->sender_sock == hdr.sock)) {
			break;
		}
	}

	if ((msg != NULL) && (msg->cookie != cookie)) {
		DLIST_REMOVE(ctx->msgs, msg);
		free(msg);
		msg = NULL;
	}

	if (msg == NULL) {
		msg = malloc(offsetof(struct unix_msg, buf) + hdr.msglen);
		if (msg == NULL) {
			goto close_fds;
		}
		*msg = (struct unix_msg) {
			.msglen = hdr.msglen,
			.sender_pid = hdr.pid,
			.sender_sock = hdr.sock,
			.cookie = cookie
		};
		DLIST_ADD(ctx->msgs, msg);
	}

	space = msg->msglen - msg->received;
	if (buflen > space) {
		goto close_fds;
	}

	memcpy(msg->buf + msg->received, buf, buflen);
	msg->received += buflen;

	if (msg->received < msg->msglen) {
		goto close_fds;
	}

	DLIST_REMOVE(ctx->msgs, msg);
	ctx->recv_callback(ctx, msg->buf, msg->msglen, fds, num_fds, ctx->private_data);
	free(msg);
	return;

close_fds:
	close_fd_array(fds, num_fds);
}

int unix_msg_free(struct unix_msg_ctx *ctx)
{
	int ret;

	ret = unix_dgram_free(ctx->dgram);
	if (ret != 0) {
		return ret;
	}

	while (ctx->msgs != NULL) {
		struct unix_msg *msg = ctx->msgs;
		DLIST_REMOVE(ctx->msgs, msg);
		free(msg);
	}

	free(ctx);
	return 0;
}

static ssize_t iov_buflen(const struct iovec *iov, int iovlen)
{
	size_t buflen = 0;
	int i;

	for (i=0; i<iovlen; i++) {
		size_t thislen = iov[i].iov_len;
		size_t tmp = buflen + thislen;

		if ((tmp < buflen) || (tmp < thislen)) {
			/* overflow */
			return -1;
		}
		buflen = tmp;
	}
	return buflen;
}
