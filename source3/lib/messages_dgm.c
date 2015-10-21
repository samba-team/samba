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
#include "system/network.h"
#include "system/filesys.h"
#include <dirent.h>
#include "lib/util/data_blob.h"
#include "lib/util/debug.h"
#include "lib/unix_msg/unix_msg.h"
#include "system/filesys.h"
#include "lib/messages_dgm.h"
#include "lib/param/param.h"
#include "poll_funcs/poll_funcs_tevent.h"
#include "unix_msg/unix_msg.h"
#include "lib/util/genrand.h"

struct sun_path_buf {
	/*
	 * This will carry enough for a socket path
	 */
	char buf[sizeof(struct sockaddr_un)];
};

struct messaging_dgm_context {
	pid_t pid;
	struct poll_funcs *msg_callbacks;
	void *tevent_handle;
	struct unix_msg_ctx *dgm_ctx;
	struct sun_path_buf socket_dir;
	struct sun_path_buf lockfile_dir;
	int lockfile_fd;

	void (*recv_cb)(const uint8_t *msg,
			size_t msg_len,
			int *fds,
			size_t num_fds,
			void *private_data);
	void *recv_cb_private_data;

	bool *have_dgm_context;
};

static struct messaging_dgm_context *global_dgm_context;

static void messaging_dgm_recv(struct unix_msg_ctx *ctx,
			       uint8_t *msg, size_t msg_len,
			       int *fds, size_t num_fds,
			       void *private_data);

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
	if (ret >= sizeof(lockfile_name.buf)) {
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

int messaging_dgm_init(struct tevent_context *ev,
		       uint64_t *punique,
		       const char *socket_dir,
		       const char *lockfile_dir,
		       void (*recv_cb)(const uint8_t *msg,
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

	ctx->msg_callbacks = poll_funcs_init_tevent(ctx);
	if (ctx->msg_callbacks == NULL) {
		goto fail_nomem;
	}

	ctx->tevent_handle = poll_funcs_tevent_register(
		ctx, ctx->msg_callbacks, ev);
	if (ctx->tevent_handle == NULL) {
		goto fail_nomem;
	}

	unlink(socket_address.sun_path);

	ret = unix_msg_init(&socket_address, ctx->msg_callbacks, 1024,
			    messaging_dgm_recv, ctx, &ctx->dgm_ctx);
	if (ret != 0) {
		DEBUG(1, ("unix_msg_init failed: %s\n", strerror(ret)));
		TALLOC_FREE(ctx);
		return ret;
	}
	talloc_set_destructor(ctx, messaging_dgm_context_destructor);

	ctx->have_dgm_context = &have_dgm_context;

	global_dgm_context = ctx;
	return 0;

fail_nomem:
	TALLOC_FREE(ctx);
	return ENOMEM;
}

static int messaging_dgm_context_destructor(struct messaging_dgm_context *c)
{
	/*
	 * First delete the socket to avoid races. The lockfile is the
	 * indicator that we're still around.
	 */
	unix_msg_free(c->dgm_ctx);

	if (getpid() == c->pid) {
		struct sun_path_buf name;
		int ret;

		ret = snprintf(name.buf, sizeof(name.buf), "%s/%u",
			       c->lockfile_dir.buf, (unsigned)c->pid);
		if (ret >= sizeof(name.buf)) {
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

void messaging_dgm_destroy(void)
{
	TALLOC_FREE(global_dgm_context);
}

int messaging_dgm_send(pid_t pid,
		       const struct iovec *iov, int iovlen,
		       const int *fds, size_t num_fds)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	struct sockaddr_un dst;
	ssize_t dst_pathlen;
	int ret;

	if (ctx == NULL) {
		return ENOTCONN;
	}

	dst = (struct sockaddr_un) { .sun_family = AF_UNIX };

	dst_pathlen = snprintf(dst.sun_path, sizeof(dst.sun_path),
			       "%s/%u", ctx->socket_dir.buf, (unsigned)pid);
	if (dst_pathlen >= sizeof(dst.sun_path)) {
		return ENAMETOOLONG;
	}

	DEBUG(10, ("%s: Sending message to %u\n", __func__, (unsigned)pid));

	ret = unix_msg_send(ctx->dgm_ctx, &dst, iov, iovlen, fds, num_fds);

	return ret;
}

static void messaging_dgm_recv(struct unix_msg_ctx *ctx,
			       uint8_t *msg, size_t msg_len,
			       int *fds, size_t num_fds,
			       void *private_data)
{
	struct messaging_dgm_context *dgm_ctx = talloc_get_type_abort(
		private_data, struct messaging_dgm_context);

	dgm_ctx->recv_cb(msg, msg_len, fds, num_fds,
			 dgm_ctx->recv_cb_private_data);
}

static int messaging_dgm_read_unique(int fd, uint64_t *punique)
{
	char buf[25];
	ssize_t rw_ret;
	unsigned long long unique;
	char *endptr;

	rw_ret = pread(fd, buf, sizeof(buf)-1, 0);
	if (rw_ret == -1) {
		return errno;
	}
	buf[rw_ret] = '\0';

	unique = strtoull(buf, &endptr, 10);
	if ((unique == 0) && (errno == EINVAL)) {
		return EINVAL;
	}
	if ((unique == ULLONG_MAX) && (errno == ERANGE)) {
		return ERANGE;
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

	if (pid == getpid()) {
		/*
		 * Protect against losing our own lock
		 */
		return messaging_dgm_read_unique(ctx->lockfile_fd, unique);
	}

	ret = snprintf(lockfile_name.buf, sizeof(lockfile_name.buf),
		       "%s/%u", ctx->lockfile_dir.buf, (int)pid);
	if (ret >= sizeof(lockfile_name.buf)) {
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
	struct flock lck = {};

	if (ctx == NULL) {
		return ENOTCONN;
	}

	len = snprintf(socket_name.buf, sizeof(socket_name.buf), "%s/%u",
		       ctx->socket_dir.buf, (unsigned)pid);
	if (len >= sizeof(socket_name.buf)) {
		return ENAMETOOLONG;
	}

	len = snprintf(lockfile_name.buf, sizeof(lockfile_name.buf), "%s/%u",
		       ctx->lockfile_dir.buf, (unsigned)pid);
	if (len >= sizeof(lockfile_name.buf)) {
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

int messaging_dgm_wipe(void)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	DIR *msgdir;
	struct dirent *dp;
	pid_t our_pid = getpid();
	int ret;

	if (ctx == NULL) {
		return ENOTCONN;
	}

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

		pid = strtoul(dp->d_name, NULL, 10);
		if (pid == 0) {
			/*
			 * . and .. and other malformed entries
			 */
			continue;
		}
		if (pid == our_pid) {
			/*
			 * fcntl(F_GETLK) will succeed for ourselves, we hold
			 * that lock ourselves.
			 */
			continue;
		}

		ret = messaging_dgm_cleanup(pid);
		DEBUG(10, ("messaging_dgm_cleanup(%lu) returned %s\n",
			   pid, ret ? strerror(ret) : "ok"));
	}
	closedir(msgdir);

	return 0;
}

void *messaging_dgm_register_tevent_context(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev)
{
	struct messaging_dgm_context *ctx = global_dgm_context;

	if (ctx == NULL) {
		return NULL;
	}
	return poll_funcs_tevent_register(mem_ctx, ctx->msg_callbacks, ev);
}
