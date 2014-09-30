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

#include "includes.h"
#include "lib/util/data_blob.h"
#include "lib/util/debug.h"
#include "lib/unix_msg/unix_msg.h"
#include "system/filesys.h"
#include "lib/messages_dgm.h"
#include "lib/param/param.h"
#include "poll_funcs/poll_funcs_tevent.h"
#include "unix_msg/unix_msg.h"

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
	struct sun_path_buf cache_dir;
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

static int messaging_dgm_lockfile_name(struct sun_path_buf *buf,
				       const char *cache_dir,
				       pid_t pid)
{
	int ret;

	ret = snprintf(buf->buf, sizeof(buf->buf), "%s/lck/%u", cache_dir,
		       (unsigned)pid);
	if (ret >= sizeof(buf->buf)) {
		return ENAMETOOLONG;
	}
	return 0;
}

static int messaging_dgm_context_destructor(struct messaging_dgm_context *c);

static int messaging_dgm_lockfile_create(const char *cache_dir,
					 uid_t dir_owner, pid_t pid,
					 int *plockfile_fd, uint64_t unique)
{
	fstring buf;
	struct sun_path_buf dir;
	struct sun_path_buf lockfile_name;
	int lockfile_fd;
	struct flock lck;
	int unique_len, ret;
	ssize_t written;
	bool ok;

	ret = messaging_dgm_lockfile_name(&lockfile_name, cache_dir, pid);
	if (ret != 0) {
		return ret;
	}

	/* shorter than lockfile_name, can't overflow */
	snprintf(dir.buf, sizeof(dir.buf), "%s/lck", cache_dir);

	ok = directory_create_or_exist_strict(dir.buf, dir_owner, 0755);
	if (!ok) {
		ret = errno;
		DEBUG(1, ("%s: Could not create lock directory: %s\n",
			  __func__, strerror(ret)));
		return ret;
	}

	/* no O_EXCL, existence check is via the fcntl lock */

	lockfile_fd = open(lockfile_name.buf, O_NONBLOCK|O_CREAT|O_WRONLY,
			   0644);
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
	return 0;

fail_unlink:
	unlink(lockfile_name.buf);
fail_close:
	close(lockfile_fd);
	return ret;
}

static int messaging_dgm_lockfile_remove(const char *cache_dir, pid_t pid)
{
	struct sun_path_buf lockfile_name;
	int ret;

	ret = messaging_dgm_lockfile_name(&lockfile_name, cache_dir, pid);
	if (ret != 0) {
		return ret;
	}

	ret = unlink(lockfile_name.buf);
	if (ret == -1) {
		ret = errno;
		DEBUG(10, ("%s: unlink(%s) failed: %s\n", __func__,
			   lockfile_name.buf, strerror(ret)));
	}

	return ret;
}

int messaging_dgm_init(struct tevent_context *ev,
		       struct server_id pid,
		       const char *cache_dir,
		       uid_t dir_owner,
		       void (*recv_cb)(const uint8_t *msg,
				       size_t msg_len,
				       int *fds,
				       size_t num_fds,
				       void *private_data),
		       void *recv_cb_private_data)
{
	struct messaging_dgm_context *ctx;
	int ret;
	bool ok;
	struct sun_path_buf socket_dir;
	struct sockaddr_un socket_address;
	size_t sockname_len;
	uint64_t cookie;
	static bool have_dgm_context = false;

	if (have_dgm_context) {
		return EEXIST;
	}

	ctx = talloc_zero(NULL, struct messaging_dgm_context);
	if (ctx == NULL) {
		goto fail_nomem;
	}
	ctx->pid = pid.pid;
	ctx->recv_cb = recv_cb;
	ctx->recv_cb_private_data = recv_cb_private_data;

	ret = snprintf(socket_dir.buf, sizeof(socket_dir.buf),
		       "%s/msg", cache_dir);
	if (ret >= sizeof(socket_dir.buf)) {
		TALLOC_FREE(ctx);
		return ENAMETOOLONG;
	}

	/* shorter than socket_dir, can't overflow */
	strlcpy(ctx->cache_dir.buf, cache_dir, sizeof(ctx->cache_dir.buf));

	socket_address = (struct sockaddr_un) { .sun_family = AF_UNIX };
	sockname_len = snprintf(socket_address.sun_path,
				sizeof(socket_address.sun_path),
				"%s/%u", socket_dir.buf, (unsigned)pid.pid);
	if (sockname_len >= sizeof(socket_address.sun_path)) {
		TALLOC_FREE(ctx);
		return ENAMETOOLONG;
	}

	ret = messaging_dgm_lockfile_create(cache_dir, dir_owner, pid.pid,
					    &ctx->lockfile_fd, pid.unique_id);
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

	ok = directory_create_or_exist_strict(socket_dir.buf, dir_owner, 0700);
	if (!ok) {
		DEBUG(1, ("Could not create socket directory\n"));
		TALLOC_FREE(ctx);
		return EACCES;
	}

	unlink(socket_address.sun_path);

	generate_random_buffer((uint8_t *)&cookie, sizeof(cookie));

	ret = unix_msg_init(&socket_address, ctx->msg_callbacks, 1024, cookie,
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
		(void)messaging_dgm_lockfile_remove(c->cache_dir.buf, c->pid);
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
			       "%s/msg/%u", ctx->cache_dir.buf, (unsigned)pid);
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

int messaging_dgm_cleanup(pid_t pid)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	struct sun_path_buf lockfile_name, socket_name;
	int fd, ret;
	struct flock lck = {};

	if (ctx == NULL) {
		return ENOTCONN;
	}

	ret = messaging_dgm_lockfile_name(&lockfile_name, ctx->cache_dir.buf,
					  pid);
	if (ret != 0) {
		return ret;
	}

	/* same length as lockfile_name, can't overflow */
	snprintf(socket_name.buf, sizeof(socket_name.buf), "%s/msg/%u",
		 ctx->cache_dir.buf, (unsigned)pid);

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
		DEBUG(10, ("%s: Could not get lock: %s\n", __func__,
			   strerror(ret)));
		close(fd);
		return ret;
	}

	(void)unlink(socket_name.buf);
	(void)unlink(lockfile_name.buf);
	(void)close(fd);
	return 0;
}

int messaging_dgm_wipe(void)
{
	struct messaging_dgm_context *ctx = global_dgm_context;
	struct sun_path_buf msgdir_name;
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

	ret = snprintf(msgdir_name.buf, sizeof(msgdir_name.buf),
		       "%s/msg", ctx->cache_dir.buf);
	if (ret >= sizeof(msgdir_name.buf)) {
		return ENAMETOOLONG;
	}

	msgdir = opendir(msgdir_name.buf);
	if (msgdir == NULL) {
		ret = errno;
		return ret;
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
