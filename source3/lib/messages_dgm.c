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
#include "messages.h"
#include "lib/param/param.h"
#include "poll_funcs/poll_funcs_tevent.h"
#include "unix_msg/unix_msg.h"
#include "librpc/gen_ndr/messaging.h"

struct messaging_dgm_context {
	struct messaging_context *msg_ctx;
	struct poll_funcs *msg_callbacks;
	void *tevent_handle;
	struct unix_msg_ctx *dgm_ctx;
	char *cache_dir;
	int lockfile_fd;
};

struct messaging_dgm_hdr {
	uint32_t msg_version;
	enum messaging_type msg_type;
	struct server_id dst;
	struct server_id src;
};

static NTSTATUS messaging_dgm_send(struct server_id src,
				   struct server_id pid, int msg_type,
				   const struct iovec *iov, int iovlen,
				   struct messaging_backend *backend);
static void messaging_dgm_recv(struct unix_msg_ctx *ctx,
			       uint8_t *msg, size_t msg_len,
			       void *private_data);

static int messaging_dgm_context_destructor(struct messaging_dgm_context *c);

static int messaging_dgm_lockfile_create(const char *cache_dir, pid_t pid,
					 int *plockfile_fd, uint64_t unique)
{
	char buf[PATH_MAX];
	char *dir, *to_free;
	ssize_t dirlen;
	char *lockfile_name;
	int lockfile_fd;
	struct flock lck = {};
	int unique_len, ret;
	ssize_t written;
	bool ok;

	dirlen = full_path_tos(cache_dir, "lck", buf, sizeof(buf),
			       &dir, &to_free);
	if (dirlen == -1) {
		return ENOMEM;
	}

	ok = directory_create_or_exist_strict(dir, sec_initial_uid(), 0755);
	if (!ok) {
		ret = errno;
		DEBUG(1, ("%s: Could not create lock directory: %s\n",
			  __func__, strerror(ret)));
		TALLOC_FREE(to_free);
		return ret;
	}

	lockfile_name = talloc_asprintf(talloc_tos(), "%s/%u", dir,
					(unsigned)pid);
	TALLOC_FREE(to_free);
	if (lockfile_name == NULL) {
		DEBUG(1, ("%s: talloc_asprintf failed\n", __func__));
		return ENOMEM;
	}

	/* no O_EXCL, existence check is via the fcntl lock */

	lockfile_fd = open(lockfile_name, O_NONBLOCK|O_CREAT|O_WRONLY, 0644);
	if (lockfile_fd == -1) {
		ret = errno;
		DEBUG(1, ("%s: open failed: %s\n", __func__, strerror(errno)));
		goto fail_free;
	}

	lck.l_type = F_WRLCK;
	lck.l_whence = SEEK_SET;
	lck.l_start = 0;
	lck.l_len = 0;

	ret = fcntl(lockfile_fd, F_SETLK, &lck);
	if (ret == -1) {
		ret = errno;
		DEBUG(1, ("%s: fcntl failed: %s\n", __func__, strerror(ret)));
		goto fail_close;
	}

	unique_len = snprintf(buf, sizeof(buf), "%"PRIu64, unique);

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
	unlink(lockfile_name);
fail_close:
	close(lockfile_fd);
fail_free:
	TALLOC_FREE(lockfile_name);
	return ret;
}

static int messaging_dgm_lockfile_remove(const char *cache_dir, pid_t pid)
{
	fstring fname;
	char buf[PATH_MAX];
	char *lockfile_name, *to_free;
	ssize_t len;
	int ret;

	fstr_sprintf(fname, "lck/%u", (unsigned)pid);

	len = full_path_tos(cache_dir, fname, buf, sizeof(buf),
			    &lockfile_name, &to_free);
	if (len == -1) {
		return ENOMEM;
	}

	ret = unlink(lockfile_name);
	if (ret == -1) {
		ret = errno;
		DEBUG(10, ("%s: unlink failed: %s\n", __func__,
			   strerror(ret)));
	}
	TALLOC_FREE(to_free);
	return ret;
}

NTSTATUS messaging_dgm_init(struct messaging_context *msg_ctx,
			    TALLOC_CTX *mem_ctx,
			    struct messaging_backend **presult)
{
	struct messaging_backend *result;
	struct messaging_dgm_context *ctx;
	struct server_id pid = messaging_server_id(msg_ctx);
	int ret;
	bool ok;
	const char *cache_dir;
	char *socket_dir, *socket_name;
	uint64_t cookie;

	cache_dir = lp_cache_directory();
	if (cache_dir == NULL) {
		NTSTATUS status = map_nt_error_from_unix(errno);
		return status;
	}

	result = talloc(mem_ctx, struct messaging_backend);
	if (result == NULL) {
		goto fail_nomem;
	}
	ctx = talloc_zero(result, struct messaging_dgm_context);
	if (ctx == NULL) {
		goto fail_nomem;
	}

	result->private_data = ctx;
	result->send_fn = messaging_dgm_send;
	ctx->msg_ctx = msg_ctx;

	ctx->cache_dir = talloc_strdup(ctx, cache_dir);
	if (ctx->cache_dir == NULL) {
		goto fail_nomem;
	}
	socket_dir = talloc_asprintf(ctx, "%s/msg", cache_dir);
	if (socket_dir == NULL) {
		goto fail_nomem;
	}
	socket_name = talloc_asprintf(ctx, "%s/%u", socket_dir,
				      (unsigned)pid.pid);
	if (socket_name == NULL) {
		goto fail_nomem;
	}

	sec_init();

	ret = messaging_dgm_lockfile_create(cache_dir, pid.pid,
					    &ctx->lockfile_fd, pid.unique_id);
	if (ret != 0) {
		DEBUG(1, ("%s: messaging_dgm_create_lockfile failed: %s\n",
			  __func__, strerror(ret)));
		TALLOC_FREE(result);
		return map_nt_error_from_unix(ret);
	}

	ctx->msg_callbacks = poll_funcs_init_tevent(ctx);
	if (ctx->msg_callbacks == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	ctx->tevent_handle = poll_funcs_tevent_register(
		ctx, ctx->msg_callbacks, msg_ctx->event_ctx);
	if (ctx->tevent_handle == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	ok = directory_create_or_exist_strict(socket_dir, sec_initial_uid(),
					      0700);
	if (!ok) {
		DEBUG(1, ("Could not create socket directory\n"));
		TALLOC_FREE(result);
		return NT_STATUS_ACCESS_DENIED;
	}
	TALLOC_FREE(socket_dir);

	unlink(socket_name);

	generate_random_buffer((uint8_t *)&cookie, sizeof(cookie));

	ret = unix_msg_init(socket_name, ctx->msg_callbacks, 1024, cookie,
			    messaging_dgm_recv, ctx, &ctx->dgm_ctx);
	TALLOC_FREE(socket_name);
	if (ret != 0) {
		DEBUG(1, ("unix_msg_init failed: %s\n", strerror(ret)));
		TALLOC_FREE(result);
		return map_nt_error_from_unix(ret);
	}
	talloc_set_destructor(ctx, messaging_dgm_context_destructor);

	*presult = result;
	return NT_STATUS_OK;

fail_nomem:
	TALLOC_FREE(result);
	return NT_STATUS_NO_MEMORY;
}

static int messaging_dgm_context_destructor(struct messaging_dgm_context *c)
{
	struct server_id pid = messaging_server_id(c->msg_ctx);

	/*
	 * First delete the socket to avoid races. The lockfile is the
	 * indicator that we're still around.
	 */
	unix_msg_free(c->dgm_ctx);

	if (getpid() == pid.pid) {
		(void)messaging_dgm_lockfile_remove(c->cache_dir, pid.pid);
	}
	close(c->lockfile_fd);
	return 0;
}

static NTSTATUS messaging_dgm_send(struct server_id src,
				   struct server_id pid, int msg_type,
				   const struct iovec *iov, int iovlen,
				   struct messaging_backend *backend)
{
	struct messaging_dgm_context *ctx = talloc_get_type_abort(
		backend->private_data, struct messaging_dgm_context);
	fstring pid_str;
	char buf[PATH_MAX];
	char *dst_sock, *to_free;
	struct messaging_dgm_hdr hdr;
	struct iovec iov2[iovlen + 1];
	ssize_t pathlen;
	int ret;

	fstr_sprintf(pid_str, "msg/%u", (unsigned)pid.pid);

	pathlen = full_path_tos(ctx->cache_dir, pid_str, buf, sizeof(buf),
				&dst_sock, &to_free);
	if (pathlen == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	hdr.msg_version = MESSAGE_VERSION;
	hdr.msg_type = msg_type & MSG_TYPE_MASK;
	hdr.dst = pid;
	hdr.src = src;

	DEBUG(10, ("%s: Sending message 0x%x to %s\n", __func__,
		   (unsigned)hdr.msg_type,
		   server_id_str(talloc_tos(), &pid)));

	iov2[0].iov_base = &hdr;
	iov2[0].iov_len = sizeof(hdr);
	memcpy(iov2+1, iov, iovlen*sizeof(struct iovec));

	become_root();
	ret = unix_msg_send(ctx->dgm_ctx, dst_sock, iov2, iovlen + 1);
	unbecome_root();

	TALLOC_FREE(to_free);

	if (ret != 0) {
		return map_nt_error_from_unix(ret);
	}
	return NT_STATUS_OK;
}

static void messaging_dgm_recv(struct unix_msg_ctx *ctx,
			       uint8_t *msg, size_t msg_len,
			       void *private_data)
{
	struct messaging_dgm_context *dgm_ctx = talloc_get_type_abort(
		private_data, struct messaging_dgm_context);
	struct messaging_dgm_hdr *hdr;
	struct messaging_rec rec;

	if (msg_len < sizeof(*hdr)) {
		DEBUG(1, ("message too short: %u\n", (unsigned)msg_len));
		return;
	}

	/*
	 * unix_msg guarantees alignment, so we can cast here
	 */
	hdr = (struct messaging_dgm_hdr *)msg;

	rec.msg_version = hdr->msg_version;
	rec.msg_type = hdr->msg_type;
	rec.dest = hdr->dst;
	rec.src = hdr->src;
	rec.buf.data = msg + sizeof(*hdr);
	rec.buf.length = msg_len - sizeof(*hdr);

	DEBUG(10, ("%s: Received message 0x%x len %u from %s\n", __func__,
		   (unsigned)hdr->msg_type, (unsigned)rec.buf.length,
		   server_id_str(talloc_tos(), &rec.src)));

	messaging_dispatch_rec(dgm_ctx->msg_ctx, &rec);
}

NTSTATUS messaging_dgm_cleanup(struct messaging_context *msg_ctx, pid_t pid)
{
	struct messaging_backend *be = messaging_local_backend(msg_ctx);
	struct messaging_dgm_context *ctx = talloc_get_type_abort(
		be->private_data, struct messaging_dgm_context);
	char *lockfile_name, *socket_name;
	int fd, ret;
	struct flock lck = {};
	NTSTATUS status = NT_STATUS_OK;

	lockfile_name = talloc_asprintf(talloc_tos(), "%s/lck/%u",
					ctx->cache_dir, (unsigned)pid);
	if (lockfile_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	socket_name = talloc_asprintf(lockfile_name, "%s/msg/%u",
				      ctx->cache_dir, (unsigned)pid);
	if (socket_name == NULL) {
		TALLOC_FREE(lockfile_name);
		return NT_STATUS_NO_MEMORY;
	}

	fd = open(lockfile_name, O_NONBLOCK|O_WRONLY, 0);
	if (fd == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(10, ("%s: open(%s) failed: %s\n", __func__,
			   lockfile_name, strerror(errno)));
		return status;
	}

	lck.l_type = F_WRLCK;
	lck.l_whence = SEEK_SET;
	lck.l_start = 0;
	lck.l_len = 0;

	ret = fcntl(fd, F_SETLK, &lck);
	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
		DEBUG(10, ("%s: Could not get lock: %s\n", __func__,
			   strerror(errno)));
		TALLOC_FREE(lockfile_name);
		close(fd);
		return status;
	}

	(void)unlink(socket_name);
	(void)unlink(lockfile_name);
	(void)close(fd);

	TALLOC_FREE(lockfile_name);
	return NT_STATUS_OK;
}

NTSTATUS messaging_dgm_wipe(struct messaging_context *msg_ctx)
{
	struct messaging_backend *be = messaging_local_backend(msg_ctx);
	struct messaging_dgm_context *ctx = talloc_get_type_abort(
		be->private_data, struct messaging_dgm_context);
	char *msgdir_name;
	DIR *msgdir;
	struct dirent *dp;
	pid_t our_pid = getpid();

	/*
	 * We scan the socket directory and not the lock directory. Otherwise
	 * we would race against messaging_dgm_lockfile_create's open(O_CREAT)
	 * and fcntl(SETLK).
	 */

	msgdir_name = talloc_asprintf(talloc_tos(), "%s/msg", ctx->cache_dir);
	if (msgdir_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msgdir = opendir(msgdir_name);
	TALLOC_FREE(msgdir_name);
	if (msgdir == NULL) {
		return map_nt_error_from_unix(errno);
	}

	while ((dp = readdir(msgdir)) != NULL) {
		NTSTATUS status;
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

		status = messaging_dgm_cleanup(msg_ctx, pid);
		DEBUG(10, ("messaging_dgm_cleanup(%lu) returned %s\n",
			   pid, nt_errstr(status)));
	}
	closedir(msgdir);

	return NT_STATUS_OK;
}

void *messaging_dgm_register_tevent_context(TALLOC_CTX *mem_ctx,
					    struct messaging_context *msg_ctx,
					    struct tevent_context *ev)
{
	struct messaging_backend *be = messaging_local_backend(msg_ctx);
	struct messaging_dgm_context *ctx = talloc_get_type_abort(
		be->private_data, struct messaging_dgm_context);
	return poll_funcs_tevent_register(mem_ctx, ctx->msg_callbacks, ev);
}
