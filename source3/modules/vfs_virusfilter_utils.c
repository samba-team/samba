/*
   Samba-VirusFilter VFS modules
   Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan
   Copyright (C) 2016-2017 Trever L. Adams

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

#include "modules/vfs_virusfilter_common.h"
#include "modules/vfs_virusfilter_utils.h"

struct iovec;

#include "lib/util/iov_buf.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"

int virusfilter_debug_class = DBGC_VFS;

/* ====================================================================== */

char *virusfilter_string_sub(
	TALLOC_CTX *mem_ctx,
	connection_struct *conn,
	const char *str)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	return talloc_sub_full(mem_ctx,
		lp_servicename(mem_ctx, lp_sub, SNUM(conn)),
		conn->session_info->unix_info->unix_name,
		conn->connectpath,
		conn->session_info->unix_token->gid,
		conn->session_info->unix_info->sanitized_username,
		conn->session_info->info->domain_name,
		str);
}

int virusfilter_vfs_next_move(
	struct vfs_handle_struct *vfs_h,
	const struct smb_filename *smb_fname_src,
	const struct smb_filename *smb_fname_dst)
{
	int result;

	result = SMB_VFS_NEXT_RENAMEAT(vfs_h,
			vfs_h->conn->cwd_fsp,
			smb_fname_src,
			vfs_h->conn->cwd_fsp,
			smb_fname_dst);
	if (result == 0 || errno != EXDEV) {
		return result;
	}

	/*
	 * For now, do not handle EXDEV as poking around violates
	 * stackability. Return -1, simply refuse access.
	 */
	return -1;
}

/* Line-based socket I/O
 * ======================================================================
 */

struct virusfilter_io_handle *virusfilter_io_new(
	TALLOC_CTX *mem_ctx,
	int connect_timeout,
	int io_timeout)
{
	struct virusfilter_io_handle *io_h = talloc_zero(mem_ctx,
						struct virusfilter_io_handle);

	if (io_h == NULL) {
		return NULL;
	}

	io_h->stream = NULL;
	io_h->r_len = 0;

	virusfilter_io_set_connect_timeout(io_h, connect_timeout);
	virusfilter_io_set_io_timeout(io_h, io_timeout);
	virusfilter_io_set_writel_eol(io_h, "\x0A", 1);
	virusfilter_io_set_readl_eol(io_h, "\x0A", 1);

	return io_h;
}

int virusfilter_io_set_connect_timeout(
	struct virusfilter_io_handle *io_h,
	int timeout)
{
	int timeout_old = io_h->connect_timeout;

	/* timeout <= 0 means infinite */
	io_h->connect_timeout = (timeout > 0) ? timeout : -1;

	return timeout_old;
}

int virusfilter_io_set_io_timeout(
	struct virusfilter_io_handle *io_h,
	int timeout)
{
	int timeout_old = io_h->io_timeout;

	/* timeout <= 0 means infinite */
	io_h->io_timeout = (timeout > 0) ? timeout : -1;

	return timeout_old;
}

void virusfilter_io_set_writel_eol(
	struct virusfilter_io_handle *io_h,
	const char *eol,
	int eol_size)
{
	if (eol_size < 1 || eol_size > VIRUSFILTER_IO_EOL_SIZE) {
		return;
	}

	memcpy(io_h->w_eol, eol, eol_size);
	io_h->w_eol_size = eol_size;
}

void virusfilter_io_set_readl_eol(
	struct virusfilter_io_handle *io_h,
	const char *eol,
	int eol_size)
{
	if (eol_size < 1 || eol_size > VIRUSFILTER_IO_EOL_SIZE) {
		return;
	}

	memcpy(io_h->r_eol, eol, eol_size);
	io_h->r_eol_size = eol_size;
}

bool virusfilter_io_connect_path(
	struct virusfilter_io_handle *io_h,
	const char *path)
{
	struct sockaddr_un addr;
	NTSTATUS status;
	int socket, ret;
	size_t len;
	bool ok;

	ZERO_STRUCT(addr);
	addr.sun_family = AF_UNIX;

	len = strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
	if (len >= sizeof(addr.sun_path)) {
		io_h->stream = NULL;
		return false;
	}

	status = open_socket_out((struct sockaddr_storage *)&addr, 0,
				 io_h->connect_timeout,
				 &socket);
	if (!NT_STATUS_IS_OK(status)) {
		io_h->stream = NULL;
		return false;
	}

	/* We must not block */
	ret = set_blocking(socket, false);
	if (ret == -1) {
		close(socket);
		io_h->stream = NULL;
		return false;
	}

	ok = smb_set_close_on_exec(socket);
	if (!ok) {
		close(socket);
		io_h->stream = NULL;
		return false;
	}

	ret = tstream_bsd_existing_socket(io_h, socket, &io_h->stream);
	if (ret == -1) {
		close(socket);
		DBG_ERR("Could not convert socket to tstream: %s.\n",
			strerror(errno));
		io_h->stream = NULL;
		return false;
	}

	return true;
}

static void disconnect_done(struct tevent_req *req)
{
	uint64_t *perr = tevent_req_callback_data(req, uint64_t);
	int ret;
	int err_ret;

	ret = tstream_disconnect_recv(req, &err_ret);
	TALLOC_FREE(req);
	if (ret == -1) {
		*perr = err_ret;
	}
}

bool virusfilter_io_disconnect(
	struct virusfilter_io_handle *io_h)
{
	struct tevent_req *req;
	struct tevent_context *ev;
	uint64_t *perror = NULL;
	bool ok = true;
	TALLOC_CTX *frame = talloc_stackframe();

	if (io_h->stream == NULL) {
		io_h->r_len = 0;
		TALLOC_FREE(frame);
		return VIRUSFILTER_RESULT_OK;
	}

	ev = tevent_context_init(frame);
	if (ev == NULL) {
		DBG_ERR("Failed to setup event context.\n");
		ok = false;
		goto fail;
	}

	/* Error return - must be talloc'ed. */
	perror = talloc_zero(frame, uint64_t);
	if (perror == NULL) {
		goto fail;
	}

	req = tstream_disconnect_send(io_h, ev, io_h->stream);

	/* Callback when disconnect is done. */
	tevent_req_set_callback(req, disconnect_done, perror);

	/* Set timeout. */
	ok = tevent_req_set_endtime(req, ev, timeval_current_ofs_msec(
				    io_h->connect_timeout));
	if (!ok) {
		DBG_ERR("Can't set endtime\n");
		goto fail;
	}

	/* Loop waiting for req to finish. */
	ok = tevent_req_poll(req, ev);
	if (!ok) {
		DBG_ERR("tevent_req_poll failed\n");
		goto fail;
	}

	/* Emit debug error if failed. */
	if (*perror != 0) {
		DBG_DEBUG("Error %s\n", strerror((int)*perror));
		goto fail;
	}

	/* Here we know we disconnected. */

	io_h->stream = NULL;
	io_h->r_len = 0;

	fail:
		TALLOC_FREE(frame);
		return ok;
}

static void writev_done(struct tevent_req *req)
{
	uint64_t *perr = tevent_req_callback_data(req, uint64_t);
	int ret;
	int err_ret;

	ret = tstream_writev_recv(req, &err_ret);
	TALLOC_FREE(req);
	if (ret == -1) {
		*perr = err_ret;
	}
}

/****************************************************************************
 Write all data from an iov array, with msec timeout (per write)
 NB. This can be called with a non-socket fd, don't add dependencies
 on socket calls.
****************************************************************************/

bool write_data_iov_timeout(
	struct tstream_context *stream,
	const struct iovec *iov,
	size_t iovcnt,
	int ms_timeout)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	uint64_t *perror = NULL;
	bool ok = false;
	TALLOC_CTX *frame = talloc_stackframe();

	ev = tevent_context_init(frame);
	if (ev == NULL) {
		DBG_ERR("Failed to setup event context.\n");
		goto fail;
	}

	/* Error return - must be talloc'ed. */
	perror = talloc_zero(frame, uint64_t);
	if (perror == NULL) {
		goto fail;
	}

	/* Send the data. */
	req = tstream_writev_send(frame, ev, stream, iov, iovcnt);
	if (req == NULL) {
		DBG_ERR("Out of memory.\n");
		goto fail;
	}

	/* Callback when *all* data sent. */
	tevent_req_set_callback(req, writev_done, perror);

	/* Set timeout. */
	ok = tevent_req_set_endtime(req, ev,
				    timeval_current_ofs_msec(ms_timeout));
	if (!ok) {
		DBG_ERR("Can't set endtime\n");
		goto fail;
	}

	/* Loop waiting for req to finish. */
	ok = tevent_req_poll(req, ev);
	if (!ok) {
		DBG_ERR("tevent_req_poll failed\n");
		goto fail;
	}

	/* Done with req - freed by the callback. */
	req = NULL;

	/* Emit debug error if failed. */
	if (*perror != 0) {
		DBG_DEBUG("Error %s\n", strerror((int)*perror));
		goto fail;
	}

	/* Here we know we correctly wrote all data. */
	TALLOC_FREE(frame);
	return true;

  fail:
	TALLOC_FREE(frame);
	return false;
}

bool virusfilter_io_write(
	struct virusfilter_io_handle *io_h,
	const char *data,
	size_t data_size)
{
	struct iovec iov;

	if (data_size == 0) {
		return VIRUSFILTER_RESULT_OK;
	}

	iov.iov_base = discard_const_p(void, data);
	iov.iov_len = data_size;

	return write_data_iov_timeout(io_h->stream, &iov, 1, io_h->io_timeout);
}

bool virusfilter_io_writel(
	struct virusfilter_io_handle *io_h,
	const char *data,
	size_t data_size)
{
	bool ok;

	ok = virusfilter_io_write(io_h, data, data_size);
	if (!ok) {
		return ok;
	}

	return virusfilter_io_write(io_h, io_h->w_eol, io_h->w_eol_size);
}

bool PRINTF_ATTRIBUTE(2, 3) virusfilter_io_writefl(
	struct virusfilter_io_handle *io_h,
	const char *data_fmt, ...)
{
	va_list ap;
	char data[VIRUSFILTER_IO_BUFFER_SIZE + VIRUSFILTER_IO_EOL_SIZE];
	int data_size;

	va_start(ap, data_fmt);
	data_size = vsnprintf(data, VIRUSFILTER_IO_BUFFER_SIZE, data_fmt, ap);
	va_end(ap);

	if (unlikely (data_size < 0)) {
		DBG_ERR("vsnprintf failed: %s\n", strerror(errno));
		return false;
	}

	memcpy(data + data_size, io_h->w_eol, io_h->w_eol_size);
	data_size += io_h->w_eol_size;

	return virusfilter_io_write(io_h, data, data_size);
}

bool PRINTF_ATTRIBUTE(2, 0) virusfilter_io_vwritefl(
	struct virusfilter_io_handle *io_h,
	const char *data_fmt, va_list ap)
{
	char data[VIRUSFILTER_IO_BUFFER_SIZE + VIRUSFILTER_IO_EOL_SIZE];
	int data_size;

	data_size = vsnprintf(data, VIRUSFILTER_IO_BUFFER_SIZE, data_fmt, ap);

	if (unlikely (data_size < 0)) {
		DBG_ERR("vsnprintf failed: %s\n", strerror(errno));
		return false;
	}

	memcpy(data + data_size, io_h->w_eol, io_h->w_eol_size);
	data_size += io_h->w_eol_size;

	return virusfilter_io_write(io_h, data, data_size);
}

bool virusfilter_io_writev(
	struct virusfilter_io_handle *io_h, ...)
{
	va_list ap;
	struct iovec iov[VIRUSFILTER_IO_IOV_MAX], *iov_p;
	int iov_n;

	va_start(ap, io_h);
	for (iov_p = iov, iov_n = 0;
	     iov_n < VIRUSFILTER_IO_IOV_MAX;
	     iov_p++, iov_n++)
	{
		iov_p->iov_base = va_arg(ap, void *);
		if (iov_p->iov_base == NULL) {
			break;
		}
		iov_p->iov_len = va_arg(ap, int);
	}
	va_end(ap);

	return write_data_iov_timeout(io_h->stream, iov, iov_n,
		io_h->io_timeout);
}

bool virusfilter_io_writevl(
	struct virusfilter_io_handle *io_h, ...)
{
	va_list ap;
	struct iovec iov[VIRUSFILTER_IO_IOV_MAX + 1], *iov_p;
	int iov_n;

	va_start(ap, io_h);
	for (iov_p = iov, iov_n = 0; iov_n < VIRUSFILTER_IO_IOV_MAX;
	     iov_p++, iov_n++)
	{
		iov_p->iov_base = va_arg(ap, void *);
		if (iov_p->iov_base == NULL) {
			break;
		}
		iov_p->iov_len = va_arg(ap, int);
	}
	va_end(ap);

	iov_p->iov_base = io_h->r_eol;
	iov_p->iov_len = io_h->r_eol_size;
	iov_n++;

	return write_data_iov_timeout(io_h->stream, iov, iov_n,
		io_h->io_timeout);
}

static bool return_existing_line(TALLOC_CTX *ctx,
				struct virusfilter_io_handle *io_h,
				char **read_line)
{
	size_t read_line_len = 0;
	char *end_p = NULL;
	char *eol = NULL;

	eol = memmem(io_h->r_buffer, io_h->r_len,
			io_h->r_eol, io_h->r_eol_size);
	if (eol == NULL) {
		return false;
	}
	end_p = eol + io_h->r_eol_size;

	*eol = '\0';
	read_line_len = strlen(io_h->r_buffer) + 1;
	*read_line = talloc_memdup(ctx,
				io_h->r_buffer,
				read_line_len);
	if (*read_line == NULL) {
		return false;
	}

	/*
	 * Copy the remaining buffer over the line
	 * we returned.
	 */
	memmove(io_h->r_buffer,
		end_p,
		io_h->r_len - (end_p - io_h->r_buffer));

	/* And reduce the size left in the buffer. */
	io_h->r_len -= (end_p - io_h->r_buffer);
	return true;
}

static void readv_done(struct tevent_req *req)
{
	uint64_t *perr = tevent_req_callback_data(req, uint64_t);
	int ret;
	int err_ret;

	ret = tstream_readv_recv(req, &err_ret);
	TALLOC_FREE(req);
	if (ret == -1) {
		*perr = err_ret;
	}
}

bool virusfilter_io_readl(TALLOC_CTX *ctx,
			struct virusfilter_io_handle *io_h,
			char **read_line)
{
	struct tevent_context *ev = NULL;
	bool ok = false;
	uint64_t *perror = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	/* Search for an existing complete line. */
	ok = return_existing_line(ctx, io_h, read_line);
	if (ok) {
		goto finish;
	}

	/*
	 * No complete line in the buffer. We must read more
	 * from the server.
	 */
	ev = tevent_context_init(frame);
	if (ev == NULL) {
		DBG_ERR("Failed to setup event context.\n");
		goto finish;
	}

	/* Error return - must be talloc'ed. */
	perror = talloc_zero(frame, uint64_t);
	if (perror == NULL) {
		goto finish;
	}

	for (;;) {
		ssize_t pending = 0;
		size_t read_size = 0;
		struct iovec iov;
		struct tevent_req *req = NULL;

		/*
		 * How much can we read ?
		 */
		pending = tstream_pending_bytes(io_h->stream);
		if (pending < 0) {
			DBG_ERR("tstream_pending_bytes failed (%s).\n",
				strerror(errno));
			goto finish;
		}

		read_size = pending;
		/* Must read at least one byte. */
		read_size = MIN(read_size, 1);

		/* And max remaining buffer space. */
		read_size = MAX(read_size,
				(sizeof(io_h->r_buffer) - io_h->r_len));

		if (read_size == 0) {
			/* Buffer is full with no EOL. Error out. */
			DBG_ERR("Line buffer full.\n");
			goto finish;
		}

		iov.iov_base = io_h->r_buffer + io_h->r_len;
		iov.iov_len = read_size;

		/* Read the data. */
		req = tstream_readv_send(frame,
					ev,
					io_h->stream,
					&iov,
					1);
		if (req == NULL) {
			DBG_ERR("out of memory.\n");
			goto finish;
		}

		/* Callback when *all* data read. */
		tevent_req_set_callback(req, readv_done, perror);

		/* Set timeout. */
		ok = tevent_req_set_endtime(req, ev,
				timeval_current_ofs_msec(io_h->io_timeout));
		if (!ok) {
			DBG_ERR("can't set endtime\n");
			goto finish;
		}

		/* Loop waiting for req to finish. */
		ok = tevent_req_poll(req, ev);
		if (!ok) {
			DBG_ERR("tevent_req_poll failed\n");
			goto finish;
		}

		/* Done with req - freed by the callback. */
		req = NULL;

		/*
		 * Emit debug error if failed.
		 * EPIPE may be success so, don't exit.
		 */
		if (*perror != 0 && *perror != EPIPE) {
			DBG_DEBUG("Error %s\n", strerror((int)*perror));
			errno = (int)*perror;
			goto finish;
		}

		/*
		 * We read read_size bytes. Extend the useable
		 * buffer length.
		 */
		io_h->r_len += read_size;

		/* Paranoia... */
		SMB_ASSERT(io_h->r_len <= sizeof(io_h->r_buffer));

		/* Exit if we have a line to return. */
		ok = return_existing_line(ctx, io_h, read_line);
		if (ok) {
			goto finish;
		}
		/* No eol - keep reading. */
	}

  finish:

	TALLOC_FREE(frame);
	return ok;
}

bool PRINTF_ATTRIBUTE(3, 4) virusfilter_io_writefl_readl(
	struct virusfilter_io_handle *io_h,
	char **read_line,
	const char *fmt, ...)
{
	bool ok;

	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		ok = virusfilter_io_vwritefl(io_h, fmt, ap);
		va_end(ap);

		if (!ok) {
			return ok;
		}
	}

	ok = virusfilter_io_readl(talloc_tos(), io_h, read_line);
	if (!ok) {
		DBG_ERR("virusfilter_io_readl not OK: %d\n", ok);
		return false;
	}
	if (io_h->r_len == 0) { /* EOF */
		DBG_ERR("virusfilter_io_readl EOF\n");
		return false;
	}

	return true;
}

struct virusfilter_cache *virusfilter_cache_new(
	TALLOC_CTX *ctx,
	int entry_limit,
	time_t time_limit)
{
	struct virusfilter_cache *cache;

	if (time_limit == 0) {
		return NULL;
	}

	cache = talloc_zero(ctx, struct virusfilter_cache);
	if (cache == NULL) {
		DBG_ERR("talloc_zero failed.\n");
		return NULL;
	}

	cache->cache = memcache_init(cache->ctx, entry_limit *
				       (sizeof(struct virusfilter_cache_entry)
				       + VIRUSFILTER_CACHE_BUFFER_SIZE));
	if (cache->cache == NULL) {
		DBG_ERR("memcache_init failed.\n");
		return NULL;
	}
	cache->ctx = ctx;
	cache->time_limit = time_limit;

	return cache;
}

bool virusfilter_cache_entry_add(
	struct virusfilter_cache *cache,
	const char *directory,
	const char *fname,
	virusfilter_result result,
	char *report)
{
	int blob_size = sizeof(struct virusfilter_cache_entry);
	struct virusfilter_cache_entry *cache_e =
					talloc_zero_size(NULL, blob_size);
	int fname_len = 0;

	if (fname == NULL || directory == NULL) {
		TALLOC_FREE(report);
		return false;
	}

	fname = talloc_asprintf(talloc_tos(), "%s/%s", directory, fname);

	if (fname == NULL) {
		TALLOC_FREE(report);
		return false;
	}

	fname_len = strlen(fname);

	if (cache_e == NULL|| cache->time_limit == 0) {
		TALLOC_FREE(report);
		return false;
	}

	cache_e->result = result;
	if (report != NULL) {
		cache_e->report = talloc_steal(cache_e, report);
	}
	if (cache->time_limit > 0) {
		cache_e->time = time(NULL);
	}

	memcache_add_talloc(cache->cache,
			    VIRUSFILTER_SCAN_RESULTS_CACHE_TALLOC,
			    data_blob_const(fname, fname_len), &cache_e);

	return true;
}

bool virusfilter_cache_entry_rename(
	struct virusfilter_cache *cache,
	const char *directory,
	char *old_fname,
	char *new_fname)
{
	int old_fname_len = 0;
	int new_fname_len = 0;
	struct virusfilter_cache_entry *new_data = NULL;
	struct virusfilter_cache_entry *old_data = NULL;

	if (old_fname == NULL || new_fname == NULL || directory == NULL) {
		return false;
	}

	old_fname = talloc_asprintf(talloc_tos(), "%s/%s", directory, old_fname);
	new_fname = talloc_asprintf(talloc_tos(), "%s/%s", directory, new_fname);

	if (old_fname == NULL || new_fname == NULL) {
		TALLOC_FREE(old_fname);
		TALLOC_FREE(new_fname);
		return false;
	}

	old_fname_len = strlen(old_fname);
	new_fname_len = strlen(new_fname);

	old_data = memcache_lookup_talloc(
				cache->cache,
				VIRUSFILTER_SCAN_RESULTS_CACHE_TALLOC,
				data_blob_const(old_fname, old_fname_len));

	if (old_data == NULL) {
		return false;
	}

	new_data = talloc_memdup(cache->ctx, old_data,
				 sizeof(struct virusfilter_cache_entry));
	if (new_data == NULL) {
		return false;
	}
	new_data->report = talloc_strdup(new_data, old_data->report);

	memcache_add_talloc(cache->cache,
			VIRUSFILTER_SCAN_RESULTS_CACHE_TALLOC,
			data_blob_const(new_fname, new_fname_len), &new_data);

	memcache_delete(cache->cache, VIRUSFILTER_SCAN_RESULTS_CACHE_TALLOC,
			data_blob_const(old_fname, old_fname_len));

	return true;
}

void virusfilter_cache_purge(struct virusfilter_cache *cache)
{
	memcache_flush(cache->cache, VIRUSFILTER_SCAN_RESULTS_CACHE_TALLOC);
}

struct virusfilter_cache_entry *virusfilter_cache_get(
	struct virusfilter_cache *cache,
	const char *directory,
	const char *fname)
{
	int fname_len = 0;
	struct virusfilter_cache_entry *cache_e = NULL;
	struct virusfilter_cache_entry *data = NULL;

	if (fname == NULL || directory == NULL) {
		return 0;
	}

	fname = talloc_asprintf(talloc_tos(), "%s/%s", directory, fname);

	if (fname == NULL) {
		return 0;
	}

	fname_len = strlen(fname);

	data = memcache_lookup_talloc(cache->cache,
				      VIRUSFILTER_SCAN_RESULTS_CACHE_TALLOC,
				      data_blob_const(fname, fname_len));

	if (data == NULL) {
		return cache_e;
	}

	if (cache->time_limit > 0) {
		if (time(NULL) - data->time  > cache->time_limit) {
			DBG_DEBUG("Cache entry is too old: %s\n",
				  fname);
			virusfilter_cache_remove(cache, directory, fname);
			return cache_e;
		}
	}
	cache_e = talloc_memdup(cache->ctx, data,
			       sizeof(struct virusfilter_cache_entry));
	if (cache_e == NULL) {
		return NULL;
	}
	if (data->report != NULL) {
		cache_e->report = talloc_strdup(cache_e, data->report);
	} else {
		cache_e->report = NULL;
	}

	return cache_e;
}

void virusfilter_cache_remove(struct virusfilter_cache *cache,
	const char *directory,
	const char *fname)
{
	DBG_DEBUG("Purging cache entry: %s/%s\n", directory, fname);

	if (fname == NULL || directory == NULL) {
		return;
	}

	fname = talloc_asprintf(talloc_tos(), "%s/%s", directory, fname);

	if (fname == NULL) {
		return;
	}

	memcache_delete(cache->cache, VIRUSFILTER_SCAN_RESULTS_CACHE_TALLOC,
			data_blob_const(fname, strlen(fname)));
}

void virusfilter_cache_entry_free(struct virusfilter_cache_entry *cache_e)
{
	if (cache_e != NULL) {
		TALLOC_FREE(cache_e->report);
		cache_e->report = NULL;
	}
	TALLOC_FREE(cache_e);
}

/* Shell scripting
 * ======================================================================
 */

int virusfilter_env_set(
	TALLOC_CTX *mem_ctx,
	char **env_list,
	const char *name,
	const char *value)
{
	char *env_new;
	int ret;

	env_new = talloc_asprintf(mem_ctx, "%s=%s", name, value);
	if (env_new == NULL) {
		DBG_ERR("talloc_asprintf failed\n");
		return -1;
	}

	ret = strv_add(mem_ctx, env_list, env_new);

	TALLOC_FREE(env_new);

	return ret;
}

/* virusfilter_env version Samba's *_sub_advanced() in substitute.c */
int virusfilter_shell_set_conn_env(
	TALLOC_CTX *mem_ctx,
	char **env_list,
	connection_struct *conn)
{
	int snum = SNUM(conn);
	char *server_addr_p;
	char *client_addr_p;
	const char *local_machine_name = get_local_machine_name();
	fstring pidstr;
	int ret;

	if (local_machine_name == NULL || *local_machine_name == '\0') {
		local_machine_name = lp_netbios_name();
	}

	server_addr_p = tsocket_address_inet_addr_string(
				conn->sconn->local_address, talloc_tos());

	if (server_addr_p != NULL) {
		ret = strncmp("::ffff:", server_addr_p, 7);
		if (ret == 0) {
			server_addr_p += 7;
		}
		virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_SERVER_IP",
				    server_addr_p);
	}
	TALLOC_FREE(server_addr_p);

	virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_SERVER_NAME",
			    myhostname());
	virusfilter_env_set(mem_ctx, env_list,
			    "VIRUSFILTER_SERVER_NETBIOS_NAME",
			    local_machine_name);
	slprintf(pidstr,sizeof(pidstr)-1, "%ld", (long)getpid());
	virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_SERVER_PID",
			    pidstr);

	virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_SERVICE_NAME",
			    lp_const_servicename(snum));
	virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_SERVICE_PATH",
			    conn->cwd_fsp->fsp_name->base_name);

	client_addr_p = tsocket_address_inet_addr_string(
				conn->sconn->remote_address, talloc_tos());

	if (client_addr_p != NULL) {
		ret = strncmp("::ffff:", client_addr_p, 7);
		if (ret == 0) {
			client_addr_p += 7;
		}
		virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_CLIENT_IP",
				    client_addr_p);
	}
	TALLOC_FREE(client_addr_p);

	virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_CLIENT_NAME",
			    conn->sconn->remote_hostname);
	virusfilter_env_set(mem_ctx, env_list,
			    "VIRUSFILTER_CLIENT_NETBIOS_NAME",
			    get_remote_machine_name());

	virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_USER_NAME",
			    get_current_username());
	virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_USER_DOMAIN",
			    current_user_info.domain);

	return 0;
}

/* Wrapper to Samba's smbrun() in smbrun.c */
int virusfilter_shell_run(
	TALLOC_CTX *mem_ctx,
	const char *cmd,
	char **env_list,
	connection_struct *conn,
	bool sanitize)
{
	int ret;

	if (conn != NULL) {
		ret = virusfilter_shell_set_conn_env(mem_ctx, env_list, conn);
		if (ret == -1) {
			return -1;
		}
	}

	if (sanitize) {
		return smbrun(cmd, NULL, strv_to_env(talloc_tos(), *env_list));
	} else {
		return smbrun_no_sanitize(cmd, NULL, strv_to_env(talloc_tos(),
					  *env_list));
	}
}
