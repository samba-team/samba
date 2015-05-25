/* 
   Unix SMB/CIFS implementation.
   Samba internal messaging functions
   Copyright (C) 2007 by Volker Lendecke

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
#include "messages.h"
#include "util_tdb.h"
#include "lib/util/iov_buf.h"

#include "ctdb.h"
#include "ctdb_private.h"
#include "ctdbd_conn.h"


struct messaging_ctdbd_context {
	struct ctdbd_connection *conn;
};

/*
 * This is a Samba3 hack/optimization. Routines like process_exists need to
 * talk to ctdbd, and they don't get handed a messaging context.
 */
static struct ctdbd_connection *global_ctdbd_connection;
static int global_ctdb_connection_pid;

struct ctdbd_connection *messaging_ctdbd_connection(void)
{
	if (!lp_clustering()) {
		return NULL;
	}

	if (global_ctdb_connection_pid == 0 &&
	    global_ctdbd_connection == NULL) {
		struct tevent_context *ev;
		struct messaging_context *msg;

		ev = samba_tevent_context_init(NULL);
		if (!ev) {
			DEBUG(0,("samba_tevent_context_init failed\n"));
		}

		msg = messaging_init(NULL, ev);
		if (!msg) {
			DEBUG(0,("messaging_init failed\n"));
			return NULL;
		}
	}

	if (global_ctdb_connection_pid != getpid()) {
		DEBUG(0,("messaging_ctdbd_connection():"
			 "valid for pid[%jd] but it's [%jd]\n",
			 (intmax_t)global_ctdb_connection_pid,
			 (intmax_t)getpid()));
		smb_panic("messaging_ctdbd_connection() invalid process\n");
	}

	return global_ctdbd_connection;
}

static int messaging_ctdb_send(struct server_id src,
			       struct server_id pid, int msg_type,
			       const struct iovec *iov, int iovlen,
			       const int *fds, size_t num_fds,
			       struct messaging_backend *backend)
{
	struct messaging_ctdbd_context *ctx = talloc_get_type_abort(
		backend->private_data, struct messaging_ctdbd_context);
	struct messaging_rec msg;
	uint8_t *buf;
	ssize_t buflen;
	DATA_BLOB blob;
	struct iovec iov2;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	if (num_fds > 0) {
		return ENOSYS;
	}

	buflen = iov_buflen(iov, iovlen);
	if (buflen == -1) {
		return EMSGSIZE;
	}

	buf = talloc_array(talloc_tos(), uint8_t, buflen);
	if (buf == NULL) {
		return ENOMEM;
	}
	iov_buf(iov, iovlen, buf, buflen);

	msg = (struct messaging_rec) {
		.msg_version	= MESSAGE_VERSION,
		.msg_type	= msg_type,
		.dest		= pid,
		.src		= src,
		.buf		= data_blob_const(buf, talloc_get_size(buf)),
	};

	ndr_err = ndr_push_struct_blob(
		&blob, buf, &msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_rec);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("ndr_push_struct_blob failed: %s\n",
			  ndr_errstr(ndr_err)));
		TALLOC_FREE(buf);
		return ndr_map_error2errno(ndr_err);
	}

	iov2 = (struct iovec) { .iov_base = blob.data,
				.iov_len = blob.length };

	status = ctdbd_messaging_send_iov(ctx->conn, pid.vnn, pid.pid,
					  &iov2, 1);
	TALLOC_FREE(buf);

	if (NT_STATUS_IS_OK(status)) {
		return 0;
	}
	return map_errno_from_nt_status(status);
}

static int messaging_ctdbd_destructor(struct messaging_ctdbd_context *ctx)
{
	/*
	 * The global connection just went away
	 */
	global_ctdb_connection_pid = 0;
	global_ctdbd_connection = NULL;
	return 0;
}

static struct messaging_rec *ctdb_pull_messaging_rec(
	TALLOC_CTX *mem_ctx, const struct ctdb_req_message *msg)
{
	struct messaging_rec *result;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	size_t len = msg->hdr.length;

	if (len < offsetof(struct ctdb_req_message, data)) {
		return NULL;
	}
	len -= offsetof(struct ctdb_req_message, data);

	if (len < msg->datalen) {
		return NULL;
	}

	result = talloc(mem_ctx, struct messaging_rec);
	if (result == NULL) {
		return NULL;
	}

	blob = data_blob_const(msg->data, msg->datalen);

	ndr_err = ndr_pull_struct_blob_all(
		&blob, result, result,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_rec);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("ndr_pull_struct_blob failed: %s\n",
			  ndr_errstr(ndr_err)));
		TALLOC_FREE(result);
		return NULL;
	}

	if (DEBUGLEVEL >= 11) {
		DEBUG(11, ("ctdb_pull_messaging_rec:\n"));
		NDR_PRINT_DEBUG(messaging_rec, result);
	}

	return result;
}

static void messaging_ctdb_recv(struct ctdb_req_message *msg,
				void *private_data)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		private_data, struct messaging_context);
	struct server_id me = messaging_server_id(msg_ctx);
	struct messaging_rec *rec;
	NTSTATUS status;
	struct iovec iov;

	rec = ctdb_pull_messaging_rec(msg_ctx, msg);
	if (rec == NULL) {
		DEBUG(10, ("%s: ctdb_pull_messaging_rec failed\n", __func__));
		return;
	}

	if (!server_id_same_process(&me, &rec->dest)) {
		struct server_id_buf id1, id2;

		DEBUG(10, ("%s: I'm %s, ignoring msg to %s\n", __func__,
			   server_id_str_buf(me, &id1),
			   server_id_str_buf(rec->dest, &id2)));
		TALLOC_FREE(rec);
		return;
	}

	iov = (struct iovec) { .iov_base = rec->buf.data,
			       .iov_len = rec->buf.length };

	status = messaging_send_iov_from(msg_ctx, rec->src, rec->dest,
					 rec->msg_type, &iov, 1, NULL, 0);
	TALLOC_FREE(rec);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("%s: messaging_send_iov_from failed: %s\n",
			   __func__, nt_errstr(status)));
	}
}

NTSTATUS messaging_ctdbd_init(struct messaging_context *msg_ctx,
			      TALLOC_CTX *mem_ctx,
			      struct messaging_backend **presult)
{
	struct messaging_backend *result;
	struct messaging_ctdbd_context *ctx;
	NTSTATUS status;

	if (!(result = talloc(mem_ctx, struct messaging_backend))) {
		DEBUG(0, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (!(ctx = talloc(result, struct messaging_ctdbd_context))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	status = ctdbd_messaging_connection(ctx, &ctx->conn);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("ctdbd_messaging_connection failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(result);
		return status;
	}

	status = ctdbd_register_msg_ctx(ctx->conn, msg_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("ctdbd_register_msg_ctx failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(result);
		return status;
	}

	status = register_with_ctdbd(ctx->conn, getpid(),
				     messaging_ctdb_recv, msg_ctx);

	global_ctdb_connection_pid = getpid();
	global_ctdbd_connection = ctx->conn;
	talloc_set_destructor(ctx, messaging_ctdbd_destructor);

	set_my_vnn(ctdbd_vnn(ctx->conn));

	result->send_fn = messaging_ctdb_send;
	result->private_data = (void *)ctx;

	*presult = result;
	return NT_STATUS_OK;
}
