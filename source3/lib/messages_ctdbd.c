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
#include "lib/messages_util.h"
#include "ctdbd_conn.h"
#include "lib/cluster_support.h"


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
			return NULL;
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
	uint8_t hdr[MESSAGE_HDR_LENGTH];
	struct iovec iov2[iovlen+1];

	if (num_fds > 0) {
		return ENOSYS;
	}

	message_hdr_put(hdr, msg_type, src, pid);
	iov2[0] = (struct iovec){ .iov_base = hdr, .iov_len = sizeof(hdr) };
	memcpy(&iov2[1], iov, iovlen * sizeof(*iov));

	return ctdbd_messaging_send_iov(ctx->conn, pid.vnn, pid.pid,
					iov2, iovlen+1);
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

static int messaging_ctdb_recv(
	uint32_t src_vnn, uint32_t dst_vnn, uint64_t dst_srvid,
	const uint8_t *msg, size_t msg_len, void *private_data)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		private_data, struct messaging_context);
	struct server_id me = messaging_server_id(msg_ctx);
	int ret;
	struct iovec iov;
	struct server_id src, dst;
	enum messaging_type msg_type;
	struct server_id_buf idbuf;

	if (msg_len < MESSAGE_HDR_LENGTH) {
		DEBUG(1, ("%s: message too short: %u\n", __func__,
			  (unsigned)msg_len));
		return 0;
	}

	message_hdr_get(&msg_type, &src, &dst, msg);

	iov = (struct iovec) {
		.iov_base = discard_const_p(uint8_t, msg) + MESSAGE_HDR_LENGTH,
		.iov_len = msg_len - MESSAGE_HDR_LENGTH
	};

	DEBUG(10, ("%s: Received message 0x%x len %u from %s\n",
		   __func__, (unsigned)msg_type, (unsigned)msg_len,
		   server_id_str_buf(src, &idbuf)));

	if (!server_id_same_process(&me, &dst)) {
		struct server_id_buf id1, id2;

		DEBUG(10, ("%s: I'm %s, ignoring msg to %s\n", __func__,
			   server_id_str_buf(me, &id1),
			   server_id_str_buf(dst, &id2)));
		return 0;
	}

	/*
	 * Go through the event loop
	 */

	ret = messaging_send_iov_from(msg_ctx, src, dst, msg_type,
				      &iov, 1, NULL, 0);

	if (ret != 0) {
		DEBUG(10, ("%s: messaging_send_iov_from failed: %s\n",
			   __func__, strerror(ret)));
	}

	return 0;
}

int messaging_ctdbd_init(struct messaging_context *msg_ctx,
			 TALLOC_CTX *mem_ctx,
			 struct messaging_backend **presult)
{
	struct messaging_backend *result;
	struct messaging_ctdbd_context *ctx;
	int ret;

	if (!(result = talloc(mem_ctx, struct messaging_backend))) {
		DEBUG(0, ("talloc failed\n"));
		return ENOMEM;
	}

	if (!(ctx = talloc(result, struct messaging_ctdbd_context))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return ENOMEM;
	}

	ret = ctdbd_messaging_connection(ctx, lp_ctdbd_socket(),
					 lp_ctdb_timeout(), &ctx->conn);

	if (ret != 0) {
		DEBUG(10, ("ctdbd_messaging_connection failed: %s\n",
			   strerror(ret)));
		TALLOC_FREE(result);
		return ret;
	}

	ret = ctdbd_register_msg_ctx(ctx->conn, msg_ctx,
				     messaging_tevent_context(msg_ctx));

	if (ret != 0) {
		DEBUG(10, ("ctdbd_register_msg_ctx failed: %s\n",
			   strerror(ret)));
		TALLOC_FREE(result);
		return ret;
	}

	ret = register_with_ctdbd(ctx->conn, getpid(),
				  messaging_ctdb_recv, msg_ctx);
	if (ret != 0) {
		DEBUG(10, ("register_with_ctdbd failed: %s\n",
			   strerror(ret)));
		TALLOC_FREE(result);
		return ret;
	}

	global_ctdb_connection_pid = getpid();
	global_ctdbd_connection = ctx->conn;
	talloc_set_destructor(ctx, messaging_ctdbd_destructor);

	set_my_vnn(ctdbd_vnn(ctx->conn));

	result->send_fn = messaging_ctdb_send;
	result->private_data = (void *)ctx;

	*presult = result;
	return 0;
}
