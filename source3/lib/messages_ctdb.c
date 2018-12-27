/*
 * Unix SMB/CIFS implementation.
 * Samba internal messaging functions
 * Copyright (C) 2017 by Volker Lendecke
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
#include "lib/messages_ctdb.h"
#include "lib/util/server_id.h"
#include "messages.h"
#include "util_tdb.h"
#include "lib/util/iov_buf.h"
#include "lib/messages_util.h"
#include "ctdbd_conn.h"
#include "lib/cluster_support.h"
#include "ctdb_srvids.h"

struct messaging_ctdb_context;

/*
 * We can only have one tevent_fd per ctdb_context and per
 * tevent_context. Maintain a list of registered tevent_contexts per
 * ctdb_context.
 */
struct messaging_ctdb_fde_ev {
	struct messaging_ctdb_fde_ev *prev, *next;

	/*
	 * Backreference to enable DLIST_REMOVE from our
	 * destructor. Also, set to NULL when the ctdb_context dies
	 * before the messaging_ctdb_fde_ev.
	 */
	struct messaging_ctdb_context *ctx;

	struct tevent_context *ev;
	struct tevent_fd *fde;
};

struct messaging_ctdb_context {
	struct ctdbd_connection *conn;

	void (*recv_cb)(struct tevent_context *ev,
			const uint8_t *msg, size_t msg_len,
			int *fds, size_t num_fds,
			void *private_data);
	void *recv_cb_private_data;

	struct messaging_ctdb_fde_ev *fde_evs;
};

static int messaging_ctdb_recv(
	struct tevent_context *ev,
	uint32_t src_vnn, uint32_t dst_vnn, uint64_t dst_srvid,
	const uint8_t *msg, size_t msg_len, void *private_data)
{
	struct messaging_ctdb_context *state = talloc_get_type_abort(
		private_data, struct messaging_ctdb_context);

	state->recv_cb(ev, msg, msg_len, NULL, 0, state->recv_cb_private_data);

	return 0;
}

struct messaging_ctdb_context *global_ctdb_context;

int messaging_ctdb_init(const char *sockname, int timeout, uint64_t unique_id,
			void (*recv_cb)(struct tevent_context *ev,
					const uint8_t *msg, size_t msg_len,
					int *fds, size_t num_fds,
					void *private_data),
			void *private_data)
{
	struct messaging_ctdb_context *ctx;
	int ret;

	if (global_ctdb_context != NULL) {
		return EBUSY;
	}

	ctx = talloc_zero(NULL, struct messaging_ctdb_context);
	if (ctx == NULL) {
		return ENOMEM;
	}
	ctx->recv_cb = recv_cb;
	ctx->recv_cb_private_data = private_data;

	ret = ctdbd_init_connection(ctx, sockname, timeout, &ctx->conn);
	if (ret != 0) {
		DBG_DEBUG("ctdbd_init_connection returned %s\n",
			  strerror(ret));
		goto fail;
	}

	ret = register_with_ctdbd(ctx->conn, getpid(), messaging_ctdb_recv,
				  ctx);
	if (ret != 0) {
		DBG_DEBUG("register_with_ctdbd returned %s (%d)\n",
			  strerror(ret), ret);
		goto fail;
	}

	ret = register_with_ctdbd(ctx->conn, CTDB_SRVID_SAMBA_PROCESS,
				  messaging_ctdb_recv, ctx);
	if (ret != 0) {
		DBG_DEBUG("register_with_ctdbd returned %s (%d)\n",
			  strerror(ret), ret);
		goto fail;
	}

	ret = register_with_ctdbd(ctx->conn, unique_id, NULL, NULL);
	if (ret != 0) {
		DBG_DEBUG("register_with_ctdbd returned %s (%d)\n",
			  strerror(ret), ret);
		goto fail;
	}

	set_my_vnn(ctdbd_vnn(ctx->conn));

	global_ctdb_context = ctx;
	return 0;
fail:
	TALLOC_FREE(ctx);
	return ret;
}

void messaging_ctdb_destroy(void)
{
	TALLOC_FREE(global_ctdb_context);
}

int messaging_ctdb_send(uint32_t dst_vnn, uint64_t dst_srvid,
			const struct iovec *iov, int iovlen)
{
	struct messaging_ctdb_context *ctx = global_ctdb_context;
	int ret;

	if (ctx == NULL) {
		return ENOTCONN;
	}

	ret = ctdbd_messaging_send_iov(ctx->conn, dst_vnn, dst_srvid,
				       iov, iovlen);
	return ret;
}

static void messaging_ctdb_read_handler(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct messaging_ctdb_context *ctx = talloc_get_type_abort(
		private_data, struct messaging_ctdb_context);

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}
	ctdbd_socket_readable(ev, ctx->conn);
}

struct messaging_ctdb_fde {
	struct tevent_fd *fde;
};

static int messaging_ctdb_fde_ev_destructor(
	struct messaging_ctdb_fde_ev *fde_ev)
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

struct messaging_ctdb_fde *messaging_ctdb_register_tevent_context(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
	struct messaging_ctdb_context *ctx = global_ctdb_context;
	struct messaging_ctdb_fde_ev *fde_ev;
	struct messaging_ctdb_fde *fde;

	if (ctx == NULL) {
		return NULL;
	}

	fde = talloc(mem_ctx, struct messaging_ctdb_fde);
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
		int sock = ctdbd_conn_get_fd(ctx->conn);

		fde_ev = talloc(fde, struct messaging_ctdb_fde_ev);
		if (fde_ev == NULL) {
			return NULL;
		}
		fde_ev->fde = tevent_add_fd(
			ev, fde_ev, sock, TEVENT_FD_READ,
			messaging_ctdb_read_handler, ctx);
		if (fde_ev->fde == NULL) {
			TALLOC_FREE(fde);
			return NULL;
		}
		fde_ev->ev = ev;
		fde_ev->ctx = ctx;
		DLIST_ADD(ctx->fde_evs, fde_ev);
		talloc_set_destructor(
			fde_ev, messaging_ctdb_fde_ev_destructor);
	} else {
		/*
		 * Same trick as with tdb_wrap: The caller will never
		 * see the talloc_referenced object, the
		 * messaging_ctdb_fde_ev, so problems with
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

bool messaging_ctdb_fde_active(struct messaging_ctdb_fde *fde)
{
	uint16_t flags;

	if (fde == NULL) {
		return false;
	}
	flags = tevent_fd_get_flags(fde->fde);
	return (flags != 0);
}

struct ctdbd_connection *messaging_ctdb_connection(void)
{
	if (global_ctdb_context == NULL) {
		smb_panic("messaging not initialized\n");
	}
	return global_ctdb_context->conn;
}
