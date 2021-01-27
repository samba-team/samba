/*
   Unix SMB/CIFS implementation.
   Manage connections_struct structures
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Jeremy Allison 2010

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "rpc_server/rpc_pipes.h"
#include "lib/util/tevent_ntstatus.h"

/****************************************************************************
 Update last used timestamps.
****************************************************************************/

static void conn_lastused_update(struct smbd_server_connection *sconn,time_t t)
{
	struct connection_struct *conn;

	for (conn=sconn->connections; conn; conn=conn->next) {
		/* Update if connection wasn't idle. */
		if (conn->lastused != conn->lastused_count) {
			conn->lastused = t;
			conn->lastused_count = t;
		}
	}
}

/****************************************************************************
 Idle inactive connections.
****************************************************************************/

bool conn_idle_all(struct smbd_server_connection *sconn, time_t t)
{
	int deadtime = lp_deadtime()*60;
	struct connection_struct *conn;

	conn_lastused_update(sconn, t);

	if (deadtime <= 0) {
		return false;
	}

	for (conn=sconn->connections;conn;conn=conn->next) {
		time_t age = t - conn->lastused;

		if (conn->num_files_open > 0 || age < deadtime) {
			return false;
		}
	}

	/*
	 * Check all pipes for any open handles. We cannot
	 * idle with a handle open.
	 */
	if (check_open_pipes()) {
		return false;
	}

	return true;
}

/****************************************************************************
 Forcibly unmount a share - async
 All instances of the parameter 'sharename' share are unmounted.
 The special sharename '*' forces unmount of all shares.
****************************************************************************/

static struct tevent_req *conn_force_tdis_send(connection_struct *conn);
static void conn_force_tdis_done(struct tevent_req *req);

void conn_force_tdis(
	struct smbd_server_connection *sconn,
	bool (*check_fn)(struct connection_struct *conn,
			 void *private_data),
	void *private_data)
{
	connection_struct *conn;

	/* SMB1 and SMB 2*/
	for (conn = sconn->connections; conn; conn = conn->next) {
		struct smbXsrv_tcon *tcon;
		bool do_close = false;
		struct tevent_req *req;

		if (conn->tcon == NULL) {
			continue;
		}
		tcon = conn->tcon;

		if (!NT_STATUS_IS_OK(tcon->status)) {
			/* In the process of already being disconnected. */
			continue;
		}

		do_close = check_fn(conn, private_data);
		if (!do_close) {
			continue;
		}

		req = conn_force_tdis_send(conn);
		if (req == NULL) {
			DBG_WARNING("talloc_fail forcing async close of "
				"share '%s'\n",
				tcon->global->share_name);
			continue;
		}

		DBG_WARNING("Forcing close of "
			    "share '%s' (wire_id=0x%08x)\n",
			    tcon->global->share_name,
			    tcon->global->tcon_wire_id);

		tevent_req_set_callback(req, conn_force_tdis_done, conn);
	}
}

struct conn_force_tdis_state {
	struct tevent_queue *wait_queue;
};

static void conn_force_tdis_wait_done(struct tevent_req *subreq);

static struct tevent_req *conn_force_tdis_send(connection_struct *conn)
{
	struct tevent_req *req;
	struct conn_force_tdis_state *state;
	struct tevent_req *subreq;
	files_struct *fsp;

	/* Create this off the NULL context. We must clean up on return. */
	req = tevent_req_create(NULL, &state,
			struct conn_force_tdis_state);
	if (req == NULL) {
		return NULL;
	}
	state->wait_queue = tevent_queue_create(state,
			"conn_force_tdis_wait_queue");
	if (tevent_req_nomem(state->wait_queue, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	/*
	 * Make sure that no new request will be able to use this tcon.
	 * This ensures that once all outstanding fsp->aio_requests
	 * on this tcon are done, we are safe to close it.
	 */
	conn->tcon->status = NT_STATUS_NETWORK_NAME_DELETED;

	for (fsp = conn->sconn->files; fsp; fsp = fsp->next) {
		if (fsp->conn != conn) {
			continue;
		}
		/*
		 * Flag the file as close in progress.
		 * This will prevent any more IO being
		 * done on it. Not strictly needed, but
		 * doesn't hurt to flag it as closing.
		 */
		fsp->fsp_flags.closing = true;

		if (fsp->num_aio_requests > 0) {
			/*
			 * Now wait until all aio requests on this fsp are
			 * finished.
			 *
			 * We don't set a callback, as we just want to block the
			 * wait queue and the talloc_free() of fsp->aio_request
			 * will remove the item from the wait queue.
			 */
			subreq = tevent_queue_wait_send(fsp->aio_requests,
						conn->sconn->ev_ctx,
						state->wait_queue);
			if (tevent_req_nomem(subreq, req)) {
				TALLOC_FREE(req);
				return NULL;
			}
		}
	}
	/*
	 * Now we add our own waiter to the end of the queue,
	 * this way we get notified when all pending requests are finished
	 * and reply to the outstanding SMB1 request.
	 */
	subreq = tevent_queue_wait_send(state,
				conn->sconn->ev_ctx,
				state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(req);
		return NULL;
	}

	tevent_req_set_callback(subreq, conn_force_tdis_wait_done, req);
	return req;
}

static void conn_force_tdis_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);

	tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static NTSTATUS conn_force_tdis_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void conn_force_tdis_done(struct tevent_req *req)
{
	connection_struct *conn = tevent_req_callback_data(
		req, connection_struct);
	NTSTATUS status;
	uint64_t vuid = UID_FIELD_INVALID;
	struct smbXsrv_tcon *tcon = conn->tcon;
	struct smbd_server_connection *sconn = conn->sconn;

	status = conn_force_tdis_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("conn_force_tdis_recv of share '%s' "
			"(wire_id=0x%08x) failed: %s\n",
			tcon->global->share_name,
			tcon->global->tcon_wire_id,
			nt_errstr(status));
		return;
	}

	if (conn->sconn->using_smb2) {
		vuid = conn->vuid;
	}

	DBG_WARNING("Closing "
		    "share '%s' (wire_id=0x%08x)\n",
		    tcon->global->share_name,
		    tcon->global->tcon_wire_id);

	conn = NULL;
	status = smbXsrv_tcon_disconnect(tcon, vuid);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smbXsrv_tcon_disconnect() of share '%s' "
			"(wire_id=0x%08x) failed: %s\n",
			tcon->global->share_name,
			tcon->global->tcon_wire_id,
			nt_errstr(status));
		return;
	}

	TALLOC_FREE(tcon);

	/*
	* As we've been awoken, we may have changed
	* uid in the meantime. Ensure we're still root.
	*/
	change_to_root_user();
	/*
	 * Use 'false' in the last parameter (test) to force
	 * a full reload of services. Prevents
	 * reload_services caching the fact it's
	 * been called multiple times in a row.
	 * See BUG: https://bugzilla.samba.org/show_bug.cgi?id=14604
	 * for details.
	 */
	reload_services(sconn, conn_snum_used, false);
}
