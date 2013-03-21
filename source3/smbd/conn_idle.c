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
		deadtime = DEFAULT_SMBD_TIMEOUT;
	}

	for (conn=sconn->connections;conn;conn=conn->next) {
		time_t age = t - conn->lastused;

		/* close dirptrs on connections that are idle */
		if (age > DPTR_IDLE_TIMEOUT) {
			dptr_idlecnum(conn);
		}

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
 Forcibly unmount a share.
 All instances of the parameter 'sharename' share are unmounted.
 The special sharename '*' forces unmount of all shares.
****************************************************************************/

void conn_force_tdis(struct smbd_server_connection *sconn, const char *sharename)
{
	connection_struct *conn, *next;
	bool close_all = false;

	if (strcmp(sharename, "*") == 0) {
		close_all = true;
		DEBUG(1, ("conn_force_tdis: Forcing close of all shares\n"));
	}

	/* SMB1 and SMB 2*/
	for (conn = sconn->connections; conn; conn = next) {
		struct smbXsrv_tcon *tcon;
		bool do_close = false;
		NTSTATUS status;
		uint64_t vuid = UID_FIELD_INVALID;

		next = conn->next;

		if (conn->tcon == NULL) {
			continue;
		}
		tcon = conn->tcon;

		if (close_all) {
			do_close = true;
		} else if (strequal(lp_servicename(talloc_tos(), SNUM(conn)),
				    sharename)) {
			DEBUG(1, ("conn_force_tdis: Forcing close of "
				  "share '%s' (wire_id=0x%08x)\n",
				  tcon->global->share_name,
				  tcon->global->tcon_wire_id));
			do_close = true;
		}

		if (!do_close) {
			continue;
		}

		if (sconn->using_smb2) {
			vuid = conn->vuid;
		}

		conn = NULL;
		status = smbXsrv_tcon_disconnect(tcon, vuid);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("conn_force_tdis: "
				  "smbXsrv_tcon_disconnect() of share '%s' "
				  "(wire_id=0x%08x) failed: %s\n",
				  tcon->global->share_name,
				  tcon->global->tcon_wire_id,
				  nt_errstr(status)));
		}

		TALLOC_FREE(tcon);
	}

	change_to_root_user();
	reload_services(sconn, conn_snum_used, true);
}
