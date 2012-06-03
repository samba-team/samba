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
 Close all conn structures.
 Return true if any were closed.
****************************************************************************/

void conn_close_all(struct smbd_server_connection *sconn)
{
	if (sconn->using_smb2) {
		/* SMB2 */
		struct smbd_smb2_session *sess;

		for (sess = sconn->smb2.sessions.list; sess; sess = sess->next) {
			struct smbd_smb2_tcon *tcon, *tc_next;

			file_close_user(sconn, sess->vuid);

			for (tcon = sess->tcons.list; tcon; tcon = tc_next) {
				tc_next = tcon->next;
				TALLOC_FREE(tcon);
			}
		}
	} else {
		/* SMB1 */
		connection_struct *conn, *next;

		for (conn=sconn->connections;conn;conn=next) {
			next=conn->next;
			set_current_service(conn, 0, True);
			close_cnum(conn, conn->vuid);
		}
	}
}


/****************************************************************************
 Forcibly unmount a share.
 All instances of the parameter 'sharename' share are unmounted.
 The special sharename '*' forces unmount of all shares.
****************************************************************************/

void conn_force_tdis(struct smbd_server_connection *sconn, const char *sharename)
{
	connection_struct *conn, *next;

	if (strcmp(sharename, "*") == 0) {
		DEBUG(1,("Forcing close of all shares\n"));
		conn_close_all(sconn);
		return;
	}

	if (sconn->using_smb2) {
		/* SMB2 */
		struct smbd_smb2_session *sess;
		for (sess = sconn->smb2.sessions.list; sess; sess = sess->next) {
			struct smbd_smb2_tcon *tcon, *tc_next;

			for (tcon = sess->tcons.list; tcon; tcon = tc_next) {
				tc_next = tcon->next;
				if (tcon->compat_conn &&
						strequal(lp_servicename(SNUM(tcon->compat_conn)),
								sharename)) {
					DEBUG(1,("Forcing close of share %s cnum=%d\n",
						sharename, tcon->compat_conn->cnum));
					TALLOC_FREE(tcon);
				}
			}
		}
	} else {
		/* SMB1 */
		for (conn=sconn->connections;conn;conn=next) {
			next=conn->next;
			if (strequal(lp_servicename(SNUM(conn)), sharename)) {
				DEBUG(1,("Forcing close of share %s cnum=%d\n",
					sharename, conn->cnum));
				close_cnum(conn, (uint16)-1);
			}
		}
	}
}
