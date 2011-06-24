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

/* The connections bitmap is expanded in increments of BITMAP_BLOCK_SZ. The
 * maximum size of the bitmap is the largest positive integer, but you will hit
 * the "max connections" limit, looong before that.
 */

#define BITMAP_BLOCK_SZ 128

/****************************************************************************
 Init the conn structures.
****************************************************************************/

void conn_init(struct smbd_server_connection *sconn)
{
	sconn->smb1.tcons.Connections = NULL;
	sconn->smb1.tcons.bmap = bitmap_talloc(sconn, BITMAP_BLOCK_SZ);
}

/****************************************************************************
 Return the number of open connections.
****************************************************************************/

int conn_num_open(struct smbd_server_connection *sconn)
{
	return sconn->num_tcons_open;
}

/****************************************************************************
 Check if a snum is in use.
****************************************************************************/

bool conn_snum_used(struct smbd_server_connection *sconn,
		    int snum)
{
	if (sconn->using_smb2) {
		/* SMB2 */
		struct smbd_smb2_session *sess;
		for (sess = sconn->smb2.sessions.list; sess; sess = sess->next) {
			struct smbd_smb2_tcon *ptcon;

			for (ptcon = sess->tcons.list; ptcon; ptcon = ptcon->next) {
				if (ptcon->compat_conn &&
						ptcon->compat_conn->params &&
						(ptcon->compat_conn->params->service = snum)) {
					return true;
				}
			}
		}
	} else {
		/* SMB1 */
		connection_struct *conn;
		for (conn=sconn->smb1.tcons.Connections;conn;conn=conn->next) {
			if (conn->params->service == snum) {
				return true;
			}
		}
	}
	return false;
}

/****************************************************************************
 Find a conn given a cnum.
****************************************************************************/

connection_struct *conn_find(struct smbd_server_connection *sconn,unsigned cnum)
{
	if (sconn->using_smb2) {
		/* SMB2 */
		struct smbd_smb2_session *sess;
		for (sess = sconn->smb2.sessions.list; sess; sess = sess->next) {
			struct smbd_smb2_tcon *ptcon;

			for (ptcon = sess->tcons.list; ptcon; ptcon = ptcon->next) {
				if (ptcon->compat_conn &&
						ptcon->compat_conn->cnum == cnum) {
					return ptcon->compat_conn;
				}
			}
		}
	} else {
		/* SMB1 */
		int count=0;
		connection_struct *conn;
		for (conn=sconn->smb1.tcons.Connections;conn;conn=conn->next,count++) {
			if (conn->cnum == cnum) {
				if (count > 10) {
					DLIST_PROMOTE(sconn->smb1.tcons.Connections,
						conn);
				}
				return conn;
			}
		}
	}

	return NULL;
}

/****************************************************************************
 Find first available connection slot, starting from a random position.
 The randomisation stops problems with the server dieing and clients
 thinking the server is still available.
****************************************************************************/

connection_struct *conn_new(struct smbd_server_connection *sconn)
{
	connection_struct *conn;
	int i;
        int find_offset = 1;

	if (sconn->using_smb2) {
		/* SMB2 */
		if (!(conn=talloc_zero(NULL, connection_struct)) ||
		    !(conn->params = talloc(conn, struct share_params))) {
			DEBUG(0,("TALLOC_ZERO() failed!\n"));
			TALLOC_FREE(conn);
			return NULL;
		}
		conn->sconn = sconn;
		return conn;
	}

	/* SMB1 */
find_again:
	i = bitmap_find(sconn->smb1.tcons.bmap, find_offset);

	if (i == -1) {
                /* Expand the connections bitmap. */
                int             oldsz = sconn->smb1.tcons.bmap->n;
                int             newsz = sconn->smb1.tcons.bmap->n +
					BITMAP_BLOCK_SZ;
                struct bitmap * nbmap;

                if (newsz <= oldsz) {
                        /* Integer wrap. */
		        DEBUG(0,("ERROR! Out of connection structures\n"));
                        return NULL;
                }

		DEBUG(4,("resizing connections bitmap from %d to %d\n",
                        oldsz, newsz));

                nbmap = bitmap_talloc(sconn, newsz);
		if (!nbmap) {
			DEBUG(0,("ERROR! malloc fail.\n"));
			return NULL;
		}

                bitmap_copy(nbmap, sconn->smb1.tcons.bmap);
		TALLOC_FREE(sconn->smb1.tcons.bmap);

                sconn->smb1.tcons.bmap = nbmap;
                find_offset = oldsz; /* Start next search in the new portion. */

                goto find_again;
	}

	/* The bitmap position is used below as the connection number
	 * conn->cnum). This ends up as the TID field in the SMB header,
	 * which is limited to 16 bits (we skip 0xffff which is the
	 * NULL TID).
	 */
	if (i > 65534) {
		DEBUG(0, ("Maximum connection limit reached\n"));
		return NULL;
	}

	if (!(conn=talloc_zero(NULL, connection_struct)) ||
	    !(conn->params = talloc(conn, struct share_params))) {
		DEBUG(0,("TALLOC_ZERO() failed!\n"));
		TALLOC_FREE(conn);
		return NULL;
	}
	conn->sconn = sconn;
	conn->cnum = i;
	conn->force_group_gid = (gid_t)-1;

	bitmap_set(sconn->smb1.tcons.bmap, i);

	sconn->num_tcons_open++;

	string_set(&conn->connectpath,"");
	string_set(&conn->origpath,"");

	DLIST_ADD(sconn->smb1.tcons.Connections, conn);

	return conn;
}

/****************************************************************************
 Clear a vuid out of the connection's vuid cache
****************************************************************************/

static void conn_clear_vuid_cache(connection_struct *conn, uint16_t vuid)
{
	int i;

	for (i=0; i<VUID_CACHE_SIZE; i++) {
		struct vuid_cache_entry *ent;

		ent = &conn->vuid_cache.array[i];

		if (ent->vuid == vuid) {
			ent->vuid = UID_FIELD_INVALID;
			/*
			 * We need to keep conn->session_info around
			 * if it's equal to ent->session_info as a SMBulogoff
			 * is often followed by a SMBtdis (with an invalid
			 * vuid). The debug code (or regular code in
			 * vfs_full_audit) wants to refer to the
			 * conn->session_info pointer to print debug
			 * statements. Theoretically this is a bug,
			 * as once the vuid is gone the session_info
			 * on the conn struct isn't valid any more,
			 * but there's enough code that assumes
			 * conn->session_info is never null that
			 * it's easier to hold onto the old pointer
			 * until we get a new sessionsetupX.
			 * As everything is hung off the
			 * conn pointer as a talloc context we're not
			 * leaking memory here. See bug #6315. JRA.
			 */
			if (conn->session_info == ent->session_info) {
				ent->session_info = NULL;
			} else {
				TALLOC_FREE(ent->session_info);
			}
			ent->read_only = False;
		}
	}
}

/****************************************************************************
 Clear a vuid out of the validity cache, and as the 'owner' of a connection.

 Called from invalidate_vuid()
****************************************************************************/

void conn_clear_vuid_caches(struct smbd_server_connection *sconn,uint16_t vuid)
{
	connection_struct *conn;

	if (sconn->using_smb2) {
		/* SMB2 */
		struct smbd_smb2_session *sess;
		for (sess = sconn->smb2.sessions.list; sess; sess = sess->next) {
			struct smbd_smb2_tcon *ptcon;

			for (ptcon = sess->tcons.list; ptcon; ptcon = ptcon->next) {
				if (ptcon->compat_conn) {
					if (ptcon->compat_conn->vuid == vuid) {
						ptcon->compat_conn->vuid = UID_FIELD_INVALID;
					}
					conn_clear_vuid_cache(ptcon->compat_conn, vuid);
				}
			}
		}
	} else {
		/* SMB1 */
		for (conn=sconn->smb1.tcons.Connections;conn;conn=conn->next) {
			if (conn->vuid == vuid) {
				conn->vuid = UID_FIELD_INVALID;
			}
			conn_clear_vuid_cache(conn, vuid);
		}
	}
}

/****************************************************************************
 Free a conn structure - internal part.
****************************************************************************/

static void conn_free_internal(connection_struct *conn)
{
	vfs_handle_struct *handle = NULL, *thandle = NULL;
	struct trans_state *state = NULL;

	/* Free vfs_connection_struct */
	handle = conn->vfs_handles;
	while(handle) {
		thandle = handle->next;
		DLIST_REMOVE(conn->vfs_handles, handle);
		if (handle->free_data)
			handle->free_data(&handle->data);
		handle = thandle;
	}

	/* Free any pending transactions stored on this conn. */
	for (state = conn->pending_trans; state; state = state->next) {
		/* state->setup is a talloc child of state. */
		SAFE_FREE(state->param);
		SAFE_FREE(state->data);
	}

	free_namearray(conn->veto_list);
	free_namearray(conn->hide_list);
	free_namearray(conn->veto_oplock_list);
	free_namearray(conn->aio_write_behind_list);

	string_free(&conn->connectpath);
	string_free(&conn->origpath);

	ZERO_STRUCTP(conn);
	talloc_destroy(conn);
}

/****************************************************************************
 Free a conn structure.
****************************************************************************/

void conn_free(connection_struct *conn)
{
	if (conn->sconn == NULL) {
		conn_free_internal(conn);
		return;
	}

	if (conn->sconn->using_smb2) {
		/* SMB2 */
		conn_free_internal(conn);
		return;
	}

	/* SMB1 */
	DLIST_REMOVE(conn->sconn->smb1.tcons.Connections, conn);

	if (conn->sconn->smb1.tcons.bmap != NULL) {
		/*
		 * Can be NULL for fake connections created by
		 * create_conn_struct()
		 */
		bitmap_clear(conn->sconn->smb1.tcons.bmap, conn->cnum);
	}

	SMB_ASSERT(conn->sconn->num_tcons_open > 0);
	conn->sconn->num_tcons_open--;

	conn_free_internal(conn);
}
