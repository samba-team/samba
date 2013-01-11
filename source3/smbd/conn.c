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
#include "lib/util/bitmap.h"

/*******************************************************************
 Static cache for storing per-user share access value. This really
 belongs inside the vuid_cache.array struct but we can't change the
 VFS ABI for 4.0.x. This is fixed in 4.1.x. JRA.
********************************************************************/

struct connection_share_access_list {
	struct connection_share_access_list *next, *prev;
	connection_struct *conn;
	uint32_t vuid_cache_share_access_array[VUID_CACHE_SIZE];
};

static struct connection_share_access_list *conn_share_access_list;

/*******************************************************************
 Destructor function for per-user share access value.
********************************************************************/

static int free_csal_entry(struct connection_share_access_list *csal)
{
	DLIST_REMOVE(conn_share_access_list, csal);
	return 0;
}

/*******************************************************************
 Utility function to find a per-user share access value struct.
********************************************************************/

static struct connection_share_access_list *find_csal_entry(connection_struct *conn)
{
	struct connection_share_access_list *csal;

	for (csal = conn_share_access_list; csal; csal = csal->next) {
		if (csal->conn == conn) {
			DLIST_PROMOTE(conn_share_access_list, csal);
			return csal;
		}
	}
	return NULL;
}

/*******************************************************************
 Accessor functions for per-user share access value.
 These are the only two functions exposed externally.
********************************************************************/

uint32_t get_connection_share_access_list_entry(connection_struct *conn,
						unsigned int i)
{
	struct connection_share_access_list *csal =
			find_csal_entry(conn);

	if (csal == NULL) {
		/*
		 * This is a faked up connection struct
		 * for internal purposes.
		 * Return full access.
		 */
		return SEC_RIGHTS_FILE_ALL;
	}

	return csal->vuid_cache_share_access_array[i];
}

void set_connection_share_access_list_entry(connection_struct *conn,
						unsigned int i,
						uint32_t val)
{
	struct connection_share_access_list *csal =
			find_csal_entry(conn);

	if (csal == NULL) {
		return;
	}

	csal->vuid_cache_share_access_array[i] = val;
}

/****************************************************************************
 Return the number of open connections.
****************************************************************************/

int conn_num_open(struct smbd_server_connection *sconn)
{
	return sconn->num_connections;
}

/****************************************************************************
 Check if a snum is in use.
****************************************************************************/

bool conn_snum_used(struct smbd_server_connection *sconn,
		    int snum)
{
	struct connection_struct *conn;

	for (conn=sconn->connections; conn; conn=conn->next) {
		if (conn->params->service == snum) {
			return true;
		}
	}

	return false;
}

/****************************************************************************
 Find first available connection slot, starting from a random position.
 The randomisation stops problems with the server dieing and clients
 thinking the server is still available.
****************************************************************************/

connection_struct *conn_new(struct smbd_server_connection *sconn)
{
	connection_struct *conn;
	struct connection_share_access_list *csal;

	if (!(conn=talloc_zero(NULL, connection_struct)) ||
	    !(conn->params = talloc(conn, struct share_params)) ||
	    !(conn->connectpath = talloc_strdup(conn, "")) ||
	    !(conn->origpath = talloc_strdup(conn, "")) ||
	    !(csal = talloc_zero(conn, struct connection_share_access_list))) {
		DEBUG(0,("TALLOC_ZERO() failed!\n"));
		TALLOC_FREE(conn);
		return NULL;
	}
	talloc_set_destructor(csal, free_csal_entry);

	conn->sconn = sconn;
	conn->force_group_gid = (gid_t)-1;

	DLIST_ADD(sconn->connections, conn);
	DLIST_ADD(conn_share_access_list, csal);
	sconn->num_connections++;

	return conn;
}

/****************************************************************************
 Clear a vuid out of the connection's vuid cache
****************************************************************************/

static void conn_clear_vuid_cache(connection_struct *conn, uint64_t vuid)
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

void conn_clear_vuid_caches(struct smbd_server_connection *sconn, uint64_t vuid)
{
	connection_struct *conn;

	for (conn=sconn->connections; conn;conn=conn->next) {
		if (conn->vuid == vuid) {
			conn->vuid = UID_FIELD_INVALID;
		}
		conn_clear_vuid_cache(conn, vuid);
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

	DLIST_REMOVE(conn->sconn->connections, conn);
	SMB_ASSERT(conn->sconn->num_connections > 0);
	conn->sconn->num_connections--;

	conn_free_internal(conn);
}
