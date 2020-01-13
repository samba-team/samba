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

/****************************************************************************
 Receive a smbcontrol message to forcibly unmount a share.
 The message contains just a share name and all instances of that
 share are unmounted.
 The special sharename '*' forces unmount of all shares.
****************************************************************************/

struct force_tdis_state {
	const char *sharename;
};

static bool force_tdis_check(
	struct connection_struct *conn,
	void *private_data)
{
	struct force_tdis_state *state = private_data;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *servicename = NULL;
	bool do_close;

	if (strcmp(state->sharename, "*") == 0) {
		DBG_WARNING("Forcing close of all shares\n");
		return true;
	}

	servicename = lp_servicename(talloc_tos(), lp_sub, SNUM(conn));
	do_close = strequal(servicename, state->sharename);

	TALLOC_FREE(servicename);

	return do_close;
}

void msg_force_tdis(struct messaging_context *msg,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data)
{
	struct force_tdis_state state = {
		.sharename = (const char *)data->data,
	};
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if ((data->length == 0) || (data->data[data->length-1] != 0)) {
		DBG_WARNING("Ignoring invalid sharename\n");
		return;
	}

	conn_force_tdis(sconn, force_tdis_check, &state);
}

static bool force_tdis_denied_check(
	struct connection_struct *conn,
	void *private_data)
{
	bool do_close;
	uint32_t share_access;
	bool read_only;
	NTSTATUS status;

	do_close = force_tdis_check(conn, private_data);
	if (!do_close) {
		return false;
	}

	status = check_user_share_access(
		conn,
		conn->session_info,
		&share_access,
		&read_only);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("check_user_share_access returned %s\n",
			  nt_errstr(status));
		return true;	/* close the share */
	}

	if (conn->share_access != share_access) {
		DBG_DEBUG("share_access changed from %"PRIx32" to %"PRIx32"\n",
			  conn->share_access, share_access);
		return true;	/* close the share */
	}

	if (conn->read_only != read_only) {
		DBG_DEBUG("read_only changed from %s to %s\n",
			  conn->read_only ? "true" : "false",
			  read_only ? "true" : "false");
		return true;	/* close the share */
	}

	/*
	 * all still ok, keep the connection open
	 */
	return false;
}

void msg_force_tdis_denied(
	struct messaging_context *msg,
	void *private_data,
	uint32_t msg_type,
	struct server_id server_id,
	DATA_BLOB *data)
{
	struct force_tdis_state state = {
		.sharename = (const char *)data->data,
	};
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if ((data->length == 0) || (data->data[data->length-1] != 0)) {
		DBG_WARNING("Ignoring invalid sharename\n");
		return;
	}

	change_to_root_user();
	reload_services(sconn, conn_snum_used, false);

	conn_force_tdis(sconn, force_tdis_denied_check, &state);
}
