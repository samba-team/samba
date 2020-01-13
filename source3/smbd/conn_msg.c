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
