/*
   Unix SMB/CIFS implementation.
   Implementation of a reliable server_exists()
   Copyright (C) Volker Lendecke 2010

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
#include "lib/util/server_id.h"
#include "serverid.h"
#include "lib/param/param.h"
#include "ctdbd_conn.h"
#include "lib/messages_ctdb.h"
#include "lib/messaging/messages_dgm.h"

static bool serverid_exists_local(const struct server_id *id)
{
	bool exists = process_exists_by_pid(id->pid);
	uint64_t unique;
	int ret;

	if (!exists) {
		return false;
	}

	if (id->unique_id == SERVERID_UNIQUE_ID_NOT_TO_VERIFY) {
		return true;
	}

	ret = messaging_dgm_get_unique(id->pid, &unique);
	if (ret != 0) {
		return false;
	}

	return (unique == id->unique_id);
}

bool serverid_exists(const struct server_id *id)
{
	if (procid_is_local(id)) {
		return serverid_exists_local(id);
	}

	if (lp_clustering()) {
		return ctdbd_process_exists(messaging_ctdb_connection(),
					    id->vnn, id->pid, id->unique_id);
	}

	return false;
}
