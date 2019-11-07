/* 
   Unix SMB/CIFS implementation.
   connection claim routines
   Copyright (C) Andrew Tridgell 1998

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
#include "dbwrap/dbwrap.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include "messages.h"

struct count_stat {
	int curr_connections;
	const char *name;
	bool verify;
};

/****************************************************************************
 Count the entries belonging to a service in the connection db.
****************************************************************************/

static int count_fn(struct smbXsrv_tcon_global0 *tcon,
		    void *udp)
{
	struct count_stat *cs = (struct count_stat *)udp;

	if (cs->verify && !process_exists(tcon->server_id)) {
		return 0;
	}

	if (strequal(tcon->share_name, cs->name)) {
		cs->curr_connections++;
	}

	return 0;
}

/****************************************************************************
 Claim an entry in the connections database.
****************************************************************************/

int count_current_connections(const char *sharename, bool verify)
{
	struct count_stat cs;
	NTSTATUS status;

	cs.curr_connections = 0;
	cs.name = sharename;
	cs.verify = verify;

	/*
	 * This has a race condition, but locking the chain before hand is worse
	 * as it leads to deadlock.
	 */

	status = smbXsrv_tcon_global_traverse(count_fn, &cs);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("count_current_connections: traverse of "
			 "smbXsrv_tcon_global.tdb failed - %s\n",
			 nt_errstr(status)));
		return 0;
	}

	return cs.curr_connections;
}

bool connections_snum_used(struct smbd_server_connection *unused, int snum)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int active;

	active = count_current_connections(lp_servicename(talloc_tos(), lp_sub, snum),
					   true);
	if (active > 0) {
		return true;
	}

	return false;
}
