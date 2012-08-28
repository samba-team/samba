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
#include "lib/conn_tdb.h"

/****************************************************************************
 Delete a connection record.
****************************************************************************/

bool yield_connection(connection_struct *conn, const char *name)
{
	struct db_record *rec;
	NTSTATUS status;

	DEBUG(3,("Yielding connection to %s\n",name));

	rec = connections_fetch_entry(talloc_tos(), conn, name);
	if (rec == NULL) {
		DEBUG(0, ("connections_fetch_entry failed\n"));
		return False;
	}

	status = dbwrap_record_delete(rec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG( NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND) ? 3 : 0,
		       ("deleting connection record returned %s\n",
			nt_errstr(status)));
	}

	TALLOC_FREE(rec);
	return NT_STATUS_IS_OK(status);
}

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
	int active;

	active = count_current_connections(lp_servicename(talloc_tos(), snum),
					   true);
	if (active > 0) {
		return true;
	}

	return false;
}

/****************************************************************************
 Claim an entry in the connections database.
****************************************************************************/

bool claim_connection(connection_struct *conn, const char *name)
{
	struct db_record *rec;
	struct connections_data crec;
	char *raddr;
	TDB_DATA dbuf;
	NTSTATUS status;

	DEBUG(5,("claiming [%s]\n", name));

	if (!(rec = connections_fetch_entry(talloc_tos(), conn, name))) {
		DEBUG(0, ("connections_fetch_entry failed\n"));
		return False;
	}

	/* Make clear that we require the optional unix_token in the source3 code */
	SMB_ASSERT(conn->session_info->unix_token);

	/* fill in the crec */
	ZERO_STRUCT(crec);
	crec.magic = 0x280267;
	crec.pid = messaging_server_id(conn->sconn->msg_ctx);
	crec.cnum = conn->cnum;
	crec.uid = conn->session_info->unix_token->uid;
	crec.gid = conn->session_info->unix_token->gid;
	strlcpy(crec.servicename, lp_servicename(rec, SNUM(conn)),
		sizeof(crec.servicename));
	crec.start = time(NULL);

	raddr = tsocket_address_inet_addr_string(conn->sconn->remote_address,
						 rec);
	if (raddr == NULL) {
		return false;
	}

	strlcpy(crec.machine,get_remote_machine_name(),sizeof(crec.machine));
	strlcpy(crec.addr, raddr, sizeof(crec.addr));

	dbuf.dptr = (uint8 *)&crec;
	dbuf.dsize = sizeof(crec);

	status = dbwrap_record_store(rec, dbuf, TDB_REPLACE);

	TALLOC_FREE(rec);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("claim_connection: tdb_store failed with error %s.\n",
			 nt_errstr(status)));
		return False;
	}

	return True;
}
