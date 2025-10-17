/*
   Unix SMB/CIFS implementation.
   service (connection) opening and closing
   Copyright (C) Andrew Tridgell 1992-1998

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
#include "system/filesys.h"
#include "system/passwd.h" /* uid_wrapper */
#include "../lib/tsocket/tsocket.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../libcli/security/security.h"
#include "printing/pcap.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "../auth/auth_util.h"
#include "lib/param/loadparm.h"
#include "messages.h"
#include "lib/afs/afs_funcs.h"
#include "lib/util_path.h"
#include "lib/util/string_wrappers.h"
#include "source3/lib/substitute.h"

/****************************************************************************
 Make a connection to a service from SMB1. Internal interface.
****************************************************************************/

static connection_struct *make_connection_smb1(struct smb_request *req,
					NTTIME now,
					int snum,
					const char *pdev,
					NTSTATUS *pstatus)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	uint32_t session_global_id;
	char *share_name = NULL;
	struct smbXsrv_tcon *tcon;
	NTSTATUS status;
	struct connection_struct *conn;

	session_global_id = req->session->global->session_global_id;
	share_name = lp_servicename(talloc_tos(), lp_sub, snum);
	if (share_name == NULL) {
		*pstatus = NT_STATUS_NO_MEMORY;
		return NULL;
	}

	if ((lp_max_connections(snum) > 0)
	    && (count_current_connections(lp_const_servicename(snum), true) >=
		lp_max_connections(snum))) {

		DBG_WARNING("Max connections (%d) exceeded for [%s][%s]\n",
			  lp_max_connections(snum),
			  lp_const_servicename(snum), share_name);
		TALLOC_FREE(share_name);
		*pstatus = NT_STATUS_INSUFFICIENT_RESOURCES;
		return NULL;
	}

	status = smb1srv_tcon_create(req->xconn,
				     session_global_id,
				     share_name,
				     now, &tcon);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("make_connection_smb1: Couldn't find free tcon for [%s] - %s\n",
			 share_name, nt_errstr(status)));
		TALLOC_FREE(share_name);
		*pstatus = status;
		return NULL;
	}
	TALLOC_FREE(share_name);

	conn = conn_new(req->sconn);
	if (!conn) {
		TALLOC_FREE(tcon);

		DEBUG(0,("make_connection_smb1: Couldn't find free connection.\n"));
		*pstatus = NT_STATUS_INSUFFICIENT_RESOURCES;
		return NULL;
	}

	conn->cnum = tcon->global->tcon_wire_id;
	conn->tcon = tcon;

	*pstatus = make_connection_snum(req->xconn,
					conn,
					snum,
					req->session,
					pdev);
	if (!NT_STATUS_IS_OK(*pstatus)) {
		TALLOC_FREE(conn);
		TALLOC_FREE(tcon);
		return NULL;
	}

	tcon->compat = talloc_move(tcon, &conn);
	tcon->status = NT_STATUS_OK;

	*pstatus = NT_STATUS_OK;

	return tcon->compat;
}

/****************************************************************************
 Make a connection to a service. External SMB1 interface.
 *
 * @param service
****************************************************************************/

connection_struct *make_connection(struct smb_request *req,
				   NTTIME now,
				   const char *service_in,
				   const char *pdev, uint64_t vuid,
				   NTSTATUS *status)
{
	struct smbd_server_connection *sconn = req->sconn;
	struct smbXsrv_session *session = req->session;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	uid_t euid;
	char *service = NULL;
	fstring dev;
	int snum = -1;

	fstrcpy(dev, pdev);

	/* This must ONLY BE CALLED AS ROOT. As it exits this function as
	 * root. */
	if (!non_root_mode() && (euid = geteuid()) != 0) {
		DEBUG(0,("make_connection: PANIC ERROR. Called as nonroot "
			 "(%u)\n", (unsigned int)euid ));
		smb_panic("make_connection: PANIC ERROR. Called as nonroot\n");
	}

	if (conn_num_open(sconn) > 2047) {
		*status = NT_STATUS_INSUFF_SERVER_RESOURCES;
		return NULL;
	}

	if (session == NULL) {
		DEBUG(1,("make_connection: refusing to connect with "
			 "no session setup\n"));
		*status = NT_STATUS_ACCESS_DENIED;
		return NULL;
	}

	/* Logic to try and connect to the correct [homes] share, preferably
	   without too many getpwnam() lookups.  This is particularly nasty for
	   winbind usernames, where the share name isn't the same as unix
	   username.
	*/

	if (strequal(service_in,HOMES_NAME)) {
		if (session->homes_snum == -1) {
			DEBUG(2, ("[homes] share not available for "
				  "this user because it was not found "
				  "or created at session setup "
				  "time\n"));
			*status = NT_STATUS_BAD_NETWORK_NAME;
			return NULL;
		}
		DEBUG(5, ("making a connection to [homes] service "
			  "created at session setup time\n"));
		return make_connection_smb1(req, now,
					    session->homes_snum,
					    dev, status);
	} else if ((session->homes_snum != -1)
		   && strequal(service_in,
			       lp_const_servicename(session->homes_snum))) {
		DEBUG(5, ("making a connection to 'homes' service [%s] "
			  "created at session setup time\n", service_in));
		return make_connection_smb1(req, now,
					    session->homes_snum,
					    dev, status);
	}

	service = talloc_strdup(talloc_tos(), service_in);
	if (!service) {
		*status = NT_STATUS_NO_MEMORY;
		return NULL;
	}

	if (!strlower_m(service)) {
		DEBUG(2, ("strlower_m %s failed\n", service));
		*status = NT_STATUS_INVALID_PARAMETER;
		return NULL;
	}

	snum = find_service(talloc_tos(), service, &service);
	if (!service) {
		*status = NT_STATUS_NO_MEMORY;
		return NULL;
	}

	if (snum < 0) {
		if (strequal(service,"IPC$") ||
		    (lp_enable_asu_support() && strequal(service,"ADMIN$"))) {
			DEBUG(3,("refusing IPC connection to %s\n", service));
			*status = NT_STATUS_ACCESS_DENIED;
			return NULL;
		}

		DEBUG(3,("%s (%s) couldn't find service %s\n",
			get_remote_machine_name(),
			tsocket_address_string(
				sconn->remote_address, talloc_tos()),
			service));
		*status = NT_STATUS_BAD_NETWORK_NAME;
		return NULL;
	}

	/* Handle non-Dfs clients attempting connections to msdfs proxy */
	if (lp_host_msdfs() && (*lp_msdfs_proxy(talloc_tos(), lp_sub, snum) != '\0'))  {
		DEBUG(3, ("refusing connection to dfs proxy share '%s' "
			  "(pointing to %s)\n",
			service, lp_msdfs_proxy(talloc_tos(), lp_sub, snum)));
		*status = NT_STATUS_BAD_NETWORK_NAME;
		return NULL;
	}

	DEBUG(5, ("making a connection to 'normal' service %s\n", service));

	return make_connection_smb1(req, now, snum,
				    dev, status);
}
