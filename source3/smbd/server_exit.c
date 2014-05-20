/*
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002-2003
   Copyright (C) Volker Lendecke		1993-2007
   Copyright (C) Jeremy Allison			1993-2007
   Copyright (C) Andrew Bartlett                2010

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
#include "ntdomain.h"
#include "../librpc/gen_ndr/srv_dfs.h"
#include "../librpc/gen_ndr/srv_dssetup.h"
#include "../librpc/gen_ndr/srv_echo.h"
#include "../librpc/gen_ndr/srv_eventlog.h"
#include "../librpc/gen_ndr/srv_initshutdown.h"
#include "../librpc/gen_ndr/srv_lsa.h"
#include "../librpc/gen_ndr/srv_netlogon.h"
#include "../librpc/gen_ndr/srv_ntsvcs.h"
#include "../librpc/gen_ndr/srv_samr.h"
#include "../librpc/gen_ndr/srv_spoolss.h"
#include "../librpc/gen_ndr/srv_srvsvc.h"
#include "../librpc/gen_ndr/srv_svcctl.h"
#include "../librpc/gen_ndr/srv_winreg.h"
#include "../librpc/gen_ndr/srv_wkssvc.h"
#include "printing/notify.h"
#include "printing.h"
#include "serverid.h"
#include "messages.h"
#include "../lib/util/pidfile.h"

static struct files_struct *log_writeable_file_fn(
	struct files_struct *fsp, void *private_data)
{
	bool *found = (bool *)private_data;
	char *path;

	if (!fsp->can_write) {
		return NULL;
	}
	if (!(*found)) {
		DEBUG(0, ("Writable files open at exit:\n"));
		*found = true;
	}

	path = talloc_asprintf(talloc_tos(), "%s/%s", fsp->conn->connectpath,
			       smb_fname_str_dbg(fsp->fsp_name));
	if (path == NULL) {
		DEBUGADD(0, ("<NOMEM>\n"));
	}

	DEBUGADD(0, ("%s\n", path));

	TALLOC_FREE(path);
	return NULL;
}

/****************************************************************************
 Exit the server.
****************************************************************************/

/* Reasons for shutting down a server process. */
enum server_exit_reason { SERVER_EXIT_NORMAL, SERVER_EXIT_ABNORMAL };

static void exit_server_common(enum server_exit_reason how,
	const char *reason) _NORETURN_;

static void exit_server_common(enum server_exit_reason how,
	const char *reason)
{
	struct smbXsrv_client *client = global_smbXsrv_client;
	struct smbXsrv_connection *xconn = NULL;
	struct smbd_server_connection *sconn = NULL;
	struct messaging_context *msg_ctx = server_messaging_context();

	if (client != NULL) {
		sconn = client->sconn;
		/*
		 * Here we typically have just one connection
		 */
		xconn = client->connections;
	}

	if (!exit_firsttime)
		exit(0);
	exit_firsttime = false;

	change_to_root_user();

	if (xconn != NULL) {
		/*
		 * This is typically the disconnect for the only
		 * (or with multi-channel last) connection of the client
		 */
		if (NT_STATUS_IS_OK(xconn->transport.status)) {
			switch (how) {
			case SERVER_EXIT_ABNORMAL:
				xconn->transport.status = NT_STATUS_INTERNAL_ERROR;
				break;
			case SERVER_EXIT_NORMAL:
				xconn->transport.status = NT_STATUS_LOCAL_DISCONNECT;
				break;
			}
		}

		TALLOC_FREE(xconn->smb1.negprot.auth_context);
	}

	change_to_root_user();

	if (sconn != NULL) {
		if (lp_log_writeable_files_on_exit()) {
			bool found = false;
			files_forall(sconn, log_writeable_file_fn, &found);
		}
	}

	change_to_root_user();

	if (xconn != NULL) {
		NTSTATUS status;

		/*
		 * Note: this is a no-op for smb2 as
		 * conn->tcon_table is empty
		 */
		status = smb1srv_tcon_disconnect_all(xconn);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Server exit (%s)\n",
				(reason ? reason : "normal exit")));
			DEBUG(0, ("exit_server_common: "
				  "smb1srv_tcon_disconnect_all() failed (%s) - "
				  "triggering cleanup\n", nt_errstr(status)));
			how = SERVER_EXIT_ABNORMAL;
			reason = "smb1srv_tcon_disconnect_all failed";
		}

		status = smbXsrv_session_logoff_all(xconn);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Server exit (%s)\n",
				(reason ? reason : "normal exit")));
			DEBUG(0, ("exit_server_common: "
				  "smbXsrv_session_logoff_all() failed (%s) - "
				  "triggering cleanup\n", nt_errstr(status)));
			how = SERVER_EXIT_ABNORMAL;
			reason = "smbXsrv_session_logoff_all failed";
		}
	}

	change_to_root_user();

	/* 3 second timeout. */
	print_notify_send_messages(msg_ctx, 3);

	/* delete our entry in the serverid database. */
	if (am_parent) {
		/*
		 * For children the parent takes care of cleaning up
		 */
		serverid_deregister(messaging_server_id(msg_ctx));
	}

#ifdef WITH_DFS
	if (dcelogin_atmost_once) {
		dfs_unlogin();
	}
#endif

#ifdef USE_DMAPI
	/* Destroy Samba DMAPI session only if we are master smbd process */
	if (am_parent) {
		if (!dmapi_destroy_session()) {
			DEBUG(0,("Unable to close Samba DMAPI session\n"));
		}
	}
#endif

	if (am_parent) {
		rpc_wkssvc_shutdown();
		rpc_dssetup_shutdown();
#ifdef DEVELOPER
		rpc_rpcecho_shutdown();
#endif
		rpc_netdfs_shutdown();
		rpc_initshutdown_shutdown();
		rpc_eventlog_shutdown();
		rpc_ntsvcs_shutdown();
		rpc_svcctl_shutdown();
		rpc_spoolss_shutdown();

		rpc_srvsvc_shutdown();
		rpc_winreg_shutdown();

		rpc_netlogon_shutdown();
		rpc_samr_shutdown();
		rpc_lsarpc_shutdown();
	}

	/*
	 * we need to force the order of freeing the following,
	 * because smbd_msg_ctx is not a talloc child of smbd_server_conn.
	 */
	if (client != NULL) {
		for (; xconn != NULL; xconn = xconn->next) {
			DLIST_REMOVE(client->connections, xconn);
			talloc_free(xconn);
		}
		TALLOC_FREE(client->sconn);
	}
	sconn = NULL;
	xconn = NULL;
	client = NULL;
	TALLOC_FREE(global_smbXsrv_client);
	server_messaging_context_free();
	server_event_context_free();
	TALLOC_FREE(smbd_memcache_ctx);

	locking_end();
	printing_end();

	if (how != SERVER_EXIT_NORMAL) {

		smb_panic(reason);

		/* Notreached. */
		exit(1);
	} else {
		DEBUG(3,("Server exit (%s)\n",
			(reason ? reason : "normal exit")));
		if (am_parent) {
			pidfile_unlink(lp_pid_directory(), "smbd");
		}
		gencache_stabilize();
	}

	exit(0);
}

void smbd_exit_server(const char *const explanation)
{
	exit_server_common(SERVER_EXIT_ABNORMAL, explanation);
}

void smbd_exit_server_cleanly(const char *const explanation)
{
	exit_server_common(SERVER_EXIT_NORMAL, explanation);
}
