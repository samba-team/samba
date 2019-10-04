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
#include "librpc/rpc/dcesrv_core.h"
#include "printing/notify.h"
#include "printing.h"
#include "serverid.h"
#include "messages.h"
#include "passdb.h"
#include "../lib/util/pidfile.h"
#include "smbprofile.h"
#include "libcli/auth/netlogon_creds_cli.h"
#include "lib/gencache.h"
#include "rpc_server/rpc_config.h"

static struct files_struct *log_writeable_file_fn(
	struct files_struct *fsp, void *private_data)
{
	bool *found = (bool *)private_data;
	char *path;

	if (!fsp->fsp_flags.can_write) {
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
	struct messaging_context *msg_ctx = global_messaging_context();
	NTSTATUS disconnect_status;

	switch (how) {
	case SERVER_EXIT_NORMAL:
		disconnect_status = NT_STATUS_LOCAL_DISCONNECT;
		break;
	case SERVER_EXIT_ABNORMAL:
	default:
		disconnect_status = NT_STATUS_INTERNAL_ERROR;
		break;
	}

	if (client != NULL) {
		sconn = client->sconn;
		xconn = client->connections;
	}

	if (!exit_firsttime)
		exit(0);
	exit_firsttime = false;

	change_to_root_user();


	/*
	 * Here we typically have just one connection
	 */
	for (; xconn != NULL; xconn = xconn->next) {
		/*
		 * This is typically the disconnect for the only
		 * (or with multi-channel last) connection of the client.
		 *
		 * smbXsrv_connection_disconnect_transport() might be called already,
		 * but calling it again is a no-op.
		 */
		smbXsrv_connection_disconnect_transport(xconn, disconnect_status);
	}

	change_to_root_user();

	if (sconn != NULL) {
		if (lp_log_writeable_files_on_exit()) {
			bool found = false;
			files_forall(sconn, log_writeable_file_fn, &found);
		}
	}

	change_to_root_user();

	if (client != NULL) {
		NTSTATUS status;

		/*
		 * Note: this is a no-op for smb2 as
		 * conn->tcon_table is empty
		 */
		status = smb1srv_tcon_disconnect_all(client);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Server exit (%s)\n",
				(reason ? reason : "normal exit")));
			DEBUG(0, ("exit_server_common: "
				  "smb1srv_tcon_disconnect_all() failed (%s) - "
				  "triggering cleanup\n", nt_errstr(status)));
		}

		status = smbXsrv_session_logoff_all(client);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Server exit (%s)\n",
				(reason ? reason : "normal exit")));
			DEBUG(0, ("exit_server_common: "
				  "smbXsrv_session_logoff_all() failed (%s) - "
				  "triggering cleanup\n", nt_errstr(status)));
		}
	}

	change_to_root_user();

	if (client != NULL) {
		struct smbXsrv_connection *xconn_next = NULL;

		for (xconn = client->connections;
		     xconn != NULL;
		     xconn = xconn_next) {
			xconn_next = xconn->next;
			DLIST_REMOVE(client->connections, xconn);
			TALLOC_FREE(xconn);
		}
	}

	change_to_root_user();

	/* 3 second timeout. */
	print_notify_send_messages(msg_ctx, 3);

#ifdef USE_DMAPI
	/* Destroy Samba DMAPI session only if we are master smbd process */
	if (am_parent) {
		if (!dmapi_destroy_session()) {
			DEBUG(0,("Unable to close Samba DMAPI session\n"));
		}
	}
#endif

	if (am_parent && sconn != NULL) {
		dcesrv_shutdown_registered_ep_servers(sconn->dce_ctx);

		global_dcesrv_context_free();
	}

	/*
	 * we need to force the order of freeing the following,
	 * because smbd_msg_ctx is not a talloc child of smbd_server_conn.
	 */
	if (client != NULL) {
		TALLOC_FREE(client->sconn);
	}
	sconn = NULL;
	xconn = NULL;
	client = NULL;
	netlogon_creds_cli_close_global_db();
	TALLOC_FREE(global_smbXsrv_client);
	smbprofile_dump();
	global_messaging_context_free();
	global_event_context_free();
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

/*
 * reinit_after_fork() wrapper that should be called when forking from
 * smbd.
 */
NTSTATUS smbd_reinit_after_fork(struct messaging_context *msg_ctx,
				struct tevent_context *ev_ctx,
				bool parent_longlived, const char *comment)
{
	NTSTATUS ret;
	am_parent = NULL;
	ret = reinit_after_fork(msg_ctx, ev_ctx, parent_longlived, comment);
	initialize_password_db(true, ev_ctx);
	return ret;
}
