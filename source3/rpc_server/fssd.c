/*
 *  File Server Shadow-Copy Daemon
 *
 *  Copyright (C) David Disseldorp	2012-2015
 *
 *  Based on epmd.c:
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#include "ntdomain.h"
#include "messages.h"

#include "librpc/rpc/dcerpc_ep.h"

#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_fsrvp_scompat.h"

#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_sock_helper.h"
#include "rpc_server/fssd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define DAEMON_NAME "fssd"

static void fssd_reopen_logs(void)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *lfile = lp_logfile(NULL, lp_sub);
	int rc;

	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s", get_dyn_LOGFILEBASE(), DAEMON_NAME);
		if (rc > 0) {
			lp_set_logfile(lfile);
			SAFE_FREE(lfile);
		}
	} else {
		if (strstr(lfile, DAEMON_NAME) == NULL) {
			rc = asprintf(&lfile, "%s.%s", lp_logfile(NULL, lp_sub), DAEMON_NAME);
			if (rc > 0) {
				lp_set_logfile(lfile);
				SAFE_FREE(lfile);
			}
		}
	}

	reopen_logs();
}

static void fssd_smb_conf_updated(struct messaging_context *msg,
				  void *private_data,
				  uint32_t msg_type,
				  struct server_id server_id,
				  DATA_BLOB *data)
{
	DEBUG(10, ("Got message saying smb.conf was updated. Reloading.\n"));
	change_to_root_user();
	fssd_reopen_logs();
}

static void fssd_sig_term_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void fssd_setup_sig_term_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGTERM, 0,
			       fssd_sig_term_handler,
			       NULL);
	if (se == NULL) {
		exit_server("failed to setup SIGTERM handler");
	}
}

static void fssd_sig_hup_handler(struct tevent_context *ev,
				    struct tevent_signal *se,
				    int signum,
				    int count,
				    void *siginfo,
				    void *private_data)
{
	change_to_root_user();

	DEBUG(1,("reopening logs after SIGHUP\n"));
	fssd_reopen_logs();
}

static void fssd_setup_sig_hup_handler(struct tevent_context *ev_ctx,
				       struct messaging_context *msg_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       fssd_sig_hup_handler,
			       msg_ctx);
	if (se == NULL) {
		exit_server("failed to setup SIGHUP handler");
	}
}

void start_fssd(struct tevent_context *ev_ctx,
		struct messaging_context *msg_ctx,
		struct dcesrv_context *dce_ctx)
{
	NTSTATUS status;
	pid_t pid;
	int rc;
	const struct dcesrv_endpoint_server *ep_server = NULL;
	struct dcesrv_endpoint *e = NULL;

	DEBUG(1, ("Forking File Server Shadow-copy Daemon\n"));

	pid = fork();

	if (pid == -1) {
		DEBUG(0, ("failed to fork file server shadow-copy daemon [%s], "
			  "aborting ...\n", strerror(errno)));
		exit(1);
	}

	if (pid) {
		/* parent */
		return;
	}

	/* child */
	status = smbd_reinit_after_fork(msg_ctx, ev_ctx, true, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	fssd_reopen_logs();

	fssd_setup_sig_term_handler(ev_ctx);
	fssd_setup_sig_hup_handler(ev_ctx, msg_ctx);

	messaging_register(msg_ctx,
			   ev_ctx,
			   MSG_SMB_CONF_UPDATED,
			   fssd_smb_conf_updated);

	DBG_INFO("Registering DCE/RPC endpoint servers\n");

	ep_server = FileServerVssAgent_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'FileServerVssAgent' endpoint "
			"server\n");
		exit(1);
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'FileServerVssAgent' endpoint "
			"server: %s\n", nt_errstr(status));
		exit(1);
	}

	DBG_INFO("Reinitializing DCE/RPC server context\n");

	status = dcesrv_reinit_context(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to reinit DCE/RPC context: %s\n",
			nt_errstr(status));
		exit(1);
	}

	DBG_INFO("Initializing DCE/RPC registered endpoint servers\n");

	status = dcesrv_init_ep_server(dce_ctx, "FileServerVssAgent");
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to init DCE/RPC endpoint server: %s\n",
			nt_errstr(status));
		exit(1);
	}

	DBG_INFO("Initializing DCE/RPC connection endpoints\n");

	for (e = dce_ctx->endpoint_list; e; e = e->next) {
		status = dcesrv_setup_endpoint_sockets(ev_ctx,
						       msg_ctx,
						       dce_ctx,
						       e,
						       NULL, /* termination function */
						       NULL); /* termination data */
		if (!NT_STATUS_IS_OK(status)) {
			char *ep_string = dcerpc_binding_string(
					dce_ctx, e->ep_description);
			DBG_ERR("Failed to setup endpoint '%s': %s\n",
					ep_string, nt_errstr(status));
			TALLOC_FREE(ep_string);
			exit(1);
		}
	}

	DEBUG(1, ("File Server Shadow-copy Daemon Started (%d)\n",
		  (int)getpid()));

	/* loop forever */
	rc = tevent_loop_wait(ev_ctx);

	/* should not be reached */
	DEBUG(0,("tevent_loop_wait() exited with %d - %s\n",
		 rc, (rc == 0) ? "out of events" : strerror(errno)));

	exit(1);
}
