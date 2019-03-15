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
#include "../librpc/gen_ndr/srv_fsrvp.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_sock_helper.h"
#include "rpc_server/fss/srv_fss_agent.h"
#include "rpc_server/fssd.h"

#define DAEMON_NAME "fssd"

void start_fssd(struct tevent_context *ev_ctx,
		struct messaging_context *msg_ctx);

static void fssd_reopen_logs(void)
{
	char *lfile = lp_logfile(NULL);
	int rc;

	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s", get_dyn_LOGFILEBASE(), DAEMON_NAME);
		if (rc > 0) {
			lp_set_logfile(lfile);
			SAFE_FREE(lfile);
		}
	} else {
		if (strstr(lfile, DAEMON_NAME) == NULL) {
			rc = asprintf(&lfile, "%s.%s", lp_logfile(NULL), DAEMON_NAME);
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
	rpc_FileServerVssAgent_shutdown();

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

static bool fss_shutdown_cb(void *ptr)
{
	srv_fssa_cleanup();
	return true;
}

static bool fss_init_cb(void *ptr)
{
	NTSTATUS status;
        struct messaging_context *msg_ctx;

	msg_ctx = talloc_get_type_abort(ptr, struct messaging_context);
	status = srv_fssa_start(msg_ctx);
	return NT_STATUS_IS_OK(status);
}

void start_fssd(struct tevent_context *ev_ctx,
		struct messaging_context *msg_ctx)
{
	struct rpc_srv_callbacks fss_cb;
	NTSTATUS status;
	pid_t pid;
	bool ok;
	int rc;

	fss_cb.init = fss_init_cb;
	fss_cb.shutdown = fss_shutdown_cb;
	fss_cb.private_data = msg_ctx;

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

	status = rpc_FileServerVssAgent_init(&fss_cb);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register fssd rpc interface! (%s)\n",
			  nt_errstr(status)));
		exit(1);
	}

	/* case is normalized by smbd on connection */
	ok = setup_named_pipe_socket("fssagentrpc", ev_ctx, msg_ctx);
	if (!ok) {
		DEBUG(0, ("Failed to open fssd named pipe!\n"));
		exit(1);
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
