/*
   Unix SMB/Netbios implementation.
   Version 3.0
   printing backend routines
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Jeremy Allison 2002
   Copyright (C) Simo Sorce 2011

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
#include "smbd/globals.h"
#include "include/messages.h"
#include "lib/util/util_process.h"
#include "printing.h"
#include "printing/pcap.h"
#include "printing/queue_process.h"
#include "locking/proto.h"
#include "smbd/smbd.h"
#include "rpc_server/rpc_config.h"
#include "printing/load.h"
#include "printing/spoolssd.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "auth.h"
#include "nt_printing.h"
#include "util_event.h"

/**
 * @brief Purge stale printers and reload from pre-populated pcap cache.
 *
 * This function should normally only be called as a callback on a successful
 * pcap_cache_reload().
 *
 * This function can cause DELETION of printers and drivers from our registry,
 * so calling it on a failed pcap reload may REMOVE permanently all printers
 * and drivers.
 *
 * @param[in] ev        The event context.
 *
 * @param[in] msg_ctx   The messaging context.
 */
static void delete_and_reload_printers_full(struct tevent_context *ev,
					    struct messaging_context *msg_ctx)
{
	struct auth_session_info *session_info = NULL;
	struct spoolss_PrinterInfo2 *pinfo2 = NULL;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int n_services;
	int pnum;
	int snum;
	const char *pname;
	const char *sname;
	NTSTATUS status;

	n_services = lp_numservices();
	pnum = lp_servicenumber(PRINTERS_NAME);

	status = make_session_info_system(talloc_tos(), &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("reload_printers: "
			  "Could not create system session_info\n"));
		/* can't remove stale printers before we
		 * are fully initilized */
		return;
	}

	/*
	 * Add default config for printers added to smb.conf file and remove
	 * stale printers
	 */
	for (snum = 0; snum < n_services; snum++) {
		/* avoid removing PRINTERS_NAME */
		if (snum == pnum) {
			continue;
		}

		/* skip no-printer services */
		if (!snum_is_shared_printer(snum)) {
			continue;
		}

		sname = lp_const_servicename(snum);
		pname = lp_printername(session_info, lp_sub, snum);

		/* check printer, but avoid removing non-autoloaded printers */
		if (lp_autoloaded(snum) && !pcap_printername_ok(pname)) {
			DEBUG(3, ("removing stale printer %s\n", pname));

			if (is_printer_published(session_info, session_info,
						 msg_ctx,
						 NULL,
						 lp_servicename(session_info,
								lp_sub,
								snum),
						 &pinfo2)) {
				nt_printer_publish(session_info,
						   session_info,
						   msg_ctx,
						   pinfo2,
						   DSPRINT_UNPUBLISH);
				TALLOC_FREE(pinfo2);
			}
			nt_printer_remove(session_info, session_info, msg_ctx,
					  pname);
		} else {
			DEBUG(8, ("Adding default registry entry for printer "
				  "[%s], if it doesn't exist.\n", sname));
			nt_printer_add(session_info, session_info, msg_ctx,
				       sname);
		}
	}

	/* finally, purge old snums */
	delete_and_reload_printers();

	TALLOC_FREE(session_info);
}


/****************************************************************************
 Notify smbds of new printcap data
**************************************************************************/
static void reload_pcap_change_notify(struct tevent_context *ev,
			       struct messaging_context *msg_ctx)
{
	/*
	 * Reload the printers first in the background process so that
	 * newly added printers get default values created in the registry.
	 *
	 * This will block the process for some time (~1 sec per printer), but
	 * it doesn't block smbd's servering clients.
	 */
	delete_and_reload_printers_full(ev, msg_ctx);

	messaging_send_all(msg_ctx, MSG_PRINTER_PCAP, NULL, 0);
}

struct bq_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct idle_event *housekeep;
};

static bool print_queue_housekeeping(const struct timeval *now, void *pvt)
{
	struct bq_state *state;

	state = talloc_get_type_abort(pvt, struct bq_state);

	DEBUG(5, ("print queue housekeeping\n"));
	pcap_cache_reload(state->ev, state->msg, &reload_pcap_change_notify);

	return true;
}

static bool printing_subsystem_queue_tasks(struct bq_state *state)
{
	uint32_t housekeeping_period = lp_printcap_cache_time();

	/* cancel any existing housekeeping event */
	TALLOC_FREE(state->housekeep);

	if ((housekeeping_period == 0) || !lp_load_printers()) {
		DEBUG(4, ("background print queue housekeeping disabled\n"));
		return true;
	}

	state->housekeep = event_add_idle(state->ev, NULL,
					  timeval_set(housekeeping_period, 0),
					  "print_queue_housekeeping",
					  print_queue_housekeeping, state);
	if (state->housekeep == NULL) {
		DEBUG(0,("Could not add print_queue_housekeeping event\n"));
		return false;
	}

	return true;
}

static void bq_reopen_logs(char *logfile)
{
	if (logfile) {
		lp_set_logfile(logfile);
	}
	reopen_logs();
}

static void bq_sig_term_handler(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum,
				int count,
				void *siginfo,
				void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void bq_setup_sig_term_handler(void)
{
	struct tevent_signal *se;

	se = tevent_add_signal(global_event_context(),
			       global_event_context(),
			       SIGTERM, 0,
			       bq_sig_term_handler,
			       NULL);
	if (!se) {
		exit_server("failed to setup SIGTERM handler");
	}
}

static void bq_sig_hup_handler(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum,
				int count,
				void *siginfo,
				void *pvt)
{
	struct bq_state *state;

	state = talloc_get_type_abort(pvt, struct bq_state);
	change_to_root_user();

	DEBUG(1, ("Reloading pcap cache after SIGHUP\n"));
	pcap_cache_reload(state->ev, state->msg,
			  &reload_pcap_change_notify);
	printing_subsystem_queue_tasks(state);
	bq_reopen_logs(NULL);
}

static void bq_setup_sig_hup_handler(struct bq_state *state)
{
	struct tevent_signal *se;

	se = tevent_add_signal(state->ev, state->ev, SIGHUP, 0,
			       bq_sig_hup_handler, state);
	if (!se) {
		exit_server("failed to setup SIGHUP handler");
	}
}

static void bq_sig_chld_handler(struct tevent_context *ev_ctx,
				struct tevent_signal *se,
				int signum, int count,
				void *siginfo, void *pvt)
{
	int status;
	pid_t pid;

	pid = waitpid(-1, &status, WNOHANG);
	if (WIFEXITED(status)) {
		DEBUG(6, ("Bq child process %d terminated with %d\n",
			  (int)pid, WEXITSTATUS(status)));
	} else {
		DEBUG(3, ("Bq child process %d terminated abnormally\n",
			  (int)pid));
	}
}

static void bq_setup_sig_chld_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx, ev_ctx, SIGCHLD, 0,
				bq_sig_chld_handler, NULL);
	if (!se) {
		exit_server("failed to setup SIGCHLD handler");
	}
}

static void bq_smb_conf_updated(struct messaging_context *msg_ctx,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data)
{
	struct bq_state *state;

	state = talloc_get_type_abort(private_data, struct bq_state);

	DEBUG(10,("smb_conf_updated: Got message saying smb.conf was "
		  "updated. Reloading.\n"));
	change_to_root_user();
	pcap_cache_reload(state->ev, msg_ctx, &reload_pcap_change_notify);
	printing_subsystem_queue_tasks(state);
}

static void printing_pause_fd_handler(struct tevent_context *ev,
				      struct tevent_fd *fde,
				      uint16_t flags,
				      void *private_data)
{
	/*
	 * If pause_pipe[1] is closed it means the parent smbd
	 * and children exited or aborted.
	 */
	exit_server_cleanly(NULL);
}

/****************************************************************************
main thread of the background lpq updater
****************************************************************************/
pid_t start_background_queue(struct tevent_context *ev,
			     struct messaging_context *msg_ctx,
			     char *logfile)
{
	pid_t pid;
	struct bq_state *state;

	/* Use local variables for this as we don't
	 * need to save the parent side of this, just
	 * ensure it closes when the process exits.
	 */
	int pause_pipe[2];

	DEBUG(3,("start_background_queue: Starting background LPQ thread\n"));

	if (pipe(pause_pipe) == -1) {
		DEBUG(5,("start_background_queue: cannot create pipe. %s\n", strerror(errno) ));
		exit(1);
	}

	/*
	 * Block signals before forking child as it will have to
	 * set its own handlers. Child will re-enable SIGHUP as
	 * soon as the handlers are set up.
	 */
	BlockSignals(true, SIGTERM);
	BlockSignals(true, SIGHUP);

	pid = fork();

	/* parent or error */
	if (pid != 0) {
		/* Re-enable SIGHUP before returnig */
		BlockSignals(false, SIGTERM);
		BlockSignals(false, SIGHUP);
		return pid;
	}

	if (pid == -1) {
		DEBUG(5,("start_background_queue: background LPQ thread failed to start. %s\n", strerror(errno) ));
		exit(1);
	}

	if (pid == 0) {
		struct tevent_fd *fde;
		int ret;
		NTSTATUS status;

		/* Child. */
		DEBUG(5,("start_background_queue: background LPQ thread started\n"));

		close(pause_pipe[0]);
		pause_pipe[0] = -1;

		status = smbd_reinit_after_fork(msg_ctx, ev, true, "lpqd");

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("reinit_after_fork() failed\n"));
			smb_panic("reinit_after_fork() failed");
		}

		state = talloc_zero(NULL, struct bq_state);
		if (state == NULL) {
			exit(1);
		}
		state->ev = ev;
		state->msg = msg_ctx;

		bq_reopen_logs(logfile);
		bq_setup_sig_term_handler();
		bq_setup_sig_hup_handler(state);
		bq_setup_sig_chld_handler(ev);

		BlockSignals(false, SIGTERM);
		BlockSignals(false, SIGHUP);

		if (!printing_subsystem_queue_tasks(state)) {
			exit(1);
		}

		if (!locking_init()) {
			exit(1);
		}
		messaging_register(msg_ctx, state, MSG_SMB_CONF_UPDATED,
				   bq_smb_conf_updated);
		messaging_register(msg_ctx, NULL, MSG_PRINTER_UPDATE,
				   print_queue_receive);
		/* Remove previous forwarder message set in parent. */
		messaging_deregister(msg_ctx, MSG_PRINTER_DRVUPGRADE, NULL);

		messaging_register(msg_ctx, NULL, MSG_PRINTER_DRVUPGRADE,
				   do_drv_upgrade_printer);

		fde = tevent_add_fd(ev, ev, pause_pipe[1], TEVENT_FD_READ,
				    printing_pause_fd_handler,
				    NULL);
		if (!fde) {
			DEBUG(0,("tevent_add_fd() failed for pause_pipe\n"));
			smb_panic("tevent_add_fd() failed for pause_pipe");
		}

		pcap_cache_reload(ev, msg_ctx, &reload_pcap_change_notify);

		DEBUG(5,("start_background_queue: background LPQ thread waiting for messages\n"));
		ret = tevent_loop_wait(ev);
		/* should not be reached */
		DEBUG(0,("background_queue: tevent_loop_wait() exited with %d - %s\n",
			 ret, (ret == 0) ? "out of events" : strerror(errno)));
		exit(1);
	}

	close(pause_pipe[1]);

	return pid;
}

/* Run before the parent forks */
bool printing_subsystem_init(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     struct dcesrv_context *dce_ctx,
			     bool start_daemons,
			     bool background_queue)
{
	pid_t pid = -1;

	if (!print_backend_init(msg_ctx)) {
		return false;
	}

	/* start spoolss daemon */
	/* start as a separate daemon only if enabled */
	if (start_daemons && rpc_spoolss_daemon() == RPC_DAEMON_FORK) {

		pid = start_spoolssd(ev_ctx, msg_ctx, dce_ctx);

	} else if (start_daemons && background_queue) {

		pid = start_background_queue(ev_ctx, msg_ctx, NULL);

	} else {
		bool ret;
		struct bq_state *state;

		state = talloc_zero(NULL, struct bq_state);
		if (state == NULL) {
			exit(1);
		}
		state->ev = ev_ctx;
		state->msg = msg_ctx;

		ret = printing_subsystem_queue_tasks(state);

		/* Publish nt printers, this requires a working winreg pipe */
		pcap_cache_reload(ev_ctx, msg_ctx,
				  &delete_and_reload_printers_full);

		return ret;
	}

	if (pid == -1) {
		return false;
	}
	background_lpq_updater_pid = pid;

	return true;
}

void printing_subsystem_update(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       bool force)
{
	if (background_lpq_updater_pid != -1) {
		load_printers();
		if (force) {
			/* Send a sighup to the background process.
			 * this will force it to reload printers */
			kill(background_lpq_updater_pid, SIGHUP);
		}
		return;
	}

	pcap_cache_reload(ev_ctx, msg_ctx,
			  &delete_and_reload_printers_full);
}
