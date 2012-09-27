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
#include "printing.h"
#include "printing/pcap.h"
#include "printing/queue_process.h"
#include "serverid.h"
#include "locking/proto.h"
#include "smbd/smbd.h"
#include "rpc_server/rpc_config.h"
#include "printing/load.h"

extern pid_t start_spoolssd(struct event_context *ev_ctx,
			    struct messaging_context *msg_ctx);

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
	delete_and_reload_printers(ev, msg_ctx);

	message_send_all(msg_ctx, MSG_PRINTER_PCAP, NULL, 0, NULL);
}

struct printing_queue_housekeeping_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
};

static bool print_queue_housekeeping(const struct timeval *now, void *pvt)
{
	struct printing_queue_housekeeping_state *state =
		talloc_get_type_abort(pvt,
		struct printing_queue_housekeeping_state);
	time_t printcap_cache_time = (time_t)lp_printcap_cache_time();
	time_t t = time_mono(NULL);

	DEBUG(5, ("print queue housekeeping\n"));

	/* if periodic printcap rescan is enabled,
	 * see if it's time to reload */
	if ((printcap_cache_time != 0) &&
	    (t >= (last_printer_reload_time + printcap_cache_time))) {
		DEBUG( 3,( "Printcap cache time expired.\n"));
		pcap_cache_reload(state->ev, state->msg,
				  &reload_pcap_change_notify);
		last_printer_reload_time = t;
	}

	return true;
}

static bool printing_subsystem_queue_tasks(struct tevent_context *ev_ctx,
					   struct messaging_context *msg_ctx)
{
	struct printing_queue_housekeeping_state *state;

	state = talloc_zero(ev_ctx, struct printing_queue_housekeeping_state);
	if (state == NULL) {
		DEBUG(0,("Could not talloc printing_queue_housekeeping_state\n"));
		return false;
	}
	state->ev = ev_ctx;
	state->msg = msg_ctx;

	if (!(event_add_idle(ev_ctx, NULL,
			     timeval_set(SMBD_HOUSEKEEPING_INTERVAL, 0),
			     "print_queue_housekeeping",
			     print_queue_housekeeping,
			     state))) {
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

	se = tevent_add_signal(server_event_context(),
			       server_event_context(),
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
	struct messaging_context *msg_ctx;

	msg_ctx = talloc_get_type_abort(pvt, struct messaging_context);
	change_to_root_user();

	DEBUG(1, ("Reloading pcap cache after SIGHUP\n"));
	pcap_cache_reload(ev, msg_ctx, &reload_pcap_change_notify);
	bq_reopen_logs(NULL);
}

static void bq_setup_sig_hup_handler(struct tevent_context *ev,
				     struct messaging_context *msg_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev, ev, SIGHUP, 0, bq_sig_hup_handler,
			       msg_ctx);
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

	pid = sys_waitpid(-1, &status, WNOHANG);
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
	struct tevent_context *ev_ctx =
		talloc_get_type_abort(private_data, struct tevent_context);

	DEBUG(10,("smb_conf_updated: Got message saying smb.conf was "
		  "updated. Reloading.\n"));
	change_to_root_user();
	pcap_cache_reload(ev_ctx, msg_ctx, &reload_pcap_change_notify);
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

		status = reinit_after_fork(msg_ctx, ev, true);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("reinit_after_fork() failed\n"));
			smb_panic("reinit_after_fork() failed");
		}

		bq_reopen_logs(logfile);
		bq_setup_sig_term_handler();
		bq_setup_sig_hup_handler(ev, msg_ctx);
		bq_setup_sig_chld_handler(ev);

		BlockSignals(false, SIGTERM);
		BlockSignals(false, SIGHUP);

		if (!printing_subsystem_queue_tasks(ev, msg_ctx)) {
			exit(1);
		}

		if (!serverid_register(messaging_server_id(msg_ctx),
				       FLAG_MSG_GENERAL |
				       FLAG_MSG_PRINT_GENERAL)) {
			exit(1);
		}

		if (!locking_init()) {
			exit(1);
		}
		messaging_register(msg_ctx, ev, MSG_SMB_CONF_UPDATED,
				   bq_smb_conf_updated);
		messaging_register(msg_ctx, NULL, MSG_PRINTER_UPDATE,
				   print_queue_receive);

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

		pid = start_spoolssd(ev_ctx, msg_ctx);

	} else if (start_daemons && background_queue) {

		pid = start_background_queue(ev_ctx, msg_ctx, NULL);

	} else {
		bool ret;

		ret = printing_subsystem_queue_tasks(ev_ctx, msg_ctx);

		/* Publish nt printers, this requires a working winreg pipe */
		pcap_cache_reload(ev_ctx, msg_ctx, &delete_and_reload_printers);

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
		if (pcap_cache_loaded()) {
			load_printers(ev_ctx, msg_ctx);
		}
		if (force) {
			/* Send a sighup to the background process.
			 * this will force it to reload printers */
			kill(background_lpq_updater_pid, SIGHUP);
		}
		return;
	}

	pcap_cache_reload(ev_ctx, msg_ctx, &delete_and_reload_printers);
}
