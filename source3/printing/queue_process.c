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
#include <spawn.h>
#include "smbd/globals.h"
#include "include/messages.h"
#include "lib/util/util_process.h"
#include "lib/util/sys_rw.h"
#include "printing.h"
#include "printing/pcap.h"
#include "printing/printer_list.h"
#include "printing/queue_process.h"
#include "locking/proto.h"
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "rpc_server/rpc_config.h"
#include "printing/load.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "auth.h"
#include "nt_printing.h"
#include "util_event.h"
#include "lib/global_contexts.h"
#include "lib/util/pidfile.h"

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
		 * are fully initialized */
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
		if (lp_autoloaded(snum) &&
		    !printer_list_printername_exists(pname)) {
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
	 * it doesn't block smbd's serving clients.
	 */
	delete_and_reload_printers_full(ev, msg_ctx);

	messaging_send_all(msg_ctx, MSG_PRINTER_PCAP, NULL, 0);
}

struct bq_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct idle_event *housekeep;
	struct tevent_signal *sighup_handler;
	struct tevent_signal *sigchld_handler;
};

static bool print_queue_housekeeping(const struct timeval *now, void *pvt)
{
	struct bq_state *state;

	state = talloc_get_type_abort(pvt, struct bq_state);

	DEBUG(5, ("print queue housekeeping\n"));
	pcap_cache_reload(state->ev, state->msg, reload_pcap_change_notify);

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

	state->housekeep = event_add_idle(
		state->ev,
		NULL,
		tevent_timeval_set(housekeeping_period, 0),
		"print_queue_housekeeping",
		print_queue_housekeeping,
		state);
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

	DBG_NOTICE("Reloading pcap cache after SIGHUP\n");
	pcap_cache_reload(state->ev, state->msg,
			  reload_pcap_change_notify);
	printing_subsystem_queue_tasks(state);
	bq_reopen_logs(NULL);
}

static void bq_sig_chld_handler(struct tevent_context *ev_ctx,
				struct tevent_signal *se,
				int signum, int count,
				void *siginfo, void *pvt)
{
	int status;
	pid_t pid;

	do {
		do {
			pid = waitpid(-1, &status, WNOHANG);
		} while ((pid == -1) && (errno == EINTR));

		if (WIFEXITED(status)) {
			DBG_INFO("Bq child process %d terminated with %d\n",
				 (int)pid,
				 WEXITSTATUS(status));
		} else {
			DBG_NOTICE("Bq child process %d terminated abnormally\n",
				   (int)pid);
		}
	} while (pid > 0);
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
	pcap_cache_reload(state->ev, msg_ctx, reload_pcap_change_notify);
	printing_subsystem_queue_tasks(state);
}

static int bq_state_destructor(struct bq_state *s)
{
	struct messaging_context *msg_ctx = s->msg;
	TALLOC_FREE(s->sighup_handler);
	TALLOC_FREE(s->sigchld_handler);
	messaging_deregister(msg_ctx, MSG_PRINTER_DRVUPGRADE, NULL);
	messaging_deregister(msg_ctx, MSG_PRINTER_UPDATE, NULL);
	messaging_deregister(msg_ctx, MSG_SMB_CONF_UPDATED, s);
	return 0;
}

struct bq_state *register_printing_bq_handlers(
	TALLOC_CTX *mem_ctx,
	struct messaging_context *msg_ctx)
{
	struct bq_state *state = NULL;
	NTSTATUS status;
	bool ok;

	state = talloc_zero(mem_ctx, struct bq_state);
	if (state == NULL) {
		return NULL;
	}
	state->ev = messaging_tevent_context(msg_ctx);
	state->msg = msg_ctx;

	status = messaging_register(
		msg_ctx, state, MSG_SMB_CONF_UPDATED, bq_smb_conf_updated);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = messaging_register(
		msg_ctx, NULL, MSG_PRINTER_UPDATE, print_queue_receive);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail_dereg_smb_conf_updated;
	}
	status = messaging_register(
		msg_ctx, NULL, MSG_PRINTER_DRVUPGRADE, do_drv_upgrade_printer);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail_dereg_printer_update;
	}

	state->sighup_handler = tevent_add_signal(
		state->ev, state, SIGHUP, 0, bq_sig_hup_handler, state);
	if (state->sighup_handler == NULL) {
		goto fail_dereg_printer_drvupgrade;
	}
	state->sigchld_handler = tevent_add_signal(
		state->ev, state, SIGCHLD, 0, bq_sig_chld_handler, NULL);
	if (state->sigchld_handler == NULL) {
		goto fail_free_handlers;
	}

	/* Initialize the printcap cache as soon as the daemon starts. */
	pcap_cache_reload(state->ev, state->msg, reload_pcap_change_notify);

	ok = printing_subsystem_queue_tasks(state);
	if (!ok) {
		goto fail_free_handlers;
	}

	talloc_set_destructor(state, bq_state_destructor);

	return state;

fail_free_handlers:
	TALLOC_FREE(state->sighup_handler);
	TALLOC_FREE(state->sigchld_handler);
fail_dereg_printer_drvupgrade:
	messaging_deregister(msg_ctx, MSG_PRINTER_DRVUPGRADE, NULL);
fail_dereg_printer_update:
	messaging_deregister(msg_ctx, MSG_PRINTER_UPDATE, NULL);
fail_dereg_smb_conf_updated:
	messaging_deregister(msg_ctx, MSG_SMB_CONF_UPDATED, state);
fail:
	TALLOC_FREE(state);
	return NULL;
}

/****************************************************************************
main thread of the background lpq updater
****************************************************************************/
pid_t start_background_queue(struct tevent_context *ev,
			     struct messaging_context *msg_ctx,
			     char *logfile)
{
	pid_t pid;
	int ret;
	ssize_t nread;
	char **argv = NULL;
	int ready_fds[2];

	DEBUG(3,("start_background_queue: Starting background LPQ thread\n"));

	ret = pipe(ready_fds);
	if (ret == -1) {
		return -1;
	}

	argv = str_list_make_empty(talloc_tos());
	str_list_add_printf(
		&argv, "%s/samba-bgqd", get_dyn_SAMBA_LIBEXECDIR());
	str_list_add_printf(
		&argv, "--ready-signal-fd=%d", ready_fds[1]);
	str_list_add_printf(
		&argv, "--parent-watch-fd=%d", 0);
	str_list_add_printf(
		&argv, "--debuglevel=%d", debuglevel_get_class(DBGC_RPC_SRV));
	if (!is_default_dyn_CONFIGFILE()) {
		str_list_add_printf(
			&argv, "--configfile=%s", get_dyn_CONFIGFILE());
	}
	if (!is_default_dyn_LOGFILEBASE()) {
		str_list_add_printf(
			&argv, "--log-basename=%s", get_dyn_LOGFILEBASE());
	}
	str_list_add_printf(&argv, "-F");
	if (argv == NULL) {
		goto nomem;
	}

	ret = posix_spawn(&pid, argv[0], NULL, NULL, argv, environ);
	if (ret == -1) {
		goto fail;
	}
	TALLOC_FREE(argv);

	close(ready_fds[1]);

	nread = sys_read(ready_fds[0], &pid, sizeof(pid));
	close(ready_fds[0]);
	if (nread != sizeof(pid)) {
		goto fail;
	}

	return pid;

nomem:
	errno = ENOMEM;
fail:
	{
		int err = errno;
		TALLOC_FREE(argv);
		errno = err;
	}

	return -1;
}


/* Run before the parent forks */
bool printing_subsystem_init(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     struct dcesrv_context *dce_ctx)
{
	pid_t pid = -1;

	pid = start_background_queue(NULL, NULL, NULL);
	if (pid == -1) {
		return false;
	}
	background_lpq_updater_pid = pid;

	if (!print_backend_init(msg_ctx)) {
		return false;
	}

	return true;
}

void send_to_bgqd(struct messaging_context *msg_ctx,
		  uint32_t msg_type,
		  const uint8_t *buf,
		  size_t buflen)
{
	pid_t bgqd = pidfile_pid(lp_pid_directory(), "samba-bgqd");

	if (bgqd == -1) {
		return;
	}
	messaging_send_buf(
		msg_ctx, pid_to_procid(bgqd), msg_type, buf, buflen);
}
