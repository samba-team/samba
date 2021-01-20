/*
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) by Tim Potter 2000-2002
   Copyright (C) Andrew Tridgell 2002
   Copyright (C) Jelmer Vernooij 2003
   Copyright (C) Volker Lendecke 2004

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
#include "popt_common.h"
#include "winbindd.h"
#include "nsswitch/winbind_client.h"
#include "nsswitch/wb_reqtrans.h"
#include "ntdomain.h"
#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_lsa_scompat.h"
#include "librpc/gen_ndr/ndr_samr_scompat.h"
#include "librpc/gen_ndr/ndr_winbind_scompat.h"
#include "secrets.h"
#include "rpc_client/cli_netlogon.h"
#include "idmap.h"
#include "lib/addrchange.h"
#include "auth.h"
#include "messages.h"
#include "../lib/util/pidfile.h"
#include "util_cluster.h"
#include "source4/lib/messaging/irpc.h"
#include "source4/lib/messaging/messaging.h"
#include "lib/param/param.h"
#include "lib/async_req/async_sock.h"
#include "libsmb/samlogon_cache.h"
#include "libcli/auth/netlogon_creds_cli.h"
#include "passdb.h"
#include "lib/util/tevent_req_profile.h"
#include "lib/gencache.h"
#include "rpc_server/rpc_config.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

#define SCRUB_CLIENTS_INTERVAL 5

static bool client_is_idle(struct winbindd_cli_state *state);
static void remove_client(struct winbindd_cli_state *state);
static void winbindd_setup_max_fds(void);

static bool opt_nocache = False;
static bool interactive = False;

extern bool override_logfile;

struct imessaging_context *winbind_imessaging_context(void)
{
	static struct imessaging_context *msg = NULL;
	struct messaging_context *msg_ctx;
	struct server_id myself;
	struct loadparm_context *lp_ctx;

	if (msg != NULL) {
		return msg;
	}

	msg_ctx = global_messaging_context();
	if (msg_ctx == NULL) {
		smb_panic("global_messaging_context failed\n");
	}
	myself = messaging_server_id(msg_ctx);

	lp_ctx = loadparm_init_s3(NULL, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		smb_panic("Could not load smb.conf to init winbindd's imessaging context.\n");
	}

	/*
	 * Note we MUST use the NULL context here, not the autofree context,
	 * to avoid side effects in forked children exiting.
	 */
	msg = imessaging_init(NULL, lp_ctx, myself, global_event_context());
	talloc_unlink(NULL, lp_ctx);

	if (msg == NULL) {
		smb_panic("Could not init winbindd's messaging context.\n");
	}
	return msg;
}

/* Reload configuration */

bool winbindd_reload_services_file(const char *lfile)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	bool ret;

	if (lp_loaded()) {
		char *fname = lp_next_configfile(talloc_tos(), lp_sub);

		if (file_exist(fname) && !strcsequal(fname,get_dyn_CONFIGFILE())) {
			set_dyn_CONFIGFILE(fname);
		}
		TALLOC_FREE(fname);
	}

	reopen_logs();
	ret = lp_load_global(get_dyn_CONFIGFILE());

	/* if this is a child, restore the logfile to the special
	   name - <domain>, idmap, etc. */
	if (lfile && *lfile) {
		lp_set_logfile(lfile);
	}

	reopen_logs();
	load_interfaces();
	winbindd_setup_max_fds();

	return(ret);
}


static void winbindd_status(void)
{
	struct winbindd_cli_state *tmp;

	DEBUG(0, ("winbindd status:\n"));

	/* Print client state information */

	DEBUG(0, ("\t%d clients currently active\n", winbindd_num_clients()));

	if (DEBUGLEVEL >= 2 && winbindd_num_clients()) {
		DEBUG(2, ("\tclient list:\n"));
		for(tmp = winbindd_client_list(); tmp; tmp = tmp->next) {
			DEBUGADD(2, ("\t\tpid %lu, sock %d (%s)\n",
				     (unsigned long)tmp->pid, tmp->sock,
				     client_is_idle(tmp) ? "idle" : "active"));
		}
	}
}

/* Flush client cache */

void winbindd_flush_caches(void)
{
	/* We need to invalidate cached user list entries on a SIGHUP 
           otherwise cached access denied errors due to restrict anonymous
           hang around until the sequence number changes. */

	if (!wcache_invalidate_cache()) {
		DEBUG(0, ("invalidating the cache failed; revalidate the cache\n"));
		if (!winbindd_cache_validate_and_initialize()) {
			exit(1);
		}
	}
}

static void flush_caches_noinit(void)
{
	/*
	 * We need to invalidate cached user list entries on a SIGHUP
         * otherwise cached access denied errors due to restrict anonymous
         * hang around until the sequence number changes.
	 * NB
	 * Skip uninitialized domains when flush cache.
	 * If domain is not initialized, it means it is never
	 * used or never become online. look, wcache_invalidate_cache()
	 * -> get_cache() -> init_dc_connection(). It causes a lot of traffic
	 * for unused domains and large traffic for primay domain's DC if there
	 * are many domains..
	 */

	if (!wcache_invalidate_cache_noinit()) {
		DEBUG(0, ("invalidating the cache failed; revalidate the cache\n"));
		if (!winbindd_cache_validate_and_initialize()) {
			exit(1);
		}
	}
}

/* Handle the signal by unlinking socket and exiting */

static void terminate(bool is_parent)
{
	if (is_parent) {
		/* When parent goes away we should
		 * remove the socket file. Not so
		 * when children terminate.
		 */ 
		char *path = NULL;

		if (asprintf(&path, "%s/%s",
			lp_winbindd_socket_directory(), WINBINDD_SOCKET_NAME) > 0) {
			unlink(path);
			SAFE_FREE(path);
		}
	}

	idmap_close();

	netlogon_creds_cli_close_global_db();

#if 0
	if (interactive) {
		TALLOC_CTX *mem_ctx = talloc_init("end_description");
		char *description = talloc_describe_all(mem_ctx);

		DEBUG(3, ("tallocs left:\n%s\n", description));
		talloc_destroy(mem_ctx);
	}
#endif

	if (is_parent) {
		pidfile_unlink(lp_pid_directory(), "winbindd");
	}

	exit(0);
}

static void winbindd_sig_term_handler(struct tevent_context *ev,
				      struct tevent_signal *se,
				      int signum,
				      int count,
				      void *siginfo,
				      void *private_data)
{
	bool *p = talloc_get_type_abort(private_data, bool);
	bool is_parent = *p;

	TALLOC_FREE(p);

	DEBUG(0,("Got sig[%d] terminate (is_parent=%d)\n",
		 signum, is_parent));
	terminate(is_parent);
}

/*
  handle stdin becoming readable when we are in --foreground mode
 */
static void winbindd_stdin_handler(struct tevent_context *ev,
			       struct tevent_fd *fde,
			       uint16_t flags,
			       void *private_data)
{
	char c;
	if (read(0, &c, 1) != 1) {
		bool *is_parent = talloc_get_type_abort(private_data, bool);

		/* we have reached EOF on stdin, which means the
		   parent has exited. Shutdown the server */
		DEBUG(0,("EOF on stdin (is_parent=%d)\n",
			 (int)*is_parent));
		terminate(*is_parent);
	}
}

bool winbindd_setup_sig_term_handler(bool parent)
{
	struct tevent_signal *se;
	bool *is_parent;

	is_parent = talloc(global_event_context(), bool);
	if (!is_parent) {
		return false;
	}

	*is_parent = parent;

	se = tevent_add_signal(global_event_context(),
			       is_parent,
			       SIGTERM, 0,
			       winbindd_sig_term_handler,
			       is_parent);
	if (!se) {
		DEBUG(0,("failed to setup SIGTERM handler"));
		talloc_free(is_parent);
		return false;
	}

	se = tevent_add_signal(global_event_context(),
			       is_parent,
			       SIGINT, 0,
			       winbindd_sig_term_handler,
			       is_parent);
	if (!se) {
		DEBUG(0,("failed to setup SIGINT handler"));
		talloc_free(is_parent);
		return false;
	}

	se = tevent_add_signal(global_event_context(),
			       is_parent,
			       SIGQUIT, 0,
			       winbindd_sig_term_handler,
			       is_parent);
	if (!se) {
		DEBUG(0,("failed to setup SIGINT handler"));
		talloc_free(is_parent);
		return false;
	}

	return true;
}

bool winbindd_setup_stdin_handler(bool parent, bool foreground)
{
	bool *is_parent;

	if (foreground) {
		struct stat st;

		is_parent = talloc(global_event_context(), bool);
		if (!is_parent) {
			return false;
		}

		*is_parent = parent;

		/* if we are running in the foreground then look for
		   EOF on stdin, and exit if it happens. This allows
		   us to die if the parent process dies
		   Only do this on a pipe or socket, no other device.
		*/
		if (fstat(0, &st) != 0) {
			return false;
		}
		if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
			tevent_add_fd(global_event_context(),
					is_parent,
					0,
					TEVENT_FD_READ,
					winbindd_stdin_handler,
					is_parent);
		}
	}

	return true;
}

static void winbindd_sig_hup_handler(struct tevent_context *ev,
				     struct tevent_signal *se,
				     int signum,
				     int count,
				     void *siginfo,
				     void *private_data)
{
	const char *file = (const char *)private_data;

	DEBUG(1,("Reloading services after SIGHUP\n"));
	flush_caches_noinit();
	winbindd_reload_services_file(file);
}

bool winbindd_setup_sig_hup_handler(const char *lfile)
{
	struct tevent_signal *se;
	char *file = NULL;

	if (lfile) {
		file = talloc_strdup(global_event_context(),
				     lfile);
		if (!file) {
			return false;
		}
	}

	se = tevent_add_signal(global_event_context(),
			       global_event_context(),
			       SIGHUP, 0,
			       winbindd_sig_hup_handler,
			       file);
	if (!se) {
		return false;
	}

	return true;
}

static void winbindd_sig_chld_handler(struct tevent_context *ev,
				      struct tevent_signal *se,
				      int signum,
				      int count,
				      void *siginfo,
				      void *private_data)
{
	pid_t pid;

	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
		winbind_child_died(pid);
	}
}

static bool winbindd_setup_sig_chld_handler(void)
{
	struct tevent_signal *se;

	se = tevent_add_signal(global_event_context(),
			       global_event_context(),
			       SIGCHLD, 0,
			       winbindd_sig_chld_handler,
			       NULL);
	if (!se) {
		return false;
	}

	return true;
}

static void winbindd_sig_usr2_handler(struct tevent_context *ev,
				      struct tevent_signal *se,
				      int signum,
				      int count,
				      void *siginfo,
				      void *private_data)
{
	winbindd_status();
}

static bool winbindd_setup_sig_usr2_handler(void)
{
	struct tevent_signal *se;

	se = tevent_add_signal(global_event_context(),
			       global_event_context(),
			       SIGUSR2, 0,
			       winbindd_sig_usr2_handler,
			       NULL);
	if (!se) {
		return false;
	}

	return true;
}

/* React on 'smbcontrol winbindd shutdown' in the same way as on SIGTERM*/
static void msg_shutdown(struct messaging_context *msg,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id server_id,
			 DATA_BLOB *data)
{
	/* only the parent waits for this message */
	DEBUG(0,("Got shutdown message\n"));
	terminate(true);
}


static void winbind_msg_validate_cache(struct messaging_context *msg_ctx,
				       void *private_data,
				       uint32_t msg_type,
				       struct server_id server_id,
				       DATA_BLOB *data)
{
	uint8_t ret;
	pid_t child_pid;
	NTSTATUS status;

	DEBUG(10, ("winbindd_msg_validate_cache: got validate-cache "
		   "message.\n"));

	/*
	 * call the validation code from a child:
	 * so we don't block the main winbindd and the validation
	 * code can safely use fork/waitpid...
	 */
	child_pid = fork();

	if (child_pid == -1) {
		DEBUG(1, ("winbind_msg_validate_cache: Could not fork: %s\n",
			  strerror(errno)));
		return;
	}

	if (child_pid != 0) {
		/* parent */
		DEBUG(5, ("winbind_msg_validate_cache: child created with "
			  "pid %d.\n", (int)child_pid));
		return;
	}

	/* child */

	status = winbindd_reinit_after_fork(NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("winbindd_reinit_after_fork failed: %s\n",
			  nt_errstr(status)));
		_exit(0);
	}

	/* install default SIGCHLD handler: validation code uses fork/waitpid */
	CatchSignal(SIGCHLD, SIG_DFL);

	setproctitle("validate cache child");

	ret = (uint8_t)winbindd_validate_cache_nobackup();
	DEBUG(10, ("winbindd_msg_validata_cache: got return value %d\n", ret));
	messaging_send_buf(msg_ctx, server_id, MSG_WINBIND_VALIDATE_CACHE, &ret,
			   (size_t)1);
	_exit(0);
}

static struct winbindd_bool_dispatch_table {
	enum winbindd_cmd cmd;
	bool (*fn)(struct winbindd_cli_state *state);
	const char *cmd_name;
} bool_dispatch_table[] = {
	{ WINBINDD_INTERFACE_VERSION,
	  winbindd_interface_version,
	  "INTERFACE_VERSION" },
	{ WINBINDD_INFO,
	  winbindd_info,
	  "INFO" },
	{ WINBINDD_PING,
	  winbindd_ping,
	  "PING" },
	{ WINBINDD_DOMAIN_NAME,
	  winbindd_domain_name,
	  "DOMAIN_NAME" },
	{ WINBINDD_NETBIOS_NAME,
	  winbindd_netbios_name,
	  "NETBIOS_NAME" },
	{ WINBINDD_DC_INFO,
	  winbindd_dc_info,
	  "DC_INFO" },
	{ WINBINDD_CCACHE_NTLMAUTH,
	  winbindd_ccache_ntlm_auth,
	  "NTLMAUTH" },
	{ WINBINDD_CCACHE_SAVE,
	  winbindd_ccache_save,
	  "CCACHE_SAVE" },
	{ WINBINDD_PRIV_PIPE_DIR,
	  winbindd_priv_pipe_dir,
	  "WINBINDD_PRIV_PIPE_DIR" },
	{ WINBINDD_LIST_TRUSTDOM,
	  winbindd_list_trusted_domains,
	  "LIST_TRUSTDOM" },
};

struct winbindd_async_dispatch_table {
	enum winbindd_cmd cmd;
	const char *cmd_name;
	struct tevent_req *(*send_req)(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct winbindd_cli_state *cli,
				       struct winbindd_request *request);
	NTSTATUS (*recv_req)(struct tevent_req *req,
			     struct winbindd_response *presp);
};

static struct winbindd_async_dispatch_table async_nonpriv_table[] = {
	{ WINBINDD_LOOKUPSID, "LOOKUPSID",
	  winbindd_lookupsid_send, winbindd_lookupsid_recv },
	{ WINBINDD_LOOKUPSIDS, "LOOKUPSIDS",
	  winbindd_lookupsids_send, winbindd_lookupsids_recv },
	{ WINBINDD_LOOKUPNAME, "LOOKUPNAME",
	  winbindd_lookupname_send, winbindd_lookupname_recv },
	{ WINBINDD_SIDS_TO_XIDS, "SIDS_TO_XIDS",
	  winbindd_sids_to_xids_send, winbindd_sids_to_xids_recv },
	{ WINBINDD_XIDS_TO_SIDS, "XIDS_TO_SIDS",
	  winbindd_xids_to_sids_send, winbindd_xids_to_sids_recv },
	{ WINBINDD_GETPWSID, "GETPWSID",
	  winbindd_getpwsid_send, winbindd_getpwsid_recv },
	{ WINBINDD_GETPWNAM, "GETPWNAM",
	  winbindd_getpwnam_send, winbindd_getpwnam_recv },
	{ WINBINDD_GETPWUID, "GETPWUID",
	  winbindd_getpwuid_send, winbindd_getpwuid_recv },
	{ WINBINDD_GETSIDALIASES, "GETSIDALIASES",
	  winbindd_getsidaliases_send, winbindd_getsidaliases_recv },
	{ WINBINDD_GETUSERDOMGROUPS, "GETUSERDOMGROUPS",
	  winbindd_getuserdomgroups_send, winbindd_getuserdomgroups_recv },
	{ WINBINDD_GETGROUPS, "GETGROUPS",
	  winbindd_getgroups_send, winbindd_getgroups_recv },
	{ WINBINDD_SHOW_SEQUENCE, "SHOW_SEQUENCE",
	  winbindd_show_sequence_send, winbindd_show_sequence_recv },
	{ WINBINDD_GETGRGID, "GETGRGID",
	  winbindd_getgrgid_send, winbindd_getgrgid_recv },
	{ WINBINDD_GETGRNAM, "GETGRNAM",
	  winbindd_getgrnam_send, winbindd_getgrnam_recv },
	{ WINBINDD_GETUSERSIDS, "GETUSERSIDS",
	  winbindd_getusersids_send, winbindd_getusersids_recv },
	{ WINBINDD_LOOKUPRIDS, "LOOKUPRIDS",
	  winbindd_lookuprids_send, winbindd_lookuprids_recv },
	{ WINBINDD_SETPWENT, "SETPWENT",
	  winbindd_setpwent_send, winbindd_setpwent_recv },
	{ WINBINDD_GETPWENT, "GETPWENT",
	  winbindd_getpwent_send, winbindd_getpwent_recv },
	{ WINBINDD_ENDPWENT, "ENDPWENT",
	  winbindd_endpwent_send, winbindd_endpwent_recv },
	{ WINBINDD_DSGETDCNAME, "DSGETDCNAME",
	  winbindd_dsgetdcname_send, winbindd_dsgetdcname_recv },
	{ WINBINDD_GETDCNAME, "GETDCNAME",
	  winbindd_getdcname_send, winbindd_getdcname_recv },
	{ WINBINDD_SETGRENT, "SETGRENT",
	  winbindd_setgrent_send, winbindd_setgrent_recv },
	{ WINBINDD_GETGRENT, "GETGRENT",
	  winbindd_getgrent_send, winbindd_getgrent_recv },
	{ WINBINDD_ENDGRENT, "ENDGRENT",
	  winbindd_endgrent_send, winbindd_endgrent_recv },
	{ WINBINDD_LIST_USERS, "LIST_USERS",
	  winbindd_list_users_send, winbindd_list_users_recv },
	{ WINBINDD_LIST_GROUPS, "LIST_GROUPS",
	  winbindd_list_groups_send, winbindd_list_groups_recv },
	{ WINBINDD_CHECK_MACHACC, "CHECK_MACHACC",
	  winbindd_check_machine_acct_send, winbindd_check_machine_acct_recv },
	{ WINBINDD_PING_DC, "PING_DC",
	  winbindd_ping_dc_send, winbindd_ping_dc_recv },
	{ WINBINDD_PAM_AUTH, "PAM_AUTH",
	  winbindd_pam_auth_send, winbindd_pam_auth_recv },
	{ WINBINDD_PAM_LOGOFF, "PAM_LOGOFF",
	  winbindd_pam_logoff_send, winbindd_pam_logoff_recv },
	{ WINBINDD_PAM_CHAUTHTOK, "PAM_CHAUTHTOK",
	  winbindd_pam_chauthtok_send, winbindd_pam_chauthtok_recv },
	{ WINBINDD_PAM_CHNG_PSWD_AUTH_CRAP, "PAM_CHNG_PSWD_AUTH_CRAP",
	  winbindd_pam_chng_pswd_auth_crap_send,
	  winbindd_pam_chng_pswd_auth_crap_recv },
	{ WINBINDD_WINS_BYIP, "WINS_BYIP",
	  winbindd_wins_byip_send, winbindd_wins_byip_recv },
	{ WINBINDD_WINS_BYNAME, "WINS_BYNAME",
	  winbindd_wins_byname_send, winbindd_wins_byname_recv },
	{ WINBINDD_DOMAIN_INFO, "DOMAIN_INFO",
	  winbindd_domain_info_send, winbindd_domain_info_recv },

	{ 0, NULL, NULL, NULL }
};

static struct winbindd_async_dispatch_table async_priv_table[] = {
	{ WINBINDD_ALLOCATE_UID, "ALLOCATE_UID",
	  winbindd_allocate_uid_send, winbindd_allocate_uid_recv },
	{ WINBINDD_ALLOCATE_GID, "ALLOCATE_GID",
	  winbindd_allocate_gid_send, winbindd_allocate_gid_recv },
	{ WINBINDD_CHANGE_MACHACC, "CHANGE_MACHACC",
	  winbindd_change_machine_acct_send, winbindd_change_machine_acct_recv },
	{ WINBINDD_PAM_AUTH_CRAP, "PAM_AUTH_CRAP",
	  winbindd_pam_auth_crap_send, winbindd_pam_auth_crap_recv },

	{ 0, NULL, NULL, NULL }
};

struct process_request_state {
	struct winbindd_cli_state *cli_state;
	struct tevent_context *ev;
};

static void process_request_done(struct tevent_req *subreq);
static void process_request_written(struct tevent_req *subreq);

static struct tevent_req *process_request_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli_state)
{
	struct tevent_req *req, *subreq;
	struct process_request_state *state;
	struct winbindd_async_dispatch_table *atable;
	enum winbindd_cmd cmd = cli_state->request->cmd;
	size_t i;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct process_request_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli_state = cli_state;
	state->ev = ev;

	ok = tevent_req_set_profile(req);
	if (!ok) {
		return tevent_req_post(req, ev);
	}

	SMB_ASSERT(cli_state->mem_ctx == NULL);
	cli_state->mem_ctx = talloc_named(cli_state, 0, "winbind request");
	if (tevent_req_nomem(cli_state->mem_ctx, req)) {
		return tevent_req_post(req, ev);
	}

	cli_state->response = talloc_zero(
		cli_state->mem_ctx,
		struct winbindd_response);
	if (tevent_req_nomem(cli_state->response, req)) {
		return tevent_req_post(req, ev);
	}
	cli_state->response->result = WINBINDD_PENDING;
	cli_state->response->length = sizeof(struct winbindd_response);

	/* Remember who asked us. */
	cli_state->pid = cli_state->request->pid;
	memcpy(cli_state->client_name,
	       cli_state->request->client_name,
	       sizeof(cli_state->client_name));

	cli_state->cmd_name = "unknown request";
	cli_state->recv_fn = NULL;

	/* client is newest */
	winbindd_promote_client(cli_state);

	for (atable = async_nonpriv_table; atable->send_req; atable += 1) {
		if (cmd == atable->cmd) {
			break;
		}
	}

	if ((atable->send_req == NULL) && cli_state->privileged) {
		for (atable = async_priv_table; atable->send_req;
		     atable += 1) {
			if (cmd == atable->cmd) {
				break;
			}
		}
	}

	if (atable->send_req != NULL) {
		cli_state->cmd_name = atable->cmd_name;
		cli_state->recv_fn = atable->recv_req;

		DBG_DEBUG("process_request: "
			  "Handling async request %s(%d):%s\n",
			  cli_state->client_name,
			  (int)cli_state->pid,
			  cli_state->cmd_name);

		subreq = atable->send_req(
			state,
			state->ev,
			cli_state,
			cli_state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, process_request_done, req);
		return req;
	}

	for (i=0; i<ARRAY_SIZE(bool_dispatch_table); i++) {
		if (cmd == bool_dispatch_table[i].cmd) {
			break;
		}
	}

	ok = false;

	if (i < ARRAY_SIZE(bool_dispatch_table)) {
		cli_state->cmd_name = bool_dispatch_table[i].cmd_name;

		DBG_DEBUG("process_request: request fn %s\n",
			  bool_dispatch_table[i].cmd_name);
		ok = bool_dispatch_table[i].fn(cli_state);
	}

	cli_state->response->result = ok ? WINBINDD_OK : WINBINDD_ERROR;

	TALLOC_FREE(cli_state->io_req);
	TALLOC_FREE(cli_state->request);

	subreq = wb_resp_write_send(
		state,
		state->ev,
		cli_state->out_queue,
		cli_state->sock,
		cli_state->response);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, process_request_written, req);

	cli_state->io_req = subreq;

	return req;
}

static void process_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct process_request_state *state = tevent_req_data(
		req, struct process_request_state);
	struct winbindd_cli_state *cli_state = state->cli_state;
	NTSTATUS status;
	bool ok;

	status = cli_state->recv_fn(subreq, cli_state->response);
	TALLOC_FREE(subreq);

	DBG_DEBUG("[%s(%d):%s]: %s\n",
		  cli_state->client_name,
		  (int)cli_state->pid,
		  cli_state->cmd_name,
		  nt_errstr(status));

	ok = NT_STATUS_IS_OK(status);
	cli_state->response->result = ok ? WINBINDD_OK : WINBINDD_ERROR;

	TALLOC_FREE(cli_state->io_req);
	TALLOC_FREE(cli_state->request);

	subreq = wb_resp_write_send(
		state,
		state->ev,
		cli_state->out_queue,
		cli_state->sock,
		cli_state->response);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, process_request_written, req);

	cli_state->io_req = subreq;
}

static void process_request_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct process_request_state *state = tevent_req_data(
		req, struct process_request_state);
	struct winbindd_cli_state *cli_state = state->cli_state;
	ssize_t ret;
	int err;

	cli_state->io_req = NULL;

	ret = wb_resp_write_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	DBG_DEBUG("[%s(%d):%s]: delivered response to client\n",
		  cli_state->client_name,
		  (int)cli_state->pid,
		  cli_state->cmd_name);

	TALLOC_FREE(cli_state->mem_ctx);
	cli_state->response = NULL;
	cli_state->cmd_name = "no request";
	cli_state->recv_fn = NULL;

	tevent_req_done(req);
}

static NTSTATUS process_request_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct tevent_req_profile **profile)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*profile = tevent_req_move_profile(req, mem_ctx);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*
 * This is the main event loop of winbind requests. It goes through a
 * state-machine of 3 read/write requests, 4 if you have extra data to send.
 *
 * An idle winbind client has a read request of 4 bytes outstanding,
 * finalizing function is request_len_recv, checking the length. request_recv
 * then processes the packet. The processing function then at some point has
 * to call request_finished which schedules sending the response.
 */

static void winbind_client_request_read(struct tevent_req *req);
static void winbind_client_activity(struct tevent_req *req);
static void winbind_client_processed(struct tevent_req *req);

/* Process a new connection by adding it to the client connection list */

static void new_connection(int listen_sock, bool privileged)
{
	struct sockaddr_un sunaddr;
	struct winbindd_cli_state *state;
	struct tevent_req *req;
	socklen_t len;
	int sock;

	/* Accept connection */

	len = sizeof(sunaddr);

	sock = accept(listen_sock, (struct sockaddr *)(void *)&sunaddr, &len);

	if (sock == -1) {
		if (errno != EINTR) {
			DEBUG(0, ("Failed to accept socket - %s\n",
				  strerror(errno)));
		}
		return;
	}
	smb_set_close_on_exec(sock);

	DEBUG(6,("accepted socket %d\n", sock));

	/* Create new connection structure */

	if ((state = talloc_zero(NULL, struct winbindd_cli_state)) == NULL) {
		close(sock);
		return;
	}

	state->sock = sock;

	state->out_queue = tevent_queue_create(state, "winbind client reply");
	if (state->out_queue == NULL) {
		close(sock);
		TALLOC_FREE(state);
		return;
	}

	state->privileged = privileged;

	req = wb_req_read_send(state, global_event_context(), state->sock,
			       WINBINDD_MAX_EXTRA_DATA);
	if (req == NULL) {
		TALLOC_FREE(state);
		close(sock);
		return;
	}
	tevent_req_set_callback(req, winbind_client_request_read, state);
	state->io_req = req;

	/* Add to connection list */

	winbindd_add_client(state);
}

static void winbind_client_request_read(struct tevent_req *req)
{
	struct winbindd_cli_state *state = tevent_req_callback_data(
		req, struct winbindd_cli_state);
	ssize_t ret;
	int err;

	state->io_req = NULL;

	ret = wb_req_read_recv(req, state, &state->request, &err);
	TALLOC_FREE(req);
	if (ret == -1) {
		if (err == EPIPE) {
			DEBUG(6, ("closing socket %d, client exited\n",
				  state->sock));
		} else {
			DEBUG(2, ("Could not read client request from fd %d: "
				  "%s\n", state->sock, strerror(err)));
		}
		close(state->sock);
		state->sock = -1;
		remove_client(state);
		return;
	}

	req = wait_for_read_send(state, global_event_context(), state->sock,
				 true);
	if (req == NULL) {
		DEBUG(0, ("winbind_client_request_read[%d:%s]:"
			  " wait_for_read_send failed - removing client\n",
			  (int)state->pid, state->cmd_name));
		remove_client(state);
		return;
	}
	tevent_req_set_callback(req, winbind_client_activity, state);
	state->io_req = req;

	req = process_request_send(state, global_event_context(), state);
	if (req == NULL) {
		DBG_ERR("process_request_send failed\n");
		remove_client(state);
		return;
	}
	tevent_req_set_callback(req, winbind_client_processed, state);
}

static void winbind_client_activity(struct tevent_req *req)
{
	struct winbindd_cli_state *state =
	    tevent_req_callback_data(req, struct winbindd_cli_state);
	int err;
	bool has_data;

	has_data = wait_for_read_recv(req, &err);

	if (has_data) {
		DEBUG(0, ("winbind_client_activity[%d:%s]:"
			  "unexpected data from client - removing client\n",
			  (int)state->pid, state->cmd_name));
	} else {
		if (err == EPIPE) {
			DEBUG(6, ("winbind_client_activity[%d:%s]: "
				  "client has closed connection - removing "
				  "client\n",
				  (int)state->pid, state->cmd_name));
		} else {
			DEBUG(2, ("winbind_client_activity[%d:%s]: "
				  "client socket error (%s) - removing "
				  "client\n",
				  (int)state->pid, state->cmd_name,
				  strerror(err)));
		}
	}

	remove_client(state);
}

static void winbind_client_processed(struct tevent_req *req)
{
	struct winbindd_cli_state *cli_state = tevent_req_callback_data(
		req, struct winbindd_cli_state);
	struct tevent_req_profile *profile = NULL;
	struct timeval start, stop, diff;
	int threshold;
	NTSTATUS status;

	status = process_request_recv(req, cli_state, &profile);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("process_request failed: %s\n", nt_errstr(status));
		remove_client(cli_state);
		return;
	}

	tevent_req_profile_get_start(profile, NULL, &start);
	tevent_req_profile_get_stop(profile, NULL, &stop);
	diff = tevent_timeval_until(&start, &stop);

	threshold = lp_parm_int(-1, "winbind", "request profile threshold", 60);

	if (diff.tv_sec >= threshold) {
		int depth;
		char *str;

		depth = lp_parm_int(
			-1,
			"winbind",
			"request profile depth",
			INT_MAX);

		DBG_ERR("request took %u.%.6u seconds\n",
			(unsigned)diff.tv_sec, (unsigned)diff.tv_usec);

		str = tevent_req_profile_string(
			talloc_tos(), profile, 0, depth);
		if (str != NULL) {
			/* No "\n", already contained in "str" */
			DEBUGADD(0, ("%s", str));
		}
		TALLOC_FREE(str);
	}

	TALLOC_FREE(profile);

	req = wb_req_read_send(
		cli_state,
		global_event_context(),
		cli_state->sock,
		WINBINDD_MAX_EXTRA_DATA);
	if (req == NULL) {
		remove_client(cli_state);
		return;
	}
	tevent_req_set_callback(req, winbind_client_request_read, cli_state);
	cli_state->io_req = req;
}

/* Remove a client connection from client connection list */

static void remove_client(struct winbindd_cli_state *state)
{
	/* It's a dead client - hold a funeral */

	if (state == NULL) {
		return;
	}

	/*
	 * We need to remove a pending wb_req_read_*
	 * or wb_resp_write_* request before closing the
	 * socket.
	 *
	 * This is important as they might have used tevent_add_fd() and we
	 * use the epoll * backend on linux. So we must remove the tevent_fd
	 * before closing the fd.
	 *
	 * Otherwise we might hit a race with close_conns_after_fork() (via
	 * winbindd_reinit_after_fork()) where a file descriptor
	 * is still open in a child, which means it's still active in
	 * the parents epoll queue, but the related tevent_fd is already
	 * already gone in the parent.
	 *
	 * See bug #11141.
	 */
	TALLOC_FREE(state->io_req);

	if (state->sock != -1) {
		char c = 0;
		int nwritten;

		/* tell client, we are closing ... */
		nwritten = write(state->sock, &c, sizeof(c));
		if (nwritten == -1) {
			DEBUG(2, ("final write to client failed: %s\n",
				strerror(errno)));
		}

		/* Close socket */

		close(state->sock);
		state->sock = -1;
	}

	TALLOC_FREE(state->mem_ctx);

	/* Remove from list and free */

	winbindd_remove_client(state);
	TALLOC_FREE(state);
}

/* Is a client idle? */

static bool client_is_idle(struct winbindd_cli_state *state) {
  return (state->request == NULL &&
	  state->response == NULL &&
	  !state->pwent_state && !state->grent_state);
}

/* Shutdown client connection which has been idle for the longest time */

static bool remove_idle_client(void)
{
	struct winbindd_cli_state *state, *remove_state = NULL;
	int nidle = 0;

	for (state = winbindd_client_list(); state; state = state->next) {
		if (client_is_idle(state)) {
			nidle++;
			/* list is sorted by access time */
			remove_state = state;
		}
	}

	if (remove_state) {
		DEBUG(5,("Found %d idle client connections, shutting down sock %d, pid %u\n",
			nidle, remove_state->sock, (unsigned int)remove_state->pid));
		remove_client(remove_state);
		return True;
	}

	return False;
}

/*
 * Terminate all clients whose requests have taken longer than
 * "winbind request timeout" seconds to process, or have been
 * idle for more than "winbind request timeout" seconds.
 */

static void remove_timed_out_clients(void)
{
	struct winbindd_cli_state *state, *prev = NULL;
	time_t curr_time = time(NULL);
	int timeout_val = lp_winbind_request_timeout();

	for (state = winbindd_client_list_tail(); state; state = prev) {
		time_t expiry_time;

		prev = winbindd_client_list_prev(state);
		expiry_time = state->last_access + timeout_val;

		if (curr_time <= expiry_time) {
			/* list is sorted, previous clients in
			   list are newer */
			break;
		}

		if (client_is_idle(state)) {
			DEBUG(5,("Idle client timed out, "
				 "shutting down sock %d, pid %u\n",
				 state->sock,
				 (unsigned int)state->pid));
		} else {
			DEBUG(5,("Client request timed out, "
				 "shutting down sock %d, pid %u\n",
				 state->sock,
				 (unsigned int)state->pid));
		}

		remove_client(state);
	}
}

static void winbindd_scrub_clients_handler(struct tevent_context *ev,
					   struct tevent_timer *te,
					   struct timeval current_time,
					   void *private_data)
{
	remove_timed_out_clients();
	if (tevent_add_timer(ev, ev,
			     timeval_current_ofs(SCRUB_CLIENTS_INTERVAL, 0),
			     winbindd_scrub_clients_handler, NULL) == NULL) {
		DEBUG(0, ("winbindd: failed to reschedule client scrubber\n"));
		exit(1);
	}
}

struct winbindd_listen_state {
	bool privileged;
	int fd;
};

static void winbindd_listen_fde_handler(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct winbindd_listen_state *s = talloc_get_type_abort(private_data,
					  struct winbindd_listen_state);

	while (winbindd_num_clients() > lp_winbind_max_clients() - 1) {
		DEBUG(5,("winbindd: Exceeding %d client "
			 "connections, removing idle "
			 "connection.\n", lp_winbind_max_clients()));
		if (!remove_idle_client()) {
			DEBUG(0,("winbindd: Exceeding %d "
				 "client connections, no idle "
				 "connection found\n",
				 lp_winbind_max_clients()));
			break;
		}
	}
	remove_timed_out_clients();
	new_connection(s->fd, s->privileged);
}

/*
 * Winbindd socket accessor functions
 */

char *get_winbind_priv_pipe_dir(void)
{
	return state_path(talloc_tos(), WINBINDD_PRIV_SOCKET_SUBDIR);
}

static void winbindd_setup_max_fds(void)
{
	int num_fds = MAX_OPEN_FUDGEFACTOR;
	int actual_fds;

	num_fds += lp_winbind_max_clients();
	/* Add some more to account for 2 sockets open
	   when the client transitions from unprivileged
	   to privileged socket
	*/
	num_fds += lp_winbind_max_clients() / 10;

	/* Add one socket per child process
	   (yeah there are child processes other than the
	   domain children but only domain children can vary
	   with configuration
	*/
	num_fds += lp_winbind_max_domain_connections() *
		   (lp_allow_trusted_domains() ? WINBIND_MAX_DOMAINS_HINT : 1);

	actual_fds = set_maxfiles(num_fds);

	if (actual_fds < num_fds) {
		DEBUG(1, ("winbindd_setup_max_fds: Information only: "
			  "requested %d open files, %d are available.\n",
			  num_fds, actual_fds));
	}
}

static bool winbindd_setup_listeners(void)
{
	struct winbindd_listen_state *pub_state = NULL;
	struct winbindd_listen_state *priv_state = NULL;
	struct tevent_fd *fde;
	int rc;
	char *socket_path;

	pub_state = talloc(global_event_context(),
			   struct winbindd_listen_state);
	if (!pub_state) {
		goto failed;
	}

	pub_state->privileged = false;
	pub_state->fd = create_pipe_sock(
		lp_winbindd_socket_directory(), WINBINDD_SOCKET_NAME, 0755);
	if (pub_state->fd == -1) {
		goto failed;
	}
	rc = listen(pub_state->fd, 5);
	if (rc < 0) {
		goto failed;
	}

	fde = tevent_add_fd(global_event_context(), pub_state, pub_state->fd,
			    TEVENT_FD_READ, winbindd_listen_fde_handler,
			    pub_state);
	if (fde == NULL) {
		close(pub_state->fd);
		goto failed;
	}
	tevent_fd_set_auto_close(fde);

	priv_state = talloc(global_event_context(),
			    struct winbindd_listen_state);
	if (!priv_state) {
		goto failed;
	}

	socket_path = get_winbind_priv_pipe_dir();
	if (socket_path == NULL) {
		goto failed;
	}

	priv_state->privileged = true;
	priv_state->fd = create_pipe_sock(
		socket_path, WINBINDD_SOCKET_NAME, 0750);
	TALLOC_FREE(socket_path);
	if (priv_state->fd == -1) {
		goto failed;
	}
	rc = listen(priv_state->fd, 5);
	if (rc < 0) {
		goto failed;
	}

	fde = tevent_add_fd(global_event_context(), priv_state,
			    priv_state->fd, TEVENT_FD_READ,
			    winbindd_listen_fde_handler, priv_state);
	if (fde == NULL) {
		close(priv_state->fd);
		goto failed;
	}
	tevent_fd_set_auto_close(fde);

	winbindd_scrub_clients_handler(global_event_context(), NULL,
				       timeval_current(), NULL);
	return true;
failed:
	TALLOC_FREE(pub_state);
	TALLOC_FREE(priv_state);
	return false;
}

bool winbindd_use_idmap_cache(void)
{
	return !opt_nocache;
}

bool winbindd_use_cache(void)
{
	return !opt_nocache;
}

static void winbindd_register_handlers(struct messaging_context *msg_ctx,
				       bool foreground)
{
	bool scan_trusts = true;
	NTSTATUS status;
	/* Setup signal handlers */

	if (!winbindd_setup_sig_term_handler(true))
		exit(1);
	if (!winbindd_setup_stdin_handler(true, foreground))
		exit(1);
	if (!winbindd_setup_sig_hup_handler(NULL))
		exit(1);
	if (!winbindd_setup_sig_chld_handler())
		exit(1);
	if (!winbindd_setup_sig_usr2_handler())
		exit(1);

	CatchSignal(SIGPIPE, SIG_IGN);                 /* Ignore sigpipe */

	/*
	 * Ensure all cache and idmap caches are consistent
	 * and initialized before we startup.
	 */
	if (!winbindd_cache_validate_and_initialize()) {
		exit(1);
	}

	/* React on 'smbcontrol winbindd reload-config' in the same way
	   as to SIGHUP signal */
	messaging_register(msg_ctx, NULL,
			   MSG_SMB_CONF_UPDATED,
			   winbindd_msg_reload_services_parent);
	messaging_register(msg_ctx, NULL,
			   MSG_SHUTDOWN, msg_shutdown);

	/* Handle online/offline messages. */
	messaging_register(msg_ctx, NULL,
			   MSG_WINBIND_OFFLINE, winbind_msg_offline);
	messaging_register(msg_ctx, NULL,
			   MSG_WINBIND_ONLINE, winbind_msg_online);
	messaging_register(msg_ctx, NULL,
			   MSG_WINBIND_ONLINESTATUS, winbind_msg_onlinestatus);

	/* Handle domain online/offline messages for domains */
	messaging_register(global_messaging_context(), NULL,
			   MSG_WINBIND_DOMAIN_OFFLINE, winbind_msg_domain_offline);
	messaging_register(global_messaging_context(), NULL,
			   MSG_WINBIND_DOMAIN_ONLINE, winbind_msg_domain_online);

	messaging_register(msg_ctx, NULL,
			   MSG_WINBIND_VALIDATE_CACHE,
			   winbind_msg_validate_cache);

	messaging_register(msg_ctx, NULL,
			   MSG_WINBIND_DUMP_DOMAIN_LIST,
			   winbind_msg_dump_domain_list);

	messaging_register(msg_ctx, NULL,
			   MSG_WINBIND_IP_DROPPED,
			   winbind_msg_ip_dropped_parent);

	/* Register handler for MSG_DEBUG. */
	messaging_register(msg_ctx, NULL,
			   MSG_DEBUG,
			   winbind_msg_debug);

	messaging_register(msg_ctx, NULL,
			   MSG_WINBIND_DISCONNECT_DC,
			   winbind_disconnect_dc_parent);

	netsamlogon_cache_init(); /* Non-critical */

	/* clear the cached list of trusted domains */

	wcache_tdc_clear();

	if (!init_domain_list()) {
		DEBUG(0,("unable to initialize domain list\n"));
		exit(1);
	}

	init_idmap_child();
	init_locator_child();

	smb_nscd_flush_user_cache();
	smb_nscd_flush_group_cache();

	if (!lp_winbind_scan_trusted_domains()) {
		scan_trusts = false;
	}

	if (!lp_allow_trusted_domains()) {
		scan_trusts = false;
	}

	if (IS_DC) {
		scan_trusts = false;
	}

	if (scan_trusts) {
		if (tevent_add_timer(global_event_context(), NULL, timeval_zero(),
			      rescan_trusted_domains, NULL) == NULL) {
			DEBUG(0, ("Could not trigger rescan_trusted_domains()\n"));
			exit(1);
		}
	}

	status = wb_irpc_register();

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Could not register IRPC handlers\n"));
		exit(1);
	}
}

struct winbindd_addrchanged_state {
	struct addrchange_context *ctx;
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
};

static void winbindd_addr_changed(struct tevent_req *req);

static void winbindd_init_addrchange(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct messaging_context *msg_ctx)
{
	struct winbindd_addrchanged_state *state;
	struct tevent_req *req;
	NTSTATUS status;

	state = talloc(mem_ctx, struct winbindd_addrchanged_state);
	if (state == NULL) {
		DEBUG(10, ("talloc failed\n"));
		return;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;

	status = addrchange_context_create(state, &state->ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("addrchange_context_create failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(state);
		return;
	}
	req = addrchange_send(state, ev, state->ctx);
	if (req == NULL) {
		DEBUG(0, ("addrchange_send failed\n"));
		TALLOC_FREE(state);
		return;
	}
	tevent_req_set_callback(req, winbindd_addr_changed, state);
}

static void winbindd_addr_changed(struct tevent_req *req)
{
	struct winbindd_addrchanged_state *state = tevent_req_callback_data(
		req, struct winbindd_addrchanged_state);
	enum addrchange_type type;
	struct sockaddr_storage addr;
	NTSTATUS status;

	status = addrchange_recv(req, &type, &addr);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("addrchange_recv failed: %s, stop listening\n",
			   nt_errstr(status)));
		TALLOC_FREE(state);
		return;
	}
	if (type == ADDRCHANGE_DEL) {
		char addrstr[INET6_ADDRSTRLEN];
		DATA_BLOB blob;

		print_sockaddr(addrstr, sizeof(addrstr), &addr);

		DEBUG(3, ("winbindd: kernel (AF_NETLINK) dropped ip %s\n",
			  addrstr));

		blob = data_blob_const(addrstr, strlen(addrstr)+1);

		status = messaging_send(state->msg_ctx,
					messaging_server_id(state->msg_ctx),
					MSG_WINBIND_IP_DROPPED, &blob);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("messaging_send failed: %s - ignoring\n",
				   nt_errstr(status)));
		}
	}
	req = addrchange_send(state, state->ev, state->ctx);
	if (req == NULL) {
		DEBUG(0, ("addrchange_send failed\n"));
		TALLOC_FREE(state);
		return;
	}
	tevent_req_set_callback(req, winbindd_addr_changed, state);
}

/* Main function */

int main(int argc, const char **argv)
{
	static bool is_daemon = False;
	static bool Fork = True;
	static bool log_stdout = False;
	static bool no_process_group = False;
	enum {
		OPT_DAEMON = 1000,
		OPT_FORK,
		OPT_NO_PROCESS_GROUP,
		OPT_LOG_STDOUT
	};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "stdout",
			.shortName  = 'S',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_LOG_STDOUT,
			.descrip    = "Log to stdout",
		},
		{
			.longName   = "foreground",
			.shortName  = 'F',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_FORK,
			.descrip    = "Daemon in foreground mode",
		},
		{
			.longName   = "no-process-group",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_NO_PROCESS_GROUP,
			.descrip    = "Don't create a new process group",
		},
		{
			.longName   = "daemon",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_DAEMON,
			.descrip    = "Become a daemon (default)",
		},
		{
			.longName   = "interactive",
			.shortName  = 'i',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'i',
			.descrip    = "Interactive mode",
		},
		{
			.longName   = "no-caching",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'n',
			.descrip    = "Disable caching",
		},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	poptContext pc;
	int opt;
	TALLOC_CTX *frame;
	NTSTATUS status;
	bool ok;
	const struct dcesrv_endpoint_server *ep_server = NULL;
	struct dcesrv_context *dce_ctx = NULL;

	setproctitle_init(argc, discard_const(argv), environ);

	/*
	 * Do this before any other talloc operation
	 */
	talloc_enable_null_tracking();
	frame = talloc_stackframe();

	/*
	 * We want total control over the permissions on created files,
	 * so set our umask to 0.
	 */
	umask(0);

	setup_logging("winbindd", DEBUG_DEFAULT_STDOUT);

	/* glibc (?) likes to print "User defined signal 1" and exit if a
	   SIGUSR[12] is received before a handler is installed */

 	CatchSignal(SIGUSR1, SIG_IGN);
 	CatchSignal(SIGUSR2, SIG_IGN);

	fault_setup();
	dump_core_setup("winbindd", lp_logfile(talloc_tos(), lp_sub));

	smb_init_locale();

	/* Initialise for running in non-root mode */

	sec_init();

	set_remote_machine_name("winbindd", False);

	/* Set environment variable so we don't recursively call ourselves.
	   This may also be useful interactively. */

	if ( !winbind_off() ) {
		DEBUG(0,("Failed to disable recusive winbindd calls.  Exiting.\n"));
		exit(1);
	}

	/* Initialise samba/rpc client stuff */

	pc = poptGetContext("winbindd", argc, argv, long_options, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
			/* Don't become a daemon */
		case OPT_DAEMON:
			is_daemon = True;
			break;
		case 'i':
			interactive = True;
			log_stdout = True;
			Fork = False;
			break;
                case OPT_FORK:
			Fork = false;
			break;
		case OPT_NO_PROCESS_GROUP:
			no_process_group = true;
			break;
		case OPT_LOG_STDOUT:
			log_stdout = true;
			break;
		case 'n':
			opt_nocache = true;
			break;
		default:
			d_fprintf(stderr, "\nInvalid option %s: %s\n\n",
				  poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	/* We call dump_core_setup one more time because the command line can
	 * set the log file or the log-basename and this will influence where
	 * cores are stored. Without this call get_dyn_LOGFILEBASE will be
	 * the default value derived from build's prefix. For EOM this value
	 * is often not related to the path where winbindd is actually run
	 * in production.
	 */
	dump_core_setup("winbindd", lp_logfile(talloc_tos(), lp_sub));
	if (is_daemon && interactive) {
		d_fprintf(stderr,"\nERROR: "
			  "Option -i|--interactive is not allowed together with -D|--daemon\n\n");
		poptPrintUsage(pc, stderr, 0);
		exit(1);
	}

	if (log_stdout && Fork) {
		d_fprintf(stderr, "\nERROR: "
			  "Can't log to stdout (-S) unless daemon is in foreground +(-F) or interactive (-i)\n\n");
		poptPrintUsage(pc, stderr, 0);
		exit(1);
	}

	poptFreeContext(pc);

	if (!override_logfile) {
		char *lfile = NULL;
		if (asprintf(&lfile,"%s/log.winbindd",
				get_dyn_LOGFILEBASE()) > 0) {
			lp_set_logfile(lfile);
			SAFE_FREE(lfile);
		}
	}

	if (log_stdout) {
		setup_logging("winbindd", DEBUG_STDOUT);
	} else {
		setup_logging("winbindd", DEBUG_FILE);
	}
	reopen_logs();

	DEBUG(0,("winbindd version %s started.\n", samba_version_string()));
	DEBUGADD(0,("%s\n", COPYRIGHT_STARTUP_MESSAGE));

	if (!lp_load_initial_only(get_dyn_CONFIGFILE())) {
		DEBUG(0, ("error opening config file '%s'\n", get_dyn_CONFIGFILE()));
		exit(1);
	}
	/* After parsing the configuration file we setup the core path one more time
	 * as the log file might have been set in the configuration and cores's
	 * path is by default basename(lp_logfile()).
	 */
	dump_core_setup("winbindd", lp_logfile(talloc_tos(), lp_sub));

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC
	    && !lp_parm_bool(-1, "server role check", "inhibit", false)) {
		DEBUG(0, ("server role = 'active directory domain controller' not compatible with running the winbindd binary. \n"));
		DEBUGADD(0, ("You should start 'samba' instead, and it will control starting the internal AD DC winbindd implementation, which is not the same as this one\n"));
		exit(1);
	}

	if (!cluster_probe_ok()) {
		exit(1);
	}

	/* Initialise messaging system */

	if (global_messaging_context() == NULL) {
		exit(1);
	}

	if (!winbindd_reload_services_file(NULL)) {
		DEBUG(0, ("error opening config file\n"));
		exit(1);
	}

	{
		size_t i;
		const char *idmap_backend;
		const char *invalid_backends[] = {
			"ad", "rfc2307", "rid",
		};

		idmap_backend = lp_idmap_default_backend();
		for (i = 0; i < ARRAY_SIZE(invalid_backends); i++) {
			ok = strequal(idmap_backend, invalid_backends[i]);
			if (ok) {
				DBG_ERR("FATAL: Invalid idmap backend %s "
					"configured as the default backend!\n",
					idmap_backend);
				exit(1);
			}
		}
	}

	ok = directory_create_or_exist(lp_lock_directory(), 0755);
	if (!ok) {
		DEBUG(0, ("Failed to create directory %s for lock files - %s\n",
			  lp_lock_directory(), strerror(errno)));
		exit(1);
	}

	ok = directory_create_or_exist(lp_pid_directory(), 0755);
	if (!ok) {
		DEBUG(0, ("Failed to create directory %s for pid files - %s\n",
			  lp_pid_directory(), strerror(errno)));
		exit(1);
	}

	/* Setup names. */

	if (!init_names())
		exit(1);

  	load_interfaces();

	if (!secrets_init()) {

		DEBUG(0,("Could not initialize domain trust account secrets. Giving up\n"));
		return False;
	}

	status = rpccli_pre_open_netlogon_creds();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("rpccli_pre_open_netlogon_creds() - %s\n",
			  nt_errstr(status)));
		exit(1);
	}

	/* Unblock all signals we are interested in as they may have been
	   blocked by the parent process. */

	BlockSignals(False, SIGINT);
	BlockSignals(False, SIGQUIT);
	BlockSignals(False, SIGTERM);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGUSR2);
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGCHLD);

	if (!interactive) {
		become_daemon(Fork, no_process_group, log_stdout);
	} else {
		daemon_status("winbindd", "Starting process ...");
	}

	pidfile_create(lp_pid_directory(), "winbindd");

#ifdef HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management.
	 */
	if (interactive && !no_process_group)
		setpgid( (pid_t)0, (pid_t)0);
#endif

	TimeInit();

	/* Don't use winbindd_reinit_after_fork here as
	 * we're just starting up and haven't created any
	 * winbindd-specific resources we must free yet. JRA.
	 */

	status = reinit_after_fork(global_messaging_context(),
				   global_event_context(),
				   false, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("Winbindd reinit_after_fork() failed", map_errno_from_nt_status(status));
	}

	ok = initialize_password_db(true, global_event_context());
	if (!ok) {
		exit_daemon("Failed to initialize passdb backend! "
			    "Check the 'passdb backend' variable in your "
			    "smb.conf file.", EINVAL);
	}

	/*
	 * Do not initialize the parent-child-pipe before becoming
	 * a daemon: this is used to detect a died parent in the child
	 * process.
	 */
	status = init_before_fork();
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon(nt_errstr(status), map_errno_from_nt_status(status));
	}

	winbindd_register_handlers(global_messaging_context(), !Fork);

	if (!messaging_parent_dgm_cleanup_init(global_messaging_context())) {
		exit(1);
	}

	status = init_system_session_info(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("Winbindd failed to setup system user info", map_errno_from_nt_status(status));
	}

	DBG_INFO("Registering DCE/RPC endpoint servers\n");

	/* Register the endpoint server to dispatch calls locally through
	 * the legacy api_struct */
	ep_server = lsarpc_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'lsarpc' endpoint server\n");
		exit(1);
	}
	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'lsarpc' endpoint "
			"server: %s\n", nt_errstr(status));
		exit(1);
	}

	/* Register the endpoint server to dispatch calls locally through
	 * the legacy api_struct */
	ep_server = samr_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'samr' endpoint server\n");
		exit(1);
	}
	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'samr' endpoint "
			"server: %s\n", nt_errstr(status));
		exit(1);
	}

	ep_server = winbind_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'winbind' endpoint server\n");
		exit(1);
	}
	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'winbind' endpoint "
			"server: %s\n", nt_errstr(status));
		exit(1);
	}

	dce_ctx = global_dcesrv_context();

	DBG_INFO("Initializing DCE/RPC registered endpoint servers\n");

	/* Init all registered ep servers */
	status = dcesrv_init_registered_ep_servers(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to init DCE/RPC endpoint servers: %s\n",
			nt_errstr(status));
		exit(1);
	}

	winbindd_init_addrchange(NULL, global_event_context(),
				 global_messaging_context());

	/* setup listen sockets */

	if (!winbindd_setup_listeners()) {
		exit_daemon("Winbindd failed to setup listeners", EPIPE);
	}

	irpc_add_name(winbind_imessaging_context(), "winbind_server");

	TALLOC_FREE(frame);

	if (!interactive) {
		daemon_ready("winbindd");
	}

	gpupdate_init();

	/* Loop waiting for requests */
	while (1) {
		frame = talloc_stackframe();

		if (tevent_loop_once(global_event_context()) == -1) {
			DEBUG(1, ("tevent_loop_once() failed: %s\n",
				  strerror(errno)));
			return 1;
		}

		TALLOC_FREE(frame);
	}

	return 0;
}
