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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static bool opt_nocache = False;
static bool interactive = False;

extern bool override_logfile;

struct event_context *winbind_event_context(void)
{
	static struct event_context *ctx;

	if (!ctx && !(ctx = event_context_init(NULL))) {
		smb_panic("Could not init winbind event context");
	}
	return ctx;
}

struct messaging_context *winbind_messaging_context(void)
{
	static struct messaging_context *ctx;

	if (ctx == NULL) {
		ctx = messaging_init(NULL, server_id_self(),
				     winbind_event_context());
	}
	if (ctx == NULL) {
		DEBUG(0, ("Could not init winbind messaging context.\n"));
	}
	return ctx;
}

/* Reload configuration */

static bool reload_services_file(const char *lfile)
{
	bool ret;

	if (lp_loaded()) {
		const char *fname = lp_configfile();

		if (file_exist(fname) && !strcsequal(fname,get_dyn_CONFIGFILE())) {
			set_dyn_CONFIGFILE(fname);
		}
	}

	/* if this is a child, restore the logfile to the special
	   name - <domain>, idmap, etc. */
	if (lfile && *lfile) {
		lp_set_logfile(lfile);
	}

	reopen_logs();
	ret = lp_load(get_dyn_CONFIGFILE(),False,False,True,True);

	reopen_logs();
	load_interfaces();

	return(ret);
}


/**************************************************************************** **
 Handle a fault..
 **************************************************************************** */

static void fault_quit(void)
{
	dump_core();
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
			DEBUGADD(2, ("\t\tpid %lu, sock %d\n",
				  (unsigned long)tmp->pid, tmp->sock));
		}
	}
}

/* Print winbindd status to log file */

static void print_winbindd_status(void)
{
	winbindd_status();
}

/* Flush client cache */

static void flush_caches(void)
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
			get_winbind_pipe_dir(), WINBINDD_SOCKET_NAME) > 0) {
			unlink(path);
			SAFE_FREE(path);
		}
	}

	idmap_close();

	trustdom_cache_shutdown();

#if 0
	if (interactive) {
		TALLOC_CTX *mem_ctx = talloc_init("end_description");
		char *description = talloc_describe_all(mem_ctx);

		DEBUG(3, ("tallocs left:\n%s\n", description));
		talloc_destroy(mem_ctx);
	}
#endif

	exit(0);
}

static void winbindd_sig_term_handler(struct tevent_context *ev,
				      struct tevent_signal *se,
				      int signum,
				      int count,
				      void *siginfo,
				      void *private_data)
{
	bool *is_parent = talloc_get_type_abort(private_data, bool);

	DEBUG(0,("Got sig[%d] terminate (is_parent=%d)\n",
		 signum, (int)*is_parent));
	terminate(*is_parent);
}

bool winbindd_setup_sig_term_handler(bool parent)
{
	struct tevent_signal *se;
	bool *is_parent;

	is_parent = talloc(winbind_event_context(), bool);
	if (!is_parent) {
		return false;
	}

	*is_parent = parent;

	se = tevent_add_signal(winbind_event_context(),
			       is_parent,
			       SIGTERM, 0,
			       winbindd_sig_term_handler,
			       is_parent);
	if (!se) {
		DEBUG(0,("failed to setup SIGTERM handler"));
		talloc_free(is_parent);
		return false;
	}

	se = tevent_add_signal(winbind_event_context(),
			       is_parent,
			       SIGINT, 0,
			       winbindd_sig_term_handler,
			       is_parent);
	if (!se) {
		DEBUG(0,("failed to setup SIGINT handler"));
		talloc_free(is_parent);
		return false;
	}

	se = tevent_add_signal(winbind_event_context(),
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

static void winbindd_sig_hup_handler(struct tevent_context *ev,
				     struct tevent_signal *se,
				     int signum,
				     int count,
				     void *siginfo,
				     void *private_data)
{
	const char *file = (const char *)private_data;

	DEBUG(1,("Reloading services after SIGHUP\n"));
	flush_caches();
	reload_services_file(file);
}

bool winbindd_setup_sig_hup_handler(const char *lfile)
{
	struct tevent_signal *se;
	char *file = NULL;

	if (lfile) {
		file = talloc_strdup(winbind_event_context(),
				     lfile);
		if (!file) {
			return false;
		}
	}

	se = tevent_add_signal(winbind_event_context(),
			       winbind_event_context(),
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

	while ((pid = sys_waitpid(-1, NULL, WNOHANG)) > 0) {
		winbind_child_died(pid);
	}
}

static bool winbindd_setup_sig_chld_handler(void)
{
	struct tevent_signal *se;

	se = tevent_add_signal(winbind_event_context(),
			       winbind_event_context(),
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
	print_winbindd_status();
}

static bool winbindd_setup_sig_usr2_handler(void)
{
	struct tevent_signal *se;

	se = tevent_add_signal(winbind_event_context(),
			       winbind_event_context(),
			       SIGUSR2, 0,
			       winbindd_sig_usr2_handler,
			       NULL);
	if (!se) {
		return false;
	}

	return true;
}

/* React on 'smbcontrol winbindd reload-config' in the same way as on SIGHUP*/
static void msg_reload_services(struct messaging_context *msg,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data)
{
        /* Flush various caches */
	flush_caches();
	reload_services_file((const char *) private_data);
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
	uint8 ret;
	pid_t child_pid;
	struct sigaction act;
	struct sigaction oldact;

	DEBUG(10, ("winbindd_msg_validate_cache: got validate-cache "
		   "message.\n"));

	/*
	 * call the validation code from a child:
	 * so we don't block the main winbindd and the validation
	 * code can safely use fork/waitpid...
	 */
	CatchChild();
	child_pid = sys_fork();

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

	/* install default SIGCHLD handler: validation code uses fork/waitpid */
	ZERO_STRUCT(act);
	act.sa_handler = SIG_DFL;
#ifdef SA_RESTART
	/* We *want* SIGALRM to interrupt a system call. */
	act.sa_flags = SA_RESTART;
#endif
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask,SIGCHLD);
	sigaction(SIGCHLD,&act,&oldact);

	ret = (uint8)winbindd_validate_cache_nobackup();
	DEBUG(10, ("winbindd_msg_validata_cache: got return value %d\n", ret));
	messaging_send_buf(msg_ctx, server_id, MSG_WINBIND_VALIDATE_CACHE, &ret,
			   (size_t)1);
	_exit(0);
}

static struct winbindd_dispatch_table {
	enum winbindd_cmd cmd;
	void (*fn)(struct winbindd_cli_state *state);
	const char *winbindd_cmd_name;
} dispatch_table[] = {

	/* User functions */

	{ WINBINDD_GETPWNAM, winbindd_getpwnam, "GETPWNAM" },
	{ WINBINDD_GETPWUID, winbindd_getpwuid, "GETPWUID" },
	{ WINBINDD_GETPWSID, winbindd_getpwsid, "GETPWSID" },

	{ WINBINDD_SETPWENT, winbindd_setpwent, "SETPWENT" },
	{ WINBINDD_ENDPWENT, winbindd_endpwent, "ENDPWENT" },
	{ WINBINDD_GETPWENT, winbindd_getpwent, "GETPWENT" },

	{ WINBINDD_GETGROUPS, winbindd_getgroups, "GETGROUPS" },
	{ WINBINDD_GETUSERSIDS, winbindd_getusersids, "GETUSERSIDS" },
	{ WINBINDD_GETUSERDOMGROUPS, winbindd_getuserdomgroups,
	  "GETUSERDOMGROUPS" },
	{ WINBINDD_GETSIDALIASES, winbindd_getsidaliases,
	   "LOOKUPUSERALIASES" },

	/* Group functions */

	{ WINBINDD_GETGRNAM, winbindd_getgrnam, "GETGRNAM" },
	{ WINBINDD_GETGRGID, winbindd_getgrgid, "GETGRGID" },
	{ WINBINDD_SETGRENT, winbindd_setgrent, "SETGRENT" },
	{ WINBINDD_ENDGRENT, winbindd_endgrent, "ENDGRENT" },
	{ WINBINDD_GETGRENT, winbindd_getgrent, "GETGRENT" },
	{ WINBINDD_GETGRLST, winbindd_getgrent, "GETGRLST" },

	/* PAM auth functions */

	{ WINBINDD_PAM_AUTH, winbindd_pam_auth, "PAM_AUTH" },
	{ WINBINDD_PAM_AUTH_CRAP, winbindd_pam_auth_crap, "AUTH_CRAP" },
	{ WINBINDD_PAM_CHAUTHTOK, winbindd_pam_chauthtok, "CHAUTHTOK" },
	{ WINBINDD_PAM_LOGOFF, winbindd_pam_logoff, "PAM_LOGOFF" },
	{ WINBINDD_PAM_CHNG_PSWD_AUTH_CRAP, winbindd_pam_chng_pswd_auth_crap, "CHNG_PSWD_AUTH_CRAP" },

	/* Enumeration functions */

	{ WINBINDD_LIST_USERS, winbindd_list_users, "LIST_USERS" },
	{ WINBINDD_LIST_GROUPS, winbindd_list_groups, "LIST_GROUPS" },
	{ WINBINDD_LIST_TRUSTDOM, winbindd_list_trusted_domains,
	  "LIST_TRUSTDOM" },
	{ WINBINDD_SHOW_SEQUENCE, winbindd_show_sequence, "SHOW_SEQUENCE" },

	/* SID related functions */

	{ WINBINDD_LOOKUPSID, winbindd_lookupsid, "LOOKUPSID" },
	{ WINBINDD_LOOKUPNAME, winbindd_lookupname, "LOOKUPNAME" },
	{ WINBINDD_LOOKUPRIDS, winbindd_lookuprids, "LOOKUPRIDS" },

	/* Lookup related functions */

	{ WINBINDD_SID_TO_UID, winbindd_sid_to_uid, "SID_TO_UID" },
	{ WINBINDD_SID_TO_GID, winbindd_sid_to_gid, "SID_TO_GID" },
	{ WINBINDD_UID_TO_SID, winbindd_uid_to_sid, "UID_TO_SID" },
	{ WINBINDD_GID_TO_SID, winbindd_gid_to_sid, "GID_TO_SID" },
	{ WINBINDD_ALLOCATE_UID, winbindd_allocate_uid, "ALLOCATE_UID" },
	{ WINBINDD_ALLOCATE_GID, winbindd_allocate_gid, "ALLOCATE_GID" },
	{ WINBINDD_SET_MAPPING, winbindd_set_mapping, "SET_MAPPING" },
	{ WINBINDD_REMOVE_MAPPING, winbindd_remove_mapping, "REMOVE_MAPPING" },
	{ WINBINDD_SET_HWM, winbindd_set_hwm, "SET_HWMS" },

	/* Miscellaneous */

	{ WINBINDD_CHECK_MACHACC, winbindd_check_machine_acct, "CHECK_MACHACC" },
	{ WINBINDD_PING, winbindd_ping, "PING" },
	{ WINBINDD_INFO, winbindd_info, "INFO" },
	{ WINBINDD_INTERFACE_VERSION, winbindd_interface_version,
	  "INTERFACE_VERSION" },
	{ WINBINDD_DOMAIN_NAME, winbindd_domain_name, "DOMAIN_NAME" },
	{ WINBINDD_DOMAIN_INFO, winbindd_domain_info, "DOMAIN_INFO" },
	{ WINBINDD_NETBIOS_NAME, winbindd_netbios_name, "NETBIOS_NAME" },
	{ WINBINDD_PRIV_PIPE_DIR, winbindd_priv_pipe_dir,
	  "WINBINDD_PRIV_PIPE_DIR" },
	{ WINBINDD_GETDCNAME, winbindd_getdcname, "GETDCNAME" },
	{ WINBINDD_DSGETDCNAME, winbindd_dsgetdcname, "DSGETDCNAME" },

	/* Credential cache access */
	{ WINBINDD_CCACHE_NTLMAUTH, winbindd_ccache_ntlm_auth, "NTLMAUTH" },

	/* WINS functions */

	{ WINBINDD_WINS_BYNAME, winbindd_wins_byname, "WINS_BYNAME" },
	{ WINBINDD_WINS_BYIP, winbindd_wins_byip, "WINS_BYIP" },

	/* End of list */

	{ WINBINDD_NUM_CMDS, NULL, "NONE" }
};

static void process_request(struct winbindd_cli_state *state)
{
	struct winbindd_dispatch_table *table = dispatch_table;

	/* Free response data - we may be interrupted and receive another
	   command before being able to send this data off. */

	SAFE_FREE(state->response.extra_data.data);  

	ZERO_STRUCT(state->response);

	state->response.result = WINBINDD_PENDING;
	state->response.length = sizeof(struct winbindd_response);

	state->mem_ctx = talloc_init("winbind request");
	if (state->mem_ctx == NULL)
		return;

	/* Remember who asked us. */
	state->pid = state->request.pid;

	/* Process command */

	for (table = dispatch_table; table->fn; table++) {
		if (state->request.cmd == table->cmd) {
			DEBUG(10,("process_request: request fn %s\n",
				  table->winbindd_cmd_name ));
			table->fn(state);
			break;
		}
	}

	if (!table->fn) {
		DEBUG(10,("process_request: unknown request fn number %d\n",
			  (int)state->request.cmd ));
		request_error(state);
	}
}

/*
 * A list of file descriptors being monitored by select in the main processing
 * loop. winbindd_fd_event->handler is called whenever the socket is readable/writable.
 */

static struct winbindd_fd_event *fd_events = NULL;

void add_fd_event(struct winbindd_fd_event *ev)
{
	struct winbindd_fd_event *match;

	/* only add unique winbindd_fd_event structs */

	for (match=fd_events; match; match=match->next ) {
#ifdef DEVELOPER
		SMB_ASSERT( match != ev );
#else
		if ( match == ev )
			return;
#endif
	}

	DLIST_ADD(fd_events, ev);
}

void remove_fd_event(struct winbindd_fd_event *ev)
{
	DLIST_REMOVE(fd_events, ev);
}

/*
 * Handler for winbindd_fd_events to complete a read/write request, set up by
 * setup_async_read/setup_async_write.
 */

static void rw_callback(struct winbindd_fd_event *event, int flags)
{
	size_t todo;
	ssize_t done = 0;

	todo = event->length - event->done;

	if (event->flags & EVENT_FD_WRITE) {
		SMB_ASSERT(flags == EVENT_FD_WRITE);
		done = sys_write(event->fd,
				 &((char *)event->data)[event->done],
				 todo);

		if (done <= 0) {
			event->flags = 0;
			event->finished(event->private_data, False);
			return;
		}
	}

	if (event->flags & EVENT_FD_READ) {
		SMB_ASSERT(flags == EVENT_FD_READ);
		done = sys_read(event->fd, &((char *)event->data)[event->done],
				todo);

		if (done <= 0) {
			event->flags = 0;
			event->finished(event->private_data, False);
			return;
		}
	}

	event->done += done;

	if (event->done == event->length) {
		event->flags = 0;
		event->finished(event->private_data, True);
	}
}

/*
 * Request an async read/write on a winbindd_fd_event structure. (*finished) is called
 * when the request is completed or an error had occurred.
 */

void setup_async_read(struct winbindd_fd_event *event, void *data, size_t length,
		      void (*finished)(void *private_data, bool success),
		      void *private_data)
{
	SMB_ASSERT(event->flags == 0);
	event->data = data;
	event->length = length;
	event->done = 0;
	event->handler = rw_callback;
	event->finished = finished;
	event->private_data = private_data;
	event->flags = EVENT_FD_READ;
}

void setup_async_write(struct winbindd_fd_event *event, void *data, size_t length,
		       void (*finished)(void *private_data, bool success),
		       void *private_data)
{
	SMB_ASSERT(event->flags == 0);
	event->data = data;
	event->length = length;
	event->done = 0;
	event->handler = rw_callback;
	event->finished = finished;
	event->private_data = private_data;
	event->flags = EVENT_FD_WRITE;
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

static void request_len_recv(void *private_data, bool success);
static void request_recv(void *private_data, bool success);
static void request_main_recv(void *private_data, bool success);
static void request_finished(struct winbindd_cli_state *state);
static void response_main_sent(void *private_data, bool success);
static void response_extra_sent(void *private_data, bool success);

static void response_extra_sent(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	TALLOC_FREE(state->mem_ctx);

	if (!success) {
		state->finished = True;
		return;
	}

	SAFE_FREE(state->response.extra_data.data);

	setup_async_read(&state->fd_event, &state->request, sizeof(uint32),
			 request_len_recv, state);
}

static void response_main_sent(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		state->finished = True;
		return;
	}

	if (state->response.length == sizeof(state->response)) {
		TALLOC_FREE(state->mem_ctx);

		setup_async_read(&state->fd_event, &state->request,
				 sizeof(uint32), request_len_recv, state);
		return;
	}

	setup_async_write(&state->fd_event, state->response.extra_data.data,
			  state->response.length - sizeof(state->response),
			  response_extra_sent, state);
}

static void request_finished(struct winbindd_cli_state *state)
{
	/* Make sure request.extra_data is freed when finish processing a request */
	SAFE_FREE(state->request.extra_data.data);
	setup_async_write(&state->fd_event, &state->response,
			  sizeof(state->response), response_main_sent, state);
}

void request_error(struct winbindd_cli_state *state)
{
	SMB_ASSERT(state->response.result == WINBINDD_PENDING);
	state->response.result = WINBINDD_ERROR;
	request_finished(state);
}

void request_ok(struct winbindd_cli_state *state)
{
	SMB_ASSERT(state->response.result == WINBINDD_PENDING);
	state->response.result = WINBINDD_OK;
	request_finished(state);
}

static void request_len_recv(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		state->finished = True;
		return;
	}

	if (*(uint32 *)(&state->request) != sizeof(state->request)) {
		DEBUG(0,("request_len_recv: Invalid request size received: %d (expected %u)\n",
			 *(uint32_t *)(&state->request), (uint32_t)sizeof(state->request)));
		state->finished = True;
		return;
	}

	setup_async_read(&state->fd_event, (uint32 *)(&state->request)+1,
			 sizeof(state->request) - sizeof(uint32),
			 request_main_recv, state);
}

static void request_main_recv(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		state->finished = True;
		return;
	}

	if (state->request.extra_len == 0) {
		state->request.extra_data.data = NULL;
		request_recv(state, True);
		return;
	}

	if ((!state->privileged) &&
	    (state->request.extra_len > WINBINDD_MAX_EXTRA_DATA)) {
		DEBUG(3, ("Got request with %d bytes extra data on "
			  "unprivileged socket\n", (int)state->request.extra_len));
		state->request.extra_data.data = NULL;
		state->finished = True;
		return;
	}

	state->request.extra_data.data =
		SMB_MALLOC_ARRAY(char, state->request.extra_len + 1);

	if (state->request.extra_data.data == NULL) {
		DEBUG(0, ("malloc failed\n"));
		state->finished = True;
		return;
	}

	/* Ensure null termination */
	state->request.extra_data.data[state->request.extra_len] = '\0';

	setup_async_read(&state->fd_event, state->request.extra_data.data,
			 state->request.extra_len, request_recv, state);
}

static void request_recv(void *private_data, bool success)
{
	struct winbindd_cli_state *state =
		talloc_get_type_abort(private_data, struct winbindd_cli_state);

	if (!success) {
		state->finished = True;
		return;
	}

	process_request(state);
}

/* Process a new connection by adding it to the client connection list */

static void new_connection(int listen_sock, bool privileged)
{
	struct sockaddr_un sunaddr;
	struct winbindd_cli_state *state;
	socklen_t len;
	int sock;

	/* Accept connection */

	len = sizeof(sunaddr);

	do {
		sock = accept(listen_sock, (struct sockaddr *)&sunaddr, &len);
	} while (sock == -1 && errno == EINTR);

	if (sock == -1)
		return;

	DEBUG(6,("accepted socket %d\n", sock));

	/* Create new connection structure */

	if ((state = TALLOC_ZERO_P(NULL, struct winbindd_cli_state)) == NULL) {
		close(sock);
		return;
	}

	state->sock = sock;

	state->last_access = time(NULL);	

	state->privileged = privileged;

	state->fd_event.fd = state->sock;
	state->fd_event.flags = 0;
	add_fd_event(&state->fd_event);

	setup_async_read(&state->fd_event, &state->request, sizeof(uint32),
			 request_len_recv, state);

	/* Add to connection list */

	winbindd_add_client(state);
}

/* Remove a client connection from client connection list */

static void remove_client(struct winbindd_cli_state *state)
{
	char c = 0;
	int nwritten;

	/* It's a dead client - hold a funeral */

	if (state == NULL) {
		return;
	}

	/* tell client, we are closing ... */
	nwritten = write(state->sock, &c, sizeof(c));
	if (nwritten == -1) {
		DEBUG(2, ("final write to client failed: %s\n",
			  strerror(errno)));
	}

	/* Close socket */

	close(state->sock);

	/* Free any getent state */

	free_getent_state(state->getpwent_state);
	free_getent_state(state->getgrent_state);

	/* We may have some extra data that was not freed if the client was
	   killed unexpectedly */

	SAFE_FREE(state->response.extra_data.data);

	TALLOC_FREE(state->mem_ctx);

	remove_fd_event(&state->fd_event);

	/* Remove from list and free */

	winbindd_remove_client(state);
	TALLOC_FREE(state);
}

/* Shutdown client connection which has been idle for the longest time */

static bool remove_idle_client(void)
{
	struct winbindd_cli_state *state, *remove_state = NULL;
	time_t last_access = 0;
	int nidle = 0;

	for (state = winbindd_client_list(); state; state = state->next) {
		if (state->response.result != WINBINDD_PENDING &&
		    state->fd_event.flags == EVENT_FD_READ &&
		    !state->getpwent_state && !state->getgrent_state) {
			nidle++;
			if (!last_access || state->last_access < last_access) {
				last_access = state->last_access;
				remove_state = state;
			}
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

struct winbindd_listen_state {
	bool privileged;
	int fd;
	struct tevent_fd *fde;
};

static void winbindd_listen_fde_handler(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct winbindd_listen_state *s = talloc_get_type_abort(private_data,
					  struct winbindd_listen_state);

	while (winbindd_num_clients() >
	       WINBINDD_MAX_SIMULTANEOUS_CLIENTS - 1) {
		DEBUG(5,("winbindd: Exceeding %d client "
			 "connections, removing idle "
			 "connection.\n",
			 WINBINDD_MAX_SIMULTANEOUS_CLIENTS));
		if (!remove_idle_client()) {
			DEBUG(0,("winbindd: Exceeding %d "
				 "client connections, no idle "
				 "connection found\n",
				 WINBINDD_MAX_SIMULTANEOUS_CLIENTS));
			break;
		}
	}

	/* new, non-privileged connection */
	new_connection(s->fd, s->privileged);
}

static bool winbindd_setup_listeners(void)
{
	struct winbindd_listen_state *pub_state = NULL;
	struct winbindd_listen_state *priv_state = NULL;

	pub_state = talloc(winbind_event_context(),
			   struct winbindd_listen_state);
	if (!pub_state) {
		goto failed;
	}

	pub_state->privileged = false;
	pub_state->fd = open_winbindd_socket();
	if (pub_state->fd == -1) {
		goto failed;
	}

	pub_state->fde = tevent_add_fd(winbind_event_context(),
				       pub_state, pub_state->fd,
				       TEVENT_FD_READ,
				       winbindd_listen_fde_handler,
				       pub_state);
	if (!pub_state->fde) {
		close(pub_state->fd);
		goto failed;
	}
	tevent_fd_set_auto_close(pub_state->fde);

	priv_state = talloc(winbind_event_context(),
			    struct winbindd_listen_state);
	if (!priv_state) {
		goto failed;
	}

	priv_state->privileged = true;
	priv_state->fd = open_winbindd_priv_socket();
	if (priv_state->fd == -1) {
		goto failed;
	}

	priv_state->fde = tevent_add_fd(winbind_event_context(),
					priv_state, priv_state->fd,
					TEVENT_FD_READ,
					winbindd_listen_fde_handler,
					priv_state);
	if (!priv_state->fde) {
		close(priv_state->fd);
		goto failed;
	}
	tevent_fd_set_auto_close(priv_state->fde);

	return true;
failed:
	TALLOC_FREE(pub_state);
	TALLOC_FREE(priv_state);
	return false;
}

/* Process incoming clients on listen_sock.  We use a tricky non-blocking,
   non-forking, non-threaded model which allows us to handle many
   simultaneous connections while remaining impervious to many denial of
   service attacks. */

static void process_loop(void)
{
	struct winbindd_fd_event *ev;
	fd_set r_fds, w_fds;
	int maxfd = 0, selret;
	struct timeval timeout, ev_timeout;

	run_events(winbind_event_context(), 0, NULL, NULL);

	/* Initialise fd lists for select() */

	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);

	timeout.tv_sec = WINBINDD_ESTABLISH_LOOP;
	timeout.tv_usec = 0;

	/* Check for any event timeouts. */
	{
		struct timeval now;
		GetTimeOfDay(&now);

		event_add_to_select_args(winbind_event_context(), &now,
					 &r_fds, &w_fds, &ev_timeout, &maxfd);
	}
	if (get_timed_events_timeout(winbind_event_context(), &ev_timeout)) {
		timeout = timeval_min(&timeout, &ev_timeout);
	}

	for (ev = fd_events; ev; ev = ev->next) {
		if (ev->flags & EVENT_FD_READ) {
			FD_SET(ev->fd, &r_fds);
			maxfd = MAX(ev->fd, maxfd);
		}
		if (ev->flags & EVENT_FD_WRITE) {
			FD_SET(ev->fd, &w_fds);
			maxfd = MAX(ev->fd, maxfd);
		}
	}

	/* Call select */

	selret = sys_select(maxfd + 1, &r_fds, &w_fds, NULL, &timeout);

	if (selret == 0) {
		goto no_fds_ready;
	}

	if (selret == -1) {
		if (errno == EINTR) {
			goto no_fds_ready;
		}

		/* Select error, something is badly wrong */

		perror("select");
		exit(1);
	}

	/* selret > 0 */

	run_events(winbind_event_context(), selret, &r_fds, &w_fds);

	ev = fd_events;
	while (ev != NULL) {
		struct winbindd_fd_event *next = ev->next;
		int flags = 0;
		if (FD_ISSET(ev->fd, &r_fds))
			flags |= EVENT_FD_READ;
		if (FD_ISSET(ev->fd, &w_fds))
			flags |= EVENT_FD_WRITE;
		if (flags)
			ev->handler(ev, flags);
		ev = next;
	}

	return;

 no_fds_ready:

	run_events(winbind_event_context(), selret, &r_fds, &w_fds);

#if 0
	winbindd_check_cache_size(time(NULL));
#endif
}

bool winbindd_use_idmap_cache(void)
{
	return !opt_nocache;
}

bool winbindd_use_cache(void)
{
	return !opt_nocache;
}

/* Main function */

int main(int argc, char **argv, char **envp)
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
		{ "stdout", 'S', POPT_ARG_NONE, NULL, OPT_LOG_STDOUT, "Log to stdout" },
		{ "foreground", 'F', POPT_ARG_NONE, NULL, OPT_FORK, "Daemon in foreground mode" },
		{ "no-process-group", 0, POPT_ARG_NONE, NULL, OPT_NO_PROCESS_GROUP, "Don't create a new process group" },
		{ "daemon", 'D', POPT_ARG_NONE, NULL, OPT_DAEMON, "Become a daemon (default)" },
		{ "interactive", 'i', POPT_ARG_NONE, NULL, 'i', "Interactive mode" },
		{ "no-caching", 'n', POPT_ARG_NONE, NULL, 'n', "Disable caching" },
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	poptContext pc;
	int opt;
	TALLOC_CTX *frame = talloc_stackframe();

	/* glibc (?) likes to print "User defined signal 1" and exit if a
	   SIGUSR[12] is received before a handler is installed */

 	CatchSignal(SIGUSR1, SIG_IGN);
 	CatchSignal(SIGUSR2, SIG_IGN);

	fault_setup((void (*)(void *))fault_quit );
	dump_core_setup("winbindd");

	load_case_tables();

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

	pc = poptGetContext("winbindd", argc, (const char **)argv, long_options, 0);

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
	setup_logging("winbindd", log_stdout);
	reopen_logs();

	DEBUG(0,("winbindd version %s started.\n", samba_version_string()));
	DEBUGADD(0,("%s\n", COPYRIGHT_STARTUP_MESSAGE));

	if (!lp_load_initial_only(get_dyn_CONFIGFILE())) {
		DEBUG(0, ("error opening config file\n"));
		exit(1);
	}

	/* Initialise messaging system */

	if (winbind_messaging_context() == NULL) {
		exit(1);
	}

	if (!reload_services_file(NULL)) {
		DEBUG(0, ("error opening config file\n"));
		exit(1);
	}

	if (!directory_exist(lp_lockdir())) {
		mkdir(lp_lockdir(), 0755);
	}

	/* Setup names. */

	if (!init_names())
		exit(1);

  	load_interfaces();

	if (!secrets_init()) {

		DEBUG(0,("Could not initialize domain trust account secrets. Giving up\n"));
		return False;
	}

	/* Enable netbios namecache */

	namecache_enable();

	/* Unblock all signals we are interested in as they may have been
	   blocked by the parent process. */

	BlockSignals(False, SIGINT);
	BlockSignals(False, SIGQUIT);
	BlockSignals(False, SIGTERM);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGUSR2);
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGCHLD);

	if (!interactive)
		become_daemon(Fork, no_process_group);

	pidfile_create("winbindd");

#if HAVE_SETPGID
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

	if (!NT_STATUS_IS_OK(reinit_after_fork(winbind_messaging_context(),
					       winbind_event_context(),
					       false))) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		exit(1);
	}

	/* Setup signal handlers */

	if (!winbindd_setup_sig_term_handler(true))
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

	/* get broadcast messages */
	claim_connection(NULL,"",FLAG_MSG_GENERAL|FLAG_MSG_DBWRAP);

	/* React on 'smbcontrol winbindd reload-config' in the same way
	   as to SIGHUP signal */
	messaging_register(winbind_messaging_context(), NULL,
			   MSG_SMB_CONF_UPDATED, msg_reload_services);
	messaging_register(winbind_messaging_context(), NULL,
			   MSG_SHUTDOWN, msg_shutdown);

	/* Handle online/offline messages. */
	messaging_register(winbind_messaging_context(), NULL,
			   MSG_WINBIND_OFFLINE, winbind_msg_offline);
	messaging_register(winbind_messaging_context(), NULL,
			   MSG_WINBIND_ONLINE, winbind_msg_online);
	messaging_register(winbind_messaging_context(), NULL,
			   MSG_WINBIND_ONLINESTATUS, winbind_msg_onlinestatus);

	messaging_register(winbind_messaging_context(), NULL,
			   MSG_DUMP_EVENT_LIST, winbind_msg_dump_event_list);

	messaging_register(winbind_messaging_context(), NULL,
			   MSG_WINBIND_VALIDATE_CACHE,
			   winbind_msg_validate_cache);

	messaging_register(winbind_messaging_context(), NULL,
			   MSG_WINBIND_DUMP_DOMAIN_LIST,
			   winbind_msg_dump_domain_list);

	/* Register handler for MSG_DEBUG. */
	messaging_register(winbind_messaging_context(), NULL,
			   MSG_DEBUG,
			   winbind_msg_debug);

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

	/* setup listen sockets */

	if (!winbindd_setup_listeners()) {
		DEBUG(0,("winbindd_setup_listeners() failed\n"));
		exit(1);
	}

	TALLOC_FREE(frame);
	/* Loop waiting for requests */
	while (1) {
		struct winbindd_cli_state *state;

		frame = talloc_stackframe();

		/* refresh the trusted domain cache */

		rescan_trusted_domains();

		/* Dispose of client connection if it is marked as
		   finished */
		state = winbindd_client_list();
		while (state) {
			struct winbindd_cli_state *next = state->next;

			if (state->finished) {
				remove_client(state);
			}

			state = next;
		}

		process_loop();

		TALLOC_FREE(frame);
	}

	return 0;
}
