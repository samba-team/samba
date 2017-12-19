/*
   Unix SMB/CIFS implementation.

   Main SMB server routines

   Copyright (C) Andrew Tridgell		1992-2005
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002
   Copyright (C) James J Myers 			2003 <myersjj@samba.org>

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
#include "lib/events/events.h"
#include "version.h"
#include "lib/cmdline/popt_common.h"
#include "system/dir.h"
#include "system/filesys.h"
#include "auth/gensec/gensec.h"
#include "libcli/auth/schannel.h"
#include "smbd/process_model.h"
#include "param/secrets.h"
#include "lib/util/pidfile.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "auth/session.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "cluster/cluster.h"
#include "dynconfig/dynconfig.h"
#include "lib/util/samba_modules.h"
#include "nsswitch/winbind_client.h"
#include "libds/common/roles.h"

struct server_state {
	struct tevent_context *event_ctx;
	const char *binary_name;
};

/*
  recursively delete a directory tree
*/
static void recursive_delete(const char *path)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir(path);
	if (!dir) {
		return;
	}

	for (de=readdir(dir);de;de=readdir(dir)) {
		char *fname;
		struct stat st;

		if (ISDOT(de->d_name) || ISDOTDOT(de->d_name)) {
			continue;
		}

		fname = talloc_asprintf(path, "%s/%s", path, de->d_name);
		if (stat(fname, &st) != 0) {
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			recursive_delete(fname);
			talloc_free(fname);
			continue;
		}
		if (unlink(fname) != 0) {
			DEBUG(0,("Unabled to delete '%s' - %s\n",
				 fname, strerror(errno)));
			smb_panic("unable to cleanup tmp files");
		}
		talloc_free(fname);
	}
	closedir(dir);
}

/*
  cleanup temporary files. This is the new alternative to
  TDB_CLEAR_IF_FIRST. Unfortunately TDB_CLEAR_IF_FIRST is not
  efficient on unix systems due to the lack of scaling of the byte
  range locking system. So instead of putting the burden on tdb to
  cleanup tmp files, this function deletes them.
*/
static void cleanup_tmp_files(struct loadparm_context *lp_ctx)
{
	char *path;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		exit_daemon("Failed to create memory context",
			    ENOMEM);
	}

	path = smbd_tmp_path(mem_ctx, lp_ctx, NULL);
	if (path == NULL) {
		exit_daemon("Failed to cleanup temporary files",
			    EINVAL);
	}

	recursive_delete(path);
	talloc_free(mem_ctx);
}

static void sig_hup(int sig)
{
	debug_schedule_reopen_logs();
}

static void sig_term(int sig)
{
#if HAVE_GETPGRP
	if (getpgrp() == getpid()) {
		/*
		 * We're the process group leader, send
		 * SIGTERM to our process group.
		 */
		DEBUG(0,("SIGTERM: killing children\n"));
		kill(-getpgrp(), SIGTERM);
	}
#endif
	DEBUG(0,("Exiting pid %d on SIGTERM\n", (int)getpid()));
	exit(127);
}

static void sigterm_signal_handler(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum, int count, void *siginfo,
				void *private_data)
{
	struct server_state *state = talloc_get_type_abort(
                private_data, struct server_state);

	DEBUG(10,("Process %s got SIGTERM\n", state->binary_name));
	TALLOC_FREE(state);
	sig_term(SIGTERM);
}

/*
  setup signal masks
*/
static void setup_signals(void)
{
	/* we are never interested in SIGPIPE */
	BlockSignals(true,SIGPIPE);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(true,SIGFPE);
#endif

	/* We are no longer interested in USR1 */
	BlockSignals(true, SIGUSR1);

#if defined(SIGUSR2)
	/* We are no longer interested in USR2 */
	BlockSignals(true,SIGUSR2);
#endif

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems,
	 * as we won't receive them. */
	BlockSignals(false, SIGHUP);
	BlockSignals(false, SIGTERM);

	CatchSignal(SIGHUP, sig_hup);
	CatchSignal(SIGTERM, sig_term);
}

/*
  handle io on stdin
*/
static void server_stdin_handler(struct tevent_context *event_ctx,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_data)
{
	struct server_state *state = talloc_get_type_abort(
		private_data, struct server_state);
	uint8_t c;
	if (read(0, &c, 1) == 0) {
		DEBUG(0,("%s: EOF on stdin - PID %d terminating\n",
				state->binary_name, (int)getpid()));
#if HAVE_GETPGRP
		if (getpgrp() == getpid()) {
			DEBUG(0,("Sending SIGTERM from pid %d\n",
				(int)getpid()));
			kill(-getpgrp(), SIGTERM);
		}
#endif
		TALLOC_FREE(state);
		exit(0);
	}
}

/*
  die if the user selected maximum runtime is exceeded
*/
_NORETURN_ static void max_runtime_handler(struct tevent_context *ev,
					   struct tevent_timer *te,
					   struct timeval t, void *private_data)
{
	struct server_state *state = talloc_get_type_abort(
		private_data, struct server_state);
	DEBUG(0,("%s: maximum runtime exceeded - "
		"terminating PID %d at %llu, current ts: %llu\n",
		 state->binary_name,
		(int)getpid(),
		(unsigned long long)t.tv_sec,
		(unsigned long long)time(NULL)));
	TALLOC_FREE(state);
	exit(0);
}

/*
  pre-open the key databases. This saves a lot of time in child
  processes
 */
static void prime_ldb_databases(struct tevent_context *event_ctx)
{
	TALLOC_CTX *db_context;
	db_context = talloc_new(event_ctx);

	samdb_connect(db_context,
			event_ctx,
			cmdline_lp_ctx,
			system_session(cmdline_lp_ctx),
			0);
	privilege_connect(db_context, cmdline_lp_ctx);

	/* we deliberately leave these open, which allows them to be
	 * re-used in ldb_wrap_connect() */
}


/*
  called when a fatal condition occurs in a child task
 */
static NTSTATUS samba_terminate(struct irpc_message *msg,
				struct samba_terminate *r)
{
	struct server_state *state = talloc_get_type(msg->private_data,
					struct server_state);
	DBG_ERR("samba_terminate of %s %d: %s\n",
		state->binary_name, (int)getpid(), r->in.reason);
	TALLOC_FREE(state);
	exit(1);
}

/*
  setup messaging for the top level samba (parent) task
 */
static NTSTATUS setup_parent_messaging(struct server_state *state,
				       struct loadparm_context *lp_ctx)
{
	struct imessaging_context *msg;
	NTSTATUS status;

	msg = imessaging_init(state->event_ctx,
			      lp_ctx,
			      cluster_id(0, SAMBA_PARENT_TASKID),
			      state->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	status = irpc_add_name(msg, "samba");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = IRPC_REGISTER(msg, irpc, SAMBA_TERMINATE,
			       samba_terminate, state);

	return status;
}


/*
  show build info
 */
static void show_build(void)
{
#define CONFIG_OPTION(n) { #n, dyn_ ## n }
	struct {
		const char *name;
		const char *value;
	} config_options[] = {
		CONFIG_OPTION(BINDIR),
		CONFIG_OPTION(SBINDIR),
		CONFIG_OPTION(CONFIGFILE),
		CONFIG_OPTION(NCALRPCDIR),
		CONFIG_OPTION(LOGFILEBASE),
		CONFIG_OPTION(LMHOSTSFILE),
		CONFIG_OPTION(DATADIR),
		CONFIG_OPTION(MODULESDIR),
		CONFIG_OPTION(LOCKDIR),
		CONFIG_OPTION(STATEDIR),
		CONFIG_OPTION(CACHEDIR),
		CONFIG_OPTION(PIDDIR),
		CONFIG_OPTION(PRIVATE_DIR),
		CONFIG_OPTION(CODEPAGEDIR),
		CONFIG_OPTION(SETUPDIR),
		CONFIG_OPTION(WINBINDD_SOCKET_DIR),
		CONFIG_OPTION(NTP_SIGND_SOCKET_DIR),
		{ NULL, NULL}
	};
	int i;

	printf("Samba version: %s\n", SAMBA_VERSION_STRING);
	printf("Build environment:\n");
#ifdef BUILD_SYSTEM
	printf("   Build host:  %s\n", BUILD_SYSTEM);
#endif

	printf("Paths:\n");
	for (i=0; config_options[i].name; i++) {
		printf("   %s: %s\n",
			config_options[i].name,
			config_options[i].value);
	}

	exit(0);
}

static int event_ctx_destructor(struct tevent_context *event_ctx)
{
	imessaging_dgm_unref_ev(event_ctx);
	return 0;
}

/*
 main server.
*/
static int binary_smbd_main(const char *binary_name,
				int argc,
				const char *argv[])
{
	bool opt_daemon = false;
	bool opt_fork = true;
	bool opt_interactive = false;
	bool opt_no_process_group = false;
	int opt;
	poptContext pc;
#define _MODULE_PROTO(init) extern NTSTATUS init(TALLOC_CTX *);
	STATIC_service_MODULES_PROTO;
	init_module_fn static_init[] = { STATIC_service_MODULES };
	init_module_fn *shared_init;
	uint16_t stdin_event_flags;
	NTSTATUS status;
	const char *model = "standard";
	int max_runtime = 0;
	struct stat st;
	enum {
		OPT_DAEMON = 1000,
		OPT_FOREGROUND,
		OPT_INTERACTIVE,
		OPT_PROCESS_MODEL,
		OPT_SHOW_BUILD,
		OPT_NO_PROCESS_GROUP,
	};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"daemon", 'D', POPT_ARG_NONE, NULL, OPT_DAEMON,
		 "Become a daemon (default)", NULL },
		{"foreground", 'F', POPT_ARG_NONE, NULL, OPT_FOREGROUND,
		 "Run the daemon in foreground", NULL },
		{"interactive",	'i', POPT_ARG_NONE, NULL, OPT_INTERACTIVE,
		 "Run interactive (not a daemon)", NULL},
		{"model", 'M', POPT_ARG_STRING,	NULL, OPT_PROCESS_MODEL,
		 "Select process model", "MODEL"},
		{"maximum-runtime",0, POPT_ARG_INT, &max_runtime, 0,
		 "set maximum runtime of the server process, "
			"till autotermination", "seconds"},
		{"show-build", 'b', POPT_ARG_NONE, NULL, OPT_SHOW_BUILD,
			"show build info", NULL },
		{"no-process-group", '\0', POPT_ARG_NONE, NULL,
		  OPT_NO_PROCESS_GROUP, "Don't create a new process group" },
		POPT_COMMON_SAMBA
		POPT_COMMON_VERSION
		{ NULL }
	};
	struct server_state *state = NULL;
	struct tevent_signal *se = NULL;

	pc = poptGetContext(binary_name, argc, argv, long_options, 0);
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		case OPT_DAEMON:
			opt_daemon = true;
			break;
		case OPT_FOREGROUND:
			opt_fork = false;
			break;
		case OPT_INTERACTIVE:
			opt_interactive = true;
			break;
		case OPT_PROCESS_MODEL:
			model = poptGetOptArg(pc);
			break;
		case OPT_SHOW_BUILD:
			show_build();
			break;
		case OPT_NO_PROCESS_GROUP:
			opt_no_process_group = true;
			break;
		default:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				  poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			return 1;
		}
	}

	if (opt_daemon && opt_interactive) {
		fprintf(stderr,"\nERROR: "
			"Option -i|--interactive is "
			"not allowed together with -D|--daemon\n\n");
		poptPrintUsage(pc, stderr, 0);
		return 1;
	} else if (!opt_interactive && opt_fork) {
		/* default is --daemon */
		opt_daemon = true;
	}

	poptFreeContext(pc);

	talloc_enable_null_tracking();

	setup_logging(binary_name, opt_interactive?DEBUG_STDOUT:DEBUG_FILE);
	setup_signals();

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	DEBUG(0,("%s version %s started.\n",
		binary_name,
		SAMBA_VERSION_STRING));
	DEBUGADD(0,("Copyright Andrew Tridgell and the Samba Team"
		" 1992-2017\n"));

	if (sizeof(uint16_t) < 2 ||
			sizeof(uint32_t) < 4 ||
			sizeof(uint64_t) < 8) {
		DEBUG(0,("ERROR: Samba is not configured correctly "
			"for the word size on your machine\n"));
		DEBUGADD(0,("sizeof(uint16_t) = %u, sizeof(uint32_t) %u, "
			"sizeof(uint64_t) = %u\n",
			(unsigned int)sizeof(uint16_t),
			(unsigned int)sizeof(uint32_t),
			(unsigned int)sizeof(uint64_t)));
		return 1;
	}

	if (opt_daemon) {
		DBG_NOTICE("Becoming a daemon.\n");
		become_daemon(opt_fork, opt_no_process_group, false);
	}

	/* Create the memory context to hang everything off. */
	state = talloc_zero(NULL, struct server_state);
	if (state == NULL) {
		exit_daemon("Samba cannot create server state", ENOMEM);
	};
	state->binary_name = binary_name;

	cleanup_tmp_files(cmdline_lp_ctx);

	if (!directory_exist(lpcfg_lock_directory(cmdline_lp_ctx))) {
		mkdir(lpcfg_lock_directory(cmdline_lp_ctx), 0755);
	}

	pidfile_create(lpcfg_pid_directory(cmdline_lp_ctx), binary_name);

	if (lpcfg_server_role(cmdline_lp_ctx) == ROLE_ACTIVE_DIRECTORY_DC) {
		if (!open_schannel_session_store(state,
				cmdline_lp_ctx)) {
			TALLOC_FREE(state);
			exit_daemon("Samba cannot open schannel store "
				"for secured NETLOGON operations.", EACCES);
		}
	}

	/* make sure we won't go through nss_winbind */
	if (!winbind_off()) {
		TALLOC_FREE(state);
		exit_daemon("Samba failed to disable recusive "
			"winbindd calls.", EACCES);
	}

	gensec_init(); /* FIXME: */

	process_model_init(cmdline_lp_ctx);

	shared_init = load_samba_modules(NULL, "service");

	run_init_functions(NULL, static_init);
	run_init_functions(NULL, shared_init);

	talloc_free(shared_init);

	/* the event context is the top level structure in smbd. Everything else
	   should hang off that */
	state->event_ctx = s4_event_context_init(state);

	if (state->event_ctx == NULL) {
		TALLOC_FREE(state);
		exit_daemon("Initializing event context failed", EACCES);
	}

	talloc_set_destructor(state->event_ctx, event_ctx_destructor);

	if (opt_interactive) {
		/* terminate when stdin goes away */
		stdin_event_flags = TEVENT_FD_READ;
	} else {
		/* stay alive forever */
		stdin_event_flags = 0;
	}

#if HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management, unless --no-process-group specified.
	 */
	if (opt_interactive && !opt_no_process_group)
		setpgid((pid_t)0, (pid_t)0);
#endif

	/* catch EOF on stdin */
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif

	if (fstat(0, &st) != 0) {
		TALLOC_FREE(state);
		exit_daemon("Samba failed to set standard input handler",
				ENOTTY);
	}

	if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
		struct tevent_fd *fde = tevent_add_fd(state->event_ctx,
				state->event_ctx,
				0,
				stdin_event_flags,
				server_stdin_handler,
				state);
		if (fde == NULL) {
			TALLOC_FREE(state);
			exit_daemon("Initializing stdin failed", ENOMEM);
		}
	}

	if (max_runtime) {
		struct tevent_timer *te;
		DEBUG(0,("%s PID %d was called with maxruntime %d - "
			"current ts %llu\n",
			binary_name, (int)getpid(),
			max_runtime, (unsigned long long) time(NULL)));
		te = tevent_add_timer(state->event_ctx, state->event_ctx,
				 timeval_current_ofs(max_runtime, 0),
				 max_runtime_handler,
				 state);
		if (te == NULL) {
			TALLOC_FREE(state);
			exit_daemon("Maxruntime handler failed", ENOMEM);
		}
	}

	se = tevent_add_signal(state->event_ctx,
				state->event_ctx,
				SIGTERM,
				0,
				sigterm_signal_handler,
				state);
	if (se == NULL) {
		TALLOC_FREE(state);
		exit_daemon("Initialize SIGTERM handler failed", ENOMEM);
	}

	if (lpcfg_server_role(cmdline_lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC
	    && !lpcfg_parm_bool(cmdline_lp_ctx, NULL,
			"server role check", "inhibit", false)
	    && !str_list_check_ci(lpcfg_server_services(cmdline_lp_ctx), "smb")
	    && !str_list_check_ci(lpcfg_dcerpc_endpoint_servers(cmdline_lp_ctx),
			"remote")
	    && !str_list_check_ci(lpcfg_dcerpc_endpoint_servers(cmdline_lp_ctx),
			"mapiproxy")) {
		DEBUG(0, ("At this time the 'samba' binary should only be used "
			"for either:\n"));
		DEBUGADD(0, ("'server role = active directory domain "
			"controller' or to access the ntvfs file server "
			"with 'server services = +smb' or the rpc proxy "
			"with 'dcerpc endpoint servers = remote'\n"));
		DEBUGADD(0, ("You should start smbd/nmbd/winbindd instead for "
			"domain member and standalone file server tasks\n"));
		exit_daemon("Samba detected misconfigured 'server role' "
			"and exited. Check logs for details", EINVAL);
	};

	prime_ldb_databases(state->event_ctx);

	status = setup_parent_messaging(state, cmdline_lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(state);
		exit_daemon("Samba failed to setup parent messaging",
			NT_STATUS_V(status));
	}

	DEBUG(0,("%s: using '%s' process model\n", binary_name, model));

	status = server_service_startup(state->event_ctx, cmdline_lp_ctx, model,
					lpcfg_server_services(cmdline_lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(state);
		exit_daemon("Samba failed to start services",
			NT_STATUS_V(status));
	}

	if (opt_daemon) {
		daemon_ready("samba");
	}

	/* wait for events - this is where smbd sits for most of its
	   life */
	tevent_loop_wait(state->event_ctx);

	/* as everything hangs off this state->event context, freeing state
	   will initiate a clean shutdown of all services */
	TALLOC_FREE(state);

	return 0;
}

int main(int argc, const char *argv[])
{
	return binary_smbd_main("samba", argc, argv);
}
