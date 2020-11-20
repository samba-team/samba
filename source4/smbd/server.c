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
#include "lib/util/tfork.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/util/server_id.h"
#include "server_util.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

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
			DBG_ERR("Unabled to delete '%s' - %s\n",
				 fname, strerror(errno));
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
#ifdef HAVE_GETPGRP
	if (getpgrp() == getpid()) {
		/*
		 * We're the process group leader, send
		 * SIGTERM to our process group.
		 */
		kill(-getpgrp(), SIGTERM);
	}
#endif
	_exit(127);
}

static void sigterm_signal_handler(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum, int count, void *siginfo,
				void *private_data)
{
	struct server_state *state = talloc_get_type_abort(
                private_data, struct server_state);

	DBG_DEBUG("Process %s got SIGTERM\n", state->binary_name);
	TALLOC_FREE(state);
	sig_term(SIGTERM);
}

static void sighup_signal_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum, int count, void *siginfo,
				  void *private_data)
{
	struct server_state *state = talloc_get_type_abort(
                private_data, struct server_state);

	DBG_DEBUG("Process %s got SIGHUP\n", state->binary_name);

	reopen_logs_internal();
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
		DBG_ERR("%s: EOF on stdin - PID %d terminating\n",
			state->binary_name, (int)getpid());
#ifdef HAVE_GETPGRP
		if (getpgrp() == getpid()) {
			DBG_ERR("Sending SIGTERM from pid %d\n",
				(int)getpid());
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
	DBG_ERR("%s: maximum runtime exceeded - "
		"terminating PID %d at %llu, current ts: %llu\n",
		 state->binary_name,
		(int)getpid(),
		(unsigned long long)t.tv_sec,
		(unsigned long long)time(NULL));
	TALLOC_FREE(state);
	exit(0);
}

/*
 * When doing an in-place upgrade of Samba, the database format may have
 * changed between versions. E.g. between 4.7 and 4.8 the DB changed from
 * DN-based indexes to GUID-based indexes, so we have to re-index the DB after
 * upgrading.
 * This function handles migrating an older samba DB to a new Samba release.
 * Note that we have to maintain DB compatibility between *all* older versions
 * of Samba, not just the ones still under maintenance support.
 */
static int handle_inplace_db_upgrade(struct ldb_context *ldb_ctx)
{
	int ret;

	/*
	 * The DSDB stack will handle reindexing the DB (if needed) upon the first
	 * DB write. Open and close a transaction on the DB now to trigger a
	 * reindex if required, rather than waiting for the first write.
	 * We do this here to guarantee that the DB will have been re-indexed by
	 * the time the main samba code runs.
	 * Refer to dsdb_schema_set_indices_and_attributes() for the actual reindexing
	 * code, called from
	 * source4/dsdb/samdb/ldb_modules/schema_load.c:schema_load_start_transaction()
	 */
	ret = ldb_transaction_start(ldb_ctx);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_transaction_commit(ldb_ctx);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return LDB_SUCCESS;
}

/*
  pre-open the key databases. This saves a lot of time in child
  processes
 */
static int prime_ldb_databases(struct tevent_context *event_ctx, bool *am_backup)
{
	struct ldb_result *res = NULL;
	struct ldb_dn *samba_dsdb_dn = NULL;
	struct ldb_context *ldb_ctx = NULL;
	struct ldb_context *pdb = NULL;
	static const char *attrs[] = { "backupDate", NULL };
	const char *msg = NULL;
	int ret;
	TALLOC_CTX *db_context = talloc_new(event_ctx);
	if (db_context == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*am_backup = false;

	/* note we deliberately leave these open, which allows them to be
	 * re-used in ldb_wrap_connect() */
	ldb_ctx = samdb_connect(db_context,
				event_ctx,
				cmdline_lp_ctx,
				system_session(cmdline_lp_ctx),
				NULL,
				0);
	if (ldb_ctx == NULL) {
		talloc_free(db_context);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = handle_inplace_db_upgrade(ldb_ctx);
	if (ret != LDB_SUCCESS) {
		talloc_free(db_context);
		return ret;
	}

	pdb = privilege_connect(db_context, cmdline_lp_ctx);
	if (pdb == NULL) {
		talloc_free(db_context);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* check the root DB object to see if it's marked as a backup */
	samba_dsdb_dn = ldb_dn_new(db_context, ldb_ctx, "@SAMBA_DSDB");
	if (!samba_dsdb_dn) {
		talloc_free(db_context);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = dsdb_search_dn(ldb_ctx, db_context, &res, samba_dsdb_dn, attrs,
			     DSDB_FLAG_AS_SYSTEM);
	if (ret != LDB_SUCCESS) {
		talloc_free(db_context);
		return ret;
	}

	if (res->count > 0) {
		msg = ldb_msg_find_attr_as_string(res->msgs[0], "backupDate",
						  NULL);
		if (msg != NULL) {
			*am_backup = true;
		}
	}
	return LDB_SUCCESS;
}

/*
  called from 'smbcontrol samba shutdown'
 */
static void samba_parent_shutdown(struct imessaging_context *msg,
				  void *private_data,
				  uint32_t msg_type,
				  struct server_id src,
				  size_t num_fds,
				  int *fds,
				  DATA_BLOB *data)
{
	struct server_state *state =
		talloc_get_type_abort(private_data,
		struct server_state);
	struct server_id_buf src_buf;
	struct server_id dst = imessaging_get_server_id(msg);
	struct server_id_buf dst_buf;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	DBG_ERR("samba_shutdown of %s %s: from %s\n",
		state->binary_name,
		server_id_str_buf(dst, &dst_buf),
		server_id_str_buf(src, &src_buf));

	TALLOC_FREE(state);
	exit(0);
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
	if (state == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	msg = imessaging_init(state->event_ctx,
			      lp_ctx,
			      cluster_id(getpid(), SAMBA_PARENT_TASKID),
			      state->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(msg);

	status = irpc_add_name(msg, "samba");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = imessaging_register(msg, state, MSG_SHUTDOWN,
				     samba_parent_shutdown);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = IRPC_REGISTER(msg, irpc, SAMBA_TERMINATE,
			       samba_terminate, state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
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

#ifdef HAVE_PTHREAD
static int to_children_fd = -1;
static void atfork_prepare(void) {
}
static void atfork_parent(void) {
}
static void atfork_child(void) {
	if (to_children_fd != -1) {
		close(to_children_fd);
		to_children_fd = -1;
	}
}
#endif

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
	bool db_is_backup = false;
	int opt;
	int ret;
	poptContext pc;
#define _MODULE_PROTO(init) extern NTSTATUS init(TALLOC_CTX *);
	STATIC_service_MODULES_PROTO;
	init_module_fn static_init[] = { STATIC_service_MODULES };
	init_module_fn *shared_init;
	uint16_t stdin_event_flags;
	NTSTATUS status;
	const char *model = "prefork";
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
		{
			.longName   = "daemon",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_DAEMON,
			.descrip    = "Become a daemon (default)",
		},
		{
			.longName   = "foreground",
			.shortName  = 'F',
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_FOREGROUND,
			.descrip    = "Run the daemon in foreground",
		},
		{
			.longName   = "interactive",
			.shortName  = 'i',
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_INTERACTIVE,
			.descrip    = "Run interactive (not a daemon)",
		},
		{
			.longName   = "model",
			.shortName  = 'M',
			.argInfo    = POPT_ARG_STRING,
			.val        = OPT_PROCESS_MODEL,
			.descrip    = "Select process model",
			.argDescrip = "MODEL",
		},
		{
			.longName   = "maximum-runtime",
			.argInfo    = POPT_ARG_INT,
			.arg        = &max_runtime,
			.descrip    = "set maximum runtime of the server process, "
			              "till autotermination",
			.argDescrip = "seconds"
		},
		{
			.longName   = "show-build",
			.shortName  = 'b',
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_SHOW_BUILD,
			.descrip    = "show build info",
		},
		{
			.longName   = "no-process-group",
			.argInfo    = POPT_ARG_NONE,
			.val        = OPT_NO_PROCESS_GROUP,
			.descrip    = "Don't create a new process group",
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};
	struct server_state *state = NULL;
	struct tevent_signal *se = NULL;
	struct samba_tevent_trace_state *samba_tevent_trace_state = NULL;

	setproctitle("root process");

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
		" 1992-2020\n"));

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
	} else if (!opt_interactive) {
		daemon_status("samba", "Starting process...");
	}

	/* Create the memory context to hang everything off. */
	state = talloc_zero(NULL, struct server_state);
	if (state == NULL) {
		exit_daemon("Samba cannot create server state", ENOMEM);
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
	};
	state->binary_name = binary_name;

	cleanup_tmp_files(cmdline_lp_ctx);

	if (!directory_exist(lpcfg_lock_directory(cmdline_lp_ctx))) {
		mkdir(lpcfg_lock_directory(cmdline_lp_ctx), 0755);
	}

	if (!directory_exist(lpcfg_pid_directory(cmdline_lp_ctx))) {
		mkdir(lpcfg_pid_directory(cmdline_lp_ctx), 0755);
	}

	pidfile_create(lpcfg_pid_directory(cmdline_lp_ctx), binary_name);

	if (lpcfg_server_role(cmdline_lp_ctx) == ROLE_ACTIVE_DIRECTORY_DC) {
		if (!open_schannel_session_store(state,
				cmdline_lp_ctx)) {
			TALLOC_FREE(state);
			exit_daemon("Samba cannot open schannel store "
				"for secured NETLOGON operations.", EACCES);
			/*
			 * return is never reached but is here to satisfy static
			 * checkers
			 */
			return 1;
		}
	}

	/* make sure we won't go through nss_winbind */
	if (!winbind_off()) {
		TALLOC_FREE(state);
		exit_daemon("Samba failed to disable recusive "
			"winbindd calls.", EACCES);
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
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
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
	}

	talloc_set_destructor(state->event_ctx, event_ctx_destructor);

	samba_tevent_trace_state = create_samba_tevent_trace_state(state);
	if (samba_tevent_trace_state == NULL) {
		exit_daemon("Samba failed to setup tevent tracing state",
			    ENOTTY);
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
	}

	tevent_set_trace_callback(state->event_ctx,
				  samba_tevent_trace_callback,
				  samba_tevent_trace_state);

	if (opt_interactive) {
		/* terminate when stdin goes away */
		stdin_event_flags = TEVENT_FD_READ;
	} else {
		/* stay alive forever */
		stdin_event_flags = 0;
	}

#ifdef HAVE_SETPGID
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
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
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
			/*
			 * return is never reached but is here to
			 * satisfy static checkers
			 */
			return 1;
		}
	}

	if (max_runtime) {
		struct tevent_timer *te;
		DBG_ERR("%s PID %d was called with maxruntime %d - "
			"current ts %llu\n",
			binary_name, (int)getpid(),
			max_runtime, (unsigned long long) time(NULL));
		te = tevent_add_timer(state->event_ctx, state->event_ctx,
				 timeval_current_ofs(max_runtime, 0),
				 max_runtime_handler,
				 state);
		if (te == NULL) {
			TALLOC_FREE(state);
			exit_daemon("Maxruntime handler failed", ENOMEM);
			/*
			 * return is never reached but is here to
			 * satisfy static checkers
			 */
			return 1;
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
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
	}

	se = tevent_add_signal(state->event_ctx,
				state->event_ctx,
				SIGHUP,
				0,
				sighup_signal_handler,
				state);
	if (se == NULL) {
		TALLOC_FREE(state);
		exit_daemon("Initialize SIGHUP handler failed", ENOMEM);
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
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

	ret = prime_ldb_databases(state->event_ctx, &db_is_backup);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(state);
		exit_daemon("Samba failed to prime database", EINVAL);
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
	}

	if (db_is_backup) {
		TALLOC_FREE(state);
		exit_daemon("Database is a backup. Please run samba-tool domain"
			    " backup restore", EINVAL);
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
	}

	status = setup_parent_messaging(state, cmdline_lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(state);
		exit_daemon("Samba failed to setup parent messaging",
			NT_STATUS_V(status));
		/*
		 * return is never reached but is here to satisfy static
		 * checkers
		 */
		return 1;
	}

	DBG_ERR("%s: using '%s' process model\n", binary_name, model);

	{
		int child_pipe[2];
		int rc;
		bool start_services = false;

		rc = pipe(child_pipe);
		if (rc < 0) {
			TALLOC_FREE(state);
			exit_daemon("Samba failed to open process control pipe",
				    errno);
			/*
			 * return is never reached but is here to satisfy static
			 * checkers
			 */
			return 1;
		}
		smb_set_close_on_exec(child_pipe[0]);
		smb_set_close_on_exec(child_pipe[1]);

#ifdef HAVE_PTHREAD
		to_children_fd = child_pipe[1];
		pthread_atfork(atfork_prepare, atfork_parent,
			       atfork_child);
		start_services = true;
#else
		pid_t pid;
		struct tfork *t = NULL;
		t = tfork_create();
		if (t == NULL) {
			exit_daemon(
				"Samba unable to fork master process",
				0);
		}
		pid = tfork_child_pid(t);
		if (pid == 0) {
			start_services = false;
		} else {
			/* In the child process */
			start_services = true;
			close(child_pipe[1]);
		}
#endif
		if (start_services) {
			status = server_service_startup(
				state->event_ctx, cmdline_lp_ctx, model,
				lpcfg_server_services(cmdline_lp_ctx),
				child_pipe[0]);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(state);
				exit_daemon("Samba failed to start services",
				NT_STATUS_V(status));
				/*
				 * return is never reached but is here to
				 * satisfy static checkers
				 */
				return 1;
			}
		}
	}

	if (!opt_interactive) {
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
	setproctitle_init(argc, discard_const(argv), environ);

	return binary_smbd_main("samba", argc, argv);
}
