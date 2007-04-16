/* 
   Unix SMB/CIFS implementation.

   Main SMB server routines

   Copyright (C) Andrew Tridgell		1992-2005
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002
   Copyright (C) James J Myers 			2003 <myersjj@samba.org>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "version.h"
#include "lib/cmdline/popt_common.h"
#include "system/dir.h"
#include "system/filesys.h"
#include "build.h"
#include "ldb/include/ldb.h"
#include "registry/registry.h"
#include "ntvfs/ntvfs.h"
#include "ntptr/ntptr.h"
#include "auth/gensec/gensec.h"
#include "smbd/process_model.h"
#include "smbd/service.h"
#include "param/secrets.h"
#include "smbd/pidfile.h"
#include "cluster/ctdb/ctdb_cluster.h"

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
static void cleanup_tmp_files(void)
{
	char *path;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	path = smbd_tmp_path(mem_ctx, NULL);

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
	static int done_sigterm;
	if (done_sigterm == 0 && getpgrp() == getpid()) {
		DEBUG(0,("SIGTERM: killing children\n"));
		done_sigterm = 1;
		kill(-getpgrp(), SIGTERM);
	}
#endif
	exit(0);
}

/*
  setup signal masks
*/
static void setup_signals(void)
{
	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif

	/* We are no longer interested in USR1 */
	BlockSignals(True, SIGUSR1);

#if defined(SIGUSR2)
	/* We are no longer interested in USR2 */
	BlockSignals(True,SIGUSR2);
#endif

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems, as we won't recieve them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGTERM);

	CatchSignal(SIGHUP, sig_hup);
	CatchSignal(SIGTERM, sig_term);
}

/*
  handle io on stdin
*/
static void server_stdin_handler(struct event_context *event_ctx, struct fd_event *fde, 
				 uint16_t flags, void *private)
{
	const char *binary_name = private;
	uint8_t c;
	if (read(0, &c, 1) == 0) {
		DEBUG(0,("%s: EOF on stdin - terminating\n", binary_name));
#if HAVE_GETPGRP
		if (getpgrp() == getpid()) {
			kill(-getpgrp(), SIGTERM);
		}
#endif
		exit(0);
	}
}

/*
  die if the user selected maximum runtime is exceeded
*/
static void max_runtime_handler(struct event_context *ev, struct timed_event *te, 
				struct timeval t, void *private)
{
	const char *binary_name = private;
	DEBUG(0,("%s: maximum runtime exceeded - terminating\n", binary_name));
	exit(0);
}

/*
 main server.
*/
static int binary_smbd_main(const char *binary_name, int argc, const char *argv[])
{
	BOOL interactive = False;
	int opt;
	poptContext pc;
	init_module_fn static_init[] = STATIC_service_MODULES;
	init_module_fn *shared_init;
	struct event_context *event_ctx;
	NTSTATUS status;
	const char *model = "standard";
	int max_runtime = 0;
	enum {
		OPT_INTERACTIVE		= 1000,
		OPT_PROCESS_MODEL
	};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"interactive",	'i', POPT_ARG_NONE, NULL, OPT_INTERACTIVE,
		 "Run interactive (not a daemon)", NULL},
		{"model", 'M', POPT_ARG_STRING,	NULL, OPT_PROCESS_MODEL, 
		 "Select process model", "MODEL"},
		{"maximum-runtime",0, POPT_ARG_INT, &max_runtime, 0, 
		 "set maximum runtime of the server process, till autotermination", "seconds"},
		POPT_COMMON_SAMBA
		POPT_COMMON_VERSION
		{ NULL }
	};

	pc = poptGetContext(binary_name, argc, argv, long_options, 0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		case OPT_INTERACTIVE:
			interactive = True;
			break;
		case OPT_PROCESS_MODEL:
			model = poptGetOptArg(pc);
			break;
		}
	}
	poptFreeContext(pc);

	setup_logging(binary_name, interactive?DEBUG_STDOUT:DEBUG_FILE);
	setup_signals();

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	DEBUG(0,("%s version %s started.\n", binary_name, SAMBA_VERSION_STRING));
	DEBUGADD(0,("Copyright Andrew Tridgell and the Samba Team 1992-2007\n"));

	if (sizeof(uint16_t) < 2 || sizeof(uint32_t) < 4 || sizeof(uint64_t) < 8) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	if (!interactive) {
		DEBUG(3,("Becoming a daemon.\n"));
		become_daemon(True);
	}

	cleanup_tmp_files();

	if (!directory_exist(lp_lockdir())) {
		mkdir(lp_lockdir(), 0755);
	}

	pidfile_create(binary_name);

	/* Do *not* remove this, until you have removed
	 * passdb/secrets.c, and proved that Samba still builds... */
	/* Setup the SECRETS subsystem */
	if (!secrets_init()) {
		exit(1);
	}

	ldb_global_init(); /* FIXME: */

	share_init();

	gensec_init(); /* FIXME: */

	registry_init(); /* FIXME: maybe run this in the initialization function 
						of the winreg RPC server instead? */

	ntptr_init();	/* FIXME: maybe run this in the initialization function 
						of the spoolss RPC server instead? */

	ntvfs_init(); 	/* FIXME: maybe run this in the initialization functions 
						of the SMB[,2] server instead? */

	process_model_init(); 

	shared_init = load_samba_modules(NULL, "service");

	run_init_functions(static_init);
	run_init_functions(shared_init);

	talloc_free(shared_init);
	
	/* the event context is the top level structure in smbd. Everything else
	   should hang off that */
	event_ctx = event_context_init(NULL);

	/* initialise clustering if needed */
	cluster_ctdb_init(event_ctx, model);

	if (interactive) {
		/* catch EOF on stdin */
#ifdef SIGTTIN
		signal(SIGTTIN, SIG_IGN);
#endif
		event_add_fd(event_ctx, event_ctx, 0, EVENT_FD_READ, 
			     server_stdin_handler,
			     discard_const(binary_name));
	}


	if (max_runtime) {
		event_add_timed(event_ctx, event_ctx, 
				timeval_current_ofs(max_runtime, 0), 
				max_runtime_handler,
				discard_const(binary_name));
	}

	DEBUG(0,("%s: using '%s' process model\n", binary_name, model));
	status = server_service_startup(event_ctx, model, lp_server_services());
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Starting Services failed - %s\n", nt_errstr(status)));
		return 1;
	}

	/* wait for events - this is where smbd sits for most of its
	   life */
	event_loop_wait(event_ctx);

	/* as everything hangs off this event context, freeing it
	   should initiate a clean shutdown of all services */
	talloc_free(event_ctx);

	return 0;
}

 int main(int argc, const char *argv[])
{
	return binary_smbd_main("smbd", argc, argv);
}
