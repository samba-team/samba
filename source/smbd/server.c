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
#include "dynconfig.h"
#include "lib/cmdline/popt_common.h"
#include "system/dir.h"
#include "system/filesys.h"


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
	DIR *dir;
	struct dirent *de;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	path = smbd_tmp_path(mem_ctx, NULL);

	dir = opendir(path);
	if (!dir) {
		talloc_free(mem_ctx);
		return;
	}

	for (de=readdir(dir);de;de=readdir(dir)) {
		/*
		 * Don't try to delete . and ..
		 */
		if (strcmp(de->d_name, ".") != 0 &&
		    strcmp(de->d_name, "..") != 0) {
		    char *fname = talloc_asprintf(mem_ctx, "%s/%s", path, de->d_name);
		    int ret = unlink(fname);
		    if (ret == -1 &&
		        errno != ENOENT &&
			errno != EPERM &&
		        errno != EISDIR) {
			    DEBUG(0,("Unabled to delete '%s' - %s\n", 
				      fname, strerror(errno)));
			    smb_panic("unable to cleanup tmp files");
		    }
		    if (ret == -1 &&
			errno == EPERM) {
			/*
			 * If it is a dir, don't complain
			 * NOTE! The test will only happen if we have
			 * sys/stat.h, otherwise we will always error out
			 */
#ifdef HAVE_SYS_STAT_H
			struct stat sb;
			if (stat(fname, &sb) != -1 &&
			    !S_ISDIR(sb.st_mode))
#endif
			{
			     DEBUG(0,("Unable to delete '%s' - %s\n",
				      fname, strerror(errno)));
			     smb_panic("unable to cleanup tmp files");
			}
		    }
		    talloc_free(fname);
		}
	}
	closedir(dir);

	talloc_free(mem_ctx);
}

/*
  setup signal masks
*/
static void setup_signals(void)
{
	fault_setup(NULL);
	
	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif

#if defined(SIGUSR2)
	/* We are no longer interested in USR2 */
	BlockSignals(True,SIGUSR2);
#endif

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems, as we won't recieve them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGTERM);
}


/*
  handle io on stdin
*/
static void server_stdin_handler(struct event_context *event_ctx, struct fd_event *fde, 
				 uint16_t flags, void *private)
{
	uint8_t c;
	if (read(0, &c, 1) == 0) {
		DEBUG(0,("smbd: EOF on stdin - terminating\n"));
		exit(0);
	}
}

/*
 main server.
*/
static int binary_smbd_main(int argc, const char *argv[])
{
	BOOL interactive = False;
	int opt;
	poptContext pc;
	struct event_context *event_ctx;
	NTSTATUS status;
	const char *model = "standard";
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		{"interactive", 'i', POPT_ARG_VAL, &interactive, True, 
		 "Run interactive (not a daemon)", NULL},
		{"model", 'M', POPT_ARG_STRING, &model, True, 
		 "Select process model", "MODEL"},
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};
	
	pc = poptGetContext("smbd", argc, argv, long_options, 0);
	
	while((opt = poptGetNextOpt(pc)) != -1) /* noop */ ;

	poptFreeContext(pc);

	setup_logging(argv[0], interactive?DEBUG_STDOUT:DEBUG_FILE);
	setup_signals();

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	reopen_logs();

	DEBUG(0,("smbd version %s started.\n", SAMBA_VERSION_STRING));
	DEBUGADD(0,("Copyright Andrew Tridgell and the Samba Team 1992-2005\n"));

	if (sizeof(uint16_t) < 2 || sizeof(uint32_t) < 4 || sizeof(uint64_t) < 8) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	lp_load(dyn_CONFIGFILE, False, False, True);

	reopen_logs();
	load_interfaces();

	if (!interactive) {
		DEBUG(3,("Becoming a daemon.\n"));
		become_daemon(True);
	}

	cleanup_tmp_files();

	if (!directory_exist(lp_lockdir())) {
		mkdir(lp_lockdir(), 0755);
	}

	pidfile_create("smbd");

	/* Do *not* remove this, until you have removed
	 * passdb/secrets.c, and proved that Samba still builds... */
	/* Setup the SECRETS subsystem */
	if (!secrets_init()) {
		exit(1);
	}

	smbd_init_subsystems;

	/* the event context is the top level structure in smbd. Everything else
	   should hang off that */
	event_ctx = event_context_init(NULL);

	if (interactive) {
		/* catch EOF on stdin */
#ifdef SIGTTIN
		signal(SIGTTIN, SIG_IGN);
#endif
		event_add_fd(event_ctx, event_ctx, 0, EVENT_FD_READ, 
			     server_stdin_handler, NULL);
	}

	DEBUG(0,("Using %s process model\n", model));
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
	return binary_smbd_main(argc, argv);
}
