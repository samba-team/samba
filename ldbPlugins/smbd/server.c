/* 
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
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
#include "lib/cmdline/popt_common.h"

static void exit_server(const char *reason)
{
	DEBUG(3,("Server exit (%s)\n", (reason ? reason : "")));
	exit(0);
}

/****************************************************************************
 main server.
****************************************************************************/
static int binary_smbd_main(int argc,const char *argv[])
{
	BOOL is_daemon = False;
	BOOL interactive = False;
	BOOL Fork = True;
	BOOL log_stdout = False;
	int opt;
	poptContext pc;
	struct server_context *srv_ctx;
	const char *model = "standard";
	struct poptOption long_options[] = {
		POPT_AUTOHELP
	POPT_COMMON_SAMBA
	{"daemon", 'D', POPT_ARG_VAL, &is_daemon, True, "Become a daemon (default)" , NULL },
	{"interactive", 'i', POPT_ARG_VAL, &interactive, True, "Run interactive (not a daemon)", NULL},
	{"foreground", 'F', POPT_ARG_VAL, &Fork, True, "Run daemon in foreground (for daemontools & etc)" , NULL },
	{"log-stdout", 'S', POPT_ARG_VAL, &log_stdout, True, "Log to stdout", NULL },
	{"port", 'p', POPT_ARG_STRING, NULL, 0, "Listen on the specified ports", "PORTS"},
	{"model", 'M', POPT_ARG_STRING, &model, True, "Select process model", "MODEL"},
	POPT_TABLEEND
	};
	
	pc = poptGetContext("smbd", argc, argv, long_options, 0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt)  {
		case 'p':
			lp_set_cmdline("smb ports", poptGetOptArg(pc));
			break;
		}
	}
	poptFreeContext(pc);

	if (interactive) {
		Fork = False;
		log_stdout = True;
	}

	if (log_stdout && Fork) {
		DEBUG(0,("ERROR: Can't log to stdout (-S) unless daemon is in foreground (-F) or interactive (-i)\n"));
		exit(1);
	}
	setup_logging(argv[0], log_stdout?DEBUG_STDOUT:DEBUG_FILE);

	fault_setup((void (*)(void *))exit_server);
	
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

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	reopen_logs();

	DEBUG(0,("smbd version %s started.\n", SAMBA_VERSION_STRING));
	DEBUGADD(0,("Copyright Andrew Tridgell and the Samba Team 1992-2004\n"));

	if (sizeof(uint16_t) < 2 || sizeof(uint32_t) < 4 || sizeof(uint64_t) < 8) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	if (!reload_services(NULL, False))
		return(-1);	

	if (!is_daemon && !is_a_socket(0)) {
		if (!interactive)
			DEBUG(0,("standard input is not a socket, assuming -D option\n"));

		/*
		 * Setting is_daemon here prevents us from eventually calling
		 * the open_sockets_inetd()
		 */

		is_daemon = True;
	}

	if (is_daemon && !interactive) {
		DEBUG(3,("Becoming a daemon.\n"));
		become_daemon(Fork);
	}

	if (!directory_exist(lp_lockdir(), NULL)) {
		mkdir(lp_lockdir(), 0755);
	}

	if (is_daemon) {
		pidfile_create("smbd");
	}

	init_subsystems();

	DEBUG(0,("Using %s process model\n", model));
	srv_ctx = server_service_startup(model);
	if (!srv_ctx) {
		DEBUG(0,("Starting Services failed.\n"));
		return 1;
	}

	/* wait for events */
	return event_loop_wait(srv_ctx->events);
}

 int main(int argc, const char *argv[])
{
	return binary_smbd_main(argc, argv);
}
