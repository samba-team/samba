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


/*
  called on a fatal error that should cause this server to terminate
*/
void exit_server(struct server_context *smb, const char *reason)
{
	smb->model_ops->terminate_connection(smb, reason);
}


/*
  setup a single listener of any type
 */
static void setup_listen(struct event_context *events,
			 const struct model_ops *model_ops, 
			 void (*accept_handler)(struct event_context *,struct fd_event *,time_t,uint16_t),
			 struct in_addr *ifip, uint_t port)
{
	struct fd_event fde;
	fde.fd = open_socket_in(SOCK_STREAM, port, 0, ifip->s_addr, True);
	if (fde.fd == -1) {
		DEBUG(0,("Failed to open socket on %s:%u - %s\n",
			 inet_ntoa(*ifip), port, strerror(errno)));
		return;
	}

	/* ready to listen */
	set_socket_options(fde.fd, "SO_KEEPALIVE"); 
	set_socket_options(fde.fd, lp_socket_options());
      
	if (listen(fde.fd, SMBD_LISTEN_BACKLOG) == -1) {
		DEBUG(0,("Failed to listen on %s:%d - %s\n",
			 inet_ntoa(*ifip), port, strerror(errno)));
		close(fde.fd);
		return;
	}

	/* we are only interested in read events on the listen socket */
	fde.flags = EVENT_FD_READ;
	fde.private = model_ops;
	fde.handler = accept_handler;
	
	event_add_fd(events, &fde);
}

/*
  add a socket address to the list of events, one event per port
*/
static void add_socket(struct event_context *events, 
		       const struct model_ops *model_ops, 
		       struct in_addr *ifip)
{
	char *ptr, *tok;
	const char *delim = ", ";

	for (tok=strtok_r(lp_smb_ports(), delim, &ptr); 
	     tok; 
	     tok=strtok_r(NULL, delim, &ptr)) {
		uint_t port = atoi(tok);
		if (port == 0) continue;
		setup_listen(events, model_ops, model_ops->accept_connection, ifip, port);
	}
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/
static void open_sockets_smbd(struct event_context *events,
			      const struct model_ops *model_ops)
{
	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);

			if (ifip == NULL) {
				DEBUG(0,("open_sockets_smbd: interface %d has NULL IP address !\n", i));
				continue;
			}

			add_socket(events, model_ops, ifip);
		}
	} else {
		TALLOC_CTX *mem_ctx = talloc_init("open_sockets_smbd");
		
		struct in_addr *ifip = interpret_addr2(mem_ctx, lp_socket_address());
		/* Just bind to lp_socket_address() (usually 0.0.0.0) */
		if (!mem_ctx) {
			smb_panic("No memory");
		}
		add_socket(events, model_ops, ifip);
		talloc_destroy(mem_ctx);
	} 
}

/****************************************************************************
 Reload the services file.
**************************************************************************/
BOOL reload_services(struct server_context *smb, BOOL test)
{
	BOOL ret;
	
	if (lp_loaded()) {
		pstring fname;
		pstrcpy(fname,lp_configfile());
		if (file_exist(fname, NULL) &&
		    !strcsequal(fname, dyn_CONFIGFILE)) {
			pstrcpy(dyn_CONFIGFILE, fname);
			test = False;
		}
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return(True);

	if (smb) {
		lp_killunused(smb, conn_snum_used);
	}
	
	ret = lp_load(dyn_CONFIGFILE, False, False, True);

	load_printers();

	/* perhaps the config filename is now set */
	if (!test)
		reload_services(smb, True);

	reopen_logs();

	load_interfaces();

	mangle_reset_cache();
	reset_stat_cache();

	/* this forces service parameters to be flushed */
	set_current_service(NULL,True);

	return(ret);
}

/****************************************************************************
 Initialise connect, service and file structs.
****************************************************************************/
static BOOL init_structs(void)
{
	init_names();
	file_init();
	secrets_init();

	/* we want to re-seed early to prevent time delays causing
           client problems at a later date. (tridge) */
	generate_random_buffer(NULL, 0, False);

	return True;
}


/*
  setup the events for the chosen process model
*/
static void setup_process_model(struct event_context *events, 
				const char *model)
{
	const struct model_ops *ops;

	ops = process_model_byname(model);
	if (!ops) {
		DEBUG(0,("Unknown process model '%s'\n", model));
		exit(-1);
	}

	ops->model_startup();

	/* now setup the listening sockets, adding 
	   event handlers to the events structure */
	open_sockets_smbd(events, ops);

	/* setup any sockets we need to listen on for RPC over TCP */
	open_sockets_rpc(events, ops);
}

/****************************************************************************
 main program.
****************************************************************************/
 int main(int argc,const char *argv[])
{
	BOOL is_daemon = False;
	BOOL interactive = False;
	BOOL Fork = True;
	BOOL log_stdout = False;
	int opt;
	poptContext pc;
	struct event_context *events;
	const char *model = "standard";
	struct poptOption long_options[] = {
		POPT_AUTOHELP
	{"daemon", 'D', POPT_ARG_VAL, &is_daemon, True, "Become a daemon (default)" },
	{"interactive", 'i', POPT_ARG_VAL, &interactive, True, "Run interactive (not a daemon)"},
	{"foreground", 'F', POPT_ARG_VAL, &Fork, False, "Run daemon in foreground (for daemontools & etc)" },
	{"log-stdout", 'S', POPT_ARG_VAL, &log_stdout, True, "Log to stdout" },
	{"build-options", 'b', POPT_ARG_NONE, NULL, 'b', "Print build options" },
	{"port", 'p', POPT_ARG_STRING, NULL, 0, "Listen on the specified ports"},
	{"model", 'M', POPT_ARG_STRING, &model, 0, "select process model"},
	POPT_COMMON_SAMBA
	{ NULL }
	};
	
	pc = poptGetContext("smbd", argc, argv, long_options, 0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt)  {
		case 'b':
			/* Display output to screen as well as debug */
			build_options(True); 
			exit(0);
			break;
		case 'p':
			lp_set_cmdline("smb ports", poptGetOptArg(pc));
			break;
		}
	}
	poptFreeContext(pc);

	events = event_context_init();

	load_case_tables();

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

	/* Output the build options to the debug log */ 
	build_options(False);

	if (sizeof(uint16_t) < 2 || sizeof(uint32_t) < 4) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}
	DEBUG(0,("Using %s process model\n", model));
			
	if (!reload_services(NULL, False))
		return(-1);	

	init_structs();

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

	register_msg_pool_usage();
	register_dmalloc_msgs();

	init_subsystems();

	setup_process_model(events, model);

	/* wait for events */
	return event_loop_wait(events);
}
