/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) by Tim Potter 2000-2002
   Copyright (C) Andrew Tridgell 2002
   
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

#include "winbindd.h"

BOOL opt_nocache = False;
BOOL opt_dual_daemon = False;

/* Reload configuration */

static BOOL reload_services_file(BOOL test)
{
	BOOL ret;
	pstring logfile;

	if (lp_loaded()) {
		pstring fname;

		pstrcpy(fname,lp_configfile());
		if (file_exist(fname,NULL) && !strcsequal(fname,dyn_CONFIGFILE)) {
			pstrcpy(dyn_CONFIGFILE,fname);
			test = False;
		}
	}

	snprintf(logfile, sizeof(logfile), "%s/log.winbindd", dyn_LOGFILEBASE);
	lp_set_logfile(logfile);

	reopen_logs();
	ret = lp_load(dyn_CONFIGFILE,False,False,True);

	snprintf(logfile, sizeof(logfile), "%s/log.winbindd", dyn_LOGFILEBASE);
	lp_set_logfile(logfile);

	reopen_logs();
	load_interfaces();

	return(ret);
}

/*******************************************************************
 Print out all talloc memory info.
********************************************************************/

void return_all_talloc_info(int msg_type, pid_t src_pid, void *buf, size_t len)
{
	TALLOC_CTX *ctx = talloc_init("info context");
	char *info = NULL;

	if (!ctx)
		return;

	info = talloc_describe_all(ctx);
	if (info)
		DEBUG(10,(info));
	message_send_pid(src_pid, MSG_TALLOC_USAGE, info, info ? strlen(info) + 1: 0, True);
	talloc_destroy(ctx);
}

#if DUMP_CORE

/**************************************************************************** **
 Prepare to dump a core file - carefully!
 **************************************************************************** */

static BOOL dump_core(void)
{
	char *p;
	pstring dname;
	pstrcpy( dname, lp_logfile() );
	if ((p=strrchr(dname,'/')))
		*p=0;
	pstrcat( dname, "/corefiles" );
	mkdir( dname, 0700 );
	sys_chown( dname, getuid(), getgid() );
	chmod( dname, 0700 );
	if ( chdir(dname) )
		return( False );
	umask( ~(0700) );
 
#ifdef HAVE_GETRLIMIT
#ifdef RLIMIT_CORE
	{
		struct rlimit rlp;
		getrlimit( RLIMIT_CORE, &rlp );
		rlp.rlim_cur = MAX( 4*1024*1024, rlp.rlim_cur );
		setrlimit( RLIMIT_CORE, &rlp );
		getrlimit( RLIMIT_CORE, &rlp );
		DEBUG( 3, ( "Core limits now %d %d\n", (int)rlp.rlim_cur, (int)rlp.rlim_max ) );
	}
#endif
#endif
 
	DEBUG(0,("Dumping core in %s\n",dname));
	abort();
	return( True );
} /* dump_core */
#endif

/**************************************************************************** **
 Handle a fault..
 **************************************************************************** */

static void fault_quit(void)
{
#if DUMP_CORE
	dump_core();
#endif
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
			DEBUG(2, ("\t\tpid %d, sock %d, rbl %d, wbl %d\n",
				  tmp->pid, tmp->sock, tmp->read_buf_len, 
				  tmp->write_buf_len));
		}
	}
}

/* Print winbindd status to log file */

static void print_winbindd_status(void)
{
	winbindd_status();
	winbindd_idmap_status();
	winbindd_cm_status();
}

/* Flush client cache */

static void flush_caches(void)
{
	/* Clear cached user and group enumation info */	
	wcache_flush_cache();
}

/* Handle the signal by unlinking socket and exiting */

static void terminate(void)
{
	pstring path;

	winbindd_idmap_close();
	
	/* Remove socket file */
	snprintf(path, sizeof(path), "%s/%s", 
		 WINBINDD_SOCKET_DIR, WINBINDD_SOCKET_NAME);
	unlink(path);
	exit(0);
}

static BOOL do_sigterm;

static void termination_handler(int signum)
{
	do_sigterm = True;
	sys_select_signal();
}

static BOOL do_sigusr2;

static void sigusr2_handler(int signum)
{
	do_sigusr2 = True;
	sys_select_signal();
}

static BOOL do_sighup;

static void sighup_handler(int signum)
{
	do_sighup = True;
	sys_select_signal();
}

struct dispatch_table {
	enum winbindd_cmd cmd;
	enum winbindd_result (*fn)(struct winbindd_cli_state *state);
	const char *winbindd_cmd_name;
};

static struct dispatch_table dispatch_table[] = {
	
	/* User functions */

	{ WINBINDD_GETPWNAM, winbindd_getpwnam, "GETPWNAM" },
	{ WINBINDD_GETPWUID, winbindd_getpwuid, "GETPWUID" },

	{ WINBINDD_SETPWENT, winbindd_setpwent, "SETPWENT" },
	{ WINBINDD_ENDPWENT, winbindd_endpwent, "ENDPWENT" },
	{ WINBINDD_GETPWENT, winbindd_getpwent, "GETPWENT" },

	{ WINBINDD_GETGROUPS, winbindd_getgroups, "GETGROUPS" },

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

	/* Enumeration functions */

	{ WINBINDD_LIST_USERS, winbindd_list_users, "LIST_USERS" },
	{ WINBINDD_LIST_GROUPS, winbindd_list_groups, "LIST_GROUPS" },
	{ WINBINDD_LIST_TRUSTDOM, winbindd_list_trusted_domains, "LIST_TRUSTDOM" },
	{ WINBINDD_SHOW_SEQUENCE, winbindd_show_sequence, "SHOW_SEQUENCE" },

	/* SID related functions */

	{ WINBINDD_LOOKUPSID, winbindd_lookupsid, "LOOKUPSID" },
	{ WINBINDD_LOOKUPNAME, winbindd_lookupname, "LOOKUPNAME" },

	/* Lookup related functions */

	{ WINBINDD_SID_TO_UID, winbindd_sid_to_uid, "SID_TO_UID" },
	{ WINBINDD_SID_TO_GID, winbindd_sid_to_gid, "SID_TO_GID" },
	{ WINBINDD_GID_TO_SID, winbindd_gid_to_sid, "GID_TO_SID" },
	{ WINBINDD_UID_TO_SID, winbindd_uid_to_sid, "UID_TO_SID" },

	/* Miscellaneous */

	{ WINBINDD_CHECK_MACHACC, winbindd_check_machine_acct, "CHECK_MACHACC" },
	{ WINBINDD_PING, winbindd_ping, "PING" },
	{ WINBINDD_INFO, winbindd_info, "INFO" },
	{ WINBINDD_INTERFACE_VERSION, winbindd_interface_version, "INTERFACE_VERSION" },
	{ WINBINDD_DOMAIN_NAME, winbindd_domain_name, "DOMAIN_NAME" },
	{ WINBINDD_NETBIOS_NAME, winbindd_netbios_name, "NETBIOS_NAME" },

	/* WINS functions */

	{ WINBINDD_WINS_BYNAME, winbindd_wins_byname, "WINS_BYNAME" },
	{ WINBINDD_WINS_BYIP, winbindd_wins_byip, "WINS_BYIP" },

	/* End of list */

	{ WINBINDD_NUM_CMDS, NULL, "NONE" }
};

static void process_request(struct winbindd_cli_state *state)
{
	struct dispatch_table *table = dispatch_table;

	/* Free response data - we may be interrupted and receive another
	   command before being able to send this data off. */

	SAFE_FREE(state->response.extra_data);  

	ZERO_STRUCT(state->response);

	state->response.result = WINBINDD_ERROR;
	state->response.length = sizeof(struct winbindd_response);

	/* Process command */

	for (table = dispatch_table; table->fn; table++) {
		if (state->request.cmd == table->cmd) {
			DEBUG(10,("process_request: request fn %s\n", table->winbindd_cmd_name ));
			state->response.result = table->fn(state);
			break;
		}
	}

	if (!table->fn)
		DEBUG(10,("process_request: unknown request fn number %d\n", (int)state->request.cmd ));

	/* In case extra data pointer is NULL */

	if (!state->response.extra_data)
		state->response.length = sizeof(struct winbindd_response);
}

/* Process a new connection by adding it to the client connection list */

static void new_connection(int listen_sock)
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
	
	if ((state = (struct winbindd_cli_state *) 
             malloc(sizeof(*state))) == NULL)
		return;
	
	ZERO_STRUCTP(state);
	state->sock = sock;

	state->last_access = time(NULL);	

	/* Add to connection list */
	
	winbindd_add_client(state);
}

/* Remove a client connection from client connection list */

static void remove_client(struct winbindd_cli_state *state)
{
	/* It's a dead client - hold a funeral */
	
	if (state != NULL) {
		
		/* Close socket */
		
		close(state->sock);
		
		/* Free any getent state */
		
		free_getent_state(state->getpwent_state);
		free_getent_state(state->getgrent_state);
		
		/* We may have some extra data that was not freed if the
		   client was killed unexpectedly */

		SAFE_FREE(state->response.extra_data);
		
		/* Remove from list and free */
		
		winbindd_remove_client(state);
		SAFE_FREE(state);
	}
}


/* Shutdown client connection which has been idle for the longest time */

static BOOL remove_idle_client(void)
{
	struct winbindd_cli_state *state, *remove_state = NULL;
	time_t last_access = 0;
	int nidle = 0;

	for (state = winbindd_client_list(); state; state = state->next) {
		if (state->read_buf_len == 0 && state->write_buf_len == 0 &&
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

/* Process a complete received packet from a client */

void winbind_process_packet(struct winbindd_cli_state *state)
{
	/* Process request */
	
	/* Ensure null termination of entire request */
	state->request.null_term = '\0';

	state->pid = state->request.pid;
	
	process_request(state);

	/* Update client state */
	
	state->read_buf_len = 0;
	state->write_buf_len = sizeof(struct winbindd_response);

	/* we might need to send it to the dual daemon */
	if (opt_dual_daemon) {
		dual_send_request(state);
	}
}

/* Read some data from a client connection */

void winbind_client_read(struct winbindd_cli_state *state)
{
	int n;
    
	/* Read data */

	n = sys_read(state->sock, state->read_buf_len + 
		 (char *)&state->request, 
		 sizeof(state->request) - state->read_buf_len);
	
	DEBUG(10,("client_read: read %d bytes. Need %d more for a full request.\n", n, sizeof(state->request) - n - state->read_buf_len ));

	/* Read failed, kill client */
	
	if (n == -1 || n == 0) {
		DEBUG(5,("read failed on sock %d, pid %d: %s\n",
			 state->sock, state->pid, 
			 (n == -1) ? strerror(errno) : "EOF"));
		
		state->finished = True;
		return;
	}
	
	/* Update client state */
	
	state->read_buf_len += n;
	state->last_access = time(NULL);
}

/* Write some data to a client connection */

static void client_write(struct winbindd_cli_state *state)
{
	char *data;
	int num_written;
	
	/* Write some data */
	
	if (!state->write_extra_data) {

		/* Write response structure */
		
		data = (char *)&state->response + sizeof(state->response) - 
			state->write_buf_len;

	} else {

		/* Write extra data */
		
		data = (char *)state->response.extra_data + 
			state->response.length - 
			sizeof(struct winbindd_response) - 
			state->write_buf_len;
	}
	
	num_written = sys_write(state->sock, data, state->write_buf_len);
	
	DEBUG(10,("client_write: wrote %d bytes.\n", num_written ));

	/* Write failed, kill cilent */
	
	if (num_written == -1 || num_written == 0) {
		
		DEBUG(3,("write failed on sock %d, pid %d: %s\n",
			 state->sock, state->pid, 
			 (num_written == -1) ? strerror(errno) : "EOF"));
		
		state->finished = True;

		SAFE_FREE(state->response.extra_data);

		return;
	}
	
	/* Update client state */
	
	state->write_buf_len -= num_written;
	state->last_access = time(NULL);

	/* Have we written all data? */
	
	if (state->write_buf_len == 0) {
		
		/* Take care of extra data */
		
		if (state->write_extra_data) {

			SAFE_FREE(state->response.extra_data);

			state->write_extra_data = False;

			DEBUG(10,("client_write: client_write: complete response written.\n"));

		} else if (state->response.length > 
			   sizeof(struct winbindd_response)) {
			
			/* Start writing extra data */

			state->write_buf_len = 
				state->response.length -
				sizeof(struct winbindd_response);
			
			DEBUG(10,("client_write: need to write %d extra data bytes.\n", (int)state->write_buf_len));

			state->write_extra_data = True;
		}
	}
}

/* Process incoming clients on listen_sock.  We use a tricky non-blocking,
   non-forking, non-threaded model which allows us to handle many
   simultaneous connections while remaining impervious to many denial of
   service attacks. */

static void process_loop(void)
{
	/* We'll be doing this a lot */

	while (1) {
		struct winbindd_cli_state *state;
		fd_set r_fds, w_fds;
		int maxfd, listen_sock, selret;
		struct timeval timeout;

		/* Handle messages */

		message_dispatch();

		/* rescan the trusted domains list. This must be done
		   regularly to cope with transitive trusts */
		rescan_trusted_domains(False);

		/* Free up temporary memory */

		lp_talloc_free();
		main_loop_talloc_free();

		/* Initialise fd lists for select() */

		listen_sock = open_winbindd_socket();

		if (listen_sock == -1) {
			perror("open_winbind_socket");
			exit(1);
		}

		maxfd = listen_sock;

		FD_ZERO(&r_fds);
		FD_ZERO(&w_fds);
		FD_SET(listen_sock, &r_fds);

		timeout.tv_sec = WINBINDD_ESTABLISH_LOOP;
		timeout.tv_usec = 0;

		if (opt_dual_daemon) {
			maxfd = dual_select_setup(&w_fds, maxfd);
		}

		/* Set up client readers and writers */

		state = winbindd_client_list();

		while (state) {

			/* Dispose of client connection if it is marked as 
			   finished */ 

			if (state->finished) {
				struct winbindd_cli_state *next = state->next;

				remove_client(state);
				state = next;
				continue;
			}

			/* Select requires we know the highest fd used */

			if (state->sock > maxfd)
				maxfd = state->sock;

			/* Add fd for reading */

			if (state->read_buf_len != sizeof(state->request))
				FD_SET(state->sock, &r_fds);

			/* Add fd for writing */

			if (state->write_buf_len)
				FD_SET(state->sock, &w_fds);

			state = state->next;
		}

		/* Call select */
        
		selret = sys_select(maxfd + 1, &r_fds, &w_fds, NULL, &timeout);

		if (selret == 0)
			continue;

		if ((selret == -1 && errno != EINTR) || selret == 0) {

			/* Select error, something is badly wrong */

			perror("select");
			exit(1);
		}

		/* Create a new connection if listen_sock readable */

		if (selret > 0) {

			if (opt_dual_daemon) {
				dual_select(&w_fds);
			}

			if (FD_ISSET(listen_sock, &r_fds)) {
				while (winbindd_num_clients() > WINBINDD_MAX_SIMULTANEOUS_CLIENTS - 1) {
					DEBUG(5,("winbindd: Exceeding %d client connections, removing idle connection.\n",
						WINBINDD_MAX_SIMULTANEOUS_CLIENTS));
					if (!remove_idle_client()) {
						DEBUG(0,("winbindd: Exceeding %d client connections, no idle connection found\n",
							WINBINDD_MAX_SIMULTANEOUS_CLIENTS));
						break;
					}
				}
				new_connection(listen_sock);
			}
            
			/* Process activity on client connections */
            
			for (state = winbindd_client_list(); state; 
			     state = state->next) {
                
				/* Data available for reading */
                
				if (FD_ISSET(state->sock, &r_fds)) {
                    
					/* Read data */
                    
					winbind_client_read(state);

					/* 
					 * If we have the start of a
					 * packet, then check the
					 * length field to make sure
					 * the client's not talking
					 * Mock Swedish.
					 */

					if (state->read_buf_len >= sizeof(uint32)
					    && *(uint32 *) &state->request != sizeof(state->request)) {
						DEBUG(0,("process_loop: Invalid request size from pid %d: %d bytes sent, should be %d\n",
								state->request.pid, *(uint32 *) &state->request, sizeof(state->request)));

						remove_client(state);
						break;
					}

					/* A request packet might be 
					   complete */
                    
					if (state->read_buf_len == 
					    sizeof(state->request)) {
						winbind_process_packet(state);
					}
				}
                
				/* Data available for writing */
                
				if (FD_ISSET(state->sock, &w_fds))
					client_write(state);
			}
		}

#if 0
		winbindd_check_cache_size(time(NULL));
#endif

		/* Check signal handling things */

		if (do_sigterm)
			terminate();

		if (do_sighup) {

			DEBUG(3, ("got SIGHUP\n"));
 
                        /* Flush various caches */

			flush_caches();
			reload_services_file(True);
			do_sighup = False;
		}

		if (do_sigusr2) {
			print_winbindd_status();
			do_sigusr2 = False;
		}
	}
}


/*
  these are split out from the main winbindd for use by the background daemon
 */
BOOL winbind_setup_common(void)
{
  	load_interfaces();

	if (!secrets_init()) {

		DEBUG(0,("Could not initialize domain trust account secrets. Giving up\n"));
		return False;
	}

	namecache_enable();	/* Enable netbios namecache */

	/* Check winbindd parameters are valid */

	ZERO_STRUCT(server_state);

	if (!winbindd_param_init())
		return False;

	/* Winbind daemon initialisation */

	if (!winbindd_idmap_init())
		return False;

	/* Unblock all signals we are interested in as they may have been
	   blocked by the parent process. */

	BlockSignals(False, SIGINT);
	BlockSignals(False, SIGQUIT);
	BlockSignals(False, SIGTERM);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGUSR2);
	BlockSignals(False, SIGHUP);

	/* Setup signal handlers */
	
	CatchSignal(SIGINT, termination_handler);      /* Exit on these sigs */
	CatchSignal(SIGQUIT, termination_handler);
	CatchSignal(SIGTERM, termination_handler);

	CatchSignal(SIGPIPE, SIG_IGN);                 /* Ignore sigpipe */

	CatchSignal(SIGUSR2, sigusr2_handler);         /* Debugging sigs */
	CatchSignal(SIGHUP, sighup_handler);

	return True;
}


/* Main function */

struct winbindd_state server_state;   /* Server state information */


static void usage(void)
{
	printf("Usage: winbindd [options]\n");
        printf("\t-F                daemon in foreground mode\n");
        printf("\t-S                log to stdout\n");
	printf("\t-i                interactive mode\n");
	printf("\t-B                dual daemon mode\n");
	printf("\t-n                disable cacheing\n");
	printf("\t-d level          set debug level\n");
	printf("\t-s configfile     choose smb.conf location\n");
	printf("\t-h                show this help message\n");
}

 int main(int argc, char **argv)
{
	extern BOOL AllowDebugChange;
	pstring logfile;
	BOOL interactive = False;
	BOOL Fork = True;
	BOOL log_stdout = False;
	int opt;

	/* glibc (?) likes to print "User defined signal 1" and exit if a
	   SIGUSR[12] is received before a handler is installed */

 	CatchSignal(SIGUSR1, SIG_IGN);
 	CatchSignal(SIGUSR2, SIG_IGN);

	fault_setup((void (*)(void *))fault_quit );

	snprintf(logfile, sizeof(logfile), "%s/log.winbindd", dyn_LOGFILEBASE);
	lp_set_logfile(logfile);

	/* Initialise for running in non-root mode */

	sec_init();

	/* Set environment variable so we don't recursively call ourselves.
	   This may also be useful interactively. */

	setenv(WINBINDD_DONT_ENV, "1", 1);

	/* Initialise samba/rpc client stuff */

	while ((opt = getopt(argc, argv, "FSid:s:nhB")) != EOF) {
		switch (opt) {

		case 'F':
			Fork = False;
			break;
		case 'S':
			log_stdout = True;
			break;
			/* Don't become a daemon */
		case 'i':
			interactive = True;
			log_stdout = True;
			Fork = False;
			break;

			/* dual daemon system */
		case 'B':
			opt_dual_daemon = True;
			break;

			/* disable cacheing */
		case 'n':
			opt_nocache = True;
			break;

			/* Run with specified debug level */
		case 'd':
			DEBUGLEVEL = atoi(optarg);
			AllowDebugChange = False;
			break;

			/* Load a different smb.conf file */
		case 's':
			pstrcpy(dyn_CONFIGFILE,optarg);
			break;

		case 'h':
			usage();
			exit(0);

		default:
			printf("Unknown option %c\n", (char)opt);
			exit(1);
		}
	}

	if (log_stdout && Fork) {
		printf("Can't log to stdout (-S) unless daemon is in foreground +(-F) or interactive (-i)\n");
		usage();
		exit(1);
	}

	snprintf(logfile, sizeof(logfile), "%s/log.winbindd", dyn_LOGFILEBASE);
	lp_set_logfile(logfile);
	setup_logging("winbindd", log_stdout);
	reopen_logs();

	DEBUG(1, ("winbindd version %s started.\n", VERSION ) );
	DEBUGADD( 1, ( "Copyright The Samba Team 2000-2001\n" ) );

	if (!reload_services_file(False)) {
		DEBUG(0, ("error opening config file\n"));
		exit(1);
	}

	/* Setup names. */

	if (!init_names())
		exit(1);

	if (!interactive) {
		become_daemon(Fork);
		pidfile_create("winbindd");
	}


#if HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management.
	 */
	if (interactive)
		setpgid( (pid_t)0, (pid_t)0);
#endif

	if (!winbind_setup_common()) {
		return 1;
	}

	if (opt_dual_daemon) {
		do_dual_daemon();
	}

	/* Initialise messaging system */

	if (!message_init()) {
		DEBUG(0, ("unable to initialise messaging system\n"));
		exit(1);
	}

	register_msg_pool_usage();
	message_register(MSG_REQ_TALLOC_USAGE, return_all_talloc_info);

	/* Loop waiting for requests */

	process_loop();

	uni_group_cache_shutdown();
	return 0;
}
