/* 
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) Martin Pool			2002
   
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

extern fstring global_myworkgroup;
extern pstring global_myname;

int am_parent = 1;

/* the last message the was processed */
int last_message = -1;

/* a useful macro to debug the last message processed */
#define LAST_MESSAGE() smb_fn_name(last_message)

extern pstring user_socket_options;

#ifdef WITH_DFS
extern int dcelogin_atmost_once;
#endif /* WITH_DFS */

extern fstring remote_machine;

/* really we should have a top level context structure that has the
   client file descriptor as an element. That would require a major rewrite :(

   the following 2 functions are an alternative - they make the file
   descriptor private to smbd
 */
static int server_fd = -1;

int smbd_server_fd(void)
{
	return server_fd;
}

void smbd_set_server_fd(int fd)
{
	server_fd = fd;
	client_setfd(fd);
}

/****************************************************************************
 Terminate signal.
****************************************************************************/

VOLATILE sig_atomic_t got_sig_term = 0;

static void sig_term(void)
{
	got_sig_term = 1;
	sys_select_signal();
}

/****************************************************************************
 Catch a sighup.
****************************************************************************/

VOLATILE sig_atomic_t reload_after_sighup = 0;

static void sig_hup(int sig)
{
	reload_after_sighup = 1;
	sys_select_signal();
}

/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/

static void  killkids(void)
{
	if(am_parent) kill(0,SIGTERM);
}

/****************************************************************************
 Process a sam sync message - not sure whether to do this here or
 somewhere else.
****************************************************************************/

static void msg_sam_sync(int UNUSED(msg_type), pid_t UNUSED(pid),
			 void *UNUSED(buf), size_t UNUSED(len))
{
        DEBUG(10, ("** sam sync message received, ignoring\n"));
}

/****************************************************************************
 Process a sam sync replicate message - not sure whether to do this here or
 somewhere else.
****************************************************************************/

static void msg_sam_repl(int msg_type, pid_t pid, void *buf, size_t len)
{
        uint32 low_serial;

        if (len != sizeof(uint32))
                return;

        low_serial = *((uint32 *)buf);

        DEBUG(3, ("received sam replication message, serial = 0x%04x\n",
                  low_serial));
}

/****************************************************************************
 Open the socket communication - inetd.
****************************************************************************/

static BOOL open_sockets_inetd(void)
{
	/* Started from inetd. fd 0 is the socket. */
	/* We will abort gracefully when the client or remote system 
	   goes away */
	smbd_set_server_fd(dup(0));
	
	/* close our standard file descriptors */
	close_low_fds();
	
	set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
	set_socket_options(smbd_server_fd(), user_socket_options);

	return True;
}


/****************************************************************************
 Open the socket communication.
****************************************************************************/

static BOOL open_sockets(BOOL is_daemon,int port)
{
	int num_interfaces = iface_count();
	int fd_listenset[FD_SETSIZE];
	fd_set listen_set;
	int s;
	int i;

	if (!is_daemon) {
		return open_sockets_inetd();
	}

		
#ifdef HAVE_ATEXIT
	{
		static int atexit_set;
		if(atexit_set == 0) {
			atexit_set=1;
			atexit(killkids);
		}
	}
#endif

	/* Stop zombies */
	CatchChild();
		
		
	FD_ZERO(&listen_set);

	if(lp_interfaces() && lp_bind_interfaces_only()) {
		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		
		if(num_interfaces > FD_SETSIZE) {
			DEBUG(0,("open_sockets: Too many interfaces specified to bind to. Number was %d \
max can be %d\n", 
				 num_interfaces, FD_SETSIZE));
			return False;
		}
		
		/* Now open a listen socket for each of the
		   interfaces. */
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);
			
			if(ifip == NULL) {
				DEBUG(0,("open_sockets: interface %d has NULL IP address !\n", i));
				continue;
			}
			s = fd_listenset[i] = open_socket_in(SOCK_STREAM, port, 0, ifip->s_addr, True);
			if(s == -1)
				return False;

			/* ready to listen */
			set_socket_options(s,"SO_KEEPALIVE"); 
			set_socket_options(s,user_socket_options);
      
			if (listen(s, 5) == -1) {
				DEBUG(0,("listen: %s\n",strerror(errno)));
				close(s);
				return False;
			}
			FD_SET(s,&listen_set);
		}
	} else {
		/* Just bind to 0.0.0.0 - accept connections
		   from anywhere. */
		num_interfaces = 1;
		
		/* open an incoming socket */
		s = open_socket_in(SOCK_STREAM, port, 0,
				   interpret_addr(lp_socket_address()),True);
		if (s == -1)
			return(False);
		
		/* ready to listen */
		set_socket_options(s,"SO_KEEPALIVE"); 
		set_socket_options(s,user_socket_options);

		if (listen(s, 5) == -1) {
			DEBUG(0,("open_sockets: listen: %s\n",
				 strerror(errno)));
			close(s);
			return False;
		}
		
		fd_listenset[0] = s;
		FD_SET(s,&listen_set);
	} 

        /* Listen to messages */

        message_register(MSG_SMB_SAM_SYNC, msg_sam_sync);
        message_register(MSG_SMB_SAM_REPL, msg_sam_repl);

	/* now accept incoming connections - forking a new process
	   for each incoming connection */
	DEBUG(2,("waiting for a connection\n"));
	while (1) {
		fd_set lfds;
		int num;
		
		/* Free up temporary memory from the main smbd. */
		lp_talloc_free();

		/* Ensure we respond to PING and DEBUG messages from the main smbd. */
		message_dispatch();

		memcpy((char *)&lfds, (char *)&listen_set, 
		       sizeof(listen_set));
		
		num = sys_select(FD_SETSIZE,&lfds,NULL,NULL,NULL);
		
		if (num == -1 && errno == EINTR) {
			if (got_sig_term) {
				exit_server("Caught TERM signal");
			}

			/* check for sighup processing */
			if (reload_after_sighup) {
				change_to_root_user();
				DEBUG(1,("Reloading services after SIGHUP\n"));
				reload_services(False);
				reload_after_sighup = 0;
			}

			continue;
		}
		
		/* check if we need to reload services */
		check_reload(time(NULL));

		/* Find the sockets that are read-ready -
		   accept on these. */
		for( ; num > 0; num--) {
			struct sockaddr addr;
			socklen_t in_addrlen = sizeof(addr);
			
			s = -1;
			for(i = 0; i < num_interfaces; i++) {
				if(FD_ISSET(fd_listenset[i],&lfds)) {
					s = fd_listenset[i];
					/* Clear this so we don't look
					   at it again. */
					FD_CLR(fd_listenset[i],&lfds);
					break;
				}
			}

			smbd_set_server_fd(accept(s,&addr,&in_addrlen));
			
			if (smbd_server_fd() == -1 && errno == EINTR)
				continue;
			
			if (smbd_server_fd() == -1) {
				DEBUG(0,("open_sockets: accept: %s\n",
					 strerror(errno)));
				continue;
			}
			
			if (smbd_server_fd() != -1 && sys_fork()==0) {
				/* Child code ... */
				
				/* close the listening socket(s) */
				for(i = 0; i < num_interfaces; i++)
					close(fd_listenset[i]);
				
				/* close our standard file
				   descriptors */
				close_low_fds();
				am_parent = 0;
				
				set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
				set_socket_options(smbd_server_fd(),user_socket_options);
				
				/* Reset global variables in util.c so
				   that client substitutions will be
				   done correctly in the process.  */
				reset_globals_after_fork();

				/* tdb needs special fork handling */
				tdb_reopen_all();

				return True; 
			}
			/* The parent doesn't need this socket */
			close(smbd_server_fd()); 

			/* Sun May 6 18:56:14 2001 ackley@cs.unm.edu:
				Clear the closed fd info out of server_fd --
				and more importantly, out of client_fd in
				util_sock.c, to avoid a possible
				getpeername failure if we reopen the logs
				and use %I in the filename.
			*/

			smbd_set_server_fd(-1);

			/* Force parent to check log size after
			 * spawning child.  Fix from
			 * klausr@ITAP.Physik.Uni-Stuttgart.De.  The
			 * parent smbd will log to logserver.smb.  It
			 * writes only two messages for each child
			 * started/finished. But each child writes,
			 * say, 50 messages also in logserver.smb,
			 * begining with the debug_count of the
			 * parent, before the child opens its own log
			 * file logserver.client. In a worst case
			 * scenario the size of logserver.smb would be
			 * checked after about 50*50=2500 messages
			 * (ca. 100kb).
			 * */
			force_check_log_size();
 
		} /* end for num */
	} /* end while 1 */

/* NOTREACHED	return True; */
}

/****************************************************************************
 Reload the services file.
**************************************************************************/

BOOL reload_services(BOOL test)
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

	lp_killunused(conn_snum_used);
	
	ret = lp_load(dyn_CONFIGFILE, False, False, True);

	load_printers();

	/* perhaps the config filename is now set */
	if (!test)
		reload_services(True);

	reopen_logs();

	load_interfaces();

	{
		if (smbd_server_fd() != -1) {      
			set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
			set_socket_options(smbd_server_fd(), user_socket_options);
		}
	}

	reset_mangled_cache();
	reset_stat_cache();

	/* this forces service parameters to be flushed */
	set_current_service(NULL,True);

	return(ret);
}

#if DUMP_CORE
/*******************************************************************
prepare to dump a core file - carefully!
********************************************************************/
static BOOL dump_core(void)
{
	char *p;
	pstring dname;
	
	pstrcpy(dname,lp_logfile());
	if ((p=strrchr_m(dname,'/'))) *p=0;
	pstrcat(dname,"/corefiles");
	mkdir(dname,0700);
	sys_chown(dname,getuid(),getgid());
	chmod(dname,0700);
	if (chdir(dname)) return(False);
	umask(~(0700));

#ifdef HAVE_GETRLIMIT
#ifdef RLIMIT_CORE
	{
		struct rlimit rlp;
		getrlimit(RLIMIT_CORE, &rlp);
		rlp.rlim_cur = MAX(4*1024*1024,rlp.rlim_cur);
		setrlimit(RLIMIT_CORE, &rlp);
		getrlimit(RLIMIT_CORE, &rlp);
		DEBUG(3,("Core limits now %d %d\n",
			 (int)rlp.rlim_cur,(int)rlp.rlim_max));
	}
#endif
#endif


	DEBUG(0,("Dumping core in %s\n", dname));
	abort();
	return(True);
}
#endif

/****************************************************************************
update the current smbd process count
****************************************************************************/

static void decrement_smbd_process_count(void)
{
	int32 total_smbds;

	if (lp_max_smbd_processes()) {
		total_smbds = 0;
		tdb_change_int32_atomic(conn_tdb_ctx(), "INFO/total_smbds", &total_smbds, -1);
	}
}

/****************************************************************************
 Exit the server.
****************************************************************************/

void exit_server(char *reason)
{
	static int firsttime=1;
	extern char *last_inbuf;
	extern struct auth_context *negprot_global_auth_context;

	if (!firsttime)
		exit(0);
	firsttime = 0;

	change_to_root_user();
	DEBUG(2,("Closing connections\n"));

	if (negprot_global_auth_context) {
		(negprot_global_auth_context->free)(&negprot_global_auth_context);
	}

	conn_close_all();

	invalidate_all_vuids();

	/* delete our entry in the connections database. */
	yield_connection(NULL,"");

	respond_to_all_remaining_local_messages();
	decrement_smbd_process_count();

#ifdef WITH_DFS
	if (dcelogin_atmost_once) {
		dfs_unlogin();
	}
#endif

	if (!reason) {   
		int oldlevel = DEBUGLEVEL;
		DEBUGLEVEL = 10;
		DEBUG(0,("Last message was %s\n",smb_fn_name(last_message)));
		if (last_inbuf)
			show_msg(last_inbuf);
		DEBUGLEVEL = oldlevel;
		DEBUG(0,("===============================================================\n"));
#if DUMP_CORE
		if (dump_core()) return;
#endif
	}    

	locking_end();

	DEBUG(3,("Server exit (%s)\n", (reason ? reason : "")));
	exit(0);
}

/****************************************************************************
 Initialise connect, service and file structs.
****************************************************************************/

static void init_structs(void )
{
	/*
	 * Set the machine NETBIOS name if not already
	 * set from the config file.
	 */

	if (!*global_myname) {
		char *p;
		pstrcpy( global_myname, myhostname() );
		p = strchr_m(global_myname, '.' );
		if (p) 
			*p = 0;
	}

	strupper(global_myname);

	conn_init();

	file_init();

	/* for RPC pipes */
	init_rpc_pipe_hnd();

	init_dptrs();

	secrets_init();

}

/****************************************************************************
 Usage on the program.
****************************************************************************/

static void usage(char *pname)
{

	d_printf("Usage: %s [-DaioPh?Vb] [-d debuglevel] [-l log basename] [-p port]\n", pname);
	d_printf("       [-O socket options] [-s services file]\n");
	d_printf("\t-D                    Become a daemon (default)\n");
	d_printf("\t-a                    Append to log file (default)\n");
	d_printf("\t-i                    Run interactive (not a daemon)\n" );
	d_printf("\t-o                    Overwrite log file, don't append\n");
	d_printf("\t-h                    Print usage\n");
	d_printf("\t-?                    Print usage\n");
	d_printf("\t-V                    Print version\n");
	d_printf("\t-b                    Print build options\n");
	d_printf("\t-d debuglevel         Set the debuglevel\n");
	d_printf("\t-l log basename.      Basename for log/debug files\n");
	d_printf("\t-p port               Listen on the specified port\n");
	d_printf("\t-O socket options     Socket options\n");
	d_printf("\t-s services file.     Filename of services file\n");
	d_printf("\n");
}

/****************************************************************************
 main program.
****************************************************************************/

 int main(int argc,char *argv[])
{
	extern BOOL append_log;
	extern BOOL AllowDebugChange;
	extern char *optarg;
	/* shall I run as a daemon */
	BOOL is_daemon = False;
	BOOL interactive = False;
	BOOL specified_logfile = False;
	int port = SMB_PORT;
	int opt;
	pstring logfile;

#ifdef HAVE_SET_AUTH_PARAMETERS
	set_auth_parameters(argc,argv);
#endif

	/* this is for people who can't start the program correctly */
	while (argc > 1 && (*argv[1] != '-')) {
		argv++;
		argc--;
	}

	while ( EOF != (opt = getopt(argc, argv, "O:l:s:d:Dp:h?bVaiof:")) )
		switch (opt)  {
		case 'O':
			pstrcpy(user_socket_options,optarg);
			break;

		case 's':
			pstrcpy(dyn_CONFIGFILE,optarg);
			break;

		case 'l':
			specified_logfile = True;
			pstr_sprintf(logfile, "%s/log.smbd", optarg);
			lp_set_logfile(logfile);
			break;

		case 'a':
			append_log = True;
			break;

		case 'i':
			interactive = True;
			break;

		case 'o':
			append_log = False;
			break;

		case 'D':
			is_daemon = True;
			break;

		case 'd':
			if (*optarg == 'A')
				DEBUGLEVEL = 10000;
			else
				DEBUGLEVEL = atoi(optarg);
			AllowDebugChange = False;
			break;

		case 'p':
			port = atoi(optarg);
			break;

		case 'h':
		case '?':
			usage(argv[0]);
			exit(0);
			break;

		case 'V':
			d_printf("Version %s\n",VERSION);
			exit(0);
			break;
		case 'b':
		        build_options(True); /* Display output to screen as well as debug */ 
			exit(0);
			break;
		default:
			DEBUG(0,("Incorrect program usage - are you sure the command line is correct?\n"));
			usage(argv[0]);
			exit(1);
		}

#ifdef HAVE_SETLUID
	/* needed for SecureWare on SCO */
	setluid(0);
#endif

	sec_init();

	load_case_tables();

	append_log = True;

	if(!specified_logfile) {
		pstr_sprintf(logfile, "%s/log.smbd", dyn_LOGFILEBASE);
		lp_set_logfile(logfile);
	}

	fstrcpy(remote_machine, "smbd");

	setup_logging(argv[0],interactive);

	/* we want to re-seed early to prevent time delays causing
           client problems at a later date. (tridge) */
	generate_random_buffer(NULL, 0, False);

	/* make absolutely sure we run as root - to handle cases where people
	   are crazy enough to have it setuid */

	gain_root_privilege();
	gain_root_group_privilege();

	fault_setup((void (*)(void *))exit_server);
	CatchSignal(SIGTERM , SIGNAL_CAST sig_term);
	CatchSignal(SIGHUP,SIGNAL_CAST sig_hup);
	
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

	init_sec_ctx();

	reopen_logs();

	DEBUG(0,( "smbd version %s started.\n", VERSION));
	DEBUGADD(0,( "Copyright Andrew Tridgell and the Samba Team 1992-2002\n"));

	DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
		 (int)getuid(),(int)getgid(),(int)geteuid(),(int)getegid()));

	/* Output the build options to the debug log */ 
	build_options(False);

	if (sizeof(uint16) < 2 || sizeof(uint32) < 4) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	/*
	 * Do this before reload_services.
	 */

	if (!reload_services(False))
		return(-1);	

	init_structs();

	/* don't call winbind for our domain if we are the DC */
	if (lp_domain_logons()) {
		winbind_exclude_domain(lp_workgroup());
	}
	
#ifdef WITH_PROFILE
	if (!profile_setup(False)) {
		DEBUG(0,("ERROR: failed to setup profiling\n"));
		return -1;
	}
#endif

#ifdef WITH_SSL
	{
		extern BOOL sslEnabled;
		sslEnabled = lp_ssl_enabled();
		if(sslEnabled)
			sslutil_init(True);
	}
#endif        /* WITH_SSL */

	fstrcpy(global_myworkgroup, lp_workgroup());

	DEBUG(3,( "loaded services\n"));

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
		DEBUG( 3, ( "Becoming a daemon.\n" ) );
		become_daemon();
	}

#if HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management.
	 */
	if (interactive)
		setpgid( (pid_t)0, (pid_t)0);
#endif

	if (!directory_exist(lp_lockdir(), NULL)) {
		mkdir(lp_lockdir(), 0755);
	}

	if (is_daemon) {
		pidfile_create("smbd");
	}

	if (!message_init()) {
		exit(1);
	}
	register_msg_pool_usage();
	register_dmalloc_msgs();

	/* Setup the main smbd so that we can get messages. */
	claim_connection(NULL,"",0,True);

	/* 
	   DO NOT ENABLE THIS TILL YOU COPE WITH KILLING THESE TASKS AND INETD
	   THIS *killed* LOTS OF BUILD FARM MACHINES. IT CREATED HUNDREDS OF 
	   smbd PROCESSES THAT NEVER DIE
	   start_background_queue(); 
	*/

	if (!open_sockets(is_daemon,port))
		exit(1);

	/*
	 * everything after this point is run after the fork()
	 */ 

	if (!locking_init(0))
		exit(1);

	if (!print_backend_init())
		exit(1);

	if (!share_info_db_init())
		exit(1);

	if(!initialize_password_db(False))
		exit(1);

	uni_group_cache_init(); /* Non-critical */
	
	/* possibly reload the services file. */
	reload_services(True);

	if(!pdb_generate_sam_sid()) {
		DEBUG(0,("ERROR: Samba cannot create a SAM SID.\n"));
		exit(1);
	}

	if (!init_account_policy()) {
		DEBUG(0,("Could not open account policy tdb.\n"));
		exit(1);
	}

	if (*lp_rootdir()) {
		if (sys_chroot(lp_rootdir()) == 0)
			DEBUG(2,("Changed root to %s\n", lp_rootdir()));
	}

	/* Setup oplocks */
	if (!init_oplocks())
		exit(1);
	
	/* Setup mangle */
	if (!init_mangle_tdb())
		exit(1);

	/* Setup change notify */
	if (!init_change_notify())
		exit(1);

	smbd_process();
	
	uni_group_cache_shutdown();
	exit_server("normal exit");
	return(0);
}
