/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB server routines
   Copyright (C) Andrew Tridgell 1992-1998
   
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
#include "trans2.h"

extern pstring servicesf;
extern pstring debugf;
extern pstring global_myname;

int am_parent = 1;

/* the last message the was processed */
int last_message = -1;

/* a useful macro to debug the last message processed */
#define LAST_MESSAGE() smb_fn_name(last_message)

extern pstring scope;
extern int DEBUGLEVEL;

extern fstring remote_machine;
extern pstring myhostname;
extern pstring pipe_name;

extern pstring OriginalDir;

/****************************************************************************
  when exiting, take the whole family
****************************************************************************/
static void *dflt_sig(void)
{
	exit_server("caught signal");
	return NULL;
}

/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/
static void  killkids(void)
{
	if(am_parent) kill(0,SIGTERM);
}


/****************************************************************************
  open and listen to a socket
****************************************************************************/
static int open_server_socket(void)
{
	int s;
	fstring dir;
	fstring path;

	slprintf(dir, sizeof(dir)-1, "%s/.msrpc", LOCKDIR);
	slprintf(path, sizeof(path)-1, "%s/%s", dir, pipe_name);

	s = create_pipe_socket(dir, 0700, path, 0700);

	if (s == -1)
		return -1;
		/* ready to listen */
	if (listen(s, 5) == -1) {
		DEBUG(0,("listen: %s\n", strerror(errno)));
		close(s);
		return -1;
	}
	return s;
}

/****************************************************************************
  open the socket communication
****************************************************************************/
static int open_sockets(BOOL is_daemon)
{
	int ClientMSRPC;
	int num_interfaces = iface_count();
	int fd_listenset;
	fd_set listen_set;
	int s;

	memset(&fd_listenset, 0, sizeof(fd_listenset));

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

	/* Just bind to 0.0.0.0 - accept connections
	   from anywhere. */
	num_interfaces = 1;
	
	/* open an incoming socket */
	s = open_server_socket();
	if (s == -1)
		return -1;
	fd_listenset = s;
	FD_SET(s,&listen_set);

	/* now accept incoming connections - forking a new process
	   for each incoming connection */
	DEBUG(2,("waiting for a connection\n"));
	while (1)
	{
		struct sockaddr_un addr;
		int in_addrlen = sizeof(addr);
		fd_set lfds;
		int num;
		
		memcpy((char *)&lfds, (char *)&listen_set, 
		       sizeof(listen_set));
		
		num = sys_select(256,&lfds,NULL, NULL);
		
		if (num == -1 && errno == EINTR)
			continue;
		
		/* Find the sockets that are read-ready -
		   accept on these. */
			
		s = -1;
		if(FD_ISSET(fd_listenset,&lfds))
		{
			s = fd_listenset;
		}

		/* Clear this so we don't look at it again. */
		FD_CLR(s,&lfds);

		ClientMSRPC = accept(s,(struct sockaddr*)&addr,&in_addrlen);
		
		if (ClientMSRPC == -1 && errno == EINTR)
			continue;
		
		if (ClientMSRPC == -1)
		{
			DEBUG(0,("open_sockets: accept: %s\n",
				 strerror(errno)));
			continue;
		}
		
		if (ClientMSRPC != -1 && fork()==0)
		{
			/* Child code ... */
			
			/* close the listening socket(s) */
			close(fd_listenset);
			
			/* close our standard file
			   descriptors */
			close_low_fds();
			am_parent = 0;
			
			/* Reset global variables in util.c so
			   that client substitutions will be
			   done correctly in the process.  */
			reset_globals_after_fork();

			return ClientMSRPC; 
		}
		/* The parent doesn't need this socket */
		close(ClientMSRPC); 

		/* Force parent to check log size after
		 * spawning child.  Fix from
		 * klausr@ITAP.Physik.Uni-Stuttgart.De.  The
		 * parent daemon will log to logserver.smb.  It
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

	} /* end while 1 */

/* NOTREACHED */
}


/****************************************************************************
this prevents zombie child processes
****************************************************************************/
BOOL reload_after_sighup = False;

static void sig_hup(int sig)
{
	BlockSignals(True,SIGHUP);
	DEBUG(0,("Got SIGHUP\n"));

	/*
	 * Fix from <branko.cibej@hermes.si> here.
	 * We used to reload in the signal handler - this
	 * is a *BIG* no-no.
	 */

	reload_after_sighup = True;
	BlockSignals(False,SIGHUP);
}



#if DUMP_CORE
/*******************************************************************
prepare to dump a core file - carefully!
********************************************************************/
static BOOL dump_core(void)
{
	char *p;
	pstring dname;
	pstrcpy(dname,debugf);
	if ((p=strrchr(dname,'/'))) *p=0;
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


	DEBUG(0,("Dumping core in %s\n",dname));
	abort();
	return(True);
}
#endif


/****************************************************************************
exit the server
****************************************************************************/
void exit_server(char *reason)
{
	static int firsttime=1;

	if (!firsttime) exit(0);
	firsttime = 0;

	unbecome_vuser();
	DEBUG(2,("Closing connections\n"));

#ifdef WITH_DFS
	if (dcelogin_atmost_once) {
		dfs_unlogin();
	}
#endif

	if (!reason) {   
		DEBUG(0,("===============================================================\n"));
#if DUMP_CORE
		if (dump_core()) return;
#endif
	}    

	locking_end();

	DEBUG(3,("Server exit (%s)\n", (reason ? reason : "")));
#ifdef MEM_MAN
	{
		extern FILE *dbf;
		smb_mem_write_verbose(dbf);
		dbgflush();
	}
#endif
	exit(0);
}



/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static void init_structs(void)
{
#if 0
	conn_init();
#endif
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
	DEBUG(0,("Incorrect program usage - are you sure the command line is correct?\n"));

	printf("Usage: %s [-D] [-p port] [-d debuglevel] ", pname);
        printf("[-l log basename] [-s services file]\n" );
	printf("Version %s\n",VERSION);
	printf("\t-D                    become a daemon\n");
	printf("\t-p port               listen on the specified port\n");
	printf("\t-d debuglevel         set the debuglevel\n");
	printf("\t-l log basename.      Basename for log/debug files\n");
	printf("\t-s services file.     Filename of services file\n");
	printf("\t-P                    passive only\n");
	printf("\t-a                    append to log file (default)\n");
	printf("\t-o                    overwrite log file, don't append\n");
	printf("\t-i scope              NetBIOS scope to use (default none)\n");
	printf("\n");
}


/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	msrpc_service_fns *fn = get_service_fns();
	extern BOOL append_log;
	/* shall I run as a daemon */
	BOOL is_daemon = False;
	int opt;
	extern char *optarg;
	int ClientMSRPC = -1;
	pipes_struct p;
	fstring service_name;

	charset_initialise();

	if (fn == NULL)
	{
		fprintf(stderr,"no services table!\n");
		exit(-1);
	}

	if (fn->main_init(argc, argv) != 0)
	{
		exit_server("fn->main() initialisation failed!");
	}

	strlower(pipe_name);
	pstrcpy(remote_machine, pipe_name);
	split_at_last_component(argv[0], NULL, '/', service_name);

	/* make absolutely sure we run as root - to handle cases where people
	   are crazy enough to have it setuid */
#ifdef HAVE_SETRESUID
	setresuid(0,0,0);
#else
	setuid(0);
	seteuid(0);
	setuid(0);
	seteuid(0);
#endif

	fault_setup((void (*)(void *))exit_server);
	CatchSignal(SIGTERM , SIGNAL_CAST dflt_sig);

	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	dos_GetWd(OriginalDir);

	init_vuid();

	/* this is for people who can't start the program correctly */
	while (argc > 1 && (*argv[1] != '-')) {
		argv++;
		argc--;
	}

	while ( EOF != (opt = getopt(argc, argv, "i:l:s:d:Dh?Paof:")) )
		switch (opt)  {
		case 'i':
			pstrcpy(scope,optarg);
			break;

		case 'P':
			{
				extern BOOL passive;
				passive = True;
			}
			break;	

		case 's':
			pstrcpy(servicesf,optarg);
			break;

		case 'l':
			pstrcpy(debugf,optarg);
			break;

		case 'a':
			append_log = True;
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
			break;

		case 'h':
		case '?':
			usage(argv[0]);
			exit(0);
			break;

		default:
			usage(argv[0]);
			exit(1);
		}

	reopen_logs();

	DEBUG(1,( "%s version %s started.\n", service_name, VERSION));
	DEBUGADD(1,( "Copyright Andrew Tridgell 1992-1999\n"));

	DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
		 (int)getuid(),(int)getgid(),(int)geteuid(),(int)getegid()));

	if (sizeof(uint16) < 2 || sizeof(uint32) < 4) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	get_myname(myhostname,NULL);

	if (!fn->reload_services(False))
		return(-1);	

	init_structs();

#ifdef WITH_PROFILE
	if (!profile_setup(False)) {
		DEBUG(0,("ERROR: failed to setup profiling\n"));
		return -1;
	}
#endif

	/*
	 * Set the machine NETBIOS name if not already
	 * set from the config file.
	 */
	if (!*global_myname)
	{
		fstrcpy(global_myname, dns_to_netbios_name(myhostname));
	}
	strupper(global_myname);

	codepage_initialise(lp_client_code_page());

	CatchSignal(SIGHUP,SIGNAL_CAST sig_hup);
	
	/* Setup the signals that allow the debug log level
	   to by dynamically changed. */
 
	/* If we are using the malloc debug code we can't use
	   SIGUSR1 and SIGUSR2 to do debug level changes. */
	
#ifndef MEM_MAN
#if defined(SIGUSR1)
	CatchSignal( SIGUSR1, SIGNAL_CAST sig_usr1 );
#endif /* SIGUSR1 */
   
#if defined(SIGUSR2)
	CatchSignal( SIGUSR2, SIGNAL_CAST sig_usr2 );
#endif /* SIGUSR2 */
#endif /* MEM_MAN */

	DEBUG(3,( "loaded services\n"));

	if (!is_daemon && !is_a_socket(0)) {
		DEBUG(0,("standard input is not a socket, assuming -D option\n"));
		is_daemon = True;
	}

	if (is_daemon) {
		DEBUG( 3, ( "Becoming a daemon.\n" ) );
		become_daemon();
	}

	if (!directory_exist(lp_lockdir(), NULL)) {
		mkdir(lp_lockdir(), 0755);
	}

	if (is_daemon)
	{
		pidfile_create(service_name);
	}

	fn->service_init(service_name);
	dbgflush();

	ClientMSRPC = open_sockets(is_daemon);
	if (ClientMSRPC == -1)
	{
		exit_server("open socket failed");
	}

	if (!locking_init(0))
		exit(1);

	/* possibly reload the services file. */
	fn->reload_services(True);
	
	if (*lp_rootdir()) {
		if (sys_chroot(lp_rootdir()) == 0)
			DEBUG(2,("Changed root to %s\n", lp_rootdir()));
	}

	ZERO_STRUCT(p);
	fstrcpy(p.name, pipe_name);
	if (msrpcd_init(ClientMSRPC, &p.l))
	{
		fn->auth_init(p.l);
		fn->reload_services(True);
		msrpcd_process(fn, p.l, p.name);
	}
	if (ClientMSRPC != -1)
	{
		close(ClientMSRPC);
	}
	
	exit_server("normal exit");
	return(0);
}

