/* 
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Jean François Micouleau      1998-2002.
   
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
#include "wins_repl.h"

extern pstring user_socket_options;

extern WINS_OWNER *global_wins_table;
extern int partner_count;

extern fd_set *listen_set;
extern int listen_number;
extern int *sock_array;

extern TALLOC_CTX *mem_ctx;

int wins_port = 42;

/****************************************************************************
  when exiting, take the whole family
****************************************************************************/
static void *dflt_sig(void)
{
	exit_server("caught signal");
	return NULL;
}

/****************************************************************************
  reload the services file
  **************************************************************************/
BOOL reload_services(BOOL test)
{
	BOOL ret;
	
	if (lp_loaded()) {
		pstring fname;
		pstrcpy(fname,lp_configfile());
		if (file_exist(fname,NULL) && !strcsequal(fname,dyn_CONFIGFILE)) {
			pstrcpy(dyn_CONFIGFILE,fname);
			test = False;
		}
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return(True);

	ret = lp_load(dyn_CONFIGFILE,False,False,True);


	/* perhaps the config filename is now set */
	if (!test)
		reload_services(True);

	reopen_logs();

	load_interfaces();

	return(ret);
}

/****************************************************************************
 Catch a sighup.
****************************************************************************/

VOLATILE sig_atomic_t reload_after_sighup = False;

static void sig_hup(int sig)
{
	BlockSignals(True,SIGHUP);
	DEBUG(0,("Got SIGHUP\n"));

	sys_select_signal();
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


	DEBUG(0,("Dumping core in %s\n",dname));
	abort();
	return(True);
}
#endif

/****************************************************************************
exit the server
****************************************************************************/
void exit_server(const char *reason)
{
	static int firsttime=1;

	if (!firsttime)
		exit(0);
	firsttime = 0;

	DEBUG(2,("Closing connections\n"));

	if (!reason) {   
		int oldlevel = DEBUGLEVEL;
		DEBUGLEVEL = 10;
		DEBUGLEVEL = oldlevel;
		DEBUG(0,("===============================================================\n"));
#if DUMP_CORE
		if (dump_core()) return;
#endif
	}

	DEBUG(3,("Server exit (%s)\n", (reason ? reason : "")));
	exit(0);
}

/****************************************************************************
  Create an fd_set containing all the sockets in the subnet structures,
  plus the broadcast sockets.
***************************************************************************/

static BOOL create_listen_fdset(void)
{
	int i;
	int num_interfaces = iface_count();
	int s;

	listen_set = (fd_set *)malloc(sizeof(fd_set));
	if(listen_set == NULL) {
		DEBUG(0,("create_listen_fdset: malloc fail !\n"));
		return True;
	}

#ifdef HAVE_ATEXIT
	{
		static int atexit_set;
		if(atexit_set == 0) {
			atexit_set=1;
		}
	}
#endif

	FD_ZERO(listen_set);

	if(lp_interfaces() && lp_bind_interfaces_only()) {
		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		
		if(num_interfaces > FD_SETSIZE) {
			DEBUG(0,("create_listen_fdset: Too many interfaces specified to bind to. Number was %d max can be %d\n", num_interfaces, FD_SETSIZE));
			return False;
		}

		/* Now open a listen socket for each of the interfaces. */
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);
			
			if(ifip == NULL) {
				DEBUG(0,("create_listen_fdset: interface %d has NULL IP address !\n", i));
				continue;
			}
			s = open_socket_in(SOCK_STREAM, wins_port, 0, ifip->s_addr, True);
			if(s == -1)
				return False;

			/* ready to listen */
			set_socket_options(s,"SO_KEEPALIVE"); 
			set_socket_options(s,user_socket_options);
      
			if (listen(s, 5) == -1) {
				DEBUG(5,("listen: %s\n",strerror(errno)));
				close(s);
				return False;
			}
			add_fd_to_sock_array(s);
			FD_SET(s, listen_set);
		}
	} else {
		/* Just bind to 0.0.0.0 - accept connections from anywhere. */
		num_interfaces = 1;
		
		/* open an incoming socket */
		s = open_socket_in(SOCK_STREAM, wins_port, 0, interpret_addr(lp_socket_address()),True);
		if (s == -1)
			return(False);
		
		/* ready to listen */
		set_socket_options(s,"SO_KEEPALIVE"); 
		set_socket_options(s,user_socket_options);

		if (listen(s, 5) == -1) {
			DEBUG(0,("create_listen_fdset: listen: %s\n", strerror(errno)));
			close(s);
			return False;
		}
		
		add_fd_to_sock_array(s);
		FD_SET(s, listen_set);
	} 

	return True;
}

/*******************************************************************
  read a packet from a socket and parse it, returning a packet ready
  to be used or put on the queue. This assumes a UDP socket
  ******************************************************************/
static struct wins_packet_struct *read_wins_packet(int fd, int timeout)
{
	struct wins_packet_struct *p;
	GENERIC_PACKET *q;
	struct BUFFER inbuf;
	ssize_t len=0;
	size_t total=0;  
	ssize_t ret;
	BOOL ok = False;

	inbuf.buffer=NULL;
	inbuf.length=0;
	inbuf.offset=0;

	if(!grow_buffer(&inbuf, 4))
		return NULL;

	ok = (read(fd, inbuf.buffer,4) == 4);
	if (!ok)
		return NULL;
	len = smb_len(inbuf.buffer);

	if (len<=0)
		return NULL;

	if(!grow_buffer(&inbuf, len))
		return NULL;
		
	while (total < len) {
		ret = read(fd, inbuf.buffer + total + 4, len - total);
		if (ret == 0) {
			DEBUG(10,("read_socket_data: recv of %d returned 0. Error = %s\n", (int)(len - total), strerror(errno) ));
			return NULL;
		}
		if (ret == -1) {
			DEBUG(0,("read_socket_data: recv failure for %d. Error = %s\n", (int)(len - total), strerror(errno) ));
			return NULL;
		}
		total += ret;
	}

	q = (GENERIC_PACKET *)talloc(mem_ctx, sizeof(GENERIC_PACKET));
	p = (struct wins_packet_struct *)talloc(mem_ctx, sizeof(*p));
	if (q==NULL || p==NULL)
		return NULL;

	decode_generic_packet(&inbuf, q);

	q->fd=fd;
	
	p->next = NULL;
	p->prev = NULL;
	p->stop_packet = False;
	p->timestamp = time(NULL);
	p->fd = fd;
	p->packet=q;
	
	return p;
}

static struct wins_packet_struct *packet_queue = NULL;

/*******************************************************************
  Queue a packet into a packet queue
******************************************************************/
static void queue_packet(struct wins_packet_struct *packet)
{
	struct wins_packet_struct *p;

	if (!packet_queue) {
		packet->prev = NULL;
		packet->next = NULL;
		packet_queue = packet;
		return;
	}
  
	/* find the bottom */
	for (p=packet_queue;p->next;p=p->next) 
		;

	p->next = packet;
	packet->next = NULL;
	packet->prev = p;
}

/****************************************************************************
  Listens for NMB or DGRAM packets, and queues them.
  return True if the socket is dead
***************************************************************************/
static BOOL listen_for_wins_packets(void)
{
	int num_interfaces = iface_count();
	fd_set fds;
	int i, num, s, new_s;
	struct timeval timeout;

	if(listen_set == NULL) {
		if(!create_listen_fdset()) {
			DEBUG(0,("listen_for_packets: Fatal error. unable to create listen set. Exiting.\n"));
			return True;
		}
	}

	memcpy((char *)&fds, (char *)listen_set, sizeof(fd_set));

	timeout.tv_sec = NMBD_SELECT_LOOP;
	timeout.tv_usec = 0;

	/* Prepare for the select - allow certain signals. */

	BlockSignals(False, SIGTERM);

	num = sys_select(FD_SETSIZE, &fds, NULL, NULL, &timeout);

	/* We can only take signals when we are in the select - block them again here. */

	BlockSignals(True, SIGTERM);

	if(num == -1)
		return False;

	for (; num > 0; num--) {
		s = -1;
		/* check the sockets we are only listening on, waiting to accept */		
		for (i=0; i<num_interfaces; i++) {
			struct sockaddr addr;
			socklen_t in_addrlen = sizeof(addr);
		
			if(FD_ISSET(sock_array[i], &fds)) {
				s = sock_array[i];
				/* Clear this so we don't look at it again. */
				FD_CLR(sock_array[i], &fds);

				/* accept and add the new socket to the listen set */
				new_s=accept(s, &addr, &in_addrlen);

				if (new_s < 0)
					continue;
	
				DEBUG(5,("listen_for_wins_packets: new connection, old: %d, new : %d\n", s, new_s));
				
				set_socket_options(new_s, "SO_KEEPALIVE");
				set_socket_options(new_s, user_socket_options);
				FD_SET(new_s, listen_set);
				add_fd_to_sock_array(new_s);
			}
		}

		/*
		 * check for the sockets we are waiting data from
		 * either client sending datas
		 * or reply to our requests
		 */
		for (i=num_interfaces; i<listen_number; i++) {
			if(FD_ISSET(sock_array[i], &fds)) {
				struct wins_packet_struct *packet = read_wins_packet(sock_array[i], timeout.tv_sec);
				if (packet) {
					packet->fd = sock_array[i];
					queue_packet(packet);
				}
				DEBUG(2,("listen_for_wins_packets: some data on fd %d\n", sock_array[i]));
				FD_CLR(sock_array[i], &fds);
				break;
			}
	
		}

	}

	return False;
}


/*******************************************************************
  Run elements off the packet queue till its empty
******************************************************************/

static void run_wins_packet_queue(void)
{
	struct wins_packet_struct *p;

	while ((p = packet_queue)) {
		packet_queue = p->next;
		if (packet_queue)
			packet_queue->prev = NULL;
		p->next = p->prev = NULL;

		construct_reply(p);

		/* if it was a stop assoc, close the connection */
		if (p->stop_packet) {
			FD_CLR(p->fd, listen_set);
			remove_fd_from_sock_array(p->fd);
			close(p->fd);
		}
	}
} 

/**************************************************************************** **
 The main select loop.
 **************************************************************************** */
static void process(void)
{

	while( True ) {
		time_t t = time(NULL);

		/* check for internal messages */
		message_dispatch();

		if(listen_for_wins_packets())
			return;

		run_wins_packet_queue();

		run_pull_replication(t);
		
		run_push_replication(t);
		
		/*
		 * Reload the services file if we got a sighup.
		 */

		if(reload_after_sighup) {
			reload_services( True );
			reopen_logs();
			reload_after_sighup = False;
		}

		/* free temp memory */
		talloc_destroy_pool(mem_ctx);

		/* free up temp memory */
		lp_talloc_free();
	}
} /* process */

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	/* shall I run as a daemon */
	static BOOL is_daemon = False;
	static BOOL interactive = False;
	static BOOL Fork = True;
	static BOOL log_stdout = False;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ "daemon", 'D', POPT_ARG_VAL, &is_daemon, True, "Become a daemon (default)" },
		{ "foreground", 'F', POPT_ARG_VAL, &Fork, False, "Run daemon in foreground (for daemontools, etc)" },
		{ "stdout", 'S', POPT_ARG_VAL, &log_stdout, True, "Log to stdout" },
		{ "interactive", 'i', POPT_ARG_NONE, NULL, 'i', "Run interactive (not a daemon)" },
		{ "port", 'p', POPT_ARG_INT, &wins_port, 'p', "Listen on the specified port" },
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	int opt;
	poptContext pc;

#ifdef HAVE_SET_AUTH_PARAMETERS
	set_auth_parameters(argc,argv);
#endif

	pc = poptGetContext("wrepld", argc, (const char **)argv, long_options, 
						POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt)  {
		case 'i':
			interactive = True;
			Fork = False;
			log_stdout = True;
			break;
		}
	}


	if (log_stdout && Fork) {
		d_printf("Can't log to stdout (-S) unless daemon is in foreground (-F) or interactive (-i)\n");
		poptPrintUsage(pc, stderr, 0);
		exit(1);
	}

#ifdef HAVE_SETLUID
	/* needed for SecureWare on SCO */
	setluid(0);
#endif

	sec_init();

	load_case_tables();

	set_remote_machine_name("wrepld", False);

	setup_logging(argv[0],log_stdout);

	/* we want to re-seed early to prevent time delays causing
           client problems at a later date. (tridge) */
	generate_random_buffer(NULL, 0, False);

	/* make absolutely sure we run as root - to handle cases where people
	   are crazy enough to have it setuid */

	gain_root_privilege();
	gain_root_group_privilege();

	fault_setup((void (*)(void *))exit_server);
	CatchSignal(SIGTERM , SIGNAL_CAST dflt_sig);

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

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	reopen_logs();

	DEBUG(1,( "wrepld version %s started.\n", SAMBA_VERSION_STRING));
	DEBUGADD(1,( "Copyright Andrew Tridgell and the Samba Team 1992-2004\n"));

	DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
		 (int)getuid(),(int)getgid(),(int)geteuid(),(int)getegid()));

	if (sizeof(uint16) < 2 || sizeof(uint32) < 4) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	/*
	 * Do this before reload_services.
	 */

	if (!reload_services(False))
		return(-1);	

	if (!init_names())
		return -1;
	
#ifdef WITH_PROFILE
	if (!profile_setup(False)) {
		DEBUG(0,("ERROR: failed to setup profiling\n"));
		return -1;
	}
#endif

	CatchSignal(SIGHUP,SIGNAL_CAST sig_hup);
	
	DEBUG(3,( "loaded services\n"));

	if (!is_daemon && !is_a_socket(0)) {
		DEBUG(0,("standard input is not a socket, assuming -D option\n"));
		is_daemon = True;
	}

	if (is_daemon && !interactive) {
		DEBUG( 3, ( "Becoming a daemon.\n" ) );
		become_daemon(Fork);
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
		pidfile_create("wrepld");
	}

	if (!message_init()) {
		exit(1);
	}

	/* Initialise the memory context */
	mem_ctx=talloc_init("wins repl talloc ctx");

	/* initialise the global partners table */
	partner_count=init_wins_partner_table();

	/* We can only take signals in the select. */
	BlockSignals( True, SIGTERM );

	process();

	poptFreeContext(pc);
	exit_server("normal exit");
	return(0);
}
