/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1998
   
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
   
   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

*/

#include "includes.h"

pstring servicesf = CONFIGFILE;

int ClientNMB       = -1;
int ClientDGRAM     = -1;
int global_nmb_port = -1;

static pstring host_file;
extern pstring global_myname;
extern fstring global_myworkgroup;
extern char **my_netbios_names;

extern BOOL global_in_nmbd;

/* are we running as a daemon ? */
static BOOL is_daemon = False;

/* have we found LanMan clients yet? */
BOOL found_lm_clients = False;

/* what server type are we currently */

time_t StartupTime = 0;

/**************************************************************************** **
 Handle a SIGTERM in band.
 **************************************************************************** */

static void terminate(void)
{
	DEBUG(0,("Got SIGTERM: going down...\n"));

	/* Write out wins.dat file if samba is a WINS server */
	wins_write_database(False);

	/* Remove all SELF registered names. */
	release_my_names();

	/* Announce all server entries as 0 time-to-live, 0 type. */
	announce_my_servers_removed();

	/* If there was an async dns child - kill it. */
	kill_async_dns_child();

	exit(0);
}

/**************************************************************************** **
 Catch a SIGTERM signal.
 **************************************************************************** */

static SIG_ATOMIC_T got_sig_term;

static void sig_term(int sig)
{
	got_sig_term = 1;
	sys_select_signal();
}

/**************************************************************************** **
 Catch a SIGHUP signal.
 **************************************************************************** */

static SIG_ATOMIC_T reload_after_sighup;

static void sig_hup(int sig)
{
	reload_after_sighup = 1;
	sys_select_signal();
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
 Possibly continue after a fault.
 **************************************************************************** */

static void fault_continue(void)
{
#if DUMP_CORE
  dump_core();
#endif
} /* fault_continue */

/**************************************************************************** **
 Expire old names from the namelist and server list.
 **************************************************************************** */

static void expire_names_and_servers(time_t t)
{
  static time_t lastrun = 0;
  
  if ( !lastrun )
    lastrun = t;
  if ( t < (lastrun + 5) )
    return;
  lastrun = t;

  /*
   * Expire any timed out names on all the broadcast
   * subnets and those registered with the WINS server.
   * (nmbd_namelistdb.c)
   */
  expire_names(t);

  /*
   * Go through all the broadcast subnets and for each
   * workgroup known on that subnet remove any expired
   * server names. If a workgroup has an empty serverlist
   * and has itself timed out then remove the workgroup.
   * (nmbd_workgroupdb.c)
   */
  expire_workgroups_and_servers(t);
} /* expire_names_and_servers */

/************************************************************************** **
 Reload the list of network interfaces.
 ************************************************************************** */

static BOOL reload_interfaces(time_t t)
{
	static time_t lastt;
	int n;
	struct subnet_record *subrec;
	extern BOOL rescan_listen_set;
	extern struct in_addr loopback_ip;

	if (t && ((t - lastt) < NMBD_INTERFACES_RELOAD)) return False;
	lastt = t;

	if (!interfaces_changed()) return False;

	/* the list of probed interfaces has changed, we may need to add/remove
	   some subnets */
	load_interfaces();

	/* find any interfaces that need adding */
	for (n=iface_count() - 1; n >= 0; n--) {
		struct interface *iface = get_interface(n);

		/*
		 * We don't want to add a loopback interface, in case
		 * someone has added 127.0.0.1 for smbd, nmbd needs to
		 * ignore it here. JRA.
		 */

		if (ip_equal(iface->ip, loopback_ip)) {
			DEBUG(2,("reload_interfaces: Ignoring loopback interface %s\n", inet_ntoa(iface->ip)));
			continue;
		}

		for (subrec=subnetlist; subrec; subrec=subrec->next) {
			if (ip_equal(iface->ip, subrec->myip) &&
			    ip_equal(iface->nmask, subrec->mask_ip)) break;
		}

		if (!subrec) {
			/* it wasn't found! add it */
			DEBUG(2,("Found new interface %s\n", 
				 inet_ntoa(iface->ip)));
			subrec = make_normal_subnet(iface);
			if (subrec) register_my_workgroup_one_subnet(subrec);
		}
	}

	/* find any interfaces that need deleting */
	for (subrec=subnetlist; subrec; subrec=subrec->next) {
		for (n=iface_count() - 1; n >= 0; n--) {
			struct interface *iface = get_interface(n);
			if (ip_equal(iface->ip, subrec->myip) &&
			    ip_equal(iface->nmask, subrec->mask_ip)) break;
		}
		if (n == -1) {
			/* oops, an interface has disapeared. This is
			 tricky, we don't dare actually free the
			 interface as it could be being used, so
			 instead we just wear the memory leak and
			 remove it from the list of interfaces without
			 freeing it */
			DEBUG(2,("Deleting dead interface %s\n", 
				 inet_ntoa(subrec->myip)));
			close_subnet(subrec);
		}
	}
	
	rescan_listen_set = True;

	/* We need to shutdown if there are no subnets... */
	if (FIRST_SUBNET == NULL) {
		DEBUG(0,("reload_interfaces: No subnets to listen to. Shutting down...\n"));
		return True;
	}
	return False;
}

/**************************************************************************** **
 Reload the services file.
 **************************************************************************** */

static BOOL reload_nmbd_services(BOOL test)
{
  BOOL ret;
  extern fstring remote_machine;

  fstrcpy( remote_machine, "nmbd" );

  if ( lp_loaded() )
  {
    pstring fname;
    pstrcpy( fname,lp_configfile());
    if (file_exist(fname,NULL) && !strcsequal(fname,servicesf))
    {
      pstrcpy(servicesf,fname);
      test = False;
    }
  }

  if ( test && !lp_file_list_changed() )
    return(True);

  ret = lp_load( servicesf, True , False, False);

  /* perhaps the config filename is now set */
  if ( !test )
  {
    DEBUG( 3, ( "services not loaded\n" ) );
    reload_nmbd_services( True );
  }

  /* Do a sanity check for a misconfigured nmbd */
  if( lp_wins_support() && *lp_wins_server() )
  {
    DEBUG(0,("ERROR: both 'wins support = true' and 'wins server = <server>' \
cannot be set in the smb.conf file. nmbd aborting.\n"));
    exit(10);
  }

  return(ret);
} /* reload_nmbd_services */

/**************************************************************************** **
 The main select loop.
 **************************************************************************** */

static void process(void)
{
  BOOL run_election;

  while( True )
  {
    time_t t = time(NULL);

    /* check for internal messages */
    message_dispatch();

    /*
     * Check all broadcast subnets to see if
     * we need to run an election on any of them.
     * (nmbd_elections.c)
     */
    run_election = check_elections();

    /*
     * Read incoming UDP packets.
     * (nmbd_packets.c)
     */
    if(listen_for_packets(run_election))
      return;

    /*
     * Handle termination inband.
     */

    if (got_sig_term) {
      got_sig_term = 0;
      terminate();
    }

    /*
     * Process all incoming packets
     * read above. This calls the success and
     * failure functions registered when response
     * packets arrrive, and also deals with request
     * packets from other sources.
     * (nmbd_packets.c)
     */
    run_packet_queue();

    /*
     * Run any elections - initiate becoming
     * a local master browser if we have won.
     * (nmbd_elections.c)
     */
    run_elections(t);

    /*
     * Send out any broadcast announcements
     * of our server names. This also announces
     * the workgroup name if we are a local
     * master browser.
     * (nmbd_sendannounce.c)
     */
    announce_my_server_names(t);

    /*
     * Send out any LanMan broadcast announcements
     * of our server names.
     * (nmbd_sendannounce.c)
     */
    announce_my_lm_server_names(t);

    /*
     * If we are a local master browser, periodically
     * announce ourselves to the domain master browser.
     * This also deals with syncronising the domain master
     * browser server lists with ourselves as a local
     * master browser.
     * (nmbd_sendannounce.c)
     */
    announce_myself_to_domain_master_browser(t);

    /*
     * Fullfill any remote announce requests.
     * (nmbd_sendannounce.c)
     */
    announce_remote(t);

    /*
     * Fullfill any remote browse sync announce requests.
     * (nmbd_sendannounce.c)
     */
    browse_sync_remote(t);

    /*
     * Scan the broadcast subnets, and WINS client
     * namelists and refresh any that need refreshing.
     * (nmbd_mynames.c)
     */
    refresh_my_names(t);

    /*
     * Scan the subnet namelists and server lists and
     * expire thos that have timed out.
     * (nmbd.c)
     */
    expire_names_and_servers(t);

    /*
     * Write out a snapshot of our current browse list into
     * the browse.dat file. This is used by smbd to service
     * incoming NetServerEnum calls - used to synchronise
     * browse lists over subnets.
     * (nmbd_serverlistdb.c)
     */
    write_browse_list(t, False);

    /*
     * If we are a domain master browser, we have a list of
     * local master browsers we should synchronise browse
     * lists with (these are added by an incoming local
     * master browser announcement packet). Expire any of
     * these that are no longer current, and pull the server
     * lists from each of these known local master browsers.
     * (nmbd_browsesync.c)
     */
    dmb_expire_and_sync_browser_lists(t);

    /*
     * Check that there is a local master browser for our
     * workgroup for all our broadcast subnets. If one
     * is not found, start an election (which we ourselves
     * may or may not participate in, depending on the
     * setting of the 'local master' parameter.
     * (nmbd_elections.c)
     */
    check_master_browser_exists(t);

    /*
     * If we are configured as a logon server, attempt to
     * register the special NetBIOS names to become such
     * (WORKGROUP<1c> name) on all broadcast subnets and
     * with the WINS server (if used). If we are configured
     * to become a domain master browser, attempt to register
     * the special NetBIOS name (WORKGROUP<1b> name) to
     * become such.
     * (nmbd_become_dmb.c)
     */
    add_domain_names(t);

    /*
     * If we are a WINS server, do any timer dependent
     * processing required.
     * (nmbd_winsserver.c)
     */
    initiate_wins_processing(t);

    /*
     * If we are a domain master browser, attempt to contact the
     * WINS server to get a list of all known WORKGROUPS/DOMAINS.
     * This will only work to a Samba WINS server.
     * (nmbd_browsesync.c)
     */
    if (lp_enhanced_browsing()) {
	    collect_all_workgroup_names_from_wins_server(t);
    }

    /*
     * Go through the response record queue and time out or re-transmit
     * and expired entries.
     * (nmbd_packets.c)
     */
    retransmit_or_expire_response_records(t);

    /*
     * check to see if any remote browse sync child processes have completed
     */
    sync_check_completion();

    /*
     * regularly sync with any other DMBs we know about 
     */
    if (lp_enhanced_browsing()) {
	    sync_all_dmbs(t);
    }

    /*
     * clear the unexpected packet queue 
     */
    clear_unexpected(t);

    /*
     * Reload the services file if we got a sighup.
     */

    if(reload_after_sighup) {
      DEBUG( 0, ( "Got SIGHUP dumping debug info.\n" ) );
      write_browse_list( 0, True );
      dump_all_namelists();
      reload_nmbd_services( True );
      reopen_logs();
      if(reload_interfaces(0))
        return;
      reload_after_sighup = 0;
    }

    /* check for new network interfaces */
    if(reload_interfaces(t))
		return;

    /* free up temp memory */
    lp_talloc_free();
  }
} /* process */

/**************************************************************************** **
 Open the socket communication.
 **************************************************************************** */

static BOOL open_sockets(BOOL isdaemon, int port)
{
  /* The sockets opened here will be used to receive broadcast
     packets *only*. Interface specific sockets are opened in
     make_subnet() in namedbsubnet.c. Thus we bind to the
     address "0.0.0.0". The parameter 'socket address' is
     now deprecated.
   */

  if ( isdaemon )
    ClientNMB = open_socket_in(SOCK_DGRAM, port,0,0,True);
  else
    ClientNMB = 0;
  
  ClientDGRAM = open_socket_in(SOCK_DGRAM,DGRAM_PORT,3,0,True);

  if ( ClientNMB == -1 )
    return( False );

  /* we are never interested in SIGPIPE */
  BlockSignals(True,SIGPIPE);

  set_socket_options( ClientNMB,   "SO_BROADCAST" );
  set_socket_options( ClientDGRAM, "SO_BROADCAST" );

  DEBUG( 3, ( "open_sockets: Broadcast sockets opened.\n" ) );
  return( True );
} /* open_sockets */

/**************************************************************************** **
 Initialise connect, service and file structs.
 **************************************************************************** */

static BOOL init_structs(void)
{
  extern fstring local_machine;
  char *p;
  const char *ptr;
  int namecount;
  int n;
  int nodup;
  pstring nbname;

  if (! *global_myname)
  {
    fstrcpy( global_myname, myhostname() );
    p = strchr( global_myname, '.' );
    if (p)
      *p = 0;
  }
  strupper( global_myname );

  /* Add any NETBIOS name aliases. Ensure that the first entry
     is equal to global_myname.
   */
  /* Work out the max number of netbios aliases that we have */
  ptr = lp_netbios_aliases();
  for( namecount=0; next_token(&ptr,nbname,NULL, sizeof(nbname)); namecount++ )
    ;
  if ( *global_myname )
    namecount++;

  /* Allocate space for the netbios aliases */
  my_netbios_names = (char **)malloc( sizeof(char *) * (namecount+1) );
  if( NULL == my_netbios_names )
  {
     DEBUG( 0, ( "init_structs: malloc fail.\n" ) );
     return( False );
  }
 
  /* Use the global_myname string first */
  namecount=0;
  if ( *global_myname )
    my_netbios_names[namecount++] = global_myname;
  
  ptr = lp_netbios_aliases();
  while ( next_token( &ptr, nbname, NULL, sizeof(nbname) ) )
  {
    strupper( nbname );
    /* Look for duplicates */
    nodup=1;
    for( n=0; n<namecount; n++ )
    {
      if( 0 == strcmp( nbname, my_netbios_names[n] ) )
        nodup=0;
    }
    if (nodup)
      my_netbios_names[namecount++] = strdup( nbname );
  }
  
  /* Check the strdups succeeded. */
  for( n = 0; n < namecount; n++ )
    if( NULL == my_netbios_names[n] )
    {
      DEBUG(0,("init_structs: malloc fail when allocating names.\n"));
      return False;
    }
  
  /* Terminate name list */
  my_netbios_names[namecount++] = NULL;
  
  fstrcpy( local_machine, global_myname );
  trim_string( local_machine, " ", " " );
  p = strchr( local_machine, ' ' );
  if (p)
    *p = 0;
  strlower( local_machine );

  DEBUG( 5, ("Netbios name list:-\n") );
  for( n=0; my_netbios_names[n]; n++ )
    DEBUGADD( 5, ( "my_netbios_names[%d]=\"%s\"\n", n, my_netbios_names[n] ) );

  return( True );
} /* init_structs */

/**************************************************************************** **
 Usage on the program.
 **************************************************************************** */

static void usage(char *pname)
{

  printf( "Usage: %s [-DaiohV] [-H lmhosts file] [-d debuglevel] [-l log basename]\n", pname );
  printf( "       [-n name] [-p port] [-s configuration file]\n" );
  printf( "\t-D                    Become a daemon (default)\n" );
  printf( "\t-a                    Append to log file (default)\n" );
  printf( "\t-i                    Run interactive (not a daemon)\n" );
  printf( "\t-o                    Overwrite log file, don't append\n" );
  printf( "\t-h                    Print usage\n" );
  printf( "\t-V                    Print version\n" );
  printf( "\t-H hosts file         Load a netbios hosts file\n" );
  printf( "\t-d debuglevel         Set the debuglevel\n" );
  printf( "\t-l log basename.      Basename for log/debug files\n" );
  printf( "\t-n netbiosname.       Primary netbios name\n" );
  printf( "\t-p port               Listen on the specified port\n" );
  printf( "\t-s configuration file Configuration file name\n" );
  printf( "\n");
} /* usage */


/**************************************************************************** **
 Main program.
 **************************************************************************** */

 int main(int argc,char *argv[])
{
  int opt;
  extern FILE *dbf;
  extern char *optarg;
  extern BOOL  append_log;
  extern BOOL AllowDebugChange;
  BOOL opt_interactive = False;
  pstring logfile;

  append_log = True;  /* Default, override with '-o' option. */

  global_nmb_port = NMB_PORT;
  *host_file = 0;
  global_in_nmbd = True;

  StartupTime = time(NULL);

  sys_srandom(time(NULL) ^ sys_getpid());

  TimeInit();

  slprintf(logfile, sizeof(logfile)-1, "%s/log.nmbd", LOGFILEBASE);
  lp_set_logfile(logfile);

  charset_initialise();

#ifdef LMHOSTSFILE
  pstrcpy( host_file, LMHOSTSFILE );
#endif

  /* this is for people who can't start the program correctly */
  while (argc > 1 && (*argv[1] != '-'))
  {
    argv++;
    argc--;
  }

  fault_setup((void (*)(void *))fault_continue );

  /* POSIX demands that signals are inherited. If the invoking process has
   * these signals masked, we will have problems, as we won't recieve them. */
  BlockSignals(False, SIGHUP);
  BlockSignals(False, SIGUSR1);
  BlockSignals(False, SIGTERM);

  CatchSignal( SIGHUP,  SIGNAL_CAST sig_hup );
  CatchSignal( SIGTERM, SIGNAL_CAST sig_term );

#if defined(SIGFPE)
  /* we are never interested in SIGFPE */
  BlockSignals(True,SIGFPE);
#endif

  /* We no longer use USR2... */
#if defined(SIGUSR2)
  BlockSignals(True, SIGUSR2);
#endif

  while( EOF != 
         (opt = getopt( argc, argv, "Vaos:T:I:C:bAB:N:Rn:l:d:Dip:hSH:G:f:" )) )
    {
      switch (opt)
        {
        case 's':
          pstrcpy(servicesf,optarg);
          break;          
        case 'N':
        case 'B':
        case 'I':
        case 'C':
        case 'G':
          DEBUG(0,("Obsolete option '%c' used\n",opt));
          break;
        case 'H':
          pstrcpy(host_file,optarg);
          break;
        case 'n':
          pstrcpy(global_myname,optarg);
          strupper(global_myname);
          break;
        case 'l':
          slprintf(logfile, sizeof(logfile)-1, "%s/log.nmbd", optarg);
          lp_set_logfile(logfile);
          break;
        case 'a':
          append_log = True;
          break;
        case 'o':
          append_log = False;
          break;
        case 'i':
          opt_interactive = True;
          break;
        case 'D':
          is_daemon = True;
          break;
        case 'd':
          DEBUGLEVEL = atoi(optarg);
	  AllowDebugChange = False;
          break;
        case 'p':
          global_nmb_port = atoi(optarg);
          break;
        case 'h':
          usage(argv[0]);
          exit(0);
          break;
        case 'V':
	  printf( "Version %s\n", VERSION );
          exit(0);
          break;
        default:
          if( !is_a_socket(0) )
          {
	    DEBUG(0,("Incorrect program usage - is the command line correct?\n"));
            usage(argv[0]);
            exit(0);
          }
          break;
        }
    }

  setup_logging( argv[0], opt_interactive );
  reopen_logs();

  DEBUG( 0, ( "Netbios nameserver version %s started.\n", VERSION ) );
  DEBUGADD( 0, ( "Copyright Andrew Tridgell and the Samba Team 1994-2002\n" ) );

  if ( !reload_nmbd_services(False) )
    return(-1);

#ifdef WITH_PROFILE
  if (!profile_setup(False)) {
	DEBUG(0,("ERROR: failed to setup profiling shared memory\n"));
	return -1;
  }
#endif /* WITH_PROFILE */

  codepage_initialise(lp_client_code_page());

  if(!init_structs())
    return -1;

  reload_nmbd_services( True );

  fstrcpy( global_myworkgroup, lp_workgroup() );

  if (strequal(global_myworkgroup,"*"))
  {
    DEBUG(0,("ERROR: a workgroup name of * is no longer supported\n"));
    exit(1);
  }

  set_samba_nb_type();

  if (!is_daemon && !is_a_socket(0))
  {
    DEBUG(0,("standard input is not a socket, assuming -D option\n"));
    is_daemon = True;
  }
  
  if (is_daemon && !opt_interactive)
  {
    DEBUG( 2, ( "Becoming a daemon.\n" ) );
    become_daemon();
  }

#if HAVE_SETPGID
  /*
   * If we're interactive we want to set our own process group for 
   * signal management.
   */
  if (opt_interactive)
    setpgid( (pid_t)0, (pid_t)0 );
#endif

#ifndef SYNC_DNS
  /* Setup the async dns. We do it here so it doesn't have all the other
     stuff initialised and thus chewing memory and sockets */
  if(lp_we_are_a_wins_server()) {
	  start_async_dns();
  }
#endif

  if (!directory_exist(lp_lockdir(), NULL)) {
	  mkdir(lp_lockdir(), 0755);
  }

  pidfile_create("nmbd");
  message_init();
  message_register(MSG_FORCE_ELECTION, nmbd_message_election);

  DEBUG( 3, ( "Opening sockets %d\n", global_nmb_port ) );

  if ( !open_sockets( is_daemon, global_nmb_port ) )
    return 1;

  /* Determine all the IP addresses we have. */
  load_interfaces();

  /* Create an nmbd subnet record for each of the above. */
  if( False == create_subnets() )
  {
    DEBUG(0,("ERROR: Failed when creating subnet lists. Exiting.\n"));
    exit(1);
  }

  /* Load in any static local names. */ 
  if ( *host_file )
  {
    load_lmhosts_file(host_file);
    DEBUG(3,("Loaded hosts file\n"));
  }

  /* If we are acting as a WINS server, initialise data structures. */
  if( !initialise_wins() )
  {
    DEBUG( 0, ( "nmbd: Failed when initialising WINS server.\n" ) );
    exit(1);
  }

  /* 
   * Register nmbd primary workgroup and nmbd names on all
   * the broadcast subnets, and on the WINS server (if specified).
   * Also initiate the startup of our primary workgroup (start
   * elections if we are setup as being able to be a local
   * master browser.
   */

  if( False == register_my_workgroup_and_names() )
  {
    DEBUG(0,("ERROR: Failed when creating my my workgroup. Exiting.\n"));
    exit(1);
  }

  /* We can only take signals in the select. */
  BlockSignals( True, SIGTERM );

  process();

  if (dbf)
    fclose(dbf);
  return(0);
} /* main */
