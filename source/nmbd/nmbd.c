/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1997
   
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

extern int DEBUGLEVEL;

extern pstring debugf;
pstring servicesf = CONFIGFILE;

extern pstring scope;

int ClientNMB            = -1;
int ClientDGRAM          = -1;
int global_nmb_port = -1;

extern pstring myhostname;
static pstring host_file;
extern pstring myname;
extern fstring myworkgroup;
extern char **my_netbios_names;

/* are we running as a daemon ? */
static BOOL is_daemon = False;

/* what server type are we currently */

time_t StartupTime =0;

extern struct in_addr ipzero;

 /****************************************************************************
  catch a sigterm
  ****************************************************************************/
static int sig_term()
{
  BlockSignals(True,SIGTERM);
  
  DEBUG(0,("Got SIGTERM: going down...\n"));
  
  /* write out wins.dat file if samba is a WINS server */
  dump_names();
  
  /* remove all samba names, with wins server if necessary. */
  remove_my_names();
  
  /* announce all server entries as 0 time-to-live, 0 type */
  /* XXXX don't care if we never receive a response back... yet */
  announce_my_servers_removed();

  /* XXXX other things: if we are a master browser, force an election? */
  
  exit(0);
  /* Keep compiler happy.. */
  return 0;
}


/****************************************************************************
catch a sighup
****************************************************************************/
static int sig_hup(void)
{
  BlockSignals(True,SIGHUP);

  DEBUG(0,("Got SIGHUP (reload not implemented)\n"));
  dump_names();
  reload_services(True);

  set_samba_nb_type();

  BlockSignals(False,SIGHUP);
#ifndef DONT_REINSTALL_SIG
  signal(SIGHUP,SIGNAL_CAST sig_hup);
#endif
  return(0);
}

/****************************************************************************
catch a sigpipe
****************************************************************************/
static int sig_pipe(void)
{
  BlockSignals(True,SIGPIPE);

  DEBUG(0,("Got SIGPIPE\n"));
  if (!is_daemon)
    exit(1);
  BlockSignals(False,SIGPIPE);
  return(0);
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
  strcat(dname,"/corefiles");
  mkdir(dname,0700);
  sys_chown(dname,getuid(),getgid());
  chmod(dname,0700);
  if (chdir(dname)) return(False);
  umask(~(0700));

#ifndef NO_GETRLIMIT
#ifdef RLIMIT_CORE
  {
    struct rlimit rlp;
    getrlimit(RLIMIT_CORE, &rlp);
    rlp.rlim_cur = MAX(4*1024*1024,rlp.rlim_cur);
    setrlimit(RLIMIT_CORE, &rlp);
    getrlimit(RLIMIT_CORE, &rlp);
    DEBUG(3,("Core limits now %d %d\n",rlp.rlim_cur,rlp.rlim_max));
  }
#endif
#endif


  DEBUG(0,("Dumping core in %s\n",dname));
  return(True);
}
#endif


/****************************************************************************
possibly continue after a fault
****************************************************************************/
static void fault_continue(void)
{
#if DUMP_CORE
  dump_core();
#endif
}

/*******************************************************************
  expire old names from the namelist and server list
  ******************************************************************/
static void expire_names_and_servers(time_t t)
{
  static time_t lastrun = 0;
  
  if (!lastrun) lastrun = t;
  if (t < lastrun + 5) return;
  lastrun = t;
  
  expire_names(t);
  expire_servers(t);
}

/*****************************************************************************
  reload the services file
  **************************************************************************/
BOOL reload_services(BOOL test)
{
  BOOL ret;
  extern fstring remote_machine;

  strcpy(remote_machine,"nmbd");

  if (lp_loaded())
    {
      pstring fname;
      pstrcpy(fname,lp_configfile());
      if (file_exist(fname,NULL) && !strcsequal(fname,servicesf))
	{
	  pstrcpy(servicesf,fname);
	  test = False;
	}
    }

  if (test && !lp_file_list_changed())
    return(True);

  ret = lp_load(servicesf,True);

  /* perhaps the config filename is now set */
  if (!test) {
    DEBUG(3,("services not loaded\n"));
    reload_services(True);
  }

  /* Do a sanity check for a misconfigured nmbd */
  if(lp_wins_support() && *lp_wins_server()) {
    DEBUG(0,("ERROR: both 'wins support = true' and 'wins server = <server>' \
cannot be set in the smb.conf file. nmbd aborting.\n"));
    exit(10);
  }

  return(ret);
}



/****************************************************************************
load a netbios hosts file
****************************************************************************/
static void load_hosts_file(char *fname)
{
  FILE *f = fopen(fname,"r");
  pstring line;
  if (!f) {
    DEBUG(2,("Can't open lmhosts file %s\n",fname));
    return;
  }

  while (!feof(f))
    {
      pstring ip,name,flags,extra;
      struct subnet_record *d;
      char *ptr;
      int count = 0;
      struct in_addr ipaddr;
      enum name_source source = LMHOSTS;

      if (!fgets_slash(line,sizeof(pstring),f)) continue;

      if (*line == '#') continue;

      strcpy(ip,"");
      strcpy(name,"");
      strcpy(flags,"");
      
      ptr = line;
      
      if (next_token(&ptr,ip   ,NULL)) ++count;
      if (next_token(&ptr,name ,NULL)) ++count;
      if (next_token(&ptr,flags,NULL)) ++count;
      if (next_token(&ptr,extra,NULL)) ++count;
      
      if (count <= 0) continue;
      
      if (count > 0 && count < 2) {
	DEBUG(0,("Ill formed hosts line [%s]\n",line));	    
	continue;
      }
      
      if (count >= 4) {
	DEBUG(0,("too many columns in %s (obsolete syntax)\n",fname));
	continue;
      }
      
      DEBUG(4, ("lmhost entry: %s %s %s\n", ip, name, flags));
      
      if (strchr(flags,'G') || strchr(flags,'S')) {
	DEBUG(0,("group flag in %s ignored (obsolete)\n",fname));
	continue;
      }
      
      if (strchr(flags,'M')) {
	source = SELF;
	pstrcpy(myname,name);
      }
      
      ipaddr = *interpret_addr2(ip);
      d = find_subnet_all(ipaddr);
      if (d) {
	add_netbios_entry(d,name,0x00,NB_ACTIVE,0,source,ipaddr,True);
	add_netbios_entry(d,name,0x20,NB_ACTIVE,0,source,ipaddr,True);
      } 
    }
  
  fclose(f);
}


/****************************************************************************
  The main select loop.
  ***************************************************************************/
static void process(void)
{
  BOOL run_election;

  while (True)
    {
      time_t t = time(NULL);
      run_election = check_elections();
      if(listen_for_packets(run_election))
        return;

      run_packet_queue();
      run_elections(t);

      announce_host(t);
      announce_master(t);
      announce_remote(t);
      browse_sync_remote(t);

      query_refresh_names(t);

      expire_names_and_servers(t);
      expire_netbios_response_entries(t);
      refresh_my_names(t);

      write_browse_list(t);
      do_browser_lists(t);
      check_master_browser(t);
      add_domain_names(t);
    }
}


/****************************************************************************
  open the socket communication
****************************************************************************/
static BOOL open_sockets(BOOL isdaemon, int port)
{
  /* The sockets opened here will be used to receive broadcast
     packets *only*. Interface specific sockets are opened in
     make_subnet() in namedbsubnet.c. Thus we bind to the
     address "0.0.0.0". The parameter 'socket address' is
     now deprecated.
   */

  if (isdaemon)
    ClientNMB = open_socket_in(SOCK_DGRAM, port,0,0);
  else
    ClientNMB = 0;
  
  ClientDGRAM = open_socket_in(SOCK_DGRAM,DGRAM_PORT,3,0);

  if (ClientNMB == -1)
    return(False);

  signal(SIGPIPE, SIGNAL_CAST sig_pipe);

  set_socket_options(ClientNMB,"SO_BROADCAST");
  set_socket_options(ClientDGRAM,"SO_BROADCAST");

  DEBUG(3,("open_sockets: Broadcast sockets opened.\n"));
  return True;
}


/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static BOOL init_structs()
{
  extern fstring local_machine;
  char *p, *ptr;
  int namecount;
  int n;
  int nodup;
  pstring nbname;

  if (! *myname) {
    fstrcpy(myname,myhostname);
    p = strchr(myname,'.');
    if (p) *p = 0;
  }
  strupper(myname);

  /* Add any NETBIOS name aliases. Ensure that the first entry
     is equal to myname. */
  /* Work out the max number of netbios aliases that we have */
  ptr=lp_netbios_aliases();
  for (namecount=0; next_token(&ptr,nbname,NULL); namecount++)
    ;
  if (*myname)
      namecount++;

  /* Allocate space for the netbios aliases */
  if((my_netbios_names=(char **)malloc(sizeof(char *)*(namecount+1))) == NULL)
  {
     DEBUG(0,("init_structs: malloc fail.\n"));
     return False;
  }
 
  /* Use the myname string first */
  namecount=0;
  if (*myname)
    my_netbios_names[namecount++] = myname;
  
  ptr=lp_netbios_aliases();
  while (next_token(&ptr,nbname,NULL)) {
    strupper(nbname);
    /* Look for duplicates */
    nodup=1;
    for(n=0; n<namecount; n++) {
      if (strcmp(nbname, my_netbios_names[n])==0)
        nodup=0;
    }
    if (nodup)
      my_netbios_names[namecount++]=strdup(nbname);
  }
  
  /* Check the strdups succeeded. */
  for(n = 0; n < namecount; n++)
    if(my_netbios_names[n]==NULL)
    {
      DEBUG(0,("init_structs: malloc fail when allocating names.\n"));
      return False;
    }
  
  /* Terminate name list */
  my_netbios_names[namecount++]=NULL;
  
  fstrcpy(local_machine,myname);
  trim_string(local_machine," "," ");
  p = strchr(local_machine,' ');
  if (p) 
    *p = 0;
  strlower(local_machine);

  DEBUG(5, ("Netbios name list:-\n"));
  for (n=0; my_netbios_names[n]; n++)
    DEBUG(5, ("my_netbios_names[%d]=\"%s\"\n", n, my_netbios_names[n]));

  return True;
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Incorrect program usage - is the command line correct?\n"));

  printf("Usage: %s [-n name] [-D] [-p port] [-d debuglevel] [-l log basename]\n",pname);
  printf("Version %s\n",VERSION);
  printf("\t-D                    become a daemon\n");
  printf("\t-p port               listen on the specified port\n");
  printf("\t-d debuglevel         set the debuglevel\n");
  printf("\t-l log basename.      Basename for log/debug files\n");
  printf("\t-n netbiosname.       the netbios name to advertise for this host\n");
  printf("\t-H hosts file        load a netbios hosts file\n");
  printf("\n");
}


/****************************************************************************
  main program
  **************************************************************************/
 int main(int argc,char *argv[])
{
  int opt;
  extern FILE *dbf;
  extern char *optarg;
  char pidFile[100] = { 0 };

  global_nmb_port = NMB_PORT;
  *host_file = 0;

  StartupTime = time(NULL);

  TimeInit();

  strcpy(debugf,NMBLOGFILE);

  setup_logging(argv[0],False);

  charset_initialise();

#ifdef LMHOSTSFILE
  strcpy(host_file,LMHOSTSFILE);
#endif

  /* this is for people who can't start the program correctly */
  while (argc > 1 && (*argv[1] != '-')) {
    argv++;
    argc--;
  }

  fault_setup(fault_continue);

  signal(SIGHUP ,SIGNAL_CAST sig_hup);
  signal(SIGTERM,SIGNAL_CAST sig_term);

  while ((opt = getopt(argc, argv, "as:T:I:C:bAi:B:N:Rn:l:d:Dp:hSH:G:f:")) != EOF)
    {
      switch (opt)
	{
        case 'f':
          strncpy(pidFile, optarg, sizeof(pidFile));
          break;
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
	  pstrcpy(myname,optarg);
	  strupper(myname);
	  break;
	case 'l':
	  sprintf(debugf,"%s.nmb",optarg);
	  break;
	case 'i':
	  pstrcpy(scope,optarg);
	  strupper(scope);
	  break;
	case 'a':
		{
			extern BOOL append_log;
			append_log = !append_log;
		}
		break;
	case 'D':
	  is_daemon = True;
	  break;
	case 'd':
	  DEBUGLEVEL = atoi(optarg);
	  break;
	case 'p':
	  global_nmb_port = atoi(optarg);
	  break;
	case 'h':
	  usage(argv[0]);
	  exit(0);
	  break;
	default:
	  if (!is_a_socket(0)) {
	    usage(argv[0]);
	  }
	  break;
	}
    }

  DEBUG(1,("%s netbios nameserver version %s started\n",timestring(),VERSION));
  DEBUG(1,("Copyright Andrew Tridgell 1994-1997\n"));

  if(!get_myname(myhostname,NULL))
  {
    DEBUG(0,("Unable to get my hostname - exiting.\n"));
    return -1;
  }

#ifndef SYNC_DNS
  start_async_dns();
#endif

  if (!reload_services(False))
    return(-1);	

  codepage_initialise(lp_client_code_page());

  if(!init_structs())
    return -1;

  reload_services(True);

  pstrcpy(myworkgroup, lp_workgroup());

  if (strequal(myworkgroup,"*")) {
    DEBUG(0,("ERROR: a workgroup name of * is no longer supported\n"));
    exit(1);
  }

  set_samba_nb_type();

  if (!is_daemon && !is_a_socket(0)) {
    DEBUG(0,("standard input is not a socket, assuming -D option\n"));
    is_daemon = True;
  }
  
  if (is_daemon) {
    DEBUG(2,("%s becoming a daemon\n",timestring()));
    become_daemon();
  }

  if (!directory_exist(lp_lockdir(), NULL)) {
	  mkdir(lp_lockdir(), 0755);
  }

  if (*pidFile)
    {
      int     fd;
      char    buf[20];

      if ((fd = open(pidFile,
#ifdef O_NONBLOCK
        O_NONBLOCK | 
#endif
        O_CREAT | O_WRONLY | O_TRUNC, 0644)) < 0)
        {
          DEBUG(0,("ERROR: can't open %s: %s\n", pidFile, strerror(errno)));
          exit(1);
        }
      if (fcntl_lock(fd,F_SETLK,0,1,F_WRLCK)==False)
        {
          DEBUG(0,("ERROR: nmbd is already running\n"));
          exit(1);
        }
      sprintf(buf, "%u\n", (unsigned int) getpid());
      if (write(fd, buf, strlen(buf)) < 0)
        {
          DEBUG(0,("ERROR: can't write to %s: %s\n", pidFile, strerror(errno)));
          exit(1);
        }
      /* Leave pid file open & locked for the duration... */
    }


  DEBUG(3,("Opening sockets %d\n", global_nmb_port));

  if (!open_sockets(is_daemon,global_nmb_port)) return 1;

  load_interfaces();
  add_my_subnets(myworkgroup);

  add_my_names();

  DEBUG(3,("Checked names\n"));
  
  load_netbios_names();

  DEBUG(3,("Loaded names\n"));

  if (*host_file) {
    load_hosts_file(host_file);
    DEBUG(3,("Loaded hosts file\n"));
  }

  write_browse_list(time(NULL));

  DEBUG(3,("Dumped names\n"));

  /* We can only take sigterm signals in the select. */
  BlockSignals(True,SIGTERM);

  process();
  close_sockets();

  if (dbf)
    fclose(dbf);
  return(0);
}
