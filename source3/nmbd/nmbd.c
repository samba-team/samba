/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1995
   
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

int ClientNMB   = -1;
int ClientDGRAM = -1;

extern pstring myhostname;
static pstring host_file;
extern pstring myname;

/* are we running as a daemon ? */
static BOOL is_daemon = False;

/* machine comment for host announcements */
pstring ServerComment="";

/* what server type are we currently */

time_t StartupTime =0;

extern struct in_addr ipzero;

 /****************************************************************************
  catch a sigterm
  ****************************************************************************/
static int sig_term()
{
  BlockSignals(True);
  
  DEBUG(0,("Got SIGTERM: going down...\n"));
  
  /* write out wins.dat file if samba is a WINS server */
  dump_names();
  
  /* remove all samba names, with wins server if necessary. */
  remove_my_names();
  
  /* announce all server entries as 0 time-to-live, 0 type */
  /* XXXX don't care if we never receive a response back... yet */
  remove_my_servers();

  /* XXXX other things: if we are a master browser, force an election? */
  
  exit(0);
}


/****************************************************************************
catch a sighup
****************************************************************************/
static int sig_hup(void)
{
  BlockSignals(True);

  DEBUG(0,("Got SIGHUP (reload not implemented)\n"));
  dump_names();
  reload_services(True);

  set_samba_nb_type();

  BlockSignals(False);
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
  BlockSignals(True);

  DEBUG(0,("Got SIGPIPE\n"));
  if (!is_daemon)
    exit(1);
  BlockSignals(False);
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
  strcpy(dname,debugf);
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
static void expire_names_and_servers(void)
{
  static time_t lastrun = 0;
  time_t t = time(NULL);
  
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
      strcpy(fname,lp_configfile());
      if (file_exist(fname,NULL) && !strcsequal(fname,servicesf))
	{
	  strcpy(servicesf,fname);
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

  load_interfaces();
  add_subnet_interfaces();

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
      if (!fgets_slash(line,sizeof(pstring),f)) continue;

      if (*line == '#') continue;

      {
	BOOL group=False;

	pstring ip,name,mask,flags,extra;

	char *ptr;
	int count = 0;
	struct in_addr ipaddr;
	struct in_addr ipmask;
	enum name_source source = LMHOSTS;

	strcpy(ip,"");
	strcpy(name,"");
	strcpy(mask,"");
	strcpy(flags,"");
	strcpy(extra,"");
	
	ptr = line;

	if (next_token(&ptr,ip   ,NULL)) ++count;
	if (next_token(&ptr,name ,NULL)) ++count;
	if (next_token(&ptr,mask ,NULL)) ++count;
	if (next_token(&ptr,flags,NULL)) ++count;
	if (next_token(&ptr,extra,NULL)) ++count;

	if (count <= 0) continue;

	if (count > 0 && count < 2) {
	  DEBUG(0,("Ill formed hosts line [%s]\n",line));	    
	  continue;
	}

	/* work out if we need to shuffle the tokens along due to the
	   optional subnet mask argument */

	if (strchr(mask, 'G') || strchr(mask, 'S') || strchr(mask, 'M')) {
	  strcpy(flags, mask );
	  /* default action for no subnet mask */
	  strcpy(mask, "");
	}

	DEBUG(4, ("lmhost entry: %s %s %s %s\n", ip, name, mask, flags));

	if (strchr(flags,'G') || strchr(flags,'S'))
	  group = True;

	if (strchr(flags,'M') && !group) {
	  source = SELF;
	  strcpy(myname,name);
	}

	ipaddr = *interpret_addr2(ip);
	if (*mask)
	  ipmask = *interpret_addr2(mask);
	else 
	  ipmask = *iface_nmask(ipaddr);

	if (group) {
	  add_subnet_entry(ipaddr, ipmask, name, True, True);
	} else {
      struct subnet_record *d = find_subnet(ipaddr);
      if (d)
      {
	    add_netbios_entry(d,name,0x00,NB_ACTIVE,0,source,ipaddr,True,True);
	    add_netbios_entry(d,name,0x20,NB_ACTIVE,0,source,ipaddr,True,True);
      }
	}
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
      listen_for_packets(run_election);

      run_packet_queue();
      run_elections();

      announce_host();

#if 1
      /* XXXX what was this stuff supposed to do? It sent
	 ANN_GetBackupListReq packets which I think should only be
	 sent when trying to find out who to browse with */	 

      announce_backup();
#endif

      announce_master();

      query_refresh_names();

      expire_names_and_servers();
      expire_netbios_response_entries();
      refresh_my_names(t);

      write_browse_list();
      do_browser_lists();
      check_master_browser();
    }
}


/****************************************************************************
  open the socket communication
****************************************************************************/
static BOOL open_sockets(BOOL isdaemon, int port)
{
  struct hostent *hp;
 
  /* get host info */
  if ((hp = Get_Hostbyname(myhostname)) == 0) {
    DEBUG(0,( "Get_Hostbyname: Unknown host. %s\n",myhostname));
    return False;
  }   

  if (isdaemon)
    ClientNMB = open_socket_in(SOCK_DGRAM, port,0);
  else
    ClientNMB = 0;
  
  ClientDGRAM = open_socket_in(SOCK_DGRAM,DGRAM_PORT,3);

  if (ClientNMB == -1)
    return(False);

  signal(SIGPIPE, SIGNAL_CAST sig_pipe);

  set_socket_options(ClientNMB,"SO_BROADCAST");
  set_socket_options(ClientDGRAM,"SO_BROADCAST");

  DEBUG(3,("Sockets opened.\n"));
  return True;
}


/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static BOOL init_structs()
{
  if (!get_myname(myhostname,NULL))
    return(False);

  if (! *myname) {
    char *p;
    strcpy(myname,myhostname);
    p = strchr(myname,'.');
    if (p) *p = 0;
  }

  return True;
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Incorrect program usage - is the command line correct?\n"));

  printf("Usage: %s [-n name] [-B bcast address] [-D] [-p port] [-d debuglevel] [-l log basename]\n",pname);
  printf("Version %s\n",VERSION);
  printf("\t-D                    become a daemon\n");
  printf("\t-p port               listen on the specified port\n");
  printf("\t-d debuglevel         set the debuglevel\n");
  printf("\t-l log basename.      Basename for log/debug files\n");
  printf("\t-n netbiosname.       the netbios name to advertise for this host\n");
  printf("\t-B broadcast address  the address to use for broadcasts\n");
  printf("\t-N netmask           the netmask to use for subnet determination\n");
  printf("\t-H hosts file        load a netbios hosts file\n");
  printf("\t-G group name        add a group name to be part of\n");
  printf("\t-I ip-address        override the IP address\n");
  printf("\t-C comment           sets the machine comment that appears in browse lists\n");
  printf("\n");
}


/****************************************************************************
  main program
  **************************************************************************/
 int main(int argc,char *argv[])
{
  int port = NMB_PORT;
  int opt;
  extern FILE *dbf;
  extern char *optarg;
  fstring group;

  *group = 0;
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

  while ((opt = getopt(argc, argv, "s:T:I:C:bAi:B:N:Rn:l:d:Dp:hSH:G:")) != EOF)
    {
      switch (opt)
	{
	case 's':
	  strcpy(servicesf,optarg);
	  break;
	case 'C':
	  strcpy(ServerComment,optarg);
	  break;
	case 'G':
	  strcpy(group,optarg);
	  break;
	case 'H':
	  strcpy(host_file,optarg);
	  break;
	case 'I':
	  iface_set_default(optarg,NULL,NULL);
	  break;
	case 'B':
	  iface_set_default(NULL,optarg,NULL);
	  break;
	case 'N':
	  iface_set_default(NULL,NULL,optarg);
	  break;
	case 'n':
	  strcpy(myname,optarg);
	  break;
	case 'l':
	  sprintf(debugf,"%s.nmb",optarg);
	  break;
	case 'i':
	  strcpy(scope,optarg);
	  strupper(scope);
	  break;
	case 'D':
	  is_daemon = True;
	  break;
	case 'd':
	  DEBUGLEVEL = atoi(optarg);
	  break;
	case 'p':
	  port = atoi(optarg);
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
  DEBUG(1,("Copyright Andrew Tridgell 1994\n"));

  init_structs();

  if (!reload_services(False))
    return(-1);	

  set_samba_nb_type();

  if (*group)
    add_my_subnets(group);

  if (!is_daemon && !is_a_socket(0)) {
    DEBUG(0,("standard input is not a socket, assuming -D option\n"));
    is_daemon = True;
  }
  
  if (is_daemon) {
    DEBUG(2,("%s becoming a daemon\n",timestring()));
    become_daemon();
  }

  DEBUG(3,("Opening sockets %d\n", port));

  if (!open_sockets(is_daemon,port)) return 1;

  if (*host_file) {
    load_hosts_file(host_file);
    DEBUG(3,("Loaded hosts file\n"));
  }



  if (!*ServerComment)
    strcpy(ServerComment,"Samba %v");
  string_sub(ServerComment,"%v",VERSION);
  string_sub(ServerComment,"%h",myhostname);

  add_my_names();
  add_my_subnets(lp_workgroup());

  DEBUG(3,("Checked names\n"));
  
  load_netbios_names();

  DEBUG(3,("Loaded names\n"));

  write_browse_list();

  DEBUG(3,("Dumped names\n"));

  process();
  close_sockets();

  if (dbf)
    fclose(dbf);
  return(0);
}
