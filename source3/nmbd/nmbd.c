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
#include "loadparm.h"
#include "localnet.h"

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

static BOOL got_bcast = False;
static BOOL got_myip = False;
static BOOL got_nmask = False;

/* what server type are we currently */

time_t StartupTime =0;

struct in_addr ipzero;


/****************************************************************************
catch a sighup
****************************************************************************/
static int sig_hup(void)
{
  BlockSignals(True);

  DEBUG(0,("Got SIGHUP (reload not implemented)\n"));
  dump_names();
  reload_services(True);

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
	  strcpy(mask, inet_ntoa(Netmask));
	}

	DEBUG(4, ("lmhost entry: %s %s %s %s\n", ip, name, mask, flags));

	if (strchr(flags,'G') || strchr(flags,'S'))
	  group = True;

	if (strchr(flags,'M') && !group) {
	  source = SELF;
	  strcpy(myname,name);
	}

	ipaddr = *interpret_addr2(ip);
	ipmask = *interpret_addr2(mask);

	if (group) {
	  add_domain_entry(ipaddr, ipmask, name, True);
	} else {
	  add_netbios_entry(name,0x20,NB_ACTIVE,0,source,ipaddr);
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
      announce_backup();
      announce_master();

      expire_names_and_servers();
      expire_netbios_response_entries(t-10);
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


/*******************************************************************
  check that a IP, bcast and netmask and consistent. Must be a 1s
  broadcast
  ******************************************************************/
static BOOL ip_consistent(struct in_addr ip,struct in_addr bcast, struct in_addr nmask)
{
  unsigned long a_ip,a_bcast,a_nmask;

  a_ip = ntohl(ip.s_addr);
  a_bcast = ntohl(bcast.s_addr);
  a_nmask = ntohl(nmask.s_addr);

  /* check the netmask is sane */
  if (((a_nmask>>24)&0xFF) != 0xFF) {
    DEBUG(0,("Insane netmask %s\n",inet_ntoa(nmask)));
    return(False);
  }

  /* check the IP and bcast are on the same net */
  if ((a_ip&a_nmask) != (a_bcast&a_nmask)) {
    DEBUG(0,("IP and broadcast are on different nets!\n"));
    return(False);
  }

  /* check the IP and bcast are on the same net */
  if ((a_bcast|a_nmask) != 0xFFFFFFFF) {
    DEBUG(0,("Not a ones based broadcast %s\n",inet_ntoa(bcast)));
    return(False);
  }

  return(True);
}


/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static BOOL init_structs()
{
  if (!get_myname(myhostname,got_myip?NULL:&myip))
    return(False);

  /* Read the broadcast address from the interface */
  {
    struct in_addr ip0,ip1,ip2;

    ip0 = myip;

    if (!(got_bcast && got_nmask))
      {
	get_broadcast(&ip0,&ip1,&ip2);

	if (!got_myip)
	  myip = ip0;
    
	if (!got_bcast)
	  bcast_ip = ip1;
    
	if (!got_nmask)
	  Netmask = ip2;   
      } 

    DEBUG(1,("Using IP %s  ",inet_ntoa(myip))); 
    DEBUG(1,("broadcast %s  ",inet_ntoa(bcast_ip)));
    DEBUG(1,("netmask %s\n",inet_ntoa(Netmask)));    

    if (!ip_consistent(myip,bcast_ip,Netmask)) {
      DEBUG(0,("WARNING: The IP address, broadcast and Netmask are not consistent\n"));
      DEBUG(0,("You are likely to experience problems with this setup!\n"));
    }
  }

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

  *host_file = 0;

  StartupTime = time(NULL);

  TimeInit();

  strcpy(debugf,NMBLOGFILE);

  setup_logging(argv[0],False);

  charset_initialise();

  ipzero = *interpret_addr2("0.0.0.0");

#ifdef LMHOSTSFILE
  strcpy(host_file,LMHOSTSFILE);
#endif

  /* this is for people who can't start the program correctly */
  while (argc > 1 && (*argv[1] != '-')) {
    argv++;
    argc--;
  }

  fault_setup(fault_continue);

  signal(SIGHUP,SIGNAL_CAST sig_hup);

  bcast_ip = ipzero;
  myip = ipzero;

  while ((opt = getopt (argc, argv, "s:T:I:C:bAi:B:N:Rn:l:d:Dp:hSH:G:")) != EOF)
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
	  if (got_bcast && got_nmask) {
	    add_domain_entry(bcast_ip,Netmask,optarg, True);
	  } else {
	    DEBUG(0, ("Warning: option -G %s added before broadcast and netmask.\n",
		      optarg));
	    DEBUG(0, ("Assuming default values: bcast %s netmask %s\n",
		      inet_ntoa(bcast_ip), inet_ntoa(Netmask))); /* (i hope) */
	  }
	  break;
	case 'H':
	  strcpy(host_file,optarg);
	  break;
	case 'I':
	  myip = *interpret_addr2(optarg);
	  got_myip = True;
	  break;
	case 'B':
	  bcast_ip = *interpret_addr2(optarg);
	  got_bcast = True;
	  break;
	case 'N':
	  Netmask = *interpret_addr2(optarg);
	  got_nmask = True;
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
  add_my_domains();

  DEBUG(3,("Checked names\n"));
  
  write_browse_list();

  DEBUG(3,("Dumped names\n"));

  process();
  close_sockets();

  if (dbf)
    fclose(dbf);
  return(0);
}
