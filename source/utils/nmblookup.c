/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT client - used to lookup netbios names
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
   
*/

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;

extern pstring scope;

extern pstring myhostname;
extern struct in_addr ipzero;

int ServerFD= -1;

int RootPort = 0;

/****************************************************************************
  open the socket communication
  **************************************************************************/
static BOOL open_sockets(void)
{
  ServerFD = open_socket_in( SOCK_DGRAM,
                             (RootPort ? 137 :0),
                             3,
                             interpret_addr(lp_socket_address()) );

  if (ServerFD == -1)
    return(False);

  set_socket_options(ServerFD,"SO_BROADCAST");

  DEBUG(3, ("Socket opened.\n"));
  return True;
}


/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static BOOL init_structs(void )
{
  if (!get_myname(myhostname,NULL))
    return(False);

  return True;
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(void)
{
  printf("Usage: nmblookup [-M] [-B bcast address] [-d debuglevel] name\n");
  printf("Version %s\n",VERSION);
  printf("\t-d debuglevel         set the debuglevel\n");
  printf("\t-B broadcast address  the address to use for broadcasts\n");
  printf("\t-U unicast   address  the address to use for unicast\n");
  printf("\t-M                    searches for a master browser\n");
  printf("\t-R                    set recursion desired in packet\n");
  printf("\t-S                    lookup node status as well\n");
  printf("\t-r                    Use root port 137 (Win95 only replies to this)\n");
  printf("\t-A                    Do a node status on <name> as an IP Address\n");
  printf("\n");
}


/****************************************************************************
  main program
****************************************************************************/
int main(int argc,char *argv[])
{
  int opt;
  unsigned int lookup_type = 0x0;
  pstring lookup;
  extern int optind;
  extern char *optarg;
  BOOL find_master=False;
  BOOL find_status=False;
  int i;
  static pstring servicesf = CONFIGFILE;
  struct in_addr bcast_addr;
  BOOL use_bcast = True;
  BOOL got_bcast = False;
  BOOL lookup_by_ip = False;
  BOOL recursion_desired = False;

  DEBUGLEVEL = 1;
  *lookup = 0;

  TimeInit();

  setup_logging(argv[0],True);

  charset_initialise();

  while ((opt = getopt(argc, argv, "d:B:U:i:s:SMrhAR")) != EOF)
    switch (opt)
      {
      case 'B':
	iface_set_default(NULL,optarg,NULL);
	bcast_addr = *interpret_addr2(optarg);
	got_bcast = True;
	use_bcast = True;
	break;
      case 'U':
	iface_set_default(NULL,optarg,NULL);
	bcast_addr = *interpret_addr2(optarg);
	got_bcast = True;
	use_bcast = False;
	break;
      case 'i':
	fstrcpy(scope,optarg);
	strupper(scope);
	break;
      case 'M':
	find_master = True;
	break;
      case 'S':
	find_status = True;
	break;
      case 'R':
	recursion_desired = True;
	break;
      case 'd':
	DEBUGLEVEL = atoi(optarg);
	break;
      case 's':
	pstrcpy(servicesf, optarg);
	break;
      case 'r':
        RootPort = -1;
        break;
      case 'h':
	usage();
	exit(0);
	break;
      case 'A':
        lookup_by_ip = True;
        break;
      default:
	usage();
	exit(1);
      }

  if (argc < 2) {
    usage();
    exit(1);
  }

  init_structs();

  if (!lp_load(servicesf,True)) {
    fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
  }

  load_interfaces();
  if (!open_sockets()) return(1);

  if (!got_bcast)
    bcast_addr = *iface_bcast(ipzero);

  DEBUG(1,("Sending queries to %s\n",inet_ntoa(bcast_addr)));


  for (i=optind;i<argc;i++)
  {
      int j, count, retries = 2;
      char *p;
      struct in_addr ip;
      struct in_addr *ip_list;

      fstrcpy(lookup,argv[i]);

      if(lookup_by_ip)
      {
        fstrcpy(lookup,"*");
        ip = *interpret_addr2(argv[i]);
        printf("Looking up status of %s\n",inet_ntoa(ip));
        name_status(ServerFD,lookup,lookup_type,True,ip,NULL,NULL,NULL);
        printf("\n");
        continue;
      }

      if (find_master) {
	if (*lookup == '-') {
	  fstrcpy(lookup,"\01\02__MSBROWSE__\02");
	  lookup_type = 1;
	} else {
	  lookup_type = 0x1d;
	}
      }

      p = strchr(lookup,'#');

      if (p) {
	*p = 0;
	sscanf(p+1,"%x",&lookup_type);
	retries = 1;
      }

      if ((ip_list = name_query(ServerFD,lookup,lookup_type,use_bcast,recursion_desired,
				bcast_addr,&count,NULL))) {
	      for (j=0;j<count;j++)
		      printf("%s %s<%02x>\n",inet_ntoa(ip_list[j]),lookup, lookup_type);
	      
	      /* We can only do find_status if the ip address returned
		 was valid - ie. name_query returned true.
		 */
	      if (find_status) {
		      printf("Looking up status of %s\n",inet_ntoa(ip_list[0]));
		      name_status(ServerFD,lookup,lookup_type,True,ip_list[0],NULL,NULL,NULL);
		      printf("\n");
	      }
      } else {
	      printf("name_query failed to find name %s\n", lookup);
      }
  }
  
  return(0);
}
