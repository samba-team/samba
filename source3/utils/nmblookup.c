/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT client - used to lookup netbios names
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

/****************************************************************************
  open the socket communication
  **************************************************************************/
static BOOL open_sockets(void)
{
  struct hostent *hp;
 
  /* get host info */
  if ((hp = Get_Hostbyname(myhostname)) == 0) 
    {
      DEBUG(0,( "Get_Hostbyname: Unknown host. %s\n",myhostname));
      return False;
    }   

  ServerFD = open_socket_in(SOCK_DGRAM, 0,3,interpret_addr(lp_socket_address()));

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
  printf("\t-M                    searches for a master browser\n");
  printf("\t-S                    lookup node status as well\n");
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
  
  DEBUGLEVEL = 1;
  *lookup = 0;

  TimeInit();

  setup_logging(argv[0],True);

  charset_initialise();

  while ((opt = getopt(argc, argv, "p:d:B:i:SMh")) != EOF)
    switch (opt)
      {
      case 'B':
	iface_set_default(NULL,optarg,NULL);
	break;
      case 'i':
	strcpy(scope,optarg);
	strupper(scope);
	break;
      case 'M':
	find_master = True;
	break;
      case 'S':
	find_status = True;
	break;
      case 'd':
	DEBUGLEVEL = atoi(optarg);
	break;
      case 'h':
	usage();
	exit(0);
	break;
      default:
	usage();
	exit(1);
      }

  if (argc < 2) {
    usage();
    exit(1);
  }

  load_interfaces();
  init_structs();
  if (!open_sockets()) return(1);

  DEBUG(1,("Sending queries to %s\n",inet_ntoa(*iface_bcast(ipzero))));


  for (i=optind;i<argc;i++)
  {
      BOOL bcast = True;
      int retries = 2;
      char *p;
      struct in_addr ip;

      strcpy(lookup,argv[i]);

      if (find_master) {
	if (*lookup == '-') {
	  strcpy(lookup,"\01\02__MSBROWSE__\02");
	  lookup_type = 1;
	} else {
	  lookup_type = 0x1b;
	}
      }

      p = strchr(lookup,'#');

      if (p) {
	*p = 0;
	sscanf(p+1,"%x",&lookup_type);
	bcast = False;
	retries = 1;
      }

    if (name_query(ServerFD,lookup,lookup_type,bcast,True,
		     *iface_bcast(ipzero),&ip,NULL)) 
	{
	  printf("%s %s\n",inet_ntoa(ip),lookup);
    }
	if (find_status) 
	{
	      printf("Looking up status of %s\n",inet_ntoa(ip));
	      name_status(ServerFD,lookup,lookup_type,True,ip,NULL,NULL,NULL);
	      printf("\n");
	}
  }

  return(0);
}
