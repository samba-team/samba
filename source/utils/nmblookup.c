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

#define NO_SYSLOG

#include "includes.h"

extern BOOL AllowDebugChange;

static BOOL give_flags = False;
static BOOL use_bcast = True;
static BOOL got_bcast = False;
static struct in_addr bcast_addr;
static BOOL recursion_desired = False;
static BOOL translate_addresses = False;
static int ServerFD= -1;
static int RootPort = False;
static BOOL find_status=False;

/****************************************************************************
  open the socket communication
  **************************************************************************/
static BOOL open_sockets(void)
{
  ServerFD = open_socket_in( SOCK_DGRAM,
                             (RootPort ? 137 : 0),
                             (RootPort ?   0 : 3),
                             interpret_addr(lp_socket_address()), True );

  if (ServerFD == -1)
    return(False);

  set_socket_options( ServerFD, "SO_BROADCAST" );

  DEBUG(3, ("Socket opened.\n"));
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
  printf("\t-f                    lists flags returned from a name query\n");
  printf("\t-U unicast   address  the address to use for unicast\n");
  printf("\t-M                    searches for a master browser\n");
  printf("\t-R                    set recursion desired in packet\n");
  printf("\t-S                    lookup node status as well\n");
  printf("\t-T                    translate IP addresses into names\n");
  printf("\t-r                    Use root port 137 (Win95 only replies to this)\n");
  printf("\t-A                    Do a node status on <name> as an IP Address\n");
  printf("\t-i NetBIOS scope      Use the given NetBIOS scope for name queries\n");
  printf("\t-s smb.conf file      Use the given path to the smb.conf file\n");
  printf("\t-h                    Print this help message.\n");
  printf("\n  If you specify -M and name is \"-\", nmblookup looks up __MSBROWSE__<01>\n");
  printf("\n");
}

/****************************************************************************
turn a node status flags field into a string
****************************************************************************/
static char *node_status_flags(unsigned char flags)
{
	static fstring ret;
	fstrcpy(ret,"");
	
	fstrcat(ret, (flags & 0x80) ? "<GROUP> " : "        ");
	if ((flags & 0x60) == 0x00) fstrcat(ret,"B ");
	if ((flags & 0x60) == 0x20) fstrcat(ret,"P ");
	if ((flags & 0x60) == 0x40) fstrcat(ret,"M ");
	if ((flags & 0x60) == 0x60) fstrcat(ret,"H ");
	if (flags & 0x10) fstrcat(ret,"<DEREGISTERING> ");
	if (flags & 0x08) fstrcat(ret,"<CONFLICT> ");
	if (flags & 0x04) fstrcat(ret,"<ACTIVE> ");
	if (flags & 0x02) fstrcat(ret,"<PERMANENT> ");
	
	return ret;
}

/****************************************************************************
turn the NMB Query flags into a string
****************************************************************************/
static char *query_flags(int flags)
{
	static fstring ret1;
	fstrcpy(ret1, "");

	if (flags & NM_FLAGS_RS) fstrcat(ret1, "Response ");
	if (flags & NM_FLAGS_AA) fstrcat(ret1, "Authoritative ");
	if (flags & NM_FLAGS_TC) fstrcat(ret1, "Truncated ");
	if (flags & NM_FLAGS_RD) fstrcat(ret1, "Recursion_Desired ");
	if (flags & NM_FLAGS_RA) fstrcat(ret1, "Recursion_Available ");
	if (flags & NM_FLAGS_B)  fstrcat(ret1, "Broadcast ");

	return ret1;
}

/****************************************************************************
do a node status query
****************************************************************************/
static void do_node_status(int fd, char *name, int type, struct in_addr ip)
{
	struct nmb_name nname;
	int count, i, j;
	struct node_status *status;
	fstring cleanname;

	printf("Looking up status of %s\n",inet_ntoa(ip));
	make_nmb_name(&nname, name, type);
	status = node_status_query(fd,&nname,ip, &count);
	if (status) {
		for (i=0;i<count;i++) {
			fstrcpy(cleanname, status[i].name);
			for (j=0;cleanname[j];j++) {
				if (!isprint((int)cleanname[j])) cleanname[j] = '.';
			}
			printf("\t%-15s <%02x> - %s\n",
			       cleanname,status[i].type,
			       node_status_flags(status[i].flags));
		}
		SAFE_FREE(status);
	}
	printf("\n");
}


/****************************************************************************
send out one query
****************************************************************************/
static BOOL query_one(char *lookup, unsigned int lookup_type)
{
	int j, count, flags;
	struct in_addr *ip_list=NULL;

	if (got_bcast) {
		printf("querying %s on %s\n", lookup, inet_ntoa(bcast_addr));
		ip_list = name_query(ServerFD,lookup,lookup_type,use_bcast,
				     use_bcast?True:recursion_desired,
				     bcast_addr,&count, &flags);
	} else {
		struct in_addr *bcast;
		for (j=iface_count() - 1;
		     !ip_list && j >= 0;
		     j--) {
			bcast = iface_n_bcast(j);
			printf("querying %s on %s\n", 
			       lookup, inet_ntoa(*bcast));
			ip_list = name_query(ServerFD,lookup,lookup_type,
					     use_bcast,
					     use_bcast?True:recursion_desired,
					     *bcast,&count, &flags);
		}
	}

	if (give_flags)
		printf("Flags: %s\n", query_flags(flags));

	if (!ip_list) return False;

	for (j=0;j<count;j++) {
		if (translate_addresses) {
			struct hostent *host = gethostbyaddr((char *)&ip_list[j], sizeof(ip_list[j]), AF_INET);
			if (host) {
				printf("%s, ", host -> h_name);
			}
		}
		printf("%s %s<%02x>\n",inet_ntoa(ip_list[j]),lookup, lookup_type);
	}

	/* We can only do find_status if the ip address returned
	   was valid - ie. name_query returned true.
	*/
	if (find_status) {
		do_node_status(ServerFD, lookup, lookup_type, ip_list[0]);
	}

	safe_free(ip_list);

	return (ip_list != NULL);
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
  int i;
  static pstring servicesf = CONFIGFILE;
  BOOL lookup_by_ip = False;

  DEBUGLEVEL = 1;
  /* Prevent smb.conf setting from overridding */
  AllowDebugChange = False;

  *lookup = 0;

  TimeInit();

  setup_logging(argv[0],True);

  charset_initialise();

  while ((opt = getopt(argc, argv, "d:fB:U:i:s:SMrhART")) != EOF)
    switch (opt)
      {
      case 'B':
	bcast_addr = *interpret_addr2(optarg);
	got_bcast = True;
	use_bcast = True;
	break;
      case 'f':
	give_flags = True;
	break;
      case 'U':
	bcast_addr = *interpret_addr2(optarg);
	got_bcast = True;
	use_bcast = False;
	break;
      case 'T':
        translate_addresses = !translate_addresses;
	break;
      case 'i':
	      {
		      extern pstring global_scope;
		      pstrcpy(global_scope,optarg);
		      strupper(global_scope);
	      }
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
        RootPort = True;
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

  if (!lp_load(servicesf,True,False,False)) {
    fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
  }

  load_interfaces();
  if (!open_sockets()) return(1);

  for (i=optind;i<argc;i++)
  {
      char *p;
      struct in_addr ip;

      fstrcpy(lookup,argv[i]);

      if(lookup_by_ip)
      {
        fstrcpy(lookup,"*");
        ip = *interpret_addr2(argv[i]);
	do_node_status(ServerFD, lookup, lookup_type, ip);
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
        *p = '\0';
        sscanf(++p,"%x",&lookup_type);
      }

      if (!query_one(lookup, lookup_type)) {
	printf( "name_query failed to find name %s", lookup );
        if( 0 != lookup_type )
          printf( "#%02x", lookup_type );
        printf( "\n" );
      }
  }
  
  return(0);
}
