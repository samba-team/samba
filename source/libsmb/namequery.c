/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   name query routines
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

#include "includes.h"

extern int DEBUGLEVEL;

/* nmbd.c sets this to True. */
BOOL global_in_nmbd = False;

/****************************************************************************
generate a random trn_id
****************************************************************************/
static int generate_trn_id(void)
{
	static int trn_id;

	if (trn_id == 0) {
		sys_srandom(sys_getpid());
	}

	trn_id = sys_random();

	return trn_id % (unsigned)0x7FFF;
}


/****************************************************************************
 parse a node status response into an array of structures
****************************************************************************/
static struct node_status *parse_node_status(char *p, int *num_names)
{
	struct node_status *ret;
	int i;

	*num_names = CVAL(p,0);

	if (*num_names == 0) return NULL;

	ret = (struct node_status *)malloc(sizeof(struct node_status)* (*num_names));
	if (!ret) return NULL;

	p++;
	for (i=0;i< *num_names;i++) {
		StrnCpy(ret[i].name,p,15);
		trim_string(ret[i].name,NULL," ");
		ret[i].type = CVAL(p,15);
		ret[i].flags = p[16];
		p += 18;
	}
	return ret;
}


/****************************************************************************
do a NBT node status query on an open socket and return an array of
structures holding the returned names or NULL if the query failed
**************************************************************************/
struct node_status *name_status_query(int fd,struct nmb_name *name,
				      struct in_addr to_ip, int *num_names)
{
	BOOL found=False;
	int retries = 2;
	int retry_time = 2000;
	struct timeval tval;
	struct packet_struct p;
	struct packet_struct *p2;
	struct nmb_packet *nmb = &p.packet.nmb;
	struct node_status *ret;

	ZERO_STRUCT(p);

	nmb->header.name_trn_id = generate_trn_id();
	nmb->header.opcode = 0;
	nmb->header.response = False;
	nmb->header.nm_flags.bcast = False;
	nmb->header.nm_flags.recursion_available = False;
	nmb->header.nm_flags.recursion_desired = False;
	nmb->header.nm_flags.trunc = False;
	nmb->header.nm_flags.authoritative = False;
	nmb->header.rcode = 0;
	nmb->header.qdcount = 1;
	nmb->header.ancount = 0;
	nmb->header.nscount = 0;
	nmb->header.arcount = 0;
	nmb->question.question_name = *name;
	nmb->question.question_type = 0x21;
	nmb->question.question_class = 0x1;

	p.ip = to_ip;
	p.port = NMB_PORT;
	p.fd = fd;
	p.timestamp = time(NULL);
	p.packet_type = NMB_PACKET;
	
	GetTimeOfDay(&tval);
  
	if (!send_packet(&p)) 
		return NULL;

	retries--;

	while (1) {
		struct timeval tval2;
		GetTimeOfDay(&tval2);
		if (TvalDiff(&tval,&tval2) > retry_time) {
			if (!retries)
				break;
			if (!found && !send_packet(&p))
				return NULL;
			GetTimeOfDay(&tval);
			retries--;
		}

		if ((p2=receive_nmb_packet(fd,90,nmb->header.name_trn_id))) {     
			struct nmb_packet *nmb2 = &p2->packet.nmb;
			debug_nmb_packet(p2);
			
			if (nmb2->header.opcode != 0 ||
			    nmb2->header.nm_flags.bcast ||
			    nmb2->header.rcode ||
			    !nmb2->header.ancount ||
			    nmb2->answers->rr_type != 0x21) {
				/* XXXX what do we do with this? could be a
				   redirect, but we'll discard it for the
				   moment */
				free_packet(p2);
				continue;
			}

			ret = parse_node_status(&nmb2->answers->rdata[0], num_names);
			free_packet(p2);
			return ret;
		}
	}
	
	return NULL;
}


/****************************************************************************
find the first type XX name in a node status reply - used for finding
a servers name given its IP
return the matched name in *name
**************************************************************************/
BOOL name_status_find(int type, struct in_addr to_ip, char *name)
{
	struct node_status *status;
	struct nmb_name nname;
	int count, i;
	int sock;

	sock = open_socket_in(SOCK_DGRAM, 0, 3, interpret_addr(lp_socket_address()), True);
	if (sock == -1) return False;

	make_nmb_name(&nname, "*", 0);
	status = name_status_query(sock, &nname, to_ip, &count);
	close(sock);
	if (!status) return False;

	for (i=0;i<count;i++) {
		if (status[i].type == type) break;
	}
	if (i == count) return False;

	StrnCpy(name, status[i].name, 15);

	dos_to_unix(name, True);

	free(status);
	return True;
}


/****************************************************************************
 Do a netbios name query to find someones IP.
 Returns an array of IP addresses or NULL if none.
 *count will be set to the number of addresses returned.
****************************************************************************/
struct in_addr *name_query(int fd,const char *name,int name_type, 
			   BOOL bcast,BOOL recurse,
			   struct in_addr to_ip, int *count)
{
  BOOL found=False;
  int i, retries = 3;
  int retry_time = bcast?250:2000;
  struct timeval tval;
  struct packet_struct p;
  struct packet_struct *p2;
  struct nmb_packet *nmb = &p.packet.nmb;
  struct in_addr *ip_list = NULL;

  memset((char *)&p,'\0',sizeof(p));
  (*count) = 0;

  nmb->header.name_trn_id = generate_trn_id();
  nmb->header.opcode = 0;
  nmb->header.response = False;
  nmb->header.nm_flags.bcast = bcast;
  nmb->header.nm_flags.recursion_available = False;
  nmb->header.nm_flags.recursion_desired = recurse;
  nmb->header.nm_flags.trunc = False;
  nmb->header.nm_flags.authoritative = False;
  nmb->header.rcode = 0;
  nmb->header.qdcount = 1;
  nmb->header.ancount = 0;
  nmb->header.nscount = 0;
  nmb->header.arcount = 0;

  make_nmb_name(&nmb->question.question_name,name,name_type);

  nmb->question.question_type = 0x20;
  nmb->question.question_class = 0x1;

  p.ip = to_ip;
  p.port = NMB_PORT;
  p.fd = fd;
  p.timestamp = time(NULL);
  p.packet_type = NMB_PACKET;

  GetTimeOfDay(&tval);

  if (!send_packet(&p)) 
    return NULL;

  retries--;

  while (1)
  {
	  struct timeval tval2;
	  GetTimeOfDay(&tval2);
	  if (TvalDiff(&tval,&tval2) > retry_time) {
		  if (!retries)
			  break;
		  if (!found && !send_packet(&p))
			  return NULL;
		  GetTimeOfDay(&tval);
		  retries--;
	  }
	  
	  if ((p2=receive_nmb_packet(fd,90,nmb->header.name_trn_id))) {     
		  struct nmb_packet *nmb2 = &p2->packet.nmb;
		  debug_nmb_packet(p2);

		  /* If we get a Negative Name Query Response from a WINS
		   * server, we should report it and give up.
		   */
		  if( 0 == nmb2->header.opcode		/* A query response   */
		      && !(bcast)			/* from a WINS server */
		      && nmb2->header.rcode		/* Error returned     */
		    ) {

                    /* BEGIN_ADMIN_LOG */
                    sys_adminlog(LOG_CRIT,(char *)gettext("Failed WINS name resolution. Unresolved name: %s. WINS server address: %s.")
						  ,name,inet_ntoa(p2->ip));
                    /* END_ADMIN_LOG */

		    if( DEBUGLVL( 3 ) ) {
		      /* Only executed if DEBUGLEVEL >= 3 */
		      dbgtext( "Negative name query response, rcode 0x%02x: ",
				nmb2->header.rcode );
		      switch( nmb2->header.rcode ) {
		        case 0x01:
			  dbgtext( "Request was invalidly formatted.\n" );
			  break;
		        case 0x02:
			  dbgtext( "Problem with NBNS, cannot process name.\n");
			  break;
		        case 0x03:
			  dbgtext( "The name requested does not exist.\n" );
			  break;
		        case 0x04:
			  dbgtext( "Unsupported request error.\n" );
			  break;
		        case 0x05:
			  dbgtext( "Query refused error.\n" );
			  break;
		        default:
			  dbgtext( "Unrecognized error code.\n" );
			  break;
		      }
		    }
	            free_packet(p2);
		    return( NULL );
		  }

		  if (nmb2->header.opcode != 0 ||
		      nmb2->header.nm_flags.bcast ||
		      nmb2->header.rcode ||
		      !nmb2->header.ancount) {
			  /* 
			   * XXXX what do we do with this? Could be a
			   * redirect, but we'll discard it for the
			   * moment.  */
			  free_packet(p2);
			  continue;
		  }

		  ip_list = (struct in_addr *)Realloc( ip_list,
				sizeof( ip_list[0] )
				* ( (*count) + nmb2->answers->rdlength/6 ) );
		  if (ip_list) {
			  DEBUG(2,("Got a positive name query response from %s ( ",
				   inet_ntoa(p2->ip)));
			  for (i=0;i<nmb2->answers->rdlength/6;i++) {
				  putip((char *)&ip_list[(*count)],&nmb2->answers->rdata[2+i*6]);
				  DEBUGADD(2,("%s ",inet_ntoa(ip_list[(*count)])));
				  (*count)++;
			  }
			  DEBUGADD(2,(")\n"));
		  }

		  found=True;
		  retries=0;
		  free_packet(p2);
		  /*
		   * If we're doing a unicast lookup we only
		   * expect one reply. Don't wait the full 2
		   * seconds if we got one. JRA.
		   */
		  if(!bcast && found)
			  break;
	  }
  }

  /* Reach here if we've timed out waiting for replies.. */
  if( !bcast && !found )
    {
    /* Timed out wating for WINS server to respond.  Mark it dead. */
    wins_srv_died( to_ip );
    }

  return ip_list;
}

/********************************************************
 This routine parses /etc/resolv.conf and finds the
 first three nameservers specified in the file.
 This routine is used by the Admin Log
 messages when a DNS lookup fails.

 Returns the number of nameservers found.
*********************************************************/

static int parse_resolvconf(char name_server_arr[][16])
{
  char *fname = NAME_SERVER_FILE;
  FILE *fp = sys_fopen(fname,"r");
  pstring line;
  int i = 0;

  if (!fp) {
    DEBUG(4,("parse_resolvconf: Can't open resolv.conf file %s. Error was %s\n",
             fname, strerror(errno)));
    return 0;
  }

  while(!feof(fp) && !ferror(fp)) {
    pstring keyword,value,extra;
    char *ptr;
    int count=0;

    if (!fgets_slash(line,sizeof(pstring),fp))
      continue;

    if (*line == '#')
      continue;

    pstrcpy(keyword,"");
    pstrcpy(value,"");

    ptr = line;

    if (next_token(&ptr,keyword,NULL,sizeof(keyword)))
      ++count;
    if (next_token(&ptr,value ,NULL, sizeof(pstring)))
      ++count;
    if (next_token(&ptr,extra,NULL, sizeof(extra)))
      ++count;
    
    if(strequal(keyword,"nameserver"))
    {
        if (count <= 0)
          continue;

        if ( count < 2)
        {
            DEBUG(0,("parse_resolvconf: Ill formed nameserver line [%s]\n",line));
            continue;
        }

        if (count >= 3)
        {
            DEBUG(0,("parse_resolvconf: too many columns in resolv.conf file (incorrect syntax)\n"));
            continue;
        }

        if( i < NAME_SERVER_NUM) /* More than 3 DNS servers are not supported ?? */
        {
            strncpy(name_server_arr[i],value,16);
            i++;
            if(i == 3)
               break;
        }
    }
  }

  return i;
}

/********************************************************
 Start parsing the lmhosts file.
*********************************************************/

FILE *startlmhosts(char *fname)
{
  FILE *fp = sys_fopen(fname,"r");
  if (!fp) {
    DEBUG(4,("startlmhosts: Can't open lmhosts file %s. Error was %s\n",
             fname, strerror(errno)));
    return NULL;
  }
  return fp;
}

/********************************************************
 Parse the next line in the lmhosts file.
*********************************************************/

BOOL getlmhostsent( FILE *fp, pstring name, int *name_type, struct in_addr *ipaddr)
{
  pstring line;

  while(!feof(fp) && !ferror(fp)) {
    pstring ip,flags,extra;
    char *ptr;
    int count = 0;

    *name_type = -1;

    if (!fgets_slash(line,sizeof(pstring),fp))
      continue;

    if (*line == '#')
      continue;

    pstrcpy(ip,"");
    pstrcpy(name,"");
    pstrcpy(flags,"");

    ptr = line;

    if (next_token(&ptr,ip   ,NULL,sizeof(ip)))
      ++count;
    if (next_token(&ptr,name ,NULL, sizeof(pstring)))
      ++count;
    if (next_token(&ptr,flags,NULL, sizeof(flags)))
      ++count;
    if (next_token(&ptr,extra,NULL, sizeof(extra)))
      ++count;

    if (count <= 0)
      continue;

    if (count > 0 && count < 2)
    {
      DEBUG(0,("getlmhostsent: Ill formed hosts line [%s]\n",line));
      continue;
    }

    if (count >= 4)
    {
      DEBUG(0,("getlmhostsent: too many columns in lmhosts file (obsolete syntax)\n"));
      continue;
    }

    DEBUG(4, ("getlmhostsent: lmhost entry: %s %s %s\n", ip, name, flags));

    if (strchr(flags,'G') || strchr(flags,'S'))
    {
      DEBUG(0,("getlmhostsent: group flag in lmhosts ignored (obsolete)\n"));
      continue;
    }

    *ipaddr = *interpret_addr2(ip);

    /* Extra feature. If the name ends in '#XX', where XX is a hex number,
       then only add that name type. */
    if((ptr = strchr(name, '#')) != NULL)
    {
      char *endptr;

      ptr++;
      *name_type = (int)strtol(ptr, &endptr, 16);

      if(!*ptr || (endptr == ptr))
      {
        DEBUG(0,("getlmhostsent: invalid name %s containing '#'.\n", name));
        continue;
      }

      *(--ptr) = '\0'; /* Truncate at the '#' */
    }

    return True;
  }

  return False;
}

/********************************************************
 Finish parsing the lmhosts file.
*********************************************************/

void endlmhosts(FILE *fp)
{
  fclose(fp);
}

/********************************************************
 Resolve via "bcast" method.
*********************************************************/

BOOL name_resolve_bcast(const char *name, int name_type,
			struct in_addr **return_ip_list, int *return_count)
{
	int sock, i;
	int num_interfaces = iface_count();

	*return_ip_list = NULL;
	*return_count = 0;
	
	/*
	 * "bcast" means do a broadcast lookup on all the local interfaces.
	 */

	DEBUG(3,("name_resolve_bcast: Attempting broadcast lookup for name %s<0x%x>\n", name, name_type));

	sock = open_socket_in( SOCK_DGRAM, 0, 3,
			       interpret_addr(lp_socket_address()), True );

	if (sock == -1) return False;

	set_socket_options(sock,"SO_BROADCAST");
	/*
	 * Lookup the name on all the interfaces, return on
	 * the first successful match.
	 */
	for( i = num_interfaces-1; i >= 0; i--) {
		struct in_addr sendto_ip;
		/* Done this way to fix compiler error on IRIX 5.x */
		sendto_ip = *iface_bcast(*iface_n_ip(i));
		*return_ip_list = name_query(sock, name, name_type, True, 
				    True, sendto_ip, return_count);
		if(*return_ip_list != NULL) {
			close(sock);
			return True;
		}
	}

	close(sock);
	return False;
}

/********************************************************
 Resolve via "wins" method.
*********************************************************/

static BOOL resolve_wins(const char *name, int name_type,
                         struct in_addr **return_iplist, int *return_count)
{
	int sock;
	struct in_addr wins_ip;
	BOOL wins_ismyip;

	*return_iplist = NULL;
	*return_count = 0;
	
	/*
	 * "wins" means do a unicast lookup to the WINS server.
	 * Ignore if there is no WINS server specified or if the
	 * WINS server is one of our interfaces (if we're being
	 * called from within nmbd - we can't do this call as we
	 * would then block).
	 */

	DEBUG(3,("resolve_wins: Attempting wins lookup for name %s<0x%x>\n", name, name_type));

	if( wins_srv_count() < 1 ) {
		DEBUG(3,("resolve_wins: WINS server resolution selected and no WINS servers listed.\n"));
		return False;
	}

	wins_ip     = wins_srv_ip();
	wins_ismyip = ismyip(wins_ip);

	DEBUG(3, ("resolve_wins: WINS server == <%s>\n", inet_ntoa(wins_ip)) );
	if((wins_ismyip && !global_in_nmbd) || !wins_ismyip) {
		sock = open_socket_in(  SOCK_DGRAM, 0, 3,
					interpret_addr(lp_socket_address()),
					True );
		if (sock != -1) {
			*return_iplist = name_query( sock,      name,
						     name_type, False, 
						     True,      wins_ip,
						     return_count);
			if(*return_iplist != NULL) {
				close(sock);
				return True;
			}
			close(sock);
		}
	}

	return False;
}

/********************************************************
 Resolve via "lmhosts" method.
*********************************************************/

static BOOL resolve_lmhosts(const char *name, int name_type,
                         struct in_addr **return_iplist, int *return_count)
{
	/*
	 * "lmhosts" means parse the local lmhosts file.
	 */
	
	FILE *fp;
	pstring lmhost_name;
	int name_type2;
	struct in_addr return_ip;

	*return_iplist = NULL;
	*return_count = 0;

	DEBUG(3,("resolve_lmhosts: Attempting lmhosts lookup for name %s<0x%x>\n", name, name_type));

	fp = startlmhosts( LMHOSTSFILE );
	if(fp) {
		while (getlmhostsent(fp, lmhost_name, &name_type2, &return_ip)) {
			if (strequal(name, lmhost_name) && 
                ((name_type2 == -1) || (name_type == name_type2))
               ) {
				endlmhosts(fp);
				*return_iplist = (struct in_addr *)malloc(sizeof(struct in_addr));
				if(*return_iplist == NULL) {
					DEBUG(3,("resolve_lmhosts: malloc fail !\n"));
					return False;
				}
				**return_iplist = return_ip;
				*return_count = 1;
				return True; 
			}
		}
		endlmhosts(fp);
	}
	return False;
}


/********************************************************
 Resolve via "hosts" method.
*********************************************************/

static BOOL resolve_hosts(const char *name,
                         struct in_addr **return_iplist, int *return_count)
{
	/*
	 * "host" means do a localhost, or dns lookup.
	 */
	struct hostent *hp;
        char name_server_arr[NAME_SERVER_NUM][16];
	*return_iplist = NULL;
	*return_count = 0;

	DEBUG(3,("resolve_hosts: Attempting host lookup for name %s<0x20>\n", name));
	
	if (((hp = sys_gethostbyname(name)) != NULL) && (hp->h_addr != NULL)) {
		struct in_addr return_ip;
		putip((char *)&return_ip,(char *)hp->h_addr);
		*return_iplist = (struct in_addr *)malloc(sizeof(struct in_addr));
		if(*return_iplist == NULL) {
			DEBUG(3,("resolve_hosts: malloc fail !\n"));
			return False;
		}
		**return_iplist = return_ip;
		*return_count = 1;
		return True;
	}
        /* BEGIN_ADMIN_LOG */
	{
		BOOL parse_ok;
		
		parse_ok = parse_resolvconf(name_server_arr);
		sys_adminlog(LOG_CRIT,
			     (char *)gettext("Failed DNS name resolution. Unresolved name: %s. DNS server address: %s."),
			     name,
			     parse_ok ? name_server_arr[0] : "UNKNOWN");
	}
        /* END_ADMIN_LOG */

	return False;
}

/********************************************************
 Internal interface to resolve a name into an IP address.
 Use this function if the string is either an IP address, DNS
 or host name or NetBIOS name. This uses the name switch in the
 smb.conf to determine the order of name resolution.
*********************************************************/

static BOOL internal_resolve_name(const char *name, int name_type,
                         		struct in_addr **return_iplist, int *return_count)
{
  pstring name_resolve_list;
  fstring tok;
  char *ptr;
  BOOL allones = (strcmp(name,"255.255.255.255") == 0);
  BOOL allzeros = (strcmp(name,"0.0.0.0") == 0);
  BOOL is_address = is_ipaddress(name);
  *return_iplist = NULL;
  *return_count = 0;

  if (allzeros || allones || is_address) {
	*return_iplist = (struct in_addr *)malloc(sizeof(struct in_addr));
	if(*return_iplist == NULL) {
		DEBUG(3,("internal_resolve_name: malloc fail !\n"));
		return False;
	}
	if(is_address) { 
		/* if it's in the form of an IP address then get the lib to interpret it */
		(*return_iplist)->s_addr = inet_addr(name);
    } else {
		(*return_iplist)->s_addr = allones ? 0xFFFFFFFF : 0;
		*return_count = 1;
	}
    return True;
  }
  
  pstrcpy(name_resolve_list, lp_name_resolve_order());
  ptr = name_resolve_list;
  if (!ptr || !*ptr)
    ptr = "host";

  while (next_token(&ptr, tok, LIST_SEP, sizeof(tok))) {
	  if((strequal(tok, "host") || strequal(tok, "hosts"))) {
		  if (name_type == 0x20 && resolve_hosts(name, return_iplist, return_count)) {
			  return True;
		  }
	  } else if(strequal( tok, "lmhosts")) {
		  if (resolve_lmhosts(name, name_type, return_iplist, return_count)) {
			  return True;
		  }
	  } else if(strequal( tok, "wins")) {
		  /* don't resolve 1D via WINS */
		  if (name_type != 0x1D &&
		      resolve_wins(name, name_type, return_iplist, return_count)) {
			  return True;
		  }
	  } else if(strequal( tok, "bcast")) {
		  if (name_resolve_bcast(name, name_type, return_iplist, return_count)) {
			  return True;
		  }
	  } else {
		  DEBUG(0,("resolve_name: unknown name switch type %s\n", tok));
	  }
  }

  if((*return_iplist) != NULL) {
    free((char *)(*return_iplist));
    *return_iplist = NULL;
  }
  return False;
}

/********************************************************
 Internal interface to resolve a name into one IP address.
 Use this function if the string is either an IP address, DNS
 or host name or NetBIOS name. This uses the name switch in the
 smb.conf to determine the order of name resolution.
*********************************************************/

BOOL resolve_name(const char *name, struct in_addr *return_ip, int name_type)
{
	struct in_addr *ip_list = NULL;
	int count = 0;

	if(internal_resolve_name(name, name_type, &ip_list, &count)) {
		*return_ip = ip_list[0];
		free((char *)ip_list);
		return True;
	}
	if(ip_list != NULL)
		free((char *)ip_list);
	return False;
}


/********************************************************
 resolve a name of format \\server_name or \\ipaddress
 into a name.  also, cut the \\ from the front for us.
*********************************************************/

BOOL resolve_srv_name(const char* srv_name, fstring dest_host,
                                struct in_addr *ip)
{
        BOOL ret;
        const char *sv_name = srv_name;

        DEBUG(10,("resolve_srv_name: %s\n", srv_name));

        if (srv_name == NULL || strequal("\\\\.", srv_name))
        {
                extern pstring global_myname;
                fstrcpy(dest_host, global_myname);
                ip = interpret_addr2("127.0.0.1");
                return True;
        }

        if (strnequal("\\\\", srv_name, 2))
        {
                sv_name = &srv_name[2];
        }

        fstrcpy(dest_host, sv_name);
        /* treat the '*' name specially - it is a magic name for the PDC */
        if (strcmp(dest_host,"*") == 0) {
                extern pstring global_myname;
                ret = resolve_name(lp_workgroup(), ip, 0x1B);
                lookup_pdc_name(global_myname, lp_workgroup(), ip, dest_host);
        } else {
                ret = resolve_name(dest_host, ip, 0x20);
        }
        
        if (is_ipaddress(dest_host))
        {
                fstrcpy(dest_host, "*SMBSERVER");
        }
        
        return ret;
}


/********************************************************
 Find the IP address of the master browser or DMB for a workgroup.
*********************************************************/

BOOL find_master_ip(char *group, struct in_addr *master_ip)
{
	struct in_addr *ip_list = NULL;
	int count = 0;

	if (internal_resolve_name(group, 0x1D, &ip_list, &count)) {
		*master_ip = ip_list[0];
		free((char *)ip_list);
		return True;
	}
	if(internal_resolve_name(group, 0x1B, &ip_list, &count)) {
		*master_ip = ip_list[0];
		free((char *)ip_list);
		return True;
	}

	if(ip_list != NULL)
		free((char *)ip_list);
	return False;
}

/********************************************************
 Lookup a PDC name given a Domain name and IP address.
*********************************************************/

BOOL lookup_pdc_name(const char *srcname, const char *domain, struct in_addr *pdc_ip, char *ret_name)
{
#if !defined(I_HATE_WINDOWS_REPLY_CODE)

  fstring pdc_name;
  BOOL ret;

  /*
   * Due to the fact win WinNT *sucks* we must do a node status
   * query here... JRA.
   */

  *pdc_name = '\0';

  ret = name_status_find(0x20,*pdc_ip,pdc_name);

  if(ret && *pdc_name) {
    fstrcpy(ret_name, pdc_name);
    return True;
  }

  return False;

#else /* defined(I_HATE_WINDOWS_REPLY_CODE) */

JRA - This code is broken with BDC rollover - we need to do a full
NT GETDC call, UNICODE, NT domain SID and uncle tom cobbley and all...

	int retries = 3;
	int retry_time = 2000;
	struct timeval tval;
	struct packet_struct p;
	struct dgram_packet *dgram = &p.packet.dgram;
	char *ptr,*p2;
	char tmp[4];
	int len;
	struct sockaddr_in sock_name;
	int sock_len = sizeof(sock_name);
	const char *mailslot = NET_LOGON_MAILSLOT;
	char *mailslot_name;
	char buffer[1024];
	char *bufp;
	int dgm_id = generate_trn_id();
	int sock = open_socket_in(SOCK_DGRAM, 0, 3, interpret_addr(lp_socket_address()), True );
	
	if(sock == -1)
		return False;
	
	/* Find out the transient UDP port we have been allocated. */
	if(getsockname(sock, (struct sockaddr *)&sock_name, &sock_len)<0) {
		DEBUG(0,("lookup_pdc_name: Failed to get local UDP port. Error was %s\n",
			 strerror(errno)));
		close(sock);
		return False;
	}

	/*
	 * Create the request data.
	 */

	memset(buffer,'\0',sizeof(buffer));
	bufp = buffer;
	SSVAL(bufp,0,QUERYFORPDC);
	bufp += 2;
	fstrcpy(bufp,srcname);
	bufp += (strlen(bufp) + 1);
	slprintf(bufp, sizeof(fstring), "\\MAILSLOT\\NET\\GETDC%d", dgm_id);
	mailslot_name = bufp;
	bufp += (strlen(bufp) + 1);
	bufp = ALIGN2(bufp, buffer);
	bufp += dos_PutUniCode(bufp, srcname, sizeof(buffer) - (bufp - buffer) - 1, True);
	SIVAL(bufp,0,1);
	SSVAL(bufp,4,0xFFFF); 
	SSVAL(bufp,6,0xFFFF); 
	bufp += 8;
	len = PTR_DIFF(bufp,buffer);

	memset((char *)&p,'\0',sizeof(p));

	/* DIRECT GROUP or UNIQUE datagram. */
	dgram->header.msg_type = 0x10;
	dgram->header.flags.node_type = M_NODE;
	dgram->header.flags.first = True;
	dgram->header.flags.more = False;
	dgram->header.dgm_id = dgm_id;
	dgram->header.source_ip = *iface_ip(*pdc_ip);
	dgram->header.source_port = ntohs(sock_name.sin_port);
	dgram->header.dgm_length = 0; /* Let build_dgram() handle this. */
	dgram->header.packet_offset = 0;
	
	make_nmb_name(&dgram->source_name,srcname,0);
	make_nmb_name(&dgram->dest_name,domain,0x1C);
	
	ptr = &dgram->data[0];
	
	/* Setup the smb part. */
	ptr -= 4; /* XXX Ugliness because of handling of tcp SMB length. */
	memcpy(tmp,ptr,4);
	set_message(ptr,17,17 + len,True);
	memcpy(ptr,tmp,4);

	CVAL(ptr,smb_com) = SMBtrans;
	SSVAL(ptr,smb_vwv1,len);
	SSVAL(ptr,smb_vwv11,len);
	SSVAL(ptr,smb_vwv12,70 + strlen(mailslot));
	SSVAL(ptr,smb_vwv13,3);
	SSVAL(ptr,smb_vwv14,1);
	SSVAL(ptr,smb_vwv15,1);
	SSVAL(ptr,smb_vwv16,2);
	p2 = smb_buf(ptr);
	pstrcpy(p2,mailslot);
	p2 = skip_string(p2,1);
	
	memcpy(p2,buffer,len);
	p2 += len;
	
	dgram->datasize = PTR_DIFF(p2,ptr+4); /* +4 for tcp length. */
	
	p.ip = *pdc_ip;
	p.port = DGRAM_PORT;
	p.fd = sock;
	p.timestamp = time(NULL);
	p.packet_type = DGRAM_PACKET;
	
	GetTimeOfDay(&tval);
	
	if (!send_packet(&p)) {
		DEBUG(0,("lookup_pdc_name: send_packet failed.\n"));
		close(sock);
		return False;
	}
	
	retries--;
	
	while (1) {
		struct timeval tval2;
		struct packet_struct *p_ret;
		
		GetTimeOfDay(&tval2);
		if (TvalDiff(&tval,&tval2) > retry_time) {
			if (!retries)
				break;
			if (!send_packet(&p)) {
				DEBUG(0,("lookup_pdc_name: send_packet failed.\n"));
				close(sock);
				return False;
			}
			GetTimeOfDay(&tval);
			retries--;
		}

		if ((p_ret = receive_dgram_packet(sock,90,mailslot_name))) {
			struct dgram_packet *dgram2 = &p_ret->packet.dgram;
			char *buf;
			char *buf2;

			buf = &dgram2->data[0];
			buf -= 4;

			if (CVAL(buf,smb_com) != SMBtrans) {
				DEBUG(0,("lookup_pdc_name: datagram type %u != SMBtrans(%u)\n", (unsigned int)
					 CVAL(buf,smb_com), (unsigned int)SMBtrans ));
				free_packet(p_ret);
				continue;
			}
			
			len = SVAL(buf,smb_vwv11);
			buf2 = smb_base(buf) + SVAL(buf,smb_vwv12);
			
			if (len <= 0) {
				DEBUG(0,("lookup_pdc_name: datagram len < 0 (%d)\n", len ));
				free_packet(p_ret);
				continue;
			}

			DEBUG(4,("lookup_pdc_name: datagram reply from %s to %s IP %s for %s of type %d len=%d\n",
				 nmb_namestr(&dgram2->source_name),nmb_namestr(&dgram2->dest_name),
				 inet_ntoa(p_ret->ip), smb_buf(buf),SVAL(buf2,0),len));

			if(SVAL(buf2,0) != QUERYFORPDC_R) {
				DEBUG(0,("lookup_pdc_name: datagram type (%u) != QUERYFORPDC_R(%u)\n",
					 (unsigned int)SVAL(buf,0), (unsigned int)QUERYFORPDC_R ));
				free_packet(p_ret);
				continue;
			}

			buf2 += 2;
			/* Note this is safe as it is a bounded strcpy. */
			fstrcpy(ret_name, buf2);
			ret_name[sizeof(fstring)-1] = '\0';
			close(sock);
			free_packet(p_ret);
			return True;
		}
	}
	
	close(sock);
	return False;
#endif /* defined(I_HATE_WINDOWS_REPLY_CODE) */
}


/********************************************************
 Get the IP address list of the PDC/BDC's of a Domain.
*********************************************************/
BOOL get_dc_list(BOOL pdc_only, char *group, struct in_addr **ip_list, int *count)
{
	return internal_resolve_name(group, pdc_only ? 0x1B : 0x1C, ip_list, count);
}
