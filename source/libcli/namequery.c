/* 
   Unix SMB/CIFS implementation.
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

/* nmbd.c sets this to True. */
BOOL global_in_nmbd = False;

/****************************************************************************
generate a random trn_id
****************************************************************************/
static int generate_trn_id(void)
{
	static int trn_id;

	if (trn_id == 0) {
		sys_srandom(getpid());
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
		DEBUG(10, ("%s#%02x: flags = 0x%02x\n", ret[i].name, 
			   ret[i].type, ret[i].flags));
	}
	return ret;
}


/****************************************************************************
do a NBT node status query on an open socket and return an array of
structures holding the returned names or NULL if the query failed
**************************************************************************/
struct node_status *node_status_query(int fd,struct nmb_name *name,
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

BOOL name_status_find(const char *q_name, int q_type, int type, struct in_addr to_ip, char *name)
{
	struct node_status *status = NULL;
	struct nmb_name nname;
	int count, i;
	int sock;
	BOOL result = False;

	if (lp_disable_netbios()) {
		DEBUG(5,("name_status_find(%s#%02x): netbios is disabled\n", q_name, q_type));
		return False;
	}

	DEBUG(10, ("name_status_find: looking up %s#%02x at %s\n", q_name, 
		   q_type, inet_ntoa(to_ip)));

	sock = open_socket_in(SOCK_DGRAM, 0, 3, interpret_addr(lp_socket_address()), True);
	if (sock == -1)
		goto done;

	/* W2K PDC's seem not to respond to '*'#0. JRA */
	make_nmb_name(&nname, q_name, q_type);
	status = node_status_query(sock, &nname, to_ip, &count);
	close(sock);
	if (!status)
		goto done;

	for (i=0;i<count;i++) {
		if (status[i].type == type)
			break;
	}
	if (i == count)
		goto done;

	pull_ascii(name, status[i].name, 16, 15, STR_TERMINATE);
	result = True;

 done:
	SAFE_FREE(status);

	DEBUG(10, ("name_status_find: name %sfound", result ? "" : "not "));

	if (result)
		DEBUGADD(10, (", ip address is %s", inet_ntoa(to_ip)));

	DEBUG(10, ("\n"));	

	return result;
}


/*
  comparison function used by sort_ip_list
*/
int ip_compare(struct in_addr *ip1, struct in_addr *ip2)
{
	int max_bits1=0, max_bits2=0;
	int num_interfaces = iface_count();
	int i;

	for (i=0;i<num_interfaces;i++) {
		struct in_addr ip;
		int bits1, bits2;
		ip = *iface_n_bcast(i);
		bits1 = matching_quad_bits((uint8_t *)&ip1->s_addr, (uint8_t *)&ip.s_addr);
		bits2 = matching_quad_bits((uint8_t *)&ip2->s_addr, (uint8_t *)&ip.s_addr);
		max_bits1 = MAX(bits1, max_bits1);
		max_bits2 = MAX(bits2, max_bits2);
	}	
	
	/* bias towards directly reachable IPs */
	if (iface_local(*ip1)) {
		max_bits1 += 32;
	}
	if (iface_local(*ip2)) {
		max_bits2 += 32;
	}

	return max_bits2 - max_bits1;
}

/*
  sort an IP list so that names that are close to one of our interfaces 
  are at the top. This prevents the problem where a WINS server returns an IP that
  is not reachable from our subnet as the first match
*/
static void sort_ip_list(struct in_addr *iplist, int count)
{
	if (count <= 1) {
		return;
	}

	qsort(iplist, count, sizeof(struct in_addr), QSORT_CAST ip_compare);	
}


/****************************************************************************
 Do a netbios name query to find someones IP.
 Returns an array of IP addresses or NULL if none.
 *count will be set to the number of addresses returned.
 *timed_out is set if we failed by timing out
****************************************************************************/
struct in_addr *name_query(int fd,const char *name,int name_type, 
			   BOOL bcast,BOOL recurse,
			   struct in_addr to_ip, int *count, int *flags,
			   BOOL *timed_out)
{
	BOOL found=False;
	int i, retries = 3;
	int retry_time = bcast?250:2000;
	struct timeval tval;
	struct packet_struct p;
	struct packet_struct *p2;
	struct nmb_packet *nmb = &p.packet.nmb;
	struct in_addr *ip_list = NULL;

	if (lp_disable_netbios()) {
		DEBUG(5,("name_query(%s#%02x): netbios is disabled\n", name, name_type));
		return NULL;
	}

	if (timed_out) {
		*timed_out = False;
	}
	
	memset((char *)&p,'\0',sizeof(p));
	(*count) = 0;
	(*flags) = 0;
	
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
	
	while (1) {
		struct timeval tval2;
		struct in_addr *tmp_ip_list;
		
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
				
				if (DEBUGLVL(3)) {
					/* Only executed if DEBUGLEVEL >= 3 */
					DEBUG(3,("Negative name query response, rcode 0x%02x: ", nmb2->header.rcode ));
					switch( nmb2->header.rcode ) {
					case 0x01:
						DEBUG(3,("Request was invalidly formatted.\n" ));
						break;
					case 0x02:
						DEBUG(3,("Problem with NBNS, cannot process name.\n"));
						break;
					case 0x03:
						DEBUG(3,("The name requested does not exist.\n" ));
						break;
					case 0x04:
						DEBUG(3,("Unsupported request error.\n" ));
						break;
					case 0x05:
						DEBUG(3,("Query refused error.\n" ));
						break;
					default:
						DEBUG(3,("Unrecognized error code.\n" ));
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
				 * moment.
				 */
				free_packet(p2);
				continue;
			}
			
			tmp_ip_list = (struct in_addr *)Realloc( ip_list, sizeof( ip_list[0] )
								 * ( (*count) + nmb2->answers->rdlength/6 ) );
			
			if (!tmp_ip_list) {
				DEBUG(0,("name_query: Realloc failed.\n"));
				SAFE_FREE(ip_list);
			}
			
			ip_list = tmp_ip_list;
			
			if (ip_list) {
				DEBUG(2,("Got a positive name query response from %s ( ", inet_ntoa(p2->ip)));
				for (i=0;i<nmb2->answers->rdlength/6;i++) {
					putip((char *)&ip_list[(*count)],&nmb2->answers->rdata[2+i*6]);
					DEBUGADD(2,("%s ",inet_ntoa(ip_list[(*count)])));
					(*count)++;
				}
				DEBUGADD(2,(")\n"));
			}
			
			found=True;
			retries=0;
			/* We add the flags back ... */
			if (nmb2->header.response)
				(*flags) |= NM_FLAGS_RS;
			if (nmb2->header.nm_flags.authoritative)
				(*flags) |= NM_FLAGS_AA;
			if (nmb2->header.nm_flags.trunc)
				(*flags) |= NM_FLAGS_TC;
			if (nmb2->header.nm_flags.recursion_desired)
				(*flags) |= NM_FLAGS_RD;
			if (nmb2->header.nm_flags.recursion_available)
				(*flags) |= NM_FLAGS_RA;
			if (nmb2->header.nm_flags.bcast)
				(*flags) |= NM_FLAGS_B;
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

	if (timed_out) {
		*timed_out = True;
	}

	/* sort the ip list so we choose close servers first if possible */
	sort_ip_list(ip_list, *count);

	return ip_list;
}

/********************************************************
 Start parsing the lmhosts file.
*********************************************************/

XFILE *startlmhosts(char *fname)
{
	XFILE *fp = x_fopen(fname,O_RDONLY, 0);
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

BOOL getlmhostsent( TALLOC_CTX *mem_ctx,
		XFILE *fp, pstring name, int *name_type, struct in_addr *ipaddr)
{
  pstring line;

  while(!x_feof(fp) && !x_ferror(fp)) {
    pstring ip,flags,extra;
    const char *ptr;
    char *ptr1;
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

    if (strchr_m(flags,'G') || strchr_m(flags,'S'))
    {
      DEBUG(0,("getlmhostsent: group flag in lmhosts ignored (obsolete)\n"));
      continue;
    }

    *ipaddr = *interpret_addr2(mem_ctx, ip);

    /* Extra feature. If the name ends in '#XX', where XX is a hex number,
       then only add that name type. */
    if((ptr1 = strchr_m(name, '#')) != NULL)
    {
      char *endptr;

      ptr1++;
      *name_type = (int)strtol(ptr1, &endptr, 16);

      if(!*ptr1 || (endptr == ptr1))
      {
        DEBUG(0,("getlmhostsent: invalid name %s containing '#'.\n", name));
        continue;
      }

      *(--ptr1) = '\0'; /* Truncate at the '#' */
    }

    return True;
  }

  return False;
}

/********************************************************
 Finish parsing the lmhosts file.
*********************************************************/

void endlmhosts(XFILE *fp)
{
	x_fclose(fp);
}


/********************************************************
 Resolve via "bcast" method.
*********************************************************/

BOOL name_resolve_bcast(const char *name, int name_type,
			struct in_addr **return_ip_list, int *return_count)
{
	int sock, i;
	int num_interfaces = iface_count();

	if (lp_disable_netbios()) {
		DEBUG(5,("name_resolve_bcast(%s#%02x): netbios is disabled\n", name, name_type));
		return False;
	}

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
		int flags;
		/* Done this way to fix compiler error on IRIX 5.x */
		sendto_ip = *iface_n_bcast(i);
		*return_ip_list = name_query(sock, name, name_type, True, 
				    True, sendto_ip, return_count, &flags, NULL);
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
BOOL resolve_wins(TALLOC_CTX *mem_ctx, const char *name, int name_type,
		  struct in_addr **return_iplist, int *return_count)
{
	int sock, t, i;
	char **wins_tags;
	struct in_addr src_ip;

	if (lp_disable_netbios()) {
		DEBUG(5,("resolve_wins(%s#%02x): netbios is disabled\n", name, name_type));
		return False;
	}

	*return_iplist = NULL;
	*return_count = 0;
	
	DEBUG(3,("resolve_wins: Attempting wins lookup for name %s<0x%x>\n", name, name_type));

	if (wins_srv_count() < 1) {
		DEBUG(3,("resolve_wins: WINS server resolution selected and no WINS servers listed.\n"));
		return False;
	}

	/* we try a lookup on each of the WINS tags in turn */
	wins_tags = wins_srv_tags();

	if (!wins_tags) {
		/* huh? no tags?? give up in disgust */
		return False;
	}

	/* the address we will be sending from */
	src_ip = *interpret_addr2(mem_ctx, lp_socket_address());

	/* in the worst case we will try every wins server with every
	   tag! */
	for (t=0; wins_tags && wins_tags[t]; t++) {
		int srv_count = wins_srv_count_tag(wins_tags[t]);
		for (i=0; i<srv_count; i++) {
			struct in_addr wins_ip;
			int flags;
			BOOL timed_out;

			wins_ip = wins_srv_ip_tag(wins_tags[t], src_ip);

			if (global_in_nmbd && ismyip(wins_ip)) {
				/* yikes! we'll loop forever */
				continue;
			}

			/* skip any that have been unresponsive lately */
			if (wins_srv_is_dead(wins_ip, src_ip)) {
				continue;
			}

			DEBUG(3,("resolve_wins: using WINS server %s and tag '%s'\n", inet_ntoa(wins_ip), wins_tags[t]));

			sock = open_socket_in(SOCK_DGRAM, 0, 3, src_ip.s_addr, True);
			if (sock == -1) {
				continue;
			}

			*return_iplist = name_query(sock,name,name_type, False, 
						    True, wins_ip, return_count, &flags, 
						    &timed_out);
			if (*return_iplist != NULL) {
				goto success;
			}
			close(sock);

			if (timed_out) {
				/* Timed out wating for WINS server to respond.  Mark it dead. */
				wins_srv_died(wins_ip, src_ip);
			} else {
				/* The name definately isn't in this
				   group of WINS servers. goto the next group  */
				break;
			}
		}
	}

	wins_srv_tags_free(wins_tags);
	return False;

success:
	wins_srv_tags_free(wins_tags);
	close(sock);
	return True;
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
	return False;
}

/********************************************************
 Internal interface to resolve a name into an IP address.
 Use this function if the string is either an IP address, DNS
 or host name or NetBIOS name. This uses the name switch in the
 smb.conf to determine the order of name resolution.
*********************************************************/

static BOOL internal_resolve_name(TALLOC_CTX *mem_ctx, const char *name, int name_type,
				  struct in_addr **return_iplist, int *return_count)
{
  char *name_resolve_list;
  fstring tok;
  const char *ptr;
  BOOL allones = (strcmp(name,"255.255.255.255") == 0);
  BOOL allzeros = (strcmp(name,"0.0.0.0") == 0);
  BOOL is_address = is_ipaddress(name);
  BOOL result = False;
  struct in_addr *nodupes_iplist;
  int i;

  *return_iplist = NULL;
  *return_count = 0;

  DEBUG(10, ("internal_resolve_name: looking up %s#%x\n", name, name_type));

  if (allzeros || allones || is_address) {
	*return_iplist = (struct in_addr *)malloc(sizeof(struct in_addr));
	if(*return_iplist == NULL) {
		DEBUG(3,("internal_resolve_name: malloc fail !\n"));
		return False;
	}
	if(is_address) { 
		/* if it's in the form of an IP address then get the lib to interpret it */
		if (((*return_iplist)->s_addr = inet_addr(name)) == 0xFFFFFFFF ){
			DEBUG(1,("internal_resolve_name: inet_addr failed on %s\n", name));
			return False;
		}
	} else {
		(*return_iplist)->s_addr = allones ? 0xFFFFFFFF : 0;
		*return_count = 1;
	}
    return True;
  }
  
  /* Check netbios name cache */

  if (namecache_fetch(mem_ctx, name, name_type, return_iplist, return_count)) {

	  /* This could be a negative response */

	  return (*return_count > 0);
  }

  name_resolve_list = talloc_strdup(mem_ctx, lp_name_resolve_order());
  ptr = name_resolve_list;
  if (!ptr || !*ptr)
    ptr = "host";

  while (next_token(&ptr, tok, LIST_SEP, sizeof(tok))) {
	  if((strequal(tok, "host") || strequal(tok, "hosts"))) {
		  if (name_type == 0x20) {
			  if (resolve_hosts(name, return_iplist, return_count)) {
				  result = True;
				  goto done;
			  }
		  }
	  } else if(strequal( tok, "lmhosts")) {
			/* REWRITE: add back in? */
			DEBUG(2,("resolve_name: REWRITE: add lmhosts back?? %s\n", tok));
	  } else if(strequal( tok, "wins")) {
		  /* don't resolve 1D via WINS */
		  if (name_type != 0x1D &&
		      resolve_wins(mem_ctx, name, name_type, return_iplist, return_count)) {
		    result = True;
		    goto done;
		  }
	  } else if(strequal( tok, "bcast")) {
		  if (name_resolve_bcast(name, name_type, return_iplist, return_count)) {
		    result = True;
		    goto done;
		  }
	  } else {
		  DEBUG(0,("resolve_name: unknown name switch type %s\n", tok));
	  }
  }

  /* All of the resolve_* functions above have returned false. */

  SAFE_FREE(*return_iplist);
  *return_count = 0;

  return False;

 done:

  /* Remove duplicate entries.  Some queries, notably #1c (domain
     controllers) return the PDC in iplist[0] and then all domain
     controllers including the PDC in iplist[1..n].  Iterating over
     the iplist when the PDC is down will cause two sets of timeouts. */

  if (*return_count && (nodupes_iplist = (struct in_addr *)
       malloc(sizeof(struct in_addr) * (*return_count)))) {
	  int nodupes_count = 0;

	  /* Iterate over return_iplist looking for duplicates */

	  for (i = 0; i < *return_count; i++) {
		  BOOL is_dupe = False;
		  int j;

		  for (j = i + 1; j < *return_count; j++) {
			  if (ip_equal((*return_iplist)[i], 
				       (*return_iplist)[j])) {
				  is_dupe = True;
				  break;
			  }
		  }

		  if (!is_dupe) {

			  /* This one not a duplicate */

			  nodupes_iplist[nodupes_count] = (*return_iplist)[i];
			  nodupes_count++;
		  }
	  }
	  
	  /* Switcheroo with original list */
	  
	  free(*return_iplist);

	  *return_iplist = nodupes_iplist;
	  *return_count = nodupes_count;
  }
 
  /* Save in name cache */
  for (i = 0; i < *return_count && DEBUGLEVEL == 100; i++)
    DEBUG(100, ("Storing name %s of type %d (ip: %s)\n", name,
                name_type, inet_ntoa((*return_iplist)[i])));
    
  namecache_store(mem_ctx, name, name_type, *return_count, *return_iplist);

  /* Display some debugging info */

  DEBUG(10, ("internal_resolve_name: returning %d addresses: ", 
	     *return_count));

  for (i = 0; i < *return_count; i++)
	  DEBUGADD(10, ("%s ", inet_ntoa((*return_iplist)[i])));

  DEBUG(10, ("\n"));

  return result;
}

/********************************************************
 Internal interface to resolve a name into one IP address.
 Use this function if the string is either an IP address, DNS
 or host name or NetBIOS name. This uses the name switch in the
 smb.conf to determine the order of name resolution.
*********************************************************/
BOOL resolve_name(TALLOC_CTX *mem_ctx, const char *name, struct in_addr *return_ip, int name_type)
{
	struct in_addr *ip_list = NULL;
	int count = 0;

	if (is_ipaddress(name)) {
		*return_ip = *interpret_addr2(mem_ctx, name);
		return True;
	}

	if (internal_resolve_name(mem_ctx, name, name_type, &ip_list, &count)) {
		int i;
		/* only return valid addresses for TCP connections */
		for (i=0; i<count; i++) {
			char *ip_str = inet_ntoa(ip_list[i]);
			if (ip_str &&
			    strcmp(ip_str, "255.255.255.255") != 0 &&
			    strcmp(ip_str, "0.0.0.0") != 0) {
				*return_ip = ip_list[i];
				SAFE_FREE(ip_list);
				return True;
			}
		}
	}
	SAFE_FREE(ip_list);
	return False;
}

/********************************************************
 Find the IP address of the master browser or DMB for a workgroup.
*********************************************************/

BOOL find_master_ip(TALLOC_CTX *mem_ctx, const char *group, struct in_addr *master_ip)
{
	struct in_addr *ip_list = NULL;
	int count = 0;

	if (lp_disable_netbios()) {
		DEBUG(5,("find_master_ip(%s): netbios is disabled\n", group));
		return False;
	}

	if (internal_resolve_name(mem_ctx, group, 0x1D, &ip_list, &count)) {
		*master_ip = ip_list[0];
		SAFE_FREE(ip_list);
		return True;
	}
	if(internal_resolve_name(mem_ctx, group, 0x1B, &ip_list, &count)) {
		*master_ip = ip_list[0];
		SAFE_FREE(ip_list);
		return True;
	}

	SAFE_FREE(ip_list);
	return False;
}

/********************************************************
 Lookup a DC name given a Domain name and IP address.
*********************************************************/

BOOL lookup_dc_name(const char *srcname, const char *domain, 
		    struct in_addr *dc_ip, char *ret_name)
{
#if !defined(I_HATE_WINDOWS_REPLY_CODE)	
	fstring dc_name;
	BOOL ret;

	if (lp_disable_netbios()) {
		DEBUG(5,("lookup_dc_name(%s): netbios is disabled\n", domain));
		return False;
	}
	
	/*
	 * Due to the fact win WinNT *sucks* we must do a node status
	 * query here... JRA.
	 */
	
	*dc_name = '\0';
	
	ret = name_status_find(domain, 0x1c, 0x20, *dc_ip, dc_name);

	if(ret && *dc_name) {
		fstrcpy(ret_name, dc_name);
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
	slprintf(bufp, sizeof(fstring)-1, "\\MAILSLOT\\NET\\GETDC%d", dgm_id);
	mailslot_name = bufp;
	bufp += (strlen(bufp) + 1);
	bufp = ALIGN2(bufp, buffer);
	bufp += push_ucs2(NULL, bufp, srcname, sizeof(buffer) - (bufp - buffer), STR_TERMINATE);	
	
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
				DEBUG(0,("lookup_pdc_name: datagram type %u != SMBtrans(%u)\n", (uint_t)
					 CVAL(buf,smb_com), (uint_t)SMBtrans ));
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
					 (uint_t)SVAL(buf,0), (uint_t)QUERYFORPDC_R ));
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
 Get the IP address list of the primary domain controller
 for a domain.
*********************************************************/

BOOL get_pdc_ip(TALLOC_CTX *mem_ctx, const char *domain, struct in_addr *ip)
{
	struct in_addr *ip_list;
	int count;
	int i = 0;

	/* Look up #1B name */

	if (!internal_resolve_name(mem_ctx, domain, 0x1b, &ip_list, &count))
		return False;

	/* if we get more than 1 IP back we have to assume it is a
	   multi-homed PDC and not a mess up */
	   
	if ( count > 1 ) {
		DEBUG(6,("get_pdc_ip: PDC has %d IP addresses!\n", count));
				
		/* look for a local net */
		for ( i=0; i<count; i++ ) {
			if ( is_local_net( ip_list[i] ) )
				break;
		}
		
		/* if we hit then end then just grab the first 
		   one from the list */
		   
		if ( i == count )
			i = 0;
	}

	*ip = ip_list[i];
	
	SAFE_FREE(ip_list);

	return True;
}

/********************************************************
 Get the IP address list of the domain controllers for
 a domain.
*********************************************************/

BOOL get_dc_list(TALLOC_CTX *mem_ctx, const char *domain, struct in_addr **ip_list, int *count, int *ordered)
{

	*ordered = False;
		
	/* If it's our domain then use the 'password server' parameter. */

	if (strequal(domain, lp_workgroup())) {
		char *p;
		char *pserver = lp_passwordserver(); /* UNIX charset. */
		fstring name;
		int num_addresses = 0;
		int  local_count, i, j;
		struct in_addr *return_iplist = NULL;
		struct in_addr *auto_ip_list = NULL;
		BOOL done_auto_lookup = False;
		int auto_count = 0;
		

		if (!*pserver)
			return internal_resolve_name(mem_ctx,
				domain, 0x1C, ip_list, count);

		p = pserver;

		/*
		 * if '*' appears in the "password server" list then add
		 * an auto lookup to the list of manually configured
		 * DC's.  If any DC is listed by name, then the list should be 
		 * considered to be ordered 
		 */
		 
		while (next_token(&p,name,LIST_SEP,sizeof(name))) {
			if (strequal(name, "*")) {
				if ( internal_resolve_name(mem_ctx, domain, 0x1C, &auto_ip_list, &auto_count) )
					num_addresses += auto_count;
				done_auto_lookup = True;
				DEBUG(8,("Adding %d DC's from auto lookup\n", auto_count));
			}
			else 
				num_addresses++;
		}

		/* if we have no addresses and haven't done the auto lookup, then
		   just return the list of DC's */
		   
		if ( (num_addresses == 0) && !done_auto_lookup )
			return internal_resolve_name(mem_ctx, domain, 0x1C, ip_list, count);

		return_iplist = (struct in_addr *)malloc(num_addresses * sizeof(struct in_addr));

		if (return_iplist == NULL) {
			DEBUG(3,("get_dc_list: malloc fail !\n"));
			return False;
		}

		p = pserver;
		local_count = 0;

		/* fill in the return list now with real IP's */
				
		while ( (local_count<num_addresses) && next_token(&p,name,LIST_SEP,sizeof(name)) ) {
			struct in_addr name_ip;
			
			/* copy any addersses from the auto lookup */
			
			if ( strequal(name, "*") ) {
				for ( j=0; j<auto_count; j++ ) 
					return_iplist[local_count++] = auto_ip_list[j];
				continue;
			}
			
			/* explicit lookup; resolve_name() will handle names & IP addresses */
					
			if ( resolve_name( mem_ctx, name, &name_ip, 0x20) ) {
				return_iplist[local_count++] = name_ip;
				*ordered = True;
			}
				
		}
				
		SAFE_FREE(auto_ip_list);

		/* need to remove duplicates in the list if we have 
		   any explicit password servers */
		   
		if ( *ordered ) {		
			/* one loop to remove duplicates */
			for ( i=0; i<local_count; i++ ) {
				if ( is_zero_ip(return_iplist[i]) )
					continue;
					
				for ( j=i+1; j<local_count; j++ ) {
					if ( ip_equal( return_iplist[i], return_iplist[j]) )
						zero_ip(&return_iplist[j]);
				}
			}
			
			/* one loop to clean up any holes we left */
			/* first ip should never be a zero_ip() */
			for (i = 0; i<local_count; ) {
				if ( is_zero_ip(return_iplist[i]) ) {
					if (i != local_count-1 )
						memmove(&return_iplist[i], &return_iplist[i+1],
							(local_count - i - 1)*sizeof(return_iplist[i]));
					local_count--;
					continue;
				}
				i++;
			}
		}
		
		*ip_list = return_iplist;
		*count = local_count;
		
		DEBUG(8,("get_dc_list: return %d ip addresses\n", *count));

		return (*count != 0);
	}
	
	return internal_resolve_name(mem_ctx, domain, 0x1C, ip_list, count);
}
