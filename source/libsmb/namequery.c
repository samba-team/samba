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

extern pstring scope;
extern int DEBUGLEVEL;

/* nmbd.c sets this to True. */
BOOL global_in_nmbd = False;

/****************************************************************************
interpret a node status response
****************************************************************************/
static void _interpret_node_status(char *p, char *master,char *rname)
{
  int numnames = CVAL(p,0);
  DEBUG(1,("received %d names\n",numnames));

  if (rname) *rname = 0;
  if (master) *master = 0;

  p += 1;
  while (numnames--)
    {
      char qname[17];
      int type;
      fstring flags;
      int i;
      *flags = 0;
      StrnCpy(qname,p,15);
      type = CVAL(p,15);
      p += 16;

      fstrcat(flags, (p[0] & 0x80) ? "<GROUP> " : "        ");
      if ((p[0] & 0x60) == 0x00) fstrcat(flags,"B ");
      if ((p[0] & 0x60) == 0x20) fstrcat(flags,"P ");
      if ((p[0] & 0x60) == 0x40) fstrcat(flags,"M ");
      if ((p[0] & 0x60) == 0x60) fstrcat(flags,"H ");
      if (p[0] & 0x10) fstrcat(flags,"<DEREGISTERING> ");
      if (p[0] & 0x08) fstrcat(flags,"<CONFLICT> ");
      if (p[0] & 0x04) fstrcat(flags,"<ACTIVE> ");
      if (p[0] & 0x02) fstrcat(flags,"<PERMANENT> ");

      if (master && !*master && type == 0x1d) {
	StrnCpy(master,qname,15);
	trim_string(master,NULL," ");
      }

      if (rname && !*rname && type == 0x20 && !(p[0]&0x80)) {
	StrnCpy(rname,qname,15);
	trim_string(rname,NULL," ");
      }
      
      for (i = strlen( qname) ; --i >= 0 ; ) {
	if (!isprint(qname[i])) qname[i] = '.';
      }
      DEBUG(1,("\t%-15s <%02x> - %s\n",qname,type,flags));
      p+=2;
    }
  DEBUG(1,("num_good_sends=%d num_good_receives=%d\n",
	       IVAL(p,20),IVAL(p,24)));
}


/****************************************************************************
  do a netbios name status query on a host

  the "master" parameter is a hack used for finding workgroups.
  **************************************************************************/
BOOL name_status(int fd,char *name,int name_type,BOOL recurse,
		 struct in_addr to_ip,char *master,char *rname,
		 void (*fn)(struct packet_struct *))
{
  BOOL found=False;
  int retries = 2;
  int retry_time = 5000;
  struct timeval tval;
  struct packet_struct p;
  struct packet_struct *p2;
  struct nmb_packet *nmb = &p.packet.nmb;
  static int name_trn_id = 0;

  bzero((char *)&p,sizeof(p));

  if (!name_trn_id) name_trn_id = (time(NULL)%(unsigned)0x7FFF) + 
    (getpid()%(unsigned)100);
  name_trn_id = (name_trn_id+1) % (unsigned)0x7FFF;

  nmb->header.name_trn_id = name_trn_id;
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

  make_nmb_name(&nmb->question.question_name,name,name_type,scope);

  nmb->question.question_type = 0x21;
  nmb->question.question_class = 0x1;

  p.ip = to_ip;
  p.port = NMB_PORT;
  p.fd = fd;
  p.timestamp = time(NULL);
  p.packet_type = NMB_PACKET;

  GetTimeOfDay(&tval);

  if (!send_packet(&p)) 
    return(False);

  retries--;

  while (1)
    {
      struct timeval tval2;
      GetTimeOfDay(&tval2);
      if (TvalDiff(&tval,&tval2) > retry_time) {
	if (!retries) break;
	if (!found && !send_packet(&p))
	  return False;
	GetTimeOfDay(&tval);
	retries--;
      }

      if ((p2=receive_packet(fd,NMB_PACKET,90)))
	{     
	  struct nmb_packet *nmb2 = &p2->packet.nmb;
      debug_nmb_packet(p2);

	  if (nmb->header.name_trn_id != nmb2->header.name_trn_id ||
	      !nmb2->header.response) {
	    /* its not for us - maybe deal with it later */
	    if (fn) 
	      fn(p2);
	    else
	      free_packet(p2);
	    continue;
	  }
	  
	  if (nmb2->header.opcode != 0 ||
	      nmb2->header.nm_flags.bcast ||
	      nmb2->header.rcode ||
	      !nmb2->header.ancount ||
	      nmb2->answers->rr_type != 0x21) {
	    /* XXXX what do we do with this? could be a redirect, but
	       we'll discard it for the moment */
	    free_packet(p2);
	    continue;
	  }

	  _interpret_node_status(&nmb2->answers->rdata[0], master,rname);
	  free_packet(p2);
	  return(True);
	}
    }
  

  DEBUG(0,("No status response (this is not unusual)\n"));

  return(False);
}


/****************************************************************************
  do a netbios name query to find someones IP
  returns an array of IP addresses or NULL if none
  *count will be set to the number of addresses returned
  ****************************************************************************/
struct in_addr *name_query(int fd,char *name,int name_type, BOOL bcast,BOOL recurse,
         struct in_addr to_ip, int *count, void (*fn)(struct packet_struct *))
{
  BOOL found=False;
  int i, retries = 3;
  int retry_time = bcast?250:2000;
  struct timeval tval;
  struct packet_struct p;
  struct packet_struct *p2;
  struct nmb_packet *nmb = &p.packet.nmb;
  static int name_trn_id = 0;
  struct in_addr *ip_list = NULL;

  bzero((char *)&p,sizeof(p));
  (*count) = 0;

  if (!name_trn_id) name_trn_id = (time(NULL)%(unsigned)0x7FFF) + 
    (getpid()%(unsigned)100);
  name_trn_id = (name_trn_id+1) % (unsigned)0x7FFF;

  nmb->header.name_trn_id = name_trn_id;
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

  make_nmb_name(&nmb->question.question_name,name,name_type,scope);

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
	if (!retries) break;
	if (!found && !send_packet(&p))
	  return NULL;
	GetTimeOfDay(&tval);
	retries--;
      }

      if ((p2=receive_packet(fd,NMB_PACKET,90)))
	{     
	  struct nmb_packet *nmb2 = &p2->packet.nmb;
	  debug_nmb_packet(p2);

	  if (nmb->header.name_trn_id != nmb2->header.name_trn_id ||
	      !nmb2->header.response) {
	    /* its not for us - maybe deal with it later 
	       (put it on the queue?) */
	    if (fn) 
	      fn(p2);
	    else
	      free_packet(p2);
	    continue;
	  }
	  
	  if (nmb2->header.opcode != 0 ||
	      nmb2->header.nm_flags.bcast ||
	      nmb2->header.rcode ||
	      !nmb2->header.ancount) {
	    /* XXXX what do we do with this? could be a redirect, but
	       we'll discard it for the moment */
	    free_packet(p2);
	    continue;
	  }

	  ip_list = (struct in_addr *)Realloc(ip_list, sizeof(ip_list[0]) * 
					      ((*count)+nmb2->answers->rdlength/6));
	  if (ip_list) {
		  DEBUG(fn?3:2,("Got a positive name query response from %s ( ",
				inet_ntoa(p2->ip)));
		  for (i=0;i<nmb2->answers->rdlength/6;i++) {
			  putip((char *)&ip_list[(*count)],&nmb2->answers->rdata[2+i*6]);
			  DEBUG(fn?3:2,("%s ",inet_ntoa(ip_list[(*count)])));
			  (*count)++;
		  }
		  DEBUG(fn?3:2,(")\n"));
	  }
	  found=True; retries=0;
	  free_packet(p2);
	  if (fn) break;
	}
    }

  return ip_list;
}

/********************************************************
 Start parsing the lmhosts file.
*********************************************************/

FILE *startlmhosts(char *fname)
{
  FILE *fp = fopen(fname,"r");
  if (!fp) {
    DEBUG(2,("startlmhosts: Can't open lmhosts file %s. Error was %s\n",
             fname, strerror(errno)));
    return NULL;
  }
  return fp;
}

/********************************************************
 Parse the next line in the lmhosts file.
*********************************************************/

BOOL getlmhostsent( FILE *fp, char *name, int *name_type, struct in_addr *ipaddr)
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

    if (next_token(&ptr,ip   ,NULL))
      ++count;
    if (next_token(&ptr,name ,NULL))
      ++count;
    if (next_token(&ptr,flags,NULL))
      ++count;
    if (next_token(&ptr,extra,NULL))
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
      *name_type = (int)strtol(ptr, &endptr,0);

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
 Resolve a name into an IP address. Use this function if
 the string is either an IP address, DNS or host name
 or NetBIOS name. This uses the name switch in the
 smb.conf to determine the order of name resolution.
*********************************************************/

BOOL resolve_name(char *name, struct in_addr *return_ip)
{
  int i;
  BOOL pure_address = True;
  pstring name_resolve_list;
  fstring tok;
  char *ptr;

  if (strcmp(name,"0.0.0.0") == 0) {
    return_ip->s_addr = 0;
    return True;
  }
  if (strcmp(name,"255.255.255.255") == 0) {
    return_ip->s_addr = 0xFFFFFFFF;
    return True;
  }
   
  for (i=0; pure_address && name[i]; i++)
    if (!(isdigit(name[i]) || name[i] == '.'))
      pure_address = False;
   
  /* if it's in the form of an IP address then get the lib to interpret it */
  if (pure_address) {
    return_ip->s_addr = inet_addr(name);
    return True;
  }

  pstrcpy(name_resolve_list, lp_name_resolve_order());
  ptr = name_resolve_list;
  if (!ptr || !*ptr) ptr = "host";

  while (next_token(&ptr, tok, LIST_SEP)) {
    if(strequal(tok, "host") || strequal(tok, "hosts")) {

      /*
       * "host" means do a localhost, or dns lookup.
       */

      struct hostent *hp;

      DEBUG(3,("resolve_name: Attempting host lookup for name %s\n", name));

      if (((hp = Get_Hostbyname(name)) != NULL) && (hp->h_addr != NULL)) {
        putip((char *)return_ip,(char *)hp->h_addr);
        return True;
      }

    } else if(strequal( tok, "lmhosts")) {

      /*
       * "lmhosts" means parse the local lmhosts file.
       */

      FILE *fp;
      pstring lmhost_name;
      int name_type;

      DEBUG(3,("resolve_name: Attempting lmhosts lookup for name %s\n", name));

      fp = startlmhosts( LMHOSTSFILE );
      if(fp) {
        while( getlmhostsent(fp, lmhost_name, &name_type, return_ip ) ) {
          if( strequal(name, lmhost_name )) {
            endlmhosts(fp);
            return True; 
          }
        }
        endlmhosts(fp);
      }

    } else if(strequal( tok, "wins")) {

      int sock;

      /*
       * "wins" means do a unicast lookup to the WINS server.
       * Ignore if there is no WINS server specified or if the
       * WINS server is one of our interfaces (if we're being
       * called from within nmbd - we can't do this call as we
       * would then block).
       */

      DEBUG(3,("resolve_name: Attempting wins lookup for name %s<0x20>\n", name));

      if(*lp_wins_server()) {
        struct in_addr wins_ip = *interpret_addr2(lp_wins_server());
        BOOL wins_ismyip = ismyip(wins_ip);

        if((wins_ismyip && !global_in_nmbd) || !wins_ismyip) {
          sock = open_socket_in( SOCK_DGRAM, 0, 3,
                               interpret_addr(lp_socket_address()) );

          if (sock != -1) {
            struct in_addr *iplist = NULL;
            int count;
            iplist = name_query(sock, name, 0x20, False, True, wins_ip, &count, NULL);
            if(iplist != NULL) {
              *return_ip = iplist[0];
              free((char *)iplist);
              close(sock);
              return True;
            }
            close(sock);
          }
        }
      } else {
        DEBUG(3,("resolve_name: WINS server resolution selected and no WINS server present.\n"));
      }
    } else if(strequal( tok, "bcast")) {

      int sock;

      /*
       * "bcast" means do a broadcast lookup on all the local interfaces.
       */

      DEBUG(3,("resolve_name: Attempting broadcast lookup for name %s<0x20>\n", name));

      sock = open_socket_in( SOCK_DGRAM, 0, 3,
                             interpret_addr(lp_socket_address()) );

      if (sock != -1) {
        struct in_addr *iplist = NULL;
        int count;
        int num_interfaces = iface_count();
        set_socket_options(sock,"SO_BROADCAST");
        /*
         * Lookup the name on all the interfaces, return on
         * the first successful match.
         */
        for( i = 0; i < num_interfaces; i++) {
          struct in_addr sendto_ip = *iface_bcast(*iface_n_ip(i));
          iplist = name_query(sock, name, 0x20, True, False, sendto_ip, &count, NULL);
          if(iplist != NULL) {
            *return_ip = iplist[0];
            free((char *)iplist);
            close(sock);
            return True;
          }
        }
        close(sock);
      }

    } else {
      DEBUG(0,("resolve_name: unknown name switch type %s\n", tok));
    }
  }

  return False;
}
