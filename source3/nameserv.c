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


enum name_search { FIND_SELF, FIND_GLOBAL };

extern int DEBUGLEVEL;

extern pstring scope;
extern BOOL CanRecurse;
extern pstring myname;
extern struct in_addr ipzero;

/* netbios names database */
struct name_record *namelist;

#define GET_TTL(ttl) ((ttl)?MIN(ttl,lp_max_ttl()):lp_max_ttl())


/****************************************************************************
  true if two netbios names are equal
****************************************************************************/
static BOOL name_equal(struct nmb_name *n1,struct nmb_name *n2)
{
  if (n1->name_type != n2->name_type) return(False);

  return(strequal(n1->name,n2->name) && strequal(n1->scope,n2->scope));
}

/****************************************************************************
  add a netbios name into the namelist
  **************************************************************************/
static void add_name(struct name_record *n)
{
  struct name_record *n2;

  if (!namelist)
  {
    namelist = n;
    n->prev = NULL;
    n->next = NULL;
    return;
  }

  for (n2 = namelist; n2->next; n2 = n2->next) ;

  n2->next = n;
  n->next = NULL;
  n->prev = n2;
}

/****************************************************************************
  remove a name from the namelist. The pointer must be an element just 
  retrieved
  **************************************************************************/
void remove_name(struct name_record *n)
{
  struct name_record *nlist = namelist;

  while (nlist && nlist != n) nlist = nlist->next;

  if (nlist)
  {
    if (nlist->next) nlist->next->prev = nlist->prev;
    if (nlist->prev) nlist->prev->next = nlist->next;
    free(nlist);
  }
}

/****************************************************************************
  find a name in the domain database namelist 
  search can be:
  FIND_SELF   - look for names the samba server has added for itself
  FIND_GLOBAL - the name can be anyone. first look on the client's
                subnet, then the server's subnet, then all subnets.
  **************************************************************************/
static struct name_record *find_name_search(struct nmb_name *name, enum name_search search,
					    struct in_addr ip)
{
	struct name_record *ret;

	/* any number of winpopup names can be added. must search by ip as well */
	if (name->name_type != 0x3) ip = ipzero;

	for (ret = namelist; ret; ret = ret->next)
	{
		if (name_equal(&ret->name,name))
		{
			/* self search: self names only */
			if (search == FIND_SELF && ret->source != SELF) continue;

			if (zero_ip(ip) || ip_equal(ip, ret->ip))
			{
				return ret;
			}
		}
	}

	return NULL;
}


/****************************************************************************
  dump a copy of the name table
  **************************************************************************/
void dump_names(void)
{
	struct name_record *n;
	time_t t = time(NULL);

	DEBUG(3,("Dump of local name table:\n"));

	for (n = namelist; n; n = n->next)
	{
		DEBUG(3,("%s %s TTL=%d NBFLAGS=%2x\n",
		        namestr(&n->name),
		        inet_ntoa(n->ip),
		        n->death_time?n->death_time-t:0,
				n->nb_flags));
	}
}


/****************************************************************************
  remove an entry from the name list
  ****************************************************************************/
void remove_netbios_name(char *name,int type, enum name_source source,
			 struct in_addr ip)
{
	struct nmb_name nn;
	struct name_record *n;

	make_nmb_name(&nn, name, type, scope);
	n = find_name_search(&nn, FIND_GLOBAL, ip);

	if (n && n->source == source) remove_name(n);
}


/****************************************************************************
  add an entry to the name list
  ****************************************************************************/
struct name_record *add_netbios_entry(char *name, int type, int nb_flags, int ttl,
				      enum name_source source, struct in_addr ip)
{
  struct name_record *n;
  struct name_record *n2=NULL;

  n = (struct name_record *)malloc(sizeof(*n));
  if (!n) return(NULL);

  bzero((char *)n,sizeof(*n));

  make_nmb_name(&n->name,name,type,scope);

  if ((n2 = find_name_search(&n->name, FIND_GLOBAL, ip)))
  {
    free(n);
    n = n2;
  }

  if (ttl) n->death_time = time(NULL)+ttl*3;
  n->ip = ip;
  n->nb_flags = nb_flags;
  n->source = source;
  
  if (!n2) add_name(n);

  DEBUG(3,("Added netbios name %s at %s ttl=%d nb_flags=%2x\n",
	        namestr(&n->name),inet_ntoa(ip),ttl,nb_flags));

  return(n);
}


/****************************************************************************
  remove an entry from the name list
  ****************************************************************************/
void remove_name_entry(char *name,int type)
{
  if (lp_wins_support())
    {
      /* we are a WINS server. */
      remove_netbios_name(name,type,SELF,myip);
    }
  else
    {
      struct in_addr ip;
      ip = ipzero;
      
      queue_netbios_pkt_wins(ClientNMB,NMB_REL,NAME_RELEASE,
			     name, type, 0,
			     False, True, ip);
    }
}


/****************************************************************************
  add an entry to the name list
  ****************************************************************************/
void add_name_entry(char *name,int type,int nb_flags)
{
  /* always add our own entries */
  add_netbios_entry(name,type,nb_flags,0,SELF,myip);

  if (!lp_wins_support())
    {
      struct in_addr ip;
      ip = ipzero;
      
      queue_netbios_pkt_wins(ClientNMB,NMB_REG,NAME_REGISTER,
			     name, type, nb_flags,
			     False, True, ip);
    }
}


/****************************************************************************
  add the magic samba names, useful for finding samba servers
  **************************************************************************/
void add_my_names(void)
{
  struct in_addr ip;

  ip = ipzero;
  
  add_name_entry(myname,0x20,NB_ACTIVE);
  add_name_entry(myname,0x03,NB_ACTIVE);
  add_name_entry(myname,0x00,NB_ACTIVE);
  add_name_entry(myname,0x1f,NB_ACTIVE);
  
  add_netbios_entry("*",0x0,NB_ACTIVE,0,SELF,ip);
  add_netbios_entry("__SAMBA__",0x20,NB_ACTIVE,0,SELF,ip);
  add_netbios_entry("__SAMBA__",0x00,NB_ACTIVE,0,SELF,ip);
  
  if (lp_wins_support()) {
    add_netbios_entry(inet_ntoa(myip),0x01,NB_ACTIVE,0,SELF,ip); /* nt as? */
  }
}

/*******************************************************************
  refresh my own names
  ******************************************************************/
void refresh_my_names(time_t t)
{
  static time_t lasttime = 0;

  if (t - lasttime < REFRESH_TIME) 
    return;
  lasttime = t;

  add_my_names();
}

/*******************************************************************
  expires old names in the namelist
  ******************************************************************/
void expire_names(time_t t)
{
  struct name_record *n;
  struct name_record *next;
  
  /* expire old names */
  for (n = namelist; n; n = next)
    {
      if (n->death_time && n->death_time < t)
	{
	  DEBUG(3,("Removing dead name %s\n", namestr(&n->name)));
	  
	  next = n->next;
	  
	  if (n->prev) n->prev->next = n->next;
	  if (n->next) n->next->prev = n->prev;
	  
	  if (namelist == n) namelist = n->next; 
	  
	  free(n);
	}
      else
	{
	  next = n->next;
	}
    }
}


/****************************************************************************
response for a reg release received
**************************************************************************/
void response_name_release(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *name = nmb->question.question_name.name;
  int   type = nmb->question.question_name.name_type;
  
  DEBUG(4,("response name release received\n"));
  
  if (nmb->header.rcode == 0 && nmb->answers->rdata)
    {
      struct in_addr found_ip;
      putip((char*)&found_ip,&nmb->answers->rdata[2]);
      
      if (ip_equal(found_ip, myip))
	{
	  remove_netbios_name(name,type,SELF,found_ip);
	}
    }
  else
    {
      DEBUG(1,("name registration for %s rejected!\n",
	       namestr(&nmb->question.question_name)));
    }
}


/****************************************************************************
reply to a name release
****************************************************************************/
void reply_name_release(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct in_addr ip;
  int rcode=0;
  int opcode = nmb->header.opcode;  
  int nb_flags = nmb->additional->rdata[0];
  BOOL bcast = nmb->header.nm_flags.bcast;
  struct name_record *n;
  char rdata[6];
  
  putip((char *)&ip,&nmb->additional->rdata[2]);  
  
  DEBUG(3,("Name release on name %s rcode=%d\n",
	   namestr(&nmb->question.question_name),rcode));
  
  n = find_name_search(&nmb->question.question_name, FIND_GLOBAL, ip);
  
  /* XXXX under what conditions should we reject the removal?? */
  if (n && n->nb_flags == nb_flags && ip_equal(n->ip,ip))
    {
      /* success = True;
	 rcode = 6; */
      
      remove_name(n);
      n = NULL;
    }
  
  if (bcast) return;
  
  /*if (success)*/
  {
    rdata[0] = nb_flags;
    rdata[1] = 0;
    putip(&rdata[2],(char *)&ip);
  }
  
  /* Send a NAME RELEASE RESPONSE */
  reply_netbios_packet(p,nmb->header.name_trn_id,rcode,opcode,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       0,
		       rdata, 6 /*success ? 6 : 0*/);
  /* XXXX reject packet never tested: cannot tell what to do */
}


/****************************************************************************
response for a reg request received
**************************************************************************/
void response_name_reg(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *name = nmb->question.question_name.name;
  int   type = nmb->question.question_name.name_type;
  
  DEBUG(4,("response name registration received!\n"));
  
  if (nmb->header.rcode == 0 && nmb->answers->rdata)
    {
      int nb_flags = nmb->answers->rdata[0];
      struct in_addr found_ip;
      int ttl = nmb->answers->ttl;
      enum name_source source = REGISTER;
      
      putip((char*)&found_ip,&nmb->answers->rdata[2]);
      
      if (ip_equal(found_ip, myip)) source = SELF;
      
      add_netbios_entry(name,type,nb_flags,ttl,source,found_ip);
    }
  else
    {
      DEBUG(1,("name registration for %s rejected!\n",
	       namestr(&nmb->question.question_name)));
    }
}


/****************************************************************************
reply to a reg request
**************************************************************************/
void reply_name_reg(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *question = &nmb->question.question_name;
  char *qname = nmb->question.question_name.name;
  int name_type = nmb->question.question_name.name_type;
  
  BOOL bcast = nmb->header.nm_flags.bcast;
  
  int ttl = GET_TTL(nmb->additional->ttl);
  int nb_flags = nmb->additional->rdata[0];
  BOOL group = (nb_flags&0x80);
  int rcode = 0;  
  int opcode = nmb->header.opcode;  
  struct name_record *n = NULL;
  int success = True;
  char rdata[6];
  struct in_addr ip, from_ip;
  
  putip((char *)&from_ip,&nmb->additional->rdata[2]);
  ip = from_ip;
  
  DEBUG(3,("Name registration for name %s at %s rcode=%d\n",
	   namestr(question),inet_ntoa(ip),rcode));
  
  if (group)
    {
      /* apparently we should return 255.255.255.255 for group queries
	 (email from MS) */
      ip = *interpret_addr2("255.255.255.255");
    }
  
  /* see if the name already exists */
  n = find_name_search(question, FIND_GLOBAL, from_ip);
  
  if (n)
    {
      if (!group && !ip_equal(ip,n->ip) && question->name_type != 0x3)
	{
	  if (n->source == SELF)
	    {
	      rcode = 6;
	      success = False;
	    }
	  else
	    {
	      n->ip = ip;
	      n->death_time = ttl?p->timestamp+ttl*3:0;
	      DEBUG(3,("%s changed owner to %s\n",
		       namestr(&n->name),inet_ntoa(n->ip)));
	    }
	}
      else
	{
	  /* refresh the name */
	  if (n->source != SELF)
	    {
	      n->death_time = ttl?p->timestamp + ttl*3:0;
	    }
	}
    }
  else
    {
      /* add the name to our subnet/name database */
      n = add_netbios_entry(qname,name_type,nb_flags,ttl,REGISTER,ip);
    }
  
  if (bcast) return;
  
  update_from_reg(nmb->question.question_name.name,
		  nmb->question.question_name.name_type, from_ip);
  
  /* XXXX don't know how to reject a name register: stick info in anyway
     and guess that it doesn't matter if info is there! */
  /*if (success)*/
  {
    rdata[0] = nb_flags;
    rdata[1] = 0;
    putip(&rdata[2],(char *)&ip);
  }
  
  /* Send a NAME REGISTRATION RESPONSE */
  reply_netbios_packet(p,nmb->header.name_trn_id,rcode,opcode,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       ttl,
		       rdata, 6 /*success ? 6 : 0*/);
}


/****************************************************************************
reply to a name status query
****************************************************************************/
void reply_name_status(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *qname   = nmb->question.question_name.name;
  int ques_type = nmb->question.question_name.name_type;
  BOOL wildcard = (qname[0] == '*'); 
  char rdata[MAX_DGRAM_SIZE];
  char *countptr, *buf;
  int count, names_added;
  struct name_record *n;
  
  DEBUG(3,("Name status for name %s %s\n",
	   namestr(&nmb->question.question_name), inet_ntoa(p->ip)));
  
  /* find a name: if it's a wildcard, search the entire database.
     if not, search for source SELF names only */
  n = find_name_search(&nmb->question.question_name,
		       wildcard ? FIND_GLOBAL : FIND_SELF, p->ip);
  
  if (!wildcard && (!n || n->source != SELF)) return;
  
  for (count=0, n = namelist ; n; n = n->next)
    {
      int name_type = n->name.name_type;
      
      if (n->source != SELF) continue;
      
      if (name_type >= 0x1b && name_type <= 0x20 && 
	  ques_type >= 0x1b && ques_type <= 0x20)
	{
	  if (!strequal(qname, n->name.name)) continue;
	}
      
      count++;
    }
  
  /* XXXX hack, we should calculate exactly how many will fit */
  count = MIN(count,(sizeof(rdata) - 64) / 18);
  
  countptr = buf = rdata;
  buf += 1;
  
  names_added = 0;
  
  for (n = namelist ; n && count >= 0; n = n->next) 
    {
      int name_type = n->name.name_type;
      
      if (n->source != SELF) continue;
      
      /* start with first bit of putting info in buffer: the name */
      
      bzero(buf,18);
      StrnCpy(buf,n->name.name,15);
      strupper(buf);
      
      /* now check if we want to exclude other workgroup names
	 from the response. if we don't exclude them, windows clients
	 get confused and will respond with an error for NET VIEW */
      
      if (name_type >= 0x1b && name_type <= 0x20 && 
	  ques_type >= 0x1b && ques_type <= 0x20)
	{
	  if (!strequal(qname, n->name.name)) continue;
	}
      
      /* carry on putting name info in buffer */
      
      buf[15] = name_type;
      buf[16]  = n->nb_flags;
      
      buf += 18;
      
      count--;
      names_added++;
    }
  
  if (count < 0)
    {
      DEBUG(3, (("too many names: missing a few!\n")));
    }
  
  SCVAL(countptr,0,names_added);
  
  /* XXXXXXX we should fill in more fields of the statistics structure */
  bzero(buf,64);
  {
    extern int num_good_sends,num_good_receives;
    SIVAL(buf,20,num_good_sends);
    SIVAL(buf,24,num_good_receives);
  }
  
  SIVAL(buf,46,0xFFB8E5); /* undocumented - used by NT */
  
  buf += 64;
  
  /* Send a POSITIVE NAME STATUS RESPONSE */
  reply_netbios_packet(p,nmb->header.name_trn_id,0,0,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       0,
		       rdata,PTR_DIFF(buf,rdata));
}


/***************************************************************************
reply to a name query
****************************************************************************/
struct name_record *search_for_name(struct nmb_name *question,
				    struct in_addr ip, int Time, int search)
{
  int name_type = question->name_type;
  char *qname = question->name;
  BOOL dns_type = name_type == 0x20 || name_type == 0;
  
  struct name_record *n;
  
  DEBUG(3,("Search for %s from %s - ", namestr(question), inet_ntoa(ip)));
  
  /* first look up name in cache */
  n = find_name_search(question,search,ip);
  
  /* now try DNS lookup. */
  if (!n)
    {
      struct in_addr dns_ip;
      unsigned long a;
      
      /* only do DNS lookups if the query is for type 0x20 or type 0x0 */
      if (!dns_type)
	{
	  DEBUG(3,("types 0x20 0x1b 0x0 only: name not found\n"));
	  return NULL;
	}
      
      /* look it up with DNS */      
      a = interpret_addr(qname);
      
      putip((char *)&dns_ip,(char *)&a);
      
      if (!a)
	{
	  /* no luck with DNS. We could possibly recurse here XXXX */
	  /* if this isn't a bcast then we should send a negative reply XXXX */
	  DEBUG(3,("no recursion\n"));
	  add_netbios_entry(qname,name_type,NB_ACTIVE,60*60,DNSFAIL,dns_ip);
	  return NULL;
	}
      
      /* add it to our cache of names. give it 2 hours in the cache */
      n = add_netbios_entry(qname,name_type,NB_ACTIVE,2*60*60,DNS,dns_ip);
      
      /* failed to add it? yikes! */
      if (!n) return NULL;
    }
  
  /* is our entry already dead? */
  if (n->death_time)
    {
      if (n->death_time < Time) return False;
    }
  
  /* it may have been an earlier failure */
  if (n->source == DNSFAIL)
    {
      DEBUG(3,("DNSFAIL\n"));
      return NULL;
    }
  
  DEBUG(3,("OK %s\n",inet_ntoa(n->ip)));      
  
  return n;
}

/* XXXX i think we should only do this if we are a WINS proxy
		if (!n && bcast)
		{
		// now try look up the name at the primary domain controller
			if (*lp_domain_controller())
			{
				struct in_addr dom_ip;
				dom_ip = *interpret_addr2(lp_domain_controller());

				if (!zero_ip(dom_ip))
				{
					struct in_addr found_ip;

					// initiate a netbios query to the PDC
					queue_netbios_packet(ClientNMB,NMB_QUERY,NAME_CONFIRM_QUERY,
										question->name, question->name_type, 0,
										False, True, dom_ip, id);
					return;
				}
			}
		}
*/

/***************************************************************************
reply to a name query.

with broadcast name queries:

	- only reply if the query is for one of YOUR names. all other machines on
	  the network will be doing the same thing (that is, only replying to a
	  broadcast query if they own it)
	  NOTE: broadcast name queries should only be sent out by a machine
	  if they HAVEN'T been configured to use WINS. this is generally bad news
	  in a wide area tcp/ip network and should be rectified by the systems
	  administrator. USE WINS! :-)
	- the exception to this is if the query is for a Primary Domain Controller
	  type name (0x1b), in which case, a reply is sent.

	- NEVER send a negative response to a broadcast query. no-one else will!

with directed name queries:

	- if you are the WINS server, you are expected to 
****************************************************************************/
extern void reply_name_query(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *question = &nmb->question.question_name;
  int name_type = question->name_type;
  BOOL dns_type = name_type == 0x20 || name_type == 0;
  BOOL bcast = nmb->header.nm_flags.bcast;
  int ttl=0;
  int rcode = 0;
  int nb_flags = 0;
  struct in_addr retip;
  char rdata[6];
  
  struct in_addr gp_ip = *interpret_addr2("255.255.255.255");
  BOOL success = True;
  
  struct name_record *n;
  enum name_search search = dns_type || name_type == 0x1b ?
    FIND_GLOBAL : FIND_SELF;
  
  DEBUG(3,("Name query "));
  
  if ((n = search_for_name(question,p->ip,p->timestamp, search)))
    {
      /* don't respond to broadcast queries unless the query is for
	 a name we own or it is for a Primary Domain Controller name */
      if (bcast && n->source != SELF && name_type != 0x1b)
	{
	  if (!lp_wins_proxy() || same_net(p->ip,n->ip,Netmask)) {
	    /* never reply with a negative response to broadcast queries */
	    return;
	  }
	}
      
      /* we will reply */
      ttl = n->death_time - p->timestamp;
      retip = n->ip;
      nb_flags = n->nb_flags;
    }
  else
    {
      if (bcast) return; /* never reply negative response to bcasts */
      success = False;
    }
  
  /* if asking for a group name (type 0x1e) return 255.255.255.255 */
  if (ip_equal(retip, gp_ip) && name_type == 0x1e) retip = gp_ip;

  /* if the IP is 0 then substitute my IP - we should see which one is on the 
     right interface for the caller to do this right XXX */
  if (zero_ip(retip)) retip = myip;

  if (success)
    {
      rcode = 0;
      DEBUG(3,("OK %s\n",inet_ntoa(retip)));      
    }
  else
    {
      rcode = 3;
      DEBUG(3,("UNKNOWN\n"));      
    }
  
  if (success)
    {
      rdata[0] = nb_flags;
      rdata[1] = 0;
      putip(&rdata[2],(char *)&retip);
    }
  
  reply_netbios_packet(p,nmb->header.name_trn_id,rcode,0,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       ttl,
		       rdata, success ? 6 : 0);
}


/****************************************************************************
response from a name query
****************************************************************************/
static void response_netbios_packet(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *question = &nmb->question.question_name;
  char *qname = question->name;
  BOOL bcast = nmb->header.nm_flags.bcast;
  struct name_response_record *n;

  if (nmb->answers == NULL)
    {
      DEBUG(3,("NMB packet response from %s (bcast=%s) - UNKNOWN\n",
	       inet_ntoa(p->ip),
	       BOOLSTR(bcast)));
      return;
    }
  
  if (nmb->answers->rr_type == NMB_STATUS) {
    DEBUG(3,("Name status "));
  }

  if (nmb->answers->rr_type == NMB_QUERY)	{
    DEBUG(3,("Name query "));
  }

  if (nmb->answers->rr_type == NMB_REG) {
    DEBUG(3,("Name registration "));
  }

  if (nmb->answers->rr_type == NMB_REL) {
    DEBUG(3,("Name release "));
  }

  DEBUG(3,("response for %s from %s (bcast=%s)\n",
	   namestr(&nmb->answers->rr_name),
	   inet_ntoa(p->ip),
	   BOOLSTR(bcast)));
  
  if (!(n = find_name_query(nmb->header.name_trn_id))) {
    DEBUG(3,("unknown response (received too late or from nmblookup?)\n"));
    return;
  }

  n->num_msgs++; /* count number of responses received */

  switch (n->cmd_type)
    {
    case MASTER_SERVER_CHECK     : DEBUG(4,("MASTER_SVR_CHECK\n")); break;
    case SERVER_CHECK            : DEBUG(4,("SERVER_CHECK\n")); break;
    case FIND_MASTER             : DEBUG(4,("FIND_MASTER\n")); break;
    case NAME_STATUS_MASTER_CHECK: DEBUG(4,("NAME_STAT_MST_CHK\n")); break;
    case NAME_STATUS_CHECK       : DEBUG(4,("NAME_STATUS_CHECK\n")); break;
    case CHECK_MASTER            : DEBUG(4,("CHECK_MASTER\n")); break;
    case NAME_CONFIRM_QUERY      : DEBUG(4,("NAME_CONFIRM_QUERY\n")); break;
    default: break;
    }
  switch (n->cmd_type)
    {
    case MASTER_SERVER_CHECK:
    case SERVER_CHECK:
    case FIND_MASTER:
      {
	if (nmb->answers->rr_type == NMB_QUERY)
	  {
	    enum cmd_type cmd = (n->cmd_type == MASTER_SERVER_CHECK) ?
	      NAME_STATUS_MASTER_CHECK :
	      NAME_STATUS_CHECK;
	    if (n->num_msgs > 1 && !strequal(qname,n->name.name))
	      {
		/* one subnet, one master browser per workgroup */
		/* XXXX force an election? */
		DEBUG(1,("more than one master browser replied!\n"));
	      }
	    
	    /* initiate a name status check on the server that replied */
	    queue_netbios_packet(ClientNMB,NMB_STATUS, cmd,
				 nmb->answers->rr_name.name,
				 nmb->answers->rr_name.name_type,0,
				 False,False,n->to_ip);
	  }
	else
	  {
	    DEBUG(1,("Name query reply has wrong answer rr_type\n"));
	  }
	break;
      }
      
    case NAME_STATUS_MASTER_CHECK:
    case NAME_STATUS_CHECK:
      {
	if (nmb->answers->rr_type == NMB_STATUS)
	  {
	    /* NMB_STATUS arrives: contains the workgroup name 
	       and server name we require */
	    struct nmb_name name;
	    fstring serv_name;
	    
	    if (interpret_node_status(nmb->answers->rdata,
				      &name,0x1d,serv_name,n->to_ip))
	      {
		if (*serv_name)
		  {
		    sync_server(n->cmd_type,serv_name,
				name.name,name.name_type,
				n->to_ip);
		  }
	      }
	    else
	      {
		DEBUG(1,("No 0x1d name type in interpret_node_status()\n"));
	      }
	  }
	else
	  {
	    DEBUG(1,("Name status reply has wrong answer rr_type\n"));
	  }
	break;
      }
      
    case CHECK_MASTER:
      {
	/* no action required here. it's when NO responses are received
	   that we need to do something (see expire_name_query_entries) */
	
	DEBUG(4, ("Master browser exists for %s at %s\n",
		  namestr(&n->name),
		  inet_ntoa(n->to_ip)));
	if (n->num_msgs > 1)
	  {
	    DEBUG(1,("more than one master browser!\n"));
	  }
	if (nmb->answers->rr_type != NMB_QUERY)
	  {
	    DEBUG(1,("Name query reply has wrong answer rr_type\n"));
	  }
	break;
      }
    case NAME_CONFIRM_QUERY:
      {
	DEBUG(4, ("Name query at WINS server: %s at %s - ",
		  namestr(&n->name),
		  inet_ntoa(n->to_ip)));
	if (nmb->header.rcode == 0 && nmb->answers->rdata)
	  {
	    int nb_flags = nmb->answers->rdata[0];
	    struct in_addr found_ip;
	    putip((char*)&found_ip,&nmb->answers->rdata[2]);
	    
	    DEBUG(4, (" OK: %s\n", inet_ntoa(found_ip)));
	    add_netbios_entry(nmb->answers->rr_name.name,
			      nmb->answers->rr_name.name_type,
			      nb_flags,GET_TTL(0),STATUS_QUERY,found_ip);
	  }
	else
	  {
	    DEBUG(4, (" NEGATIVE RESPONSE\n"));
	  }
	
	break;
      }
    default:
      {
	DEBUG(0,("unknown command received in response_netbios_packet\n"));
	break;
      }
    }
}


/****************************************************************************
  process a nmb packet
  ****************************************************************************/
void process_nmb(struct packet_struct *p)
{
	struct nmb_packet *nmb = &p->packet.nmb;

	debug_nmb_packet(p);

	switch (nmb->header.opcode) 
	{
		case 5:
		case 8:
		case 9:
		{
			if (nmb->header.qdcount==0 || nmb->header.arcount==0) break;
			if (nmb->header.response)
				response_name_reg(p);
			else
				reply_name_reg(p);
			break;
		}

		case 0:
		{
			if (nmb->header.response)
			{
				switch (nmb->question.question_type)
				{
					case 0x0:
					{
						response_netbios_packet(p);
						break;
					}
				}
				return;
			}
			else if (nmb->header.qdcount>0) 
			{
				switch (nmb->question.question_type)
				{
					case NMB_QUERY:
					{
						reply_name_query(p);
						break;
					}
					case NMB_STATUS:
					{
						reply_name_status(p);
						break;
					}
				}
				return;
			}
			break;
		}

		case 6:
		{
			if (nmb->header.qdcount==0 || nmb->header.arcount==0)
			{
				DEBUG(2,("netbios release packet rejected\n"));
				break;
			}

			if (nmb->header.response)
				response_name_release(p);
			else
				reply_name_release(p);
			break;
		}
	}

}

