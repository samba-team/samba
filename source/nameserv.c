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

extern int ClientNMB;
extern int ClientDGRAM;

#define FIND_SELF  0x01
#define FIND_WINS  0x02
#define FIND_LOCAL 0x04

extern int DEBUGLEVEL;

extern pstring scope;
extern BOOL CanRecurse;
extern pstring myname;
extern struct in_addr ipzero;
extern struct in_addr ipgrp;

extern struct subnet_record *subnetlist;

#define WINS_LIST "wins.dat"

#define GET_TTL(ttl) ((ttl)?MIN(ttl,lp_max_ttl()):lp_max_ttl())

/****************************************************************************
  finds the appropriate subnet structure. directed packets (non-bcast) are
  assumed to come from a point-to-point (P or M node), and so the subnet we
  return in this instance is the WINS 'pseudo-subnet' with ip 255.255.255.255
  ****************************************************************************/
static struct subnet_record *find_req_subnet(struct in_addr ip, BOOL bcast)
{
  if (bcast)
  {
    /* identify the subnet the broadcast request came from */
    return find_subnet(*iface_bcast(ip));
  }
  /* find the subnet under the pseudo-ip of 255.255.255.255 */
  return find_subnet(ipgrp);
}

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
static void add_name(struct subnet_record *d, struct name_record *n)
{
  struct name_record *n2;

  if (!d) return;

  if (!d->namelist)
  {
    d->namelist = n;
    n->prev = NULL;
    n->next = NULL;
    return;
  }

  for (n2 = d->namelist; n2->next; n2 = n2->next) ;

  n2->next = n;
  n->next = NULL;
  n->prev = n2;
}

/****************************************************************************
  remove a name from the namelist. The pointer must be an element just 
  retrieved
  **************************************************************************/
void remove_name(struct subnet_record *d, struct name_record *n)
{
  struct name_record *nlist;
  if (!d) return;

  nlist = d->namelist;

  while (nlist && nlist != n) nlist = nlist->next;

  if (nlist)
  {
    if (nlist->next) nlist->next->prev = nlist->prev;
    if (nlist->prev) nlist->prev->next = nlist->next;
    free(nlist);
  }
}


/****************************************************************************
  find a name in a namelist.
  **************************************************************************/
static struct name_record *find_name(struct name_record *n,
			struct nmb_name *name,
			int search, struct in_addr ip)
{
	struct name_record *ret;
  
	for (ret = n; ret; ret = ret->next)
	{
		if (name_equal(&ret->name,name))
		{
			/* self search: self names only */
			if ((search&FIND_SELF) == FIND_SELF && ret->source != SELF)
				continue;
	  
			/* zero ip is either samba's ip or a way of finding a
			   name without needing to know the ip address */
			if (zero_ip(ip) || ip_equal(ip, ret->ip))
			{
				return ret;
			}
		}
	}
    return NULL;
}


/****************************************************************************
  find a name in the domain database namelist 
  search can be any of:
  FIND_SELF - look exclusively for names the samba server has added for itself
  FIND_LOCAL - look for names in the local subnet record.
  FIND_WINS - look for names in the WINS record
  **************************************************************************/
static struct name_record *find_name_search(struct subnet_record **d,
			struct nmb_name *name,
			int search, struct in_addr ip)
{
	if (d == NULL) return NULL; /* bad error! */
	
    if ((search & FIND_LOCAL) == FIND_LOCAL)
	{
		if (*d != NULL)
        {
			return find_name((*d)->namelist, name, search, ip);
		}
        else
        {
			DEBUG(4,("local find_name_search with a NULL subnet pointer\n"));
            return NULL;
		}
	}

	if ((search & FIND_WINS) != FIND_WINS) return NULL;

	if (*d == NULL)
	{
		/* find WINS subnet record */
		*d = find_subnet(ipgrp);
    }

	if (*d == NULL) return NULL;

	return find_name((*d)->namelist, name, search, ip);
}


/****************************************************************************
  dump a copy of the name table
  **************************************************************************/
void dump_names(void)
{
  struct name_record *n;
  struct subnet_record *d;
  fstring fname, fnamenew;
  time_t t = time(NULL);
  
  FILE *f;
  
  strcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,WINS_LIST);
  strcpy(fnamenew,fname);
  strcat(fnamenew,".");
  
  f = fopen(fnamenew,"w");
  
  if (!f)
  {
    DEBUG(4,("Can't open %s - %s\n",fnamenew,strerror(errno)));
  }
  
  DEBUG(3,("Dump of local name table:\n"));
  
  for (d = subnetlist; d; d = d->next)
   for (n = d->namelist; n; n = n->next)
    {
      if (f && ip_equal(d->bcast_ip, ipgrp) && n->source == REGISTER)
      {
        fstring data;

      /* XXXX i have little imagination as to how to output nb_flags as
         anything other than as a hexadecimal number :-) */

        sprintf(data, "%s#%02x %s %ld %2x",
	       n->name.name,n->name.name_type, /* XXXX ignore the scope for now */
	       inet_ntoa(n->ip),
	       n->death_time,
	       n->nb_flags);
	    fprintf(f, "%s\n", data);
      }

	  DEBUG(3,("%15s ", inet_ntoa(d->bcast_ip)));
	  DEBUG(3,("%15s ", inet_ntoa(d->mask_ip)));
      DEBUG(3,("%s %15s TTL=%15d NBFLAGS=%2x\n",
	       namestr(&n->name),
	       inet_ntoa(n->ip),
           n->death_time?n->death_time-t:0,
	       n->nb_flags));
    }

  fclose(f);
  unlink(fname);
  chmod(fnamenew,0644);
  rename(fnamenew,fname);   

  DEBUG(3,("Wrote wins database %s\n",fname));
}

/****************************************************************************
load a netbios name database file
****************************************************************************/
void load_netbios_names(void)
{
  struct subnet_record *d = find_subnet(ipgrp);
  fstring fname;

  FILE *f;
  pstring line;

  if (!d) return;

  strcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,WINS_LIST);

  f = fopen(fname,"r");

  if (!f) {
    DEBUG(2,("Can't open wins database file %s\n",fname));
    return;
  }

  while (!feof(f))
    {
      pstring name_str, ip_str, ttd_str, nb_flags_str;

      pstring name;
      int type = 0;
      int nb_flags;
      time_t ttd;
	  struct in_addr ipaddr;

	  enum name_source source;

      char *ptr;
	  int count = 0;

      char *p;

      if (!fgets_slash(line,sizeof(pstring),f)) continue;

      if (*line == '#') continue;

	ptr = line;

	if (next_token(&ptr,name_str    ,NULL)) ++count;
	if (next_token(&ptr,ip_str      ,NULL)) ++count;
	if (next_token(&ptr,ttd_str     ,NULL)) ++count;
	if (next_token(&ptr,nb_flags_str,NULL)) ++count;

	if (count <= 0) continue;

	if (count != 4) {
	  DEBUG(0,("Ill formed wins line"));
	  DEBUG(0,("[%s]: name#type ip nb_flags abs_time\n",line));
	  continue;
	}

      /* netbios name. # divides the name from the type (hex): netbios#xx */
      strcpy(name,name_str);

      p = strchr(name,'#');

      if (p) {
	    *p = 0;
	    sscanf(p+1,"%x",&type);
      }

      /* decode the netbios flags (hex) and the time-to-die (seconds) */
	  sscanf(nb_flags_str,"%x",&nb_flags);
	  sscanf(ttd_str,"%ld",&ttd);

	  ipaddr = *interpret_addr2(ip_str);

      if (ip_equal(ipaddr,ipzero)) {
         source = SELF;
      }
      else
      {
         source = REGISTER;
      }

      DEBUG(4, ("add WINS line: %s#%02x %s %ld %2x\n",
	       name,type, inet_ntoa(ipaddr), ttd, nb_flags));

      /* add all entries that have 60 seconds or more to live */
      if (ttd - 10 < time(NULL) || ttd == 0)
      {
        time_t t = (ttd?ttd-time(NULL):0) / 3;

        /* add netbios entry read from the wins.dat file. IF it's ok */
        add_netbios_entry(d,name,type,nb_flags,t,source,ipaddr,True,True);
      }
    }

  fclose(f);
}


/****************************************************************************
  remove an entry from the name list
  ****************************************************************************/
void remove_netbios_name(struct subnet_record *d,
			char *name,int type, enum name_source source,
			 struct in_addr ip)
{
  struct nmb_name nn;
  struct name_record *n;
  int search = FIND_LOCAL;

  /* if it's not a special browser name, search the WINS database */
  if (type != 0x01 && type != 0x1d && type != 0x1e)
    search |= FIND_WINS;

  make_nmb_name(&nn, name, type, scope);
  n = find_name_search(&d, &nn, search, ip);
  
  if (n && n->source == source) remove_name(d,n);
}


/****************************************************************************
  add an entry to the name list.

  this is a multi-purpose function.

  it adds samba's own names in to its records on each interface, keeping a
  record of whether it is a master browser, domain master, or WINS server.

  it also keeps a record of WINS entries (names of type 0x00, 0x20, 0x03 etc)

  ****************************************************************************/
struct name_record *add_netbios_entry(struct subnet_record *d,
		char *name, int type, int nb_flags, 
		int ttl, enum name_source source, struct in_addr ip,
		BOOL new_only,BOOL wins)
{
  struct name_record *n;
  struct name_record *n2=NULL;
  int search = 0;
  BOOL self = source == SELF;

  /* add the name to the WINS list if the name comes from a directed query */
  search |= wins ? FIND_WINS : FIND_LOCAL;
  /* search for SELF names only */
  search |= self ? FIND_SELF : 0;

  if (!self)
  {
    if (wins)
    {
	  if (type == 0x01 || type == 0x1d || type == 0x1e)
      {
         /* XXXX WINS server supposed to ignore special browser names. hm.
            but is a primary domain controller supposed to ignore special
            browser names? luke doesn't think so, but can't test it! :-)
          */
         return NULL;
      }
    }
    else /* !wins */
    {
       /* the only broadcast (non-WINS) names we are adding are ours (SELF) */
       return NULL;
    }
  }

  n = (struct name_record *)malloc(sizeof(*n));
  if (!n) return(NULL);

  bzero((char *)n,sizeof(*n));

  make_nmb_name(&n->name,name,type,scope);

  if ((n2 = find_name_search(&d, &n->name, search, new_only?ipzero:ip)))
  {
    free(n);
    if (new_only || (n2->source==SELF && source!=SELF)) return n2;
    n = n2;
  }

  if (ttl)
     n->death_time = time(NULL)+ttl*3;
  n->refresh_time = time(NULL)+GET_TTL(ttl);

  n->ip = ip;
  n->nb_flags = nb_flags;
  n->source = source;
  
  if (!n2) add_name(d,n);

  DEBUG(3,("Added netbios name %s at %s ttl=%d nb_flags=%2x\n",
	        namestr(&n->name),inet_ntoa(ip),ttl,nb_flags));

  return(n);
}


/****************************************************************************
  remove an entry from the name list
  ****************************************************************************/
void remove_name_entry(struct subnet_record *d, char *name,int type)
{
  /* XXXX BUG: if samba is offering WINS support, it should still broadcast
      a de-registration packet to the local subnet before removing the
      name from its local-subnet name database. */

  if (lp_wins_support())
    {
      /* we are a WINS server. */
      /* XXXX assume that if we are a WINS server that we are therefore
         not pointing to another WINS server as well. this may later NOT
         actually be true */
      remove_netbios_name(d,name,type,SELF,ipzero);
    }
  else
    {
      /* not a WINS server: cannot just remove our own names: we have to
         ask permission from the WINS server, or if no reply is received,
		 _then_ we can remove the name */

  	  struct name_record n;
  	  struct name_record *n2=NULL;
      
      make_nmb_name(&n.name,name,type,scope);

      if ((n2 = find_name_search(&d, &n.name, FIND_SELF, ipzero)))
      {
        /* check name isn't already being de-registered */
		if (NAME_DEREG(n2->nb_flags))
          return;

		/* mark the name as in the process of deletion. */
         n2->nb_flags &= NB_DEREG;
      }
      queue_netbios_pkt_wins(d,ClientNMB,NMB_REL,NAME_RELEASE,
			     name, type, 0, 0,
			     False, True, ipzero);
    }
}


/****************************************************************************
  add an entry to the name list
  ****************************************************************************/
void add_my_name_entry(struct subnet_record *d,char *name,int type,int nb_flags)
{
  BOOL re_reg = False;
  struct nmb_name n;

  if (!d) return;

  /* not that it particularly matters, but if the SELF name already exists,
     it must be re-registered, rather than just registered */

  make_nmb_name(&n, name, type, scope);
  if (find_name(d->namelist, &n, SELF, ipzero))
	re_reg = True;

  /* always add our own entries */
  add_netbios_entry(d,name,type,nb_flags,0,SELF,ipzero,False,lp_wins_support());

  /* XXXX BUG: if samba is offering WINS support, it should still add the
     name entry to a local-subnet name database. see rfc1001.txt 15.1.1 p28
     regarding the point about M-nodes. */

  if (!lp_wins_support())
  {
    /* samba isn't supporting WINS itself: register the name using broadcast
       or with another WINS server.
       XXXX note: we may support WINS and also know about other WINS servers
       in the future.
     */
      
    queue_netbios_pkt_wins(d,ClientNMB,
				 re_reg ? NMB_REG_REFRESH : NMB_REG, NAME_REGISTER,
			     name, type, nb_flags, GET_TTL(0),
			     False, True, ipzero);
  }
}


/****************************************************************************
  add the magic samba names, useful for finding samba servers
  **************************************************************************/
void add_my_names(void)
{
  BOOL wins = lp_wins_support();
  struct subnet_record *d;

  struct in_addr ip = ipzero;

  /* each subnet entry, including WINS pseudo-subnet, has SELF names */

  /* XXXX if there was a transport layer added to samba (ipx/spx etc) then
     there would be yet _another_ for-loop, this time on the transport type
   */

  for (d = subnetlist; d; d = d->next)
  {
	add_my_name_entry(d, myname,0x20,NB_ACTIVE);
	add_my_name_entry(d, myname,0x03,NB_ACTIVE);
	add_my_name_entry(d, myname,0x00,NB_ACTIVE);
	add_my_name_entry(d, myname,0x1f,NB_ACTIVE);

	add_netbios_entry(d,"*",0x0,NB_ACTIVE,0,SELF,ip,False,wins);
	add_netbios_entry(d,"__SAMBA__",0x20,NB_ACTIVE,0,SELF,ip,False,wins);
	add_netbios_entry(d,"__SAMBA__",0x00,NB_ACTIVE,0,SELF,ip,False,wins);

    if (wins) {
	/* the 0x1c name gets added by any WINS server it seems */
	  add_my_name_entry(d, my_workgroup(),0x1c,NB_ACTIVE|NB_GROUP);
    }
  }
}


/****************************************************************************
  remove all the samba names... from a WINS server if necessary.
  **************************************************************************/
void remove_my_names()
{
	struct subnet_record *d;

	for (d = subnetlist; d; d = d->next)
	{
		struct name_record *n, *next;

		for (n = d->namelist; n; n = next)
		{
			next = n->next;
			if (n->source == SELF)
			{
				/* get all SELF names removed from the WINS server's database */
				/* XXXX note: problem occurs if this removes the wrong one! */

				remove_name_entry(d,n->name.name, n->name.name_type);
			}
		}
	}
}


/*******************************************************************
  refresh my own names
  ******************************************************************/
void refresh_my_names(time_t t)
{
  struct subnet_record *d;

  for (d = subnetlist; d; d = d->next)
  {
    struct name_record *n;
	  
	for (n = d->namelist; n; n = n->next)
    {
      /* each SELF name has an individual time to be refreshed */
      if (n->source == SELF && n->refresh_time < time(NULL))
      {
        add_my_name_entry(d,n->name.name,n->name.name_type,n->nb_flags);
      }
    }
  }
}

/*******************************************************************
  queries names occasionally. an over-cautious, non-trusting WINS server!

  this function has been added because nmbd could be restarted. it
  is generally a good idea to check all the names that have been
  reloaded from file.

  XXXX which names to poll and which not can be refined at a later date.
  ******************************************************************/
void query_refresh_names(void)
{
	struct name_record *n;
	struct subnet_record *d = find_subnet(ipgrp);

	static time_t lasttime = 0;
	time_t t = time(NULL);

	int count = 0;
	int name_refresh_time = NAME_POLL_REFRESH_TIME;
	int max_count = name_refresh_time * 2 / NAME_POLL_INTERVAL;
	if (max_count > 10) max_count = 10;

	name_refresh_time = NAME_POLL_INTERVAL * max_count / 2;

	/* if (!lp_poll_wins()) return; polling of registered names allowed */

	if (!d) return;

	if (t - lasttime < NAME_POLL_INTERVAL) return;

	for (n = d->namelist; n; n = n->next)
	{
		/* only do unique, registered names */

		if (n->source != REGISTER) continue;
		if (!NAME_GROUP(n->nb_flags)) continue;

		if (n->refresh_time < t)
		{
		  DEBUG(3,("Polling name %s\n", namestr(&n->name)));
		  
    	  queue_netbios_packet(d,ClientNMB,NMB_QUERY,NAME_QUERY_CONFIRM,
				n->name.name, n->name.name_type,
				0,0,
				False,False,n->ip);
		  count++;
		}

		if (count >= max_count)
		{
			/* don't do too many of these at once, but do enough to
			   cover everyone in the list */
			return;
		}

		/* this name will be checked on again, if it's not removed */
		n->refresh_time += name_refresh_time;
	}
}


/*******************************************************************
  expires old names in the namelist
  ******************************************************************/
void expire_names(time_t t)
{
	struct name_record *n;
	struct name_record *next;
	struct subnet_record *d;

	/* expire old names */
	for (d = subnetlist; d; d = d->next)
	{
	  for (n = d->namelist; n; n = next)
		{
		  if (n->death_time && n->death_time < t)
		{
		  DEBUG(3,("Removing dead name %s\n", namestr(&n->name)));
		  
		  next = n->next;
		  
		  if (n->prev) n->prev->next = n->next;
		  if (n->next) n->next->prev = n->prev;
		  
		  if (d->namelist == n) d->namelist = n->next; 
		  
		  free(n);
		}
		  else
		{
		  next = n->next;
		}
		}
	}
}


/****************************************************************************
  response for a reg release received. samba has asked a WINS server if it
  could release a name.
  **************************************************************************/
void response_name_release(struct subnet_record *d, struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *name = nmb->question.question_name.name;
  int   type = nmb->question.question_name.name_type;
  
  DEBUG(4,("response name release received\n"));
  
  if (nmb->header.rcode == 0 && nmb->answers->rdata)
    {
      /* IMPORTANT: see expire_netbios_response_entries() */

      struct in_addr found_ip;
      putip((char*)&found_ip,&nmb->answers->rdata[2]);
      
      if (ismyip(found_ip))
      {
	    remove_netbios_name(d,name,type,SELF,found_ip);
	  }
    }
  else
    {
      DEBUG(2,("name release for %s rejected!\n",
	       namestr(&nmb->question.question_name)));

		/* XXXX do we honestly care if our name release was rejected? 
           only if samba is issuing the release on behalf of some out-of-sync
           server. if it's one of samba's SELF names, we don't care. */
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
  struct subnet_record *d = NULL;
  char rdata[6];
  int search = 0;
  
  putip((char *)&ip,&nmb->additional->rdata[2]);  
  
  DEBUG(3,("Name release on name %s rcode=%d\n",
	   namestr(&nmb->question.question_name),rcode));
  
  if (!(d = find_req_subnet(p->ip, bcast)))
  {
    DEBUG(3,("response packet: bcast %s not known\n",
			inet_ntoa(p->ip)));
    return;
  }

  if (bcast)
	search &= FIND_LOCAL;
  else
	search &= FIND_WINS;

  n = find_name_search(&d, &nmb->question.question_name, 
					search, ip);
  
  /* XXXX under what conditions should we reject the removal?? */
  if (n && n->nb_flags == nb_flags)
    {
      /* success = True;
	 rcode = 6; */
      
      remove_name(d,n);
      n = NULL;
    }
  
  if (bcast) return;
  
  rdata[0] = nb_flags;
  rdata[1] = 0;
  putip(&rdata[2],(char *)&ip);
  
  /* Send a NAME RELEASE RESPONSE */
  reply_netbios_packet(p,nmb->header.name_trn_id,
			   rcode,opcode,True,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       0,
		       rdata, 6);
}


/****************************************************************************
response for a reg request received
**************************************************************************/
void response_name_reg(struct subnet_record *d, struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *name = nmb->question.question_name.name;
  int   type = nmb->question.question_name.name_type;
  BOOL bcast = nmb->header.nm_flags.bcast;
  
  DEBUG(4,("response name registration received!\n"));
  
  if (nmb->header.rcode == 0 && nmb->answers->rdata)
    {
      /* IMPORTANT: see expire_netbios_response_entries() */

      int nb_flags = nmb->answers->rdata[0];
      struct in_addr found_ip;
      int ttl = nmb->answers->ttl;
      enum name_source source = REGISTER;
      
      putip((char*)&found_ip,&nmb->answers->rdata[2]);
      
      if (ismyip(found_ip)) source = SELF;
      
      add_netbios_entry(d, name,type,nb_flags,ttl,source,found_ip,True,!bcast);
    }
  else
    {
		struct work_record *work;

      DEBUG(1,("name registration for %s rejected!\n",
	       namestr(&nmb->question.question_name)));

	  /* XXXX oh dear. we have problems. must deal with our name having
         been rejected: e.g if it was our GROUP(1d) name, we must unbecome
         a master browser. */
	
        remove_netbios_name(d,name,type,SELF,ipzero);

		if (!(work = find_workgroupstruct(d, name, False))) return;

		if (AM_MASTER(work) && (type == 0x1d || type == 0x1b))
		{
			int remove_type = 0;
			if (type == 0x1d) remove_type = SV_TYPE_MASTER_BROWSER;
			if (type == 0x1b) remove_type = SV_TYPE_DOMAIN_MASTER;
			
			become_nonmaster(d, work, remove_type);
		}
    }
}


/****************************************************************************
reply to a reg request
**************************************************************************/
void reply_name_reg(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *question = &nmb->question.question_name;
  
  struct nmb_name *reply_name = question;
  char *qname = question->name;
  int name_type  = question->name_type;
  int name_class = nmb->question.question_class;
 
  BOOL bcast = nmb->header.nm_flags.bcast;
  
  int ttl = GET_TTL(nmb->additional->ttl);
  int nb_flags = nmb->additional->rdata[0];
  BOOL group = NAME_GROUP(nb_flags);
  int rcode = 0;  
  int opcode = nmb->header.opcode;  

  struct subnet_record *d = NULL;
  struct name_record *n = NULL;
  BOOL success = True;
  BOOL recurse = True; /* true if samba replies yes/no: false if caller */
  /* must challenge the current owner of the unique name */
  char rdata[6];
  struct in_addr ip, from_ip;
  int search = 0;
  
  putip((char *)&from_ip,&nmb->additional->rdata[2]);
  ip = from_ip;
  
  DEBUG(3,("Name registration for name %s at %s rcode=%d\n",
	   namestr(question),inet_ntoa(ip),rcode));
  
  if (group)
    {
      /* apparently we should return 255.255.255.255 for group queries
	 (email from MS) */
      ip = ipgrp;
    }
  
  if (!(d = find_req_subnet(p->ip, bcast)))
  {
    DEBUG(3,("response packet: bcast %s not known\n",
				inet_ntoa(p->ip)));
    return;
  }

  if (bcast)
	search &= FIND_LOCAL;
  else
	search &= FIND_WINS;

  /* see if the name already exists */
  n = find_name_search(&d, question, search, from_ip);
  
  if (n)
  {
    if (!group) /* unique names */
	{
	  if (n->source == SELF || NAME_GROUP(n->nb_flags))
	  {
	      /* no-one can register one of samba's names, nor can they
		 register a name that's a group name as a unique name */
	      
	      rcode = 6;
	      success = False;
	  }
	  else if(!ip_equal(ip, n->ip))
	  {
	      /* hm. this unique name doesn't belong to them. */
	      
	      /* XXXX rfc1001.txt says:
	       * if we are doing secured WINS, we must send a Wait-Acknowledge
	       * packet (WACK) to the person who wants the name, then do a
	       * name query on the person who currently owns the unique name.
	       * if the current owner still says they own it, the person who wants
		   * the name can't have it. if they do not, or are not alive, they can.
	       *
	       * if we are doing non-secured WINS (which is much simpler) then
	       * we send a message to the person wanting the name saying 'he
	       * owns this name: i don't want to hear from you ever again
	       * until you've checked with him if you can have it!'. we then
	       * abandon the registration. once the person wanting the name
	       * has checked with the current owner, they will repeat the
	       * registration packet if the current owner is dead or doesn't
	       * want the name.
	       */
	      
	      /* non-secured WINS implementation: caller is responsible
		 for checking with current owner of name, then getting back
		 to us... IF current owner no longer owns the unique name */
	      
           /* XXXX please note also that samba cannot cope with 
              _receiving_ such redirecting, non-secured registration
              packets. code to do this needs to be added.
            */

	      rcode = 0;
	      success = False;
	      recurse = False;
	      
	      /* we inform on the current owner to the caller (which is
		 why it's non-secure */
	      
	      reply_name = &n->name;
	      
	      /* name_type  = ?;
		 name_class = ?;
		 XXXX sorry, guys: i really can't see what name_type
		 and name_class should be set to according to rfc1001 */
	  }
	  else
	  {
	      n->ip = ip;
	      n->death_time = ttl?p->timestamp+ttl*3:0;
	      DEBUG(3,("%s owner: %s\n",namestr(&n->name),inet_ntoa(n->ip)));
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

    /* XXXX bug reported by terryt@ren.pc.athabascau.ca */
    /* names that people have checked for and not found get DNSFAILed. 
       we need to update the name record if someone then registers */

    if (n->source == DNSFAIL)
      n->source = REGISTER;

  }
  else
  {
      /* add the name to our name/subnet, or WINS, database */
      n = add_netbios_entry(d,qname,name_type,nb_flags,ttl,REGISTER,ip,
				True,!bcast);
  }
  
  /* if samba owns a unique name on a subnet, then it must respond and
     disallow the attempted registration. if the registration is
     successful by broadcast, only then is there no need to respond
     (implicit registration: see rfc1001.txt 15.2.1).
   */

  if (bcast || !success) return;
  
  rdata[0] = nb_flags;
  rdata[1] = 0;
  putip(&rdata[2],(char *)&ip);
  
  /* Send a NAME REGISTRATION RESPONSE (pos/neg)
     or an END-NODE CHALLENGE REGISTRATION RESPONSE */
  reply_netbios_packet(p,nmb->header.name_trn_id,
		       rcode,opcode,recurse,
		       reply_name, name_type, name_class,
		       ttl,
		       rdata, 6);
}


/****************************************************************************
reply to a name status query
****************************************************************************/
void reply_name_status(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *qname   = nmb->question.question_name.name;
  int ques_type = nmb->question.question_name.name_type;
  char rdata[MAX_DGRAM_SIZE];
  char *countptr, *buf, *bufend;
  int names_added;
  struct name_record *n;
  struct subnet_record *d = NULL;

  BOOL bcast = nmb->header.nm_flags.bcast;
  
  if (!(d = find_req_subnet(p->ip, bcast)))
  {
    DEBUG(3,("Name status req: bcast %s not known\n",
			inet_ntoa(p->ip)));
    return;
  }

  DEBUG(3,("Name status for name %s %s\n",
	   namestr(&nmb->question.question_name), inet_ntoa(p->ip)));
  
  n = find_name_search(&d, &nmb->question.question_name,
				FIND_SELF|FIND_LOCAL,
				p->ip);
  
  if (!n) return;
  
  /* XXXX hack, we should calculate exactly how many will fit */
  bufend = &rdata[MAX_DGRAM_SIZE] - 18;
  countptr = buf = rdata;
  buf += 1;
  
  names_added = 0;
  
  for (n = d->namelist ; n && buf < bufend; n = n->next) 
    {
      int name_type = n->name.name_type;
      
      if (n->source != SELF) continue;
      
      /* start with first bit of putting info in buffer: the name */
      
      bzero(buf,18);
	  sprintf(buf,"%-15.15s",n->name.name);
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
      
      names_added++;
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
  reply_netbios_packet(p,nmb->header.name_trn_id,
			   0,0,True,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       0,
		       rdata,PTR_DIFF(buf,rdata));
}


/***************************************************************************
  reply to a name query
  ****************************************************************************/
struct name_record *search_for_name(struct subnet_record **d,
					struct nmb_name *question,
				    struct in_addr ip, int Time, int search)
{
  int name_type = question->name_type;
  char *qname = question->name;
  BOOL dns_type = name_type == 0x20 || name_type == 0;
  
  struct name_record *n;
  
  DEBUG(3,("Search for %s from %s - ", namestr(question), inet_ntoa(ip)));
  
  /* first look up name in cache */
  n = find_name_search(d,question,search,ip);
  
  if (*d == NULL) return NULL;

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
	  DEBUG(3,("no recursion.\n"));
      /* add the fail to our WINS cache of names. give it 1 hour in the cache */
	  add_netbios_entry(*d,qname,name_type,NB_ACTIVE,60*60,DNSFAIL,dns_ip,
						True, True);
	  return NULL;
	}
      
      /* add it to our WINS cache of names. give it 2 hours in the cache */
      n = add_netbios_entry(*d,qname,name_type,NB_ACTIVE,2*60*60,DNS,dns_ip,
						True,True);
      
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

	- if you are the WINS server, you are expected to respond with either
      a negative response, a positive response, or a wait-for-acknowledgement
      packet, and then later on a pos/neg response.

****************************************************************************/
void reply_name_query(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *question = &nmb->question.question_name;
  int name_type = question->name_type;
  BOOL bcast = nmb->header.nm_flags.bcast;
  int ttl=0;
  int rcode = 0;
  int nb_flags = 0;
  struct in_addr retip;
  char rdata[6];
  struct subnet_record *d = NULL;

  BOOL success = True;
  
  struct name_record *n;
  int search = 0;

  if (name_type == 0x20 || name_type == 0x00 || name_type == 0x1b ||
      name_type == 0x1f || name_type == 0x03 || name_type == 0x01 ||
      name_type == 0x1c)
  {
    /* search for any of the non-'special browser' names, or for a PDC type
       (0x1b) name in the WINS database.
       XXXX should we include name type 0x1c: WINS server type?
     */
	search |= FIND_WINS;
  }
  else
  {
	/* special browser name types e.g 
       ^1^2__MSBROWSE__^2^1, GROUP(1d) and GROUP(1e)

       name_type == 0x01 || name_type == 0x1d || name_type == 0x1e.

       XXXX luke reckons we should be able to search for any SELF name
       in the WINS database, if we are a primary domain controller.
     */

    if (!(d = find_req_subnet(p->ip, bcast)))
    {
      DEBUG(3,("name query: bcast %s not known\n",
				  inet_ntoa(p->ip)));
      success = False;
    }

    /* XXXX delete if shouldn't search for SELF names in WINS database */
    search |= FIND_WINS;
  }

  if (bcast)
  {
    /* a name query has been made by a non-WINS configured host. search the
       local interface database as well */
    search |= FIND_LOCAL;
  }

  DEBUG(3,("Name query "));
  
  if (search == 0)
  {
    /* eh? no criterion for searching database. help! */
    success = False;
  }

  if (success && (n = search_for_name(&d,question,p->ip,p->timestamp, search)))
  {
      /* don't respond to broadcast queries unless the query is for
         a name we own or it is for a Primary Domain Controller name */

      if (bcast && n->source != SELF && name_type != 0x1b) {
	    if (!lp_wins_proxy() || same_net(p->ip,n->ip,*iface_nmask(p->ip))) {
	      /* never reply with a negative response to broadcast queries */
	      return;
	    }
	  }
      
      /* name is directed query, or it's self, or it's a PDC type name, or
	     we're replying on behalf of a caller because they are on a different
         subnet and cannot hear the broadcast. XXXX lp_wins_proxy should be
		 switched off in environments where broadcasts are forwarded */

      /* XXXX note: for proxy servers, we should forward the query on to
         another WINS server if the name is not in our database, or we are
         not a WINS server ourselves
       */
      ttl = n->death_time - p->timestamp;
      retip = n->ip;
      nb_flags = n->nb_flags;
  }
  else
  {
      if (bcast) return; /* never reply negative response to bcasts */
      success = False;
  }
  
  /* if the IP is 0 then substitute my IP */
  if (zero_ip(retip)) retip = *iface_ip(p->ip);

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
  
  reply_netbios_packet(p,nmb->header.name_trn_id,
			   rcode,0,True,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       ttl,
		       rdata, success ? 6 : 0);
}


/****************************************************************************
  response from a name query server check. commands of type NAME_QUERY_MST_SRV_CHK,
  NAME_QUERY_SRV_CHK, and NAME_QUERY_FIND_MST dealt with here.
  ****************************************************************************/
static void response_server_check(struct nmb_name *ans_name, 
		struct response_record *n, struct subnet_record *d)
{
    /* issue another command: this time to do a name status check */

    enum cmd_type cmd = (n->cmd_type == NAME_QUERY_MST_SRV_CHK) ?
	      NAME_STATUS_MASTER_CHECK : NAME_STATUS_CHECK;

    /* initiate a name status check on the server that replied */
    queue_netbios_packet(d,ClientNMB,NMB_STATUS, cmd,
				ans_name->name, ans_name->name_type,
				0,0,
				False,False,n->to_ip);
}

/****************************************************************************
  response from a name status check. commands of type NAME_STATUS_MASTER_CHECK
  and NAME_STATUS_CHECK dealt with here.
  ****************************************************************************/
static void response_name_status_check(struct in_addr ip,
		struct nmb_packet *nmb, BOOL bcast,
		struct response_record *n, struct subnet_record *d)
{
	/* NMB_STATUS arrives: contains workgroup name and server name required.
       amongst other things. */

	struct nmb_name name;
	fstring serv_name;

	if (interpret_node_status(d,nmb->answers->rdata,
	                          &name,0x1d,serv_name,ip,bcast))
	{
		if (*serv_name)
		{
			sync_server(n->cmd_type,serv_name,
			            name.name,name.name_type, n->to_ip);
		}
	}
	else
	{
		DEBUG(1,("No 0x1d name type in interpret_node_status()\n"));
	}
}


/****************************************************************************
  response from a name query to sync browse lists or to update our netbios
  entry. commands of type NAME_QUERY_SYNC and NAME_QUERY_CONFIRM 
  ****************************************************************************/
static void response_name_query_sync(struct nmb_packet *nmb, 
		struct nmb_name *ans_name, BOOL bcast,
		struct response_record *n, struct subnet_record *d)
{
	DEBUG(4, ("Name query at %s ip %s - ",
		  namestr(&n->name), inet_ntoa(n->to_ip)));

	if (!name_equal(n->name, ans_name))
	{
		/* someone gave us the wrong name as a reply. oops. */
		DEBUG(4,("unexpected name received: %s\n", namestr(ans_name)));
		return;
	}

	if (nmb->header.rcode == 0 && nmb->answers->rdata)
    {
		int nb_flags = nmb->answers->rdata[0];
		struct in_addr found_ip;

		putip((char*)&found_ip,&nmb->answers->rdata[2]);

		if (!ip_equal(n->ip, found_ip))
		{
			/* someone gave us the wrong ip as a reply. oops. */
			DEBUG(4,("expected ip: %s\n", inet_ntoa(n->ip)));
			DEBUG(4,("unexpected ip: %s\n", inet_ntoa(found_ip)));
			return;
		}

		DEBUG(4, (" OK: %s\n", inet_ntoa(found_ip)));

		if (n->cmd_type == NAME_QUERY_SYNC)
		{
			struct work_record *work = NULL;
			if ((work = find_workgroupstruct(d, ans_name->name, False)))
			{
				/* the server is there: sync quick before it (possibly) dies! */
				sync_browse_lists(d, work, ans_name->name, ans_name->name_type,
							found_ip);
			}
		}
		else
		{
			/* update our netbios name list (re-register it if necessary) */
			add_netbios_entry(d, ans_name->name, ans_name->name_type,
								nb_flags,GET_TTL(0),REGISTER,
								found_ip,False,!bcast);
		}
	}
	else
	{
		DEBUG(4, (" NEGATIVE RESPONSE!\n"));

		if (n->cmd_type == NAME_QUERY_CONFIRM)
		{
			/* XXXX remove_netbios_entry()? */
			/* lots of things we ought to do, here. if we get here,
			   then we're in a mess: our name database doesn't match
			   reality. sort it out
             */
      		remove_netbios_name(d,n->name.name, n->name.name_type,
								REGISTER,n->ip);
		}
	}
}

/****************************************************************************
  report the response record type
  ****************************************************************************/
static void debug_rr_type(int rr_type)
{
  switch (rr_type)
  {
      case NMB_STATUS: DEBUG(3,("Name status ")); break;
	  case NMB_QUERY : DEBUG(3,("Name query ")); break;
	  case NMB_REG   : DEBUG(3,("Name registration ")); break;
	  case NMB_REL   : DEBUG(3,("Name release ")); break;
      default        : DEBUG(1,("wrong response packet type received")); break;
  }
}

/****************************************************************************
  report the response record nmbd command type
  ****************************************************************************/
static void debug_cmd_type(int cmd_type)
{
  /* report the command type to help debugging */
  switch (cmd_type)
  {
    case NAME_QUERY_MST_SRV_CHK  : DEBUG(4,("MASTER_SVR_CHECK\n")); break;
    case NAME_QUERY_SRV_CHK      : DEBUG(4,("NAME_QUERY_SRV_CHK\n")); break;
    case NAME_QUERY_FIND_MST     : DEBUG(4,("NAME_QUERY_FIND_MST\n")); break;
    case NAME_STATUS_MASTER_CHECK: DEBUG(4,("NAME_STAT_MST_CHK\n")); break;
    case NAME_STATUS_CHECK       : DEBUG(4,("NAME_STATUS_CHECK\n")); break;
    case NAME_QUERY_MST_CHK      : DEBUG(4,("NAME_QUERY_MST_CHK\n")); break;
    case NAME_REGISTER           : DEBUG(4,("NAME_REGISTER\n")); break;
    case NAME_RELEASE            : DEBUG(4,("NAME_RELEASE\n")); break;
    case NAME_QUERY_CONFIRM      : DEBUG(4,("NAME_QUERY_CONFIRM\n")); break;
    case NAME_QUERY_SYNC         : DEBUG(4,("NAME_QUERY_SYNC\n")); break;
    default: break;
  }
}

/****************************************************************************
  report any problems with the fact that a response has been received.

  (responses for certain types of operations are only expected from one host)
  ****************************************************************************/
static BOOL response_problem_check(struct response_record *n,
			struct nmb_packet *nmb, char *qname)
{
  switch (nmb->answers->rr_type)
  {
    case NMB_REL:
    {
        if (n->num_msgs > 1)
        {
            DEBUG(1,("more than one release name response received!\n"));
            return True;
        }
        break;
    }

    case NMB_REG:
    {
        if (n->num_msgs > 1)
        {
            DEBUG(1,("more than one register name response received!\n"));
            return True;
        }
        break;
    }

    case NMB_QUERY:
    { 
      if (n->num_msgs > 1)
      {
		  if (nmb->header.rcode == 0 && nmb->answers->rdata)
		  {
			int nb_flags = nmb->answers->rdata[0];

			if ((!NAME_GROUP(nb_flags)))
			{
			   /* oh dear. more than one person responded to a unique name.
				  there is either a network problem, a configuration problem
				  or a server is mis-behaving */

			   /* XXXX mark the name as in conflict, and then let the
				  person who just responded know that they must also mark it
				  as in conflict, and therefore must NOT use it.
                  see rfc1001.txt 15.1.3.5 */
					
               /* this may cause problems for some early versions of nmbd */

               switch (n->cmd_type)
               {
    			case NAME_QUERY_MST_SRV_CHK:
                case NAME_QUERY_SRV_CHK:
                case NAME_QUERY_MST_CHK:
                /* don't do case NAME_QUERY_FIND_MST: MSBROWSE isn't a unique name. */
                {
	              if (!strequal(qname,n->name.name))
	              {
		             /* one subnet, one master browser per workgroup */
		             /* XXXX force an election? */

		             DEBUG(3,("more than one master browser replied!\n"));
			         return True;
	      		  }
                   break;
                }
                default: break;
               }
               DEBUG(3,("Unique Name conflict detected!\n"));
			   return True;
			}
		  }
		  else
		  {
             /* we have received a negative reply, having already received
                at least one response (pos/neg). something's really wrong! */

	         DEBUG(3,("wierd name query problem detected!\n"));
		     return True;
		  }
       }
    }
  }
  return False;
}

/****************************************************************************
  check that the response received is compatible with the response record
  ****************************************************************************/
static BOOL response_compatible(struct response_record *n,
			struct nmb_packet *nmb)
{
  switch (n->cmd_type)
  {
    case NAME_RELEASE:
    {
  		if (nmb->answers->rr_type != NMB_REL)
		{
			DEBUG(1,("Name release reply has wrong answer rr_type\n"));
			return False;
		}
        break;
    }

    case NAME_REGISTER:
    {
  		if (nmb->answers->rr_type != NMB_REG)
		{
			DEBUG(1,("Name register reply has wrong answer rr_type\n"));
			return False;
		}
        break;
    }

    case NAME_QUERY_CONFIRM:
    case NAME_QUERY_SYNC:
    case NAME_QUERY_MST_SRV_CHK:
    case NAME_QUERY_SRV_CHK:
    case NAME_QUERY_FIND_MST:
    case NAME_QUERY_MST_CHK:
    {
		if (nmb->answers->rr_type != NMB_QUERY)
		{
			DEBUG(1,("Name query reply has wrong answer rr_type\n"));
			return False;
		}
		break;
    }
      
    case NAME_STATUS_MASTER_CHECK:
    case NAME_STATUS_CHECK:
    {
		if (nmb->answers->rr_type != NMB_STATUS)
		{
			DEBUG(1,("Name status reply has wrong answer rr_type\n"));
			return False;
		}
		break;
    }
      
    default:
    {
		DEBUG(0,("unknown command received in response_netbios_packet\n"));
		break;
    }
  }
  return True;
}


/****************************************************************************
  process the response packet received
  ****************************************************************************/
static void response_process(struct subnet_record *d, struct packet_struct *p,
				struct response_record *n, struct nmb_packet *nmb,
				BOOL bcast, struct nmb_name *ans_name)
{
  switch (n->cmd_type)
  {
    case NAME_RELEASE:
    {
        response_name_release(d, p);
        break;
    }

    case NAME_REGISTER:
    {
       	response_name_reg(d, p);
        break;
    }

    case NAME_QUERY_MST_SRV_CHK:
    case NAME_QUERY_SRV_CHK:
    case NAME_QUERY_FIND_MST:
    {
		response_server_check(ans_name, n, d);
		break;
    }
      
    case NAME_STATUS_MASTER_CHECK:
    case NAME_STATUS_CHECK:
    {
		response_name_status_check(p->ip, nmb, bcast, n, d);
		break;
    }
      
    case NAME_QUERY_CONFIRM:
    case NAME_QUERY_SYNC:
    {
		response_name_query_sync(nmb, ans_name, bcast, n, d);
		break;
    }
    case NAME_QUERY_MST_CHK:
    {
		/* no action required here. it's when NO responses are received
		   that we need to do something. see expire_name_query_entries() */
	
		DEBUG(4, ("Master browser exists for %s at %s (just checking!)\n",
					namestr(&n->name), inet_ntoa(n->to_ip)));
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
  response from a netbios packet.
  ****************************************************************************/
static void response_netbios_packet(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *question = &nmb->question.question_name;
  struct nmb_name *ans_name = NULL;
  char *qname = question->name;
  BOOL bcast = nmb->header.nm_flags.bcast;
  struct response_record *n;
  struct subnet_record *d = NULL;

  if (!(n = find_response_record(&d,nmb->header.name_trn_id))) {
    DEBUG(2,("unknown netbios response (received late or from nmblookup?)\n"));
    return;
  }

  if (!d)
  {
    DEBUG(2,("response packet: subnet %s not known\n", inet_ntoa(p->ip)));
    return;
  }

  if (!same_net(d->bcast_ip, d->mask_ip, p->ip)) /* copes with WINS 'subnet' */
  {
    DEBUG(2,("response from %s. ", inet_ntoa(p->ip)));
    DEBUG(2,("expected on subnet %s. hmm.\n", inet_ntoa(d->bcast_ip)));
    return;
  }

  if (nmb->answers == NULL)
  {
      /* hm. the packet received was a response, but with no answer. wierd! */
      DEBUG(2,("NMB packet response from %s (bcast=%s) - UNKNOWN\n",
	       inet_ntoa(p->ip), BOOLSTR(bcast)));
      return;
  }

  ans_name = &nmb->answers->rr_name;
  DEBUG(3,("response for %s from %s (bcast=%s)\n",
	   namestr(ans_name), inet_ntoa(p->ip), BOOLSTR(bcast)));
  
  debug_rr_type(nmb->answers->rr_type);

  n->num_msgs++; /* count number of responses received */
  n->repeat_count = 0; /* don't resend: see expire_netbios_packets() */

  debug_cmd_type(n->cmd_type);

  /* problem checking: multiple responses etc */
  if (response_problem_check(n, nmb, qname))
    return;

  /* now check whether the command has received the correct type of response*/
  if (!response_compatible(n, nmb))
    return;

  /* now deal with the command */
  response_process(d, p, n, nmb, bcast, ans_name);
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
    case 8: /* what is this?? */
    case NMB_REG:
    case NMB_REG_REFRESH:
    {
	if (nmb->header.qdcount==0 || nmb->header.arcount==0) break;
	if (nmb->header.response)
	  response_netbios_packet(p); /* response to registration dealt with here */
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
      
    case NMB_REL:
    {
      if (nmb->header.qdcount==0 || nmb->header.arcount==0)
	  {
	    DEBUG(2,("netbios release packet rejected\n"));
	    break;
	  }
	
	if (nmb->header.response)
	  response_netbios_packet(p); /* response to reply dealt with in here */
	else
	  reply_name_release(p);
      break;
    }
  }
}

