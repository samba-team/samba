/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1996
   
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
   
   Module name: nameserv.c

   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

   04 jul 96: lkcl@pires.co.uk
   module nameserv contains name server management functions
*/

#include "includes.h"

extern int ClientNMB;

extern int DEBUGLEVEL;

extern pstring scope;
extern pstring myname;
extern struct in_addr ipzero;
extern struct in_addr ipgrp;

extern struct subnet_record *subnetlist;

extern uint16 nb_type; /* samba's NetBIOS type */

/****************************************************************************
  remove an entry from the name list

  note: the name will _always_ be removed
  XXXX at present, the name is removed _even_ if a WINS server says keep it.

  ****************************************************************************/
void remove_name_entry(struct subnet_record *d, char *name,int type)
{
  /* XXXX BUG: if samba is offering WINS support, it should still broadcast
      a de-registration packet to the local subnet before removing the
      name from its local-subnet name database. */

  struct name_record n;
  struct name_record *n2=NULL;
      
  make_nmb_name(&n.name,name,type,scope);

  if ((n2 = find_name_search(&d, &n.name, FIND_SELF, ipzero)))
  {
    /* check name isn't already being de-registered */
    if (NAME_DEREG(n2->ip_flgs[0].nb_flags))
      return;

    /* mark the name as in the process of deletion. */
    n2->ip_flgs[0].nb_flags &= NB_DEREG;
  }

  if (!n2) return;

  /* remove the name immediately. even if the spec says we should
     first try to release them, this is too dangerous with our current
     name structures as otherwise we will end up replying to names we
     don't really own */  
  remove_netbios_name(d,name,type,SELF,n2->ip_flgs[0].ip);

  if (ip_equal(d->bcast_ip, ipgrp)) {
    if (!lp_wins_support()) {
      /* not a WINS server: we have to release them on the network */
      queue_netbios_pkt_wins(d,ClientNMB,NMB_REL,NAME_RELEASE,
			     name, type, 0, 0,0,NULL,NULL,
			     False, True, ipzero, ipzero);
    }
  } else {
    /* local interface: release them on the network */
    queue_netbios_packet(d,ClientNMB,NMB_REL,NAME_RELEASE,
			 name, type, 0, 0,0,NULL,NULL,
			 True, True, d->bcast_ip, d->bcast_ip);
  }
}


/****************************************************************************
  add an entry to the name list
  
  big note: our name will _always_ be added (if there are no objections).
  it's just a matter of when this will be done (e.g after a time-out).

  ****************************************************************************/
void add_my_name_entry(struct subnet_record *d,char *name,int type,int nb_flags)
{
  BOOL re_reg = False;
  struct nmb_name n;

  if (!d) return;

  /* not that it particularly matters, but if the SELF name already exists,
     it must be re-registered, rather than just registered */

  make_nmb_name(&n, name, type, scope);
  if (find_name(d->namelist, &n, SELF))
	re_reg = True;

  /* XXXX BUG: if samba is offering WINS support, it should still add the
     name entry to a local-subnet name database. see rfc1001.txt 15.1.1 p28
     regarding the point about M-nodes. */

  if (ip_equal(d->bcast_ip, ipgrp))
  {
    if (lp_wins_support())
    {
      /* we are a WINS server. */
      /* XXXX assume that if we are a WINS server that we are therefore
         not pointing to another WINS server as well. this may later NOT
         actually be true
       */

      DEBUG(4,("samba as WINS server adding: "));
      /* this will call add_netbios_entry() */
      name_register_work(d, name, type, nb_flags,0, ipzero, False);
    }
    else
    {
      /* a time-to-live allows us to refresh this name with the WINS server. */
  	  queue_netbios_pkt_wins(d,ClientNMB,
				 re_reg ? NMB_REG_REFRESH : NMB_REG, NAME_REGISTER,
			     name, type, nb_flags, GET_TTL(0),0,NULL,NULL,
			     False, True, ipzero, ipzero);
    }
  }
  else
  {
    /* broadcast the packet, but it comes from ipzero */
  	queue_netbios_packet(d,ClientNMB,
				 re_reg ? NMB_REG_REFRESH : NMB_REG, NAME_REGISTER,
			     name, type, nb_flags, GET_TTL(0),0,NULL,NULL,
			     True, True, d->bcast_ip, ipzero);
  }
}


/****************************************************************************
  add the magic samba names, useful for finding samba servers
  **************************************************************************/
void add_my_names(void)
{
  struct subnet_record *d;
  /* each subnet entry, including WINS pseudo-subnet, has SELF names */

  /* XXXX if there was a transport layer added to samba (ipx/spx etc) then
     there would be yet _another_ for-loop, this time on the transport type
   */

  for (d = subnetlist; d; d = d->next)
  {
    BOOL wins = lp_wins_support() && ip_equal(d->bcast_ip,ipgrp);

    add_my_name_entry(d, myname,0x20,nb_type|NB_ACTIVE);
    add_my_name_entry(d, myname,0x03,nb_type|NB_ACTIVE);
    add_my_name_entry(d, myname,0x00,nb_type|NB_ACTIVE);
    add_my_name_entry(d, myname,0x1f,nb_type|NB_ACTIVE);
    
    /* these names are added permanently (ttl of zero) and will NOT be
       refreshed with the WINS server  */
    add_netbios_entry(d,"*",0x0,nb_type|NB_ACTIVE,0,SELF,d->myip,False,wins);
    add_netbios_entry(d,"*",0x20,nb_type|NB_ACTIVE,0,SELF,d->myip,False,wins);
    add_netbios_entry(d,"__SAMBA__",0x20,nb_type|NB_ACTIVE,0,SELF,d->myip,False,wins);
    add_netbios_entry(d,"__SAMBA__",0x00,nb_type|NB_ACTIVE,0,SELF,d->myip,False,wins);
    
    if (lp_domain_logons()) {
      /* XXXX the 0x1c is apparently something to do with domain logons */
      add_my_name_entry(d, lp_workgroup(),0x1c,nb_type|NB_ACTIVE|NB_GROUP);
    }
  }
  if (lp_domain_master() && (d = find_subnet(ipgrp)))
  {
    struct work_record *work = find_workgroupstruct(d, lp_workgroup(), True);
    if (work && work->state == MST_NONE)
    {
      work->state = MST_DOMAIN_NONE;
      become_master(d, work);
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
      if (n->source == SELF && n->refresh_time < time(NULL) && 
          n->death_time != 0)
      {
        add_my_name_entry(d,n->name.name,n->name.name_type,
                          n->ip_flgs[0].nb_flags);
	/* they get a new lease on life :-) */
	n->death_time += GET_TTL(0);
	n->refresh_time += GET_TTL(0);
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

    if (!lasttime) lasttime = t;
	if (t - lasttime < NAME_POLL_INTERVAL) return;

    lasttime = time(NULL);

	for (n = d->namelist; n; n = n->next)
	{
		/* only do unique, registered names */

		if (n->source != REGISTER) continue;
		if (!NAME_GROUP(n->ip_flgs[0].nb_flags)) continue;

		if (n->refresh_time < t)
		{
		  DEBUG(3,("Polling name %s\n", namestr(&n->name)));
		  
    	  queue_netbios_packet(d,ClientNMB,NMB_QUERY,NAME_QUERY_CONFIRM,
				n->name.name, n->name.name_type,
				0,0,0,NULL,NULL,
				False,False,n->ip_flgs[0].ip,n->ip_flgs[0].ip);
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

