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

#define TEST_CODE

extern int DEBUGLEVEL;
extern BOOL CanRecurse;

extern struct in_addr ipzero;

extern pstring myname;

extern int ClientDGRAM;
extern int ClientNMB;

/* this is our domain/workgroup/server database */
extern struct subnet_record *subnetlist;

extern int  updatecount;
extern int  workgroup_count;

extern struct in_addr ipgrp;



/****************************************************************************
  send a announce request to the local net
  **************************************************************************/
void announce_request(struct work_record *work, struct in_addr ip)
{
  pstring outbuf;
  char *p;

  if (!work) return;

  work->needannounce = True;

  DEBUG(2,("sending announce request to %s for workgroup %s\n",
	   inet_ntoa(ip),work->work_group));

  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = ANN_AnnouncementRequest;
  p++;

  CVAL(p,0) = work->token; /* (local) unique workgroup token id */
  p++;
  StrnCpy(p,myname,16);
  strupper(p);
  p = skip_string(p,1);
  
  /* XXXX note: if we sent the announcement request to 0x1d instead
     of 0x1e, then we could get the master browser to announce to
     us instead of the members of the workgroup. wha-hey! */

  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,work->work_group,0x20,0x1e,ip,*iface_ip(ip));
}


/****************************************************************************
  request an announcement
  **************************************************************************/
void do_announce_request(char *info, char *to_name, int announce_type, 
			 int from,
			 int to, struct in_addr dest_ip)
{
  pstring outbuf;
  char *p;
  
  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = announce_type; 
  p++;
  
  DEBUG(2,("sending announce type %d: info %s to %s - server %s(%x)\n",
	   announce_type, info, inet_ntoa(dest_ip),to_name,to));
  
  StrnCpy(p,info,16);
  strupper(p);
  p = skip_string(p,1);
  
  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,to_name,from,to,dest_ip,*iface_ip(dest_ip));
}


/****************************************************************************
  find a server responsible for a workgroup, and sync browse lists
  control ends up back here via response_name_query.
  **************************************************************************/
void sync_server(enum state_type state, char *serv_name, char *work_name, 
		 int name_type,
		 struct in_addr ip)
{                     
  /* with a domain master we can get the whole list (not local only list) */
  BOOL local_only = (state != NAME_STATUS_DOM_SRV_CHK);

  add_browser_entry(serv_name, name_type, work_name, 0, ip, local_only);

  if (state == NAME_STATUS_DOM_SRV_CHK)
  {
    /* announce ourselves as a master browser to serv_name */
    do_announce_request(myname, serv_name, ANN_MasterAnnouncement,
			  0x20, 0, ip);
  }
}


/****************************************************************************
  send a host announcement packet
  **************************************************************************/
void do_announce_host(int command,
		char *from_name, int from_type, struct in_addr from_ip,
		char *to_name  , int to_type  , struct in_addr to_ip,
		time_t announce_interval,
		char *server_name, int server_type, char *server_comment)
{
	pstring outbuf;
	char *p;

	bzero(outbuf,sizeof(outbuf));
	p = outbuf+1;

	/* command type */
	CVAL(outbuf,0) = command;

	/* announcement parameters */
	CVAL(p,0) = updatecount;
	SIVAL(p,1,announce_interval*1000); /* ms - despite the spec */

	StrnCpy(p+5,server_name,16);
	strupper(p+5);

	CVAL(p,21) = 0x02; /* major version */
	CVAL(p,22) = 0x02; /* minor version */

	SIVAL(p,23,server_type);
	SSVAL(p,27,0x010f); /* browse version: got from NT/AS 4.00 */
	SSVAL(p,29,0xaa55); /* browse signature */

	strcpy(p+31,server_comment);
	p += 31;
	p = skip_string(p,1);

    debug_browse_data(outbuf, PTR_DIFF(p,outbuf));

	/* send the announcement */
	send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,
					  PTR_DIFF(p,outbuf),
					  from_name, to_name,
					  from_type, to_type,
					  to_ip, from_ip);
}


/****************************************************************************
  remove all samba's server entries
  ****************************************************************************/
void remove_my_servers(void)
{
	struct subnet_record *d; 
	for (d = subnetlist; d; d = d->next)
	{
		struct work_record *work;
		for (work = d->workgrouplist; work; work = work->next)
		{
			struct server_record *s;
			for (s = work->serverlist; s; s = s->next)
			{
				if (!strequal(myname,s->serv.name)) continue;
				announce_server(d, work, s->serv.name, s->serv.comment, 0, 0);
			}
		}
	}
}


/****************************************************************************
  announce a server entry
  ****************************************************************************/
void announce_server(struct subnet_record *d, struct work_record *work,
		     char *name, char *comment, time_t ttl, int server_type)
{
	uint32 domain_type = SV_TYPE_DOMAIN_ENUM|DFLT_SERVER_TYPE;
	BOOL wins_iface = ip_equal(d->bcast_ip, ipgrp);
	
	if (wins_iface && server_type != 0)
	{
		/* wins pseudo-ip interface */
		if (!AM_MASTER(work))
		{
			/* non-master announce by unicast to the domain 
			   master */
			if (!lp_wins_support() && *lp_wins_server())
			{
				/* look up the domain master with the WINS server */
				queue_netbios_pkt_wins(d,ClientNMB,NMB_QUERY,
					 NAME_QUERY_ANNOUNCE_HOST,
					 work->work_group,0x1b,0,ttl*1000,
					 server_type,name,comment,
					 False, False, ipzero, d->bcast_ip);
			}
			else
			{
				/* we are the WINS server, but not the domain master.  */
				/* XXXX we need to look up the domain master in our
				   WINS database list, and do_announce_host(). maybe
				   we could do a name query on the unsuspecting domain
				   master just to make sure it's awake. */
			}
		}

		/* XXXX any other kinds of announcements we need to consider here?
		   e.g local master browsers... no. local master browsers do
		   local master announcements to their domain master. they even
		   use WINS lookup of the domain master if another wins server
		   is being used! 
		 */
	}
	else
	{
		if (AM_MASTER(work))
		{
			DEBUG(3,("sending local master announce to %s for %s(1e)\n",
							inet_ntoa(d->bcast_ip),work->work_group));

			do_announce_host(ANN_LocalMasterAnnouncement,
							name            , 0x00, d->myip,
							work->work_group, 0x1e, d->bcast_ip,
							ttl*1000,
							name, server_type, comment);

			DEBUG(3,("sending domain announce to %s for %s\n",
							inet_ntoa(d->bcast_ip),work->work_group));

			/* XXXX should we do a domain-announce-kill? */
			if (server_type != 0)
			{
				do_announce_host(ANN_DomainAnnouncement,
							name    , 0x00, d->myip,
							MSBROWSE, 0x01, d->bcast_ip,
							ttl*1000,
							work->work_group, server_type ? domain_type : 0,
							name);
			}
		}
		else
		{
			DEBUG(3,("sending host announce to %s for %s(1d)\n",
							inet_ntoa(d->bcast_ip),work->work_group));

			do_announce_host(ANN_HostAnnouncement,
							name            , 0x00, d->myip,
							work->work_group, 0x1d, d->bcast_ip,
							ttl*1000,
							name, server_type, comment);
		}
	}
}

/****************************************************************************
  construct a host announcement unicast
  **************************************************************************/
void announce_host(void)
{
  time_t t = time(NULL);
  struct subnet_record *d;
  pstring comment;
  char *my_name;

  StrnCpy(comment, lp_serverstring(), 43);

  my_name = *myname ? myname : "NoName";

  for (d = subnetlist; d; d = d->next)
    {
      struct work_record *work;
      
      if (ip_equal(d->bcast_ip, ipgrp)) continue;

      for (work = d->workgrouplist; work; work = work->next)
	{
	  uint32 stype = work->ServerType;
	  struct server_record *s;
	  BOOL announce = False;
	  
      /* must work on the code that does announcements at up to
         30 seconds later if a master browser sends us a request
         announce.
       */

	  if (work->needannounce) {
	    /* drop back to a max 3 minute announce - this is to prevent a
	       single lost packet from stuffing things up for too long */
	    work->announce_interval = MIN(work->announce_interval,
						CHECK_TIME_MIN_HOST_ANNCE*60);
	    work->lastannounce_time = t - (work->announce_interval+1);
	  }
	  
	  /* announce every minute at first then progress to every 12 mins */
	  if (work->lastannounce_time && 
	      (t - work->lastannounce_time) < work->announce_interval)
	    continue;
	  
	  if (work->announce_interval < CHECK_TIME_MAX_HOST_ANNCE * 60) 
	    work->announce_interval += 60;
	  
	  work->lastannounce_time = t;

	  for (s = work->serverlist; s; s = s->next) {
	    if (strequal(myname, s->serv.name)) { 
	      announce = True; 
	      break; 
	    }
	  }
	  
	  if (announce) {
	    announce_server(d,work,my_name,comment,
			    work->announce_interval,stype);
	  }
	  
	  if (work->needannounce)
	  {
	      work->needannounce = False;
	      break;
	      /* sorry: can't do too many announces. do some more later */
	  }
	}
  }
}


/****************************************************************************
  announce myself as a master to all other primary domain conrollers.

  this actually gets done in search_and_sync_workgroups() via the
  NAME_QUERY_DOM_SRV_CHK command, if there is a response from the
  name query initiated here.  see response_name_query()
  **************************************************************************/
void announce_master(void)
{
  struct subnet_record *d;
  static time_t last=0;
  time_t t = time(NULL);
  BOOL am_master = False; /* are we a master of some sort? :-) */

  if (!last) last = t;
  if (t-last < CHECK_TIME_MST_ANNOUNCE * 60)
	return;

  last = t;

  for (d = subnetlist; d; d = d->next)
    {
      struct work_record *work;
      for (work = d->workgrouplist; work; work = work->next)
	{
	  if (AM_MASTER(work))
	    {
	      am_master = True;
	    }
	}
    }
  
  if (!am_master) return; /* only proceed if we are a master browser */
  
  for (d = subnetlist; d; d = d->next)
    {
      struct work_record *work;
      for (work = d->workgrouplist; work; work = work->next)
	{
	  struct server_record *s;
	  for (s = work->serverlist; s; s = s->next)
	    {
	      if (strequal(s->serv.name, myname)) continue;
	      
	      /* all DOMs (which should also be master browsers) */
	      if (s->serv.type & SV_TYPE_DOMAIN_CTRL)
		{
		  /* check the existence of a pdc for this workgroup, and if
		     one exists at the specified ip, sync with it and announce
		     ourselves as a master browser to it */
		  
		  if (!*lp_domain_controller() ||
		      !strequal(lp_domain_controller(), s->serv.name))
		    {
		      if (!lp_wins_support() && *lp_wins_server())
			{
			  queue_netbios_pkt_wins(d,ClientNMB,NMB_QUERY,
						 NAME_QUERY_DOM_SRV_CHK,
						 work->work_group,0x1b,0,0,0,NULL,NULL,
						 False, False, ipzero, ipzero);
			}
		      else
			{
			  struct subnet_record *d2;
			  for (d2 = subnetlist; d2; d2 = d2->next)
			    {
			      queue_netbios_packet(d,ClientNMB,NMB_QUERY,
						   NAME_QUERY_DOM_SRV_CHK,
						   work->work_group,0x1b,0,0,0,NULL,NULL,
						   True, False, d2->bcast_ip, d2->bcast_ip);
			    }
			}
		    }
		}
	    }
	  
	  /* now do primary domain controller - the one that's not
	     necessarily in our browse lists, although it ought to be
	     this pdc is the one that we get TOLD about through smb.conf.
	     basically, if it's on a subnet that we know about, it may end
	     up in our browse lists (which is why it's explicitly excluded
	     in the code above) */
	  
	  if (*lp_domain_controller())
	    {
	      struct in_addr ip;
	      BOOL bcast = False;
	      
	      ip = *interpret_addr2(lp_domain_controller());
	      
	      if (zero_ip(ip)) {
		ip = d->bcast_ip;
		bcast = True;
	      }

	      DEBUG(2, ("Searching for DOM %s at %s\n",
			lp_domain_controller(), inet_ntoa(ip)));
	      
	      /* check the existence of a pdc for this workgroup, and if
		 one exists at the specified ip, sync with it and announce
		 ourselves as a master browser to it */
	      queue_netbios_pkt_wins(d,ClientNMB,NMB_QUERY,NAME_QUERY_DOM_SRV_CHK,
				     work->work_group,0x1b,0,0,0,NULL,NULL,
				     bcast, False, ip, ip);
	    }
	}
    }
}



/****************************************************************************
  do all the "remote" announcements. These are used to put ourselves
  on a remote browse list. They are done blind, no checking is done to
  see if there is actually a browse master at the other end.
  **************************************************************************/
void announce_remote(void)
{
  char *s,*ptr;
  static time_t last_time = 0;
  time_t t = time(NULL);
  pstring s2;
  struct in_addr addr;
  char *comment,*workgroup;
  int stype = DFLT_SERVER_TYPE;

  if (last_time && t < last_time + REMOTE_ANNOUNCE_INTERVAL)
    return;

  last_time = t;

  s = lp_remote_announce();
  if (!*s) return;

  comment = lp_serverstring();
  workgroup = lp_workgroup();

  for (ptr=s; next_token(&ptr,s2,NULL); ) {
    /* the entries are of the form a.b.c.d/WORKGROUP with 
       WORKGROUP being optional */
    char *wgroup;

    wgroup = strchr(s2,'/');
    if (wgroup) *wgroup++ = 0;
    if (!wgroup || !*wgroup)
      wgroup = workgroup;

    addr = *interpret_addr2(s2);
    
    do_announce_host(ANN_HostAnnouncement,myname,0x20,*iface_ip(addr),
		     wgroup,0x1e,addr,
		     REMOTE_ANNOUNCE_INTERVAL,
		     myname,stype,comment);    
  }

}
