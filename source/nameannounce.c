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

#define TEST_CODE

extern int DEBUGLEVEL;
extern BOOL CanRecurse;

extern struct in_addr myip;
extern struct in_addr bcast_ip;
extern struct in_addr Netmask;
extern struct in_addr ipzero;

extern pstring myname;

extern int ClientDGRAM;
extern int ClientNMB;

/* this is our domain/workgroup/server database */
extern struct domain_record *domainlist;

/* machine comment for host announcements */
extern  pstring ServerComment;

extern int  updatecount;
extern int  workgroup_count;

/* what server type are we currently */

#define AM_MASTER(work) (work->ServerType & SV_TYPE_MASTER_BROWSER)
#define AM_BACKUP(work) (work->ServerType & SV_TYPE_BACKUP_BROWSER)
#define AM_DOMCTL(work) (work->ServerType & SV_TYPE_DOMAIN_CTRL)

#define MSBROWSE "\001\002__MSBROWSE__\002"
#define BROWSE_MAILSLOT "\\MAILSLOT\\BROWSE"

/****************************************************************************
  send a announce request to the local net
  **************************************************************************/
void announce_request(struct work_record *work, struct in_addr ip)
{
  pstring outbuf;
  char *p;

  if (!work) return;

  work->needannounce = True;

  DEBUG(2,("Sending announce request to %s for workgroup %s\n",
	   inet_ntoa(ip),work->work_group));

  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = 2; /* announce request */
  p++;

  CVAL(p,0) = work->token; /* flags?? XXXX probably a token*/
  p++;
  StrnCpy(p,myname,16);
  strupper(p);
  p = skip_string(p,1);
  
  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,work->work_group,0x20,0x0,ip,myip);
}


/****************************************************************************
  request an announcement
  **************************************************************************/
void do_announce_request(char *info, char *to_name, int announce_type, int from,
			 int to, struct in_addr dest_ip)
{
  pstring outbuf;
  char *p;
  
  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = announce_type; /* announce request */
  p++;
  
  DEBUG(2,("Sending announce type %d: info %s to %s - server %s(%x)\n",
	   announce_type, info, inet_ntoa(dest_ip),to_name,to));
  
  StrnCpy(p,info,16);
  strupper(p);
  p = skip_string(p,1);
  
  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,to_name,from,to,dest_ip,myip);
}

/****************************************************************************
  construct a host announcement unicast
  **************************************************************************/
void announce_backup(void)
{
	static time_t lastrun = 0;
	time_t t = time(NULL);
	pstring outbuf;
	char *p;
	struct domain_record *d1;
	int tok;

	if (!lastrun) lastrun = t;
	if (t < lastrun + 1*60) return;
	lastrun = t;

	for (tok = 0; tok <= workgroup_count; tok++)
	{
		for (d1 = domainlist; d1; d1 = d1->next)
		{
			struct work_record *work;
			struct domain_record *d;

			/* search for unique workgroup: only the name matters */
			for (work = d1->workgrouplist;
			     work && (tok != work->token);
			     work = work->next);

			if (work)
			{
				/* found one: announce it across all domains */
				for (d = domainlist; d; d = d->next)
				{
					DEBUG(2,("Sending announce backup %s workgroup %s(%d)\n",
						 inet_ntoa(d->bcast_ip),work->work_group,
					     work->token));

					bzero(outbuf,sizeof(outbuf));
					p = outbuf;
					CVAL(p,0) = 9; /* backup list response */
					p++;

					CVAL(p,0) = 1; /* count? */
					SIVAL(p,1,work->token); /* workgroup unique key index */
					p += 5;
					p++;

					if (AM_DOMCTL(work))
					{
						send_mailslot_reply(BROWSE_MAILSLOT,
							   ClientDGRAM,outbuf,
							   PTR_DIFF(p,outbuf),
							   myname, work->work_group,
							   0x0,0x1b,d->bcast_ip,myip);
					}
					else if (AM_MASTER(work))
					{
						send_mailslot_reply(BROWSE_MAILSLOT,
							   ClientDGRAM,outbuf,
							   PTR_DIFF(p,outbuf),
							   myname, work->work_group,
							   0x0,0x1d,d->bcast_ip,myip);
					}
				}
			}
		}
	}
}


/****************************************************************************
  construct a host announcement unicast
  **************************************************************************/
void announce_host(void)
{
  time_t t = time(NULL);
  pstring outbuf;
  char *p;
  char *namep;
  char *stypep;
  char *commentp;
  pstring comment;
  char *my_name;
  struct domain_record *d;

  StrnCpy(comment, *ServerComment ? ServerComment : "NoComment", 43);

  my_name = *myname ? myname : "NoName";

  for (d = domainlist; d; d = d->next)
    {
      struct work_record *work;
      
      if (!ip_equal(bcast_ip,d->bcast_ip))
	continue;

      for (work = d->workgrouplist; work; work = work->next)
	{
	  uint32 stype = work->ServerType;
	  struct server_record *s;
	  BOOL announce = False;
	  
	  if (work->needannounce) {
	    /* drop back to a max 3 minute announce - this is to prevent a
	       single lost packet from stuffing things up for too long */
	    work->announce_interval = MIN(work->announce_interval,3*60);
	    work->lastannounce_time = t - (work->announce_interval+1);
	  }
	  
	  /* announce every minute at first then progress to every 12 mins */
	  if (work->lastannounce_time && 
	      (t - work->lastannounce_time) < work->announce_interval)
	    continue;
	  
	  if (work->announce_interval < 12*60) 
	    work->announce_interval += 60;
	  
	  work->lastannounce_time = t;

	  DEBUG(2,("Sending announcement to subnet %s for workgroup %s\n",
		   inet_ntoa(d->bcast_ip),work->work_group));

	  if (!ip_equal(bcast_ip,d->bcast_ip)) {
	    stype &= ~(SV_TYPE_POTENTIAL_BROWSER | SV_TYPE_MASTER_BROWSER |
		       SV_TYPE_DOMAIN_MASTER | SV_TYPE_BACKUP_BROWSER |
		       SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_MEMBER);
	  }

	  for (s = work->serverlist; s; s = s->next) {
	    if (strequal(myname, s->serv.name)) { 
	      announce = True; 
	      break; 
	    }
	  }
	  
	  if (announce)
	    {
	      bzero(outbuf,sizeof(outbuf));
	      p = outbuf+1;
	      
	      CVAL(p,0) = updatecount;
	      SIVAL(p,1,work->announce_interval*1000); /* ms - despite the spec */
	      namep = p+5;
	      StrnCpy(namep,my_name,16);
	      strupper(namep);
	      CVAL(p,21) = 2; /* major version */
	      CVAL(p,22) = 2; /* minor version */
	      stypep = p+23;
	      SIVAL(p,23,stype);
	      SSVAL(p,27,0xaa55); /* browse signature */
	      SSVAL(p,29,1); /* browse version */
	      commentp = p+31;
	      strcpy(commentp,comment);
	      p = p+31;
	      p = skip_string(p,1);
	      
	      if (ip_equal(bcast_ip,d->bcast_ip))
		{
		  if (AM_MASTER(work))
		    {
		      SIVAL(stypep,0,work->ServerType);
		      
		      CVAL(outbuf,0) = 15; /* local member announce */
		      
		      send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,
					  PTR_DIFF(p,outbuf),
					  my_name,work->work_group,0,
					  0x1e,d->bcast_ip,myip);
		      
		      CVAL(outbuf,0) = 12; /* domain announce */
		      
		      StrnCpy(namep,work->work_group,15);
		      strupper(namep);
		      StrnCpy(commentp,myname,15);
		      strupper(commentp);
		      
		      SIVAL(stypep,0,(unsigned)0x80000000);
		      p = commentp + strlen(commentp) + 1;
		      
		      send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,
					  PTR_DIFF(p,outbuf),
					  my_name,MSBROWSE,0,0x01,d->bcast_ip,myip);
		    }
		  else
		    {
		      CVAL(outbuf,0) = 1; /* host announce */
		      
		      send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,
					  PTR_DIFF(p,outbuf),
					  my_name,work->work_group,0,0x1d,d->bcast_ip,myip);
		    }
		}
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

  BIG NOTE: this code will remain untested until some kind soul that has access
  to a couple of windows NT advanced servers runs this version of nmbd for at
  least 15 minutes.
  
  this actually gets done in search_and_sync_workgroups() via the
  MASTER_SERVER_CHECK command, if there is a response from the
  name query initiated here.  see response_name_query()
  **************************************************************************/
void announce_master(void)
{
  struct domain_record *d;
  static time_t last=0;
  time_t t = time(NULL);
  BOOL am_master = False; /* are we a master of some sort? :-) */

#ifdef TEST_CODE
  if (last && (t-last < 2*60)) return;
#else
  if (last && (t-last < 15*60)) return; 
#endif

  last = t;

  for (d = domainlist; d; d = d->next)
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
  
  for (d = domainlist; d; d = d->next)
    {
      struct work_record *work;
      for (work = d->workgrouplist; work; work = work->next)
	{
	  struct server_record *s;
	  for (s = work->serverlist; s; s = s->next)
	    {
	      if (strequal(s->serv.name, myname)) continue;
	      
	      /* all PDCs (which should also be master browsers) */
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
			  struct in_addr ip;
			  ip = ipzero;
			  
			  queue_netbios_pkt_wins(ClientNMB,NMB_QUERY,
						 MASTER_SERVER_CHECK,
						 work->work_group,0x1b,0,
						 False, False, ip);
			}
		      else
			{
			  struct domain_record *d2;
			  for (d2 = domainlist; d2; d2 = d2->next)
			    {
			      queue_netbios_packet(ClientNMB,NMB_QUERY,
						   MASTER_SERVER_CHECK,
						   work->work_group,0x1b,0,
						   True, False, d2->bcast_ip);
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
	      
	      if (zero_ip(ip))
		{
		  ip = bcast_ip;
		  bcast = True;
		}

	      DEBUG(2, ("Searching for PDC %s at %s\n",
			lp_domain_controller(), inet_ntoa(ip)));
	      
	      /* check the existence of a pdc for this workgroup, and if
		 one exists at the specified ip, sync with it and announce
		 ourselves as a master browser to it */
	      queue_netbios_pkt_wins(ClientNMB, NMB_QUERY,MASTER_SERVER_CHECK,
				     work->work_group,0x1b, 0,
				     bcast, False, ip);
	    }
	}
    }
}
