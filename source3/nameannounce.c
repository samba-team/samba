/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1997

   SMB Version handling
   Copyright (C) John H Terpstra 1995-1997
   
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
extern fstring myworkgroup;
extern char **my_netbios_names;

extern int ClientDGRAM;
extern int ClientNMB;

/* this is our domain/workgroup/server database */
extern struct subnet_record *subnetlist;

extern int  updatecount;
extern int  workgroup_count;

extern struct in_addr wins_ip;

extern pstring scope;

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

  send_mailslot_reply(False, BROWSE_MAILSLOT, ClientDGRAM,
                      outbuf,PTR_DIFF(p,outbuf),
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
  
  send_mailslot_reply(False,BROWSE_MAILSLOT, ClientDGRAM,
                      outbuf,PTR_DIFF(p,outbuf),
                      myname,to_name,from,to,dest_ip,*iface_ip(dest_ip));
}


/****************************************************************************
  find a server responsible for a workgroup, and sync browse lists
  control ends up back here via response_name_query.
  **************************************************************************/
void sync_server(enum state_type state, char *serv_name, char *work_name, 
		 int name_type,
                 struct subnet_record *d,
		 struct in_addr ip)
{                     
  /* with a domain master we can get the whole list (not local only list) */
  BOOL local_only = (state != NAME_STATUS_DOM_SRV_CHK);

  add_browser_entry(serv_name, name_type, work_name, 0, d, ip, local_only);

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
static void do_announce_host(int command,
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

  CVAL(p,21) = lp_major_announce_version(); /* major version */
  CVAL(p,22) = lp_minor_announce_version(); /* minor version */

  SIVAL(p,23,server_type & ~SV_TYPE_LOCAL_LIST_ONLY);
  /* browse version: got from NT/AS 4.00  - Value defined in smb.h (JHT)*/
  SSVAL(p,27,BROWSER_ELECTION_VERSION);
  SSVAL(p,29,BROWSER_CONSTANT); /* browse signature */

  pstrcpy(p+31,server_comment);
  p += 31;
  p = skip_string(p,1);

  debug_browse_data(outbuf, PTR_DIFF(p,outbuf));

  /* send the announcement */
  send_mailslot_reply(False,BROWSE_MAILSLOT, ClientDGRAM, outbuf,
			  PTR_DIFF(p,outbuf),
			  from_name, to_name,
			  from_type, to_type,
			  to_ip, from_ip);
}


/****************************************************************************
announce all samba's server entries as 'gone'.
****************************************************************************/
void announce_my_servers_removed(void)
{
	struct subnet_record *d; 
	for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_EXCLUDING_WINS(d))
	{
		struct work_record *work;
		for (work = d->workgrouplist; work; work = work->next)
		{
			struct server_record *s;
			for (s = work->serverlist; s; s = s->next)
			{
				if (!is_myname(s->serv.name)) continue;
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
  /* domain type cannot have anything in it that might confuse
     a client into thinking that the domain is in fact a server.
     (SV_TYPE_SERVER_UNIX, for example)
   */
  uint32 domain_type = SV_TYPE_DOMAIN_ENUM|SV_TYPE_NT;
  BOOL wins_iface = ip_equal(d->bcast_ip, wins_ip);

  if(wins_iface)
  {
    DEBUG(0,("announce_server: error - announcement requested on WINS \
interface for workgroup %s, name %s\n", work->work_group, name));
    return;
  }

  /* Only do domain announcements if we are a master and it's
     our name we're being asked to announce. */
  if (AM_MASTER(work) && strequal(myname,name))
  {
    DEBUG(3,("sending local master announce to %s for %s(1e)\n",
              inet_ntoa(d->bcast_ip),work->work_group));

    do_announce_host(ANN_LocalMasterAnnouncement,
                     name            , 0x00, d->myip,
                     work->work_group, 0x1e, d->bcast_ip,
                     ttl,
                     name, server_type, comment);

    DEBUG(3,("sending domain announce to %s for %s\n",
              inet_ntoa(d->bcast_ip),work->work_group));

    /* XXXX should we do a domain-announce-kill? */
    if (server_type != 0)
    {
      do_announce_host(ANN_DomainAnnouncement,
                       name    , 0x00, d->myip,
                       MSBROWSE, 0x01, d->bcast_ip,
                       ttl,
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
                     ttl,
                     name, server_type, comment);
  }
}

/****************************************************************************
  construct a host announcement unicast
  **************************************************************************/
void announce_host(time_t t)
{
  struct subnet_record *d;
  pstring comment;
  char *my_name;

  StrnCpy(comment, lp_serverstring(), 43);

  my_name = *myname ? myname : "NoName";

  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_EXCLUDING_WINS(d))
    {
      struct work_record *work;
      
      for (work = d->workgrouplist; work; work = work->next)
	{
	  uint32 stype = work->ServerType;
	  struct server_record *s;
	  
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
	    if (is_myname(s->serv.name)) { 
              /* If we are any kind of browser or logon server, only 
                 announce it for our primary name, not our aliases. */
              if(!strequal(myname, s->serv.name))
                stype &= ~(SV_TYPE_MASTER_BROWSER|SV_TYPE_POTENTIAL_BROWSER|
                           SV_TYPE_DOMAIN_MASTER|SV_TYPE_DOMAIN_MEMBER);
	      announce_server(d,work,s->serv.name,comment,
			    work->announce_interval,stype);
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

/* Announce timer. Moved into global static so it can be reset
   when a machine becomes a master browser. */
static time_t announce_timer_last=0;

/****************************************************************************
 Reset the announce_timer so that a master browser announce will be done
 immediately.
 ****************************************************************************/

void reset_announce_timer()
{
  announce_timer_last = time(NULL) - (CHECK_TIME_MST_ANNOUNCE * 60);
}

/****************************************************************************
  announce myself as a master to all other domain master browsers.

  this actually gets done in search_and_sync_workgroups() via the
  NAME_QUERY_DOM_SRV_CHK command, if there is a response from the
  name query initiated here.  see response_name_query()
  **************************************************************************/
void announce_master(time_t t)
{
  struct subnet_record *d;
  struct work_record *work;
  BOOL am_master = False; /* are we a master of some sort? :-) */

  if (!announce_timer_last) announce_timer_last = t;
  if (t-announce_timer_last < CHECK_TIME_MST_ANNOUNCE * 60)
    {
      DEBUG(10,("announce_master: t (%d) - last(%d) < %d\n",
                 t, announce_timer_last, CHECK_TIME_MST_ANNOUNCE * 60 ));
      return;
    }

  if(wins_subnet == NULL)
    {
      DEBUG(10,("announce_master: no wins subnet, ignoring.\n"));
      return;
    }

  announce_timer_last = t;

  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_EXCLUDING_WINS(d))
    {
      for (work = d->workgrouplist; work; work = work->next)
	{
	  if (AM_MASTER(work))
	    {
	      am_master = True;
              DEBUG(4,( "announce_master: am_master = %d for \
workgroup %s\n", am_master, work->work_group));
	    }
	}
    }
 
  if (!am_master) return; /* only proceed if we are a master browser */
  
  /* Note that we don't do this if we are domain master browser
     and that we *only* do this on the WINS subnet. */

  /* Try and find our workgroup on the WINS subnet */
  work = find_workgroupstruct(wins_subnet, myworkgroup, False);

  if (work)
    {
      char *name;
      int   type;

        {
          /* assume that the domain master browser we want to sync
             with is our own domain.
           */
          name = work->work_group;
          type = 0x1b;
        }

      /* check the existence of a dmb for this workgroup, and if
         one exists at the specified ip, sync with it and announce
         ourselves as a master browser to it
       */

      if (!lp_wins_support() && *lp_wins_server() )
        {
          DEBUG(4, ("Local Announce: find %s<%02x> from WINS server %s\n",
                     name, type, lp_wins_server()));

          queue_netbios_pkt_wins(ClientNMB,
                    NMB_QUERY,NAME_QUERY_DOM_SRV_CHK,
                    name, type, 0,0,0,
                    work->work_group,NULL,
                    ipzero, ipzero);
        }
      else if(lp_wins_support()) 
        {
           /* We are the WINS server - query ourselves for the dmb name. */

           struct nmb_name netb_name;
           struct name_record *nr = 0;

	   d = NULL;

           make_nmb_name(&netb_name, name, type, scope);

           if ((nr = find_name_search(&d, &netb_name, FIND_WINS, ipzero)) == 0)
             {
               DEBUG(0, ("announce_master: unable to find domain master browser for workgroup %s \
in our own WINS database.\n", work->work_group));
               return;
             }

           /* Check that this isn't one of our addresses (ie. we are not domain master
              ourselves) */
           if(ismyip(nr->ip_flgs[0].ip) || ip_equal(nr->ip_flgs[0].ip, ipzero))
             {
               DEBUG(4, ("announce_master: domain master ip found (%s) for workgroup %s \
is one of our interfaces.\n", work->work_group, inet_ntoa(nr->ip_flgs[0].ip) ));
               return;
             }

           /* Issue a NAME_STATUS_DOM_SRV_CHK immediately - short circuit the
              NAME_QUERY_DOM_SRV_CHK which is done only if we are talking to a 
              remote WINS server. */

           DEBUG(4, ("announce_master: doing name status for %s<%02x> to domain master ip %s \
for workgroup %s\n", name, type, inet_ntoa(nr->ip_flgs[0].ip), work->work_group ));

           queue_netbios_packet(wins_subnet, ClientNMB,
                    NMB_QUERY,NAME_STATUS_DOM_SRV_CHK,
                    name, type, 0,0,0,
                    work->work_group,NULL,
                    False, False, nr->ip_flgs[0].ip, nr->ip_flgs[0].ip, 0);
         }

    }
}

/****************************************************************************
  do all the "remote" announcements. These are used to put ourselves
  on a remote browse list. They are done blind, no checking is done to
  see if there is actually a browse master at the other end.
  **************************************************************************/
void announce_remote(time_t t)
{
  char *s,*ptr;
  static time_t last_time = 0;
  pstring s2;
  struct in_addr addr;
  char *comment,*workgroup;
  int stype = lp_default_server_announce();

  if (last_time && t < last_time + REMOTE_ANNOUNCE_INTERVAL)
    return;

  last_time = t;

  s = lp_remote_announce();
  if (!*s) return;

  comment = lp_serverstring();
  workgroup = myworkgroup;

  for (ptr=s; next_token(&ptr,s2,NULL); ) 
  {
    /* the entries are of the form a.b.c.d/WORKGROUP with 
       WORKGROUP being optional */
    char *wgroup;
    int n;

    wgroup = strchr(s2,'/');
    if (wgroup) *wgroup++ = 0;
    if (!wgroup || !*wgroup)
      wgroup = workgroup;

    addr = *interpret_addr2(s2);
    
    /* Announce all our names including aliases */
    for (n=0; my_netbios_names[n]; n++) 
    {
      char *name = my_netbios_names[n];
      do_announce_host(ANN_HostAnnouncement,name,0x20,*iface_ip(addr),
		     wgroup,0x1e,addr,
		     REMOTE_ANNOUNCE_INTERVAL,
		     name,stype,comment);    
    }
  }

}
