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
   
   Module name: nameelect.c

   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

   04 jul 96: lkcl@pires.co.uk
   added system to become a master browser by stages.


*/

#include "includes.h"

extern int ClientNMB;
extern int ClientDGRAM;

extern int DEBUGLEVEL;
extern pstring scope;

extern pstring myname;
extern struct in_addr ipzero;
extern struct in_addr ipgrp;

/* here are my election parameters */

extern time_t StartupTime;

extern struct subnet_record *subnetlist;

extern uint16 nb_type; /* samba's NetBIOS name type */

/*******************************************************************
  occasionally check to see if the master browser is around
  ******************************************************************/
void check_master_browser(void)
{
  static time_t lastrun=0;
  time_t t = time(NULL);
  struct subnet_record *d;

  if (!lastrun) lastrun = t;
  if (t < lastrun + CHECK_TIME_MST_BROWSE * 60)
    return;
  lastrun = t;

  dump_workgroups();

  for (d = subnetlist; d; d = d->next)
    {
      struct work_record *work;

      for (work = d->workgrouplist; work; work = work->next)
	{
	  /* if we are not the browse master of a workgroup, and we can't
	     find a browser on the subnet, do something about it. */

	  if (!AM_MASTER(work))
	    {
	      queue_netbios_packet(d,ClientNMB,NMB_QUERY,NAME_QUERY_MST_CHK,
				   work->work_group,0x1d,0,0,0,NULL,NULL,
				   True,False,d->bcast_ip,d->bcast_ip);
	    }
	}
    }
}


/*******************************************************************
  what to do if a master browser DOESN't exist
  ******************************************************************/
void browser_gone(char *work_name, struct in_addr ip)
{
  struct subnet_record *d = find_subnet(ip);
  struct work_record *work = find_workgroupstruct(d, work_name, False);

  /* i don't know about this workgroup, therefore i don't care */
  if (!work || !d) return;

  /* don't do election stuff on the WINS subnet */
  if (ip_equal(d->bcast_ip,ipgrp)) 
    return;

  if (strequal(work->work_group, lp_workgroup()))
  {

      DEBUG(2,("Forcing election on %s %s\n",
	       work->work_group,inet_ntoa(d->bcast_ip)));

      /* we can attempt to become master browser */
      work->needelection = True;
  }
  else
  {
     /* local interfaces: force an election */
    send_election(d, work->work_group, 0, 0, myname);

     /* only removes workgroup completely on a local interface 
        persistent lmhosts entries on a local interface _will_ be removed).
      */
     remove_workgroup(d, work,True);
  }
}


/****************************************************************************
  send an election packet
  **************************************************************************/
void send_election(struct subnet_record *d, char *group,uint32 criterion,
		   int timeup,char *name)
{
  pstring outbuf;
  char *p;

  if (!d) return;
  
  DEBUG(2,("Sending election to %s for workgroup %s\n",
	   inet_ntoa(d->bcast_ip),group));	   

  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = ANN_Election; /* election */
  p++;

  CVAL(p,0) = (criterion == 0 && timeup == 0) ? 0 : ELECTION_VERSION;
  SIVAL(p,1,criterion);
  SIVAL(p,5,timeup*1000); /* ms - despite the spec */
  p += 13;
  strcpy(p,name);
  strupper(p);
  p = skip_string(p,1);
  
  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      name,group,0,0x1e,d->bcast_ip,*iface_ip(d->bcast_ip));
}


/****************************************************************************
  un-register a SELF name that got rejected.

  if this name happens to be rejected when samba is in the process
  of becoming a master browser (registering __MSBROWSE__, WORKGROUP(1d)
  or WORKGROUP(1b)) then we must stop being a master browser. sad.

  **************************************************************************/
void name_unregister_work(struct subnet_record *d, char *name, int name_type)
{
    struct work_record *work;

    remove_netbios_name(d,name,name_type,SELF,ipzero);

    if (!(work = find_workgroupstruct(d, name, False))) return;

    if (ms_browser_name(name, name_type) ||
        (AM_MASTER(work) && strequal(name, lp_workgroup()) == 0 &&
         (name_type == 0x1d || name_type == 0x1b)))
    {
      int remove_type = 0;

      if (ms_browser_name(name, name_type))
        remove_type = SV_TYPE_MASTER_BROWSER|SV_TYPE_DOMAIN_MASTER;
      if (name_type == 0x1d)
        remove_type = SV_TYPE_MASTER_BROWSER;
      if (name_type == 0x1b)
        remove_type = SV_TYPE_DOMAIN_MASTER;
			
      become_nonmaster(d, work, remove_type);
    }
}


/****************************************************************************
  registers a name.

  if the name being added is a SELF name, we must additionally check
  whether to proceed to the next stage in samba becoming a master browser.

  **************************************************************************/
void name_register_work(struct subnet_record *d, char *name, int name_type,
				int nb_flags, time_t ttl, struct in_addr ip, BOOL bcast)
{
  enum name_source source = (ismyip(ip) || ip_equal(ip, ipzero)) ?
								SELF : REGISTER;

  if (source == SELF)
  {
    struct work_record *work = find_workgroupstruct(d, lp_workgroup(), False);

    add_netbios_entry(d,name,name_type,nb_flags,ttl,source,ip,True,!bcast);

    if (work)
    {
      if (work->state != MST_NONE)
      {
        /* samba is in the process of working towards master browser-ness.
           initiate the next stage.
         */
        become_master(d, work);
        return;
      }
    }
  }
}


/*******************************************************************
  become the master browser.

  this is done in stages. note that this could take a while, 
  particularly on a broadcast subnet, as we have to wait for
  the implicit registration of each name to be accepted.

  as each name is successfully registered, become_master() is
  called again, in order to initiate the next stage. see
  dead_netbios_entry() - deals with implicit name registration
  and response_name_reg() - deals with explicit registration
  with a WINS server.

  stage 1: was MST_NONE - go to MST_NONE and register ^1^2__MSBROWSE__^2^1.
  stage 2: was MST_WON  - go to MST_MSB  and register WORKGROUP(0x1d)
  stage 3: was MST_MSB  - go to MST_BROWSER and register WORKGROUP(0x1b)
  stage 4: was MST_BROWSER - go to MST_DOMAIN (do not pass GO, do not...)

  XXXX note: this code still does not cope with the distinction
  between different types of nodes, particularly between M and P
  nodes. that comes later.

  ******************************************************************/
void become_master(struct subnet_record *d, struct work_record *work)
{
  uint32 domain_type = SV_TYPE_DOMAIN_ENUM|DFLT_SERVER_TYPE|
    SV_TYPE_POTENTIAL_BROWSER;

  if (!work) return;
  
  DEBUG(2,("Becoming master for %s %s (currently at stage %d)\n",
					work->work_group,inet_ntoa(d->bcast_ip),work->state));
  
  switch (work->state)
  {
    case MST_NONE: /* while we were nothing but a server... */
    {
      DEBUG(3,("go to first stage: register ^1^2__MSBROWSE__^2^1\n"));
      work->state = MST_WON; /* ... an election win was successful */

      work->ElectionCriterion |= 0x5;

      /* update our server status */
      work->ServerType &= ~SV_TYPE_POTENTIAL_BROWSER;
      add_server_entry(d,work,myname,work->ServerType,0,lp_serverstring(),True);

      /* add special browser name */
      add_my_name_entry(d,MSBROWSE        ,0x01,nb_type|NB_ACTIVE|NB_GROUP);

      /* DON'T do anything else after calling add_my_name_entry() */
      return;
    }
    case MST_WON: /* while nothing had happened except we won an election... */
    {
      DEBUG(3,("go to second stage: register as master browser\n"));
      work->state = MST_MSB; /* ... registering MSBROWSE was successful */

      /* add server entry on successful registration of MSBROWSE */
      add_server_entry(d,work,work->work_group,domain_type,0,myname,True);

      /* add master name */
      add_my_name_entry(d,work->work_group,0x1d,nb_type|NB_ACTIVE);
  
      /* DON'T do anything else after calling add_my_name_entry() */
      return;
    }
    case MST_MSB: /* while we were still only registered MSBROWSE state... */
    {
      DEBUG(3,("2nd stage complete: registered as master browser\n"));
      work->state = MST_BROWSER; /* ... registering WORKGROUP(1d) succeeded */

      /* update our server status */
      work->ServerType |= SV_TYPE_MASTER_BROWSER;
      add_server_entry(d,work,myname,work->ServerType,0,lp_serverstring(),True);

      if (work->serverlist == NULL) /* no servers! */
      {
        /* ask all servers on our local net to announce to us */
        announce_request(work, d->bcast_ip);
      }
      break;
   }

   case MST_BROWSER:
   {
      /* don't have to do anything: just report success */
      DEBUG(3,("3rd stage: become master browser!\n"));

      break;
   }

   case MST_DOMAIN_NONE:
   {
      if (lp_domain_master())
      {
        work->state = MST_DOMAIN_MEM; /* ... become domain member */
        DEBUG(3,("domain first stage: register as domain member\n"));

        /* add domain member name */
        add_my_name_entry(d,work->work_group,0x1e,nb_type|NB_ACTIVE|NB_GROUP);

        /* DON'T do anything else after calling add_my_name_entry() */
        return;
      }
      else
      {
        DEBUG(4,("samba not configured as a domain master.\n"));
      }
  
      break;
   }

   case MST_DOMAIN_MEM:
   {
      if (lp_domain_master())
      {
        work->state = MST_DOMAIN_TST; /* ... possibly become domain master */
        DEBUG(3,("domain second stage: register as domain master\n"));

        if (lp_domain_logons())
	    {
          work->ServerType |= SV_TYPE_DOMAIN_MEMBER;
          add_server_entry(d,work,myname,work->ServerType,0,lp_serverstring(),True);
        }

        /* add domain master name */
        add_my_name_entry(d,work->work_group,0x1b,nb_type|NB_ACTIVE         );

        /* DON'T do anything else after calling add_my_name_entry() */
        return;
      }
      else
      {
        DEBUG(4,("samba not configured as a domain master.\n"));
      }
  
      break;
    }

    case MST_DOMAIN_TST: /* while we were still a master browser... */
    {
      /* update our server status */
      if (lp_domain_master())
      {
        struct subnet_record *d1;
		uint32 update_type = 0;

        DEBUG(3,("domain third stage: samba is now a domain master.\n"));
        work->state = MST_DOMAIN; /* ... registering WORKGROUP(1b) succeeded */

        update_type |= DFLT_SERVER_TYPE | SV_TYPE_DOMAIN_MASTER | 
	  SV_TYPE_POTENTIAL_BROWSER;

		work->ServerType |= update_type;
		add_server_entry(d,work,myname,work->ServerType,0,lp_serverstring(),True);

		for (d1 = subnetlist; d1; d1 = d1->next)
		{
        	struct work_record *w;
			if (ip_equal(d1->bcast_ip, d->bcast_ip)) continue;

        	for (w = d1->workgrouplist; w; w = w->next)
			{
				struct server_record *s = find_server(w, myname);
				if (strequal(w->work_group, work->work_group))
				{
					w->ServerType |= update_type;
				}
				if (s)
				{
					s->serv.type |= update_type;
					DEBUG(4,("found server %s on %s: update to %8x\n",
									s->serv.name, inet_ntoa(d1->bcast_ip),
									s->serv.type));
				}
			}
		}
      }
  
      break;
    }

    case MST_DOMAIN:
    {
      /* don't have to do anything: just report success */
      DEBUG(3,("fifth stage: there isn't one yet!\n"));
      break;
    }
  }
}


/*******************************************************************
  unbecome the master browser. initates removal of necessary netbios 
  names, and tells the world that we are no longer a master browser.
  ******************************************************************/
void become_nonmaster(struct subnet_record *d, struct work_record *work,
				int remove_type)
{
  int new_server_type = work->ServerType;

  DEBUG(2,("Becoming non-master for %s\n",work->work_group));
  
  /* can only remove master or domain types with this function */
  remove_type &= SV_TYPE_MASTER_BROWSER|SV_TYPE_DOMAIN_MASTER;

  /* unbecome a master browser; unbecome a domain master, too :-( */
  if (remove_type & SV_TYPE_MASTER_BROWSER)
    remove_type |= SV_TYPE_DOMAIN_MASTER;

  new_server_type &= ~remove_type;

  if (!(new_server_type & (SV_TYPE_MASTER_BROWSER|SV_TYPE_DOMAIN_MASTER)))
  {
    /* no longer a master browser of any sort */

    work->ServerType |= SV_TYPE_POTENTIAL_BROWSER;
    work->ElectionCriterion &= ~0x4;
    work->state = MST_NONE;

	/* announce ourselves as no longer active as a master browser. */
    announce_server(d, work, work->work_group, myname, 0, 0);
    remove_name_entry(d,MSBROWSE        ,0x01);
  }
  
  work->ServerType = new_server_type;

  if (!(work->ServerType & SV_TYPE_DOMAIN_MASTER))
  {
    if (work->state == MST_DOMAIN)
      work->state = MST_BROWSER;
    remove_name_entry(d,work->work_group,0x1b);    
  }

  if (!(work->ServerType & SV_TYPE_MASTER_BROWSER))
  {
    if (work->state >= MST_BROWSER)
      work->state = MST_NONE;
    remove_name_entry(d,work->work_group,0x1d);
  }
}


/*******************************************************************
  run the election
  ******************************************************************/
void run_elections(void)
{
  time_t t = time(NULL);
  static time_t lastime = 0;
  
  struct subnet_record *d;
  
  /* send election packets once a second */
  if (lastime && t-lastime <= 0) return;
  
  lastime = t;
  
  for (d = subnetlist; d; d = d->next)
  {
    struct work_record *work;
    for (work = d->workgrouplist; work; work = work->next)
	{
	  if (work->RunningElection)
	  {
	    send_election(d,work->work_group, work->ElectionCriterion,
			    t-StartupTime,myname);
	      
	    if (work->ElectionCount++ >= 4)
		{
		  /* I won! now what :-) */
		  DEBUG(2,(">>> Won election on %s %s <<<\n",
			   work->work_group,inet_ntoa(d->bcast_ip)));
		  
		  work->RunningElection = False;
		  work->state = MST_NONE;

		  become_master(d, work);
		}
	  }
	}
  }
}


/*******************************************************************
  work out if I win an election
  ******************************************************************/
static BOOL win_election(struct work_record *work,int version,uint32 criterion,
			 int timeup,char *name)
{  
  int mytimeup = time(NULL) - StartupTime;
  uint32 mycriterion = work->ElectionCriterion;

  DEBUG(4,("election comparison: %x:%x %x:%x %d:%d %s:%s\n",
	   version,ELECTION_VERSION,
	   criterion,mycriterion,
	   timeup,mytimeup,
	   name,myname));

  if (version > ELECTION_VERSION) return(False);
  if (version < ELECTION_VERSION) return(True);
  
  if (criterion > mycriterion) return(False);
  if (criterion < mycriterion) return(True);

  if (timeup > mytimeup) return(False);
  if (timeup < mytimeup) return(True);

  if (strcasecmp(myname,name) > 0) return(False);
  
  return(True);
}


/*******************************************************************
  process a election packet

  An election dynamically decides who will be the master. 
  ******************************************************************/
void process_election(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  struct in_addr ip = dgram->header.source_ip;
  struct subnet_record *d = find_subnet(ip);
  int version = CVAL(buf,0);
  uint32 criterion = IVAL(buf,1);
  int timeup = IVAL(buf,5)/1000;
  char *name = buf+13;
  struct work_record *work;

  if (!d) return;

  if (ip_equal(d->bcast_ip,ipgrp)) {
    DEBUG(3,("Unexpected election request from %s %s on WINS net\n",
	     name, inet_ntoa(p->ip)));
    return;
  }
  
  name[15] = 0;  

  DEBUG(3,("Election request from %s %s vers=%d criterion=%08x timeup=%d\n",
	   name,inet_ntoa(p->ip),version,criterion,timeup));
  
  if (same_context(dgram)) return;
  
  for (work = d->workgrouplist; work; work = work->next)
    {
      if (!strequal(work->work_group, lp_workgroup()))
	continue;

      if (win_election(work, version,criterion,timeup,name)) {
	if (!work->RunningElection) {
	  work->needelection = True;
	  work->ElectionCount=0;
	  work->state = MST_NONE;
	}
      } else {
	work->needelection = False;
	  
	if (work->RunningElection || AM_MASTER(work)) {
	  work->RunningElection = False;
	  DEBUG(3,(">>> Lost election on %s %s <<<\n",
		   work->work_group,inet_ntoa(d->bcast_ip)));
	  if (AM_MASTER(work))
	    become_nonmaster(d, work,
			     SV_TYPE_MASTER_BROWSER|
			     SV_TYPE_DOMAIN_MASTER);
	}
      }
    }
}


/****************************************************************************
  checks whether a browser election is to be run on any workgroup

  this function really ought to return the time between election
  packets (which depends on whether samba intends to be a domain
  master or a master browser) in milliseconds.

  ***************************************************************************/
BOOL check_elections(void)
{
  struct subnet_record *d;
  BOOL run_any_election = False;

  for (d = subnetlist; d; d = d->next)
    {
      struct work_record *work;
      for (work = d->workgrouplist; work; work = work->next)
	{
	  run_any_election |= work->RunningElection;
	  
	  if (work->needelection && !work->RunningElection)
	    {
	      DEBUG(3,(">>> Starting election on %s %s <<<\n",
		       work->work_group,inet_ntoa(d->bcast_ip)));
	      work->ElectionCount = 0;
	      work->RunningElection = True;
	      work->needelection = False;
	    }
	}
    }
  return run_any_election;
}

