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

extern int DEBUGLEVEL;
extern pstring scope;

extern pstring myname;
extern struct in_addr ipzero;

/* machine comment for host announcements */
extern  pstring ServerComment;

/* here are my election parameters */

extern time_t StartupTime;

extern struct subnet_record *subnetlist;


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
				   work->work_group,0x1d,0,0,
				   True,False,d->bcast_ip);
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

  if (!work || !d) return;

  if (strequal(work->work_group, lp_workgroup()) &&
      ismybcast(d->bcast_ip))
    {

      DEBUG(2,("Forcing election on %s %s\n",
	       work->work_group,inet_ntoa(d->bcast_ip)));

      /* we can attempt to become master browser */
      work->needelection = True;
    }
  else
    {
      /* XXXX note: this will delete entries that have been added in by
	 lmhosts as well. a flag to ensure that these are not deleted may
	 be considered */
      
      /* workgroup with no master browser is not the default workgroup:
	 it's also not on our subnet. therefore delete it: it can be
	 recreated dynamically */
      
      send_election(d, work->work_group, 0, 0, myname);
      remove_workgroup(d, work);      
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
  CVAL(p,0) = 8; /* election */
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

    if (special_browser_name(name, name_type) ||
        (AM_MASTER(work) && strequal(name, lp_workgroup()) == 0 &&
         (name_type == 0x1d || name_type == 0x1b)))
    {
      int remove_type = 0;

      if (special_browser_name(name, name_type))
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
  enum name_source source = ismyip(ip) ? SELF : REGISTER;

  if (source == SELF)
  {
    struct work_record *work = find_workgroupstruct(d, lp_workgroup(), False);

    if (work && work->state != MST_NONE)
    {
      /* samba is in the process of working towards master browser-ness.
         initiate the next stage.
       */
      become_master(d, work);
    }
  }
  add_netbios_entry(d,name,name_type,nb_flags,ttl,source,ip,True,!bcast);
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
  uint32 domain_type = SV_TYPE_DOMAIN_ENUM|SV_TYPE_SERVER_UNIX|0x00400000;

  if (!work) return;
  
  DEBUG(2,("Becoming master for %s (stage %d)",work->work_group,work->state));
  
  switch (work->state)
  {
    case MST_NONE: /* while we were nothing but a server... */
    {
      work->state = MST_WON; /* election win was successful */

      work->ElectionCriterion |= 0x5;

      /* update our server status */
      work->ServerType &= ~SV_TYPE_POTENTIAL_BROWSER;
      add_server_entry(d,work,myname,work->ServerType,0,ServerComment,True);

      DEBUG(2,("first stage: register ^1^2__MSBROWSE__^2^1\n"));

      /* add special browser name */
      add_my_name_entry(d,MSBROWSE        ,0x01,NB_ACTIVE|NB_GROUP);

      break;
    }
    case MST_WON: /* while nothing had happened except we won an election... */
    {
      work->state = MST_MSB; /* registering MSBROWSE was successful */

      /* add server entry on successful registration of MSBROWSE */
      add_server_entry(d,work,work->work_group,domain_type,0,myname,True);

      DEBUG(2,("second stage: register as master browser\n"));

      /* add master name */
      add_my_name_entry(d,work->work_group,0x1d,NB_ACTIVE         );
  
      break;
    }
    case MST_MSB: /* while we were still only registered MSBROWSE state */
    {
      work->state = MST_BROWSER; /* registering WORKGROUP(1d) was successful */

      /* update our server status */
      work->ServerType |= SV_TYPE_MASTER_BROWSER;
      add_server_entry(d,work,myname,work->ServerType,0,ServerComment,True);

      if (d->my_interface && work->serverlist == NULL) /* no servers! */
      {
        /* ask all servers on our local net to announce to us */
        announce_request(work, d->bcast_ip);
      }

      if (lp_domain_master())
      {
        DEBUG(2,("third stage: register as domain master\n"));
        /* add domain master name */
        add_my_name_entry(d,work->work_group,0x1b,NB_ACTIVE         );
      }
  
      break;
    }
    case MST_BROWSER: /* while we were still a master browser... */
    {
      work->state = MST_DOMAIN; /* registering WORKGROUP(1b) was successful */

      /* update our server status */
      if (lp_domain_master())
      {
        work->ServerType |= SV_TYPE_DOMAIN_MASTER;
      
        if (lp_domain_logons())
	    {
	      work->ServerType |= SV_TYPE_DOMAIN_CTRL;
	      work->ServerType |= SV_TYPE_DOMAIN_MEMBER;
	    }
        DEBUG(2,("fourth stage: samba is now a domain master.\n"));
        add_server_entry(d,work,myname,work->ServerType,0,ServerComment,True);
      }
  
      break;
    }
    case MST_DOMAIN:
    {
      /* nothing else to become, at the moment: we are top-dog. */
      DEBUG(2,("fifth stage: there isn't one yet!\n"));
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
  remove_type &= ~(SV_TYPE_MASTER_BROWSER|SV_TYPE_DOMAIN_MASTER);

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

  if (!(work->ServerType & SV_TYPE_DOMAIN_MASTER))
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
  time_t t = time(NULL);
  uint32 mycriterion;
  if (version > ELECTION_VERSION) return(False);
  if (version < ELECTION_VERSION) return(True);
  
  mycriterion = work->ElectionCriterion;

  if (criterion > mycriterion) return(False);
  if (criterion < mycriterion) return(True);

  if (timeup > (t - StartupTime)) return(False);
  if (timeup < (t - StartupTime)) return(True);

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
  
  name[15] = 0;  

  DEBUG(3,("Election request from %s vers=%d criterion=%08x timeup=%d\n",
	   name,version,criterion,timeup));
  
  if (same_context(dgram)) return;
  
  for (work = d->workgrouplist; work; work = work->next)
    {
      if (listening_name(work, &dgram->dest_name) && 
	  strequal(work->work_group, lp_workgroup()) &&
	  d->my_interface)
	{
	  if (win_election(work, version,criterion,timeup,name))
	    {
	      if (!work->RunningElection)
		{
		  work->needelection = True;
		  work->ElectionCount=0;
          work->state = MST_NONE;
		}
	    }
	  else
	    {
	      work->needelection = False;
	      
	      if (work->RunningElection)
		{
		  work->RunningElection = False;
		  DEBUG(3,(">>> Lost election on %s %s <<<\n",
			   work->work_group,inet_ntoa(d->bcast_ip)));
		  
		  /* if we are the master then remove our masterly names */
		  if (AM_MASTER(work))
		  {
		      become_nonmaster(d, work,
					SV_TYPE_MASTER_BROWSER|SV_TYPE_DOMAIN_MASTER);
		  }
		}
	    }
	}
    }
}


/****************************************************************************
  checks whether a browser election is to be run on any workgroup
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

