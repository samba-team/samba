/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1997
   
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
extern fstring myworkgroup;
extern struct in_addr ipzero;
extern struct in_addr wins_ip;

/* here are my election parameters */

extern time_t StartupTime;

extern struct subnet_record *subnetlist;

extern uint16 nb_type; /* samba's NetBIOS name type */


/*******************************************************************
  occasionally check to see if the master browser is around
  ******************************************************************/
void check_master_browser(time_t t)
{
  static time_t lastrun=0;
  struct subnet_record *d;

  if (!lastrun) lastrun = t;
  if (t < lastrun + CHECK_TIME_MST_BROWSE * 60) return;

  lastrun = t;

  dump_workgroups();

  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_EXCLUDING_WINS(d))
  {
    struct work_record *work;

    for (work = d->workgrouplist; work; work = work->next)
    {
      if (strequal(work->work_group, myworkgroup) && !AM_MASTER(work))
      {
        if (lp_local_master() && lp_preferred_master())
        {
          /* potential master browser - not a master browser.  force
             becoming a master browser, hence the log message.
           */

          DEBUG(2,("%s potential master for %s %s - force election\n",
                   timestring(), work->work_group,
                   inet_ntoa(d->bcast_ip)));

          browser_gone(work->work_group, d->bcast_ip);
        }
        else
        {
          /* if we are not the browse master of a workgroup,
             and we can't find a browser on the subnet, do
             something about it.
           */

          queue_netbios_packet(d,ClientNMB,NMB_QUERY,NAME_QUERY_MST_CHK,
                    work->work_group,0x1d,0,0,0,NULL,NULL,
                    True,False,d->bcast_ip,d->bcast_ip, 0);
        }
      }
    }
  }
}


/*******************************************************************
  what to do if a master browser DOESN't exist.

  option 1: force an election, and participate in it
  option 2: force an election, and let everyone else participate.

  ******************************************************************/
void browser_gone(char *work_name, struct in_addr ip)
{
  struct subnet_record *d = find_subnet(ip);
  struct work_record *work = find_workgroupstruct(d, work_name, False);

  /* i don't know about this workgroup, therefore i don't care */
  if (!work || !d) return;

  /* don't do election stuff on the WINS subnet */
  if (ip_equal(d->bcast_ip,wins_ip)) 
    return;

  if (strequal(work->work_group, myworkgroup))
  {

    if (lp_local_master())
    {
      /* we have discovered that there is no local master
         browser, and we are configured to initiate
         an election under exactly such circumstances.
       */
      DEBUG(2,("Forcing election on %s %s\n",
	       work->work_group,inet_ntoa(d->bcast_ip)));

      /* we can attempt to become master browser */
      work->needelection = True;
    }
    else
    {
      /* we need to force an election, because we are configured
         not to _become_ the local master, but we still _need_ one,
         having detected that one doesn't exist.
       */

      /* local interfaces: force an election */
      send_election(d, work->work_group, 0, 0, myname);

      /* only removes workgroup completely on a local interface 
         persistent lmhosts entries on a local interface _will_ be removed).
       */
      remove_workgroup(d, work,True);
      add_workgroup_to_subnet(d, work->work_group);
    }
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
  pstrcpy(p,name);
  strupper(p);
  p = skip_string(p,1);
  
  send_mailslot_reply(False,BROWSE_MAILSLOT,ClientDGRAM,
              outbuf,PTR_DIFF(p,outbuf),
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
    int remove_type_local  = 0;
    int remove_type_domain = 0;
    int remove_type_logon  = 0;

    remove_netbios_name(d,name,name_type,SELF,ipzero);

    if (!(work = find_workgroupstruct(d, name, False))) return;

    /* work out what to unbecome, from the name type being removed */

    if (ms_browser_name(name, name_type))
    {
      remove_type_local |= SV_TYPE_MASTER_BROWSER;
    }
    if (AM_MASTER(work) && strequal(name, myworkgroup) && name_type == 0x1d)
    {
      remove_type_local |= SV_TYPE_MASTER_BROWSER;
    }
    if (AM_DOMMST(work) && strequal(name, myworkgroup) && name_type == 0x1b)
    {
      remove_type_domain |= SV_TYPE_DOMAIN_MASTER;
    }
    if (AM_DOMMEM(work) && strequal(name, myworkgroup) && name_type == 0x1c)
    {
      remove_type_logon|= SV_TYPE_DOMAIN_MEMBER;
    }

    if (remove_type_local ) unbecome_local_master (d, work, remove_type_local );
    if (remove_type_domain) unbecome_domain_master(d, work, remove_type_domain);
    if (remove_type_logon ) unbecome_logon_server (d, work, remove_type_logon );
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
      struct work_record *work = find_workgroupstruct(d, 
                                  myworkgroup, False);

      add_netbios_entry(d,name,name_type,nb_flags,ttl,source,ip,True,!bcast);

      if (work)
      {
        int add_type_local  = False;
        int add_type_domain = False;
        int add_type_logon  = False;

        DEBUG(4,("checking next stage: name_register_work %s\n", name));

        /* work out what to become, from the name type being added */

        if (ms_browser_name(name, name_type))
        {
          add_type_local = True;
        }
        if (strequal(name, myworkgroup) && name_type == 0x1d)
        {
          add_type_local = True;
        }
        if (strequal(name, myworkgroup) && name_type == 0x1b)
        {
          add_type_domain = True;
        }
        if (strequal(name, myworkgroup) && name_type == 0x1c)
        {
          add_type_logon = True;
        }

        if (add_type_local ) become_local_master (d, work);
        if (add_type_domain) become_domain_master(d, work);
        if (add_type_logon ) become_logon_server (d, work);
      }
    }
}


/*******************************************************************
  become the local master browser.

  this is done in stages. note that this could take a while, 
  particularly on a broadcast subnet, as we have to wait for
  the implicit registration of each name to be accepted.

  as each name is successfully registered, become_local_master() is
  called again, in order to initiate the next stage. see
  dead_netbios_entry() - deals with implicit name registration
  and response_name_reg() - deals with explicit registration
  with a WINS server.

  stage 1: was MST_POTENTIAL - go to MST_POTENTIAL and register ^1^2__MSBROWSE__^2^1.
  stage 2: was MST_BACK  - go to MST_MSB  and register WORKGROUP(0x1d)
  stage 3: was MST_MSB  - go to MST_BROWSER and stay there 

  XXXX note: this code still does not cope with the distinction
  between different types of nodes, particularly between M and P
  nodes. that comes later.

  ******************************************************************/
void become_local_master(struct subnet_record *d, struct work_record *work)
{
  /* domain type must be limited to domain enum + server type. it must
     not have SV_TYPE_SERVER or anything else with SERVER in it, else
     clients get confused and start thinking this entry is a server
     not a workgroup
   */
  uint32 domain_type = SV_TYPE_DOMAIN_ENUM|SV_TYPE_NT;

  if (!work || !d) 
    return;
  
  if (!lp_local_master())
  { 
    DEBUG(0,("Samba not configured as a local master browser.\n"));
    return;
  }

  DEBUG(2,("Becoming master for %s %s (currently at stage %d)\n",
           work->work_group,inet_ntoa(d->bcast_ip),work->mst_state));
  
  switch (work->mst_state)
  {
    case MST_POTENTIAL: /* while we were nothing but a server... */
    {
      DEBUG(3,("go to first stage: register ^1^2__MSBROWSE__^2^1\n"));
      work->mst_state = MST_BACK; /* an election win was successful */

      work->ElectionCriterion |= 0x5;

      /* update our server status */
      work->ServerType &= ~SV_TYPE_POTENTIAL_BROWSER;
      add_server_entry(d,work,myname,work->ServerType|SV_TYPE_LOCAL_LIST_ONLY,
				0,lp_serverstring(),True);

      /* add special browser name */
      add_my_name_entry(d,MSBROWSE,0x01,nb_type|NB_ACTIVE|NB_GROUP);

      /* DON'T do anything else after calling add_my_name_entry() */
      break;
    }

    case MST_BACK: /* while nothing had happened except we won an election... */
    {
      DEBUG(3,("go to second stage: register as master browser\n"));
      work->mst_state = MST_MSB; /* registering MSBROWSE was successful */

      /* add server entry on successful registration of MSBROWSE */
      add_server_entry(d,work,work->work_group,domain_type|SV_TYPE_LOCAL_LIST_ONLY,
				0,myname,True);

      /* add master name */
      add_my_name_entry(d,work->work_group,0x1d,nb_type|NB_ACTIVE);
  
      /* DON'T do anything else after calling add_my_name_entry() */
      break;
    }

    case MST_MSB: /* while we were still only registered MSBROWSE state... */
    {
      int i = 0;
      struct server_record *sl;

      DEBUG(3,("2nd stage complete: registered as master browser for workgroup %s \
on subnet %s\n", work->work_group, inet_ntoa(d->bcast_ip)));
      work->mst_state = MST_BROWSER; /* registering WORKGROUP(1d) succeeded */

      /* update our server status */
      work->ServerType |= SV_TYPE_MASTER_BROWSER;

      DEBUG(3,("become_local_master: updating our server %s to type %x\n", 
                myname, work->ServerType));

      add_server_entry(d,work,myname,work->ServerType|SV_TYPE_LOCAL_LIST_ONLY,
				0,lp_serverstring(),True);

      /* Count the number of servers we have on our list. If it's
         less than 10 (just a heuristic) request the servers
         to announce themselves.
       */
      for( sl = work->serverlist; sl != NULL; sl = sl->next)
        i++;

      if (i < 10)
      {
        /* ask all servers on our local net to announce to us */
        announce_request(work, d->bcast_ip);
      }

      /* Reset the announce master timer so that we do an announce as soon as possible
         now we are a master. */
      reset_announce_timer();

      DEBUG(0,("Samba is now a local master browser for workgroup %s on subnet %s\n", 
                work->work_group, inet_ntoa(d->bcast_ip)));

      break;
    }

    case MST_BROWSER:
    {
      /* don't have to do anything: just report success */
      DEBUG(3,("3rd stage: become master browser!\n"));
      break;
    }
  }
}


/*******************************************************************
  become the domain master browser.

  this is done in stages. note that this could take a while, 
  particularly on a broadcast subnet, as we have to wait for
  the implicit registration of each name to be accepted.

  as each name is successfully registered, become_domain_master() is
  called again, in order to initiate the next stage. see
  dead_netbios_entry() - deals with implicit name registration
  and response_name_reg() - deals with explicit registration
  with a WINS server.

  stage 1: was DOMAIN_NONE - go to DOMAIN_MST 

  XXXX note: this code still does not cope with the distinction
  between different types of nodes, particularly between M and P
  nodes. that comes later.

  ******************************************************************/
void become_domain_master(struct subnet_record *d, struct work_record *work)
{
	/* domain type must be limited to domain enum + server type. it must
	not have SV_TYPE_SERVER or anything else with SERVER in it, else
	clients get confused and start thinking this entry is a server
	not a workgroup
	*/

	if (!work || !d) return;

	if (!lp_domain_master())
	{ 
		DEBUG(0,("Samba not configured as a domain master browser.\n"));
		return;
	}

	DEBUG(2,("Becoming domain master for %s %s (currently at stage %d)\n",
	work->work_group,inet_ntoa(d->bcast_ip),work->dom_state));

	switch (work->dom_state)
	{
		case DOMAIN_NONE: /* while we were nothing but a server... */
		{
			DEBUG(3,("become_domain_master: go to first stage: register <1b> name\n"));
			work->dom_state = DOMAIN_WAIT;

			/* XXXX the 0x1b is domain master browser name */
			add_my_name_entry(d, work->work_group,0x1b,nb_type|NB_ACTIVE);

			/* DON'T do anything else after calling add_my_name_entry() */
			break;
		}

		case DOMAIN_WAIT:
		{
			work->dom_state = DOMAIN_MST; /* ... become domain master */
			DEBUG(3,("become_domain_master: first stage - register as domain member\n"));

			/* update our server status */
			work->ServerType |= SV_TYPE_NT|SV_TYPE_DOMAIN_MASTER;
			add_server_entry(d,work,myname,work->ServerType|SV_TYPE_LOCAL_LIST_ONLY,
			                 0, lp_serverstring(),True);

			DEBUG(0,("Samba is now a domain master browser for workgroup %s on subnet %s\n", 
			work->work_group, inet_ntoa(d->bcast_ip)));

			if (d == wins_subnet)
			{
				/* ok! we successfully registered by unicast with the
				   WINS server.  we now expect to become the domain
				   master on the local subnets.  if this fails, it's
				   probably a 1.9.16p2 to 1.9.16p11 server's fault.

				   this is a configuration issue that should be addressed
				   by the network administrator - you shouldn't have
				   several machines configured as a domain master browser
				   for the same WINS scope (except if they are 1.9.17 or
				   greater, and you know what you're doing.

				   see DOMAIN.txt.

				 */
				add_domain_master_bcast();
			}
			break;
		}

		case DOMAIN_MST:
		{
			/* don't have to do anything: just report success */
			DEBUG(3,("domain second stage: there isn't one!\n"));
			break;
		}
	}
}


/*******************************************************************
  become a logon server.
  ******************************************************************/
void become_logon_server(struct subnet_record *d, struct work_record *work)
{
  if (!work || !d) return;
  
  if (!lp_domain_logons())
  {
    DEBUG(0,("samba not configured as a logon master.\n"));
    return;
  }

  DEBUG(2,("Becoming logon server for %s %s (currently at stage %d)\n",
	work->work_group,inet_ntoa(d->bcast_ip),work->log_state));
  
  switch (work->log_state)
  {
    case LOGON_NONE: /* while we were nothing but a server... */
    {
      DEBUG(3,("go to first stage: register <1c> name\n"));
            work->log_state = LOGON_WAIT;

     /* XXXX the 0x1c is apparently something to do with domain logons */
     add_my_name_entry(d, myworkgroup,0x1c,nb_type|NB_ACTIVE|NB_GROUP);

      /* DON'T do anything else after calling add_my_name_entry() */
      break;
    }

    case LOGON_WAIT:
    {
      work->log_state = LOGON_SRV; /* ... become logon server */
      DEBUG(3,("logon second stage: register \n"));
 
      /* update our server status */
      work->ServerType |= SV_TYPE_NT|SV_TYPE_DOMAIN_MEMBER;
      add_server_entry(d,work,myname,work->ServerType|SV_TYPE_LOCAL_LIST_ONLY
					,0, lp_serverstring(),True);

      /* DON'T do anything else after calling add_my_name_entry() */
      break;
    }

    case LOGON_SRV:
    {
      DEBUG(3,("logon third stage: there isn't one!\n"));
      break;
    }
  }
}


/*******************************************************************
  unbecome the local master browser. initates removal of necessary netbios 
  names, and tells the world that we are no longer a master browser.

  XXXX this _should_ be used to demote to a backup master browser, without
  going straight to non-master browser.  another time.

  ******************************************************************/
void unbecome_local_master(struct subnet_record *d, struct work_record *work,
				int remove_type)
{
  int new_server_type = work->ServerType;

  /* can only remove master types with this function */
  remove_type &= SV_TYPE_MASTER_BROWSER;

  new_server_type &= ~remove_type;

  if (remove_type)
  {
    DEBUG(2,("Becoming local non-master for %s\n",work->work_group));
  
    /* no longer a master browser of any sort */

    work->ServerType |= SV_TYPE_POTENTIAL_BROWSER;
    work->ElectionCriterion &= ~0x4;
    work->mst_state = MST_POTENTIAL;

	/* announce ourselves as no longer active as a master browser. */
    announce_server(d, work, work->work_group, myname, 0, 0);
    remove_name_entry(d,MSBROWSE        ,0x01);
    remove_name_entry(d,work->work_group,0x1d);
  }
}


/*******************************************************************
  unbecome the domain master browser. initates removal of necessary netbios 
  names, and tells the world that we are no longer a domain browser.
  ******************************************************************/
void unbecome_domain_master(struct subnet_record *d, struct work_record *work,
				int remove_type)
{
  int new_server_type = work->ServerType;

  DEBUG(2,("Becoming domain non-master for %s\n",work->work_group));
  
  /* can only remove master or domain types with this function */
  remove_type &= SV_TYPE_DOMAIN_MASTER;

  new_server_type &= ~remove_type;

  if (remove_type)
  {
    /* no longer a domain master browser of any sort */

    work->dom_state = DOMAIN_NONE;

    /* announce ourselves as no longer active as a master browser on
       all our local subnets. */
    for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_EXCLUDING_WINS(d))
    {
      work = find_workgroupstruct(d, myworkgroup, False);

      announce_server(d, work, work->work_group, myname, 0, 0);
      /* Remove the name entry without any NetBIOS traffic as that's
         how it was registered. */
      remove_name_entry(d,work->work_group,0x1b);    
    }

    /* Unregister the 1b name from the WINS server. */
    if(wins_subnet != NULL)
      remove_name_entry(wins_subnet, myworkgroup, 0x1b);
  }
}


/*******************************************************************
  unbecome the logon server. initates removal of necessary netbios 
  names, and tells the world that we are no longer a logon server.
  ******************************************************************/
void unbecome_logon_server(struct subnet_record *d, struct work_record *work,
				int remove_type)
{
  int new_server_type = work->ServerType;

  DEBUG(2,("Becoming logon non-server for %s\n",work->work_group));
  
  /* can only remove master or domain types with this function */
  remove_type &= SV_TYPE_DOMAIN_MEMBER;

  new_server_type &= ~remove_type;

  if (remove_type)
  {
    /* no longer a master browser of any sort */

    work->log_state = LOGON_NONE;

	/* announce ourselves as no longer active as a master browser. */
    announce_server(d, work, work->work_group, myname, 0, 0);
    remove_name_entry(d,work->work_group,0x1c);    
  }
}


/*******************************************************************
  run the election
  ******************************************************************/
void run_elections(time_t t)
{
  static time_t lastime = 0;
  
  struct subnet_record *d;
  
  /* send election packets once a second */
  if (lastime && t-lastime <= 0) return;
  
  lastime = t;
  
  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_EXCLUDING_WINS(d))
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
		  work->mst_state = MST_POTENTIAL;

		  become_local_master(d, work);
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

  /* If local master is false then never win
     in election broadcasts. */
  if(!lp_local_master())
  {
    DEBUG(3,("win_election: Losing election as local master == False\n"));
    return False;
  }
 
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

	if (ip_equal(d->bcast_ip,wins_ip))
	{
		DEBUG(0,("Unexpected election request from %s %s on WINS net\n",
		          name, inet_ntoa(p->ip)));
		return;
	}

	name[15] = 0;  

	DEBUG(3,("Election request from %s %s vers=%d criterion=%08x timeup=%d\n",
	          name,inet_ntoa(p->ip),version,criterion,timeup));

	if (same_context(dgram)) return;

	for (work = d->workgrouplist; work; work = work->next)
	{
		if (!strequal(work->work_group, myworkgroup))
		continue;

		if (win_election(work, version,criterion,timeup,name))
		{
			if (!work->RunningElection)
			{
				work->needelection = True;
				work->ElectionCount=0;
				work->mst_state = MST_POTENTIAL;
			}
		}
		else
		{
			work->needelection = False;

			if (work->RunningElection || AM_MASTER(work))
			{
				work->RunningElection = False;
				DEBUG(3,(">>> Lost election on %s %s <<<\n",
						  work->work_group,inet_ntoa(d->bcast_ip)));
				if (AM_MASTER(work))
				{
					unbecome_local_master(d, work, SV_TYPE_MASTER_BROWSER);
				}
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

  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_EXCLUDING_WINS(d))
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

