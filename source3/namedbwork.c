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
   
   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

   04 jul 96: lkcl@pires.co.uk
   created module namedbwork containing workgroup database functions

*/

#include "includes.h"
#include "smb.h"

extern int ClientNMB;

extern int DEBUGLEVEL;

/* this is our domain/workgroup/server database */
extern struct subnet_record *subnetlist;

extern struct in_addr wins_ip;

extern fstring myworkgroup;

int workgroup_count = 0; /* unique index key: one for each workgroup */



/****************************************************************************
  add a workgroup into the domain list
  **************************************************************************/
static void add_workgroup(struct work_record *work, struct subnet_record *d)
{
  struct work_record *w2;

  if (!work || !d) return;

  if (!d->workgrouplist)
    {
      d->workgrouplist = work;
      work->prev = NULL;
      work->next = NULL;
      return;
    }
  
  for (w2 = d->workgrouplist; w2->next; w2 = w2->next);
  
  w2->next = work;
  work->next = NULL;
  work->prev = w2;
}


/****************************************************************************
  create a blank workgroup 
  **************************************************************************/
static struct work_record *make_workgroup(char *name)
{
  struct work_record *work;
  struct subnet_record *d;
  int t = -1;
  
  if (!name || !name[0]) return NULL;
  
  work = (struct work_record *)malloc(sizeof(*work));
  if (!work) return(NULL);
  bzero((char *)work, sizeof(*work));
 
  StrnCpy(work->work_group,name,sizeof(work->work_group)-1);
  work->serverlist = NULL;
  
  /* set up initial value for server announce type */
  work->ServerType  = lp_default_server_announce();
  work->ServerType |= lp_local_master() ? SV_TYPE_POTENTIAL_BROWSER : 0;
  work->ServerType |= lp_domain_controller() ?  SV_TYPE_DOMAIN_CTRL : 0;

  work->RunningElection = False;
  work->ElectionCount = 0;
  work->announce_interval = 0;
  work->needelection = False;
  work->needannounce = True;
  work->mst_state = MST_POTENTIAL;
  work->dom_state = DOMAIN_NONE;
  work->log_state = LOGON_NONE;
  
  /* make sure all token representations of workgroups are unique */
  
  for (d = FIRST_SUBNET; d && t == -1; d = NEXT_SUBNET_INCLUDING_WINS(d))
    {
      struct work_record *w;
      for (w = d->workgrouplist; w && t == -1; w = w->next)
	{
	  if (strequal(w->work_group, work->work_group)) t = w->token;
	}
    }
  
  if (t == -1)
    {
      work->token = ++workgroup_count;
    }
  else
    {
      work->token = t;
    }
  
  
  /* WfWg  uses 01040b01 */
  /* Win95 uses 01041501 */
  /* NTAS  uses ???????? */
  work->ElectionCriterion  = (MAINTAIN_LIST)|(ELECTION_VERSION<<8); 
  work->ElectionCriterion |= (lp_os_level() << 24);
  if (lp_domain_master()) {
    work->ElectionCriterion |= 0x80;
  }
  
  return work;
}


/*******************************************************************
  remove workgroups
  ******************************************************************/
struct work_record *remove_workgroup(struct subnet_record *d, 
				     struct work_record *work,
					 BOOL remove_all_servers)
{
  struct work_record *ret_work = NULL;
  
  if (!d || !work) return NULL;
  
  DEBUG(3,("Removing old workgroup %s\n", work->work_group));
  
  ret_work = work->next;

  remove_old_servers(work, -1, remove_all_servers);
  
  if (!work->serverlist)
  {
    if (work->prev) work->prev->next = work->next;
    if (work->next) work->next->prev = work->prev;
  
    if (d->workgrouplist == work) d->workgrouplist = work->next; 
  
    free(work);
  }
  
  return ret_work;
}


/****************************************************************************
  find a workgroup in the workgrouplist 
  only create it if the domain allows it, or the parameter 'add' insists
  that it get created/added anyway. this allows us to force entries in
  lmhosts file to be added.
  **************************************************************************/
struct work_record *find_workgroupstruct(struct subnet_record *d, 
					 fstring name, BOOL add)
{
  struct work_record *ret, *work;
  
  if (!d) return NULL;
  
  DEBUG(4, ("workgroup search for %s: ", name));
  
  for (ret = d->workgrouplist; ret; ret = ret->next) {
    if (!strcmp(ret->work_group,name)) {
      DEBUG(4, ("found\n"));
      return(ret);
    }
  }

  if (!add) {
    DEBUG(4, ("not found\n"));
    return NULL;
  }

  DEBUG(4,("not found: creating\n"));
  
  if ((work = make_workgroup(name)))
    {
      if (!ip_equal(d->bcast_ip, wins_ip) &&
	  lp_preferred_master() && lp_local_master() &&
	  strequal(myworkgroup, name))
	{
	  DEBUG(3, ("preferred master startup for %s\n", work->work_group));
	  work->needelection = True;
	  work->ElectionCriterion |= (1<<3);
	}
      add_workgroup(work, d);
      return(work);
    }
  return NULL;
}


/****************************************************************************
  dump a copy of the workgroup/domain database
  **************************************************************************/
void dump_workgroups(void)
{
  struct subnet_record *d;
  
  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_INCLUDING_WINS(d))
    {
      if (d->workgrouplist)
	{
	  struct work_record *work;
	  
	  DEBUG(4,("dump domain bcast=%15s: ", inet_ntoa(d->bcast_ip)));
	  DEBUG(4,(" netmask=%15s:\n", inet_ntoa(d->mask_ip)));
	  
	  for (work = d->workgrouplist; work; work = work->next)
	    {
	      DEBUG(4,("\t%s(%d)\n", work->work_group, work->token));
	      if (work->serverlist)
		{
		  struct server_record *s;		  
		  for (s = work->serverlist; s; s = s->next)
		    {
		      DEBUG(4,("\t\t%s %8x (%s)\n",
			       s->serv.name, s->serv.type, s->serv.comment));
		    }
		}
	    }
	}
    }
}
