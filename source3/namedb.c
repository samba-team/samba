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
#include "smb.h"
#include "loadparm.h"

extern int ClientNMB;
extern int ClientDGRAM;

extern int DEBUGLEVEL;

extern time_t StartupTime;
extern pstring myname;
extern pstring scope;

/* this is our browse master/backup cache database */
struct browse_cache_record *browserlist = NULL;

/* this is our domain/workgroup/server database */
struct domain_record *domainlist = NULL;

static BOOL updatedlists = True;
int  updatecount=0;

int workgroup_count = 0; /* unique index key: one for each workgroup */

/* what server type are we currently */

#define DFLT_SERVER_TYPE (SV_TYPE_WORKSTATION | SV_TYPE_SERVER | \
			SV_TYPE_TIME_SOURCE | SV_TYPE_SERVER_UNIX | \
			SV_TYPE_PRINTQ_SERVER | SV_TYPE_POTENTIAL_BROWSER)

/* here are my election parameters */
#define MSBROWSE "\001\002__MSBROWSE__\002"


/****************************************************************************
  add a workgroup into the domain list
  **************************************************************************/
static void add_workgroup(struct work_record *work, struct domain_record *d)
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
  struct domain_record *d;
  int t = -1;
  
  if (!name || !name[0]) return NULL;
  
  work = (struct work_record *)malloc(sizeof(*work));
  if (!work) return(NULL);
  
  StrnCpy(work->work_group,name,sizeof(work->work_group)-1);
  work->serverlist = NULL;
  
  work->ServerType = DFLT_SERVER_TYPE;
  work->RunningElection = False;
  work->ElectionCount = 0;
  work->needelection = False;
  work->needannounce = True;
  
  /* make sure all token representations of workgroups are unique */
  
  for (d = domainlist; d && t == -1; d = d->next)
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
  work->ElectionCriterion  = (MAINTAIN_LIST<<1)|(ELECTION_VERSION<<8); 
  work->ElectionCriterion |= (lp_os_level() << 24);
  if (lp_domain_master()) {
    work->ElectionCriterion |= 0x80;
  }
  
  return work;
}


/*******************************************************************
  expire old servers in the serverlist
  time of -1 indicates everybody dies
  ******************************************************************/
static void remove_old_servers(struct work_record *work, time_t t)
{
  struct server_record *s;
  struct server_record *nexts;
  
  /* expire old entries in the serverlist */
  for (s = work->serverlist; s; s = nexts)
    {
      if (t == -1 || (s->death_time && s->death_time < t))
	{
	  DEBUG(3,("Removing dead server %s\n",s->serv.name));
	  updatedlists = True;
	  nexts = s->next;
	  
	  if (s->prev) s->prev->next = s->next;
	  if (s->next) s->next->prev = s->prev;
	  
	  if (work->serverlist == s) 
	    work->serverlist = s->next; 

	  free(s);
	}
      else
	{
	  nexts = s->next;
	}
    }
}


/*******************************************************************
  remove workgroups
  ******************************************************************/
struct work_record *remove_workgroup(struct domain_record *d, 
				     struct work_record *work)
{
  struct work_record *ret_work = NULL;
  
  if (!d || !work) return NULL;
  
  DEBUG(3,("Removing old workgroup %s\n", work->work_group));
  
  remove_old_servers(work, -1);
  
  ret_work = work->next;
  
  if (work->prev) work->prev->next = work->next;
  if (work->next) work->next->prev = work->prev;
  
  if (d->workgrouplist == work) d->workgrouplist = work->next; 
  
  free(work);
  
  return ret_work;
}


/****************************************************************************
  add a domain into the list
  **************************************************************************/
static void add_domain(struct domain_record *d)
{
  struct domain_record *d2;

  if (!domainlist)
  {
    domainlist = d;
    d->prev = NULL;
    d->next = NULL;
    return;
  }

  for (d2 = domainlist; d2->next; d2 = d2->next);

  d2->next = d;
  d->next = NULL;
  d->prev = d2;
}

/***************************************************************************
  add a browser into the list
  **************************************************************************/
static void add_browse_cache(struct browse_cache_record *b)
{
  struct browse_cache_record *b2;

  if (!browserlist)
    {
      browserlist = b;
      b->prev = NULL;
      b->next = NULL;
      return;
    }
  
  for (b2 = browserlist; b2->next; b2 = b2->next) ;
  
  b2->next = b;
  b->next = NULL;
  b->prev = b2;
}


/***************************************************************************
  add a server into the list
  **************************************************************************/
static void add_server(struct work_record *work,struct server_record *s)
{
  struct server_record *s2;

  if (!work->serverlist) {
    work->serverlist = s;
    s->prev = NULL;
    s->next = NULL;
    return;
  }

  for (s2 = work->serverlist; s2->next; s2 = s2->next) ;

  s2->next = s;
  s->next = NULL;
  s->prev = s2;
}


/*******************************************************************
  remove old browse entries
  ******************************************************************/
void expire_browse_cache(time_t t)
{
  struct browse_cache_record *b;
  struct browse_cache_record *nextb;
  
  /* expire old entries in the serverlist */
  for (b = browserlist; b; b = nextb)
    {
      if (b->synced && b->sync_time < t)
	{
	  DEBUG(3,("Removing dead cached browser %s\n",b->name));
	  nextb = b->next;
	  
	  if (b->prev) b->prev->next = b->next;
	  if (b->next) b->next->prev = b->prev;
	  
	  if (browserlist == b) browserlist = b->next; 
	  
	  free(b);
	}
      else
	{
	  nextb = b->next;
	}
    }
}


/****************************************************************************
  find a workgroup in the workgrouplist 
  only create it if the domain allows it, or the parameter 'add' insists
  that it get created/added anyway. this allows us to force entries in
  lmhosts file to be added.
  **************************************************************************/
struct work_record *find_workgroupstruct(struct domain_record *d, 
					 fstring name, BOOL add)
{
  struct work_record *ret, *work;
  
  if (!d) return NULL;
  
  DEBUG(4, ("workgroup search for %s: ", name));
  
  if (strequal(name, "*"))
    {
      DEBUG(2,("add any workgroups: initiating browser search on %s\n",
	       inet_ntoa(d->bcast_ip)));
      queue_netbios_pkt_wins(ClientNMB,NMB_QUERY, FIND_MASTER,
			     MSBROWSE,0x1,0,
			     True,False, d->bcast_ip);
      return NULL;
    }
  
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
      if (lp_preferred_master() &&
	  strequal(lp_workgroup(), name) &&
	  ismybcast(d->bcast_ip))
	{
	  DEBUG(3, ("preferred master startup for %s\n", work->work_group));
	  work->needelection = True;
	  work->ElectionCriterion |= (1<<3);
	}
      if (!ismybcast(d->bcast_ip))
	{
	  work->needelection = False;
	}
      add_workgroup(work, d);
      return(work);
    }
  return NULL;
}

/****************************************************************************
  find a domain in the domainlist 
  **************************************************************************/
struct domain_record *find_domain(struct in_addr source_ip)
{   
  struct domain_record *d;
  
  /* search through domain list for broadcast/netmask that matches
     the source ip address */
  
  for (d = domainlist; d; d = d->next)
    {
      if (same_net(source_ip, d->bcast_ip, d->mask_ip))
	{
	  return(d);
	}
    }
  
  return (NULL);
}


/****************************************************************************
  dump a copy of the workgroup/domain database
  **************************************************************************/
void dump_workgroups(void)
{
  struct domain_record *d;
  
  for (d = domainlist; d; d = d->next)
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

/****************************************************************************
  create a domain entry
  ****************************************************************************/
static struct domain_record *make_domain(struct in_addr ip, struct in_addr mask)
{
  struct domain_record *d;
  d = (struct domain_record *)malloc(sizeof(*d));
  
  if (!d) return(NULL);
  
  bzero((char *)d,sizeof(*d));
  
  DEBUG(4, ("making domain %s ", inet_ntoa(ip)));
  DEBUG(4, ("%s\n", inet_ntoa(mask)));
  
  d->bcast_ip = ip;
  d->mask_ip  = mask;
  d->workgrouplist = NULL;
  
  add_domain(d);
  
  return d;
}

/****************************************************************************
  add a domain entry. creates a workgroup, if necessary, and adds the domain
  to the named a workgroup.
  ****************************************************************************/
struct domain_record *add_domain_entry(struct in_addr source_ip, 
				       struct in_addr source_mask,
				       char *name, BOOL add)
{
  struct domain_record *d;
  struct in_addr ip;
  
  ip = *interpret_addr2("255.255.255.255");
  
  if (zero_ip(source_ip)) 
    source_ip = *iface_bcast(source_ip);
  
  /* add the domain into our domain database */
  if ((d = find_domain(source_ip)) ||
      (d = make_domain(source_ip, source_mask)))
    {
      struct work_record *w = find_workgroupstruct(d, name, add);
      
      /* add WORKGROUP(1e) and WORKGROUP(00) entries into name database
	 or register with WINS server, if it's our workgroup */
      if (strequal(lp_workgroup(), name))
	{
	  extern pstring ServerComment;
	  add_name_entry(name,0x1e,NB_ACTIVE|NB_GROUP);
	  add_name_entry(name,0x0 ,NB_ACTIVE|NB_GROUP);
	  add_server_entry(d,w,myname,w->ServerType,0,ServerComment,True);
	}
      
      DEBUG(3,("Added domain name entry %s at %s\n", name,inet_ntoa(ip)));
      return d;
    }
  return NULL;
}

/****************************************************************************
  add a browser entry
  ****************************************************************************/
struct browse_cache_record *add_browser_entry(char *name, int type, char *wg,
					      time_t ttl, struct in_addr ip)
{
  BOOL newentry=False;
  
  struct browse_cache_record *b;

  /* search for the entry: if it's already in the cache, update that entry */
  for (b = browserlist; b; b = b->next)
    {
      if (ip_equal(ip,b->ip) && strequal(b->group, wg)) break;
    }
  
  if (b && b->synced)
    {
      /* entries get left in the cache for a while. this stops sync'ing too
	 often if the network is large */
      DEBUG(4, ("browser %s %s %s already sync'd at time %d\n",
		b->name, b->group, inet_ntoa(b->ip), b->sync_time));
      return NULL;
    }
  
  if (!b)
    {
      newentry = True;
      b = (struct browse_cache_record *)malloc(sizeof(*b));
      
      if (!b) return(NULL);
      
      bzero((char *)b,sizeof(*b));
    }
  
  /* update the entry */
  ttl = time(NULL)+ttl;
  
  StrnCpy(b->name ,name,sizeof(b->name )-1);
  StrnCpy(b->group,wg  ,sizeof(b->group)-1);
  strupper(b->name);
  strupper(b->group);
  
  b->ip     = ip;
  b->type   = type;
  
  if (newentry || ttl < b->sync_time) 
    b->sync_time = ttl;
  
  if (newentry)
    {
      b->synced = False;
      add_browse_cache(b);
      
      DEBUG(3,("Added cache entry %s %s(%2x) %s ttl %d\n",
	       wg, name, type, inet_ntoa(ip),ttl));
    }
  else
    {
      DEBUG(3,("Updated cache entry %s %s(%2x) %s ttl %d\n",
	       wg, name, type, inet_ntoa(ip),ttl));
    }
  
  return(b);
}


/****************************************************************************
  add a server entry
  ****************************************************************************/
struct server_record *add_server_entry(struct domain_record *d, 
				       struct work_record *work,
				       char *name,int servertype, 
				       int ttl,char *comment,
				       BOOL replace)
{
  BOOL newentry=False;
  struct server_record *s;
  
  if (name[0] == '*')
    {
      return (NULL);
    }
  
  for (s = work->serverlist; s; s = s->next)
    {
      if (strequal(name,s->serv.name)) break;
    }
  
  if (s && !replace)
    {
      DEBUG(4,("Not replacing %s\n",name));
      return(s);
    }
  
  updatedlists=True;
  
  if (!s)
    {
      newentry = True;
      s = (struct server_record *)malloc(sizeof(*s));
      
      if (!s) return(NULL);
      
      bzero((char *)s,sizeof(*s));
    }
  
  if (ismybcast(d->bcast_ip) &&
      strequal(lp_workgroup(),work->work_group))
    {
      servertype |= SV_TYPE_LOCAL_LIST_ONLY;
    }
  else
    {
      servertype &= ~SV_TYPE_LOCAL_LIST_ONLY;
    }
  
  /* update the entry */
  StrnCpy(s->serv.name,name,sizeof(s->serv.name)-1);
  StrnCpy(s->serv.comment,comment,sizeof(s->serv.comment)-1);
  strupper(s->serv.name);
  s->serv.type  = servertype;
  s->death_time = ttl?time(NULL)+ttl*3:0;
  
  /* for a domain entry, the comment field refers to the server name */
  
  if (s->serv.type & SV_TYPE_DOMAIN_ENUM) strupper(s->serv.comment);
  
  if (newentry)
    {
      add_server(work, s);
      
      DEBUG(3,("Added "));
    }
  else
    {
      DEBUG(3,("Updated "));
    }
  
  DEBUG(3,("server entry %s of type %x (%s) to %s %s\n",
	   name,servertype,comment,
	   work->work_group,inet_ntoa(d->bcast_ip)));
  
  return(s);
}


/*******************************************************************
  write out browse.dat
  ******************************************************************/
void write_browse_list(void)
{
  struct domain_record *d;
  
  pstring fname,fnamenew;
  FILE *f;
  
  if (!updatedlists) return;
  
  dump_names();
  dump_workgroups();
  
  updatedlists = False;
  updatecount++;
  
  strcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,SERVER_LIST);
  strcpy(fnamenew,fname);
  strcat(fnamenew,".");
  
  f = fopen(fnamenew,"w");
  
  if (!f)
    {
      DEBUG(4,("Can't open %s - %s\n",fnamenew,strerror(errno)));
      return;
    }
  
  for (d = domainlist; d ; d = d->next)
    {
      struct work_record *work;
      for (work = d->workgrouplist; work ; work = work->next)
	{
	  struct server_record *s;
	  for (s = work->serverlist; s ; s = s->next)
	    {
	      fstring tmp;
	      
	      /* don't list domains I don't have a master for */
	      if ((s->serv.type & SV_TYPE_DOMAIN_ENUM) &&
		  !s->serv.comment[0])
		{
		  continue;
		}
	      
	      /* output server details, plus what workgroup/domain
		 they're in. without the domain information, the
		 combined list of all servers in all workgroups gets
		 sent to anyone asking about any workgroup! */
	      
	      sprintf(tmp, "\"%s\"", s->serv.name);
	      fprintf(f, "%-25s ", tmp);
	      fprintf(f, "%08x ", s->serv.type);
	      sprintf(tmp, "\"%s\" ", s->serv.comment);
	      fprintf(f, "%-30s", tmp);
	      fprintf(f, "\"%s\"\n", work->work_group);
	    }
	}
    }
  
  fclose(f);
  unlink(fname);
  chmod(fnamenew,0644);
  rename(fnamenew,fname);   
  DEBUG(3,("Wrote browse list %s\n",fname));
}


/*******************************************************************
  expire old servers in the serverlist
  ******************************************************************/
void expire_servers(time_t t)
{
  struct domain_record *d;
  
  for (d = domainlist ; d ; d = d->next)
    {
      struct work_record *work;
      
      for (work = d->workgrouplist; work; work = work->next)
	{
	  remove_old_servers(work, t);
	}
    }
}

