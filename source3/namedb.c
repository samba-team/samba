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

extern int ClientNMB;
extern int ClientDGRAM;

extern int DEBUGLEVEL;

extern time_t StartupTime;
extern pstring myname;
extern pstring scope;

extern struct in_addr ipgrp;
extern struct in_addr ipzero;

/* local interfaces structure */
extern struct interface *local_interfaces;

/* remote interfaces structure */
extern struct interface *remote_interfaces;

/* this is our domain/workgroup/server database */
struct subnet_record *subnetlist = NULL;

static BOOL updatedlists = True;
int  updatecount=0;

int workgroup_count = 0; /* unique index key: one for each workgroup */

/* what server type are we currently */

#define DFLT_SERVER_TYPE (SV_TYPE_WORKSTATION | SV_TYPE_SERVER | \
			SV_TYPE_TIME_SOURCE | SV_TYPE_SERVER_UNIX | \
			SV_TYPE_PRINTQ_SERVER | SV_TYPE_POTENTIAL_BROWSER)


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
  
  StrnCpy(work->work_group,name,sizeof(work->work_group)-1);
  work->serverlist = NULL;
  
  work->ServerType = DFLT_SERVER_TYPE;
  work->RunningElection = False;
  work->ElectionCount = 0;
  work->needelection = False;
  work->needannounce = True;
  
  /* make sure all token representations of workgroups are unique */
  
  for (d = subnetlist; d && t == -1; d = d->next)
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
struct work_record *remove_workgroup(struct subnet_record *d, 
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
static void add_subnet(struct subnet_record *d)
{
  struct subnet_record *d2;

  if (!subnetlist)
  {
    subnetlist = d;
    d->prev = NULL;
    d->next = NULL;
    return;
  }

  for (d2 = subnetlist; d2->next; d2 = d2->next);

  d2->next = d;
  d->next = NULL;
  d->prev = d2;
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
  
  if (strequal(name, "*"))
    {
      DEBUG(2,("add any workgroups: initiating browser search on %s\n",
	       inet_ntoa(d->bcast_ip)));
      queue_netbios_pkt_wins(d,ClientNMB,NMB_QUERY, NAME_QUERY_FIND_MST,
			     MSBROWSE,0x1,0,0,
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
	  d->my_interface)
	{
	  DEBUG(3, ("preferred master startup for %s\n", work->work_group));
	  work->needelection = True;
	  work->ElectionCriterion |= (1<<3);
	}
      if (!d->my_interface)
	{
	  work->needelection = False;
	}
      add_workgroup(work, d);
      return(work);
    }
  return NULL;
}

/****************************************************************************
  find a subnet in the subnetlist 
  **************************************************************************/
struct subnet_record *find_subnet(struct in_addr bcast_ip)
{   
  struct subnet_record *d;
  struct in_addr wins_ip = ipgrp;
  
  /* search through subnet list for broadcast/netmask that matches
     the source ip address. a subnet 255.255.255.255 represents the
     WINS list. */
  
  for (d = subnetlist; d; d = d->next)
    {
        if (ip_equal(bcast_ip, wins_ip))
	    {
           if (ip_equal(bcast_ip, d->bcast_ip))
           {
               return d;
           }
        }
        else if (same_net(bcast_ip, d->bcast_ip, d->mask_ip))
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
  struct subnet_record *d;
  
  for (d = subnetlist; d; d = d->next)
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
static struct subnet_record *make_subnet(struct in_addr bcast_ip, struct in_addr mask_ip)
{
  struct subnet_record *d;
  d = (struct subnet_record *)malloc(sizeof(*d));
  
  if (!d) return(NULL);
  
  bzero((char *)d,sizeof(*d));
  
  DEBUG(4, ("making domain %s ", inet_ntoa(bcast_ip)));
  DEBUG(4, ("%s\n", inet_ntoa(mask_ip)));
  
  d->bcast_ip = bcast_ip;
  d->mask_ip  = mask_ip;
  d->workgrouplist = NULL;
  d->my_interface = False; /* True iff the interface is on the samba host */
  
  add_subnet(d);
  
  return d;
}


/****************************************************************************
  add the remote interfaces from lp_remote_interfaces() and lp_interfaces()
  to the netbios subnet database.
  ****************************************************************************/
void add_subnet_interfaces(void)
{
	struct interface *i;

	/* loop on all local interfaces */
	for (i = local_interfaces; i; i = i->next)
	{
		/* add the interface into our subnet database */
		if (!find_subnet(i->bcast))
		{
		    struct subnet_record *d = make_subnet(i->bcast,i->nmask);
			if (d)
			{
				/* short-cut method to identifying local interfaces */
				d->my_interface = True;
			}
		}
	}

	/* loop on all remote interfaces */
	for (i = remote_interfaces; i; i = i->next)
	{
		/* add the interface into our subnet database */
		if (!find_subnet(i->bcast))
		{
		    make_subnet(i->bcast,i->nmask);
		}
	}

	/* add the pseudo-ip interface for WINS: 255.255.255.255 */
	if (lp_wins_support())
    {
		struct in_addr wins_bcast = ipgrp;
		struct in_addr wins_nmask = ipzero;
		make_subnet(wins_bcast, wins_nmask);
    }
}


/****************************************************************************
  add a domain entry. creates a workgroup, if necessary, and adds the domain
  to the named a workgroup.
  ****************************************************************************/
struct subnet_record *add_subnet_entry(struct in_addr bcast_ip, 
				       struct in_addr mask_ip,
				       char *name, BOOL add, BOOL lmhosts)
{
  struct subnet_record *d;

  /* XXXX andrew: struct in_addr ip appears not to be referenced at all except
     in the DEBUG comment. i assume that the DEBUG comment below actually
     intends to refer to bcast_ip? i don't know.

  struct in_addr ip = ipgrp;

  */

  if (zero_ip(bcast_ip)) 
    bcast_ip = *iface_bcast(bcast_ip);
  
  /* add the domain into our domain database */
  if ((d = find_subnet(bcast_ip)) ||
      (d = make_subnet(bcast_ip, mask_ip)))
    {
      struct work_record *w = find_workgroupstruct(d, name, add);
	  extern pstring ServerComment;
      
      if (!w) return NULL;

      /* add WORKGROUP(1e) and WORKGROUP(00) entries into name database
	 or register with WINS server, if it's our workgroup */
      if (strequal(lp_workgroup(), name) && d->my_interface)
	{
	  add_my_name_entry(d,name,0x1e,NB_ACTIVE|NB_GROUP);
	  add_my_name_entry(d,name,0x0 ,NB_ACTIVE|NB_GROUP);
	}
      /* add samba server name to workgroup list */
      if ((strequal(lp_workgroup(), name) && d->my_interface) || lmhosts)
      {
	    add_server_entry(d,w,myname,w->ServerType,0,ServerComment,True);
      }
      
      DEBUG(3,("Added domain name entry %s at %s\n", name,inet_ntoa(bcast_ip)));
      return d;
    }
  return NULL;
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
  add a server entry
  ****************************************************************************/
struct server_record *add_server_entry(struct subnet_record *d, 
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
  
  if (!s || s->serv.type != servertype || !strequal(s->serv.comment, comment))
    updatedlists=True;

  if (!s)
    {
      newentry = True;
      s = (struct server_record *)malloc(sizeof(*s));
      
      if (!s) return(NULL);
      
      bzero((char *)s,sizeof(*s));
    }
  
  
  if (d->my_interface && strequal(lp_workgroup(),work->work_group))
    {
	  if (servertype)
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
  s->death_time = servertype ? (ttl?time(NULL)+ttl*3:0) : (time(NULL)-1);
  
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


/****************************************************************************
  add the default workgroup into my domain
  **************************************************************************/
void add_my_subnets(char *group)
{
  struct interface *i;

  /* add or find domain on our local subnet, in the default workgroup */
  
  if (*group == '*') return;

	/* the coding choice is up to you, andrew: i can see why you don't want
       global access to the local_interfaces structure: so it can't get
       messed up! */
    for (i = local_interfaces; i; i = i->next)
    {
      add_subnet_entry(i->bcast,i->nmask,group, True, False);
    }
}


/*******************************************************************
  write out browse.dat
  ******************************************************************/
void write_browse_list(void)
{
  struct subnet_record *d;
  
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
  
  for (d = subnetlist; d ; d = d->next)
    {
      struct work_record *work;
      for (work = d->workgrouplist; work ; work = work->next)
	{
	  struct server_record *s;
	  for (s = work->serverlist; s ; s = s->next)
	    {
	      fstring tmp;
	      
	      /* don't list domains I don't have a master for */
	      if ((s->serv.type & SV_TYPE_DOMAIN_ENUM) && !s->serv.comment[0])
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
  struct subnet_record *d;
  
  for (d = subnetlist ; d ; d = d->next)
    {
      struct work_record *work;
      
      for (work = d->workgrouplist; work; work = work->next)
	{
	  remove_old_servers(work, t);
	}
    }
}

