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
   created module namedbsubnet containing subnet database functions

*/

#include "includes.h"
#include "smb.h"

extern int ClientNMB;
extern int ClientDGRAM;

extern int DEBUGLEVEL;

extern struct in_addr wins_ip;
extern struct in_addr ipzero;

extern pstring myname;

BOOL updatedlists = True;
int updatecount = 0;

/* local interfaces structure */
extern struct interface *local_interfaces;

/* this is our domain/workgroup/server database */
struct subnet_record *subnetlist = NULL;

/* WINS subnet - keep this separate so enumeration code doesn't
   run onto it by mistake. */
struct subnet_record *wins_subnet = 0;

extern uint16 nb_type; /* samba's NetBIOS name type */

/* Forward references. */
static struct subnet_record *add_subnet_entry(struct in_addr bcast_ip, 
				       struct in_addr mask_ip,
				       char *name, BOOL add, BOOL lmhosts);

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


/****************************************************************************
  find a subnet in the subnetlist - not including WINS.
  **************************************************************************/
struct subnet_record *find_subnet(struct in_addr bcast_ip)
{   
  struct subnet_record *d;
  
  /* search through subnet list for broadcast/netmask that matches
     the source ip address. */
  
  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_EXCLUDING_WINS(d))
    {
      if (same_net(bcast_ip, d->bcast_ip, d->mask_ip))
        return d;
    }
  
  return (NULL);
}


/****************************************************************************
  finds the appropriate subnet structure. directed packets (non-bcast) are
  assumed to come from a point-to-point (P or M node), and so the subnet we
  return in this instance is the WINS 'pseudo-subnet' with ip 255.255.255.255
  ****************************************************************************/
struct subnet_record *find_req_subnet(struct in_addr ip, BOOL bcast)
{
  if (bcast)
  {
    /* identify the subnet the broadcast request came from */
    return find_subnet(*iface_bcast(ip));
  }
  /* Return the subnet with the pseudo-ip of 255.255.255.255 */
  return wins_subnet;
}

/****************************************************************************
  find a subnet in the subnetlist - if the subnet is not found
  then return the WINS subnet.
  **************************************************************************/
struct subnet_record *find_subnet_all(struct in_addr bcast_ip)
{
  struct subnet_record *d = find_subnet(bcast_ip);
  if(!d)
    return wins_subnet;
}

/****************************************************************************
  create a domain entry
  ****************************************************************************/
static struct subnet_record *make_subnet(struct in_addr bcast_ip, struct in_addr mask_ip, BOOL add)
{
  struct subnet_record *d;
  d = (struct subnet_record *)malloc(sizeof(*d));
  
  if (!d) return(NULL);
  
  bzero((char *)d,sizeof(*d));
  
  DEBUG(4, ("making subnet %s ", inet_ntoa(bcast_ip)));
  DEBUG(4, ("%s\n", inet_ntoa(mask_ip)));
  
  d->bcast_ip = bcast_ip;
  d->mask_ip  = mask_ip;
  d->workgrouplist = NULL;
  
  if(add)
    add_subnet(d);
  
  return d;
}


/****************************************************************************
  add the remote interfaces from lp_interfaces()
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
	  make_subnet(i->bcast,i->nmask, True);
	}
    }

  /* add the pseudo-ip interface for WINS: 255.255.255.255 */
  if (lp_wins_support() || (*lp_wins_server()))
    {
      struct in_addr wins_bcast = wins_ip;
      struct in_addr wins_nmask = ipzero;
      wins_subnet = make_subnet(wins_bcast, wins_nmask, False);
    }
}



/****************************************************************************
  add the default workgroup into the subnet lists.
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

    /* If we are setup as a domain master browser, and are using
       WINS, then we must add the workgroup to the WINS subnet. This
       is used as a place to keep collated server lists. */

    if(lp_domain_master() && (lp_wins_support() || lp_wins_server()))
      if(find_workgroupstruct(wins_subnet, group, True) == 0)
        DEBUG(0, ("add_my_subnets: Failed to add workgroup %s to \
WINS subnet.\n", group));
      else
        DEBUG(3,("add_my_subnets: Added workgroup %s to WINS subnet.\n",
                 group));
}


/****************************************************************************
  add a domain entry. creates a workgroup, if necessary, and adds the domain
  to the named a workgroup.
  ****************************************************************************/
static struct subnet_record *add_subnet_entry(struct in_addr bcast_ip, 
				       struct in_addr mask_ip,
				       char *name, BOOL add, BOOL lmhosts)
{
  struct subnet_record *d;

  /* XXXX andrew: struct in_addr ip appears not to be referenced at all except
     in the DEBUG comment. i assume that the DEBUG comment below actually
     intends to refer to bcast_ip? i don't know.

  struct in_addr ip = wins_ip;

  */

  if (zero_ip(bcast_ip)) 
    bcast_ip = *iface_bcast(bcast_ip);
  
  /* add the domain into our domain database */
  /* Note that we never add into the WINS subnet as add_subnet_entry
     is only called to add our local interfaces. */
  if ((d = find_subnet(bcast_ip)) ||
      (d = make_subnet(bcast_ip, mask_ip, True)))
    {
      struct work_record *w = find_workgroupstruct(d, name, add);
      
      if (!w) return NULL;

      /* add WORKGROUP(1e) and WORKGROUP(00) entries into name database
	 or register with WINS server, if it's our workgroup */
      if (strequal(lp_workgroup(), name))
	{
	  add_my_name_entry(d,name,0x1e,nb_type|NB_ACTIVE|NB_GROUP);
	  add_my_name_entry(d,name,0x0 ,nb_type|NB_ACTIVE|NB_GROUP);
	}
      /* add samba server name to workgroup list. don't add
         lmhosts server entries to local interfaces */
      if (strequal(lp_workgroup(), name))
      {
	add_server_entry(d,w,myname,w->ServerType,0,lp_serverstring(),True);
        DEBUG(3,("Added server name entry %s at %s\n",
                  name,inet_ntoa(bcast_ip)));
      }
      
      return d;
    }
  return NULL;
}


/*******************************************************************
  write out browse.dat
  ******************************************************************/
void write_browse_list(time_t t)
{
  struct subnet_record *d;
  pstring fname,fnamenew;
  FILE *f;

  static time_t lasttime = 0;

  if (!lasttime) lasttime = t;
  if (!updatedlists || t - lasttime < 5) return;
  
  lasttime = t;
  updatedlists = False;
  updatecount++;
  
  dump_names();
  dump_workgroups();
  
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
  
  for (d = FIRST_SUBNET; d ; d = NEXT_SUBNET_INCLUDING_WINS(d))
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

