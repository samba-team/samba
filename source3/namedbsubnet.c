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
extern int global_nmb_port;

extern int DEBUGLEVEL;

extern struct in_addr wins_ip;
extern struct in_addr ipzero;

extern pstring myname;
extern fstring myworkgroup;
extern char **my_netbios_names;

BOOL updatedlists = True;
int updatecount = 0;

/* local interfaces structure */
extern struct interface *local_interfaces;

/* this is our domain/workgroup/server database */
struct subnet_record *subnetlist = NULL;

/* WINS subnet - keep this separate so enumeration code doesn't
   run onto it by mistake. */
struct subnet_record *wins_subnet = NULL;

extern uint16 nb_type; /* samba's NetBIOS name type */

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
  return d;
}

/****************************************************************************
  create a subnet entry
  ****************************************************************************/
static struct subnet_record *make_subnet(struct in_addr myip, struct in_addr bcast_ip, 
                                         struct in_addr mask_ip, BOOL add)
{
  struct subnet_record *d = NULL;
  int nmb_sock, dgram_sock;

  /* Check if we are creating the WINS subnet - if so don't create
     sockets, use the ClientNMB and ClientDGRAM sockets instead.
   */

  if(ip_equal(bcast_ip, wins_ip))
  {
    nmb_sock = -1;
    dgram_sock = -1;
  }
  else
  {
    /*
     * Attempt to open the sockets on port 137/138 for this interface
     * and bind them.
     * Fail the subnet creation if this fails.
     */

    if((nmb_sock = open_socket_in(SOCK_DGRAM, global_nmb_port,0, myip.s_addr)) == -1)
    {
      DEBUG(0,("make_subnet: Failed to open nmb socket on interface %s \
for port %d. Error was %s\n", inet_ntoa(myip), global_nmb_port, strerror(errno)));
      return NULL;
    }

    if((dgram_sock = open_socket_in(SOCK_DGRAM,DGRAM_PORT,3, myip.s_addr)) == -1)
    {
      DEBUG(0,("make_subnet: Failed to open dgram socket on interface %s \
for port %d. Error was %s\n", inet_ntoa(myip), DGRAM_PORT, strerror(errno)));
      return NULL;
    }

    /* Make sure we can broadcast from these sockets. */
    set_socket_options(nmb_sock,"SO_BROADCAST");
    set_socket_options(dgram_sock,"SO_BROADCAST");

  }

  d = (struct subnet_record *)malloc(sizeof(*d));
  
  if (!d) 
  {
    DEBUG(0,("make_subnet: malloc fail !\n"));
    close(nmb_sock);
    close(dgram_sock);
    return(NULL);
  }
  
  bzero((char *)d,sizeof(*d));
  
  DEBUG(4, ("making subnet %s ", inet_ntoa(bcast_ip)));
  DEBUG(4, ("%s\n", inet_ntoa(mask_ip)));
  
  d->bcast_ip = bcast_ip;
  d->mask_ip  = mask_ip;
  d->myip = myip;
  d->nmb_sock = nmb_sock;
  d->dgram_sock = dgram_sock;
  d->workgrouplist = NULL;
  
  if(add)
    add_subnet(d);
  
  return d;
}

/****************************************************************************
  add a domain entry. creates a workgroup, if necessary, and adds the domain
  to the named a workgroup.
  ****************************************************************************/
static struct subnet_record *add_subnet_entry(struct in_addr myip,
                                       struct in_addr bcast_ip, 
				       struct in_addr mask_ip, char *name, 
                                       BOOL create_subnets, BOOL add)
{
  struct subnet_record *d = NULL;

  if (zero_ip(bcast_ip)) 
    bcast_ip = *iface_bcast(bcast_ip);
  
  /* Note that we should also add into the WINS subnet as add_subnet_entry
    should be called to add NetBIOS names and server entries on all
    interfaces, including the WINS interface
   */

  if(create_subnets == True)
  {
    /* Create new subnets. */
    if((d = make_subnet(myip, bcast_ip, mask_ip, add)) == NULL)
    {
      DEBUG(0,("add_subnet_entry: Unable to create subnet %s\n",
               inet_ntoa(bcast_ip) ));
      return NULL;
    }
    return d;
  }
  if(ip_equal(bcast_ip, wins_ip))
    return wins_subnet;
  return find_subnet(bcast_ip);
}

/****************************************************************************
 Add a workgroup into a subnet, and if it's our primary workgroup,
 add the required names to it.
**************************************************************************/

void add_workgroup_to_subnet( struct subnet_record *d, char *group)
{
  struct work_record *w = NULL;

  DEBUG(5,("add_workgroup_to_subnet: Adding workgroup %s to subnet %s\n",
            group, inet_ntoa(d->bcast_ip)));

  /* This next statement creates the workgroup struct if it doesn't
     already exist. 
   */
  if((w = find_workgroupstruct(d, group, True)) == NULL)
  {
    DEBUG(0,("add_workgroup_to_subnet: Unable to add workgroup %s to subnet %s\n",
              group, inet_ntoa(d->bcast_ip) ));
    return;
  }

  /* add WORKGROUP(00) entries into name database
     or register with WINS server, if it's our workgroup.
   */
  if (strequal(myworkgroup, group))
  {
    int n;

    add_my_name_entry(d,group,0x0 ,nb_type|NB_ACTIVE|NB_GROUP);

    /* Only register the WORKGROUP<0x1e> name if we could be a local master
       browser. */
    if(lp_local_master())
      add_my_name_entry(d,group,0x1e,nb_type|NB_ACTIVE|NB_GROUP);

    /* Add all our server names to the workgroup list. We remove any
       browser or logon server flags from all but the primary name.
     */
    for( n = 0; my_netbios_names[n]; n++)
    {    
      char *name = my_netbios_names[n];
      int stype = w->ServerType;

      if(!strequal(myname, name))
          stype &= ~(SV_TYPE_MASTER_BROWSER|SV_TYPE_POTENTIAL_BROWSER|
                     SV_TYPE_DOMAIN_MASTER|SV_TYPE_DOMAIN_MEMBER);

      add_server_entry(d,w,name,stype|SV_TYPE_LOCAL_LIST_ONLY,0,
		lp_serverstring(),True);
      DEBUG(3,("add_workgroup_to_subnet: Added server name entry %s \
to subnet %s\n", name, inet_ntoa(d->bcast_ip)));
    }
  }
}

/****************************************************************************
  create subnet / workgroup / server entries
     
  - add or create the subnet lists
  - add or create the workgroup entries in each subnet entry
  - register appropriate NetBIOS names for the workgroup entries
     
**************************************************************************/
void add_my_subnets(char *group)
{    
  static BOOL create_subnets = True;
  struct subnet_record *d = NULL;
  struct interface *i = NULL;

  if (*group == '*') return;

  /* Create subnets from all the local interfaces and thread them onto
     the linked list. 
   */
  for (i = local_interfaces; i; i = i->next)
  {
    add_subnet_entry(i->ip, i->bcast,i->nmask,group, create_subnets, True);
  }

  /* If we are using WINS, then we must add the workgroup to the WINS
     subnet. This is used as a place to keep collated server lists.
   */

  /* Create the WINS subnet if we are using WINS - but don't thread it
     onto the linked subnet list. 
   */    
  if (lp_wins_support() || lp_wins_server())
  {
    struct in_addr wins_nmask = ipzero;
    wins_subnet = add_subnet_entry(ipzero, wins_ip, wins_nmask, group, create_subnets, False);
  }

  /* Ensure we only create the subnets once. */
  create_subnets = False;

  /* Now we have created all the subnets - we can add the names
     that make us a client member in the workgroup.
   */
  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_INCLUDING_WINS(d))
    add_workgroup_to_subnet(d, group);
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
  
  pstrcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,SERVER_LIST);
  pstrcpy(fnamenew,fname);
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

