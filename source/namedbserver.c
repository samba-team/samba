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
   
   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

   04 jul 96: lkcl@pires.co.uk
   created module namedbserver containing server database functions

*/

#include "includes.h"
#include "smb.h"

extern int ClientNMB;
extern int ClientDGRAM;

extern int DEBUGLEVEL;

extern pstring myname;

/* this is our domain/workgroup/server database */
extern struct subnet_record *subnetlist;

extern BOOL updatedlists;


/*******************************************************************
  expire old servers in the serverlist
  time of -1 indicates everybody dies except those with time of 0
  remove_all_servers indicates everybody dies.
  ******************************************************************/
void remove_old_servers(struct work_record *work, time_t t,
					BOOL remove_all)
{
  struct server_record *s;
  struct server_record *nexts;
  
  /* expire old entries in the serverlist */
  for (s = work->serverlist; s; s = nexts)
    {
      if (remove_all || (s->death_time && (t == -1 || s->death_time < t)))
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
  find a server in a server list.
  **************************************************************************/
struct server_record *find_server(struct work_record *work, char *name)
{
	struct server_record *ret;
  
	if (!work) return NULL;

	for (ret = work->serverlist; ret; ret = ret->next)
	{
		if (strequal(ret->serv.name,name))
		{
			return ret;
		}
	}
    return NULL;
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
  
  s = find_server(work, name);

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
  
  
  if (strequal(lp_workgroup(),work->work_group))
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
	  remove_old_servers(work, t, False);
	}
    }
}

