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

extern int DEBUGLEVEL;

/* this is our browse master/backup cache database */
static struct browse_cache_record *browserlist = NULL;


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
  add a browser entry
  ****************************************************************************/
struct browse_cache_record *add_browser_entry(char *name, int type, char *wg,
					      time_t ttl, struct in_addr ip, BOOL local)
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
  b->local  = local; /* local server list sync or complete sync required */
  
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
find a server responsible for a workgroup, and sync browse lists
**************************************************************************/
static void start_sync_browse_entry(struct browse_cache_record *b)
{                     
  struct subnet_record *d;
  struct work_record *work;

  if (!(d = find_subnet(b->ip))) return;

  if (!(work = find_workgroupstruct(d, b->group, False))) return;

  /* only sync if we are the master */
  if (AM_MASTER(work)) {

      /* first check whether the group we intend to sync with exists. if it
         doesn't, the server must have died. o dear. */

      /* see response_netbios_packet() or expire_netbios_response_entries() */
      queue_netbios_packet(d,ClientNMB,NMB_QUERY,
                       b->local?NAME_QUERY_SYNC_LOCAL:NAME_QUERY_SYNC_REMOTE,
					   b->group,0x20,0,0,0,NULL,NULL,
					   False,False,b->ip,b->ip);
  }

  b->synced = True;
}


/****************************************************************************
  search through browser list for an entry to sync with
  **************************************************************************/
void do_browser_lists(void)
{
  struct browse_cache_record *b;
  static time_t last = 0;
  time_t t = time(NULL);
  
  if (t-last < 20) return; /* don't do too many of these at once! */
                           /* XXXX equally this period should not be too long
                              the server may die in the intervening gap */
  
  last = t;
  
  /* pick any entry in the list, preferably one whose time is up */
  for (b = browserlist; b && b->next; b = b->next)
    {
      if (b->sync_time < t && b->synced == False) break;
    }
  
  if (b && !b->synced)
  {
    /* sync with the selected entry then remove some dead entries */
    start_sync_browse_entry(b);
    expire_browse_cache(t - 60);
  }

}

