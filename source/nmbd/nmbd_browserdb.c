/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Luke Kenneth Casson Leighton 1994-1998
   Copyright (C) Jeremy Allison 1994-1998
   
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
   
*/

#include "includes.h"
#include "smb.h"

extern int DEBUGLEVEL;

/* This is our local master browser list database. */
struct browse_cache_record *lmb_browserlist = NULL;

/***************************************************************************
Add a browser into the lmb list.
**************************************************************************/

static void add_to_lmb_browse_cache(struct browse_cache_record *browc)
{
  struct browse_cache_record *browc2;

  if (lmb_browserlist == NULL)
  {
    lmb_browserlist = browc;
    browc->prev = NULL;
    browc->next = NULL;
    return;
  }
  
  for (browc2 = lmb_browserlist; browc2->next; browc2 = browc2->next)
    ;
  
  browc2->next = browc;
  browc->next = NULL;
  browc->prev = browc2;
}

/*******************************************************************
Remove a lmb browser entry.
******************************************************************/

void remove_lmb_browser_entry(struct browse_cache_record *browc)
{
  if (browc->prev)
    browc->prev->next = browc->next;
  if (browc->next)
    browc->next->prev = browc->prev;

  if (lmb_browserlist == browc)
    lmb_browserlist = browc->next; 
	  
  free((char *)browc);
}

/****************************************************************************
Update a browser death time.
****************************************************************************/

void update_browser_death_time(struct browse_cache_record *browc)
{
  /* Allow the new lmb to miss an announce period before we remove it. */
  browc->death_time = time(NULL) + (CHECK_TIME_MST_ANNOUNCE + 2)*60;
}

/****************************************************************************
Create a browser entry.
****************************************************************************/

struct browse_cache_record *create_browser_in_lmb_cache(char *work_name, char *browser_name, 
                                                        struct in_addr ip)
{
  struct browse_cache_record *browc;
  time_t now = time(NULL);

  browc = (struct browse_cache_record *)malloc(sizeof(*browc));
     
  if (browc == NULL)
  {
    DEBUG(0,("create_browser_in_lmb_cache: malloc fail !\n"));
    return(NULL);
  }

  bzero((char *)browc,sizeof(*browc));
  
  /* For a new lmb entry we want to sync with it after one minute. This
     will allow it time to send out a local announce and build its
     browse list. */

  browc->sync_time = now + 60;

  /* Allow the new lmb to miss an announce period before we remove it. */
  browc->death_time = now + (CHECK_TIME_MST_ANNOUNCE + 2)*60;

  StrnCpy(browc->lmb_name, browser_name,sizeof(browc->lmb_name)-1);
  StrnCpy(browc->work_group,work_name,sizeof(browc->work_group)-1);
  strupper(browc->lmb_name);
  strupper(browc->work_group);
  
  browc->ip = ip;
 
  add_to_lmb_browse_cache(browc);
      
  DEBUG(3,("create_browser_in_lmb_cache: Added lmb cache entry for workgroup %s name %s IP %s ttl %d\n",
            browc->work_group, browc->lmb_name, inet_ntoa(ip), browc->death_time));
  
  return(browc);
}

/****************************************************************************
Find a browser entry.
****************************************************************************/

struct browse_cache_record *find_browser_in_lmb_cache( char *browser_name )
{
  struct browse_cache_record *browc = NULL;

  for( browc = lmb_browserlist; browc; browc = browc->next)
    if(strequal( browser_name, browc->lmb_name))
      break;

  return browc;
}

/*******************************************************************
  Expire timed out browsers in the browserlist.
******************************************************************/

void expire_lmb_browsers(time_t t)
{
  struct browse_cache_record *browc;
  struct browse_cache_record *nextbrowc;

  for (browc = lmb_browserlist; browc; browc = nextbrowc)
  {
    nextbrowc = browc->next;

    if (browc->death_time < t)
    {
      DEBUG(3,("expire_lmb_browsers: Removing timed out lmb entry %s\n",browc->lmb_name));
      remove_lmb_browser_entry(browc);
    }
  }
}

/*******************************************************************
  Remove browsers from a named workgroup in the browserlist.
******************************************************************/

void remove_workgroup_lmb_browsers(char *work_group)
{
  struct browse_cache_record *browc;
  struct browse_cache_record *nextbrowc;

  for (browc = lmb_browserlist; browc; browc = nextbrowc)
  {
    nextbrowc = browc->next;

    if (strequal(work_group, browc->work_group))
    {
      DEBUG(3,("remove_workgroup_browsers: Removing lmb entry %s\n",browc->lmb_name));
      remove_lmb_browser_entry(browc);
    }
  }
}

