
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 3.0
 *  Samba utility functions
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Shirish Kalele               2000.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

extern FILE* out_hnd;
/*
 * Dfs namespace enumeration (info level 1)
 */
void display_dfs_enum_1(FILE *hnd, DFS_INFO_CTR *ctr)
{
  int i=0;
  for(i=0;i<ctr->num_entries;i++)
    {
      fstring path;
      UNISTR2 *unipath = &(ctr->dfs.info1[i].entrypath);
      unistr2_to_ascii(path, unipath, sizeof(path)-1);
      report(hnd, "Path: %s\n",path);
    }
  free(ctr->dfs.info1);
}

/*
 * Dfs namespace enumeration (info level 2)
 */
void display_dfs_enum_2(FILE *hnd, DFS_INFO_CTR *ctr)
{
  int i=0;
  for(i=0;i<ctr->num_entries;i++)
    {
      fstring path, comment;
      fstring state;
      UNISTR2 *unipath = &(ctr->dfs.info2[i].entrypath);
      UNISTR2 *unicomment = &(ctr->dfs.info2[i].comment);
      unistr2_to_ascii(path, unipath, sizeof(path)-1);
      unistr2_to_ascii(comment, unicomment, sizeof(comment)-1);
      
      report(hnd, "Path: %s\n",path);
      if(*comment)
	report(hnd, "Comment: [%s]\n",comment);
	
      switch(ctr->dfs.info2[i].state)
	{
	case 1: fstrcpy(state, "OK"); break;
	case 2: fstrcpy(state, "INCONSISTENT"); break;
	case 3: fstrcpy(state, "OFFLINE"); break;
	case 4: fstrcpy(state, "ONLINE"); break;
	default: fstrcpy(state, "UNKNOWN"); break;
	}
      report(hnd, "State: %s Number of storages: %u\n\n",state,
	     ctr->dfs.info2[i].num_storages);
    }
  free(ctr->dfs.info2);
}

/*
 * Dfs namespace enumeration (info level 3:storages)
 */
void display_dfs_enum_3_storages(FILE *hnd, DFS_INFO_3 *info3)
{
  int i=0;
  if((info3 == NULL) || (info3->storages==NULL))
    return;

  for(i=0;i<info3->num_storages;i++)
    {
      DFS_STORAGE_INFO *stor = &(info3->storages[i]);
      fstring servername, sharename,storagepath;
      unistr2_to_ascii(servername, &(stor->servername), sizeof(servername)-1);
      unistr2_to_ascii(sharename, &(stor->sharename), sizeof(sharename)-1);
      fstrcpy(storagepath,"\\\\");
      fstrcat(storagepath,servername);
      fstrcat(storagepath,"\\");
      fstrcat(storagepath,sharename);
      
      report(hnd, "     Storage %1u: %-33s[%s] \n",i+1, storagepath,
	     (stor->state==2?"ONLINE":"OFFLINE"));
    }
}

/*
 * Dfs namespace enumeration (info level 3)
 */
void display_dfs_enum_3(FILE *hnd, DFS_INFO_CTR *ctr)
{
  int i=0;

  for(i=0;i<ctr->num_entries;i++)
    {
      fstring path, comment;
      fstring state;
      UNISTR2 *unipath = &(ctr->dfs.info3[i].entrypath);
      UNISTR2 *unicomment = &(ctr->dfs.info3[i].comment);
      unistr2_to_ascii(path, unipath, sizeof(path)-1);
      unistr2_to_ascii(comment, unicomment, sizeof(comment)-1);

      switch(ctr->dfs.info3[i].state)
	{
	case 1: fstrcpy(state, "OK"); break;
	case 2: fstrcpy(state, "INCONSISTENT"); break;
	case 3: fstrcpy(state, "OFFLINE"); break;
	case 4: fstrcpy(state, "ONLINE"); break;
	default: fstrcpy(state, "UNKNOWN"); break;
	}

      report(hnd, "Dfs path:%-40sState: %s\n",path,state);
      if(*comment)
	report(hnd, "Comment: [%s]\n",comment);

      display_dfs_enum_3_storages(hnd, &(ctr->dfs.info3[i]));
      report(hnd,"\n");
    }
  free(ctr->dfs.info3);
}

/*
 * Dfs namespace enumeration 
 */
void display_dfs_enum(FILE *hnd, char *srv_name, DFS_INFO_CTR *ctr)
{
  /* print header */
  report(hnd, "\tDfs Namespace at %s [Info level %u]\n\n",srv_name, 
	 ctr->switch_value);
  switch(ctr->switch_value)
    {
    case 1:
      display_dfs_enum_1(hnd, ctr);
      break;
    case 2:
      display_dfs_enum_2(hnd, ctr);
      break;
    case 3:
      display_dfs_enum_3(hnd, ctr);
      break;
    default:
      report(hnd, "\tUnknown info level [%u]\n",ctr->switch_value);
    }
  report(hnd, "\n");
}
