/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 2000
   Copyright (C) Shirish Kalele 2000
   
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE* out_hnd;

extern struct user_creds *usr_creds;

void cmd_dfs_add(struct client_info *info, int argc, char *argv[])
{
  fstring srv_name;
  char *entrypath, *servername, *sharename, *comment=NULL;

  /* parse out the args */
  if(argc < 4)
    {
      report(out_hnd, "dfsadd Dfspath storage_server share [\"comment\"]\n");
      return;
    }

  fstrcpy(srv_name,"\\\\");
  fstrcat(srv_name, info->dest_host);
  strupper(srv_name);

  entrypath = argv[1];
  servername = argv[2];
  sharename = argv[3];
  if(argc > 4)
    comment = argv[4];

  DEBUG(5,("Adding Dfs path: %s\n(physically located at \\\\%s\\%s\n",
	   entrypath, servername, sharename));
  
  if(!dfs_add(srv_name, entrypath, servername, sharename, comment))
    {
      report(out_hnd, "dfsadd: Unable to add dfs share\n");
      return;
    }
  else
    {
      report(out_hnd, "dfsadd: Successfully added dfs share\n");
      return;
    }
}

void cmd_dfs_remove(struct client_info *info, int argc, char *argv[])
{
  fstring srv_name;
  char *dfs_entrypath, *dfs_servername, *dfs_sharename;
  
  if(argc != 4)
    {
      report(out_hnd, "dfsremove Dfspath storage_server share\n");
      return;
    }

  fstrcpy(srv_name, "\\\\");
  fstrcat(srv_name, info->dest_host);
  strupper(srv_name);

  dfs_entrypath = argv[1];
  dfs_servername = argv[2];
  dfs_sharename = argv[3];

  DEBUG(5,("Removing Dfs path: %s\n[physically located at \\\\%s\\%s\n",
	 dfs_entrypath, dfs_servername, dfs_sharename));
  
  if(!dfs_remove(srv_name, dfs_entrypath, dfs_servername, dfs_sharename))
    {
      report(out_hnd, "dfsremove: Unsuccessful!\n");
      return;
    }
  else
    {
      report(out_hnd, "dfsremove: Removed.\n");
      return;
    }
}



/****************************************************************************
 DFS enum query
 ****************************************************************************/
void cmd_dfs_enum(struct client_info *info, int argc, char *argv[])
{
  fstring srv_name;
  DFS_INFO_CTR ctr;
  uint32 info_level = 3;
  uint32 res=0;
  fstrcpy(srv_name,"\\\\");
  fstrcat(srv_name, info->dest_host);
  strupper(srv_name);

  if(argc > 2)
    {
      report(out_hnd, "dfsenum [1,2,3]\n");
      return;
    }
  
  if(argc == 2)
    info_level = (uint32)strtol(argv[1], (char**)NULL, 10); 
  
  if(info_level<1 || info_level>3)
    {
      report(out_hnd, "dfsenum [1,2,3]\n");
      return;
    }
  DEBUG(5,("cmd_dfs_enum: info_level: %u query\n",info_level));

  res = dfs_enum(srv_name, info_level, &ctr);
  if(res==0)
    {
      DEBUG(5,("cmd_dfs_enum: query succeeded\n"));
      display_dfs_enum(out_hnd, srv_name, &ctr);
      return;
    }
  else
    {
      report(out_hnd, "FAILED: %s\n",get_nt_error_msg(res)); 
      return;
    }
}

    
