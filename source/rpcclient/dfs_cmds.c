/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   MSDfs rpcclient commands
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

#include "includes.h"
#include "ntdomain.h"
#include "rpcclient.h"
#include "rpc_parse.h"
#include "rpc_client.h"

extern struct client_info cli_info;

/* DFS command completion function */
static char *complete_dfsenum(char *text, int state)
{
  static uint32 i=0;
  DFS_INFO_CTR ctr;
  fstring srv_name;

  fstrcpy(srv_name, "\\\\");
  fstrcat(srv_name, cli_info.dest_host);
  strupper(srv_name);

  /* first time that the completion is called */
  if(i==0 && state==0)
    {
      free(ctr.dfs.info1);
      if(0 != dfs_enum(srv_name, 1, &ctr))
	{
	  return NULL;
	}
     
    }

  for(; i<ctr.num_entries;i++)
    {
      fstring dfspath;
      unistr2_to_ascii(dfspath, &(ctr.dfs.info1[i].entrypath),
		       sizeof(dfspath)-1);
      strupper(dfspath); 
      if(text==NULL || text[0] == 0 ||
	 strnequal(text, dfspath, strlen(text)))
	{
	  char *name = strdup(dfspath);
	  i++;
	  return name;
	}
    }
  return NULL;
}
      

/**************************************************************************** 
 Defines Dfs commands supported by this client
 ***************************************************************************/

static const struct command_set dfs_commands[] = 
{
  { "dfsenum", cmd_dfs_enum, "Enumerate Dfs volumes", {NULL, NULL} },
  { "dfsadd" , cmd_dfs_add,  "Add a Dfs volume", {complete_dfsenum, NULL} },
  { "dfsremove", cmd_dfs_remove, "Remove a Dfs volume",
    {complete_dfsenum, NULL} },
  { "", NULL, NULL, {NULL, NULL} }
};

void add_dfs_commands(void)
{
  add_command_set(dfs_commands);
}
