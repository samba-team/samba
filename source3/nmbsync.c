/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines to synchronise browse lists
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
   
*/

#include "includes.h"

extern int DEBUGLEVEL;

static struct work_record *call_w;
static struct subnet_record *call_d;

/*******************************************************************
  This is the NetServerEnum callback
  ******************************************************************/
static void callback(char *sname, uint32 stype, char *comment)
{
	struct work_record *w = call_w;

	stype &= ~SV_TYPE_LOCAL_LIST_ONLY;

	if (stype & SV_TYPE_DOMAIN_ENUM) {
		/* creates workgroup on remote subnet */
		if ((w = find_workgroupstruct(call_d,sname,True))) {
			announce_request(w, call_d->bcast_ip);
		}
	}
	      
	if (w) {
		add_server_entry(call_d,w,sname,stype,
				 lp_max_ttl(),comment,False);
	}
}


/*******************************************************************
  synchronise browse lists with another browse server.

  log in on the remote server's SMB port to their IPC$ service,
  do a NetServerEnum and update our server and workgroup databases.
  ******************************************************************/
void sync_browse_lists(struct subnet_record *d, struct work_record *work,
		       char *name, int nm_type, struct in_addr ip, BOOL local)
{
	extern fstring local_machine;
	static struct cli_state cli;
	uint32 local_type = local ? SV_TYPE_LOCAL_LIST_ONLY : 0;

	if (!d || !work ) return;

	if(d != wins_client_subnet) {
		DEBUG(0,("sync_browse_lists: ERROR sync requested on non-WINS subnet.\n"));
		return;
	}

	DEBUG(2,("sync_browse_lists: Sync browse lists with %s for %s %s\n",
		 name, work->work_group, inet_ntoa(ip)));

	if (!cli_initialise(&cli) || !cli_connect(&cli, name, &ip)) {
		DEBUG(1,("Failed to start browse sync with %s\n", name));
	}

	if (!cli_session_request(&cli, name, nm_type, local_machine)) {
		DEBUG(1,("%s rejected the browse sync session\n",name));
		cli_shutdown(&cli);
		return;
	}

	if (!cli_negprot(&cli)) {
		DEBUG(1,("%s rejected the negprot\n",name));
		cli_shutdown(&cli);
		return;
	}

	if (!cli_session_setup(&cli, "", "", 1, "", 0, work->work_group)) {
		DEBUG(1,("%s rejected the browse sync sessionsetup\n", 
			 name));
		cli_shutdown(&cli);
		return;
	}

	if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1)) {
		DEBUG(1,("%s refused browse sync IPC$ connect\n", name));
		cli_shutdown(&cli);
		return;
	}

	call_w = work;
	call_d = d;
	
	cli_NetServerEnum(&cli, work->work_group, 
			  local_type|SV_TYPE_DOMAIN_ENUM,
			  callback);

	cli_NetServerEnum(&cli, work->work_group, 
			  local?SV_TYPE_LOCAL_LIST_ONLY:SV_TYPE_ALL,
			  callback);

	cli_shutdown(&cli);
}
