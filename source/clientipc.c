/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern pstring debugf;
extern int DEBUGLEVEL;

extern FILE* out_hnd;

static struct cli_state ipccli;
struct cli_state *ipc_cli = &ipccli;
int ipc_tidx = -1;



/****************************************************************************
try and browse available connections on a host
****************************************************************************/
void client_browse_host(struct cli_state *cli, int t_idx, char *workgroup, BOOL sort)
{
	BOOL long_share_name = False;
	
	fprintf(out_hnd, "\n\tSharename      Type      Comment\n");
	fprintf(out_hnd,   "\t---------      ----      -------\n");

	if (!cli_NetShareEnum(cli, t_idx,
	                         out_hnd, DISPLAY_TXT, ACTION_ENUMERATE,
	                         sort, &long_share_name, display_share))
	{
		fprintf(out_hnd, "\tNo shares available on this host\n");
	}

	if (long_share_name)
	{
		fprintf(out_hnd, "\nNOTE: There were share names longer than 8 chars.\nOn older clients these may not be accessible or may give browsing errors\n");
	}

	fprintf(out_hnd, "\n");
	fprintf(out_hnd, "\tWorkgroup      Type                 Master\n");
	fprintf(out_hnd, "\t---------      ----                 ------\n");

	cli_NetServerEnum(cli, t_idx,
	                  out_hnd, DISPLAY_TXT, ACTION_ENUMERATE,
	                  workgroup, SV_TYPE_DOMAIN_ENUM, display_server);

	fprintf(out_hnd, "\n");
	fprintf(out_hnd, "\tServer         Type                 Comment\n");
	fprintf(out_hnd, "\t------         ----                 -------\n");
	
	cli_NetServerEnum(cli, t_idx,
	                  out_hnd, DISPLAY_TXT, ACTION_ENUMERATE,
	                  workgroup, SV_TYPE_ALL, display_server);
}


/****************************************************************************
show shares
****************************************************************************/
void cmd_list_shares(struct client_info *info)
{
	int count = 0;
	BOOL long_share_name = False;
	
	fprintf(out_hnd, "\n\tSharename      Type      Comment\n");
	fprintf(out_hnd,   "\t---------      ----      -------\n");

	count = cli_NetShareEnum(ipc_cli, ipc_tidx,
	                         out_hnd, DISPLAY_TXT, ACTION_ENUMERATE,
	                         True, &long_share_name, display_share);

	if (count == 0)
	{
		fprintf(out_hnd, "\tNo shares available on this host\n");
	}

	if (long_share_name)
	{
		fprintf(out_hnd, "\nNOTE: There were share names longer than 8 chars.\nOn older clients these may not be accessible or may give browsing errors\n");
	}
}


/****************************************************************************
show browse workgroup
****************************************************************************/
void cmd_list_wgps(struct client_info *info)
{
	fstring workgroup;
	fstring type;
	uint32 svc_type = 0;

	if (!next_token(NULL, workgroup,NULL))
	{
		fstrcpy(workgroup, info->workgroup);
	}

	if (next_token(NULL, type,NULL))
	{
		svc_type = strtoul(type, (char**)NULL, 16);
	}
	else
	{
		svc_type = SV_TYPE_ALL;
	}

	fprintf(out_hnd, "\n");
	fprintf(out_hnd, "\tServer         Type                 Comment\n");
	fprintf(out_hnd, "\t------         ----                 -------\n");

	cli_NetServerEnum(ipc_cli, ipc_tidx,
	                  out_hnd, DISPLAY_TXT, ACTION_ENUMERATE,
	                  workgroup, SV_TYPE_DOMAIN_ENUM, display_server);
}


/****************************************************************************
show browse servers
****************************************************************************/
void cmd_list_servers(struct client_info *info)
{
	fstring workgroup;
	fstring type;
	uint32 svc_type = 0;

	if (!next_token(NULL, workgroup,NULL))
	{
		fstrcpy(workgroup, info->workgroup);
	}

	if (next_token(NULL, type,NULL))
	{
		svc_type = strtoul(type, (char**)NULL, 16);
	}
	else
	{
		svc_type = SV_TYPE_DOMAIN_ENUM;
	}

	fprintf(out_hnd, "\n");
	fprintf(out_hnd, "\tWorkgroup      Type                 Master\n");
	fprintf(out_hnd, "\t---------      ----                 ------\n");

	cli_NetServerEnum(ipc_cli, ipc_tidx,
	                  out_hnd, DISPLAY_TXT, ACTION_ENUMERATE,
	                  workgroup, SV_TYPE_ALL, display_server);
}


/****************************************************************************
initialise anon ipc client structure
****************************************************************************/
void client_ipc_init(void)
{
	bzero(ipc_cli, sizeof(*ipc_cli));
}

/****************************************************************************
make anon ipc client connection
****************************************************************************/
void client_ipc_connect(struct client_info *info, 
				char *username, char *password, char *workgroup)
{
	BOOL anonymous = !username || username[0] == 0;
	BOOL got_pass = password && password[0] != 0;

	DEBUG(5,("client_ipc_init: %d\n", __LINE__));

	if (!cli_establish_connection(ipc_cli, &ipc_tidx,
			info->dest_host, 0x20, &info->dest_ip,
		     info->myhostname,
		   (got_pass || anonymous) ? NULL : "Enter Password:",
		   username, !anonymous ? password : NULL, workgroup,
	       info->share, info->svc_type,
	       False, True, !anonymous))
	{
		DEBUG(0,("client_ipc_init: connection failed\n"));
		cli_shutdown(ipc_cli);
	}

	DEBUG(5,("client_ipc_init: t_idx=%d\n", ipc_tidx));
}

/****************************************************************************
stop the ipc client connection
****************************************************************************/
void client_ipc_stop(void)
{
	cli_shutdown(ipc_cli);
}
