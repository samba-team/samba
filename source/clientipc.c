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
 print browse connection on a host
 ****************************************************************************/
static void print_server(char *sname, uint32 type, char *comment)
{
	fstring typestr;
	*typestr=0;

	if (type == SV_TYPE_ALL)
	{
		strcpy(typestr, "All");
	}
	else
	{
		int i;
		typestr[0] = 0;
		for (i = 0; i < 32; i++)
		{
			if (IS_BITS_SET_ALL(type, 1 << i))
			{
				switch (1 << i)
				{
					case SV_TYPE_WORKSTATION      : strcat(typestr, "Wk " ); break;
					case SV_TYPE_SERVER           : strcat(typestr, "Sv " ); break;
					case SV_TYPE_SQLSERVER        : strcat(typestr, "Sql "); break;
					case SV_TYPE_DOMAIN_CTRL      : strcat(typestr, "PDC "); break;
					case SV_TYPE_DOMAIN_BAKCTRL   : strcat(typestr, "BDC "); break;
					case SV_TYPE_TIME_SOURCE      : strcat(typestr, "Tim "); break;
					case SV_TYPE_AFP              : strcat(typestr, "AFP "); break;
					case SV_TYPE_NOVELL           : strcat(typestr, "Nov "); break;
					case SV_TYPE_DOMAIN_MEMBER    : strcat(typestr, "Dom "); break;
					case SV_TYPE_PRINTQ_SERVER    : strcat(typestr, "PrQ "); break;
					case SV_TYPE_DIALIN_SERVER    : strcat(typestr, "Din "); break;
					case SV_TYPE_SERVER_UNIX      : strcat(typestr, "Unx "); break;
					case SV_TYPE_NT               : strcat(typestr, "NT " ); break;
					case SV_TYPE_WFW              : strcat(typestr, "Wfw "); break;
					case SV_TYPE_SERVER_MFPN      : strcat(typestr, "Mfp "); break;
					case SV_TYPE_SERVER_NT        : strcat(typestr, "SNT "); break;
					case SV_TYPE_POTENTIAL_BROWSER: strcat(typestr, "PtB "); break;
					case SV_TYPE_BACKUP_BROWSER   : strcat(typestr, "BMB "); break;
					case SV_TYPE_MASTER_BROWSER   : strcat(typestr, "LMB "); break;
					case SV_TYPE_DOMAIN_MASTER    : strcat(typestr, "DMB "); break;
					case SV_TYPE_SERVER_OSF       : strcat(typestr, "OSF "); break;
					case SV_TYPE_SERVER_VMS       : strcat(typestr, "VMS "); break;
					case SV_TYPE_WIN95_PLUS       : strcat(typestr, "W95 "); break;
					case SV_TYPE_ALTERNATE_XPORT  : strcat(typestr, "Xpt "); break;
					case SV_TYPE_LOCAL_LIST_ONLY  : strcat(typestr, "Dom "); break;
					case SV_TYPE_DOMAIN_ENUM      : strcat(typestr, "Loc "); break;
				}
			}
		}
		i = strlen(typestr)-1;
		if (typestr[i] == ' ') typestr[i] = 0;

	}

	fprintf(out_hnd, "\t%-15.15s%-20s %s\n", sname, typestr, comment);
}


/****************************************************************************
print browse connection on a host
****************************************************************************/
static void print_share(char *sname, uint32 type, char *comment)
{
	fstring typestr;
	*typestr=0;

	switch (type)
	{
		case STYPE_DISKTREE: strcpy(typestr,"Disk"); break;
		case STYPE_PRINTQ  : strcpy(typestr,"Printer"); break;	      
		case STYPE_DEVICE  : strcpy(typestr,"Device"); break;
		case STYPE_IPC     : strcpy(typestr,"IPC"); break;      
		default            : strcpy(typestr,"????"); break;      
	}

	fprintf(out_hnd, "\t%-15.15s%-10.10s%s\n", sname, typestr, comment);
}


/****************************************************************************
try and browse available connections on a host
****************************************************************************/
void client_browse_host(struct cli_state *cli, int t_idx, char *workgroup, BOOL sort)
{
	int count = 0;
	BOOL long_share_name = False;
	
	fprintf(out_hnd, "\n\tSharename      Type      Comment\n");
	fprintf(out_hnd,   "\t---------      ----      -------\n");

	count = cli_NetShareEnum(cli, t_idx, sort, &long_share_name, print_share);

	if (count == 0)
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

	cli_NetServerEnum(cli, t_idx, workgroup, SV_TYPE_DOMAIN_ENUM, print_server);

	fprintf(out_hnd, "\n");
	fprintf(out_hnd, "\tServer         Type                 Comment\n");
	fprintf(out_hnd, "\t------         ----                 -------\n");
	
	cli_NetServerEnum(cli, t_idx, workgroup, SV_TYPE_ALL, print_server);
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

	count = cli_NetShareEnum(ipc_cli, ipc_tidx, True, &long_share_name, print_share);

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

	cli_NetServerEnum(ipc_cli, ipc_tidx, workgroup, svc_type, print_server);
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

	cli_NetServerEnum(ipc_cli, ipc_tidx, workgroup, svc_type, print_server);
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
