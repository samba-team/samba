/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   Copyright (C) Tim Potter 2000

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
#include "rpcclient.h"

/* Display server query info */

static char *get_server_type_str(uint32 type)
{
	static fstring typestr;
	int i;

	if (type == SV_TYPE_ALL) {
		fstrcpy(typestr, "All");
		return typestr;
	}
		
	typestr[0] = 0;

	for (i = 0; i < 32; i++) {
		if (type & (1 << i)) {
			switch (1 << i) {
			case SV_TYPE_WORKSTATION:
				fstrcat(typestr, "Wk ");
				break;
			case SV_TYPE_SERVER:
				fstrcat(typestr, "Sv ");
				break;
			case SV_TYPE_SQLSERVER:
				fstrcat(typestr, "Sql ");
				break;
			case SV_TYPE_DOMAIN_CTRL:
				fstrcat(typestr, "PDC ");
				break;
			case SV_TYPE_DOMAIN_BAKCTRL:
				fstrcat(typestr, "BDC ");
				break;
			case SV_TYPE_TIME_SOURCE:
				fstrcat(typestr, "Tim ");
				break;
			case SV_TYPE_AFP:
				fstrcat(typestr, "AFP ");
				break;
			case SV_TYPE_NOVELL:
				fstrcat(typestr, "Nov ");
				break;
			case SV_TYPE_DOMAIN_MEMBER:
				fstrcat(typestr, "Dom ");
				break;
			case SV_TYPE_PRINTQ_SERVER:
				fstrcat(typestr, "PrQ ");
				break;
			case SV_TYPE_DIALIN_SERVER:
				fstrcat(typestr, "Din ");
				break;
			case SV_TYPE_SERVER_UNIX:
				fstrcat(typestr, "Unx ");
				break;
			case SV_TYPE_NT:
				fstrcat(typestr, "NT ");
				break;
			case SV_TYPE_WFW:
				fstrcat(typestr, "Wfw ");
				break;
			case SV_TYPE_SERVER_MFPN:
				fstrcat(typestr, "Mfp ");
				break;
			case SV_TYPE_SERVER_NT:
				fstrcat(typestr, "SNT ");
				break;
			case SV_TYPE_POTENTIAL_BROWSER:
				fstrcat(typestr, "PtB ");
				break;
			case SV_TYPE_BACKUP_BROWSER:
				fstrcat(typestr, "BMB ");
				break;
			case SV_TYPE_MASTER_BROWSER:
				fstrcat(typestr, "LMB ");
				break;
			case SV_TYPE_DOMAIN_MASTER:
				fstrcat(typestr, "DMB ");
				break;
			case SV_TYPE_SERVER_OSF:
				fstrcat(typestr, "OSF ");
				break;
			case SV_TYPE_SERVER_VMS:
				fstrcat(typestr, "VMS ");
				break;
			case SV_TYPE_WIN95_PLUS:
				fstrcat(typestr, "W95 ");
				break;
			case SV_TYPE_ALTERNATE_XPORT:
				fstrcat(typestr, "Xpt ");
				break;
			case SV_TYPE_LOCAL_LIST_ONLY:
				fstrcat(typestr, "Dom ");
				break;
			case SV_TYPE_DOMAIN_ENUM:
				fstrcat(typestr, "Loc ");
				break;
			}
		}
	}

	i = strlen(typestr) - 1;

	if (typestr[i] == ' ')
		typestr[i] = 0;
	
	return typestr;
}

static void display_server(char *sname, uint32 type, const char *comment)
{
	printf("\t%-15.15s%-20s %s\n", sname, get_server_type_str(type), 
	       comment);
}

static void display_srv_info_101(SRV_INFO_101 *sv101)
{
	fstring name;
	fstring comment;

	unistr2_to_unix(name, &sv101->uni_name, sizeof(name) - 1);
	unistr2_to_unix(comment, &sv101->uni_comment, sizeof(comment) - 1);

	display_server(name, sv101->srv_type, comment);

	printf("\tplatform_id     :\t%d\n", sv101->platform_id);
	printf("\tos version      :\t%d.%d\n", sv101->ver_major, 
	       sv101->ver_minor);

	printf("\tserver type     :\t0x%x\n", sv101->srv_type);
}

static void display_srv_info_102(SRV_INFO_102 *sv102)
{
	fstring name;
	fstring comment;
	fstring usr_path;
	
	unistr2_to_unix(name, &sv102->uni_name, sizeof(name) - 1);
	unistr2_to_unix(comment, &sv102->uni_comment, sizeof(comment) - 1);
	unistr2_to_unix(usr_path, &sv102->uni_usr_path, sizeof(usr_path) - 1);

	display_server(name, sv102->srv_type, comment);

	printf("\tplatform_id     :\t%d\n", sv102->platform_id);
	printf("\tos version      :\t%d.%d\n", sv102->ver_major, 
	       sv102->ver_minor);

	printf("\tusers           :\t%x\n", sv102->users);
	printf("\tdisc, hidden    :\t%x, %x\n", sv102->disc, sv102->hidden);
	printf("\tannounce, delta :\t%d, %d\n", sv102->announce, 
	       sv102->ann_delta);
	printf("\tlicenses        :\t%d\n", sv102->licenses);
	printf("\tuser path       :\t%s\n", usr_path);
}

/* Server query info */

static NTSTATUS cmd_srvsvc_srv_query_info(struct cli_state *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, char **argv)
{
	uint32 info_level = 101;
	SRV_INFO_CTR ctr;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	result = cli_srvsvc_net_srv_get_info(cli, mem_ctx, info_level,
					     &ctr);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

	switch (info_level) {
	case 101:
		display_srv_info_101(&ctr.srv.sv101);
		break;
	case 102:
		display_srv_info_102(&ctr.srv.sv102);
		break;
	default:
		printf("unsupported info level %d\n", info_level);
		break;
	}

 done:
	return result;
}

/* List of commands exported by this module */

struct cmd_set srvsvc_commands[] = {

	{ "SRVSVC" },

	{ "srvinfo",    cmd_srvsvc_srv_query_info,  PIPE_SRVSVC, "Server query info", "" },

	{ NULL }
};
