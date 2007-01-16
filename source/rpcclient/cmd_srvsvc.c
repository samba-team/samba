/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   Copyright (C) Tim Potter 2000,2002

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

static void display_server(const char *sname, uint32 type, const char *comment)
{
	printf("\t%-15.15s%-20s %s\n", sname, get_server_type_str(type), 
	       comment);
}

static void display_srv_info_101(struct srvsvc_NetSrvInfo101 *sv101)
{
	display_server(sv101->server_name, sv101->server_type, sv101->comment);

	printf("\tplatform_id     :\t%d\n", sv101->platform_id);
	printf("\tos version      :\t%d.%d\n", sv101->version_major, 
	       sv101->version_minor);

	printf("\tserver type     :\t0x%x\n", sv101->server_type);
}

static void display_srv_info_102(struct srvsvc_NetSrvInfo102 *sv102)
{
	display_server(sv102->server_name, sv102->server_type, 
				   sv102->comment);

	printf("\tplatform_id     :\t%d\n", sv102->platform_id);
	printf("\tos version      :\t%d.%d\n", sv102->version_major, 
	       sv102->version_minor);

	printf("\tusers           :\t%x\n", sv102->users);
	printf("\tdisc, hidden    :\t%x, %x\n", sv102->disc, sv102->hidden);
	printf("\tannounce, delta :\t%d, %d\n", sv102->announce, 
	       sv102->anndelta);
	printf("\tlicenses        :\t%d\n", sv102->licenses);
	printf("\tuser path       :\t%s\n", sv102->userpath);
}

/* Server query info */
static NTSTATUS cmd_srvsvc_srv_query_info(struct rpc_pipe_client *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, const char **argv)
{
	uint32 info_level = 101;
	union srvsvc_NetSrvInfo ctr;
	NTSTATUS result;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	result = rpccli_srvsvc_NetSrvGetInfo(cli, mem_ctx, NULL, info_level,
					     &ctr);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

	switch (info_level) {
	case 101:
		display_srv_info_101(ctr.info101);
		break;
	case 102:
		display_srv_info_102(ctr.info102);
		break;
	default:
		printf("unsupported info level %d\n", info_level);
		break;
	}

 done:
	return result;
}

static void display_share_info_1(struct srvsvc_NetShareInfo1 *info1)
{
	printf("netname: %s\n", info1->name);
	printf("\tremark:\t%s\n", info1->comment);
}

static void display_share_info_2(struct srvsvc_NetShareInfo2 *info2)
{
	printf("netname: %s\n", info2->name);
	printf("\tremark:\t%s\n", info2->comment);
	printf("\tpath:\t%s\n", info2->path);
	printf("\tpassword:\t%s\n", info2->password);
}

static void display_share_info_502(struct srvsvc_NetShareInfo502 *info502)
{
	printf("netname: %s\n", info502->name);
	printf("\tremark:\t%s\n", info502->comment);
	printf("\tpath:\t%s\n", info502->path);
	printf("\tpassword:\t%s\n", info502->password);

	printf("\ttype:\t0x%x\n", info502->type);
	printf("\tperms:\t%d\n", info502->permissions);
	printf("\tmax_uses:\t%d\n", info502->max_users);
	printf("\tnum_uses:\t%d\n", info502->current_users);
	
	if (info502->sd)
		display_sec_desc(info502->sd);

}

static NTSTATUS cmd_srvsvc_net_share_enum(struct rpc_pipe_client *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, const char **argv)
{
	uint32 info_level = 2;
	struct srvsvc_NetShareCtr1 ctr1;
	struct srvsvc_NetShareCtr2 ctr2;
	struct srvsvc_NetShareCtr502 ctr502;
	union srvsvc_NetShareCtr ctr;
	NTSTATUS result;
	uint32 hnd;
	uint32 preferred_len = 0xffffffff, i;
	uint32 numentries;

	ZERO_STRUCT(ctr);

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	hnd = 0;

	switch (info_level) {
	case 1: {
		ZERO_STRUCT(ctr1);
		ctr.ctr1 = &ctr1;
		}
		break;

	case 2: {
		ZERO_STRUCT(ctr2);
		ctr.ctr2 = &ctr2;
		}
		break;
	case 502: {
		ZERO_STRUCT(ctr502);
		ctr.ctr502 = &ctr502;
		}
		break;

	default:
		break;
	}

	result = rpccli_srvsvc_NetShareEnum(
		cli, mem_ctx, cli->cli->desthost, &info_level, &ctr, preferred_len, &numentries, 
		&hnd);

	if (!NT_STATUS_IS_OK(result) || !numentries)
		goto done;

	/* Display results */

	switch (info_level) {
	case 1:
		for (i = 0; i < numentries; i++)
			display_share_info_1(&ctr.ctr1->array[i]);
		break;
	case 2:
		for (i = 0; i < numentries; i++)
			display_share_info_2(&ctr.ctr2->array[i]);
		break;
	case 502:
		for (i = 0; i < numentries; i++)
			display_share_info_502(&ctr.ctr502->array[i]);
		break;
	default:
		printf("unsupported info level %d\n", info_level);
		break;
	}

 done:
	return result;
}

static NTSTATUS cmd_srvsvc_net_share_get_info(struct rpc_pipe_client *cli, 
					    TALLOC_CTX *mem_ctx,
					    int argc, const char **argv)
{
	uint32 info_level = 502;
	union srvsvc_NetShareInfo info;
	NTSTATUS result;

	if (argc > 3) {
		printf("Usage: %s [sharename] [infolevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 3)
		info_level = atoi(argv[2]);

	result = rpccli_srvsvc_NetShareGetInfo(cli, mem_ctx, NULL, argv[1], info_level, &info);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Display results */

	switch (info_level) {
	case 1:
		display_share_info_1(info.info1);
		break;
	case 2:
		display_share_info_2(info.info2);
		break;
	case 502:
		display_share_info_502(info.info502);
		break;
	default:
		printf("unsupported info level %d\n", info_level);
		break;
	}

 done:
	return result;
}

static NTSTATUS cmd_srvsvc_net_share_set_info(struct rpc_pipe_client *cli, 
					    TALLOC_CTX *mem_ctx,
					    int argc, const char **argv)
{
	uint32 info_level = 502;
	union srvsvc_NetShareInfo info_get;
	NTSTATUS result;
	uint32 parm_error = 0;

	if (argc > 3) {
		printf("Usage: %s [sharename] [comment]\n", argv[0]);
		return NT_STATUS_OK;
	}

	/* retrieve share info */
	result = rpccli_srvsvc_NetShareGetInfo(cli, mem_ctx, NULL, argv[1], info_level, &info_get);
	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* set share info */
	result = rpccli_srvsvc_NetShareSetInfo(cli, mem_ctx, NULL, argv[1], info_level, info_get, &parm_error);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* re-retrieve share info and display */
	result = rpccli_srvsvc_NetShareGetInfo(cli, mem_ctx, NULL, argv[1], info_level, &info_get);
	if (!NT_STATUS_IS_OK(result))
		goto done;

	display_share_info_502(info_get.info502);
	
 done:
	return result;
}

static NTSTATUS cmd_srvsvc_net_remote_tod(struct rpc_pipe_client *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, const char **argv)
{
	fstring srv_name_slash;
	NTSTATUS result;
	struct srvsvc_NetRemoteTODInfo tod;

	if (argc > 1) {
		printf("Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	fstr_sprintf(srv_name_slash, "\\\\%s", cli->cli->desthost);
	result = rpccli_srvsvc_NetRemoteTOD(
		cli, mem_ctx, srv_name_slash, &tod);

	if (!NT_STATUS_IS_OK(result))
		goto done;

 done:
	return result;
}

static NTSTATUS cmd_srvsvc_net_file_enum(struct rpc_pipe_client *cli, 
					 TALLOC_CTX *mem_ctx,
					 int argc, const char **argv)
{
	uint32 info_level = 3;
	union srvsvc_NetFileCtr ctr;
	NTSTATUS result;
	uint32 hnd;
	uint32 preferred_len = 0xffff;
	uint32 numentries;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	hnd = 0;

	ZERO_STRUCT(ctr);

	result = rpccli_srvsvc_NetFileEnum(
		cli, mem_ctx, NULL, NULL, NULL, &info_level, &ctr, preferred_len, &numentries, &hnd);

	if (!NT_STATUS_IS_OK(result))
		goto done;

 done:
	return result;
}

/* List of commands exported by this module */

struct cmd_set srvsvc_commands[] = {

	{ "SRVSVC" },

	{ "srvinfo",     RPC_RTYPE_NTSTATUS, cmd_srvsvc_srv_query_info, NULL, PI_SRVSVC, NULL, "Server query info", "" },
	{ "netshareenum",RPC_RTYPE_NTSTATUS, cmd_srvsvc_net_share_enum, NULL, PI_SRVSVC, NULL, "Enumerate shares", "" },
	{ "netsharegetinfo",RPC_RTYPE_NTSTATUS, cmd_srvsvc_net_share_get_info, NULL, PI_SRVSVC, NULL, "Get Share Info", "" },
	{ "netsharesetinfo",RPC_RTYPE_NTSTATUS, cmd_srvsvc_net_share_set_info, NULL, PI_SRVSVC, NULL, "Set Share Info", "" },
	{ "netfileenum", RPC_RTYPE_NTSTATUS, cmd_srvsvc_net_file_enum, NULL, PI_SRVSVC, NULL, "Enumerate open files", "" },
	{ "netremotetod",RPC_RTYPE_NTSTATUS, cmd_srvsvc_net_remote_tod, NULL, PI_SRVSVC, NULL, "Fetch remote time of day", "" },

	{ NULL }
};
