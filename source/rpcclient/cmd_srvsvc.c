/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   Copyright (C) Tim Potter 2000,2002

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

static void display_srv_info_101(struct srvsvc_NetSrvInfo101 *r)
{
	display_server(r->server_name, r->server_type, r->comment);

	printf("\tplatform_id     :\t%d\n", r->platform_id);
	printf("\tos version      :\t%d.%d\n",
		r->version_major, r->version_minor);
	printf("\tserver type     :\t0x%x\n", r->server_type);
}

static void display_srv_info_102(struct srvsvc_NetSrvInfo102 *r)
{
	display_server(r->server_name, r->server_type, r->comment);

	printf("\tplatform_id     :\t%d\n", r->platform_id);
	printf("\tos version      :\t%d.%d\n",
		r->version_major, r->version_minor);
	printf("\tserver type     :\t0x%x\n", r->server_type);

	printf("\tusers           :\t%x\n", r->users);
	printf("\tdisc, hidden    :\t%x, %x\n", r->disc, r->hidden);
	printf("\tannounce, delta :\t%d, %d\n", r->announce,
	       r->anndelta);
	printf("\tlicenses        :\t%d\n", r->licenses);
	printf("\tuser path       :\t%s\n", r->userpath);
}

/* Server query info */
static WERROR cmd_srvsvc_srv_query_info(struct rpc_pipe_client *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, const char **argv)
{
	uint32 info_level = 101;
	union srvsvc_NetSrvInfo info;
	WERROR result;
	NTSTATUS status;
	const char *server_name;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return WERR_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	server_name = talloc_asprintf_strupper_m(mem_ctx, "\\\\%s",
						 cli->cli->desthost);
	W_ERROR_HAVE_NO_MEMORY(server_name);

	status = rpccli_srvsvc_NetSrvGetInfo(cli, mem_ctx,
					     server_name,
					     info_level,
					     &info,
					     &result);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(result)) {
		goto done;
	}

	/* Display results */

	switch (info_level) {
	case 101:
		display_srv_info_101(info.info101);
		break;
	case 102:
		display_srv_info_102(info.info102);
		break;
	default:
		printf("unsupported info level %d\n", info_level);
		break;
	}

 done:
	return result;
}

static void display_share_info_1(SRV_SHARE_INFO_1 *info1)
{
	fstring netname = "", remark = "";

	rpcstr_pull_unistr2_fstring(netname, &info1->info_1_str.uni_netname);
	rpcstr_pull_unistr2_fstring(remark, &info1->info_1_str.uni_remark);

	printf("netname: %s\n", netname);
	printf("\tremark:\t%s\n", remark);
}

static void display_share_info_2(SRV_SHARE_INFO_2 *info2)
{
	fstring netname = "", remark = "", path = "", passwd = "";

	rpcstr_pull_unistr2_fstring(netname, &info2->info_2_str.uni_netname);
	rpcstr_pull_unistr2_fstring(remark, &info2->info_2_str.uni_remark);
	rpcstr_pull_unistr2_fstring(path, &info2->info_2_str.uni_path);
	rpcstr_pull_unistr2_fstring(passwd, &info2->info_2_str.uni_passwd);

	printf("netname: %s\n", netname);
	printf("\tremark:\t%s\n", remark);
	printf("\tpath:\t%s\n", path);
	printf("\tpassword:\t%s\n", passwd);
}

static void display_share_info_502(SRV_SHARE_INFO_502 *info502)
{
	fstring netname = "", remark = "", path = "", passwd = "";

	rpcstr_pull_unistr2_fstring(netname, &info502->info_502_str.uni_netname);
	rpcstr_pull_unistr2_fstring(remark, &info502->info_502_str.uni_remark);
	rpcstr_pull_unistr2_fstring(path, &info502->info_502_str.uni_path);
	rpcstr_pull_unistr2_fstring(passwd, &info502->info_502_str.uni_passwd);

	printf("netname: %s\n", netname);
	printf("\tremark:\t%s\n", remark);
	printf("\tpath:\t%s\n", path);
	printf("\tpassword:\t%s\n", passwd);

	printf("\ttype:\t0x%x\n", info502->info_502.type);
	printf("\tperms:\t%d\n", info502->info_502.perms);
	printf("\tmax_uses:\t%d\n", info502->info_502.max_uses);
	printf("\tnum_uses:\t%d\n", info502->info_502.num_uses);
	
	if (info502->info_502_str.sd)
		display_sec_desc(info502->info_502_str.sd);

}

static WERROR cmd_srvsvc_net_share_enum(struct rpc_pipe_client *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, const char **argv)
{
	uint32 info_level = 2;
	SRV_SHARE_INFO_CTR ctr;
	WERROR result;
	ENUM_HND hnd;
	uint32 preferred_len = 0xffffffff, i;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return WERR_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	init_enum_hnd(&hnd, 0);

	result = rpccli_srvsvc_net_share_enum(
		cli, mem_ctx, info_level, &ctr, preferred_len, &hnd);

	if (!W_ERROR_IS_OK(result) || !ctr.num_entries)
		goto done;

	/* Display results */

	switch (info_level) {
	case 1:
		for (i = 0; i < ctr.num_entries; i++)
			display_share_info_1(&ctr.share.info1[i]);
		break;
	case 2:
		for (i = 0; i < ctr.num_entries; i++)
			display_share_info_2(&ctr.share.info2[i]);
		break;
	case 502:
		for (i = 0; i < ctr.num_entries; i++)
			display_share_info_502(&ctr.share.info502[i]);
		break;
	default:
		printf("unsupported info level %d\n", info_level);
		break;
	}

 done:
	return result;
}

static WERROR cmd_srvsvc_net_share_get_info(struct rpc_pipe_client *cli, 
					    TALLOC_CTX *mem_ctx,
					    int argc, const char **argv)
{
	uint32 info_level = 502;
	SRV_SHARE_INFO info;
	WERROR result;

	if (argc > 3) {
		printf("Usage: %s [sharename] [infolevel]\n", argv[0]);
		return WERR_OK;
	}

	if (argc == 3)
		info_level = atoi(argv[2]);

	result = rpccli_srvsvc_net_share_get_info(cli, mem_ctx, argv[1], info_level, &info);

	if (!W_ERROR_IS_OK(result))
		goto done;

	/* Display results */

	switch (info_level) {
	case 1:
		display_share_info_1(&info.share.info1);
		break;
	case 2:
		display_share_info_2(&info.share.info2);
		break;
	case 502:
		display_share_info_502(&info.share.info502);
		break;
	default:
		printf("unsupported info level %d\n", info_level);
		break;
	}

 done:
	return result;
}

static WERROR cmd_srvsvc_net_share_set_info(struct rpc_pipe_client *cli, 
					    TALLOC_CTX *mem_ctx,
					    int argc, const char **argv)
{
	uint32 info_level = 502;
	SRV_SHARE_INFO info_get;
	WERROR result;

	if (argc > 3) {
		printf("Usage: %s [sharename] [comment]\n", argv[0]);
		return WERR_OK;
	}

	/* retrieve share info */
	result = rpccli_srvsvc_net_share_get_info(cli, mem_ctx, argv[1], info_level, &info_get);
	if (!W_ERROR_IS_OK(result))
		goto done;

	info_get.switch_value = info_level;
	info_get.ptr_share_ctr = 1;
	init_unistr2(&(info_get.share.info502.info_502_str.uni_remark), argv[2], UNI_STR_TERMINATE);
	
	/* set share info */
	result = rpccli_srvsvc_net_share_set_info(cli, mem_ctx, argv[1], info_level, &info_get);

	if (!W_ERROR_IS_OK(result))
		goto done;

	/* re-retrieve share info and display */
	result = rpccli_srvsvc_net_share_get_info(cli, mem_ctx, argv[1], info_level, &info_get);
	if (!W_ERROR_IS_OK(result))
		goto done;

	display_share_info_502(&info_get.share.info502);
	
 done:
	return result;
}

static WERROR cmd_srvsvc_net_remote_tod(struct rpc_pipe_client *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, const char **argv)
{
	TIME_OF_DAY_INFO tod;
	fstring srv_name_slash;
	WERROR result;

	if (argc > 1) {
		printf("Usage: %s\n", argv[0]);
		return WERR_OK;
	}

	fstr_sprintf(srv_name_slash, "\\\\%s", cli->cli->desthost);
	result = rpccli_srvsvc_net_remote_tod(
		cli, mem_ctx, srv_name_slash, &tod);

	if (!W_ERROR_IS_OK(result))
		goto done;

 done:
	return result;
}

static WERROR cmd_srvsvc_net_file_enum(struct rpc_pipe_client *cli, 
					 TALLOC_CTX *mem_ctx,
					 int argc, const char **argv)
{
	uint32 info_level = 3;
	SRV_FILE_INFO_CTR ctr;
	WERROR result;
	ENUM_HND hnd;
	uint32 preferred_len = 0xffff;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return WERR_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	init_enum_hnd(&hnd, 0);

	ZERO_STRUCT(ctr);

	result = rpccli_srvsvc_net_file_enum(
		cli, mem_ctx, info_level, NULL, &ctr, preferred_len, &hnd);

	if (!W_ERROR_IS_OK(result))
		goto done;

 done:
	return result;
}

/* List of commands exported by this module */

struct cmd_set srvsvc_commands[] = {

	{ "SRVSVC" },

	{ "srvinfo",     RPC_RTYPE_WERROR, NULL, cmd_srvsvc_srv_query_info, PI_SRVSVC, NULL, "Server query info", "" },
	{ "netshareenum",RPC_RTYPE_WERROR, NULL, cmd_srvsvc_net_share_enum, PI_SRVSVC, NULL, "Enumerate shares", "" },
	{ "netsharegetinfo",RPC_RTYPE_WERROR, NULL, cmd_srvsvc_net_share_get_info, PI_SRVSVC, NULL, "Get Share Info", "" },
	{ "netsharesetinfo",RPC_RTYPE_WERROR, NULL, cmd_srvsvc_net_share_set_info, PI_SRVSVC, NULL, "Set Share Info", "" },
	{ "netfileenum", RPC_RTYPE_WERROR, NULL, cmd_srvsvc_net_file_enum,  PI_SRVSVC, NULL, "Enumerate open files", "" },
	{ "netremotetod",RPC_RTYPE_WERROR, NULL, cmd_srvsvc_net_remote_tod, PI_SRVSVC, NULL, "Fetch remote time of day", "" },

	{ NULL }
};
