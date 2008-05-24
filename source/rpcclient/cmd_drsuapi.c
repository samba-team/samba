/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Guenther Deschner 2008

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

static WERROR cmd_drsuapi_cracknames(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx, int argc,
				     const char **argv)
{
	NTSTATUS status;
	WERROR werr;
	int i;

	struct GUID bind_guid;
	struct policy_handle bind_handle;

	int32_t level = 1;
	union drsuapi_DsNameRequest req;
	int32_t level_out;
	union drsuapi_DsNameCtr ctr;
	struct drsuapi_DsNameString names[1];

	if (argc < 2) {
		printf("usage: %s name\n", argv[0]);
		return WERR_OK;
	}

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &bind_guid);

	status = rpccli_drsuapi_DsBind(cli, mem_ctx,
				       &bind_guid,
				       NULL,
				       &bind_handle,
				       &werr);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	names[0].str = argv[1];

	req.req1.codepage	= 1252; /* german */
	req.req1.language	= 0x00000407; /* german */
	req.req1.count		= 1;
	req.req1.names		= names;
	req.req1.format_flags	= DRSUAPI_DS_NAME_FLAG_NO_FLAGS;
	req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_UKNOWN;
	req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;

	status = rpccli_drsuapi_DsCrackNames(cli, mem_ctx,
					     &bind_handle,
					     level,
					     &req,
					     &level_out,
					     &ctr,
					     &werr);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto out;
	}

	if (!W_ERROR_IS_OK(werr)) {
		goto out;
	}

	for (i=0; i < ctr.ctr1->count; i++) {
		printf("status: %d\n",
			ctr.ctr1->array[i].status);
		printf("dns_domain_name: %s\n",
			ctr.ctr1->array[i].dns_domain_name);
		printf("result_name: %s\n",
			ctr.ctr1->array[i].result_name);
	}

 out:
	if (is_valid_policy_hnd(&bind_handle)) {
		rpccli_drsuapi_DsUnbind(cli, mem_ctx, &bind_handle, &werr);
	}

	return werr;
}

static void display_domain_controller_info_01(struct drsuapi_DsGetDCConnection01 *r)
{
	printf("client_ip_address:\t%s\n", r->client_ip_address);
	printf("unknown2:\t%d\n", r->unknown2);
	printf("connection_time:\t%d\n", r->connection_time);
	printf("unknown4:\t%d\n", r->unknown4);
	printf("unknown5:\t%d\n", r->unknown5);
	printf("unknown6:\t%d\n", r->unknown6);
	printf("client_account:\t%s\n", r->client_account);
}

static void display_domain_controller_info_1(struct drsuapi_DsGetDCInfo1 *r)
{
	printf("netbios_name:\t%s\n", r->netbios_name);
	printf("dns_name:\t%s\n", r->dns_name);
	printf("site_name:\t%s\n", r->site_name);
	printf("computer_dn:\t%s\n", r->computer_dn);
	printf("server_dn:\t%s\n", r->server_dn);
	printf("is_pdc:\t\t%s\n", r->is_pdc ? "true" : "false");
	printf("is_enabled:\t%s\n", r->is_enabled ? "true" : "false");
}

static void display_domain_controller_info_2(struct drsuapi_DsGetDCInfo2 *r)
{
	printf("netbios_name:\t%s\n", r->netbios_name);
	printf("dns_name:\t%s\n", r->dns_name);
	printf("site_name:\t%s\n", r->site_name);
	printf("site_dn:\t%s\n", r->site_dn);
	printf("computer_dn:\t%s\n", r->computer_dn);
	printf("server_dn:\t%s\n", r->server_dn);
	printf("ntds_dn:\t%s\n", r->ntds_dn);
	printf("is_pdc:\t\t%s\n", r->is_pdc ? "true" : "false");
	printf("is_enabled:\t%s\n", r->is_enabled ? "true" : "false");
	printf("is_gc:\t\t%s\n", r->is_gc ? "true" : "false");
	printf("site_guid:\t%s\n", GUID_string(talloc_tos(), &r->site_guid));
	printf("computer_guid:\t%s\n", GUID_string(talloc_tos(), &r->computer_guid));
	printf("server_guid:\t%s\n", GUID_string(talloc_tos(), &r->server_guid));
	printf("ntds_guid:\t%s\n", GUID_string(talloc_tos(), &r->ntds_guid));
}

static void display_domain_controller_info_3(struct drsuapi_DsGetDCInfo3 *r)
{
	printf("netbios_name:\t%s\n", r->netbios_name);
	printf("dns_name:\t%s\n", r->dns_name);
	printf("site_name:\t%s\n", r->site_name);
	printf("site_dn:\t%s\n", r->site_dn);
	printf("computer_dn:\t%s\n", r->computer_dn);
	printf("server_dn:\t%s\n", r->server_dn);
	printf("ntds_dn:\t%s\n", r->ntds_dn);
	printf("is_pdc:\t\t%s\n", r->is_pdc ? "true" : "false");
	printf("is_enabled:\t%s\n", r->is_enabled ? "true" : "false");
	printf("is_gc:\t\t%s\n", r->is_gc ? "true" : "false");
	printf("is_rodc:\t%s\n", r->is_rodc ? "true" : "false");
	printf("site_guid:\t%s\n", GUID_string(talloc_tos(), &r->site_guid));
	printf("computer_guid:\t%s\n", GUID_string(talloc_tos(), &r->computer_guid));
	printf("server_guid:\t%s\n", GUID_string(talloc_tos(), &r->server_guid));
	printf("ntds_guid:\t%s\n", GUID_string(talloc_tos(), &r->ntds_guid));
}

static void display_domain_controller_info(int32_t level,
					   union drsuapi_DsGetDCInfoCtr *ctr)
{
	int i;

	switch (level) {
		case DRSUAPI_DC_CONNECTION_CTR_01:
			for (i=0; i<ctr->ctr01.count; i++) {
				printf("----------\n");
				display_domain_controller_info_01(&ctr->ctr01.array[i]);
			}
			break;
		case DRSUAPI_DC_INFO_CTR_1:
			for (i=0; i<ctr->ctr1.count; i++) {
				printf("----------\n");
				display_domain_controller_info_1(&ctr->ctr1.array[i]);
			}
			break;
		case DRSUAPI_DC_INFO_CTR_2:
			for (i=0; i<ctr->ctr2.count; i++) {
				printf("----------\n");
				display_domain_controller_info_2(&ctr->ctr2.array[i]);
			}
			break;
		case DRSUAPI_DC_INFO_CTR_3:
			for (i=0; i<ctr->ctr3.count; i++) {
				printf("----------\n");
				display_domain_controller_info_3(&ctr->ctr3.array[i]);
			}
			break;
		default:
			break;
	}
}

static WERROR cmd_drsuapi_getdcinfo(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx, int argc,
				    const char **argv)
{
	NTSTATUS status;
	WERROR werr;

	struct GUID bind_guid;
	struct policy_handle bind_handle;

	const char *domain = NULL;
	int32_t level = 1;
	int32_t level_out;
	union drsuapi_DsGetDCInfoRequest req;
	union drsuapi_DsGetDCInfoCtr ctr;

	if (argc < 2) {
		printf("usage: %s domain [level]\n", argv[0]);
		return WERR_OK;
	}

	domain = argv[1];
	if (argc >= 3) {
		level = atoi(argv[2]);
	}

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &bind_guid);

	status = rpccli_drsuapi_DsBind(cli, mem_ctx,
				       &bind_guid,
				       NULL,
				       &bind_handle,
				       &werr);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	req.req1.domain_name = domain;
	req.req1.level = level;

	status = rpccli_drsuapi_DsGetDomainControllerInfo(cli, mem_ctx,
							  &bind_handle,
							  1,
							  &req,
							  &level_out,
							  &ctr,
							  &werr);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto out;
	}

	if (!W_ERROR_IS_OK(werr)) {
		goto out;
	}

	display_domain_controller_info(level_out, &ctr);
 out:
	if (is_valid_policy_hnd(&bind_handle)) {
		rpccli_drsuapi_DsUnbind(cli, mem_ctx, &bind_handle, &werr);
	}

	return werr;
}

/* List of commands exported by this module */

struct cmd_set drsuapi_commands[] = {

	{ "DRSUAPI" },
	{ "dscracknames", RPC_RTYPE_WERROR, NULL, cmd_drsuapi_cracknames, PI_DRSUAPI, NULL, "Crack Name", "" },
	{ "dsgetdcinfo", RPC_RTYPE_WERROR, NULL, cmd_drsuapi_getdcinfo, PI_DRSUAPI, NULL, "Get Domain Controller Info", "" },
	{ NULL }
};
