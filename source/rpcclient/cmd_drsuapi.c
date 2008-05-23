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
	struct drsuapi_DsBindInfoCtr bind_info;
	struct policy_handle bind_handle;

	int32_t level = 1;
	union drsuapi_DsNameRequest req;
	struct drsuapi_DsNameRequest1 req1;
	int32_t level_out;
	union drsuapi_DsNameCtr ctr;
	struct drsuapi_DsNameString names[1];

	if (argc < 2) {
		printf("usage: %s name\n", argv[0]);
		return WERR_OK;
	}

	ZERO_STRUCT(bind_info);

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &bind_guid);

	status = rpccli_drsuapi_DsBind(cli, mem_ctx,
				       &bind_guid,
				       NULL,
				       &bind_handle,
				       &werr);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	ZERO_STRUCT(req1);

	names[0].str = argv[1];

	req1.codepage		= 1252; /* german */
	req1.language		= 0x00000407; /* german */
	req1.count		= 1;
	req1.names		= names;
	req1.format_flags	= DRSUAPI_DS_NAME_FLAG_NO_FLAGS;
	req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_UKNOWN;
	req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;

	req.req1 = req1;

	status = rpccli_drsuapi_DsCrackNames(cli, mem_ctx,
					     &bind_handle,
					     level,
					     &req,
					     &level_out,
					     &ctr,
					     &werr);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	for (i=0; i < ctr.ctr1->count; i++) {
		printf("status: %d\n",
			ctr.ctr1->array[i].status);
		printf("dns_domain_name: %s\n",
			ctr.ctr1->array[i].dns_domain_name);
		printf("result_name: %s\n",
			ctr.ctr1->array[i].result_name);
	}

	return werr;
}

/* List of commands exported by this module */

struct cmd_set drsuapi_commands[] = {

	{ "DRSUAPI" },
	{ "dscracknames", RPC_RTYPE_WERROR, NULL, cmd_drsuapi_cracknames, PI_DRSUAPI, NULL, "Crack Name", "" },
	{ NULL }
};
