/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Group Support
 *  Copyright (C) Guenther Deschner 2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#include "librpc/gen_ndr/libnetapi.h"
#include "lib/netapi/netapi.h"
#include "lib/netapi/netapi_private.h"
#include "lib/netapi/libnetapi.h"

/****************************************************************
****************************************************************/

WERROR NetGroupAdd_r(struct libnetapi_ctx *ctx,
		     struct NetGroupAdd *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	POLICY_HND connect_handle, domain_handle, group_handle;
	struct lsa_String lsa_group_name;
	struct dom_sid2 *domain_sid = NULL;
	uint32_t rid = 0;

	struct GROUP_INFO_0 *info0 = NULL;
	struct GROUP_INFO_1 *info1 = NULL;
	struct GROUP_INFO_2 *info2 = NULL;
	struct GROUP_INFO_3 *info3 = NULL;
	union samr_GroupInfo info;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(group_handle);

	if (!r->in.buf) {
		return WERR_INVALID_PARAM;
	}

	switch (r->in.level) {
		case 0:
			info0 = (struct GROUP_INFO_0 *)r->in.buf;
			break;
		case 1:
			info1 = (struct GROUP_INFO_1 *)r->in.buf;
			break;
		case 2:
			info2 = (struct GROUP_INFO_2 *)r->in.buf;
			break;
		case 3:
			info3 = (struct GROUP_INFO_3 *)r->in.buf;
			break;
		default:
			werr = WERR_UNKNOWN_LEVEL;
			goto done;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_CREATE_GROUP |
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	switch (r->in.level) {
		case 0:
			init_lsa_String(&lsa_group_name, info0->grpi0_name);
			break;
		case 1:
			init_lsa_String(&lsa_group_name, info1->grpi1_name);
			break;
		case 2:
			init_lsa_String(&lsa_group_name, info2->grpi2_name);
			break;
		case 3:
			init_lsa_String(&lsa_group_name, info3->grpi3_name);
			break;
	}

	status = rpccli_samr_CreateDomainGroup(pipe_cli, ctx,
					       &domain_handle,
					       &lsa_group_name,
					       SEC_STD_DELETE |
					       SAMR_GROUP_ACCESS_SET_INFO,
					       &group_handle,
					       &rid);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	switch (r->in.level) {
		case 1:
			if (info1->grpi1_comment) {
				init_lsa_String(&info.description,
						info1->grpi1_comment);

				status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
								  &group_handle,
								  GROUPINFODESCRIPTION,
								  &info);
			}
			break;
		case 2:
			if (info2->grpi2_comment) {
				init_lsa_String(&info.description,
						info2->grpi2_comment);

				status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
								  &group_handle,
								  GROUPINFODESCRIPTION,
								  &info);
				if (!NT_STATUS_IS_OK(status)) {
					werr = ntstatus_to_werror(status);
					goto failed;
				}
			}

			if (info2->grpi2_attributes != 0) {
				info.attributes.attributes = info2->grpi2_attributes;
				status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
								  &group_handle,
								  GROUPINFOATTRIBUTES,
								  &info);

			}
			break;
		case 3:
			if (info3->grpi3_comment) {
				init_lsa_String(&info.description,
						info3->grpi3_comment);

				status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
								  &group_handle,
								  GROUPINFODESCRIPTION,
								  &info);
				if (!NT_STATUS_IS_OK(status)) {
					werr = ntstatus_to_werror(status);
					goto failed;
				}
			}

			if (info3->grpi3_attributes != 0) {
				info.attributes.attributes = info3->grpi3_attributes;
				status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
								  &group_handle,
								  GROUPINFOATTRIBUTES,
								  &info);
			}
			break;
		default:
			break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto failed;
	}

	werr = WERR_OK;
	goto done;

 failed:
	rpccli_samr_DeleteDomainGroup(pipe_cli, ctx,
				      &group_handle);

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&group_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &group_handle);
	}
	if (is_valid_policy_hnd(&domain_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &domain_handle);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetGroupAdd_l(struct libnetapi_ctx *ctx,
		     struct NetGroupAdd *r)
{
	return NetGroupAdd_r(ctx, r);
}

/****************************************************************
****************************************************************/

WERROR NetGroupDel_r(struct libnetapi_ctx *ctx,
		     struct NetGroupDel *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	POLICY_HND connect_handle, domain_handle, group_handle;
	struct lsa_String lsa_group_name;
	struct dom_sid2 *domain_sid = NULL;
	int i = 0;

	struct samr_Ids rids;
	struct samr_Ids types;
	union samr_GroupInfo *info = NULL;
	struct samr_RidTypeArray *rid_array = NULL;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(group_handle);

	if (!r->in.group_name) {
		return WERR_INVALID_PARAM;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	init_lsa_String(&lsa_group_name, r->in.group_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_group_name,
					 &rids,
					 &types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (types.ids[0] != SID_NAME_DOM_GRP) {
		werr = WERR_INVALID_DATATYPE;
		goto done;
	}

	status = rpccli_samr_OpenGroup(pipe_cli, ctx,
				       &domain_handle,
				       SEC_STD_DELETE |
				       SAMR_GROUP_ACCESS_GET_MEMBERS |
				       SAMR_GROUP_ACCESS_REMOVE_MEMBER |
				       SAMR_GROUP_ACCESS_ADD_MEMBER |
				       SAMR_GROUP_ACCESS_LOOKUP_INFO,
				       rids.ids[0],
				       &group_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_QueryGroupInfo(pipe_cli, ctx,
					    &group_handle,
					    GROUPINFOATTRIBUTES,
					    &info);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (!(info->attributes.attributes & SE_GROUP_ENABLED)) {
		werr = WERR_ACCESS_DENIED;
		goto done;
	}

	status = rpccli_samr_QueryGroupMember(pipe_cli, ctx,
					      &group_handle,
					      &rid_array);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	{
	struct lsa_Strings names;
	struct samr_Ids member_types;

	status = rpccli_samr_LookupRids(pipe_cli, ctx,
					&domain_handle,
					rid_array->count,
					rid_array->rids,
					&names,
					&member_types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}
	}

	for (i=0; i < rid_array->count; i++) {

		status = rpccli_samr_DeleteGroupMember(pipe_cli, ctx,
						       &group_handle,
						       rid_array->rids[i]);
		if (!NT_STATUS_IS_OK(status)) {
			werr = ntstatus_to_werror(status);
			goto done;
		}
	}

	status = rpccli_samr_DeleteDomainGroup(pipe_cli, ctx,
					       &group_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	ZERO_STRUCT(group_handle);

	werr = WERR_OK;

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&group_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &group_handle);
	}
	if (is_valid_policy_hnd(&domain_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &domain_handle);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetGroupDel_l(struct libnetapi_ctx *ctx,
		     struct NetGroupDel *r)
{
	return NetGroupDel_r(ctx, r);
}

/****************************************************************
****************************************************************/

WERROR NetGroupSetInfo_r(struct libnetapi_ctx *ctx,
			 struct NetGroupSetInfo *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	POLICY_HND connect_handle, domain_handle, group_handle;
	struct lsa_String lsa_group_name;
	struct dom_sid2 *domain_sid = NULL;

	struct samr_Ids rids;
	struct samr_Ids types;
	union samr_GroupInfo info;
	struct GROUP_INFO_0 *g0;
	struct GROUP_INFO_1 *g1;
	struct GROUP_INFO_2 *g2;
	struct GROUP_INFO_3 *g3;
	struct GROUP_INFO_1002 *g1002;
	struct GROUP_INFO_1005 *g1005;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(group_handle);

	if (!r->in.group_name) {
		return WERR_INVALID_PARAM;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	init_lsa_String(&lsa_group_name, r->in.group_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_group_name,
					 &rids,
					 &types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (types.ids[0] != SID_NAME_DOM_GRP) {
		werr = WERR_INVALID_DATATYPE;
		goto done;
	}

	status = rpccli_samr_OpenGroup(pipe_cli, ctx,
				       &domain_handle,
				       SAMR_GROUP_ACCESS_SET_INFO |
				       SAMR_GROUP_ACCESS_LOOKUP_INFO,
				       rids.ids[0],
				       &group_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	switch (r->in.level) {
		case 0:
			g0 = (struct GROUP_INFO_0 *)r->in.buf;
			init_lsa_String(&info.name, g0->grpi0_name);
			status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
							  &group_handle,
							  GROUPINFONAME,
							  &info);
			break;
		case 1:
			g1 = (struct GROUP_INFO_1 *)r->in.buf;
			init_lsa_String(&info.description, g1->grpi1_comment);
			status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
							  &group_handle,
							  GROUPINFODESCRIPTION,
							  &info);
			break;
		case 2:
			g2 = (struct GROUP_INFO_2 *)r->in.buf;
			init_lsa_String(&info.description, g2->grpi2_comment);
			status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
							  &group_handle,
							  GROUPINFODESCRIPTION,
							  &info);
			if (!NT_STATUS_IS_OK(status)) {
				werr = ntstatus_to_werror(status);
				goto done;
			}
			info.attributes.attributes = g2->grpi2_attributes;
			status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
							  &group_handle,
							  GROUPINFOATTRIBUTES,
							  &info);
			break;
		case 3:
			g3 = (struct GROUP_INFO_3 *)r->in.buf;
			init_lsa_String(&info.description, g3->grpi3_comment);
			status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
							  &group_handle,
							  GROUPINFODESCRIPTION,
							  &info);
			if (!NT_STATUS_IS_OK(status)) {
				werr = ntstatus_to_werror(status);
				goto done;
			}
			info.attributes.attributes = g3->grpi3_attributes;
			status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
							  &group_handle,
							  GROUPINFOATTRIBUTES,
							  &info);
			break;
		case 1002:
			g1002 = (struct GROUP_INFO_1002 *)r->in.buf;
			init_lsa_String(&info.description, g1002->grpi1002_comment);
			status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
							  &group_handle,
							  GROUPINFODESCRIPTION,
							  &info);
			break;
		case 1005:
			g1005 = (struct GROUP_INFO_1005 *)r->in.buf;
			info.attributes.attributes = g1005->grpi1005_attributes;
			status = rpccli_samr_SetGroupInfo(pipe_cli, ctx,
							  &group_handle,
							  GROUPINFOATTRIBUTES,
							  &info);
			break;
		default:
			status = NT_STATUS_INVALID_LEVEL;
			break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = WERR_OK;

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&group_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &group_handle);
	}
	if (is_valid_policy_hnd(&domain_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &domain_handle);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetGroupSetInfo_l(struct libnetapi_ctx *ctx,
			 struct NetGroupSetInfo *r)
{
	return NetGroupSetInfo_r(ctx, r);
}

/****************************************************************
****************************************************************/

static WERROR map_group_info_to_buffer(TALLOC_CTX *mem_ctx,
				       uint32_t level,
				       struct samr_GroupInfoAll *info,
				       struct dom_sid2 *domain_sid,
				       uint32_t rid,
				       uint8_t **buffer)
{
	struct GROUP_INFO_0 info0;
	struct GROUP_INFO_1 info1;
	struct GROUP_INFO_2 info2;
	struct GROUP_INFO_3 info3;

	switch (level) {
		case 0:
			info0.grpi0_name	= info->name.string;

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, &info0, sizeof(info0));

			break;
		case 1:
			info1.grpi1_name	= info->name.string;
			info1.grpi1_comment	= info->description.string;

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, &info1, sizeof(info1));

			break;
		case 2:
			info2.grpi2_name	= info->name.string;
			info2.grpi2_comment	= info->description.string;
			info2.grpi2_group_id	= rid;
			info2.grpi2_attributes	= info->attributes;

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, &info2, sizeof(info2));

			break;
		case 3:
			info3.grpi3_name	= info->name.string;
			info3.grpi3_comment	= info->description.string;
			info3.grpi3_attributes	= info->attributes;

			if (!sid_compose((struct dom_sid *)&info3.grpi3_group_sid, domain_sid, rid)) {
				return WERR_NOMEM;
			}

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, &info3, sizeof(info3));

			break;
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	W_ERROR_HAVE_NO_MEMORY(*buffer);

	return WERR_OK;
}

/****************************************************************
****************************************************************/

WERROR NetGroupGetInfo_r(struct libnetapi_ctx *ctx,
			 struct NetGroupGetInfo *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	POLICY_HND connect_handle, domain_handle, group_handle;
	struct lsa_String lsa_group_name;
	struct dom_sid2 *domain_sid = NULL;

	struct samr_Ids rids;
	struct samr_Ids types;
	union samr_GroupInfo *info = NULL;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(group_handle);

	if (!r->in.group_name) {
		return WERR_INVALID_PARAM;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	init_lsa_String(&lsa_group_name, r->in.group_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_group_name,
					 &rids,
					 &types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (types.ids[0] != SID_NAME_DOM_GRP) {
		werr = WERR_INVALID_DATATYPE;
		goto done;
	}

	status = rpccli_samr_OpenGroup(pipe_cli, ctx,
				       &domain_handle,
				       SAMR_GROUP_ACCESS_LOOKUP_INFO,
				       rids.ids[0],
				       &group_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_QueryGroupInfo(pipe_cli, ctx,
					    &group_handle,
					    GROUPINFOALL2,
					    &info);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = map_group_info_to_buffer(ctx, r->in.level,
					&info->all2, domain_sid, rids.ids[0],
					r->out.buf);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}
 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&group_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &group_handle);
	}
	if (is_valid_policy_hnd(&domain_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &domain_handle);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetGroupGetInfo_l(struct libnetapi_ctx *ctx,
			 struct NetGroupGetInfo *r)
{
	return NetGroupGetInfo_r(ctx, r);
}

/****************************************************************
****************************************************************/

WERROR NetGroupAddUser_r(struct libnetapi_ctx *ctx,
			 struct NetGroupAddUser *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	POLICY_HND connect_handle, domain_handle, group_handle;
	struct lsa_String lsa_group_name, lsa_user_name;
	struct dom_sid2 *domain_sid = NULL;

	struct samr_Ids rids;
	struct samr_Ids types;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(group_handle);

	if (!r->in.group_name) {
		return WERR_INVALID_PARAM;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	init_lsa_String(&lsa_group_name, r->in.group_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_group_name,
					 &rids,
					 &types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = WERR_GROUP_NOT_FOUND;
		goto done;
	}

	if (types.ids[0] != SID_NAME_DOM_GRP) {
		werr = WERR_GROUP_NOT_FOUND;
		goto done;
	}

	status = rpccli_samr_OpenGroup(pipe_cli, ctx,
				       &domain_handle,
				       SAMR_GROUP_ACCESS_ADD_MEMBER,
				       rids.ids[0],
				       &group_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	init_lsa_String(&lsa_user_name, r->in.user_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_user_name,
					 &rids,
					 &types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = WERR_USER_NOT_FOUND;
		goto done;
	}

	if (types.ids[0] != SID_NAME_USER) {
		werr = WERR_USER_NOT_FOUND;
		goto done;
	}

	status = rpccli_samr_AddGroupMember(pipe_cli, ctx,
					    &group_handle,
					    rids.ids[0],
					    7); /* why ? */
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = WERR_OK;

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&group_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &group_handle);
	}
	if (is_valid_policy_hnd(&domain_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &domain_handle);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetGroupAddUser_l(struct libnetapi_ctx *ctx,
			 struct NetGroupAddUser *r)
{
	return NetGroupAddUser_r(ctx, r);
}

/****************************************************************
****************************************************************/

WERROR NetGroupDelUser_r(struct libnetapi_ctx *ctx,
			 struct NetGroupDelUser *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	POLICY_HND connect_handle, domain_handle, group_handle;
	struct lsa_String lsa_group_name, lsa_user_name;
	struct dom_sid2 *domain_sid = NULL;

	struct samr_Ids rids;
	struct samr_Ids types;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(group_handle);

	if (!r->in.group_name) {
		return WERR_INVALID_PARAM;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	init_lsa_String(&lsa_group_name, r->in.group_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_group_name,
					 &rids,
					 &types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = WERR_GROUP_NOT_FOUND;
		goto done;
	}

	if (types.ids[0] != SID_NAME_DOM_GRP) {
		werr = WERR_GROUP_NOT_FOUND;
		goto done;
	}

	status = rpccli_samr_OpenGroup(pipe_cli, ctx,
				       &domain_handle,
				       SAMR_GROUP_ACCESS_REMOVE_MEMBER,
				       rids.ids[0],
				       &group_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	init_lsa_String(&lsa_user_name, r->in.user_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_user_name,
					 &rids,
					 &types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = WERR_USER_NOT_FOUND;
		goto done;
	}

	if (types.ids[0] != SID_NAME_USER) {
		werr = WERR_USER_NOT_FOUND;
		goto done;
	}

	status = rpccli_samr_DeleteGroupMember(pipe_cli, ctx,
					       &group_handle,
					       rids.ids[0]);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = WERR_OK;

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&group_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &group_handle);
	}
	if (is_valid_policy_hnd(&domain_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &domain_handle);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetGroupDelUser_l(struct libnetapi_ctx *ctx,
			 struct NetGroupDelUser *r)
{
	return NetGroupDelUser_r(ctx, r);
}

/****************************************************************
****************************************************************/

WERROR NetGroupEnum_r(struct libnetapi_ctx *ctx,
		      struct NetGroupEnum *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetGroupEnum_l(struct libnetapi_ctx *ctx,
		      struct NetGroupEnum *r)
{
	return WERR_NOT_SUPPORTED;
}
