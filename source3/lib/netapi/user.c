/*
 *  Unix SMB/CIFS implementation.
 *  NetApi User Support
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

static void convert_USER_INFO_X_to_samr_user_info21(struct USER_INFO_X *infoX,
						    struct samr_UserInfo21 *info21)
{
	uint32_t fields_present = SAMR_FIELD_ACCT_FLAGS;
	struct samr_LogonHours zero_logon_hours;
	struct lsa_BinaryString zero_parameters;
	uint32_t acct_flags = 0;
	NTTIME password_age;

	ZERO_STRUCTP(info21);
	ZERO_STRUCT(zero_logon_hours);
	ZERO_STRUCT(zero_parameters);

	if (infoX->usriX_name) {
		fields_present |= SAMR_FIELD_FULL_NAME;
	}
	if (infoX->usriX_password) {
		fields_present |= SAMR_FIELD_PASSWORD;
	}
	if (infoX->usriX_flags) {
		fields_present |= SAMR_FIELD_ACCT_FLAGS;
	}
	if (infoX->usriX_name) {
		fields_present |= SAMR_FIELD_FULL_NAME;
	}
	if (infoX->usriX_home_dir) {
		fields_present |= SAMR_FIELD_HOME_DIRECTORY;
	}
	if (infoX->usriX_script_path) {
		fields_present |= SAMR_FIELD_LOGON_SCRIPT;
	}
	if (infoX->usriX_comment) {
		fields_present |= SAMR_FIELD_DESCRIPTION;
	}
	if (infoX->usriX_password_age) {
		fields_present |= SAMR_FIELD_FORCE_PWD_CHANGE;
	}

	acct_flags |= infoX->usriX_flags | ACB_NORMAL;

	unix_to_nt_time_abs(&password_age, infoX->usriX_password_age);

	/* TODO: infoX->usriX_priv */
	init_samr_user_info21(info21,
			      0,
			      0,
			      0,
			      0,
			      0,
			      password_age,
			      NULL,
			      infoX->usriX_name,
			      infoX->usriX_home_dir,
			      NULL,
			      infoX->usriX_script_path,
			      NULL,
			      infoX->usriX_comment,
			      NULL,
			      NULL,
			      &zero_parameters,
			      0,
			      0,
			      acct_flags,
			      fields_present,
			      zero_logon_hours,
			      0,
			      0,
			      0,
			      0,
			      0,
			      0,
			      0);
}

/****************************************************************
****************************************************************/

static NTSTATUS construct_USER_INFO_X(uint32_t level,
				      uint8_t *buffer,
				      struct USER_INFO_X *uX)
{
	struct USER_INFO_0 *u0 = NULL;
	struct USER_INFO_1 *u1 = NULL;
	struct USER_INFO_2 *u2 = NULL;
	struct USER_INFO_1007 *u1007 = NULL;

	if (!buffer || !uX) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ZERO_STRUCTP(uX);

	switch (level) {
		case 0:
			u0 = (struct USER_INFO_0 *)buffer;
			uX->usriX_name		= u0->usri0_name;
			break;
		case 1:
			u1 = (struct USER_INFO_1 *)buffer;
			uX->usriX_name		= u1->usri1_name;
			uX->usriX_password	= u1->usri1_password;
			uX->usriX_password_age	= u1->usri1_password_age;
			uX->usriX_priv		= u1->usri1_priv;
			uX->usriX_home_dir	= u1->usri1_home_dir;
			uX->usriX_comment	= u1->usri1_comment;
			uX->usriX_flags		= u1->usri1_flags;
			uX->usriX_script_path	= u1->usri1_script_path;
			break;
		case 2:
			u2 = (struct USER_INFO_2 *)buffer;
			uX->usriX_name		= u2->usri2_name;
			uX->usriX_password	= u2->usri2_password;
			uX->usriX_password_age	= u2->usri2_password_age;
			uX->usriX_priv		= u2->usri2_priv;
			uX->usriX_home_dir	= u2->usri2_home_dir;
			uX->usriX_comment	= u2->usri2_comment;
			uX->usriX_flags		= u2->usri2_flags;
			uX->usriX_script_path	= u2->usri2_script_path;
			uX->usriX_auth_flags	= u2->usri2_auth_flags;
			uX->usriX_full_name	= u2->usri2_full_name;
			uX->usriX_usr_comment	= u2->usri2_usr_comment;
			uX->usriX_parms		= u2->usri2_parms;
			uX->usriX_workstations	= u2->usri2_workstations;
			uX->usriX_last_logon	= u2->usri2_last_logon;
			uX->usriX_last_logoff	= u2->usri2_last_logoff;
			uX->usriX_acct_expires	= u2->usri2_acct_expires;
			uX->usriX_max_storage	= u2->usri2_max_storage;
			uX->usriX_units_per_week= u2->usri2_units_per_week;
			uX->usriX_logon_hours	= u2->usri2_logon_hours;
			uX->usriX_bad_pw_count	= u2->usri2_bad_pw_count;
			uX->usriX_num_logons	= u2->usri2_num_logons;
			uX->usriX_logon_server	= u2->usri2_logon_server;
			uX->usriX_country_code	= u2->usri2_country_code;
			uX->usriX_code_page	= u2->usri2_code_page;
			break;
		case 1007:
			u1007 = (struct USER_INFO_1007 *)buffer;
			uX->usriX_comment	= u1007->usri1007_comment;
			break;
		case 3:
		case 4:
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

WERROR NetUserAdd_r(struct libnetapi_ctx *ctx,
		    struct NetUserAdd *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	POLICY_HND connect_handle, domain_handle, user_handle;
	struct lsa_String lsa_account_name;
	struct dom_sid2 *domain_sid = NULL;
	struct samr_UserInfo21 info21;
	union samr_UserInfo *user_info = NULL;
	struct samr_PwInfo pw_info;
	uint32_t access_granted = 0;
	uint32_t rid = 0;
	struct USER_INFO_X uX;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(user_handle);

	if (!r->in.buffer) {
		return WERR_INVALID_PARAM;
	}

	switch (r->in.level) {
		case 1:
			break;
		case 2:
		case 3:
		case 4:
		default:
			werr = WERR_NOT_SUPPORTED;
			goto done;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, &ndr_table_samr.syntax_id,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = construct_USER_INFO_X(r->in.level, r->in.buffer, &uX);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_LOOKUP_INFO_1 |
					  SAMR_DOMAIN_ACCESS_CREATE_USER |
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	init_lsa_String(&lsa_account_name, uX.usriX_name);

	status = rpccli_samr_CreateUser2(pipe_cli, ctx,
					 &domain_handle,
					 &lsa_account_name,
					 ACB_NORMAL,
					 SEC_STD_WRITE_DAC |
					 SEC_STD_DELETE |
					 SAMR_USER_ACCESS_SET_PASSWORD |
					 SAMR_USER_ACCESS_SET_ATTRIBUTES |
					 SAMR_USER_ACCESS_GET_ATTRIBUTES,
					 &user_handle,
					 &access_granted,
					 &rid);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_QueryUserInfo(pipe_cli, ctx,
					   &user_handle,
					   16,
					   &user_info);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	if (!(user_info->info16.acct_flags & ACB_NORMAL)) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	status = rpccli_samr_GetUserPwInfo(pipe_cli, ctx,
					   &user_handle,
					   &pw_info);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	convert_USER_INFO_X_to_samr_user_info21(&uX,
						&info21);

	ZERO_STRUCTP(user_info);

	if (uX.usriX_password) {

		user_info->info25.info = info21;

		init_samr_CryptPasswordEx(uX.usriX_password,
					  &cli->user_session_key,
					  &user_info->info25.password);

		status = rpccli_samr_SetUserInfo2(pipe_cli, ctx,
						  &user_handle,
						  25,
						  user_info);

		if (NT_STATUS_EQUAL(status, NT_STATUS(DCERPC_FAULT_INVALID_TAG))) {

			user_info->info23.info = info21;

			init_samr_CryptPassword(uX.usriX_password,
						&cli->user_session_key,
						&user_info->info23.password);

			status = rpccli_samr_SetUserInfo2(pipe_cli, ctx,
							  &user_handle,
							  23,
							  user_info);
		}
	} else {

		user_info->info21 = info21;

		status = rpccli_samr_SetUserInfo(pipe_cli, ctx,
						 &user_handle,
						 21,
						 user_info);

	}
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto failed;
	}

	werr = WERR_OK;
	goto done;

 failed:
	rpccli_samr_DeleteUser(pipe_cli, ctx,
			       &user_handle);

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&user_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &user_handle);
	}

	if (ctx->disable_policy_handle_cache) {
		libnetapi_samr_close_domain_handle(ctx, &domain_handle);
		libnetapi_samr_close_connect_handle(ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetUserAdd_l(struct libnetapi_ctx *ctx,
		    struct NetUserAdd *r)
{
	/* for now just talk to local RPC server */
	if (!r->in.server_name) {
		r->in.server_name = "localhost";
	}

	return NetUserAdd_r(ctx, r);
}

/****************************************************************
****************************************************************/

WERROR NetUserDel_r(struct libnetapi_ctx *ctx,
		    struct NetUserDel *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;
	POLICY_HND connect_handle, builtin_handle, domain_handle, user_handle;
	struct lsa_String lsa_account_name;
	struct samr_Ids user_rids, name_types;
	struct dom_sid2 *domain_sid = NULL;
	struct dom_sid2 user_sid;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(builtin_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(user_handle);

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, &ndr_table_samr.syntax_id,
				   &pipe_cli);
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

	status = rpccli_samr_OpenDomain(pipe_cli, ctx,
					&connect_handle,
					SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					CONST_DISCARD(DOM_SID *, &global_sid_Builtin),
					&builtin_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	init_lsa_String(&lsa_account_name, r->in.user_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_account_name,
					 &user_rids,
					 &name_types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_OpenUser(pipe_cli, ctx,
				      &domain_handle,
				      STD_RIGHT_DELETE_ACCESS,
				      user_rids.ids[0],
				      &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	sid_compose(&user_sid, domain_sid, user_rids.ids[0]);

	status = rpccli_samr_RemoveMemberFromForeignDomain(pipe_cli, ctx,
							   &builtin_handle,
							   &user_sid);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_DeleteUser(pipe_cli, ctx,
					&user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = WERR_OK;

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&user_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &user_handle);
	}

	if (ctx->disable_policy_handle_cache) {
		libnetapi_samr_close_builtin_handle(ctx, &builtin_handle);
		libnetapi_samr_close_domain_handle(ctx, &domain_handle);
		libnetapi_samr_close_connect_handle(ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetUserDel_l(struct libnetapi_ctx *ctx,
		    struct NetUserDel *r)
{
	/* for now just talk to local RPC server */
	if (!r->in.server_name) {
		r->in.server_name = "localhost";
	}

	return NetUserDel_r(ctx, r);
}

/****************************************************************
****************************************************************/

static NTSTATUS libnetapi_samr_lookup_user(TALLOC_CTX *mem_ctx,
					   struct rpc_pipe_client *pipe_cli,
					   struct policy_handle *domain_handle,
					   struct policy_handle *builtin_handle,
					   const char *user_name,
					   uint32_t rid,
					   uint32_t level,
					   struct samr_UserInfo21 **info21,
					   struct sec_desc_buf **sec_desc)
{
	NTSTATUS status;

	struct policy_handle user_handle;
	union samr_UserInfo *user_info = NULL;
	struct samr_RidWithAttributeArray *rid_array = NULL;
	uint32_t access_mask = SEC_STD_READ_CONTROL |
			       SAMR_USER_ACCESS_GET_ATTRIBUTES |
			       SAMR_USER_ACCESS_GET_NAME_ETC;

	ZERO_STRUCT(user_handle);

	switch (level) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 10:
		case 11:
		case 20:
		case 23:
			break;
		default:
			return NT_STATUS_INVALID_LEVEL;
	}

	if (level == 0) {
		return NT_STATUS_OK;
	}

	status = rpccli_samr_OpenUser(pipe_cli, mem_ctx,
				      domain_handle,
				      access_mask,
				      rid,
				      &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_samr_QueryUserInfo(pipe_cli, mem_ctx,
					   &user_handle,
					   21,
					   &user_info);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_samr_QuerySecurity(pipe_cli, mem_ctx,
					   &user_handle,
					   SECINFO_DACL,
					   sec_desc);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (level == 1) {
		status = rpccli_samr_GetGroupsForUser(pipe_cli, mem_ctx,
						      &user_handle,
						      &rid_array);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

#if 0
		status = rpccli_samr_GetAliasMembership(pipe_cli, ctx,
							&builtin_handle,
							&sids,
							&rids);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
#endif
	}

	*info21 = &user_info->info21;

 done:
	if (is_valid_policy_hnd(&user_handle)) {
		rpccli_samr_Close(pipe_cli, mem_ctx, &user_handle);
	}

	return status;
}

/****************************************************************
****************************************************************/

static NTSTATUS libnetapi_samr_lookup_user_map_USER_INFO(TALLOC_CTX *mem_ctx,
							 struct rpc_pipe_client *pipe_cli,
							 struct dom_sid *domain_sid,
							 struct policy_handle *domain_handle,
							 struct policy_handle *builtin_handle,
							 const char *user_name,
							 uint32_t rid,
							 uint32_t level,
							 uint8_t **buffer,
							 uint32_t *num_entries)
{
	NTSTATUS status;

	struct samr_UserInfo21 *info21 = NULL;
	struct sec_desc_buf *sec_desc = NULL;
	struct dom_sid sid;

	struct USER_INFO_0 info0;
	struct USER_INFO_10 info10;
	struct USER_INFO_20 info20;
	struct USER_INFO_23 info23;

	switch (level) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 10:
		case 11:
		case 20:
		case 23:
			break;
		default:
			return NT_STATUS_INVALID_LEVEL;
	}

	if (level == 0) {
		info0.usri0_name = talloc_strdup(mem_ctx, user_name);
		NT_STATUS_HAVE_NO_MEMORY(info0.usri0_name);

		ADD_TO_ARRAY(mem_ctx, struct USER_INFO_0, info0,
			     (struct USER_INFO_0 **)buffer, num_entries);

		return NT_STATUS_OK;
	}

	status = libnetapi_samr_lookup_user(mem_ctx, pipe_cli,
					    domain_handle,
					    builtin_handle,
					    user_name,
					    rid,
					    level,
					    &info21,
					    &sec_desc);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	switch (level) {
		case 10:
			info10.usri10_name = talloc_strdup(mem_ctx, user_name);
			NT_STATUS_HAVE_NO_MEMORY(info10.usri10_name);

			info10.usri10_comment = talloc_strdup(mem_ctx,
				info21->description.string);

			info10.usri10_full_name = talloc_strdup(mem_ctx,
				info21->full_name.string);

			info10.usri10_usr_comment = talloc_strdup(mem_ctx,
				info21->comment.string);

			ADD_TO_ARRAY(mem_ctx, struct USER_INFO_10, info10,
				     (struct USER_INFO_10 **)buffer, num_entries);

			break;

		case 20:
			info20.usri20_name = talloc_strdup(mem_ctx, user_name);
			NT_STATUS_HAVE_NO_MEMORY(info20.usri20_name);

			info20.usri20_comment = talloc_strdup(mem_ctx,
				info21->description.string);

			info20.usri20_full_name = talloc_strdup(mem_ctx,
				info21->full_name.string);

			info20.usri20_flags = info21->acct_flags;
			info20.usri20_user_id = rid;

			ADD_TO_ARRAY(mem_ctx, struct USER_INFO_20, info20,
				     (struct USER_INFO_20 **)buffer, num_entries);

			break;
		case 23:
			info23.usri23_name = talloc_strdup(mem_ctx, user_name);
			NT_STATUS_HAVE_NO_MEMORY(info23.usri23_name);

			info23.usri23_comment = talloc_strdup(mem_ctx,
				info21->description.string);

			info23.usri23_full_name = talloc_strdup(mem_ctx,
				info21->full_name.string);

			info23.usri23_flags = info21->acct_flags;

			if (!sid_compose(&sid, domain_sid, rid)) {
				return NT_STATUS_NO_MEMORY;
			}

			info23.usri23_user_sid =
				(struct domsid *)sid_dup_talloc(mem_ctx, &sid);

			ADD_TO_ARRAY(mem_ctx, struct USER_INFO_23, info23,
				     (struct USER_INFO_23 **)buffer, num_entries);
			break;
	}

 done:
	return status;
}

/****************************************************************
****************************************************************/

WERROR NetUserEnum_r(struct libnetapi_ctx *ctx,
		     struct NetUserEnum *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	struct policy_handle connect_handle;
	struct dom_sid2 *domain_sid = NULL;
	struct policy_handle domain_handle;
	struct samr_SamArray *sam = NULL;
	uint32_t filter = ACB_NORMAL;
	int i;
	uint32_t entries_read = 0;

	NTSTATUS status = NT_STATUS_OK;
	WERROR werr;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);

	if (!r->out.buffer) {
		return WERR_INVALID_PARAM;
	}

	*r->out.buffer = NULL;
	*r->out.entries_read = 0;

	switch (r->in.level) {
		case 0:
		case 10:
		case 20:
		case 23:
			break;
		case 1:
		case 2:
		case 3:
		case 11:
		default:
			return WERR_NOT_SUPPORTED;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, &ndr_table_samr.syntax_id,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_LOOKUP_INFO_2 |
					  SAMR_DOMAIN_ACCESS_ENUM_ACCOUNTS |
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	switch (r->in.filter) {
		case FILTER_NORMAL_ACCOUNT:
			filter = ACB_NORMAL;
			break;
		case FILTER_TEMP_DUPLICATE_ACCOUNT:
			filter = ACB_TEMPDUP;
			break;
		case FILTER_INTERDOMAIN_TRUST_ACCOUNT:
			filter = ACB_DOMTRUST;
			break;
		case FILTER_WORKSTATION_TRUST_ACCOUNT:
			filter = ACB_WSTRUST;
			break;
		case FILTER_SERVER_TRUST_ACCOUNT:
			filter = ACB_SVRTRUST;
			break;
		default:
			break;
	}

	status = rpccli_samr_EnumDomainUsers(pipe_cli,
					     ctx,
					     &domain_handle,
					     r->in.resume_handle,
					     filter,
					     &sam,
					     r->in.prefmaxlen,
					     &entries_read);
	werr = ntstatus_to_werror(status);
	if (NT_STATUS_IS_ERR(status)) {
		goto done;
	}

	for (i=0; i < sam->count; i++) {

		status = libnetapi_samr_lookup_user_map_USER_INFO(ctx, pipe_cli,
								  domain_sid,
								  &domain_handle,
								  NULL, /*&builtin_handle, */
								  sam->entries[i].name.string,
								  sam->entries[i].idx,
								  r->in.level,
								  r->out.buffer,
								  r->out.entries_read);
		if (!NT_STATUS_IS_OK(status)) {
			werr = ntstatus_to_werror(status);
			goto done;
		}
	}

 done:
	if (!cli) {
		return werr;
	}

	/* if last query */
	if (NT_STATUS_IS_OK(status) ||
	    NT_STATUS_IS_ERR(status)) {

		if (ctx->disable_policy_handle_cache) {
			libnetapi_samr_close_domain_handle(ctx, &domain_handle);
			libnetapi_samr_close_connect_handle(ctx, &connect_handle);
		}
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetUserEnum_l(struct libnetapi_ctx *ctx,
		     struct NetUserEnum *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

static WERROR convert_samr_dispinfo_to_NET_DISPLAY_USER(TALLOC_CTX *mem_ctx,
							struct samr_DispInfoGeneral *info,
							uint32_t *entries_read,
							void **buffer)
{
	struct NET_DISPLAY_USER *user = NULL;
	int i;

	user = TALLOC_ZERO_ARRAY(mem_ctx,
				 struct NET_DISPLAY_USER,
				 info->count);
	W_ERROR_HAVE_NO_MEMORY(user);

	for (i = 0; i < info->count; i++) {
		user[i].usri1_name = talloc_strdup(mem_ctx,
			info->entries[i].account_name.string);
		user[i].usri1_comment = talloc_strdup(mem_ctx,
			info->entries[i].description.string);
		user[i].usri1_flags =
			info->entries[i].acct_flags;
		user[i].usri1_full_name = talloc_strdup(mem_ctx,
			info->entries[i].full_name.string);
		user[i].usri1_user_id =
			info->entries[i].rid;
		user[i].usri1_next_index =
			info->entries[i].idx;

		if (!user[i].usri1_name) {
			return WERR_NOMEM;
		}
	}

	*buffer = talloc_memdup(mem_ctx, user,
		sizeof(struct NET_DISPLAY_USER) * info->count);
	W_ERROR_HAVE_NO_MEMORY(*buffer);

	*entries_read = info->count;

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static WERROR convert_samr_dispinfo_to_NET_DISPLAY_MACHINE(TALLOC_CTX *mem_ctx,
							   struct samr_DispInfoFull *info,
							   uint32_t *entries_read,
							   void **buffer)
{
	struct NET_DISPLAY_MACHINE *machine = NULL;
	int i;

	machine = TALLOC_ZERO_ARRAY(mem_ctx,
				    struct NET_DISPLAY_MACHINE,
				    info->count);
	W_ERROR_HAVE_NO_MEMORY(machine);

	for (i = 0; i < info->count; i++) {
		machine[i].usri2_name = talloc_strdup(mem_ctx,
			info->entries[i].account_name.string);
		machine[i].usri2_comment = talloc_strdup(mem_ctx,
			info->entries[i].description.string);
		machine[i].usri2_flags =
			info->entries[i].acct_flags;
		machine[i].usri2_user_id =
			info->entries[i].rid;
		machine[i].usri2_next_index =
			info->entries[i].idx;

		if (!machine[i].usri2_name) {
			return WERR_NOMEM;
		}
	}

	*buffer = talloc_memdup(mem_ctx, machine,
		sizeof(struct NET_DISPLAY_MACHINE) * info->count);
	W_ERROR_HAVE_NO_MEMORY(*buffer);

	*entries_read = info->count;

	return WERR_OK;
}

/****************************************************************
****************************************************************/

static WERROR convert_samr_dispinfo_to_NET_DISPLAY_GROUP(TALLOC_CTX *mem_ctx,
							 struct samr_DispInfoFullGroups *info,
							 uint32_t *entries_read,
							 void **buffer)
{
	struct NET_DISPLAY_GROUP *group = NULL;
	int i;

	group = TALLOC_ZERO_ARRAY(mem_ctx,
				  struct NET_DISPLAY_GROUP,
				  info->count);
	W_ERROR_HAVE_NO_MEMORY(group);

	for (i = 0; i < info->count; i++) {
		group[i].grpi3_name = talloc_strdup(mem_ctx,
			info->entries[i].account_name.string);
		group[i].grpi3_comment = talloc_strdup(mem_ctx,
			info->entries[i].description.string);
		group[i].grpi3_group_id =
			info->entries[i].rid;
		group[i].grpi3_attributes =
			info->entries[i].acct_flags;
		group[i].grpi3_next_index =
			info->entries[i].idx;

		if (!group[i].grpi3_name) {
			return WERR_NOMEM;
		}
	}

	*buffer = talloc_memdup(mem_ctx, group,
		sizeof(struct NET_DISPLAY_GROUP) * info->count);
	W_ERROR_HAVE_NO_MEMORY(*buffer);

	*entries_read = info->count;

	return WERR_OK;

}

/****************************************************************
****************************************************************/

static WERROR convert_samr_dispinfo_to_NET_DISPLAY(TALLOC_CTX *mem_ctx,
						   union samr_DispInfo *info,
						   uint32_t level,
						   uint32_t *entries_read,
						   void **buffer)
{
	switch (level) {
		case 1:
			return convert_samr_dispinfo_to_NET_DISPLAY_USER(mem_ctx,
									 &info->info1,
									 entries_read,
									 buffer);
		case 2:
			return convert_samr_dispinfo_to_NET_DISPLAY_MACHINE(mem_ctx,
									    &info->info2,
									    entries_read,
									    buffer);
		case 3:
			return convert_samr_dispinfo_to_NET_DISPLAY_GROUP(mem_ctx,
									  &info->info3,
									  entries_read,
									  buffer);
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

WERROR NetQueryDisplayInformation_r(struct libnetapi_ctx *ctx,
				    struct NetQueryDisplayInformation *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	struct policy_handle connect_handle;
	struct dom_sid2 *domain_sid = NULL;
	struct policy_handle domain_handle;
	union samr_DispInfo info;

	uint32_t total_size = 0;
	uint32_t returned_size = 0;

	NTSTATUS status = NT_STATUS_OK;
	WERROR werr;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);

	switch (r->in.level) {
		case 1:
		case 2:
		case 3:
			break;
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, &ndr_table_samr.syntax_id,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_LOOKUP_INFO_2 |
					  SAMR_DOMAIN_ACCESS_ENUM_ACCOUNTS |
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = rpccli_samr_QueryDisplayInfo2(pipe_cli,
					       ctx,
					       &domain_handle,
					       r->in.level,
					       r->in.idx,
					       r->in.entries_requested,
					       r->in.prefmaxlen,
					       &total_size,
					       &returned_size,
					       &info);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = convert_samr_dispinfo_to_NET_DISPLAY(ctx, &info,
						    r->in.level,
						    r->out.entries_read,
						    r->out.buffer);
 done:
	if (!cli) {
		return werr;
	}

	/* if last query */
	if (NT_STATUS_IS_OK(status) ||
	    NT_STATUS_IS_ERR(status)) {

		if (ctx->disable_policy_handle_cache) {
			libnetapi_samr_close_domain_handle(ctx, &domain_handle);
			libnetapi_samr_close_connect_handle(ctx, &connect_handle);
		}
	}

	return werr;

}

/****************************************************************
****************************************************************/


WERROR NetQueryDisplayInformation_l(struct libnetapi_ctx *ctx,
				    struct NetQueryDisplayInformation *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetUserChangePassword_r(struct libnetapi_ctx *ctx,
			       struct NetUserChangePassword *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetUserChangePassword_l(struct libnetapi_ctx *ctx,
			       struct NetUserChangePassword *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetUserGetInfo_r(struct libnetapi_ctx *ctx,
			struct NetUserGetInfo *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;

	struct policy_handle connect_handle, domain_handle, builtin_handle, user_handle;
	struct lsa_String lsa_account_name;
	struct dom_sid2 *domain_sid = NULL;
	struct samr_Ids user_rids, name_types;
	uint32_t num_entries = 0;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(builtin_handle);
	ZERO_STRUCT(user_handle);

	if (!r->out.buffer) {
		return WERR_INVALID_PARAM;
	}

	switch (r->in.level) {
		case 0:
		/* case 1: */
		case 10:
		case 20:
		case 23:
			break;
		default:
			werr = WERR_NOT_SUPPORTED;
			goto done;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, &ndr_table_samr.syntax_id,
				   &pipe_cli);
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

	werr = libnetapi_samr_open_builtin_domain(ctx, pipe_cli,
						  SAMR_ACCESS_ENUM_DOMAINS |
						  SAMR_ACCESS_OPEN_DOMAIN,
						  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT |
						  SAMR_DOMAIN_ACCESS_LOOKUP_ALIAS,
						  &connect_handle,
						  &builtin_handle);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	init_lsa_String(&lsa_account_name, r->in.user_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_account_name,
					 &user_rids,
					 &name_types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = libnetapi_samr_lookup_user_map_USER_INFO(ctx, pipe_cli,
							  domain_sid,
							  &domain_handle,
							  &builtin_handle,
							  r->in.user_name,
							  user_rids.ids[0],
							  r->in.level,
							  r->out.buffer,
							  &num_entries);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&user_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &user_handle);
	}

	if (ctx->disable_policy_handle_cache) {
		libnetapi_samr_close_domain_handle(ctx, &domain_handle);
		libnetapi_samr_close_connect_handle(ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetUserGetInfo_l(struct libnetapi_ctx *ctx,
			struct NetUserGetInfo *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetUserSetInfo_r(struct libnetapi_ctx *ctx,
			struct NetUserSetInfo *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;

	struct policy_handle connect_handle, domain_handle, builtin_handle, user_handle;
	struct lsa_String lsa_account_name;
	struct dom_sid2 *domain_sid = NULL;
	struct samr_Ids user_rids, name_types;
	union samr_UserInfo user_info;

	struct USER_INFO_X uX;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(builtin_handle);
	ZERO_STRUCT(user_handle);

	if (!r->in.buffer) {
		return WERR_INVALID_PARAM;
	}

	switch (r->in.level) {
		case 0:
		case 1007:
			break;
		default:
			werr = WERR_NOT_SUPPORTED;
			goto done;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, &ndr_table_samr.syntax_id,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  SAMR_DOMAIN_ACCESS_LOOKUP_INFO_1 |
					  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_builtin_domain(ctx, pipe_cli,
						  SAMR_ACCESS_ENUM_DOMAINS |
						  SAMR_ACCESS_OPEN_DOMAIN,
						  SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT |
						  SAMR_DOMAIN_ACCESS_LOOKUP_ALIAS,
						  &connect_handle,
						  &builtin_handle);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	init_lsa_String(&lsa_account_name, r->in.user_name);

	status = rpccli_samr_LookupNames(pipe_cli, ctx,
					 &domain_handle,
					 1,
					 &lsa_account_name,
					 &user_rids,
					 &name_types);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_OpenUser(pipe_cli, ctx,
				      &domain_handle,
				      SAMR_USER_ACCESS_SET_ATTRIBUTES,
				      user_rids.ids[0],
				      &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = construct_USER_INFO_X(r->in.level, r->in.buffer, &uX);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	convert_USER_INFO_X_to_samr_user_info21(&uX, &user_info.info21);

	status = rpccli_samr_SetUserInfo(pipe_cli, ctx,
					 &user_handle,
					 21,
					 &user_info);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = WERR_OK;

 done:
	if (!cli) {
		return werr;
	}

	if (is_valid_policy_hnd(&user_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &user_handle);
	}

	if (ctx->disable_policy_handle_cache) {
		libnetapi_samr_close_domain_handle(ctx, &domain_handle);
		libnetapi_samr_close_builtin_handle(ctx, &builtin_handle);
		libnetapi_samr_close_connect_handle(ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetUserSetInfo_l(struct libnetapi_ctx *ctx,
			struct NetUserSetInfo *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

static NTSTATUS query_USER_MODALS_INFO_rpc(TALLOC_CTX *mem_ctx,
					   struct rpc_pipe_client *pipe_cli,
					   struct policy_handle *domain_handle,
					   struct samr_DomInfo1 *info1,
					   struct samr_DomInfo3 *info3,
					   struct samr_DomInfo5 *info5,
					   struct samr_DomInfo6 *info6,
					   struct samr_DomInfo7 *info7,
					   struct samr_DomInfo12 *info12)
{
	NTSTATUS status;
	union samr_DomainInfo *dom_info = NULL;

	if (info1) {
		status = rpccli_samr_QueryDomainInfo(pipe_cli, mem_ctx,
						     domain_handle,
						     1,
						     &dom_info);
		NT_STATUS_NOT_OK_RETURN(status);

		*info1 = dom_info->info1;
	}

	if (info3) {
		status = rpccli_samr_QueryDomainInfo(pipe_cli, mem_ctx,
						     domain_handle,
						     3,
						     &dom_info);
		NT_STATUS_NOT_OK_RETURN(status);

		*info3 = dom_info->info3;
	}

	if (info5) {
		status = rpccli_samr_QueryDomainInfo(pipe_cli, mem_ctx,
						     domain_handle,
						     5,
						     &dom_info);
		NT_STATUS_NOT_OK_RETURN(status);

		*info5 = dom_info->info5;
	}

	if (info6) {
		status = rpccli_samr_QueryDomainInfo(pipe_cli, mem_ctx,
						     domain_handle,
						     6,
						     &dom_info);
		NT_STATUS_NOT_OK_RETURN(status);

		*info6 = dom_info->info6;
	}

	if (info7) {
		status = rpccli_samr_QueryDomainInfo(pipe_cli, mem_ctx,
						     domain_handle,
						     7,
						     &dom_info);
		NT_STATUS_NOT_OK_RETURN(status);

		*info7 = dom_info->info7;
	}

	if (info12) {
		status = rpccli_samr_QueryDomainInfo2(pipe_cli, mem_ctx,
						      domain_handle,
						      12,
						      &dom_info);
		NT_STATUS_NOT_OK_RETURN(status);

		*info12 = dom_info->info12;
	}

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS query_USER_MODALS_INFO_0(TALLOC_CTX *mem_ctx,
					 struct rpc_pipe_client *pipe_cli,
					 struct policy_handle *domain_handle,
					 struct USER_MODALS_INFO_0 *info0)
{
	NTSTATUS status;
	struct samr_DomInfo1 dom_info1;
	struct samr_DomInfo3 dom_info3;

	ZERO_STRUCTP(info0);

	status = query_USER_MODALS_INFO_rpc(mem_ctx,
					    pipe_cli,
					    domain_handle,
					    &dom_info1,
					    &dom_info3,
					    NULL,
					    NULL,
					    NULL,
					    NULL);
	NT_STATUS_NOT_OK_RETURN(status);

	info0->usrmod0_min_passwd_len =
		dom_info1.min_password_length;
	info0->usrmod0_max_passwd_age =
		nt_time_to_unix_abs((NTTIME *)&dom_info1.max_password_age);
	info0->usrmod0_min_passwd_age =
		nt_time_to_unix_abs((NTTIME *)&dom_info1.min_password_age);
	info0->usrmod0_password_hist_len =
		dom_info1.password_history_length;

	info0->usrmod0_force_logoff =
		nt_time_to_unix_abs(&dom_info3.force_logoff_time);

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS query_USER_MODALS_INFO_1(TALLOC_CTX *mem_ctx,
					 struct rpc_pipe_client *pipe_cli,
					 struct policy_handle *domain_handle,
					 struct USER_MODALS_INFO_1 *info1)
{
	NTSTATUS status;
	struct samr_DomInfo6 dom_info6;
	struct samr_DomInfo7 dom_info7;

	status = query_USER_MODALS_INFO_rpc(mem_ctx,
					    pipe_cli,
					    domain_handle,
					    NULL,
					    NULL,
					    NULL,
					    &dom_info6,
					    &dom_info7,
					    NULL);
	NT_STATUS_NOT_OK_RETURN(status);

	info1->usrmod1_primary =
		talloc_strdup(mem_ctx, dom_info6.primary.string);

	info1->usrmod1_role = dom_info7.role;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS query_USER_MODALS_INFO_2(TALLOC_CTX *mem_ctx,
					 struct rpc_pipe_client *pipe_cli,
					 struct policy_handle *domain_handle,
					 struct dom_sid *domain_sid,
					 struct USER_MODALS_INFO_2 *info2)
{
	NTSTATUS status;
	struct samr_DomInfo5 dom_info5;

	status = query_USER_MODALS_INFO_rpc(mem_ctx,
					    pipe_cli,
					    domain_handle,
					    NULL,
					    NULL,
					    &dom_info5,
					    NULL,
					    NULL,
					    NULL);
	NT_STATUS_NOT_OK_RETURN(status);

	info2->usrmod2_domain_name =
		talloc_strdup(mem_ctx, dom_info5.domain_name.string);
	info2->usrmod2_domain_id =
		(struct domsid *)sid_dup_talloc(mem_ctx, domain_sid);

	NT_STATUS_HAVE_NO_MEMORY(info2->usrmod2_domain_name);
	NT_STATUS_HAVE_NO_MEMORY(info2->usrmod2_domain_id);

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS query_USER_MODALS_INFO_3(TALLOC_CTX *mem_ctx,
					 struct rpc_pipe_client *pipe_cli,
					 struct policy_handle *domain_handle,
					 struct USER_MODALS_INFO_3 *info3)
{
	NTSTATUS status;
	struct samr_DomInfo12 dom_info12;

	status = query_USER_MODALS_INFO_rpc(mem_ctx,
					    pipe_cli,
					    domain_handle,
					    NULL,
					    NULL,
					    NULL,
					    NULL,
					    NULL,
					    &dom_info12);
	NT_STATUS_NOT_OK_RETURN(status);

	info3->usrmod3_lockout_duration =
		nt_time_to_unix_abs(&dom_info12.lockout_duration);
	info3->usrmod3_lockout_observation_window =
		nt_time_to_unix_abs(&dom_info12.lockout_window);
	info3->usrmod3_lockout_threshold =
		dom_info12.lockout_threshold;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS query_USER_MODALS_INFO_to_buffer(TALLOC_CTX *mem_ctx,
						 struct rpc_pipe_client *pipe_cli,
						 uint32_t level,
						 struct policy_handle *domain_handle,
						 struct dom_sid *domain_sid,
						 uint8_t **buffer)
{
	NTSTATUS status;

	struct USER_MODALS_INFO_0 info0;
	struct USER_MODALS_INFO_1 info1;
	struct USER_MODALS_INFO_2 info2;
	struct USER_MODALS_INFO_3 info3;

	if (!buffer) {
		return ERROR_INSUFFICIENT_BUFFER;
	}

	switch (level) {
		case 0:
			status = query_USER_MODALS_INFO_0(mem_ctx,
							  pipe_cli,
							  domain_handle,
							  &info0);
			NT_STATUS_NOT_OK_RETURN(status);

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, &info0,
							   sizeof(info0));
			break;

		case 1:
			status = query_USER_MODALS_INFO_1(mem_ctx,
							  pipe_cli,
							  domain_handle,
							  &info1);
			NT_STATUS_NOT_OK_RETURN(status);

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, &info1,
							   sizeof(info1));
			break;
		case 2:
			status = query_USER_MODALS_INFO_2(mem_ctx,
							  pipe_cli,
							  domain_handle,
							  domain_sid,
							  &info2);
			NT_STATUS_NOT_OK_RETURN(status);

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, &info2,
							   sizeof(info2));
			break;
		case 3:
			status = query_USER_MODALS_INFO_3(mem_ctx,
							  pipe_cli,
							  domain_handle,
							  &info3);
			NT_STATUS_NOT_OK_RETURN(status);

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, &info3,
							   sizeof(info3));
			break;
		default:
			break;
	}

	NT_STATUS_HAVE_NO_MEMORY(*buffer);

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

WERROR NetUserModalsGet_r(struct libnetapi_ctx *ctx,
			  struct NetUserModalsGet *r)
{
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *pipe_cli = NULL;
	NTSTATUS status;
	WERROR werr;

	struct policy_handle connect_handle, domain_handle;
	struct dom_sid2 *domain_sid = NULL;
	uint32_t access_mask = SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);

	if (!r->out.buffer) {
		return WERR_INVALID_PARAM;
	}

	switch (r->in.level) {
		case 0:
			access_mask |= SAMR_DOMAIN_ACCESS_LOOKUP_INFO_1 |
				       SAMR_DOMAIN_ACCESS_LOOKUP_INFO_2;
			break;
		case 1:
		case 2:
			access_mask |= SAMR_DOMAIN_ACCESS_LOOKUP_INFO_2;
			break;
		case 3:
			access_mask |= SAMR_DOMAIN_ACCESS_LOOKUP_INFO_1;
			break;
		default:
			werr = WERR_UNKNOWN_LEVEL;
			goto done;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, &ndr_table_samr.syntax_id,
				   &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_samr_open_domain(ctx, pipe_cli,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  access_mask,
					  &connect_handle,
					  &domain_handle,
					  &domain_sid);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	/* 0:  1 + 3 */
	/* 1:  6 + 7 */
	/* 2:  5 */
	/* 3: 12 (DomainInfo2) */

	status = query_USER_MODALS_INFO_to_buffer(ctx,
						  pipe_cli,
						  r->in.level,
						  &domain_handle,
						  domain_sid,
						  r->out.buffer);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

 done:
	if (!cli) {
		return werr;
	}

	if (ctx->disable_policy_handle_cache) {
		libnetapi_samr_close_domain_handle(ctx, &domain_handle);
		libnetapi_samr_close_connect_handle(ctx, &connect_handle);
	}

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetUserModalsGet_l(struct libnetapi_ctx *ctx,
			  struct NetUserModalsGet *r)
{
	return NetUserModalsGet_r(ctx, r);
}

/****************************************************************
****************************************************************/

WERROR NetUserModalsSet_r(struct libnetapi_ctx *ctx,
			  struct NetUserModalsSet *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR NetUserModalsSet_l(struct libnetapi_ctx *ctx,
			  struct NetUserModalsSet *r)
{
	return WERR_NOT_SUPPORTED;
}
