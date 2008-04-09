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
#include "lib/netapi/libnetapi.h"

/****************************************************************
****************************************************************/

WERROR NetUserAdd_l(struct libnetapi_ctx *ctx,
		    struct NetUserAdd *r)
{
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

static void convert_USER_INFO_1_to_samr_user_info25(struct USER_INFO_1 *info1,
						    DATA_BLOB *user_session_key,
						    struct samr_UserInfo25 *info25)
{
	uint32_t fields_present = SAMR_FIELD_ACCT_FLAGS;
	struct samr_LogonHours zero_logon_hours;
	struct lsa_BinaryString zero_parameters;
	uint32_t acct_flags = 0;
	NTTIME password_age;

	ZERO_STRUCTP(info25);
	ZERO_STRUCT(zero_logon_hours);
	ZERO_STRUCT(zero_parameters);

	if (info1->usri1_name) {
		fields_present |= SAMR_FIELD_FULL_NAME;
	}
	if (info1->usri1_password) {
		fields_present |= SAMR_FIELD_PASSWORD;
	}
	if (info1->usri1_flags) {
		fields_present |= SAMR_FIELD_ACCT_FLAGS;
	}
	if (info1->usri1_name) {
		fields_present |= SAMR_FIELD_FULL_NAME;
	}
	if (info1->usri1_home_dir) {
		fields_present |= SAMR_FIELD_HOME_DIRECTORY;
	}
	if (info1->usri1_script_path) {
		fields_present |= SAMR_FIELD_LOGON_SCRIPT;
	}
	if (info1->usri1_comment) {
		fields_present |= SAMR_FIELD_DESCRIPTION;
	}
	if (info1->usri1_password_age) {
		fields_present |= SAMR_FIELD_FORCE_PWD_CHANGE;
	}

	acct_flags |= info1->usri1_flags | ACB_NORMAL;

	unix_to_nt_time_abs(&password_age, info1->usri1_password_age);

	/* TODO: info1->usri1_priv */
	init_samr_user_info21(&info25->info,
			      0,
			      0,
			      0,
			      0,
			      0,
			      password_age,
			      NULL,
			      info1->usri1_name,
			      info1->usri1_home_dir,
			      NULL,
			      info1->usri1_script_path,
			      NULL,
			      info1->usri1_comment,
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

	if (info1->usri1_password) {
		uchar pwbuf[532];
		struct MD5Context ctx;
		uint8_t confounder[16];
		DATA_BLOB confounded_session_key = data_blob(NULL, 16);

		encode_pw_buffer(pwbuf, info1->usri1_password, STR_UNICODE);

		generate_random_buffer((uint8_t *)confounder, 16);

		MD5Init(&ctx);
		MD5Update(&ctx, confounder, 16);
		MD5Update(&ctx, user_session_key->data,
				user_session_key->length);
		MD5Final(confounded_session_key.data, &ctx);

		SamOEMhashBlob(pwbuf, 516, &confounded_session_key);
		memcpy(&pwbuf[516], confounder, 16);

		memcpy(info25->password.data, pwbuf, sizeof(pwbuf));
		data_blob_free(&confounded_session_key);
	}
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
	uint32_t resume_handle = 0;
	uint32_t num_entries = 0;
	POLICY_HND connect_handle, domain_handle, user_handle;
	struct samr_SamArray *sam = NULL;
	const char *domain_name = NULL;
	struct lsa_String lsa_domain_name, lsa_account_name;
	struct dom_sid2 *domain_sid = NULL;
	struct samr_UserInfo25 info25;
	union samr_UserInfo *user_info = NULL;
	struct samr_PwInfo pw_info;
	uint32_t access_granted = 0;
	uint32_t rid = 0;
	bool domain_found = true;
	int i;
	struct USER_INFO_1 *info1;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(user_handle);

	if (!r->in.buffer) {
		return WERR_INVALID_PARAM;
	}

	switch (r->in.level) {
		case 1:
			info1 = (struct USER_INFO_1 *)r->in.buffer;
			break;
		case 2:
		case 3:
		case 4:
		default:
			werr = WERR_NOT_SUPPORTED;
			goto done;
	}

	status = cli_full_connection(&cli, NULL, r->in.server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     ctx->username,
				     ctx->workgroup,
				     ctx->password,
				     CLI_FULL_CONNECTION_USE_KERBEROS |
				     CLI_FULL_CONNECTION_FALLBACK_AFTER_KERBEROS,
				     Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_SAMR, &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_try_samr_connects(pipe_cli, ctx,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  &connect_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_EnumDomains(pipe_cli, ctx,
					 &connect_handle,
					 &resume_handle,
					 &sam,
					 0xffffffff,
					 &num_entries);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	for (i=0; i<num_entries; i++) {

		domain_name = sam->entries[i].name.string;

		if (strequal(domain_name, builtin_domain_name())) {
			continue;
		}

		domain_found = true;
		break;
	}

	if (!domain_found) {
		werr = WERR_NO_SUCH_DOMAIN;
		goto done;
	}

	init_lsa_String(&lsa_domain_name, domain_name);

	status = rpccli_samr_LookupDomain(pipe_cli, ctx,
					  &connect_handle,
					  &lsa_domain_name,
					  &domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_OpenDomain(pipe_cli, ctx,
					&connect_handle,
					SAMR_DOMAIN_ACCESS_LOOKUP_INFO_1 |
					SAMR_DOMAIN_ACCESS_CREATE_USER |
					SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					domain_sid,
					&domain_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	init_lsa_String(&lsa_account_name, info1->usri1_name);

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

	ZERO_STRUCTP(user_info);

	convert_USER_INFO_1_to_samr_user_info25(info1,
						&cli->user_session_key,
						&info25);

	if (info1->usri1_password) {
		user_info->info25 = info25;
		status = rpccli_samr_SetUserInfo2(pipe_cli, ctx,
						  &user_handle,
						  25,
						  user_info);
	} else {
		user_info->info21 = info25.info;
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
	status = rpccli_samr_DeleteUser(pipe_cli, ctx,
					&user_handle);
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
	if (is_valid_policy_hnd(&domain_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &domain_handle);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &connect_handle);
	}

	cli_shutdown(cli);

	return werr;
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
	uint32_t resume_handle = 0;
	uint32_t num_entries = 0;
	POLICY_HND connect_handle, builtin_handle, domain_handle, user_handle;
	struct samr_SamArray *sam = NULL;
	const char *domain_name = NULL;
	struct lsa_String lsa_domain_name, lsa_account_name;
	struct samr_Ids user_rids, name_types;
	struct dom_sid2 *domain_sid = NULL;
	struct dom_sid2 user_sid;
	bool domain_found = true;
	int i;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(builtin_handle);
	ZERO_STRUCT(domain_handle);
	ZERO_STRUCT(user_handle);

	status = cli_full_connection(&cli, NULL, r->in.server_name,
				     NULL, 0,
				     "IPC$", "IPC",
				     ctx->username,
				     ctx->workgroup,
				     ctx->password,
				     CLI_FULL_CONNECTION_USE_KERBEROS |
				     CLI_FULL_CONNECTION_FALLBACK_AFTER_KERBEROS,
				     Undefined, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	pipe_cli = cli_rpc_pipe_open_noauth(cli, PI_SAMR, &status);
	if (!pipe_cli) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_try_samr_connects(pipe_cli, ctx,
					  SAMR_ACCESS_ENUM_DOMAINS |
					  SAMR_ACCESS_OPEN_DOMAIN,
					  &connect_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_EnumDomains(pipe_cli, ctx,
					 &connect_handle,
					 &resume_handle,
					 &sam,
					 0xffffffff,
					 &num_entries);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	for (i=0; i<num_entries; i++) {

		domain_name = sam->entries[i].name.string;

		if (strequal(domain_name, builtin_domain_name())) {
			continue;
		}

		domain_found = true;
		break;
	}

	if (!domain_found) {
		werr = WERR_NO_SUCH_DOMAIN;
		goto done;
	}

	init_lsa_String(&lsa_domain_name, domain_name);

	status = rpccli_samr_LookupDomain(pipe_cli, ctx,
					  &connect_handle,
					  &lsa_domain_name,
					  &domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_OpenDomain(pipe_cli, ctx,
					&connect_handle,
					SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					domain_sid,
					&domain_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
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
	if (is_valid_policy_hnd(&builtin_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &builtin_handle);
	}
	if (is_valid_policy_hnd(&domain_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &domain_handle);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		rpccli_samr_Close(pipe_cli, ctx, &connect_handle);
	}

	cli_shutdown(cli);

	return werr;
}

/****************************************************************
****************************************************************/

WERROR NetUserDel_l(struct libnetapi_ctx *ctx,
		    struct NetUserDel *r)
{
	return WERR_NOT_SUPPORTED;
}
