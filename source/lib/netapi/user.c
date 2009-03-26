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

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
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
	rpccli_samr_DeleteUser(pipe_cli, ctx,
			       &user_handle);

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

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
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

static WERROR convert_samr_samarray_to_USER_INFO_buffer(TALLOC_CTX *mem_ctx,
							struct samr_SamArray *sam_array,
							uint32_t level,
							uint8_t **buffer)
{
	struct USER_INFO_0 *info0 = NULL;
	int i;

	switch (level) {
		case 0:
			info0 = TALLOC_ZERO_ARRAY(mem_ctx, struct USER_INFO_0,
						  sam_array->count);
			W_ERROR_HAVE_NO_MEMORY(info0);

			for (i=0; i<sam_array->count; i++) {
				info0[i].usri0_name = talloc_strdup(mem_ctx,
					sam_array->entries[i].name.string);
				W_ERROR_HAVE_NO_MEMORY(info0[i].usri0_name);
			}

			*buffer = (uint8_t *)talloc_memdup(mem_ctx, info0,
				sizeof(struct USER_INFO_0) * sam_array->count);
			W_ERROR_HAVE_NO_MEMORY(*buffer);
			break;
		default:
			return WERR_NOT_SUPPORTED;
	}

	return WERR_OK;
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
	uint32_t num_entries = 0;
	int i;
	const char *domain_name = NULL;
	bool domain_found = true;
	uint32_t dom_resume_handle = 0;
	struct lsa_String lsa_domain_name;

	NTSTATUS status;
	WERROR werr;

	ZERO_STRUCT(connect_handle);
	ZERO_STRUCT(domain_handle);

	switch (r->in.level) {
		case 0:
			break;
		case 1:
		case 2:
		case 3:
		case 10:
		case 11:
		case 20:
		case 23:
		default:
			return WERR_NOT_SUPPORTED;
	}

	werr = libnetapi_open_ipc_connection(ctx, r->in.server_name, &cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = rpccli_try_samr_connects(pipe_cli, ctx,
					  SAMR_ACCESS_OPEN_DOMAIN |
					  SAMR_ACCESS_ENUM_DOMAINS,
					  &connect_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_EnumDomains(pipe_cli, ctx,
					 &connect_handle,
					 &dom_resume_handle,
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

	status = rpccli_samr_OpenDomain(pipe_cli,
					ctx,
					&connect_handle,
					SAMR_DOMAIN_ACCESS_LOOKUP_INFO_2 |
					SAMR_DOMAIN_ACCESS_ENUM_ACCOUNTS |
					SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					domain_sid,
					&domain_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_EnumDomainUsers(pipe_cli,
					     ctx,
					     &domain_handle,
					     r->in.resume_handle,
					     r->in.filter,
					     &sam,
					     r->in.prefmaxlen,
					     r->out.entries_read);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = convert_samr_samarray_to_USER_INFO_buffer(ctx, sam,
							 r->in.level,
							 r->out.buffer);

 done:
	if (!cli) {
		return werr;
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

WERROR convert_samr_dispinfo_to_NET_DISPLAY(TALLOC_CTX *mem_ctx,
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
	struct samr_SamArray *sam = NULL;
	uint32_t num_entries = 0;
	int i;
	const char *domain_name = NULL;
	bool domain_found = true;
	uint32_t dom_resume_handle = 0;
	struct lsa_String lsa_domain_name;

	uint32_t total_size = 0;
	uint32_t returned_size = 0;

	NTSTATUS status;
	WERROR werr;
	WERROR werr_tmp;

	*r->out.entries_read = 0;

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

	werr = libnetapi_open_pipe(ctx, cli, PI_SAMR, &pipe_cli);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	status = rpccli_try_samr_connects(pipe_cli, ctx,
					  SAMR_ACCESS_OPEN_DOMAIN |
					  SAMR_ACCESS_ENUM_DOMAINS,
					  &connect_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_EnumDomains(pipe_cli, ctx,
					 &connect_handle,
					 &dom_resume_handle,
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

	status = rpccli_samr_OpenDomain(pipe_cli,
					ctx,
					&connect_handle,
					SAMR_DOMAIN_ACCESS_ENUM_ACCOUNTS |
					SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					domain_sid,
					&domain_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
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
	werr = ntstatus_to_werror(status);
	if (NT_STATUS_IS_ERR(status)) {
		goto done;
	}

	werr_tmp = convert_samr_dispinfo_to_NET_DISPLAY(ctx, &info,
							r->in.level,
							r->out.entries_read,
							r->out.buffer);
	if (!W_ERROR_IS_OK(werr_tmp)) {
		werr = werr_tmp;
	}
 done:
	if (!cli) {
		return werr;
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


WERROR NetQueryDisplayInformation_l(struct libnetapi_ctx *ctx,
				    struct NetQueryDisplayInformation *r)
{
	return WERR_NOT_SUPPORTED;
}
