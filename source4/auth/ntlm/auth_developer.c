/* 
   Unix SMB/CIFS implementation.
   Generic authentication types
   Copyright (C) Andrew Bartlett         2001-2002
   Copyright (C) Jelmer Vernooij              2002
   Copyright (C) Stefan Metzmacher            2005
   
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
#include <tevent.h>
#include "auth/auth.h"
#include "auth/ntlm/auth_proto.h"
#include "libcli/security/security.h"
#include "lib/util/tevent_ntstatus.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

_PUBLIC_ NTSTATUS auth4_developer_init(TALLOC_CTX *);

static NTSTATUS name_to_ntstatus_want_check(struct auth_method_context *ctx,
			      		    TALLOC_CTX *mem_ctx,
					    const struct auth_usersupplied_info *user_info)
{
	return NT_STATUS_OK;
}

/** 
 * Return an error based on username
 *
 * This function allows the testing of obsure errors, as well as the generation
 * of NT_STATUS -> DOS error mapping tables.
 *
 * This module is of no value to end-users.
 *
 * The password is ignored.
 *
 * @return An NTSTATUS value based on the username
 **/

static NTSTATUS name_to_ntstatus_check_password(struct auth_method_context *ctx,
			      		        TALLOC_CTX *mem_ctx,
					        const struct auth_usersupplied_info *user_info, 
					        struct auth_user_info_dc **_user_info_dc,
						bool *authoritative)
{
	NTSTATUS nt_status;
	struct auth_user_info_dc *user_info_dc;
	struct auth_user_info *info;
	uint32_t error_num;
	const char *user;

	user = user_info->client.account_name;

	if (strncasecmp("NT_STATUS", user, strlen("NT_STATUS")) == 0) {
		nt_status = nt_status_string_to_code(user);
	} else {
		error_num = strtoul(user, NULL, 16);
		DEBUG(5,("name_to_ntstatus_check_password: Error for user %s was 0x%08X\n", user, error_num));
		nt_status = NT_STATUS(error_num);
	}
	NT_STATUS_NOT_OK_RETURN(nt_status);

	user_info_dc = talloc(mem_ctx, struct auth_user_info_dc);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc);

	/* This returns a pointer to a struct dom_sid, which is the
	 * same as a 1 element list of struct dom_sid */
	user_info_dc->num_sids = 1;
	user_info_dc->sids = dom_sid_parse_talloc(user_info_dc, SID_NT_ANONYMOUS);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc->sids);

	/* annoying, but the Anonymous really does have a session key, 
	   and it is all zeros! */
	user_info_dc->user_session_key = data_blob_talloc(user_info_dc, NULL, 16);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc->user_session_key.data);

	user_info_dc->lm_session_key = data_blob_talloc(user_info_dc, NULL, 16);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc->lm_session_key.data);

	data_blob_clear(&user_info_dc->user_session_key);
	data_blob_clear(&user_info_dc->lm_session_key);

	user_info_dc->info = info = talloc_zero(user_info_dc, struct auth_user_info);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc->info);

	info->account_name = talloc_asprintf(user_info_dc, "NAME TO NTSTATUS %s ANONYMOUS LOGON", user);
	NT_STATUS_HAVE_NO_MEMORY(info->account_name);

	info->domain_name = talloc_strdup(user_info_dc, "NT AUTHORITY");
	NT_STATUS_HAVE_NO_MEMORY(info->domain_name);

	info->full_name = talloc_asprintf(user_info_dc, "NAME TO NTSTATUS %s Anonymous Logon", user);
	NT_STATUS_HAVE_NO_MEMORY(info->full_name);

	info->logon_script = talloc_strdup(user_info_dc, "");
	NT_STATUS_HAVE_NO_MEMORY(info->logon_script);

	info->profile_path = talloc_strdup(user_info_dc, "");
	NT_STATUS_HAVE_NO_MEMORY(info->profile_path);

	info->home_directory = talloc_strdup(user_info_dc, "");
	NT_STATUS_HAVE_NO_MEMORY(info->home_directory);

	info->home_drive = talloc_strdup(user_info_dc, "");
	NT_STATUS_HAVE_NO_MEMORY(info->home_drive);

	info->last_logon = 0;
	info->last_logoff = 0;
	info->acct_expiry = 0;
	info->last_password_change = 0;
	info->allow_password_change = 0;
	info->force_password_change = 0;

	info->logon_count = 0;
	info->bad_password_count = 0;

	info->acct_flags = ACB_NORMAL;

	info->authenticated = true;

	*_user_info_dc = user_info_dc;

	return nt_status;
}

struct name_to_ntstatus_check_password_state {
	struct auth_user_info_dc *user_info_dc;
	bool authoritative;
};

static struct tevent_req *name_to_ntstatus_check_password_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct auth_method_context *ctx,
	const struct auth_usersupplied_info *user_info)
{
	struct tevent_req *req = NULL;
	struct name_to_ntstatus_check_password_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(
		mem_ctx,
		&state,
		struct name_to_ntstatus_check_password_state);
	if (req == NULL) {
		return NULL;
	}

	status = name_to_ntstatus_check_password(
		ctx,
		state,
		user_info,
		&state->user_info_dc,
		&state->authoritative);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS name_to_ntstatus_check_password_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct auth_user_info_dc **interim_info,
	bool *authoritative)
{
	struct name_to_ntstatus_check_password_state *state = tevent_req_data(
		req, struct name_to_ntstatus_check_password_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	*interim_info = talloc_move(mem_ctx, &state->user_info_dc);
	*authoritative = state->authoritative;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

static const struct auth_operations name_to_ntstatus_auth_ops = {
	.name		= "name_to_ntstatus",
	.want_check	= name_to_ntstatus_want_check,
	.check_password_send	= name_to_ntstatus_check_password_send,
	.check_password_recv	= name_to_ntstatus_check_password_recv,
};

_PUBLIC_ NTSTATUS auth4_developer_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = auth_register(ctx, &name_to_ntstatus_auth_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'name_to_ntstatus' auth backend!\n"));
		return ret;
	}

	return ret;
}
