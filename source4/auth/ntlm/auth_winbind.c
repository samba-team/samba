/* 
   Unix SMB/CIFS implementation.

   Winbind authentication mechnism

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Bartlett 2001 - 2002
   Copyright (C) Stefan Metzmacher 2005
   
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
#include "auth/auth.h"
#include "auth/ntlm/auth_proto.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "lib/messaging/irpc.h"
#include "param/param.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "auth/auth_sam_reply.h"
#include "libcli/security/security.h"

_PUBLIC_ NTSTATUS auth4_winbind_init(void);

static NTSTATUS winbind_want_check(struct auth_method_context *ctx,
				   TALLOC_CTX *mem_ctx,
				   const struct auth_usersupplied_info *user_info)
{
	if (!user_info->mapped.account_name || !*user_info->mapped.account_name) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/* TODO: maybe limit the user scope to remote users only */
	return NT_STATUS_OK;
}

struct winbind_check_password_state {
	struct winbind_SamLogon req;
};

/*
 Authenticate a user with a challenge/response
 using IRPC to the winbind task
*/
static NTSTATUS winbind_check_password(struct auth_method_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       const struct auth_usersupplied_info *user_info, 
				       struct auth_user_info_dc **user_info_dc)
{
	NTSTATUS status;
	struct dcerpc_binding_handle *irpc_handle;
	struct winbind_check_password_state *s;
	const struct auth_usersupplied_info *user_info_new;
	struct netr_IdentityInfo *identity_info;

	if (!ctx->auth_ctx->msg_ctx) {
		DEBUG(0,("winbind_check_password: auth_context_create was called with out messaging context\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	s = talloc(mem_ctx, struct winbind_check_password_state);
	NT_STATUS_HAVE_NO_MEMORY(s);

	irpc_handle = irpc_binding_handle_by_name(s, ctx->auth_ctx->msg_ctx,
						  "winbind_server",
						  &ndr_table_winbind);
	if (irpc_handle == NULL) {
		DEBUG(0, ("Winbind authentication for [%s]\\[%s] failed, " 
			  "no winbind_server running!\n",
			  user_info->client.domain_name, user_info->client.account_name));
		return NT_STATUS_NO_LOGON_SERVERS;
	}

	if (user_info->flags & USER_INFO_INTERACTIVE_LOGON) {
		struct netr_PasswordInfo *password_info;

		status = encrypt_user_info(s, ctx->auth_ctx, AUTH_PASSWORD_HASH,
					   user_info, &user_info_new);
		NT_STATUS_NOT_OK_RETURN(status);
		user_info = user_info_new;

		password_info = talloc(s, struct netr_PasswordInfo);
		NT_STATUS_HAVE_NO_MEMORY(password_info);

		password_info->lmpassword = *user_info->password.hash.lanman;
		password_info->ntpassword = *user_info->password.hash.nt;

		identity_info = &password_info->identity_info;
		s->req.in.logon_level	= 1;
		s->req.in.logon.password= password_info;
	} else {
		struct netr_NetworkInfo *network_info;
		uint8_t chal[8];

		status = encrypt_user_info(s, ctx->auth_ctx, AUTH_PASSWORD_RESPONSE,
					   user_info, &user_info_new);
		NT_STATUS_NOT_OK_RETURN(status);
		user_info = user_info_new;

		network_info = talloc(s, struct netr_NetworkInfo);
		NT_STATUS_HAVE_NO_MEMORY(network_info);

		status = auth_get_challenge(ctx->auth_ctx, chal);
		NT_STATUS_NOT_OK_RETURN(status);

		memcpy(network_info->challenge, chal, sizeof(network_info->challenge));

		network_info->nt.length = user_info->password.response.nt.length;
		network_info->nt.data	= user_info->password.response.nt.data;

		network_info->lm.length = user_info->password.response.lanman.length;
		network_info->lm.data	= user_info->password.response.lanman.data;

		identity_info = &network_info->identity_info;
		s->req.in.logon_level	= 2;
		s->req.in.logon.network = network_info;
	}

	identity_info->domain_name.string	= user_info->client.domain_name;
	identity_info->parameter_control	= user_info->logon_parameters; /* see MSV1_0_* */
	identity_info->logon_id_low		= 0;
	identity_info->logon_id_high		= 0;
	identity_info->account_name.string	= user_info->client.account_name;
	identity_info->workstation.string	= user_info->workstation_name;

	s->req.in.validation_level	= 3;

	/* Note: this makes use of nested event loops... */
	dcerpc_binding_handle_set_sync_ev(irpc_handle, ctx->auth_ctx->event_ctx);
	status = dcerpc_winbind_SamLogon_r(irpc_handle, s, &s->req);
	NT_STATUS_NOT_OK_RETURN(status);

	status = make_user_info_dc_netlogon_validation(mem_ctx,
						      user_info->client.account_name,
						      s->req.in.validation_level,
						      &s->req.out.validation,
						       true, /* This user was authenticated */
						      user_info_dc);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

/*
 Authenticate a user with a challenge/response
 using the samba3 winbind protocol via libwbclient
*/
static NTSTATUS winbind_check_password_wbclient(struct auth_method_context *ctx,
						TALLOC_CTX *mem_ctx,
						const struct auth_usersupplied_info *user_info,
						struct auth_user_info_dc **user_info_dc)
{
	struct wbcAuthUserParams params;
	struct wbcAuthUserInfo *info = NULL;
	struct wbcAuthErrorInfo *err = NULL;
	wbcErr wbc_status;
	NTSTATUS nt_status;
	struct netr_SamInfo3 *info3;
	union netr_Validation validation;


	/* Send off request */
	const struct auth_usersupplied_info *user_info_temp;
	nt_status = encrypt_user_info(mem_ctx, ctx->auth_ctx,
				      AUTH_PASSWORD_RESPONSE,
				      user_info, &user_info_temp);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}
	user_info = user_info_temp;

	ZERO_STRUCT(params);
	ZERO_STRUCT(info3);
	/*params.flags = WBFLAG_PAM_INFO3_NDR;*/

	params.parameter_control = user_info->logon_parameters;
	params.parameter_control |= WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT |
				    WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;
	params.level = WBC_AUTH_USER_LEVEL_RESPONSE;

	params.account_name     = user_info->client.account_name;
	params.domain_name      = user_info->client.domain_name;
	params.workstation_name = user_info->workstation_name;

	d_fprintf(stderr, "looking up %s@%s logging in from %s\n",
		  params.account_name, params.domain_name,
		  params.workstation_name);

	memcpy(params.password.response.challenge,
	       ctx->auth_ctx->challenge.data.data,
	       sizeof(params.password.response.challenge));

	params.password.response.lm_length =
		user_info->password.response.lanman.length;
	params.password.response.nt_length =
		user_info->password.response.nt.length;

	params.password.response.lm_data =
		user_info->password.response.lanman.data;
	params.password.response.nt_data =
		user_info->password.response.nt.data;

	wbc_status = wbcAuthenticateUserEx(&params, &info, &err);
	if (wbc_status == WBC_ERR_AUTH_ERROR) {
		DEBUG(1, ("error was %s (0x%08x)\nerror message was '%s'\n",
		      err->nt_string, err->nt_status, err->display_string));

		nt_status = NT_STATUS(err->nt_status);
		wbcFreeMemory(err);
		NT_STATUS_NOT_OK_RETURN(nt_status);
	} else if (!WBC_ERROR_IS_OK(wbc_status)) {
		DEBUG(1, ("wbcAuthenticateUserEx: failed with %u - %s\n",
			wbc_status, wbcErrorString(wbc_status)));
		return NT_STATUS_LOGON_FAILURE;
	}
	info3 = wbcAuthUserInfo_to_netr_SamInfo3(mem_ctx, info);
	wbcFreeMemory(info);
	if (!info3) {
		DEBUG(1, ("wbcAuthUserInfo_to_netr_SamInfo3 failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	validation.sam3 = info3;
	nt_status = make_user_info_dc_netlogon_validation(mem_ctx,
							  user_info->client.account_name,
							  3, &validation,
							  true, /* This user was authenticated */
							  user_info_dc);
	return nt_status;

}

static const struct auth_operations winbind_ops = {
	.name		= "winbind",
	.want_check	= winbind_want_check,
	.check_password	= winbind_check_password
};

static const struct auth_operations winbind_wbclient_ops = {
	.name		= "winbind_wbclient",
	.want_check	= winbind_want_check,
	.check_password	= winbind_check_password_wbclient
};

_PUBLIC_ NTSTATUS auth4_winbind_init(void)
{
	NTSTATUS ret;

	ret = auth_register(&winbind_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'winbind' auth backend!\n"));
		return ret;
	}

	ret = auth_register(&winbind_wbclient_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'winbind_wbclient' auth backend!\n"));
		return ret;
	}

	return NT_STATUS_OK;
}
