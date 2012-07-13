/*
   Unix SMB/CIFS implementation.
   Authenticate against Samba4's auth subsystem
   Copyright (C) Volker Lendecke 2008
   Copyright (C) Andrew Bartlett 2010

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
#include "source3/include/auth.h"
#include "source4/auth/auth.h"
#include "auth/auth_sam_reply.h"
#include "param/param.h"
#include "source4/lib/events/events.h"
#include "source4/lib/messaging/messaging.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/* 
 * This hook is currently unused, as all NTLM logins go via the hooks
 * provided by make_auth4_context_s4() below.
 *
 * This is only left in case we find a way that it might become useful
 * in future.  Importantly, this routine returns the information
 * needed for a NETLOGON SamLogon, not what is needed to establish a
 * session.
 */

static NTSTATUS check_samba4_security(const struct auth_context *auth_context,
				      void *my_private_data,
				      TALLOC_CTX *mem_ctx,
				      const struct auth_usersupplied_info *user_info,
				      struct auth_serversupplied_info **server_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct netr_SamInfo3 *info3 = NULL;
	NTSTATUS nt_status;
	struct auth_user_info_dc *user_info_dc;
	struct auth4_context *auth4_context;
	struct loadparm_context *lp_ctx;

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DEBUG(10, ("loadparm_init_s3 failed\n"));
		talloc_free(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	/* We create a private tevent context here to avoid nested loops in
	 * the s3 one, as that may not be expected */
	nt_status = auth_context_create(mem_ctx,
					s4_event_context_init(frame), NULL, 
					lp_ctx,
					&auth4_context);
	NT_STATUS_NOT_OK_RETURN(nt_status);
		
	nt_status = auth_context_set_challenge(auth4_context, auth_context->challenge.data, "auth_samba4");
	NT_STATUS_NOT_OK_RETURN_AND_FREE(nt_status, auth4_context);

	nt_status = auth_check_password(auth4_context, auth4_context, user_info, &user_info_dc);
	NT_STATUS_NOT_OK_RETURN_AND_FREE(nt_status, auth4_context);
	
	nt_status = auth_convert_user_info_dc_saminfo3(mem_ctx,
						       user_info_dc,
						       &info3);
	if (NT_STATUS_IS_OK(nt_status)) {
		/* We need the strings from the server_info to be valid as long as the info3 is around */
		talloc_steal(info3, user_info_dc);
	}
	talloc_free(auth4_context);

	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	nt_status = make_server_info_info3(mem_ctx, user_info->client.account_name,
					   user_info->mapped.domain_name, server_info,
					info3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(10, ("make_server_info_info3 failed: %s\n",
			   nt_errstr(nt_status)));
		TALLOC_FREE(frame);
		return nt_status;
	}

	nt_status = NT_STATUS_OK;

 done:
	TALLOC_FREE(frame);
	return nt_status;
}

/* Hook to allow GENSEC to handle blob-based authentication
 * mechanisms, without directly linking the mechansim code */
static NTSTATUS prepare_gensec(TALLOC_CTX *mem_ctx,
			       struct gensec_security **gensec_context)
{
	NTSTATUS status;
	struct loadparm_context *lp_ctx;
	struct tevent_context *event_ctx;
	TALLOC_CTX *frame = talloc_stackframe();
	struct gensec_security *gensec_ctx;
	struct imessaging_context *msg_ctx;
	struct cli_credentials *server_credentials;
	struct server_id *server_id;

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DEBUG(1, ("loadparm_init_s3 failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}
	event_ctx = s4_event_context_init(frame);
	if (event_ctx == NULL) {
		DEBUG(1, ("s4_event_context_init failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	server_id = new_server_id_task(frame);
	if (server_id == NULL) {
		DEBUG(1, ("new_server_id_task failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	msg_ctx = imessaging_init(frame,
				  lp_ctx,
				  *server_id,
				  event_ctx, true);
	if (msg_ctx == NULL) {
		DEBUG(1, ("imessaging_init failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	talloc_reparent(frame, msg_ctx, server_id);

	server_credentials
		= cli_credentials_init(frame);
	if (!server_credentials) {
		DEBUG(1, ("Failed to init server credentials"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	cli_credentials_set_conf(server_credentials, lp_ctx);
	status = cli_credentials_set_machine_account(server_credentials, lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Failed to obtain server credentials, perhaps a standalone server?: %s\n", nt_errstr(status)));
		talloc_free(server_credentials);
		server_credentials = NULL;
	}

	status = samba_server_gensec_start(mem_ctx,
					   event_ctx, msg_ctx,
					   lp_ctx, server_credentials, "cifs",
					   &gensec_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC server code: %s\n", nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	talloc_reparent(frame, gensec_ctx, msg_ctx);
	talloc_reparent(frame, gensec_ctx, event_ctx);
	talloc_reparent(frame, gensec_ctx, lp_ctx);
	talloc_reparent(frame, gensec_ctx, server_credentials);

	gensec_want_feature(gensec_ctx, GENSEC_FEATURE_SESSION_KEY);
	gensec_want_feature(gensec_ctx, GENSEC_FEATURE_UNIX_TOKEN);

	*gensec_context = gensec_ctx;
	TALLOC_FREE(frame);
	return status;
}

/* Hook to allow handling of NTLM authentication for AD operation
 * without directly linking the s4 auth stack */
static NTSTATUS make_auth4_context_s4(TALLOC_CTX *mem_ctx,
				      struct auth4_context **auth4_context)
{
	NTSTATUS status;
	struct loadparm_context *lp_ctx;
	struct tevent_context *event_ctx;
	TALLOC_CTX *frame = talloc_stackframe();
	struct imessaging_context *msg_ctx;
	struct server_id *server_id;

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DEBUG(1, ("loadparm_init_s3 failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}
	event_ctx = s4_event_context_init(frame);
	if (event_ctx == NULL) {
		DEBUG(1, ("s4_event_context_init failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	server_id = new_server_id_task(frame);
	if (server_id == NULL) {
		DEBUG(1, ("new_server_id_task failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	msg_ctx = imessaging_init(frame,
				  lp_ctx,
				  *server_id,
				  event_ctx, true);
	if (msg_ctx == NULL) {
		DEBUG(1, ("imessaging_init failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}
	talloc_reparent(frame, msg_ctx, server_id);

	status = auth_context_create(mem_ctx,
					event_ctx,
					msg_ctx,
					lp_ctx,
					auth4_context);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start auth server code: %s\n", nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	talloc_reparent(frame, *auth4_context, msg_ctx);
	talloc_reparent(frame, *auth4_context, event_ctx);
	talloc_reparent(frame, *auth4_context, lp_ctx);

	TALLOC_FREE(frame);
	return status;
}

/* module initialisation */
static NTSTATUS auth_init_samba4(struct auth_context *auth_context,
				    const char *param,
				    auth_methods **auth_method)
{
	struct auth_methods *result;

	gensec_init();

	result = talloc_zero(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->name = "samba4";
	result->auth = check_samba4_security;
	result->prepare_gensec = prepare_gensec;
	result->make_auth4_context = make_auth4_context_s4;

        *auth_method = result;
	return NT_STATUS_OK;
}

NTSTATUS auth_samba4_init(void)
{
	smb_register_auth(AUTH_INTERFACE_VERSION, "samba4",
			  auth_init_samba4);
	return NT_STATUS_OK;
}
