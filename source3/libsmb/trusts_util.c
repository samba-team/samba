/*
 *  Unix SMB/CIFS implementation.
 *  Routines to operate on various trust relationships
 *  Copyright (C) Andrew Bartlett                   2001
 *  Copyright (C) Rafal Szczesniak                  2003
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
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/auth/netlogon_creds_cli.h"
#include "rpc_client/cli_netlogon.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "secrets.h"
#include "passdb.h"
#include "libsmb/libsmb.h"
#include "source3/include/messages.h"
#include "source3/include/g_lock.h"

/*********************************************************
 Change the domain password on the PDC.
 Do most of the legwork ourselfs.  Caller must have
 already setup the connection to the NETLOGON pipe
**********************************************************/

struct trust_pw_change_state {
	struct g_lock_ctx *g_ctx;
	char *g_lock_key;
};

static int trust_pw_change_state_destructor(struct trust_pw_change_state *state)
{
	g_lock_unlock(state->g_ctx, state->g_lock_key);
	return 0;
}

NTSTATUS trust_pw_change(struct netlogon_creds_cli_context *context,
			 struct messaging_context *msg_ctx,
			 struct dcerpc_binding_handle *b,
			 const char *domain,
			 bool force)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct trust_pw_change_state *state;
	struct samr_Password current_nt_hash;
	const struct samr_Password *previous_nt_hash = NULL;
	enum netr_SchannelType sec_channel_type = SEC_CHAN_NULL;
	const char *account_name;
	char *new_trust_passwd;
	char *pwd;
	struct dom_sid sid;
	time_t pass_last_set_time;
	struct timeval g_timeout = { 0, };
	int timeout = 0;
	struct timeval tv = { 0, };
	NTSTATUS status;

	state = talloc_zero(frame, struct trust_pw_change_state);
	if (state == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	state->g_ctx = g_lock_ctx_init(state, msg_ctx);
	if (state->g_ctx == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	state->g_lock_key = talloc_asprintf(state,
				"trust_password_change_%s",
				domain);
	if (state->g_lock_key == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	g_timeout = timeval_current_ofs(10, 0);
	status = g_lock_lock(state->g_ctx,
			     state->g_lock_key,
			     G_LOCK_WRITE, g_timeout);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("could not get g_lock on [%s]!\n",
			  state->g_lock_key));
		TALLOC_FREE(frame);
		return status;
	}

	talloc_set_destructor(state, trust_pw_change_state_destructor);

	if (!get_trust_pw_hash(domain, current_nt_hash.hash,
			       &account_name,
			       &sec_channel_type)) {
		DEBUG(0, ("could not fetch domain secrets for domain %s!\n", domain));
		TALLOC_FREE(frame);
		return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
	}

	switch (sec_channel_type) {
	case SEC_CHAN_WKSTA:
		pwd = secrets_fetch_machine_password(domain,
						     &pass_last_set_time,
						     NULL);
		if (pwd == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
		}
		free(pwd);
		break;
	case SEC_CHAN_DOMAIN:
		if (!pdb_get_trusteddom_pw(domain, &pwd, &sid, &pass_last_set_time)) {
			TALLOC_FREE(frame);
			return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
		}
		break;
	default:
		TALLOC_FREE(frame);
		return NT_STATUS_NOT_SUPPORTED;
	}

	timeout = lp_machine_password_timeout();
	if (timeout == 0) {
		if (!force) {
			DEBUG(10,("machine password never expires\n"));
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}
	}

	tv.tv_sec = pass_last_set_time;
	DEBUG(10, ("password last changed %s\n",
		   timeval_string(talloc_tos(), &tv, false)));
	tv.tv_sec += timeout;
	DEBUGADD(10, ("password valid until %s\n",
		      timeval_string(talloc_tos(), &tv, false)));

	if (!force && !timeval_expired(&tv)) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	/* Create a random machine account password */
	new_trust_passwd = generate_random_password(frame,
				DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH,
				DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
	if (new_trust_passwd == NULL) {
		DEBUG(0, ("generate_random_password failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = netlogon_creds_cli_auth(context, b,
					 current_nt_hash,
					 previous_nt_hash);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_ServerPasswordSet(context, b,
						      new_trust_passwd, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	DEBUG(3,("%s : trust_pw_change_and_store_it: Changed password.\n",
		 current_timestring(talloc_tos(), False)));

	/*
	 * Return the result of trying to write the new password
	 * back into the trust account file.
	 */

	switch (sec_channel_type) {

	case SEC_CHAN_WKSTA:
		if (!secrets_store_machine_password(new_trust_passwd, domain, sec_channel_type)) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		break;

	case SEC_CHAN_DOMAIN:
		/*
		 * we need to get the sid first for the
		 * pdb_set_trusteddom_pw call
		 */
		if (!pdb_set_trusteddom_pw(domain, new_trust_passwd, &sid)) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		break;

	default:
		break;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
