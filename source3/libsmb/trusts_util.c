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

char *trust_pw_new_value(TALLOC_CTX *mem_ctx,
			 enum netr_SchannelType sec_channel_type,
			 int security)
{
	/*
	 * use secure defaults.
	 */
	size_t min = 128;
	size_t max = 255;

	switch (sec_channel_type) {
	case SEC_CHAN_WKSTA:
	case SEC_CHAN_BDC:
		if (security == SEC_DOMAIN) {
			/*
			 * The maximum length of a trust account password.
			 * Used when we randomly create it, 15 char passwords
			 * exceed NT4's max password length.
			 */
			min = 14;
			max = 14;
		}
		break;
	case SEC_CHAN_DNS_DOMAIN:
		/*
		 * new_len * 2 = 498 bytes is the largest possible length
		 * NL_PASSWORD_VERSION consumes the rest of the possible 512 bytes
		 * and a confounder with at least 2 bytes is required.
		 *
		 * Windows uses new_len = 120 => 240 bytes (utf16)
		 */
		min = 120;
		max = 120;
		break;
		/* fall through */
	case SEC_CHAN_DOMAIN:
		/*
		 * The maximum length of a trust account password.
		 * Used when we randomly create it, 15 char passwords
		 * exceed NT4's max password length.
		 */
		min = 14;
		max = 14;
		break;
	default:
		break;
	}

	/*
	 * Create a random machine account password
	 * We create a random buffer and convert that to utf8.
	 * This is similar to what windows is doing.
	 */
	return generate_random_machine_password(mem_ctx, min, max);
}

NTSTATUS trust_pw_change(struct netlogon_creds_cli_context *context,
			 struct messaging_context *msg_ctx,
			 struct dcerpc_binding_handle *b,
			 const char *domain,
			 bool force)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *context_name = NULL;
	struct trust_pw_change_state *state;
	struct cli_credentials *creds = NULL;
	const struct samr_Password *current_nt_hash = NULL;
	const struct samr_Password *previous_nt_hash = NULL;
	enum netr_SchannelType sec_channel_type = SEC_CHAN_NULL;
	time_t pass_last_set_time;
	uint32_t old_version = 0;
	struct pdb_trusted_domain *td = NULL;
	struct timeval g_timeout = { 0, };
	int timeout = 0;
	struct timeval tv = { 0, };
	char *new_trust_passwd = NULL;
	uint32_t new_version = 0;
	uint32_t *new_trust_version = NULL;
	NTSTATUS status;
	bool ok;

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

	status = pdb_get_trust_credentials(domain, NULL, frame, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("could not fetch domain creds for domain %s - %s!\n",
			  domain, nt_errstr(status)));
		TALLOC_FREE(frame);
		return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
	}

	current_nt_hash = cli_credentials_get_nt_hash(creds, frame);
	if (current_nt_hash == NULL) {
		DEBUG(0, ("cli_credentials_get_nt_hash failed for domain %s!\n",
			  domain));
		TALLOC_FREE(frame);
		return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
	}

	old_version = cli_credentials_get_kvno(creds);
	pass_last_set_time = cli_credentials_get_password_last_changed_time(creds);
	sec_channel_type = cli_credentials_get_secure_channel_type(creds);

	new_version = old_version + 1;

	switch (sec_channel_type) {
	case SEC_CHAN_WKSTA:
	case SEC_CHAN_BDC:
		break;
	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
		status = pdb_get_trusted_domain(frame, domain, &td);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("pdb_get_trusted_domain() failed for domain %s - %s!\n",
				  domain, nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		new_trust_version = &new_version;
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

	context_name = netlogon_creds_cli_debug_string(context, talloc_tos());
	if (context_name == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Create a random machine account password
	 * We create a random buffer and convert that to utf8.
	 * This is similar to what windows is doing.
	 */
	new_trust_passwd = trust_pw_new_value(frame, sec_channel_type,
					      lp_security());
	if (new_trust_passwd == NULL) {
		DEBUG(0, ("trust_pw_new_value() failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * We could use cli_credentials_get_old_nt_hash(creds, frame) to
	 * set previous_nt_hash.
	 *
	 * But we want to check if the dc has our current password and only do
	 * a change if that's the case. So we keep previous_nt_hash = NULL.
	 *
	 * TODO:
	 * If the previous password is the only password in common with the dc,
	 * we better skip the password change, or use something like
	 * ServerTrustPasswordsGet() or netr_ServerGetTrustInfo() to fix our
	 * local secrets before doing the change.
	 */
	status = netlogon_creds_cli_auth(context, b,
					 *current_nt_hash,
					 previous_nt_hash);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("netlogon_creds_cli_auth(%s) failed for old password - %s!\n",
			  context_name, nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	DEBUG(0,("%s : %s(%s): Verified old password remotely using %s\n",
		 current_timestring(talloc_tos(), false),
		 __func__, domain, context_name));

	/*
	 * Return the result of trying to write the new password
	 * back into the trust account file.
	 */

	switch (sec_channel_type) {

	case SEC_CHAN_WKSTA:
	case SEC_CHAN_BDC:
		ok = secrets_store_machine_password(new_trust_passwd, domain, sec_channel_type);
		if (!ok) {
			DEBUG(0, ("secrets_store_machine_password failed for domain %s!\n",
				  domain));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		break;

	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
		/*
		 * we need to get the sid first for the
		 * pdb_set_trusteddom_pw call
		 */
		ok = pdb_set_trusteddom_pw(domain, new_trust_passwd,
					   &td->security_identifier);
		if (!ok) {
			DEBUG(0, ("pdb_set_trusteddom_pw() failed for domain %s!\n",
				  domain));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		break;

	default:
		smb_panic("Unsupported secure channel type");
		break;
	}

	DEBUG(0,("%s : %s(%s): Changed password locally\n",
		 current_timestring(talloc_tos(), false), __func__, domain));

	status = netlogon_creds_cli_ServerPasswordSet(context, b,
						      new_trust_passwd,
						      new_trust_version);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("%s : %s(%s) remote password change set with %s failed - %s\n",
			 current_timestring(talloc_tos(), false),
			 __func__, domain, context_name,
			 nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	DEBUG(0,("%s : %s(%s): Changed password remotely using %s\n",
		 current_timestring(talloc_tos(), false),
		 __func__, domain, context_name));

	ok = cli_credentials_set_password(creds, new_trust_passwd, CRED_SPECIFIED);
	if (!ok) {
		DEBUG(0, ("cli_credentials_set_password failed for domain %s!\n",
			  domain));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	current_nt_hash = cli_credentials_get_nt_hash(creds, frame);
	if (current_nt_hash == NULL) {
		DEBUG(0, ("cli_credentials_get_nt_hash failed for domain %s!\n",
			  domain));
		TALLOC_FREE(frame);
		return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
	}

	/*
	 * Now we verify the new password.
	 */
	status = netlogon_creds_cli_auth(context, b,
					 *current_nt_hash,
					 NULL); /* previous_nt_hash */
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("netlogon_creds_cli_auth(%s) failed for new password - %s!\n",
			  context_name, nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	DEBUG(0,("%s : %s(%s): Verified new password remotely using %s\n",
		 current_timestring(talloc_tos(), false),
		 __func__, domain, context_name));

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
