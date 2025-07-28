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
#include "lib/krb5_wrap/krb5_samba.h"
#include "librpc/gen_ndr/secrets.h"
#include "secrets.h"
#include "ads.h"
#include "passdb.h"
#include "libsmb/libsmb.h"
#include "source3/include/messages.h"
#include "source3/include/g_lock.h"
#include "lib/util/util_tdb.h"

/*********************************************************
 Change the domain password on the PDC.
 Do most of the legwork ourselves.  Caller must have
 already setup the connection to the NETLOGON pipe
**********************************************************/

struct trust_pw_change_state {
	struct g_lock_ctx *g_ctx;
	char *g_lock_key;
};

static int trust_pw_change_state_destructor(struct trust_pw_change_state *state)
{
	g_lock_unlock(state->g_ctx,
		      string_term_tdb_data(state->g_lock_key));
	return 0;
}

char *trust_pw_new_value(TALLOC_CTX *mem_ctx,
			 enum netr_SchannelType sec_channel_type,
			 int security)
{
	/*
	 * use secure defaults, which match
	 * what windows uses for computer passwords.
	 *
	 * We used to have min=128 and max=255 here, but
	 * it's a bad idea because of bugs in the Windows
	 * RODC/RWDC PasswordUpdateForward handling via
	 * NetrLogonSendToSam.
	 *
	 * See https://bugzilla.samba.org/show_bug.cgi?id=14984
	 */
	size_t min = 120;
	size_t max = 120;

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

/*
 * Temporary function to wrap cli_auth in a lck
 */

static NTSTATUS netlogon_creds_cli_lck_auth(
	struct netlogon_creds_cli_context *context,
	struct dcerpc_binding_handle *b,
	uint8_t num_nt_hashes,
	const struct samr_Password * const *nt_hashes,
	uint8_t *idx_nt_hashes)
{
	struct netlogon_creds_cli_lck *lck;
	NTSTATUS status;

	status = netlogon_creds_cli_lck(
		context, NETLOGON_CREDS_CLI_LCK_EXCLUSIVE,
		talloc_tos(), &lck);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("netlogon_creds_cli_lck failed: %s\n",
			    nt_errstr(status));
		return status;
	}

	status = netlogon_creds_cli_auth(context, b, num_nt_hashes, nt_hashes,
					 idx_nt_hashes);
	TALLOC_FREE(lck);

	return status;
}

static NTSTATUS extract_nt_hash_and_pwd(TALLOC_CTX *mem_ctx,
					const struct secrets_domain_info1_password *pw,
					const struct samr_Password **nt_hash,
					const char **_pwd)
{
	char *pwd = NULL;
	size_t pwd_len = 0;
	bool ok;

	ok = convert_string_talloc(mem_ctx,
				   CH_UTF16MUNGED, CH_UTF8,
				   pw->cleartext_blob.data,
				   pw->cleartext_blob.length,
				   &pwd, &pwd_len);
	if (!ok) {
		NTSTATUS status = NT_STATUS_UNMAPPABLE_CHARACTER;
		if (errno == ENOMEM) {
			status = NT_STATUS_NO_MEMORY;
		}
		return status;
	}
	talloc_keep_secret(pwd);

	*_pwd = pwd;
	*nt_hash = &pw->nt_hash;
	return NT_STATUS_OK;
}

NTSTATUS trust_pw_change(struct netlogon_creds_cli_context *context,
			 struct messaging_context *msg_ctx,
			 struct dcerpc_binding_handle *b,
			 const char *domain,
			 const char *dcname,
			 bool force)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *context_name = NULL;
	struct trust_pw_change_state *state;
	struct cli_credentials *creds = NULL;
	struct secrets_domain_info1 *info = NULL;
	struct secrets_domain_info1_change *prev = NULL;
	const struct samr_Password *current_nt_hash = NULL;
	const struct samr_Password *previous_nt_hash = NULL;
	uint8_t num_passwords = 0;
	uint8_t idx = 0;
	const struct samr_Password *nt_hashes[1+3] = { NULL, };
	uint8_t idx_passwords = 0;
	uint8_t idx_current = UINT8_MAX;
	const char *passwords[1+3] = { NULL, };
	enum netr_SchannelType sec_channel_type = SEC_CHAN_NULL;
	struct netlogon_creds_CredentialState *ncreds = NULL;
	time_t pass_last_set_time;
	uint32_t old_version = 0;
	struct pdb_trusted_domain *td = NULL;
	struct timeval g_timeout = { 0, };
	int timeout = 0;
	struct timeval tv = { 0, };
	char *new_trust_pw_str = NULL;
	size_t len = 0;
	DATA_BLOB new_trust_pw_blob = data_blob_null;
	uint32_t new_version = 0;
	uint32_t *new_trust_version = NULL;
	const char *account_principal = NULL;
	const char *explicit_kdc = NULL;
	char *cache_name = NULL;
	const char *check_password = NULL;
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
			     string_term_tdb_data(state->g_lock_key),
			     G_LOCK_WRITE, g_timeout, NULL, NULL);
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
	previous_nt_hash = cli_credentials_get_old_nt_hash(creds, frame);

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
	new_trust_pw_str = trust_pw_new_value(frame, sec_channel_type,
					      lp_security());
	if (new_trust_pw_str == NULL) {
		DEBUG(0, ("trust_pw_new_value() failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	len = strlen(new_trust_pw_str);
	ok = convert_string_talloc(frame, CH_UNIX, CH_UTF16,
				   new_trust_pw_str, len,
				   &new_trust_pw_blob.data,
				   &new_trust_pw_blob.length);
	if (!ok) {
		status = NT_STATUS_UNMAPPABLE_CHARACTER;
		if (errno == ENOMEM) {
			status = NT_STATUS_NO_MEMORY;
		}
		DBG_ERR("convert_string_talloc(CH_UTF16MUNGED, CH_UNIX) "
			"failed for of %s - %s\n",
			domain, nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}
	talloc_keep_secret(new_trust_pw_blob.data);

	switch (sec_channel_type) {

	case SEC_CHAN_WKSTA:
	case SEC_CHAN_BDC:
		status = secrets_prepare_password_change(domain,
							 dcname,
							 new_trust_pw_str,
							 frame,
							 &info,
							 &prev,
#ifdef HAVE_ADS
							 sync_pw2keytabs,
#else
							 NULL,
#endif
							 NULL /* opt_host */);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("secrets_prepare_password_change() failed for domain %s!\n",
				  domain));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		TALLOC_FREE(new_trust_pw_str);

		if (prev != NULL) {
			/*
			 * We had a failure before we changed the password.
			 */
			status = extract_nt_hash_and_pwd(frame,
							 prev->password,
							 &nt_hashes[idx],
							 &passwords[idx]);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("extract_nt_hash_and_pwd(%s) failed "
					  "for prev->password - %s!\n",
					  domain, nt_errstr(status)));
				TALLOC_FREE(frame);
				return status;
			}
			idx += 1;

			DEBUG(0,("%s : %s(%s): A password change was already "
				 "started against '%s' at %s. Trying to "
				 "recover...\n",
				 current_timestring(talloc_tos(), false),
				 __func__, domain,
				 prev->password->change_server,
				 nt_time_string(talloc_tos(),
				 prev->password->change_time)));
			DEBUG(0,("%s : %s(%s): Last failure local[%s] remote[%s] "
				 "against '%s' at %s.\n",
				 current_timestring(talloc_tos(), false),
				 __func__, domain,
				 nt_errstr(prev->local_status),
				 nt_errstr(prev->remote_status),
				 prev->change_server,
				 nt_time_string(talloc_tos(),
				 prev->change_time)));
		}

		idx_current = idx;
		status = extract_nt_hash_and_pwd(frame,
						 info->password,
						 &nt_hashes[idx],
						 &passwords[idx]);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("extract_nt_hash_and_pwd(%s) failed "
				  "for info->password - %s!\n",
				  domain, nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}
		idx += 1;
		if (info->old_password != NULL) {
			status = extract_nt_hash_and_pwd(frame,
							 info->old_password,
							 &nt_hashes[idx],
							 &passwords[idx]);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("extract_nt_hash_and_pwd(%s) failed "
					  "for info->old_password - %s!\n",
					  domain, nt_errstr(status)));
				TALLOC_FREE(frame);
				return status;
			}
			idx += 1;
		}
		if (info->older_password != NULL) {
			status = extract_nt_hash_and_pwd(frame,
							 info->older_password,
							 &nt_hashes[idx],
							 &passwords[idx]);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("extract_nt_hash_and_pwd(%s) failed "
					  "for info->older_password - %s!\n",
					  domain, nt_errstr(status)));
				TALLOC_FREE(frame);
				return status;
			}
			idx += 1;
		}

		/*
		 * We use the password that's already persistent in
		 * our database in order to handle failures.
		 */
		data_blob_free(&new_trust_pw_blob);
		new_trust_pw_blob = info->next_change->password->cleartext_blob;
		break;

	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
		idx_current = idx;
		nt_hashes[idx] = current_nt_hash;
		passwords[idx] = cli_credentials_get_password(creds);
		idx += 1;
		if (previous_nt_hash != NULL) {
			nt_hashes[idx] = previous_nt_hash;
			passwords[idx] = cli_credentials_get_old_password(creds);
			idx += 1;
		}
		break;

	default:
		smb_panic("Unsupported secure channel type");
		break;
	}
	num_passwords = idx;

	DEBUG(0,("%s : %s(%s): Verifying passwords remotely %s.\n",
		 current_timestring(talloc_tos(), false),
		 __func__, domain, context_name));

	/*
	 * Check which password the dc knows about.
	 *
	 * TODO:
	 * If the previous password is the only password in common with the dc,
	 * we better skip the password change, or use something like
	 * ServerTrustPasswordsGet() or netr_ServerGetTrustInfo() to fix our
	 * local secrets before doing the change.
	 */
	status = netlogon_creds_cli_lck_auth(context, b,
					     num_passwords,
					     nt_hashes,
					     &idx_passwords);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("netlogon_creds_cli_auth(%s) failed for old passwords (%u) - %s!\n",
			  context_name, num_passwords, nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(context, frame, &ncreds);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("netlogon_creds_cli_get(%s) failed  %s!\n",
			context_name, nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	if (ncreds->authenticate_kerberos) {
		const struct dcerpc_binding *bd =
			dcerpc_binding_handle_get_binding(b);
		const char *host = NULL;
		krb5_context kctx = NULL;
		krb5_ccache kccid = NULL;
		int ret;

		SMB_ASSERT(idx_passwords == 0);

		account_principal = cli_credentials_get_principal(creds,
								  frame);
		if (account_principal == NULL) {
			status = NT_STATUS_NO_MEMORY;
			DEBUG(0, ("cli_credentials_get_principal[%s] %s!\n",
				  context_name,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		host = dcerpc_binding_get_string_option(bd, "host");
		if (host == NULL) {
			status = NT_STATUS_INTERNAL_ERROR;
			DEBUG(0, ("dcerpc_binding_get_string_option(host)[%s] %s!\n",
				  context_name,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}
		if (!is_ipaddress(host)) {
			status = NT_STATUS_INTERNAL_ERROR;
			DEBUG(0, ("is_ipaddress(%s)[%s] => false %s!\n",
				  host,
				  context_name,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}
		explicit_kdc = host;

		ret = smb_krb5_init_context_common(&kctx);
		if (ret != 0) {
			status = krb5_to_nt_status(ret);
			DEBUG(0, ("smb_krb5_init_context_common[%s] %s!\n",
				  context_name,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		ret = smb_krb5_cc_new_unique_memory(kctx,
						    frame,
						    &cache_name,
						    &kccid);
		if (ret != 0) {
			krb5_free_context(kctx);
			status = krb5_to_nt_status(ret);
			DEBUG(0, ("smb_krb5_cc_new_unique_memory[%s] %s!\n",
				  context_name,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		ret = kerberos_kinit_passwords_ext(account_principal,
						   num_passwords,
						   passwords,
						   nt_hashes,
						   &idx_passwords,
						   explicit_kdc,
						   cache_name,
						   NULL,
						   NULL,
						   NULL,
						   &status);
		krb5_cc_destroy(kctx, kccid);
		krb5_free_context(kctx);
		if (ret != 0) {
			DEBUG(0, ("kerberos_kinit_passwords_ext(%s)[%s] "
				  "failed for old passwords (%u) - %s!\n",
				  account_principal,
				  context_name,
				  num_passwords,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}
	}

	if (prev != NULL && idx_passwords == 0) {
		DEBUG(0,("%s : %s(%s): Verified new password remotely "
			 "without changing %s\n",
			 current_timestring(talloc_tos(), false),
			 __func__, domain, context_name));

		status = secrets_finish_password_change(
			prev->password->change_server,
			prev->password->change_time,
			info,
#ifdef HAVE_ADS
			sync_pw2keytabs,
#else
			NULL,
#endif
			prev->password->change_server);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("secrets_prepare_password_change() failed for domain %s!\n",
				  domain));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		DEBUG(0,("%s : %s(%s): Recovered previous password change.\n",
			 current_timestring(talloc_tos(), false),
			 __func__, domain));
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (idx_passwords != idx_current) {
		DEBUG(0,("%s : %s(%s): Verified older password remotely "
			 "skip changing %s\n",
			 current_timestring(talloc_tos(), false),
			 __func__, domain, context_name));

		if (info == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
		}

		status = secrets_defer_password_change(dcname,
					NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE,
					NT_STATUS_NOT_COMMITTED,
					info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("secrets_defer_password_change() failed for domain %s!\n",
				  domain));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		TALLOC_FREE(frame);
		return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
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
		/*
		 * we called secrets_prepare_password_change() above.
		 */
		break;

	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
		/*
		 * we need to get the sid first for the
		 * pdb_set_trusteddom_pw call
		 */
		ok = pdb_set_trusteddom_pw(domain, new_trust_pw_str,
					   &td->security_identifier);
		if (!ok) {
			DEBUG(0, ("pdb_set_trusteddom_pw() failed for domain %s!\n",
				  domain));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		TALLOC_FREE(new_trust_pw_str);
		break;

	default:
		smb_panic("Unsupported secure channel type");
		break;
	}

	DEBUG(0,("%s : %s(%s): Changed password locally\n",
		 current_timestring(talloc_tos(), false), __func__, domain));

	status = netlogon_creds_cli_ServerPasswordSet(context, b,
						      &new_trust_pw_blob,
						      new_trust_version);
	if (!NT_STATUS_IS_OK(status)) {
		NTSTATUS status2;
		const char *fn = NULL;

		ok = dcerpc_binding_handle_is_connected(b);

		DEBUG(0,("%s : %s(%s) remote password change with %s failed "
			 "- %s (%s)\n",
			 current_timestring(talloc_tos(), false),
			 __func__, domain, context_name,
			 nt_errstr(status),
			 ok ? "connected": "disconnected"));

		if (!ok) {
			/*
			 * The connection is broken, we don't
			 * know if the password was changed,
			 * we hope to have more luck next time.
			 */
			status2 = secrets_failed_password_change(dcname,
							NT_STATUS_NOT_COMMITTED,
							status,
							info);
			fn = "secrets_failed_password_change";
		} else {
			/*
			 * The server rejected the change, we don't
			 * retry and defer the change to the next
			 * "machine password timeout" interval.
			 */
			status2 = secrets_defer_password_change(dcname,
							NT_STATUS_NOT_COMMITTED,
							status,
							info);
			fn = "secrets_defer_password_change";
		}
		if (!NT_STATUS_IS_OK(status2)) {
			DEBUG(0, ("%s() failed for domain %s!\n",
				  fn, domain));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		TALLOC_FREE(frame);
		return status;
	}

	DEBUG(0,("%s : %s(%s): Changed password remotely using %s\n",
		 current_timestring(talloc_tos(), false),
		 __func__, domain, context_name));

	switch (sec_channel_type) {

	case SEC_CHAN_WKSTA:
	case SEC_CHAN_BDC:
		status = secrets_finish_password_change(
			info->next_change->change_server,
			info->next_change->change_time,
			info,
#ifdef HAVE_ADS
			sync_pw2keytabs,
#else
			NULL,
#endif
			info->next_change->change_server);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("secrets_finish_password_change() failed for domain %s!\n",
				  domain));
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		DEBUG(0,("%s : %s(%s): Finished password change.\n",
			 current_timestring(talloc_tos(), false),
			 __func__, domain));
		break;

	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
		/*
		 * we used pdb_set_trusteddom_pw().
		 */
		break;

	default:
		smb_panic("Unsupported secure channel type");
		break;
	}

	ok = cli_credentials_set_utf16_password(creds,
						&new_trust_pw_blob,
						CRED_SPECIFIED);
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

	check_password = cli_credentials_get_password(creds);
	if (check_password == NULL) {
		DEBUG(0, ("cli_credentials_get_password failed for domain %s!\n",
			  domain));
		TALLOC_FREE(frame);
		return NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
	}

	/*
	 * Now we verify the new password.
	 */
	idx = 0;
	nt_hashes[idx] = current_nt_hash;
	passwords[idx] = check_password;
	idx += 1;
	num_passwords = idx;
	if (ncreds->authenticate_kerberos) {
		krb5_context kctx = NULL;
		krb5_ccache kccid = NULL;
		int ret;

		ret = smb_krb5_init_context_common(&kctx);
		if (ret != 0) {
			status = krb5_to_nt_status(ret);
			DEBUG(0, ("smb_krb5_init_context_common[%s] %s!\n",
				  context_name,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		ret = smb_krb5_cc_new_unique_memory(kctx,
						    frame,
						    &cache_name,
						    &kccid);
		if (ret != 0) {
			krb5_free_context(kctx);
			status = krb5_to_nt_status(ret);
			DEBUG(0, ("smb_krb5_cc_new_unique_memory[%s] %s!\n",
				  context_name,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		ret = kerberos_kinit_passwords_ext(account_principal,
						   num_passwords,
						   passwords,
						   nt_hashes,
						   &idx_passwords,
						   explicit_kdc,
						   cache_name,
						   NULL,
						   NULL,
						   NULL,
						   &status);
		krb5_cc_destroy(kctx, kccid);
		krb5_free_context(kctx);
		if (ret != 0) {
			DEBUG(0, ("kerberos_kinit_passwords_ext(%s)[%s] "
				  "failed for new password - %s!\n",
				  account_principal,
				  context_name,
				  nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}
	} else {
		status = netlogon_creds_cli_lck_auth(context, b,
						     num_passwords,
						     nt_hashes,
						     &idx_passwords);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("netlogon_creds_cli_auth(%s) failed for new password - %s!\n",
				  context_name, nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}
	}

	DEBUG(0,("%s : %s(%s): Verified new password remotely using %s\n",
		 current_timestring(talloc_tos(), false),
		 __func__, domain, context_name));

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
