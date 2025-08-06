/*
   Unix SMB/CIFS implementation.

   User credentials handling

   Copyright (C) Jelmer Vernooij 2005
   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
#include "lib/util/util_file.h"
#include "librpc/gen_ndr/samr.h" /* for struct samrPassword */
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include "auth/gensec/gensec.h"
#include "libcli/auth/libcli_auth.h"
#include "tevent.h"
#include "param/param.h"
#include "system/filesys.h"
#include "system/passwd.h"

static bool str_is_ascii(const char *s) {
	if (s != NULL) {
		for (; s[0] != '\0'; s++) {
			if (!isascii(s[0])) {
				return false;
			}
		}
	}

	return true;
}

/**
 * Create a new credentials structure
 * @param mem_ctx TALLOC_CTX parent for credentials structure
 */
_PUBLIC_ struct cli_credentials *cli_credentials_init(TALLOC_CTX *mem_ctx)
{
	struct cli_credentials *cred = talloc_zero(mem_ctx, struct cli_credentials);
	if (cred == NULL) {
		return cred;
	}

	cred->winbind_separator = '\\';

	cred->kerberos_state = CRED_USE_KERBEROS_DESIRED;

	cred->signing_state = SMB_SIGNING_DEFAULT;

	/*
	 * The default value of lpcfg_client_ipc_signing() is REQUIRED, so use
	 * the same value here.
	 */
	cred->ipc_signing_state = SMB_SIGNING_REQUIRED;
	cred->encryption_state = SMB_ENCRYPTION_DEFAULT;

	return cred;
}

_PUBLIC_
struct cli_credentials *cli_credentials_init_server(TALLOC_CTX *mem_ctx,
						    struct loadparm_context *lp_ctx)
{
	struct cli_credentials *server_creds = NULL;
	NTSTATUS status;
	bool ok;

	server_creds = cli_credentials_init(mem_ctx);
	if (server_creds == NULL) {
		return NULL;
	}

	ok = cli_credentials_set_conf(server_creds, lp_ctx);
	if (!ok) {
		TALLOC_FREE(server_creds);
		return NULL;
	}

	status = cli_credentials_set_machine_account(server_creds, lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to obtain server credentials: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(server_creds);
		return NULL;
	}

	return server_creds;
}

_PUBLIC_ void cli_credentials_set_callback_data(struct cli_credentials *cred,
						void *callback_data)
{
	cred->priv_data = callback_data;
}

_PUBLIC_ void *_cli_credentials_callback_data(struct cli_credentials *cred)
{
	return cred->priv_data;
}

/**
 * Create a new anonymous credential
 * @param mem_ctx TALLOC_CTX parent for credentials structure
 */
_PUBLIC_ struct cli_credentials *cli_credentials_init_anon(TALLOC_CTX *mem_ctx)
{
	struct cli_credentials *anon_credentials;

	anon_credentials = cli_credentials_init(mem_ctx);
	cli_credentials_set_anonymous(anon_credentials);

	return anon_credentials;
}

_PUBLIC_ bool cli_credentials_set_kerberos_state(struct cli_credentials *creds,
						 enum credentials_use_kerberos kerberos_state,
						 enum credentials_obtained obtained)
{
	if (obtained >= creds->kerberos_state_obtained) {
		creds->kerberos_state = kerberos_state;
		creds->kerberos_state_obtained = obtained;

		return true;
	}

	return false;
}

_PUBLIC_ void cli_credentials_set_forced_sasl_mech(struct cli_credentials *creds,
						   const char *sasl_mech)
{
	TALLOC_FREE(creds->forced_sasl_mech);
	creds->forced_sasl_mech = talloc_strdup(creds, sasl_mech);
}

_PUBLIC_ void cli_credentials_set_krb_forwardable(struct cli_credentials *creds,
						  enum credentials_krb_forwardable krb_forwardable)
{
	creds->krb_forwardable = krb_forwardable;
}

_PUBLIC_ enum credentials_use_kerberos cli_credentials_get_kerberos_state(struct cli_credentials *creds)
{
	return creds->kerberos_state;
}

_PUBLIC_ enum credentials_obtained cli_credentials_get_kerberos_state_obtained(struct cli_credentials *creds)
{
	return creds->kerberos_state_obtained;
}

_PUBLIC_ const char *cli_credentials_get_forced_sasl_mech(struct cli_credentials *creds)
{
	return creds->forced_sasl_mech;
}

_PUBLIC_ enum credentials_krb_forwardable cli_credentials_get_krb_forwardable(struct cli_credentials *creds)
{
	return creds->krb_forwardable;
}

_PUBLIC_ bool cli_credentials_set_gensec_features(struct cli_credentials *creds,
						  uint32_t gensec_features,
						  enum credentials_obtained obtained)
{
	if (obtained >= creds->gensec_features_obtained) {
		creds->gensec_features_obtained = obtained;
		creds->gensec_features = gensec_features;

		return true;
	}

	return false;
}

_PUBLIC_ bool cli_credentials_add_gensec_features(
	struct cli_credentials *creds,
	uint32_t gensec_features,
	enum credentials_obtained obtained)
{
	return cli_credentials_set_gensec_features(
		creds, creds->gensec_features | gensec_features, obtained);
}

_PUBLIC_ uint32_t cli_credentials_get_gensec_features(struct cli_credentials *creds)
{
	return creds->gensec_features;
}

/**
 * @brief Find out how the username was obtained.
 *
 * @param cred A credentials context.
 *
 * @return The obtained information for the username.
 */
_PUBLIC_ enum credentials_obtained
cli_credentials_get_username_obtained(struct cli_credentials *cred)
{
	return cred->username_obtained;
}

/**
 * Obtain the username for this credentials context.
 * @param cred credentials context
 * @retval The username set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
_PUBLIC_ const char *cli_credentials_get_username(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred,
					cred->machine_account_pending_lp_ctx);
	}

	if (cred->username_obtained == CRED_CALLBACK &&
	    !cred->callback_running) {
	    	cred->callback_running = true;
		cred->username = cred->username_cb(cred);
	    	cred->callback_running = false;
		if (cred->username_obtained == CRED_CALLBACK) {
			cred->username_obtained = CRED_CALLBACK_RESULT;
			cli_credentials_invalidate_ccache(cred, cred->username_obtained);
		}
	}

	return cred->username;
}

/**
 * @brief Obtain the username for this credentials context.
 *
 * @param[in]  cred  The credential context.
 *
 * @param[in]  obtained  A pointer to store the obtained information.
 *
 * return The user name or NULL if an error occurred.
 */
_PUBLIC_ const char *
cli_credentials_get_username_and_obtained(struct cli_credentials *cred,
					  enum credentials_obtained *obtained)
{
	if (obtained != NULL) {
		*obtained = cred->username_obtained;
	}

	return cli_credentials_get_username(cred);
}

_PUBLIC_ bool cli_credentials_set_username(struct cli_credentials *cred,
				  const char *val, enum credentials_obtained obtained)
{
	if (obtained >= cred->username_obtained) {
		cred->username = talloc_strdup(cred, val);
		cred->username_obtained = obtained;
		cli_credentials_invalidate_ccache(cred, cred->username_obtained);
		return true;
	}

	return false;
}

_PUBLIC_ bool cli_credentials_set_username_callback(struct cli_credentials *cred,
				  const char *(*username_cb) (struct cli_credentials *))
{
	if (cred->username_obtained < CRED_CALLBACK) {
		cred->username_cb = username_cb;
		cred->username_obtained = CRED_CALLBACK;
		return true;
	}

	return false;
}

_PUBLIC_ bool cli_credentials_set_bind_dn(struct cli_credentials *cred,
				 const char *bind_dn)
{
	cred->bind_dn = talloc_strdup(cred, bind_dn);
	return true;
}

/**
 * Obtain the BIND DN for this credentials context.
 * @param cred credentials context
 * @retval The username set on this context.
 * @note Return value will be NULL if not specified explicitly
 */
_PUBLIC_ const char *cli_credentials_get_bind_dn(struct cli_credentials *cred)
{
	return cred->bind_dn;
}


/**
 * @brief Find out how the principal was obtained.
 *
 * @param cred A credentials context.
 *
 * @return The obtained information for the principal.
 */
_PUBLIC_ enum credentials_obtained
cli_credentials_get_principal_obtained(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred,
					cred->machine_account_pending_lp_ctx);
	}

	if (cred->principal_obtained < cred->username_obtained
	    || cred->principal_obtained < MAX(cred->domain_obtained, cred->realm_obtained)) {
		const char *effective_username = NULL;
		const char *effective_realm = NULL;
		enum credentials_obtained effective_obtained;

		/*
		 * We don't want to trigger a callbacks in
		 * cli_credentials_get_username()
		 * cli_credentials_get_domain()
		 * nor
		 * cli_credentials_get_realm()
		 */

		effective_username = cred->username;
		if (effective_username == NULL || strlen(effective_username) == 0) {
			return cred->username_obtained;
		}

		if (cred->domain_obtained > cred->realm_obtained) {
			effective_realm = cred->domain;
			effective_obtained = MIN(cred->domain_obtained,
						 cred->username_obtained);
		} else {
			effective_realm = cred->realm;
			effective_obtained = MIN(cred->realm_obtained,
						 cred->username_obtained);
		}

		if (effective_realm == NULL || strlen(effective_realm) == 0) {
			effective_realm = cred->domain;
			effective_obtained = MIN(cred->domain_obtained,
						 cred->username_obtained);
		}

		if (effective_realm != NULL && strlen(effective_realm) != 0) {
			return effective_obtained;
		}
	}

	return cred->principal_obtained;
}

/**
 * Obtain the client principal for this credentials context.
 * @param cred credentials context
 * @retval The username set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
_PUBLIC_ char *cli_credentials_get_principal_and_obtained(struct cli_credentials *cred, TALLOC_CTX *mem_ctx, enum credentials_obtained *obtained)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred,
					cred->machine_account_pending_lp_ctx);
	}

	if (cred->principal_obtained == CRED_CALLBACK &&
	    !cred->callback_running) {
		const char *princ = NULL;

	    	cred->callback_running = true;
		princ = cred->principal_cb(cred);
	    	cred->callback_running = false;

		cred->principal = NULL;
		if (princ != NULL) {
			char *p = NULL;

			cred->principal = talloc_strdup(cred, princ);
			if (cred->principal == NULL) {
				return NULL;
			}

			p = strchr(cred->principal, '@');
			if (p != NULL) {
				p += 1;

				for (; p[0] != '\0'; p++) {
					*p = toupper(p[0]);
				}
			}
		}

		if (cred->principal_obtained == CRED_CALLBACK) {
			cred->principal_obtained = CRED_CALLBACK_RESULT;
			cli_credentials_invalidate_ccache(cred, cred->principal_obtained);
		}
	}

	if (cred->principal_obtained < cred->username_obtained
	    || cred->principal_obtained < MAX(cred->domain_obtained, cred->realm_obtained)) {
		const char *effective_username = NULL;
		const char *effective_realm = NULL;
		enum credentials_obtained effective_obtained;

		effective_username = cli_credentials_get_username(cred);
		if (effective_username == NULL || strlen(effective_username) == 0) {
			*obtained = cred->username_obtained;
			return NULL;
		}

		if (cred->domain_obtained > cred->realm_obtained) {
			effective_realm = cli_credentials_get_domain(cred);
			effective_obtained = MIN(cred->domain_obtained,
						 cred->username_obtained);
		} else {
			effective_realm = cli_credentials_get_realm(cred);
			effective_obtained = MIN(cred->realm_obtained,
						 cred->username_obtained);
		}

		if (effective_realm == NULL || strlen(effective_realm) == 0) {
			effective_realm = cli_credentials_get_domain(cred);
			effective_obtained = MIN(cred->domain_obtained,
						 cred->username_obtained);
		}

		if (effective_realm != NULL && strlen(effective_realm) != 0) {
			*obtained = effective_obtained;
			return talloc_asprintf(mem_ctx, "%s@%s",
					       effective_username,
					       effective_realm);
		}
	}
	*obtained = cred->principal_obtained;
	return talloc_strdup(mem_ctx, cred->principal);
}

/**
 * Obtain the client principal for this credentials context.
 * @param cred credentials context
 * @retval The username set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
_PUBLIC_ char *cli_credentials_get_principal(struct cli_credentials *cred, TALLOC_CTX *mem_ctx)
{
	enum credentials_obtained obtained;
	return cli_credentials_get_principal_and_obtained(cred, mem_ctx, &obtained);
}

_PUBLIC_ bool cli_credentials_set_principal(struct cli_credentials *cred,
				   const char *val,
				   enum credentials_obtained obtained)
{
	if (obtained >= cred->principal_obtained) {
		/* If `val = NULL` is passed, principal is reset */
		cred->principal = NULL;
		if (val != NULL) {
			char *p = strchr(val, '@');
			if (p != NULL) {
				/* For realm names, only ASCII is allowed */
				if (!str_is_ascii(p + 1)) {
					return false;
				}
			}

			cred->principal = talloc_strdup(cred, val);
			if (cred->principal == NULL) {
				return false;
			}

			p = strchr(cred->principal, '@');
			if (p != NULL) {
				p += 1;

				for (; p[0] != '\0'; p++) {
					*p = toupper(p[0]);
				}
			}
		}
		cred->principal_obtained = obtained;
		cli_credentials_invalidate_ccache(cred, cred->principal_obtained);
		return true;
	}

	return false;
}

/* Set a callback to get the principal.  This could be a popup dialog,
 * a terminal prompt or similar.  */
_PUBLIC_ bool cli_credentials_set_principal_callback(struct cli_credentials *cred,
				  const char *(*principal_cb) (struct cli_credentials *))
{
	if (cred->principal_obtained < CRED_CALLBACK) {
		cred->principal_cb = principal_cb;
		cred->principal_obtained = CRED_CALLBACK;
		return true;
	}

	return false;
}

/* Some of our tools are 'anonymous by default'.  This is a single
 * function to determine if authentication has been explicitly
 * requested */

_PUBLIC_ bool cli_credentials_authentication_requested(struct cli_credentials *cred)
{
	uint32_t gensec_features = 0;

	if (cred->bind_dn) {
		return true;
	}

	/*
	 * If we forced the mech we clearly want authentication. E.g. to use
	 * SASL/EXTERNAL which has no credentials.
	 */
	if (cred->forced_sasl_mech) {
		return true;
	}

	if (cli_credentials_is_anonymous(cred)){
		return false;
	}

	if (cred->principal_obtained >= CRED_SPECIFIED) {
		return true;
	}
	if (cred->username_obtained >= CRED_SPECIFIED) {
		return true;
	}

	if (cli_credentials_get_kerberos_state(cred) == CRED_USE_KERBEROS_REQUIRED) {
		return true;
	}

	gensec_features = cli_credentials_get_gensec_features(cred);
	if (gensec_features & GENSEC_FEATURE_NTLM_CCACHE) {
		return true;
	}

	if (gensec_features & GENSEC_FEATURE_SIGN) {
		return true;
	}

	if (gensec_features & GENSEC_FEATURE_SEAL) {
		return true;
	}

	return false;
}

/**
 * Obtain the password for this credentials context.
 * @param cred credentials context
 * @retval If set, the cleartext password, otherwise NULL
 */
_PUBLIC_ const char *cli_credentials_get_password(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred,
						    cred->machine_account_pending_lp_ctx);
	}

	if (cred->password_obtained == CRED_CALLBACK &&
	    !cred->callback_running &&
	    !cred->password_will_be_nt_hash) {
		cred->callback_running = true;
		cred->password = cred->password_cb(cred);
		cred->callback_running = false;
		if (cred->password_obtained == CRED_CALLBACK) {
			cred->password_obtained = CRED_CALLBACK_RESULT;
			cli_credentials_invalidate_ccache(cred, cred->password_obtained);
		}
	}

	return cred->password;
}

/**
 * @brief Find out how the password was obtained.
 *
 * @param cred A credentials context.
 *
 * @return The obtained information for the password.
 */
_PUBLIC_ enum credentials_obtained
cli_credentials_get_password_obtained(struct cli_credentials *cred)
{
	return cred->password_obtained;
}

/**
 * @brief Obtain the password for this credentials context.
 *
 * @param[in]  cred  The credential context.
 *
 * @param[in]  obtained  A pointer to store the obtained information.
 *
 * return The user name or NULL if an error occurred.
 */
_PUBLIC_ const char *
cli_credentials_get_password_and_obtained(struct cli_credentials *cred,
					  enum credentials_obtained *obtained)
{
	const char *password = cli_credentials_get_password(cred);

	if (obtained != NULL) {
		*obtained = cred->password_obtained;
	}

	return password;
}

/* Set a password on the credentials context, including an indication
 * of 'how' the password was obtained */

_PUBLIC_ bool cli_credentials_set_password(struct cli_credentials *cred,
				  const char *val,
				  enum credentials_obtained obtained)
{
	if (obtained >= cred->password_obtained) {

		cred->lm_response = data_blob_null;
		cred->nt_response = data_blob_null;
		cred->nt_hash = NULL;
		cred->password = NULL;

		cli_credentials_invalidate_ccache(cred, obtained);

		cred->password_tries = 0;

		if (val == NULL) {
			cred->password_obtained = obtained;
			return true;
		}

		if (cred->password_will_be_nt_hash) {
			struct samr_Password *nt_hash = NULL;
			size_t val_len = strlen(val);
			size_t converted;

			nt_hash = talloc(cred, struct samr_Password);
			if (nt_hash == NULL) {
				return false;
			}
			talloc_keep_secret(nt_hash);

			converted = strhex_to_str((char *)nt_hash->hash,
						  sizeof(nt_hash->hash),
						  val, val_len);
			if (converted != sizeof(nt_hash->hash)) {
				TALLOC_FREE(nt_hash);
				return false;
			}

			cred->nt_hash = nt_hash;
			cred->password_obtained = obtained;
			return true;
		}

		cred->password = talloc_strdup(cred, val);
		if (cred->password == NULL) {
			return false;
		}
		talloc_keep_secret(discard_const(cred->password));

		/* Don't print the actual password in talloc memory dumps */
		talloc_set_name_const(cred->password,
			"password set via cli_credentials_set_password");
		cred->password_obtained = obtained;

		return true;
	}

	return false;
}

_PUBLIC_ bool cli_credentials_set_password_callback(struct cli_credentials *cred,
					   const char *(*password_cb) (struct cli_credentials *))
{
	if (cred->password_obtained < CRED_CALLBACK) {
		cred->password_tries = 3;
		cred->password_cb = password_cb;
		cred->password_obtained = CRED_CALLBACK;
		cli_credentials_invalidate_ccache(cred, cred->password_obtained);
		return true;
	}

	return false;
}

/**
 * Obtain the 'old' password for this credentials context (used for join accounts).
 * @param cred credentials context
 * @retval If set, the cleartext password, otherwise NULL
 */
_PUBLIC_ const char *cli_credentials_get_old_password(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred,
						    cred->machine_account_pending_lp_ctx);
	}

	return cred->old_password;
}

_PUBLIC_ bool cli_credentials_set_old_password(struct cli_credentials *cred,
				      const char *val,
				      enum credentials_obtained obtained)
{
	cred->old_password = talloc_strdup(cred, val);
	if (cred->old_password) {
		/* Don't print the actual password in talloc memory dumps */
		talloc_set_name_const(cred->old_password, "password set via cli_credentials_set_old_password");
	}
	cred->old_nt_hash = NULL;
	return true;
}

/**
 * Obtain the password, in the form MD4(unicode(password)) for this credentials context.
 *
 * Sometimes we only have this much of the password, while the rest of
 * the time this call avoids calling E_md4hash themselves.
 *
 * @param cred credentials context
 * @retval If set, the cleartext password, otherwise NULL
 */
_PUBLIC_ struct samr_Password *cli_credentials_get_nt_hash(struct cli_credentials *cred,
							   TALLOC_CTX *mem_ctx)
{
	enum credentials_obtained password_obtained;
	enum credentials_obtained ccache_threshold;
	enum credentials_obtained client_gss_creds_threshold;
	bool password_is_nt_hash;
	const char *password = NULL;
	struct samr_Password *nt_hash = NULL;

	if (cred->nt_hash != NULL) {
		/*
		 * If we already have a hash it's easy.
		 */
		goto return_hash;
	}

	/*
	 * This is a bit tricky, with password_will_be_nt_hash
	 * we still need to get the value via the password_callback
	 * but if we did that we should not remember it's state
	 * in the long run so we need to undo it.
	 */

	password_obtained = cred->password_obtained;
	ccache_threshold = cred->ccache_threshold;
	client_gss_creds_threshold = cred->client_gss_creds_threshold;
	password_is_nt_hash = cred->password_will_be_nt_hash;

	cred->password_will_be_nt_hash = false;
	password = cli_credentials_get_password(cred);

	cred->password_will_be_nt_hash = password_is_nt_hash;
	if (password_is_nt_hash && password_obtained == CRED_CALLBACK) {
		/*
		 * We got the nt_hash as string via the callback,
		 * so we need to undo the state change.
		 *
		 * And also don't remember it as plaintext password.
		 */
		cred->client_gss_creds_threshold = client_gss_creds_threshold;
		cred->ccache_threshold = ccache_threshold;
		cred->password_obtained = password_obtained;
		cred->password = NULL;
	}

	if (password == NULL) {
		return NULL;
	}

	nt_hash = talloc(cred, struct samr_Password);
	if (nt_hash == NULL) {
		return NULL;
	}
	talloc_keep_secret(nt_hash);

	if (password_is_nt_hash) {
		size_t password_len = strlen(password);
		size_t converted;

		converted = strhex_to_str((char *)nt_hash->hash,
					  sizeof(nt_hash->hash),
					  password, password_len);
		if (converted != sizeof(nt_hash->hash)) {
			TALLOC_FREE(nt_hash);
			return NULL;
		}
	} else {
		E_md4hash(password, nt_hash->hash);
	}

	cred->nt_hash = nt_hash;
	nt_hash = NULL;

return_hash:
	nt_hash = talloc(mem_ctx, struct samr_Password);
	if (nt_hash == NULL) {
		return NULL;
	}
	talloc_keep_secret(nt_hash);

	*nt_hash = *cred->nt_hash;

	return nt_hash;
}

/**
 * Obtain the old password, in the form MD4(unicode(password)) for this credentials context.
 *
 * Sometimes we only have this much of the password, while the rest of
 * the time this call avoids calling E_md4hash themselves.
 *
 * @param cred credentials context
 * @retval If set, the cleartext password, otherwise NULL
 */
_PUBLIC_ struct samr_Password *cli_credentials_get_old_nt_hash(struct cli_credentials *cred,
							       TALLOC_CTX *mem_ctx)
{
	const char *old_password = NULL;

	if (cred->old_nt_hash != NULL) {
		struct samr_Password *nt_hash = talloc(mem_ctx, struct samr_Password);
		if (!nt_hash) {
			return NULL;
		}
		talloc_keep_secret(nt_hash);

		*nt_hash = *cred->old_nt_hash;

		return nt_hash;
	}

	old_password = cli_credentials_get_old_password(cred);
	if (old_password) {
		struct samr_Password *nt_hash = talloc(mem_ctx, struct samr_Password);
		if (!nt_hash) {
			return NULL;
		}
		talloc_keep_secret(nt_hash);

		E_md4hash(old_password, nt_hash->hash);

		return nt_hash;
	}

	return NULL;
}

/**
 * Obtain the 'short' or 'NetBIOS' domain for this credentials context.
 * @param cred credentials context
 * @retval The domain set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
_PUBLIC_ const char *cli_credentials_get_domain(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred,
						    cred->machine_account_pending_lp_ctx);
	}

	if (cred->domain_obtained == CRED_CALLBACK &&
	    !cred->callback_running) {
	    	cred->callback_running = true;
		cred->domain = cred->domain_cb(cred);
	    	cred->callback_running = false;
		if (cred->domain_obtained == CRED_CALLBACK) {
			cred->domain_obtained = CRED_CALLBACK_RESULT;
			cli_credentials_invalidate_ccache(cred, cred->domain_obtained);
		}
	}

	return cred->domain;
}

/**
 * @brief Obtain the domain for this credential context.
 *
 * @param[in] cred  The credential context.
 *
 * @param[out] obtained A pointer to store the obtained information.
 *
 * @return The domain name or NULL if an error occurred.
 */
_PUBLIC_ const char *cli_credentials_get_domain_and_obtained(
	struct cli_credentials *cred,
	enum credentials_obtained *obtained)
{
	const char *domain = cli_credentials_get_domain(cred);

	if (obtained != NULL) {
		*obtained = cred->domain_obtained;
	}

	return domain;
}


_PUBLIC_ bool cli_credentials_set_domain(struct cli_credentials *cred,
				const char *val,
				enum credentials_obtained obtained)
{
	if (obtained >= cred->domain_obtained) {
		/* it is important that the domain be in upper case,
		 * particularly for the sensitive NTLMv2
		 * calculations */
		cred->domain = strupper_talloc(cred, val);
		cred->domain_obtained = obtained;
		/* setting domain does not mean we have to invalidate ccache
		 * because domain in not used for Kerberos operations.
		 * If ccache invalidation is required, one will anyway specify
		 * a password to kinit, and that will force invalidation of the ccache
		 */
		return true;
	}

	return false;
}

bool cli_credentials_set_domain_callback(struct cli_credentials *cred,
					 const char *(*domain_cb) (struct cli_credentials *))
{
	if (cred->domain_obtained < CRED_CALLBACK) {
		cred->domain_cb = domain_cb;
		cred->domain_obtained = CRED_CALLBACK;
		return true;
	}

	return false;
}

/**
 * Obtain the Kerberos realm for this credentials context.
 * @param cred credentials context
 * @retval The realm set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
_PUBLIC_ const char *cli_credentials_get_realm(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred,
						    cred->machine_account_pending_lp_ctx);
	}

	if (cred->realm_obtained == CRED_CALLBACK &&
	    !cred->callback_running) {
		const char *realm = NULL;

	    	cred->callback_running = true;
		realm = cred->realm_cb(cred);
	    	cred->callback_running = false;

		cred->realm = NULL;
		if (realm != NULL) {
			cred->realm = strupper_talloc(cred, realm);
			if (cred->realm == NULL) {
				return NULL;
			}
		}

		if (cred->realm_obtained == CRED_CALLBACK) {
			cred->realm_obtained = CRED_CALLBACK_RESULT;
			cli_credentials_invalidate_ccache(cred, cred->realm_obtained);
		}
	}

	return cred->realm;
}

/**
 * Set the realm for this credentials context, and force it to
 * uppercase for the sanity of our local kerberos libraries
 */
_PUBLIC_ bool cli_credentials_set_realm(struct cli_credentials *cred,
			       const char *val,
			       enum credentials_obtained obtained)
{
	if (obtained >= cred->realm_obtained) {
		/* If `val = NULL` is passed, realm is reset */
		cred->realm = NULL;
		if (val != NULL) {
			/* For realm names, only ASCII is allowed */
			if (!str_is_ascii(val)) {
				return false;
			}

			cred->realm = strupper_talloc(cred, val);
			if (cred->realm == NULL) {
				return false;
			}
		}
		cred->realm_obtained = obtained;
		cli_credentials_invalidate_ccache(cred, cred->realm_obtained);
		return true;
	}

	return false;
}

bool cli_credentials_set_realm_callback(struct cli_credentials *cred,
					const char *(*realm_cb) (struct cli_credentials *))
{
	if (cred->realm_obtained < CRED_CALLBACK) {
		cred->realm_cb = realm_cb;
		cred->realm_obtained = CRED_CALLBACK;
		return true;
	}

	return false;
}

/**
 * Obtain the 'short' or 'NetBIOS' workstation name for this credentials context.
 *
 * @param cred credentials context
 * @retval The workstation name set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
_PUBLIC_ const char *cli_credentials_get_workstation(struct cli_credentials *cred)
{
	if (cred->workstation_obtained == CRED_CALLBACK &&
	    !cred->callback_running) {
	    	cred->callback_running = true;
		cred->workstation = cred->workstation_cb(cred);
	    	cred->callback_running = false;
		if (cred->workstation_obtained == CRED_CALLBACK) {
			cred->workstation_obtained = CRED_CALLBACK_RESULT;
		}
	}

	return cred->workstation;
}

_PUBLIC_ bool cli_credentials_set_workstation(struct cli_credentials *cred,
				     const char *val,
				     enum credentials_obtained obtained)
{
	if (obtained >= cred->workstation_obtained) {
		cred->workstation = talloc_strdup(cred, val);
		cred->workstation_obtained = obtained;
		return true;
	}

	return false;
}

bool cli_credentials_set_workstation_callback(struct cli_credentials *cred,
					      const char *(*workstation_cb) (struct cli_credentials *))
{
	if (cred->workstation_obtained < CRED_CALLBACK) {
		cred->workstation_cb = workstation_cb;
		cred->workstation_obtained = CRED_CALLBACK;
		return true;
	}

	return false;
}

/**
 * Given a string, typically obtained from a -U argument, parse it into domain, username, realm and password fields
 *
 * The format accepted is [domain\\]user[%password] or user[@realm][%password]
 *
 * @param credentials Credentials structure on which to set the password
 * @param data the string containing the username, password etc
 * @param obtained This enum describes how 'specified' this password is
 */

_PUBLIC_ void cli_credentials_parse_string(struct cli_credentials *credentials, const char *data, enum credentials_obtained obtained)
{
	char *uname, *p;
	char *uname_free = NULL;

	if (strcmp("%",data) == 0) {
		cli_credentials_set_anonymous(credentials);
		return;
	}

	uname = talloc_strdup(credentials, data);
	uname_free = uname;

	if ((p = strchr_m(uname,'%'))) {
		*p = 0;
		cli_credentials_set_password(credentials, p+1, obtained);
	}

	if ((p = strchr_m(uname,'@'))) {
		/*
		 * We also need to set username and domain
		 * in order to undo the effect of
		 * cli_credentials_guess().
		 */
		cli_credentials_set_username(credentials, uname, obtained);
		cli_credentials_set_domain(credentials, "", obtained);

		cli_credentials_set_principal(credentials, uname, obtained);
		*p = 0;
		cli_credentials_set_realm(credentials, p+1, obtained);
		TALLOC_FREE(uname_free);
		return;
	} else if ((p = strchr_m(uname,'\\'))
		   || (p = strchr_m(uname, '/'))
		   || (p = strchr_m(uname, credentials->winbind_separator)))
	{
		const char *domain = NULL;

		domain = uname;
		*p = 0;
		uname = p+1;

		if (obtained == credentials->realm_obtained &&
		    !strequal_m(credentials->domain, domain))
		{
			/*
			 * We need to undo a former set with the same level
			 * in order to get the expected result from
			 * cli_credentials_get_principal().
			 *
			 * But we only need to do that if the domain
			 * actually changes.
			 */
			cli_credentials_set_realm(credentials, domain, obtained);
		}
		cli_credentials_set_domain(credentials, domain, obtained);
	}
	if (obtained == credentials->principal_obtained &&
	    !strequal_m(credentials->username, uname))
	{
		/*
		 * We need to undo a former set with the same level
		 * in order to get the expected result from
		 * cli_credentials_get_principal().
		 *
		 * But we only need to do that if the username
		 * actually changes.
		 */
		credentials->principal_obtained = CRED_UNINITIALISED;
		credentials->principal = NULL;
	}
	cli_credentials_set_username(credentials, uname, obtained);

	TALLOC_FREE(uname_free);
}

/**
 * Given a a credentials structure, print it as a string
 *
 * The format output is [domain\\]user[%password] or user[@realm][%password]
 *
 * @param credentials Credentials structure on which to set the password
 * @param mem_ctx The memory context to place the result on
 */

_PUBLIC_ char *cli_credentials_get_unparsed_name(struct cli_credentials *credentials, TALLOC_CTX *mem_ctx)
{
	const char *bind_dn = cli_credentials_get_bind_dn(credentials);
	const char *domain = NULL;
	const char *username = NULL;
	char *name = NULL;

	if (bind_dn) {
		name = talloc_strdup(mem_ctx, bind_dn);
	} else {
		cli_credentials_get_ntlm_username_domain(credentials, mem_ctx, &username, &domain);
		if (domain && domain[0]) {
			name = talloc_asprintf(mem_ctx, "%s\\%s",
					       domain, username);
		} else {
			name = talloc_asprintf(mem_ctx, "%s",
					       username);
		}
	}
	return name;
}


/**
 * Specifies default values for domain, workstation and realm
 * from the smb.conf configuration file
 *
 * @param cred Credentials structure to fill in
 *
 * @return true on success, false on error.
 */
_PUBLIC_ bool cli_credentials_set_conf(struct cli_credentials *cred,
				       struct loadparm_context *lp_ctx)
{
	const char *sep = NULL;
	const char *realm = lpcfg_realm(lp_ctx);
	enum credentials_client_protection protection =
		lpcfg_client_protection(lp_ctx);
	const char *workgroup = lpcfg_workgroup(lp_ctx);
	const char *netbios_name = lpcfg_netbios_name(lp_ctx);
	bool ok;

	(void)cli_credentials_set_username(cred, "", CRED_UNINITIALISED);

	if (workgroup != NULL && strlen(workgroup) == 0) {
		workgroup = NULL;
	}

	if (workgroup != NULL) {
		if (lpcfg_parm_is_cmdline(lp_ctx, "workgroup")) {
			ok = cli_credentials_set_domain(cred,
							workgroup,
							CRED_SPECIFIED);
			if (!ok) {
				DBG_ERR("Failed to set domain!\n");
				return false;
			}
		} else {
			(void)cli_credentials_set_domain(cred,
							 workgroup,
							 CRED_SMB_CONF);
		}
	}

	if (netbios_name != NULL && strlen(netbios_name) == 0) {
		netbios_name = NULL;
	}

	if (netbios_name != NULL) {
		if (lpcfg_parm_is_cmdline(lp_ctx, "netbios name")) {
			ok = cli_credentials_set_workstation(cred,
							     netbios_name,
							     CRED_SPECIFIED);
			if (!ok) {
				DBG_ERR("Failed to set workstation!\n");
				return false;
			}
		} else {
			(void)cli_credentials_set_workstation(cred,
							      netbios_name,
							      CRED_SMB_CONF);
		}
	}

	if (realm != NULL && strlen(realm) == 0) {
		realm = NULL;
	}

	if (realm != NULL) {
		if (lpcfg_parm_is_cmdline(lp_ctx, "realm")) {
			ok = cli_credentials_set_realm(cred,
						       realm,
						       CRED_SPECIFIED);
			if (!ok) {
				DBG_ERR("Failed to set realm!\n");
				return false;
			}
		} else {
			(void)cli_credentials_set_realm(cred,
							realm,
							CRED_SMB_CONF);
		}
	}

	sep = lpcfg_winbind_separator(lp_ctx);
	if (sep != NULL && sep[0] != '\0') {
		cred->winbind_separator = *lpcfg_winbind_separator(lp_ctx);
	}

	if (cred->signing_state_obtained <= CRED_SMB_CONF) {
		/* Will be set to default for invalid smb.conf values */
		cred->signing_state = lpcfg_client_signing(lp_ctx);
		if (cred->signing_state == SMB_SIGNING_DEFAULT) {
			switch (protection) {
			case CRED_CLIENT_PROTECTION_DEFAULT:
				break;
			case CRED_CLIENT_PROTECTION_PLAIN:
				cred->signing_state = SMB_SIGNING_OFF;
				break;
			case CRED_CLIENT_PROTECTION_SIGN:
			case CRED_CLIENT_PROTECTION_ENCRYPT:
				cred->signing_state = SMB_SIGNING_REQUIRED;
				break;
			}
		}

		cred->signing_state_obtained = CRED_SMB_CONF;
	}

	if (cred->ipc_signing_state_obtained <= CRED_SMB_CONF) {
		/* Will be set to required for invalid smb.conf values */
		cred->ipc_signing_state = lpcfg_client_ipc_signing(lp_ctx);
		cred->ipc_signing_state_obtained = CRED_SMB_CONF;
	}

	if (cred->encryption_state_obtained <= CRED_SMB_CONF) {
		/* Will be set to default for invalid smb.conf values */
		cred->encryption_state = lpcfg_client_smb_encrypt(lp_ctx);
		if (cred->encryption_state == SMB_ENCRYPTION_DEFAULT) {
			switch (protection) {
			case CRED_CLIENT_PROTECTION_DEFAULT:
				break;
			case CRED_CLIENT_PROTECTION_PLAIN:
			case CRED_CLIENT_PROTECTION_SIGN:
				cred->encryption_state = SMB_ENCRYPTION_OFF;
				break;
			case CRED_CLIENT_PROTECTION_ENCRYPT:
				cred->encryption_state = SMB_ENCRYPTION_REQUIRED;
				break;
			}
		}
	}

	if (cred->kerberos_state_obtained <= CRED_SMB_CONF) {
		/* Will be set to default for invalid smb.conf values */
		cred->kerberos_state = lpcfg_client_use_kerberos(lp_ctx);
		cred->kerberos_state_obtained = CRED_SMB_CONF;
	}

	if (cred->gensec_features_obtained <= CRED_SMB_CONF) {
		switch (protection) {
		case CRED_CLIENT_PROTECTION_DEFAULT:
			break;
		case CRED_CLIENT_PROTECTION_PLAIN:
			cred->gensec_features = 0;
			break;
		case CRED_CLIENT_PROTECTION_SIGN:
			cred->gensec_features = GENSEC_FEATURE_SIGN;
			break;
		case CRED_CLIENT_PROTECTION_ENCRYPT:
			cred->gensec_features =
				GENSEC_FEATURE_SIGN|GENSEC_FEATURE_SEAL;
			break;
		}
		cred->gensec_features_obtained = CRED_SMB_CONF;
	}

	return true;
}

/**
 * Guess defaults for credentials from environment variables,
 * and from the configuration file
 *
 * @param cred Credentials structure to fill in
 */
_PUBLIC_ bool cli_credentials_guess(struct cli_credentials *cred,
				    struct loadparm_context *lp_ctx)
{
	const char *error_string;
	const char *env = NULL;
	struct passwd *pwd = NULL;
	bool ok;

	if (lp_ctx != NULL) {
		ok = cli_credentials_set_conf(cred, lp_ctx);
		if (!ok) {
			return false;
		}
	}

	pwd = getpwuid(getuid());
	if (pwd != NULL) {
		size_t len = strlen(pwd->pw_name);

		if (len > 0 && len <= 1024) {
			(void)cli_credentials_parse_string(cred,
							   pwd->pw_name,
							   CRED_GUESS_ENV);
		}
	}

	env = getenv("LOGNAME");
	if (env != NULL) {
		size_t len = strlen(env);

		if (len > 0 && len <= 1024) {
			(void)cli_credentials_set_username(cred,
							   env,
							   CRED_GUESS_ENV);
		}
	}

	env = getenv("USER");
	if (env != NULL) {
		size_t len = strlen(env);

		if (len > 0 && len <= 1024) {
			char *p = NULL;

			(void)cli_credentials_parse_string(cred,
							   env,
							   CRED_GUESS_ENV);
			if ((p = strchr_m(env, '%'))) {
				memset(p, '\0', strlen(cred->password));
			}
		}
	}

	env = getenv("PASSWD");
	if (env != NULL) {
		size_t len = strlen(env);

		if (len > 0 && len <= 1024) {
			(void)cli_credentials_set_password(cred,
							   env,
							   CRED_GUESS_ENV);
		}
	}

	env = getenv("PASSWD_FD");
	if (env != NULL) {
		size_t len = strlen(env);

		if (len > 0 && len <= 1024) {
			int fd = atoi(env);

			(void)cli_credentials_parse_password_fd(cred,
								fd,
								CRED_GUESS_FILE);
		}
	}

	env = getenv("PASSWD_FILE");
	if (env != NULL) {
		size_t len = strlen(env);

		if (len > 0 && len <= 4096) {
			(void)cli_credentials_parse_password_file(cred,
								  env,
								  CRED_GUESS_FILE);
		}
	}

	if (lp_ctx != NULL &&
	    cli_credentials_get_kerberos_state(cred) != CRED_USE_KERBEROS_DISABLED) {
		(void)cli_credentials_set_ccache(cred,
						 lp_ctx,
						 NULL,
						 CRED_GUESS_FILE,
						 &error_string);
	}

	return true;
}

/**
 * Attach NETLOGON credentials for use with SCHANNEL
 */

_PUBLIC_ void cli_credentials_set_netlogon_creds(
	struct cli_credentials *cred,
	const struct netlogon_creds_CredentialState *netlogon_creds)
{
	TALLOC_FREE(cred->netlogon_creds);
	if (netlogon_creds == NULL) {
		return;
	}
	cred->netlogon_creds = netlogon_creds_copy(cred, netlogon_creds);
}

/**
 * Return attached NETLOGON credentials
 */

_PUBLIC_ struct netlogon_creds_CredentialState *cli_credentials_get_netlogon_creds(struct cli_credentials *cred)
{
	return cred->netlogon_creds;
}

/**
 * Set NETLOGON secure channel type
 */

_PUBLIC_ void cli_credentials_set_secure_channel_type(struct cli_credentials *cred,
					     enum netr_SchannelType secure_channel_type)
{
	cred->secure_channel_type = secure_channel_type;
}

/**
 * Return NETLOGON secure channel type
 */

_PUBLIC_ time_t cli_credentials_get_password_last_changed_time(struct cli_credentials *cred)
{
	return cred->password_last_changed_time;
}

/**
 * Set NETLOGON secure channel type
 */

_PUBLIC_ void cli_credentials_set_password_last_changed_time(struct cli_credentials *cred,
							     time_t last_changed_time)
{
	cred->password_last_changed_time = last_changed_time;
}

/**
 * Return NETLOGON secure channel type
 */

_PUBLIC_ enum netr_SchannelType cli_credentials_get_secure_channel_type(struct cli_credentials *cred)
{
	return cred->secure_channel_type;
}

/**
 * Fill in a credentials structure as the anonymous user
 */
_PUBLIC_ void cli_credentials_set_anonymous(struct cli_credentials *cred)
{
	cli_credentials_set_username(cred, "", CRED_SPECIFIED);
	cli_credentials_set_domain(cred, "", CRED_SPECIFIED);
	cli_credentials_set_password(cred, NULL, CRED_SPECIFIED);
	cli_credentials_set_principal(cred, NULL, CRED_SPECIFIED);
	cli_credentials_set_realm(cred, NULL, CRED_SPECIFIED);
	cli_credentials_set_workstation(cred, "", CRED_UNINITIALISED);
	cli_credentials_set_kerberos_state(cred,
					   CRED_USE_KERBEROS_DISABLED,
					   CRED_SPECIFIED);
}

/**
 * Describe a credentials context as anonymous or authenticated
 * @retval true if anonymous, false if a username is specified
 */

_PUBLIC_ bool cli_credentials_is_anonymous(struct cli_credentials *cred)
{
	const char *username;

	/* if bind dn is set it's not anonymous */
	if (cred->bind_dn) {
		return false;
	}

	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred,
						    cred->machine_account_pending_lp_ctx);
	}

	/* if principal is set, it's not anonymous */
	if ((cred->principal != NULL) && cred->principal_obtained >= cred->username_obtained) {
		return false;
	}

	username = cli_credentials_get_username(cred);

	/* Yes, it is deliberate that we die if we have a NULL pointer
	 * here - anonymous is "", not NULL, which is 'never specified,
	 * never guessed', ie programmer bug */
	if (!username[0]) {
		return true;
	}

	return false;
}

/**
 * Mark the current password for a credentials struct as wrong. This will
 * cause the password to be prompted again (if a callback is set).
 *
 * This will decrement the number of times the password can be tried.
 *
 * @retval whether the credentials struct is finished
 */
_PUBLIC_ bool cli_credentials_wrong_password(struct cli_credentials *cred)
{
	if (cred->password_obtained != CRED_CALLBACK_RESULT) {
		return false;
	}

	if (cred->password_tries == 0) {
		return false;
	}

	cred->password_tries--;

	if (cred->password_tries == 0) {
		return false;
	}

	cred->password_obtained = CRED_CALLBACK;
	return true;
}

_PUBLIC_ void cli_credentials_get_ntlm_username_domain(struct cli_credentials *cred, TALLOC_CTX *mem_ctx,
					      const char **username,
					      const char **domain)
{
	if (!cli_credentials_is_anonymous(cred) &&
	    cred->principal_obtained >= cred->username_obtained)
	{
		*domain = talloc_strdup(mem_ctx, "");
		*username = cli_credentials_get_principal(cred, mem_ctx);
	} else {
		*domain = cli_credentials_get_domain(cred);
		*username = cli_credentials_get_username(cred);
	}
}

/**
 * Read a named file, and parse it for username, domain, realm and password
 *
 * @param credentials Credentials structure on which to set the password
 * @param file a named file to read the details from
 * @param obtained This enum describes how 'specified' this password is
 */

_PUBLIC_ bool cli_credentials_parse_file(struct cli_credentials *cred, const char *file, enum credentials_obtained obtained)
{
	uint16_t len = 0;
	char *ptr, *val, *param;
	char **lines;
	int i, numlines;
	const char *realm = NULL;
	const char *domain = NULL;
	const char *password = NULL;
	const char *username = NULL;

	lines = file_lines_load(file, &numlines, 0, NULL);

	if (lines == NULL)
	{
		/* fail if we can't open the credentials file */
		d_printf("ERROR: Unable to open credentials file!\n");
		return false;
	}

	for (i = 0; i < numlines; i++) {
		len = strlen(lines[i]);

		if (len == 0)
			continue;

		/* break up the line into parameter & value.
		 * will need to eat a little whitespace possibly */
		param = lines[i];
		if (!(ptr = strchr_m (lines[i], '=')))
			continue;

		val = ptr+1;
		*ptr = '\0';

		/* eat leading white space */
		while ((*val!='\0') && ((*val==' ') || (*val=='\t')))
			val++;

		if (strwicmp("password", param) == 0) {
			password = val;
		} else if (strwicmp("username", param) == 0) {
			username = val;
		} else if (strwicmp("domain", param) == 0) {
			domain = val;
		} else if (strwicmp("realm", param) == 0) {
			realm = val;
		}

		/*
		 * We need to readd '=' in order to let
		 * the strlen() work in the last loop
		 * that clears the memory.
		 */
		*ptr = '=';
	}

	if (realm != NULL && strlen(realm) != 0) {
		/*
		 * only overwrite with a valid string
		 */
		cli_credentials_set_realm(cred, realm, obtained);
	}

	if (domain != NULL && strlen(domain) != 0) {
		/*
		 * only overwrite with a valid string
		 */
		cli_credentials_set_domain(cred, domain, obtained);
	}

	if (password != NULL) {
		/*
		 * Here we allow "".
		 */
		cli_credentials_set_password(cred, password, obtained);
	}

	if (username != NULL) {
		/*
		 * The last "username" line takes preference
		 * if the string also contains domain, realm or
		 * password.
		 */
		cli_credentials_parse_string(cred, username, obtained);
	}

	for (i = 0; i < numlines; i++) {
		len = strlen(lines[i]);
		memset(lines[i], 0, len);
	}
	talloc_free(lines);

	return true;
}

/**
 * Read a named file, and parse it for a password
 *
 * @param credentials Credentials structure on which to set the password
 * @param file a named file to read the password from
 * @param obtained This enum describes how 'specified' this password is
 */

_PUBLIC_ bool cli_credentials_parse_password_file(struct cli_credentials *credentials, const char *file, enum credentials_obtained obtained)
{
	int fd = open(file, O_RDONLY, 0);
	bool ret;

	if (fd < 0) {
		fprintf(stderr, "Error opening password file %s: %s\n",
				file, strerror(errno));
		return false;
	}

	ret = cli_credentials_parse_password_fd(credentials, fd, obtained);

	close(fd);

	return ret;
}


/**
 * Read a file descriptor, and parse it for a password (eg from a file or stdin)
 *
 * @param credentials Credentials structure on which to set the password
 * @param fd open file descriptor to read the password from
 * @param obtained This enum describes how 'specified' this password is
 */

_PUBLIC_ bool cli_credentials_parse_password_fd(struct cli_credentials *credentials,
				       int fd, enum credentials_obtained obtained)
{
	char *p;
	char pass[128];

	if (credentials->password_obtained >= obtained) {
		return false;
	}

	for(p = pass, *p = '\0'; /* ensure that pass is null-terminated */
		p && p - pass < sizeof(pass) - 1;) {
		switch (read(fd, p, 1)) {
		case 1:
			if (*p != '\n' && *p != '\0') {
				*++p = '\0'; /* advance p, and null-terminate pass */
				break;
			}

			FALL_THROUGH;
		case 0:
			if (p - pass) {
				*p = '\0'; /* null-terminate it, just in case... */
				p = NULL; /* then force the loop condition to become false */
				break;
			}

			fprintf(stderr,
				"Error reading password from file descriptor "
				"%d: empty password\n",
				fd);
			return false;

		default:
			fprintf(stderr, "Error reading password from file descriptor %d: %s\n",
					fd, strerror(errno));
			return false;
		}
	}

	cli_credentials_set_password(credentials, pass, obtained);
	return true;
}

/**
 * @brief Set the SMB signing state to request for a SMB connection.
 *
 * @param[in]  creds          The credentials structure to update.
 *
 * @param[in]  signing_state  The signing state to set.
 *
 * @param obtained            This way the described signing state was specified.
 *
 * @return true if we could set the signing state, false otherwise.
 */
_PUBLIC_ bool cli_credentials_set_smb_signing(struct cli_credentials *creds,
					      enum smb_signing_setting signing_state,
					      enum credentials_obtained obtained)
{
	if (obtained >= creds->signing_state_obtained) {
		creds->signing_state_obtained = obtained;
		creds->signing_state = signing_state;
		return true;
	}

	return false;
}

/**
 * @brief Obtain the SMB signing state from a credentials structure.
 *
 * @param[in]  creds  The credential structure to obtain the SMB signing state
 *                    from.
 *
 * @return The SMB signing state.
 */
_PUBLIC_ enum smb_signing_setting
cli_credentials_get_smb_signing(struct cli_credentials *creds)
{
	return creds->signing_state;
}

/**
 * @brief Set the SMB IPC signing state to request for a SMB connection.
 *
 * @param[in]  creds          The credentials structure to update.
 *
 * @param[in]  signing_state  The signing state to set.
 *
 * @param obtained            This way the described signing state was specified.
 *
 * @return true if we could set the signing state, false otherwise.
 */
_PUBLIC_ bool
cli_credentials_set_smb_ipc_signing(struct cli_credentials *creds,
				    enum smb_signing_setting ipc_signing_state,
				    enum credentials_obtained obtained)
{
	if (obtained >= creds->ipc_signing_state_obtained) {
		creds->ipc_signing_state_obtained = obtained;
		creds->ipc_signing_state = ipc_signing_state;
		return true;
	}

	return false;
}

/**
 * @brief Obtain the SMB IPC signing state from a credentials structure.
 *
 * @param[in]  creds  The credential structure to obtain the SMB IPC signing
 *                    state from.
 *
 * @return The SMB signing state.
 */
_PUBLIC_ enum smb_signing_setting
cli_credentials_get_smb_ipc_signing(struct cli_credentials *creds)
{
	return creds->ipc_signing_state;
}

/**
 * @brief Set the SMB encryption state to request for a SMB connection.
 *
 * @param[in]  creds  The credentials structure to update.
 *
 * @param[in]  encryption_state  The encryption state to set.
 *
 * @param obtained  This way the described encryption state was specified.
 *
 * @return true if we could set the encryption state, false otherwise.
 */
_PUBLIC_ bool cli_credentials_set_smb_encryption(struct cli_credentials *creds,
						 enum smb_encryption_setting encryption_state,
						 enum credentials_obtained obtained)
{
	if (obtained >= creds->encryption_state_obtained) {
		creds->encryption_state_obtained = obtained;
		creds->encryption_state = encryption_state;
		return true;
	}

	return false;
}

static const char *obtained_to_str(enum credentials_obtained obtained)
{
	switch (obtained) {
	case CRED_UNINITIALISED:
		return "CRED_UNINITIALISED";
	case CRED_SMB_CONF:
		return "CRED_SMB_CONF";
	case CRED_CALLBACK:
		return "CRED_CALLBACK";
	case CRED_GUESS_ENV:
		return "CRED_GUESS_ENV";
	case CRED_GUESS_FILE:
		return "CRED_GUESS_FILE";
	case CRED_CALLBACK_RESULT:
		return "CRED_CALLBACK_RESULT";
	case CRED_SPECIFIED:
		return "CRED_SPECIFIED";
	}

	/* Never reached */
	return "";
}

static const char *krb5_state_to_str(enum credentials_use_kerberos krb5_state)
{
	switch (krb5_state) {
	case CRED_USE_KERBEROS_DISABLED:
		return "CRED_USE_KERBEROS_DISABLED";
	case CRED_USE_KERBEROS_DESIRED:
		return "CRED_USE_KERBEROS_DESIRED";
	case CRED_USE_KERBEROS_REQUIRED:
		return "CRED_USE_KERBEROS_REQUIRED";
	}

	/* Never reached */
	return "";
}

static const char *krb5_fwd_to_str(enum credentials_krb_forwardable krb5_fwd)
{
	switch (krb5_fwd) {
	case CRED_AUTO_KRB_FORWARDABLE:
		return "CRED_AUTO_KRB_FORWARDABLE";
	case CRED_NO_KRB_FORWARDABLE:
		return "CRED_NO_KRB_FORWARDABLE";
	case CRED_FORCE_KRB_FORWARDABLE:
		return "CRED_FORCE_KRB_FORWARDABLE";
	}

	/* Never reached */
	return "";
}

static const char *signing_state_to_str(enum smb_signing_setting signing_state)
{
	switch(signing_state) {
	case SMB_SIGNING_IPC_DEFAULT:
		return "SMB_SIGNING_IPC_DEFAULT";
	case SMB_SIGNING_DEFAULT:
		return "SMB_SIGNING_DEFAULT";
	case SMB_SIGNING_OFF:
		return "SMB_SIGNING_OFF";
	case SMB_SIGNING_IF_REQUIRED:
		return "SMB_SIGNING_IF_REQUIRED";
	case SMB_SIGNING_DESIRED:
		return "SMB_SIGNING_DESIRED";
	case SMB_SIGNING_REQUIRED:
		return "SMB_SIGNING_REQUIRED";
	}

	/* Never reached */
	return "";
}

static const char *encryption_state_to_str(enum smb_encryption_setting encryption_state)
{
	switch(encryption_state) {
	case SMB_ENCRYPTION_DEFAULT:
		return "SMB_ENCRYPTION_DEFAULT";
	case SMB_ENCRYPTION_OFF:
		return "SMB_ENCRYPTION_OFF";
	case SMB_ENCRYPTION_IF_REQUIRED:
		return "SMB_ENCRYPTION_IF_REQUIRED";
	case SMB_ENCRYPTION_DESIRED:
		return "SMB_ENCRYPTION_DESIRED";
	case SMB_ENCRYPTION_REQUIRED:
		return "SMB_ENCRYPTION_REQUIRED";
	}

	/* Never reached */
	return "";
}

_PUBLIC_ void cli_credentials_dump(struct cli_credentials *creds)
{
	DBG_ERR("CLI_CREDENTIALS:\n");
	DBG_ERR("\n");
	DBG_ERR("  Username: %s - %s\n",
		creds->username,
		obtained_to_str(creds->username_obtained));
	DBG_ERR("  Workstation: %s - %s\n",
		creds->workstation,
		obtained_to_str(creds->workstation_obtained));
	DBG_ERR("  Domain: %s - %s\n",
		creds->domain,
		obtained_to_str(creds->domain_obtained));
	DBG_ERR("  Password: %s - %s\n",
		creds->password != NULL ? "*SECRET*" : "NULL",
		obtained_to_str(creds->password_obtained));
	DBG_ERR("  Old password: %s\n",
		creds->old_password != NULL ? "*SECRET*" : "NULL");
	DBG_ERR("  Password tries: %u\n",
		creds->password_tries);
	DBG_ERR("  Realm: %s - %s\n",
		creds->realm,
		obtained_to_str(creds->realm_obtained));
	DBG_ERR("  Principal: %s - %s\n",
		creds->principal,
		obtained_to_str(creds->principal_obtained));
	DBG_ERR("  Salt principal: %s\n",
		creds->salt_principal);
	DBG_ERR("  Impersonate principal: %s\n",
		creds->impersonate_principal);
	DBG_ERR("  Self service: %s\n",
		creds->self_service);
	DBG_ERR("  Target service: %s\n",
		creds->target_service);
	DBG_ERR("  Kerberos state: %s - %s\n",
		krb5_state_to_str(creds->kerberos_state),
		obtained_to_str(creds->kerberos_state_obtained));
	DBG_ERR("  Kerberos forwardable ticket: %s\n",
		krb5_fwd_to_str(creds->krb_forwardable));
	DBG_ERR("  Signing state: %s - %s\n",
		signing_state_to_str(creds->signing_state),
		obtained_to_str(creds->signing_state_obtained));
	DBG_ERR("  IPC signing state: %s - %s\n",
		signing_state_to_str(creds->ipc_signing_state),
		obtained_to_str(creds->ipc_signing_state_obtained));
	DBG_ERR("  Encryption state: %s - %s\n",
		encryption_state_to_str(creds->encryption_state),
		obtained_to_str(creds->encryption_state_obtained));
	DBG_ERR("  Gensec features: %#X\n",
		creds->gensec_features);
	DBG_ERR("  Forced sasl mech: %s\n",
		creds->forced_sasl_mech);
	DBG_ERR("  CCACHE: %p - %s\n",
		creds->ccache,
		obtained_to_str(creds->ccache_obtained));
	DBG_ERR("  CLIENT_GSS_CREDS: %p - %s\n",
		creds->client_gss_creds,
		obtained_to_str(creds->client_gss_creds_obtained));
	DBG_ERR("  SERVER_GSS_CREDS: %p - %s\n",
		creds->server_gss_creds,
		obtained_to_str(creds->server_gss_creds_obtained));
	DBG_ERR("  KEYTAB: %p - %s\n",
		creds->keytab,
		obtained_to_str(creds->keytab_obtained));
	DBG_ERR("  KVNO: %u\n",
		creds->kvno);
	DBG_ERR("\n");
}

/**
 * @brief Obtain the SMB encryption state from a credentials structure.
 *
 * @param[in]  creds  The credential structure to obtain the SMB encryption state
 *                    from.
 *
 * @return The SMB signing state.
 */
_PUBLIC_ enum smb_encryption_setting
cli_credentials_get_smb_encryption(struct cli_credentials *creds)
{
	return creds->encryption_state;
}
