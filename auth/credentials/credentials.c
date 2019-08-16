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
#include "librpc/gen_ndr/samr.h" /* for struct samrPassword */
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include "auth/gensec/gensec.h"
#include "libcli/auth/libcli_auth.h"
#include "tevent.h"
#include "param/param.h"
#include "system/filesys.h"

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

	return cred;
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

_PUBLIC_ void cli_credentials_set_kerberos_state(struct cli_credentials *creds, 
					enum credentials_use_kerberos use_kerberos)
{
	creds->use_kerberos = use_kerberos;
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
	return creds->use_kerberos;
}

_PUBLIC_ const char *cli_credentials_get_forced_sasl_mech(struct cli_credentials *creds)
{
	return creds->forced_sasl_mech;
}

_PUBLIC_ enum credentials_krb_forwardable cli_credentials_get_krb_forwardable(struct cli_credentials *creds)
{
	return creds->krb_forwardable;
}

_PUBLIC_ void cli_credentials_set_gensec_features(struct cli_credentials *creds, uint32_t gensec_features)
{
	creds->gensec_features = gensec_features;
}

_PUBLIC_ uint32_t cli_credentials_get_gensec_features(struct cli_credentials *creds)
{
	return creds->gensec_features;
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
 * @note Return value will be NULL if not specified explictly
 */
_PUBLIC_ const char *cli_credentials_get_bind_dn(struct cli_credentials *cred)
{
	return cred->bind_dn;
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
	    	cred->callback_running = true;
		cred->principal = cred->principal_cb(cred);
	    	cred->callback_running = false;
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
		cred->principal = talloc_strdup(cred, val);
		if (cred->principal == NULL) {
			return false;
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

	if (cli_credentials_get_kerberos_state(cred) == CRED_MUST_USE_KERBEROS) {
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

		*nt_hash = *cred->old_nt_hash;

		return nt_hash;
	}

	old_password = cli_credentials_get_old_password(cred);
	if (old_password) {
		struct samr_Password *nt_hash = talloc(mem_ctx, struct samr_Password);
		if (!nt_hash) {
			return NULL;
		}

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
	    	cred->callback_running = true;
		cred->realm = cred->realm_cb(cred);
	    	cred->callback_running = false;
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
		cred->realm = strupper_talloc(cred, val);
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

	if (strcmp("%",data) == 0) {
		cli_credentials_set_anonymous(credentials);
		return;
	}

	uname = talloc_strdup(credentials, data); 
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
 */
_PUBLIC_ void cli_credentials_set_conf(struct cli_credentials *cred, 
			      struct loadparm_context *lp_ctx)
{
	const char *sep = NULL;
	const char *realm = lpcfg_realm(lp_ctx);

	cli_credentials_set_username(cred, "", CRED_UNINITIALISED);
	if (lpcfg_parm_is_cmdline(lp_ctx, "workgroup")) {
		cli_credentials_set_domain(cred, lpcfg_workgroup(lp_ctx), CRED_SPECIFIED);
	} else {
		cli_credentials_set_domain(cred, lpcfg_workgroup(lp_ctx), CRED_UNINITIALISED);
	}
	if (lpcfg_parm_is_cmdline(lp_ctx, "netbios name")) {
		cli_credentials_set_workstation(cred, lpcfg_netbios_name(lp_ctx), CRED_SPECIFIED);
	} else {
		cli_credentials_set_workstation(cred, lpcfg_netbios_name(lp_ctx), CRED_UNINITIALISED);
	}
	if (realm != NULL && strlen(realm) == 0) {
		realm = NULL;
	}
	if (lpcfg_parm_is_cmdline(lp_ctx, "realm")) {
		cli_credentials_set_realm(cred, realm, CRED_SPECIFIED);
	} else {
		cli_credentials_set_realm(cred, realm, CRED_UNINITIALISED);
	}

	sep = lpcfg_winbind_separator(lp_ctx);
	if (sep != NULL && sep[0] != '\0') {
		cred->winbind_separator = *lpcfg_winbind_separator(lp_ctx);
	}
}

/**
 * Guess defaults for credentials from environment variables, 
 * and from the configuration file
 * 
 * @param cred Credentials structure to fill in
 */
_PUBLIC_ void cli_credentials_guess(struct cli_credentials *cred,
			   struct loadparm_context *lp_ctx)
{
	char *p;
	const char *error_string;

	if (lp_ctx != NULL) {
		cli_credentials_set_conf(cred, lp_ctx);
	}
	
	if (getenv("LOGNAME")) {
		cli_credentials_set_username(cred, getenv("LOGNAME"), CRED_GUESS_ENV);
	}

	if (getenv("USER")) {
		cli_credentials_parse_string(cred, getenv("USER"), CRED_GUESS_ENV);
		if ((p = strchr_m(getenv("USER"),'%'))) {
			memset(p,0,strlen(cred->password));
		}
	}

	if (getenv("PASSWD")) {
		cli_credentials_set_password(cred, getenv("PASSWD"), CRED_GUESS_ENV);
	}

	if (getenv("PASSWD_FD")) {
		cli_credentials_parse_password_fd(cred, atoi(getenv("PASSWD_FD")), 
						  CRED_GUESS_FILE);
	}
	
	p = getenv("PASSWD_FILE");
	if (p && p[0]) {
		cli_credentials_parse_password_file(cred, p, CRED_GUESS_FILE);
	}
	
	if (lp_ctx != NULL &&
	    cli_credentials_get_kerberos_state(cred) != CRED_DONT_USE_KERBEROS) {
		cli_credentials_set_ccache(cred, lp_ctx, NULL, CRED_GUESS_FILE,
					   &error_string);
	}
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
 * Return NETLOGON secure chanel type
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
 * Return NETLOGON secure chanel type
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
	cli_credentials_set_kerberos_state(cred, CRED_DONT_USE_KERBEROS);
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
	if (cred->principal_obtained >= cred->username_obtained) {
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

	for(p = pass, *p = '\0'; /* ensure that pass is null-terminated */
		p && p - pass < sizeof(pass);) {
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
 * Encrypt a data blob using the session key and the negotiated encryption
 * algorithm
 *
 * @param state Credential state, contains the session key and algorithm
 * @param data Data blob containing the data to be encrypted.
 *
 */
_PUBLIC_ NTSTATUS netlogon_creds_session_encrypt(
	struct netlogon_creds_CredentialState *state,
	DATA_BLOB data)
{
	NTSTATUS status;

	if (data.data == NULL || data.length == 0) {
		DBG_ERR("Nothing to encrypt "
			"data.data == NULL or data.length == 0");
		return NT_STATUS_INVALID_PARAMETER;
	}
	/*
	 * Don't crypt an all-zero password it will give away the
	 * NETLOGON pipe session key .
	 */
	if (all_zero(data.data, data.length)) {
		DBG_ERR("Supplied data all zeros, could leak session key");
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (state->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		status = netlogon_creds_aes_encrypt(state,
						    data.data,
						    data.length);
	} else if (state->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
		status = netlogon_creds_arcfour_crypt(state,
						      data.data,
						      data.length);
	} else {
		DBG_ERR("Unsupported encryption option negotiated");
		status = NT_STATUS_NOT_SUPPORTED;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return NT_STATUS_OK;
}

