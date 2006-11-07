/* 
   Unix SMB/CIFS implementation.

   User credentials handling

   Copyright (C) Jelmer Vernooij 2005
   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "librpc/gen_ndr/samr.h" /* for struct samrPassword */
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "libcli/auth/libcli_auth.h"

/**
 * Create a new credentials structure
 * @param mem_ctx TALLOC_CTX parent for credentials structure 
 */
struct cli_credentials *cli_credentials_init(TALLOC_CTX *mem_ctx) 
{
	struct cli_credentials *cred = talloc(mem_ctx, struct cli_credentials);
	if (!cred) {
		return cred;
	}

	cred->netlogon_creds = NULL;
	cred->machine_account_pending = False;
	cred->workstation_obtained = CRED_UNINITIALISED;
	cred->username_obtained = CRED_UNINITIALISED;
	cred->password_obtained = CRED_UNINITIALISED;
	cred->domain_obtained = CRED_UNINITIALISED;
	cred->realm_obtained = CRED_UNINITIALISED;
	cred->ccache_obtained = CRED_UNINITIALISED;
	cred->client_gss_creds_obtained = CRED_UNINITIALISED;
	cred->server_gss_creds_obtained = CRED_UNINITIALISED;
	cred->keytab_obtained = CRED_UNINITIALISED;
	cred->principal_obtained = CRED_UNINITIALISED;

	cred->old_password = NULL;
	cred->smb_krb5_context = NULL;
	cred->salt_principal = NULL;
	cred->machine_account = False;

	cred->bind_dn = NULL;

	cred->tries = 3;
	cred->callback_running = False;

	cli_credentials_set_kerberos_state(cred, CRED_AUTO_USE_KERBEROS);

	return cred;
}

void cli_credentials_set_kerberos_state(struct cli_credentials *creds, 
					enum credentials_use_kerberos use_kerberos)
{
	creds->use_kerberos = use_kerberos;
}

enum credentials_use_kerberos cli_credentials_get_kerberos_state(struct cli_credentials *creds)
{
	return creds->use_kerberos;
}


/**
 * Obtain the username for this credentials context.
 * @param cred credentials context
 * @retval The username set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
const char *cli_credentials_get_username(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred);
	}

	if (cred->username_obtained == CRED_CALLBACK && 
	    !cred->callback_running) {
	    	cred->callback_running = True;
		cred->username = cred->username_cb(cred);
	    	cred->callback_running = False;
		cred->username_obtained = CRED_SPECIFIED;
	}

	return cred->username;
}

BOOL cli_credentials_set_username(struct cli_credentials *cred, 
				  const char *val, enum credentials_obtained obtained)
{
	if (obtained >= cred->username_obtained) {
		cred->username = talloc_strdup(cred, val);
		cred->username_obtained = obtained;
		return True;
	}

	return False;
}

BOOL cli_credentials_set_username_callback(struct cli_credentials *cred,
				  const char *(*username_cb) (struct cli_credentials *))
{
	if (cred->username_obtained < CRED_CALLBACK) {
		cred->username_cb = username_cb;
		cred->username_obtained = CRED_CALLBACK;
		return True;
	}

	return False;
}

BOOL cli_credentials_set_bind_dn(struct cli_credentials *cred, 
				 const char *bind_dn)
{
	cred->bind_dn = talloc_strdup(cred, bind_dn);
	return True;
}

/**
 * Obtain the BIND DN for this credentials context.
 * @param cred credentials context
 * @retval The username set on this context.
 * @note Return value will be NULL if not specified explictly
 */
const char *cli_credentials_get_bind_dn(struct cli_credentials *cred)
{
	return cred->bind_dn;
}


/**
 * Obtain the client principal for this credentials context.
 * @param cred credentials context
 * @retval The username set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
const char *cli_credentials_get_principal(struct cli_credentials *cred, TALLOC_CTX *mem_ctx)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred);
	}

	if (cred->principal_obtained == CRED_CALLBACK && 
	    !cred->callback_running) {
	    	cred->callback_running = True;
		cred->principal = cred->principal_cb(cred);
	    	cred->callback_running = False;
		cred->principal_obtained = CRED_SPECIFIED;
	}

	if (cred->principal_obtained < cred->username_obtained) {
		if (cred->domain_obtained > cred->realm_obtained) {
			return talloc_asprintf(mem_ctx, "%s@%s", 
					       cli_credentials_get_username(cred),
					       cli_credentials_get_domain(cred));
		} else {
			return talloc_asprintf(mem_ctx, "%s@%s", 
					       cli_credentials_get_username(cred),
					       cli_credentials_get_realm(cred));
		}
	}
	return talloc_reference(mem_ctx, cred->principal);
}

BOOL cli_credentials_set_principal(struct cli_credentials *cred, 
				   const char *val, 
				   enum credentials_obtained obtained)
{
	if (obtained >= cred->principal_obtained) {
		cred->principal = talloc_strdup(cred, val);
		cred->principal_obtained = obtained;
		return True;
	}

	return False;
}

/* Set a callback to get the principal.  This could be a popup dialog,
 * a terminal prompt or similar.  */

BOOL cli_credentials_set_principal_callback(struct cli_credentials *cred,
				  const char *(*principal_cb) (struct cli_credentials *))
{
	if (cred->principal_obtained < CRED_CALLBACK) {
		cred->principal_cb = principal_cb;
		cred->principal_obtained = CRED_CALLBACK;
		return True;
	}

	return False;
}

/* Some of our tools are 'anonymous by default'.  This is a single
 * function to determine if authentication has been explicitly
 * requested */

BOOL cli_credentials_authentication_requested(struct cli_credentials *cred) 
{
	if (cred->bind_dn) {
		return True;
	}

	if (cli_credentials_is_anonymous(cred)){
		return False;
	}

	if (cred->principal_obtained >= CRED_SPECIFIED) {
		return True;
	}
	if (cred->username_obtained >= CRED_SPECIFIED) {
		return True;
	}
	return False;
}

/**
 * Obtain the password for this credentials context.
 * @param cred credentials context
 * @retval If set, the cleartext password, otherwise NULL
 */
const char *cli_credentials_get_password(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred);
	}

	if (cred->password_obtained == CRED_CALLBACK && 
	    !cred->callback_running) {
	    	cred->callback_running = True;
		cred->password = cred->password_cb(cred);
	    	cred->callback_running = False;
		cred->password_obtained = CRED_CALLBACK_RESULT;
	}

	return cred->password;
}

/* Set a password on the credentials context, including an indication
 * of 'how' the password was obtained */

BOOL cli_credentials_set_password(struct cli_credentials *cred, 
				  const char *val, 
				  enum credentials_obtained obtained)
{
	if (obtained >= cred->password_obtained) {
		cred->password = talloc_strdup(cred, val);
		cred->password_obtained = obtained;

		cred->nt_hash = NULL;
		return True;
	}

	return False;
}

BOOL cli_credentials_set_password_callback(struct cli_credentials *cred,
					   const char *(*password_cb) (struct cli_credentials *))
{
	if (cred->password_obtained < CRED_CALLBACK) {
		cred->password_cb = password_cb;
		cred->password_obtained = CRED_CALLBACK;
		return True;
	}

	return False;
}

/**
 * Obtain the 'old' password for this credentials context (used for join accounts).
 * @param cred credentials context
 * @retval If set, the cleartext password, otherwise NULL
 */
const char *cli_credentials_get_old_password(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred);
	}

	return cred->old_password;
}

BOOL cli_credentials_set_old_password(struct cli_credentials *cred, 
				      const char *val, 
				      enum credentials_obtained obtained)
{
	cred->old_password = talloc_strdup(cred, val);
	return True;
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
const struct samr_Password *cli_credentials_get_nt_hash(struct cli_credentials *cred, 
							TALLOC_CTX *mem_ctx)
{
	const char *password = cli_credentials_get_password(cred);

	if (password) {
		struct samr_Password *nt_hash = talloc(mem_ctx, struct samr_Password);
		if (!nt_hash) {
			return NULL;
		}
		
		E_md4hash(password, nt_hash->hash);    

		return nt_hash;
	} else {
		return cred->nt_hash;
	}
}

BOOL cli_credentials_set_nt_hash(struct cli_credentials *cred,
				 const struct samr_Password *nt_hash, 
				 enum credentials_obtained obtained)
{
	if (obtained >= cred->password_obtained) {
		cli_credentials_set_password(cred, NULL, obtained);
		cred->nt_hash = talloc(cred, struct samr_Password);
		*cred->nt_hash = *nt_hash;
		return True;
	}

	return False;
}

/**
 * Obtain the 'short' or 'NetBIOS' domain for this credentials context.
 * @param cred credentials context
 * @retval The domain set on this context. 
 * @note Return value will never be NULL except by programmer error.
 */
const char *cli_credentials_get_domain(struct cli_credentials *cred)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred);
	}

	if (cred->domain_obtained == CRED_CALLBACK && 
	    !cred->callback_running) {
	    	cred->callback_running = True;
		cred->domain = cred->domain_cb(cred);
	    	cred->callback_running = False;
		cred->domain_obtained = CRED_SPECIFIED;
	}

	return cred->domain;
}


BOOL cli_credentials_set_domain(struct cli_credentials *cred, 
				const char *val, 
				enum credentials_obtained obtained)
{
	if (obtained >= cred->domain_obtained) {
		/* it is important that the domain be in upper case,
		 * particularly for the sensitive NTLMv2
		 * calculations */
		cred->domain = strupper_talloc(cred, val);
		cred->domain_obtained = obtained;
		return True;
	}

	return False;
}

BOOL cli_credentials_set_domain_callback(struct cli_credentials *cred,
					 const char *(*domain_cb) (struct cli_credentials *))
{
	if (cred->domain_obtained < CRED_CALLBACK) {
		cred->domain_cb = domain_cb;
		cred->domain_obtained = CRED_CALLBACK;
		return True;
	}

	return False;
}

/**
 * Obtain the Kerberos realm for this credentials context.
 * @param cred credentials context
 * @retval The realm set on this context. 
 * @note Return value will never be NULL except by programmer error.
 */
const char *cli_credentials_get_realm(struct cli_credentials *cred)
{	
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred);
	}

	if (cred->realm_obtained == CRED_CALLBACK && 
	    !cred->callback_running) {
	    	cred->callback_running = True;
		cred->realm = cred->realm_cb(cred);
	    	cred->callback_running = False;
		cred->realm_obtained = CRED_SPECIFIED;
	}

	return cred->realm;
}

/**
 * Set the realm for this credentials context, and force it to
 * uppercase for the sainity of our local kerberos libraries 
 */
BOOL cli_credentials_set_realm(struct cli_credentials *cred, 
			       const char *val, 
			       enum credentials_obtained obtained)
{
	if (obtained >= cred->realm_obtained) {
		cred->realm = strupper_talloc(cred, val);
		cred->realm_obtained = obtained;
		return True;
	}

	return False;
}

BOOL cli_credentials_set_realm_callback(struct cli_credentials *cred,
					const char *(*realm_cb) (struct cli_credentials *))
{
	if (cred->realm_obtained < CRED_CALLBACK) {
		cred->realm_cb = realm_cb;
		cred->realm_obtained = CRED_CALLBACK;
		return True;
	}

	return False;
}

/**
 * Obtain the 'short' or 'NetBIOS' workstation name for this credentials context.
 *
 * @param cred credentials context
 * @retval The workstation name set on this context. 
 * @note Return value will never be NULL except by programmer error.
 */
const char *cli_credentials_get_workstation(struct cli_credentials *cred)
{
	if (cred->workstation_obtained == CRED_CALLBACK && 
	    !cred->callback_running) {
	    	cred->callback_running = True;
		cred->workstation = cred->workstation_cb(cred);
	    	cred->callback_running = False;
		cred->workstation_obtained = CRED_SPECIFIED;
	}

	return cred->workstation;
}

BOOL cli_credentials_set_workstation(struct cli_credentials *cred, 
				     const char *val, 
				     enum credentials_obtained obtained)
{
	if (obtained >= cred->workstation_obtained) {
		cred->workstation = talloc_strdup(cred, val);
		cred->workstation_obtained = obtained;
		return True;
	}

	return False;
}

BOOL cli_credentials_set_workstation_callback(struct cli_credentials *cred,
					      const char *(*workstation_cb) (struct cli_credentials *))
{
	if (cred->workstation_obtained < CRED_CALLBACK) {
		cred->workstation_cb = workstation_cb;
		cred->workstation_obtained = CRED_CALLBACK;
		return True;
	}

	return False;
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

void cli_credentials_parse_string(struct cli_credentials *credentials, const char *data, enum credentials_obtained obtained)
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
		cli_credentials_set_principal(credentials, uname, obtained);
		*p = 0;
		cli_credentials_set_realm(credentials, p+1, obtained);
		return;
	} else if ((p = strchr_m(uname,'\\')) || (p = strchr_m(uname, '/'))) {
		*p = 0;
		cli_credentials_set_domain(credentials, uname, obtained);
		uname = p+1;
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

const char *cli_credentials_get_unparsed_name(struct cli_credentials *credentials, TALLOC_CTX *mem_ctx)
{
	const char *bind_dn = cli_credentials_get_bind_dn(credentials);
	const char *domain;
	const char *username;
	const char *name;

	if (bind_dn) {
		name = talloc_reference(mem_ctx, bind_dn);
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
void cli_credentials_set_conf(struct cli_credentials *cred)
{
	cli_credentials_set_username(cred, "", CRED_UNINITIALISED);
	cli_credentials_set_domain(cred, lp_workgroup(), CRED_UNINITIALISED);
	cli_credentials_set_workstation(cred, lp_netbios_name(), CRED_UNINITIALISED);
	cli_credentials_set_realm(cred, lp_realm(), CRED_UNINITIALISED);
}

/**
 * Guess defaults for credentials from environment variables, 
 * and from the configuration file
 * 
 * @param cred Credentials structure to fill in
 */
void cli_credentials_guess(struct cli_credentials *cred)
{
	char *p;

	cli_credentials_set_conf(cred);
	
	if (getenv("LOGNAME")) {
		cli_credentials_set_username(cred, getenv("LOGNAME"), CRED_GUESS_ENV);
	}

	if (getenv("USER")) {
		cli_credentials_parse_string(cred, getenv("USER"), CRED_GUESS_ENV);
		if ((p = strchr_m(getenv("USER"),'%'))) {
			memset(p,0,strlen(cred->password));
		}
	}

	if (getenv("DOMAIN")) {
		cli_credentials_set_domain(cred, getenv("DOMAIN"), CRED_GUESS_ENV);
	}

	if (getenv("PASSWD")) {
		cli_credentials_set_password(cred, getenv("PASSWD"), CRED_GUESS_ENV);
	}

	if (getenv("PASSWD_FD")) {
		cli_credentials_parse_password_fd(cred, atoi(getenv("PASSWD_FD")), CRED_GUESS_FILE);
	}
	
	if (getenv("PASSWD_FILE")) {
		cli_credentials_parse_password_file(cred, getenv("PASSWD_FILE"), CRED_GUESS_FILE);
	}
	
	if (cli_credentials_get_kerberos_state(cred) != CRED_DONT_USE_KERBEROS) {
		cli_credentials_set_ccache(cred, NULL, CRED_GUESS_FILE);
	}
}

/**
 * Attach NETLOGON credentials for use with SCHANNEL
 */

void cli_credentials_set_netlogon_creds(struct cli_credentials *cred, 
					struct creds_CredentialState *netlogon_creds)
{
	cred->netlogon_creds = talloc_reference(cred, netlogon_creds);
}

/**
 * Return attached NETLOGON credentials 
 */

struct creds_CredentialState *cli_credentials_get_netlogon_creds(struct cli_credentials *cred)
{
	return cred->netlogon_creds;
}

/** 
 * Set NETLOGON secure channel type
 */

void cli_credentials_set_secure_channel_type(struct cli_credentials *cred,
					     enum netr_SchannelType secure_channel_type)
{
	cred->secure_channel_type = secure_channel_type;
}

/**
 * Return NETLOGON secure chanel type
 */

enum netr_SchannelType cli_credentials_get_secure_channel_type(struct cli_credentials *cred)
{
	return cred->secure_channel_type;
}

/**
 * Fill in a credentials structure as the anonymous user
 */
void cli_credentials_set_anonymous(struct cli_credentials *cred) 
{
	cli_credentials_set_username(cred, "", CRED_SPECIFIED);
	cli_credentials_set_domain(cred, "", CRED_SPECIFIED);
	cli_credentials_set_password(cred, NULL, CRED_SPECIFIED);
}

/**
 * Describe a credentials context as anonymous or authenticated
 * @retval True if anonymous, False if a username is specified
 */

BOOL cli_credentials_is_anonymous(struct cli_credentials *cred)
{
	const char *username;
	
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred);
	}

	username = cli_credentials_get_username(cred);
	
	/* Yes, it is deliberate that we die if we have a NULL pointer
	 * here - anonymous is "", not NULL, which is 'never specified,
	 * never guessed', ie programmer bug */
	if (!username[0]) {
		return True;
	}

	return False;
}

/**
 * Mark the current password for a credentials struct as wrong. This will 
 * cause the password to be prompted again (if a callback is set).
 *
 * This will decrement the number of times the password can be tried.
 *
 * @retval whether the credentials struct is finished
 */
BOOL cli_credentials_wrong_password(struct cli_credentials *cred)
{
	if (cred->password_obtained != CRED_CALLBACK_RESULT) {
		return False;
	}
	
	cred->password_obtained = CRED_CALLBACK;

	cred->tries--;

	return (cred->tries > 0);
}
