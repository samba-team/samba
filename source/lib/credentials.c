/* 
   Unix SMB/CIFS implementation.

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
#include "system/filesys.h"
#include "include/secrets.h"
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/ndr_samr.h" /* for struct samrPassword */
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"


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
	cred->principal_obtained = CRED_UNINITIALISED;
	return cred;
}

/**
 * Obtain the username for this credentials context.
 * @param cred credentials context
 * @retval The username set on this context.
 * @note Return value will never be NULL except by programmer error.
 */
const char *cli_credentials_get_username(struct cli_credentials *cred, TALLOC_CTX *mem_ctx)
{
	if (cred->machine_account_pending) {
		cli_credentials_set_machine_account(cred);
	}

	/* If we have a principal set on this, we want to login with "" domain and user@realm */
	if (cred->username_obtained < cred->principal_obtained) {
		return cli_credentials_get_principal(cred, mem_ctx);
	}

	if (cred->username_obtained == CRED_CALLBACK) {
		cred->username = cred->username_cb(cred);
		cred->username_obtained = CRED_SPECIFIED;
	}

	return talloc_reference(mem_ctx, cred->username);
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

	if (cred->principal_obtained == CRED_CALLBACK) {
		cred->principal = cred->principal_cb(cred);
		cred->principal_obtained = CRED_SPECIFIED;
	}

	if (cred->principal_obtained < cred->username_obtained) {
		return talloc_asprintf(mem_ctx, "%s@%s", 
				       cli_credentials_get_username(cred, mem_ctx),
				       cli_credentials_get_realm(cred));
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

BOOL cli_credentials_authentication_requested(struct cli_credentials *cred) 
{
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

	if (cred->password_obtained == CRED_CALLBACK) {
		cred->password = cred->password_cb(cred);
		cred->password_obtained = CRED_SPECIFIED;
	}

	return cred->password;
}

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
 * Obtain the password for this credentials context.
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

int cli_credentials_set_from_ccache(struct cli_credentials *cred, 
				    enum credentials_obtained obtained)
{
	
	krb5_principal princ;
	krb5_error_code ret;
	char *name;
	char **realm;

	ret = krb5_cc_get_principal(cred->ccache->smb_krb5_context->krb5_context, 
				    cred->ccache->ccache, &princ);

	if (ret) {
		char *err_mess = smb_get_krb5_error_message(cred->ccache->smb_krb5_context->krb5_context, ret, cred);
		DEBUG(1,("failed to get principal from ccache: %s\n", 
			 err_mess));
		talloc_free(err_mess);
		return ret;
	}
	
	ret = krb5_unparse_name(cred->ccache->smb_krb5_context->krb5_context, princ, &name);
	if (ret) {
		char *err_mess = smb_get_krb5_error_message(cred->ccache->smb_krb5_context->krb5_context, ret, cred);
		DEBUG(1,("failed to unparse principal from ccache: %s\n", 
			 err_mess));
		talloc_free(err_mess);
		return ret;
	}

	realm = krb5_princ_realm(cred->ccache->smb_krb5_context->krb5_context, princ);

	cli_credentials_set_realm(cred, *realm, obtained);
	cli_credentials_set_principal(cred, name, obtained);

	free(name);

	krb5_free_principal(cred->ccache->smb_krb5_context->krb5_context, princ);

	cred->ccache_obtained = obtained;

	return 0;
}


static int free_mccache(void *ptr) {
	struct ccache_container *ccc = ptr;
	krb5_cc_destroy(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

static int free_dccache(void *ptr) {
	struct ccache_container *ccc = ptr;
	krb5_cc_close(ccc->smb_krb5_context->krb5_context, ccc->ccache);

	return 0;
}

static int cli_credentials_set_ccache(struct cli_credentials *cred, 
				      const char *name, 
				      enum credentials_obtained obtained)
{
	krb5_error_code ret;
	krb5_principal princ;
	struct ccache_container *ccc = talloc(cred, struct ccache_container);
	if (!ccc) {
		return ENOMEM;
	}

	ret = smb_krb5_init_context(ccc, &ccc->smb_krb5_context);
	if (ret) {
		talloc_free(ccc);
		return ret;
	}
	if (name) {
		ret = krb5_cc_resolve(ccc->smb_krb5_context->krb5_context, name, &ccc->ccache);
		if (ret) {
			DEBUG(1,("failed to read krb5 ccache: %s: %s\n", 
				 name, 
				 smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context, ret, ccc)));
			talloc_free(ccc);
			return ret;
		}
	} else {
		ret = krb5_cc_default(ccc->smb_krb5_context->krb5_context, &ccc->ccache);
		if (ret) {
			DEBUG(3,("failed to read default krb5 ccache: %s\n", 
				 smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context, ret, ccc)));
			talloc_free(ccc);
			return ret;
		}
	}

	talloc_set_destructor(ccc, free_dccache);

	ret = krb5_cc_get_principal(ccc->smb_krb5_context->krb5_context, ccc->ccache, &princ);

	if (ret) {
		DEBUG(3,("failed to get principal from default ccache: %s\n", 
			 smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context, ret, ccc)));
		talloc_free(ccc);		
		return ret;
	}

	krb5_free_principal(ccc->smb_krb5_context->krb5_context, princ);

	cred->ccache = ccc;
	talloc_steal(cred, ccc);

	ret = cli_credentials_set_from_ccache(cred, obtained);

	if (ret) {
		return ret;
	}

	return 0;
}


int cli_credentials_new_ccache(struct cli_credentials *cred)
{
	krb5_error_code ret;
	char *rand_string;
	struct ccache_container *ccc = talloc(cred, struct ccache_container);
	char *ccache_name;
	if (!ccc) {
		return ENOMEM;
	}

	rand_string = generate_random_str(NULL, 16);
	if (!rand_string) {
		talloc_free(ccc);
		return ENOMEM;
	}

	ccache_name = talloc_asprintf(ccc, "MEMORY:%s", 
			      rand_string);
	talloc_free(rand_string);

	if (!ccache_name) {
		talloc_free(ccc);
		return ENOMEM;
	}

	ret = smb_krb5_init_context(ccc, &ccc->smb_krb5_context);
	if (ret) {
		talloc_free(ccache_name);
		talloc_free(ccc);
		return ret;
	}

	ret = krb5_cc_resolve(ccc->smb_krb5_context->krb5_context, ccache_name, &ccc->ccache);
	if (ret) {
		DEBUG(1,("failed to generate a new krb5 ccache (%s): %s\n", 
			 ccache_name,
			 smb_get_krb5_error_message(ccc->smb_krb5_context->krb5_context, ret, ccc)));
		talloc_free(ccache_name);
		talloc_free(ccc);
		return ret;
	}

	talloc_set_destructor(ccc, free_mccache);

	cred->ccache = ccc;
	talloc_steal(cred, ccc);
	talloc_free(ccache_name);

	return ret;
}

int cli_credentials_get_ccache(struct cli_credentials *cred, 
			       struct ccache_container **ccc)
{
	krb5_error_code ret;
	
	if (cred->ccache_obtained >= (MAX(cred->principal_obtained, 
					  cred->username_obtained))) {
		*ccc = cred->ccache;
		return 0;
	}
	if (cli_credentials_is_anonymous(cred)) {
		return EINVAL;
	}

	ret = cli_credentials_new_ccache(cred);
	if (ret) {
		return ret;
	}
	ret = kinit_to_ccache(cred, cred, cred->ccache->smb_krb5_context, cred->ccache->ccache);
	if (ret) {
		return ret;
	}
	ret = cli_credentials_set_from_ccache(cred, cred->principal_obtained);

	if (ret) {
		return ret;
	}
	*ccc = cred->ccache;
	return ret;
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

	/* If we have a principal set on this, we want to login with "" domain and user@realm */
	if (cred->domain_obtained < cred->principal_obtained) {
		return "";
	}

	if (cred->domain_obtained == CRED_CALLBACK) {
		cred->domain = cred->domain_cb(cred);
		cred->domain_obtained = CRED_SPECIFIED;
	}

	return cred->domain;
}


BOOL cli_credentials_set_domain(struct cli_credentials *cred, 
				const char *val, 
				enum credentials_obtained obtained)
{
	if (obtained >= cred->domain_obtained) {
		cred->domain = talloc_strdup(cred, val);
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

	if (cred->realm_obtained == CRED_CALLBACK) {
		cred->realm = cred->realm_cb(cred);
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
	if (cred->workstation_obtained == CRED_CALLBACK) {
		cred->workstation = cred->workstation_cb(cred);
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
 * Read a file descriptor, and parse it for a password (eg from a file or stdin)
 *
 * @param credentials Credentials structure on which to set the password
 * @param fd open file descriptor to read the password from 
 * @param obtained This enum describes how 'specified' this password is
 */

BOOL cli_credentials_parse_password_fd(struct cli_credentials *credentials, 
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
		case 0:
			if (p - pass) {
				*p = '\0'; /* null-terminate it, just in case... */
				p = NULL; /* then force the loop condition to become false */
				break;
			} else {
				fprintf(stderr, "Error reading password from file descriptor %d: %s\n", fd, "empty password\n");
				return False;
			}

		default:
			fprintf(stderr, "Error reading password from file descriptor %d: %s\n",
					fd, strerror(errno));
			return False;
		}
	}

	cli_credentials_set_password(credentials, pass, obtained);
	return True;
}

/**
 * Read a named file, and parse it for a password
 *
 * @param credentials Credentials structure on which to set the password
 * @param file a named file to read the password from 
 * @param obtained This enum describes how 'specified' this password is
 */

BOOL cli_credentials_parse_password_file(struct cli_credentials *credentials, const char *file, enum credentials_obtained obtained)
{
	int fd = open(file, O_RDONLY, 0);
	BOOL ret;

	if (fd < 0) {
		fprintf(stderr, "Error opening PASSWD_FILE %s: %s\n",
				file, strerror(errno));
		return False;
	}

	ret = cli_credentials_parse_password_fd(credentials, fd, obtained);

	close(fd);
	
	return ret;
}

/**
 * Read a named file, and parse it for username, domain, realm and password
 *
 * @param credentials Credentials structure on which to set the password
 * @param file a named file to read the details from 
 * @param obtained This enum describes how 'specified' this password is
 */

BOOL cli_credentials_parse_file(struct cli_credentials *cred, const char *file, enum credentials_obtained obtained) 
{
	XFILE *auth;
	char buf[128];
	uint16_t len = 0;
	char *ptr, *val, *param;

	if ((auth=x_fopen(file, O_RDONLY, 0)) == NULL)
	{
		/* fail if we can't open the credentials file */
		d_printf("ERROR: Unable to open credentials file!\n");
		return False;
	}

	while (!x_feof(auth))
	{
		/* get a line from the file */
		if (!x_fgets(buf, sizeof(buf), auth))
			continue;
		len = strlen(buf);

		if ((len) && (buf[len-1]=='\n'))
		{
			buf[len-1] = '\0';
			len--;
		}
		if (len == 0)
			continue;

		/* break up the line into parameter & value.
		 * will need to eat a little whitespace possibly */
		param = buf;
		if (!(ptr = strchr_m (buf, '=')))
			continue;

		val = ptr+1;
		*ptr = '\0';

		/* eat leading white space */
		while ((*val!='\0') && ((*val==' ') || (*val=='\t')))
			val++;

		if (strwicmp("password", param) == 0) {
			cli_credentials_set_password(cred, val, obtained);
		} else if (strwicmp("username", param) == 0) {
			cli_credentials_set_username(cred, val, obtained);
		} else if (strwicmp("domain", param) == 0) {
			cli_credentials_set_domain(cred, val, obtained);
		} else if (strwicmp("realm", param) == 0) {
			cli_credentials_set_realm(cred, val, obtained);
		}
		memset(buf, 0, sizeof(buf));
	}

	x_fclose(auth);
	return True;
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

	cli_credentials_set_ccache(cred, NULL, CRED_GUESS_FILE);
}

/**
 * Fill in credentials for the machine trust account, from the secrets database.
 * 
 * @param cred Credentials structure to fill in
 * @retval NTSTATUS error detailing any failure
 */
NTSTATUS cli_credentials_set_machine_account(struct cli_credentials *cred)
{
	TALLOC_CTX *mem_ctx;
	
	struct ldb_context *ldb;
	int ldb_ret;
	struct ldb_message **msgs;
	const char *attrs[] = {
		"secret",
		"samAccountName",
		"flatname",
		"realm",
		"secureChannelType",
		"ntPwdHash",
		"msDS-KeyVersionNumber",
		NULL
	};
	
	const char *machine_account;
	const char *password;
	const char *domain;
	const char *realm;
	enum netr_SchannelType sct;
	
	/* ok, we are going to get it now, don't recurse back here */
	cred->machine_account_pending = False;

	mem_ctx = talloc_named(cred, 0, "cli_credentials fetch machine password");
	/* Local secrets are stored in secrets.ldb */
	ldb = secrets_db_connect(mem_ctx);
	if (!ldb) {
		DEBUG(1, ("Could not open secrets.ldb\n"));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* search for the secret record */
	ldb_ret = gendb_search(ldb,
			       mem_ctx, ldb_dn_explode(mem_ctx, SECRETS_PRIMARY_DOMAIN_DN), 
			       &msgs, attrs,
			       SECRETS_PRIMARY_DOMAIN_FILTER, 
			       cli_credentials_get_domain(cred));
	if (ldb_ret == 0) {
		DEBUG(1, ("Could not find join record to domain: %s\n",
			  cli_credentials_get_domain(cred)));
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	} else if (ldb_ret != 1) {
		DEBUG(1, ("Found more than one (%d) join records to domain: %s\n",
			  ldb_ret, cli_credentials_get_domain(cred)));
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	
	password = ldb_msg_find_string(msgs[0], "secret", NULL);

	machine_account = ldb_msg_find_string(msgs[0], "samAccountName", NULL);

	if (!machine_account) {
		DEBUG(1, ("Could not find 'samAccountName' in join record to domain: %s\n",
			  cli_credentials_get_domain(cred)));
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	
	sct = ldb_msg_find_int(msgs[0], "secureChannelType", 0);
	if (!sct) { 
		DEBUG(1, ("Domain join for acocunt %s did not have a secureChannelType set!\n",
			  machine_account));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	
	if (!password) {
		const struct ldb_val *nt_password_hash = ldb_msg_find_ldb_val(msgs[0], "ntPwdHash");
		struct samr_Password hash;
		ZERO_STRUCT(hash);
		if (nt_password_hash) {
			memcpy(hash.hash, nt_password_hash->data, 
			       MIN(nt_password_hash->length, sizeof(hash.hash)));
		
			cli_credentials_set_nt_hash(cred, &hash, CRED_SPECIFIED);
		} else {
		
			DEBUG(1, ("Could not find 'secret' in join record to domain: %s\n",
				  cli_credentials_get_domain(cred)));
			talloc_free(mem_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	}
	
	cli_credentials_set_secure_channel_type(cred, sct);

	domain = ldb_msg_find_string(msgs[0], "flatname", NULL);
	if (domain) {
		cli_credentials_set_domain(cred, domain, CRED_SPECIFIED);
	}

	realm = ldb_msg_find_string(msgs[0], "realm", NULL);
	if (realm) {
		cli_credentials_set_realm(cred, realm, CRED_SPECIFIED);
	}

	cli_credentials_set_username(cred, machine_account, CRED_SPECIFIED);
	if (password) {
		cli_credentials_set_password(cred, password, CRED_SPECIFIED);
	}

	cli_credentials_set_kvno(cred, ldb_msg_find_int(msgs[0], "msDS-KeyVersionNumber", 0));
	
	talloc_free(mem_ctx);
	
	return NT_STATUS_OK;
}

/**
 * Ask that when required, the credentials system will be filled with
 * machine trust account, from the secrets database.
 * 
 * @param cred Credentials structure to fill in
 * @note This function is used to call the above function after, rather 
 *       than during, popt processing.
 *
 */
void cli_credentials_set_machine_account_pending(struct cli_credentials *cred)
{
	cred->machine_account_pending = True;
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
 * Set Kerberos KVNO
 */

void cli_credentials_set_kvno(struct cli_credentials *cred,
			      int kvno)
{
	cred->kvno = kvno;
}

/**
 * Return Kerberos KVNO
 */

int cli_credentials_get_kvno(struct cli_credentials *cred)
{
	return cred->kvno;
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
	TALLOC_CTX *tmp_ctx = talloc_new(cred);
	const char *username = cli_credentials_get_username(cred, tmp_ctx);
	
	/* Yes, it is deliberate that we die if we have a NULL pointer
	 * here - anonymous is "", not NULL, which is 'never specified,
	 * never guessed', ie programmer bug */
	if (!username[0]) {
		talloc_free(tmp_ctx);
		return True;
	}
	
	talloc_free(tmp_ctx);
	return False;
}
