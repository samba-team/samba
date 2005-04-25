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
#include "lib/cmdline/popt_common.h"
#include "include/secrets.h"
#include "lib/ldb/include/ldb.h"

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
	return cred;
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

	if (cred->username_obtained == CRED_CALLBACK) {
		cred->username = cred->username_cb(cred);
		cred->username_obtained = CRED_SPECIFIED;
	}

	return cred->username;
}

BOOL cli_credentials_set_username(struct cli_credentials *cred, const char *val, enum credentials_obtained obtained)
{
	if (obtained >= cred->username_obtained) {
		cred->username = talloc_strdup(cred, val);
		cred->username_obtained = obtained;
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

BOOL cli_credentials_set_password(struct cli_credentials *cred, const char *val, enum credentials_obtained obtained)
{
	if (obtained >= cred->password_obtained) {
		cred->password = talloc_strdup(cred, val);
		cred->password_obtained = obtained;
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

	if (cred->domain_obtained == CRED_CALLBACK) {
		cred->domain = cred->domain_cb(cred);
		cred->domain_obtained = CRED_SPECIFIED;
	}

	return cred->domain;
}


BOOL cli_credentials_set_domain(struct cli_credentials *cred, const char *val, enum credentials_obtained obtained)
{
	if (obtained >= cred->domain_obtained) {
		cred->domain = talloc_strdup(cred, val);
		cred->domain_obtained = obtained;
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
 * Obtain the user's Kerberos principal for this credentials context.
 * @param cred credentials context
 * @param mem_ctx A talloc context to return the prinipal name on.
 * @retval The user's Kerberos principal
 * @note Return value may be NULL due to out-of memeory or invalid mem_ctx
 */
char *cli_credentials_get_principal(struct cli_credentials *cred,
				    TALLOC_CTX *mem_ctx)
{
	return talloc_asprintf(mem_ctx, "%s@%s", 
			       cli_credentials_get_username(cred),
			       cli_credentials_get_realm(cred));
}

BOOL cli_credentials_set_realm(struct cli_credentials *cred, const char *val, enum credentials_obtained obtained)
{
	if (obtained >= cred->realm_obtained) {
		cred->realm = talloc_strdup(cred, val);
		cred->realm_obtained = obtained;
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

BOOL cli_credentials_set_workstation(struct cli_credentials *cred, const char *val, enum credentials_obtained obtained)
{
	if (obtained >= cred->workstation_obtained) {
		cred->workstation = talloc_strdup(cred, val);
		cred->workstation_obtained = obtained;
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

BOOL cli_credentials_parse_password_fd(struct cli_credentials *credentials, int fd, enum credentials_obtained obtained)
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

	uname = talloc_strdup(credentials, data); 
	if ((p = strchr_m(uname,'%'))) {
		*p = 0;
		cli_credentials_set_password(credentials, p+1, obtained);
	}

	if ((p = strchr_m(uname,'@'))) {
		*p = 0;
		cli_credentials_set_realm(credentials, p+1, obtained);
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
	cli_credentials_set_domain(cred, lp_workgroup(), CRED_GUESSED);
	cli_credentials_set_workstation(cred, lp_netbios_name(), CRED_GUESSED);
	cli_credentials_set_realm(cred, lp_realm(), CRED_GUESSED);
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

	cli_credentials_set_username(cred, "", CRED_GUESSED);
	cli_credentials_set_conf(cred);
	
	if (getenv("LOGNAME")) {
		cli_credentials_set_username(cred, getenv("LOGNAME"), CRED_GUESSED);
	}

	if (getenv("USER")) {
		cli_credentials_parse_string(cred, getenv("USER"), CRED_GUESSED);
		if ((p = strchr_m(getenv("USER"),'%'))) {
			memset(p,0,strlen(cred->password));
		}
	}

	if (getenv("DOMAIN")) {
		cli_credentials_set_domain(cred, getenv("DOMAIN"), CRED_GUESSED);
	}

	if (getenv("PASSWD")) {
		cli_credentials_set_password(cred, getenv("PASSWD"), CRED_GUESSED);
	}

	if (getenv("PASSWD_FD")) {
		cli_credentials_parse_password_fd(cred, atoi(getenv("PASSWD_FD")), CRED_GUESSED);
	}
	
	if (getenv("PASSWD_FILE")) {
		cli_credentials_parse_password_file(cred, getenv("PASSWD_FILE"), CRED_GUESSED);
	}
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
	const char *base_dn = SECRETS_PRIMARY_DOMAIN_DN;
	const char *attrs[] = {
		"secret",
		"samAccountName",
		"flatname",
		"realm",
		NULL
	};
	
	const char *machine_account;
	const char *password;
	const char *domain;
	const char *realm;
	
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
			       mem_ctx, base_dn, &msgs, attrs,
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
	if (!password) {
		DEBUG(1, ("Could not find 'secret' in join record to domain: %s\n",
			  cli_credentials_get_domain(cred)));
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	
	machine_account = ldb_msg_find_string(msgs[0], "samAccountName", NULL);
	if (!machine_account) {
		DEBUG(1, ("Could not find 'samAccountName' in join record to domain: %s\n",
			  cli_credentials_get_domain(cred)));
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	
	domain = ldb_msg_find_string(msgs[0], "flatname", NULL);
	if (domain) {
		cli_credentials_set_domain(cred, domain, CRED_SPECIFIED);
	}

	realm = ldb_msg_find_string(msgs[0], "realm", NULL);
	if (realm) {
		cli_credentials_set_realm(cred, realm, CRED_SPECIFIED);
	}
	
	cli_credentials_set_username(cred, machine_account, CRED_SPECIFIED);
	cli_credentials_set_password(cred, password, CRED_SPECIFIED);
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
	const char *username = cli_credentials_get_username(cred);

	/* Yes, it is deliberate that we die if we have a NULL pointer
	 * here - anonymous is "", not NULL, which is 'never specified,
	 * never guessed', ie programmer bug */
	if (!username[0]) 
		return True;

	return False;
}
