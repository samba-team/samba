/* 
   Unix SMB/CIFS implementation.

   User credentials handling (as regards on-disk files)

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
#include "lib/ldb/include/ldb.h"
#include "librpc/gen_ndr/samr.h" /* for struct samrPassword */
#include "param/secrets.h"
#include "system/filesys.h"
#include "db_wrap.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"

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
			/* fall through */
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
	uint16_t len = 0;
	char *ptr, *val, *param;
	char **lines;
	int i, numlines;

	lines = file_lines_load(file, &numlines, NULL);

	if (lines == NULL)
	{
		/* fail if we can't open the credentials file */
		d_printf("ERROR: Unable to open credentials file!\n");
		return False;
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
			cli_credentials_set_password(cred, val, obtained);
		} else if (strwicmp("username", param) == 0) {
			cli_credentials_set_username(cred, val, obtained);
		} else if (strwicmp("domain", param) == 0) {
			cli_credentials_set_domain(cred, val, obtained);
		} else if (strwicmp("realm", param) == 0) {
			cli_credentials_set_realm(cred, val, obtained);
		}
		memset(lines[i], 0, len);
	}

	talloc_free(lines);

	return True;
}


/**
 * Fill in credentials for the machine trust account, from the secrets database.
 * 
 * @param cred Credentials structure to fill in
 * @retval NTSTATUS error detailing any failure
 */
NTSTATUS cli_credentials_set_secrets(struct cli_credentials *cred, 
				     const char *base,
				     const char *filter)
{
	TALLOC_CTX *mem_ctx;
	
	struct ldb_context *ldb;
	int ldb_ret;
	struct ldb_message **msgs;
	const char *attrs[] = {
		"secret",
		"priorSecret",
		"samAccountName",
		"flatname",
		"realm",
		"secureChannelType",
		"ntPwdHash",
		"msDS-KeyVersionNumber",
		"saltPrincipal",
		"privateKeytab",
		"krb5Keytab",
		NULL
	};
	
	const char *machine_account;
	const char *password;
	const char *old_password;
	const char *domain;
	const char *realm;
	enum netr_SchannelType sct;
	const char *salt_principal;
	const char *keytab;
	
	/* ok, we are going to get it now, don't recurse back here */
	cred->machine_account_pending = False;

	/* some other parts of the system will key off this */
	cred->machine_account = True;

	mem_ctx = talloc_named(cred, 0, "cli_credentials fetch machine password");

	/* Local secrets are stored in secrets.ldb */
	ldb = secrets_db_connect(mem_ctx);
	if (!ldb) {
		/* set anonymous as the fallback, if the machine account won't work */
		cli_credentials_set_anonymous(cred);
		DEBUG(1, ("Could not open secrets.ldb\n"));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* search for the secret record */
	ldb_ret = gendb_search(ldb,
			       mem_ctx, ldb_dn_explode(mem_ctx, base), 
			       &msgs, attrs,
			       "%s", filter);
	if (ldb_ret == 0) {
		DEBUG(1, ("Could not find entry to match filter: %s\n",
			  filter));
		/* set anonymous as the fallback, if the machine account won't work */
		cli_credentials_set_anonymous(cred);
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	} else if (ldb_ret != 1) {
		DEBUG(1, ("Found more than one (%d) entry to match filter: %s\n",
			  ldb_ret, filter));
		/* set anonymous as the fallback, if the machine account won't work */
		cli_credentials_set_anonymous(cred);
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
	
	password = ldb_msg_find_attr_as_string(msgs[0], "secret", NULL);
	old_password = ldb_msg_find_attr_as_string(msgs[0], "priorSecret", NULL);

	machine_account = ldb_msg_find_attr_as_string(msgs[0], "samAccountName", NULL);

	if (!machine_account) {
		DEBUG(1, ("Could not find 'samAccountName' in join record to domain: %s\n",
			  cli_credentials_get_domain(cred)));
		/* set anonymous as the fallback, if the machine account won't work */
		cli_credentials_set_anonymous(cred);
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	salt_principal = ldb_msg_find_attr_as_string(msgs[0], "saltPrincipal", NULL);
	cli_credentials_set_salt_principal(cred, salt_principal);
	
	sct = ldb_msg_find_attr_as_int(msgs[0], "secureChannelType", 0);
	if (sct) { 
		cli_credentials_set_secure_channel_type(cred, sct);
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
			cli_credentials_set_password(cred, NULL, CRED_SPECIFIED);
		}
	} else {
		cli_credentials_set_password(cred, password, CRED_SPECIFIED);
	}

	
	domain = ldb_msg_find_attr_as_string(msgs[0], "flatname", NULL);
	if (domain) {
		cli_credentials_set_domain(cred, domain, CRED_SPECIFIED);
	}

	realm = ldb_msg_find_attr_as_string(msgs[0], "realm", NULL);
	if (realm) {
		cli_credentials_set_realm(cred, realm, CRED_SPECIFIED);
	}

	cli_credentials_set_username(cred, machine_account, CRED_SPECIFIED);

	cli_credentials_set_kvno(cred, ldb_msg_find_attr_as_int(msgs[0], "msDS-KeyVersionNumber", 0));

	/* If there was an external keytab specified by reference in
	 * the LDB, then use this.  Otherwise we will make one up
	 * (chewing CPU time) from the password */
	keytab = ldb_msg_find_attr_as_string(msgs[0], "krb5Keytab", NULL);
	if (keytab) {
		cli_credentials_set_keytab_name(cred, keytab, CRED_SPECIFIED);
	} else {
		keytab = ldb_msg_find_attr_as_string(msgs[0], "privateKeytab", NULL);
		if (keytab) {
			keytab = talloc_asprintf(mem_ctx, "FILE:%s", private_path(mem_ctx, keytab));
			if (keytab) {
				cli_credentials_set_keytab_name(cred, keytab, CRED_SPECIFIED);
			}
		}
	}
	talloc_free(mem_ctx);
	
	return NT_STATUS_OK;
}

/**
 * Fill in credentials for the machine trust account, from the secrets database.
 * 
 * @param cred Credentials structure to fill in
 * @retval NTSTATUS error detailing any failure
 */
NTSTATUS cli_credentials_set_machine_account(struct cli_credentials *cred)
{
	char *filter;
	/* Bleh, nasty recursion issues: We are setting a machine
	 * account here, so we don't want the 'pending' flag around
	 * any more */
	cred->machine_account_pending = False;
	filter = talloc_asprintf(cred, SECRETS_PRIMARY_DOMAIN_FILTER, 
				       cli_credentials_get_domain(cred));
	return cli_credentials_set_secrets(cred, SECRETS_PRIMARY_DOMAIN_DN,
					   filter);
}

/**
 * Fill in credentials for the machine trust account, from the secrets database.
 * 
 * @param cred Credentials structure to fill in
 * @retval NTSTATUS error detailing any failure
 */
NTSTATUS cli_credentials_set_krbtgt(struct cli_credentials *cred)
{
	char *filter;
	/* Bleh, nasty recursion issues: We are setting a machine
	 * account here, so we don't want the 'pending' flag around
	 * any more */
	cred->machine_account_pending = False;
	filter = talloc_asprintf(cred, SECRETS_KRBTGT_SEARCH,
				       cli_credentials_get_realm(cred),
				       cli_credentials_get_domain(cred));
	return cli_credentials_set_secrets(cred, SECRETS_PRINCIPALS_DN,
					   filter);
}

/**
 * Fill in credentials for the machine trust account, from the secrets database.
 * 
 * @param cred Credentials structure to fill in
 * @retval NTSTATUS error detailing any failure
 */
NTSTATUS cli_credentials_set_stored_principal(struct cli_credentials *cred,
					      const char *serviceprincipal)
{
	char *filter;
	/* Bleh, nasty recursion issues: We are setting a machine
	 * account here, so we don't want the 'pending' flag around
	 * any more */
	cred->machine_account_pending = False;
	filter = talloc_asprintf(cred, SECRETS_PRINCIPAL_SEARCH,
				 cli_credentials_get_realm(cred),
				 cli_credentials_get_domain(cred),
				 serviceprincipal);
	return cli_credentials_set_secrets(cred, SECRETS_PRINCIPALS_DN,
					   filter);
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


NTSTATUS cli_credentials_update_all_keytabs(TALLOC_CTX *parent_ctx)
{
	TALLOC_CTX *mem_ctx;
	int ldb_ret;
	struct ldb_context *ldb;
	struct ldb_message **msgs;
	const char *attrs[] = { NULL };
	struct cli_credentials *creds;
	const char *filter;
	NTSTATUS status;
	int i, ret;

	mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Local secrets are stored in secrets.ldb */
	ldb = secrets_db_connect(mem_ctx);
	if (!ldb) {
		DEBUG(1, ("Could not open secrets.ldb\n"));
		talloc_free(mem_ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* search for the secret record, but only of things we can
	 * actually update */
	ldb_ret = gendb_search(ldb,
			       mem_ctx, NULL,
			       &msgs, attrs,
			       "(&(objectClass=kerberosSecret)(|(secret=*)(ntPwdHash=*)))");
	if (ldb_ret == -1) {
		DEBUG(1, ("Error looking for kerberos type secrets to push into a keytab:: %s", ldb_errstring(ldb)));
		talloc_free(mem_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	for (i=0; i < ldb_ret; i++) {
		/* Make a credentials structure from it */
		creds = cli_credentials_init(mem_ctx);
		if (!creds) {
			DEBUG(1, ("cli_credentials_init failed!"));
			talloc_free(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		cli_credentials_set_conf(creds);
		filter = talloc_asprintf(mem_ctx, "dn=%s", ldb_dn_linearize(mem_ctx, msgs[i]->dn));
		status = cli_credentials_set_secrets(creds, NULL, filter);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to read secrets for keytab update for %s\n", 
				  filter));
			continue;
		} 
		ret = cli_credentials_update_keytab(creds);
		if (ret != 0) {
			DEBUG(1, ("Failed to update keytab for %s\n", 
				  filter));
			continue;
		}
	}
	return NT_STATUS_OK;
}

