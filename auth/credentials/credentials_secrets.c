/*
   Unix SMB/CIFS implementation.

   User credentials handling (as regards on-disk files)

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
#include "lib/events/events.h"
#include <ldb.h>
#include "librpc/gen_ndr/samr.h" /* for struct samrPassword */
#include "param/secrets.h"
#include "system/filesys.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include "auth/credentials/credentials_proto.h"
#include "auth/credentials/credentials_krb5.h"
#include "auth/kerberos/kerberos_util.h"
#include "param/param.h"
#include "lib/events/events.h"
#include "dsdb/samdb/samdb.h"
#include "source3/include/secrets.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "lib/util/util_tdb.h"
#include "libds/common/roles.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/**
 * Fill in credentials for the machine trust account, from the secrets database.
 *
 * @param cred Credentials structure to fill in
 * @retval NTSTATUS error detailing any failure
 */
static NTSTATUS cli_credentials_set_secrets_lct(struct cli_credentials *cred,
						struct loadparm_context *lp_ctx,
						struct ldb_context *ldb,
						const char *base,
						const char *filter,
						time_t secrets_tdb_last_change_time,
						const char *secrets_tdb_password,
						char **error_string)
{
	TALLOC_CTX *mem_ctx;

	int ldb_ret;
	struct ldb_message *msg;

	const char *machine_account;
	const char *password;
	const char *domain;
	const char *realm;
	enum netr_SchannelType sct;
	const char *salt_principal;
	char *keytab;
	const struct ldb_val *whenChanged;
	time_t lct;

	/* ok, we are going to get it now, don't recurse back here */
	cred->machine_account_pending = false;

	/* some other parts of the system will key off this */
	cred->machine_account = true;

	mem_ctx = talloc_named(cred, 0, "cli_credentials_set_secrets from ldb");

	if (!ldb) {
		/* Local secrets are stored in secrets.ldb */
		ldb = secrets_db_connect(mem_ctx, lp_ctx);
		if (!ldb) {
			*error_string = talloc_strdup(cred, "Could not open secrets.ldb");
			talloc_free(mem_ctx);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	}

	ldb_ret = dsdb_search_one(ldb, mem_ctx, &msg,
				  ldb_dn_new(mem_ctx, ldb, base),
				  LDB_SCOPE_SUBTREE,
				  NULL, 0, "%s", filter);

	if (ldb_ret != LDB_SUCCESS) {
		*error_string = talloc_asprintf(cred, "Could not find entry to match filter: '%s' base: '%s': %s: %s",
						filter, base ? base : "",
						ldb_strerror(ldb_ret), ldb_errstring(ldb));
		talloc_free(mem_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	password = ldb_msg_find_attr_as_string(msg, "secret", NULL);

	whenChanged = ldb_msg_find_ldb_val(msg, "whenChanged");
	if (!whenChanged || ldb_val_to_time(whenChanged, &lct) != LDB_SUCCESS) {
		/* This attribute is mandatory */
		talloc_free(mem_ctx);
		return NT_STATUS_NOT_FOUND;
	}

	/* Don't set secrets.ldb info if the secrets.tdb entry was more recent */
	if (lct < secrets_tdb_last_change_time) {
		talloc_free(mem_ctx);
		return NT_STATUS_NOT_FOUND;
	}

	if ((lct == secrets_tdb_last_change_time) &&
	    (secrets_tdb_password != NULL) &&
	    (password != NULL) &&
	    (strcmp(password, secrets_tdb_password) != 0)) {
		talloc_free(mem_ctx);
		return NT_STATUS_NOT_FOUND;
	}

	cli_credentials_set_password_last_changed_time(cred, lct);

	machine_account = ldb_msg_find_attr_as_string(msg, "samAccountName", NULL);

	if (!machine_account) {
		machine_account = ldb_msg_find_attr_as_string(msg, "servicePrincipalName", NULL);

		if (!machine_account) {
			const char *ldap_bind_dn = ldb_msg_find_attr_as_string(msg, "ldapBindDn", NULL);
			if (!ldap_bind_dn) {
				*error_string = talloc_asprintf(cred,
								"Could not find 'samAccountName', "
								"'servicePrincipalName' or "
								"'ldapBindDn' in secrets record: %s",
								ldb_dn_get_linearized(msg->dn));
				talloc_free(mem_ctx);
				return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
			} else {
				/* store bind dn in credentials */
				cli_credentials_set_bind_dn(cred, ldap_bind_dn);
			}
		}
	}

	salt_principal = ldb_msg_find_attr_as_string(msg, "saltPrincipal", NULL);
	cli_credentials_set_salt_principal(cred, salt_principal);

	sct = ldb_msg_find_attr_as_int(msg, "secureChannelType", 0);
	if (sct) {
		cli_credentials_set_secure_channel_type(cred, sct);
	}

	if (!password) {
		const struct ldb_val *nt_password_hash = ldb_msg_find_ldb_val(msg, "unicodePwd");
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

	domain = ldb_msg_find_attr_as_string(msg, "flatname", NULL);
	if (domain) {
		cli_credentials_set_domain(cred, domain, CRED_SPECIFIED);
	}

	realm = ldb_msg_find_attr_as_string(msg, "realm", NULL);
	if (realm) {
		cli_credentials_set_realm(cred, realm, CRED_SPECIFIED);
	}

	if (machine_account) {
		cli_credentials_set_username(cred, machine_account, CRED_SPECIFIED);
	}

	cli_credentials_set_kvno(cred, ldb_msg_find_attr_as_int(msg, "msDS-KeyVersionNumber", 0));

	/* If there was an external keytab specified by reference in
	 * the LDB, then use this.  Otherwise we will make one up
	 * (chewing CPU time) from the password */
	keytab = keytab_name_from_msg(cred, ldb, msg);
	if (keytab) {
		cli_credentials_set_keytab_name(cred, lp_ctx, keytab, CRED_SPECIFIED);
		talloc_free(keytab);
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
_PUBLIC_ NTSTATUS cli_credentials_set_secrets(struct cli_credentials *cred,
					      struct loadparm_context *lp_ctx,
					      struct ldb_context *ldb,
					      const char *base,
					      const char *filter,
					      char **error_string)
{
	NTSTATUS status = cli_credentials_set_secrets_lct(cred, lp_ctx, ldb, base, filter, 0, NULL, error_string);
	if (!NT_STATUS_IS_OK(status)) {
		/* set anonymous as the fallback, if the machine account won't work */
		cli_credentials_set_anonymous(cred);
	}
	return status;
}

/**
 * Fill in credentials for the machine trust account, from the secrets database.
 *
 * @param cred Credentials structure to fill in
 * @retval NTSTATUS error detailing any failure
 */
_PUBLIC_ NTSTATUS cli_credentials_set_machine_account(struct cli_credentials *cred,
						      struct loadparm_context *lp_ctx)
{
	struct db_context *db_ctx;
	char *secrets_tdb_path;
	int hash_size, tdb_flags;

	secrets_tdb_path = lpcfg_private_db_path(cred, lp_ctx, "secrets");
	if (secrets_tdb_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	hash_size = lpcfg_tdb_hash_size(lp_ctx, secrets_tdb_path);
	tdb_flags = lpcfg_tdb_flags(lp_ctx, TDB_DEFAULT);

	db_ctx = dbwrap_local_open(
		cred,
		secrets_tdb_path,
		hash_size,
		tdb_flags,
		O_RDWR,
		0600,
		DBWRAP_LOCK_ORDER_1,
		DBWRAP_FLAG_NONE);
	TALLOC_FREE(secrets_tdb_path);

	/*
	 * We do not check for errors here, we might not have a
	 * secrets.tdb at all, and so we just need to check the
	 * secrets.ldb
	 */
	return cli_credentials_set_machine_account_db_ctx(cred, lp_ctx, db_ctx);
}

/**
 * Fill in credentials for the machine trust account, from the
 * secrets.ldb or passed in handle to secrets.tdb (perhaps in CTDB).
 *
 * This version is used in parts of the code that can link in the
 * CTDB dbwrap backend, by passing down the already open handle.
 *
 * @param cred Credentials structure to fill in
 * @param db_ctx dbwrap context for secrets.tdb
 * @retval NTSTATUS error detailing any failure
 */
_PUBLIC_ NTSTATUS cli_credentials_set_machine_account_db_ctx(struct cli_credentials *cred,
							     struct loadparm_context *lp_ctx,
							     struct db_context *db_ctx)
{
	NTSTATUS status;
	char *filter;
	char *error_string = NULL;
	const char *domain;
	bool secrets_tdb_password_more_recent;
	time_t secrets_tdb_lct = 0;
	char *secrets_tdb_password = NULL;
	char *secrets_tdb_old_password = NULL;
	uint32_t secrets_tdb_secure_channel_type = SEC_CHAN_NULL;
	int server_role = lpcfg_server_role(lp_ctx);
	int security = lpcfg_security(lp_ctx);
	char *keystr;
	char *keystr_upper = NULL;
	TALLOC_CTX *tmp_ctx = talloc_named(cred, 0, "cli_credentials_set_secrets from ldb");
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Bleh, nasty recursion issues: We are setting a machine
	 * account here, so we don't want the 'pending' flag around
	 * any more */
	cred->machine_account_pending = false;

	/* We have to do this, as the fallback in
	 * cli_credentials_set_secrets is to run as anonymous, so the domain is wiped */
	domain = cli_credentials_get_domain(cred);

	if (db_ctx) {
		TDB_DATA dbuf;
		keystr = talloc_asprintf(tmp_ctx, "%s/%s",
					 SECRETS_MACHINE_LAST_CHANGE_TIME,
					 domain);
		keystr_upper = strupper_talloc(tmp_ctx, keystr);
		status = dbwrap_fetch(db_ctx, tmp_ctx, string_tdb_data(keystr_upper),
				      &dbuf);
		if (NT_STATUS_IS_OK(status) && dbuf.dsize == 4) {
			secrets_tdb_lct = IVAL(dbuf.dptr,0);
		}

		keystr = talloc_asprintf(tmp_ctx, "%s/%s",
					 SECRETS_MACHINE_PASSWORD,
					 domain);
		keystr_upper = strupper_talloc(tmp_ctx, keystr);
		status = dbwrap_fetch(db_ctx, tmp_ctx, string_tdb_data(keystr_upper),
				      &dbuf);
		if (NT_STATUS_IS_OK(status)) {
			secrets_tdb_password = (char *)dbuf.dptr;
		}

		keystr = talloc_asprintf(tmp_ctx, "%s/%s",
					 SECRETS_MACHINE_PASSWORD_PREV,
					 domain);
		keystr_upper = strupper_talloc(tmp_ctx, keystr);
		status = dbwrap_fetch(db_ctx, tmp_ctx, string_tdb_data(keystr_upper),
				      &dbuf);
		if (NT_STATUS_IS_OK(status)) {
			secrets_tdb_old_password = (char *)dbuf.dptr;
		}

		keystr = talloc_asprintf(tmp_ctx, "%s/%s",
					 SECRETS_MACHINE_SEC_CHANNEL_TYPE,
					 domain);
		keystr_upper = strupper_talloc(tmp_ctx, keystr);
		status = dbwrap_fetch(db_ctx, tmp_ctx, string_tdb_data(keystr_upper),
				      &dbuf);
		if (NT_STATUS_IS_OK(status) && dbuf.dsize == 4) {
			secrets_tdb_secure_channel_type = IVAL(dbuf.dptr,0);
		}
	}

	filter = talloc_asprintf(cred, SECRETS_PRIMARY_DOMAIN_FILTER, 
				 domain);
	status = cli_credentials_set_secrets_lct(cred, lp_ctx, NULL,
						 SECRETS_PRIMARY_DOMAIN_DN,
						 filter, secrets_tdb_lct, secrets_tdb_password, &error_string);
	if (secrets_tdb_password == NULL) {
		secrets_tdb_password_more_recent = false;
	} else if (NT_STATUS_EQUAL(NT_STATUS_CANT_ACCESS_DOMAIN_INFO, status)
	    || NT_STATUS_EQUAL(NT_STATUS_NOT_FOUND, status)) {
		secrets_tdb_password_more_recent = true;
	} else if (secrets_tdb_lct > cli_credentials_get_password_last_changed_time(cred)) {
		secrets_tdb_password_more_recent = true;
	} else if (secrets_tdb_lct == cli_credentials_get_password_last_changed_time(cred)) {
		secrets_tdb_password_more_recent = strcmp(secrets_tdb_password, cli_credentials_get_password(cred)) != 0;
	} else {
		secrets_tdb_password_more_recent = false;
	}

	if (secrets_tdb_password_more_recent) {
		enum credentials_use_kerberos use_kerberos = CRED_DONT_USE_KERBEROS;
		char *machine_account = talloc_asprintf(tmp_ctx, "%s$", lpcfg_netbios_name(lp_ctx));
		cli_credentials_set_password(cred, secrets_tdb_password, CRED_SPECIFIED);
		cli_credentials_set_old_password(cred, secrets_tdb_old_password, CRED_SPECIFIED);
		cli_credentials_set_domain(cred, domain, CRED_SPECIFIED);
		if (strequal(domain, lpcfg_workgroup(lp_ctx))) {
			cli_credentials_set_realm(cred, lpcfg_realm(lp_ctx), CRED_SPECIFIED);

			switch (server_role) {
			case ROLE_DOMAIN_MEMBER:
				if (security != SEC_ADS) {
					break;
				}

				FALL_THROUGH;
			case ROLE_ACTIVE_DIRECTORY_DC:
				use_kerberos = CRED_AUTO_USE_KERBEROS;
				break;
			}
		}
		cli_credentials_set_kerberos_state(cred, use_kerberos);
		cli_credentials_set_username(cred, machine_account, CRED_SPECIFIED);
		cli_credentials_set_password_last_changed_time(cred, secrets_tdb_lct);
		cli_credentials_set_secure_channel_type(cred, secrets_tdb_secure_channel_type);
		status = NT_STATUS_OK;
	} else if (!NT_STATUS_IS_OK(status)) {
		if (db_ctx) {
			error_string
				= talloc_asprintf(cred,
						  "Failed to fetch machine account password for %s from both "
						  "secrets.ldb (%s) and from %s",
						  domain,
						  error_string == NULL ? "error" : error_string,
						  dbwrap_name(db_ctx));
		} else {
			char *secrets_tdb_path;

			secrets_tdb_path = lpcfg_private_db_path(tmp_ctx,
								 lp_ctx,
								 "secrets");
			if (secrets_tdb_path == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			error_string = talloc_asprintf(cred,
						       "Failed to fetch machine account password from "
						       "secrets.ldb: %s and failed to open %s",
						       error_string == NULL ? "error" : error_string,
						       secrets_tdb_path);
		}
		DEBUG(1, ("Could not find machine account in secrets database: %s: %s\n",
			  error_string == NULL ? "error" : error_string,
			  nt_errstr(status)));
		/* set anonymous as the fallback, if the machine account won't work */
		cli_credentials_set_anonymous(cred);
	}

	TALLOC_FREE(tmp_ctx);
	return status;
}

/**
 * Fill in credentials for a particular principal, from the secrets database.
 *
 * @param cred Credentials structure to fill in
 * @retval NTSTATUS error detailing any failure
 */
_PUBLIC_ NTSTATUS cli_credentials_set_stored_principal(struct cli_credentials *cred,
					      struct loadparm_context *lp_ctx,
					      const char *serviceprincipal)
{
	NTSTATUS status;
	char *filter;
	char *error_string = NULL;
	/* Bleh, nasty recursion issues: We are setting a machine
	 * account here, so we don't want the 'pending' flag around
	 * any more */
	cred->machine_account_pending = false;
	filter = talloc_asprintf(cred, SECRETS_PRINCIPAL_SEARCH,
				 cli_credentials_get_realm(cred),
				 cli_credentials_get_domain(cred),
				 serviceprincipal);
	status = cli_credentials_set_secrets_lct(cred, lp_ctx, NULL,
					     SECRETS_PRINCIPALS_DN, filter,
					     0, NULL, &error_string);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Could not find %s principal in secrets database: %s: %s\n",
			  serviceprincipal, nt_errstr(status),
			  error_string ? error_string : "<no error>"));
	}
	return status;
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
_PUBLIC_ void cli_credentials_set_machine_account_pending(struct cli_credentials *cred,
						 struct loadparm_context *lp_ctx)
{
	cred->machine_account_pending = true;
	cred->machine_account_pending_lp_ctx = lp_ctx;
}


