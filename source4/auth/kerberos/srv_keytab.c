/*
   Unix SMB/CIFS implementation.

   Kerberos utility functions

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005

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

/**
 * @file srv_keytab.c
 *
 * @brief Kerberos keytab utility functions
 *
 */

#include "includes.h"
#include "system/kerberos.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "auth/kerberos/kerberos.h"
#include "auth/kerberos/kerberos_util.h"
#include "auth/kerberos/kerberos_srv_keytab.h"
#include "librpc/gen_ndr/ndr_gmsa.h"
#include "dsdb/samdb/samdb.h"

static void keytab_principals_free(krb5_context context,
				   uint32_t num_principals,
				   krb5_principal *set)
{
	uint32_t i;

	for (i = 0; i < num_principals; i++) {
		krb5_free_principal(context, set[i]);
	}
}

static krb5_error_code keytab_add_keys(TALLOC_CTX *parent_ctx,
				       uint32_t num_principals,
				       krb5_principal *principals,
				       krb5_principal salt_princ,
				       int kvno,
				       const char *password_s,
				       krb5_context context,
				       krb5_enctype *enctypes,
				       krb5_keytab keytab,
				       const char **error_string)
{
	unsigned int i, p;
	krb5_error_code ret;
	krb5_data password;
	char *unparsed;

	password.data = discard_const_p(char, password_s);
	password.length = strlen(password_s);

	for (i = 0; enctypes[i]; i++) {
		krb5_keytab_entry entry;

		ZERO_STRUCT(entry);

		ret = smb_krb5_create_key_from_string(context,
						      salt_princ,
						      NULL,
						      &password,
						      enctypes[i],
						      KRB5_KT_KEY(&entry));
		if (ret != 0) {
			*error_string = talloc_strdup(parent_ctx,
						      "Failed to create key from string");
			return ret;
		}

		entry.vno = kvno;

		for (p = 0; p < num_principals; p++) {
			bool found = false;

			unparsed = NULL;
			entry.principal = principals[p];

			ret = smb_krb5_is_exact_entry_in_keytab(parent_ctx,
								context,
								keytab,
								&entry,
								&found,
								error_string);
			if (ret != 0) {
				krb5_free_keyblock_contents(context,
							    KRB5_KT_KEY(&entry));
				return ret;
			}

			/*
			 * Do not add the exact same key twice, this
			 * will allow "samba-tool domain exportkeytab"
			 * to refresh a keytab rather than infinitely
			 * extend it
			 */
			if (found) {
				continue;
			}

			ret = krb5_kt_add_entry(context, keytab, &entry);
			if (ret != 0) {
				char *k5_error_string =
					smb_get_krb5_error_message(context,
								   ret, NULL);
				krb5_unparse_name(context,
						principals[p], &unparsed);
				*error_string = talloc_asprintf(parent_ctx,
					"Failed to add enctype %d entry for "
					"%s(kvno %d) to keytab: %s\n",
					(int)enctypes[i], unparsed,
					kvno, k5_error_string);

				free(unparsed);
				talloc_free(k5_error_string);
				krb5_free_keyblock_contents(context,
							    KRB5_KT_KEY(&entry));
				return ret;
			}

			DEBUG(5, ("Added key (kvno %d) to keytab (enctype %d)\n",
				  kvno, (int)enctypes[i]));
		}
		krb5_free_keyblock_contents(context, KRB5_KT_KEY(&entry));
	}
	return 0;
}

/*
 * This is the inner part of smb_krb5_update_keytab on an open keytab
 * and without the deletion
 */
static krb5_error_code smb_krb5_fill_keytab(TALLOC_CTX *parent_ctx,
					    const char *saltPrincipal,
					    int kvno,
					    const char *new_secret,
					    const char *old_secret,
					    uint32_t supp_enctypes,
					    uint32_t num_principals,
					    krb5_principal *principals,
					    krb5_context context,
					    krb5_keytab keytab,
					    bool add_old,
					    const char **perror_string)
{
	krb5_error_code ret;
	krb5_principal salt_princ = NULL;
	krb5_enctype *enctypes;
	TALLOC_CTX *mem_ctx;
	const char *error_string = NULL;

	if (!new_secret) {
		/* There is no password here, so nothing to do */
		return 0;
	}

	mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		*perror_string = talloc_strdup(parent_ctx,
			"unable to allocate tmp_ctx for smb_krb5_fill_keytab");
		return ENOMEM;
	}

	/* The salt used to generate these entries may be different however,
	 * fetch that */
	ret = krb5_parse_name(context, saltPrincipal, &salt_princ);
	if (ret) {
		*perror_string = smb_get_krb5_error_message(context,
							   ret,
							   parent_ctx);
		talloc_free(mem_ctx);
		return ret;
	}

	ret = ms_suptypes_to_ietf_enctypes(mem_ctx, supp_enctypes, &enctypes);
	if (ret) {
		*perror_string = talloc_asprintf(parent_ctx,
					"smb_krb5_fill_keytab: generating list of "
					"encryption types failed (%s)\n",
					smb_get_krb5_error_message(context,
								ret, mem_ctx));
		goto done;
	}

	ret = keytab_add_keys(mem_ctx,
			      num_principals,
			      principals,
			      salt_princ, kvno, new_secret,
			      context, enctypes, keytab, &error_string);
	if (ret) {
		*perror_string = talloc_steal(parent_ctx, error_string);
		goto done;
	}

	if (old_secret && add_old && kvno != 0) {
		ret = keytab_add_keys(mem_ctx,
				      num_principals,
				      principals,
				      salt_princ, kvno - 1, old_secret,
				      context, enctypes, keytab, &error_string);
		if (ret) {
			*perror_string = talloc_steal(parent_ctx, error_string);
		}
	}

done:
	krb5_free_principal(context, salt_princ);
	talloc_free(mem_ctx);
	return ret;
}

NTSTATUS smb_krb5_fill_keytab_gmsa_keys(TALLOC_CTX *mem_ctx,
					struct smb_krb5_context *smb_krb5_context,
					krb5_keytab keytab,
					krb5_principal principal,
					struct ldb_context *samdb,
					struct ldb_dn *dn,
					bool include_historic_keys,
					const char **error_string)
{
	const char *gmsa_attrs[] = {
		"msDS-ManagedPassword",
		"msDS-KeyVersionNumber",
		"sAMAccountName",
		"msDS-SupportedEncryptionTypes",
		NULL
	};

	NTSTATUS status;
	struct ldb_message *msg;
	const struct ldb_val *managed_password_blob;
	const char *managed_pw_utf8;
	const char *previous_managed_pw_utf8;
	const char *username;
	const char *salt_principal;
	uint32_t kvno = 0;
	uint32_t supported_enctypes = 0;
	krb5_context context = smb_krb5_context->krb5_context;
	struct cli_credentials *cred = NULL;
	const char *realm = NULL;

	/*
	 * Search for msDS-ManagedPassword (and other attributes to
	 * avoid a race) as this was not in the original search.
	 */
	int ret;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_search_one(samdb,
			      tmp_ctx,
			      &msg,
			      dn,
			      LDB_SCOPE_BASE,
			      gmsa_attrs, 0,
			      "(objectClass=msDS-GroupManagedServiceAccount)");

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/*
		 * Race condition, object has gone, or just wasn't a
		 * gMSA
		 */
		*error_string = talloc_asprintf(mem_ctx,
						"Did not find gMSA at %s",
						ldb_dn_get_linearized(dn));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (ret != LDB_SUCCESS) {
		*error_string = talloc_asprintf(mem_ctx,
						"Error looking for gMSA at %s: %s",
						ldb_dn_get_linearized(dn), ldb_errstring(samdb));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Extract out passwords */
	managed_password_blob = ldb_msg_find_ldb_val(msg, "msDS-ManagedPassword");

	if (managed_password_blob == NULL) {
		/*
		 * No password set on this yet or not readable by this user
		 */
		*error_string = talloc_asprintf(mem_ctx,
						"Did not find msDS-ManagedPassword at %s",
						ldb_dn_get_extended_linearized(mem_ctx, msg->dn, 1));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_USER_KEYS;
	}

	cred = cli_credentials_init(tmp_ctx);
	if (cred == NULL) {
		*error_string = talloc_asprintf(mem_ctx,
						"Could not allocate cli_credentials for %s",
						ldb_dn_get_linearized(msg->dn));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	realm = smb_krb5_principal_get_realm(tmp_ctx,
					     context,
					     principal);
	if (realm == NULL) {
		*error_string = talloc_asprintf(mem_ctx,
						"Could not allocate copy of realm for %s",
						ldb_dn_get_linearized(msg->dn));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_set_realm(cred, realm, CRED_SPECIFIED);

	username = ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL);
	if (username == NULL) {
		*error_string = talloc_asprintf(mem_ctx,
						"No sAMAccountName on %s",
						ldb_dn_get_linearized(msg->dn));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_INVALID_ACCOUNT_NAME;
	}

	cli_credentials_set_username(cred, username, CRED_SPECIFIED);

	/*
	 * Note that this value may not be correct, it is updated
	 * after the query that gives us the passwords
	 */
	kvno = ldb_msg_find_attr_as_uint(msg, "msDS-KeyVersionNumber", 0);

	cli_credentials_set_kvno(cred, kvno);

	supported_enctypes = ldb_msg_find_attr_as_uint(msg,
						       "msDS-SupportedEncryptionTypes",
						       ENC_STRONG_SALTED_TYPES);
	/*
	 * We trim this down to just the salted AES types, as the
	 * passwords are now wrong for rc4-hmac due to the mapping of
	 * invalid sequences in UTF16_MUNGED -> UTF8 string conversion
	 * within cli_credentials_get_password(). Users using this new
	 * feature won't be using such weak crypto anyway.  If
	 * required we could also set the NT Hash as a key directly,
	 * this is just a limitation of smb_krb5_fill_keytab() taking
	 * a simple string as input.
	 */
	supported_enctypes &= ENC_STRONG_SALTED_TYPES;

	/* Update the keytab */

	status = cli_credentials_set_gmsa_passwords(cred,
						    managed_password_blob,
						    true /* for keytab */,
						    error_string);

	if (!NT_STATUS_IS_OK(status)) {
		*error_string = talloc_asprintf(mem_ctx,
						"Could not parse gMSA passwords on %s: %s",
						ldb_dn_get_linearized(msg->dn),
						*error_string);
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	managed_pw_utf8 = cli_credentials_get_password(cred);

	previous_managed_pw_utf8 = cli_credentials_get_old_password(cred);

	salt_principal = cli_credentials_get_salt_principal(cred, tmp_ctx);
	if (salt_principal == NULL) {
		*error_string = talloc_asprintf(mem_ctx,
						"Failed to generate salt principal for %s",
						ldb_dn_get_linearized(msg->dn));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ret = smb_krb5_fill_keytab(tmp_ctx,
				   salt_principal,
				   kvno,
				   managed_pw_utf8,
				   previous_managed_pw_utf8,
				   supported_enctypes,
				   1,
				   &principal,
				   context,
				   keytab,
				   include_historic_keys,
				   error_string);
	if (ret) {
		*error_string = talloc_asprintf(mem_ctx,
						"Failed to add keys from %s to keytab: %s",
						ldb_dn_get_linearized(msg->dn),
						*error_string);
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

/**
 * @brief Update a Kerberos keytab and removes any obsolete keytab entries.
 *
 * If the keytab does not exist, this function will create one.
 *
 * @param[in] parent_ctx	Talloc memory context
 * @param[in] context		Kerberos context
 * @param[in] keytab_name	Keytab to open
 * @param[in] samAccountName	User account to update
 * @param[in] realm		Kerberos realm
 * @param[in] SPNs		Service principal names to update
 * @param[in] num_SPNs		Length of SPNs
 * @param[in] saltPrincipal	Salt used for AES encryption.
 * 				Required, unless delete_all_kvno is set.
 * @param[in] new_secret	New password
 * @param[in] old_secret	Old password
 * @param[in] kvno		Current key version number
 * @param[in] supp_enctypes	msDS-SupportedEncryptionTypes bit-field
 * @param[in] delete_all_kvno	Removes all obsolete entries, without
 * 				recreating the keytab.
 * @param[out] _keytab		If supplied, returns the keytab
 * @param[out] perror_string	Error string on failure
 *
 * @return			0 on success, errno on failure
 */
krb5_error_code smb_krb5_update_keytab(TALLOC_CTX *parent_ctx,
				krb5_context context,
				const char *keytab_name,
				const char *samAccountName,
				const char *realm,
				const char **SPNs,
				int num_SPNs,
				const char *saltPrincipal,
				const char *new_secret,
				const char *old_secret,
				int kvno,
				uint32_t supp_enctypes,
				bool delete_all_kvno,
			        krb5_keytab *_keytab,
				const char **perror_string)
{
	krb5_keytab keytab = NULL;
	krb5_error_code ret;
	bool found_previous = false;
	TALLOC_CTX *tmp_ctx = NULL;
	krb5_principal *principals = NULL;
	uint32_t num_principals = 0;
	char *upper_realm;
	const char *error_string = NULL;

	if (keytab_name == NULL) {
		return ENOENT;
	}

	ret = krb5_kt_resolve(context, keytab_name, &keytab);
	if (ret) {
		*perror_string = smb_get_krb5_error_message(context,
							   ret, parent_ctx);
		return ret;
	}

	DEBUG(5, ("Opened keytab %s\n", keytab_name));

	tmp_ctx = talloc_new(parent_ctx);
	if (!tmp_ctx) {
		*perror_string = talloc_strdup(parent_ctx,
					      "Failed to allocate memory context");
		ret = ENOMEM;
		goto done;
	}

	upper_realm = strupper_talloc(tmp_ctx, realm);
	if (upper_realm == NULL) {
		*perror_string = talloc_strdup(parent_ctx,
					      "Cannot allocate memory to upper case realm");
		ret = ENOMEM;
		goto done;
	}

	ret = smb_krb5_create_principals_array(tmp_ctx,
					       context,
					       samAccountName,
					       upper_realm,
					       num_SPNs,
					       SPNs,
					       &num_principals,
					       &principals,
					       &error_string);
	if (ret != 0) {
		*perror_string = talloc_asprintf(parent_ctx,
			"Failed to load principals from ldb message: %s\n",
			error_string);
		goto done;
	}

	ret = smb_krb5_remove_obsolete_keytab_entries(tmp_ctx,
						      context,
						      keytab,
						      num_principals,
						      principals,
						      kvno,
						      &found_previous,
						      &error_string);
	if (ret != 0) {
		*perror_string = talloc_asprintf(parent_ctx,
			"Failed to remove old principals from keytab: %s\n",
			error_string);
		goto done;
	}

	if (!delete_all_kvno) {
		/* Create a new keytab.  If during the cleanout we found
		 * entries for kvno -1, then don't try and duplicate them.
		 * Otherwise, add kvno, and kvno -1 */
		if (saltPrincipal == NULL) {
			*perror_string = talloc_strdup(parent_ctx,
						       "No saltPrincipal provided");
			ret = EINVAL;
			goto done;
		}

		ret = smb_krb5_fill_keytab(tmp_ctx,
				    saltPrincipal,
				    kvno, new_secret, old_secret,
				    supp_enctypes,
				    num_principals,
				    principals,
				    context, keytab,
				    found_previous ? false : true,
				    &error_string);
		if (ret) {
			*perror_string = talloc_steal(parent_ctx, error_string);
		}
	}

	if (ret == 0 && _keytab != NULL) {
		/* caller wants the keytab handle back */
		*_keytab = keytab;
	}

done:
	keytab_principals_free(context, num_principals, principals);
	if (ret != 0 || _keytab == NULL) {
		krb5_kt_close(context, keytab);
	}
	talloc_free(tmp_ctx);
	return ret;
}

/**
 * @brief Wrapper around smb_krb5_update_keytab() for creating an in-memory keytab
 *
 * @param[in] parent_ctx	Talloc memory context
 * @param[in] context		Kerberos context
 * @param[in] new_secret	New password
 * @param[in] samAccountName	User account to update
 * @param[in] realm		Kerberos realm
 * @param[in] salt_principal	Salt used for AES encryption.
 * 				Required, unless delete_all_kvno is set.
 * @param[in] kvno		Current key version number
 * @param[out] keytab		If supplied, returns the keytab
 * @param[out] keytab_name	Returns the created keytab name
 *
 * @return			0 on success, errno on failure
 */
krb5_error_code smb_krb5_create_memory_keytab(TALLOC_CTX *parent_ctx,
				krb5_context context,
				const char *new_secret,
				const char *samAccountName,
				const char *realm,
				const char *salt_principal,
				int kvno,
				krb5_keytab *keytab,
				const char **keytab_name)
{
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	const char *rand_string;
	const char *error_string = NULL;
	if (!mem_ctx) {
		return ENOMEM;
	}

	rand_string = generate_random_str(mem_ctx, 16);
	if (!rand_string) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	*keytab_name = talloc_asprintf(mem_ctx, "MEMORY:%s", rand_string);
	if (*keytab_name == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	ret = smb_krb5_update_keytab(mem_ctx, context,
				     *keytab_name, samAccountName, realm,
				     NULL, 0, salt_principal, new_secret, NULL,
				     kvno, ENC_ALL_TYPES,
				     false, keytab, &error_string);
	if (ret == 0) {
		talloc_steal(parent_ctx, *keytab_name);
	} else {
		DEBUG(0, ("Failed to create in-memory keytab: %s\n",
			  error_string));
		*keytab_name = NULL;
	}
	talloc_free(mem_ctx);
	return ret;
}
