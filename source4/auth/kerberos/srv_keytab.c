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


#include "includes.h"
#include "system/kerberos.h"
#include "auth/credentials/credentials.h"
#include "auth/kerberos/kerberos.h"
#include "auth/kerberos/kerberos_util.h"
#include "auth/kerberos/kerberos_srv_keytab.h"

static void keytab_principals_free(krb5_context context,
				   uint32_t num_principals,
				   krb5_principal *set)
{
	uint32_t i;

	for (i = 0; i < num_principals; i++) {
		krb5_free_principal(context, set[i]);
	}
}

static krb5_error_code salt_principal(TALLOC_CTX *parent_ctx,
				const char *samAccountName,
				const char *realm,
				const char *saltPrincipal,
				krb5_context context,
				krb5_principal *salt_princ,
				const char **error_string)
{

	krb5_error_code ret;
	char *machine_username;
	char *salt_body;
	char *lower_realm;
	char *upper_realm;

	TALLOC_CTX *tmp_ctx;

	if (saltPrincipal) {
		ret = krb5_parse_name(context, saltPrincipal, salt_princ);
		if (ret) {
			*error_string = smb_get_krb5_error_message(
						context, ret, parent_ctx);
		}
		return ret;
	}

	if (!samAccountName) {
		(*error_string) = "Cannot determine salt principal, no "
				"saltPrincipal or samAccountName specified";
		return EINVAL;
	}

	if (!realm) {
		*error_string = "Cannot make principal without a realm";
		return EINVAL;
	}

	tmp_ctx = talloc_new(parent_ctx);
	if (!tmp_ctx) {
		*error_string = "Cannot allocate tmp_ctx";
		return ENOMEM;
	}

	machine_username = strlower_talloc(tmp_ctx, samAccountName);
	if (!machine_username) {
		*error_string = "Cannot duplicate samAccountName";
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	if (machine_username[strlen(machine_username)-1] == '$') {
		machine_username[strlen(machine_username)-1] = '\0';
	}

	lower_realm = strlower_talloc(tmp_ctx, realm);
	if (!lower_realm) {
		*error_string = "Cannot allocate to lower case realm";
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	upper_realm = strupper_talloc(tmp_ctx, realm);
	if (!upper_realm) {
		*error_string = "Cannot allocate to upper case realm";
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	salt_body = talloc_asprintf(tmp_ctx, "%s.%s",
				    machine_username, lower_realm);
	if (!salt_body) {
		*error_string = "Cannot form salt principal body";
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	ret = smb_krb5_make_principal(context, salt_princ, upper_realm,
						"host", salt_body, NULL);
	if (ret) {
		*error_string = smb_get_krb5_error_message(context,
							   ret, parent_ctx);
	}

	talloc_free(tmp_ctx);
	return ret;
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
			return ret;
		}

                entry.vno = kvno;

		for (p = 0; p < num_principals; p++) {
			unparsed = NULL;
			entry.principal = principals[p];
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

static krb5_error_code create_keytab(TALLOC_CTX *parent_ctx,
				     const char *samAccountName,
				     const char *realm,
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
				     const char **error_string)
{
	krb5_error_code ret;
	krb5_principal salt_princ = NULL;
	krb5_enctype *enctypes;
	TALLOC_CTX *mem_ctx;

	if (!new_secret) {
		/* There is no password here, so nothing to do */
		return 0;
	}

	mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		*error_string = talloc_strdup(parent_ctx,
			"unable to allocate tmp_ctx for create_keytab");
		return ENOMEM;
	}

	/* The salt used to generate these entries may be different however,
	 * fetch that */
	ret = salt_principal(mem_ctx, samAccountName, realm, saltPrincipal,
			     context, &salt_princ, error_string);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = ms_suptypes_to_ietf_enctypes(mem_ctx, supp_enctypes, &enctypes);
	if (ret) {
		*error_string = talloc_asprintf(parent_ctx,
					"create_keytab: generating list of "
					"encryption types failed (%s)\n",
					smb_get_krb5_error_message(context,
								ret, mem_ctx));
		goto done;
	}

	ret = keytab_add_keys(mem_ctx,
			      num_principals,
			      principals,
			      salt_princ, kvno, new_secret,
			      context, enctypes, keytab, error_string);
	if (ret) {
		talloc_steal(parent_ctx, *error_string);
		goto done;
	}

	if (old_secret && add_old && kvno != 0) {
		ret = keytab_add_keys(mem_ctx,
				      num_principals,
				      principals,
				      salt_princ, kvno - 1, old_secret,
				      context, enctypes, keytab, error_string);
		if (ret) {
			talloc_steal(parent_ctx, *error_string);
		}
	}

done:
	krb5_free_principal(context, salt_princ);
	talloc_free(mem_ctx);
	return ret;
}

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
				const char **error_string)
{
	krb5_keytab keytab;
	krb5_error_code ret;
	bool found_previous = false;
	TALLOC_CTX *tmp_ctx;
	krb5_principal *principals = NULL;
	uint32_t num_principals = 0;
	char *upper_realm;

	if (keytab_name == NULL) {
		return ENOENT;
	}

	ret = krb5_kt_resolve(context, keytab_name, &keytab);
	if (ret) {
		*error_string = smb_get_krb5_error_message(context,
							   ret, parent_ctx);
		return ret;
	}

	DEBUG(5, ("Opened keytab %s\n", keytab_name));

	tmp_ctx = talloc_new(parent_ctx);
	if (!tmp_ctx) {
		return ENOMEM;
	}

	upper_realm = strupper_talloc(tmp_ctx, realm);
	if (upper_realm == NULL) {
		*error_string = "Cannot allocate memory to upper case realm";
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	ret = smb_krb5_create_principals_array(tmp_ctx,
					       context,
					       samAccountName,
					       upper_realm,
					       num_SPNs,
					       SPNs,
					       &num_principals,
					       &principals,
					       error_string);
	if (ret != 0) {
		*error_string = talloc_asprintf(parent_ctx,
			"Failed to load principals from ldb message: %s\n",
			*error_string);
		goto done;
	}

	ret = smb_krb5_remove_obsolete_keytab_entries(tmp_ctx,
						      context,
						      keytab,
						      num_principals,
						      principals,
						      kvno,
						      &found_previous,
						      error_string);
	if (ret != 0) {
		*error_string = talloc_asprintf(parent_ctx,
			"Failed to remove old principals from keytab: %s\n",
			*error_string);
		goto done;
	}

	if (!delete_all_kvno) {
		/* Create a new keytab.  If during the cleanout we found
		 * entires for kvno -1, then don't try and duplicate them.
		 * Otherwise, add kvno, and kvno -1 */

		ret = create_keytab(tmp_ctx,
				    samAccountName, upper_realm, saltPrincipal,
				    kvno, new_secret, old_secret,
				    supp_enctypes,
				    num_principals,
				    principals,
				    context, keytab,
				    found_previous ? false : true,
				    error_string);
		if (ret) {
			talloc_steal(parent_ctx, *error_string);
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

krb5_error_code smb_krb5_create_memory_keytab(TALLOC_CTX *parent_ctx,
				krb5_context context,
				const char *new_secret,
				const char *samAccountName,
				const char *realm,
				int kvno,
				krb5_keytab *keytab,
				const char **keytab_name)
{
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	const char *rand_string;
	const char *error_string;
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
				     NULL, 0, NULL, new_secret, NULL,
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
