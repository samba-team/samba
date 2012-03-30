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
#include "auth/credentials/credentials.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "auth/kerberos/kerberos_srv_keytab.h"
#include "auth/kerberos/kerberos_util.h"
#include <ldb.h>
#include "param/secrets.h"

static krb5_error_code principals_from_msg(TALLOC_CTX *parent_ctx,
			struct ldb_message *msg,
			struct smb_krb5_context *smb_krb5_context,
			struct principal_container ***principals_out,
			const char **error_string)
{
	unsigned int i;
	krb5_error_code ret;
	char *upper_realm;
	const char *realm = ldb_msg_find_attr_as_string(msg, "realm", NULL);
	const char *samAccountName = ldb_msg_find_attr_as_string(msg,
						"samAccountName", NULL);
	struct ldb_message_element *spn_el = ldb_msg_find_element(msg,
						"servicePrincipalName");
	TALLOC_CTX *tmp_ctx;
	struct principal_container **principals;
	tmp_ctx = talloc_new(parent_ctx);
	if (!tmp_ctx) {
		*error_string = "Cannot allocate tmp_ctx";
		return ENOMEM;
	}

	if (!realm) {
		*error_string = "Cannot have a kerberos secret in "
				"secrets.ldb without a realm";
		return EINVAL;
	}

	upper_realm = strupper_talloc(tmp_ctx, realm);
	if (!upper_realm) {
		talloc_free(tmp_ctx);
		*error_string = "Cannot allocate full upper case realm";
		return ENOMEM;
	}

	principals = talloc_array(tmp_ctx, struct principal_container *,
				  spn_el ? (spn_el->num_values + 2) : 2);

	spn_el = ldb_msg_find_element(msg, "servicePrincipalName");
	for (i=0; spn_el && i < spn_el->num_values; i++) {
		principals[i] = talloc(principals, struct principal_container);
		if (!principals[i]) {
			talloc_free(tmp_ctx);
			*error_string = "Cannot allocate mem_ctx";
			return ENOMEM;
		}

		principals[i]->smb_krb5_context =
			talloc_reference(principals[i], smb_krb5_context);
		principals[i]->string_form =
			talloc_asprintf(principals[i], "%*.*s@%s",
					(int)spn_el->values[i].length,
					(int)spn_el->values[i].length,
					(const char *)spn_el->values[i].data,
					upper_realm);
		if (!principals[i]->string_form) {
			talloc_free(tmp_ctx);
			*error_string = "Cannot allocate full samAccountName";
			return ENOMEM;
		}

		ret = krb5_parse_name(smb_krb5_context->krb5_context,
				      principals[i]->string_form,
				      &principals[i]->principal);

		if (ret) {
			talloc_free(tmp_ctx);
			(*error_string) = smb_get_krb5_error_message(
						smb_krb5_context->krb5_context,
						ret, parent_ctx);
			return ret;
		}

		/* This song-and-dance effectivly puts the principal
		 * into talloc, so we can't loose it. */
		talloc_set_destructor(principals[i], free_principal);
	}

	if (samAccountName) {
		principals[i] = talloc(principals, struct principal_container);
		if (!principals[i]) {
			talloc_free(tmp_ctx);
			*error_string = "Cannot allocate mem_ctx";
			return ENOMEM;
		}

		principals[i]->smb_krb5_context =
			talloc_reference(principals[i], smb_krb5_context);
		principals[i]->string_form =
			talloc_asprintf(parent_ctx, "%s@%s",
					samAccountName, upper_realm);
		if (!principals[i]->string_form) {
			talloc_free(tmp_ctx);
			*error_string = "Cannot allocate full samAccountName";
			return ENOMEM;
		}

		ret = krb5_make_principal(smb_krb5_context->krb5_context,
					  &principals[i]->principal,
					  upper_realm, samAccountName,
					  NULL);
		if (ret) {
			talloc_free(tmp_ctx);
			(*error_string) = smb_get_krb5_error_message(
						smb_krb5_context->krb5_context,
						ret, parent_ctx);
			return ret;
		}

		/* This song-and-dance effectively puts the principal
		 * into talloc, so we can't loose it. */
		talloc_set_destructor(principals[i], free_principal);
		i++;
	}

	principals[i] = NULL;
	*principals_out = talloc_steal(parent_ctx, principals);

	talloc_free(tmp_ctx);
	return ret;
}

static krb5_error_code salt_principal_from_msg(TALLOC_CTX *parent_ctx,
				struct ldb_message *msg,
				struct smb_krb5_context *smb_krb5_context,
				krb5_principal *salt_princ,
				const char **error_string)
{
	const char *salt_principal = ldb_msg_find_attr_as_string(msg,
						"saltPrincipal", NULL);
	const char *samAccountName = ldb_msg_find_attr_as_string(msg,
						"samAccountName", NULL);
	const char *realm = ldb_msg_find_attr_as_string(msg, "realm", NULL);

	struct principal_container *mem_ctx;
	krb5_error_code ret;
	char *machine_username;
	char *salt_body;
	char *lower_realm;
	char *upper_realm;

	TALLOC_CTX *tmp_ctx;

	if (salt_principal) {
		return parse_principal(parent_ctx, salt_principal,
					smb_krb5_context, salt_princ,
					error_string);
	}

	if (!samAccountName) {
		(*error_string) = "Cannot determine salt principal, no "
				"saltPrincipal or samAccountName specified";
		return EINVAL;
	}


	mem_ctx = talloc(parent_ctx, struct principal_container);
	if (!mem_ctx) {
		*error_string = "Cannot allocate mem_ctx";
		return ENOMEM;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		talloc_free(mem_ctx);
		*error_string = "Cannot allocate tmp_ctx";
		return ENOMEM;
	}

	if (!realm) {
		*error_string = "Cannot have a kerberos secret in "
				"secrets.ldb without a realm";
		return EINVAL;
	}

	machine_username = talloc_strdup(tmp_ctx, samAccountName);
	if (!machine_username) {
		talloc_free(mem_ctx);
		*error_string = "Cannot duplicate samAccountName";
		return ENOMEM;
	}

	if (machine_username[strlen(machine_username)-1] == '$') {
		machine_username[strlen(machine_username)-1] = '\0';
	}

	lower_realm = strlower_talloc(tmp_ctx, realm);
	if (!lower_realm) {
		talloc_free(mem_ctx);
		*error_string = "Cannot allocate to lower case realm";
		return ENOMEM;
	}

	upper_realm = strupper_talloc(tmp_ctx, realm);
	if (!upper_realm) {
		talloc_free(mem_ctx);
		*error_string = "Cannot allocate to upper case realm";
		return ENOMEM;
	}

	salt_body = talloc_asprintf(tmp_ctx, "%s.%s", machine_username,
				    lower_realm);
	talloc_free(lower_realm);
	talloc_free(machine_username);
	if (!salt_body) {
		talloc_free(mem_ctx);
		*error_string = "Cannot form salt principal body";
		return ENOMEM;
	}

	ret = krb5_make_principal(smb_krb5_context->krb5_context, salt_princ,
				  upper_realm,
				  "host", salt_body, NULL);
	if (ret == 0) {
		/* This song-and-dance effectively puts the principal
		 * into talloc, so we can't loose it. */
		mem_ctx->smb_krb5_context = talloc_reference(mem_ctx,
							smb_krb5_context);
		mem_ctx->principal = *salt_princ;
		talloc_set_destructor(mem_ctx, free_principal);
	} else {
		(*error_string) = smb_get_krb5_error_message(
					smb_krb5_context->krb5_context,
					ret, parent_ctx);
	}
	talloc_free(tmp_ctx);
	return ret;
}

/* Translate between the Microsoft msDS-SupportedEncryptionTypes values
 * and the IETF encryption type values */
static krb5_enctype ms_suptype_to_ietf_enctype(uint32_t enctype_bitmap)
{
	switch (enctype_bitmap) {
	case ENC_CRC32:
		return ENCTYPE_DES_CBC_CRC;
	case ENC_RSA_MD5:
		return ENCTYPE_DES_CBC_MD5;
	case ENC_RC4_HMAC_MD5:
		return ENCTYPE_ARCFOUR_HMAC_MD5;
	case ENC_HMAC_SHA1_96_AES128:
		return ENCTYPE_AES128_CTS_HMAC_SHA1_96;
	case ENC_HMAC_SHA1_96_AES256:
		return ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	default:
		return 0;
	}
}

/* Return an array of krb5_enctype values */
static krb5_error_code ms_suptypes_to_ietf_enctypes(TALLOC_CTX *mem_ctx,
						uint32_t enctype_bitmap,
						krb5_enctype **enctypes)
{
	unsigned int i, j = 0;
	*enctypes = talloc_zero_array(mem_ctx, krb5_enctype,
					(8 * sizeof(enctype_bitmap)) + 1);
	if (!*enctypes) {
		return ENOMEM;
	}
	for (i = 0; i < (8 * sizeof(enctype_bitmap)); i++) {
		uint32_t bit_value = (1 << i) & enctype_bitmap;
		if (bit_value & enctype_bitmap) {
			(*enctypes)[j] = ms_suptype_to_ietf_enctype(bit_value);
			if (!(*enctypes)[j]) {
				continue;
			}
			j++;
		}
	}
	(*enctypes)[j] = 0;
	return 0;
}

static krb5_error_code keytab_add_keys(TALLOC_CTX *parent_ctx,
				       struct principal_container **principals,
				       krb5_principal salt_princ,
				       int kvno,
				       const char *password_s,
				       krb5_context krb5_context,
				       krb5_enctype *enctypes,
				       krb5_keytab keytab,
				       const char **error_string)
{
	unsigned int i, p;
	krb5_error_code ret;
	krb5_data password;

	password.data = discard_const_p(char *, password_s);
	password.length = strlen(password_s);

	for (i = 0; enctypes[i]; i++) {
		krb5_keytab_entry entry;

		ZERO_STRUCT(entry);

		ret = create_kerberos_key_from_string_direct(krb5_context,
						salt_princ, &password,
						&entry.keyblock, enctypes[i]);
		if (ret != 0) {
			return ret;
		}

                entry.vno = kvno;

		for (p = 0; principals[p]; p++) {
			entry.principal = principals[p]->principal;
			ret = krb5_kt_add_entry(krb5_context,
						keytab, &entry);
			if (ret != 0) {
				char *k5_error_string =
					smb_get_krb5_error_message(
						krb5_context, ret, NULL);
				*error_string = talloc_asprintf(parent_ctx,
					"Failed to add enctype %d entry for "
					"%s(kvno %d) to keytab: %s\n",
					(int)enctypes[i],
					principals[p]->string_form,
					kvno, k5_error_string);

				talloc_free(k5_error_string);
				krb5_free_keyblock_contents(krb5_context,
							    &entry.keyblock);
				return ret;
			}

			DEBUG(5, ("Added %s(kvno %d) to keytab (enctype %d)\n",
				  principals[p]->string_form, kvno,
				  (int)enctypes[i]));
		}
		krb5_free_keyblock_contents(krb5_context, &entry.keyblock);
	}
	return 0;
}

static krb5_error_code create_keytab(TALLOC_CTX *parent_ctx,
				     struct ldb_message *msg,
				     struct principal_container **principals,
				     struct smb_krb5_context *smb_krb5_context,
				     krb5_keytab keytab,
				     bool add_old,
				     const char **error_string)
{
	krb5_error_code ret;
	const char *password_s;
	const char *old_secret;
	int kvno;
	uint32_t enctype_bitmap;
	krb5_principal salt_princ;
	krb5_enctype *enctypes;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		*error_string = "unable to allocate tmp_ctx for create_keytab";
		return ENOMEM;
	}

	/* The salt used to generate these entries may be different however,
	 * fetch that */
	ret = salt_principal_from_msg(mem_ctx, msg,
				      smb_krb5_context,
				      &salt_princ, error_string);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	kvno = ldb_msg_find_attr_as_int(msg, "msDS-KeyVersionNumber", 0);

	/* Finally, do the dance to get the password to put in the entry */
	password_s =  ldb_msg_find_attr_as_string(msg, "secret", NULL);

	if (!password_s) {
		/* There is no password here, so nothing to do */
		talloc_free(mem_ctx);
		return 0;
	}

	if (add_old && kvno != 0) {
		old_secret = ldb_msg_find_attr_as_string(msg,
							"priorSecret", NULL);
	} else {
		old_secret = NULL;
	}

	enctype_bitmap = (uint32_t)ldb_msg_find_attr_as_int(msg,
					"msDS-SupportedEncryptionTypes",
					ENC_ALL_TYPES);

	ret = ms_suptypes_to_ietf_enctypes(mem_ctx, enctype_bitmap, &enctypes);
	if (ret) {
		*error_string = talloc_asprintf(parent_ctx,
					"create_keytab: generating list of "
					"encryption types failed (%s)\n",
					smb_get_krb5_error_message(
						smb_krb5_context->krb5_context,
						ret, mem_ctx));
		talloc_free(mem_ctx);
		return ret;
	}

	ret = keytab_add_keys(mem_ctx, principals,
			      salt_princ, kvno, password_s,
			      smb_krb5_context->krb5_context,
			      enctypes, keytab, error_string);
	if (ret) {
		talloc_free(mem_ctx);
		return ret;
	}

	if (old_secret) {
		ret = keytab_add_keys(mem_ctx, principals,
				      salt_princ, kvno - 1, old_secret,
				      smb_krb5_context->krb5_context,
				      enctypes, keytab, error_string);
		if (ret) {
			talloc_free(mem_ctx);
			return ret;
		}
	}

	talloc_free(mem_ctx);
	return ret;
}

/*
 * Walk the keytab, looking for entries of this principal name,
 * with KVNO other than current kvno -1.
 *
 * These entries are now stale,
 * we only keep the current and previous entries around.
 *
 * Inspired by the code in Samba3 for 'use kerberos keytab'.
 */

static krb5_error_code remove_old_entries(TALLOC_CTX *parent_ctx,
					  struct ldb_message *msg,
					  struct principal_container **principals,
					  bool delete_all_kvno,
					  krb5_context krb5_context,
					  krb5_keytab keytab,
					  bool *found_previous,
					  const char **error_string)
{
	krb5_error_code ret, ret2;
	krb5_kt_cursor cursor;
	int kvno;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);

	if (!mem_ctx) {
		return ENOMEM;
	}

	*found_previous = false;

	kvno = ldb_msg_find_attr_as_int(msg, "msDS-KeyVersionNumber", 0);

	/* for each entry in the keytab */
	ret = krb5_kt_start_seq_get(krb5_context, keytab, &cursor);
	switch (ret) {
	case 0:
		break;
	case HEIM_ERR_OPNOTSUPP:
	case ENOENT:
	case KRB5_KT_END:
		/* no point enumerating if there isn't anything here */
		talloc_free(mem_ctx);
		return 0;
	default:
		*error_string = talloc_asprintf(parent_ctx,
			"failed to open keytab for read of old entries: %s\n",
			smb_get_krb5_error_message(krb5_context,
						   ret, mem_ctx));
		talloc_free(mem_ctx);
		return ret;
	}

	while (!ret) {
		unsigned int i;
		bool matched = false;
		krb5_keytab_entry entry;
		ret = krb5_kt_next_entry(krb5_context, keytab,
					 &entry, &cursor);
		if (ret) {
			break;
		}
		for (i = 0; principals[i]; i++) {
			/* if it matches our principal */
			if (krb5_kt_compare(krb5_context, &entry,
					    principals[i]->principal, 0, 0)) {
				matched = true;
				break;
			}
		}

		if (!matched) {
			/* Free the entry,
			 * it wasn't the one we were looking for anyway */
			krb5_kt_free_entry(krb5_context, &entry);
			continue;
		}

		/* delete it, if it is not kvno -1 */
		if (entry.vno != (kvno - 1 )) {
			/* Release the enumeration.  We are going to
			 * have to start this from the top again,
			 * because deletes during enumeration may not
			 * always be consistent.
			 *
			 * Also, the enumeration locks a FILE: keytab
			 */

			krb5_kt_end_seq_get(krb5_context, keytab, &cursor);

			ret = krb5_kt_remove_entry(krb5_context, keytab, &entry);
			krb5_kt_free_entry(krb5_context, &entry);

			/* Deleted: Restart from the top */
			ret2 = krb5_kt_start_seq_get(krb5_context,
						     keytab, &cursor);
			if (ret2) {
				krb5_kt_free_entry(krb5_context, &entry);
				DEBUG(1, ("failed to restart enumeration of keytab: %s\n",
					  smb_get_krb5_error_message(krb5_context,
								    ret, mem_ctx)));

				talloc_free(mem_ctx);
				return ret2;
			}

			if (ret) {
				break;
			}

		} else {
			*found_previous = true;
		}

		/* Free the entry, we don't need it any more */
		krb5_kt_free_entry(krb5_context, &entry);
	}
	krb5_kt_end_seq_get(krb5_context, keytab, &cursor);

	switch (ret) {
	case 0:
		break;
	case ENOENT:
	case KRB5_KT_END:
		ret = 0;
		break;
	default:
		*error_string = talloc_asprintf(parent_ctx,
			"failed in deleting old entries for principal: %s\n",
			smb_get_krb5_error_message(krb5_context,
						   ret, mem_ctx));
	}
	talloc_free(mem_ctx);
	return ret;
}

krb5_error_code smb_krb5_update_keytab(TALLOC_CTX *parent_ctx,
				       struct smb_krb5_context *smb_krb5_context,
				       struct ldb_context *ldb,
				       struct ldb_message *msg,
				       bool delete_all_kvno,
				       const char **error_string)
{
	krb5_error_code ret;
	bool found_previous;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct keytab_container *keytab_container;
	struct principal_container **principals;
	const char *keytab_name;

	if (!mem_ctx) {
		return ENOMEM;
	}

	keytab_name = keytab_name_from_msg(mem_ctx, ldb, msg);
	if (!keytab_name) {
		return ENOENT;
	}

	ret = smb_krb5_get_keytab_container(mem_ctx, smb_krb5_context,
					keytab_name, &keytab_container);

	if (ret != 0) {
		talloc_free(mem_ctx);
		return ret;
	}

	DEBUG(5, ("Opened keytab %s\n", keytab_name));

	/* Get the principal we will store the new keytab entries under */
	ret = principals_from_msg(mem_ctx, msg, smb_krb5_context,
					&principals, error_string);

	if (ret != 0) {
		*error_string = talloc_asprintf(parent_ctx,
			"Failed to load principals from ldb message: %s\n",
			*error_string);
		talloc_free(mem_ctx);
		return ret;
	}

	ret = remove_old_entries(mem_ctx, msg, principals, delete_all_kvno,
				 smb_krb5_context->krb5_context,
				 keytab_container->keytab,
				 &found_previous, error_string);
	if (ret != 0) {
		*error_string = talloc_asprintf(parent_ctx,
			"Failed to remove old principals from keytab: %s\n",
			*error_string);
		talloc_free(mem_ctx);
		return ret;
	}

	if (!delete_all_kvno) {
		/* Create a new keytab.  If during the cleanout we found
		 * entires for kvno -1, then don't try and duplicate them.
		 * Otherwise, add kvno, and kvno -1 */

		ret = create_keytab(mem_ctx, msg, principals,
				    smb_krb5_context,
				    keytab_container->keytab,
				    found_previous ? false : true,
				    error_string);
	}
	talloc_free(mem_ctx);
	return ret;
}

krb5_error_code smb_krb5_create_memory_keytab(TALLOC_CTX *parent_ctx,
				struct cli_credentials *machine_account,
				struct smb_krb5_context *smb_krb5_context,
				struct keytab_container **keytab_container)
{
	krb5_error_code ret;
	TALLOC_CTX *mem_ctx = talloc_new(parent_ctx);
	const char *rand_string;
	const char *keytab_name;
	struct ldb_message *msg;
	const char *error_string;
	if (!mem_ctx) {
		return ENOMEM;
	}

	*keytab_container = talloc(mem_ctx, struct keytab_container);

	rand_string = generate_random_str(mem_ctx, 16);
	if (!rand_string) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	keytab_name = talloc_asprintf(mem_ctx, "MEMORY:%s",
				      rand_string);
	if (!keytab_name) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	ret = smb_krb5_get_keytab_container(mem_ctx, smb_krb5_context,
					    keytab_name, keytab_container);
	if (ret) {
		return ret;
	}

	msg = ldb_msg_new(mem_ctx);
	if (!msg) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}
	ldb_msg_add_string(msg, "krb5Keytab", keytab_name);
	ldb_msg_add_string(msg, "secret",
			   cli_credentials_get_password(machine_account));
	ldb_msg_add_string(msg, "samAccountName",
			   cli_credentials_get_username(machine_account));
	ldb_msg_add_string(msg, "realm",
			   cli_credentials_get_realm(machine_account));
	ldb_msg_add_fmt(msg, "msDS-KeyVersionNumber", "%d",
			   (int)cli_credentials_get_kvno(machine_account));

	ret = smb_krb5_update_keytab(mem_ctx, smb_krb5_context, NULL,
				     msg, false, &error_string);
	if (ret == 0) {
		talloc_steal(parent_ctx, *keytab_container);
	} else {
		DEBUG(0, ("Failed to create in-memory keytab: %s\n",
			  error_string));
		*keytab_container = NULL;
	}
	talloc_free(mem_ctx);
	return ret;
}
