/*
   Unix SMB/CIFS implementation.

   Samba KDB plugin for MIT Kerberos

   Copyright (c) 2010      Simo Sorce <idra@samba.org>.
   Copyright (c) 2014      Andreas Schneider <asn@samba.org>

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

#include <profile.h>
#include <kdb.h>

#include "kdc/mit_samba.h"
#include "kdb_samba.h"

#define ADMIN_LIFETIME 60*60*3 /* 3 hours */
#define CHANGEPW_LIFETIME 60*5 /* 5 minutes */

krb5_error_code ks_get_principal(krb5_context context,
				 krb5_const_principal principal,
				 unsigned int kflags,
				 krb5_db_entry **kentry)
{
	struct mit_samba_context *mit_ctx;
	krb5_error_code code;

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return KRB5_KDB_DBNOTINITED;
	}

	code = mit_samba_get_principal(mit_ctx,
				       principal,
				       kflags,
				       kentry);
	if (code != 0) {
		goto cleanup;
	}

cleanup:

	return code;
}

static void ks_free_principal_e_data(krb5_context context, krb5_octet *e_data)
{
	struct samba_kdc_entry *skdc_entry;

	skdc_entry = talloc_get_type_abort(e_data,
					   struct samba_kdc_entry);
	talloc_set_destructor(skdc_entry, NULL);
	TALLOC_FREE(skdc_entry);
}

void ks_free_principal(krb5_context context, krb5_db_entry *entry)
{
	krb5_tl_data *tl_data_next = NULL;
	krb5_tl_data *tl_data = NULL;
	size_t i, j;

	if (entry != NULL) {
		krb5_free_principal(context, entry->princ);

		for (tl_data = entry->tl_data; tl_data; tl_data = tl_data_next) {
			tl_data_next = tl_data->tl_data_next;
			if (tl_data->tl_data_contents != NULL) {
				free(tl_data->tl_data_contents);
			}
			free(tl_data);
		}

		if (entry->key_data != NULL) {
			for (i = 0; i < entry->n_key_data; i++) {
				for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
					if (entry->key_data[i].key_data_length[j] != 0) {
						if (entry->key_data[i].key_data_contents[j] != NULL) {
							memset(entry->key_data[i].key_data_contents[j], 0, entry->key_data[i].key_data_length[j]);
							free(entry->key_data[i].key_data_contents[j]);
						}
					}
					entry->key_data[i].key_data_contents[j] = NULL;
					 entry->key_data[i].key_data_length[j] = 0;
					 entry->key_data[i].key_data_type[j] = 0;
				}
			}
			free(entry->key_data);
		}

		if (entry->e_data) {
			ks_free_principal_e_data(context, entry->e_data);
		}

		free(entry);
	}
}

static krb5_boolean ks_is_master_key_principal(krb5_context context,
					       krb5_const_principal princ)
{
	return krb5_princ_size(context, princ) == 2 &&
	       ks_data_eq_string(princ->data[0], "K") &&
	       ks_data_eq_string(princ->data[1], "M");
}

static krb5_error_code ks_get_master_key_principal(krb5_context context,
						   krb5_const_principal princ,
						   krb5_db_entry **kentry_ptr)
{
	krb5_error_code code;
	krb5_key_data *key_data;
	krb5_timestamp now;
	krb5_db_entry *kentry;

	*kentry_ptr = NULL;

	kentry = calloc(1, sizeof(krb5_db_entry));
	if (kentry == NULL) {
		return ENOMEM;
	}

	kentry->magic = KRB5_KDB_MAGIC_NUMBER;
	kentry->len = KRB5_KDB_V1_BASE_LENGTH;
	kentry->attributes = KRB5_KDB_DISALLOW_ALL_TIX;

	if (princ == NULL) {
		code = krb5_parse_name(context, KRB5_KDB_M_NAME, &kentry->princ);
	} else {
		code = krb5_copy_principal(context, princ, &kentry->princ);
	}
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	now = time(NULL);

	code = krb5_dbe_update_mod_princ_data(context, kentry, now, kentry->princ);
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	/* Return a dummy key */
	kentry->n_key_data = 1;
	kentry->key_data = calloc(1, sizeof(krb5_key_data));
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	key_data = &kentry->key_data[0];

	key_data->key_data_ver          = KRB5_KDB_V1_KEY_DATA_ARRAY;
	key_data->key_data_kvno         = 1;
	key_data->key_data_type[0]      = ENCTYPE_UNKNOWN;
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	*kentry_ptr = kentry;

	return 0;
}

static krb5_error_code ks_create_principal(krb5_context context,
					   krb5_const_principal princ,
					   int attributes,
					   int max_life,
					   const char *password,
					   krb5_db_entry **kentry_ptr)
{
	krb5_error_code code;
	krb5_key_data *key_data;
	krb5_timestamp now;
	krb5_db_entry *kentry;
	krb5_keyblock key;
	krb5_data salt;
	krb5_data pwd;
	int enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	int sts = KRB5_KDB_SALTTYPE_SPECIAL;

	if (princ == NULL) {
		return KRB5_KDB_NOENTRY;
	}

	*kentry_ptr = NULL;

	kentry = calloc(1, sizeof(krb5_db_entry));
	if (kentry == NULL) {
		return ENOMEM;
	}

	kentry->magic = KRB5_KDB_MAGIC_NUMBER;
	kentry->len = KRB5_KDB_V1_BASE_LENGTH;

	if (attributes > 0) {
		kentry->attributes = attributes;
	}

	if (max_life > 0) {
		kentry->max_life = max_life;
	}

	code = krb5_copy_principal(context, princ, &kentry->princ);
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	now = time(NULL);

	code = krb5_dbe_update_mod_princ_data(context, kentry, now, kentry->princ);
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	code = mit_samba_generate_salt(&salt);
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	if (password != NULL) {
		pwd.data = strdup(password);
		pwd.length = strlen(password);
	} else {
		/* create a random password */
		code = mit_samba_generate_random_password(&pwd);
		if (code != 0) {
			krb5_db_free_principal(context, kentry);
			return code;
		}
	}

	code = krb5_c_string_to_key(context, enctype, &pwd, &salt, &key);
	SAFE_FREE(pwd.data);
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	kentry->n_key_data = 1;
	kentry->key_data = calloc(1, sizeof(krb5_key_data));
	if (code != 0) {
		krb5_db_free_principal(context, kentry);
		return code;
	}

	key_data = &kentry->key_data[0];

	key_data->key_data_ver          = KRB5_KDB_V1_KEY_DATA_ARRAY;
	key_data->key_data_kvno         = 1;
	key_data->key_data_type[0]      = key.enctype;
	key_data->key_data_length[0]    = key.length;
	key_data->key_data_contents[0]  = key.contents;
	key_data->key_data_type[1]      = sts;
	key_data->key_data_length[1]    = salt.length;
	key_data->key_data_contents[1]  = (krb5_octet*)salt.data;

	*kentry_ptr = kentry;

	return 0;
}

static krb5_error_code ks_get_admin_principal(krb5_context context,
					      krb5_const_principal princ,
					      krb5_db_entry **kentry_ptr)
{
	krb5_error_code code = EINVAL;

	code = ks_create_principal(context,
				   princ,
				   KRB5_KDB_DISALLOW_TGT_BASED,
				   ADMIN_LIFETIME,
				   NULL,
				   kentry_ptr);

	return code;
}

krb5_error_code kdb_samba_db_get_principal(krb5_context context,
					   krb5_const_principal princ,
					   unsigned int kflags,
					   krb5_db_entry **kentry)
{
	struct mit_samba_context *mit_ctx;
	krb5_error_code code;

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return KRB5_KDB_DBNOTINITED;
	}

	if (ks_is_master_key_principal(context, princ)) {
		return ks_get_master_key_principal(context, princ, kentry);
	}

	/*
	 * Fake a kadmin/admin and kadmin/history principal so that kadmindd can
	 * start
	 */
	if (ks_is_kadmin_admin(context, princ) ||
	    ks_is_kadmin_history(context, princ)) {
		return ks_get_admin_principal(context, princ, kentry);
	}

	code = ks_get_principal(context, princ, kflags, kentry);

	/*
	 * This restricts the changepw account so it isn't able to request a
	 * service ticket. It also marks the principal as the changepw service.
	 */
	if (ks_is_kadmin_changepw(context, princ)) {
		/* FIXME: shouldn't we also set KRB5_KDB_DISALLOW_TGT_BASED ?
		 * testing showed that setpw kpasswd command fails then on the
		 * server though... */
		(*kentry)->attributes |= KRB5_KDB_PWCHANGE_SERVICE;
		(*kentry)->max_life = CHANGEPW_LIFETIME;
	}

	return code;
}

krb5_error_code kdb_samba_db_put_principal(krb5_context context,
					   krb5_db_entry *entry,
					   char **db_args)
{

	/* NOTE: deferred, samba does not allow the KDC to store
	 * principals for now. We should not return KRB5_KDB_DB_INUSE as this
	 * would result in confusing error messages after password changes. */
	return 0;
}

krb5_error_code kdb_samba_db_delete_principal(krb5_context context,
					      krb5_const_principal princ)
{

	/* NOTE: deferred, samba does not allow the KDC to delete
	 * principals for now */
	return KRB5_KDB_DB_INUSE;
}

#if KRB5_KDB_API_VERSION >= 8
krb5_error_code kdb_samba_db_iterate(krb5_context context,
				     char *match_entry,
				     int (*func)(krb5_pointer, krb5_db_entry *),
				     krb5_pointer func_arg,
				     krb5_flags iterflags)
#else
krb5_error_code kdb_samba_db_iterate(krb5_context context,
				     char *match_entry,
				     int (*func)(krb5_pointer, krb5_db_entry *),
				     krb5_pointer func_arg)
#endif
{
	struct mit_samba_context *mit_ctx;
	krb5_db_entry *kentry = NULL;
	krb5_error_code code;


	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return KRB5_KDB_DBNOTINITED;
	}

	code = mit_samba_get_firstkey(mit_ctx, &kentry);
	while (code == 0) {
		code = (*func)(func_arg, kentry);
		if (code != 0) {
			break;
		}

		code = mit_samba_get_nextkey(mit_ctx, &kentry);
	}

	if (code == KRB5_KDB_NOENTRY) {
		code = 0;
	}

	return code;
}
