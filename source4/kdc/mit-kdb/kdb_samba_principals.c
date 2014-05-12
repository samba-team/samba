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

static krb5_error_code ks_get_principal(krb5_context context,
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

	kentry = malloc(sizeof(krb5_db_entry));
	if (kentry == NULL) {
		return ENOMEM;
	}

	ZERO_STRUCTP(kentry);

	kentry->magic = KRB5_KDB_MAGIC_NUMBER;
	kentry->len = KRB5_KDB_V1_BASE_LENGTH;
	kentry->attributes = KRB5_KDB_DISALLOW_ALL_TIX;

	if (princ == NULL) {
		code = krb5_parse_name(context, KRB5_KDB_M_NAME, &kentry->princ);
	} else {
		code = krb5_copy_principal(context, princ, &kentry->princ);
	}
	if (code != 0) {
		ks_free_krb5_db_entry(context, kentry);
		return code;
	}

	now = time(NULL);

	code = krb5_dbe_update_mod_princ_data(context, kentry, now, kentry->princ);
	if (code != 0) {
		ks_free_krb5_db_entry(context, kentry);
		return code;
	}

	/* Return a dummy key */
	kentry->n_key_data = 1;
	kentry->key_data = malloc(sizeof(krb5_key_data));
	if (code != 0) {
		ks_free_krb5_db_entry(context, kentry);
		return code;
	}

	key_data = &kentry->key_data[0];

	key_data->key_data_ver          = KRB5_KDB_V1_KEY_DATA_ARRAY;
	key_data->key_data_kvno         = 1;
	key_data->key_data_type[0]      = ENCTYPE_UNKNOWN;
	if (code != 0) {
		ks_free_krb5_db_entry(context, kentry);
		return code;
	}

	*kentry_ptr = kentry;

	return 0;
}

static krb5_boolean ks_is_kadmin_history(krb5_context context,
					 krb5_const_principal princ)
{
	return krb5_princ_size(context, princ) == 2 &&
	       ks_data_eq_string(princ->data[0], "kadmin") &&
	       ks_data_eq_string(princ->data[1], "history");
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

	/* FIXME: temporarily fake up kadmin history to let kadmin.local work */
	if (ks_is_kadmin_history(context, princ)) {
		return ks_get_dummy_principal(context, princ, kentry);
	}

	code = ks_get_principal(context, princ, kflags, kentry);

	return code;
}

void kdb_samba_db_free_principal(krb5_context context,
				 krb5_db_entry *entry)
{
	struct mit_samba_context *mit_ctx;

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return;
	}

	ks_free_krb5_db_entry(context, entry);
}

krb5_error_code kdb_samba_db_put_principal(krb5_context context,
					   krb5_db_entry *entry,
					   char **db_args)
{

	/* NOTE: deferred, samba does not allow the KDC to store
	 * principals for now */
	return KRB5_KDB_DB_INUSE;
}

krb5_error_code kdb_samba_db_delete_principal(krb5_context context,
					      krb5_const_principal princ)
{

	/* NOTE: deferred, samba does not allow the KDC to delete
	 * principals for now */
	return KRB5_KDB_DB_INUSE;
}

krb5_error_code kdb_samba_db_iterate(krb5_context context,
				     char *match_entry,
				     int (*func)(krb5_pointer, krb5_db_entry *),
				     krb5_pointer func_arg)
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
