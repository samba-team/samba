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

static krb5_error_code kdb_samba_init_library(void)
{
	return 0;
}

static krb5_error_code kdb_samba_fini_library(void)
{
	return 0;
}

static krb5_error_code kdb_samba_init_module(krb5_context context,
					     char *conf_section,
					     char **db_args,
					     int mode)
{
	/* TODO mit_samba_context_init */
	struct mit_samba_context *mit_ctx;
	krb5_error_code code;
	int rc;

	rc = mit_samba_context_init(&mit_ctx);
	if (rc != 0) {
		return ENOMEM;
	}


	code = krb5_db_set_context(context, mit_ctx);

	return code;
}
static krb5_error_code kdb_samba_fini_module(krb5_context context)
{
	struct mit_samba_context *mit_ctx;

	mit_ctx = ks_get_context(context);
	if (mit_ctx == NULL) {
		return 0;
	}

	mit_samba_context_free(mit_ctx);

	return 0;
}

static krb5_error_code kdb_samba_db_create(krb5_context context,
					   char *conf_section,
					   char **db_args)
{
	/* NOTE: used only by kadmin */
	return KRB5_KDB_DBTYPE_NOSUP;
}

static krb5_error_code kdb_samba_db_destroy(krb5_context context,
					    char *conf_section,
					    char **db_args)
{
	/* NOTE: used only by kadmin */
	return KRB5_KDB_DBTYPE_NOSUP;
}

static krb5_error_code kdb_samba_db_get_age(krb5_context context,
					    char *db_name,
					    time_t *age)
{
	/* TODO: returns last modification time of the db */

	/* NOTE: used by and affects only lookaside cache,
	 *       defer implementation until needed as samba doesn't keep this
	 *       specific value readily available and it would require a full
	 *       database search to get it. */

	*age = time(NULL);

	return 0;
}

static krb5_error_code kdb_samba_db_lock(krb5_context context, int kmode)
{

	/* NOTE: important only for kadmin */
	/* NOTE: deferred as samba's DB cannot be easily locked and doesn't
	 * really make sense to do so anyway as the db is shared and support
	 * transactions */
	return 0;
}

static krb5_error_code kdb_samba_db_unlock(krb5_context context)
{

	/* NOTE: important only for kadmin */
	/* NOTE: deferred as samba's DB cannot be easily locked and doesn't
	 * really make sense to do so anyway as the db is shared and support
	 * transactions */
	return 0;
}

static void kdb_samba_db_free_principal_e_data(krb5_context context,
					       krb5_octet *e_data)
{
	struct samba_kdc_entry *skdc_entry;

	skdc_entry = talloc_get_type_abort(e_data,
					   struct samba_kdc_entry);
	talloc_set_destructor(skdc_entry, NULL);
	TALLOC_FREE(skdc_entry);
}

kdb_vftabl kdb_function_table = {
	.maj_ver                   = KRB5_KDB_DAL_MAJOR_VERSION,
	.min_ver                   = KRB5_KDB_DAL_MAJOR_VERSION == 6 ? 1 : 0,

	.init_library              = kdb_samba_init_library,
	.fini_library              = kdb_samba_fini_library,
	.init_module               = kdb_samba_init_module,
	.fini_module               = kdb_samba_fini_module,

	.create                    = kdb_samba_db_create,
	.destroy                   = kdb_samba_db_destroy,
	.get_age                   = kdb_samba_db_get_age,
	.lock                      = kdb_samba_db_lock,
	.unlock                    = kdb_samba_db_unlock,

	.get_principal             = kdb_samba_db_get_principal,
	.put_principal             = kdb_samba_db_put_principal,
	.delete_principal          = kdb_samba_db_delete_principal,

	.iterate                   = kdb_samba_db_iterate,

	.fetch_master_key          = kdb_samba_fetch_master_key,
	.fetch_master_key_list     = kdb_samba_fetch_master_key_list,

	.change_pwd                = kdb_samba_change_pwd,

	.decrypt_key_data          = kdb_samba_dbekd_decrypt_key_data,
	.encrypt_key_data          = kdb_samba_dbekd_encrypt_key_data,

	.sign_authdata             = kdb_samba_db_sign_auth_data,
	.check_policy_as           = kdb_samba_db_check_policy_as,
	.audit_as_req              = kdb_samba_db_audit_as_req,
	.check_allowed_to_delegate = kdb_samba_db_check_allowed_to_delegate,

	.free_principal_e_data     = kdb_samba_db_free_principal_e_data,
};
