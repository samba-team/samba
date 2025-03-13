/*
   Unix SMB/CIFS implementation.

   KDC Server startup

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-20011

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
#include "kdc/kdc-glue.h"
#include "lib/param/param.h"

static krb5_error_code hdb_samba4_create(krb5_context context, struct HDB **db, const char *arg)
{
	NTSTATUS nt_status;
	void *ptr = NULL;
	struct samba_kdc_base_context *base_ctx = NULL;

	if (sscanf(arg, "&%p", &ptr) != 1) {
		return EINVAL;
	}

	base_ctx = talloc_get_type_abort(ptr, struct samba_kdc_base_context);

	/* The global kdc_mem_ctx and kdc_lp_ctx, Disgusting, ugly hack, but it means one less private hook */
	nt_status = hdb_samba4_kpasswd_create_kdc(base_ctx, context, db);

	if (NT_STATUS_IS_OK(nt_status)) {
		return 0;
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ERROR_DS_INCOMPATIBLE_VERSION)) {
		return EINVAL;
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_CANT_ACCESS_DOMAIN_INFO)) {
		
		krb5_set_error_message(context, EINVAL, "Failed to open Samba4 LDB at %s", lpcfg_private_path(base_ctx, base_ctx->lp_ctx, "sam.ldb"));
	} else {
		krb5_set_error_message(context, EINVAL, "Failed to connect to Samba4 DB: %s (%s)", get_friendly_nt_error_msg(nt_status), nt_errstr(nt_status));
	}

	return EINVAL;
}

#if (HDB_INTERFACE_VERSION != 12)
#error "Unsupported Heimdal HDB version"
#endif

#if HDB_INTERFACE_VERSION >= 8
static krb5_error_code hdb_samba4_init(krb5_context context, void **ctx)
{
	*ctx = NULL;
	return 0;
}

static void hdb_samba4_fini(void *ctx)
{
}
#endif

/* Only used in the hdb-backed keytab code
 * for a keytab of 'samba4&<address>' or samba4, to find
 * kpasswd's key in the main DB
 *
 * The <address> is the string form of a pointer to a talloced struct hdb_samba_context
 */
struct hdb_method hdb_samba4_interface = {
	HDB_INTERFACE_VERSION,
#if HDB_INTERFACE_VERSION >= 8
	.init = hdb_samba4_init,
	.fini = hdb_samba4_fini,
#endif
	.prefix = "samba4",
	.create = hdb_samba4_create
};
