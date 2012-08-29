/*
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009

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
#include "auth/kerberos/kerberos.h"
#include <hdb.h>
#include "kdc/samba_kdc.h"
#include "libnet/libnet_export_keytab.h"

NTSTATUS libnet_export_keytab(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_export_keytab *r)
{
	krb5_error_code ret;
	struct smb_krb5_context *smb_krb5_context;
	const char *from_keytab;

	/* Register hdb-samba4 hooks for use as a keytab */

	struct samba_kdc_base_context *base_ctx = talloc_zero(mem_ctx, struct samba_kdc_base_context);
	if (!base_ctx) {
		return NT_STATUS_NO_MEMORY; 
	}

	base_ctx->ev_ctx = ctx->event_ctx;
	base_ctx->lp_ctx = ctx->lp_ctx;

	from_keytab = talloc_asprintf(base_ctx, "HDB:samba4&%p", base_ctx);
	if (!from_keytab) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = smb_krb5_init_context(ctx, ctx->event_ctx, ctx->lp_ctx, &smb_krb5_context);
	if (ret) {
		return NT_STATUS_NO_MEMORY; 
	}

	ret = krb5_plugin_register(smb_krb5_context->krb5_context, 
				   PLUGIN_TYPE_DATA, "hdb",
				   &hdb_samba4_interface);
	if(ret) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = krb5_kt_register(smb_krb5_context->krb5_context, &hdb_kt_ops);
	if(ret) {
		return NT_STATUS_NO_MEMORY;
	}

	if (r->in.principal) {
		ret = kt_copy_one_principal(smb_krb5_context->krb5_context, from_keytab, r->in.keytab_name, r->in.principal, 0, samba_all_enctypes());
	} else {
		unlink(r->in.keytab_name);
		ret = kt_copy(smb_krb5_context->krb5_context, from_keytab, r->in.keytab_name);
	}

	if(ret) {
		r->out.error_string = smb_get_krb5_error_message(smb_krb5_context->krb5_context,
								 ret, mem_ctx);
		if (ret == KRB5_KT_NOTFOUND) {
			return NT_STATUS_NO_SUCH_USER;
		} else {
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	return NT_STATUS_OK;
}
