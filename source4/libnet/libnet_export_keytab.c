/*
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009
   Copyright (C) Andreas Schneider <asn@samba.org> 2016

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
#include "kdc/samba_kdc.h"
#include "libnet/libnet_export_keytab.h"

#include "kdc/db-glue.h"
#include "kdc/sdb.h"

static NTSTATUS sdb_kt_copy(TALLOC_CTX *mem_ctx,
			    krb5_context context,
			    struct samba_kdc_db_context *db_ctx,
			    const char *keytab_name,
			    const char *principal,
			    const char **error_string)
{
	struct sdb_entry_ex sentry = {
		.free_entry = NULL,
	};
	krb5_keytab keytab;
	krb5_error_code code = 0;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *entry_principal = NULL;
	bool copy_one_principal = (principal != NULL);
	krb5_data password;

	code = smb_krb5_kt_open_relative(context,
					 keytab_name,
					 true, /* write_access */
					 &keytab);
	if (code != 0) {
		*error_string = talloc_asprintf(mem_ctx,
						"Failed to open keytab: %s",
						keytab_name);
		status = NT_STATUS_NO_SUCH_FILE;
		goto done;
	}

	if (copy_one_principal) {
		krb5_principal k5_princ;

		code = smb_krb5_parse_name(context, principal, &k5_princ);
		if (code != 0) {
			*error_string = smb_get_krb5_error_message(context,
								   code,
								   mem_ctx);
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		code = samba_kdc_fetch(context, db_ctx, k5_princ,
				       SDB_F_GET_ANY, 0, &sentry);

		krb5_free_principal(context, k5_princ);
	} else {
		code = samba_kdc_firstkey(context, db_ctx, &sentry);
	}

	for (; code == 0; code = samba_kdc_nextkey(context, db_ctx, &sentry)) {
		int i;

		code = krb5_unparse_name(context,
					 sentry.entry.principal,
					 &entry_principal);
		if (code != 0) {
			*error_string = smb_get_krb5_error_message(context,
								   code,
								   mem_ctx);
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		if (sentry.entry.keys.len == 0) {
			SAFE_FREE(entry_principal);
			sdb_free_entry(&sentry);
			sentry = (struct sdb_entry_ex) {
				.free_entry = NULL,
			};

			continue;
		}

		for (i = 0; i < sentry.entry.keys.len; i++) {
			struct sdb_key *s = &(sentry.entry.keys.val[i]);
			krb5_enctype enctype;

			enctype = KRB5_KEY_TYPE(&(s->key));
			password.length = KRB5_KEY_LENGTH(&s->key);
			password.data = (char *)KRB5_KEY_DATA(&s->key);

			DBG_INFO("smb_krb5_kt_add_entry for enctype=0x%04x\n",
				  (int)enctype);
			code = smb_krb5_kt_add_entry(context,
						     keytab,
						     sentry.entry.kvno,
						     entry_principal,
						     NULL,
						     enctype,
						     &password,
						     true,    /* no_salt */
						     false);  /* keeyp_old_entries */
			if (code != 0) {
				status = NT_STATUS_UNSUCCESSFUL;
				*error_string = smb_get_krb5_error_message(context,
									   code,
									   mem_ctx);
				DEBUG(0, ("smb_krb5_kt_add_entry failed code=%d, error = %s\n",
					  code, *error_string));
				goto done;
			}
		}

		if (copy_one_principal) {
			break;
		}

		SAFE_FREE(entry_principal);
		sdb_free_entry(&sentry);
		sentry = (struct sdb_entry_ex) {
			.free_entry = NULL,
		};
	}

	if (code != 0 && code != SDB_ERR_NOENTRY) {
		*error_string = smb_get_krb5_error_message(context,
							   code,
							   mem_ctx);
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	status = NT_STATUS_OK;
done:
	SAFE_FREE(entry_principal);
	sdb_free_entry(&sentry);

	return status;
}

NTSTATUS libnet_export_keytab(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_export_keytab *r)
{
	krb5_error_code ret;
	struct smb_krb5_context *smb_krb5_context;
	struct samba_kdc_base_context *base_ctx;
	struct samba_kdc_db_context *db_ctx = NULL;
	const char *error_string = NULL;
	NTSTATUS status;

	ret = smb_krb5_init_context(ctx, ctx->lp_ctx, &smb_krb5_context);
	if (ret) {
		return NT_STATUS_NO_MEMORY; 
	}

	base_ctx = talloc_zero(mem_ctx, struct samba_kdc_base_context);
	if (base_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	base_ctx->ev_ctx = ctx->event_ctx;
	base_ctx->lp_ctx = ctx->lp_ctx;

	status = samba_kdc_setup_db_ctx(mem_ctx, base_ctx, &db_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (r->in.principal != NULL) {
		DEBUG(0, ("Export one principal to %s\n", r->in.keytab_name));
		status = sdb_kt_copy(mem_ctx,
				     smb_krb5_context->krb5_context,
				     db_ctx,
				     r->in.keytab_name,
				     r->in.principal,
				     &error_string);
	} else {
		unlink(r->in.keytab_name);
		DEBUG(0, ("Export complete keytab to %s\n", r->in.keytab_name));
		status = sdb_kt_copy(mem_ctx,
				     smb_krb5_context->krb5_context,
				     db_ctx,
				     r->in.keytab_name,
				     NULL,
				     &error_string);
	}

	talloc_free(db_ctx);
	talloc_free(base_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = error_string;
	}

	return status;
}
