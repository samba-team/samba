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
#include "auth/credentials/credentials.h"
#include "auth/kerberos/kerberos.h"
#include "auth/kerberos/kerberos_credentials.h"
#include "auth/kerberos/kerberos_util.h"
#include "auth/kerberos/kerberos_srv_keytab.h"
#include "kdc/samba_kdc.h"
#include "libnet/libnet_export_keytab.h"
#include "kdc/db-glue.h"
#include "kdc/sdb.h"

static NTSTATUS sdb_kt_copy(TALLOC_CTX *mem_ctx,
			    struct smb_krb5_context *smb_krb5_context,
			    struct samba_kdc_db_context *db_ctx,
			    const char *keytab_name,
			    const char *principal,
			    bool keep_stale_entries,
			    const char **error_string)
{
	struct sdb_entry sentry = {};
	krb5_keytab keytab;
	krb5_error_code code = 0;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *entry_principal = NULL;
	bool copy_one_principal = (principal != NULL);
	bool keys_exported = false;
	krb5_context context = smb_krb5_context->krb5_context;
	TALLOC_CTX *tmp_ctx = NULL;

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
				       SDB_F_GET_ANY | SDB_F_ADMIN_DATA,
				       0, &sentry);

		krb5_free_principal(context, k5_princ);
	} else {
		code = samba_kdc_firstkey(context, db_ctx, &sentry);
	}

	for (; code == 0; code = samba_kdc_nextkey(context, db_ctx, &sentry)) {
		int i;
		bool found_previous = false;
		tmp_ctx = talloc_new(mem_ctx);
		if (tmp_ctx == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		code = krb5_unparse_name(context,
					 sentry.principal,
					 &entry_principal);
		if (code != 0) {
			*error_string = smb_get_krb5_error_message(context,
								   code,
								   mem_ctx);
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		if (!keep_stale_entries) {
			code = smb_krb5_remove_obsolete_keytab_entries(mem_ctx,
								       context,
								       keytab,
								       1, &sentry.principal,
								       sentry.kvno,
								       &found_previous,
								       error_string);
			if (code != 0) {
				*error_string = talloc_asprintf(mem_ctx,
								"Failed to remove old principals from keytab: %s\n",
								*error_string);
				status = NT_STATUS_UNSUCCESSFUL;
				goto done;
			}
		}

		/*
		 * If this was a gMSA and we did not just read the
		 * keys directly, then generate them
		 */
		if (sentry.skdc_entry->group_managed_service_account
		    && sentry.keys.len == 0) {
			struct ldb_dn *dn = sentry.skdc_entry->msg->dn;
			/*
			 * for error message only, but we are about to
			 * destroy the string name, so write this out
			 * now
			 */
			const char *extended_dn =
				ldb_dn_get_extended_linearized(mem_ctx,
							       dn,
							       1);

			/*
			 * Modify the DN in the entry (not needed by
			 * the KDC code any longer) to be minimal, so
			 * we can search on it over LDAP.
			 */
			ldb_dn_minimise(dn);

			status = smb_krb5_fill_keytab_gmsa_keys(tmp_ctx,
								smb_krb5_context,
								keytab,
								sentry.principal,
								db_ctx->samdb,
								dn,
								error_string);
			if (NT_STATUS_IS_OK(status)) {
				keys_exported = true;
			} else if (copy_one_principal) {
				*error_string = talloc_asprintf(mem_ctx,
								"Failed to write gMSA password for %s to keytab: %s\n",
								principal,
								*error_string);
				goto done;
			} else if (!NT_STATUS_EQUAL(status, NT_STATUS_NO_USER_KEYS)) {
				*error_string = talloc_asprintf(mem_ctx,
								"Failed to write gMSA password for %s to keytab: %s\n",
								extended_dn,
								*error_string);
				goto done;
			}
		} else {
			krb5_keytab_entry kt_entry;
			ZERO_STRUCT(kt_entry);
			kt_entry.principal = sentry.principal;
			kt_entry.vno       = sentry.kvno;

			for (i = 0; i < sentry.keys.len; i++) {
				struct sdb_key *s = &(sentry.keys.val[i]);
				krb5_keyblock *keyp;
				bool found;

				keyp = KRB5_KT_KEY(&kt_entry);

				*keyp = s->key;

				code = smb_krb5_is_exact_entry_in_keytab(mem_ctx,
									 context,
									 keytab,
									 &kt_entry,
									 &found,
									 error_string);
				if (code != 0) {
					status = NT_STATUS_UNSUCCESSFUL;
					*error_string = smb_get_krb5_error_message(context,
										   code,
										   mem_ctx);
					DEBUG(0, ("smb_krb5_is_exact_entry_in_keytab failed code=%d, error = %s\n",
						  code, *error_string));
					goto done;
				}

				if (found) {
					continue;
				}

				code = krb5_kt_add_entry(context, keytab, &kt_entry);
				if (code != 0) {
					status = NT_STATUS_UNSUCCESSFUL;
					*error_string = smb_get_krb5_error_message(context,
										   code,
										   mem_ctx);
					DEBUG(0, ("smb_krb5_kt_add_entry failed code=%d, error = %s\n",
						  code, *error_string));
					goto done;
				}
				keys_exported = true;
			}
		}

		if (copy_one_principal) {
			break;
		}

		TALLOC_FREE(tmp_ctx);
		SAFE_FREE(entry_principal);
		sdb_entry_free(&sentry);
	}

	if (code != 0 && code != SDB_ERR_NOENTRY) {
		*error_string = smb_get_krb5_error_message(context,
							   code,
							   mem_ctx);
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	if (keys_exported == false) {
		if (keep_stale_entries == false) {
			*error_string = talloc_asprintf(mem_ctx,
							"No keys found while exporting %s.  "
							"Consider connecting to a local sam.ldb, "
							"only gMSA accounts can be exported over "
							"LDAP and connecting user needs to be authorized",
							principal ? principal : "all users in domain");
			status = NT_STATUS_NO_USER_KEYS;
		} else {
			DBG_NOTICE("No new keys found while exporting %s.  "
				   "If new keys were expected, consider connecting "
				   "to a local sam.ldb, only gMSA accounts can be exported over "
				   "LDAP and connecting user needs to be authorized\n",
				   principal ? principal : "all users in domain");
			status = NT_STATUS_OK;
		}
	} else {
		status = NT_STATUS_OK;
	}

done:
	TALLOC_FREE(tmp_ctx);
	SAFE_FREE(entry_principal);
	sdb_entry_free(&sentry);

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

	bool keep_stale_entries = r->in.keep_stale_entries;

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
	base_ctx->samdb = r->in.samdb;

	status = samba_kdc_setup_db_ctx(mem_ctx, base_ctx, &db_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (r->in.principal != NULL) {
		DEBUG(0, ("Export one principal to %s\n", r->in.keytab_name));
	} else {
		DEBUG(0, ("Export complete keytab to %s\n", r->in.keytab_name));
		if (!keep_stale_entries) {
			struct stat st;
			int stat_ret = stat(r->in.keytab_name, &st);
			if (stat_ret == -1 && errno == ENOENT) {
				/* continue */
			} else if (stat_ret == -1) {
				int errno_save = errno;
				r->out.error_string
					= talloc_asprintf(mem_ctx,
							  "Failure checking if keytab export location %s is an existing file: %s",
							  r->in.keytab_name,
							  strerror(errno_save));
				return map_nt_error_from_unix_common(errno_save);
			} else {
				r->out.error_string
					= talloc_asprintf(mem_ctx,
							  "Refusing to export keytab to existing file %s",
							  r->in.keytab_name);
				return NT_STATUS_OBJECT_NAME_EXISTS;
			}

			/*
			 * No point looking for old
			 * keys in a empty file
			 */
			keep_stale_entries = true;
		}
	}


	status = sdb_kt_copy(mem_ctx,
			     smb_krb5_context,
			     db_ctx,
			     r->in.keytab_name,
			     r->in.principal,
			     keep_stale_entries,
			     &error_string);

	talloc_free(db_ctx);
	talloc_free(base_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = error_string;
	}

	return status;
}
