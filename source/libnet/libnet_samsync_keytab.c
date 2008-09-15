/*
   Unix SMB/CIFS implementation.
   dump the remote SAM using rpc samsync operations

   Copyright (C) Guenther Deschner 2008.

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
#include "libnet/libnet.h"

#if defined(HAVE_ADS) && defined(ENCTYPE_ARCFOUR_HMAC)

/****************************************************************
****************************************************************/

static NTSTATUS keytab_ad_connect(TALLOC_CTX *mem_ctx,
				  const char *domain_name,
				  const char *username,
				  const char *password,
				  struct libnet_keytab_context *ctx)
{
	NTSTATUS status;
	ADS_STATUS ad_status;
	ADS_STRUCT *ads;
	struct netr_DsRGetDCNameInfo *info = NULL;
	const char *dc;

	status = dsgetdcname(mem_ctx, NULL, domain_name, NULL, NULL, 0, &info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dc = strip_hostname(info->dc_unc);

	ads = ads_init(NULL, domain_name, dc);
	NT_STATUS_HAVE_NO_MEMORY(ads);

	if (getenv(KRB5_ENV_CCNAME) == NULL) {
		setenv(KRB5_ENV_CCNAME, "MEMORY:libnet_samsync_keytab", 1);
	}

	ads->auth.user_name = SMB_STRDUP(username);
	ads->auth.password = SMB_STRDUP(password);

	ad_status = ads_connect_user_creds(ads);
	if (!ADS_ERR_OK(ad_status)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ctx->ads = ads;

	ctx->dns_domain_name = talloc_strdup_upper(mem_ctx, ads->config.realm);
	NT_STATUS_HAVE_NO_MEMORY(ctx->dns_domain_name);

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS fetch_sam_entry_keytab(TALLOC_CTX *mem_ctx,
				       enum netr_SamDatabaseID database_id,
				       uint32_t rid,
				       struct netr_DELTA_USER *r,
				       bool last_query,
				       struct libnet_keytab_context *ctx)
{
	uchar nt_passwd[16];
	struct libnet_keytab_entry entry;

	if (memcmp(r->ntpassword.hash, ctx->zero_buf, 16) == 0) {
		return NT_STATUS_OK;
	}

	sam_pwd_hash(rid, r->ntpassword.hash, nt_passwd, 0);

	entry.name = talloc_strdup(mem_ctx, r->account_name.string);
	entry.principal = talloc_asprintf(mem_ctx, "%s@%s",
					  r->account_name.string,
					  ctx->dns_domain_name);
	entry.password = data_blob_talloc(mem_ctx, nt_passwd, 16);
	entry.kvno = ads_get_kvno(ctx->ads, entry.name);
	entry.enctype = ENCTYPE_NULL;

	NT_STATUS_HAVE_NO_MEMORY(entry.name);
	NT_STATUS_HAVE_NO_MEMORY(entry.principal);
	NT_STATUS_HAVE_NO_MEMORY(entry.password.data);


	ADD_TO_ARRAY(mem_ctx, struct libnet_keytab_entry, entry,
		     &ctx->entries, &ctx->count);

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

NTSTATUS fetch_sam_entries_keytab(TALLOC_CTX *mem_ctx,
				  enum netr_SamDatabaseID database_id,
				  struct netr_DELTA_ENUM_ARRAY *r,
				  bool last_query,
				  struct samsync_context *ctx)
{
	NTSTATUS status = NT_STATUS_OK;
	krb5_error_code ret = 0;
	static struct libnet_keytab_context *keytab_ctx = NULL;
	int i;

	if (!keytab_ctx) {
		ret = libnet_keytab_init(mem_ctx, ctx->output_filename,
					 &keytab_ctx);
		if (ret) {
			status = krb5_to_nt_status(ret);
			goto out;
		}
	}

	status = keytab_ad_connect(mem_ctx,
				   ctx->domain_name,
				   ctx->username,
				   ctx->password,
				   keytab_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	for (i = 0; i < r->num_deltas; i++) {

		if (r->delta_enum[i].delta_type != NETR_DELTA_USER) {
			continue;
		}

		status = fetch_sam_entry_keytab(mem_ctx, database_id,
						r->delta_enum[i].delta_id_union.rid,
						r->delta_enum[i].delta_union.user,
						last_query,
						keytab_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	if (last_query) {

		ret = libnet_keytab_add(keytab_ctx);
		if (ret) {
			status = krb5_to_nt_status(ret);
			ctx->error_message = talloc_asprintf(mem_ctx,
				"Failed to add entries to keytab %s: %s",
				keytab_ctx->keytab_name, error_message(ret));
			goto out;
		}

		ctx->result_message = talloc_asprintf(mem_ctx,
			"Vampired %d accounts to keytab %s",
			keytab_ctx->count,
			keytab_ctx->keytab_name);

		TALLOC_FREE(keytab_ctx);
	}

	return NT_STATUS_OK;
 out:
	TALLOC_FREE(keytab_ctx);

	return status;
}

#else

NTSTATUS fetch_sam_entries_keytab(TALLOC_CTX *mem_ctx,
				  enum netr_SamDatabaseID database_id,
				  struct netr_DELTA_ENUM_ARRAY *r,
				  bool last_query,
				  struct samsync_context *ctx)
{
	return NT_STATUS_NOT_SUPPORTED;
}

#endif /* defined(HAVE_ADS) && defined(ENCTYPE_ARCFOUR_HMAC) */
