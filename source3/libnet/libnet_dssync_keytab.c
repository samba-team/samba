/*
   Unix SMB/CIFS implementation.

   Copyright (C) Guenther Deschner <gd@samba.org> 2008

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
#include "librpc/gen_ndr/ndr_drsblobs.h"

#if defined(HAVE_ADS) && defined(ENCTYPE_ARCFOUR_HMAC)

static NTSTATUS add_to_keytab_entries(TALLOC_CTX *mem_ctx,
				      struct libnet_keytab_context *ctx,
				      uint32_t kvno,
				      const char *name,
				      const char *prefix,
				      const krb5_enctype enctype,
				      DATA_BLOB blob)
{
	struct libnet_keytab_entry entry;

	entry.kvno = kvno;
	entry.name = talloc_strdup(mem_ctx, name);
	entry.principal = talloc_asprintf(mem_ctx, "%s%s%s@%s",
					  prefix ? prefix : "",
					  prefix ? "/" : "",
					  name, ctx->dns_domain_name);
	entry.enctype = enctype;
	entry.password = blob;
	NT_STATUS_HAVE_NO_MEMORY(entry.name);
	NT_STATUS_HAVE_NO_MEMORY(entry.principal);
	NT_STATUS_HAVE_NO_MEMORY(entry.password.data);

	ADD_TO_ARRAY(mem_ctx, struct libnet_keytab_entry, entry,
		     &ctx->entries, &ctx->count);
	NT_STATUS_HAVE_NO_MEMORY(ctx->entries);

	return NT_STATUS_OK;
}

static NTSTATUS keytab_startup(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			       struct replUpToDateVectorBlob **pold_utdv)
{
	krb5_error_code ret = 0;
	struct libnet_keytab_context *keytab_ctx;
	struct libnet_keytab_entry *entry;
	struct replUpToDateVectorBlob *old_utdv = NULL;
	char *principal;

	ret = libnet_keytab_init(mem_ctx, ctx->output_filename, &keytab_ctx);
	if (ret) {
		return krb5_to_nt_status(ret);
	}

	keytab_ctx->dns_domain_name = ctx->dns_domain_name;
	ctx->private_data = keytab_ctx;

	principal = talloc_asprintf(mem_ctx, "UTDV/%s@%s",
				    ctx->nc_dn, ctx->dns_domain_name);
	NT_STATUS_HAVE_NO_MEMORY(principal);

	entry = libnet_keytab_search(keytab_ctx, principal, 0, ENCTYPE_ARCFOUR_HMAC,
				     mem_ctx);
	if (entry) {
		enum ndr_err_code ndr_err;
		old_utdv = talloc(mem_ctx, struct replUpToDateVectorBlob);

		ndr_err = ndr_pull_struct_blob(&entry->password, old_utdv,
				old_utdv,
				(ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
			ctx->error_message = talloc_asprintf(mem_ctx,
					"Failed to pull UpToDateVector: %s",
					nt_errstr(status));
			return status;
		}

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(replUpToDateVectorBlob, old_utdv);
		}
	}

	if (pold_utdv) {
		*pold_utdv = old_utdv;
	}

	return NT_STATUS_OK;
}

static NTSTATUS keytab_finish(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			      struct replUpToDateVectorBlob *new_utdv)
{
	NTSTATUS status = NT_STATUS_OK;
	krb5_error_code ret = 0;
	struct libnet_keytab_context *keytab_ctx =
		(struct libnet_keytab_context *)ctx->private_data;

	if (new_utdv) {
		enum ndr_err_code ndr_err;
		DATA_BLOB blob;

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(replUpToDateVectorBlob, new_utdv);
		}

		ndr_err = ndr_push_struct_blob(&blob, mem_ctx, new_utdv,
				(ndr_push_flags_fn_t)ndr_push_replUpToDateVectorBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			ctx->error_message = talloc_asprintf(mem_ctx,
					"Failed to push UpToDateVector: %s",
					nt_errstr(status));
			goto done;
		}

		status = add_to_keytab_entries(mem_ctx, keytab_ctx, 0,
					       ctx->nc_dn, "UTDV",
					       ENCTYPE_ARCFOUR_HMAC,
					       blob);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	ret = libnet_keytab_add(keytab_ctx);
	if (ret) {
		status = krb5_to_nt_status(ret);
		ctx->error_message = talloc_asprintf(mem_ctx,
			"Failed to add entries to keytab %s: %s",
			keytab_ctx->keytab_name, error_message(ret));
		goto done;
	}

	ctx->result_message = talloc_asprintf(mem_ctx,
		"Vampired %d accounts to keytab %s",
		keytab_ctx->count,
		keytab_ctx->keytab_name);

done:
	TALLOC_FREE(keytab_ctx);
	return status;
}

/****************************************************************
****************************************************************/

static NTSTATUS parse_object(TALLOC_CTX *mem_ctx,
			     struct libnet_keytab_context *ctx,
			     struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	NTSTATUS status = NT_STATUS_OK;
	uchar nt_passwd[16];
	DATA_BLOB *blob;
	int i = 0;
	struct drsuapi_DsReplicaAttribute *attr;
	bool got_pwd = false;

	char *upn = NULL;
	char *name = NULL;
	uint32_t kvno = 0;
	uint32_t uacc = 0;
	uint32_t sam_type = 0;

	uint32_t pwd_history_len = 0;
	uint8_t *pwd_history = NULL;

	ZERO_STRUCT(nt_passwd);

	for (i=0; i < cur->object.attribute_ctr.num_attributes; i++) {

		attr = &cur->object.attribute_ctr.attributes[i];

		if (attr->value_ctr.num_values != 1) {
			continue;
		}

		if (!attr->value_ctr.values[0].blob) {
			continue;
		}

		blob = attr->value_ctr.values[0].blob;

		switch (attr->attid) {
			case DRSUAPI_ATTRIBUTE_unicodePwd:

				if (blob->length != 16) {
					break;
				}

				memcpy(&nt_passwd, blob->data, 16);
				got_pwd = true;

				/* pick the kvno from the meta_data version,
				 * thanks, metze, for explaining this */

				if (!cur->meta_data_ctr) {
					break;
				}
				if (cur->meta_data_ctr->count !=
				    cur->object.attribute_ctr.num_attributes) {
					break;
				}
				kvno = cur->meta_data_ctr->meta_data[i].version;
				break;
			case DRSUAPI_ATTRIBUTE_ntPwdHistory:
				pwd_history_len = blob->length / 16;
				pwd_history = blob->data;
				break;
			case DRSUAPI_ATTRIBUTE_userPrincipalName:
				pull_string_talloc(mem_ctx, NULL, 0, &upn,
						   blob->data, blob->length,
						   STR_UNICODE);
				break;
			case DRSUAPI_ATTRIBUTE_sAMAccountName:
				pull_string_talloc(mem_ctx, NULL, 0, &name,
						   blob->data, blob->length,
						   STR_UNICODE);
				break;
			case DRSUAPI_ATTRIBUTE_sAMAccountType:
				sam_type = IVAL(blob->data, 0);
				break;
			case DRSUAPI_ATTRIBUTE_userAccountControl:
				uacc = IVAL(blob->data, 0);
				break;
			default:
				break;
		}
	}

	if (!got_pwd || !name) {
		return NT_STATUS_OK;
	}

	DEBUG(1,("#%02d: %s:%d, ", ctx->count, name, kvno));
	DEBUGADD(1,("sAMAccountType: 0x%08x, userAccountControl: 0x%08x ",
		sam_type, uacc));
	if (upn) {
		DEBUGADD(1,("upn: %s", upn));
	}
	DEBUGADD(1,("\n"));

	status = add_to_keytab_entries(mem_ctx, ctx, kvno, name, NULL,
				       ENCTYPE_ARCFOUR_HMAC,
				       data_blob_talloc(mem_ctx, nt_passwd, 16));

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((kvno < 0) && (kvno < pwd_history_len)) {
		return status;
	}

	/* add password history */

	/* skip first entry */
	if (got_pwd) {
		kvno--;
		i = 1;
	} else {
		i = 0;
	}

	for (; i<pwd_history_len; i++) {
		status = add_to_keytab_entries(mem_ctx, ctx, kvno--, name, NULL,
				ENCTYPE_ARCFOUR_HMAC,
				data_blob_talloc(mem_ctx, &pwd_history[i*16], 16));
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}
	}

	return status;
}

/****************************************************************
****************************************************************/

static NTSTATUS keytab_process_objects(struct dssync_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsReplicaObjectListItemEx *cur,
				       struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr)
{
	NTSTATUS status = NT_STATUS_OK;
	struct libnet_keytab_context *keytab_ctx =
		(struct libnet_keytab_context *)ctx->private_data;

	for (; cur; cur = cur->next_object) {
		status = parse_object(mem_ctx, keytab_ctx, cur);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

 out:
	return status;
}

#else

static NTSTATUS keytab_startup(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			       struct replUpToDateVectorBlob **pold_utdv)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS keytab_finish(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			      struct replUpToDateVectorBlob *new_utdv)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS keytab_process_objects(struct dssync_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsReplicaObjectListItemEx *cur,
				       struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif /* defined(HAVE_ADS) && defined(ENCTYPE_ARCFOUR_HMAC) */

const struct dssync_ops libnet_dssync_keytab_ops = {
	.startup		= keytab_startup,
	.process_objects	= keytab_process_objects,
	.finish			= keytab_finish,
};
