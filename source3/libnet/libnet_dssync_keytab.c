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

#if defined(HAVE_ADS) && defined(ENCTYPE_ARCFOUR_HMAC)

/****************************************************************
****************************************************************/

static NTSTATUS parse_object(TALLOC_CTX *mem_ctx,
			     struct libnet_keytab_context *ctx,
			     struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	NTSTATUS status = NT_STATUS_OK;
	uchar nt_passwd[16];
	struct libnet_keytab_entry entry;
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
			case DRSUAPI_ATTRIBUTE_msDS_KeyVersionNumber:
				kvno = IVAL(blob->data, 0);
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

	entry.kvno = kvno;
	entry.name = talloc_strdup(mem_ctx, name);
	entry.principal = talloc_asprintf(mem_ctx, "%s@%s",
					  name, ctx->dns_domain_name);
	entry.password = data_blob_talloc(mem_ctx, nt_passwd, 16);
	NT_STATUS_HAVE_NO_MEMORY(entry.name);
	NT_STATUS_HAVE_NO_MEMORY(entry.principal);
	NT_STATUS_HAVE_NO_MEMORY(entry.password.data);

	ADD_TO_ARRAY(mem_ctx, struct libnet_keytab_entry, entry,
		     &ctx->entries, &ctx->count);

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

		entry.kvno = kvno--;
		entry.name = talloc_strdup(mem_ctx, name);
		entry.principal = talloc_asprintf(mem_ctx, "%s@%s",
						  name, ctx->dns_domain_name);
		entry.password = data_blob_talloc(mem_ctx, &pwd_history[i*16], 16);
		NT_STATUS_HAVE_NO_MEMORY(entry.name);
		NT_STATUS_HAVE_NO_MEMORY(entry.principal);
		NT_STATUS_HAVE_NO_MEMORY(entry.password.data);

		ADD_TO_ARRAY(mem_ctx, struct libnet_keytab_entry, entry,
			     &ctx->entries, &ctx->count);
	}

	return status;
}

/****************************************************************
****************************************************************/

NTSTATUS libnet_dssync_dump_keytab(TALLOC_CTX *mem_ctx,
				   struct drsuapi_DsReplicaObjectListItemEx *cur,
				   struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr,
				   bool last_query,
				   struct dssync_context *ctx)
{
	NTSTATUS status = NT_STATUS_OK;
	krb5_error_code ret = 0;
	static struct libnet_keytab_context *keytab_ctx = NULL;

	if (!keytab_ctx) {
		ret = libnet_keytab_init(mem_ctx,
					 ctx->output_filename,
					 &keytab_ctx);
		if (ret) {
			status = krb5_to_nt_status(ret);
			goto out;
		}

		keytab_ctx->dns_domain_name = ctx->dns_domain_name;
	}

	for (; cur; cur = cur->next_object) {
		status = parse_object(mem_ctx, keytab_ctx, cur);
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

NTSTATUS libnet_dssync_dump_keytab(TALLOC_CTX *mem_ctx,
				   struct drsuapi_DsReplicaObjectListItemEx *cur,
				   struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr,
				   bool last_query,
				   struct dssync_context *ctx)
{
	return NT_STATUS_NOT_SUPPORTED;
}

#endif /* defined(HAVE_ADS) && defined(ENCTYPE_ARCFOUR_HMAC) */
