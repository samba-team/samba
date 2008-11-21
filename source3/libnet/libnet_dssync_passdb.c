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
#include "libnet/libnet_dssync.h"
#include "../libds/common/flags.h"

/****************************************************************
****************************************************************/

static NTSTATUS passdb_startup(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			       struct replUpToDateVectorBlob **pold_utdv)
{
	NTSTATUS status;
	struct pdb_methods *methods = NULL;

	if (ctx->output_filename) {
		status = make_pdb_method_name(&methods, ctx->output_filename);
	} else {
		status = make_pdb_method_name(&methods, lp_passdb_backend());
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ctx->private_data = methods;

	return status;
}

/****************************************************************
****************************************************************/

static NTSTATUS passdb_finish(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			      struct replUpToDateVectorBlob *new_utdv)
{
	struct pdb_methods *methods =
		(struct pdb_methods *)ctx->private_data;

	TALLOC_FREE(methods);

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS handle_account_object(TALLOC_CTX *mem_ctx,
				      struct pdb_methods *methods,
				      struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS handle_alias_object(TALLOC_CTX *mem_ctx,
				    struct pdb_methods *methods,
				    struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS handle_group_object(TALLOC_CTX *mem_ctx,
				    struct pdb_methods *methods,
				    struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS handle_interdomain_trust_object(TALLOC_CTX *mem_ctx,
						struct pdb_methods *methods,
						struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

struct dssync_object_table_t {
	uint32_t type;
	NTSTATUS (*fn) (TALLOC_CTX *mem_ctx,
			struct pdb_methods *methods,
			struct drsuapi_DsReplicaObjectListItemEx *cur);
};

static const struct dssync_object_table_t dssync_object_table[] = {
	{ ATYPE_NORMAL_ACCOUNT,		handle_account_object },
	{ ATYPE_WORKSTATION_TRUST,	handle_account_object },
	{ ATYPE_SECURITY_LOCAL_GROUP,	handle_alias_object },
	{ ATYPE_SECURITY_GLOBAL_GROUP,	handle_group_object },
	{ ATYPE_INTERDOMAIN_TRUST,	handle_interdomain_trust_object },
};

/****************************************************************
****************************************************************/

static NTSTATUS parse_object(TALLOC_CTX *mem_ctx,
			     struct pdb_methods *methods,
			     struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	NTSTATUS status = NT_STATUS_OK;
	DATA_BLOB *blob;
	int i = 0;
	int a = 0;
	struct drsuapi_DsReplicaAttribute *attr;

	char *name = NULL;
	uint32_t uacc = 0;
	uint32_t sam_type = 0;

	DEBUG(3, ("parsing object '%s'\n", cur->object.identifier->dn));

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
			case DRSUAPI_ATTID_sAMAccountName:
				pull_string_talloc(mem_ctx, NULL, 0, &name,
						   blob->data, blob->length,
						   STR_UNICODE);
				break;
			case DRSUAPI_ATTID_sAMAccountType:
				sam_type = IVAL(blob->data, 0);
				break;
			case DRSUAPI_ATTID_userAccountControl:
				uacc = IVAL(blob->data, 0);
				break;
			default:
				break;
		}
	}

	for (a=0; a < ARRAY_SIZE(dssync_object_table); a++) {
		if (sam_type == dssync_object_table[a].type) {
			if (dssync_object_table[a].fn) {
				status = dssync_object_table[a].fn(mem_ctx,
								   methods,
								   cur);
				break;
			}
		}
	}

	return status;
}

/****************************************************************
****************************************************************/

static NTSTATUS passdb_process_objects(struct dssync_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsReplicaObjectListItemEx *cur,
				       struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr)
{
	NTSTATUS status = NT_STATUS_OK;
	struct pdb_methods *methods =
		(struct pdb_methods *)ctx->private_data;

	for (; cur; cur = cur->next_object) {
		status = parse_object(mem_ctx, methods, cur);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

 out:
	return status;
}

/****************************************************************
****************************************************************/

const struct dssync_ops libnet_dssync_passdb_ops = {
	.startup		= passdb_startup,
	.process_objects	= passdb_process_objects,
	.finish			= passdb_finish,
};
