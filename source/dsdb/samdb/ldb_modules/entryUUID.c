/* 
   ldb database module

   LDAP semantics mapping module

   Copyright (C) Jelmer Vernooij 2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* 
   This module relies on ldb_map to do all the real work, but performs
   some of the trivial mappings between AD semantics and that provided
   by OpenLDAP and similar servers.
*/

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/modules/ldb_map.h"

#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/ndr/libndr.h"

struct entryUUID_private {
	struct ldb_result *objectclass_res;	
};

static struct ldb_val encode_guid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct GUID guid;
	NTSTATUS status = GUID_from_string((char *)val->data, &guid);
	struct ldb_val out = data_blob(NULL, 0);

	if (!NT_STATUS_IS_OK(status)) {
		return out;
	}
	status = ndr_push_struct_blob(&out, ctx, &guid, 
				      (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NT_STATUS_IS_OK(status)) {
		return out;
	}

	return out;
}

static struct ldb_val decode_guid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct GUID *guid;
	NTSTATUS status;
	struct ldb_val out = data_blob(NULL, 0);
	
	guid = talloc(ctx, struct GUID);
	if (guid == NULL) {
		return out;
	}
	status = ndr_pull_struct_blob(val, guid, guid, 
				      (ndr_pull_flags_fn_t)ndr_pull_GUID);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(guid);
		return out;
	}
	out = data_blob_string_const(GUID_string(ctx, guid));
	talloc_free(guid);
	return out;
}

/* The backend holds binary sids, so just copy them back */
static struct ldb_val val_copy(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_val out = data_blob(NULL, 0);
	ldb_handler_copy(module->ldb, ctx, val, &out);

	return out;
}

/* Ensure we always convert sids into binary, so the backend doesn't have to know about both forms */
static struct ldb_val sid_always_binary(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_val out = data_blob(NULL, 0);
	const struct ldb_attrib_handler *handler = ldb_attrib_handler(module->ldb, "objectSid");
	
	if (handler->canonicalise_fn(module->ldb, ctx, val, &out) != LDB_SUCCESS) {
		return data_blob(NULL, 0);
	}

	return out;
}

static struct ldb_val objectCategory_always_dn(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	struct ldb_result *list;

	if (ldb_dn_explode(ctx, val->data)) {
		return *val;
	}
	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc_get_type(map_private->caller_private, struct entryUUID_private);
	list = entryUUID_private->objectclass_res;

	for (i=0; i < list->count; i++) {
		if (ldb_attr_cmp(val->data, ldb_msg_find_attr_as_string(list->msgs[i], "lDAPDisplayName", NULL)) == 0) {
			char *dn = ldb_dn_linearize(ctx, list->msgs[i]->dn);
			return data_blob_string_const(dn);
		}
	}
	return *val;
}

static struct ldb_val class_to_oid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	struct ldb_result *list;

	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc_get_type(map_private->caller_private, struct entryUUID_private);
	list = entryUUID_private->objectclass_res;

	for (i=0; i < list->count; i++) {
		if (ldb_attr_cmp(val->data, ldb_msg_find_attr_as_string(list->msgs[i], "lDAPDisplayName", NULL)) == 0) {
			const char *oid = ldb_msg_find_attr_as_string(list->msgs[i], "governsID", NULL);
			return data_blob_string_const(oid);
		}
	}
	return *val;
}

static struct ldb_val class_from_oid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	struct ldb_result *list;

	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc_get_type(map_private->caller_private, struct entryUUID_private);
	list = entryUUID_private->objectclass_res;

	for (i=0; i < list->count; i++) {
		if (ldb_attr_cmp(val->data, ldb_msg_find_attr_as_string(list->msgs[i], "governsID", NULL)) == 0) {
			const char *oc = ldb_msg_find_attr_as_string(list->msgs[i], "lDAPDisplayName", NULL);
			return data_blob_string_const(oc);
		}
	}
	return *val;
}




const struct ldb_map_attribute entryUUID_attributes[] = 
{
	/* objectGUID */
	{
		.local_name = "objectGUID",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "entryUUID", 
				.convert_local = decode_guid,
				.convert_remote = encode_guid,
			},
		},
	},
	/* objectSid */
	{
		.local_name = "objectSid",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "objectSid", 
				.convert_local = sid_always_binary,
				.convert_remote = val_copy,
			},
		},
	},
	{
		.local_name = "whenCreated",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				 .remote_name = "createTimestamp"
			 }
		}
	},
	{
		.local_name = "whenChanged",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				 .remote_name = "modifyTimestamp"
			 }
		}
	},
	{
		.local_name = "allowedChildClassesEffective",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "allowedChildClassesEffective", 
				.convert_local = class_to_oid,
				.convert_remote = class_from_oid,
			},
		},
	},
	{
		.local_name = "objectCategory",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "objectCategory", 
				.convert_local = objectCategory_always_dn,
				.convert_remote = val_copy,
			},
		},
	},
	{
		.local_name = "distinguishedName",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				 .remote_name = "entryDN"
			 }
		}
	},
	{
		.local_name = "*",
		.type = MAP_KEEP,
	},
	{
		.local_name = NULL,
	}
};

static struct ldb_dn *find_schema_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx) 
{
	const char *rootdse_attrs[] = {"schemaNamingContext", NULL};
	struct ldb_dn *schemadn;
	struct ldb_dn *basedn = ldb_dn_explode(mem_ctx, "");
	struct ldb_result *rootdse_res;
	int ldb_ret;
	if (!basedn) {
		return NULL;
	}
	
	/* Search for rootdse */
	ldb_ret = ldb_search(ldb, basedn, LDB_SCOPE_BASE, NULL, rootdse_attrs, &rootdse_res);
	if (ldb_ret != LDB_SUCCESS) {
		printf("Search failed: %s\n", ldb_errstring(ldb));
		return NULL;
	}
	
	talloc_steal(mem_ctx, rootdse_res);

	if (rootdse_res->count != 1) {
		printf("Failed to find rootDSE");
		return NULL;
	}
	
	/* Locate schema */
	schemadn = ldb_msg_find_attr_as_dn(mem_ctx, rootdse_res->msgs[0], "schemaNamingContext");
	if (!schemadn) {
		return NULL;
	}

	talloc_free(rootdse_res);
	return schemadn;
}

static int fetch_objectclass_schema(struct ldb_context *ldb, struct ldb_dn *schemadn,
			      TALLOC_CTX *mem_ctx, 
			      struct ldb_result **objectclass_res)
{
	TALLOC_CTX *local_ctx = talloc_new(mem_ctx);
	int ret;
	const char *attrs[] = {
		"lDAPDisplayName",
		"governsID",
		NULL
	};

	if (!local_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* Downlaod schema */
	ret = ldb_search(ldb, schemadn, LDB_SCOPE_SUBTREE, 
			 "objectClass=classSchema", 
			 attrs, objectclass_res);
	if (ret != LDB_SUCCESS) {
		printf("Search failed: %s\n", ldb_errstring(ldb));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	return ret;
}

/* the context init function */
static int entryUUID_init(struct ldb_module *module)
{
        int ret;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	struct ldb_dn *schema_dn;

	ret = ldb_map_init(module, entryUUID_attributes, NULL, NULL);
        if (ret != LDB_SUCCESS)
                return ret;

	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc(map_private, struct entryUUID_private);
	map_private->caller_private = entryUUID_private;

	schema_dn = find_schema_dn(module->ldb, map_private);
	if (!schema_dn) {
		printf("Failed to find schema DN: %s\n", ldb_errstring(module->ldb));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ret = fetch_objectclass_schema(module->ldb, schema_dn, entryUUID_private, &entryUUID_private->objectclass_res);
	if (ret != LDB_SUCCESS) {
		printf("Failed to fetch objectClass schema elements: %s\n", ldb_errstring(module->ldb));
		return ret;
	}
	
	
	return ldb_next_init(module);
}

static struct ldb_module_ops entryUUID_ops = {
	.name		   = "entryUUID",
	.init_context	   = entryUUID_init,
};

/* the init function */
int ldb_entryUUID_module_init(void)
{
	struct ldb_module_ops ops = ldb_map_get_ops();
	entryUUID_ops.add	= ops.add;
	entryUUID_ops.modify	= ops.modify;
	entryUUID_ops.del	= ops.del;
	entryUUID_ops.rename	= ops.rename;
	entryUUID_ops.search	= ops.search;
	entryUUID_ops.wait	= ops.wait;

	return ldb_register_module(&entryUUID_ops);
}
