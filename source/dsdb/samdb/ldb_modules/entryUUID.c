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
static struct ldb_val sid_copy(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
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
				.convert_remote = sid_copy,
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
		.local_name = "*",
		.type = MAP_KEEP,
	},
	{
		.local_name = NULL,
	}
};

/* the context init function */
static int entryUUID_init(struct ldb_module *module)
{
        int ret;

	ret = ldb_map_init(module, entryUUID_attributes, NULL, NULL);
        if (ret != LDB_SUCCESS)
                return ret;

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
