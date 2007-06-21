/* 
   Unix SMB/CIFS mplementation.

   The module that handles the Schema FSMO Role Owner
   checkings, it also loads the dsdb_schema.
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
    
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

#include "includes.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/util/dlinklist.h"

static int schema_fsmo_init(struct ldb_module *module)
{
	WERROR status;
	TALLOC_CTX *mem_ctx;
	struct ldb_dn *schema_dn;
	struct dsdb_schema *schema;
	struct dsdb_schema_fsmo *schema_fsmo;
	struct ldb_result *schema_res;
	const struct ldb_val *prefix_val;
	const struct ldb_val *info_val;
	struct ldb_val info_val_default;
	struct ldb_result *a_res;
	struct ldb_result *c_res;
	uint32_t i;
	int ret;
	static const char *schema_attrs[] = {
		"prefixMap",
		"schemaInfo",
		"fSMORoleOwner",
		NULL
	};

	if (dsdb_get_schema(module->ldb)) {
	  return ldb_next_init(module);
	}

	schema_dn = samdb_schema_dn(module->ldb);
	if (!schema_dn) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING,
			  "schema_fsmo_init: no schema dn present: (skip schema loading)\n");
		return ldb_next_init(module);
	}

	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	schema_fsmo = talloc_zero(mem_ctx, struct dsdb_schema_fsmo);
	if (!schema_fsmo) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	module->private_data = schema_fsmo;

	schema = talloc_zero(mem_ctx, struct dsdb_schema);
	if (!schema) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * setup the prefix mappings and schema info
	 */
	ret = ldb_search(module->ldb, schema_dn,
			 LDB_SCOPE_BASE,
			 NULL, schema_attrs,
			 &schema_res);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_init: failed to search the schema head: %d:%s\n",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}
	talloc_steal(mem_ctx, schema_res);
	if (schema_res->count == 0) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING,
			  "schema_fsmo_init: no schema head present: (skip schema loading)\n");
		talloc_free(mem_ctx);
		return ldb_next_init(module);
	} else if (schema_res->count > 1) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_init: [%u] schema heads found on a base search\n",
			      schema_res->count);
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	prefix_val = ldb_msg_find_ldb_val(schema_res->msgs[0], "prefixMap");
	if (!prefix_val) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_init: no prefixMap attribute found\n");
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	info_val = ldb_msg_find_ldb_val(schema_res->msgs[0], "schemaInfo");
	if (!info_val) {
		info_val_default = strhex_to_data_blob("FF0000000000000000000000000000000000000000");
		if (!info_val_default.data) {
			ldb_oom(module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		talloc_steal(mem_ctx, info_val_default.data);
		info_val = &info_val_default;
	}

	status = dsdb_load_oid_mappings_ldb(schema, prefix_val, info_val);
	if (!W_ERROR_IS_OK(status)) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_init: failed to load oid mappings: %s\n",
			      win_errstr(status));
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/*
	 * load the attribute definitions
	 */
	ret = ldb_search(module->ldb, schema_dn,
			 LDB_SCOPE_ONELEVEL,
			 "(objectClass=attributeSchema)", NULL,
			 &a_res);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_init: failed to search attributeSchema objects: %d:%s\n",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}
	talloc_steal(mem_ctx, a_res);

	for (i=0; i < a_res->count; i++) {
		struct dsdb_attribute *sa;

		sa = talloc_zero(schema, struct dsdb_attribute);
		if (!sa) {
			ldb_oom(module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		status = dsdb_attribute_from_ldb(schema, a_res->msgs[i], sa, sa);
		if (!W_ERROR_IS_OK(status)) {
			ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
				      "schema_fsmo_init: failed to load attriute definition: %s:%s\n",
				      ldb_dn_get_linearized(a_res->msgs[i]->dn),
				      win_errstr(status));
			talloc_free(mem_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		DLIST_ADD_END(schema->attributes, sa, struct dsdb_attribute *);
	}
	talloc_free(a_res);

	/*
	 * load the objectClass definitions
	 */
	ret = ldb_search(module->ldb, schema_dn,
			 LDB_SCOPE_ONELEVEL,
			 "(objectClass=classSchema)", NULL,
			 &c_res);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_init: failed to search classSchema objects: %d:%s\n",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}
	talloc_steal(mem_ctx, c_res);

	for (i=0; i < c_res->count; i++) {
		struct dsdb_class *sc;

		sc = talloc_zero(schema, struct dsdb_class);
		if (!sc) {
			ldb_oom(module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		status = dsdb_class_from_ldb(schema, c_res->msgs[i], sc, sc);
		if (!W_ERROR_IS_OK(status)) {
			ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
				      "schema_fsmo_init: failed to load class definition: %s:%s\n",
				      ldb_dn_get_linearized(c_res->msgs[i]->dn),
				      win_errstr(status));
			talloc_free(mem_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		DLIST_ADD_END(schema->classes, sc, struct dsdb_class *);
	}
	talloc_free(c_res);

	/* dsdb_set_schema() steal schema into the ldb_context */
	ret = dsdb_set_schema(module->ldb, schema);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_init: dsdb_set_schema() failed: %d:%s\n",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}

	schema_fsmo->master_dn = ldb_msg_find_attr_as_dn(module->ldb, schema_fsmo, schema_res->msgs[0], "fSMORoleOwner");
	if (ldb_dn_compare(samdb_ntds_settings_dn(module->ldb), schema_fsmo->master_dn) == 0) {
		schema_fsmo->we_are_master = true;
	} else {
		schema_fsmo->we_are_master = false;
	}

	if (ldb_set_opaque(module->ldb, "dsdb_schema_fsmo", schema_fsmo) != LDB_SUCCESS) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_steal(module, schema_fsmo);

	ldb_debug(module->ldb, LDB_DEBUG_TRACE,
			  "schema_fsmo_init: we are master: %s\n",
			  (schema_fsmo->we_are_master?"yes":"no"));

	talloc_free(mem_ctx);
	return ldb_next_init(module);
}

static const struct ldb_module_ops schema_fsmo_ops = {
	.name		= "schema_fsmo",
	.init_context	= schema_fsmo_init
};

int schema_fsmo_module_init(void)
{
	return ldb_register_module(&schema_fsmo_ops);
}
