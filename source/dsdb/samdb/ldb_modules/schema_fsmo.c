/* 
   Unix SMB/CIFS mplementation.

   The module that handles the Schema FSMO Role Owner
   checkings, it also loads the dsdb_schema.
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
    
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
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/util/dlinklist.h"
#include "param/param.h"

static int schema_fsmo_init(struct ldb_module *module)
{
	TALLOC_CTX *mem_ctx;
	struct ldb_dn *schema_dn;
	struct dsdb_schema *schema;
	char *error_string = NULL;
	int ret;

	if (dsdb_get_schema(module->ldb)) {
		return ldb_next_init(module);
	}

	schema_dn = samdb_schema_dn(module->ldb);
	if (!schema_dn) {
		ldb_reset_err_string(module->ldb);
		ldb_debug(module->ldb, LDB_DEBUG_WARNING,
			  "schema_fsmo_init: no schema dn present: (skip schema loading)\n");
		return ldb_next_init(module);
	}

	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = dsdb_schema_from_schema_dn(mem_ctx, module->ldb,
					 lp_iconv_convenience(ldb_get_opaque(module->ldb, "loadparm")),
					 schema_dn, &schema, &error_string);

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ldb_reset_err_string(module->ldb);
		ldb_debug(module->ldb, LDB_DEBUG_WARNING,
			  "schema_fsmo_init: no schema head present: (skip schema loading)\n");
		talloc_free(mem_ctx);
		return ldb_next_init(module);
	}

	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(module->ldb, 
				       "schema_fsmo_init: dsdb_schema load failed: %s",
				       error_string);
		talloc_free(mem_ctx);
	}

	/* dsdb_set_schema() steal schema into the ldb_context */
	ret = dsdb_set_schema(module->ldb, schema);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_init: dsdb_set_schema() failed: %d:%s",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return ldb_next_init(module);
}

static int schema_fsmo_add(struct ldb_module *module, struct ldb_request *req)
{
	struct dsdb_schema *schema;
	const char *attributeID = NULL;
	const char *governsID = NULL;
	const char *oid_attr = NULL;
	const char *oid = NULL;
	uint32_t id32;
	WERROR status;

	schema = dsdb_get_schema(module->ldb);
	if (!schema) {
		return ldb_next_request(module, req);
	}

	if (!schema->fsmo.we_are_master) {
		ldb_debug_set(module->ldb, LDB_DEBUG_ERROR,
			  "schema_fsmo_add: we are not master: reject request\n");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	attributeID = samdb_result_string(req->op.add.message, "attributeID", NULL);
	governsID = samdb_result_string(req->op.add.message, "governsID", NULL);

	if (attributeID) {
		oid_attr = "attributeID";
		oid = attributeID;
	} else if (governsID) {
		oid_attr = "governsID";
		oid = governsID;
	}

	if (!oid) {
		return ldb_next_request(module, req);
	}

	status = dsdb_map_oid2int(schema, oid, &id32);
	if (W_ERROR_IS_OK(status)) {
		return ldb_next_request(module, req);
	} else if (!W_ERROR_EQUAL(WERR_DS_NO_MSDS_INTID, status)) {
		ldb_debug_set(module->ldb, LDB_DEBUG_ERROR,
			  "schema_fsmo_add: failed to map %s[%s]: %s\n",
			  oid_attr, oid, win_errstr(status));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	status = dsdb_create_prefix_mapping(module->ldb, schema, oid);
	if (!W_ERROR_IS_OK(status)) {
		ldb_debug_set(module->ldb, LDB_DEBUG_ERROR,
			  "schema_fsmo_add: failed to create prefix mapping for %s[%s]: %s\n",
			  oid_attr, oid, win_errstr(status));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	return ldb_next_request(module, req);
}

static int schema_fsmo_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_dn *schema_dn;
	struct dsdb_schema *schema;
	char *error_string = NULL;
	int ret;
	TALLOC_CTX *mem_ctx;
	
	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_SCHEMA_UPDATE_NOW_OID) != 0) {
		return ldb_next_request(module, req);
	}
	
	schema_dn = samdb_schema_dn(module->ldb);
	if (!schema_dn) {
		ldb_reset_err_string(module->ldb);
		ldb_debug(module->ldb, LDB_DEBUG_WARNING,
			  "schema_fsmo_extended: no schema dn present: (skip schema loading)\n");
		return ldb_next_request(module, req);
	}
	
	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ret = dsdb_schema_from_schema_dn(mem_ctx, module->ldb,
					 lp_iconv_convenience(ldb_get_opaque(module->ldb, "loadparm")),
					 schema_dn, &schema, &error_string);

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ldb_reset_err_string(module->ldb);
		ldb_debug(module->ldb, LDB_DEBUG_WARNING,
			  "schema_fsmo_extended: no schema head present: (skip schema loading)\n");
		talloc_free(mem_ctx);
		return ldb_next_request(module, req);
	}

	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(module->ldb, 
				       "schema_fsmo_extended: dsdb_schema load failed: %s",
				       error_string);
		talloc_free(mem_ctx);
		return ldb_next_request(module, req);
	}

	/* Replace the old schema*/
	ret = dsdb_set_schema(module->ldb, schema);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "schema_fsmo_extended: dsdb_set_schema() failed: %d:%s",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return LDB_SUCCESS;
}

_PUBLIC_ const struct ldb_module_ops ldb_schema_fsmo_module_ops = {
	.name		= "schema_fsmo",
	.init_context	= schema_fsmo_init,
	.add		= schema_fsmo_add,
	.extended	= schema_fsmo_extended
};
