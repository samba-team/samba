/* 
   Unix SMB/CIFS mplementation.

   The module that handles the Schema FSMO Role Owner
   checkings, it also loads the dsdb_schema.
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009
    
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
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "dsdb/samdb/ldb_modules/util.h"

/*
  Given an LDB module (pointing at the schema DB), and the DN, set the populated schema
*/

static int dsdb_schema_from_schema_dn(TALLOC_CTX *mem_ctx, struct ldb_module *module,
				      struct smb_iconv_convenience *iconv_convenience, 
				      struct ldb_dn *schema_dn,
				      struct dsdb_schema **schema) 
{
	TALLOC_CTX *tmp_ctx;
	char *error_string;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_result *schema_res;
	struct ldb_result *a_res;
	struct ldb_result *c_res;
	static const char *schema_attrs[] = {
		"prefixMap",
		"schemaInfo",
		"fSMORoleOwner",
		NULL
	};
	unsigned flags;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we don't want to trace the schema load */
	flags = ldb_get_flags(ldb);
	ldb_set_flags(ldb, flags & ~LDB_FLG_ENABLE_TRACING);

	/*
	 * setup the prefix mappings and schema info
	 */
	ret = dsdb_module_search_dn(module, tmp_ctx, &schema_res,
				    schema_dn, schema_attrs);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		goto failed;
	} else if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema: failed to search the schema head: %s",
				       ldb_errstring(ldb));
		goto failed;
	}

	/*
	 * load the attribute definitions
	 */
	ret = dsdb_module_search(module, tmp_ctx, &a_res,
				 schema_dn, LDB_SCOPE_ONELEVEL, NULL,
				 "(objectClass=attributeSchema)");
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema: failed to search attributeSchema objects: %s",
				       ldb_errstring(ldb));
		goto failed;
	}

	/*
	 * load the objectClass definitions
	 */
	ret = dsdb_module_search(module, tmp_ctx, &c_res,
				 schema_dn, LDB_SCOPE_ONELEVEL, NULL,
				 "(objectClass=classSchema)");
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema: failed to search attributeSchema objects: %s",
				       ldb_errstring(ldb));
		goto failed;
	}

	ret = dsdb_schema_from_ldb_results(tmp_ctx, ldb,
					   lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")),
					   schema_res, a_res, c_res, schema, &error_string);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
						    "dsdb_schema load failed: %s",
						    error_string);
		goto failed;
	}
	talloc_steal(mem_ctx, *schema);

failed:
	if (flags & LDB_FLG_ENABLE_TRACING) {
		flags = ldb_get_flags(ldb);
		ldb_set_flags(ldb, flags | LDB_FLG_ENABLE_TRACING);
	}
	talloc_free(tmp_ctx);
	return ret;
}	


static int schema_load_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	TALLOC_CTX *mem_ctx;
	struct ldb_dn *schema_dn;
	struct dsdb_schema *schema;
	int ret;

	ret = ldb_next_init(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ldb = ldb_module_get_ctx(module);
	schema_dn = samdb_schema_dn(ldb);
	if (!schema_dn) {
		ldb_reset_err_string(ldb);
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "schema_load_init: no schema dn present: (skip schema loading)\n");
		return LDB_SUCCESS;
	}

	if (dsdb_get_schema(ldb)) {
		return LDB_SUCCESS;
	}

	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = dsdb_schema_from_schema_dn(mem_ctx, module,
					 lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")),
					 schema_dn, &schema);

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ldb_reset_err_string(ldb);
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "schema_load_init: no schema head present: (skip schema loading)\n");
		talloc_free(mem_ctx);
		return LDB_SUCCESS;
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}

	/* dsdb_set_schema() steal schema into the ldb_context */
	ret = dsdb_set_schema(ldb, schema);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_init: dsdb_set_schema() failed: %d:%s",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return LDB_SUCCESS;
}

static int schema_load_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_dn *schema_dn;
	struct dsdb_schema *schema;
	int ret;
	TALLOC_CTX *mem_ctx;

	ldb = ldb_module_get_ctx(module);

	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_SCHEMA_UPDATE_NOW_OID) != 0) {
		return ldb_next_request(module, req);
	}
	
	schema_dn = samdb_schema_dn(ldb);
	if (!schema_dn) {
		ldb_reset_err_string(ldb);
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "schema_load_extended: no schema dn present: (skip schema loading)\n");
		return ldb_next_request(module, req);
	}
	
	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ret = dsdb_schema_from_schema_dn(mem_ctx, module,
					 lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")),
					 schema_dn, &schema);

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ldb_reset_err_string(ldb);
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "schema_load_extended: no schema head present: (skip schema loading)\n");
		talloc_free(mem_ctx);
		return ldb_next_request(module, req);
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ldb_next_request(module, req);
	}

	/* Replace the old schema*/
	ret = dsdb_set_schema(ldb, schema);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_extended: dsdb_set_schema() failed: %d:%s",
			      ret, ldb_strerror(ret));
		talloc_free(mem_ctx);
		return ret;
	}

	dsdb_make_schema_global(ldb);

	talloc_free(mem_ctx);
	return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
}


_PUBLIC_ const struct ldb_module_ops ldb_schema_load_module_ops = {
	.name		= "schema_load",
	.init_context	= schema_load_init,
	.extended	= schema_load_extended,
};
