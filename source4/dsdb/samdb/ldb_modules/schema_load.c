/* 
   Unix SMB/CIFS mplementation.

   The module that handles the Schema FSMO Role Owner
   checkings, it also loads the dsdb_schema.
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009-2010

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

struct schema_load_private_data {
	bool in_transaction;
};

static int dsdb_schema_from_db(struct ldb_module *module, struct ldb_dn *schema_dn, uint64_t current_usn,
			       struct dsdb_schema **schema);

struct dsdb_schema *dsdb_schema_refresh(struct ldb_module *module, struct dsdb_schema *schema, bool is_global_schema)
{
	uint64_t current_usn;
	int ret;
	struct schema_load_private_data *private_data = talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);
	if (!private_data) {
		/* We can't refresh until the init function has run */
		return schema;
	}

	/* We don't allow a schema reload during a transaction - nobody else can modify our schema behind our backs */
	if (private_data->in_transaction) {
		return schema;
	}

	ret = dsdb_module_load_partition_usn(module, schema->base_dn, &current_usn, NULL);
	if (ret == LDB_SUCCESS && current_usn != schema->loaded_usn) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		struct dsdb_schema *new_schema;

		ret = dsdb_schema_from_db(module, schema->base_dn, current_usn, &new_schema);
		if (ret != LDB_SUCCESS) {
			return schema;
		}

		if (is_global_schema) {
			dsdb_make_schema_global(ldb, new_schema);
		}
		return new_schema;
	}
	return schema;
}


/*
  Given an LDB module (pointing at the schema DB), and the DN, set the populated schema
*/

static int dsdb_schema_from_db(struct ldb_module *module, struct ldb_dn *schema_dn, uint64_t current_usn,
			       struct dsdb_schema **schema)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx;
	char *error_string;
	int ret;
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

	tmp_ctx = talloc_new(module);
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
				    schema_dn, schema_attrs, 0);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ldb_reset_err_string(ldb);
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "schema_load_init: no schema head present: (skip schema loading)\n");
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
				 0, 
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
				 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				 "(objectClass=classSchema)");
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema: failed to search classSchema objects: %s",
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

	(*schema)->refresh_fn = dsdb_schema_refresh;
	(*schema)->loaded_from_module = module;
	(*schema)->loaded_usn = current_usn;

	/* dsdb_set_schema() steal schema into the ldb_context */
	ret = dsdb_set_schema(ldb, (*schema));

	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_init: dsdb_set_schema() failed: %d:%s: %s",
			      ret, ldb_strerror(ret), ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Ensure this module won't go away before the callback */
	if (talloc_reference(*schema, ldb) == NULL) {
		ldb_oom(ldb);
		ret = LDB_ERR_OPERATIONS_ERROR;
	}

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
	struct schema_load_private_data *private_data;
	struct dsdb_schema *schema;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret;
	uint64_t current_usn;
	struct ldb_dn *schema_dn;

	private_data = talloc_zero(module, struct schema_load_private_data);
	if (private_data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_module_set_private(module, private_data);

	ret = ldb_next_init(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (dsdb_get_schema(ldb, NULL)) {
		return LDB_SUCCESS;
	}

	schema_dn = samdb_schema_dn(ldb);
	if (!schema_dn) {
		ldb_reset_err_string(ldb);
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "schema_load_init: no schema dn present: (skip schema loading)\n");
		return LDB_SUCCESS;
	}

	ret = dsdb_module_load_partition_usn(module, schema_dn, &current_usn, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb,
				       "dsdb_load_partition_usn failed: %s",
				       ldb_errstring(ldb));
		return ret;
	}

	return dsdb_schema_from_db(module, schema_dn, current_usn, &schema);
}

static int schema_load_start_transaction(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);

	private_data->in_transaction = true;

	return ldb_next_start_trans(module);
}

static int schema_load_del_transaction(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);

	private_data->in_transaction = false;

	return ldb_next_del_trans(module);
}

static int schema_load_prepare_commit(struct ldb_module *module)
{
	int ret;
	struct schema_load_private_data *private_data =
		talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);

	ret = ldb_next_prepare_commit(module);
	private_data->in_transaction = false;
	return ret;
}

static int schema_load_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;

	ldb = ldb_module_get_ctx(module);

	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_SCHEMA_UPDATE_NOW_OID) != 0) {
		return ldb_next_request(module, req);
	}

	/* This is a no-op.  We reload as soon as we can */
	return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
}


_PUBLIC_ const struct ldb_module_ops ldb_schema_load_module_ops = {
	.name		= "schema_load",
	.init_context	= schema_load_init,
	.extended	= schema_load_extended,
	.start_transaction = schema_load_start_transaction,
	.prepare_commit    = schema_load_prepare_commit,
	.del_transaction   = schema_load_del_transaction,
};
