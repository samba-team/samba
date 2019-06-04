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
#include <tdb.h>
#include "lib/tdb_wrap/tdb_wrap.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/ldb-samba/ldb_wrap.h"

#include "system/filesys.h"
struct schema_load_private_data {
	struct ldb_module *module;
	uint64_t in_transaction;
	uint64_t in_read_transaction;
	struct tdb_wrap *metadata;
	uint64_t schema_seq_num_cache;
	int tdb_seqnum;

	/*
	 * Please write out the updated schema on the next transaction
	 * start
	 */
	bool need_write;
};

static int dsdb_schema_from_db(struct ldb_module *module,
			       TALLOC_CTX *mem_ctx,
			       uint64_t schema_seq_num,
			       struct dsdb_schema **schema);

/*
 * Open sam.ldb.d/metadata.tdb.
 */
static int schema_metadata_open(struct ldb_module *module)
{
	struct schema_load_private_data *data = talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx;
	struct loadparm_context *lp_ctx;
	char *filename;
	int open_flags;
	struct stat statbuf;

	if (!data) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"schema_load: metadata not initialized");
	}
	data->metadata = NULL;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ldb_module_oom(module);
	}

	filename = ldb_relative_path(ldb,
				     tmp_ctx,
				     "sam.ldb.d/metadata.tdb");
	if (filename == NULL) {
		talloc_free(tmp_ctx);
		return ldb_module_oom(module);
	}

	open_flags = O_RDWR;
	if (stat(filename, &statbuf) != 0) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lp_ctx = talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"),
				       struct loadparm_context);

	data->metadata = tdb_wrap_open(data, filename, 10,
				       lpcfg_tdb_flags(lp_ctx, TDB_DEFAULT|TDB_SEQNUM),
				       open_flags, 0660);
	if (data->metadata == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

static int schema_metadata_get_uint64(struct schema_load_private_data *data,
					 const char *key, uint64_t *value,
					 uint64_t default_value)
{
	struct tdb_context *tdb;
	TDB_DATA tdb_key, tdb_data;
	char *value_str;
	TALLOC_CTX *tmp_ctx;
	int tdb_seqnum;
	int error = 0;

	if (!data) {
		*value = default_value;
		return LDB_SUCCESS;
	}

	if (!data->metadata) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	tdb_seqnum = tdb_get_seqnum(data->metadata->tdb);
	if (tdb_seqnum == data->tdb_seqnum) {
		*value = data->schema_seq_num_cache;
		return LDB_SUCCESS;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ldb_module_oom(data->module);
	}

	tdb = data->metadata->tdb;

	tdb_key.dptr = (uint8_t *)discard_const_p(char, key);
	tdb_key.dsize = strlen(key);

	tdb_data = tdb_fetch(tdb, tdb_key);
	if (!tdb_data.dptr) {
		if (tdb_error(tdb) == TDB_ERR_NOEXIST) {
			*value = default_value;
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		} else {
			talloc_free(tmp_ctx);
			return ldb_module_error(data->module, LDB_ERR_OPERATIONS_ERROR,
						tdb_errorstr(tdb));
		}
	}

	value_str = talloc_strndup(tmp_ctx, (char *)tdb_data.dptr, tdb_data.dsize);
	if (value_str == NULL) {
		SAFE_FREE(tdb_data.dptr);
		talloc_free(tmp_ctx);
		return ldb_module_oom(data->module);
	}

	/*
	 * Now store it in the cache.  We don't mind that tdb_seqnum
	 * may be stale now, that just means the cache won't be used
	 * next time
	 */
	data->tdb_seqnum = tdb_seqnum;
	data->schema_seq_num_cache = smb_strtoull(value_str,
						  NULL,
						  10,
						  &error,
						  SMB_STR_STANDARD);
	if (error != 0) {
		talloc_free(tmp_ctx);
		return ldb_module_error(data->module, LDB_ERR_OPERATIONS_ERROR,
					"Failed to convert value");
	}

	*value = data->schema_seq_num_cache;

	SAFE_FREE(tdb_data.dptr);
	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}

static struct dsdb_schema *dsdb_schema_refresh(struct ldb_module *module, struct tevent_context *ev,
					       struct dsdb_schema *schema, bool is_global_schema)
{
	TALLOC_CTX *mem_ctx;
	uint64_t schema_seq_num = 0;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_schema *new_schema;
	
	struct schema_load_private_data *private_data = talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);
	if (!private_data) {
		/* We can't refresh until the init function has run */
		return schema;
	}

	if (schema != NULL) {
		/*
		 * If we have a schema already (not in the startup)
		 * and we are in a read or write transaction, then
		 * avoid a schema reload, it can't have changed
		 */
		if (private_data->in_transaction > 0
		    || private_data->in_read_transaction > 0 ) {
			/*
			 * If the refresh is not an expected part of a
			 * larger transaction, then we don't allow a
			 * schema reload during a transaction. This
			 * stops others from modifying our schema
			 * behind our backs
			 */
			if (ldb_get_opaque(ldb,
					   "dsdb_schema_refresh_expected")
			    != (void *)1) {
				return schema;
			}
		}
	}

	SMB_ASSERT(ev == ldb_get_event_context(ldb));

	mem_ctx = talloc_new(module);
	if (mem_ctx == NULL) {
		return NULL;
	}

	/*
	 * We update right now the last refresh timestamp so that if
	 * the schema partition hasn't change we don't keep on retrying.
	 * Otherwise if the timestamp was update only when the schema has
	 * actually changed (and therefor completely reloaded) we would
	 * continue to hit the database to get the highest USN.
	 */

	ret = schema_metadata_get_uint64(private_data,
					 DSDB_METADATA_SCHEMA_SEQ_NUM,
					 &schema_seq_num, 0);

	if (schema != NULL) {
		if (ret == LDB_SUCCESS) {
			if (schema->metadata_usn == schema_seq_num) {
				TALLOC_FREE(mem_ctx);
				return schema;
			} else {
				DEBUG(3, ("Schema refresh needed %lld != %lld\n",
					  (unsigned long long)schema->metadata_usn,
					  (unsigned long long)schema_seq_num));
			}
		} else {
			/* From an old provision it can happen that the tdb didn't exists yet */
			DEBUG(0, ("Error while searching for the schema usn in the metadata ignoring: %d:%s:%s\n",
			      ret, ldb_strerror(ret), ldb_errstring(ldb)));
			TALLOC_FREE(mem_ctx);
			return schema;
		}
	} else {
		DEBUG(10, ("Initial schema load needed, as we have no existing schema, seq_num: %lld\n",
			  (unsigned long long)schema_seq_num));
	}

	ret = dsdb_schema_from_db(module, mem_ctx, schema_seq_num, &new_schema);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "dsdb_schema_from_db() failed: %d:%s: %s",
			      ret, ldb_strerror(ret), ldb_errstring(ldb));
		TALLOC_FREE(mem_ctx);
		return schema;
	}

	ret = dsdb_set_schema(ldb, new_schema, SCHEMA_MEMORY_ONLY);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "dsdb_set_schema() failed: %d:%s: %s",
			      ret, ldb_strerror(ret), ldb_errstring(ldb));
		TALLOC_FREE(mem_ctx);
		return schema;
	}
	if (is_global_schema) {
		dsdb_make_schema_global(ldb, new_schema);
	}
	TALLOC_FREE(mem_ctx);
	return new_schema;
}


/*
  Given an LDB module (pointing at the schema DB), and the DN, set the populated schema
*/

static int dsdb_schema_from_db(struct ldb_module *module,
			       TALLOC_CTX *mem_ctx,
			       uint64_t schema_seq_num,
			       struct dsdb_schema **schema)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx;
	char *error_string;
	int ret, i;
	struct ldb_dn *schema_dn = ldb_get_schema_basedn(ldb);
	struct ldb_result *res;
	struct ldb_message *schema_msg = NULL;
	static const char *schema_attrs[] = {
		DSDB_SCHEMA_COMMON_ATTRS,
		DSDB_SCHEMA_ATTR_ATTRS,
		DSDB_SCHEMA_CLASS_ATTRS,
		"prefixMap",
		"schemaInfo",
		"fSMORoleOwner",
		NULL
	};
	unsigned flags;

	tmp_ctx = talloc_new(module);
	if (!tmp_ctx) {
		return ldb_oom(ldb);
	}

	/* we don't want to trace the schema load */
	flags = ldb_get_flags(ldb);
	ldb_set_flags(ldb, flags & ~LDB_FLG_ENABLE_TRACING);

	/*
	 * Load the attribute and class definitions, as well as
	 * the schema object. We do this in one search and then
	 * split it so that there isn't a race condition when
	 * the schema is changed between two searches.
	 */
	ret = dsdb_module_search(module, tmp_ctx, &res,
				 schema_dn, LDB_SCOPE_SUBTREE,
				 schema_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT,
				 NULL,
				 "(|(objectClass=attributeSchema)"
				 "(objectClass=classSchema)"
				 "(objectClass=dMD))");
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema: failed to search attributeSchema and classSchema objects: %s",
				       ldb_errstring(ldb));
		goto failed;
	}

	/*
	 * Separate the schema object from the attribute and
	 * class objects.
	 */
	for (i = 0; i < res->count; i++) {
		if (ldb_msg_find_element(res->msgs[i], "prefixMap")) {
			schema_msg = res->msgs[i];
			break;
		}
	}

	if (schema_msg == NULL) {
		ldb_asprintf_errstring(ldb,
				       "dsdb_schema load failed: failed to find prefixMap");
		ret = LDB_ERR_NO_SUCH_ATTRIBUTE;
		goto failed;
	}

	ret = dsdb_schema_from_ldb_results(tmp_ctx, ldb,
					   schema_msg, res, schema, &error_string);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, 
				       "dsdb_schema load failed: %s",
				       error_string);
		goto failed;
	}

	(*schema)->metadata_usn = schema_seq_num;

	talloc_steal(mem_ctx, *schema);

failed:
	if (flags & LDB_FLG_ENABLE_TRACING) {
		flags = ldb_get_flags(ldb);
		ldb_set_flags(ldb, flags | LDB_FLG_ENABLE_TRACING);
	}
	talloc_free(tmp_ctx);
	return ret;
}	

static int schema_load(struct ldb_context *ldb,
		       struct ldb_module *module,
		       bool *need_write)
{
	struct dsdb_schema *schema;
	int ret, metadata_ret;
	TALLOC_CTX *frame = talloc_stackframe();
	
	schema = dsdb_get_schema(ldb, frame);

	metadata_ret = schema_metadata_open(module);

	/* We might already have a schema */
	if (schema != NULL) {
		/* If we have the metadata.tdb, then hook up the refresh function */
		if (metadata_ret == LDB_SUCCESS && dsdb_uses_global_schema(ldb)) {
			ret = dsdb_set_schema_refresh_function(ldb, dsdb_schema_refresh, module);

			if (ret != LDB_SUCCESS) {
				ldb_debug_set(ldb, LDB_DEBUG_FATAL,
					      "schema_load_init: dsdb_set_schema_refresh_fns() failed: %d:%s: %s",
					      ret, ldb_strerror(ret), ldb_errstring(ldb));
				TALLOC_FREE(frame);
				return ret;
			}
		}

		TALLOC_FREE(frame);
		return LDB_SUCCESS;
	}

	if (metadata_ret == LDB_SUCCESS) {
		ret = dsdb_set_schema_refresh_function(ldb, dsdb_schema_refresh, module);

		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "schema_load_init: dsdb_set_schema_refresh_fns() failed: %d:%s: %s",
				      ret, ldb_strerror(ret), ldb_errstring(ldb));
			TALLOC_FREE(frame);
			return ret;
		}
	} else {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_init: failed to open metadata.tdb");
		TALLOC_FREE(frame);
		return metadata_ret;
	}

	schema = dsdb_get_schema(ldb, frame);

	/* We do this, invoking the refresh handler, so we know that it works */
	if (schema == NULL) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_init: dsdb_get_schema failed");
		TALLOC_FREE(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Now check the @INDEXLIST is correct, or fix it up */
	ret = dsdb_schema_set_indices_and_attributes(ldb, schema,
						     SCHEMA_COMPARE);
	if (ret == LDB_ERR_BUSY) {
		*need_write = true;
		ret = LDB_SUCCESS;
	} else {
		*need_write = false;
	}

	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to update "
				       "@INDEXLIST and @ATTRIBUTES "
				       "records to match database schema: %s",
				       ldb_errstring(ldb));
		TALLOC_FREE(frame);
		return ret;
	}

	TALLOC_FREE(frame);
	return LDB_SUCCESS;
}

static int schema_load_init(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct schema_load_private_data *private_data =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct schema_load_private_data);
	int ret;

	ret = ldb_next_init(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return schema_load(ldb, module, &private_data->need_write);
}

static int schema_load_start_transaction(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct schema_load_private_data);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_schema *schema;
	int ret;

	ret = ldb_next_start_trans(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Try the schema refresh now */
	schema = dsdb_get_schema(ldb, NULL);
	if (schema == NULL) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_init: dsdb_get_schema failed");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (private_data->need_write) {
		ret = dsdb_schema_set_indices_and_attributes(ldb,
							     schema,
							     SCHEMA_WRITE);
		private_data->need_write = false;
	}

	private_data->in_transaction++;

	return ret;
}

static int schema_load_end_transaction(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct schema_load_private_data);
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	if (private_data->in_transaction == 0) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_end_transaction: transaction mismatch");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	private_data->in_transaction--;

	return ldb_next_end_trans(module);
}

static int schema_load_del_transaction(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	if (private_data->in_transaction == 0) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "schema_load_del_transaction: transaction mismatch");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	private_data->in_transaction--;

	return ldb_next_del_trans(module);
}

/* This is called in a transaction held by the callers */
static int schema_load_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_schema *schema;
	int ret;

	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_SCHEMA_LOAD) == 0) {

		ret = dsdb_schema_from_db(module, req, 0, &schema);
		if (ret == LDB_SUCCESS) {
			return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
		}
		return ret;

	} else if (strcmp(req->op.extended.oid, DSDB_EXTENDED_SCHEMA_UPDATE_NOW_OID) == 0) {
		/* Force a refresh */
		schema = dsdb_get_schema(ldb, NULL);

		ret = dsdb_schema_set_indices_and_attributes(ldb,
							     schema,
							     SCHEMA_WRITE);

		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "Failed to write new "
					       "@INDEXLIST and @ATTRIBUTES "
					       "records for updated schema: %s",
					       ldb_errstring(ldb));
			return ret;
		}

		return ldb_next_request(module, req);
	} else {
		/* Pass to next module, the partition one should finish the chain */
		return ldb_next_request(module, req);
	}
}

static int schema_read_lock(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type(ldb_module_get_private(module), struct schema_load_private_data);
	int ret;

	if (private_data == NULL) {
		private_data = talloc_zero(module, struct schema_load_private_data);
		if (private_data == NULL) {
			return ldb_module_oom(module);
		}

		private_data->module = module;

		ldb_module_set_private(module, private_data);
	}

	ret = ldb_next_read_lock(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (private_data->in_transaction == 0 &&
	    private_data->in_read_transaction == 0) {
		/* Try the schema refresh now */
		dsdb_get_schema(ldb_module_get_ctx(module), NULL);
	}

	private_data->in_read_transaction++;

	return LDB_SUCCESS;
}

static int schema_read_unlock(struct ldb_module *module)
{
	struct schema_load_private_data *private_data =
		talloc_get_type_abort(ldb_module_get_private(module),
				      struct schema_load_private_data);

	private_data->in_read_transaction--;

	return ldb_next_read_unlock(module);
}


static const struct ldb_module_ops ldb_schema_load_module_ops = {
	.name		= "schema_load",
	.init_context	= schema_load_init,
	.extended	= schema_load_extended,
	.start_transaction = schema_load_start_transaction,
	.end_transaction   = schema_load_end_transaction,
	.del_transaction   = schema_load_del_transaction,
	.read_lock	= schema_read_lock,
	.read_unlock	= schema_read_unlock,
};

int ldb_schema_load_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_schema_load_module_ops);
}
