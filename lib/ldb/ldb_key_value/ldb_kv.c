/*
   ldb database library

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2006-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009-2010

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb_kv
 *
 *  Component: ldb key value backend
 *
 *  Description: core functions for ldb key value backend
 *
 *  Author: Andrew Tridgell
 *  Author: Stefan Metzmacher
 *
 *  Modifications:
 *
 *  - description: make the module use asynchronous calls
 *    date: Feb 2006
 *    Author: Simo Sorce
 *
 *  - description: make it possible to use event contexts
 *    date: Jan 2008
 *    Author: Simo Sorce
 *
 *  - description: fix up memory leaks and small bugs
 *    date: Oct 2009
 *    Author: Matthias Dieter Wallnöfer
 */

#include "ldb_kv.h"
#include "ldb_private.h"
#include "lib/util/attr.h"

/*
  prevent memory errors on callbacks
*/
struct ldb_kv_req_spy {
	struct ldb_kv_context *ctx;
};

/*
 * Determine if this key could hold a record.  We allow the new GUID
 * index, the old DN index and a possible future ID=
 */
bool ldb_kv_key_is_normal_record(struct ldb_val key)
{
	if (key.length < 4) {
		return false;
	}

	/*
	 * @ records are not normal records, we don't want to index
	 * them nor search on them
	 */
	if (key.length > 4 &&
	    memcmp(key.data, "DN=@", 4) == 0) {
		return false;
	}

	/* All other DN= records are however */
	if (memcmp(key.data, "DN=", 3) == 0) {
		return true;
	}

	if (memcmp(key.data, "ID=", 3) == 0) {
		return true;
	}

	if (key.length < sizeof(LDB_KV_GUID_KEY_PREFIX)) {
		return false;
	}

	if (memcmp(key.data, LDB_KV_GUID_KEY_PREFIX,
		   sizeof(LDB_KV_GUID_KEY_PREFIX) - 1) == 0) {
		return true;
	}

	return false;
}

/*
  form a ldb_val for a record key
  caller frees

  note that the key for a record can depend on whether the
  dn refers to a case sensitive index record or not
*/
struct ldb_val ldb_kv_key_dn(TALLOC_CTX *mem_ctx,
			     struct ldb_dn *dn)
{
	struct ldb_val key;
	char *key_str = NULL;
	const char *dn_folded = NULL;

	/*
	  most DNs are case insensitive. The exception is index DNs for
	  case sensitive attributes

	  there are 3 cases dealt with in this code:

	  1) if the dn doesn't start with @ then uppercase the attribute
             names and the attributes values of case insensitive attributes
	  2) if the dn starts with @ then leave it alone -
	     the indexing code handles the rest
	*/

	dn_folded = ldb_dn_get_casefold(dn);
	if (!dn_folded) {
		goto failed;
	}

	key_str = talloc_strdup(mem_ctx, "DN=");
	if (!key_str) {
		goto failed;
	}

	key_str = talloc_strdup_append_buffer(key_str, dn_folded);
	if (!key_str) {
		goto failed;
	}

	key.data = (uint8_t *)key_str;
	key.length = strlen(key_str) + 1;

	return key;

failed:
	errno = ENOMEM;
	key.data = NULL;
	key.length = 0;
	return key;
}

/* The caller is to provide a correctly sized key */
int ldb_kv_guid_to_key(const struct ldb_val *GUID_val,
		       struct ldb_val *key)
{
	const char *GUID_prefix = LDB_KV_GUID_KEY_PREFIX;
	const int GUID_prefix_len = sizeof(LDB_KV_GUID_KEY_PREFIX) - 1;

	if (key->length != (GUID_val->length+GUID_prefix_len)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	memcpy(key->data, GUID_prefix, GUID_prefix_len);
	memcpy(&key->data[GUID_prefix_len],
	       GUID_val->data, GUID_val->length);
	return LDB_SUCCESS;
}

/*
 * The caller is to provide a correctly sized key, used only in
 * the GUID index mode
 */
int ldb_kv_idx_to_key(struct ldb_module *module,
		      struct ldb_kv_private *ldb_kv,
		      TALLOC_CTX *mem_ctx,
		      const struct ldb_val *idx_val,
		      struct ldb_val *key)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *dn;

	if (ldb_kv->cache->GUID_index_attribute != NULL) {
		return ldb_kv_guid_to_key(idx_val, key);
	}

	dn = ldb_dn_from_ldb_val(mem_ctx, ldb, idx_val);
	if (dn == NULL) {
		/*
		 * LDB_ERR_INVALID_DN_SYNTAX would just be confusing
		 * to the caller, as this in an invalid index value
		 */
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* form the key */
	*key = ldb_kv_key_dn(mem_ctx, dn);
	TALLOC_FREE(dn);
	if (!key->data) {
		return ldb_module_oom(module);
	}
	return LDB_SUCCESS;
}

/*
  form a TDB_DATA for a record key
  caller frees mem_ctx, which may or may not have the key
  as a child.

  note that the key for a record can depend on whether a
  GUID index is in use, or the DN is used as the key
*/
struct ldb_val ldb_kv_key_msg(struct ldb_module *module,
			TALLOC_CTX *mem_ctx,
			const struct ldb_message *msg)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct ldb_val key;
	const struct ldb_val *guid_val;
	int ret;

	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		return ldb_kv_key_dn(mem_ctx, msg->dn);
	}

	if (ldb_dn_is_special(msg->dn)) {
		return ldb_kv_key_dn(mem_ctx, msg->dn);
	}

	guid_val =
	    ldb_msg_find_ldb_val(msg, ldb_kv->cache->GUID_index_attribute);
	if (guid_val == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Did not find GUID attribute %s "
				       "in %s, required for TDB record "
				       "key in " LDB_KV_IDXGUID " mode.",
				       ldb_kv->cache->GUID_index_attribute,
				       ldb_dn_get_linearized(msg->dn));
		errno = EINVAL;
		key.data = NULL;
		key.length = 0;
		return key;
	}

	/* In this case, allocate with talloc */
	key.data = talloc_size(mem_ctx, LDB_KV_GUID_KEY_SIZE);
	if (key.data == NULL) {
		errno = ENOMEM;
		key.data = NULL;
		key.length = 0;
		return key;
	}
	key.length = talloc_get_size(key.data);

	ret = ldb_kv_guid_to_key(guid_val, &key);

	if (ret != LDB_SUCCESS) {
		errno = EINVAL;
		key.data = NULL;
		key.length = 0;
		return key;
	}
	return key;
}

/*
  check special dn's have valid attributes
  currently only @ATTRIBUTES is checked
*/
static int ldb_kv_check_special_dn(struct ldb_module *module,
				   const struct ldb_message *msg)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	unsigned int i, j;

	if (! ldb_dn_is_special(msg->dn) ||
	    ! ldb_dn_check_special(msg->dn, LDB_KV_ATTRIBUTES)) {
		return LDB_SUCCESS;
	}

	/* we have @ATTRIBUTES, let's check attributes are fine */
	/* should we check that we deny multivalued attributes ? */
	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(msg->elements[i].name, "distinguishedName") == 0) continue;

		for (j = 0; j < msg->elements[i].num_values; j++) {
			if (ldb_kv_check_at_attributes_values(
				&msg->elements[i].values[j]) != 0) {
				ldb_set_errstring(ldb, "Invalid attribute value in an @ATTRIBUTES entry");
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}
		}
	}

	return LDB_SUCCESS;
}

/*
 * Called after modifies and when starting a transaction. Checks target pack
 * format version and current pack format version, which are set by cache_load,
 * and repacks if necessary.
 */
static int ldb_kv_maybe_repack(struct ldb_kv_private *ldb_kv) {
	/* Override option taken from ldb options */
	if (ldb_kv->pack_format_override != 0) {
		ldb_kv->target_pack_format_version =
			ldb_kv->pack_format_override;
	}

	if (ldb_kv->pack_format_version !=
	    ldb_kv->target_pack_format_version) {
		int r;
		struct ldb_context *ldb = ldb_module_get_ctx(ldb_kv->module);
		r = ldb_kv_repack(ldb_kv->module);
		if (r != LDB_SUCCESS) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Database repack failed.");
		}
		return r;
	}

	return LDB_SUCCESS;
}

/*
  we've made a modification to a dn - possibly reindex and
  update sequence number
*/
static int ldb_kv_modified(struct ldb_module *module, struct ldb_dn *dn)
{
	int ret = LDB_SUCCESS;
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);

	/* only allow modifies inside a transaction, otherwise the
	 * ldb is unsafe */
	if (ldb_kv->kv_ops->transaction_active(ldb_kv) == false) {
		ldb_set_errstring(ldb_module_get_ctx(module), "ltdb modify without transaction");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ldb_dn_is_special(dn) &&
	    (ldb_dn_check_special(dn, LDB_KV_INDEXLIST) ||
	     ldb_dn_check_special(dn, LDB_KV_ATTRIBUTES)) )
	{
		if (ldb_kv->warn_reindex) {
			ldb_debug(ldb_module_get_ctx(module),
				  LDB_DEBUG_ERROR,
				  "Reindexing %s due to modification on %s",
				  ldb_kv->kv_ops->name(ldb_kv),
				  ldb_dn_get_linearized(dn));
		}
		ret = ldb_kv_reindex(module);
	}

	/* If the modify was to a normal record, or any special except @BASEINFO, update the seq number */
	if (ret == LDB_SUCCESS &&
	    !(ldb_dn_is_special(dn) &&
	      ldb_dn_check_special(dn, LDB_KV_BASEINFO)) ) {
		ret = ldb_kv_increase_sequence_number(module);
	}

	/* If the modify was to @OPTIONS, reload the cache */
	if (ret == LDB_SUCCESS &&
	    ldb_dn_is_special(dn) &&
	    (ldb_dn_check_special(dn, LDB_KV_OPTIONS)) ) {
		ret = ldb_kv_cache_reload(module);
	}

	if (ret != LDB_SUCCESS) {
		ldb_kv->reindex_failed = true;
	}

	return ret;
}
/*
  store a record into the db
*/
int ldb_kv_store(struct ldb_module *module,
		 const struct ldb_message *msg,
		 int flgs)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct ldb_val key;
	struct ldb_val ldb_data;
	int ret = LDB_SUCCESS;
	TALLOC_CTX *key_ctx = talloc_new(module);

	if (key_ctx == NULL) {
		return ldb_module_oom(module);
	}

	if (ldb_kv->read_only) {
		talloc_free(key_ctx);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	key = ldb_kv_key_msg(module, key_ctx, msg);
	if (key.data == NULL) {
		TALLOC_FREE(key_ctx);
		return LDB_ERR_OTHER;
	}

	ret = ldb_pack_data(ldb_module_get_ctx(module),
			    msg, &ldb_data,
			    ldb_kv->pack_format_version);
	if (ret == -1) {
		TALLOC_FREE(key_ctx);
		return LDB_ERR_OTHER;
	}

	ret = ldb_kv->kv_ops->store(ldb_kv, key, ldb_data, flgs);
	if (ret != 0) {
		bool is_special = ldb_dn_is_special(msg->dn);
		ret = ldb_kv->kv_ops->error(ldb_kv);

		/*
		 * LDB_ERR_ENTRY_ALREADY_EXISTS means the DN, not
		 * the GUID, so re-map
		 */
		if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS && !is_special &&
		    ldb_kv->cache->GUID_index_attribute != NULL) {
			ret = LDB_ERR_CONSTRAINT_VIOLATION;
		}
		goto done;
	}

done:
	TALLOC_FREE(key_ctx);
	talloc_free(ldb_data.data);

	return ret;
}


/*
  check if a attribute is a single valued, for a given element
 */
static bool ldb_kv_single_valued(const struct ldb_schema_attribute *a,
				 struct ldb_message_element *el)
{
	if (!a) return false;
	if (el != NULL) {
		if (el->flags & LDB_FLAG_INTERNAL_FORCE_SINGLE_VALUE_CHECK) {
			/* override from a ldb module, for example
			   used for the description field, which is
			   marked multi-valued in the schema but which
			   should not actually accept multiple
			   values */
			return true;
		}
		if (el->flags & LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK) {
			/* override from a ldb module, for example used for
			   deleted linked attribute entries */
			return false;
		}
	}
	if (a->flags & LDB_ATTR_FLAG_SINGLE_VALUE) {
		return true;
	}
	return false;
}

/*
 * Starts a sub transaction if they are supported by the backend
 * and the ldb connection has not been opened in batch mode.
 */
static int ldb_kv_sub_transaction_start(struct ldb_kv_private *ldb_kv)
{
	int ret = LDB_SUCCESS;

	if (ldb_kv->batch_mode) {
		return ret;
	}

	ret = ldb_kv->kv_ops->begin_nested_write(ldb_kv);
	if (ret == LDB_SUCCESS) {
		ret = ldb_kv_index_sub_transaction_start(ldb_kv);
	}
	return ret;
}

/*
 * Commits a sub transaction if they are supported by the backend
 * and the ldb connection has not been opened in batch mode.
 */
static int ldb_kv_sub_transaction_commit(struct ldb_kv_private *ldb_kv)
{
	int ret = LDB_SUCCESS;

	if (ldb_kv->batch_mode) {
		return ret;
	}

	ret = ldb_kv_index_sub_transaction_commit(ldb_kv);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = ldb_kv->kv_ops->finish_nested_write(ldb_kv);
	return ret;
}

/*
 * Cancels a sub transaction if they are supported by the backend
 * and the ldb connection has not been opened in batch mode.
 */
static int ldb_kv_sub_transaction_cancel(struct ldb_kv_private *ldb_kv)
{
	int ret = LDB_SUCCESS;

	if (ldb_kv->batch_mode) {
		return ret;
	}

	ret = ldb_kv_index_sub_transaction_cancel(ldb_kv);
	if (ret != LDB_SUCCESS) {
		struct ldb_context *ldb = ldb_module_get_ctx(ldb_kv->module);
		/*
		 * In the event of a failure we log the failure and continue
		 * as we need to cancel the database transaction.
		 */
		ldb_debug(ldb,
			  LDB_DEBUG_ERROR,
			  __location__": ldb_kv_index_sub_transaction_cancel "
			  "failed: %s",
			  ldb_errstring(ldb));
	}
	ret = ldb_kv->kv_ops->abort_nested_write(ldb_kv);
	return ret;
}

static int ldb_kv_add_internal(struct ldb_module *module,
			       struct ldb_kv_private *ldb_kv,
			       const struct ldb_message *msg,
			       bool check_single_value)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret = LDB_SUCCESS;
	unsigned int i;
	bool valid_dn = false;

	/* Check the new DN is reasonable */
	valid_dn = ldb_dn_validate(msg->dn);
	if (valid_dn == false) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Invalid DN in ADD: %s",
				       ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	for (i=0;i<msg->num_elements;i++) {
		struct ldb_message_element *el = &msg->elements[i];
		const struct ldb_schema_attribute *a = ldb_schema_attribute_by_name(ldb, el->name);

		if (el->num_values == 0) {
			ldb_asprintf_errstring(ldb, "attribute '%s' on '%s' specified, but with 0 values (illegal)",
					       el->name, ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if (check_single_value && el->num_values > 1 &&
		    ldb_kv_single_valued(a, el)) {
			ldb_asprintf_errstring(ldb, "SINGLE-VALUE attribute %s on %s specified more than once",
					       el->name, ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		/* Do not check "@ATTRIBUTES" for duplicated values */
		if (ldb_dn_is_special(msg->dn) &&
		    ldb_dn_check_special(msg->dn, LDB_KV_ATTRIBUTES)) {
			continue;
		}

		if (check_single_value &&
		    !(el->flags &
		      LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK)) {
			struct ldb_val *duplicate = NULL;

			ret = ldb_msg_find_duplicate_val(ldb, discard_const(msg),
							 el, &duplicate, 0);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			if (duplicate != NULL) {
				ldb_asprintf_errstring(
					ldb,
					"attribute '%s': value '%.*s' on '%s' "
					"provided more than once in ADD object",
					el->name,
					(int)duplicate->length,
					duplicate->data,
					ldb_dn_get_linearized(msg->dn));
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			}
		}
	}

	ret = ldb_kv_store(module, msg, TDB_INSERT);
	if (ret != LDB_SUCCESS) {
		/*
		 * Try really hard to get the right error code for
		 * a re-add situation, as this can matter!
		 */
		if (ret == LDB_ERR_CONSTRAINT_VIOLATION) {
			int ret2;
			struct ldb_dn *dn2 = NULL;
			TALLOC_CTX *mem_ctx = talloc_new(module);
			if (mem_ctx == NULL) {
				return ldb_module_operr(module);
			}
			ret2 =
			    ldb_kv_search_base(module, mem_ctx, msg->dn, &dn2);
			TALLOC_FREE(mem_ctx);
			if (ret2 == LDB_SUCCESS) {
				ret = LDB_ERR_ENTRY_ALREADY_EXISTS;
			}
		}
		if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
			ldb_asprintf_errstring(ldb,
					       "Entry %s already exists",
					       ldb_dn_get_linearized(msg->dn));
		}
		return ret;
	}

	ret = ldb_kv_index_add_new(module, ldb_kv, msg);
	if (ret != LDB_SUCCESS) {
		/*
		 * If we failed to index, delete the message again.
		 *
		 * This is particularly important for the GUID index
		 * case, which will only fail for a duplicate DN
		 * in the index add.
		 *
		 * Note that the caller may not cancel the transation
		 * and this means the above add might really show up!
		 */
		ldb_kv_delete_noindex(module, msg);
		return ret;
	}

	ret = ldb_kv_modified(module, msg->dn);

	/*
	 * To allow testing of the error recovery code in ldb_kv_add
	 * cmocka tests can define CMOCKA_UNIT_TEST_ADD_INTERNAL_FAIL
	 * to inject failures at this point.
	 */
#ifdef CMOCKA_UNIT_TEST_ADD_INTERNAL_FAIL
	CMOCKA_UNIT_TEST_ADD_INTERNAL_FAIL
#endif

	return ret;
}

/*
  add a record to the database
*/
static int ldb_kv_add(struct ldb_kv_context *ctx)
{
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	int ret = LDB_SUCCESS;

	if (ldb_kv->max_key_length != 0 &&
	    ldb_kv->cache->GUID_index_attribute == NULL &&
	    !ldb_dn_is_special(req->op.add.message->dn)) {
		ldb_set_errstring(ldb_module_get_ctx(module),
				  "Must operate ldb_mdb in GUID "
				  "index mode, but " LDB_KV_IDXGUID " not set.");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	ret = ldb_kv_check_special_dn(module, req->op.add.message);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ldb_kv_cache_load(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_sub_transaction_start(ldb_kv);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = ldb_kv_add_internal(module, ldb_kv, req->op.add.message, true);
	if (ret != LDB_SUCCESS) {
		int r = ldb_kv_sub_transaction_cancel(ldb_kv);
		if (r != LDB_SUCCESS) {
			ldb_debug(
				ldb_module_get_ctx(module),
				LDB_DEBUG_FATAL,
				__location__
				": Unable to roll back sub transaction");
		}
		ldb_kv->operation_failed = true;
		return ret;
	}
	ret = ldb_kv_sub_transaction_commit(ldb_kv);

	return ret;
}

/*
  delete a record from the database, not updating indexes (used for deleting
  index records)
*/
int ldb_kv_delete_noindex(struct ldb_module *module,
			  const struct ldb_message *msg)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct ldb_val key;
	int ret;
	TALLOC_CTX *tdb_key_ctx = talloc_new(module);

	if (tdb_key_ctx == NULL) {
		return ldb_module_oom(module);
	}

	if (ldb_kv->read_only) {
		talloc_free(tdb_key_ctx);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	key = ldb_kv_key_msg(module, tdb_key_ctx, msg);
	if (!key.data) {
		TALLOC_FREE(tdb_key_ctx);
		return LDB_ERR_OTHER;
	}

	ret = ldb_kv->kv_ops->delete(ldb_kv, key);
	TALLOC_FREE(tdb_key_ctx);

	if (ret != 0) {
		ret = ldb_kv->kv_ops->error(ldb_kv);
	}

	return ret;
}

static int ldb_kv_delete_internal(struct ldb_module *module, struct ldb_dn *dn)
{
	struct ldb_message *msg;
	int ret = LDB_SUCCESS;

	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* in case any attribute of the message was indexed, we need
	   to fetch the old record */
	ret = ldb_kv_search_dn1(module, dn, msg, 0);
	if (ret != LDB_SUCCESS) {
		/* not finding the old record is an error */
		goto done;
	}

	ret = ldb_kv_delete_noindex(module, msg);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	/* remove any indexed attributes */
	ret = ldb_kv_index_delete(module, msg);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	ret = ldb_kv_modified(module, dn);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

done:
	talloc_free(msg);
	/*
	 * To allow testing of the error recovery code in ldb_kv_delete
	 * cmocka tests can define CMOCKA_UNIT_TEST_DELETE_INTERNAL_FAIL
	 * to inject failures at this point.
	 */
#ifdef CMOCKA_UNIT_TEST_DELETE_INTERNAL_FAIL
	CMOCKA_UNIT_TEST_DELETE_INTERNAL_FAIL
#endif
	return ret;
}

/*
  delete a record from the database
*/
static int ldb_kv_delete(struct ldb_kv_context *ctx)
{
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	int ret = LDB_SUCCESS;

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ldb_kv_cache_load(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_sub_transaction_start(ldb_kv);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = ldb_kv_delete_internal(module, req->op.del.dn);
	if (ret != LDB_SUCCESS) {
		int r = ldb_kv_sub_transaction_cancel(ldb_kv);
		if (r != LDB_SUCCESS) {
			ldb_debug(
				ldb_module_get_ctx(module),
				LDB_DEBUG_FATAL,
				__location__
				": Unable to roll back sub transaction");
		}
		if (ret != LDB_ERR_NO_SUCH_OBJECT) {
			ldb_kv->operation_failed = true;
		}
		return ret;
	}
	ret = ldb_kv_sub_transaction_commit(ldb_kv);

	return ret;
}

/*
  find an element by attribute name. At the moment this does a linear search,
  it should be re-coded to use a binary search once all places that modify
  records guarantee sorted order

  return the index of the first matching element if found, otherwise -1
*/
static int ldb_kv_find_element(const struct ldb_message *msg, const char *name)
{
	unsigned int i;
	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, name) == 0) {
			return i;
		}
	}
	return -1;
}


/*
  add an element to an existing record. Assumes a elements array that we
  can call re-alloc on, and assumed that we can re-use the data pointers from
  the passed in additional values. Use with care!

  returns 0 on success, -1 on failure (and sets errno)
*/
static int ldb_kv_msg_add_element(struct ldb_message *msg,
				  struct ldb_message_element *el)
{
	struct ldb_message_element *e2;
	unsigned int i;

	if (el->num_values == 0) {
		/* nothing to do here - we don't add empty elements */
		return 0;
	}

	e2 = talloc_realloc(msg, msg->elements, struct ldb_message_element,
			      msg->num_elements+1);
	if (!e2) {
		errno = ENOMEM;
		return -1;
	}

	msg->elements = e2;

	e2 = &msg->elements[msg->num_elements];

	e2->name = el->name;
	e2->flags = el->flags;
	e2->values = talloc_array(msg->elements,
				  struct ldb_val, el->num_values);
	if (!e2->values) {
		errno = ENOMEM;
		return -1;
	}
	for (i=0;i<el->num_values;i++) {
		e2->values[i] = el->values[i];
	}
	e2->num_values = el->num_values;

	++msg->num_elements;

	return 0;
}

/*
  delete all elements having a specified attribute name
*/
static int ldb_kv_msg_delete_attribute(struct ldb_module *module,
				       struct ldb_kv_private *ldb_kv,
				       struct ldb_message *msg,
				       const char *name)
{
	int ret;
	struct ldb_message_element *el;
	bool is_special = ldb_dn_is_special(msg->dn);

	if (!is_special && ldb_kv->cache->GUID_index_attribute != NULL &&
	    ldb_attr_cmp(name, ldb_kv->cache->GUID_index_attribute) == 0) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(ldb,
				       "Must not modify GUID "
				       "attribute %s (used as DB index)",
				       ldb_kv->cache->GUID_index_attribute);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	el = ldb_msg_find_element(msg, name);
	if (el == NULL) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	ret = ldb_kv_index_del_element(module, ldb_kv, msg, el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_free(el->values);
	ldb_msg_remove_element(msg, el);
	msg->elements = talloc_realloc(msg, msg->elements,
				       struct ldb_message_element,
				       msg->num_elements);
	return LDB_SUCCESS;
}

/*
  delete all elements matching an attribute name/value

  return LDB Error on failure
*/
static int ldb_kv_msg_delete_element(struct ldb_module *module,
				     struct ldb_kv_private *ldb_kv,
				     struct ldb_message *msg,
				     const char *name,
				     const struct ldb_val *val)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	unsigned int i;
	int found, ret;
	struct ldb_message_element *el;
	const struct ldb_schema_attribute *a;

	found = ldb_kv_find_element(msg, name);
	if (found == -1) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	i = (unsigned int) found;
	el = &(msg->elements[i]);

	a = ldb_schema_attribute_by_name(ldb, el->name);

	for (i=0;i<el->num_values;i++) {
		bool matched;
		if (a->syntax->operator_fn) {
			ret = a->syntax->operator_fn(ldb, LDB_OP_EQUALITY, a,
						     &el->values[i], val, &matched);
			if (ret != LDB_SUCCESS) return ret;
		} else {
			matched = (a->syntax->comparison_fn(ldb, ldb,
							    &el->values[i], val) == 0);
		}
		if (matched) {
			if (el->num_values == 1) {
				return ldb_kv_msg_delete_attribute(
				    module, ldb_kv, msg, name);
			}

			ret =
			    ldb_kv_index_del_value(module, ldb_kv, msg, el, i);
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			if (i<el->num_values-1) {
				memmove(&el->values[i], &el->values[i+1],
					sizeof(el->values[i])*
						(el->num_values-(i+1)));
			}
			el->num_values--;

			/* per definition we find in a canonicalised message an
			   attribute value only once. So we are finished here */
			return LDB_SUCCESS;
		}
	}

	/* Not found */
	return LDB_ERR_NO_SUCH_ATTRIBUTE;
}

/*
  modify a record - internal interface

  yuck - this is O(n^2). Luckily n is usually small so we probably
  get away with it, but if we ever have really large attribute lists
  then we'll need to look at this again

  'req' is optional, and is used to specify controls if supplied
*/
int ldb_kv_modify_internal(struct ldb_module *module,
			   const struct ldb_message *msg,
			   struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct ldb_message *msg2;
	unsigned int i, j;
	int ret = LDB_SUCCESS, idx;
	struct ldb_control *control_permissive = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(req);

	if (mem_ctx == NULL) {
		return ldb_module_oom(module);
	}

	if (req) {
		control_permissive = ldb_request_get_control(req,
					LDB_CONTROL_PERMISSIVE_MODIFY_OID);
	}

	msg2 = ldb_msg_new(mem_ctx);
	if (msg2 == NULL) {
		ret = LDB_ERR_OTHER;
		goto done;
	}

	ret = ldb_kv_search_dn1(module, msg->dn, msg2, 0);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	for (i=0; i<msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i], *el2;
		struct ldb_val *vals;
		const struct ldb_schema_attribute *a = ldb_schema_attribute_by_name(ldb, el->name);
		const char *dn;
		uint32_t options = 0;
		if (control_permissive != NULL) {
			options |= LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES;
		}

		switch (msg->elements[i].flags & LDB_FLAG_MOD_MASK) {
		case LDB_FLAG_MOD_ADD:

			if (el->num_values == 0) {
				ldb_asprintf_errstring(ldb,
						       "attribute '%s': attribute on '%s' specified, but with 0 values (illegal)",
						       el->name, ldb_dn_get_linearized(msg2->dn));
				ret = LDB_ERR_CONSTRAINT_VIOLATION;
				goto done;
			}

			/* make a copy of the array so that a permissive
			 * control can remove duplicates without changing the
			 * original values, but do not copy data as we do not
			 * need to keep it around once the operation is
			 * finished */
			if (control_permissive) {
				el = talloc(msg2, struct ldb_message_element);
				if (!el) {
					ret = LDB_ERR_OTHER;
					goto done;
				}
				*el = msg->elements[i];
				el->values = talloc_array(el, struct ldb_val, el->num_values);
				if (el->values == NULL) {
					ret = LDB_ERR_OTHER;
					goto done;
				}
				for (j = 0; j < el->num_values; j++) {
					el->values[j] = msg->elements[i].values[j];
				}
			}

			if (el->num_values > 1 && ldb_kv_single_valued(a, el)) {
				ldb_asprintf_errstring(ldb, "SINGLE-VALUE attribute %s on %s specified more than once",
						       el->name, ldb_dn_get_linearized(msg2->dn));
				ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
				goto done;
			}

			/* Checks if element already exists */
			idx = ldb_kv_find_element(msg2, el->name);
			if (idx == -1) {
				if (ldb_kv_msg_add_element(msg2, el) != 0) {
					ret = LDB_ERR_OTHER;
					goto done;
				}
				ret = ldb_kv_index_add_element(
				    module, ldb_kv, msg2, el);
				if (ret != LDB_SUCCESS) {
					goto done;
				}
			} else {
				j = (unsigned int) idx;
				el2 = &(msg2->elements[j]);

				/* We cannot add another value on a existing one
				   if the attribute is single-valued */
				if (ldb_kv_single_valued(a, el)) {
					ldb_asprintf_errstring(ldb, "SINGLE-VALUE attribute %s on %s specified more than once",
						               el->name, ldb_dn_get_linearized(msg2->dn));
					ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
					goto done;
				}

				/* Check that values don't exist yet on multi-
				   valued attributes or aren't provided twice */
				if (!(el->flags &
				      LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK)) {
					struct ldb_val *duplicate = NULL;
					ret = ldb_msg_find_common_values(ldb,
									 msg2,
									 el,
									 el2,
									 options);

					if (ret ==
					    LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS) {
						ldb_asprintf_errstring(ldb,
							"attribute '%s': value "
							"#%u on '%s' already "
							"exists", el->name, j,
							ldb_dn_get_linearized(msg2->dn));
						goto done;
					} else if (ret != LDB_SUCCESS) {
						goto done;
					}

					ret = ldb_msg_find_duplicate_val(
						ldb, msg2, el, &duplicate, 0);
					if (ret != LDB_SUCCESS) {
						goto done;
					}
					if (duplicate != NULL) {
						ldb_asprintf_errstring(
							ldb,
							"attribute '%s': value "
							"'%.*s' on '%s' "
							"provided more than "
							"once in ADD",
							el->name,
							(int)duplicate->length,
							duplicate->data,
							ldb_dn_get_linearized(msg->dn));
						ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
						goto done;
					}
				}

				/* Now combine existing and new values to a new
				   attribute record */
				vals = talloc_realloc(msg2->elements,
						      el2->values, struct ldb_val,
						      el2->num_values + el->num_values);
				if (vals == NULL) {
					ldb_oom(ldb);
					ret = LDB_ERR_OTHER;
					goto done;
				}

				for (j=0; j<el->num_values; j++) {
					vals[el2->num_values + j] =
						ldb_val_dup(vals, &el->values[j]);
				}

				el2->values = vals;
				el2->num_values += el->num_values;

				ret = ldb_kv_index_add_element(
				    module, ldb_kv, msg2, el);
				if (ret != LDB_SUCCESS) {
					goto done;
				}
			}

			break;

		case LDB_FLAG_MOD_REPLACE:

			if (el->num_values > 1 && ldb_kv_single_valued(a, el)) {
				ldb_asprintf_errstring(ldb, "SINGLE-VALUE attribute %s on %s specified more than once",
						       el->name, ldb_dn_get_linearized(msg2->dn));
				ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
				goto done;
			}

			/*
			 * We don't need to check this if we have been
			 * pre-screened by the repl_meta_data module
			 * in Samba, or someone else who can claim to
			 * know what they are doing.
			 */
			if (!(el->flags & LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK)) {
				struct ldb_val *duplicate = NULL;

				ret = ldb_msg_find_duplicate_val(ldb, msg2, el,
								 &duplicate, 0);
				if (ret != LDB_SUCCESS) {
					goto done;
				}
				if (duplicate != NULL) {
					ldb_asprintf_errstring(
						ldb,
						"attribute '%s': value '%.*s' "
						"on '%s' provided more than "
						"once in REPLACE",
						el->name,
						(int)duplicate->length,
						duplicate->data,
						ldb_dn_get_linearized(msg2->dn));
					ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
					goto done;
				}
			}

			/* Checks if element already exists */
			idx = ldb_kv_find_element(msg2, el->name);
			if (idx != -1) {
				j = (unsigned int) idx;
				el2 = &(msg2->elements[j]);

				/* we consider two elements to be
				 * equal only if the order
				 * matches. This allows dbcheck to
				 * fix the ordering on attributes
				 * where order matters, such as
				 * objectClass
				 */
				if (ldb_msg_element_equal_ordered(el, el2)) {
					continue;
				}

				/* Delete the attribute if it exists in the DB */
				if (ldb_kv_msg_delete_attribute(
					module, ldb_kv, msg2, el->name) != 0) {
					ret = LDB_ERR_OTHER;
					goto done;
				}
			}

			/* Recreate it with the new values */
			if (ldb_kv_msg_add_element(msg2, el) != 0) {
				ret = LDB_ERR_OTHER;
				goto done;
			}

			ret =
			    ldb_kv_index_add_element(module, ldb_kv, msg2, el);
			if (ret != LDB_SUCCESS) {
				goto done;
			}

			break;

		case LDB_FLAG_MOD_DELETE:
			dn = ldb_dn_get_linearized(msg2->dn);
			if (dn == NULL) {
				ret = LDB_ERR_OTHER;
				goto done;
			}

			if (msg->elements[i].num_values == 0) {
				/* Delete the whole attribute */
				ret = ldb_kv_msg_delete_attribute(
				    module,
				    ldb_kv,
				    msg2,
				    msg->elements[i].name);
				if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE &&
				    control_permissive) {
					ret = LDB_SUCCESS;
				} else {
					ldb_asprintf_errstring(ldb,
							       "attribute '%s': no such attribute for delete on '%s'",
							       msg->elements[i].name, dn);
				}
				if (ret != LDB_SUCCESS) {
					goto done;
				}
			} else {
				/* Delete specified values from an attribute */
				for (j=0; j < msg->elements[i].num_values; j++) {
					ret = ldb_kv_msg_delete_element(
					    module,
					    ldb_kv,
					    msg2,
					    msg->elements[i].name,
					    &msg->elements[i].values[j]);
					if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE &&
					    control_permissive) {
						ret = LDB_SUCCESS;
					} else if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
						ldb_asprintf_errstring(ldb,
								       "attribute '%s': no matching attribute value while deleting attribute on '%s'",
								       msg->elements[i].name, dn);
					}
					if (ret != LDB_SUCCESS) {
						goto done;
					}
				}
			}
			break;
		default:
			ldb_asprintf_errstring(ldb,
					       "attribute '%s': invalid modify flags on '%s': 0x%x",
					       msg->elements[i].name, ldb_dn_get_linearized(msg->dn),
					       msg->elements[i].flags & LDB_FLAG_MOD_MASK);
			ret = LDB_ERR_PROTOCOL_ERROR;
			goto done;
		}
	}

	ret = ldb_kv_store(module, msg2, TDB_MODIFY);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	ret = ldb_kv_modified(module, msg2->dn);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

done:
	TALLOC_FREE(mem_ctx);
	/*
	 * To allow testing of the error recovery code in ldb_kv_modify
	 * cmocka tests can define CMOCKA_UNIT_TEST_MODIFY_INTERNAL_FAIL
	 * to inject failures at this point.
	 */
#ifdef CMOCKA_UNIT_TEST_MODIFY_INTERNAL_FAIL
	CMOCKA_UNIT_TEST_MODIFY_INTERNAL_FAIL
#endif
	return ret;
}

/*
  modify a record
*/
static int ldb_kv_modify(struct ldb_kv_context *ctx)
{
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	int ret = LDB_SUCCESS;

	ret = ldb_kv_check_special_dn(module, req->op.mod.message);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ldb_kv_cache_load(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_sub_transaction_start(ldb_kv);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret = ldb_kv_modify_internal(module, req->op.mod.message, req);
	if (ret != LDB_SUCCESS) {
		int r = ldb_kv_sub_transaction_cancel(ldb_kv);
		if (r != LDB_SUCCESS) {
			ldb_debug(
				ldb_module_get_ctx(module),
				LDB_DEBUG_FATAL,
				__location__
				": Unable to roll back sub transaction");
		}
		if (ret != LDB_ERR_NO_SUCH_OBJECT) {
			ldb_kv->operation_failed = true;
		}
		return ret;
	}
	ret = ldb_kv_sub_transaction_commit(ldb_kv);


	return ret;
}

static int ldb_kv_rename_internal(struct ldb_module *module,
			   struct ldb_request *req,
			   struct ldb_message *msg)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	int ret = LDB_SUCCESS;

	/* Always delete first then add, to avoid conflicts with
	 * unique indexes. We rely on the transaction to make this
	 * atomic
	 */
	ret = ldb_kv_delete_internal(module, msg->dn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	msg->dn = ldb_dn_copy(msg, req->op.rename.newdn);
	if (msg->dn == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* We don't check single value as we can have more than 1 with
	 * deleted attributes. We could go through all elements but that's
	 * maybe not the most efficient way
	 */
	ret = ldb_kv_add_internal(module, ldb_kv, msg, false);

	/*
	 * To allow testing of the error recovery code in ldb_kv_rename
	 * cmocka tests can define CMOCKA_UNIT_TEST_RENAME_INTERNAL_FAIL
	 * to inject failures at this point.
	 */
#ifdef CMOCKA_UNIT_TEST_RENAME_INTERNAL_FAIL
	CMOCKA_UNIT_TEST_RENAME_INTERNAL_FAIL
#endif
	return ret;
}

/*
  rename a record
*/
static int ldb_kv_rename(struct ldb_kv_context *ctx)
{
	struct ldb_module *module = ctx->module;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct ldb_request *req = ctx->req;
	struct ldb_message *msg;
	int ret = LDB_SUCCESS;
	struct ldb_val  key, key_old;
	struct ldb_dn *db_dn;
	bool valid_dn = false;

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ldb_kv_cache_load(ctx->module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg = ldb_msg_new(ctx);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Check the new DN is reasonable */
	valid_dn = ldb_dn_validate(req->op.rename.newdn);
	if (valid_dn == false) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Invalid New DN: %s",
				       ldb_dn_get_linearized(req->op.rename.newdn));
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	/* we need to fetch the old record to re-add under the new name */
	ret = ldb_kv_search_dn1(module, req->op.rename.olddn, msg, 0);
	if (ret == LDB_ERR_INVALID_DN_SYNTAX) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Invalid Old DN: %s",
				       ldb_dn_get_linearized(req->op.rename.newdn));
		return ret;
	} else if (ret != LDB_SUCCESS) {
		/* not finding the old record is an error */
		return ret;
	}

	/* We need to, before changing the DB, check if the new DN
	 * exists, so we can return this error to the caller with an
	 * unmodified DB
	 *
	 * Even in GUID index mode we use ltdb_key_dn() as we are
	 * trying to figure out if this is just a case rename
	 */
	key = ldb_kv_key_dn(msg, req->op.rename.newdn);
	if (!key.data) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	key_old = ldb_kv_key_dn(msg, req->op.rename.olddn);
	if (!key_old.data) {
		talloc_free(msg);
		talloc_free(key.data);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Only declare a conflict if the new DN already exists,
	 * and it isn't a case change on the old DN
	 */
	if (key_old.length != key.length
	    || memcmp(key.data, key_old.data, key.length) != 0) {
		ret = ldb_kv_search_base(
		    module, msg, req->op.rename.newdn, &db_dn);
		if (ret == LDB_SUCCESS) {
			ret = LDB_ERR_ENTRY_ALREADY_EXISTS;
		} else if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			ret = LDB_SUCCESS;
		}
	}

	/* finding the new record already in the DB is an error */

	if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Entry %s already exists",
				       ldb_dn_get_linearized(req->op.rename.newdn));
	}
	if (ret != LDB_SUCCESS) {
		talloc_free(key_old.data);
		talloc_free(key.data);
		talloc_free(msg);
		return ret;
	}

	talloc_free(key_old.data);
	talloc_free(key.data);


	ret = ldb_kv_sub_transaction_start(ldb_kv);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}
	ret = ldb_kv_rename_internal(module, req, msg);
	if (ret != LDB_SUCCESS) {
		int r = ldb_kv_sub_transaction_cancel(ldb_kv);
		if (r != LDB_SUCCESS) {
			ldb_debug(
				ldb_module_get_ctx(module),
				LDB_DEBUG_FATAL,
				__location__
				": Unable to roll back sub transaction");
		}
		talloc_free(msg);
		ldb_kv->operation_failed = true;
		return ret;
	}
	ret = ldb_kv_sub_transaction_commit(ldb_kv);
	talloc_free(msg);

	return ret;
}

static int ldb_kv_start_trans(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);

	pid_t pid = getpid();

	if (ldb_kv->pid != pid) {
		ldb_asprintf_errstring(ldb_module_get_ctx(ldb_kv->module),
				       __location__
				       ": Reusing ldb opend by pid %d in "
				       "process %d\n",
				       ldb_kv->pid,
				       pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	/* Do not take out the transaction lock on a read-only DB */
	if (ldb_kv->read_only) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (ldb_kv->kv_ops->begin_write(ldb_kv) != 0) {
		return ldb_kv->kv_ops->error(ldb_kv);
	}

	ldb_kv_index_transaction_start(
		module,
		ldb_kv->index_transaction_cache_size);

	ldb_kv->reindex_failed = false;
	ldb_kv->operation_failed = false;

	return LDB_SUCCESS;
}

/*
 * Forward declaration to allow prepare_commit to in fact abort the
 * transaction
 */
static int ldb_kv_del_trans(struct ldb_module *module);

static int ldb_kv_prepare_commit(struct ldb_module *module)
{
	int ret;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	pid_t pid = getpid();

	if (ldb_kv->pid != pid) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       __location__
				       ": Reusing ldb opend by pid %d in "
				       "process %d\n",
				       ldb_kv->pid,
				       pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (!ldb_kv->kv_ops->transaction_active(ldb_kv)) {
		ldb_set_errstring(ldb_module_get_ctx(module),
				  "ltdb_prepare_commit() called "
				  "without transaction active");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Check if the last re-index failed.
	 *
	 * This can happen if for example a duplicate value was marked
	 * unique.  We must not write a partial re-index into the DB.
	 */
	if (ldb_kv->reindex_failed) {
		/*
		 * We must instead abort the transaction so we get the
		 * old values and old index back
		 */
		ldb_kv_del_trans(module);
		ldb_set_errstring(ldb_module_get_ctx(module),
				  "Failure during re-index, so "
				  "transaction must be aborted.");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_index_transaction_commit(module);
	if (ret != LDB_SUCCESS) {
		ldb_kv->kv_ops->abort_write(ldb_kv);
		return ret;
	}

	/*
	 * If GUID indexing was toggled in this transaction, we repack at
	 * format version 2 if GUID indexing was enabled, or version 1 if
	 * it was disabled.
	 */
	ret = ldb_kv_maybe_repack(ldb_kv);
	if (ret != LDB_SUCCESS) {
		ldb_kv_del_trans(module);
		ldb_set_errstring(ldb_module_get_ctx(module),
				  "Failure during re-pack, so "
				  "transaction must be aborted.");
		return ret;
	}

	if (ldb_kv->kv_ops->prepare_write(ldb_kv) != 0) {
		ret = ldb_kv->kv_ops->error(ldb_kv);
		ldb_debug_set(ldb_module_get_ctx(module),
			      LDB_DEBUG_FATAL,
			      "Failure during "
			      "prepare_write): %s -> %s",
			      ldb_kv->kv_ops->errorstr(ldb_kv),
			      ldb_strerror(ret));
		return ret;
	}

	ldb_kv->prepared_commit = true;

	return LDB_SUCCESS;
}

static int ldb_kv_end_trans(struct ldb_module *module)
{
	int ret;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);

	/*
	 * If in batch mode and there has been an operation failure
	 * rollback the transaction rather than committing it to avoid
	 * any possible corruption
	 */
	if (ldb_kv->batch_mode && ldb_kv->operation_failed) {
		ret = ldb_kv_del_trans( module);
		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb_module_get_ctx(module),
				      LDB_DEBUG_FATAL,
				      "An operation failed during a batch mode "
				      "transaction. The transaction could not"
				      "be rolled back, ldb_kv_del_trans "
				      "returned (%s, %s)",
				      ldb_kv->kv_ops->errorstr(ldb_kv),
				      ldb_strerror(ret));
		} else {
			ldb_debug_set(ldb_module_get_ctx(module),
				      LDB_DEBUG_FATAL,
				      "An operation failed during a batch mode "
				      "transaction, the transaction was "
				      "rolled back");
		}
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (!ldb_kv->prepared_commit) {
		ret = ldb_kv_prepare_commit(module);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ldb_kv->prepared_commit = false;

	if (ldb_kv->kv_ops->finish_write(ldb_kv) != 0) {
		ret = ldb_kv->kv_ops->error(ldb_kv);
		ldb_asprintf_errstring(
		    ldb_module_get_ctx(module),
		    "Failure during tdb_transaction_commit(): %s -> %s",
		    ldb_kv->kv_ops->errorstr(ldb_kv),
		    ldb_strerror(ret));
		return ret;
	}

	return LDB_SUCCESS;
}

static int ldb_kv_del_trans(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);

	if (ldb_kv_index_transaction_cancel(module) != 0) {
		ldb_kv->kv_ops->abort_write(ldb_kv);
		return ldb_kv->kv_ops->error(ldb_kv);
	}

	ldb_kv->kv_ops->abort_write(ldb_kv);
	return LDB_SUCCESS;
}

/*
  return sequenceNumber from @BASEINFO
*/
static int ldb_kv_sequence_number(struct ldb_kv_context *ctx,
				  struct ldb_extended **ext)
{
	struct ldb_context *ldb;
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	TALLOC_CTX *tmp_ctx = NULL;
	struct ldb_seqnum_request *seq;
	struct ldb_seqnum_result *res;
	struct ldb_message *msg = NULL;
	struct ldb_dn *dn;
	const char *date;
	int ret = LDB_SUCCESS;

	ldb = ldb_module_get_ctx(module);

	seq = talloc_get_type(req->op.extended.data,
				struct ldb_seqnum_request);
	if (seq == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ldb_kv->kv_ops->lock_read(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	res = talloc_zero(req, struct ldb_seqnum_result);
	if (res == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	tmp_ctx = talloc_new(req);
	if (tmp_ctx == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	dn = ldb_dn_new(tmp_ctx, ldb, LDB_KV_BASEINFO);
	if (dn == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = ldb_kv_search_dn1(module, dn, msg, 0);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	switch (seq->type) {
	case LDB_SEQ_HIGHEST_SEQ:
		res->seq_num = ldb_msg_find_attr_as_uint64(msg, LDB_KV_SEQUENCE_NUMBER, 0);
		break;
	case LDB_SEQ_NEXT:
		res->seq_num = ldb_msg_find_attr_as_uint64(msg, LDB_KV_SEQUENCE_NUMBER, 0);
		res->seq_num++;
		break;
	case LDB_SEQ_HIGHEST_TIMESTAMP:
		date = ldb_msg_find_attr_as_string(msg, LDB_KV_MOD_TIMESTAMP, NULL);
		if (date) {
			res->seq_num = ldb_string_to_time(date);
		} else {
			res->seq_num = 0;
			/* zero is as good as anything when we don't know */
		}
		break;
	}

	*ext = talloc_zero(req, struct ldb_extended);
	if (*ext == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}
	(*ext)->oid = LDB_EXTENDED_SEQUENCE_NUMBER;
	(*ext)->data = talloc_steal(*ext, res);

done:
	talloc_free(tmp_ctx);

	ldb_kv->kv_ops->unlock_read(module);
	return ret;
}

static void ldb_kv_request_done(struct ldb_kv_context *ctx, int error)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	struct ldb_reply *ares;

	ldb = ldb_module_get_ctx(ctx->module);
	req = ctx->req;

	/* if we already returned an error just return */
	if (ldb_request_get_status(req) != LDB_SUCCESS) {
		return;
	}

	ares = talloc_zero(req, struct ldb_reply);
	if (!ares) {
		ldb_oom(ldb);
		req->callback(req, NULL);
		return;
	}
	ares->type = LDB_REPLY_DONE;
	ares->error = error;

	req->callback(req, ares);
}

static void ldb_kv_timeout(_UNUSED_ struct tevent_context *ev,
			   _UNUSED_ struct tevent_timer *te,
			   _UNUSED_ struct timeval t,
			   void *private_data)
{
	struct ldb_kv_context *ctx;
	ctx = talloc_get_type(private_data, struct ldb_kv_context);

	if (!ctx->request_terminated) {
		/* request is done now */
		ldb_kv_request_done(ctx, LDB_ERR_TIME_LIMIT_EXCEEDED);
	}

	if (ctx->spy) {
		/* neutralize the spy */
		ctx->spy->ctx = NULL;
		ctx->spy = NULL;
	}
	talloc_free(ctx);
}

static void ldb_kv_request_extended_done(struct ldb_kv_context *ctx,
					 struct ldb_extended *ext,
					 int error)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	struct ldb_reply *ares;

	ldb = ldb_module_get_ctx(ctx->module);
	req = ctx->req;

	/* if we already returned an error just return */
	if (ldb_request_get_status(req) != LDB_SUCCESS) {
		return;
	}

	ares = talloc_zero(req, struct ldb_reply);
	if (!ares) {
		ldb_oom(ldb);
		req->callback(req, NULL);
		return;
	}
	ares->type = LDB_REPLY_DONE;
	ares->response = ext;
	ares->error = error;

	req->callback(req, ares);
}

static void ldb_kv_handle_extended(struct ldb_kv_context *ctx)
{
	struct ldb_extended *ext = NULL;
	int ret;

	if (strcmp(ctx->req->op.extended.oid,
		   LDB_EXTENDED_SEQUENCE_NUMBER) == 0) {
		/* get sequence number */
		ret = ldb_kv_sequence_number(ctx, &ext);
	} else {
		/* not recognized */
		ret = LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
	}

	ldb_kv_request_extended_done(ctx, ext, ret);
}

static void ldb_kv_callback(struct tevent_context *ev,
			    struct tevent_timer *te,
			    struct timeval t,
			    void *private_data)
{
	struct ldb_kv_context *ctx;
	int ret;

	ctx = talloc_get_type(private_data, struct ldb_kv_context);

	if (ctx->request_terminated) {
		goto done;
	}

	switch (ctx->req->operation) {
	case LDB_SEARCH:
		ret = ldb_kv_search(ctx);
		break;
	case LDB_ADD:
		ret = ldb_kv_add(ctx);
		break;
	case LDB_MODIFY:
		ret = ldb_kv_modify(ctx);
		break;
	case LDB_DELETE:
		ret = ldb_kv_delete(ctx);
		break;
	case LDB_RENAME:
		ret = ldb_kv_rename(ctx);
		break;
	case LDB_EXTENDED:
		ldb_kv_handle_extended(ctx);
		goto done;
	default:
		/* no other op supported */
		ret = LDB_ERR_PROTOCOL_ERROR;
	}

	if (!ctx->request_terminated) {
		/* request is done now */
		ldb_kv_request_done(ctx, ret);
	}

done:
	if (ctx->spy) {
		/* neutralize the spy */
		ctx->spy->ctx = NULL;
		ctx->spy = NULL;
	}
	talloc_free(ctx);
}

static int ldb_kv_request_destructor(void *ptr)
{
	struct ldb_kv_req_spy *spy =
	    talloc_get_type(ptr, struct ldb_kv_req_spy);

	if (spy->ctx != NULL) {
		spy->ctx->spy = NULL;
		spy->ctx->request_terminated = true;
		spy->ctx = NULL;
	}

	return 0;
}

static int ldb_kv_handle_request(struct ldb_module *module,
				 struct ldb_request *req)
{
	struct ldb_control *control_permissive;
	struct ldb_context *ldb;
	struct tevent_context *ev;
	struct ldb_kv_context *ac;
	struct tevent_timer *te;
	struct timeval tv;
	unsigned int i;

	ldb = ldb_module_get_ctx(module);

	control_permissive = ldb_request_get_control(req,
					LDB_CONTROL_PERMISSIVE_MODIFY_OID);

	for (i = 0; req->controls && req->controls[i]; i++) {
		if (req->controls[i]->critical &&
		    req->controls[i] != control_permissive) {
			ldb_asprintf_errstring(ldb, "Unsupported critical extension %s",
					       req->controls[i]->oid);
			return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
		}
	}

	if (req->starttime == 0 || req->timeout == 0) {
		ldb_set_errstring(ldb, "Invalid timeout settings");
		return LDB_ERR_TIME_LIMIT_EXCEEDED;
	}

	ev = ldb_handle_get_event_context(req->handle);

	ac = talloc_zero(ldb, struct ldb_kv_context);
	if (ac == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	te = tevent_add_timer(ev, ac, tv, ldb_kv_callback, ac);
	if (NULL == te) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (req->timeout > 0) {
		tv.tv_sec = req->starttime + req->timeout;
		tv.tv_usec = 0;
		ac->timeout_event =
		    tevent_add_timer(ev, ac, tv, ldb_kv_timeout, ac);
		if (NULL == ac->timeout_event) {
			talloc_free(ac);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/* set a spy so that we do not try to use the request context
	 * if it is freed before ltdb_callback fires */
	ac->spy = talloc(req, struct ldb_kv_req_spy);
	if (NULL == ac->spy) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->spy->ctx = ac;

	talloc_set_destructor((TALLOC_CTX *)ac->spy, ldb_kv_request_destructor);

	return LDB_SUCCESS;
}

static int ldb_kv_init_rootdse(struct ldb_module *module)
{
	/* ignore errors on this - we expect it for non-sam databases */
	ldb_mod_register_control(module, LDB_CONTROL_PERMISSIVE_MODIFY_OID);

	/* there can be no module beyond the backend, just return */
	return LDB_SUCCESS;
}

static int ldb_kv_lock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	return ldb_kv->kv_ops->lock_read(module);
}

static int ldb_kv_unlock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	return ldb_kv->kv_ops->unlock_read(module);
}

static const struct ldb_module_ops ldb_kv_ops = {
    .name = "tdb",
    .init_context = ldb_kv_init_rootdse,
    .search = ldb_kv_handle_request,
    .add = ldb_kv_handle_request,
    .modify = ldb_kv_handle_request,
    .del = ldb_kv_handle_request,
    .rename = ldb_kv_handle_request,
    .extended = ldb_kv_handle_request,
    .start_transaction = ldb_kv_start_trans,
    .end_transaction = ldb_kv_end_trans,
    .prepare_commit = ldb_kv_prepare_commit,
    .del_transaction = ldb_kv_del_trans,
    .read_lock = ldb_kv_lock_read,
    .read_unlock = ldb_kv_unlock_read,
};

int ldb_kv_init_store(struct ldb_kv_private *ldb_kv,
		      const char *name,
		      struct ldb_context *ldb,
		      const char *options[],
		      struct ldb_module **_module)
{
	if (getenv("LDB_WARN_UNINDEXED")) {
		ldb_kv->warn_unindexed = true;
	}

	if (getenv("LDB_WARN_REINDEX")) {
		ldb_kv->warn_reindex = true;
	}

	ldb_kv->sequence_number = 0;

	ldb_kv->pid = getpid();

	ldb_kv->pack_format_override = 0;

	ldb_kv->module = ldb_module_new(ldb, ldb, name, &ldb_kv_ops);
	if (!ldb_kv->module) {
		ldb_oom(ldb);
		talloc_free(ldb_kv);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ldb_module_set_private(ldb_kv->module, ldb_kv);
	talloc_steal(ldb_kv->module, ldb_kv);

	if (ldb_kv_cache_load(ldb_kv->module) != 0) {
		ldb_asprintf_errstring(ldb, "Unable to load ltdb cache "
				       "records for backend '%s'", name);
		talloc_free(ldb_kv->module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*_module = ldb_kv->module;
	/*
	 * Set or override the maximum key length
	 *
	 * The ldb_mdb code will have set this to 511, but our tests
	 * set this even smaller (to make the tests more practical).
	 *
	 * This must only be used for the selftest as the length
	 * becomes encoded in the index keys.
	 */
	{
		const char *len_str =
			ldb_options_find(ldb, options,
					 "max_key_len_for_self_test");
		if (len_str != NULL) {
			unsigned len = strtoul(len_str, NULL, 0);
			ldb_kv->max_key_length = len;
		}
	}

	/*
	 * Usually the presence of GUID indexing determines the pack format
	 * we use but in certain circumstances such as downgrading an
	 * MDB-backed database, we want to override the target pack format.
	 *
	 * We set/get opaques here because in the Samba partitions module,
	 * 'options' are not passed correctly so sub-databases can't see
	 * the options they need.
	 */
	{
		const char *pack_format_override =
			ldb_options_find(ldb, options, "pack_format_override");
		if (pack_format_override != NULL) {
			int ret;
			ldb_kv->pack_format_override =
				strtoul(pack_format_override, NULL, 0);
			ret = ldb_set_opaque(ldb,
					     "pack_format_override",
			     (void *)(intptr_t)ldb_kv->pack_format_override);
			if (ret != LDB_SUCCESS) {
				talloc_free(ldb_kv->module);
				return ldb_module_operr(ldb_kv->module);
			}
		} else {
			/*
			 * NULL -> 0 is fine, otherwise we get back
			 * the number we needed
			 */
			ldb_kv->pack_format_override
				= (intptr_t)ldb_get_opaque(ldb,
						   "pack_format_override");
		}
	}

	/*
	 * Override full DB scans
	 *
	 * A full DB scan is expensive on a large database.  This
	 * option is for testing to show that the full DB scan is not
	 * triggered.
	 */
	{
		const char *len_str =
			ldb_options_find(ldb, options,
					 "disable_full_db_scan_for_self_test");
		if (len_str != NULL) {
			ldb_kv->disable_full_db_scan = true;
		}
	}

	/*
	 * Set the size of the transaction index cache.
	 * If the ldb option "transaction_index_cache_size" is set use that
	 * otherwise use DEFAULT_INDEX_CACHE_SIZE
	 */
	ldb_kv->index_transaction_cache_size = DEFAULT_INDEX_CACHE_SIZE;
	{
		const char *size = ldb_options_find(
			ldb,
			options,
			"transaction_index_cache_size");
		if (size != NULL) {
			size_t cache_size = 0;
			errno = 0;

			cache_size = strtoul( size, NULL, 0);
			if (cache_size == 0 || errno == ERANGE) {
				ldb_debug(
					ldb,
					LDB_DEBUG_WARNING,
					"Invalid transaction_index_cache_size "
					"value [%s], using default(%d)\n",
					size,
					DEFAULT_INDEX_CACHE_SIZE);
			} else {
				ldb_kv->index_transaction_cache_size =
					cache_size;
			}
		}
	}
	/*
	 * Set batch mode operation.
	 * This disables the nested sub transactions, and increases the
	 * chance of index corruption.  If using this mode the transaction
	 * commit will be aborted if any operation fails.
	 */
	{
		const char *batch_mode = ldb_options_find(
			ldb, options, "batch_mode");
		if (batch_mode != NULL) {
			ldb_kv->batch_mode = true;
		}
	}

	return LDB_SUCCESS;
}
