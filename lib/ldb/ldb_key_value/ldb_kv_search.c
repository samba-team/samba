/*
   ldb database library

   Copyright (C) Andrew Tridgell  2004

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
 *  Name: ldb
 *
 *  Component: ldb search functions
 *
 *  Description: functions to search ldb+tdb databases
 *
 *  Author: Andrew Tridgell
 */

#include "ldb_kv.h"
#include "ldb_private.h"
#include "lib/util/attr.h"
/*
  search the database for a single simple dn.
  return LDB_ERR_NO_SUCH_OBJECT on record-not-found
  and LDB_SUCCESS on success
*/
int ldb_kv_search_base(struct ldb_module *module,
		       TALLOC_CTX *mem_ctx,
		       struct ldb_dn *dn,
		       struct ldb_dn **ret_dn)
{
	int exists;
	int ret;
	struct ldb_message *msg = NULL;

	if (ldb_dn_is_null(dn)) {
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	/*
	 * We can't use tdb_exists() directly on a key when the TDB
	 * key is the GUID one, not the DN based one.  So we just do a
	 * normal search and avoid most of the allocation with the
	 * LDB_UNPACK_DATA_FLAG_NO_ATTRS flag
	 */
	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_search_dn1(module, dn, msg, LDB_UNPACK_DATA_FLAG_NO_ATTRS);
	if (ret == LDB_SUCCESS) {
		const char *dn_linearized
			= ldb_dn_get_linearized(dn);
		const char *msg_dn_linearized
			= ldb_dn_get_linearized(msg->dn);

		if (strcmp(dn_linearized, msg_dn_linearized) == 0) {
			/*
			 * Re-use the full incoming DN for
			 * subtree checks
			 */
			*ret_dn = dn;
		} else {
			/*
			 * Use the string DN from the unpack, so that
			 * we have a case-exact match of the base
			 */
			*ret_dn = talloc_steal(mem_ctx, msg->dn);
		}
		exists = true;
	} else if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		exists = false;
	} else {
		talloc_free(msg);
		return ret;
	}
	talloc_free(msg);
	if (exists) {
		return LDB_SUCCESS;
	}
	return LDB_ERR_NO_SUCH_OBJECT;
}

struct ldb_kv_parse_data_unpack_ctx {
	struct ldb_message *msg;
	struct ldb_module *module;
	struct ldb_kv_private *ldb_kv;
	unsigned int unpack_flags;
};

static int ldb_kv_parse_data_unpack(struct ldb_val key,
				    struct ldb_val data,
				    void *private_data)
{
	struct ldb_kv_parse_data_unpack_ctx *ctx = private_data;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(ctx->module);
	struct ldb_val data_parse = data;

	struct ldb_kv_private *ldb_kv = ctx->ldb_kv;

	if ((ldb_kv->kv_ops->options & LDB_KV_OPTION_STABLE_READ_LOCK) &&
	    (ctx->unpack_flags & LDB_UNPACK_DATA_FLAG_READ_LOCKED) &&
	    !ldb_kv->kv_ops->transaction_active(ldb_kv)) {
		/*
		 * In the case where no transactions are active and
		 * we're in a read-lock, we can point directly into
		 * database memory.
		 *
		 * The database can't be changed underneath us and we
		 * will duplicate this data in the call to filter.
		 *
		 * This is seen in:
		 * - ldb_kv_index_filter
		 * - ldb_kv_search_and_return_base
		 */
	} else {
		/*
		 * In every other case, since unpack doesn't memdup, we need
		 * to at least do a memdup on the whole data buffer as that
		 * may change later and the caller needs a stable result.
		 *
		 * During transactions, pointers could change and in
		 * TDB, there just aren't the same guarantees.
		 */
		data_parse.data = talloc_memdup(ctx->msg,
						data.data,
						data.length);
		if (data_parse.data == NULL) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Unable to allocate data(%d) for %*.*s\n",
				  (int)data.length,
				  (int)key.length, (int)key.length, key.data);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	ret = ldb_unpack_data_flags(ldb, &data_parse,
				    ctx->msg, ctx->unpack_flags);
	if (ret == -1) {
		if (data_parse.data != data.data) {
			talloc_free(data_parse.data);
		}

		ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid data for index %*.*s\n",
			  (int)key.length, (int)key.length, key.data);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return ret;
}

/*
  search the database for a single simple dn, returning all attributes
  in a single message

  return LDB_ERR_NO_SUCH_OBJECT on record-not-found
  and LDB_SUCCESS on success
*/
int ldb_kv_search_key(struct ldb_module *module,
		      struct ldb_kv_private *ldb_kv,
		      const struct ldb_val ldb_key,
		      struct ldb_message *msg,
		      unsigned int unpack_flags)
{
	int ret;
	struct ldb_kv_parse_data_unpack_ctx ctx = {
		.msg = msg,
		.module = module,
		.unpack_flags = unpack_flags,
		.ldb_kv = ldb_kv
	};

	memset(msg, 0, sizeof(*msg));

	msg->num_elements = 0;
	msg->elements = NULL;

	ret = ldb_kv->kv_ops->fetch_and_parse(
	    ldb_kv, ldb_key, ldb_kv_parse_data_unpack, &ctx);

	if (ret == -1) {
		ret = ldb_kv->kv_ops->error(ldb_kv);
		if (ret == LDB_SUCCESS) {
			/*
			 * Just to be sure we don't turn errors
			 * into success
			 */
			return LDB_ERR_OPERATIONS_ERROR;
		}
		return ret;
	} else if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

/*
  search the database for a single simple dn, returning all attributes
  in a single message

  return LDB_ERR_NO_SUCH_OBJECT on record-not-found
  and LDB_SUCCESS on success
*/
int ldb_kv_search_dn1(struct ldb_module *module,
		      struct ldb_dn *dn,
		      struct ldb_message *msg,
		      unsigned int unpack_flags)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	int ret;
	uint8_t guid_key[LDB_KV_GUID_KEY_SIZE];
	struct ldb_val key = {
		.data = guid_key,
		.length = sizeof(guid_key)
	};
	TALLOC_CTX *tdb_key_ctx = NULL;

	bool valid_dn = ldb_dn_validate(dn);
	if (valid_dn == false) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Invalid Base DN: %s",
				       ldb_dn_get_linearized(dn));
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	if (ldb_kv->cache->GUID_index_attribute == NULL ||
	    ldb_dn_is_special(dn)) {

		tdb_key_ctx = talloc_new(msg);
		if (!tdb_key_ctx) {
			return ldb_module_oom(module);
		}

		/* form the key */
		key = ldb_kv_key_dn(tdb_key_ctx, dn);
		if (!key.data) {
			TALLOC_FREE(tdb_key_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		/*
		 * Look in the index to find the key for this DN.
		 *
		 * the tdb_key memory is allocated above, msg is just
		 * used for internal memory.
		 *
		 */
		ret = ldb_kv_key_dn_from_idx(module, ldb_kv, msg, dn, &key);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ret = ldb_kv_search_key(module, ldb_kv, key, msg, unpack_flags);

	TALLOC_FREE(tdb_key_ctx);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if ((unpack_flags & LDB_UNPACK_DATA_FLAG_NO_DN) == 0) {
		if (!msg->dn) {
			msg->dn = ldb_dn_copy(msg, dn);
		}
		if (!msg->dn) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	return LDB_SUCCESS;
}

/*
 * filter the specified list of attributes from msg,
 * adding requested attributes, and perhaps all for *,
 * but not the DN to filtered_msg.
 */
int ldb_kv_filter_attrs(struct ldb_context *ldb,
			const struct ldb_message *msg,
			const char *const *attrs,
			struct ldb_message *filtered_msg)
{
	return ldb_filter_attrs(ldb, msg, attrs, filtered_msg);
}

/*
  search function for a non-indexed search
 */
static int search_func(_UNUSED_ struct ldb_kv_private *ldb_kv,
		       struct ldb_val key,
		       struct ldb_val val,
		       void *state)
{
	struct ldb_context *ldb;
	struct ldb_kv_context *ac;
	struct ldb_message *msg, *filtered_msg;
	int ret;
	bool matched;

	ac = talloc_get_type(state, struct ldb_kv_context);
	ldb = ldb_module_get_ctx(ac->module);

	/*
	 * We want to skip @ records early in a search full scan
	 *
	 * @ records like @IDXLIST are only available via a base
	 * search on the specific name but the method by which they
	 * were excluded was expensive, after the unpack the DN is
	 * exploded and ldb_match_msg_error() would reject it for
	 * failing to match the scope.
	 *
	 * ldb_kv_key_is_normal_record() uses the fact that @ records
	 * have the DN=@ prefix on their TDB/LMDB key to quickly
	 * exclude them from consideration.
	 *
	 * (any other non-records are also excluded by the same key
	 * match)
	 */

	if (ldb_kv_key_is_normal_record(key) == false) {
		return 0;
	}

	msg = ldb_msg_new(ac);
	if (!msg) {
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	/* unpack the record */
	ret = ldb_unpack_data_flags(ldb, &val, msg,
				    LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC);
	if (ret == -1) {
		talloc_free(msg);
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	if (!msg->dn) {
		msg->dn = ldb_dn_new(msg, ldb,
				     (char *)key.data + 3);
		if (msg->dn == NULL) {
			talloc_free(msg);
			ac->error = LDB_ERR_OPERATIONS_ERROR;
			return -1;
		}
	}

	/* see if it matches the given expression */
	ret = ldb_match_msg_error(ldb, msg,
				  ac->tree, ac->base, ac->scope, &matched);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}
	if (!matched) {
		talloc_free(msg);
		return 0;
	}

	filtered_msg = ldb_msg_new(ac);
	if (filtered_msg == NULL) {
		TALLOC_FREE(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	filtered_msg->dn = talloc_steal(filtered_msg, msg->dn);

	/* filter the attributes that the user wants */
	ret = ldb_kv_filter_attrs(ldb, msg, ac->attrs, filtered_msg);
	talloc_free(msg);

	if (ret == -1) {
		TALLOC_FREE(filtered_msg);
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	ret = ldb_module_send_entry(ac->req, filtered_msg, NULL);
	if (ret != LDB_SUCCESS) {
		ac->request_terminated = true;
		/* the callback failed, abort the operation */
		ac->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	return 0;
}

/*
 * Key pointing to just before the first GUID indexed record for
 * iterate_range
 */
struct ldb_val start_of_db_key = {.data=discard_const_p(uint8_t, "GUID<"),
				  .length=6};
/*
 * Key pointing to just after the last GUID indexed record for
 * iterate_range
 */
struct ldb_val end_of_db_key = {.data=discard_const_p(uint8_t, "GUID>"),
				.length=6};

/*
  search the database with a LDAP-like expression.
  this is the "full search" non-indexed variant
*/
static int ldb_kv_search_full(struct ldb_kv_context *ctx)
{
	void *data = ldb_module_get_private(ctx->module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	int ret;

	/*
	 * If the backend has an iterate_range op, use it to start the search
	 * at the first GUID indexed record, skipping the indexes section.
	 */
	ctx->error = LDB_SUCCESS;
	ret = ldb_kv->kv_ops->iterate_range(ldb_kv,
					    start_of_db_key,
					    end_of_db_key,
					    search_func,
					    ctx);
	if (ret == LDB_ERR_OPERATIONS_ERROR) {
		/*
		 * If iterate_range isn't defined, it'll return an error,
		 * so just iterate over the whole DB.
		 */
		ret = ldb_kv->kv_ops->iterate(ldb_kv, search_func, ctx);
	}

	if (ret < 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ctx->error;
}

static int ldb_kv_search_and_return_base(struct ldb_kv_private *ldb_kv,
					 struct ldb_kv_context *ctx)
{
	struct ldb_message *msg, *filtered_msg;
	struct ldb_context *ldb = ldb_module_get_ctx(ctx->module);
	const char *dn_linearized;
	const char *msg_dn_linearized;
	int ret;
	bool matched;

	msg = ldb_msg_new(ctx);
	if (!msg) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_kv_search_dn1(ctx->module,
				ctx->base,
				msg,
				LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC |
				LDB_UNPACK_DATA_FLAG_READ_LOCKED);

	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		if (ldb_kv->check_base == false) {
			/*
			 * In this case, we are done, as no base
			 * checking is allowed in this DB
			 */
			talloc_free(msg);
			return LDB_SUCCESS;
		}
		ldb_asprintf_errstring(ldb,
				       "No such Base DN: %s",
				       ldb_dn_get_linearized(ctx->base));
	}
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}


	/*
	 * We use this, not ldb_match_msg_error() as we know
	 * we matched on the scope BASE, as we just fetched
	 * the base DN
	 */

	ret = ldb_match_message(ldb, msg,
				ctx->tree,
				ctx->scope,
				&matched);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}
	if (!matched) {
		talloc_free(msg);
		return LDB_SUCCESS;
	}

	dn_linearized = ldb_dn_get_linearized(ctx->base);
	msg_dn_linearized = ldb_dn_get_linearized(msg->dn);

	filtered_msg = ldb_msg_new(ctx);
	if (filtered_msg == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (strcmp(dn_linearized, msg_dn_linearized) == 0) {
		/*
		 * If the DN is exactly the same string, then
		 * re-use the full incoming DN for the
		 * returned result, as it has already been
		 * casefolded
		 */
		filtered_msg->dn = ldb_dn_copy(filtered_msg, ctx->base);
	}

	/*
	 * If the ldb_dn_copy() failed, or if we did not choose that
	 * optimisation (filtered_msg is zeroed at allocation),
	 * steal the one from the unpack
	 */
	if (filtered_msg->dn == NULL) {
		filtered_msg->dn = talloc_steal(filtered_msg, msg->dn);
	}

	/*
	 * filter the attributes that the user wants.
	 */
	ret = ldb_kv_filter_attrs(ldb, msg, ctx->attrs, filtered_msg);
	if (ret == -1) {
		talloc_free(msg);
		filtered_msg = NULL;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Remove any extended components possibly copied in from
	 * msg->dn, we just want the casefold components
	 */
	ldb_dn_remove_extended_components(filtered_msg->dn);
	talloc_free(msg);

	ret = ldb_module_send_entry(ctx->req, filtered_msg, NULL);
	if (ret != LDB_SUCCESS) {
		/* Regardless of success or failure, the msg
		 * is the callbacks responsiblity, and should
		 * not be talloc_free()'ed */
		ctx->request_terminated = true;
		return ret;
	}

	return LDB_SUCCESS;
}

/*
  search the database with a LDAP-like expression.
  choses a search method
*/
int ldb_kv_search(struct ldb_kv_context *ctx)
{
	struct ldb_context *ldb;
	struct ldb_module *module = ctx->module;
	struct ldb_request *req = ctx->req;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	int ret;

	ldb = ldb_module_get_ctx(module);

	ldb_request_set_state(req, LDB_ASYNC_PENDING);

	if (ldb_kv->kv_ops->lock_read(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ldb_kv_cache_load(module) != 0) {
		ldb_kv->kv_ops->unlock_read(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (req->op.search.tree == NULL) {
		ldb_kv->kv_ops->unlock_read(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ctx->tree = req->op.search.tree;
	ctx->scope = req->op.search.scope;
	ctx->base = req->op.search.base;
	ctx->attrs = req->op.search.attrs;

	if ((req->op.search.base == NULL) || (ldb_dn_is_null(req->op.search.base) == true)) {

		/* Check what we should do with a NULL dn */
		switch (req->op.search.scope) {
		case LDB_SCOPE_BASE:
			ldb_asprintf_errstring(ldb,
					       "NULL Base DN invalid for a base search");
			ret = LDB_ERR_INVALID_DN_SYNTAX;
			break;
		case LDB_SCOPE_ONELEVEL:
			ldb_asprintf_errstring(ldb,
					       "NULL Base DN invalid for a one-level search");
			ret = LDB_ERR_INVALID_DN_SYNTAX;
			break;
		case LDB_SCOPE_SUBTREE:
		default:
			/* We accept subtree searches from a NULL base DN, ie over the whole DB */
			ret = LDB_SUCCESS;
		}
	} else if (req->op.search.scope == LDB_SCOPE_BASE) {

		/*
		 * If we are LDB_SCOPE_BASE, do just one search and
		 * return early.  This is critical to ensure we do not
		 * go into the index code for special DNs, as that
		 * will try to look up an index record for a special
		 * record (which doesn't exist).
		 */
		ret = ldb_kv_search_and_return_base(ldb_kv, ctx);

		ldb_kv->kv_ops->unlock_read(module);

		return ret;

	} else if (ldb_kv->check_base) {
		/*
		 * This database has been marked as
		 * 'checkBaseOnSearch', so do a spot check of the base
		 * dn.  Also optimise the subsequent filter by filling
		 * in the ctx->base to be exactly case correct
		 */
		ret = ldb_kv_search_base(
		    module, ctx, req->op.search.base, &ctx->base);

		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			ldb_asprintf_errstring(ldb,
					       "No such Base DN: %s",
					       ldb_dn_get_linearized(req->op.search.base));
		}

	} else if (ldb_dn_validate(req->op.search.base) == false) {

		/* We don't want invalid base DNs here */
		ldb_asprintf_errstring(ldb,
				       "Invalid Base DN: %s",
				       ldb_dn_get_linearized(req->op.search.base));
		ret = LDB_ERR_INVALID_DN_SYNTAX;

	} else {
		/* If we are not checking the base DN life is easy */
		ret = LDB_SUCCESS;
	}

	if (ret == LDB_SUCCESS) {
		uint32_t match_count = 0;

		ret = ldb_kv_search_indexed(ctx, &match_count);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			/* Not in the index, therefore OK! */
			ret = LDB_SUCCESS;

		}
		/* Check if we got just a normal error.
		 * In that case proceed to a full search unless we got a
		 * callback error */
		if (!ctx->request_terminated && ret != LDB_SUCCESS) {
			/* Not indexed, so we need to do a full scan */
			if (ldb_kv->warn_unindexed ||
			    ldb_kv->disable_full_db_scan) {
				/* useful for debugging when slow performance
				 * is caused by unindexed searches */
				char *expression = ldb_filter_from_tree(ctx, ctx->tree);
				ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb FULL SEARCH: %s SCOPE: %s DN: %s",
							expression,
							req->op.search.scope==LDB_SCOPE_BASE?"base":
							req->op.search.scope==LDB_SCOPE_ONELEVEL?"one":
							req->op.search.scope==LDB_SCOPE_SUBTREE?"sub":"UNKNOWN",
							ldb_dn_get_linearized(req->op.search.base));

				talloc_free(expression);
			}

			if (match_count != 0) {
				/* the indexing code gave an error
				 * after having returned at least one
				 * entry. This means the indexes are
				 * corrupt or a database record is
				 * corrupt. We cannot continue with a
				 * full search or we may return
				 * duplicate entries
				 */
				ldb_kv->kv_ops->unlock_read(module);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			if (ldb_kv->disable_full_db_scan) {
				ldb_set_errstring(ldb,
						  "ldb FULL SEARCH disabled");
				ldb_kv->kv_ops->unlock_read(module);
				return LDB_ERR_INAPPROPRIATE_MATCHING;
			}

			ret = ldb_kv_search_full(ctx);
			if (ret != LDB_SUCCESS) {
				ldb_set_errstring(ldb, "Indexed and full searches both failed!\n");
			}
		}
	}

	ldb_kv->kv_ops->unlock_read(module);

	return ret;
}
