/*
   RID allocation helper functions

   Copyright (C) Andrew Bartlett 2010
   Copyright (C) Andrew Tridgell 2010

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

/*
 *  Name: ldb
 *
 *  Component: RID allocation logic
 *
 *  Description: manage RID Set and RID Manager objects
 *
 */

#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

/* allocate a RID using our RID Set
   If we run out of RIDs then allocate a new pool
   either locally or by contacting the RID Manager
*/
int ridalloc_allocate_rid(struct ldb_module *module, uint32_t *rid)
{
	struct ldb_context *ldb;
	static const char * const attrs[] = { "rIDAllocationPool", "rIDNextRID" , NULL };
	int ret;
	struct ldb_dn *rid_set_dn;
	struct ldb_result *res;
	uint64_t alloc_pool;
	uint32_t alloc_pool_lo, alloc_pool_hi;
	int next_rid;
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	struct ldb_message_element *el;
	struct ldb_val v1, v2;
	char *ridstring;

	ldb = ldb_module_get_ctx(module);

	ret = samdb_rid_set_dn(ldb, tmp_ctx, &rid_set_dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, __location__ ": No RID Set DN");
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_module_search_dn(module, tmp_ctx, &res, rid_set_dn, attrs, 0);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, __location__ ": No RID Set %s",
				       ldb_dn_get_linearized(rid_set_dn));
		talloc_free(tmp_ctx);
		return ret;
	}

	alloc_pool = ldb_msg_find_attr_as_uint64(res->msgs[0], "rIDAllocationPool", 0);
	next_rid = ldb_msg_find_attr_as_int(res->msgs[0], "rIDNextRID", -1);
	if (next_rid == -1 || alloc_pool == 0) {
		ldb_asprintf_errstring(ldb, __location__ ": Bad RID Set %s",
				       ldb_dn_get_linearized(rid_set_dn));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	alloc_pool_lo = alloc_pool & 0xFFFFFFFF;
	alloc_pool_hi = alloc_pool >> 32;
	if (next_rid > alloc_pool_hi) {
		/* TODO: add call to RID Manager */
		ldb_asprintf_errstring(ldb, __location__ ": Out of RIDs in RID Set %s",
				       ldb_dn_get_linearized(rid_set_dn));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* despite the name, rIDNextRID is the value of the last user
	 * added by this DC, not the next available RID */

	(*rid) = next_rid + 1;

	/* now modify the RID Set to use up this RID using a
	 * constrained delete/add */
	msg = ldb_msg_new(tmp_ctx);
	msg->dn = rid_set_dn;

	ret = ldb_msg_add_empty(msg, "rIDNextRID", LDB_FLAG_MOD_DELETE, &el);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	el->num_values = 1;
	el->values = &v1;
	ridstring = talloc_asprintf(msg, "%u", (unsigned)next_rid);
	if (!ridstring) {
		ldb_module_oom(module);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	v1 = data_blob_string_const(ridstring);

	ret = ldb_msg_add_empty(msg, "rIDNextRID", LDB_FLAG_MOD_ADD, &el);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	el->num_values = 1;
	el->values = &v2;
	ridstring = talloc_asprintf(msg, "%u", (unsigned)next_rid+1);
	if (!ridstring) {
		ldb_module_oom(module);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	v2 = data_blob_string_const(ridstring);

	ret = dsdb_module_modify(module, msg, 0);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}
