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


/*
  create a RID Set object for the specified DC
 */
static int ridalloc_create_rid_set_ntds(struct ldb_module *module, TALLOC_CTX *mem_ctx,
					struct ldb_dn *rid_manager_dn,
					struct ldb_dn *ntds_dn, struct ldb_dn **dn)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_dn *server_dn, *machine_dn, *rid_set_dn;
	int ret;
	const char *attrs[] = { "rIDAvailablePool", NULL };
	uint64_t rid_pool, new_rid_pool, dc_pool;
	uint32_t rid_pool_lo, rid_pool_hi;
	struct ldb_message *msg;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const unsigned int alloc_size = 500;
	struct ldb_result *res;

	/*
	  steps:

	  find the machine object for the DC
	  construct the RID Set DN
	  load rIDAvailablePool to find next available set
	  modify RID Manager object to update rIDAvailablePool
	  add the RID Set object
	  link to the RID Set object in machine object
	 */

	server_dn = ldb_dn_get_parent(tmp_ctx, ntds_dn);
	if (!server_dn) {
		ldb_module_oom(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = dsdb_module_reference_dn(module, tmp_ctx, server_dn, "serverReference", &machine_dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to find serverReference in %s - %s",
				       ldb_dn_get_linearized(server_dn), ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	rid_set_dn = ldb_dn_copy(tmp_ctx, machine_dn);
	if (rid_set_dn == NULL) {
		ldb_module_oom(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (! ldb_dn_add_child_fmt(rid_set_dn, "CN=RID Set")) {
		ldb_module_oom(module);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = dsdb_module_search_dn(module, tmp_ctx, &res, rid_manager_dn, attrs, 0);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to find rIDAvailablePool in %s - %s",
				       ldb_dn_get_linearized(rid_manager_dn), ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	rid_pool = ldb_msg_find_attr_as_uint64(res->msgs[0], "rIDAvailablePool", 0);
	rid_pool_lo = rid_pool & 0xFFFFFFFF;
	rid_pool_hi = rid_pool >> 32;
	if (rid_pool_lo >= rid_pool_hi) {
		ldb_asprintf_errstring(ldb, "Out of RIDs in RID Manager - rIDAvailablePool is %u-%u",
				       rid_pool_lo, rid_pool_hi);
		talloc_free(tmp_ctx);
		return ret;
	}

	/* lower part of new pool is the low part of the rIDAvailablePool */
	dc_pool = rid_pool_lo;

	/* allocate 500 RIDs to this DC */
	rid_pool_lo = MIN(rid_pool_hi, rid_pool_lo + alloc_size);

	/* work out upper part of new pool */
	dc_pool |= (((uint64_t)rid_pool_lo-1)<<32);

	/* and new rIDAvailablePool value */
	new_rid_pool = rid_pool_lo | (((uint64_t)rid_pool_hi)<<32);

	ret = dsdb_module_constrainted_update_integer(module, rid_manager_dn, "rIDAvailablePool",
						      rid_pool, new_rid_pool);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to update rIDAvailablePool - %s",
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* create the RID Set object */
	msg = ldb_msg_new(tmp_ctx);
	msg->dn = rid_set_dn;

	ret = ldb_msg_add_string(msg, "objectClass", "top");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	ret = ldb_msg_add_string(msg, "objectClass", "rIDSet");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	ret = ldb_msg_add_string(msg, "cn", "RID Set");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	ret = ldb_msg_add_string(msg, "name", "RID Set");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	ret = ldb_msg_add_fmt(msg, "rIDAllocationPool", "%llu", (unsigned long long)dc_pool);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	ret = ldb_msg_add_fmt(msg, "rIDPreviousAllocationPool", "%llu", (unsigned long long)dc_pool);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	ret = ldb_msg_add_fmt(msg, "rIDUsedPool", "0");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	ret = ldb_msg_add_fmt(msg, "rIDNextRID", "%lu", (unsigned long)(dc_pool & 0xFFFFFFFF));
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_module_add(module, msg, 0);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to add RID Set %s - %s",
				       ldb_dn_get_linearized(msg->dn),
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* add the rIDSetReferences link */
	msg = ldb_msg_new(tmp_ctx);
	msg->dn = machine_dn;

	ret = ldb_msg_add_string(msg, "rIDSetReferences", ldb_dn_get_linearized(rid_set_dn));
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	msg->elements[0].flags = LDB_FLAG_MOD_ADD;

	ret = dsdb_module_modify(module, msg, 0);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to add rIDSetReferences to %s - %s",
				       ldb_dn_get_linearized(msg->dn),
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	(*dn) = talloc_steal(mem_ctx, rid_set_dn);

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}


/*
  create a RID Set object for this DC
 */
static int ridalloc_create_own_rid_set(struct ldb_module *module, TALLOC_CTX *mem_ctx,
				       struct ldb_dn **dn)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_dn *rid_manager_dn, *fsmo_role_dn;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	/* work out who is the RID Manager */
	ret = dsdb_module_rid_manager_dn(module, tmp_ctx, &rid_manager_dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to find RID Manager object - %s",
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* find the DN of the RID Manager */
	ret = dsdb_module_reference_dn(module, tmp_ctx, rid_manager_dn, "fSMORoleOwner", &fsmo_role_dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to find fSMORoleOwner in RID Manager object - %s",
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	if (ldb_dn_compare(samdb_ntds_settings_dn(ldb), fsmo_role_dn) != 0) {
		ldb_asprintf_errstring(ldb, "Remote RID Set allocation not implemented");
		talloc_free(tmp_ctx);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	ret = ridalloc_create_rid_set_ntds(module, mem_ctx, rid_manager_dn, fsmo_role_dn, dn);
	talloc_free(tmp_ctx);
	return ret;
}

/*
  refresh a RID Set object for the specified DC
  also returns the first RID for the new pool
 */
static int ridalloc_refresh_rid_set_ntds(struct ldb_module *module,
					struct ldb_dn *rid_manager_dn,
					struct ldb_dn *ntds_dn, uint32_t *first_rid)
{
	ldb_asprintf_errstring(ldb, "Refresh of RID Set not implemented");
	return LDB_ERR_UNWILLING_TO_PERFORM;
}



/*
  get a new RID pool for ourselves
  also returns the first rid for the new pool
 */
static int ridalloc_refresh_own_pool(struct ldb_module *module, uint32_t *first_rid)
{
	TALLOC_CTX *tmp_ctx = talloc_new(module);
	struct ldb_dn *rid_manager_dn, *fsmo_role_dn;
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	/* work out who is the RID Manager */
	ret = dsdb_module_rid_manager_dn(module, tmp_ctx, &rid_manager_dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to find RID Manager object - %s",
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* find the DN of the RID Manager */
	ret = dsdb_module_reference_dn(module, tmp_ctx, rid_manager_dn, "fSMORoleOwner", &fsmo_role_dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to find fSMORoleOwner in RID Manager object - %s",
				       ldb_errstring(ldb));
		talloc_free(tmp_ctx);
		return ret;
	}

	if (ldb_dn_compare(samdb_ntds_settings_dn(ldb), fsmo_role_dn) != 0) {
		ldb_asprintf_errstring(ldb, "Remote RID Set allocation not implemented");
		talloc_free(tmp_ctx);
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	ret = ridalloc_refresh_rid_set_ntds(module, rid_manager_dn, fsmo_role_dn, first_rid);
	talloc_free(tmp_ctx);
	return ret;
}


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
	int prev_rid;
	TALLOC_CTX *tmp_ctx = talloc_new(module);

	ldb = ldb_module_get_ctx(module);

	ret = samdb_rid_set_dn(ldb, tmp_ctx, &rid_set_dn);
	if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
		ret = ridalloc_create_own_rid_set(module, tmp_ctx, &rid_set_dn);
	}
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, __location__ ": No RID Set DN - %s",
				       ldb_errstring(ldb));
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
	prev_rid = ldb_msg_find_attr_as_int(res->msgs[0], "rIDNextRID", -1);
	if (prev_rid == -1 || alloc_pool == 0) {
		ldb_asprintf_errstring(ldb, __location__ ": Bad RID Set %s",
				       ldb_dn_get_linearized(rid_set_dn));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	alloc_pool_lo = alloc_pool & 0xFFFFFFFF;
	alloc_pool_hi = alloc_pool >> 32;
	if (prev_rid > alloc_pool_hi) {
		ret = ridalloc_refresh_own_pool(module, rid);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	} else {
		/* despite the name, rIDNextRID is the value of the last user
		 * added by this DC, not the next available RID */
		(*rid) = prev_rid + 1;
	}

	/* now modify the RID Set to use up this RID using a
	 * constrained delete/add */
	ret = dsdb_module_constrainted_update_integer(module, rid_set_dn, "rIDNextRID", prev_rid, *rid);
	talloc_free(tmp_ctx);

	return ret;
}
