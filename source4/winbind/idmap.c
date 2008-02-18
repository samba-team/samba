/*
   Unix SMB/CIFS implementation.

   Map SIDs to uids/gids and back

   Copyright (C) Kai Blin 2008

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
#include "auth/auth.h"
#include "librpc/gen_ndr/lsa.h"
#include "librpc/gen_ndr/samr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb_wrap.h"
#include "param/param.h"
#include "winbind/idmap.h"
#include "libcli/security/proto.h"
#include "libcli/ldap/ldap_ndr.h"

/**
 * Get uid/gid bounds from idmap database
 *
 * \param idmap_ctx idmap context to use
 * \param low lower uid/gid bound is stored here
 * \param high upper uid/gid bound is stored here
 * \return 0 on success, nonzero on failure
 */
static int idmap_get_bounds(struct idmap_context *idmap_ctx, uint32_t *low,
		uint32_t *high)
{
	int ret = -1;
	struct ldb_context *ldb = idmap_ctx->ldb_ctx;
	struct ldb_dn *dn;
	struct ldb_result *res = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(idmap_ctx);
	uint32_t lower_bound = (uint32_t) -1;
	uint32_t upper_bound = (uint32_t) -1;

	dn = ldb_dn_new(tmp_ctx, ldb, "CN=CONFIG");
	if (dn == NULL) goto failed;

	ret = ldb_search(ldb, dn, LDB_SCOPE_BASE, NULL, NULL, &res);
	if (ret != LDB_SUCCESS) goto failed;

	talloc_steal(tmp_ctx, res);

	if (res->count != 1) {
		ret = -1;
		goto failed;
	}

	lower_bound = ldb_msg_find_attr_as_uint(res->msgs[0], "lowerBound", -1);
	if (lower_bound != (uint32_t) -1) {
		ret = LDB_SUCCESS;
	} else {
		ret = -1;
		goto failed;
	}

	upper_bound = ldb_msg_find_attr_as_uint(res->msgs[0], "upperBound", -1);
	if (upper_bound != (uint32_t) -1) {
		ret = LDB_SUCCESS;
	} else {
		ret = -1;
	}

failed:
	talloc_free(tmp_ctx);
	*low  = lower_bound;
	*high = upper_bound;
	return ret;
}

/**
 * Add a dom_sid structure to a ldb_message
 * \param idmap_ctx idmap context to use
 * \param mem_ctx talloc context to use
 * \param ldb_message ldb message to add dom_sid to
 * \param attr_name name of the attribute to store the dom_sid in
 * \param sid dom_sid to store
 * \return 0 on success, an ldb error code on failure.
 */
static int idmap_msg_add_dom_sid(struct idmap_context *idmap_ctx,
		TALLOC_CTX *mem_ctx, struct ldb_message *msg,
		const char *attr_name, const struct dom_sid *sid)
{
	struct ldb_val val;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(&val, mem_ctx,
				       lp_iconv_convenience(idmap_ctx->lp_ctx),
				       sid,
				       (ndr_push_flags_fn_t)ndr_push_dom_sid);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}

	return ldb_msg_add_value(msg, attr_name, &val, NULL);
}

/**
 * Get a dom_sid structure from a ldb message.
 *
 * \param mem_ctx talloc context to allocate dom_sid memory in
 * \param msg ldb_message to get dom_sid from
 * \param attr_name key that has the dom_sid as data
 * \return dom_sid structure on success, NULL on failure
 */
static struct dom_sid *idmap_msg_get_dom_sid(TALLOC_CTX *mem_ctx,
		struct ldb_message *msg, const char *attr_name)
{
	struct dom_sid *sid;
	const struct ldb_val *val;
	enum ndr_err_code ndr_err;

	val = ldb_msg_find_ldb_val(msg, attr_name);
	if (val == NULL) {
		return NULL;
	}

	sid = talloc(mem_ctx, struct dom_sid);
	if (sid == NULL) {
		return NULL;
	}

	ndr_err = ndr_pull_struct_blob(val, sid, NULL, sid,
				       (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(sid);
		return NULL;
	}

	return sid;
}

/**
 * Initialize idmap context
 *
 * talloc_free to close.
 *
 * \param mem_ctx talloc context to use.
 * \return allocated idmap_context on success, NULL on error
 */
struct idmap_context *idmap_init(TALLOC_CTX *mem_ctx,
		struct loadparm_context *lp_ctx)
{
	struct idmap_context *idmap_ctx;

	idmap_ctx = talloc(mem_ctx, struct idmap_context);
	if (idmap_ctx == NULL) {
		return NULL;
	}

	idmap_ctx->lp_ctx = lp_ctx;

	idmap_ctx->ldb_ctx = ldb_wrap_connect(mem_ctx, lp_ctx,
					      lp_idmap_url(lp_ctx),
					      system_session(mem_ctx, lp_ctx),
					      NULL, 0, NULL);
	if (idmap_ctx->ldb_ctx == NULL) {
		return NULL;
	}

	return idmap_ctx;
}

/**
 * Convert a uid to the corresponding SID
 *
 * \param idmap_ctx idmap context to use
 * \param mem_ctx talloc context the memory for the struct dom_sid is allocated
 * from.
 * \param uid Unix uid to map to a SID
 * \param sid Pointer that will take the struct dom_sid pointer if the mapping
 * succeeds.
 * \return NT_STATUS_OK on success, NT_STATUS_NONE_MAPPED if mapping not
 * possible or some other NTSTATUS that is more descriptive on failure.
 */

NTSTATUS idmap_uid_to_sid(struct idmap_context *idmap_ctx, TALLOC_CTX *mem_ctx,
		const uid_t uid, struct dom_sid **sid)
{
	int ret;
	NTSTATUS status = NT_STATUS_NONE_MAPPED;
	struct ldb_context *ldb = idmap_ctx->ldb_ctx;
	struct ldb_message *msg;
	struct ldb_result *res = NULL;
	int trans = -1;
	uid_t low, high;
	char *sid_string, *uid_string;
	struct dom_sid *unix_users_sid, *new_sid;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	ret = ldb_search_exp_fmt(ldb, tmp_ctx, &res, NULL, LDB_SCOPE_SUBTREE,
				 NULL, "(&(objectClass=sidMap)(uidNumber=%u))",
				 uid);
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Search failed: %s\n", ldb_errstring(ldb)));
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	if (res->count == 1) {
		*sid = idmap_msg_get_dom_sid(mem_ctx, res->msgs[0],
					     "objectSid");
		if (*sid == NULL) {
			DEBUG(1, ("Failed to get sid from db: %u\n", ret));
			status = NT_STATUS_NONE_MAPPED;
			goto failed;
		}
		talloc_free(tmp_ctx);
		return NT_STATUS_OK;
	}

	DEBUG(6, ("uid not found in idmap db, trying to allocate SID.\n"));

	trans = ldb_transaction_start(ldb);
	if (trans != LDB_SUCCESS) {
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	/* Now redo the search to make sure noone added a mapping for that SID
	 * while we weren't looking.*/
	ret = ldb_search_exp_fmt(ldb, tmp_ctx, &res, NULL, LDB_SCOPE_SUBTREE,
				 NULL, "(&(objectClass=sidMap)(uidNumber=%u))",
				 uid);
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Search failed: %s\n", ldb_errstring(ldb)));
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	if (res->count > 0) {
		DEBUG(1, ("sidMap modified while trying to add a mapping.\n"));
		status = NT_STATUS_RETRY;
		goto failed;
	}

	ret = idmap_get_bounds(idmap_ctx, &low, &high);
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Failed to get id bounds from db: %u\n", ret));
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	if (uid >= low && uid <= high) {
		/* An existing user would have been mapped before */
		status = NT_STATUS_NO_SUCH_USER;
		goto failed;
	}

	/* For local users, we just create a rid = uid +1, so root doesn't end
	 * up with a 0 rid */
	unix_users_sid = dom_sid_parse_talloc(tmp_ctx, "S-1-22-1");
	if (unix_users_sid == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	new_sid = dom_sid_add_rid(mem_ctx, unix_users_sid, uid + 1);
	if (new_sid == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	sid_string = dom_sid_string(tmp_ctx, new_sid);
	if (sid_string == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	uid_string = talloc_asprintf(tmp_ctx, "%u", uid);
	if (uid_string == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	msg->dn = ldb_dn_new_fmt(tmp_ctx, ldb, "CN=%s", sid_string);
	if (msg->dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	ret = ldb_msg_add_string(msg, "uidNumber", uid_string);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	ret = idmap_msg_add_dom_sid(idmap_ctx, tmp_ctx, msg, "objectSid",
				    new_sid);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	ret = ldb_msg_add_string(msg, "objectClass", "sidMap");
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	ret = ldb_msg_add_string(msg, "cn", sid_string);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	ret = ldb_add(ldb, msg);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	trans = ldb_transaction_commit(ldb);
	if (trans != LDB_SUCCESS) {
		status = NT_STATUS_NONE_MAPPED;
		goto failed;
	}

	*sid = new_sid;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;

failed:
	if (trans == LDB_SUCCESS) ldb_transaction_cancel(ldb);
	talloc_free(tmp_ctx);
	return status;
}

/**
 * Map a Unix gid to the corresponding SID
 *
 * \todo Create a SID from the S-1-22-2 range for unmapped groups
 *
 * \param idmap_ctx idmap context to use
 * \param mem_ctx talloc context the memory for the struct dom_sid is allocated
 * from.
 * \param gid Unix gid to map to a SID
 * \param sid Pointer that will take the struct dom_sid pointer if mapping
 * succeeds.
 * \return NT_STATUS_OK on success, NT_STATUS_NONE_MAPPED if mapping not
 * possible or some other NTSTATUS that is more descriptive on failure.
 */
NTSTATUS idmap_gid_to_sid(struct idmap_context *idmap_ctx, TALLOC_CTX *mem_ctx,
		const gid_t gid, struct dom_sid **sid)
{
	return NT_STATUS_NONE_MAPPED;
}

/**
 * Map a SID to a Unix uid.
 *
 * If no mapping exists, a new mapping will be created.
 *
 * \todo Create mappings for users not from our primary domain.
 *
 * \param idmap_ctx idmap context to use
 * \param mem_ctx talloc context to use
 * \param sid SID to map to a Unix uid
 * \param uid pointer to receive the mapped uid
 * \return NT_STATUS_OK on success, NT_STATUS_INVALID_SID if the sid is not from
 * a trusted domain and idmap trusted only = true, NT_STATUS_NONE_MAPPED if the
 * mapping failed.
 */
NTSTATUS idmap_sid_to_uid(struct idmap_context *idmap_ctx, TALLOC_CTX *mem_ctx,
		const struct dom_sid *sid, uid_t *uid)
{
	return NT_STATUS_NONE_MAPPED;
}

/**
 * Map a SID to a Unix gid.
 *
 * If no mapping exist, a new mapping will be created.
 *
 * \todo Create mappings for groups not from our primary domain.
 *
 * \param idmap_ctx idmap context to use
 * \param mem_ctx talloc context to use
 * \param sid SID to map to a Unix gid
 * \param gid pointer to receive the mapped gid
 * \return NT_STATUS_OK on success, NT_STATUS_INVALID_SID if the sid is not from
 * a trusted domain and idmap trusted only = true, NT_STATUS_NONE_MAPPED if the
 * mapping failed.
 */
NTSTATUS idmap_sid_to_gid(struct idmap_context *idmap_ctx, TALLOC_CTX *mem_ctx,
		const struct dom_sid *sid, gid_t *gid)
{
	return NT_STATUS_NONE_MAPPED;
}

