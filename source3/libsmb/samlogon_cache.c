/*
   Unix SMB/CIFS implementation.
   Net_sam_logon info3 helpers
   Copyright (C) Alexander Bokovoy              2002.
   Copyright (C) Andrew Bartlett                2002.
   Copyright (C) Gerald Carter			2003.
   Copyright (C) Tim Potter			2003.
   Copyright (C) Guenther Deschner		2008.

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

#include "replace.h"
#include "samlogon_cache.h"
#include "system/filesys.h"
#include "system/time.h"
#include "lib/util/debug.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/memory.h" /* for SAFE_FREE() */
#include "source3/lib/util_path.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "../libcli/security/security.h"
#include "util_tdb.h"

#define NETSAMLOGON_TDB	"netsamlogon_cache.tdb"

static TDB_CONTEXT *netsamlogon_tdb = NULL;

/***********************************************************************
 open the tdb
 ***********************************************************************/

bool netsamlogon_cache_init(void)
{
	bool first_try = true;
	char *path = NULL;
	int ret;
	struct tdb_context *tdb;

	if (netsamlogon_tdb) {
		return true;
	}

	path = cache_path(talloc_tos(), NETSAMLOGON_TDB);
	if (path == NULL) {
		return false;
	}
again:
	tdb = tdb_open_log(path, 0, TDB_DEFAULT|TDB_INCOMPATIBLE_HASH,
			   O_RDWR | O_CREAT, 0600);
	if (tdb == NULL) {
		DEBUG(0,("tdb_open_log('%s') - failed\n", path));
		goto clear;
	}

	ret = tdb_check(tdb, NULL, NULL);
	if (ret != 0) {
		tdb_close(tdb);
		DEBUG(0,("tdb_check('%s') - failed\n", path));
		goto clear;
	}

	netsamlogon_tdb = tdb;
	talloc_free(path);
	return true;

clear:
	if (!first_try) {
		talloc_free(path);
		return false;
	}
	first_try = false;

	DEBUG(0,("retry after truncate for '%s'\n", path));
	ret = truncate(path, 0);
	if (ret == -1) {
		DBG_ERR("truncate failed: %s\n", strerror(errno));
		talloc_free(path);
		return false;
	}

	goto again;
}

/***********************************************************************
 Clear cache getpwnam and getgroups entries from the winbindd cache
***********************************************************************/

void netsamlogon_clear_cached_user(const struct dom_sid *user_sid)
{
	struct dom_sid_buf keystr;

	if (!netsamlogon_cache_init()) {
		DEBUG(0,("netsamlogon_clear_cached_user: cannot open "
			"%s for write!\n",
			NETSAMLOGON_TDB));
		return;
	}

	/* Prepare key as DOMAIN-SID/USER-RID string */
	dom_sid_str_buf(user_sid, &keystr);

	DBG_DEBUG("SID [%s]\n", keystr.buf);

	tdb_delete_bystring(netsamlogon_tdb, keystr.buf);
}

/***********************************************************************
 Store a netr_SamInfo3 structure in a tdb for later user
 username should be in UTF-8 format
***********************************************************************/

bool netsamlogon_cache_store(const char *username, struct netr_SamInfo3 *info3)
{
	uint8_t dummy = 0;
	TDB_DATA data = { .dptr = &dummy, .dsize = sizeof(dummy) };
	struct dom_sid_buf keystr;
	bool result = false;
	struct dom_sid	user_sid;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct netsamlogoncache_entry r;
	int ret;

	if (!info3) {
		goto fail;
	}

	if (!netsamlogon_cache_init()) {
		DEBUG(0,("netsamlogon_cache_store: cannot open %s for write!\n",
			NETSAMLOGON_TDB));
		goto fail;
	}

	/*
	 * First write a record with just the domain sid for
	 * netsamlogon_cache_domain_known. Use TDB_INSERT to avoid
	 * overwriting potentially other data. We're just interested
	 * in the existence of that record.
	 */
	dom_sid_str_buf(info3->base.domain_sid, &keystr);

	ret = tdb_store_bystring(netsamlogon_tdb, keystr.buf, data, TDB_INSERT);

	if ((ret == -1) && (tdb_error(netsamlogon_tdb) != TDB_ERR_EXISTS)) {
		DBG_WARNING("Could not store domain marker for %s: %s\n",
			    keystr.buf, tdb_errorstr(netsamlogon_tdb));
		goto fail;
	}

	sid_compose(&user_sid, info3->base.domain_sid, info3->base.rid);

	/* Prepare key as DOMAIN-SID/USER-RID string */
	dom_sid_str_buf(&user_sid, &keystr);

	DBG_DEBUG("SID [%s]\n", keystr.buf);

	/* Prepare data */

	if (info3->base.full_name.string == NULL) {
		struct netr_SamInfo3 *cached_info3;
		const char *full_name = NULL;

		cached_info3 = netsamlogon_cache_get(tmp_ctx, &user_sid);
		if (cached_info3 != NULL) {
			full_name = cached_info3->base.full_name.string;
		}

		if (full_name != NULL) {
			info3->base.full_name.string = talloc_strdup(info3, full_name);
			if (info3->base.full_name.string == NULL) {
				goto fail;
			}
		}
	}

	/* only Samba fills in the username, not sure why NT doesn't */
	/* so we fill it in since winbindd_getpwnam() makes use of it */

	if (!info3->base.account_name.string) {
		info3->base.account_name.string = talloc_strdup(info3, username);
		if (info3->base.account_name.string == NULL) {
			goto fail;
		}
	}

	r.timestamp = time(NULL);
	r.info3 = *info3;

	/* avoid storing secret information */
	ZERO_STRUCT(r.info3.base.key);
	ZERO_STRUCT(r.info3.base.LMSessKey);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(netsamlogoncache_entry, &r);
	}

	ndr_err = ndr_push_struct_blob(&blob, tmp_ctx, &r,
				       (ndr_push_flags_fn_t)ndr_push_netsamlogoncache_entry);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("failed to push entry to cache: %s\n",
			    ndr_errstr(ndr_err));
		goto fail;
	}

	data.dsize = blob.length;
	data.dptr = blob.data;

	if (tdb_store_bystring(netsamlogon_tdb, keystr.buf, data, TDB_REPLACE) == 0) {
		result = true;
	}

fail:
	TALLOC_FREE(tmp_ctx);
	return result;
}

/***********************************************************************
 Retrieves a netr_SamInfo3 structure from a tdb.  Caller must
 free the user_info struct (talloced memory)
***********************************************************************/

struct netr_SamInfo3 *netsamlogon_cache_get(TALLOC_CTX *mem_ctx, const struct dom_sid *user_sid)
{
	struct netr_SamInfo3 *info3 = NULL;
	TDB_DATA data;
	struct dom_sid_buf keystr;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	struct netsamlogoncache_entry r;

	if (!netsamlogon_cache_init()) {
		DEBUG(0,("netsamlogon_cache_get: cannot open %s for write!\n",
			NETSAMLOGON_TDB));
		return NULL;
	}

	/* Prepare key as DOMAIN-SID/USER-RID string */
	dom_sid_str_buf(user_sid, &keystr);
	DBG_DEBUG("SID [%s]\n", keystr.buf);
	data = tdb_fetch_bystring( netsamlogon_tdb, keystr.buf );

	if (!data.dptr) {
		return NULL;
	}

	info3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
	if (!info3) {
		goto done;
	}

	blob = data_blob_const(data.dptr, data.dsize);

	ndr_err = ndr_pull_struct_blob_all(
		&blob, mem_ctx, &r,
		(ndr_pull_flags_fn_t)ndr_pull_netsamlogoncache_entry);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0,("netsamlogon_cache_get: failed to pull entry from cache\n"));
		tdb_delete_bystring(netsamlogon_tdb, keystr.buf);
		TALLOC_FREE(info3);
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(netsamlogoncache_entry, &r);
	}

	info3 = (struct netr_SamInfo3 *)talloc_memdup(mem_ctx, &r.info3,
						      sizeof(r.info3));

 done:
	SAFE_FREE(data.dptr);

	return info3;
}

bool netsamlogon_cache_have(const struct dom_sid *sid)
{
	struct dom_sid_buf keystr;
	bool ok;

	if (!netsamlogon_cache_init()) {
		DBG_WARNING("Cannot open %s\n", NETSAMLOGON_TDB);
		return false;
	}

	dom_sid_str_buf(sid, &keystr);

	ok = tdb_exists(netsamlogon_tdb, string_term_tdb_data(keystr.buf));
	return ok;
}

struct netsamlog_cache_forall_state {
	TALLOC_CTX *mem_ctx;
	int (*cb)(const char *sid_str,
		  time_t when_cached,
		  struct netr_SamInfo3 *,
		  void *private_data);
	void *private_data;
};

static int netsamlog_cache_traverse_cb(struct tdb_context *tdb,
				       TDB_DATA key,
				       TDB_DATA data,
				       void *private_data)
{
	struct netsamlog_cache_forall_state *state =
		(struct netsamlog_cache_forall_state *)private_data;
	TALLOC_CTX *mem_ctx = NULL;
	DATA_BLOB blob;
	const char *sid_str = NULL;
	struct dom_sid sid;
	struct netsamlogoncache_entry r;
	enum ndr_err_code ndr_err;
	int ret;
	bool ok;

	if (key.dsize == 0) {
		return 0;
	}
	if (key.dptr[key.dsize - 1] != '\0') {
		return 0;
	}
	if (data.dptr == NULL) {
		return 0;
	}
	sid_str = (char *)key.dptr;

	ok = string_to_sid(&sid, sid_str);
	if (!ok) {
		DBG_ERR("String to SID failed for %s\n", sid_str);
		return -1;
	}

	if (sid.num_auths != 5) {
		return 0;
	}

	mem_ctx = talloc_new(state->mem_ctx);
	if (mem_ctx == NULL) {
		return -1;
	}

	blob = data_blob_const(data.dptr, data.dsize);

	ndr_err = ndr_pull_struct_blob(
		&blob, state->mem_ctx, &r,
		(ndr_pull_flags_fn_t)ndr_pull_netsamlogoncache_entry);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("failed to pull entry from cache\n");
		return -1;
	}

	ret = state->cb(sid_str, r.timestamp, &r.info3, state->private_data);

	TALLOC_FREE(mem_ctx);
	return ret;
}

int netsamlog_cache_for_all(int (*cb)(const char *sid_str,
				      time_t when_cached,
				      struct netr_SamInfo3 *,
				      void *private_data),
			    void *private_data)
{
	int ret;
	TALLOC_CTX *mem_ctx = NULL;
	struct netsamlog_cache_forall_state state;

	if (!netsamlogon_cache_init()) {
		DBG_ERR("Cannot open %s\n", NETSAMLOGON_TDB);
		return -1;
	}

	mem_ctx = talloc_init("netsamlog_cache_for_all");
	if (mem_ctx == NULL) {
		return -1;
	}

	state = (struct netsamlog_cache_forall_state) {
		.mem_ctx = mem_ctx,
		.cb = cb,
		.private_data = private_data,
	};

	ret = tdb_traverse_read(netsamlogon_tdb,
				netsamlog_cache_traverse_cb,
				&state);

	TALLOC_FREE(state.mem_ctx);
	return ret;
}
