/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme 2012-2014

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
#include "smbd/proto.h"
#include "librpc/gen_ndr/auth.h"
#include "dbwrap/dbwrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/util_tdb.h"
#include "lib/util/time_basic.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security.h"
#include "mdssvc.h"
#include "mdssvc_noindex.h"
#ifdef HAVE_SPOTLIGHT_BACKEND_TRACKER
#include "mdssvc_tracker.h"
#endif
#ifdef HAVE_SPOTLIGHT_BACKEND_ES
#include "mdssvc_es.h"
#endif

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

struct slrpc_cmd {
	const char *name;
	bool (*function)(struct mds_ctx *mds_ctx,
			 const DALLOC_CTX *query,
			 DALLOC_CTX *reply);
};

struct slq_destroy_state {
	struct tevent_context *ev;
	struct sl_query *slq;
};

/*
 * This is a static global because we may be called multiple times and
 * we only want one mdssvc_ctx per connection to Tracker.
 *
 * The client will bind multiple times to the mdssvc RPC service, once
 * for every tree connect.
 */
static struct mdssvc_ctx *mdssvc_ctx = NULL;

/*
 * If these functions return an error, they hit something like a non
 * recoverable talloc error. Most errors are dealt with by returning
 * an error code in the Spotlight RPC reply.
 */
static bool slrpc_fetch_properties(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_open_query(struct mds_ctx *mds_ctx,
			     const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_fetch_query_results(struct mds_ctx *mds_ctx,
				      const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_store_attributes(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_fetch_attributenames(struct mds_ctx *mds_ctx,
				       const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_fetch_attributes(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_close_query(struct mds_ctx *mds_ctx,
			      const DALLOC_CTX *query, DALLOC_CTX *reply);

/************************************************
 * Misc utility functions
 ************************************************/

/**
 * Add requested metadata for a query result element
 *
 * This could be rewritten to something more sophisticated like
 * querying metadata from Tracker.
 *
 * If path or sp is NULL, simply add nil values for all attributes.
 **/
static bool add_filemeta(struct mds_ctx *mds_ctx,
			 sl_array_t *reqinfo,
			 sl_array_t *fm_array,
			 const char *path,
			 const struct stat_ex *sp)
{
	sl_array_t *meta;
	sl_nil_t nil;
	int i, metacount, result;
	uint64_t uint64var;
	sl_time_t sl_time;
	char *p;
	const char *attribute;
	size_t nfc_len;
	const char *nfc_path = path;
	size_t nfd_buf_size;
	char *nfd_path = NULL;
	char *dest = NULL;
	size_t dest_remaining;
	size_t nconv;

	metacount = dalloc_size(reqinfo);
	if (metacount == 0 || path == NULL || sp == NULL) {
		result = dalloc_add_copy(fm_array, &nil, sl_nil_t);
		if (result != 0) {
			return false;
		}
		return true;
	}

	meta = dalloc_zero(fm_array, sl_array_t);
	if (meta == NULL) {
		return false;
	}

	nfc_len = strlen(nfc_path);
	/*
	 * Simple heuristic, strlen by two should give enough room for NFC to
	 * NFD conversion.
	 */
	nfd_buf_size = nfc_len * 2;
	nfd_path = talloc_array(meta, char, nfd_buf_size);
	if (nfd_path == NULL) {
		return false;
	}
	dest = nfd_path;
	dest_remaining = talloc_array_length(dest);

	nconv = smb_iconv(mds_ctx->ic_nfc_to_nfd,
			  &nfc_path,
			  &nfc_len,
			  &dest,
			  &dest_remaining);
	if (nconv == (size_t)-1) {
		return false;
	}

	for (i = 0; i < metacount; i++) {
		attribute = dalloc_get_object(reqinfo, i);
		if (attribute == NULL) {
			return false;
		}
		if (strcmp(attribute, "kMDItemDisplayName") == 0
		    || strcmp(attribute, "kMDItemFSName") == 0) {
			p = strrchr(nfd_path, '/');
			if (p) {
				result = dalloc_stradd(meta, p + 1);
				if (result != 0) {
					return false;
				}
			}
		} else if (strcmp(attribute, "kMDItemPath") == 0) {
			result = dalloc_stradd(meta, nfd_path);
			if (result != 0) {
				return false;
			}
		} else if (strcmp(attribute, "kMDItemFSSize") == 0) {
			uint64var = sp->st_ex_size;
			result = dalloc_add_copy(meta, &uint64var, uint64_t);
			if (result != 0) {
				return false;
			}
		} else if (strcmp(attribute, "kMDItemFSOwnerUserID") == 0) {
			uint64var = sp->st_ex_uid;
			result = dalloc_add_copy(meta, &uint64var, uint64_t);
			if (result != 0) {
				return false;
			}
		} else if (strcmp(attribute, "kMDItemFSOwnerGroupID") == 0) {
			uint64var = sp->st_ex_gid;
			result = dalloc_add_copy(meta, &uint64var, uint64_t);
			if (result != 0) {
				return false;
			}
		} else if (strcmp(attribute, "kMDItemFSContentChangeDate") == 0) {
			sl_time.tv_sec = sp->st_ex_mtime.tv_sec;
			result = dalloc_add_copy(meta, &sl_time, sl_time_t);
			if (result != 0) {
				return false;
			}
		} else {
			result = dalloc_add_copy(meta, &nil, sl_nil_t);
			if (result != 0) {
				return false;
			}
		}
	}

	result = dalloc_add(fm_array, meta, sl_array_t);
	if (result != 0) {
		return false;
	}
	return true;
}

static int cnid_comp_fn(const void *p1, const void *p2)
{
	const uint64_t *cnid1 = p1, *cnid2 = p2;
	if (*cnid1 == *cnid2) {
		return 0;
	}
	if (*cnid1 < *cnid2) {
		return -1;
	}
	return 1;
}

/**
 * Create a sorted copy of a CNID array
 **/
static bool sort_cnids(struct sl_query *slq, const DALLOC_CTX *d)
{
	uint64_t *cnids = NULL;
	int i;
	const void *p;

	cnids = talloc_array(slq, uint64_t, dalloc_size(d));
	if (cnids == NULL) {
		return false;
	}

	for (i = 0; i < dalloc_size(d); i++) {
		p = dalloc_get_object(d, i);
		if (p == NULL) {
			return NULL;
		}
		memcpy(&cnids[i], p, sizeof(uint64_t));
	}
	qsort(cnids, dalloc_size(d), sizeof(uint64_t), cnid_comp_fn);

	slq->cnids = cnids;
	slq->cnids_num = dalloc_size(d);

	return true;
}

/**
 * Allocate result handle used in the async Tracker cursor result
 * handler for storing results
 **/
static bool create_result_handle(struct sl_query *slq)
{
	sl_nil_t nil = 0;
	struct sl_rslts *query_results;
	int result;

	if (slq->query_results) {
		DEBUG(1, ("unexpected existing result handle\n"));
		return false;
	}

	query_results = talloc_zero(slq, struct sl_rslts);
	if (query_results == NULL) {
		return false;
	}

	/* CNIDs */
	query_results->cnids = talloc_zero(query_results, sl_cnids_t);
	if (query_results->cnids == NULL) {
		return false;
	}
	query_results->cnids->ca_cnids = dalloc_new(query_results->cnids);
	if (query_results->cnids->ca_cnids == NULL) {
		return false;
	}

	query_results->cnids->ca_unkn1 = 0xadd;
	if (slq->ctx2 > UINT32_MAX) {
		DEBUG(1,("64bit ctx2 id too large: 0x%jx", (uintmax_t)slq->ctx2));
		return false;
	}
	query_results->cnids->ca_context = (uint32_t)slq->ctx2;

	/* FileMeta */
	query_results->fm_array = dalloc_zero(query_results, sl_array_t);
	if (query_results->fm_array == NULL) {
		return false;
	}

	/* For some reason the list of results always starts with a nil entry */
	result = dalloc_add_copy(query_results->fm_array, &nil, sl_nil_t);
	if (result != 0) {
		return false;
	}

	slq->query_results = query_results;
	return true;
}

static bool add_results(sl_array_t *array, struct sl_query *slq)
{
	sl_filemeta_t *fm;
	uint64_t status = 0;
	int result;
	bool ok;

	/* FileMeta */
	fm = dalloc_zero(array, sl_filemeta_t);
	if (fm == NULL) {
		return false;
	}

	result = dalloc_add_copy(array, &status, uint64_t);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(array, slq->query_results->cnids, sl_cnids_t);
	if (result != 0) {
		return false;
	}
	if (slq->query_results->num_results > 0) {
		result = dalloc_add(fm, slq->query_results->fm_array, sl_array_t);
		if (result != 0) {
			return false;
		}
	}
	result = dalloc_add(array, fm, sl_filemeta_t);
	if (result != 0) {
		return false;
	}

	/* This ensure the results get clean up after been sent to the client */
	talloc_move(array, &slq->query_results);

	ok = create_result_handle(slq);
	if (!ok) {
		DEBUG(1, ("couldn't add result handle\n"));
		slq->state = SLQ_STATE_ERROR;
		return false;
	}

	return true;
}

static const struct slrpc_cmd *slrpc_cmd_by_name(const char *rpccmd)
{
	size_t i;
	static const struct slrpc_cmd cmds[] = {
		{ "fetchPropertiesForContext:", slrpc_fetch_properties},
		{ "openQueryWithParams:forContext:", slrpc_open_query},
		{ "fetchQueryResultsForContext:", slrpc_fetch_query_results},
		{ "storeAttributes:forOIDArray:context:", slrpc_store_attributes},
		{ "fetchAttributeNamesForOIDArray:context:", slrpc_fetch_attributenames},
		{ "fetchAttributes:forOIDArray:context:", slrpc_fetch_attributes},
		{ "fetchAllAttributes:forOIDArray:context:", slrpc_fetch_attributes},
		{ "closeQueryForContext:", slrpc_close_query},
	};

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		int cmp;

		cmp = strcmp(cmds[i].name, rpccmd);
		if (cmp == 0) {
			return &cmds[i];
		}
	}

	return NULL;
}

/**
 * Search the list of active queries given their context ids
 **/
static struct sl_query *slq_for_ctx(struct mds_ctx *mds_ctx,
				    uint64_t ctx1, uint64_t ctx2)
{
	struct sl_query *q;

	for (q = mds_ctx->query_list; q; q = q->next) {
		if ((q->ctx1 == ctx1) && (q->ctx2 == ctx2)) {
			return q;
		}
	}

	return NULL;
}

static int slq_destructor_cb(struct sl_query *slq)
{
	SLQ_DEBUG(10, slq, "destroying");

	/* Free all entries before freeing the slq handle! */
	TALLOC_FREE(slq->entries_ctx);
	TALLOC_FREE(slq->te);

	if (slq->mds_ctx != NULL) {
		DLIST_REMOVE(slq->mds_ctx->query_list, slq);
		slq->mds_ctx = NULL;
	}

	TALLOC_FREE(slq->backend_private);

	return 0;
}

/**
 * Remove talloc_refcounted entry from mapping db
 *
 * Multiple queries (via the slq handle) may reference a
 * sl_inode_path_map entry, when the last reference goes away as the
 * queries are closed and this gets called to remove the entry from
 * the db.
 **/
static int ino_path_map_destr_cb(struct sl_inode_path_map *entry)
{
	NTSTATUS status;
	TDB_DATA key;

	key = make_tdb_data((uint8_t *)&entry->ino, sizeof(entry->ino));

	status = dbwrap_delete(entry->mds_ctx->ino_path_map, key);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to delete record: %s\n", nt_errstr(status)));
		return -1;
	}

	DBG_DEBUG("deleted [0x%"PRIx64"] [%s]\n", entry->ino, entry->path);
	return 0;
}

/**
 * Add result to inode->path mapping dbwrap rbt db
 *
 * This is necessary as a CNID db substitute, ie we need a way to
 * simulate unique, constant numerical identifiers for paths with an
 * API that supports mapping from id to path.
 *
 * Entries are talloc'ed of the query, using talloc_reference() if
 * multiple queries returned the same result. That way we can cleanup
 * entries by calling talloc_free() on the query slq handles.
 **/

static bool inode_map_add(struct sl_query *slq, uint64_t ino, const char *path)
{
	NTSTATUS status;
	struct sl_inode_path_map *entry;
	TDB_DATA key, value;
	void *p;

	key = make_tdb_data((uint8_t *)&ino, sizeof(ino));
	status = dbwrap_fetch(slq->mds_ctx->ino_path_map, slq, key, &value);

	if (NT_STATUS_IS_OK(status)) {
		/*
		 * We have one db, so when different parallel queries
		 * return the same file, we have to refcount entries
		 * in the db.
		 */

		if (value.dsize != sizeof(void *)) {
			DEBUG(1, ("invalide dsize\n"));
			return false;
		}
		memcpy(&p, value.dptr, sizeof(p));
		entry = talloc_get_type_abort(p, struct sl_inode_path_map);

		DEBUG(10, ("map: %s\n", entry->path));

		entry = talloc_reference(slq->entries_ctx, entry);
		if (entry == NULL) {
			DEBUG(1, ("talloc_reference failed\n"));
			return false;
		}
		return true;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DEBUG(1, ("dbwrap_fetch failed %s\n", nt_errstr(status)));
		return false;
	}

	entry = talloc_zero(slq->entries_ctx, struct sl_inode_path_map);
	if (entry == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return false;
	}

	entry->ino = ino;
	entry->mds_ctx = slq->mds_ctx;
	entry->path = talloc_strdup(entry, path);
	if (entry->path == NULL) {
		DEBUG(1, ("talloc failed\n"));
		TALLOC_FREE(entry);
		return false;
	}

	status = dbwrap_store(slq->mds_ctx->ino_path_map, key,
			      make_tdb_data((void *)&entry, sizeof(void *)), 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to store record: %s\n", nt_errstr(status)));
		TALLOC_FREE(entry);
		return false;
	}

	talloc_set_destructor(entry, ino_path_map_destr_cb);

	return true;
}

bool mds_add_result(struct sl_query *slq, const char *path)
{
	struct smb_filename *smb_fname = NULL;
	struct stat_ex sb;
	uint32_t attr;
	uint64_t ino64;
	int result;
	NTSTATUS status;
	bool ok;

	smb_fname = synthetic_smb_fname(talloc_tos(),
					path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		DBG_ERR("synthetic_smb_fname() failed\n");
		return false;
	}

	/*
	 * We're in a tevent callback which means in the case of
	 * running as external RPC service we're running as root and
	 * not as the user.
	 */
	if (!become_authenticated_pipe_user(slq->mds_ctx->pipe_session_info)) {
		DBG_ERR("can't become authenticated user: %d\n",
			slq->mds_ctx->uid);
		smb_panic("can't become authenticated user");
	}

	if (geteuid() != slq->mds_ctx->uid) {
		DBG_ERR("uid mismatch: %d/%d\n", geteuid(), slq->mds_ctx->uid);
		smb_panic("uid mismatch");
	}

	/*
	 * We've changed identity to the authenticated pipe user, so
	 * any function exit below must ensure we switch back
	 */

	result = SMB_VFS_STAT(slq->mds_ctx->conn, smb_fname);
	if (result != 0) {
		DBG_DEBUG("SMB_VFS_STAT [%s] failed: %s\n",
			  smb_fname_str_dbg(smb_fname),
			  strerror(errno));
		unbecome_authenticated_pipe_user();
		TALLOC_FREE(smb_fname);
		return true;
	}

	status = smbd_check_access_rights(slq->mds_ctx->conn,
					  slq->mds_ctx->conn->cwd_fsp,
					  smb_fname,
					  false,
					  FILE_READ_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		unbecome_authenticated_pipe_user();
		TALLOC_FREE(smb_fname);
		return true;
	}

	/* This is needed to fetch the itime from the DOS attribute blob */
	status = SMB_VFS_GET_DOS_ATTRIBUTES(slq->mds_ctx->conn,
					    smb_fname,
					    &attr);
	if (!NT_STATUS_IS_OK(status)) {
		/* Ignore the error, likely no DOS attr xattr */
		DBG_DEBUG("SMB_VFS_FGET_DOS_ATTRIBUTES [%s]: %s\n",
			  smb_fname_str_dbg(smb_fname),
			  nt_errstr(status));
	}

	unbecome_authenticated_pipe_user();

	sb = smb_fname->st;
	TALLOC_FREE(smb_fname);
	ino64 = SMB_VFS_FS_FILE_ID(slq->mds_ctx->conn, &sb);

	if (slq->cnids) {
		bool found;

		/*
		 * Check whether the found element is in the requested
		 * set of IDs. Note that we're faking CNIDs by using
		 * filesystem inode numbers here
		 */
		found = bsearch(&ino64,
				slq->cnids,
				slq->cnids_num,
				sizeof(uint64_t),
				cnid_comp_fn);
		if (!found) {
			return true;
		}
	}

	/*
	 * Add inode number and filemeta to result set, this is what
	 * we return as part of the result set of a query
	 */
	result = dalloc_add_copy(slq->query_results->cnids->ca_cnids,
				 &ino64,
				 uint64_t);
	if (result != 0) {
		DBG_ERR("dalloc error\n");
		slq->state = SLQ_STATE_ERROR;
		return false;
	}
	ok = add_filemeta(slq->mds_ctx,
			  slq->reqinfo,
			  slq->query_results->fm_array,
			  path,
			  &sb);
	if (!ok) {
		DBG_ERR("add_filemeta error\n");
		slq->state = SLQ_STATE_ERROR;
		return false;
	}

	ok = inode_map_add(slq, ino64, path);
	if (!ok) {
		DEBUG(1, ("inode_map_add error\n"));
		slq->state = SLQ_STATE_ERROR;
		return false;
	}

	slq->query_results->num_results++;
	return true;
}

/***********************************************************
 * Spotlight RPC functions
 ***********************************************************/

static bool slrpc_fetch_properties(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	sl_dict_t *dict;
	sl_array_t *array;
	char *s;
	uint64_t u;
	sl_bool_t b;
	sl_uuid_t uuid;
	int result;

	dict = dalloc_zero(reply, sl_dict_t);
	if (dict == NULL) {
		return false;
	}

	/* kMDSStoreHasPersistentUUID = false */
	result = dalloc_stradd(dict, "kMDSStoreHasPersistentUUID");
	if (result != 0) {
		return false;
	}
	b = false;
	result = dalloc_add_copy(dict, &b, sl_bool_t);
	if (result != 0) {
		return false;
	}

	/* kMDSStoreIsBackup = false */
	result = dalloc_stradd(dict, "kMDSStoreIsBackup");
	if (result != 0) {
		return false;
	}
	b = false;
	result = dalloc_add_copy(dict, &b, sl_bool_t);
	if (result != 0) {
		return false;
	}

	/* kMDSStoreUUID = uuid */
	result = dalloc_stradd(dict, "kMDSStoreUUID");
	if (result != 0) {
		return false;
	}
	memcpy(uuid.sl_uuid, "fakeuuidfakeuuid", sizeof(uuid.sl_uuid));
	result = dalloc_add_copy(dict, &uuid, sl_uuid_t);
	if (result != 0) {
		return false;
	}

	/* kMDSStoreSupportsVolFS = true */
	result = dalloc_stradd(dict, "kMDSStoreSupportsVolFS");
	if (result != 0) {
		return false;
	}
	b = true;
	result = dalloc_add_copy(dict, &b, sl_bool_t);
	if (result != 0) {
		return false;
	}

	/* kMDSVolumeUUID = uuid */
	result = dalloc_stradd(dict, "kMDSVolumeUUID");
	if (result != 0) {
		return false;
	}
	memcpy(uuid.sl_uuid, "fakeuuidfakeuuid", sizeof(uuid.sl_uuid));
	result = dalloc_add_copy(dict, &uuid, sl_uuid_t);
	if (result != 0) {
		return false;
	}

	/* kMDSDiskStoreSpindleNumber = 1 (fake) */
	result = dalloc_stradd(dict, "kMDSDiskStoreSpindleNumber");
	if (result != 0) {
		return false;
	}
	u = 1;
	result = dalloc_add_copy(dict, &u, uint64_t);
	if (result != 0) {
		return false;
	}

	/* kMDSDiskStorePolicy = 3 (whatever that means, taken from OS X) */
	result = dalloc_stradd(dict, "kMDSDiskStorePolicy");
	if (result != 0) {
		return false;
	}
	u = 3;
	result = dalloc_add_copy(dict, &u, uint64_t);
	if (result != 0) {
		return false;
	}

	/* kMDSStoreMetaScopes array */
	array = dalloc_zero(dict, sl_array_t);
	if (array == NULL) {
		return NULL;
	}
	result = dalloc_stradd(array, "kMDQueryScopeComputer");
	if (result != 0) {
		return false;
	}
	result = dalloc_stradd(array, "kMDQueryScopeAllIndexed");
	if (result != 0) {
		return false;
	}
	result = dalloc_stradd(array, "kMDQueryScopeComputerIndexed");
	if (result != 0) {
		return false;
	}
	result = dalloc_add(dict, array, sl_array_t);
	if (result != 0) {
		return false;
	}

	/* kMDSStoreDevice = 0x1000003 (whatever that means, taken from OS X) */
	result = dalloc_stradd(dict, "kMDSStoreDevice");
	if (result != 0) {
		return false;
	}
	u = 0x1000003;
	result = dalloc_add_copy(dict, &u, uint64_t);
	if (result != 0) {
		return false;
	}

	/* kMDSStoreSupportsTCC = true (whatever that means, taken from OS X) */
	result = dalloc_stradd(dict, "kMDSStoreSupportsTCC");
	if (result != 0) {
		return false;
	}
	b = true;
	result = dalloc_add_copy(dict, &b, sl_bool_t);
	if (result != 0) {
		return false;
	}

	/* kMDSStorePathScopes = ["/"] (whatever that means, taken from OS X) */
	result = dalloc_stradd(dict, "kMDSStorePathScopes");
	if (result != 0) {
		return false;
	}
	array = dalloc_zero(dict, sl_array_t);
	if (array == NULL) {
		return false;
	}
	s = talloc_strdup(dict, "/");
	if (s == NULL) {
		return false;
	}
	talloc_set_name(s, "smb_ucs2_t *");
	result = dalloc_add(array, s, smb_ucs2_t *);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(dict, array, sl_array_t);
	if (result != 0) {
		return false;
	}

	result = dalloc_add(reply, dict, sl_dict_t);
	if (result != 0) {
		return false;
	}

	return true;
}

static void slq_close_timer(struct tevent_context *ev,
			    struct tevent_timer *te,
			    struct timeval current_time,
			    void *private_data)
{
	struct sl_query *slq = talloc_get_type_abort(
		private_data, struct sl_query);
	struct mds_ctx *mds_ctx = slq->mds_ctx;

	SLQ_DEBUG(10, slq, "expired");

	TALLOC_FREE(slq);

	if (CHECK_DEBUGLVL(10)) {
		for (slq = mds_ctx->query_list; slq != NULL; slq = slq->next) {
			SLQ_DEBUG(10, slq, "pending");
		}
	}
}

/**
 * Begin a search query
 **/
static bool slrpc_open_query(struct mds_ctx *mds_ctx,
			     const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	bool ok;
	uint64_t sl_result;
	uint64_t *uint64p;
	DALLOC_CTX *reqinfo;
	sl_array_t *array, *path_scope;
	sl_cnids_t *cnids;
	struct sl_query *slq = NULL;
	int result;
	const char *querystring = NULL;
	size_t querystring_len;
	char *dest = NULL;
	size_t dest_remaining;
	size_t nconv;
	char *scope = NULL;

	array = dalloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	/* Allocate and initialize query object */
	slq = talloc_zero(mds_ctx, struct sl_query);
	if (slq == NULL) {
		return false;
	}
	slq->entries_ctx = talloc_named_const(slq, 0, "struct sl_query.entries_ctx");
	if (slq->entries_ctx == NULL) {
		TALLOC_FREE(slq);
		return false;
	}
	talloc_set_destructor(slq, slq_destructor_cb);
	slq->state = SLQ_STATE_NEW;
	slq->mds_ctx = mds_ctx;

	slq->last_used = timeval_current();
	slq->start_time = slq->last_used;
	slq->expire_time = timeval_add(&slq->last_used, MAX_SL_RUNTIME, 0);
	slq->te = tevent_add_timer(global_event_context(), slq,
				   slq->expire_time, slq_close_timer, slq);
	if (slq->te == NULL) {
		DEBUG(1, ("tevent_add_timer failed\n"));
		goto error;
	}

	querystring = dalloc_value_for_key(query, "DALLOC_CTX", 0,
					   "DALLOC_CTX", 1,
					   "kMDQueryString");
	if (querystring == NULL) {
		DEBUG(1, ("missing kMDQueryString\n"));
		goto error;
	}

	querystring_len = talloc_array_length(querystring);

	slq->query_string = talloc_array(slq, char, querystring_len);
	if (slq->query_string == NULL) {
		DEBUG(1, ("out of memory\n"));
		goto error;
	}
	dest = slq->query_string;
	dest_remaining = talloc_array_length(dest);

	nconv = smb_iconv(mds_ctx->ic_nfd_to_nfc,
			  &querystring,
			  &querystring_len,
			  &dest,
			  &dest_remaining);
	if (nconv == (size_t)-1) {
		DBG_ERR("smb_iconv failed for: %s\n", querystring);
		return false;
	}

	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 1);
	if (uint64p == NULL) {
		goto error;
	}
	slq->ctx1 = *uint64p;
	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 2);
	if (uint64p == NULL) {
		goto error;
	}
	slq->ctx2 = *uint64p;

	path_scope = dalloc_value_for_key(query, "DALLOC_CTX", 0,
					  "DALLOC_CTX", 1, "kMDScopeArray");
	if (path_scope == NULL) {
		goto error;
	}

	scope = dalloc_get(path_scope, "char *", 0);
	if (scope == NULL) {
		goto error;
	}

	slq->path_scope = talloc_strdup(slq, scope);
	if (slq->path_scope == NULL) {
		goto error;
	}

	reqinfo = dalloc_value_for_key(query, "DALLOC_CTX", 0,
				       "DALLOC_CTX", 1, "kMDAttributeArray");
	if (reqinfo == NULL) {
		goto error;
	}

	slq->reqinfo = talloc_steal(slq, reqinfo);
	DEBUG(10, ("requested attributes: %s", dalloc_dump(reqinfo, 0)));

	cnids = dalloc_value_for_key(query, "DALLOC_CTX", 0,
				     "DALLOC_CTX", 1, "kMDQueryItemArray");
	if (cnids) {
		ok = sort_cnids(slq, cnids->ca_cnids);
		if (!ok) {
			goto error;
		}
	}

	ok = create_result_handle(slq);
	if (!ok) {
		DEBUG(1, ("create_result_handle error\n"));
		slq->state = SLQ_STATE_ERROR;
		goto error;
	}

	SLQ_DEBUG(10, slq, "new");

	DLIST_ADD(mds_ctx->query_list, slq);

	ok = mds_ctx->backend->search_start(slq);
	if (!ok) {
		DBG_ERR("backend search_start failed\n");
		goto error;
	}

	sl_result = 0;
	result = dalloc_add_copy(array, &sl_result, uint64_t);
	if (result != 0) {
		goto error;
	}
	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		goto error;
	}
	return true;

error:
	sl_result = UINT64_MAX;
	TALLOC_FREE(slq);
	result = dalloc_add_copy(array, &sl_result, uint64_t);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		return false;
	}
	return true;
}

/**
 * Fetch results of a query
 **/
static bool slrpc_fetch_query_results(struct mds_ctx *mds_ctx,
				      const DALLOC_CTX *query,
				      DALLOC_CTX *reply)
{
	bool ok;
	struct sl_query *slq = NULL;
	uint64_t *uint64p, ctx1, ctx2;
	uint64_t status;
	sl_array_t *array;
	int result;

	array = dalloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	/* Get query for context */
	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 1);
	if (uint64p == NULL) {
		goto error;
	}
	ctx1 = *uint64p;

	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 2);
	if (uint64p == NULL) {
		goto error;
	}
	ctx2 = *uint64p;

	slq = slq_for_ctx(mds_ctx, ctx1, ctx2);
	if (slq == NULL) {
		DEBUG(1, ("bad context: [0x%jx,0x%jx]\n",
			  (uintmax_t)ctx1, (uintmax_t)ctx2));
		goto error;
	}

	TALLOC_FREE(slq->te);
	slq->last_used = timeval_current();
	slq->expire_time = timeval_add(&slq->last_used, MAX_SL_RUNTIME, 0);
	slq->te = tevent_add_timer(global_event_context(), slq,
				   slq->expire_time, slq_close_timer, slq);
	if (slq->te == NULL) {
		DEBUG(1, ("tevent_add_timer failed\n"));
		goto error;
	}

	SLQ_DEBUG(10, slq, "fetch");

	switch (slq->state) {
	case SLQ_STATE_RUNNING:
	case SLQ_STATE_RESULTS:
	case SLQ_STATE_FULL:
	case SLQ_STATE_DONE:
		ok = add_results(array, slq);
		if (!ok) {
			DEBUG(1, ("error adding results\n"));
			goto error;
		}
		if (slq->state == SLQ_STATE_FULL) {
			slq->state = SLQ_STATE_RESULTS;
			slq->mds_ctx->backend->search_cont(slq);
		}
		break;

	case SLQ_STATE_ERROR:
		DEBUG(1, ("query in error state\n"));
		goto error;

	default:
		DEBUG(1, ("unexpected query state %d\n", slq->state));
		goto error;
	}

	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		goto error;
	}
	return true;

error:
	status = UINT64_MAX;
	TALLOC_FREE(slq);
	result = dalloc_add_copy(array, &status, uint64_t);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		return false;
	}
	return true;
}

/**
 * Store metadata attributes for a CNID
 **/
static bool slrpc_store_attributes(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	uint64_t sl_result;
	sl_array_t *array;
	int result;

	array = dalloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	/*
	 * FIXME: not implemented. Used by the client for eg setting
	 * the modification date of the shared directory which clients
	 * poll indicating changes on the share and cause the client
	 * to refresh view.
	 */

	sl_result = 0;
	result = dalloc_add_copy(array, &sl_result, uint64_t);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		return false;
	}

	return true;
}

/**
 * Fetch supported metadata attributes for a CNID
 **/
static bool slrpc_fetch_attributenames(struct mds_ctx *mds_ctx,
				       const DALLOC_CTX *query,
				       DALLOC_CTX *reply)
{
	uint64_t id;
	sl_cnids_t *cnids;
	sl_array_t *array;
	uint64_t sl_result;
	sl_cnids_t *replycnids;
	sl_array_t *mdattrs;
	sl_filemeta_t *fmeta;
	int result;
	void *p;

	cnids = dalloc_get(query, "DALLOC_CTX", 0, "sl_cnids_t", 1);
	if (cnids == NULL) {
		return false;
	}

	p = dalloc_get_object(cnids->ca_cnids, 0);
	if (p == NULL) {
		return NULL;
	}
	memcpy(&id, p, sizeof(uint64_t));

	/* Result array */
	array = dalloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		return false;
	}

	/* Return result value 0 */
	sl_result = 0;
	result = dalloc_add_copy(array, &sl_result, uint64_t);
	if (result != 0) {
		return false;
	}

	/* Return CNID array */
	replycnids = talloc_zero(reply, sl_cnids_t);
	if (replycnids == NULL) {
		return false;
	}

	replycnids->ca_cnids = dalloc_new(cnids);
	if (replycnids->ca_cnids == NULL) {
		return false;
	}

	replycnids->ca_unkn1 = 0xfec;
	replycnids->ca_context = cnids->ca_context;
	result = dalloc_add_copy(replycnids->ca_cnids, &id, uint64_t);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(array, replycnids, sl_cnids_t);
	if (result != 0) {
		return false;
	}

	/*
	 * FIXME: this should return the real attributes from all
	 * known metadata sources (Tracker and filesystem)
	 */
	mdattrs = dalloc_zero(reply, sl_array_t);
	if (mdattrs == NULL) {
		return false;
	}

	result = dalloc_stradd(mdattrs, "kMDItemFSName");
	if (result != 0) {
		return false;
	}
	result = dalloc_stradd(mdattrs, "kMDItemDisplayName");
	if (result != 0) {
		return false;
	}
	result = dalloc_stradd(mdattrs, "kMDItemFSSize");
	if (result != 0) {
		return false;
	}
	result = dalloc_stradd(mdattrs, "kMDItemFSOwnerUserID");
	if (result != 0) {
		return false;
	}
	result = dalloc_stradd(mdattrs, "kMDItemFSOwnerGroupID");
	if (result != 0) {
		return false;
	}
	result = dalloc_stradd(mdattrs, "kMDItemFSContentChangeDate");
	if (result != 0) {
		return false;
	}

	fmeta = dalloc_zero(reply, sl_filemeta_t);
	if (fmeta == NULL) {
		return false;
	}
	result = dalloc_add(fmeta, mdattrs, sl_array_t);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(array, fmeta, sl_filemeta_t);
	if (result != 0) {
		return false;
	}

	return true;
}

/**
 * Fetch metadata attribute values for a CNID
 **/
static bool slrpc_fetch_attributes(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	int result;
	bool ok;
	sl_array_t *array;
	sl_cnids_t *cnids;
	sl_cnids_t *replycnids;
	sl_array_t *reqinfo;
	uint64_t ino;
	uint64_t sl_result;
	sl_filemeta_t *fm;
	sl_array_t *fm_array;
	sl_nil_t nil;
	char *path = NULL;
	struct smb_filename *smb_fname = NULL;
	struct stat_ex *sp = NULL;
	struct sl_inode_path_map *elem = NULL;
	void *p;
	TDB_DATA val = tdb_null;
	NTSTATUS status;

	array = dalloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}
	replycnids = talloc_zero(reply, sl_cnids_t);
	if (replycnids == NULL) {
		goto error;
	}
	replycnids->ca_cnids = dalloc_new(replycnids);
	if (replycnids->ca_cnids == NULL) {
		goto error;
	}
	fm = dalloc_zero(array, sl_filemeta_t);
	if (fm == NULL) {
		goto error;
	}
	fm_array = dalloc_zero(fm, sl_array_t);
	if (fm_array == NULL) {
		goto error;
	}
	/* For some reason the list of results always starts with a nil entry */
	result = dalloc_add_copy(fm_array, &nil, sl_nil_t);
	if (result == -1) {
		goto error;
	}

	reqinfo = dalloc_get(query, "DALLOC_CTX", 0, "sl_array_t", 1);
	if (reqinfo == NULL) {
		goto error;
	}

	cnids = dalloc_get(query, "DALLOC_CTX", 0, "sl_cnids_t", 2);
	if (cnids == NULL) {
		goto error;
	}
	p = dalloc_get_object(cnids->ca_cnids, 0);
	if (p == NULL) {
		goto error;
	}
	memcpy(&ino, p, sizeof(uint64_t));

	replycnids->ca_unkn1 = 0xfec;
	replycnids->ca_context = cnids->ca_context;
	result = dalloc_add_copy(replycnids->ca_cnids, &ino, uint64_t);
	if (result != 0) {
		goto error;
	}

	status = dbwrap_fetch(mds_ctx->ino_path_map, reply,
			      make_tdb_data((void*)&ino, sizeof(uint64_t)),
			      &val);
	if (NT_STATUS_IS_OK(status)) {
		if (val.dsize != sizeof(p)) {
			DBG_ERR("invalid record pointer size: %zd\n", val.dsize);
			TALLOC_FREE(val.dptr);
			goto error;
		}

		memcpy(&p, val.dptr, sizeof(p));
		elem = talloc_get_type_abort(p, struct sl_inode_path_map);
		path = elem->path;

		smb_fname = synthetic_smb_fname(talloc_tos(),
						path,
						NULL,
						NULL,
						0,
						0);
		if (smb_fname == NULL) {
			DBG_ERR("synthetic_smb_fname() failed\n");
			goto error;
		}

		result = SMB_VFS_STAT(mds_ctx->conn, smb_fname);
		if (result != 0) {
			goto error;
		}

		sp = &smb_fname->st;
	}

	ok = add_filemeta(mds_ctx, reqinfo, fm_array, path, sp);
	if (!ok) {
		goto error;
	}

	sl_result = 0;
	result = dalloc_add_copy(array, &sl_result, uint64_t);
	if (result != 0) {
		goto error;
	}
	result = dalloc_add(array, replycnids, sl_cnids_t);
	if (result != 0) {
		goto error;
	}
	result = dalloc_add(fm, fm_array, sl_array_t);
	if (result != 0) {
		goto error;
	}
	result = dalloc_add(array, fm, sl_filemeta_t);
	if (result != 0) {
		goto error;
	}
	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		goto error;
	}

	TALLOC_FREE(smb_fname);
	return true;

error:

	TALLOC_FREE(smb_fname);
	sl_result = UINT64_MAX;
	result = dalloc_add_copy(array, &sl_result, uint64_t);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		return false;
	}

	return true;
}

/**
 * Close a query
 **/
static bool slrpc_close_query(struct mds_ctx *mds_ctx,
			      const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	struct sl_query *slq = NULL;
	uint64_t *uint64p, ctx1, ctx2;
	sl_array_t *array;
	uint64_t sl_res;
	int result;

	array = dalloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	/* Context */
	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 1);
	if (uint64p == NULL) {
		goto done;
	}
	ctx1 = *uint64p;

	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 2);
	if (uint64p == NULL) {
		goto done;
	}
	ctx2 = *uint64p;

	/* Get query for context and free it */
	slq = slq_for_ctx(mds_ctx, ctx1, ctx2);
	if (slq == NULL) {
		DEBUG(1, ("bad context: [0x%jx,0x%jx]\n",
			  (uintmax_t)ctx1, (uintmax_t)ctx2));
		goto done;
	}

	SLQ_DEBUG(10, slq, "close");
	TALLOC_FREE(slq);

done:
	sl_res = UINT64_MAX;
	result = dalloc_add_copy(array, &sl_res, uint64_t);
	if (result != 0) {
		return false;
	}
	result = dalloc_add(reply, array, sl_array_t);
	if (result != 0) {
		return false;
	}
	return true;
}

static struct mdssvc_ctx *mdssvc_init(struct tevent_context *ev)
{
	bool ok;

	if (mdssvc_ctx != NULL) {
		return mdssvc_ctx;
	}

	mdssvc_ctx = talloc_zero(ev, struct mdssvc_ctx);
	if (mdssvc_ctx == NULL) {
		return NULL;
	}

	mdssvc_ctx->ev_ctx = ev;

	ok = mdsscv_backend_noindex.init(mdssvc_ctx);
	if (!ok) {
		DBG_ERR("backend init failed\n");
		TALLOC_FREE(mdssvc_ctx);
		return NULL;
	}

#ifdef HAVE_SPOTLIGHT_BACKEND_ES
	ok = mdsscv_backend_es.init(mdssvc_ctx);
	if (!ok) {
		DBG_ERR("backend init failed\n");
		TALLOC_FREE(mdssvc_ctx);
		return NULL;
	}
#endif

#ifdef HAVE_SPOTLIGHT_BACKEND_TRACKER
	ok = mdsscv_backend_tracker.init(mdssvc_ctx);
	if (!ok) {
		DBG_ERR("backend init failed\n");
		TALLOC_FREE(mdssvc_ctx);
		return NULL;
	}
#endif

	return mdssvc_ctx;
}

/**
 * Init callbacks at startup
 *
 * This gets typically called in the main parent smbd which means we can't
 * initialize our global state here.
 **/
bool mds_init(struct messaging_context *msg_ctx)
{
	return true;
}

bool mds_shutdown(void)
{
	bool ok;

	if (mdssvc_ctx == NULL) {
		return false;
	}

	ok = mdsscv_backend_noindex.shutdown(mdssvc_ctx);
	if (!ok) {
		goto fail;
	}

#ifdef HAVE_SPOTLIGHT_BACKEND_ES
	ok = mdsscv_backend_es.shutdown(mdssvc_ctx);
	if (!ok) {
		goto fail;
	}
#endif

#ifdef HAVE_SPOTLIGHT_BACKEND_TRACKER
	ok = mdsscv_backend_tracker.shutdown(mdssvc_ctx);
	if (!ok) {
		goto fail;
	}
#endif

	ok = true;
fail:
	TALLOC_FREE(mdssvc_ctx);
	return ok;
}

/**
 * Tear down connections and free all resources
 **/
static int mds_ctx_destructor_cb(struct mds_ctx *mds_ctx)
{
	/*
	 * We need to free query_list before ino_path_map
	 */
	while (mds_ctx->query_list != NULL) {
		/*
		 * slq destructor removes element from list.
		 * Don't use TALLOC_FREE()!
		 */
		talloc_free(mds_ctx->query_list);
	}
	TALLOC_FREE(mds_ctx->ino_path_map);

	ZERO_STRUCTP(mds_ctx);

	return 0;
}

/**
 * Initialise a context per RPC bind
 *
 * This ends up being called for every tcon, because the client does a
 * RPC bind for every tcon, so this is acually a per tcon context.
 **/
struct mds_ctx *mds_init_ctx(TALLOC_CTX *mem_ctx,
			     struct tevent_context *ev,
			     struct messaging_context *msg_ctx,
			     struct auth_session_info *session_info,
			     int snum,
			     const char *sharename,
			     const char *path)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smb_filename conn_basedir;
	struct mds_ctx *mds_ctx;
	int backend;
	int ret;
	bool ok;
	smb_iconv_t iconv_hnd = (smb_iconv_t)-1;
	NTSTATUS status;

	mds_ctx = talloc_zero(mem_ctx, struct mds_ctx);
	if (mds_ctx == NULL) {
		return NULL;
	}
	talloc_set_destructor(mds_ctx, mds_ctx_destructor_cb);

	mds_ctx->mdssvc_ctx = mdssvc_init(ev);
	if (mds_ctx->mdssvc_ctx == NULL) {
		goto error;
	}

	backend = lp_spotlight_backend(snum);
	if (!lp_spotlight(snum)) {
		backend = SPOTLIGHT_BACKEND_NOINDEX;
	}
	switch (backend) {
	case SPOTLIGHT_BACKEND_NOINDEX:
		mds_ctx->backend = &mdsscv_backend_noindex;
		break;

#ifdef HAVE_SPOTLIGHT_BACKEND_ES
	case SPOTLIGHT_BACKEND_ES:
		mds_ctx->backend = &mdsscv_backend_es;
		break;
#endif

#ifdef HAVE_SPOTLIGHT_BACKEND_TRACKER
	case SPOTLIGHT_BACKEND_TRACKER:
		mds_ctx->backend = &mdsscv_backend_tracker;
		break;
#endif
	default:
		DBG_ERR("Unknown backend %d\n", backend);
		TALLOC_FREE(mdssvc_ctx);
		goto error;
	}

	iconv_hnd = smb_iconv_open_ex(mds_ctx,
						   "UTF8-NFD",
						   "UTF8-NFC",
						   false);
	if (iconv_hnd == (smb_iconv_t)-1) {
		goto error;
	}
	mds_ctx->ic_nfc_to_nfd = iconv_hnd;

	iconv_hnd = smb_iconv_open_ex(mds_ctx,
						   "UTF8-NFC",
						   "UTF8-NFD",
						   false);
	if (iconv_hnd == (smb_iconv_t)-1) {
		goto error;
	}
	mds_ctx->ic_nfd_to_nfc = iconv_hnd;

	mds_ctx->sharename = talloc_strdup(mds_ctx, sharename);
	if (mds_ctx->sharename == NULL) {
		goto error;
	}

	mds_ctx->spath = talloc_strdup(mds_ctx, path);
	if (mds_ctx->spath == NULL) {
		goto error;
	}

	mds_ctx->snum = snum;
	mds_ctx->pipe_session_info = session_info;

	if (session_info->security_token->num_sids < 1) {
		goto error;
	}
	sid_copy(&mds_ctx->sid, &session_info->security_token->sids[0]);
	mds_ctx->uid = session_info->unix_token->uid;

	mds_ctx->ino_path_map = db_open_rbt(mds_ctx);
	if (mds_ctx->ino_path_map == NULL) {
		DEBUG(1,("open inode map db failed\n"));
		goto error;
	}

	status = create_conn_struct_cwd(mds_ctx,
					ev,
					msg_ctx,
					session_info,
					snum,
					lp_path(talloc_tos(), lp_sub, snum),
					&mds_ctx->conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to create conn for vfs: %s\n",
			nt_errstr(status));
		goto error;
	}

	conn_basedir = (struct smb_filename) {
		.base_name = mds_ctx->conn->connectpath,
	};

	ret = vfs_ChDir(mds_ctx->conn, &conn_basedir);
	if (ret != 0) {
		DBG_ERR("vfs_ChDir [%s] failed: %s\n",
			conn_basedir.base_name, strerror(errno));
		goto error;
	}

	ok = mds_ctx->backend->connect(mds_ctx);
	if (!ok) {
		DBG_ERR("backend connect failed\n");
		goto error;
	}

	return mds_ctx;

error:
	if (mds_ctx->ic_nfc_to_nfd != NULL) {
		smb_iconv_close(mds_ctx->ic_nfc_to_nfd);
	}
	if (mds_ctx->ic_nfd_to_nfc != NULL) {
		smb_iconv_close(mds_ctx->ic_nfd_to_nfc);
	}

	TALLOC_FREE(mds_ctx);
	return NULL;
}

/**
 * Dispatch a Spotlight RPC command
 **/
bool mds_dispatch(struct mds_ctx *mds_ctx,
		  struct mdssvc_blob *request_blob,
		  struct mdssvc_blob *response_blob)
{
	bool ok;
	int ret;
	ssize_t len;
	DALLOC_CTX *query = NULL;
	DALLOC_CTX *reply = NULL;
	char *rpccmd;
	const struct slrpc_cmd *slcmd;
	const struct smb_filename conn_basedir = {
		.base_name = mds_ctx->conn->connectpath,
	};

	if (CHECK_DEBUGLVL(10)) {
		const struct sl_query *slq;

		for (slq = mds_ctx->query_list; slq != NULL; slq = slq->next) {
			SLQ_DEBUG(10, slq, "pending");
		}
	}

	response_blob->length = 0;

	DEBUG(10, ("share path: %s\n", mds_ctx->spath));

	query = dalloc_new(mds_ctx);
	if (query == NULL) {
		ok = false;
		goto cleanup;
	}
	reply = dalloc_new(mds_ctx);
	if (reply == NULL) {
		ok = false;
		goto cleanup;
	}

	ok = sl_unpack(query, (char *)request_blob->spotlight_blob,
		       request_blob->length);
	if (!ok) {
		DEBUG(1, ("error unpacking Spotlight RPC blob\n"));
		goto cleanup;
	}

	DEBUG(5, ("%s", dalloc_dump(query, 0)));

	rpccmd = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			    "char *", 0);
	if (rpccmd == NULL) {
		DEBUG(1, ("missing primary Spotlight RPC command\n"));
		ok = false;
		goto cleanup;
	}

	DEBUG(10, ("Spotlight RPC cmd: %s\n", rpccmd));

	slcmd = slrpc_cmd_by_name(rpccmd);
	if (slcmd == NULL) {
		DEBUG(1, ("unsupported primary Spotlight RPC command %s\n",
			  rpccmd));
		ok = false;
		goto cleanup;
	}

	ret = vfs_ChDir(mds_ctx->conn, &conn_basedir);
	if (ret != 0) {
		DBG_ERR("vfs_ChDir [%s] failed: %s\n",
			conn_basedir.base_name, strerror(errno));
		ok = false;
		goto cleanup;
	}

	ok = slcmd->function(mds_ctx, query, reply);
	if (ok) {
		DBG_DEBUG("%s", dalloc_dump(reply, 0));

		len = sl_pack(reply,
			      (char *)response_blob->spotlight_blob,
			      response_blob->size);
		if (len == -1) {
			DBG_ERR("error packing Spotlight RPC reply\n");
			ok = false;
			goto cleanup;
		}
		response_blob->length = len;
	}

cleanup:
	talloc_free(query);
	talloc_free(reply);
	return ok;
}
