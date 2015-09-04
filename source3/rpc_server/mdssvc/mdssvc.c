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
#include "librpc/gen_ndr/auth.h"
#include "dbwrap/dbwrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/util_tdb.h"
#include "lib/util/time_basic.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "libcli/security/dom_sid.h"
#include "mdssvc.h"
#include "sparql_parser.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define SLQ_DEBUG(lvl, _slq, state) do { if (CHECK_DEBUGLVL(lvl)) {	\
	const struct sl_query *__slq = _slq;				\
	struct timeval_buf start_buf;					\
	const char *start;						\
	struct timeval_buf last_used_buf;				\
	const char *last_used;						\
	struct timeval_buf expire_buf;					\
	const char *expire;						\
	start = timeval_str_buf(&__slq->start_time, false,		\
				true, &start_buf);			\
	last_used = timeval_str_buf(&__slq->last_used, false,		\
				    true, &last_used_buf);		\
	expire = timeval_str_buf(&__slq->expire_time, false,		\
				 true, &expire_buf);			\
	DEBUG(lvl,("%s slq[0x%jx,0x%jx], start: %s, last_used: %s, "	\
		   "expires: %s, query: '%s'\n", state,			\
		   (uintmax_t)__slq->ctx1, (uintmax_t)__slq->ctx2,	\
		   start, last_used, expire, __slq->query_string));	\
}} while(0)

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
 * If these functions return an error, they hit something like a non
 * recoverable talloc error. Most errors are dealt with by returning
 * an errror code in the Spotlight RPC reply.
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

static struct tevent_req *slq_destroy_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct sl_query **slq)
{
	struct tevent_req *req;
	struct slq_destroy_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct slq_destroy_state);
	if (req == NULL) {
		return NULL;
	}
	state->slq = talloc_move(state, slq);
	tevent_req_done(req);

	return tevent_req_post(req, ev);
}

static void slq_destroy_recv(struct tevent_req *req)
{
	tevent_req_received(req);
}

/************************************************
 * Misc utility functions
 ************************************************/

static char *tab_level(TALLOC_CTX *mem_ctx, int level)
{
	int i;
	char *string = talloc_array(mem_ctx, char, level + 1);

	for (i = 0; i < level; i++) {
		string[i] = '\t';
	}

	string[i] = '\0';
	return string;
}

char *mds_dalloc_dump(DALLOC_CTX *dd, int nestinglevel)
{
	const char *type;
	int n, result;
	uint64_t i;
	sl_bool_t bl;
	sl_time_t t;
	struct tm *tm;
	char datestring[256];
	sl_cnids_t cnids;
	char *logstring, *nested_logstring;
	char *tab_string1, *tab_string2;
	void *p;
	bool ok;
	char *utf8string;
	size_t utf8len;

	tab_string1 = tab_level(dd, nestinglevel);
	if (tab_string1 == NULL) {
		return NULL;
	}
	tab_string2 = tab_level(dd, nestinglevel + 1);
	if (tab_string2 == NULL) {
		return NULL;
	}

	logstring = talloc_asprintf(dd,
				    "%s%s(#%lu): {\n",
				    tab_string1,
				    talloc_get_name(dd),
				    dalloc_size(dd));
	if (logstring == NULL) {
		return NULL;
	}

	for (n = 0; n < dalloc_size(dd); n++) {
		type = dalloc_get_name(dd, n);
		if (type == NULL) {
			return NULL;
		}
		p = dalloc_get_object(dd, n);
		if (p == NULL) {
			return NULL;
		}
		if (strcmp(type, "DALLOC_CTX") == 0
		    || strcmp(type, "sl_array_t") == 0
		    || strcmp(type, "sl_filemeta_t") == 0
		    || strcmp(type, "sl_dict_t") == 0) {
			nested_logstring = mds_dalloc_dump(p, nestinglevel + 1);
			if (nested_logstring == NULL) {
				return NULL;
			}
			logstring = talloc_strdup_append(logstring,
							 nested_logstring);
		} else if (strcmp(type, "uint64_t") == 0) {
			memcpy(&i, p, sizeof(uint64_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%suint64_t: 0x%04jx\n",
				tab_string2, (uintmax_t)i);
		} else if (strcmp(type, "char *") == 0) {
			logstring = talloc_asprintf_append(
				logstring,
				"%sstring: %s\n",
				tab_string2,
				(char *)p);
		} else if (strcmp(type, "smb_ucs2_t *") == 0) {
			ok = convert_string_talloc(talloc_tos(),
						   CH_UTF16LE,
						   CH_UTF8,
						   p,
						   talloc_get_size(p),
						   &utf8string,
						   &utf8len);
			if (!ok) {
				return NULL;
			}
			logstring = talloc_asprintf_append(
				logstring,
				"%sUTF16-string: %s\n",
				tab_string2,
				utf8string);
			TALLOC_FREE(utf8string);
		} else if (strcmp(type, "sl_bool_t") == 0) {
			memcpy(&bl, p, sizeof(sl_bool_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%sbool: %s\n",
				tab_string2,
				bl ? "true" : "false");
		} else if (strcmp(type, "sl_nil_t") == 0) {
			logstring = talloc_asprintf_append(
				logstring,
				"%snil\n",
				tab_string2);
		} else if (strcmp(type, "sl_time_t") == 0) {
			memcpy(&t, p, sizeof(sl_time_t));
			tm = localtime(&t.tv_sec);
			if (tm == NULL) {
				return NULL;
			}
			result = strftime(datestring,
					 sizeof(datestring),
					 "%Y-%m-%d %H:%M:%S", tm);
			if (result == 0) {
				return NULL;
			}
			logstring = talloc_asprintf_append(
				logstring,
				"%ssl_time_t: %s.%06lu\n",
				tab_string2,
				datestring,
				(unsigned long)t.tv_usec);
		} else if (strcmp(type, "sl_cnids_t") == 0) {
			memcpy(&cnids, p, sizeof(sl_cnids_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%sCNIDs: unkn1: 0x%" PRIx16 ", unkn2: 0x%" PRIx32 "\n",
				tab_string2,
				cnids.ca_unkn1,
				cnids.ca_context);
			if (logstring == NULL) {
				return NULL;
			}
			if (cnids.ca_cnids) {
				nested_logstring = mds_dalloc_dump(
					cnids.ca_cnids,
					nestinglevel + 2);
				if (!nested_logstring) {
					return NULL;
				}
				logstring = talloc_strdup_append(logstring,
								 nested_logstring);
			}
		} else {
			logstring = talloc_asprintf_append(
				logstring,
				"%stype: %s\n",
				tab_string2,
				type);
		}
		if (logstring == NULL) {
			return NULL;
		}
	}
	logstring = talloc_asprintf_append(logstring,
					   "%s}\n",
					   tab_string1);
	if (logstring == NULL) {
		return NULL;
	}
	return logstring;
}

static char *tracker_to_unix_path(TALLOC_CTX *mem_ctx, const char *uri)
{
	GFile *f;
	char *path;
	char *talloc_path;

	f = g_file_new_for_uri(uri);
	if (f == NULL) {
		return NULL;
	}

	path = g_file_get_path(f);
	g_object_unref(f);

	if (path == NULL) {
		return NULL;
	}

	talloc_path = talloc_strdup(mem_ctx, path);
	g_free(path);
	if (talloc_path == NULL) {
		return NULL;
	}

	return talloc_path;
}

/**
 * Add requested metadata for a query result element
 *
 * This could be rewritten to something more sophisticated like
 * querying metadata from Tracker.
 *
 * If path or sp is NULL, simply add nil values for all attributes.
 **/
static bool add_filemeta(sl_array_t *reqinfo,
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

	for (i = 0; i < metacount; i++) {
		attribute = dalloc_get_object(reqinfo, i);
		if (attribute == NULL) {
			return false;
		}
		if (strcmp(attribute, "kMDItemDisplayName") == 0
		    || strcmp(attribute, "kMDItemFSName") == 0) {
			p = strrchr(path, '/');
			if (p) {
				result = dalloc_stradd(meta, p + 1);
				if (result != 0) {
					return false;
				}
			}
		} else if (strcmp(attribute, "kMDItemPath") == 0) {
			result = dalloc_stradd(meta, path);
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

	if (slq->tracker_cursor != NULL) {
		g_object_unref(slq->tracker_cursor);
		slq->tracker_cursor = NULL;
	}

	if (slq->gcancellable != NULL) {
		g_cancellable_cancel(slq->gcancellable);
		g_object_unref(slq->gcancellable);
		slq->gcancellable = NULL;
	}

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

	DEBUG(10,("deleted: %s\n", entry->path));
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

/************************************************
 * Tracker async callbacks
 ************************************************/

static void tracker_con_cb(GObject *object,
			   GAsyncResult *res,
			   gpointer user_data)
{
	struct mds_ctx *mds_ctx = talloc_get_type_abort(user_data, struct mds_ctx);
	GError *error = NULL;

	mds_ctx->tracker_con = tracker_sparql_connection_get_finish(res,
								    &error);
	if (error) {
		DEBUG(1, ("Could not connect to Tracker: %s\n",
			  error->message));
		g_error_free(error);
	}

	DEBUG(10, ("connected to Tracker\n"));
	g_main_loop_quit(mds_ctx->gmainloop);
}

static void tracker_cursor_cb_destroy_done(struct tevent_req *subreq);

static void tracker_cursor_cb(GObject *object,
			      GAsyncResult *res,
			      gpointer user_data)
{
	GError *error = NULL;
	struct sl_query *slq = talloc_get_type_abort(user_data, struct sl_query);
	gboolean more_results;
	const gchar *uri;
	char *path;
	int result;
	struct stat_ex sb;
	uint64_t ino64;
	bool ok;
	struct tevent_req *req;

	SLQ_DEBUG(10, slq, "tracker_cursor_cb");

	more_results = tracker_sparql_cursor_next_finish(slq->tracker_cursor,
							 res,
							 &error);

	if (slq->state == SLQ_STATE_DONE) {
		/*
		 * The query was closed in slrpc_close_query(), so we
		 * don't care for results or errors from
		 * tracker_sparql_cursor_next_finish(), we just go
		 * ahead and schedule deallocation of the slq handle.
		 *
		 * We have to shedule the deallocation via tevent,
		 * because we have to unref the cursor glib object and
		 * we can't do it here, because it's still used after
		 * we return.
		 */
		SLQ_DEBUG(10, slq, "closed");
		g_main_loop_quit(slq->mds_ctx->gmainloop);

		req = slq_destroy_send(slq, server_event_context(), &slq);
		if (req == NULL) {
			slq->state = SLQ_STATE_ERROR;
			return;
		}
		tevent_req_set_callback(req, tracker_cursor_cb_destroy_done, NULL);
		return;
	}

	if (error) {
		DEBUG(1, ("Tracker cursor: %s\n", error->message));
		g_error_free(error);
		slq->state = SLQ_STATE_ERROR;
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}

	if (!more_results) {
		slq->state = SLQ_STATE_DONE;
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}

	uri = tracker_sparql_cursor_get_string(slq->tracker_cursor, 0, NULL);
	if (uri == NULL) {
		DEBUG(1, ("error fetching Tracker URI\n"));
		slq->state = SLQ_STATE_ERROR;
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}
	path = tracker_to_unix_path(slq->query_results, uri);
	if (path == NULL) {
		DEBUG(1, ("error converting Tracker URI to path: %s\n", uri));
		slq->state = SLQ_STATE_ERROR;
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}

	if (geteuid() != slq->mds_ctx->uid) {
		DEBUG(0, ("uid mismatch: %d/%d\n", geteuid(), slq->mds_ctx->uid));
		smb_panic("uid mismatch");
	}

	result = sys_stat(path, &sb, false);
	if (result != 0) {
		goto done;
	}
	result = access(path, R_OK);
	if (result != 0) {
		goto done;
	}

	ino64 = sb.st_ex_ino;
	if (slq->cnids) {
		/*
		 * Check whether the found element is in the requested
		 * set of IDs. Note that we're faking CNIDs by using
		 * filesystem inode numbers here
		 */
		ok = bsearch(&ino64, slq->cnids, slq->cnids_num,
			     sizeof(uint64_t), cnid_comp_fn);
		if (!ok) {
			goto done;
		}
	}

	/*
	 * Add inode number and filemeta to result set, this is what
	 * we return as part of the result set of a query
	 */
	result = dalloc_add_copy(slq->query_results->cnids->ca_cnids,
				 &ino64, uint64_t);
	if (result != 0) {
		DEBUG(1, ("dalloc error\n"));
		slq->state = SLQ_STATE_ERROR;
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}
	ok = add_filemeta(slq->reqinfo, slq->query_results->fm_array,
			  path, &sb);
	if (!ok) {
		DEBUG(1, ("add_filemeta error\n"));
		slq->state = SLQ_STATE_ERROR;
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}

	ok = inode_map_add(slq, ino64, path);
	if (!ok) {
		DEBUG(1, ("inode_map_add error\n"));
		slq->state = SLQ_STATE_ERROR;
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}

	slq->query_results->num_results++;

done:
	if (slq->query_results->num_results >= MAX_SL_RESULTS) {
		slq->state = SLQ_STATE_FULL;
		SLQ_DEBUG(10, slq, "full");
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}

	slq->state = SLQ_STATE_RESULTS;
	SLQ_DEBUG(10, slq, "cursor next");
	tracker_sparql_cursor_next_async(slq->tracker_cursor,
					 slq->gcancellable,
					 tracker_cursor_cb,
					 slq);
}

static void tracker_cursor_cb_destroy_done(struct tevent_req *req)
{
	slq_destroy_recv(req);
	TALLOC_FREE(req);

	DEBUG(10, ("%s\n", __func__));
}

static void tracker_query_cb(GObject *object,
			     GAsyncResult *res,
			     gpointer user_data)
{
	GError *error = NULL;
	struct sl_query *slq = talloc_get_type_abort(user_data, struct sl_query);

	SLQ_DEBUG(10, slq, "tracker_query_cb");

	slq->tracker_cursor = tracker_sparql_connection_query_finish(
		TRACKER_SPARQL_CONNECTION(object),
		res,
		&error);
	if (error) {
		slq->state = SLQ_STATE_ERROR;
		DEBUG(1, ("Tracker query error: %s\n", error->message));
		g_error_free(error);
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		return;
	}

	if (slq->state == SLQ_STATE_DONE) {
		SLQ_DEBUG(10, slq, "done");
		g_main_loop_quit(slq->mds_ctx->gmainloop);
		talloc_free(slq);
		return;
	}

	slq->state = SLQ_STATE_RESULTS;

	tracker_sparql_cursor_next_async(slq->tracker_cursor,
					 slq->gcancellable,
					 tracker_cursor_cb,
					 slq);
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
	char *querystring;

	array = dalloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	if (mds_ctx->tracker_con == NULL) {
		DEBUG(1, ("no connection to Tracker\n"));
		goto error;
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
	slq->te = tevent_add_timer(server_event_context(), slq,
				   slq->expire_time, slq_close_timer, slq);
	if (slq->te == NULL) {
		DEBUG(1, ("tevent_add_timer failed\n"));
		goto error;
	}

	slq->gcancellable = g_cancellable_new();
	if (slq->gcancellable == NULL) {
		DEBUG(1,("error from g_cancellable_new\n"));
		goto error;
	}

	querystring = dalloc_value_for_key(query, "DALLOC_CTX", 0,
					   "DALLOC_CTX", 1,
					   "kMDQueryString");
	if (querystring == NULL) {
		DEBUG(1, ("missing kMDQueryString\n"));
		goto error;
	}
	slq->query_string = talloc_strdup(slq, querystring);
	if (slq->query_string == NULL) {
		DEBUG(1, ("out of memory\n"));
		goto error;
	}

	/*
	 * FIXME: convert spotlight query charset from decomposed UTF8
	 * to host charset precomposed UTF8.
	 */

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

	slq->path_scope = dalloc_get(path_scope, "char *", 0);
	if (slq->path_scope == NULL) {
		goto error;
	}

	slq->path_scope = talloc_strdup(slq, slq->path_scope);
	if (slq->path_scope == NULL) {
		goto error;
	}


	reqinfo = dalloc_value_for_key(query, "DALLOC_CTX", 0,
				       "DALLOC_CTX", 1, "kMDAttributeArray");
	if (reqinfo == NULL) {
		goto error;
	}

	slq->reqinfo = talloc_steal(slq, reqinfo);
	DEBUG(10, ("requested attributes: %s", mds_dalloc_dump(reqinfo, 0)));

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

	ok = map_spotlight_to_sparql_query(slq);
	if (!ok) {
		/*
		 * Two cases:
		 *
		 * 1) the query string is "false", the parser returns
		 * an error for that. We're supposed to return -1
		 * here.
		 *
		 * 2) the parsing really failed, in that case we're
		 * probably supposed to return -1 too, this needs
		 * verification though
		 */
		SLQ_DEBUG(10, slq, "map failed");
		goto error;
	}

	DEBUG(10, ("SPARQL query: \"%s\"\n", slq->sparql_query));

	g_main_context_push_thread_default(mds_ctx->gcontext);
	tracker_sparql_connection_query_async(mds_ctx->tracker_con,
					      slq->sparql_query,
					      slq->gcancellable,
					      tracker_query_cb,
					      slq);
	g_main_context_pop_thread_default(mds_ctx->gcontext);
	slq->state = SLQ_STATE_RUNNING;

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
	slq->te = tevent_add_timer(server_event_context(), slq,
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
			g_main_context_push_thread_default(mds_ctx->gcontext);
			tracker_sparql_cursor_next_async(
				slq->tracker_cursor,
				slq->gcancellable,
				tracker_cursor_cb,
				slq);
			g_main_context_pop_thread_default(mds_ctx->gcontext);
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
	struct stat_ex sb;
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
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to fetch inode: %s\n", nt_errstr(status)));
		goto error;
	}
	if (val.dsize != sizeof(p)) {
		DEBUG(1, ("invalid record pointer size: %zd\n", val.dsize));
		TALLOC_FREE(val.dptr);
		goto error;
	}

	memcpy(&p, val.dptr, sizeof(p));
	elem = talloc_get_type_abort(p, struct sl_inode_path_map);

	result = sys_stat(elem->path, &sb, false);
	if (result != 0) {
		goto error;
	}

	ok = add_filemeta(reqinfo, fm_array, elem->path, &sb);
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

	return true;

error:
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

	switch (slq->state) {
	case SLQ_STATE_RUNNING:
	case SLQ_STATE_RESULTS:
		DEBUG(10, ("close: requesting query close\n"));
		/*
		 * Mark the query is done so the cursor callback can
		 * act accordingly by stopping to request more results
		 * and sheduling query resource deallocation via
		 * tevent.
		 */
		slq->state = SLQ_STATE_DONE;
		break;

	case SLQ_STATE_FULL:
	case SLQ_STATE_DONE:
		DEBUG(10, ("close: query was done or result queue was full\n"));
		/*
		 * We can directly deallocate the query because there
		 * are no pending Tracker async calls in flight in
		 * these query states.
		 */
		TALLOC_FREE(slq);
		break;

	default:
		DEBUG(1, ("close: unexpected state: %d\n", slq->state));
		break;
	}


done:
	sl_res = 0;
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

/**
 * Init callbacks at startup, nothing to do here really
 **/
bool mds_init(struct messaging_context *msg_ctx)
{
	return true;
}

bool mds_shutdown(void)
{
	return true;
}

static gboolean gmainloop_timer(gpointer user_data)
{
	struct mds_ctx *ctx = talloc_get_type_abort(user_data, struct mds_ctx);

	DEBUG(10,("%s\n", __func__));
	g_main_loop_quit(ctx->gmainloop);

	return G_SOURCE_CONTINUE;
}

/**
 * Initialise a context per share handle
 **/
struct mds_ctx *mds_init_ctx(TALLOC_CTX *mem_ctx,
			     const struct auth_session_info *session_info,
			     const char *path)
{
	struct mds_ctx *mds_ctx;

	mds_ctx = talloc_zero(mem_ctx, struct mds_ctx);
	if (mds_ctx == NULL) {
		return NULL;
	}
	talloc_set_destructor(mds_ctx, mds_ctx_destructor_cb);

	mds_ctx->spath = talloc_strdup(mds_ctx, path);
	if (mds_ctx->spath == NULL) {
		goto error;
	}

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

	mds_ctx->gcontext = g_main_context_new();
	if (mds_ctx->gcontext == NULL) {
		DEBUG(1,("error from g_main_context_new\n"));
		goto error;
	}

	mds_ctx->gmainloop = g_main_loop_new(mds_ctx->gcontext, false);
	if (mds_ctx->gmainloop == NULL) {
		DEBUG(1,("error from g_main_loop_new\n"));
		goto error;
	}

	g_main_context_push_thread_default(mds_ctx->gcontext);
	tracker_sparql_connection_get_async(mds_ctx->gcancellable,
					    tracker_con_cb, mds_ctx);
	g_main_context_pop_thread_default(mds_ctx->gcontext);

	return mds_ctx;

error:
	TALLOC_FREE(mds_ctx);
	return NULL;
}

/**
 * Tear down connections and free all resources
 **/
int mds_ctx_destructor_cb(struct mds_ctx *mds_ctx)
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

	if (mds_ctx->tracker_con != NULL) {
		g_object_unref(mds_ctx->tracker_con);
	}
	if (mds_ctx->gcancellable != NULL) {
		g_cancellable_cancel(mds_ctx->gcancellable);
		g_object_unref(mds_ctx->gcancellable);
	}
	if (mds_ctx->gmainloop != NULL) {
		g_main_loop_unref(mds_ctx->gmainloop);
	}
	if (mds_ctx->gcontext != NULL) {
		g_main_context_unref(mds_ctx->gcontext);
	}

	ZERO_STRUCTP(mds_ctx);

	return 0;
}

static bool mds_run_gmainloop(struct mds_ctx *mds_ctx, guint timeout)
{
	guint timer_id;
	GSource *timer;

	/*
	 * It seems the event processing of the libtracker-sparql
	 * async subsystem defers callbacks until *all* events are
	 * processes by the async subsystem main processing loop.
	 *
	 * g_main_context_iteration(may_block=FALSE) can't be used,
	 * because a search that produces a few thousand matches
	 * generates as many events that must be processed in either
	 * g_main_context_iteration() or g_main_loop_run() before
	 * callbacks are called.
	 *
	 * Unfortunately g_main_context_iteration() only processes a
	 * small subset of these event (1-30) at a time when run in
	 * mds_dispatch(), which happens once a second while the
	 * client polls for results.
	 *
	 * Carefully using the blocking g_main_loop_run() fixes
	 * this. It processes events until we exit from the loop at
	 * defined exit points. By adding a 1 ms timeout we at least
	 * try to get as close as possible to non-blocking behaviour.
	 */

	if (!g_main_context_pending(mds_ctx->gcontext)) {
		return true;
	}

	g_main_context_push_thread_default(mds_ctx->gcontext);

	timer = g_timeout_source_new(timeout);
	if (timer == NULL) {
		DEBUG(1,("g_timeout_source_new_seconds\n"));
		g_main_context_pop_thread_default(mds_ctx->gcontext);
		return false;
	}

	timer_id = g_source_attach(timer, mds_ctx->gcontext);
	if (timer_id == 0) {
		DEBUG(1,("g_timeout_add failed\n"));
		g_source_destroy(timer);
		g_main_context_pop_thread_default(mds_ctx->gcontext);
		return false;
	}

	g_source_set_callback(timer, gmainloop_timer, mds_ctx, NULL);

	g_main_loop_run(mds_ctx->gmainloop);

	g_source_destroy(timer);

	g_main_context_pop_thread_default(mds_ctx->gcontext);
	return true;
}

/**
 * Dispatch a Spotlight RPC command
 **/
bool mds_dispatch(struct mds_ctx *mds_ctx,
		  struct mdssvc_blob *request_blob,
		  struct mdssvc_blob *response_blob)
{
	bool ok;
	ssize_t len;
	DALLOC_CTX *query = NULL;
	DALLOC_CTX *reply = NULL;
	char *rpccmd;
	const struct slrpc_cmd *slcmd;

	if (CHECK_DEBUGLVL(10)) {
		const struct sl_query *slq;

		for (slq = mds_ctx->query_list; slq != NULL; slq = slq->next) {
			SLQ_DEBUG(10, slq, "pending");
		}
	}

	response_blob->length = 0;

	/*
	 * Process finished glib events.
	 *
	 * FIXME: integrate with tevent instead of piggy packing it
	 * onto the processing of new requests.
	 *
	 * mds_dispatch() is called by the client a few times in a row:
	 *
	 * - first in order to open/start a search query
	 *
	 * - later in order to fetch results asynchronously, typically
	 *   once a second. If no results have been retrieved from the
	 *   search store (Tracker) yet, we return no results.
	 *   The client asks for more results every second as long
	 *   as the "Search Window" in the client gui is open.
	 *
	 * - at some point the query is closed
	 *
	 * This means we try to iterate through the glib event loop
	 * before processing the request in order to get result
	 * from tracker which can be returned to the client.
	 */

	ok = mds_run_gmainloop(mds_ctx, MDS_TRACKER_ASYNC_TIMEOUT_MS);
	if (!ok) {
		goto cleanup;
	}

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

	DEBUG(5, ("%s", mds_dalloc_dump(query, 0)));

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

	/*
	 * If these functions return an error, they hit something like
	 * a non recoverable talloc error
	 */
	ok = slcmd->function(mds_ctx, query, reply);
	if (!ok) {
		DEBUG(1, ("error in Spotlight RPC handler\n"));
		goto cleanup;
	}

	DEBUG(5, ("%s", mds_dalloc_dump(reply, 0)));

	len = sl_pack(reply, (char *)response_blob->spotlight_blob,
		      response_blob->size);
	if (len == -1) {
		DEBUG(1, ("error packing Spotlight RPC reply\n"));
		ok = false;
		goto cleanup;
	}

	/*
	 * Run g_main_loop a second time in order to dispatch events
	 * that may have been queued at the libtracker-sparql level.
	 * As we only want to dispatch (write out requests) but not
	 * wait for anything, we use a much shorter timeout here.
	 */
	ok = mds_run_gmainloop(mds_ctx, MDS_TRACKER_ASYNC_TIMEOUT_MS / 10);
	if (!ok) {
		goto cleanup;
	}

	response_blob->length = len;

cleanup:
	talloc_free(query);
	talloc_free(reply);
	return ok;
}
