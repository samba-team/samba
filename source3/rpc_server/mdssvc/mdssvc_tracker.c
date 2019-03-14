/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines / Tracker backend

   Copyright (C) Ralph Boehme 2019

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
#include "lib/util/time_basic.h"
#include "mdssvc.h"
#include "mdssvc_tracker.h"
#include "lib/tevent_glib_glue.h"
#include "rpc_server/mdssvc/sparql_parser.tab.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static struct mdssvc_tracker_ctx *mdssvc_tracker_ctx;

/************************************************
 * Tracker async callbacks
 ************************************************/

static void tracker_con_cb(GObject *object,
			   GAsyncResult *res,
			   gpointer user_data)
{
	struct mds_tracker_ctx *ctx = NULL;
	TrackerSparqlConnection *tracker_con = NULL;
	GError *error = NULL;

	tracker_con = tracker_sparql_connection_get_finish(res, &error);
	if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		/*
		 * If the async request was cancelled, user_data will already be
		 * talloc_free'd, so we must be carefully checking for
		 * G_IO_ERROR_CANCELLED before using user_data.
		 */
		DBG_ERR("Tracker connection cancelled\n");
		g_error_free(error);
		return;
	}
	/*
	 * Ok, we're not canclled, we can now safely use user_data.
	 */
	ctx = talloc_get_type_abort(user_data, struct mds_tracker_ctx);
	ctx->async_pending = false;
	/*
	 * Check error again, above we only checked for G_IO_ERROR_CANCELLED.
	 */
	if (error) {
		DBG_ERR("Could not connect to Tracker: %s\n", error->message);
		g_error_free(error);
		return;
	}

	ctx->tracker_con = tracker_con;

	DBG_DEBUG("connected to Tracker\n");
}

static void tracker_cursor_cb(GObject *object,
			      GAsyncResult *res,
			      gpointer user_data);

static void tracker_query_cb(GObject *object,
			     GAsyncResult *res,
			     gpointer user_data)
{
	struct sl_tracker_query *tq = NULL;
	struct sl_query *slq = NULL;
	TrackerSparqlConnection *conn = NULL;
	TrackerSparqlCursor *cursor = NULL;
	GError *error = NULL;

	conn = TRACKER_SPARQL_CONNECTION(object);

	cursor = tracker_sparql_connection_query_finish(conn, res, &error);
	/*
	 * If the async request was cancelled, user_data will already be
	 * talloc_free'd, so we must be carefully checking for
	 * G_IO_ERROR_CANCELLED before using user_data.
	 */
	if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		DBG_ERR("Tracker query cancelled\n");
		if (cursor != NULL) {
			g_object_unref(cursor);
		}
		g_error_free(error);
		return;
	}
	/*
	 * Ok, we're not cancelled, we can now safely use user_data.
	 */
	tq = talloc_get_type_abort(user_data, struct sl_tracker_query);
	tq->async_pending = false;
	slq = tq->slq;
	/*
	 * Check error again, above we only checked for G_IO_ERROR_CANCELLED.
	 */
	if (error) {
		DBG_ERR("Tracker query error: %s\n", error->message);
		g_error_free(error);
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	tq->cursor = cursor;
	slq->state = SLQ_STATE_RESULTS;

	tracker_sparql_cursor_next_async(tq->cursor,
					 tq->gcancellable,
					 tracker_cursor_cb,
					 tq);
	tq->async_pending = true;
}

static char *tracker_to_unix_path(TALLOC_CTX *mem_ctx, const char *uri)
{
	GFile *f = NULL;
	char *path = NULL;
	char *talloc_path = NULL;

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

static void tracker_cursor_cb(GObject *object,
			      GAsyncResult *res,
			      gpointer user_data)
{
	TrackerSparqlCursor *cursor = NULL;
	struct sl_tracker_query *tq = NULL;
	struct sl_query *slq = NULL;
	const gchar *uri = NULL;
	GError *error = NULL;
	char *path = NULL;
	gboolean more_results;
	bool ok;

	cursor = TRACKER_SPARQL_CURSOR(object);
	more_results = tracker_sparql_cursor_next_finish(cursor,
							 res,
							 &error);
	/*
	 * If the async request was cancelled, user_data will already be
	 * talloc_free'd, so we must be carefully checking for
	 * G_IO_ERROR_CANCELLED before using user_data.
	 */
	if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free(error);
		g_object_unref(cursor);
		return;
	}
	/*
	 * Ok, we're not canclled, we can now safely use user_data.
	 */
	tq = talloc_get_type_abort(user_data, struct sl_tracker_query);
	tq->async_pending = false;
	slq = tq->slq;
	/*
	 * Check error again, above we only checked for G_IO_ERROR_CANCELLED.
	 */
	if (error) {
		DBG_ERR("Tracker cursor: %s\n", error->message);
		g_error_free(error);
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	SLQ_DEBUG(10, slq, "results");

	if (!more_results) {
		slq->state = SLQ_STATE_DONE;

		g_object_unref(tq->cursor);
		tq->cursor = NULL;

		g_object_unref(tq->gcancellable);
		tq->gcancellable = NULL;
		return;
	}

	uri = tracker_sparql_cursor_get_string(tq->cursor, 0, NULL);
	if (uri == NULL) {
		DBG_ERR("error fetching Tracker URI\n");
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	path = tracker_to_unix_path(slq->query_results, uri);
	if (path == NULL) {
		DBG_ERR("error converting Tracker URI to path: %s\n", uri);
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	ok = mds_add_result(slq, path);
	if (!ok) {
		DBG_ERR("error adding result for path: %s\n", uri);
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	if (slq->query_results->num_results >= MAX_SL_RESULTS) {
		slq->state = SLQ_STATE_FULL;
		SLQ_DEBUG(10, slq, "full");
		return;
	}

	slq->state = SLQ_STATE_RESULTS;
	SLQ_DEBUG(10, slq, "cursor next");

	tracker_sparql_cursor_next_async(tq->cursor,
					 tq->gcancellable,
					 tracker_cursor_cb,
					 tq);
	tq->async_pending = true;
}

/*
 * This gets called once, even if the backend is not configured by the user
 */
static bool mdssvc_tracker_init(struct mdssvc_ctx *mdssvc_ctx)
{
	if (mdssvc_tracker_ctx != NULL) {
		return true;
	}

#if (GLIB_MAJOR_VERSION < 3) && (GLIB_MINOR_VERSION < 36)
	g_type_init();
#endif

	mdssvc_tracker_ctx = talloc_zero(mdssvc_ctx, struct mdssvc_tracker_ctx);
	if (mdssvc_tracker_ctx == NULL) {
		return false;
	}
	mdssvc_tracker_ctx->mdssvc_ctx = mdssvc_ctx;

	return true;
}

/*
 * This gets called per mdscmd_open / tcon. This runs initialisation code that
 * should only run if the tracker backend is actually used.
 */
static bool mdssvc_tracker_prepare(void)
{
	if (mdssvc_tracker_ctx->gmain_ctx != NULL) {
		/*
		 * Assuming everything is setup if gmain_ctx is.
		 */
		return true;
	}

	mdssvc_tracker_ctx->gmain_ctx = g_main_context_new();
	if (mdssvc_tracker_ctx->gmain_ctx == NULL) {
		DBG_ERR("error from g_main_context_new\n");
		TALLOC_FREE(mdssvc_tracker_ctx);
		return false;
	}

	mdssvc_tracker_ctx->glue = samba_tevent_glib_glue_create(
		mdssvc_tracker_ctx,
		mdssvc_tracker_ctx->mdssvc_ctx->ev_ctx,
		mdssvc_tracker_ctx->gmain_ctx);
	if (mdssvc_tracker_ctx->glue == NULL) {
		DBG_ERR("samba_tevent_glib_glue_create failed\n");
		g_object_unref(mdssvc_tracker_ctx->gmain_ctx);
		TALLOC_FREE(mdssvc_tracker_ctx);
		return false;
	}

	return true;
}

static bool mdssvc_tracker_shutdown(struct mdssvc_ctx *mdssvc_ctx)
{
	samba_tevent_glib_glue_quit(mdssvc_tracker_ctx->glue);
	TALLOC_FREE(mdssvc_tracker_ctx->glue);

	g_object_unref(mdssvc_tracker_ctx->gmain_ctx);
	return true;
}

static int mds_tracker_ctx_destructor(struct mds_tracker_ctx *ctx)
{
	/*
	 * Don't g_object_unref() the connection if there's an async request
	 * pending, it's used in the async callback and will be unreferenced
	 * there.
	 */
	if (ctx->async_pending) {
		g_cancellable_cancel(ctx->gcancellable);
		ctx->gcancellable = NULL;
		return 0;
	}

	if (ctx->tracker_con == NULL) {
		return 0;
	}
	g_object_unref(ctx->tracker_con);
	ctx->tracker_con = NULL;

	return 0;
}

static bool mds_tracker_connect(struct mds_ctx *mds_ctx)
{
	struct mds_tracker_ctx *ctx = NULL;
	bool ok;

	ok = mdssvc_tracker_prepare();
	if (!ok) {
		return false;
	}

	ctx = talloc_zero(mds_ctx, struct mds_tracker_ctx);
	if (ctx == NULL) {
		return false;
	}
	talloc_set_destructor(ctx, mds_tracker_ctx_destructor);

	ctx->mds_ctx = mds_ctx;

	ctx->gcancellable = g_cancellable_new();
	if (ctx->gcancellable == NULL) {
		DBG_ERR("error from g_cancellable_new\n");
		TALLOC_FREE(ctx);
		return false;
	}

	tracker_sparql_connection_get_async(ctx->gcancellable,
					    tracker_con_cb,
					    ctx);
	ctx->async_pending = true;

	mds_ctx->backend_private = ctx;

	return true;
}

static int tq_destructor(struct sl_tracker_query *tq)
{
	/*
	 * Don't g_object_unref() the cursor if there's an async request
	 * pending, it's used in the async callback and will be unreferenced
	 * there.
	 */
	if (tq->async_pending) {
		g_cancellable_cancel(tq->gcancellable);
		tq->gcancellable = NULL;
		return 0;
	}

	if (tq->cursor == NULL) {
		return 0;
	}
	g_object_unref(tq->cursor);
	tq->cursor = NULL;
	return 0;
}

static bool mds_tracker_search_start(struct sl_query *slq)
{
	struct mds_tracker_ctx *tmds_ctx = talloc_get_type_abort(
		slq->mds_ctx->backend_private, struct mds_tracker_ctx);
	struct sl_tracker_query *tq = NULL;
	char *escaped_scope = NULL;
	bool ok;

	if (tmds_ctx->tracker_con == NULL) {
		DBG_ERR("no connection to Tracker\n");
		return false;
	}

	tq = talloc_zero(slq, struct sl_tracker_query);
	if (tq == NULL) {
		return false;
	}
	tq->slq = slq;
	talloc_set_destructor(tq, tq_destructor);

	tq->gcancellable = g_cancellable_new();
	if (tq->gcancellable == NULL) {
		DBG_ERR("g_cancellable_new() failed\n");
		goto error;
	}

	escaped_scope = g_uri_escape_string(
				slq->path_scope,
				G_URI_RESERVED_CHARS_ALLOWED_IN_PATH,
				TRUE);
	if (escaped_scope == NULL) {
		goto error;
	}

	tq->path_scope = talloc_strdup(tq, escaped_scope);
	g_free(escaped_scope);
	escaped_scope = NULL;
	if (tq->path_scope == NULL) {
		goto error;
	}

	slq->backend_private = tq;

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
		goto error;
	}

	DBG_DEBUG("SPARQL query: \"%s\"\n", tq->sparql_query);

	tracker_sparql_connection_query_async(tmds_ctx->tracker_con,
					      tq->sparql_query,
					      tq->gcancellable,
					      tracker_query_cb,
					      tq);
	tq->async_pending = true;

	slq->state = SLQ_STATE_RUNNING;
	return true;
error:
	g_object_unref(tq->gcancellable);
	TALLOC_FREE(tq);
	slq->backend_private = NULL;
	return false;
}

static bool mds_tracker_search_cont(struct sl_query *slq)
{
	struct sl_tracker_query *tq = talloc_get_type_abort(
		slq->backend_private, struct sl_tracker_query);

	tracker_sparql_cursor_next_async(tq->cursor,
					 tq->gcancellable,
					 tracker_cursor_cb,
					 tq);
	tq->async_pending = true;

	return true;
}

struct mdssvc_backend mdsscv_backend_tracker = {
	.init = mdssvc_tracker_init,
	.shutdown = mdssvc_tracker_shutdown,
	.connect = mds_tracker_connect,
	.search_start = mds_tracker_search_start,
	.search_cont = mds_tracker_search_cont,
};
