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

/* allow building with --enable-developer */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#include <gio/gio.h>
#include <tracker-sparql.h>
#pragma GCC diagnostic pop

/* Global */
struct mdssvc_tracker_ctx {
	struct mdssvc_ctx *mdssvc_ctx;
	GMainContext *gmain_ctx;
	struct tevent_glib_glue *glue;
};

/* Per tree connect state */
struct mds_tracker_ctx {
	struct mds_ctx *mds_ctx;
	GCancellable *gcancellable;
	bool async_pending;
	TrackerSparqlConnection *tracker_con;
};

/* Per query */
struct sl_tracker_query {
	struct sl_query *slq;
	const char *path_scope;
	const char *sparql_query;

	/*
	 * Notes on the lifetime of cursor: we hold a reference on the object
	 * and have to call g_object_unref(cursor) at the right place. This is
	 * either done in the talloc destructor on a struct sl_tracker_query
	 * talloc object when there are no tracker glib async requests
	 * running. Or in the glib callback after cancelling the glib async
	 * request.
	 */
	TrackerSparqlCursor *cursor;
	GCancellable *gcancellable;
	bool async_pending;
};

extern struct mdssvc_backend mdsscv_backend_tracker;
