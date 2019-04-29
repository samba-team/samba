/*
 * Copyright (C) 2011, Nokia <ivan.frade@nokia.com>
 * Copyright (C) 2015, Noel Power <nopower@suse.com>
 * Copyright (C) 2016, Ralph Boehme <slow@samba.org.>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.          See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include "includes.h"
#include "lib/util/debug.h"
#include "popt_common.h"
#include "param.h"
/*
 * glib uses TRUE and FALSE which was redefined by "includes.h" to be
 * unusable, undefine so glib can establish its own working
 * replacement.
 */
#undef TRUE
#undef FALSE
#include <glib.h>
#include <libtracker-sparql/tracker-sparql.h>
#include "lib/tevent_glib_glue.h"

enum loop_type {TEVENT_LOOP, GLIB_LOOP};

struct test_state {
	enum loop_type loop_type;
	TrackerSparqlConnection *connection;
	GCancellable *cancellable;
	GTimer *timer;
	GMainLoop *loop;
	struct tevent_context *ev;
	struct tevent_glib_glue *glue;
};

static void cleanup(struct test_state *state)
{
	g_cancellable_cancel(state->cancellable);
	g_object_unref(state->cancellable);
	g_timer_destroy(state->timer);
	if (state->connection != NULL) {
		g_object_unref(state->connection);
		state->connection = NULL;
	}
	if (state->loop_type == GLIB_LOOP) {
		g_main_loop_quit(state->loop);
	} else {
		samba_tevent_glib_glue_quit(state->glue);
	}
}

static void cursor_cb(GObject      *object,
		      GAsyncResult *res,
		      gpointer      user_data)
{
	struct test_state *state = talloc_get_type_abort(
		user_data, struct test_state);
	TrackerSparqlCursor *cursor = NULL;
	GError *error = NULL;
	gboolean more_results;
	static gint i = 0;

	cursor = TRACKER_SPARQL_CURSOR(object);
	more_results = tracker_sparql_cursor_next_finish(cursor,
							 res,
							 &error);
	if (error) {
		g_critical("Could not run cursor next: %s", error->message);

		if (cursor != NULL) {
			g_object_unref(cursor);
		}

		g_error_free(error);
		cleanup(state);
		return;
	}

	if (!more_results) {
		g_print("\n");
		g_print("\nAsync cursor next took: %.6f (for all %d results)\n",
			g_timer_elapsed (state->timer, NULL), i);

		g_object_unref(cursor);
		cleanup(state);
		return;
	}

	if (i++ < 5) {
		int num_cols = tracker_sparql_cursor_get_n_columns(cursor);
		int col;

		if (i == 1) {
			g_print("Printing first 5 results:\n");
		}
		for (col = 0; col < num_cols; col++) {
			g_print(" %s ", tracker_sparql_cursor_get_string(
					cursor, col, NULL));
			if (col == num_cols -1 ) {
				g_print("\n");
			}
		}

		if (i == 5) {
			g_print("  ...\n");
			g_print("  Printing nothing for remaining results\n");
		}
	}

	tracker_sparql_cursor_next_async(cursor,
					 state->cancellable,
					 cursor_cb,
					 state);
}

static void query_cb(GObject      *object,
		     GAsyncResult *res,
		     gpointer      user_data)
{
	struct test_state *state = talloc_get_type_abort(
		user_data, struct test_state);
	TrackerSparqlCursor *cursor = NULL;
	GError *error = NULL;

	g_print("Async query took: %.6f\n", g_timer_elapsed(state->timer, NULL));

	cursor = tracker_sparql_connection_query_finish(
			TRACKER_SPARQL_CONNECTION(object),
			res,
			&error);
	if (error) {
		g_critical("Could not run query: %s", error->message);

		if (cursor) {
			g_object_unref(cursor);
		}

		g_error_free(error);
		cleanup(state);
		return;
	}

	g_timer_start(state->timer);

	tracker_sparql_cursor_next_async(cursor,
					 state->cancellable,
					 cursor_cb,
					 state);
}

static void connection_cb(GObject      *object,
			  GAsyncResult *res,
			  gpointer      user_data)
{
	struct test_state *state = talloc_get_type_abort(
		user_data, struct test_state);
	GError *error = NULL;

	g_print("Async connection took: %.6f\n",
		g_timer_elapsed(state->timer, NULL));

	state->connection = tracker_sparql_connection_get_finish(res, &error);
	if (error) {
		g_critical("Could not connect: %s", error->message);
		g_error_free(error);
		cleanup(state);
		return;
	}

	g_timer_start(state->timer);

	tracker_sparql_connection_query_async(
		state->connection,
		"SELECT ?name nie:mimeType(?s) nfo:fileName(?s) "
		"WHERE { {?s nie:url ?name}}",
		state->cancellable,
		query_cb,
		state);
}

static void debug_fn(void *private_data,
		     enum tevent_debug_level level,
		     const char *fmt,
		     va_list ap)
{
	dbgtext_va(fmt, ap);
}

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct test_state *state = NULL;
	int c;
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName  = "tevent",
			.shortName = 't',
			.argInfo   = POPT_ARG_NONE,
			.val       = 'v',
			.descrip   = "Use tevent loop",
		},
		{
			.longName  = "glib",
			.shortName = 'g',
			.argInfo   = POPT_ARG_NONE,
			.val       = 'g',
			.descrip   = "Use glib loop",
		},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		exit(1);
	}

	state = talloc_zero(mem_ctx, struct test_state);
	if (state == NULL) {
		exit(1);
	}

	state->loop_type = TEVENT_LOOP;

	setup_logging(argv[0], DEBUG_STDERR);
	smb_init_locale();

	if (!lp_load_client(get_dyn_CONFIGFILE())) {
		fprintf(stderr, "ERROR: Can't load %s\n",
			get_dyn_CONFIGFILE());
		exit(1);
	}

	pc = poptGetContext(NULL, argc, argv, long_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while ((c = poptGetNextOpt(pc)) != -1) {
		switch (c) {
		case 'g':
			state->loop_type = GLIB_LOOP;
			break;
		case 't':
			state->loop_type = TEVENT_LOOP;
			break;
		}
	}

	if (state->loop_type == GLIB_LOOP) {
		state->loop = g_main_loop_new(NULL, false);
	} else {
		state->ev = tevent_context_init(mem_ctx);
		if (CHECK_DEBUGLVL(10)) {
			tevent_set_debug(state->ev, debug_fn, NULL);
		}
		state->glue = samba_tevent_glib_glue_create(
			mem_ctx, state->ev, g_main_context_default());
		if (state->glue == NULL) {
			printf("tevent_glib_glue_create failed\n");
			exit(1);
		}
	}

	state->timer = g_timer_new();
	state->cancellable = g_cancellable_new();

	tracker_sparql_connection_get_async(state->cancellable,
	                                    connection_cb,
	                                    state);

	if (state->loop_type == GLIB_LOOP) {
		printf("entering g_main_loop_run\n");
		g_main_loop_run(state->loop);
	} else {
		printf("entering tevent_loop_wait\n");
		tevent_loop_wait(state->ev);

		TALLOC_FREE(state->glue);
		TALLOC_FREE(state->ev);
	}

	TALLOC_FREE(mem_ctx);
	poptFreeContext(pc);

	return 0;
}
