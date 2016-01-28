/*
   Unix SMB/CIFS implementation.

   testing of the tevent glib glue subsystem

   Copyright (C) Ralph Boehme      2016

   glib tests adapted from glib2 glib/tests/mainloop.c
   Copyright (C) 2011 Red Hat Inc., Matthias Clasen

     ** NOTE! The following LGPL license applies to the tevent
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

#include "replace.h"

/*
 * glib uses TRUE and FALSE which may have redefined by "includes.h" to be
 * unusable. Unndefine so glib can establish its own working replacement.
 */
#undef TRUE
#undef FALSE
#include <glib.h>
#include <glib-unix.h>
#include "lib/tevent_glib_glue.h"

/*
 * Unfortunately the glib test suite runner doesn't pass args to tests
 * so we must keep a few globals here.
 */
static struct tevent_context *ev;

static gboolean count_calls(gpointer data)
{
	gint *i = (gint *)data;

	(*i)++;

	return TRUE;
}

static gboolean quit_loop(gpointer data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		data, struct tevent_glib_glue);

	samba_tevent_glib_glue_quit(glue);

	return G_SOURCE_REMOVE;
}

static void test_timeouts(void)
{
	GMainContext *ctx = NULL;
	struct tevent_glib_glue *glue = NULL;
	GSource *source = NULL;
	gint a;
	gint b;
	gint c;

	a = b = c = 0;

	ctx = g_main_context_new();
	glue = samba_tevent_glib_glue_create(ev, ev, ctx);
	g_assert(glue != NULL);

	source = g_timeout_source_new(100);
	g_source_set_callback(source, count_calls, &a, NULL);
	g_source_attach(source, ctx);
	g_source_unref(source);

	source = g_timeout_source_new(250);
	g_source_set_callback(source, count_calls, &b, NULL);
	g_source_attach(source, ctx);
	g_source_unref(source);

	source = g_timeout_source_new(330);
	g_source_set_callback(source, count_calls, &c, NULL);
	g_source_attach(source, ctx);
	g_source_unref(source);

	source = g_timeout_source_new(1050);
	g_source_set_callback(source, quit_loop, glue, NULL);
	g_source_attach(source, ctx);
	g_source_unref(source);

	g_assert(tevent_loop_wait(ev) == 0);

	/* We may be delayed for an arbitrary amount of time - for example,
	 * it's possible for all timeouts to fire exactly once.
	 */
	g_assert_cmpint(a, >, 0);
	g_assert_cmpint(a, >=, b);
	g_assert_cmpint(b, >=, c);

	g_assert_cmpint(a, <=, 10);
	g_assert_cmpint(b, <=, 4);
	g_assert_cmpint(c, <=, 3);

	samba_tevent_glib_glue_quit(glue);
	TALLOC_FREE(glue);
	g_main_context_unref(ctx);
}

struct test_glib_ev_source_data {
	GMainContext *ctx;
	struct tevent_glib_glue *glue;
};

static gboolean test_glib_ev_source_quit_loop(gpointer data);

static gboolean test_glib_ev_source_timeout_cb(gpointer data)
{
	struct test_glib_ev_source_data *state = talloc_get_type_abort(
		data, struct test_glib_ev_source_data);
	GSource *source = NULL;

	source = g_timeout_source_new(100);
	g_source_set_callback(source,
			      test_glib_ev_source_quit_loop,
			      state,
			      NULL);
	g_source_attach(source, state->ctx);
	g_source_unref(source);

	return TRUE;
}

static gboolean test_glib_ev_source_quit_loop(gpointer data)
{
	struct test_glib_ev_source_data *state = talloc_get_type_abort(
		data, struct test_glib_ev_source_data);

	samba_tevent_glib_glue_quit(state->glue);

	return G_SOURCE_REMOVE;
}

static void test_glib_ev_source(void)
{
	GMainContext *ctx = NULL;
	struct tevent_glib_glue *glue = NULL;
	struct test_glib_ev_source_data *state = NULL;
	GSource *source = NULL;

	ctx = g_main_context_new();
	g_assert(ctx != NULL);

	glue = samba_tevent_glib_glue_create(ev, ev, ctx);
	g_assert(glue != NULL);

	state = talloc_zero(glue, struct test_glib_ev_source_data);
	g_assert(state != NULL);

	state->ctx = ctx;
	state->glue = glue;

	source = g_timeout_source_new(100);
	g_source_set_callback(source,
			      test_glib_ev_source_timeout_cb,
			      state,
			      NULL);
	g_source_attach(source, ctx);
	g_source_unref(source);

	g_assert(tevent_loop_wait(ev) == 0);

	TALLOC_FREE(glue);
	g_main_context_unref(ctx);
}

struct test_tevent_ev_source_data {
	GMainContext *ctx;
	struct tevent_glib_glue *glue;
};

static gboolean test_tevent_ev_source_quit_loop(gpointer data);

static void test_tevent_ev_source_timeout_cb(struct tevent_context *_ev,
					     struct tevent_timer *te,
					     struct timeval current_time,
					     void *data)
{
	struct test_tevent_ev_source_data *state = talloc_get_type_abort(
		data, struct test_tevent_ev_source_data);
	GSource *source = NULL;

	source = g_timeout_source_new(100);
	g_source_set_callback(source,
			      test_tevent_ev_source_quit_loop,
			      state,
			      NULL);
	g_source_attach(source, state->ctx);
	g_source_unref(source);

	return;
}

static gboolean test_tevent_ev_source_quit_loop(gpointer data)
{
	struct test_tevent_ev_source_data *state = talloc_get_type_abort(
		data, struct test_tevent_ev_source_data);

	samba_tevent_glib_glue_quit(state->glue);

	return G_SOURCE_REMOVE;
}

static void test_tevent_ev_source(void)
{
	GMainContext *ctx = NULL;
	struct tevent_glib_glue *glue = NULL;
	struct test_tevent_ev_source_data *state = NULL;
	struct tevent_timer *timer = NULL;

	ctx = g_main_context_new();
	g_assert(ctx != NULL);

	glue = samba_tevent_glib_glue_create(ev, ev, ctx);
	g_assert(glue != NULL);

	state = talloc_zero(glue, struct test_tevent_ev_source_data);
	g_assert(state != NULL);

	state->ctx = ctx;
	state->glue = glue;

	timer = tevent_add_timer(ev,
				 state,
				 tevent_timeval_current_ofs(0, 1000),
				 test_tevent_ev_source_timeout_cb,
				 state);
	g_assert(timer != NULL);

	g_assert(tevent_loop_wait(ev) == 0);

	TALLOC_FREE(glue);
	g_main_context_unref(ctx);
}

static gchar zeros[1024];

static gsize fill_a_pipe(gint fd)
{
	gsize written = 0;
	GPollFD pfd;

	pfd.fd = fd;
	pfd.events = G_IO_OUT;
	while (g_poll(&pfd, 1, 0) == 1)
		/* we should never see -1 here */
		written += write(fd, zeros, sizeof zeros);

	return written;
}

static gboolean write_bytes(gint	  fd,
			     GIOCondition condition,
			     gpointer	  user_data)
{
	gssize *to_write = user_data;
	gint limit;

	if (*to_write == 0)
		return FALSE;

	/* Detect if we run before we should */
	g_assert(*to_write >= 0);

	limit = MIN(*to_write, sizeof zeros);
	*to_write -= write(fd, zeros, limit);

	return TRUE;
}

static gboolean read_bytes(gint	 fd,
			    GIOCondition condition,
			    gpointer	 user_data)
{
	static gchar buffer[1024];
	gssize *to_read = user_data;

	*to_read -= read(fd, buffer, sizeof buffer);

	/* The loop will exit when there is nothing else to read, then we will
	 * use g_source_remove() to destroy this source.
	 */
	return TRUE;
}

static void test_unix_fd(void)
{
	gssize to_write = -1;
	gssize to_read;
	gint fds[2];
	gint a, b;
	gint s;
	GSource *source_a = NULL;
	GSource *source_b = NULL;
	struct tevent_glib_glue *glue = NULL;

	glue = samba_tevent_glib_glue_create(ev, ev, g_main_context_default());
	g_assert(glue != NULL);

	s = pipe(fds);
	g_assert(s == 0);

	to_read = fill_a_pipe(fds[1]);
	/* write at higher priority to keep the pipe full... */
	a = g_unix_fd_add_full(G_PRIORITY_HIGH,
			       fds[1],
			       G_IO_OUT,
			       write_bytes,
			       &to_write,
			       NULL);
	source_a = g_source_ref(g_main_context_find_source_by_id(NULL, a));
	/* make sure no 'writes' get dispatched yet */
	while (tevent_loop_once(ev));

	to_read += 128 * 1024 * 1024;
	to_write = 128 * 1024 * 1024;
	b = g_unix_fd_add(fds[0], G_IO_IN, read_bytes, &to_read);
	source_b = g_source_ref(g_main_context_find_source_by_id(NULL, b));

	/* Assuming the kernel isn't internally 'laggy' then there will always
	 * be either data to read or room in which to write.  That will keep
	 * the loop running until all data has been read and written.
	 */
	while (to_write > 0 || to_read > 0)
	{
		gssize to_write_was = to_write;
		gssize to_read_was = to_read;

		if (tevent_loop_once(ev) != 0)
			break;

		/* Since the sources are at different priority, only one of them
		 * should possibly have run.
		 */
		g_assert(to_write == to_write_was || to_read == to_read_was);
	}

	g_assert(to_write == 0);
	g_assert(to_read == 0);

	/* 'a' is already removed by itself */
	g_assert(g_source_is_destroyed(source_a));
	g_source_unref(source_a);
	g_source_remove(b);
	g_assert(g_source_is_destroyed(source_b));
	g_source_unref(source_b);

	samba_tevent_glib_glue_quit(glue);
	TALLOC_FREE(glue);

	close(fds[1]);
	close(fds[0]);
}

int main(int argc, const char *argv[])
{
	int test_argc = 3;
	char *test_argv[] = {
		discard_const("test_glib_glue"),
		discard_const("-m"),
		discard_const("no-undefined")
	};
	char **argvp = test_argv;

	g_test_init(&test_argc, &argvp, NULL);

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		exit(1);
	}

	g_test_add_func("/mainloop/timeouts", test_timeouts);
	g_test_add_func("/mainloop/glib_ev_source", test_glib_ev_source);
	g_test_add_func("/mainloop/tevent_ev_source", test_tevent_ev_source);
	g_test_add_func("/mainloop/unix-fd", test_unix_fd);

	return g_test_run();
}
