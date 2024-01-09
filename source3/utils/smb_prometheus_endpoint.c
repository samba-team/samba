/*
 * Unix SMB/CIFS implementation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "system/filesys.h"
#include <tdb.h>
#include "source3/include/smbprofile.h"
#include "event2/event.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "event2/buffer.h"

struct export_state {
	struct evbuffer *buf;
	bool sent_help_cpu_seconds : 1;
	bool sent_help_smb1_request_total : 1;
	bool sent_help_smb2_request_inbytes : 1;
	bool sent_help_smb2_request_outbytes : 1;
	bool sent_help_smb2_request_hist : 1;
	bool sent_help_smb2_request_failed : 1;
};

static void export_count(const char *name,
			 const struct smbprofile_stats_count *val,
			 struct export_state *state)
{
	return;
}

static void export_time(const char *name,
			const struct smbprofile_stats_time *val,
			struct export_state *state)
{
	bool is_cpu;

	is_cpu = (strncmp(name, "cpu_", 4) == 0);
	if (is_cpu) {
		const char *mode = name + 4;

		if (!state->sent_help_cpu_seconds) {
			evbuffer_add_printf(
				state->buf,
				"# HELP smb_cpu_seconds_total Seconds spent "
				"in worker smbds\n"
				"# TYPE smb_cpu_seconds_total counter\n");
			state->sent_help_cpu_seconds = true;
		}

		evbuffer_add_printf(
			state->buf,
			"smb_cpu_seconds_total { mode=\"%s\" } %f\n",
			mode,
			((double)val->time) / 1000000);
	}
}

static void export_basic(const char *name,
			 const struct smbprofile_stats_basic *val,
			 struct export_state *state)
{
	bool is_smb;

	is_smb = (strncmp(name, "SMB", 3) == 0);
	if (is_smb) {

		if (!state->sent_help_smb1_request_total) {
			evbuffer_add_printf(
				state->buf,
				"# HELP smb_smb1_request_total Number of "
				"SMB1 requests\n"
				"# TYPE smb_smb1_request_total counter\n");
			state->sent_help_smb1_request_total = true;
		}

		evbuffer_add_printf(
			state->buf,
			"smb_smb1_request_total { operation=\"%s\" } "
			"%" PRIu64 "\n",
			name + 3,
			val->count);
	}
	return;
}

static void export_iobytes_inbytes(const char *name,
				   const struct smbprofile_stats_iobytes *val,
				   struct export_state *state)
{
	bool is_smb2;

	is_smb2 = (strncmp(name, "smb2_", 5) == 0);
	if (is_smb2) {
		if (!state->sent_help_smb2_request_inbytes) {
			evbuffer_add_printf(
				state->buf,
				"# HELP smb_smb2_request_inbytes Bytes "
				"received for SMB2 requests\n"
				"# TYPE smb_smb2_request_inbytes counter\n");
			state->sent_help_smb2_request_inbytes = true;
		}

		evbuffer_add_printf(
			state->buf,
			"smb_smb2_request_inbytes { operation=\"%s\" } "
			"%" PRIu64 "\n",
			name + 5,
			val->inbytes);
	}
}

static void export_iobytes_outbytes(const char *name,
				   const struct smbprofile_stats_iobytes *val,
				   struct export_state *state)
{
	bool is_smb2;

	is_smb2 = (strncmp(name, "smb2_", 5) == 0);
	if (is_smb2) {
		if (!state->sent_help_smb2_request_outbytes) {
			evbuffer_add_printf(
				state->buf,
				"# HELP smb_smb2_request_outbytes Bytes "
				"received for SMB2 requests\n"
				"# TYPE smb_smb2_request_outbytes counter\n");
			state->sent_help_smb2_request_outbytes = true;
		}

		evbuffer_add_printf(
			state->buf,
			"smb_smb2_request_outbytes { operation=\"%s\" } "
			"%" PRIu64 "\n",
			name + 5,
			val->outbytes);
	}
}

static void export_iobytes_buckets(const char *name,
				   const struct smbprofile_stats_iobytes *val,
				   struct export_state *state)
{
	bool is_smb2;

	is_smb2 = (strncmp(name, "smb2_", 5) == 0);
	if (is_smb2) {
		int i;

		if (!state->sent_help_smb2_request_hist) {
			evbuffer_add_printf(
				state->buf,
				"# HELP smb_smb2_request_duration_microseconds "
				"Histogram of latencies for SMB2 requests\n"
				"# TYPE smb_smb2_request_duration_microseconds "
				"histogram\n");
			state->sent_help_smb2_request_hist = true;
		}

		for (i=0; i<9; i++) {
			evbuffer_add_printf(
				state->buf,
				"smb_smb2_request_duration_microseconds_bucket "
				"{operation=\"%s\",le=\"%d000\"} "
				"%" PRIu64 "\n",
				name + 5,
				1<<i,
				val->buckets[i]);
		}
		evbuffer_add_printf(
			state->buf,
			"smb_smb2_request_duration_microseconds_bucket "
			"{operation=\"%s\",le=\"+Inf\"} "
			"%" PRIu64 "\n",
			name + 5,
			val->buckets[9]);
		evbuffer_add_printf(
			state->buf,
			"smb_smb2_request_duration_microseconds_sum "
			"{operation=\"%s\"} "
			"%" PRIu64 "\n",
			name + 5,
			val->time);
		evbuffer_add_printf(
			state->buf,
			"smb_smb2_request_duration_microseconds_count "
			"{operation=\"%s\"} "
			"%" PRIu64 "\n",
			name + 5,
			val->count);
	}
}

static void export_iobytes_failed(const char *name,
				  const struct smbprofile_stats_iobytes *val,
				  struct export_state *state)
{
	bool is_smb2;

	is_smb2 = (strncmp(name, "smb2_", 5) == 0);
	if (is_smb2) {
		if (!state->sent_help_smb2_request_failed) {
			evbuffer_add_printf(
				state->buf,
				"# HELP smb_smb2_request_failed Number "
				"of failed SMB2 requests\n"
				"# TYPE smb_smb2_request_failed counter\n");
			state->sent_help_smb2_request_failed = true;
		}

		evbuffer_add_printf(
			state->buf,
			"smb_smb2_request_failed { operation=\"%s\" } "
			"%" PRIu64 "\n",
			name + 5,
			val->failed_count);
	}
}

static void metrics_handler(struct evhttp_request *req, void *arg)
{
	struct export_state state = {.buf = NULL};
	const char *tdbfilename = arg;
	struct tdb_context *tdb = NULL;
	struct profile_stats stats = {.magic = 0};
	uint64_t magic;
	size_t num_workers;
	int ret;

	evhttp_add_header(req->output_headers,
			  "Content-Type",
			  "text/plain; charset=UTF-8");
	evhttp_add_header(req->output_headers, "Connection", "close");

	state.buf = evbuffer_new();
	if (state.buf == NULL) {
		evhttp_send_reply(req, HTTP_INTERNAL, "NOMEM", state.buf);
		return;
	}

	/*
	 * Open with O_RDWR although we won't write, but we want
	 * locking.
	 */
	tdb = tdb_open(tdbfilename,
		       0,
		       TDB_CLEAR_IF_FIRST | TDB_MUTEX_LOCKING,
		       O_RDWR,
		       0);
	if (tdb == NULL) {
		evbuffer_add_printf(state.buf,
				    "Could not open %s: %s\n",
				    tdbfilename,
				    strerror(errno));
		evhttp_send_reply(req,
				  HTTP_INTERNAL,
				  "TDB failure",
				  state.buf);
		evbuffer_free(state.buf);
		return;
	}

	ret = smbprofile_magic(&stats, &magic);
	if (ret != 0) {
		evbuffer_add_printf(state.buf, "Could calculate magic");
		evhttp_send_reply(req,
				  HTTP_INTERNAL,
				  "magic failure",
				  state.buf);
		evbuffer_free(state.buf);
		return;
	}

	num_workers = smbprofile_collect_tdb(tdb, magic, &stats);

	tdb_close(tdb);

	evbuffer_add_printf(
		state.buf,
		"# HELP smb_worker_smbd_num Number of worker smbds "
		"serving clients\n"
		"# TYPE smb_worker_smbd_num gauge\n"
		"smb_worker_smbd_num %zu\n",
		num_workers);

	evbuffer_add_printf(
		state.buf,
		"# HELP smb_num_authenticated_sessions Number of users "
		"logged in\n"
		"# TYPE smb_num_authenticated_sessions gauge\n"
		"smb_num_authenticated_sessions %"PRIu64"\n",
		stats.values.num_sessions_stats.count);

	evbuffer_add_printf(
		state.buf,
		"# HELP smb_num_tree_connects Number of share connections\n"
		"# TYPE smb_num_tree_connects gauge\n"
		"smb_num_tree_connects %"PRIu64"\n",
		stats.values.num_tcons_stats.count);

	evbuffer_add_printf(
		state.buf,
		"# HELP smb_num_open_files Number of open files\n"
		"# TYPE smb_num_open_files gauge\n"
		"smb_num_open_files %"PRIu64"\n",
		stats.values.num_files_stats.count);

#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name)                                     \
	do {                                                             \
		export_count(#name, &stats.values.name##_stats, &state); \
	} while (0);
#define SMBPROFILE_STATS_TIME(name)                                     \
	do {                                                            \
		export_time(#name, &stats.values.name##_stats, &state); \
	} while (0);
#define SMBPROFILE_STATS_BASIC(name)                                     \
	do {                                                             \
		export_basic(#name, &stats.values.name##_stats, &state); \
	} while (0);
#define SMBPROFILE_STATS_BYTES(name)
#define SMBPROFILE_STATS_IOBYTES(name)
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name)
#define SMBPROFILE_STATS_TIME(name)
#define SMBPROFILE_STATS_BASIC(name)
#define SMBPROFILE_STATS_BYTES(name)
#define SMBPROFILE_STATS_IOBYTES(name)					\
	do {                                                               \
		export_iobytes_inbytes(                                    \
	           #name, &stats.values.name##_stats, &state);             \
	} while (0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name)
#define SMBPROFILE_STATS_TIME(name)
#define SMBPROFILE_STATS_BASIC(name)
#define SMBPROFILE_STATS_BYTES(name)
#define SMBPROFILE_STATS_IOBYTES(name)					\
	do {                                                               \
		export_iobytes_outbytes(                                    \
	           #name, &stats.values.name##_stats, &state);             \
	} while (0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name)
#define SMBPROFILE_STATS_TIME(name)
#define SMBPROFILE_STATS_BASIC(name)
#define SMBPROFILE_STATS_BYTES(name)
#define SMBPROFILE_STATS_IOBYTES(name)					\
	do {                                                               \
		export_iobytes_buckets(                                    \
	           #name, &stats.values.name##_stats, &state);             \
	} while (0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name)
#define SMBPROFILE_STATS_TIME(name)
#define SMBPROFILE_STATS_BASIC(name)
#define SMBPROFILE_STATS_BYTES(name)
#define SMBPROFILE_STATS_IOBYTES(name)                            \
	do {                                                      \
		export_iobytes_failed(#name,                      \
				      &stats.values.name##_stats, \
				      &state);                    \
	} while (0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

	evhttp_send_reply(req, HTTP_OK, "OK", state.buf);
	evbuffer_free(state.buf);
}

static void default_handler(struct evhttp_request *req, void *arg)
{
	struct evbuffer *buf = NULL;

	evhttp_add_header(req->output_headers,
			  "Content-Type",
			  "text/plain; charset=UTF-8");
	evhttp_add_header(req->output_headers, "Connection", "close");

	buf = evbuffer_new();
	if (buf != NULL) {
		evbuffer_add_printf(buf, "404 Not Found\n");
	}

	evhttp_send_reply(req, HTTP_NOTFOUND, "OK", buf);

	if (buf != NULL) {
		evbuffer_free(buf);
	}
}

int main(int argc, char *argv[])
{
	struct event_base *ev = NULL;
	struct evhttp *http_server = NULL;
	char *tdbfilename = NULL;
	const char *addr = "127.0.0.1";
	uint16_t port = 9922;
	int ret, c;

	while ((c = getopt(argc, argv, "a:p:")) != -1) {
		switch (c) {
		case 'a':
			addr = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		}
	}

	if (optind != argc - 1) {
		fprintf(stderr, "Missing tdb filename\n");
		return 1;
	}
	tdbfilename = argv[optind];

	ev = event_base_new();
	if (ev == NULL) {
		fprintf(stderr, "event_base_new() failed\n");
		return 1;
	}

	http_server = evhttp_new(ev);
	if (http_server == NULL) {
		fprintf(stderr, "evhttp_new() failed\n");
		return 1;
	}

	ret = evhttp_bind_socket(http_server, addr, port);
	if (ret != 0) {
		fprintf(stderr, "evhttp_bind_socket failed\n");
		return 1;
	}

	evhttp_set_gencb(http_server, default_handler, ev);
	evhttp_set_cb(http_server, "/metrics", metrics_handler, tdbfilename);
	event_base_dispatch(ev);

	evhttp_free(http_server);
	event_base_free(ev);

	return 0;
}
