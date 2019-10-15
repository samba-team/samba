/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines / ES backend

   Copyright (C) Ralph Boehme			2019

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
#include "system/filesys.h"
#include "lib/util/time_basic.h"
#include "lib/tls/tls.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/http/http.h"
#include "lib/util/tevent_unix.h"
#include "credentials.h"
#include "mdssvc.h"
#include "mdssvc_es.h"
#include "rpc_server/mdssvc/es_parser.tab.h"

#include <jansson.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define MDSSVC_ELASTIC_QUERY_TEMPLATE	\
	"{"				\
	"    \"from\": %zu,"		\
	"    \"size\": %zu,"		\
	"    \"_source\": [%s],"	\
	"    \"query\": {"		\
        "        \"query_string\": {"	\
	"            \"query\": \"%s\"" \
	"        }"			\
	"    }"				\
	"}"

#define MDSSVC_ELASTIC_SOURCES \
	"\"path.real\""

static bool mdssvc_es_init(struct mdssvc_ctx *mdssvc_ctx)
{
	struct mdssvc_es_ctx *mdssvc_es_ctx = NULL;
	json_error_t json_error;
	char *default_path = NULL;
	const char *path = NULL;

	mdssvc_es_ctx = talloc_zero(mdssvc_ctx, struct mdssvc_es_ctx);
	if (mdssvc_es_ctx == NULL) {
		return false;
	}
	mdssvc_es_ctx->mdssvc_ctx = mdssvc_ctx;

	mdssvc_es_ctx->creds = cli_credentials_init_anon(mdssvc_es_ctx);
	if (mdssvc_es_ctx->creds == NULL) {
		TALLOC_FREE(mdssvc_es_ctx);
		return false;
	}

	default_path = talloc_asprintf(
		mdssvc_es_ctx,
		"%s/mdssvc/elasticsearch_mappings.json",
		get_dyn_SAMBA_DATADIR());
	if (default_path == NULL) {
		TALLOC_FREE(mdssvc_es_ctx);
		return false;
	}

	path = lp_parm_const_string(GLOBAL_SECTION_SNUM,
				    "elasticsearch",
				    "mappings",
				    default_path);
	if (path == NULL) {
		TALLOC_FREE(mdssvc_es_ctx);
		return false;
	}

	mdssvc_es_ctx->mappings = json_load_file(path, 0, &json_error);
	if (mdssvc_es_ctx->mappings == NULL) {
		DBG_ERR("Opening mapping file [%s] failed: %s\n",
			path, json_error.text);
		TALLOC_FREE(mdssvc_es_ctx);
		return false;
	}
	TALLOC_FREE(default_path);

	mdssvc_ctx->backend_private = mdssvc_es_ctx;
	return true;
}

static bool mdssvc_es_shutdown(struct mdssvc_ctx *mdssvc_ctx)
{
	return true;
}

static struct tevent_req *mds_es_connect_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct mds_es_ctx *mds_es_ctx);
static int mds_es_connect_recv(struct tevent_req *req);
static void mds_es_connected(struct tevent_req *subreq);
static bool mds_es_next_search_trigger(struct mds_es_ctx *mds_es_ctx);

static bool mds_es_connect(struct mds_ctx *mds_ctx)
{
	struct mdssvc_es_ctx *mdssvc_es_ctx = talloc_get_type_abort(
		mds_ctx->mdssvc_ctx->backend_private, struct mdssvc_es_ctx);
	struct mds_es_ctx *mds_es_ctx = NULL;
	struct tevent_req *subreq = NULL;

	mds_es_ctx = talloc_zero(mds_ctx, struct mds_es_ctx);
	if (mds_es_ctx == NULL) {
		return false;
	}
	*mds_es_ctx = (struct mds_es_ctx) {
		.mdssvc_es_ctx = mdssvc_es_ctx,
		.mds_ctx = mds_ctx,
	};

	mds_ctx->backend_private = mds_es_ctx;

	subreq = mds_es_connect_send(
			mds_es_ctx,
			mdssvc_es_ctx->mdssvc_ctx->ev_ctx,
			mds_es_ctx);
	if (subreq == NULL) {
		TALLOC_FREE(mds_es_ctx);
		return false;
	}
	tevent_req_set_callback(subreq, mds_es_connected, mds_es_ctx);
	return true;
}

static void mds_es_connected(struct tevent_req *subreq)
{
	struct mds_es_ctx *mds_es_ctx = tevent_req_callback_data(
		subreq, struct mds_es_ctx);
	int ret;
	bool ok;

	ret = mds_es_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		DBG_ERR("HTTP connect failed\n");
		return;
	}

	ok = mds_es_next_search_trigger(mds_es_ctx);
	if (!ok) {
		DBG_ERR("mds_es_next_search_trigger failed\n");
	}
	return;
}

struct mds_es_connect_state {
	struct tevent_context *ev;
	struct mds_es_ctx *mds_es_ctx;
	struct tevent_queue_entry *qe;
	const char *server_addr;
	uint16_t server_port;
	struct tstream_tls_params *tls_params;
};

static void mds_es_http_connect_done(struct tevent_req *subreq);
static void mds_es_http_waited(struct tevent_req *subreq);

static struct tevent_req *mds_es_connect_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct mds_es_ctx *mds_es_ctx)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct mds_es_connect_state *state = NULL;
	const char *server_addr = NULL;
	bool use_tls;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct mds_es_connect_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct mds_es_connect_state) {
		.ev = ev,
		.mds_es_ctx = mds_es_ctx,
	};

	server_addr = lp_parm_const_string(
		mds_es_ctx->mds_ctx->snum,
		"elasticsearch",
		"address",
		"localhost");
	state->server_addr = talloc_strdup(state, server_addr);
	if (tevent_req_nomem(state->server_addr, req)) {
		return tevent_req_post(req, ev);
	}

	state->server_port = lp_parm_int(
		mds_es_ctx->mds_ctx->snum,
		"elasticsearch",
		"port",
		9200);

	use_tls = lp_parm_bool(
		mds_es_ctx->mds_ctx->snum,
		"elasticsearch",
		"use tls",
		false);

	DBG_DEBUG("Connecting to HTTP%s [%s] port [%"PRIu16"]\n",
		  use_tls ? "S" : "", state->server_addr, state->server_port);

	if (use_tls) {
		const char *ca_file = lp__tls_cafile();
		const char *crl_file = lp__tls_crlfile();
		const char *tls_priority = lp_tls_priority();
		enum tls_verify_peer_state verify_peer = lp_tls_verify_peer();

		status = tstream_tls_params_client(state,
						   ca_file,
						   crl_file,
						   tls_priority,
						   verify_peer,
						   state->server_addr,
						   &state->tls_params);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed tstream_tls_params_client - %s\n",
				nt_errstr(status));
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
	}

	subreq = http_connect_send(state,
				   state->ev,
				   state->server_addr,
				   state->server_port,
				   mds_es_ctx->mdssvc_es_ctx->creds,
				   state->tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, mds_es_http_connect_done, req);
	return req;
}

static void mds_es_http_connect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mds_es_connect_state *state = tevent_req_data(
		req, struct mds_es_connect_state);
	int error;

	error = http_connect_recv(subreq,
				  state->mds_es_ctx,
				  &state->mds_es_ctx->http_conn);
	TALLOC_FREE(subreq);
	if (error != 0) {
		DBG_ERR("HTTP connect failed, retrying...\n");

		subreq = tevent_wakeup_send(
			state->mds_es_ctx,
			state->mds_es_ctx->mdssvc_es_ctx->mdssvc_ctx->ev_ctx,
			tevent_timeval_current_ofs(10, 0));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					mds_es_http_waited,
					req);
		return;
	}

	DBG_DEBUG("Connected to HTTP%s [%s] port [%"PRIu16"]\n",
		  state->tls_params ? "S" : "",
		  state->server_addr, state->server_port);

	tevent_req_done(req);
	return;
}

static void mds_es_http_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mds_es_connect_state *state = tevent_req_data(
		req, struct mds_es_connect_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, ETIMEDOUT);
		return;
	}

	subreq = mds_es_connect_send(
			state->mds_es_ctx,
			state->mds_es_ctx->mdssvc_es_ctx->mdssvc_ctx->ev_ctx,
			state->mds_es_ctx);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, mds_es_connected, state->mds_es_ctx);
}

static int mds_es_connect_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static void mds_es_reconnect_on_error(struct sl_es_search *s)
{
	struct mds_es_ctx *mds_es_ctx = s->mds_es_ctx;
	struct tevent_req *subreq = NULL;

	if (s->slq != NULL) {
		s->slq->state = SLQ_STATE_ERROR;
	}

	DBG_WARNING("Reconnecting HTTP...\n");
	TALLOC_FREE(mds_es_ctx->http_conn);

	subreq = mds_es_connect_send(
			mds_es_ctx,
			mds_es_ctx->mdssvc_es_ctx->mdssvc_ctx->ev_ctx,
			mds_es_ctx);
	if (subreq == NULL) {
		DBG_ERR("mds_es_connect_send failed\n");
		return;
	}
	tevent_req_set_callback(subreq, mds_es_connected, mds_es_ctx);
}

static int search_destructor(struct sl_es_search *s)
{
	DLIST_REMOVE(s->mds_es_ctx->searches, s);
	return 0;
}

static struct tevent_req *mds_es_search_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct sl_es_search *s);
static int mds_es_search_recv(struct tevent_req *req);
static void mds_es_search_done(struct tevent_req *subreq);

static bool mds_es_search(struct sl_query *slq)
{
	struct mds_es_ctx *mds_es_ctx = talloc_get_type_abort(
		slq->mds_ctx->backend_private, struct mds_es_ctx);
	struct sl_es_search *s = NULL;
	bool ok;

	s = talloc_zero(slq, struct sl_es_search);
	if (s == NULL) {
		return false;
	}
	*s = (struct sl_es_search) {
		.ev = mds_es_ctx->mdssvc_es_ctx->mdssvc_ctx->ev_ctx,
		.mds_es_ctx = mds_es_ctx,
		.slq = slq,
		.size = MAX_SL_RESULTS,
	};

	/* 0 would mean no limit */
	s->max = lp_parm_ulonglong(s->slq->mds_ctx->snum,
				   "elasticsearch",
				   "max results",
				   MAX_SL_RESULTS);

	DBG_DEBUG("Spotlight query: '%s'\n", slq->query_string);

	ok = map_spotlight_to_es_query(
		s,
		mds_es_ctx->mdssvc_es_ctx->mappings,
		slq->path_scope,
		slq->query_string,
		&s->es_query);
	if (!ok) {
		TALLOC_FREE(s);
		return false;
	}
	DBG_DEBUG("Elasticsearch query: '%s'\n", s->es_query);

	slq->backend_private = s;
	slq->state = SLQ_STATE_RUNNING;
	DLIST_ADD_END(mds_es_ctx->searches, s);
	talloc_set_destructor(s, search_destructor);

	return mds_es_next_search_trigger(mds_es_ctx);
}

static bool mds_es_next_search_trigger(struct mds_es_ctx *mds_es_ctx)
{
	struct tevent_req *subreq = NULL;
	struct sl_es_search *s = mds_es_ctx->searches;

	if (mds_es_ctx->http_conn == NULL) {
		DBG_DEBUG("Waiting for HTTP connection...\n");
		return true;
	}
	if (s == NULL) {
		DBG_DEBUG("No pending searches, idling...\n");
		return true;
	}
	if (s->pending) {
		DBG_DEBUG("Search pending [%p]\n", s);
		return true;
	}

	subreq = mds_es_search_send(s, s->ev, s);
	if (subreq == NULL) {
		return false;
	}
	tevent_req_set_callback(subreq, mds_es_search_done, s);
	return true;
}

static void mds_es_search_done(struct tevent_req *subreq)
{
	struct sl_es_search *s = tevent_req_callback_data(
		subreq, struct sl_es_search);
	struct mds_es_ctx *mds_es_ctx = s->mds_es_ctx;
	struct sl_query *slq = s->slq;
	int ret;
	bool ok;

	DBG_DEBUG("Search done for search [%p]\n", s);

	DLIST_REMOVE(mds_es_ctx->searches, s);

	ret = mds_es_search_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		mds_es_reconnect_on_error(s);
		return;
	}

	if (slq == NULL) {
		/*
		 * Closed by the user. This is the only place where we free "s"
		 * explicitly because the talloc parent slq is already gone.
		 * Everywhere else we rely on the destructor of slq to free s"."
		 */
		TALLOC_FREE(s);
		goto trigger;
	}

	SLQ_DEBUG(10, slq, "search done");

	if (s->total == 0 || s->from >= s->max) {
		slq->state = SLQ_STATE_DONE;
		goto trigger;
	}

	if (slq->query_results->num_results >= MAX_SL_RESULTS) {
		slq->state = SLQ_STATE_FULL;
		goto trigger;
	}

	/*
	 * Reschedule this query as there are more results waiting in the
	 * Elasticsearch server and the client result queue has room as
	 * well. But put it at the end of the list of active queries as a simple
	 * heuristic that should ensure all client queries are dispatched to the
	 * server.
	 */
	DLIST_ADD_END(mds_es_ctx->searches, s);

trigger:
	ok = mds_es_next_search_trigger(mds_es_ctx);
	if (!ok) {
		DBG_ERR("mds_es_next_search_trigger failed\n");
	}
}

static void mds_es_search_http_send_done(struct tevent_req *subreq);
static void mds_es_search_http_read_done(struct tevent_req *subreq);

struct mds_es_search_state {
	struct tevent_context *ev;
	struct sl_es_search *s;
	struct tevent_queue_entry *qe;
	struct http_request http_request;
	struct http_request *http_response;
};

static int mds_es_search_pending_destructor(struct sl_es_search *s)
{
	/*
	 * s is a child of slq which may get freed when a user closes a
	 * query. To maintain the HTTP request/response sequence on the HTTP
	 * channel, we keep processing pending requests and free s when we
	 * receive the HTTP response for pending requests.
	 */
	DBG_DEBUG("Preserving pending search [%p]\n", s);
	s->slq = NULL;
	return -1;
}

static void mds_es_search_set_pending(struct sl_es_search *s)
{
	DBG_DEBUG("Set pending [%p]\n", s);
	SLQ_DEBUG(10, s->slq, "pending");

	s->pending = true;
	talloc_set_destructor(s, mds_es_search_pending_destructor);
}

static void mds_es_search_unset_pending(struct sl_es_search *s)
{
	DBG_DEBUG("Unset pending [%p]\n", s);
	if (s->slq != NULL) {
		SLQ_DEBUG(10, s->slq, "unset pending");
	}

	s->pending = false;
	talloc_set_destructor(s, NULL);
}

static struct tevent_req *mds_es_search_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct sl_es_search *s)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct mds_es_search_state *state = NULL;
	const char *index = NULL;
	char *elastic_query = NULL;
	char *uri = NULL;
	size_t elastic_query_len;
	char *elastic_query_len_str = NULL;
	char *hostname = NULL;
	bool pretty = false;

	req = tevent_req_create(mem_ctx, &state, struct mds_es_search_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct mds_es_search_state) {
		.ev = ev,
		.s = s,
	};

	if (!tevent_req_set_endtime(req, ev, timeval_current_ofs(60, 0))) {
		return tevent_req_post(req, s->ev);
	}

	index = lp_parm_const_string(s->slq->mds_ctx->snum,
				     "elasticsearch",
				     "index",
				     "_all");
	if (tevent_req_nomem(index, req)) {
		return tevent_req_post(req, ev);
	}

	if (DEBUGLVL(10)) {
		pretty = true;
	}

	uri = talloc_asprintf(state,
			      "/%s/_search%s",
			      index,
			      pretty ? "?pretty" : "");
	if (tevent_req_nomem(uri, req)) {
		return tevent_req_post(req, ev);
	}

	elastic_query = talloc_asprintf(state,
					MDSSVC_ELASTIC_QUERY_TEMPLATE,
					s->from,
					s->size,
					MDSSVC_ELASTIC_SOURCES,
					s->es_query);
	if (tevent_req_nomem(elastic_query, req)) {
		return tevent_req_post(req, ev);
	}
	DBG_DEBUG("Elastic query: '%s'\n", elastic_query);

	elastic_query_len = strlen(elastic_query);

	state->http_request = (struct http_request) {
		.type = HTTP_REQ_POST,
		.uri = uri,
		.body = data_blob_const(elastic_query, elastic_query_len),
		.major = '1',
		.minor = '1',
	};

	elastic_query_len_str = talloc_asprintf(state, "%zu", elastic_query_len);
	if (tevent_req_nomem(elastic_query_len_str, req)) {
		return tevent_req_post(req, ev);
	}

	hostname = get_myname(state);
	if (tevent_req_nomem(hostname, req)) {
		return tevent_req_post(req, ev);
	}

	http_add_header(state, &state->http_request.headers,
			"Content-Type",	"application/json");
	http_add_header(state, &state->http_request.headers,
			"Accept", "application/json");
	http_add_header(state, &state->http_request.headers,
			"User-Agent", "Samba/mdssvc");
	http_add_header(state, &state->http_request.headers,
			"Host", hostname);
	http_add_header(state, &state->http_request.headers,
			"Content-Length", elastic_query_len_str);

	subreq = http_send_request_send(state,
					ev,
					s->mds_es_ctx->http_conn,
					&state->http_request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	mds_es_search_set_pending(s);
	tevent_req_set_callback(subreq, mds_es_search_http_send_done, req);
	return req;
}

static void mds_es_search_http_send_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mds_es_search_state *state = tevent_req_data(
		req, struct mds_es_search_state);
	NTSTATUS status;

	DBG_DEBUG("Sent out search [%p]\n", state->s);

	status = http_send_request_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_error(req, map_errno_from_nt_status(status));
		return;
	}

	if (state->s->mds_es_ctx->mds_ctx == NULL) {
		mds_es_search_unset_pending(state->s);
		tevent_req_error(req, ECANCELED);
		return;
	}

	subreq = http_read_response_send(state,
					 state->ev,
					 state->s->mds_es_ctx->http_conn,
					 MAX_SL_RESULTS * 8192);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, mds_es_search_http_read_done, req);
}

static void mds_es_search_http_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mds_es_search_state *state = tevent_req_data(
		req, struct mds_es_search_state);
	struct sl_es_search *s = state->s;
	struct sl_query *slq = s->slq;
	json_t *root = NULL;
	json_t *matches = NULL;
	json_t *match = NULL;
	size_t i;
	json_error_t error;
	int hits;
	NTSTATUS status;
	int ret;
	bool ok;

	DBG_DEBUG("Got response for search [%p]\n", s);

	mds_es_search_unset_pending(s);

	status = http_read_response_recv(subreq, state, &state->http_response);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("HTTP response failed: %s\n", nt_errstr(status));
		tevent_req_error(req, map_errno_from_nt_status(status));
		return;
	}

	if (slq == NULL) {
		tevent_req_done(req);
		return;
	}
	if (s->mds_es_ctx->mds_ctx == NULL) {
		tevent_req_error(req, ECANCELED);
		return;
	}

	switch (state->http_response->response_code) {
	case 200:
		break;
	default:
		DBG_ERR("HTTP server response: %u\n",
			state->http_response->response_code);
		goto fail;
	}

	DBG_DEBUG("JSON response:\n%s\n",
		  talloc_strndup(talloc_tos(),
				 (char *)state->http_response->body.data,
				 state->http_response->body.length));

	root = json_loadb((char *)state->http_response->body.data,
			  state->http_response->body.length,
			  0,
			  &error);
	if (root == NULL) {
		DBG_ERR("json_loadb failed\n");
		goto fail;
	}

	if (s->total == 0) {
		/*
		 * Get the total number of results the first time, format
		 * used by Elasticsearch 7.0 or newer
		 */
		ret = json_unpack(root, "{s: {s: {s: i}}}",
				  "hits", "total", "value", &s->total);
		if (ret != 0) {
			/* Format used before 7.0 */
			ret = json_unpack(root, "{s: {s: i}}",
					  "hits", "total", &s->total);
			if (ret != 0) {
				DBG_ERR("json_unpack failed\n");
				goto fail;
			}
		}

		DBG_DEBUG("Total: %zu\n", s->total);

		if (s->total == 0) {
			json_decref(root);
			tevent_req_done(req);
			return;
		}
	}

	if (s->max == 0 || s->max > s->total) {
		s->max = s->total;
	}

	ret = json_unpack(root, "{s: {s:o}}",
			  "hits", "hits", &matches);
	if (ret != 0 || matches == NULL) {
		DBG_ERR("json_unpack hits failed\n");
		goto fail;
	}

	hits = json_array_size(matches);
	if (hits == 0) {
		DBG_ERR("Hu?! No results?\n");
		goto fail;
	}
	DBG_DEBUG("Hits: %d\n", hits);

	for (i = 0; i < hits; i++) {
		const char *path = NULL;

		match = json_array_get(matches, i);
		if (match == NULL) {
			DBG_ERR("Hu?! No value for index %zu\n", i);
			goto fail;
		}
		ret = json_unpack(match,
				  "{s: {s: {s: s}}}",
				  "_source",
				  "path",
				  "real",
				  &path);
		if (ret != 0) {
			DBG_ERR("Missing path.real in JSON result\n");
			goto fail;
		}

		ok = mds_add_result(slq, path);
		if (!ok) {
			DBG_ERR("error adding result for path: %s\n", path);
			goto fail;
		}
	}
	json_decref(root);

	s->from += hits;
	slq->state = SLQ_STATE_RESULTS;
	tevent_req_done(req);
	return;

fail:
	if (root != NULL) {
		json_decref(root);
	}
	slq->state = SLQ_STATE_ERROR;
	tevent_req_error(req, EINVAL);
	return;
}

static int mds_es_search_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static bool mds_es_search_cont(struct sl_query *slq)
{
	struct sl_es_search *s = talloc_get_type_abort(
		slq->backend_private, struct sl_es_search);

	SLQ_DEBUG(10, slq, "continue");
	DLIST_ADD_END(s->mds_es_ctx->searches, s);
	return mds_es_next_search_trigger(s->mds_es_ctx);
}

struct mdssvc_backend mdsscv_backend_es = {
	.init = mdssvc_es_init,
	.shutdown = mdssvc_es_shutdown,
	.connect = mds_es_connect,
	.search_start = mds_es_search,
	.search_cont = mds_es_search_cont,
};
