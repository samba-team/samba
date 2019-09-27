/*
   CTDB client code

   Copyright (C) Amitay Isaacs  2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "common/logging.h"

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "client/client_private.h"
#include "client/client.h"

struct tdb_context *client_db_tdb(struct ctdb_db_context *db)
{
	return db->ltdb->tdb;
}

static struct ctdb_db_context *client_db_handle(
					struct ctdb_client_context *client,
					const char *db_name)
{
	struct ctdb_db_context *db;

	for (db = client->db; db != NULL; db = db->next) {
		if (strcmp(db_name, db->db_name) == 0) {
			return db;
		}
	}

	return NULL;
}

static bool ctdb_db_persistent(struct ctdb_db_context *db)
{
	if (db->db_flags & CTDB_DB_FLAGS_PERSISTENT) {
		return true;
	}
	return false;
}

static bool ctdb_db_replicated(struct ctdb_db_context *db)
{
	if (db->db_flags & CTDB_DB_FLAGS_REPLICATED) {
		return true;
	}
	return false;
}

static bool ctdb_db_volatile(struct ctdb_db_context *db)
{
	if (db->db_flags & CTDB_DB_FLAGS_PERSISTENT ||
	    db->db_flags & CTDB_DB_FLAGS_REPLICATED) {
		return false;
	}
	return true;
}

struct ctdb_set_db_flags_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct timeval timeout;
	uint32_t db_id;
	uint8_t db_flags;
	bool readonly_done, sticky_done;
	uint32_t *pnn_list;
	int count;
};

static void ctdb_set_db_flags_nodemap_done(struct tevent_req *subreq);
static void ctdb_set_db_flags_readonly_done(struct tevent_req *subreq);
static void ctdb_set_db_flags_sticky_done(struct tevent_req *subreq);

static struct tevent_req *ctdb_set_db_flags_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t destnode, struct timeval timeout,
				uint32_t db_id, uint8_t db_flags)
{
	struct tevent_req *req, *subreq;
	struct ctdb_set_db_flags_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_set_db_flags_state);
	if (req == NULL) {
		return NULL;
	}

	if (! (db_flags & (CTDB_DB_FLAGS_READONLY | CTDB_DB_FLAGS_STICKY))) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	state->ev = ev;
	state->client = client;
	state->timeout = timeout;
	state->db_id = db_id;
	state->db_flags = db_flags;

	ctdb_req_control_get_nodemap(&request);
	subreq = ctdb_client_control_send(state, ev, client, destnode, timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_set_db_flags_nodemap_done, req);

	return req;
}

static void ctdb_set_db_flags_nodemap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_set_db_flags_state *state = tevent_req_data(
		req, struct ctdb_set_db_flags_state);
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	struct ctdb_node_map *nodemap;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("set_db_flags: 0x%08x GET_NODEMAP failed, ret=%d\n",
		       state->db_id, ret));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_nodemap(reply, state, &nodemap);
	talloc_free(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("set_db_flags: 0x%08x GET_NODEMAP parse failed, ret=%d\n",
		      state->db_id, ret));
		tevent_req_error(req, ret);
		return;
	}

	state->count = list_of_connected_nodes(nodemap, CTDB_UNKNOWN_PNN,
					       state, &state->pnn_list);
	talloc_free(nodemap);
	if (state->count <= 0) {
		DEBUG(DEBUG_ERR,
		      ("set_db_flags: 0x%08x no connected nodes, count=%d\n",
		       state->db_id, state->count));
		tevent_req_error(req, ENOMEM);
		return;
	}

	if (state->db_flags & CTDB_DB_FLAGS_READONLY) {
		ctdb_req_control_set_db_readonly(&request, state->db_id);
		subreq = ctdb_client_control_multi_send(
					state, state->ev, state->client,
					state->pnn_list, state->count,
					state->timeout, &request);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					ctdb_set_db_flags_readonly_done, req);
	} else {
		state->readonly_done = true;
	}

	if (state->db_flags & CTDB_DB_FLAGS_STICKY) {
		ctdb_req_control_set_db_sticky(&request, state->db_id);
		subreq = ctdb_client_control_multi_send(
					state, state->ev, state->client,
					state->pnn_list, state->count,
					state->timeout, &request);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, ctdb_set_db_flags_sticky_done,
					req);
	} else {
		state->sticky_done = true;
	}
}

static void ctdb_set_db_flags_readonly_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_set_db_flags_state *state = tevent_req_data(
		req, struct ctdb_set_db_flags_state);
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, NULL,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("set_db_flags: 0x%08x SET_DB_READONLY failed, ret=%d\n",
		       state->db_id, ret));
		tevent_req_error(req, ret);
		return;
	}

	state->readonly_done = true;

	if (state->readonly_done && state->sticky_done) {
		tevent_req_done(req);
	}
}

static void ctdb_set_db_flags_sticky_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_set_db_flags_state *state = tevent_req_data(
		req, struct ctdb_set_db_flags_state);
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, NULL,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("set_db_flags: 0x%08x SET_DB_STICKY failed, ret=%d\n",
		       state->db_id, ret));
		tevent_req_error(req, ret);
		return;
	}

	state->sticky_done = true;

	if (state->readonly_done && state->sticky_done) {
		tevent_req_done(req);
	}
}

static bool ctdb_set_db_flags_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}
	return true;
}

struct ctdb_attach_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct timeval timeout;
	uint32_t destnode;
	uint8_t db_flags;
	struct ctdb_db_context *db;
};

static void ctdb_attach_dbid_done(struct tevent_req *subreq);
static void ctdb_attach_dbpath_done(struct tevent_req *subreq);
static void ctdb_attach_health_done(struct tevent_req *subreq);
static void ctdb_attach_flags_done(struct tevent_req *subreq);
static void ctdb_attach_open_flags_done(struct tevent_req *subreq);

struct tevent_req *ctdb_attach_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    struct timeval timeout,
				    const char *db_name, uint8_t db_flags)
{
	struct tevent_req *req, *subreq;
	struct ctdb_attach_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state, struct ctdb_attach_state);
	if (req == NULL) {
		return NULL;
	}

	state->db = client_db_handle(client, db_name);
	if (state->db != NULL) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	state->ev = ev;
	state->client = client;
	state->timeout = timeout;
	state->destnode = ctdb_client_pnn(client);
	state->db_flags = db_flags;

	state->db = talloc_zero(client, struct ctdb_db_context);
	if (tevent_req_nomem(state->db, req)) {
		return tevent_req_post(req, ev);
	}

	state->db->db_name = talloc_strdup(state->db, db_name);
	if (tevent_req_nomem(state->db, req)) {
		return tevent_req_post(req, ev);
	}

	state->db->db_flags = db_flags;

	if (ctdb_db_persistent(state->db)) {
		ctdb_req_control_db_attach_persistent(&request,
						      state->db->db_name);
	} else if (ctdb_db_replicated(state->db)) {
		ctdb_req_control_db_attach_replicated(&request,
						      state->db->db_name);
	} else {
		ctdb_req_control_db_attach(&request, state->db->db_name);
	}

	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, state->timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_attach_dbid_done, req);

	return req;
}

static void ctdb_attach_dbid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_attach_state *state = tevent_req_data(
		req, struct ctdb_attach_state);
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("attach: %s %s failed, ret=%d\n",
				  state->db->db_name,
				  (ctdb_db_persistent(state->db)
					? "DB_ATTACH_PERSISTENT"
					: (ctdb_db_replicated(state->db)
						? "DB_ATTACH_REPLICATED"
						: "DB_ATTACH")),
				  ret));
		tevent_req_error(req, ret);
		return;
	}

	if (ctdb_db_persistent(state->db)) {
		ret = ctdb_reply_control_db_attach_persistent(
				reply, &state->db->db_id);
	} else if (ctdb_db_replicated(state->db)) {
		ret = ctdb_reply_control_db_attach_replicated(
				reply, &state->db->db_id);
	} else {
		ret = ctdb_reply_control_db_attach(reply, &state->db->db_id);
	}
	talloc_free(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("attach: %s failed to get db_id, ret=%d\n",
				  state->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_getdbpath(&request, state->db->db_id);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, state->timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_attach_dbpath_done, req);
}

static void ctdb_attach_dbpath_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_attach_state *state = tevent_req_data(
		req, struct ctdb_attach_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("attach: %s GETDBPATH failed, ret=%d\n",
				  state->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_getdbpath(reply, state->db,
					   &state->db->db_path);
	talloc_free(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("attach: %s GETDBPATH parse failed, ret=%d\n",
				  state->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_db_get_health(&request, state->db->db_id);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, state->timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_attach_health_done, req);
}

static void ctdb_attach_health_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_attach_state *state = tevent_req_data(
		req, struct ctdb_attach_state);
	struct ctdb_reply_control *reply;
	const char *reason;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("attach: %s DB_GET_HEALTH failed, ret=%d\n",
				  state->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_db_get_health(reply, state, &reason);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("attach: %s DB_GET_HEALTH parse failed, ret=%d\n",
		       state->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	if (reason != NULL) {
		/* Database unhealthy, avoid attach */
		DEBUG(DEBUG_ERR, ("attach: %s database unhealthy (%s)\n",
				  state->db->db_name, reason));
		tevent_req_error(req, EIO);
		return;
	}

	subreq = ctdb_set_db_flags_send(state, state->ev, state->client,
					state->destnode, state->timeout,
					state->db->db_id, state->db_flags);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_attach_flags_done, req);
}

static void ctdb_attach_flags_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_attach_state *state = tevent_req_data(
		req, struct ctdb_attach_state);
	struct ctdb_req_control request;
	bool status;
	int ret;

	status = ctdb_set_db_flags_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("attach: %s set db flags 0x%08x failed\n",
				  state->db->db_name, state->db_flags));
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_db_open_flags(&request, state->db->db_id);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, state->timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_attach_open_flags_done, req);
}

static void ctdb_attach_open_flags_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_attach_state *state = tevent_req_data(
		req, struct ctdb_attach_state);
	struct ctdb_reply_control *reply;
	bool status;
	int ret, tdb_flags;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("attach: %s DB_OPEN_FLAGS failed, ret=%d\n",
				  state->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_db_open_flags(reply, &tdb_flags);
	talloc_free(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("attach: %s DB_OPEN_FLAGS parse failed,"
				  " ret=%d\n", state->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	state->db->ltdb = tdb_wrap_open(state->db, state->db->db_path, 0,
					tdb_flags, O_RDWR, 0);
	if (tevent_req_nomem(state->db->ltdb, req)) {
		DEBUG(DEBUG_ERR, ("attach: %s tdb_wrap_open failed\n",
				  state->db->db_name));
		return;
	}
	DLIST_ADD(state->client->db, state->db);

	tevent_req_done(req);
}

bool ctdb_attach_recv(struct tevent_req *req, int *perr,
		      struct ctdb_db_context **out)
{
	struct ctdb_attach_state *state = tevent_req_data(
		req, struct ctdb_attach_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	if (out != NULL) {
		*out = state->db;
	}
	return true;
}

int ctdb_attach(struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout,
		const char *db_name, uint8_t db_flags,
		struct ctdb_db_context **out)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_req *req;
	bool status;
	int ret;

	mem_ctx = talloc_new(client);
	if (mem_ctx == NULL) {
		return ENOMEM;
	}

	req = ctdb_attach_send(mem_ctx, ev, client, timeout,
			       db_name, db_flags);
	if (req == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_attach_recv(req, &ret, out);
	if (! status) {
		talloc_free(mem_ctx);
		return ret;
	}

	/*
	ctdb_set_call(db, CTDB_NULL_FUNC, ctdb_null_func);
	ctdb_set_call(db, CTDB_FETCH_FUNC, ctdb_fetch_func);
	ctdb_set_call(db, CTDB_FETCH_WITH_HEADER_FUNC, ctdb_fetch_with_header_func);
	*/

	talloc_free(mem_ctx);
	return 0;
}

struct ctdb_detach_state {
	struct ctdb_client_context *client;
	struct tevent_context *ev;
	struct timeval timeout;
	uint32_t db_id;
	const char *db_name;
};

static void ctdb_detach_dbname_done(struct tevent_req *subreq);
static void ctdb_detach_done(struct tevent_req *subreq);

struct tevent_req *ctdb_detach_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    struct timeval timeout, uint32_t db_id)
{
	struct tevent_req *req, *subreq;
	struct ctdb_detach_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state, struct ctdb_detach_state);
	if (req == NULL) {
		return NULL;
	}

	state->client = client;
	state->ev = ev;
	state->timeout = timeout;
	state->db_id = db_id;

	ctdb_req_control_get_dbname(&request, db_id);
	subreq = ctdb_client_control_send(state, ev, client,
					  ctdb_client_pnn(client), timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_detach_dbname_done, req);

	return req;
}

static void ctdb_detach_dbname_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_detach_state *state = tevent_req_data(
		req, struct ctdb_detach_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("detach: 0x%x GET_DBNAME failed, ret=%d\n",
				  state->db_id, ret));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_dbname(reply, state, &state->db_name);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("detach: 0x%x GET_DBNAME failed, ret=%d\n",
				  state->db_id, ret));
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_db_detach(&request, state->db_id);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  ctdb_client_pnn(state->client),
					  state->timeout, &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_detach_done, req);

}

static void ctdb_detach_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_detach_state *state = tevent_req_data(
		req, struct ctdb_detach_state);
	struct ctdb_reply_control *reply;
	struct ctdb_db_context *db;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("detach: %s DB_DETACH failed, ret=%d\n",
				  state->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_db_detach(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("detach: %s DB_DETACH failed, ret=%d\n",
				  state->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	db = client_db_handle(state->client, state->db_name);
	if (db != NULL) {
		DLIST_REMOVE(state->client->db, db);
		TALLOC_FREE(db);
	}

	tevent_req_done(req);
}

bool ctdb_detach_recv(struct tevent_req *req, int *perr)
{
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	return true;
}

int ctdb_detach(struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout, uint32_t db_id)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_req *req;
	int ret;
	bool status;

	mem_ctx = talloc_new(client);
	if (mem_ctx == NULL) {
		return ENOMEM;
	}

	req = ctdb_detach_send(mem_ctx, ev, client, timeout, db_id);
	if (req == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_detach_recv(req, &ret);
	if (! status) {
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return 0;
}

uint32_t ctdb_db_id(struct ctdb_db_context *db)
{
	return db->db_id;
}

struct ctdb_db_traverse_local_state {
	ctdb_rec_parser_func_t parser;
	void *private_data;
	bool extract_header;
	int error;
};

static int ctdb_db_traverse_local_handler(struct tdb_context *tdb,
					  TDB_DATA key, TDB_DATA data,
					  void *private_data)
{
	struct ctdb_db_traverse_local_state *state =
		(struct ctdb_db_traverse_local_state *)private_data;
	int ret;

	if (state->extract_header) {
		struct ctdb_ltdb_header header;

		ret = ctdb_ltdb_header_extract(&data, &header);
		if (ret != 0) {
			state->error = ret;
			return 1;
		}

		ret = state->parser(0, &header, key, data, state->private_data);
	} else {
		ret = state->parser(0, NULL, key, data, state->private_data);
	}

	if (ret != 0) {
		state->error = ret;
		return 1;
	}

	return 0;
}

int ctdb_db_traverse_local(struct ctdb_db_context *db, bool readonly,
			   bool extract_header,
			   ctdb_rec_parser_func_t parser, void *private_data)
{
	struct ctdb_db_traverse_local_state state;
	int ret;

	state.parser = parser;
	state.private_data = private_data;
	state.extract_header = extract_header;
	state.error = 0;

	if (readonly) {
		ret = tdb_traverse_read(client_db_tdb(db),
					ctdb_db_traverse_local_handler,
					&state);
	} else {
		ret = tdb_traverse(client_db_tdb(db),
				   ctdb_db_traverse_local_handler, &state);
	}

	if (ret == -1) {
		return EIO;
	}

	return state.error;
}

struct ctdb_db_traverse_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *db;
	uint32_t destnode;
	uint64_t srvid;
	struct timeval timeout;
	ctdb_rec_parser_func_t parser;
	void *private_data;
	int result;
};

static void ctdb_db_traverse_handler_set(struct tevent_req *subreq);
static void ctdb_db_traverse_started(struct tevent_req *subreq);
static void ctdb_db_traverse_handler(uint64_t srvid, TDB_DATA data,
				     void *private_data);
static void ctdb_db_traverse_remove_handler(struct tevent_req *req);
static void ctdb_db_traverse_handler_removed(struct tevent_req *subreq);

struct tevent_req *ctdb_db_traverse_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_db_context *db,
					 uint32_t destnode,
					 struct timeval timeout,
					 ctdb_rec_parser_func_t parser,
					 void *private_data)
{
	struct tevent_req *req, *subreq;
	struct ctdb_db_traverse_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_db_traverse_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->db = db;
	state->destnode = destnode;
	state->srvid = CTDB_SRVID_CLIENT_RANGE | getpid();
	state->timeout = timeout;
	state->parser = parser;
	state->private_data = private_data;

	subreq = ctdb_client_set_message_handler_send(state, ev, client,
						      state->srvid,
						      ctdb_db_traverse_handler,
						      req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_db_traverse_handler_set, req);

	return req;
}

static void ctdb_db_traverse_handler_set(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_db_traverse_state *state = tevent_req_data(
		req, struct ctdb_db_traverse_state);
	struct ctdb_traverse_start_ext traverse;
	struct ctdb_req_control request;
	int ret = 0;
	bool status;

	status = ctdb_client_set_message_handler_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	traverse = (struct ctdb_traverse_start_ext) {
		.db_id = ctdb_db_id(state->db),
		.reqid = 0,
		.srvid = state->srvid,
		.withemptyrecords = false,
	};

	ctdb_req_control_traverse_start_ext(&request, &traverse);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, state->timeout,
					  &request);
	if (subreq == NULL) {
		state->result = ENOMEM;
		ctdb_db_traverse_remove_handler(req);
		return;
	}
	tevent_req_set_callback(subreq, ctdb_db_traverse_started, req);
}

static void ctdb_db_traverse_started(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_db_traverse_state *state = tevent_req_data(
		req, struct ctdb_db_traverse_state);
	struct ctdb_reply_control *reply;
	int ret = 0;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("traverse: control failed, ret=%d\n", ret));
		state->result = ret;
		ctdb_db_traverse_remove_handler(req);
		return;
	}

	ret = ctdb_reply_control_traverse_start_ext(reply);
	talloc_free(reply);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("traverse: control reply failed, ret=%d\n",
				  ret));
		state->result = ret;
		ctdb_db_traverse_remove_handler(req);
		return;
	}
}

static void ctdb_db_traverse_handler(uint64_t srvid, TDB_DATA data,
				     void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct ctdb_db_traverse_state *state = tevent_req_data(
		req, struct ctdb_db_traverse_state);
	struct ctdb_rec_data *rec;
	struct ctdb_ltdb_header header;
	size_t np;
	int ret;

	ret = ctdb_rec_data_pull(data.dptr, data.dsize, state, &rec, &np);
	if (ret != 0) {
		return;
	}

	if (rec->key.dsize == 0 && rec->data.dsize == 0) {
		talloc_free(rec);
		ctdb_db_traverse_remove_handler(req);
		return;
	}

	ret = ctdb_ltdb_header_extract(&rec->data, &header);
	if (ret != 0) {
		talloc_free(rec);
		return;
	}

	if (rec->data.dsize == 0) {
		talloc_free(rec);
		return;
	}

	ret = state->parser(rec->reqid, &header, rec->key, rec->data,
			    state->private_data);
	talloc_free(rec);
	if (ret != 0) {
		state->result = ret;
		ctdb_db_traverse_remove_handler(req);
	}
}

static void ctdb_db_traverse_remove_handler(struct tevent_req *req)
{
	struct ctdb_db_traverse_state *state = tevent_req_data(
		req, struct ctdb_db_traverse_state);
	struct tevent_req *subreq;

	subreq = ctdb_client_remove_message_handler_send(state, state->ev,
							 state->client,
							 state->srvid, req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_db_traverse_handler_removed, req);
}

static void ctdb_db_traverse_handler_removed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_db_traverse_state *state = tevent_req_data(
		req, struct ctdb_db_traverse_state);
	int ret;
	bool status;

	status = ctdb_client_remove_message_handler_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	if (state->result != 0) {
		tevent_req_error(req, state->result);
		return;
	}

	tevent_req_done(req);
}

bool ctdb_db_traverse_recv(struct tevent_req *req, int *perr)
{
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	return true;
}

int ctdb_db_traverse(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		     struct ctdb_client_context *client,
		     struct ctdb_db_context *db,
		     uint32_t destnode, struct timeval timeout,
		     ctdb_rec_parser_func_t parser, void *private_data)
{
	struct tevent_req *req;
	int ret = 0;
	bool status;

	req = ctdb_db_traverse_send(mem_ctx, ev, client, db, destnode,
				    timeout, parser, private_data);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_db_traverse_recv(req, &ret);
	if (! status) {
		return ret;
	}

	return 0;
}

int ctdb_ltdb_fetch(struct ctdb_db_context *db, TDB_DATA key,
		    struct ctdb_ltdb_header *header,
		    TALLOC_CTX *mem_ctx, TDB_DATA *data)
{
	TDB_DATA rec;
	size_t np;
	int ret;

	rec = tdb_fetch(client_db_tdb(db), key);
	if (rec.dsize < sizeof(struct ctdb_ltdb_header)) {
		/* No record present */
		if (rec.dptr != NULL) {
			free(rec.dptr);
		}

		if (tdb_error(client_db_tdb(db)) != TDB_ERR_NOEXIST) {
			return EIO;
		}

		*header = (struct ctdb_ltdb_header) {
			.dmaster = CTDB_UNKNOWN_PNN,
		};

		if (data != NULL) {
			*data = tdb_null;
		}
		return 0;
	}

	ret = ctdb_ltdb_header_pull(rec.dptr, rec.dsize, header, &np);
	if (ret != 0) {
		return ret;
	}

	ret = 0;
	if (data != NULL) {
		data->dsize = rec.dsize - np;
		data->dptr = talloc_memdup(mem_ctx, rec.dptr + np,
					   data->dsize);
		if (data->dptr == NULL) {
			ret = ENOMEM;
		}
	}

	free(rec.dptr);
	return ret;
}

/*
 * Fetch a record from volatile database
 *
 * Steps:
 *  1. Get a lock on the hash chain
 *  2. If the record does not exist, migrate the record
 *  3. If readonly=true and delegations do not exist, migrate the record.
 *  4. If readonly=false and delegations exist, migrate the record.
 *  5. If the local node is not dmaster, migrate the record.
 *  6. Return record
 */

struct ctdb_fetch_lock_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_record_handle *h;
	bool readonly;
	uint32_t pnn;
};

static int ctdb_fetch_lock_check(struct tevent_req *req);
static void ctdb_fetch_lock_migrate(struct tevent_req *req);
static void ctdb_fetch_lock_migrate_done(struct tevent_req *subreq);

struct tevent_req *ctdb_fetch_lock_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					struct ctdb_db_context *db,
					TDB_DATA key, bool readonly)
{
	struct ctdb_fetch_lock_state *state;
	struct tevent_req *req;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct ctdb_fetch_lock_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;

	state->h = talloc_zero(db, struct ctdb_record_handle);
	if (tevent_req_nomem(state->h, req)) {
		return tevent_req_post(req, ev);
	}
	state->h->ev = ev;
	state->h->client = client;
	state->h->db = db;
	state->h->key.dptr = talloc_memdup(state->h, key.dptr, key.dsize);
	if (tevent_req_nomem(state->h->key.dptr, req)) {
		return tevent_req_post(req, ev);
	}
	state->h->key.dsize = key.dsize;
	state->h->readonly = false;

	state->readonly = readonly;
	state->pnn = ctdb_client_pnn(client);

	/* Check that database is not persistent */
	if (! ctdb_db_volatile(db)) {
		DEBUG(DEBUG_ERR, ("fetch_lock: %s database not volatile\n",
				  db->db_name));
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_fetch_lock_check(req);
	if (ret == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (ret != EAGAIN) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}
	return req;
}

static int ctdb_fetch_lock_check(struct tevent_req *req)
{
	struct ctdb_fetch_lock_state *state = tevent_req_data(
		req, struct ctdb_fetch_lock_state);
	struct ctdb_record_handle *h = state->h;
	struct ctdb_ltdb_header header;
	TDB_DATA data = tdb_null;
	size_t np;
	int ret, err = 0;
	bool do_migrate = false;

	ret = tdb_chainlock(client_db_tdb(h->db), h->key);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("fetch_lock: %s tdb_chainlock failed, %s\n",
		       h->db->db_name, tdb_errorstr(client_db_tdb(h->db))));
		err = EIO;
		goto failed;
	}

	data = tdb_fetch(client_db_tdb(h->db), h->key);
	if (data.dptr == NULL) {
		if (tdb_error(client_db_tdb(h->db)) == TDB_ERR_NOEXIST) {
			goto migrate;
		} else {
			err = EIO;
			goto failed;
		}
	}

	/* Got the record */
	ret = ctdb_ltdb_header_pull(data.dptr, data.dsize, &header, &np);
	if (ret != 0) {
		err = ret;
		goto failed;
	}

	if (! state->readonly) {
		/* Read/write access */
		if (header.dmaster == state->pnn &&
		    header.flags & CTDB_REC_RO_HAVE_DELEGATIONS) {
			goto migrate;
		}

		if (header.dmaster != state->pnn) {
			goto migrate;
		}
	} else {
		/* Readonly access */
		if (header.dmaster != state->pnn &&
		    ! (header.flags & (CTDB_REC_RO_HAVE_READONLY |
				       CTDB_REC_RO_HAVE_DELEGATIONS))) {
			goto migrate;
		}
	}

	/* We are the dmaster or readonly delegation */
	h->header = header;
	h->data = data;
	if (header.flags & (CTDB_REC_RO_HAVE_READONLY |
			    CTDB_REC_RO_HAVE_DELEGATIONS)) {
		h->readonly = true;
	}
	return 0;

migrate:
	do_migrate = true;
	err = EAGAIN;

failed:
	if (data.dptr != NULL) {
		free(data.dptr);
	}
	ret = tdb_chainunlock(client_db_tdb(h->db), h->key);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("fetch_lock: %s tdb_chainunlock failed, %s\n",
		       h->db->db_name, tdb_errorstr(client_db_tdb(h->db))));
		return EIO;
	}

	if (do_migrate) {
		ctdb_fetch_lock_migrate(req);
	}
	return err;
}

static void ctdb_fetch_lock_migrate(struct tevent_req *req)
{
	struct ctdb_fetch_lock_state *state = tevent_req_data(
		req, struct ctdb_fetch_lock_state);
	struct ctdb_req_call request;
	struct tevent_req *subreq;

	ZERO_STRUCT(request);
	request.flags = CTDB_IMMEDIATE_MIGRATION;
	if (state->readonly) {
		request.flags |= CTDB_WANT_READONLY;
	}
	request.db_id = state->h->db->db_id;
	request.callid = CTDB_NULL_FUNC;
	request.key = state->h->key;
	request.calldata = tdb_null;

	subreq = ctdb_client_call_send(state, state->ev, state->client,
				       &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, ctdb_fetch_lock_migrate_done, req);
}

static void ctdb_fetch_lock_migrate_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_fetch_lock_state *state = tevent_req_data(
		req, struct ctdb_fetch_lock_state);
	struct ctdb_reply_call *reply;
	int ret;
	bool status;

	status = ctdb_client_call_recv(subreq, state, &reply, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR, ("fetch_lock: %s CALL failed, ret=%d\n",
				  state->h->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	if (reply->status != 0) {
		tevent_req_error(req, EIO);
		return;
	}
	talloc_free(reply);

	ret = ctdb_fetch_lock_check(req);
	if (ret != 0) {
		if (ret != EAGAIN) {
			tevent_req_error(req, ret);
		}
		return;
	}

	tevent_req_done(req);
}

static int ctdb_record_handle_destructor(struct ctdb_record_handle *h)
{
	int ret;

	ret = tdb_chainunlock(client_db_tdb(h->db), h->key);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("fetch_lock: %s tdb_chainunlock failed, %s\n",
		       h->db->db_name, tdb_errorstr(client_db_tdb(h->db))));
	}
	free(h->data.dptr);
	return 0;
}

struct ctdb_record_handle *ctdb_fetch_lock_recv(struct tevent_req *req,
						struct ctdb_ltdb_header *header,
						TALLOC_CTX *mem_ctx,
						TDB_DATA *data, int *perr)
{
	struct ctdb_fetch_lock_state *state = tevent_req_data(
		req, struct ctdb_fetch_lock_state);
	struct ctdb_record_handle *h = state->h;
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			TALLOC_FREE(state->h);
			*perr = err;
		}
		return NULL;
	}

	if (header != NULL) {
		*header = h->header;
	}
	if (data != NULL) {
		size_t offset;

		offset = ctdb_ltdb_header_len(&h->header);

		data->dsize = h->data.dsize - offset;
		if (data->dsize == 0) {
			data->dptr = NULL;
		} else {
			data->dptr = talloc_memdup(mem_ctx,
						   h->data.dptr + offset,
						   data->dsize);
			if (data->dptr == NULL) {
				TALLOC_FREE(state->h);
				if (perr != NULL) {
					*perr = ENOMEM;
				}
				return NULL;
			}
		}
	}

	talloc_set_destructor(h, ctdb_record_handle_destructor);
	return h;
}

int ctdb_fetch_lock(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		    struct ctdb_client_context *client,
		    struct ctdb_db_context *db, TDB_DATA key, bool readonly,
		    struct ctdb_record_handle **out,
		    struct ctdb_ltdb_header *header, TDB_DATA *data)
{
	struct tevent_req *req;
	struct ctdb_record_handle *h;
	int ret = 0;

	req = ctdb_fetch_lock_send(mem_ctx, ev, client, db, key, readonly);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	h = ctdb_fetch_lock_recv(req, header, mem_ctx, data, &ret);
	if (h == NULL) {
		return ret;
	}

	*out = h;
	return 0;
}

int ctdb_store_record(struct ctdb_record_handle *h, TDB_DATA data)
{
	uint8_t header[sizeof(struct ctdb_ltdb_header)];
	TDB_DATA rec[2];
	size_t np;
	int ret;

	/* Cannot modify the record if it was obtained as a readonly copy */
	if (h->readonly) {
		return EINVAL;
	}

	/* Check if the new data is same */
	if (h->data.dsize == data.dsize &&
	    memcmp(h->data.dptr, data.dptr, data.dsize) == 0) {
		/* No need to do anything */
		return 0;
	}

	ctdb_ltdb_header_push(&h->header, header, &np);

	rec[0].dsize = np;
	rec[0].dptr = header;

	rec[1].dsize = data.dsize;
	rec[1].dptr = data.dptr;

	ret = tdb_storev(client_db_tdb(h->db), h->key, rec, 2, TDB_REPLACE);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("store_record: %s tdb_storev failed, %s\n",
		       h->db->db_name, tdb_errorstr(client_db_tdb(h->db))));
		return EIO;
	}

	return 0;
}

struct ctdb_delete_record_state {
	struct ctdb_record_handle *h;
};

static void ctdb_delete_record_done(struct tevent_req *subreq);

struct tevent_req *ctdb_delete_record_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_record_handle *h)
{
	struct tevent_req *req, *subreq;
	struct ctdb_delete_record_state *state;
	struct ctdb_key_data key;
	struct ctdb_req_control request;
	uint8_t header[sizeof(struct ctdb_ltdb_header)];
	TDB_DATA rec;
	size_t  np;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_delete_record_state);
	if (req == NULL) {
		return NULL;
	}

	state->h = h;

	/* Cannot delete the record if it was obtained as a readonly copy */
	if (h->readonly) {
		DEBUG(DEBUG_ERR, ("fetch_lock delete: %s readonly record\n",
				  h->db->db_name));
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	ctdb_ltdb_header_push(&h->header, header, &np);

	rec.dsize = np;
	rec.dptr = header;

	ret = tdb_store(client_db_tdb(h->db), h->key, rec, TDB_REPLACE);
	if (ret != 0) {
		D_ERR("fetch_lock delete: %s tdb_store failed, %s\n",
		      h->db->db_name,
		      tdb_errorstr(client_db_tdb(h->db)));
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	key.db_id = h->db->db_id;
	key.header = h->header;
	key.key = h->key;

	ctdb_req_control_schedule_for_deletion(&request, &key);
	subreq = ctdb_client_control_send(state, ev, h->client,
					  ctdb_client_pnn(h->client),
					  tevent_timeval_zero(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_delete_record_done, req);

	return req;
}

static void ctdb_delete_record_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_delete_record_state *state = tevent_req_data(
		req, struct ctdb_delete_record_state);
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, NULL, NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("delete_record: %s SCHEDULE_FOR_DELETION failed, ret=%d\n",
		      state->h->db->db_name,
		      ret);
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

bool ctdb_delete_record_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}


int ctdb_delete_record(struct ctdb_record_handle *h)
{
	struct tevent_context *ev = h->ev;
	TALLOC_CTX *mem_ctx;
	struct tevent_req *req;
	int ret;
	bool status;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return ENOMEM;
	}

	req = ctdb_delete_record_send(mem_ctx, ev, h);
	if (req == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_delete_record_recv(req, &ret);
	talloc_free(mem_ctx);
	if (! status) {
		return ret;
	}

	return 0;
}

/*
 * Global lock functions
 */

struct ctdb_g_lock_lock_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *db;
	TDB_DATA key;
	struct ctdb_server_id my_sid;
	enum ctdb_g_lock_type lock_type;
	struct ctdb_record_handle *h;
	/* state for verification of active locks */
	struct ctdb_g_lock_list *lock_list;
	unsigned int current;
};

static void ctdb_g_lock_lock_fetched(struct tevent_req *subreq);
static void ctdb_g_lock_lock_process_locks(struct tevent_req *req);
static void ctdb_g_lock_lock_checked(struct tevent_req *subreq);
static int ctdb_g_lock_lock_update(struct tevent_req *req);
static void ctdb_g_lock_lock_retry(struct tevent_req *subreq);

static bool ctdb_g_lock_conflicts(enum ctdb_g_lock_type l1,
				  enum ctdb_g_lock_type l2)
{
	if ((l1 == CTDB_G_LOCK_READ) && (l2 == CTDB_G_LOCK_READ)) {
		return false;
	}
	return true;
}

struct tevent_req *ctdb_g_lock_lock_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_db_context *db,
					 const char *keyname,
					 struct ctdb_server_id *sid,
					 bool readonly)
{
	struct tevent_req *req, *subreq;
	struct ctdb_g_lock_lock_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_g_lock_lock_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->db = db;
	state->key.dptr = discard_const(keyname);
	state->key.dsize = strlen(keyname) + 1;
	state->my_sid = *sid;
	state->lock_type = (readonly ? CTDB_G_LOCK_READ : CTDB_G_LOCK_WRITE);

	subreq = ctdb_fetch_lock_send(state, ev, client, db, state->key,
				      false);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_g_lock_lock_fetched, req);

	return req;
}

static void ctdb_g_lock_lock_fetched(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_g_lock_lock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_lock_state);
	TDB_DATA data;
	size_t np;
	int ret = 0;

	state->h = ctdb_fetch_lock_recv(subreq, NULL, state, &data, &ret);
	TALLOC_FREE(subreq);
	if (state->h == NULL) {
		DEBUG(DEBUG_ERR, ("g_lock_lock: %s fetch lock failed\n",
				  (char *)state->key.dptr));
		tevent_req_error(req, ret);
		return;
	}

	if (state->lock_list != NULL) {
		TALLOC_FREE(state->lock_list);
		state->current = 0;
	}

	ret = ctdb_g_lock_list_pull(data.dptr, data.dsize, state,
				    &state->lock_list, &np);
	talloc_free(data.dptr);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("g_lock_lock: %s invalid lock data\n",
				  (char *)state->key.dptr));
		tevent_req_error(req, ret);
		return;
	}

	ctdb_g_lock_lock_process_locks(req);
}

static void ctdb_g_lock_lock_process_locks(struct tevent_req *req)
{
	struct ctdb_g_lock_lock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_lock_state);
	struct tevent_req *subreq;
	struct ctdb_g_lock *lock;
	bool check_server = false;
	int ret;

	while (state->current < state->lock_list->num) {
		lock = &state->lock_list->lock[state->current];

		/* We should not ask for the same lock more than once */
		if (ctdb_server_id_equal(&lock->sid, &state->my_sid)) {
			DEBUG(DEBUG_ERR, ("g_lock_lock: %s deadlock\n",
					  (char *)state->key.dptr));
			tevent_req_error(req, EDEADLK);
			return;
		}

		if (ctdb_g_lock_conflicts(lock->type, state->lock_type)) {
			check_server = true;
			break;
		}

		state->current += 1;
	}

	if (check_server) {
		struct ctdb_req_control request;

		ctdb_req_control_process_exists(&request, lock->sid.pid);
		subreq = ctdb_client_control_send(state, state->ev,
						  state->client,
						  lock->sid.vnn,
						  tevent_timeval_zero(),
						  &request);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, ctdb_g_lock_lock_checked, req);
		return;
	}

	/* There is no conflict, add ourself to the lock_list */
	state->lock_list->lock = talloc_realloc(state->lock_list,
						state->lock_list->lock,
						struct ctdb_g_lock,
						state->lock_list->num + 1);
	if (state->lock_list->lock == NULL) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	lock = &state->lock_list->lock[state->lock_list->num];
	lock->type = state->lock_type;
	lock->sid = state->my_sid;
	state->lock_list->num += 1;

	ret = ctdb_g_lock_lock_update(req);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	TALLOC_FREE(state->h);
	tevent_req_done(req);
}

static void ctdb_g_lock_lock_checked(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_g_lock_lock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_lock_state);
	struct ctdb_reply_control *reply;
	int ret, value;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("g_lock_lock: %s PROCESS_EXISTS failed, ret=%d\n",
		       (char *)state->key.dptr, ret));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_process_exists(reply, &value);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}
	talloc_free(reply);

	if (value == 0) {
		/* server process exists, need to retry */
		TALLOC_FREE(state->h);
		subreq = tevent_wakeup_send(state, state->ev,
					    tevent_timeval_current_ofs(0,1000));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, ctdb_g_lock_lock_retry, req);
		return;
	}

	/* server process does not exist, remove conflicting entry */
	state->lock_list->lock[state->current] =
		state->lock_list->lock[state->lock_list->num-1];
	state->lock_list->num -= 1;

	ret = ctdb_g_lock_lock_update(req);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ctdb_g_lock_lock_process_locks(req);
}

static int ctdb_g_lock_lock_update(struct tevent_req *req)
{
	struct ctdb_g_lock_lock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_lock_state);
	TDB_DATA data;
	size_t np;
	int ret;

	data.dsize = ctdb_g_lock_list_len(state->lock_list);
	data.dptr = talloc_size(state, data.dsize);
	if (data.dptr == NULL) {
		return ENOMEM;
	}

	ctdb_g_lock_list_push(state->lock_list, data.dptr, &np);
	ret = ctdb_store_record(state->h, data);
	talloc_free(data.dptr);
	return ret;
}

static void ctdb_g_lock_lock_retry(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_g_lock_lock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_lock_state);
	bool success;

	success = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! success) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	subreq = ctdb_fetch_lock_send(state, state->ev, state->client,
				      state->db, state->key, false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_g_lock_lock_fetched, req);
}

bool ctdb_g_lock_lock_recv(struct tevent_req *req, int *perr)
{
	struct ctdb_g_lock_lock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_lock_state);
	int err;

	TALLOC_FREE(state->h);

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}

struct ctdb_g_lock_unlock_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *db;
	TDB_DATA key;
	struct ctdb_server_id my_sid;
	struct ctdb_record_handle *h;
	struct ctdb_g_lock_list *lock_list;
};

static void ctdb_g_lock_unlock_fetched(struct tevent_req *subreq);
static int ctdb_g_lock_unlock_update(struct tevent_req *req);
static void ctdb_g_lock_unlock_deleted(struct tevent_req *subreq);

struct tevent_req *ctdb_g_lock_unlock_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client,
					   struct ctdb_db_context *db,
					   const char *keyname,
					   struct ctdb_server_id sid)
{
	struct tevent_req *req, *subreq;
	struct ctdb_g_lock_unlock_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_g_lock_unlock_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->db = db;
	state->key.dptr = discard_const(keyname);
	state->key.dsize = strlen(keyname) + 1;
	state->my_sid = sid;

	subreq = ctdb_fetch_lock_send(state, ev, client, db, state->key,
				      false);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_g_lock_unlock_fetched, req);

	return req;
}

static void ctdb_g_lock_unlock_fetched(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_g_lock_unlock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_unlock_state);
	TDB_DATA data;
	size_t np;
	int ret = 0;

	state->h = ctdb_fetch_lock_recv(subreq, NULL, state, &data, &ret);
	TALLOC_FREE(subreq);
	if (state->h == NULL) {
		DEBUG(DEBUG_ERR, ("g_lock_unlock: %s fetch lock failed\n",
				  (char *)state->key.dptr));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_g_lock_list_pull(data.dptr, data.dsize, state,
				    &state->lock_list, &np);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("g_lock_unlock: %s invalid lock data\n",
				  (char *)state->key.dptr));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_g_lock_unlock_update(req);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	if (state->lock_list->num == 0) {
		subreq = ctdb_delete_record_send(state, state->ev, state->h);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, ctdb_g_lock_unlock_deleted,
					req);
		return;
	}

	TALLOC_FREE(state->h);
	tevent_req_done(req);
}

static int ctdb_g_lock_unlock_update(struct tevent_req *req)
{
	struct ctdb_g_lock_unlock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_unlock_state);
	struct ctdb_g_lock *lock;
	unsigned int i;
	int ret;

	for (i=0; i<state->lock_list->num; i++) {
		lock = &state->lock_list->lock[i];

		if (ctdb_server_id_equal(&lock->sid, &state->my_sid)) {
			break;
		}
	}

	if (i < state->lock_list->num) {
		state->lock_list->lock[i] =
			state->lock_list->lock[state->lock_list->num-1];
		state->lock_list->num -= 1;
	}

	if (state->lock_list->num != 0) {
		TDB_DATA data;
		size_t np;

		data.dsize = ctdb_g_lock_list_len(state->lock_list);
		data.dptr = talloc_size(state, data.dsize);
		if (data.dptr == NULL) {
			return ENOMEM;
		}

		ctdb_g_lock_list_push(state->lock_list, data.dptr, &np);
		ret = ctdb_store_record(state->h, data);
		talloc_free(data.dptr);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

static void ctdb_g_lock_unlock_deleted(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_g_lock_unlock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_unlock_state);
	int ret;
	bool status;

	status = ctdb_delete_record_recv(subreq, &ret);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("g_lock_unlock %s delete record failed, ret=%d\n",
		       (char *)state->key.dptr, ret));
		tevent_req_error(req, ret);
		return;
	}

	TALLOC_FREE(state->h);
	tevent_req_done(req);
}

bool ctdb_g_lock_unlock_recv(struct tevent_req *req, int *perr)
{
	struct ctdb_g_lock_unlock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_unlock_state);
	int err;

	TALLOC_FREE(state->h);

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}

/*
 * Persistent database functions
 */
struct ctdb_transaction_start_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct timeval timeout;
	struct ctdb_transaction_handle *h;
	uint32_t destnode;
};

static void ctdb_transaction_g_lock_attached(struct tevent_req *subreq);
static void ctdb_transaction_g_lock_done(struct tevent_req *subreq);

struct tevent_req *ctdb_transaction_start_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct ctdb_client_context *client,
					       struct timeval timeout,
					       struct ctdb_db_context *db,
					       bool readonly)
{
	struct ctdb_transaction_start_state *state;
	struct tevent_req *req, *subreq;
	struct ctdb_transaction_handle *h;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_transaction_start_state);
	if (req == NULL) {
		return NULL;
	}

	if (ctdb_db_volatile(db)) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	state->ev = ev;
	state->client = client;
	state->destnode = ctdb_client_pnn(client);

	h = talloc_zero(db, struct ctdb_transaction_handle);
	if (tevent_req_nomem(h, req)) {
		return tevent_req_post(req, ev);
	}

	h->ev = ev;
	h->client = client;
	h->db = db;
	h->readonly = readonly;
	h->updated = false;

	/* SRVID is unique for databases, so client can have transactions
	 * active for multiple databases */
	h->sid = ctdb_client_get_server_id(client, db->db_id);

	h->recbuf = ctdb_rec_buffer_init(h, db->db_id);
	if (tevent_req_nomem(h->recbuf, req)) {
		return tevent_req_post(req, ev);
	}

	h->lock_name = talloc_asprintf(h, "transaction_db_0x%08x", db->db_id);
	if (tevent_req_nomem(h->lock_name, req)) {
		return tevent_req_post(req, ev);
	}

	state->h = h;

	subreq = ctdb_attach_send(state, ev, client, timeout, "g_lock.tdb", 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_transaction_g_lock_attached, req);

	return req;
}

static void ctdb_transaction_g_lock_attached(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_transaction_start_state *state = tevent_req_data(
		req, struct ctdb_transaction_start_state);
	bool status;
	int ret;

	status = ctdb_attach_recv(subreq, &ret, &state->h->db_g_lock);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("transaction_start: %s attach g_lock.tdb failed\n",
		       state->h->db->db_name));
		tevent_req_error(req, ret);
		return;
	}

	subreq = ctdb_g_lock_lock_send(state, state->ev, state->client,
				       state->h->db_g_lock,
				       state->h->lock_name,
				       &state->h->sid, state->h->readonly);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_transaction_g_lock_done, req);
}

static void ctdb_transaction_g_lock_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_transaction_start_state *state = tevent_req_data(
		req, struct ctdb_transaction_start_state);
	int ret;
	bool status;

	status = ctdb_g_lock_lock_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("transaction_start: %s g_lock lock failed, ret=%d\n",
		       state->h->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

struct ctdb_transaction_handle *ctdb_transaction_start_recv(
					struct tevent_req *req,
					int *perr)
{
	struct ctdb_transaction_start_state *state = tevent_req_data(
		req, struct ctdb_transaction_start_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return NULL;
	}

	return state->h;
}

int ctdb_transaction_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   struct timeval timeout,
			   struct ctdb_db_context *db, bool readonly,
			   struct ctdb_transaction_handle **out)
{
	struct tevent_req *req;
	struct ctdb_transaction_handle *h;
	int ret = 0;

	req = ctdb_transaction_start_send(mem_ctx, ev, client, timeout, db,
					  readonly);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	h = ctdb_transaction_start_recv(req, &ret);
	if (h == NULL) {
		return ret;
	}

	*out = h;
	return 0;
}

struct ctdb_transaction_record_fetch_state {
	TDB_DATA key, data;
	struct ctdb_ltdb_header header;
	bool found;
};

static int ctdb_transaction_record_fetch_traverse(
				uint32_t reqid,
				struct ctdb_ltdb_header *nullheader,
				TDB_DATA key, TDB_DATA data,
				void *private_data)
{
	struct ctdb_transaction_record_fetch_state *state =
		(struct ctdb_transaction_record_fetch_state *)private_data;

	if (state->key.dsize == key.dsize &&
	    memcmp(state->key.dptr, key.dptr, key.dsize) == 0) {
		int ret;

		ret = ctdb_ltdb_header_extract(&data, &state->header);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,
			      ("record_fetch: Failed to extract header, "
			       "ret=%d\n", ret));
			return 1;
		}

		state->data = data;
		state->found = true;
	}

	return 0;
}

static int ctdb_transaction_record_fetch(struct ctdb_transaction_handle *h,
					 TDB_DATA key,
					 struct ctdb_ltdb_header *header,
					 TDB_DATA *data)
{
	struct ctdb_transaction_record_fetch_state state;
	int ret;

	state.key = key;
	state.found = false;

	ret = ctdb_rec_buffer_traverse(h->recbuf,
				       ctdb_transaction_record_fetch_traverse,
				       &state);
	if (ret != 0) {
		return ret;
	}

	if (state.found) {
		if (header != NULL) {
			*header = state.header;
		}
		if (data != NULL) {
			*data = state.data;
		}
		return 0;
	}

	return ENOENT;
}

int ctdb_transaction_fetch_record(struct ctdb_transaction_handle *h,
				  TDB_DATA key,
				  TALLOC_CTX *mem_ctx, TDB_DATA *data)
{
	TDB_DATA tmp_data;
	struct ctdb_ltdb_header header;
	int ret;

	ret = ctdb_transaction_record_fetch(h, key, NULL, &tmp_data);
	if (ret == 0) {
		data->dptr = talloc_memdup(mem_ctx, tmp_data.dptr,
					   tmp_data.dsize);
		if (data->dptr == NULL) {
			return ENOMEM;
		}
		data->dsize = tmp_data.dsize;
		return 0;
	}

	ret = ctdb_ltdb_fetch(h->db, key, &header, mem_ctx, data);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_rec_buffer_add(h, h->recbuf, 0, &header, key, *data);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

int ctdb_transaction_store_record(struct ctdb_transaction_handle *h,
				  TDB_DATA key, TDB_DATA data)
{
	TALLOC_CTX *tmp_ctx;
	struct ctdb_ltdb_header header;
	TDB_DATA old_data;
	int ret;

	if (h->readonly) {
		return EINVAL;
	}

	tmp_ctx = talloc_new(h);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	ret = ctdb_transaction_record_fetch(h, key, &header, &old_data);
	if (ret != 0) {
		ret = ctdb_ltdb_fetch(h->db, key, &header, tmp_ctx, &old_data);
		if (ret != 0) {
			return ret;
		}
	}

	if (old_data.dsize == data.dsize &&
	    memcmp(old_data.dptr, data.dptr, data.dsize) == 0) {
		talloc_free(tmp_ctx);
		return 0;
	}

	header.dmaster = ctdb_client_pnn(h->client);
	header.rsn += 1;

	ret = ctdb_rec_buffer_add(h, h->recbuf, 0, &header, key, data);
	talloc_free(tmp_ctx);
	if (ret != 0) {
		return ret;
	}
	h->updated = true;

	return 0;
}

int ctdb_transaction_delete_record(struct ctdb_transaction_handle *h,
				   TDB_DATA key)
{
	return ctdb_transaction_store_record(h, key, tdb_null);
}

static int ctdb_transaction_fetch_db_seqnum(struct ctdb_transaction_handle *h,
					    uint64_t *seqnum)
{
	const char *keyname = CTDB_DB_SEQNUM_KEY;
	TDB_DATA key, data;
	struct ctdb_ltdb_header header;
	int ret;

	key.dptr = discard_const(keyname);
	key.dsize = strlen(keyname) + 1;

	ret = ctdb_ltdb_fetch(h->db, key, &header, h, &data);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("transaction_commit: %s seqnum fetch failed, ret=%d\n",
		       h->db->db_name, ret));
		return ret;
	}

	if (data.dsize == 0) {
		/* initial data */
		*seqnum = 0;
		return 0;
	}

	if (data.dsize != sizeof(uint64_t)) {
		talloc_free(data.dptr);
		return EINVAL;
	}

	*seqnum = *(uint64_t *)data.dptr;

	talloc_free(data.dptr);
	return 0;
}

static int ctdb_transaction_store_db_seqnum(struct ctdb_transaction_handle *h,
					    uint64_t seqnum)
{
	const char *keyname = CTDB_DB_SEQNUM_KEY;
	TDB_DATA key, data;

	key.dptr = discard_const(keyname);
	key.dsize = strlen(keyname) + 1;

	data.dptr = (uint8_t *)&seqnum;
	data.dsize = sizeof(seqnum);

	return ctdb_transaction_store_record(h, key, data);
}

struct ctdb_transaction_commit_state {
	struct tevent_context *ev;
	struct timeval timeout;
	struct ctdb_transaction_handle *h;
	uint64_t seqnum;
};

static void ctdb_transaction_commit_done(struct tevent_req *subreq);
static void ctdb_transaction_commit_g_lock_done(struct tevent_req *subreq);

struct tevent_req *ctdb_transaction_commit_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct timeval timeout,
					struct ctdb_transaction_handle *h)
{
	struct tevent_req *req, *subreq;
	struct ctdb_transaction_commit_state *state;
	struct ctdb_req_control request;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_transaction_commit_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->timeout = timeout;
	state->h = h;

	ret = ctdb_transaction_fetch_db_seqnum(h, &state->seqnum);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_transaction_store_db_seqnum(h, state->seqnum+1);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ctdb_req_control_trans3_commit(&request, h->recbuf);
	subreq = ctdb_client_control_send(state, ev, h->client,
					  ctdb_client_pnn(h->client),
					  timeout, &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_transaction_commit_done, req);

	return req;
}

static void ctdb_transaction_commit_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_transaction_commit_state *state = tevent_req_data(
		req, struct ctdb_transaction_commit_state);
	struct ctdb_transaction_handle *h = state->h;
	struct ctdb_reply_control *reply;
	uint64_t seqnum;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("transaction_commit: %s TRANS3_COMMIT failed, ret=%d\n",
		       h->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_trans3_commit(reply);
	talloc_free(reply);

	if (ret != 0) {
		/* Control failed due to recovery */

		ret = ctdb_transaction_fetch_db_seqnum(h, &seqnum);
		if (ret != 0) {
			tevent_req_error(req, ret);
			return;
		}

		if (seqnum == state->seqnum) {
			struct ctdb_req_control request;

			/* try again */
			ctdb_req_control_trans3_commit(&request,
						       state->h->recbuf);
			subreq = ctdb_client_control_send(
					state, state->ev, state->h->client,
					ctdb_client_pnn(state->h->client),
					state->timeout, &request);
			if (tevent_req_nomem(subreq, req)) {
				return;
			}
			tevent_req_set_callback(subreq,
						ctdb_transaction_commit_done,
						req);
			return;
		}

		if (seqnum != state->seqnum + 1) {
			DEBUG(DEBUG_ERR,
			      ("transaction_commit: %s seqnum mismatch "
			       "0x%"PRIx64" != 0x%"PRIx64" + 1\n",
			       state->h->db->db_name, seqnum, state->seqnum));
			tevent_req_error(req, EIO);
			return;
		}
	}

	/* trans3_commit successful */
	subreq = ctdb_g_lock_unlock_send(state, state->ev, h->client,
					 h->db_g_lock, h->lock_name, h->sid);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_transaction_commit_g_lock_done,
				req);
}

static void ctdb_transaction_commit_g_lock_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_transaction_commit_state *state = tevent_req_data(
		req, struct ctdb_transaction_commit_state);
	int ret;
	bool status;

	status = ctdb_g_lock_unlock_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("transaction_commit: %s g_lock unlock failed, ret=%d\n",
		       state->h->db->db_name, ret));
		tevent_req_error(req, ret);
		return;
	}

	talloc_free(state->h);
	tevent_req_done(req);
}

bool ctdb_transaction_commit_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}

int ctdb_transaction_commit(struct ctdb_transaction_handle *h)
{
	struct tevent_context *ev = h->ev;
	TALLOC_CTX *mem_ctx;
	struct tevent_req *req;
	int ret;
	bool status;

	if (h->readonly || ! h->updated) {
		return ctdb_transaction_cancel(h);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return ENOMEM;
	}

	req = ctdb_transaction_commit_send(mem_ctx, ev,
					   tevent_timeval_zero(), h);
	if (req == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_transaction_commit_recv(req, &ret);
	if (! status) {
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return 0;
}

struct ctdb_transaction_cancel_state {
	struct tevent_context *ev;
	struct ctdb_transaction_handle *h;
	struct timeval timeout;
};

static void ctdb_transaction_cancel_done(struct tevent_req *subreq);

struct tevent_req *ctdb_transaction_cancel_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct timeval timeout,
					struct ctdb_transaction_handle *h)
{
	struct tevent_req *req, *subreq;
	struct ctdb_transaction_cancel_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_transaction_cancel_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->h = h;
	state->timeout = timeout;

	subreq = ctdb_g_lock_unlock_send(state, state->ev, state->h->client,
					 state->h->db_g_lock,
					 state->h->lock_name, state->h->sid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_transaction_cancel_done,
				req);

	return req;
}

static void ctdb_transaction_cancel_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_transaction_cancel_state *state = tevent_req_data(
		req, struct ctdb_transaction_cancel_state);
	int ret;
	bool status;

	status = ctdb_g_lock_unlock_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		DEBUG(DEBUG_ERR,
		      ("transaction_cancel: %s g_lock unlock failed, ret=%d\n",
		       state->h->db->db_name, ret));
		talloc_free(state->h);
		tevent_req_error(req, ret);
		return;
	}

	talloc_free(state->h);
	tevent_req_done(req);
}

bool ctdb_transaction_cancel_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}

int ctdb_transaction_cancel(struct ctdb_transaction_handle *h)
{
	struct tevent_context *ev = h->ev;
	struct tevent_req *req;
	TALLOC_CTX *mem_ctx;
	int ret;
	bool status;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		talloc_free(h);
		return ENOMEM;
	}

	req = ctdb_transaction_cancel_send(mem_ctx, ev,
					   tevent_timeval_zero(), h);
	if (req == NULL) {
		talloc_free(mem_ctx);
		talloc_free(h);
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_transaction_cancel_recv(req, &ret);
	if (! status) {
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return 0;
}

/*
 * TODO:
 *
 * In future Samba should register SERVER_ID.
 * Make that structure same as struct srvid {}.
 */
