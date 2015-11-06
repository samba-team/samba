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
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_nodemap(reply, state, &nodemap);
	talloc_free(reply);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	state->count = list_of_connected_nodes(nodemap, CTDB_UNKNOWN_PNN,
					       state, &state->pnn_list);
	talloc_free(nodemap);
	if (state->count <= 0) {
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
	uint32_t tdb_flags;
	struct ctdb_db_context *db;
};

static void ctdb_attach_mutex_done(struct tevent_req *subreq);
static void ctdb_attach_dbid_done(struct tevent_req *subreq);
static void ctdb_attach_dbpath_done(struct tevent_req *subreq);
static void ctdb_attach_health_done(struct tevent_req *subreq);
static void ctdb_attach_flags_done(struct tevent_req *subreq);

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

	if (db_flags & CTDB_DB_FLAGS_PERSISTENT) {
		state->db->persistent = true;
	}

	ctdb_req_control_get_tunable(&request, "TDBMutexEnabled");
	subreq = ctdb_client_control_send(state, ev, client,
					  ctdb_client_pnn(client), timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_attach_mutex_done, req);

	return req;
}

static void ctdb_attach_mutex_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_attach_state *state = tevent_req_data(
		req, struct ctdb_attach_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	uint32_t mutex_enabled;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_tunable(reply, &mutex_enabled);
	if (ret != 0) {
		/* Treat error as mutex support not available */
		mutex_enabled = 0;
	}

	state->tdb_flags = TDB_DEFAULT;
	if (! state->db->persistent) {
		state->tdb_flags |= (TDB_INCOMPATIBLE_HASH |
				     TDB_CLEAR_IF_FIRST);
	}
	if (mutex_enabled == 1) {
		state->tdb_flags |= TDB_MUTEX_LOCKING;
	}

	if (state->db->persistent) {
		ctdb_req_control_db_attach_persistent(&request,
						      state->db->db_name,
						      state->tdb_flags);
	} else {
		ctdb_req_control_db_attach(&request, state->db->db_name,
					   state->tdb_flags);
	}

	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, state->timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_attach_dbid_done, req);
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
		tevent_req_error(req, ret);
		return;
	}

	if (state->db->persistent) {
		ret = ctdb_reply_control_db_attach_persistent(
				reply, &state->db->db_id);
	} else {
		ret = ctdb_reply_control_db_attach(reply, &state->db->db_id);
	}
	talloc_free(reply);
	if (ret != 0) {
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
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_getdbpath(reply, state->db,
					   &state->db->db_path);
	talloc_free(reply);
	if (ret != 0) {
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
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_db_get_health(reply, state, &reason);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	if (reason != NULL) {
		/* Database unhealthy, avoid attach */
		/* FIXME: Log here */
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
	bool status;
	int ret;

	status = ctdb_set_db_flags_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	state->db->ltdb = tdb_wrap_open(state->db, state->db->db_path, 0,
					state->tdb_flags, O_RDWR, 0);
	if (tevent_req_nomem(state->db->ltdb, req)) {
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

int ctdb_attach(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout,
		const char *db_name, uint8_t db_flags,
		struct ctdb_db_context **out)
{
	struct tevent_req *req;
	bool status;
	int ret;

	req = ctdb_attach_send(mem_ctx, ev, client, timeout,
			       db_name, db_flags);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_attach_recv(req, &ret, out);
	if (! status) {
		return ret;
	}

	/*
	ctdb_set_call(db, CTDB_NULL_FUNC, ctdb_null_func);
	ctdb_set_call(db, CTDB_FETCH_FUNC, ctdb_fetch_func);
	ctdb_set_call(db, CTDB_FETCH_WITH_HEADER_FUNC, ctdb_fetch_with_header_func);
	*/

	return 0;
}

int ctdb_detach(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		struct ctdb_client_context *client,
		struct timeval timeout, uint32_t db_id)
{
	struct ctdb_db_context *db;
	int ret;

	ret = ctdb_ctrl_db_detach(mem_ctx, ev, client, client->pnn, timeout,
				  db_id);
	if (ret != 0) {
		return ret;
	}

	for (db = client->db; db != NULL; db = db->next) {
		if (db->db_id == db_id) {
			DLIST_REMOVE(client->db, db);
			break;
		}
	}

	return 0;
}

uint32_t ctdb_db_id(struct ctdb_db_context *db)
{
	return db->db_id;
}

struct ctdb_db_traverse_state {
	ctdb_rec_parser_func_t parser;
	void *private_data;
	bool extract_header;
	int error;
};

static int ctdb_db_traverse_handler(struct tdb_context *tdb, TDB_DATA key,
				    TDB_DATA data, void *private_data)
{
	struct ctdb_db_traverse_state *state =
		(struct ctdb_db_traverse_state *)private_data;
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

int ctdb_db_traverse(struct ctdb_db_context *db, bool readonly,
		     bool extract_header,
		     ctdb_rec_parser_func_t parser, void *private_data)
{
	struct ctdb_db_traverse_state state;
	int ret;

	state.parser = parser;
	state.private_data = private_data;
	state.extract_header = extract_header;
	state.error = 0;

	if (readonly) {
		ret = tdb_traverse_read(db->ltdb->tdb,
					ctdb_db_traverse_handler, &state);
	} else {
		ret = tdb_traverse(db->ltdb->tdb,
				   ctdb_db_traverse_handler, &state);
	}

	if (ret == -1) {
		return EIO;
	}

	return state.error;
}

static int ctdb_ltdb_fetch(struct ctdb_db_context *db, TDB_DATA key,
			   struct ctdb_ltdb_header *header,
			   TALLOC_CTX *mem_ctx, TDB_DATA *data)
{
	TDB_DATA rec;
	int ret;

	rec = tdb_fetch(db->ltdb->tdb, key);
	if (rec.dsize < sizeof(struct ctdb_ltdb_header)) {
		/* No record present */
		if (rec.dptr != NULL) {
			free(rec.dptr);
		}

		if (tdb_error(db->ltdb->tdb) != TDB_ERR_NOEXIST) {
			return EIO;
		}

		header->rsn = 0;
		header->dmaster = CTDB_UNKNOWN_PNN;
		header->flags = 0;

		if (data != NULL) {
			*data = tdb_null;
		}
		return 0;
	}

	ret = ctdb_ltdb_header_pull(rec.dptr, rec.dsize, header);
	if (ret != 0) {
		return ret;
	}

	ret = 0;
	if (data != NULL) {
		size_t offset = ctdb_ltdb_header_len(header);

		data->dsize = rec.dsize - offset;
		data->dptr = talloc_memdup(mem_ctx, rec.dptr + offset,
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
	if (db->persistent) {
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
	int ret, err = 0;
	bool do_migrate = false;

	ret = tdb_chainlock(state->h->db->ltdb->tdb, state->h->key);
	if (ret != 0) {
		err = EIO;
		goto failed;
	}

	data = tdb_fetch(h->db->ltdb->tdb, h->key);
	if (data.dptr == NULL) {
		if (tdb_error(h->db->ltdb->tdb) == TDB_ERR_NOEXIST) {
			goto migrate;
		} else {
			err = EIO;
			goto failed;
		}
	}

	/* Got the record */
	ret = ctdb_ltdb_header_pull(data.dptr, data.dsize, &header);
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
	ret = tdb_chainunlock(h->db->ltdb->tdb, h->key);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("tdb_chainunlock failed on %s\n",
				  h->db->db_name));
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
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static int ctdb_record_handle_destructor(struct ctdb_record_handle *h)
{
	tdb_chainunlock(h->db->ltdb->tdb, h->key);
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
		data->dptr = talloc_memdup(mem_ctx, h->data.dptr + offset,
					   data->dsize);
		if (data->dptr == NULL) {
			TALLOC_FREE(state->h);
			if (perr != NULL) {
				*perr = ENOMEM;
			}
			return NULL;
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
	int ret;

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
	TDB_DATA rec;
	size_t offset;
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

	offset = ctdb_ltdb_header_len(&h->header);
	rec.dsize = offset + data.dsize;
	rec.dptr = talloc_size(h, rec.dsize);
	if (rec.dptr == NULL) {
		return ENOMEM;
	}

	ctdb_ltdb_header_push(&h->header, rec.dptr);
	memcpy(rec.dptr + offset, data.dptr, data.dsize);

	ret = tdb_store(h->db->ltdb->tdb, h->key, rec, TDB_REPLACE);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to store record in DB %s\n",
				  h->db->db_name));
		return EIO;
	}

	talloc_free(rec.dptr);
	return 0;
}

int ctdb_delete_record(struct ctdb_record_handle *h)
{
	TDB_DATA rec;
	struct ctdb_key_data key;
	int ret;

	/* Cannot delete the record if it was obtained as a readonly copy */
	if (h->readonly) {
		return EINVAL;
	}

	rec.dsize = ctdb_ltdb_header_len(&h->header);
	rec.dptr = talloc_size(h, rec.dsize);
	if (rec.dptr == NULL) {
		return ENOMEM;
	}

	ctdb_ltdb_header_push(&h->header, rec.dptr);

	ret = tdb_store(h->db->ltdb->tdb, h->key, rec, TDB_REPLACE);
	talloc_free(rec.dptr);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to delete record in DB %s\n",
				  h->db->db_name));
		return EIO;
	}

	key.db_id = h->db->db_id;
	key.header = h->header;
	key.key = h->key;

	ret = ctdb_ctrl_schedule_for_deletion(h, h->ev, h->client,
					      h->client->pnn,
					      tevent_timeval_zero(), &key);
	if (ret != 0) {
		DEBUG(DEBUG_WARNING,
		      ("Failed to mark record to be deleted in DB %s\n",
		       h->db->db_name));
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
	int ret = 0;

	state->h = ctdb_fetch_lock_recv(subreq, NULL, state, &data, &ret);
	TALLOC_FREE(subreq);
	if (state->h == NULL) {
		tevent_req_error(req, ret);
		return;
	}

	if (state->lock_list != NULL) {
		TALLOC_FREE(state->lock_list);
		state->current = 0;
	}

	ret = ctdb_g_lock_list_pull(data.dptr, data.dsize, state,
				    &state->lock_list);
	talloc_free(data.dptr);
	if (ret != 0) {
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
		struct ctdb_uint64_array u64_array;

		u64_array.num = 1;
		u64_array.val = &lock->sid.unique_id;

		ctdb_req_control_check_srvids(&request, &u64_array);
		subreq = ctdb_client_control_send(state, state->ev,
						  state->client,
						  state->client->pnn,
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

	tevent_req_done(req);
}

static void ctdb_g_lock_lock_checked(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_g_lock_lock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_lock_state);
	struct ctdb_reply_control *reply;
	struct ctdb_uint8_array *u8_array;
	int ret;
	bool status;
	int8_t val;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_check_srvids(reply, state, &u8_array);
	if (ret != 0) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	if (u8_array->num != 1) {
		talloc_free(u8_array);
		tevent_req_error(req, EIO);
		return;
	}

	val = u8_array->val[0];
	talloc_free(u8_array);

	if (val == 1) {
		/* server process exists, need to retry */
		subreq = tevent_wakeup_send(state, state->ev,
					    tevent_timeval_current_ofs(1,0));
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
	int ret;

	data.dsize = ctdb_g_lock_list_len(state->lock_list);
	data.dptr = talloc_size(state, data.dsize);
	if (data.dptr == NULL) {
		return ENOMEM;
	}

	ctdb_g_lock_list_push(state->lock_list, data.dptr);
	ret = ctdb_store_record(state->h, data);
	talloc_free(data.dptr);
	return ret;
}

#if 0
static int ctdb_g_lock_lock_update(struct ctdb_g_lock_lock_state *state,
				   struct ctdb_g_lock_list *lock_list,
				   struct ctdb_record_handle *h)
{
	struct ctdb_g_lock *lock;
	bool conflict = false;
	bool modified = false;
	int ret, i;

	for (i=0; i<lock_list->num; i++) {
		lock = &lock_list->lock[i];

		/* We should not ask for lock more than once */
		if (ctdb_server_id_equal(&lock->sid, &state->my_sid)) {
			return EDEADLK;
		}

		if (ctdb_g_lock_conflicts(lock->type, state->lock_type)) {
			bool exists;

			conflict = true;
			ret = ctdb_server_id_exists(state->client, &lock->sid,
						    &exists);
			if (ret != 0) {
				return ret;
			}

			if (exists) {
				break;
			}

			/* Server does not exist, delete conflicting entry */
			lock_list->lock[i] = lock_list->lock[lock_list->num-1];
			lock_list->num -= 1;
			modified = true;
		}
	}

	if (! conflict) {
		lock = talloc_realloc(lock_list, lock_list->lock,
				      struct ctdb_g_lock, lock_list->num+1);
		if (lock == NULL) {
			return ENOMEM;
		}

		lock[lock_list->num].type = state->lock_type;
		lock[lock_list->num].sid = state->my_sid;
		lock_list->lock = lock;
		lock_list->num += 1;
		modified = true;
	}

	if (modified) {
		TDB_DATA data;

		data.dsize = ctdb_g_lock_list_len(lock_list);
		data.dptr = talloc_size(state, data.dsize);
		if (data.dptr == NULL) {
			return ENOMEM;
		}

		ctdb_g_lock_list_push(lock_list, data.dptr);
		ret = ctdb_store_record(h, data);
		talloc_free(data.dptr);
		if (ret != 0) {
			return ret;
		}
	}

	if (conflict) {
		return EAGAIN;
	}
	return 0;
}
#endif

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
	int ret = 0;

	state->h = ctdb_fetch_lock_recv(subreq, NULL, state, &data, &ret);
	TALLOC_FREE(subreq);
	if (state->h == NULL) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_g_lock_list_pull(data.dptr, data.dsize, state,
				    &state->lock_list);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_g_lock_unlock_update(req);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static int ctdb_g_lock_unlock_update(struct tevent_req *req)
{
	struct ctdb_g_lock_unlock_state *state = tevent_req_data(
		req, struct ctdb_g_lock_unlock_state);
	struct ctdb_g_lock *lock;
	int ret, i;

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

	if (state->lock_list->num == 0) {
		ctdb_delete_record(state->h);
	} else {
		TDB_DATA data;

		data.dsize = ctdb_g_lock_list_len(state->lock_list);
		data.dptr = talloc_size(state, data.dsize);
		if (data.dptr == NULL) {
			return ENOMEM;
		}

		ctdb_g_lock_list_push(state->lock_list, data.dptr);
		ret = ctdb_store_record(state->h, data);
		talloc_free(data.dptr);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
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
static void ctdb_transaction_register_done(struct tevent_req *subreq);
static void ctdb_transaction_g_lock_done(struct tevent_req *subreq);
static int ctdb_transaction_handle_destructor(struct ctdb_transaction_handle *h);

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

	if (! db->persistent) {
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

	/* SRVID is unique for databases, so client can have transactions active
	 * for multiple databases */
	h->sid.pid = getpid();
	h->sid.task_id = db->db_id;
	h->sid.vnn = state->destnode;
	h->sid.unique_id = h->sid.task_id;
	h->sid.unique_id = (h->sid.unique_id << 32) | h->sid.pid;

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
	struct ctdb_req_control request;
	bool status;
	int ret;

	status = ctdb_attach_recv(subreq, &ret, &state->h->db_g_lock);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_register_srvid(&request, state->h->sid.unique_id);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, state->timeout,
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_transaction_register_done, req);
}

static void ctdb_transaction_register_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_transaction_start_state *state = tevent_req_data(
		req, struct ctdb_transaction_start_state);
	struct ctdb_reply_control *reply;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_register_srvid(reply);
	talloc_free(reply);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = ctdb_g_lock_lock_send(state, state->ev, state->client,
				       state->h->db_g_lock, state->h->lock_name,
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
	int ret;
	bool status;

	status = ctdb_g_lock_lock_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
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
	struct ctdb_transaction_handle *h = state->h;
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return NULL;
	}

	talloc_set_destructor(h, ctdb_transaction_handle_destructor);
	return h;
}

static int ctdb_transaction_handle_destructor(struct ctdb_transaction_handle *h)
{
	int ret;

	ret = ctdb_ctrl_deregister_srvid(h, h->ev, h->client, h->client->pnn,
					 tevent_timeval_zero(),
					 h->sid.unique_id);
	if (ret != 0) {
		DEBUG(DEBUG_WARNING, ("Failed to deregister SRVID\n"));
	}

	return 0;
}

int ctdb_transaction_start(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   struct ctdb_client_context *client,
			   struct timeval timeout,
			   struct ctdb_db_context *db, bool readonly,
			   struct ctdb_transaction_handle **out)
{
	struct tevent_req *req;
	struct ctdb_transaction_handle *h;
	int ret;

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

static int ctdb_transaction_record_fetch_traverse(uint32_t reqid,
						  struct ctdb_ltdb_header *header,
						  TDB_DATA key,
						  TDB_DATA data,
						  void *private_data)
{
	struct ctdb_transaction_record_fetch_state *state =
		(struct ctdb_transaction_record_fetch_state *)private_data;

	if (state->key.dsize == key.dsize &&
	    memcmp(state->key.dptr, key.dptr, key.dsize) == 0) {
		state->data = data;
		state->header = *header;
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
	struct ctdb_transaction_handle *h;
	uint64_t seqnum;
};

static void ctdb_transaction_commit_done(struct tevent_req *subreq);
static void ctdb_transaction_commit_try(struct tevent_req *subreq);

struct tevent_req *ctdb_transaction_commit_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_transaction_handle *h)
{
	struct tevent_req *req, *subreq;
	struct ctdb_transaction_commit_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_transaction_commit_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->h = h;

	ret = ctdb_ctrl_get_db_seqnum(state, ev, h->client,
				      h->client->pnn, tevent_timeval_zero(),
				      h->db->db_id, &state->seqnum);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_transaction_store_db_seqnum(h, state->seqnum+1);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	subreq = ctdb_recovery_wait_send(state, ev, h->client);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_transaction_commit_try, req);

	return req;
}

static void ctdb_transaction_commit_try(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_transaction_commit_state *state = tevent_req_data(
		req, struct ctdb_transaction_commit_state);
	struct ctdb_req_control request;
	int ret;
	bool status;

	status = ctdb_recovery_wait_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_trans3_commit(&request, state->h->recbuf);
	subreq = ctdb_client_control_send(state, state->ev, state->h->client,
					  state->h->client->pnn,
					  tevent_timeval_zero(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_transaction_commit_done, req);
}

static void ctdb_transaction_commit_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_transaction_commit_state *state = tevent_req_data(
		req, struct ctdb_transaction_commit_state);
	struct ctdb_reply_control *reply;
	uint64_t seqnum;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_trans3_commit(reply);
	if (ret < 0) {
		/* Control failed due to recovery */
		subreq = ctdb_recovery_wait_send(state, state->ev,
						 state->h->client);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, ctdb_transaction_commit_try,
					req);
		return;
	}

	ret = ctdb_ctrl_get_db_seqnum(state, state->ev, state->h->client,
				      state->h->client->pnn,
				      tevent_timeval_zero(),
				      state->h->db->db_id, &seqnum);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	if (seqnum == state->seqnum) {
		subreq = ctdb_recovery_wait_send(state, state->ev,
						 state->h->client);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, ctdb_transaction_commit_try,
					req);
		return;
	}

	if (seqnum != state->seqnum + 1) {
		tevent_req_error(req, EIO);
		return;
	}

	tevent_req_done(req);
}

bool ctdb_transaction_commit_recv(struct tevent_req *req, int *perr)
{
	struct ctdb_transaction_commit_state *state = tevent_req_data(
		req, struct ctdb_transaction_commit_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		TALLOC_FREE(state->h);
		return false;
	}

	TALLOC_FREE(state->h);
	return true;
}

int ctdb_transaction_commit(struct ctdb_transaction_handle *h)
{
	struct tevent_req *req;
	int ret;
	bool status;

	if (h->readonly || ! h->updated) {
		talloc_free(h);
		return 0;
	}

	req = ctdb_transaction_commit_send(h, h->ev, h);
	if (req == NULL) {
		talloc_free(h);
		return ENOMEM;
	}

	tevent_req_poll(req, h->ev);

	status = ctdb_transaction_commit_recv(req, &ret);
	if (! status) {
		talloc_free(h);
		return ret;
	}

	talloc_free(h);
	return 0;
}

int ctdb_transaction_cancel(struct ctdb_transaction_handle *h)
{
	talloc_free(h);
	return 0;
}

/*
 * TODO:
 *
 * In future Samba should register SERVER_ID.
 * Make that structure same as struct srvid {}.
 */
