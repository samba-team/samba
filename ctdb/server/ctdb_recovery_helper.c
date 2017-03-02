/*
   ctdb parallel database recovery

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
#include <libgen.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/sys_rw.h"
#include "lib/util/time.h"
#include "lib/util/tevent_unix.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "client/client.h"

#include "common/logging.h"

static int recover_timeout = 30;

#define NUM_RETRIES	3

#define TIMEOUT()	timeval_current_ofs(recover_timeout, 0)

/*
 * Utility functions
 */

static bool generic_recv(struct tevent_req *req, int *perr)
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

static uint64_t rec_srvid = CTDB_SRVID_RECOVERY;

static uint64_t srvid_next(void)
{
	rec_srvid += 1;
	return rec_srvid;
}

/*
 * Recovery database functions
 */

struct recdb_context {
	uint32_t db_id;
	const char *db_name;
	const char *db_path;
	struct tdb_wrap *db;
	bool persistent;
};

static struct recdb_context *recdb_create(TALLOC_CTX *mem_ctx, uint32_t db_id,
					  const char *db_name,
					  const char *db_path,
					  uint32_t hash_size, bool persistent)
{
	static char *db_dir_state = NULL;
	struct recdb_context *recdb;
	unsigned int tdb_flags;

	recdb = talloc(mem_ctx, struct recdb_context);
	if (recdb == NULL) {
		return NULL;
	}

	if (db_dir_state == NULL) {
		db_dir_state = getenv("CTDB_DBDIR_STATE");
	}

	recdb->db_name = db_name;
	recdb->db_id = db_id;
	recdb->db_path = talloc_asprintf(recdb, "%s/recdb.%s",
					 db_dir_state != NULL ?
					    db_dir_state :
					    dirname(discard_const(db_path)),
					 db_name);
	if (recdb->db_path == NULL) {
		talloc_free(recdb);
		return NULL;
	}
	unlink(recdb->db_path);

	tdb_flags = TDB_NOLOCK | TDB_INCOMPATIBLE_HASH | TDB_DISALLOW_NESTING;
	recdb->db = tdb_wrap_open(mem_ctx, recdb->db_path, hash_size,
				  tdb_flags, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (recdb->db == NULL) {
		talloc_free(recdb);
		D_ERR("failed to create recovery db %s\n", recdb->db_path);
		return NULL;
	}

	recdb->persistent = persistent;

	return recdb;
}

static uint32_t recdb_id(struct recdb_context *recdb)
{
	return recdb->db_id;
}

static const char *recdb_name(struct recdb_context *recdb)
{
	return recdb->db_name;
}

static const char *recdb_path(struct recdb_context *recdb)
{
	return recdb->db_path;
}

static struct tdb_context *recdb_tdb(struct recdb_context *recdb)
{
	return recdb->db->tdb;
}

static bool recdb_persistent(struct recdb_context *recdb)
{
	return recdb->persistent;
}

struct recdb_add_traverse_state {
	struct recdb_context *recdb;
	int mypnn;
};

static int recdb_add_traverse(uint32_t reqid, struct ctdb_ltdb_header *header,
			      TDB_DATA key, TDB_DATA data,
			      void *private_data)
{
	struct recdb_add_traverse_state *state =
		(struct recdb_add_traverse_state *)private_data;
	struct ctdb_ltdb_header *hdr;
	TDB_DATA prev_data;
	int ret;

	/* header is not marshalled separately in the pulldb control */
	if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
		return -1;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	/* fetch the existing record, if any */
	prev_data = tdb_fetch(recdb_tdb(state->recdb), key);

	if (prev_data.dptr != NULL) {
		struct ctdb_ltdb_header prev_hdr;

		prev_hdr = *(struct ctdb_ltdb_header *)prev_data.dptr;
		free(prev_data.dptr);
		if (hdr->rsn < prev_hdr.rsn ||
		    (hdr->rsn == prev_hdr.rsn &&
		     prev_hdr.dmaster != state->mypnn)) {
			return 0;
		}
	}

	ret = tdb_store(recdb_tdb(state->recdb), key, data, TDB_REPLACE);
	if (ret != 0) {
		return -1;
	}
	return 0;
}

static bool recdb_add(struct recdb_context *recdb, int mypnn,
		      struct ctdb_rec_buffer *recbuf)
{
	struct recdb_add_traverse_state state;
	int ret;

	state.recdb = recdb;
	state.mypnn = mypnn;

	ret = ctdb_rec_buffer_traverse(recbuf, recdb_add_traverse, &state);
	if (ret != 0) {
		return false;
	}

	return true;
}

/* This function decides which records from recdb are retained */
static int recbuf_filter_add(struct ctdb_rec_buffer *recbuf, bool persistent,
			     uint32_t reqid, uint32_t dmaster,
			     TDB_DATA key, TDB_DATA data)
{
	struct ctdb_ltdb_header *header;
	int ret;

	/* Skip empty records */
	if (data.dsize <= sizeof(struct ctdb_ltdb_header)) {
		return 0;
	}

	/* update the dmaster field to point to us */
	header = (struct ctdb_ltdb_header *)data.dptr;
	if (!persistent) {
		header->dmaster = dmaster;
		header->flags |= CTDB_REC_FLAG_MIGRATED_WITH_DATA;
	}

	ret = ctdb_rec_buffer_add(recbuf, recbuf, reqid, NULL, key, data);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

struct recdb_records_traverse_state {
	struct ctdb_rec_buffer *recbuf;
	uint32_t dmaster;
	uint32_t reqid;
	bool persistent;
	bool failed;
};

static int recdb_records_traverse(struct tdb_context *tdb,
				  TDB_DATA key, TDB_DATA data,
				  void *private_data)
{
	struct recdb_records_traverse_state *state =
		(struct recdb_records_traverse_state *)private_data;
	int ret;

	ret = recbuf_filter_add(state->recbuf, state->persistent,
				state->reqid, state->dmaster, key, data);
	if (ret != 0) {
		state->failed = true;
		return ret;
	}

	return 0;
}

static struct ctdb_rec_buffer *recdb_records(struct recdb_context *recdb,
					     TALLOC_CTX *mem_ctx,
					     uint32_t dmaster)
{
	struct recdb_records_traverse_state state;
	int ret;

	state.recbuf = ctdb_rec_buffer_init(mem_ctx, recdb_id(recdb));
	if (state.recbuf == NULL) {
		return NULL;
	}
	state.dmaster = dmaster;
	state.reqid = 0;
	state.persistent = recdb_persistent(recdb);
	state.failed = false;

	ret = tdb_traverse_read(recdb_tdb(recdb), recdb_records_traverse,
				&state);
	if (ret == -1 || state.failed) {
		D_ERR("Failed to marshall recovery records for %s\n",
		      recdb_name(recdb));
		TALLOC_FREE(state.recbuf);
		return NULL;
	}

	return state.recbuf;
}

struct recdb_file_traverse_state {
	struct ctdb_rec_buffer *recbuf;
	struct recdb_context *recdb;
	TALLOC_CTX *mem_ctx;
	uint32_t dmaster;
	uint32_t reqid;
	bool persistent;
	bool failed;
	int fd;
	int max_size;
	int num_buffers;
};

static int recdb_file_traverse(struct tdb_context *tdb,
			       TDB_DATA key, TDB_DATA data,
			       void *private_data)
{
	struct recdb_file_traverse_state *state =
		(struct recdb_file_traverse_state *)private_data;
	int ret;

	ret = recbuf_filter_add(state->recbuf, state->persistent,
				state->reqid, state->dmaster, key, data);
	if (ret != 0) {
		state->failed = true;
		return ret;
	}

	if (ctdb_rec_buffer_len(state->recbuf) > state->max_size) {
		ret = ctdb_rec_buffer_write(state->recbuf, state->fd);
		if (ret != 0) {
			D_ERR("Failed to collect recovery records for %s\n",
			      recdb_name(state->recdb));
			state->failed = true;
			return ret;
		}

		state->num_buffers += 1;

		TALLOC_FREE(state->recbuf);
		state->recbuf = ctdb_rec_buffer_init(state->mem_ctx,
						     recdb_id(state->recdb));
		if (state->recbuf == NULL) {
			state->failed = true;
			return ENOMEM;
		}
	}

	return 0;
}

static int recdb_file(struct recdb_context *recdb, TALLOC_CTX *mem_ctx,
		      uint32_t dmaster, int fd, int max_size)
{
	struct recdb_file_traverse_state state;
	int ret;

	state.recbuf = ctdb_rec_buffer_init(mem_ctx, recdb_id(recdb));
	if (state.recbuf == NULL) {
		return -1;
	}
	state.recdb = recdb;
	state.mem_ctx = mem_ctx;
	state.dmaster = dmaster;
	state.reqid = 0;
	state.persistent = recdb_persistent(recdb);
	state.failed = false;
	state.fd = fd;
	state.max_size = max_size;
	state.num_buffers = 0;

	ret = tdb_traverse_read(recdb_tdb(recdb), recdb_file_traverse, &state);
	if (ret == -1 || state.failed) {
		TALLOC_FREE(state.recbuf);
		return -1;
	}

	ret = ctdb_rec_buffer_write(state.recbuf, fd);
	if (ret != 0) {
		D_ERR("Failed to collect recovery records for %s\n",
		      recdb_name(recdb));
		TALLOC_FREE(state.recbuf);
		return -1;
	}
	state.num_buffers += 1;

	D_DEBUG("Wrote %d buffers of recovery records for %s\n",
		state.num_buffers, recdb_name(recdb));

	return state.num_buffers;
}

/*
 * Pull database from a single node
 */

struct pull_database_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct recdb_context *recdb;
	uint32_t pnn;
	uint64_t srvid;
	int num_records;
};

static void pull_database_handler(uint64_t srvid, TDB_DATA data,
				  void *private_data);
static void pull_database_register_done(struct tevent_req *subreq);
static void pull_database_old_done(struct tevent_req *subreq);
static void pull_database_unregister_done(struct tevent_req *subreq);
static void pull_database_new_done(struct tevent_req *subreq);

static struct tevent_req *pull_database_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t pnn, uint32_t caps,
			struct recdb_context *recdb)
{
	struct tevent_req *req, *subreq;
	struct pull_database_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state, struct pull_database_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->recdb = recdb;
	state->pnn = pnn;
	state->srvid = srvid_next();

	if (caps & CTDB_CAP_FRAGMENTED_CONTROLS) {
		subreq = ctdb_client_set_message_handler_send(
					state, state->ev, state->client,
					state->srvid, pull_database_handler,
					req);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}

		tevent_req_set_callback(subreq, pull_database_register_done,
					req);

	} else {
		struct ctdb_pulldb pulldb;

		pulldb.db_id = recdb_id(recdb);
		pulldb.lmaster = CTDB_LMASTER_ANY;

		ctdb_req_control_pull_db(&request, &pulldb);
		subreq = ctdb_client_control_send(state, state->ev,
						  state->client,
						  pnn, TIMEOUT(),
						  &request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, pull_database_old_done, req);
	}

	return req;
}

static void pull_database_handler(uint64_t srvid, TDB_DATA data,
				  void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct pull_database_state *state = tevent_req_data(
		req, struct pull_database_state);
	struct ctdb_rec_buffer *recbuf;
	int ret;
	bool status;

	if (srvid != state->srvid) {
		return;
	}

	ret = ctdb_rec_buffer_pull(data.dptr, data.dsize, state, &recbuf);
	if (ret != 0) {
		D_ERR("Invalid data received for DB_PULL messages\n");
		return;
	}

	if (recbuf->db_id != recdb_id(state->recdb)) {
		talloc_free(recbuf);
		D_ERR("Invalid dbid:%08x for DB_PULL messages for %s\n",
		      recbuf->db_id, recdb_name(state->recdb));
		return;
	}

	status = recdb_add(state->recdb, ctdb_client_pnn(state->client),
			   recbuf);
	if (! status) {
		talloc_free(recbuf);
		D_ERR("Failed to add records to recdb for %s\n",
		      recdb_name(state->recdb));
		return;
	}

	state->num_records += recbuf->count;
	talloc_free(recbuf);
}

static void pull_database_register_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct pull_database_state *state = tevent_req_data(
		req, struct pull_database_state);
	struct ctdb_req_control request;
	struct ctdb_pulldb_ext pulldb_ext;
	int ret;
	bool status;

	status = ctdb_client_set_message_handler_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("Failed to set message handler for DB_PULL for %s\n",
		      recdb_name(state->recdb));
		tevent_req_error(req, ret);
		return;
	}

	pulldb_ext.db_id = recdb_id(state->recdb);
	pulldb_ext.lmaster = CTDB_LMASTER_ANY;
	pulldb_ext.srvid = state->srvid;

	ctdb_req_control_db_pull(&request, &pulldb_ext);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->pnn, TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, pull_database_new_done, req);
}

static void pull_database_old_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct pull_database_state *state = tevent_req_data(
		req, struct pull_database_state);
	struct ctdb_reply_control *reply;
	struct ctdb_rec_buffer *recbuf;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control PULL_DB failed for %s on node %u, ret=%d\n",
		      recdb_name(state->recdb), state->pnn, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_pull_db(reply, state, &recbuf);
	talloc_free(reply);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	status = recdb_add(state->recdb, ctdb_client_pnn(state->client),
			   recbuf);
	if (! status) {
		talloc_free(recbuf);
		tevent_req_error(req, EIO);
		return;
	}

	state->num_records = recbuf->count;
	talloc_free(recbuf);

	D_INFO("Pulled %d records for db %s from node %d\n",
	       state->num_records, recdb_name(state->recdb), state->pnn);

	tevent_req_done(req);
}

static void pull_database_new_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct pull_database_state *state = tevent_req_data(
		req, struct pull_database_state);
	struct ctdb_reply_control *reply;
	uint32_t num_records;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control DB_PULL failed for %s on node %u, ret=%d\n",
		      recdb_name(state->recdb), state->pnn, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_db_pull(reply, &num_records);
	talloc_free(reply);
	if (num_records != state->num_records) {
		D_ERR("mismatch (%u != %u) in DB_PULL records for db %s\n",
		      num_records, state->num_records,
		      recdb_name(state->recdb));
		tevent_req_error(req, EIO);
		return;
	}

	D_INFO("Pulled %d records for db %s from node %d\n",
	       state->num_records, recdb_name(state->recdb), state->pnn);

	subreq = ctdb_client_remove_message_handler_send(
					state, state->ev, state->client,
					state->srvid, req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, pull_database_unregister_done, req);
}

static void pull_database_unregister_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct pull_database_state *state = tevent_req_data(
		req, struct pull_database_state);
	int ret;
	bool status;

	status = ctdb_client_remove_message_handler_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("failed to remove message handler for DB_PULL for db %s\n",
		      recdb_name(state->recdb));
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool pull_database_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}

/*
 * Push database to specified nodes (old style)
 */

struct push_database_old_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct recdb_context *recdb;
	uint32_t *pnn_list;
	int count;
	struct ctdb_rec_buffer *recbuf;
	int index;
};

static void push_database_old_push_done(struct tevent_req *subreq);

static struct tevent_req *push_database_old_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t *pnn_list, int count,
			struct recdb_context *recdb)
{
	struct tevent_req *req, *subreq;
	struct push_database_old_state *state;
	struct ctdb_req_control request;
	uint32_t pnn;

	req = tevent_req_create(mem_ctx, &state,
				struct push_database_old_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->recdb = recdb;
	state->pnn_list = pnn_list;
	state->count = count;
	state->index = 0;

	state->recbuf = recdb_records(recdb, state,
				      ctdb_client_pnn(client));
	if (tevent_req_nomem(state->recbuf, req)) {
		return tevent_req_post(req, ev);
	}

	pnn = state->pnn_list[state->index];

	ctdb_req_control_push_db(&request, state->recbuf);
	subreq = ctdb_client_control_send(state, ev, client, pnn,
					  TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, push_database_old_push_done, req);

	return req;
}

static void push_database_old_push_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct push_database_old_state *state = tevent_req_data(
		req, struct push_database_old_state);
	struct ctdb_req_control request;
	uint32_t pnn;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, NULL, NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control PUSH_DB failed for db %s on node %u, ret=%d\n",
		      recdb_name(state->recdb), state->pnn_list[state->index],
		      ret);
		tevent_req_error(req, ret);
		return;
	}

	state->index += 1;
	if (state->index == state->count) {
		TALLOC_FREE(state->recbuf);
		tevent_req_done(req);
		return;
	}

	pnn = state->pnn_list[state->index];

	ctdb_req_control_push_db(&request, state->recbuf);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  pnn, TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, push_database_old_push_done, req);
}

static bool push_database_old_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}

/*
 * Push database to specified nodes (new style)
 */

struct push_database_new_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct recdb_context *recdb;
	uint32_t *pnn_list;
	int count;
	uint64_t srvid;
	uint32_t dmaster;
	int fd;
	int num_buffers;
	int num_buffers_sent;
	int num_records;
};

static void push_database_new_started(struct tevent_req *subreq);
static void push_database_new_send_msg(struct tevent_req *req);
static void push_database_new_send_done(struct tevent_req *subreq);
static void push_database_new_confirmed(struct tevent_req *subreq);

static struct tevent_req *push_database_new_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t *pnn_list, int count,
			struct recdb_context *recdb,
			int max_size)
{
	struct tevent_req *req, *subreq;
	struct push_database_new_state *state;
	struct ctdb_req_control request;
	struct ctdb_pulldb_ext pulldb_ext;
	char *filename;
	off_t offset;

	req = tevent_req_create(mem_ctx, &state,
				struct push_database_new_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->recdb = recdb;
	state->pnn_list = pnn_list;
	state->count = count;

	state->srvid = srvid_next();
	state->dmaster = ctdb_client_pnn(client);
	state->num_buffers_sent = 0;
	state->num_records = 0;

	filename = talloc_asprintf(state, "%s.dat", recdb_path(recdb));
	if (tevent_req_nomem(filename, req)) {
		return tevent_req_post(req, ev);
	}

	state->fd = open(filename, O_RDWR|O_CREAT, 0644);
	if (state->fd == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	unlink(filename);
	talloc_free(filename);

	state->num_buffers = recdb_file(recdb, state, state->dmaster,
					state->fd, max_size);
	if (state->num_buffers == -1) {
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}

	offset = lseek(state->fd, 0, SEEK_SET);
	if (offset != 0) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	pulldb_ext.db_id = recdb_id(recdb);
	pulldb_ext.srvid = state->srvid;

	ctdb_req_control_db_push_start(&request, &pulldb_ext);
	subreq = ctdb_client_control_multi_send(state, ev, client,
						pnn_list, count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, push_database_new_started, req);

	return req;
}

static void push_database_new_started(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct push_database_new_state *state = tevent_req_data(
		req, struct push_database_new_state);
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, state,
						&err_list, NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("control DB_PUSH_START failed for db %s"
			      " on node %u, ret=%d\n",
			      recdb_name(state->recdb), pnn, ret2);
		} else {
			D_ERR("control DB_PUSH_START failed for db %s,"
			      " ret=%d\n",
			      recdb_name(state->recdb), ret);
		}
		talloc_free(err_list);

		tevent_req_error(req, ret);
		return;
	}

	push_database_new_send_msg(req);
}

static void push_database_new_send_msg(struct tevent_req *req)
{
	struct push_database_new_state *state = tevent_req_data(
		req, struct push_database_new_state);
	struct tevent_req *subreq;
	struct ctdb_rec_buffer *recbuf;
	struct ctdb_req_message message;
	TDB_DATA data;
	int ret;

	if (state->num_buffers_sent == state->num_buffers) {
		struct ctdb_req_control request;

		ctdb_req_control_db_push_confirm(&request,
						 recdb_id(state->recdb));
		subreq = ctdb_client_control_multi_send(state, state->ev,
							state->client,
							state->pnn_list,
							state->count,
							TIMEOUT(), &request);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, push_database_new_confirmed,
					req);
		return;
	}

	ret = ctdb_rec_buffer_read(state->fd, state, &recbuf);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	data.dsize = ctdb_rec_buffer_len(recbuf);
	data.dptr = talloc_size(state, data.dsize);
	if (tevent_req_nomem(data.dptr, req)) {
		return;
	}

	ctdb_rec_buffer_push(recbuf, data.dptr);

	message.srvid = state->srvid;
	message.data.data = data;

	D_DEBUG("Pushing buffer %d with %d records for db %s\n",
		state->num_buffers_sent, recbuf->count,
		recdb_name(state->recdb));

	subreq = ctdb_client_message_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						&message);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, push_database_new_send_done, req);

	state->num_records += recbuf->count;

	talloc_free(data.dptr);
	talloc_free(recbuf);
}

static void push_database_new_send_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct push_database_new_state *state = tevent_req_data(
		req, struct push_database_new_state);
	bool status;
	int ret;

	status = ctdb_client_message_multi_recv(subreq, &ret, NULL, NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("Sending recovery records failed for %s\n",
		      recdb_name(state->recdb));
		tevent_req_error(req, ret);
		return;
	}

	state->num_buffers_sent += 1;

	push_database_new_send_msg(req);
}

static void push_database_new_confirmed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct push_database_new_state *state = tevent_req_data(
		req, struct push_database_new_state);
	struct ctdb_reply_control **reply;
	int *err_list;
	bool status;
	int ret, i;
	uint32_t num_records;

	status = ctdb_client_control_multi_recv(subreq, &ret, state,
						&err_list, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count, err_list,
						       &pnn);
		if (ret2 != 0) {
			D_ERR("control DB_PUSH_CONFIRM failed for db %s"
			      " on node %u, ret=%d\n",
			      recdb_name(state->recdb), pnn, ret2);
		} else {
			D_ERR("control DB_PUSH_CONFIRM failed for db %s,"
			      " ret=%d\n",
			      recdb_name(state->recdb), ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	for (i=0; i<state->count; i++) {
		ret = ctdb_reply_control_db_push_confirm(reply[i],
							 &num_records);
		if (ret != 0) {
			tevent_req_error(req, EPROTO);
			return;
		}

		if (num_records != state->num_records) {
			D_ERR("Node %u received %d of %d records for %s\n",
			      state->pnn_list[i], num_records,
			      state->num_records, recdb_name(state->recdb));
			tevent_req_error(req, EPROTO);
			return;
		}
	}

	talloc_free(reply);

	D_INFO("Pushed %d records for db %s\n",
	       state->num_records, recdb_name(state->recdb));

	tevent_req_done(req);
}

static bool push_database_new_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}

/*
 * wrapper for push_database_old and push_database_new
 */

struct push_database_state {
	bool old_done, new_done;
};

static void push_database_old_done(struct tevent_req *subreq);
static void push_database_new_done(struct tevent_req *subreq);

static struct tevent_req *push_database_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t *pnn_list, int count, uint32_t *caps,
			struct ctdb_tunable_list *tun_list,
			struct recdb_context *recdb)
{
	struct tevent_req *req, *subreq;
	struct push_database_state *state;
	uint32_t *old_list, *new_list;
	int old_count, new_count;
	int i;

	req = tevent_req_create(mem_ctx, &state, struct push_database_state);
	if (req == NULL) {
		return NULL;
	}

	state->old_done = false;
	state->new_done = false;

	old_count = 0;
	new_count = 0;
	old_list = talloc_array(state, uint32_t, count);
	new_list = talloc_array(state, uint32_t, count);
	if (tevent_req_nomem(old_list, req) ||
	    tevent_req_nomem(new_list,req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<count; i++) {
		uint32_t pnn = pnn_list[i];

		if (caps[pnn] & CTDB_CAP_FRAGMENTED_CONTROLS) {
			new_list[new_count] = pnn;
			new_count += 1;
		} else {
			old_list[old_count] = pnn;
			old_count += 1;
		}
	}

	if (old_count > 0) {
		subreq = push_database_old_send(state, ev, client,
						old_list, old_count, recdb);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, push_database_old_done, req);
	} else {
		state->old_done = true;
	}

	if (new_count > 0) {
		subreq = push_database_new_send(state, ev, client,
						new_list, new_count, recdb,
						tun_list->rec_buffer_size_limit);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, push_database_new_done, req);
	} else {
		state->new_done = true;
	}

	return req;
}

static void push_database_old_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct push_database_state *state = tevent_req_data(
		req, struct push_database_state);
	bool status;
	int ret;

	status = push_database_old_recv(subreq, &ret);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	state->old_done = true;

	if (state->old_done && state->new_done) {
		tevent_req_done(req);
	}
}

static void push_database_new_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct push_database_state *state = tevent_req_data(
		req, struct push_database_state);
	bool status;
	int ret;

	status = push_database_new_recv(subreq, &ret);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	state->new_done = true;

	if (state->old_done && state->new_done) {
		tevent_req_done(req);
	}
}

static bool push_database_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}

/*
 * Collect databases using highest sequence number
 */

struct collect_highseqnum_db_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	uint32_t *pnn_list;
	int count;
	uint32_t *caps;
	uint32_t *ban_credits;
	uint32_t db_id;
	struct recdb_context *recdb;
	uint32_t max_pnn;
};

static void collect_highseqnum_db_seqnum_done(struct tevent_req *subreq);
static void collect_highseqnum_db_pulldb_done(struct tevent_req *subreq);

static struct tevent_req *collect_highseqnum_db_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t *pnn_list, int count, uint32_t *caps,
			uint32_t *ban_credits, uint32_t db_id,
			struct recdb_context *recdb)
{
	struct tevent_req *req, *subreq;
	struct collect_highseqnum_db_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state,
				struct collect_highseqnum_db_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->pnn_list = pnn_list;
	state->count = count;
	state->caps = caps;
	state->ban_credits = ban_credits;
	state->db_id = db_id;
	state->recdb = recdb;

	ctdb_req_control_get_db_seqnum(&request, db_id);
	subreq = ctdb_client_control_multi_send(mem_ctx, ev, client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, collect_highseqnum_db_seqnum_done,
				req);

	return req;
}

static void collect_highseqnum_db_seqnum_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct collect_highseqnum_db_state *state = tevent_req_data(
		req, struct collect_highseqnum_db_state);
	struct ctdb_reply_control **reply;
	int *err_list;
	bool status;
	int ret, i;
	uint64_t seqnum, max_seqnum;

	status = ctdb_client_control_multi_recv(subreq, &ret, state,
						&err_list, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count, err_list,
						       &pnn);
		if (ret2 != 0) {
			D_ERR("control GET_DB_SEQNUM failed for db %s"
			      " on node %u, ret=%d\n",
			      recdb_name(state->recdb), pnn, ret2);
		} else {
			D_ERR("control GET_DB_SEQNUM failed for db %s,"
			      " ret=%d\n",
			      recdb_name(state->recdb), ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	max_seqnum = 0;
	state->max_pnn = state->pnn_list[0];
	for (i=0; i<state->count; i++) {
		ret = ctdb_reply_control_get_db_seqnum(reply[i], &seqnum);
		if (ret != 0) {
			tevent_req_error(req, EPROTO);
			return;
		}

		if (max_seqnum < seqnum) {
			max_seqnum = seqnum;
			state->max_pnn = state->pnn_list[i];
		}
	}

	talloc_free(reply);

	D_INFO("Pull persistent db %s from node %d with seqnum 0x%"PRIx64"\n",
	       recdb_name(state->recdb), state->max_pnn, max_seqnum);

	subreq = pull_database_send(state, state->ev, state->client,
				    state->max_pnn,
				    state->caps[state->max_pnn],
				    state->recdb);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, collect_highseqnum_db_pulldb_done,
				req);
}

static void collect_highseqnum_db_pulldb_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct collect_highseqnum_db_state *state = tevent_req_data(
		req, struct collect_highseqnum_db_state);
	int ret;
	bool status;

	status = pull_database_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		state->ban_credits[state->max_pnn] += 1;
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool collect_highseqnum_db_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}

/*
 * Collect all databases
 */

struct collect_all_db_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	uint32_t *pnn_list;
	int count;
	uint32_t *caps;
	uint32_t *ban_credits;
	uint32_t db_id;
	struct recdb_context *recdb;
	struct ctdb_pulldb pulldb;
	int index;
};

static void collect_all_db_pulldb_done(struct tevent_req *subreq);

static struct tevent_req *collect_all_db_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t *pnn_list, int count, uint32_t *caps,
			uint32_t *ban_credits, uint32_t db_id,
			struct recdb_context *recdb)
{
	struct tevent_req *req, *subreq;
	struct collect_all_db_state *state;
	uint32_t pnn;

	req = tevent_req_create(mem_ctx, &state,
				struct collect_all_db_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->pnn_list = pnn_list;
	state->count = count;
	state->caps = caps;
	state->ban_credits = ban_credits;
	state->db_id = db_id;
	state->recdb = recdb;
	state->index = 0;

	pnn = state->pnn_list[state->index];

	subreq = pull_database_send(state, ev, client, pnn, caps[pnn], recdb);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, collect_all_db_pulldb_done, req);

	return req;
}

static void collect_all_db_pulldb_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct collect_all_db_state *state = tevent_req_data(
		req, struct collect_all_db_state);
	uint32_t pnn;
	int ret;
	bool status;

	status = pull_database_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		pnn = state->pnn_list[state->index];
		state->ban_credits[pnn] += 1;
		tevent_req_error(req, ret);
		return;
	}

	state->index += 1;
	if (state->index == state->count) {
		tevent_req_done(req);
		return;
	}

	pnn = state->pnn_list[state->index];
	subreq = pull_database_send(state, state->ev, state->client,
				    pnn, state->caps[pnn], state->recdb);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, collect_all_db_pulldb_done, req);
}

static bool collect_all_db_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}


/**
 * For each database do the following:
 *  - Get DB name
 *  - Get DB path
 *  - Freeze database on all nodes
 *  - Start transaction on all nodes
 *  - Collect database from all nodes
 *  - Wipe database on all nodes
 *  - Push database to all nodes
 *  - Commit transaction on all nodes
 *  - Thaw database on all nodes
 */

struct recover_db_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_tunable_list *tun_list;
	uint32_t *pnn_list;
	int count;
	uint32_t *caps;
	uint32_t *ban_credits;
	uint32_t db_id;
	uint8_t db_flags;

	uint32_t destnode;
	struct ctdb_transdb transdb;

	const char *db_name, *db_path;
	struct recdb_context *recdb;
};

static void recover_db_name_done(struct tevent_req *subreq);
static void recover_db_path_done(struct tevent_req *subreq);
static void recover_db_freeze_done(struct tevent_req *subreq);
static void recover_db_transaction_started(struct tevent_req *subreq);
static void recover_db_collect_done(struct tevent_req *subreq);
static void recover_db_wipedb_done(struct tevent_req *subreq);
static void recover_db_pushdb_done(struct tevent_req *subreq);
static void recover_db_transaction_committed(struct tevent_req *subreq);
static void recover_db_thaw_done(struct tevent_req *subreq);

static struct tevent_req *recover_db_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_client_context *client,
					  struct ctdb_tunable_list *tun_list,
					  uint32_t *pnn_list, int count,
					  uint32_t *caps,
					  uint32_t *ban_credits,
					  uint32_t generation,
					  uint32_t db_id, uint8_t db_flags)
{
	struct tevent_req *req, *subreq;
	struct recover_db_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state, struct recover_db_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->tun_list = tun_list;
	state->pnn_list = pnn_list;
	state->count = count;
	state->caps = caps;
	state->ban_credits = ban_credits;
	state->db_id = db_id;
	state->db_flags = db_flags;

	state->destnode = ctdb_client_pnn(client);
	state->transdb.db_id = db_id;
	state->transdb.tid = generation;

	ctdb_req_control_get_dbname(&request, db_id);
	subreq = ctdb_client_control_send(state, ev, client, state->destnode,
					  TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, recover_db_name_done, req);

	return req;
}

static void recover_db_name_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control GET_DBNAME failed for db=0x%x, ret=%d\n",
		      state->db_id, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_dbname(reply, state, &state->db_name);
	if (ret != 0) {
		D_ERR("control GET_DBNAME failed for db=0x%x, ret=%d\n",
		      state->db_id, ret);
		tevent_req_error(req, EPROTO);
		return;
	}

	talloc_free(reply);

	ctdb_req_control_getdbpath(&request, state->db_id);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, TIMEOUT(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recover_db_path_done, req);
}

static void recover_db_path_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control GETDBPATH failed for db %s, ret=%d\n",
		      state->db_name, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_getdbpath(reply, state, &state->db_path);
	if (ret != 0) {
		D_ERR("control GETDBPATH failed for db %s, ret=%d\n",
		      state->db_name, ret);
		tevent_req_error(req, EPROTO);
		return;
	}

	talloc_free(reply);

	ctdb_req_control_db_freeze(&request, state->db_id);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recover_db_freeze_done, req);
}

static void recover_db_freeze_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	struct ctdb_req_control request;
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count, err_list,
						       &pnn);
		if (ret2 != 0) {
			D_ERR("control FREEZE_DB failed for db %s"
			      " on node %u, ret=%d\n",
			      state->db_name, pnn, ret2);
			state->ban_credits[pnn] += 1;
		} else {
			D_ERR("control FREEZE_DB failed for db %s, ret=%d\n",
			      state->db_name, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_db_transaction_start(&request, &state->transdb);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recover_db_transaction_started, req);
}

static void recover_db_transaction_started(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("control TRANSACTION_DB failed for db=%s"
			      " on node %u, ret=%d\n",
			      state->db_name, pnn, ret2);
		} else {
			D_ERR("control TRANSACTION_DB failed for db=%s,"
			      " ret=%d\n", state->db_name, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	state->recdb = recdb_create(state, state->db_id, state->db_name,
				    state->db_path,
				    state->tun_list->database_hash_size,
				    state->db_flags & CTDB_DB_FLAGS_PERSISTENT);
	if (tevent_req_nomem(state->recdb, req)) {
		return;
	}

	if ((state->db_flags & CTDB_DB_FLAGS_PERSISTENT) ||
	    (state->db_flags & CTDB_DB_FLAGS_REPLICATED)) {
		subreq = collect_highseqnum_db_send(
				state, state->ev, state->client,
				state->pnn_list, state->count, state->caps,
				state->ban_credits, state->db_id,
				state->recdb);
	} else {
		subreq = collect_all_db_send(
				state, state->ev, state->client,
				state->pnn_list, state->count, state->caps,
				state->ban_credits, state->db_id,
				state->recdb);
	}
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recover_db_collect_done, req);
}

static void recover_db_collect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	struct ctdb_req_control request;
	int ret;
	bool status;

	if ((state->db_flags & CTDB_DB_FLAGS_PERSISTENT) ||
	    (state->db_flags & CTDB_DB_FLAGS_REPLICATED)) {
		status = collect_highseqnum_db_recv(subreq, &ret);
	} else {
		status = collect_all_db_recv(subreq, &ret);
	}
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_wipe_database(&request, &state->transdb);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recover_db_wipedb_done, req);
}

static void recover_db_wipedb_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("control WIPEDB failed for db %s on node %u,"
			      " ret=%d\n", state->db_name, pnn, ret2);
		} else {
			D_ERR("control WIPEDB failed for db %s, ret=%d\n",
			      state->db_name, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	subreq = push_database_send(state, state->ev, state->client,
				    state->pnn_list, state->count,
				    state->caps, state->tun_list,
				    state->recdb);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recover_db_pushdb_done, req);
}

static void recover_db_pushdb_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	struct ctdb_req_control request;
	int ret;
	bool status;

	status = push_database_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	TALLOC_FREE(state->recdb);

	ctdb_req_control_db_transaction_commit(&request, &state->transdb);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recover_db_transaction_committed, req);
}

static void recover_db_transaction_committed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	struct ctdb_req_control request;
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("control DB_TRANSACTION_COMMIT failed for db %s"
			      " on node %u, ret=%d\n",
			      state->db_name, pnn, ret2);
		} else {
			D_ERR("control DB_TRANSACTION_COMMIT failed for db %s,"
			      " ret=%d\n", state->db_name, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_db_thaw(&request, state->db_id);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recover_db_thaw_done, req);
}

static void recover_db_thaw_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recover_db_state *state = tevent_req_data(
		req, struct recover_db_state);
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("control DB_THAW failed for db %s on node %u,"
			      " ret=%d\n", state->db_name, pnn, ret2);
		} else {
			D_ERR("control DB_THAW failed for db %s, ret=%d\n",
			      state->db_name, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool recover_db_recv(struct tevent_req *req)
{
	return generic_recv(req, NULL);
}


/*
 * Start database recovery for each database
 *
 * Try to recover each database 5 times before failing recovery.
 */

struct db_recovery_state {
	struct tevent_context *ev;
	struct ctdb_dbid_map *dbmap;
	int num_replies;
	int num_failed;
};

struct db_recovery_one_state {
	struct tevent_req *req;
	struct ctdb_client_context *client;
	struct ctdb_dbid_map *dbmap;
	struct ctdb_tunable_list *tun_list;
	uint32_t *pnn_list;
	int count;
	uint32_t *caps;
	uint32_t *ban_credits;
	uint32_t generation;
	uint32_t db_id;
	uint8_t db_flags;
	int num_fails;
};

static void db_recovery_one_done(struct tevent_req *subreq);

static struct tevent_req *db_recovery_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client,
					   struct ctdb_dbid_map *dbmap,
					   struct ctdb_tunable_list *tun_list,
					   uint32_t *pnn_list, int count,
					   uint32_t *caps,
					   uint32_t *ban_credits,
					   uint32_t generation)
{
	struct tevent_req *req, *subreq;
	struct db_recovery_state *state;
	int i;

	req = tevent_req_create(mem_ctx, &state, struct db_recovery_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->dbmap = dbmap;
	state->num_replies = 0;
	state->num_failed = 0;

	if (dbmap->num == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	for (i=0; i<dbmap->num; i++) {
		struct db_recovery_one_state *substate;

		substate = talloc_zero(state, struct db_recovery_one_state);
		if (tevent_req_nomem(substate, req)) {
			return tevent_req_post(req, ev);
		}

		substate->req = req;
		substate->client = client;
		substate->dbmap = dbmap;
		substate->tun_list = tun_list;
		substate->pnn_list = pnn_list;
		substate->count = count;
		substate->caps = caps;
		substate->ban_credits = ban_credits;
		substate->generation = generation;
		substate->db_id = dbmap->dbs[i].db_id;
		substate->db_flags = dbmap->dbs[i].flags;

		subreq = recover_db_send(state, ev, client, tun_list,
					 pnn_list, count, caps, ban_credits,
					 generation, substate->db_id,
					 substate->db_flags);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, db_recovery_one_done,
					substate);
		D_NOTICE("recover database 0x%08x\n", substate->db_id);
	}

	return req;
}

static void db_recovery_one_done(struct tevent_req *subreq)
{
	struct db_recovery_one_state *substate = tevent_req_callback_data(
		subreq, struct db_recovery_one_state);
	struct tevent_req *req = substate->req;
	struct db_recovery_state *state = tevent_req_data(
		req, struct db_recovery_state);
	bool status;

	status = recover_db_recv(subreq);
	TALLOC_FREE(subreq);

	if (status) {
		talloc_free(substate);
		goto done;
	}

	substate->num_fails += 1;
	if (substate->num_fails < NUM_RETRIES) {
		subreq = recover_db_send(state, state->ev, substate->client,
					 substate->tun_list,
					 substate->pnn_list, substate->count,
					 substate->caps, substate->ban_credits,
					 substate->generation, substate->db_id,
					 substate->db_flags);
		if (tevent_req_nomem(subreq, req)) {
			goto failed;
		}
		tevent_req_set_callback(subreq, db_recovery_one_done, substate);
		D_NOTICE("recover database 0x%08x, attempt %d\n",
			 substate->db_id, substate->num_fails+1);
		return;
	}

failed:
	state->num_failed += 1;

done:
	state->num_replies += 1;

	if (state->num_replies == state->dbmap->num) {
		tevent_req_done(req);
	}
}

static bool db_recovery_recv(struct tevent_req *req, int *count)
{
	struct db_recovery_state *state = tevent_req_data(
		req, struct db_recovery_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		*count = 0;
		return false;
	}

	*count = state->num_replies - state->num_failed;

	if (state->num_failed > 0) {
		return false;
	}

	return true;
}


/*
 * Run the parallel database recovery
 *
 * - Get tunables
 * - Get nodemap
 * - Get vnnmap
 * - Get capabilities from all nodes
 * - Get dbmap
 * - Set RECOVERY_ACTIVE
 * - Send START_RECOVERY
 * - Update vnnmap on all nodes
 * - Run database recovery
 * - Set RECOVERY_NORMAL
 * - Send END_RECOVERY
 */

struct recovery_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	uint32_t generation;
	uint32_t *pnn_list;
	int count;
	uint32_t destnode;
	struct ctdb_node_map *nodemap;
	uint32_t *caps;
	uint32_t *ban_credits;
	struct ctdb_tunable_list *tun_list;
	struct ctdb_vnn_map *vnnmap;
	struct ctdb_dbid_map *dbmap;
};

static void recovery_tunables_done(struct tevent_req *subreq);
static void recovery_nodemap_done(struct tevent_req *subreq);
static void recovery_vnnmap_done(struct tevent_req *subreq);
static void recovery_capabilities_done(struct tevent_req *subreq);
static void recovery_dbmap_done(struct tevent_req *subreq);
static void recovery_active_done(struct tevent_req *subreq);
static void recovery_start_recovery_done(struct tevent_req *subreq);
static void recovery_vnnmap_update_done(struct tevent_req *subreq);
static void recovery_db_recovery_done(struct tevent_req *subreq);
static void recovery_failed_done(struct tevent_req *subreq);
static void recovery_normal_done(struct tevent_req *subreq);
static void recovery_end_recovery_done(struct tevent_req *subreq);

static struct tevent_req *recovery_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint32_t generation)
{
	struct tevent_req *req, *subreq;
	struct recovery_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state, struct recovery_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->generation = generation;
	state->destnode = ctdb_client_pnn(client);

	ctdb_req_control_get_all_tunables(&request);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, TIMEOUT(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, recovery_tunables_done, req);

	return req;
}

static void recovery_tunables_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control GET_ALL_TUNABLES failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_all_tunables(reply, state,
						  &state->tun_list);
	if (ret != 0) {
		D_ERR("control GET_ALL_TUNABLES failed, ret=%d\n", ret);
		tevent_req_error(req, EPROTO);
		return;
	}

	talloc_free(reply);

	recover_timeout = state->tun_list->recover_timeout;

	ctdb_req_control_get_nodemap(&request);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, TIMEOUT(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_nodemap_done, req);
}

static void recovery_nodemap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control GET_NODEMAP failed to node %u, ret=%d\n",
		      state->destnode, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_nodemap(reply, state, &state->nodemap);
	if (ret != 0) {
		D_ERR("control GET_NODEMAP failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	state->count = list_of_active_nodes(state->nodemap, CTDB_UNKNOWN_PNN,
					    state, &state->pnn_list);
	if (state->count <= 0) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	state->ban_credits = talloc_zero_array(state, uint32_t,
					       state->nodemap->num);
	if (tevent_req_nomem(state->ban_credits, req)) {
		return;
	}

	ctdb_req_control_getvnnmap(&request);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, TIMEOUT(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_vnnmap_done, req);
}

static void recovery_vnnmap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control GETVNNMAP failed to node %u, ret=%d\n",
		      state->destnode, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_getvnnmap(reply, state, &state->vnnmap);
	if (ret != 0) {
		D_ERR("control GETVNNMAP failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_get_capabilities(&request);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_capabilities_done, req);
}

static void recovery_capabilities_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_reply_control **reply;
	struct ctdb_req_control request;
	int *err_list;
	int ret, i;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, state, &err_list,
						&reply);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("control GET_CAPABILITIES failed on node %u,"
			      " ret=%d\n", pnn, ret2);
		} else {
			D_ERR("control GET_CAPABILITIES failed, ret=%d\n",
			      ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	/* Make the array size same as nodemap */
	state->caps = talloc_zero_array(state, uint32_t,
					state->nodemap->num);
	if (tevent_req_nomem(state->caps, req)) {
		return;
	}

	for (i=0; i<state->count; i++) {
		uint32_t pnn;

		pnn = state->pnn_list[i];
		ret = ctdb_reply_control_get_capabilities(reply[i],
							  &state->caps[pnn]);
		if (ret != 0) {
			D_ERR("control GET_CAPABILITIES failed on node %u\n",
			      pnn);
			tevent_req_error(req, EPROTO);
			return;
		}
	}

	talloc_free(reply);

	ctdb_req_control_get_dbmap(&request);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, TIMEOUT(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_dbmap_done, req);
}

static void recovery_dbmap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control GET_DBMAP failed to node %u, ret=%d\n",
		      state->destnode, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_dbmap(reply, state, &state->dbmap);
	if (ret != 0) {
		D_ERR("control GET_DBMAP failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	ctdb_req_control_set_recmode(&request, CTDB_RECOVERY_ACTIVE);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_active_done, req);
}

static void recovery_active_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_req_control request;
	struct ctdb_vnn_map *vnnmap;
	int *err_list;
	int ret, count, i;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("failed to set recovery mode ACTIVE on node %u,"
			      " ret=%d\n", pnn, ret2);
		} else {
			D_ERR("failed to set recovery mode ACTIVE, ret=%d\n",
			      ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	D_ERR("Set recovery mode to ACTIVE\n");

	/* Calculate new VNNMAP */
	count = 0;
	for (i=0; i<state->nodemap->num; i++) {
		if (state->nodemap->node[i].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (!(state->caps[i] & CTDB_CAP_LMASTER)) {
			continue;
		}
		count += 1;
	}

	if (count == 0) {
		D_WARNING("No active lmasters found. Adding recmaster anyway\n");
	}

	vnnmap = talloc_zero(state, struct ctdb_vnn_map);
	if (tevent_req_nomem(vnnmap, req)) {
		return;
	}

	vnnmap->size = (count == 0 ? 1 : count);
	vnnmap->map = talloc_array(vnnmap, uint32_t, vnnmap->size);
	if (tevent_req_nomem(vnnmap->map, req)) {
		return;
	}

	if (count == 0) {
		vnnmap->map[0] = state->destnode;
	} else {
		count = 0;
		for (i=0; i<state->nodemap->num; i++) {
			if (state->nodemap->node[i].flags &
			    NODE_FLAGS_INACTIVE) {
				continue;
			}
			if (!(state->caps[i] & CTDB_CAP_LMASTER)) {
				continue;
			}

			vnnmap->map[count] = state->nodemap->node[i].pnn;
			count += 1;
		}
	}

	vnnmap->generation = state->generation;

	talloc_free(state->vnnmap);
	state->vnnmap = vnnmap;

	ctdb_req_control_start_recovery(&request);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_start_recovery_done, req);
}

static void recovery_start_recovery_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_req_control request;
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("failed to run start_recovery event on node %u,"
			      " ret=%d\n", pnn, ret2);
		} else {
			D_ERR("failed to run start_recovery event, ret=%d\n",
			      ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	D_ERR("start_recovery event finished\n");

	ctdb_req_control_setvnnmap(&request, state->vnnmap);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_vnnmap_update_done, req);
}

static void recovery_vnnmap_update_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, NULL, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("failed to update VNNMAP on node %u, ret=%d\n",
			      pnn, ret2);
		} else {
			D_ERR("failed to update VNNMAP, ret=%d\n", ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	D_NOTICE("updated VNNMAP\n");

	subreq = db_recovery_send(state, state->ev, state->client,
				  state->dbmap, state->tun_list,
				  state->pnn_list, state->count,
				  state->caps, state->ban_credits,
				  state->vnnmap->generation);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_db_recovery_done, req);
}

static void recovery_db_recovery_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_req_control request;
	bool status;
	int count;

	status = db_recovery_recv(subreq, &count);
	TALLOC_FREE(subreq);

	D_ERR("%d of %d databases recovered\n", count, state->dbmap->num);

	if (! status) {
		uint32_t max_pnn = CTDB_UNKNOWN_PNN, max_credits = 0;
		int i;

		/* Bans are not enabled */
		if (state->tun_list->enable_bans == 0) {
			tevent_req_error(req, EIO);
			return;
		}

		for (i=0; i<state->count; i++) {
			uint32_t pnn;
			pnn = state->pnn_list[i];
			if (state->ban_credits[pnn] > max_credits) {
				max_pnn = pnn;
				max_credits = state->ban_credits[pnn];
			}
		}

		/* If pulling database fails multiple times */
		if (max_credits >= NUM_RETRIES) {
			struct ctdb_req_message message;

			D_ERR("Assigning banning credits to node %u\n",
			      max_pnn);

			message.srvid = CTDB_SRVID_BANNING;
			message.data.pnn = max_pnn;

			subreq = ctdb_client_message_send(
					state, state->ev, state->client,
					ctdb_client_pnn(state->client),
					&message);
			if (tevent_req_nomem(subreq, req)) {
				return;
			}
			tevent_req_set_callback(subreq, recovery_failed_done,
						req);
		} else {
			tevent_req_error(req, EIO);
		}
		return;
	}

	ctdb_req_control_set_recmode(&request, CTDB_RECOVERY_NORMAL);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_normal_done, req);
}

static void recovery_failed_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = ctdb_client_message_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("failed to assign banning credits, ret=%d\n", ret);
	}

	tevent_req_error(req, EIO);
}

static void recovery_normal_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	struct ctdb_req_control request;
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, state, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("failed to set recovery mode NORMAL on node %u,"
			      " ret=%d\n", pnn, ret2);
		} else {
			D_ERR("failed to set recovery mode NORMAL, ret=%d\n",
			      ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	D_ERR("Set recovery mode to NORMAL\n");

	ctdb_req_control_end_recovery(&request);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_end_recovery_done, req);
}

static void recovery_end_recovery_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct recovery_state *state = tevent_req_data(
		req, struct recovery_state);
	int *err_list;
	int ret;
	bool status;

	status = ctdb_client_control_multi_recv(subreq, &ret, state, &err_list,
						NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		int ret2;
		uint32_t pnn;

		ret2 = ctdb_client_control_multi_error(state->pnn_list,
						       state->count,
						       err_list, &pnn);
		if (ret2 != 0) {
			D_ERR("failed to run recovered event on node %u,"
			      " ret=%d\n", pnn, ret2);
		} else {
			D_ERR("failed to run recovered event, ret=%d\n", ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	D_ERR("recovered event finished\n");

	tevent_req_done(req);
}

static void recovery_recv(struct tevent_req *req, int *perr)
{
	generic_recv(req, perr);
}

static void usage(const char *progname)
{
	fprintf(stderr, "\nUsage: %s <output-fd> <ctdb-socket-path> <generation>\n",
		progname);
}


/*
 * Arguments - log fd, write fd, socket path, generation
 */
int main(int argc, char *argv[])
{
	int write_fd;
	const char *sockpath;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	int ret;
	struct tevent_req *req;
	uint32_t generation;

	if (argc != 4) {
		usage(argv[0]);
		exit(1);
	}

	write_fd = atoi(argv[1]);
	sockpath = argv[2];
	generation = (uint32_t)strtoul(argv[3], NULL, 0);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "recovery: talloc_new() failed\n");
		goto failed;
	}

	ret = logging_init(mem_ctx, NULL, NULL, "ctdb-recovery");
	if (ret != 0) {
		fprintf(stderr, "recovery: Unable to initialize logging\n");
		goto failed;
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		D_ERR("tevent_context_init() failed\n");
		goto failed;
	}

	ret = ctdb_client_init(mem_ctx, ev, sockpath, &client);
	if (ret != 0) {
		D_ERR("ctdb_client_init() failed, ret=%d\n", ret);
		goto failed;
	}

	req = recovery_send(mem_ctx, ev, client, generation);
	if (req == NULL) {
		D_ERR("database_recover_send() failed\n");
		goto failed;
	}

	if (! tevent_req_poll(req, ev)) {
		D_ERR("tevent_req_poll() failed\n");
		goto failed;
	}

	recovery_recv(req, &ret);
	TALLOC_FREE(req);
	if (ret != 0) {
		D_ERR("database recovery failed, ret=%d\n", ret);
		goto failed;
	}

	sys_write(write_fd, &ret, sizeof(ret));
	return 0;

failed:
	TALLOC_FREE(mem_ctx);
	return 1;
}
