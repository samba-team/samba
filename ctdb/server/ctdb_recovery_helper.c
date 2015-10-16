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
#include "lib/util/time.h"
#include "lib/util/tevent_unix.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "client/client.h"

#define TIMEOUT()	timeval_current_ofs(10, 0)

static void LOG(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/*
 * Utility functions
 */

static ssize_t sys_write(int fd, const void *buf, size_t count)
{
        ssize_t ret;

        do {
                ret = write(fd, buf, count);
#if defined(EWOULDBLOCK)
        } while (ret == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
#else
        } while (ret == -1 && (errno == EINTR || errno == EAGAIN));
#endif
        return ret;
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
	struct recdb_context *recdb;
	unsigned int tdb_flags;

	recdb = talloc(mem_ctx, struct recdb_context);
	if (recdb == NULL) {
		return NULL;
	}

	recdb->db_name = db_name;
	recdb->db_id = db_id;
	recdb->db_path = talloc_asprintf(recdb, "%s/recdb.%s",
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
		LOG("failed to create recovery db %s\n", recdb->db_path);
	}

	recdb->persistent = persistent;

	return recdb;
}

static const char *recdb_name(struct recdb_context *recdb)
{
	return recdb->db_name;
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
	prev_data = tdb_fetch(state->recdb->db->tdb, key);

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

	ret = tdb_store(state->recdb->db->tdb, key, data, TDB_REPLACE);
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

struct recdb_traverse_state {
	struct ctdb_rec_buffer *recbuf;
	uint32_t pnn;
	uint32_t reqid;
	bool persistent;
	bool failed;
};

static int recdb_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data,
			  void *private_data)
{
	struct recdb_traverse_state *state =
		(struct recdb_traverse_state *)private_data;
	struct ctdb_ltdb_header *header;
	int ret;

	/*
	 * skip empty records - but NOT for persistent databases:
	 *
	 * The record-by-record mode of recovery deletes empty records.
	 * For persistent databases, this can lead to data corruption
	 * by deleting records that should be there:
	 *
	 * - Assume the cluster has been running for a while.
	 *
	 * - A record R in a persistent database has been created and
	 *   deleted a couple of times, the last operation being deletion,
	 *   leaving an empty record with a high RSN, say 10.
	 *
	 * - Now a node N is turned off.
	 *
	 * - This leaves the local database copy of D on N with the empty
	 *   copy of R and RSN 10. On all other nodes, the recovery has deleted
	 *   the copy of record R.
	 *
	 * - Now the record is created again while node N is turned off.
	 *   This creates R with RSN = 1 on all nodes except for N.
	 *
	 * - Now node N is turned on again. The following recovery will chose
	 *   the older empty copy of R due to RSN 10 > RSN 1.
	 *
	 * ==> Hence the record is gone after the recovery.
	 *
	 * On databases like Samba's registry, this can damage the higher-level
	 * data structures built from the various tdb-level records.
	 */
	if (!state->persistent &&
	    data.dsize <= sizeof(struct ctdb_ltdb_header)) {
		return 0;
	}

	/* update the dmaster field to point to us */
	header = (struct ctdb_ltdb_header *)data.dptr;
	if (!state->persistent) {
		header->dmaster = state->pnn;
		header->flags |= CTDB_REC_FLAG_MIGRATED_WITH_DATA;
	}

	ret = ctdb_rec_buffer_add(state->recbuf, state->recbuf, state->reqid,
				  NULL, key, data);
	if (ret != 0) {
		state->failed = true;
		return ret;
	}

	return 0;
}

static struct ctdb_rec_buffer *recdb_records(struct recdb_context *recdb,
					     TALLOC_CTX *mem_ctx, uint32_t pnn)
{
	struct recdb_traverse_state state;
	int ret;

	state.recbuf = ctdb_rec_buffer_init(mem_ctx, recdb->db_id);
	if (state.recbuf == NULL) {
		return NULL;
	}
	state.pnn = pnn;
	state.reqid = 0;
	state.persistent = recdb->persistent;
	state.failed = false;

	ret = tdb_traverse_read(recdb->db->tdb, recdb_traverse, &state);
	if (ret == -1 || state.failed) {
		TALLOC_FREE(state.recbuf);
		return NULL;
	}

	return state.recbuf;
}

/*
 * Collect databases using highest sequence number
 */

struct collect_highseqnum_db_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	uint32_t *pnn_list;
	int count;
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
			uint32_t *pnn_list, int count,
			uint32_t db_id, struct recdb_context *recdb)
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
	struct ctdb_req_control request;
	struct ctdb_pulldb pulldb;
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
			LOG("control GET_DB_SEQNUM failed for %s on node %u,"
			    " ret=%d\n", recdb_name(state->recdb), pnn, ret2);
		} else {
			LOG("control GET_DB_SEQNUM failed for %s, ret=%d\n",
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

	LOG("Pull persistent db %s from node %d with seqnum 0x%"PRIx64"\n",
	    recdb_name(state->recdb), state->max_pnn, max_seqnum);

	pulldb.db_id = state->db_id;
	pulldb.lmaster = CTDB_LMASTER_ANY;

	ctdb_req_control_pull_db(&request, &pulldb);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->max_pnn, TIMEOUT(), &request);
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
	struct ctdb_reply_control *reply;
	struct ctdb_rec_buffer *recbuf;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		LOG("control PULL_DB failed for %s on node %u, ret=%d\n",
		    recdb_name(state->recdb), state->max_pnn, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_pull_db(reply, state, &recbuf);
	if (ret != 0) {
		tevent_req_error(req, EPROTO);
		return;
	}

	talloc_free(reply);

	ret = recdb_add(state->recdb, ctdb_client_pnn(state->client), recbuf);
	talloc_free(recbuf);
	if (! ret) {
		tevent_req_error(req, EIO);
		return;
	}

	tevent_req_done(req);
}

static bool collect_highseqnum_db_recv(struct tevent_req *req, int *perr)
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

/*
 * Collect all databases
 */

struct collect_all_db_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	uint32_t *pnn_list;
	int count;
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
			uint32_t *pnn_list, int count,
			uint32_t db_id, struct recdb_context *recdb)
{
	struct tevent_req *req, *subreq;
	struct collect_all_db_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state,
				struct collect_all_db_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->pnn_list = pnn_list;
	state->count = count;
	state->db_id = db_id;
	state->recdb = recdb;

	state->pulldb.db_id = db_id;
	state->pulldb.lmaster = CTDB_LMASTER_ANY;

	state->index = 0;

	ctdb_req_control_pull_db(&request, &state->pulldb);
	subreq = ctdb_client_control_send(state, ev, client,
					  state->pnn_list[state->index],
					  TIMEOUT(), &request);
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
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	struct ctdb_rec_buffer *recbuf;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		LOG("control PULL_DB failed for %s from node %u, ret=%d\n",
		    recdb_name(state->recdb), state->pnn_list[state->index],
		    ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_pull_db(reply, state, &recbuf);
	if (ret != 0) {
		LOG("control PULL_DB failed for %s, ret=%d\n",
		    recdb_name(state->recdb), ret);
		tevent_req_error(req, EPROTO);
		return;
	}

	talloc_free(reply);

	status = recdb_add(state->recdb, ctdb_client_pnn(state->client), recbuf);
	talloc_free(recbuf);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	state->index += 1;
	if (state->index == state->count) {
		tevent_req_done(req);
		return;
	}

	ctdb_req_control_pull_db(&request, &state->pulldb);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->pnn_list[state->index],
					  TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, collect_all_db_pulldb_done, req);
}

static bool collect_all_db_recv(struct tevent_req *req, int *perr)
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
	uint32_t db_id;
	bool persistent;

	uint32_t destnode;
	struct ctdb_transdb transdb;

	const char *db_name, *db_path;
	struct recdb_context *recdb;
	struct ctdb_rec_buffer *recbuf;

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
					  uint32_t generation,
					  uint32_t db_id, bool persistent)
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
	state->db_id = db_id;
	state->persistent = persistent;

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
		LOG("control GET_DBNAME failed for db=0x%x\n, ret=%d",
		    state->db_id, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_dbname(reply, state, &state->db_name);
	if (ret != 0) {
		LOG("control GET_DBNAME failed for db=0x%x\n, ret=%d\n",
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
		LOG("control GETDBPATH failed for db %s, ret=%d\n",
		    state->db_name, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_getdbpath(reply, state, &state->db_path);
	if (ret != 0) {
		LOG("control GETDBPATH failed for db %s, ret=%d\n",
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
			LOG("control FREEZE_DB failed for db %s on node %u,"
			    " ret=%d\n", state->db_name, pnn, ret2);
		} else {
			LOG("control FREEZE_DB failed for db %s, ret=%d\n",
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
			LOG("control TRANSACTION_DB failed for db=%s,"
			    " ret=%d\n", state->db_name, pnn, ret2);
		} else {
			LOG("control TRANSACTION_DB failed for db=%s,"
			    " ret=%d\n", state->db_name, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	state->recdb = recdb_create(state, state->db_id, state->db_name,
				    state->db_path,
				    state->tun_list->database_hash_size,
				    state->persistent);
	if (tevent_req_nomem(state->recdb, req)) {
		return;
	}

	if (state->persistent && state->tun_list->recover_pdb_by_seqnum != 0) {
		subreq = collect_highseqnum_db_send(
				state, state->ev, state->client,
				state->pnn_list, state->count,
				state->db_id, state->recdb);
	} else {
		subreq = collect_all_db_send(
				state, state->ev, state->client,
				state->pnn_list, state->count,
				state->db_id, state->recdb);
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

	if (state->persistent && state->tun_list->recover_pdb_by_seqnum != 0) {
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
			LOG("control WIPEDB failed for db %s on node %u,"
			    " ret=%d\n", state->db_name, pnn, ret2);
		} else {
			LOG("control WIPEDB failed for db %s, ret=%d\n",
			    state->db_name, pnn, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	state->recbuf = recdb_records(state->recdb, state, state->destnode);
	if (tevent_req_nomem(state->recbuf, req)) {
		return;
	}

	TALLOC_FREE(state->recdb);

	ctdb_req_control_push_db(&request, state->recbuf);
	subreq = ctdb_client_control_multi_send(state, state->ev,
						state->client,
						state->pnn_list, state->count,
						TIMEOUT(), &request);
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
			LOG("control PUSHDB failed for db %s on node %u,"
			    " ret=%d\n", state->db_name, pnn, ret2);
		} else {
			LOG("control PUSHDB failed for db %s, ret=%d\n",
			    state->db_name, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	TALLOC_FREE(state->recbuf);

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
			LOG("control DB_TRANSACTION_COMMIT failed for db %s"
			    " on node %u, ret=%d", state->db_name, pnn, ret2);
		} else {
			LOG("control DB_TRANSACTION_COMMIT failed for db %s\n,"
			    " ret=%d", state->db_name, ret);
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
			LOG("control DB_THAW failed for db %s on node %u,"
			    " ret=%d\n", state->db_name, pnn, ret2);
		} else {
			LOG("control DB_THAW failed for db %s, ret=%d\n",
			    state->db_name, ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool recover_db_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return false;
	}

	return true;
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
	uint32_t generation;
	uint32_t db_id;
	bool persistent;
	int num_fails;
};

static void db_recovery_one_done(struct tevent_req *subreq);

static struct tevent_req *db_recovery_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client,
					   struct ctdb_dbid_map *dbmap,
					   struct ctdb_tunable_list *tun_list,
					   uint32_t *pnn_list, int count,
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
		substate->generation = generation;
		substate->db_id = dbmap->dbs[i].db_id;
		substate->persistent = dbmap->dbs[i].flags &
				       CTDB_DB_FLAGS_PERSISTENT;

		subreq = recover_db_send(state, ev, client, tun_list,
					 pnn_list, count, generation,
					 substate->db_id,
					 substate->persistent);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, db_recovery_one_done,
					substate);
		LOG("recover database 0x%08x\n", substate->db_id);
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
	if (substate->num_fails < 5) {
		subreq = recover_db_send(state, state->ev, substate->client,
					 substate->tun_list,
					 substate->pnn_list, substate->count,
					 substate->generation, substate->db_id,
					 substate->persistent);
		if (tevent_req_nomem(subreq, req)) {
			goto failed;
		}
		tevent_req_set_callback(subreq, db_recovery_one_done, substate);
		LOG("recover database 0x%08x, attempt %d\n", substate->db_id,
		    substate->num_fails+1);
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
 * - Get nodemap
 * - Get vnnmap
 * - Get capabilities from all nodes
 * - Get tunables from all nodes
 * - Get dbmap
 * - Set RECOVERY_ACTIVE
 * - Send START_RECOVERY
 * - Update vnnmap on all nodes
 * - Run database recovery
 * - Send END_RECOVERY
 * - Set RECOVERY_NORMAL
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
	struct ctdb_tunable_list *tun_list;
	struct ctdb_vnn_map *vnnmap;
	struct ctdb_dbid_map *dbmap;
};

static void recovery_nodemap_done(struct tevent_req *subreq);
static void recovery_vnnmap_done(struct tevent_req *subreq);
static void recovery_capabilities_done(struct tevent_req *subreq);
static void recovery_tunables_done(struct tevent_req *subreq);
static void recovery_dbmap_done(struct tevent_req *subreq);
static void recovery_active_done(struct tevent_req *subreq);
static void recovery_start_recovery_done(struct tevent_req *subreq);
static void recovery_vnnmap_update_done(struct tevent_req *subreq);
static void recovery_db_recovery_done(struct tevent_req *subreq);
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

	ctdb_req_control_get_nodemap(&request);
	subreq = ctdb_client_control_send(mem_ctx, ev, client, state->destnode,
					  TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, recovery_nodemap_done, req);

	return req;
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
		LOG("control GET_NODEMAP failed to node %u, ret=%d\n",
		    state->destnode, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_nodemap(reply, state, &state->nodemap);
	if (ret != 0) {
		LOG("control GET_NODEMAP failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	state->count = list_of_active_nodes(state->nodemap, CTDB_UNKNOWN_PNN,
					    state, &state->pnn_list);
	if (state->count <= 0) {
		tevent_req_error(req, ENOMEM);
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
		LOG("control GETVNNMAP failed to node %u, ret=%d\n",
		    state->destnode, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_getvnnmap(reply, state, &state->vnnmap);
	if (ret != 0) {
		LOG("control GETVNNMAP failed, ret=%d\n", ret);
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
			LOG("control GET_CAPABILITIES failed on node %u,"
			    " ret=%d\n", pnn, ret2);
		} else {
			LOG("control GET_CAPABILITIES failed, ret=%d\n", ret);
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
			LOG("control GET_CAPABILITIES failed on node %u\n", pnn);
			tevent_req_error(req, EPROTO);
			return;
		}
	}

	talloc_free(reply);

	ctdb_req_control_get_all_tunables(&request);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, TIMEOUT(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, recovery_tunables_done, req);
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
		LOG("control GET_ALL_TUNABLES failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_all_tunables(reply, state,
						  &state->tun_list);
	if (ret != 0) {
		LOG("control GET_ALL_TUNABLES failed, ret=%d\n", ret);
		tevent_req_error(req, EPROTO);
		return;
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
		LOG("control GET_DBMAP failed to node %u, ret=%d\n",
		    state->destnode, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_dbmap(reply, state, &state->dbmap);
	if (ret != 0) {
		LOG("control GET_DBMAP failed, ret=%d\n", ret);
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
			LOG("failed to set recovery mode to ACTIVE on node %u,"
			    " ret=%d\n", pnn, ret2);
		} else {
			LOG("failed to set recovery mode to ACTIVE, ret=%d\n",
			    ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	LOG("set recovery mode to ACTIVE\n");

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
		LOG("no active lmasters found. Adding recmaster anyway\n");
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
			LOG("failed to run start_recovery event on node %u,"
			    " ret=%d\n", pnn, ret2);
		} else {
			LOG("failed to run start_recovery event, ret=%d\n",
			    ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	LOG("start_recovery event finished\n");

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
			LOG("failed to update VNNMAP on node %u, ret=%d\n",
			    pnn, ret2);
		} else {
			LOG("failed to update VNNMAP, ret=%d\n", ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	LOG("updated VNNMAP\n");

	subreq = db_recovery_send(state, state->ev, state->client,
				  state->dbmap, state->tun_list,
				  state->pnn_list, state->count,
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

	LOG("%d databases recovered\n", count);

	if (! status) {
		tevent_req_error(req, EIO);
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
			LOG("failed to set recovery mode to NORMAL on node %u,"
			    " ret=%d\n", pnn, ret2);
		} else {
			LOG("failed to set recovery mode to NORMAL, ret=%d\n",
			    ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	LOG("set recovery mode to NORMAL\n");

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
			LOG("failed to run recovered event on node %u,"
			    " ret=%d\n", pnn, ret2);
		} else {
			LOG("failed to run recovered event, ret=%d\n", ret);
		}
		tevent_req_error(req, ret);
		return;
	}

	LOG("recovered event finished\n");

	tevent_req_done(req);
}

static void recovery_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return;
	}
}

static void usage(const char *progname)
{
	fprintf(stderr, "\nUsage: %s <log-fd> <output-fd> <ctdb-socket-path> <generation>\n",
		progname);
}


/*
 * Arguments - log fd, write fd, socket path, generation
 */
int main(int argc, char *argv[])
{
	int log_fd, write_fd;
	const char *sockpath;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	int ret;
	struct tevent_req *req;
	uint32_t generation;

	if (argc != 5) {
		usage(argv[0]);
		exit(1);
	}

	log_fd = atoi(argv[1]);
	if (log_fd != STDOUT_FILENO && log_fd != STDERR_FILENO) {
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		dup2(log_fd, STDOUT_FILENO);
		dup2(log_fd, STDERR_FILENO);
	}
	close(log_fd);

	write_fd = atoi(argv[2]);
	sockpath = argv[3];
	generation = (uint32_t)strtoul(argv[4], NULL, 0);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		LOG("talloc_new() failed\n");
		goto failed;
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		LOG("tevent_context_init() failed\n");
		goto failed;
	}

	ret = ctdb_client_init(mem_ctx, ev, sockpath, &client);
	if (ret != 0) {
		LOG("ctdb_client_init() failed, ret=%d\n", ret);
		goto failed;
	}

	req = recovery_send(mem_ctx, ev, client, generation);
	if (req == NULL) {
		LOG("database_recover_send() failed\n");
		goto failed;
	}

	if (! tevent_req_poll(req, ev)) {
		LOG("tevent_req_poll() failed\n");
		goto failed;
	}

	recovery_recv(req, &ret);
	TALLOC_FREE(req);
	if (ret != 0) {
		LOG("database recovery failed, ret=%d\n", ret);
		goto failed;
	}

	sys_write(write_fd, &ret, sizeof(ret));
	return 0;

failed:
	talloc_free(mem_ctx);
	return 1;
}
