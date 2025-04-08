/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2011-2012
   Copyright (C) Michael Adam 2012

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
#include "smbXsrv_session.h"
#include "system/filesys.h"
#include <tevent.h>
#include "lib/util/server_id.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "dbwrap/dbwrap_open.h"
#include "dbwrap/dbwrap_watch.h"
#include "session.h"
#include "auth.h"
#include "auth/gensec/gensec.h"
#include "../lib/tsocket/tsocket.h"
#include "../libcli/security/security.h"
#include "messages.h"
#include "lib/util/util_tdb.h"
#include "librpc/gen_ndr/ndr_smbXsrv.h"
#include "serverid.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/global_contexts.h"
#include "source3/include/util_tdb.h"

struct smbXsrv_session_table {
	struct {
		struct db_context *db_ctx;
		uint32_t lowest_id;
		uint32_t highest_id;
		uint32_t max_sessions;
		uint32_t num_sessions;
	} local;
	struct {
		struct db_context *db_ctx;
	} global;
};

static struct db_context *smbXsrv_session_global_db_ctx = NULL;

NTSTATUS smbXsrv_session_global_init(struct messaging_context *msg_ctx)
{
	char *global_path = NULL;
	struct db_context *backend = NULL;
	struct db_context *db_ctx = NULL;

	if (smbXsrv_session_global_db_ctx != NULL) {
		return NT_STATUS_OK;
	}

	/*
	 * This contains secret information like session keys!
	 */
	global_path = lock_path(talloc_tos(), "smbXsrv_session_global.tdb");
	if (global_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	backend = db_open(NULL, global_path,
			  SMBD_VOLATILE_TDB_HASH_SIZE,
			  SMBD_VOLATILE_TDB_FLAGS,
			  O_RDWR | O_CREAT, 0600,
			  DBWRAP_LOCK_ORDER_1,
			  DBWRAP_FLAG_NONE);
	TALLOC_FREE(global_path);
	if (backend == NULL) {
		NTSTATUS status;

		status = map_nt_error_from_unix_common(errno);

		return status;
	}

	db_ctx = db_open_watched(NULL, &backend, global_messaging_context());
	if (db_ctx == NULL) {
		TALLOC_FREE(backend);
		return NT_STATUS_NO_MEMORY;
	}

	smbXsrv_session_global_db_ctx = db_ctx;

	return NT_STATUS_OK;
}

/*
 * NOTE:
 * We need to store the keys in big endian so that dbwrap_rbt's memcmp
 * has the same result as integer comparison between the uint32_t
 * values.
 *
 * TODO: implement string based key
 */

#define SMBXSRV_SESSION_GLOBAL_TDB_KEY_SIZE sizeof(uint32_t)

static TDB_DATA smbXsrv_session_global_id_to_key(uint32_t id,
						 uint8_t *key_buf)
{
	TDB_DATA key;

	RSIVAL(key_buf, 0, id);

	key = make_tdb_data(key_buf, SMBXSRV_SESSION_GLOBAL_TDB_KEY_SIZE);

	return key;
}

#if 0
static NTSTATUS smbXsrv_session_global_key_to_id(TDB_DATA key, uint32_t *id)
{
	if (id == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (key.dsize != SMBXSRV_SESSION_GLOBAL_TDB_KEY_SIZE) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*id = RIVAL(key.dptr, 0);

	return NT_STATUS_OK;
}
#endif

#define SMBXSRV_SESSION_LOCAL_TDB_KEY_SIZE sizeof(uint32_t)

static TDB_DATA smbXsrv_session_local_id_to_key(uint32_t id,
						uint8_t *key_buf)
{
	TDB_DATA key;

	RSIVAL(key_buf, 0, id);

	key = make_tdb_data(key_buf, SMBXSRV_SESSION_LOCAL_TDB_KEY_SIZE);

	return key;
}

static NTSTATUS smbXsrv_session_local_key_to_id(TDB_DATA key, uint32_t *id)
{
	if (id == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (key.dsize != SMBXSRV_SESSION_LOCAL_TDB_KEY_SIZE) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*id = RIVAL(key.dptr, 0);

	return NT_STATUS_OK;
}

static struct db_record *smbXsrv_session_global_fetch_locked(
			struct db_context *db,
			uint32_t id,
			TALLOC_CTX *mem_ctx)
{
	TDB_DATA key;
	uint8_t key_buf[SMBXSRV_SESSION_GLOBAL_TDB_KEY_SIZE];
	struct db_record *rec = NULL;

	key = smbXsrv_session_global_id_to_key(id, key_buf);

	rec = dbwrap_fetch_locked(db, mem_ctx, key);

	if (rec == NULL) {
		DBG_DEBUG("Failed to lock global id 0x%08x, key '%s'\n", id,
			  tdb_data_dbg(key));
	}

	return rec;
}

static struct db_record *smbXsrv_session_local_fetch_locked(
			struct db_context *db,
			uint32_t id,
			TALLOC_CTX *mem_ctx)
{
	TDB_DATA key;
	uint8_t key_buf[SMBXSRV_SESSION_LOCAL_TDB_KEY_SIZE];
	struct db_record *rec = NULL;

	key = smbXsrv_session_local_id_to_key(id, key_buf);

	rec = dbwrap_fetch_locked(db, mem_ctx, key);

	if (rec == NULL) {
		DBG_DEBUG("Failed to lock local id 0x%08x, key '%s'\n", id,
			  tdb_data_dbg(key));
	}

	return rec;
}

static void smbXsrv_session_close_loop(struct tevent_req *subreq);

static NTSTATUS smbXsrv_session_table_init(struct smbXsrv_connection *conn,
					   uint32_t lowest_id,
					   uint32_t highest_id,
					   uint32_t max_sessions)
{
	struct smbXsrv_client *client = conn->client;
	struct smbXsrv_session_table *table;
	NTSTATUS status;
	struct tevent_req *subreq;
	uint64_t max_range;

	if (lowest_id > highest_id) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	max_range = highest_id;
	max_range -= lowest_id;
	max_range += 1;

	if (max_sessions > max_range) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	table = talloc_zero(client, struct smbXsrv_session_table);
	if (table == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	table->local.db_ctx = db_open_rbt(table);
	if (table->local.db_ctx == NULL) {
		TALLOC_FREE(table);
		return NT_STATUS_NO_MEMORY;
	}
	table->local.lowest_id = lowest_id;
	table->local.highest_id = highest_id;
	table->local.max_sessions = max_sessions;

	status = smbXsrv_session_global_init(client->msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(table);
		return status;
	}

	table->global.db_ctx = smbXsrv_session_global_db_ctx;

	subreq = messaging_read_send(table,
				     client->raw_ev_ctx,
				     client->msg_ctx,
				     MSG_SMBXSRV_SESSION_CLOSE);
	if (subreq == NULL) {
		TALLOC_FREE(table);
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smbXsrv_session_close_loop, client);

	client->session_table = table;
	return NT_STATUS_OK;
}

static void smbXsrv_session_close_shutdown_done(struct tevent_req *subreq);

static void smbXsrv_session_close_loop(struct tevent_req *subreq)
{
	struct smbXsrv_client *client =
		tevent_req_callback_data(subreq,
		struct smbXsrv_client);
	struct smbXsrv_session_table *table = client->session_table;
	int ret;
	struct messaging_rec *rec = NULL;
	struct smbXsrv_session_closeB close_blob;
	enum ndr_err_code ndr_err;
	struct smbXsrv_session_close0 *close_info0 = NULL;
	struct smbXsrv_session *session = NULL;
	NTSTATUS status;
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);

	ret = messaging_read_recv(subreq, talloc_tos(), &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		goto next;
	}

	ndr_err = ndr_pull_struct_blob(&rec->buf, rec, &close_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_session_closeB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("ndr_pull_struct_blob - %s\n", nt_errstr(status));
		goto next;
	}

	DBG_DEBUG("MSG_SMBXSRV_SESSION_CLOSE\n");
	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_session_closeB, &close_blob);
	}

	if (close_blob.version != SMBXSRV_VERSION_0) {
		DBG_ERR("ignore invalid version %u\n", close_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_session_closeB, &close_blob);
		goto next;
	}

	close_info0 = close_blob.info.info0;
	if (close_info0 == NULL) {
		DBG_ERR("ignore NULL info %u\n", close_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_session_closeB, &close_blob);
		goto next;
	}

	status = smb2srv_session_lookup_client(client,
					       close_info0->old_session_wire_id,
					       now, &session);
	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_SESSION_DELETED)) {
		DBG_INFO("old_session_wire_id %" PRIu64 " not found\n",
			 close_info0->old_session_wire_id);
		if (DEBUGLVL(DBGLVL_INFO)) {
			NDR_PRINT_DEBUG(smbXsrv_session_closeB, &close_blob);
		}
		goto next;
	}
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		DBG_WARNING("old_session_wire_id %" PRIu64 " - %s\n",
			    close_info0->old_session_wire_id,
			    nt_errstr(status));
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_session_closeB, &close_blob);
		}
		goto next;
	}

	if (session->global->session_global_id != close_info0->old_session_global_id) {
		DBG_WARNING("old_session_wire_id %" PRIu64 " - "
			    "global %" PRIu32 " != %" PRIu32 "\n",
			    close_info0->old_session_wire_id,
			    session->global->session_global_id,
			    close_info0->old_session_global_id);
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_session_closeB, &close_blob);
		}
		goto next;
	}

	if (session->global->creation_time != close_info0->old_creation_time) {
		DBG_WARNING("old_session_wire_id %" PRIu64 " - "
			    "creation %s (%" PRIu64 ") != %s (%" PRIu64 ")\n",
			    close_info0->old_session_wire_id,
			    nt_time_string(rec,
					   session->global->creation_time),
			    session->global->creation_time,
			    nt_time_string(rec,
					   close_info0->old_creation_time),
			    close_info0->old_creation_time);
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_session_closeB, &close_blob);
		}
		goto next;
	}

	subreq = smb2srv_session_shutdown_send(session, client->raw_ev_ctx,
					       session, NULL);
	if (subreq == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DBG_ERR("smb2srv_session_shutdown_send(%" PRIu64
			") failed: %s\n",
			session->global->session_wire_id,
			nt_errstr(status));
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_session_closeB, &close_blob);
		}
		goto next;
	}
	tevent_req_set_callback(subreq,
				smbXsrv_session_close_shutdown_done,
				session);

next:
	TALLOC_FREE(rec);

	subreq = messaging_read_send(table,
				     client->raw_ev_ctx,
				     client->msg_ctx,
				     MSG_SMBXSRV_SESSION_CLOSE);
	if (subreq == NULL) {
		const char *r;
		r = "messaging_read_send(MSG_SMBXSRV_SESSION_CLOSE) failed";
		exit_server_cleanly(r);
		return;
	}
	tevent_req_set_callback(subreq, smbXsrv_session_close_loop, client);
}

static void smbXsrv_session_close_shutdown_done(struct tevent_req *subreq)
{
	struct smbXsrv_session *session =
		tevent_req_callback_data(subreq,
		struct smbXsrv_session);
	NTSTATUS status;

	status = smb2srv_session_shutdown_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smb2srv_session_shutdown_recv(%" PRIu64
			") failed: %s\n",
			session->global->session_wire_id,
			nt_errstr(status));
	}

	status = smbXsrv_session_logoff(session);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smbXsrv_session_logoff(%" PRIu64 ") failed: %s\n",
			session->global->session_wire_id,
			nt_errstr(status));
	}

	TALLOC_FREE(session);
}

struct smb1srv_session_local_allocate_state {
	const uint32_t lowest_id;
	const uint32_t highest_id;
	uint32_t last_id;
	uint32_t useable_id;
	NTSTATUS status;
};

static int smb1srv_session_local_allocate_traverse(struct db_record *rec,
						   void *private_data)
{
	struct smb1srv_session_local_allocate_state *state =
		(struct smb1srv_session_local_allocate_state *)private_data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	uint32_t id = 0;
	NTSTATUS status;

	status = smbXsrv_session_local_key_to_id(key, &id);
	if (!NT_STATUS_IS_OK(status)) {
		state->status = status;
		return -1;
	}

	if (id <= state->last_id) {
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return -1;
	}
	state->last_id = id;

	if (id > state->useable_id) {
		state->status = NT_STATUS_OK;
		return -1;
	}

	if (state->useable_id == state->highest_id) {
		state->status = NT_STATUS_INSUFFICIENT_RESOURCES;
		return -1;
	}

	state->useable_id +=1;
	return 0;
}

static NTSTATUS smb1srv_session_local_allocate_id(struct db_context *db,
						  uint32_t lowest_id,
						  uint32_t highest_id,
						  TALLOC_CTX *mem_ctx,
						  struct db_record **_rec,
						  uint32_t *_id)
{
	struct smb1srv_session_local_allocate_state state = {
		.lowest_id = lowest_id,
		.highest_id = highest_id,
		.last_id = 0,
		.useable_id = lowest_id,
		.status = NT_STATUS_INTERNAL_ERROR,
	};
	uint32_t i;
	uint32_t range;
	NTSTATUS status;
	int count = 0;

	*_rec = NULL;
	*_id = 0;

	if (lowest_id > highest_id) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	/*
	 * first we try randomly
	 */
	range = (highest_id - lowest_id) + 1;

	for (i = 0; i < (range / 2); i++) {
		uint32_t id;
		TDB_DATA val;
		struct db_record *rec = NULL;

		id = generate_random() % range;
		id += lowest_id;

		if (id < lowest_id) {
			id = lowest_id;
		}
		if (id > highest_id) {
			id = highest_id;
		}

		rec = smbXsrv_session_local_fetch_locked(db, id, mem_ctx);
		if (rec == NULL) {
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}

		val = dbwrap_record_get_value(rec);
		if (val.dsize != 0) {
			TALLOC_FREE(rec);
			continue;
		}

		*_rec = rec;
		*_id = id;
		return NT_STATUS_OK;
	}

	/*
	 * if the range is almost full,
	 * we traverse the whole table
	 * (this relies on sorted behavior of dbwrap_rbt)
	 */
	status = dbwrap_traverse_read(db, smb1srv_session_local_allocate_traverse,
				      &state, &count);
	if (NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_IS_OK(state.status)) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		if (!NT_STATUS_EQUAL(state.status, NT_STATUS_INTERNAL_ERROR)) {
			return state.status;
		}

		if (state.useable_id <= state.highest_id) {
			state.status = NT_STATUS_OK;
		} else {
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}
	} else if (!NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_DB_CORRUPTION)) {
		/*
		 * Here we really expect NT_STATUS_INTERNAL_DB_CORRUPTION!
		 *
		 * If we get anything else it is an error, because it
		 * means we did not manage to find a free slot in
		 * the db.
		 */
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	if (NT_STATUS_IS_OK(state.status)) {
		uint32_t id;
		TDB_DATA val;
		struct db_record *rec = NULL;

		id = state.useable_id;

		rec = smbXsrv_session_local_fetch_locked(db, id, mem_ctx);
		if (rec == NULL) {
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}

		val = dbwrap_record_get_value(rec);
		if (val.dsize != 0) {
			TALLOC_FREE(rec);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		*_rec = rec;
		*_id = id;
		return NT_STATUS_OK;
	}

	return state.status;
}

struct smbXsrv_session_local_fetch_state {
	struct smbXsrv_session *session;
	NTSTATUS status;
};

static void smbXsrv_session_local_fetch_parser(TDB_DATA key, TDB_DATA data,
					       void *private_data)
{
	struct smbXsrv_session_local_fetch_state *state =
		(struct smbXsrv_session_local_fetch_state *)private_data;
	void *ptr;

	if (data.dsize != sizeof(ptr)) {
		state->status = NT_STATUS_INTERNAL_DB_ERROR;
		return;
	}

	memcpy(&ptr, data.dptr, data.dsize);
	state->session = talloc_get_type_abort(ptr, struct smbXsrv_session);
	state->status = NT_STATUS_OK;
}

static NTSTATUS smbXsrv_session_local_lookup(struct smbXsrv_session_table *table,
					     /* conn: optional */
					     struct smbXsrv_connection *conn,
					     uint32_t session_local_id,
					     NTTIME now,
					     struct smbXsrv_session **_session)
{
	struct smbXsrv_session_local_fetch_state state = {
		.session = NULL,
		.status = NT_STATUS_INTERNAL_ERROR,
	};
	uint8_t key_buf[SMBXSRV_SESSION_LOCAL_TDB_KEY_SIZE];
	TDB_DATA key;
	NTSTATUS status;

	*_session = NULL;

	if (session_local_id == 0) {
		return NT_STATUS_USER_SESSION_DELETED;
	}

	if (table == NULL) {
		/* this might happen before the end of negprot */
		return NT_STATUS_USER_SESSION_DELETED;
	}

	if (table->local.db_ctx == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = smbXsrv_session_local_id_to_key(session_local_id, key_buf);

	status = dbwrap_parse_record(table->local.db_ctx, key,
				     smbXsrv_session_local_fetch_parser,
				     &state);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		return NT_STATUS_USER_SESSION_DELETED;
	} else if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		return state.status;
	}

	if (NT_STATUS_EQUAL(state.session->status, NT_STATUS_USER_SESSION_DELETED)) {
		return NT_STATUS_USER_SESSION_DELETED;
	}

	/*
	 * If a connection is specified check if the session is
	 * valid on the channel.
	 */
	if (conn != NULL) {
		struct smbXsrv_channel_global0 *c = NULL;

		status = smbXsrv_session_find_channel(state.session, conn, &c);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	state.session->idle_time = now;

	if (!NT_STATUS_IS_OK(state.session->status)) {
		*_session = state.session;
		return state.session->status;
	}

	if (now > state.session->global->expiration_time) {
		state.session->status = NT_STATUS_NETWORK_SESSION_EXPIRED;
	}

	*_session = state.session;
	return state.session->status;
}

static int smbXsrv_session_global_destructor(struct smbXsrv_session_global0 *global)
{
	return 0;
}

static void smbXsrv_session_global_verify_record(struct db_record *db_rec,
					bool *is_free,
					bool *was_free,
					TALLOC_CTX *mem_ctx,
					struct smbXsrv_session_global0 **_g,
					uint32_t *pseqnum);

static NTSTATUS smbXsrv_session_global_allocate(struct db_context *db,
					TALLOC_CTX *mem_ctx,
					struct smbXsrv_session_global0 **_global)
{
	uint32_t i;
	struct smbXsrv_session_global0 *global = NULL;
	uint32_t last_free = 0;
	const uint32_t min_tries = 3;

	*_global = NULL;

	global = talloc_zero(mem_ctx, struct smbXsrv_session_global0);
	if (global == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(global, smbXsrv_session_global_destructor);

	/*
	 * Here we just randomly try the whole 32-bit space
	 *
	 * We use just 32-bit, because we want to reuse the
	 * ID for SRVSVC.
	 */
	for (i = 0; i < UINT32_MAX; i++) {
		bool is_free = false;
		bool was_free = false;
		uint32_t id;

		if (i >= min_tries && last_free != 0) {
			id = last_free;
		} else {
			id = generate_random();
		}
		if (id == 0) {
			id++;
		}
		if (id == UINT32_MAX) {
			id--;
		}

		global->db_rec = smbXsrv_session_global_fetch_locked(db, id,
								     mem_ctx);
		if (global->db_rec == NULL) {
			talloc_free(global);
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}

		smbXsrv_session_global_verify_record(global->db_rec,
						     &is_free,
						     &was_free,
						     NULL, NULL, NULL);

		if (!is_free) {
			TALLOC_FREE(global->db_rec);
			continue;
		}

		if (!was_free && i < min_tries) {
			/*
			 * The session_id is free now,
			 * but was not free before.
			 *
			 * This happens if a smbd crashed
			 * and did not cleanup the record.
			 *
			 * If this is one of our first tries,
			 * then we try to find a real free one.
			 */
			if (last_free == 0) {
				last_free = id;
			}
			TALLOC_FREE(global->db_rec);
			continue;
		}

		global->session_global_id = id;

		*_global = global;
		return NT_STATUS_OK;
	}

	/* should not be reached */
	talloc_free(global);
	return NT_STATUS_INTERNAL_ERROR;
}

static void smbXsrv_session_global_verify_record(struct db_record *db_rec,
					bool *is_free,
					bool *was_free,
					TALLOC_CTX *mem_ctx,
					struct smbXsrv_session_global0 **_g,
					uint32_t *pseqnum)
{
	TDB_DATA key;
	TDB_DATA val;
	DATA_BLOB blob;
	struct smbXsrv_session_globalB global_blob;
	enum ndr_err_code ndr_err;
	struct smbXsrv_session_global0 *global = NULL;
	bool exists;
	TALLOC_CTX *frame = talloc_stackframe();

	*is_free = false;

	if (was_free) {
		*was_free = false;
	}
	if (_g) {
		*_g = NULL;
	}
	if (pseqnum) {
		*pseqnum = 0;
	}

	key = dbwrap_record_get_key(db_rec);

	val = dbwrap_record_get_value(db_rec);
	if (val.dsize == 0) {
		TALLOC_FREE(frame);
		*is_free = true;
		if (was_free) {
			*was_free = true;
		}
		return;
	}

	blob = data_blob_const(val.dptr, val.dsize);

	ndr_err = ndr_pull_struct_blob(&blob, frame, &global_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_session_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("key '%s' ndr_pull_struct_blob - %s\n",
			    tdb_data_dbg(key),
			    nt_errstr(status));
		TALLOC_FREE(frame);
		*is_free = true;
		if (was_free) {
			*was_free = true;
		}
		return;
	}

	DBG_DEBUG("smbXsrv_session_global_verify_record\n");
	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_session_globalB, &global_blob);
	}

	if (global_blob.version != SMBXSRV_VERSION_0) {
		DBG_ERR("key '%s' use unsupported version %u\n",
			tdb_data_dbg(key),
			global_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_session_globalB, &global_blob);
		TALLOC_FREE(frame);
		*is_free = true;
		if (was_free) {
			*was_free = true;
		}
		return;
	}

	global = global_blob.info.info0;

#define __BLOB_KEEP_SECRET(__blob) do { \
	if ((__blob).length != 0) { \
		talloc_keep_secret((__blob).data); \
	} \
} while(0)
	{
		uint32_t i;
		__BLOB_KEEP_SECRET(global->application_key_blob);
		__BLOB_KEEP_SECRET(global->signing_key_blob);
		__BLOB_KEEP_SECRET(global->encryption_key_blob);
		__BLOB_KEEP_SECRET(global->decryption_key_blob);
		for (i = 0; i < global->num_channels; i++) {
			__BLOB_KEEP_SECRET(global->channels[i].signing_key_blob);
		}
	}
#undef __BLOB_KEEP_SECRET

	exists = serverid_exists(&global->channels[0].server_id);
	if (!exists) {
		struct server_id_buf idbuf;
		DBG_NOTICE("key '%s' server_id %s does not exist.\n",
			   tdb_data_dbg(key),
			   server_id_str_buf(global->channels[0].server_id,
					     &idbuf));
		if (DEBUGLVL(DBGLVL_NOTICE)) {
			NDR_PRINT_DEBUG(smbXsrv_session_globalB, &global_blob);
		}
		TALLOC_FREE(frame);
		dbwrap_record_delete(db_rec);
		*is_free = true;
		return;
	}

	if (_g) {
		*_g = talloc_move(mem_ctx, &global);
	}
	if (pseqnum) {
		*pseqnum = global_blob.seqnum;
	}
	TALLOC_FREE(frame);
}

static NTSTATUS smbXsrv_session_global_store(struct smbXsrv_session_global0 *global)
{
	struct smbXsrv_session_globalB global_blob;
	DATA_BLOB blob = data_blob_null;
	TDB_DATA key;
	TDB_DATA val;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	/*
	 * TODO: if we use other versions than '0'
	 * we would add glue code here, that would be able to
	 * store the information in the old format.
	 */

	key = dbwrap_record_get_key(global->db_rec);
	val = dbwrap_record_get_value(global->db_rec);

	global_blob = (struct smbXsrv_session_globalB){
		.version = smbXsrv_version_global_current(),
		.info.info0 = global,
	};

	if (val.dsize >= 8) {
		global_blob.seqnum = IVAL(val.dptr, 4);
	}
	global_blob.seqnum += 1;

	ndr_err = ndr_push_struct_blob(
		&blob,
		talloc_tos(),
		&global_blob,
		(ndr_push_flags_fn_t)ndr_push_smbXsrv_session_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("key '%s' ndr_push - %s\n",
			    tdb_data_dbg(key),
			    nt_errstr(status));
		TALLOC_FREE(global->db_rec);
		return status;
	}

	val = make_tdb_data(blob.data, blob.length);
	status = dbwrap_record_store(global->db_rec, val, TDB_REPLACE);
	TALLOC_FREE(blob.data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("key '%s' store - %s\n",
			    tdb_data_dbg(key),
			    nt_errstr(status));
		TALLOC_FREE(global->db_rec);
		return status;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("key '%s' stored\n", tdb_data_dbg(key));
		NDR_PRINT_DEBUG(smbXsrv_session_globalB, &global_blob);
	}

	TALLOC_FREE(global->db_rec);

	return NT_STATUS_OK;
}

struct smb2srv_session_close_previous_state {
	struct tevent_context *ev;
	struct smbXsrv_connection *connection;
	struct dom_sid *current_sid;
	uint64_t previous_session_id;
	uint64_t current_session_id;
	struct db_record *db_rec;
	uint64_t watch_instance;
	uint32_t last_seqnum;
};

static void smb2srv_session_close_previous_cleanup(struct tevent_req *req,
						   enum tevent_req_state req_state)
{
	struct smb2srv_session_close_previous_state *state =
		tevent_req_data(req,
		struct smb2srv_session_close_previous_state);

	if (state->db_rec != NULL) {
		dbwrap_watched_watch_remove_instance(state->db_rec,
						     state->watch_instance);
		state->watch_instance = 0;
		TALLOC_FREE(state->db_rec);
	}
}

static void smb2srv_session_close_previous_check(struct tevent_req *req);
static void smb2srv_session_close_previous_modified(struct tevent_req *subreq);

struct tevent_req *smb2srv_session_close_previous_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbXsrv_connection *conn,
					struct auth_session_info *session_info,
					uint64_t previous_session_id,
					uint64_t current_session_id)
{
	struct tevent_req *req = NULL;
	struct smb2srv_session_close_previous_state *state = NULL;
	uint32_t global_id = previous_session_id & UINT32_MAX;
	uint64_t global_zeros = previous_session_id & 0xFFFFFFFF00000000LLU;
	struct smbXsrv_session_table *table = conn->client->session_table;
	struct security_token *current_token = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2srv_session_close_previous_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->connection = conn;
	state->previous_session_id = previous_session_id;
	state->current_session_id = current_session_id;

	tevent_req_set_cleanup_fn(req, smb2srv_session_close_previous_cleanup);

	if (global_zeros != 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (session_info == NULL) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	current_token = session_info->security_token;

	if (current_token->num_sids <= PRIMARY_USER_SID_INDEX) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	state->current_sid = &current_token->sids[PRIMARY_USER_SID_INDEX];

	if (!security_token_has_nt_authenticated_users(current_token)) {
		/* TODO */
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	state->db_rec = smbXsrv_session_global_fetch_locked(
							table->global.db_ctx,
							global_id,
							state /* TALLOC_CTX */);
	if (state->db_rec == NULL) {
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, ev);
	}

	smb2srv_session_close_previous_check(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void smb2srv_session_close_previous_check(struct tevent_req *req)
{
	struct smb2srv_session_close_previous_state *state =
		tevent_req_data(req,
		struct smb2srv_session_close_previous_state);
	struct smbXsrv_connection *conn = state->connection;
	DATA_BLOB blob;
	struct security_token *previous_token = NULL;
	struct smbXsrv_session_global0 *global = NULL;
	enum ndr_err_code ndr_err;
	struct smbXsrv_session_close0 close_info0;
	struct smbXsrv_session_closeB close_blob;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;
	bool is_free = false;
	uint32_t seqnum = 0;

	smbXsrv_session_global_verify_record(state->db_rec,
					     &is_free,
					     NULL,
					     state,
					     &global,
					     &seqnum);

	if (is_free) {
		tevent_req_done(req);
		return;
	}

	if (global->auth_session_info == NULL) {
		tevent_req_done(req);
		return;
	}

	previous_token = global->auth_session_info->security_token;

	if (!security_token_is_sid(previous_token, state->current_sid)) {
		tevent_req_done(req);
		return;
	}

	/*
	 * If the record changed, but we are not happy with the change yet,
	 * we better remove ourself from the waiter list
	 * (most likely the first position)
	 * and re-add us at the end of the list.
	 *
	 * This gives other waiters a change
	 * to make progress.
	 *
	 * Otherwise we'll keep our waiter instance alive,
	 * keep waiting (most likely at first position).
	 * It means the order of watchers stays fair.
	 */
	if (state->last_seqnum != seqnum) {
		state->last_seqnum = seqnum;
		dbwrap_watched_watch_remove_instance(state->db_rec,
						     state->watch_instance);
		state->watch_instance =
			dbwrap_watched_watch_add_instance(state->db_rec);
	}

	subreq = dbwrap_watched_watch_send(state, state->ev, state->db_rec,
					   state->watch_instance,
					   (struct server_id){0});
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				smb2srv_session_close_previous_modified,
				req);

	close_info0 = (struct smbXsrv_session_close0){
		.old_session_global_id = global->session_global_id,
		.old_session_wire_id = global->session_wire_id,
		.old_creation_time = global->creation_time,
		.new_session_wire_id = state->current_session_id,
	};

	close_blob = (struct smbXsrv_session_closeB){
		.version = smbXsrv_version_global_current(),
		.info.info0 = &close_info0,
	};

	ndr_err = ndr_push_struct_blob(&blob, state, &close_blob,
			(ndr_push_flags_fn_t)ndr_push_smbXsrv_session_closeB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("old_session[%" PRIu64 "] "
			    "new_session[%" PRIu64 "] ndr_push - %s\n",
			    close_info0.old_session_wire_id,
			    close_info0.new_session_wire_id,
			    nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}

	status = messaging_send(conn->client->msg_ctx,
				global->channels[0].server_id,
				MSG_SMBXSRV_SESSION_CLOSE, &blob);
	TALLOC_FREE(global);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	TALLOC_FREE(state->db_rec);
	return;
}

static void smb2srv_session_close_previous_modified(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2srv_session_close_previous_state *state =
		tevent_req_data(req,
		struct smb2srv_session_close_previous_state);
	uint32_t global_id;
	NTSTATUS status;
	uint64_t instance = 0;

	status = dbwrap_watched_watch_recv(subreq, &instance, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->watch_instance = instance;

	global_id = state->previous_session_id & UINT32_MAX;

	state->db_rec = smbXsrv_session_global_fetch_locked(
		state->connection->client->session_table->global.db_ctx,
		global_id, state /* TALLOC_CTX */);
	if (state->db_rec == NULL) {
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	smb2srv_session_close_previous_check(req);
}

NTSTATUS smb2srv_session_close_previous_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static NTSTATUS smbXsrv_session_clear_and_logoff(struct smbXsrv_session *session)
{
	NTSTATUS status;
	struct smbXsrv_connection *xconn = NULL;

	if (session->client != NULL) {
		xconn = session->client->connections;
	}

	for (; xconn != NULL; xconn = xconn->next) {
		struct smbd_smb2_request *preq;

		for (preq = xconn->smb2.requests; preq != NULL; preq = preq->next) {
			if (preq->session != session) {
				continue;
			}

			preq->session = NULL;
			/*
			 * If we no longer have a session we can't
			 * sign or encrypt replies.
			 */
			preq->do_signing = false;
			preq->do_encryption = false;
			preq->preauth = NULL;
		}
	}

	status = smbXsrv_session_logoff(session);
	return status;
}

static int smbXsrv_session_destructor(struct smbXsrv_session *session)
{
	NTSTATUS status;

	DBG_DEBUG("destructing session(%" PRIu64 ")\n",
		  session->global->session_wire_id);

	status = smbXsrv_session_clear_and_logoff(session);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smbXsrv_session_logoff() failed: %s\n",
			nt_errstr(status));
	}

	TALLOC_FREE(session->global);

	return 0;
}

NTSTATUS smbXsrv_session_create(struct smbXsrv_connection *conn,
				NTTIME now,
				struct smbXsrv_session **_session)
{
	struct smbXsrv_session_table *table = conn->client->session_table;
	struct db_record *local_rec = NULL;
	struct smbXsrv_session *session = NULL;
	void *ptr = NULL;
	TDB_DATA val;
	struct smbXsrv_session_global0 *global = NULL;
	struct smbXsrv_channel_global0 *channel = NULL;
	NTSTATUS status;

	if (table->local.num_sessions >= table->local.max_sessions) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	session = talloc_zero(table, struct smbXsrv_session);
	if (session == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	session->table = table;
	session->idle_time = now;
	session->status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	session->client = conn->client;
	session->homes_snum = -1;

	status = smbXsrv_session_global_allocate(table->global.db_ctx,
						 session,
						 &global);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(session);
		return status;
	}
	session->global = global;

	if (conn->protocol >= PROTOCOL_SMB2_02) {
		uint64_t id = global->session_global_id;

		global->connection_dialect = conn->smb2.server.dialect;
		global->client_guid = conn->smb2.client.guid;

		global->session_wire_id = id;

		status = smb2srv_tcon_table_init(session);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(session);
			return status;
		}

		session->local_id = global->session_global_id;

		local_rec = smbXsrv_session_local_fetch_locked(
						table->local.db_ctx,
						session->local_id,
						session /* TALLOC_CTX */);
		if (local_rec == NULL) {
			TALLOC_FREE(session);
			return NT_STATUS_NO_MEMORY;
		}

		val = dbwrap_record_get_value(local_rec);
		if (val.dsize != 0) {
			TALLOC_FREE(session);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else {

		status = smb1srv_session_local_allocate_id(table->local.db_ctx,
							table->local.lowest_id,
							table->local.highest_id,
							session,
							&local_rec,
							&session->local_id);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(session);
			return status;
		}

		global->session_wire_id = session->local_id;
	}

	global->creation_time = now;
	global->expiration_time = GENSEC_EXPIRE_TIME_INFINITY;

	status = smbXsrv_session_add_channel(session, conn, now, &channel);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(session);
		return status;
	}

	ptr = session;
	val = make_tdb_data((uint8_t const *)&ptr, sizeof(ptr));
	status = dbwrap_record_store(local_rec, val, TDB_REPLACE);
	TALLOC_FREE(local_rec);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(session);
		return status;
	}
	table->local.num_sessions += 1;

	talloc_set_destructor(session, smbXsrv_session_destructor);

	status = smbXsrv_session_global_store(global);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("global_id (0x%08x) store failed - %s\n",
			session->global->session_global_id,
			nt_errstr(status));
		TALLOC_FREE(session);
		return status;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		struct smbXsrv_sessionB session_blob = {
			.version = SMBXSRV_VERSION_0,
			.info.info0 = session,
		};

		DBG_DEBUG("global_id (0x%08x) stored\n",
			  session->global->session_global_id);
		NDR_PRINT_DEBUG(smbXsrv_sessionB, &session_blob);
	}

	*_session = session;
	return NT_STATUS_OK;
}

NTSTATUS smbXsrv_session_add_channel(struct smbXsrv_session *session,
				     struct smbXsrv_connection *conn,
				     NTTIME now,
				     struct smbXsrv_channel_global0 **_c)
{
	struct smbXsrv_session_global0 *global = session->global;
	struct smbXsrv_channel_global0 *c = NULL;

	if (global->num_channels > 31) {
		/*
		 * Windows allow up to 32 channels
		 */
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	c = talloc_realloc(global,
			   global->channels,
			   struct smbXsrv_channel_global0,
			   global->num_channels + 1);
	if (c == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	global->channels = c;

	c = &global->channels[global->num_channels];

	*c = (struct smbXsrv_channel_global0){
		.server_id = messaging_server_id(conn->client->msg_ctx),
		.channel_id = conn->channel_id,
		.creation_time = now,
		.connection = conn,
		.transport_type = conn->transport.type,
	};

	c->local_address = tsocket_address_string(conn->local_address,
						  global->channels);
	if (c->local_address == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	c->remote_address = tsocket_address_string(conn->remote_address,
						   global->channels);
	if (c->remote_address == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	c->remote_name = talloc_strdup(global->channels,
				       conn->remote_hostname);
	if (c->remote_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	global->num_channels += 1;

	*_c = c;
	return NT_STATUS_OK;
}

NTSTATUS smbXsrv_session_update(struct smbXsrv_session *session)
{
	struct smbXsrv_session_table *table = session->table;
	NTSTATUS status;

	if (session->global->db_rec != NULL) {
		DBG_ERR("smbXsrv_session_update(0x%08x): "
			  "Called with db_rec != NULL'\n",
			  session->global->session_global_id);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (table == NULL) {
		DBG_ERR("smbXsrv_session_update(0x%08x): "
			  "Called with table == NULL'\n",
			  session->global->session_global_id);
		return NT_STATUS_INTERNAL_ERROR;
	}

	session->global->db_rec = smbXsrv_session_global_fetch_locked(
					table->global.db_ctx,
					session->global->session_global_id,
					session->global /* TALLOC_CTX */);
	if (session->global->db_rec == NULL) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	status = smbXsrv_session_global_store(session->global);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("global_id (0x%08x) store failed - %s\n",
			session->global->session_global_id,
			nt_errstr(status));
		return status;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		struct smbXsrv_sessionB session_blob = {
			.version = SMBXSRV_VERSION_0,
			.info.info0 = session,
		};

		DBG_DEBUG("global_id (0x%08x) stored\n",
			  session->global->session_global_id);
		NDR_PRINT_DEBUG(smbXsrv_sessionB, &session_blob);
	}

	return NT_STATUS_OK;
}

NTSTATUS smbXsrv_session_find_channel(const struct smbXsrv_session *session,
				      const struct smbXsrv_connection *conn,
				      struct smbXsrv_channel_global0 **_c)
{
	uint32_t i;

	for (i=0; i < session->global->num_channels; i++) {
		struct smbXsrv_channel_global0 *c = &session->global->channels[i];

		if (c->channel_id != conn->channel_id) {
			continue;
		}

		if (c->connection != conn) {
			continue;
		}

		*_c = c;
		return NT_STATUS_OK;
	}

	return NT_STATUS_USER_SESSION_DELETED;
}

NTSTATUS smbXsrv_session_find_auth(const struct smbXsrv_session *session,
				   const struct smbXsrv_connection *conn,
				   NTTIME now,
				   struct smbXsrv_session_auth0 **_a)
{
	struct smbXsrv_session_auth0 *a;

	for (a = session->pending_auth; a != NULL; a = a->next) {
		if (a->channel_id != conn->channel_id) {
			continue;
		}

		if (a->connection == conn) {
			if (now != 0) {
				a->idle_time = now;
			}
			*_a = a;
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_USER_SESSION_DELETED;
}

static int smbXsrv_session_auth0_destructor(struct smbXsrv_session_auth0 *a)
{
	if (a->session == NULL) {
		return 0;
	}

	DLIST_REMOVE(a->session->pending_auth, a);
	a->session = NULL;
	return 0;
}

NTSTATUS smbXsrv_session_create_auth(struct smbXsrv_session *session,
				     struct smbXsrv_connection *conn,
				     NTTIME now,
				     uint8_t in_flags,
				     uint8_t in_security_mode,
				     struct smbXsrv_session_auth0 **_a)
{
	struct smbXsrv_session_auth0 *a;
	NTSTATUS status;

	status = smbXsrv_session_find_auth(session, conn, 0, &a);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	a = talloc(session, struct smbXsrv_session_auth0);
	if (a == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*a = (struct smbXsrv_session_auth0){
		.session = session,
		.connection = conn,
		.in_flags = in_flags,
		.in_security_mode = in_security_mode,
		.creation_time = now,
		.idle_time = now,
		.channel_id = conn->channel_id,
	};

	if (conn->protocol >= PROTOCOL_SMB3_11) {
		a->preauth = talloc(a, struct smbXsrv_preauth);
		if (a->preauth == NULL) {
			TALLOC_FREE(session);
			return NT_STATUS_NO_MEMORY;
		}
		*a->preauth = conn->smb2.preauth;
	}

	talloc_set_destructor(a, smbXsrv_session_auth0_destructor);
	DLIST_ADD_END(session->pending_auth, a);

	*_a = a;
	return NT_STATUS_OK;
}

static void smbXsrv_session_remove_channel_done(struct tevent_req *subreq);

NTSTATUS smbXsrv_session_remove_channel(struct smbXsrv_session *session,
					struct smbXsrv_connection *xconn)
{
	struct smbXsrv_session_auth0 *a = NULL;
	struct smbXsrv_channel_global0 *c = NULL;
	NTSTATUS status;
	bool need_update = false;

	status = smbXsrv_session_find_auth(session, xconn, 0, &a);
	if (!NT_STATUS_IS_OK(status)) {
		a = NULL;
	}
	status = smbXsrv_session_find_channel(session, xconn, &c);
	if (!NT_STATUS_IS_OK(status)) {
		c = NULL;
	}

	if (a != NULL) {
		smbXsrv_session_auth0_destructor(a);
		a->connection = NULL;
		need_update = true;
	}

	if (c != NULL) {
		struct smbXsrv_session_global0 *global = session->global;
		ptrdiff_t n;

		n = (c - global->channels);
		if (n >= global->num_channels || n < 0) {
			return NT_STATUS_INTERNAL_ERROR;
		}
		ARRAY_DEL_ELEMENT(global->channels, n, global->num_channels);
		global->num_channels--;
		if (global->num_channels == 0) {
			struct smbXsrv_client *client = session->client;
			struct tevent_queue *xconn_wait_queue =
				xconn->transport.shutdown_wait_queue;
			struct tevent_req *subreq = NULL;

			/*
			 * Let the connection wait until the session is
			 * destroyed.
			 *
			 * We don't set a callback, as we just want to block the
			 * wait queue and the talloc_free() of the session will
			 * remove the item from the wait queue in order
			 * to remove allow the connection to disappear.
			 */
			if (xconn_wait_queue != NULL) {
				subreq = tevent_queue_wait_send(session,
								client->raw_ev_ctx,
								xconn_wait_queue);
				if (subreq == NULL) {
					status = NT_STATUS_NO_MEMORY;
					DBG_ERR("tevent_queue_wait_send() "
						"session(%" PRIu64
						") failed: %s\n",
						session->global
							->session_wire_id,
						nt_errstr(status));
					return status;
				}
			}

			/*
			 * This is guaranteed to set
			 * session->status = NT_STATUS_USER_SESSION_DELETED
			 * even if NULL is returned.
			 */
			subreq = smb2srv_session_shutdown_send(session,
							       client->raw_ev_ctx,
							       session,
							       NULL);
			if (subreq == NULL) {
				status = NT_STATUS_NO_MEMORY;
				DBG_ERR("smb2srv_session_shutdown_send("
					"%" PRIu64 " failed: %s\n",
					session->global->session_wire_id,
					nt_errstr(status));
				return status;
			}
			tevent_req_set_callback(subreq,
						smbXsrv_session_remove_channel_done,
						session);
		}
		need_update = true;
	}

	if (!need_update) {
		return NT_STATUS_OK;
	}

	return smbXsrv_session_update(session);
}

static void smbXsrv_session_remove_channel_done(struct tevent_req *subreq)
{
	struct smbXsrv_session *session =
		tevent_req_callback_data(subreq,
		struct smbXsrv_session);
	NTSTATUS status;

	status = smb2srv_session_shutdown_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smb2srv_session_shutdown_recv(%" PRIu64
			") failed: %s\n",
			session->global->session_wire_id,
			nt_errstr(status));
	}

	status = smbXsrv_session_logoff(session);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smbXsrv_session_logoff(%" PRIu64 ") failed: %s\n",
			session->global->session_wire_id,
			nt_errstr(status));
	}

	TALLOC_FREE(session);
}

struct smb2srv_session_shutdown_state {
	struct tevent_queue *wait_queue;
};

static void smb2srv_session_shutdown_wait_done(struct tevent_req *subreq);

struct check_for_lease_break_fsp_cmp_state {
	struct smbXsrv_session *session;
};

static bool check_for_lease_break_fsp_cmp_fn(struct files_struct *fsp,
					     void *private_data)
{
	struct check_for_lease_break_fsp_cmp_state *state =
		(struct check_for_lease_break_fsp_cmp_state *)private_data;

	return (fsp->vuid == state->session->global->session_wire_id);
}

struct tevent_req *smb2srv_session_shutdown_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbXsrv_session *session,
					struct smbd_smb2_request *current_req)
{
	struct tevent_req *req = NULL;
	struct smb2srv_session_shutdown_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct smbXsrv_connection *xconn = NULL;
	struct check_for_lease_break_fsp_cmp_state fsp_cmp_state;
	size_t len = 0;

	/*
	 * Make sure that no new request will be able to use this session.
	 */
	session->status = NT_STATUS_USER_SESSION_DELETED;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2srv_session_shutdown_state);
	if (req == NULL) {
		return NULL;
	}

	state->wait_queue = tevent_queue_create(state, "smb2srv_session_shutdown_queue");
	if (tevent_req_nomem(state->wait_queue, req)) {
		return tevent_req_post(req, ev);
	}

	for (xconn = session->client->connections; xconn != NULL; xconn = xconn->next) {
		struct smbd_smb2_request *preq;

		for (preq = xconn->smb2.requests; preq != NULL; preq = preq->next) {
			if (preq == current_req) {
				/* Can't cancel current request. */
				continue;
			}
			if (preq->session != session) {
				/* Request on different session. */
				continue;
			}

			if (preq->subreq != NULL) {
				tevent_req_cancel(preq->subreq);
			}

			/*
			 * Now wait until the request is finished.
			 *
			 * We don't set a callback, as we just want to block the
			 * wait queue and the talloc_free() of the request will
			 * remove the item from the wait queue.
			 */
			subreq = tevent_queue_wait_send(preq, ev, state->wait_queue);
			if (tevent_req_nomem(subreq, req)) {
				return tevent_req_post(req, ev);
			}
		}
	}

	fsp_cmp_state = (struct check_for_lease_break_fsp_cmp_state) {
		.session = session,
	};

	smbXsrv_wait_for_handle_lease_break(
		req,
		ev,
		session->client,
		state->wait_queue,
		check_for_lease_break_fsp_cmp_fn,
		&fsp_cmp_state);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	len = tevent_queue_length(state->wait_queue);
	if (len == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	/*
	 * Now we add our own waiter to the end of the queue,
	 * this way we get notified when all pending requests are finished
	 * and send to the socket.
	 */
	subreq = tevent_queue_wait_send(state, ev, state->wait_queue);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2srv_session_shutdown_wait_done, req);

	return req;
}

static void smb2srv_session_shutdown_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);

	tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);

	tevent_req_done(req);
}

NTSTATUS smb2srv_session_shutdown_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smbXsrv_session_logoff(struct smbXsrv_session *session)
{
	struct smbXsrv_session_table *table;
	struct db_record *local_rec = NULL;
	struct db_record *global_rec = NULL;
	struct smbd_server_connection *sconn = NULL;
	NTSTATUS status;
	NTSTATUS error = NT_STATUS_OK;

	if (session->table == NULL) {
		return NT_STATUS_OK;
	}

	table = session->table;
	session->table = NULL;

	sconn = session->client->sconn;
	session->client = NULL;
	session->status = NT_STATUS_USER_SESSION_DELETED;

	/*
	 * For SMB2 this is a bit redundant as files are also close
	 * below via smb2srv_tcon_disconnect_all() -> ... ->
	 * smbXsrv_tcon_disconnect() -> close_cnum() ->
	 * file_close_conn().
	 */
	file_close_user(sconn, session->global->session_wire_id);

	if (session->tcon_table != NULL) {
		/*
		 * Note: We only have a tcon_table for SMB2.
		 */
		status = smb2srv_tcon_disconnect_all(session);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("smbXsrv_session_logoff(0x%08x): "
				  "smb2srv_tcon_disconnect_all() failed: %s\n",
				  session->global->session_global_id,
				  nt_errstr(status));
			error = status;
		}
	}

	invalidate_vuid(sconn, session->global->session_wire_id);

	global_rec = session->global->db_rec;
	session->global->db_rec = NULL;
	if (global_rec == NULL) {
		global_rec = smbXsrv_session_global_fetch_locked(
					table->global.db_ctx,
					session->global->session_global_id,
					session->global /* TALLOC_CTX */);
		if (global_rec == NULL) {
			error = NT_STATUS_INTERNAL_ERROR;
		}
	}

	if (global_rec != NULL) {
		status = dbwrap_record_delete(global_rec);
		if (!NT_STATUS_IS_OK(status)) {
			TDB_DATA key = dbwrap_record_get_key(global_rec);

			DBG_ERR("smbXsrv_session_logoff(0x%08x): "
				  "failed to delete global key '%s': %s\n",
				  session->global->session_global_id,
				  tdb_data_dbg(key),
				  nt_errstr(status));
			error = status;
		}
	}
	TALLOC_FREE(global_rec);

	local_rec = session->db_rec;
	if (local_rec == NULL) {
		local_rec = smbXsrv_session_local_fetch_locked(
						table->local.db_ctx,
						session->local_id,
						session /* TALLOC_CTX */);
		if (local_rec == NULL) {
			error = NT_STATUS_INTERNAL_ERROR;
		}
	}

	if (local_rec != NULL) {
		status = dbwrap_record_delete(local_rec);
		if (!NT_STATUS_IS_OK(status)) {
			TDB_DATA key = dbwrap_record_get_key(local_rec);

			DBG_ERR("smbXsrv_session_logoff(0x%08x): "
				  "failed to delete local key '%s': %s\n",
				  session->global->session_global_id,
				  tdb_data_dbg(key),
				  nt_errstr(status));
			error = status;
		}
		table->local.num_sessions -= 1;
	}
	if (session->db_rec == NULL) {
		TALLOC_FREE(local_rec);
	}
	session->db_rec = NULL;

	return error;
}

struct smbXsrv_session_logoff_all_state {
	NTSTATUS first_status;
	int errors;
};

static int smbXsrv_session_logoff_all_callback(struct db_record *local_rec,
					       void *private_data);

NTSTATUS smbXsrv_session_logoff_all(struct smbXsrv_client *client)
{
	struct smbXsrv_session_table *table = client->session_table;
	struct smbXsrv_session_logoff_all_state state = {};
	NTSTATUS status;
	int count = 0;

	if (table == NULL) {
		DBG_DEBUG("empty session_table, nothing to do.\n");
		return NT_STATUS_OK;
	}

	status = dbwrap_traverse(table->local.db_ctx,
				 smbXsrv_session_logoff_all_callback,
				 &state, &count);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dbwrap_traverse() failed: %s\n", nt_errstr(status));
		return status;
	}

	if (!NT_STATUS_IS_OK(state.first_status)) {
		DBG_ERR("count[%d] errors[%d] first[%s]\n",
			count,
			state.errors,
			nt_errstr(state.first_status));
		return state.first_status;
	}

	return NT_STATUS_OK;
}

static int smbXsrv_session_logoff_all_callback(struct db_record *local_rec,
					       void *private_data)
{
	struct smbXsrv_session_logoff_all_state *state =
		(struct smbXsrv_session_logoff_all_state *)private_data;
	TDB_DATA val;
	void *ptr = NULL;
	struct smbXsrv_session *session = NULL;
	NTSTATUS status;

	val = dbwrap_record_get_value(local_rec);
	if (val.dsize != sizeof(ptr)) {
		status = NT_STATUS_INTERNAL_ERROR;
		if (NT_STATUS_IS_OK(state->first_status)) {
			state->first_status = status;
		}
		state->errors++;
		return 0;
	}

	memcpy(&ptr, val.dptr, val.dsize);
	session = talloc_get_type_abort(ptr, struct smbXsrv_session);

	session->db_rec = local_rec;
	status = smbXsrv_session_clear_and_logoff(session);
	session->db_rec = NULL;
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_IS_OK(state->first_status)) {
			state->first_status = status;
		}
		state->errors++;
		return 0;
	}

	return 0;
}

struct smbXsrv_session_local_trav_state {
	NTSTATUS status;
	int (*caller_cb)(struct smbXsrv_session *session,
			 void *caller_data);
	void *caller_data;
};

static int smbXsrv_session_local_traverse_cb(struct db_record *local_rec,
					     void *private_data);

NTSTATUS smbXsrv_session_local_traverse(
	struct smbXsrv_client *client,
	int (*caller_cb)(struct smbXsrv_session *session,
			 void *caller_data),
	void *caller_data)
{
	struct smbXsrv_session_table *table = client->session_table;
	struct smbXsrv_session_local_trav_state state;
	NTSTATUS status;
	int count = 0;

	state = (struct smbXsrv_session_local_trav_state) {
		.status = NT_STATUS_OK,
		.caller_cb = caller_cb,
		.caller_data = caller_data,
	};

	if (table == NULL) {
		DBG_DEBUG("empty session_table, nothing to do.\n");
		return NT_STATUS_OK;
	}

	status = dbwrap_traverse(table->local.db_ctx,
				 smbXsrv_session_local_traverse_cb,
				 &state,
				 &count);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dbwrap_traverse() failed: %s\n", nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_ERR("count[%d] status[%s]\n",
			count, nt_errstr(state.status));
		return state.status;
	}

	return NT_STATUS_OK;
}

static int smbXsrv_session_local_traverse_cb(struct db_record *local_rec,
					     void *private_data)
{
	struct smbXsrv_session_local_trav_state *state =
		(struct smbXsrv_session_local_trav_state *)private_data;
	TDB_DATA val;
	void *ptr = NULL;
	struct smbXsrv_session *session = NULL;
	int ret;

	val = dbwrap_record_get_value(local_rec);
	if (val.dsize != sizeof(ptr)) {
		state->status = NT_STATUS_INTERNAL_ERROR;
		return -1;
	}

	memcpy(&ptr, val.dptr, val.dsize);
	session = talloc_get_type_abort(ptr, struct smbXsrv_session);

	session->db_rec = local_rec;
	ret = state->caller_cb(session, state->caller_data);
	session->db_rec = NULL;

	return ret;
}

struct smbXsrv_session_disconnect_xconn_state {
	struct smbXsrv_connection *xconn;
	NTSTATUS first_status;
	int errors;
};

static int smbXsrv_session_disconnect_xconn_callback(struct db_record *local_rec,
					       void *private_data);

NTSTATUS smbXsrv_session_disconnect_xconn(struct smbXsrv_connection *xconn)
{
	struct smbXsrv_client *client = xconn->client;
	struct smbXsrv_session_table *table = client->session_table;
	struct smbXsrv_session_disconnect_xconn_state state = {
		.xconn = xconn,
	};
	NTSTATUS status;
	int count = 0;

	if (table == NULL) {
		DBG_ERR("empty session_table, nothing to do.\n");
		return NT_STATUS_OK;
	}

	status = dbwrap_traverse(table->local.db_ctx,
				 smbXsrv_session_disconnect_xconn_callback,
				 &state, &count);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dbwrap_traverse() failed: %s\n",
			nt_errstr(status));
		return status;
	}

	if (!NT_STATUS_IS_OK(state.first_status)) {
		DBG_ERR("count[%d] errors[%d] first[%s]\n",
			count, state.errors,
			nt_errstr(state.first_status));
		return state.first_status;
	}

	return NT_STATUS_OK;
}

static int smbXsrv_session_disconnect_xconn_callback(struct db_record *local_rec,
					       void *private_data)
{
	struct smbXsrv_session_disconnect_xconn_state *state =
		(struct smbXsrv_session_disconnect_xconn_state *)private_data;
	TDB_DATA val;
	void *ptr = NULL;
	struct smbXsrv_session *session = NULL;
	NTSTATUS status;

	val = dbwrap_record_get_value(local_rec);
	if (val.dsize != sizeof(ptr)) {
		status = NT_STATUS_INTERNAL_ERROR;
		if (NT_STATUS_IS_OK(state->first_status)) {
			state->first_status = status;
		}
		state->errors++;
		return 0;
	}

	memcpy(&ptr, val.dptr, val.dsize);
	session = talloc_get_type_abort(ptr, struct smbXsrv_session);

	session->db_rec = local_rec;
	status = smbXsrv_session_remove_channel(session, state->xconn);
	session->db_rec = NULL;
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_IS_OK(state->first_status)) {
			state->first_status = status;
		}
		state->errors++;
	}

	return 0;
}

NTSTATUS smb1srv_session_table_init(struct smbXsrv_connection *conn)
{
	/*
	 * Allow a range from 1..65534 with 65534 values.
	 */
	return smbXsrv_session_table_init(conn, 1, UINT16_MAX - 1,
					  UINT16_MAX - 1);
}

NTSTATUS smb1srv_session_lookup(struct smbXsrv_connection *conn,
				uint16_t vuid, NTTIME now,
				struct smbXsrv_session **session)
{
	struct smbXsrv_session_table *table = conn->client->session_table;
	uint32_t local_id = vuid;

	return smbXsrv_session_local_lookup(table, conn, local_id, now,
					    session);
}

NTSTATUS smbXsrv_session_info_lookup(struct smbXsrv_client *client,
				     uint64_t session_wire_id,
				     struct auth_session_info **si)
{
	struct smbXsrv_session_table *table = client->session_table;
	uint8_t key_buf[SMBXSRV_SESSION_LOCAL_TDB_KEY_SIZE];
	struct smbXsrv_session_local_fetch_state state = {
		.status = NT_STATUS_INTERNAL_ERROR,
	};
	TDB_DATA key;
	NTSTATUS status;

	if (session_wire_id == 0) {
		return NT_STATUS_USER_SESSION_DELETED;
	}

	if (table == NULL) {
		/* this might happen before the end of negprot */
		return NT_STATUS_USER_SESSION_DELETED;
	}

	if (table->local.db_ctx == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = smbXsrv_session_local_id_to_key(session_wire_id, key_buf);

	status = dbwrap_parse_record(table->local.db_ctx, key,
				     smbXsrv_session_local_fetch_parser,
				     &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		return state.status;
	}
	if (state.session->global->auth_session_info == NULL) {
		return NT_STATUS_USER_SESSION_DELETED;
	}

	*si = state.session->global->auth_session_info;
	return NT_STATUS_OK;
}

/*
 * In memory of get_valid_user_struct()
 *
 * This function is similar to smbXsrv_session_local_lookup() and it's wrappers,
 * but it doesn't implement the state checks of
 * those. get_valid_smbXsrv_session() is NOT meant to be called to validate the
 * session wire-id of incoming SMB requests, it MUST only be used in later
 * internal processing where the session wire-id has already been validated.
 */
NTSTATUS get_valid_smbXsrv_session(struct smbXsrv_client *client,
				   uint64_t session_wire_id,
				   struct smbXsrv_session **session)
{
	struct smbXsrv_session_table *table = client->session_table;
	uint8_t key_buf[SMBXSRV_SESSION_LOCAL_TDB_KEY_SIZE];
	struct smbXsrv_session_local_fetch_state state = {
		.status = NT_STATUS_INTERNAL_ERROR,
	};
	TDB_DATA key;
	NTSTATUS status;

	if (session_wire_id == 0) {
		return NT_STATUS_USER_SESSION_DELETED;
	}

	if (table == NULL) {
		/* this might happen before the end of negprot */
		return NT_STATUS_USER_SESSION_DELETED;
	}

	if (table->local.db_ctx == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = smbXsrv_session_local_id_to_key(session_wire_id, key_buf);

	status = dbwrap_parse_record(table->local.db_ctx, key,
				     smbXsrv_session_local_fetch_parser,
				     &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		return state.status;
	}
	if (state.session->global->auth_session_info == NULL) {
		return NT_STATUS_USER_SESSION_DELETED;
	}

	*session = state.session;
	return NT_STATUS_OK;
}

NTSTATUS smb2srv_session_lookup_global(struct smbXsrv_client *client,
				       uint64_t session_wire_id,
				       TALLOC_CTX *mem_ctx,
				       struct smbXsrv_session **_session)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct smbXsrv_session_table *table = client->session_table;
	uint32_t global_id = session_wire_id & UINT32_MAX;
	uint64_t global_zeros = session_wire_id & 0xFFFFFFFF00000000LLU;
	struct smbXsrv_session *session = NULL;
	struct db_record *global_rec = NULL;
	bool is_free = false;
	NTSTATUS status;

	if (global_id == 0) {
		TALLOC_FREE(frame);
		return NT_STATUS_USER_SESSION_DELETED;
	}
	if (global_zeros != 0) {
		TALLOC_FREE(frame);
		return NT_STATUS_USER_SESSION_DELETED;
	}

	if (table == NULL) {
		/* this might happen before the end of negprot */
		TALLOC_FREE(frame);
		return NT_STATUS_USER_SESSION_DELETED;
	}

	if (table->global.db_ctx == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	session = talloc_zero(mem_ctx, struct smbXsrv_session);
	if (session == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_steal(frame, session);

	session->client = client;
	session->status = NT_STATUS_BAD_LOGON_SESSION_STATE;
	session->local_id = global_id;

	/*
	 * This means smb2_get_new_nonce() will return
	 * NT_STATUS_ENCRYPTION_FAILED.
	 *
	 * But we initialize some random parts just in case...
	 */
	session->nonce_high_max = session->nonce_high = 0;
	generate_nonce_buffer((uint8_t *)&session->nonce_high_random,
			      sizeof(session->nonce_high_random));
	generate_nonce_buffer((uint8_t *)&session->nonce_low,
			      sizeof(session->nonce_low));

	global_rec = smbXsrv_session_global_fetch_locked(table->global.db_ctx,
							 global_id,
							 frame);
	if (global_rec == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	smbXsrv_session_global_verify_record(global_rec,
					     &is_free,
					     NULL,
					     session,
					     &session->global,
					     NULL);
	if (is_free) {
		TALLOC_FREE(frame);
		return NT_STATUS_USER_SESSION_DELETED;
	}

	/*
	 * We don't have channels on this session
	 * and only the main signing key
	 */
	session->global->num_channels = 0;
	status = smb2_signing_key_sign_create(session->global,
					      session->global->signing_algo,
					      NULL, /* no master key */
					      NULL, /* derivations */
					      &session->global->signing_key);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	session->global->signing_key->blob = session->global->signing_key_blob;
	session->global->signing_flags = 0;

	status = smb2_signing_key_cipher_create(session->global,
						session->global->encryption_cipher,
						NULL, /* no master key */
						NULL, /* derivations */
						&session->global->decryption_key);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	session->global->decryption_key->blob = session->global->decryption_key_blob;
	session->global->encryption_flags = 0;

	*_session = talloc_move(mem_ctx, &session);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS smb2srv_session_table_init(struct smbXsrv_connection *conn)
{
	/*
	 * Allow a range from 1..4294967294 with 65534 (same as SMB1) values.
	 */
	return smbXsrv_session_table_init(conn, 1, UINT32_MAX - 1,
					  UINT16_MAX - 1);
}

static NTSTATUS smb2srv_session_lookup_raw(struct smbXsrv_session_table *table,
					   /* conn: optional */
					   struct smbXsrv_connection *conn,
					   uint64_t session_id, NTTIME now,
					   struct smbXsrv_session **session)
{
	uint32_t local_id = session_id & UINT32_MAX;
	uint64_t local_zeros = session_id & 0xFFFFFFFF00000000LLU;

	if (local_zeros != 0) {
		return NT_STATUS_USER_SESSION_DELETED;
	}

	return smbXsrv_session_local_lookup(table, conn, local_id, now,
					    session);
}

NTSTATUS smb2srv_session_lookup_conn(struct smbXsrv_connection *conn,
				     uint64_t session_id, NTTIME now,
				     struct smbXsrv_session **session)
{
	struct smbXsrv_session_table *table = conn->client->session_table;
	return smb2srv_session_lookup_raw(table, conn, session_id, now,
					  session);
}

NTSTATUS smb2srv_session_lookup_client(struct smbXsrv_client *client,
				       uint64_t session_id, NTTIME now,
				       struct smbXsrv_session **session)
{
	struct smbXsrv_session_table *table = client->session_table;
	return smb2srv_session_lookup_raw(table, NULL, session_id, now,
					  session);
}

struct smbXsrv_session_global_traverse_state {
	int (*fn)(struct smbXsrv_session_global0 *, void *);
	void *private_data;
};

static int smbXsrv_session_global_traverse_fn(struct db_record *rec, void *data)
{
	int ret = -1;
	struct smbXsrv_session_global_traverse_state *state =
		(struct smbXsrv_session_global_traverse_state*)data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA val = dbwrap_record_get_value(rec);
	DATA_BLOB blob = data_blob_const(val.dptr, val.dsize);
	struct smbXsrv_session_globalB global_blob;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *frame = talloc_stackframe();

	ndr_err = ndr_pull_struct_blob(&blob, frame, &global_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_session_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("Invalid record in smbXsrv_session_global.tdb:"
			 "key '%s' ndr_pull_struct_blob - %s\n",
			 tdb_data_dbg(key),
			 ndr_errstr(ndr_err));
		goto done;
	}

	if (global_blob.version != SMBXSRV_VERSION_0) {
		DBG_WARNING("Invalid record in smbXsrv_session_global.tdb:"
			 "key '%s' unsupported version - %d\n",
			 tdb_data_dbg(key),
			 (int)global_blob.version);
		goto done;
	}

	if (global_blob.info.info0 == NULL) {
		DBG_WARNING("Invalid record in smbXsrv_tcon_global.tdb:"
			 "key '%s' info0 NULL pointer\n",
			 tdb_data_dbg(key));
		goto done;
	}

	global_blob.info.info0->db_rec = rec;
	ret = state->fn(global_blob.info.info0, state->private_data);
done:
	TALLOC_FREE(frame);
	return ret;
}

NTSTATUS smbXsrv_session_global_traverse(
			int (*fn)(struct smbXsrv_session_global0 *, void *),
			void *private_data)
{

	NTSTATUS status;
	int count = 0;
	struct smbXsrv_session_global_traverse_state state = {
		.fn = fn,
		.private_data = private_data,
	};

	become_root();
	status = smbXsrv_session_global_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		unbecome_root();
		DBG_ERR("Failed to initialize session_global: %s\n",
			  nt_errstr(status));
		return status;
	}

	status = dbwrap_traverse_read(smbXsrv_session_global_db_ctx,
				      smbXsrv_session_global_traverse_fn,
				      &state,
				      &count);
	unbecome_root();

	return status;
}

static struct files_struct *smbXsrv_wait_for_handle_lease_break_fn(
						struct files_struct *fsp,
						void *private_data);
static void smbXsrv_wait_for_handle_lease_break_done(
						struct tevent_req *subreq);

struct delay_for_handle_lease_break_state {
	struct tevent_req *req;
	struct tevent_context *ev;
	struct smbXsrv_client *client;
	struct tevent_queue *wait_queue;
	bool (*fsp_cmp_fn)(struct files_struct *fsp,
			   void *private_data);
	void *fsp_cmp_private_data;
};

void smbXsrv_wait_for_handle_lease_break(
				struct tevent_req *req,
				struct tevent_context *ev,
				struct smbXsrv_client *client,
				struct tevent_queue *wait_queue,
				bool (*fsp_cmp_fn)(struct files_struct *fsp,
						   void *private_data),
				void *fsp_cmp_private_data)
{
	struct delay_for_handle_lease_break_state state;

	state = (struct delay_for_handle_lease_break_state) {
		.req = req,
		.ev = ev,
		.client = client,
		.wait_queue = wait_queue,
		.fsp_cmp_fn = fsp_cmp_fn,
		.fsp_cmp_private_data = fsp_cmp_private_data,
	};

	files_forall(client->sconn,
		     smbXsrv_wait_for_handle_lease_break_fn,
		     &state);
}

static struct files_struct *smbXsrv_wait_for_handle_lease_break_fn(
						struct files_struct *fsp,
						void *private_data)
{
	struct delay_for_handle_lease_break_state *state = private_data;
	struct tevent_req *subreq = NULL;
	struct share_mode_lock *lck = NULL;
	struct timeval timeout = timeval_current_ofs(OPLOCK_BREAK_TIMEOUT, 0);
	bool match;
	NTSTATUS status;

	match = state->fsp_cmp_fn(fsp, state->fsp_cmp_private_data);
	if (!match) {
		return NULL;
	}

	if (!fsp->fsp_flags.initial_delete_on_close) {
		return NULL;
	}

	lck = get_existing_share_mode_lock(fsp, fsp->file_id);
	if (lck == NULL) {
		/* No opens on this file */
		return NULL;
	}

	subreq = delay_for_handle_lease_break_send(fsp,
						   state->ev,
						   timeout,
						   fsp,
						   false,
						   &lck);
	if (tevent_req_nomem(subreq, state->req)) {
		TALLOC_FREE(lck);
		/* Reminder: returning != NULL means STOP traverse */
		return fsp;
	}
	if (tevent_req_is_in_progress(subreq)) {
		struct tevent_req *wait_subreq = NULL;

		tevent_req_set_callback(
			subreq,
			smbXsrv_wait_for_handle_lease_break_done,
			state->req);

		/*
		 * This just adds a blocker that unblocks when subreq is
		 * completed and goes away.
		 */
		wait_subreq = tevent_queue_wait_send(subreq,
						     state->ev,
						     state->wait_queue);
		if (wait_subreq == NULL) {
			exit_server("tevent_queue_wait_send failed");
		}
		return NULL;
	}

	status = delay_for_handle_lease_break_recv(subreq, state->req, &lck);
	TALLOC_FREE(subreq);
	TALLOC_FREE(lck);
	if (tevent_req_nterror(state->req, status)) {
		DBG_ERR("delay_for_handle_lease_break_recv failed %s\n",
			nt_errstr(status));
		return fsp;
	}
	return NULL;
}

static void smbXsrv_wait_for_handle_lease_break_done(
						struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct share_mode_lock *lck = NULL;
	NTSTATUS status;

	status = delay_for_handle_lease_break_recv(subreq,
						   req,
						   &lck);
	TALLOC_FREE(subreq);
	TALLOC_FREE(lck);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("delay_for_handle_lease_break_recv failed %s\n",
			nt_errstr(status));
		return;
	}
}
