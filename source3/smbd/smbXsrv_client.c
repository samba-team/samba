/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2014

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
#include "lib/util/iov_buf.h"
#include "lib/global_contexts.h"
#include "source3/include/util_tdb.h"

struct smbXsrv_client_table {
	struct {
		uint32_t max_clients;
		uint32_t num_clients;
	} local;
	struct {
		struct db_context *db_ctx;
	} global;
};

static struct db_context *smbXsrv_client_global_db_ctx = NULL;

NTSTATUS smbXsrv_client_global_init(void)
{
	char *global_path = NULL;
	struct db_context *backend = NULL;
	struct db_context *db_ctx = NULL;

	if (smbXsrv_client_global_db_ctx != NULL) {
		return NT_STATUS_OK;
	}

	/*
	 * This contains secret information like client keys!
	 */
	global_path = lock_path(talloc_tos(), "smbXsrv_client_global.tdb");
	if (global_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	backend = db_open(NULL, global_path,
			  0, /* hash_size */
			  TDB_DEFAULT |
			  TDB_CLEAR_IF_FIRST |
			  TDB_INCOMPATIBLE_HASH,
			  O_RDWR | O_CREAT, 0600,
			  DBWRAP_LOCK_ORDER_1,
			  DBWRAP_FLAG_NONE);
	TALLOC_FREE(global_path);
	if (backend == NULL) {
		NTSTATUS status = map_nt_error_from_unix_common(errno);
		return status;
	}

	db_ctx = db_open_watched(NULL, &backend, global_messaging_context());
	if (db_ctx == NULL) {
		TALLOC_FREE(backend);
		return NT_STATUS_NO_MEMORY;
	}

	smbXsrv_client_global_db_ctx = db_ctx;

	return NT_STATUS_OK;
}

#define SMBXSRV_CLIENT_GLOBAL_TDB_KEY_SIZE 16

static TDB_DATA smbXsrv_client_global_id_to_key(const struct GUID *client_guid,
						uint8_t *key_buf)
{
	TDB_DATA key = { .dsize = 0, };
	struct GUID_ndr_buf buf = { .buf = {0}, };

	GUID_to_ndr_buf(client_guid, &buf);
	memcpy(key_buf, buf.buf, SMBXSRV_CLIENT_GLOBAL_TDB_KEY_SIZE);

	key = make_tdb_data(key_buf, SMBXSRV_CLIENT_GLOBAL_TDB_KEY_SIZE);

	return key;
}

static struct db_record *smbXsrv_client_global_fetch_locked(
			struct db_context *db,
			const struct GUID *client_guid,
			TALLOC_CTX *mem_ctx)
{
	TDB_DATA key;
	uint8_t key_buf[SMBXSRV_CLIENT_GLOBAL_TDB_KEY_SIZE];
	struct db_record *rec = NULL;

	key = smbXsrv_client_global_id_to_key(client_guid, key_buf);

	rec = dbwrap_fetch_locked(db, mem_ctx, key);

	if (rec == NULL) {
		struct GUID_txt_buf buf;
		DBG_DEBUG("Failed to lock guid [%s], key '%s'\n",
			  GUID_buf_string(client_guid, &buf),
			  tdb_data_dbg(key));
	}

	return rec;
}

static NTSTATUS smbXsrv_client_table_create(TALLOC_CTX *mem_ctx,
					    struct messaging_context *msg_ctx,
					    uint32_t max_clients,
					    struct smbXsrv_client_table **_table)
{
	struct smbXsrv_client_table *table;
	NTSTATUS status;

	if (max_clients > 1) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	table = talloc_zero(mem_ctx, struct smbXsrv_client_table);
	if (table == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	table->local.max_clients = max_clients;

	status = smbXsrv_client_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(table);
		return status;
	}

	table->global.db_ctx = smbXsrv_client_global_db_ctx;

	*_table = table;
	return NT_STATUS_OK;
}

static int smbXsrv_client_global_destructor(struct smbXsrv_client_global0 *global)
{
	return 0;
}

static void smbXsrv_client_global_verify_record(struct db_record *db_rec,
					bool *is_free,
					bool *was_free,
					TALLOC_CTX *mem_ctx,
					const struct server_id *dead_server_id,
					struct smbXsrv_client_global0 **_g,
					uint32_t *pseqnum)
{
	TDB_DATA key;
	TDB_DATA val;
	DATA_BLOB blob;
	struct smbXsrv_client_globalB global_blob;
	enum ndr_err_code ndr_err;
	struct smbXsrv_client_global0 *global = NULL;
	bool dead = false;
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
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_client_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("key '%s' ndr_pull_struct_blob - %s\n",
			    tdb_data_dbg(key),
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return;
	}

	DBG_DEBUG("client_global:\n");
	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_client_globalB, &global_blob);
	}

	if (global_blob.version != SMBXSRV_VERSION_0) {
		DBG_ERR("key '%s' uses unsupported version %u\n",
			tdb_data_dbg(key),
			global_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_client_globalB, &global_blob);
		TALLOC_FREE(frame);
		return;
	}

	global = global_blob.info.info0;

	dead = server_id_equal(dead_server_id, &global->server_id);
	if (dead) {
		struct server_id_buf tmp;

		DBG_NOTICE("key '%s' server_id %s is already dead.\n",
			   tdb_data_dbg(key),
			   server_id_str_buf(global->server_id, &tmp));
		if (DEBUGLVL(DBGLVL_NOTICE)) {
			NDR_PRINT_DEBUG(smbXsrv_client_globalB, &global_blob);
		}
		TALLOC_FREE(frame);
		dbwrap_record_delete(db_rec);
		*is_free = true;
		return;
	}

	exists = serverid_exists(&global->server_id);
	if (!exists) {
		struct server_id_buf tmp;

		DBG_NOTICE("key '%s' server_id %s does not exist.\n",
			   tdb_data_dbg(key),
			   server_id_str_buf(global->server_id, &tmp));
		if (DEBUGLVL(DBGLVL_NOTICE)) {
			NDR_PRINT_DEBUG(smbXsrv_client_globalB, &global_blob);
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

static NTSTATUS smb2srv_client_connection_pass(struct smbd_smb2_request *smb2req,
					       struct smbXsrv_client_global0 *global)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	struct smbXsrv_connection_pass0 pass_info0;
	struct smbXsrv_connection_passB pass_blob;
	ssize_t reqlen;
	struct iovec iov;

	pass_info0 = (struct smbXsrv_connection_pass0) {
		.client_guid = global->client_guid,
		.src_server_id = smb2req->xconn->client->global->server_id,
		.xconn_connect_time = smb2req->xconn->client->global->initial_connect_time,
		.dst_server_id = global->server_id,
		.client_connect_time = global->initial_connect_time,
		.transport_type = smb2req->xconn->transport.type,
	};

	reqlen = iov_buflen(smb2req->in.vector, smb2req->in.vector_count);
	if (reqlen == -1) {
		return NT_STATUS_INVALID_BUFFER_SIZE;
	}

	pass_info0.negotiate_request.length = reqlen;
	pass_info0.negotiate_request.data = talloc_array(talloc_tos(), uint8_t,
							 reqlen);
	if (pass_info0.negotiate_request.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	iov_buf(smb2req->in.vector, smb2req->in.vector_count,
		pass_info0.negotiate_request.data,
		pass_info0.negotiate_request.length);

	ZERO_STRUCT(pass_blob);
	pass_blob.version = smbXsrv_version_global_current();
	pass_blob.info.info0 = &pass_info0;

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
	}

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &pass_blob,
			(ndr_push_flags_fn_t)ndr_push_smbXsrv_connection_passB);
	data_blob_free(&pass_info0.negotiate_request);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	iov.iov_base = blob.data;
	iov.iov_len = blob.length;

	status = messaging_send_iov(smb2req->xconn->client->msg_ctx,
				    global->server_id,
				    MSG_SMBXSRV_CONNECTION_PASS,
				    &iov, 1,
				    &smb2req->xconn->transport.sock, 1);
	data_blob_free(&blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS smb2srv_client_connection_drop(struct smbd_smb2_request *smb2req,
					       struct smbXsrv_client_global0 *global)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	struct smbXsrv_connection_drop0 drop_info0;
	struct smbXsrv_connection_dropB drop_blob;
	struct iovec iov;

	drop_info0 = (struct smbXsrv_connection_drop0) {
		.client_guid = global->client_guid,
		.src_server_id = smb2req->xconn->client->global->server_id,
		.xconn_connect_time = smb2req->xconn->client->global->initial_connect_time,
		.dst_server_id = global->server_id,
		.client_connect_time = global->initial_connect_time,
	};

	ZERO_STRUCT(drop_blob);
	drop_blob.version = smbXsrv_version_global_current();
	drop_blob.info.info0 = &drop_info0;

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_connection_dropB, &drop_blob);
	}

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &drop_blob,
			(ndr_push_flags_fn_t)ndr_push_smbXsrv_connection_dropB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	iov.iov_base = blob.data;
	iov.iov_len = blob.length;

	status = messaging_send_iov(smb2req->xconn->client->msg_ctx,
				    global->server_id,
				    MSG_SMBXSRV_CONNECTION_DROP,
				    &iov, 1,
				    NULL, 0);
	data_blob_free(&blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS smbXsrv_client_global_store(struct smbXsrv_client_global0 *global)
{
	struct smbXsrv_client_globalB global_blob;
	DATA_BLOB blob = data_blob_null;
	TDB_DATA key;
	TDB_DATA val;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	bool saved_stored = global->stored;

	/*
	 * TODO: if we use other versions than '0'
	 * we would add glue code here, that would be able to
	 * store the information in the old format.
	 */

	SMB_ASSERT(global->local_address != NULL);
	SMB_ASSERT(global->remote_address != NULL);
	SMB_ASSERT(global->remote_name != NULL);

	if (global->db_rec == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = dbwrap_record_get_key(global->db_rec);
	val = dbwrap_record_get_value(global->db_rec);

	global_blob = (struct smbXsrv_client_globalB) {
		.version = smbXsrv_version_global_current(),
		.info.info0 = global,
	};
	if (val.dsize >= 8) {
		global_blob.seqnum = IVAL(val.dptr, 4);
	}
	global_blob.seqnum += 1;

	global->stored = true;
	ndr_err = ndr_push_struct_blob(&blob, global->db_rec, &global_blob,
			(ndr_push_flags_fn_t)ndr_push_smbXsrv_client_globalB);
	global->stored = saved_stored;
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
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("key '%s' store - %s\n",
			tdb_data_dbg(key),
			nt_errstr(status));
		TALLOC_FREE(global->db_rec);
		return status;
	}

	global->stored = true;

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("key '%s' stored\n",
			  tdb_data_dbg(key));
		NDR_PRINT_DEBUG(smbXsrv_client_globalB, &global_blob);
	}

	TALLOC_FREE(global->db_rec);

	return NT_STATUS_OK;
}

struct smb2srv_client_mc_negprot_state {
	struct tevent_context *ev;
	struct smbd_smb2_request *smb2req;
	struct db_record *db_rec;
	struct server_id sent_server_id;
	uint64_t watch_instance;
	uint32_t last_seqnum;
	struct tevent_req *filter_subreq;
};

static void smb2srv_client_mc_negprot_cleanup(struct tevent_req *req,
					      enum tevent_req_state req_state)
{
	struct smb2srv_client_mc_negprot_state *state =
		tevent_req_data(req,
		struct smb2srv_client_mc_negprot_state);

	if (state->db_rec != NULL) {
		dbwrap_watched_watch_remove_instance(state->db_rec,
						     state->watch_instance);
		state->watch_instance = 0;
		TALLOC_FREE(state->db_rec);
	}
}

static void smb2srv_client_mc_negprot_next(struct tevent_req *req);
static bool smb2srv_client_mc_negprot_filter(struct messaging_rec *rec, void *private_data);
static void smb2srv_client_mc_negprot_done(struct tevent_req *subreq);
static void smb2srv_client_mc_negprot_watched(struct tevent_req *subreq);

struct tevent_req *smb2srv_client_mc_negprot_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct smbd_smb2_request *smb2req)
{
	struct tevent_req *req = NULL;
	struct smb2srv_client_mc_negprot_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2srv_client_mc_negprot_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->smb2req = smb2req;

	tevent_req_set_cleanup_fn(req, smb2srv_client_mc_negprot_cleanup);

	server_id_set_disconnected(&state->sent_server_id);

	smb2srv_client_mc_negprot_next(req);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void smb2srv_client_mc_negprot_next(struct tevent_req *req)
{
	struct smb2srv_client_mc_negprot_state *state =
		tevent_req_data(req,
		struct smb2srv_client_mc_negprot_state);
	struct smbXsrv_connection *xconn = state->smb2req->xconn;
	struct smbXsrv_client *client = xconn->client;
	struct smbXsrv_client_table *table = client->table;
	struct GUID client_guid = xconn->smb2.client.guid;
	struct smbXsrv_client_global0 *global = NULL;
	bool is_free = false;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;
	uint32_t seqnum = 0;
	struct server_id last_server_id = { .pid = 0, };

	SMB_ASSERT(state->db_rec == NULL);
	state->db_rec = smbXsrv_client_global_fetch_locked(table->global.db_ctx,
							   &client_guid,
							   state);
	if (state->db_rec == NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_DB_ERROR);
		return;
	}

verify_again:
	TALLOC_FREE(global);

	smbXsrv_client_global_verify_record(state->db_rec,
					    &is_free,
					    NULL,
					    state,
					    &last_server_id,
					    &global,
					    &seqnum);
	if (is_free) {
		dbwrap_watched_watch_remove_instance(state->db_rec,
						     state->watch_instance);
		state->watch_instance = 0;

		/*
		 * This stores the new client information in
		 * smbXsrv_client_global.tdb
		 */
		client->global->client_guid = xconn->smb2.client.guid;

		client->global->db_rec = state->db_rec;
		state->db_rec = NULL;
		status = smbXsrv_client_global_store(client->global);
		SMB_ASSERT(client->global->db_rec == NULL);
		if (!NT_STATUS_IS_OK(status)) {
			struct GUID_txt_buf buf;
			DBG_ERR("client_guid[%s] store failed - %s\n",
				GUID_buf_string(&client->global->client_guid,
						&buf),
				nt_errstr(status));
			tevent_req_nterror(req, status);
			return;
		}

		if (DEBUGLVL(DBGLVL_DEBUG)) {
			struct smbXsrv_clientB client_blob = {
				.version = SMBXSRV_VERSION_0,
				.info.info0 = client,
			};
			struct GUID_txt_buf buf;

			DBG_DEBUG("client_guid[%s] stored\n",
				  GUID_buf_string(&client->global->client_guid,
						  &buf));
			NDR_PRINT_DEBUG(smbXsrv_clientB, &client_blob);
		}

		xconn->smb2.client.guid_verified = true;
		tevent_req_done(req);
		return;
	}

	if (global == NULL) {
		/*
		 * most likely ndr_pull_struct_blob() failed
		 */
		tevent_req_nterror(req, NT_STATUS_INTERNAL_DB_CORRUPTION);
		return;
	}

	if (server_id_equal(&state->sent_server_id, &global->server_id)) {
		/*
		 * We hit a race with other concurrent connections,
		 * which have woken us.
		 *
		 * We already sent the pass or drop message to
		 * the process, so we need to wait for a
		 * response and not pass the connection
		 * again! Otherwise the process would
		 * receive the same tcp connection via
		 * more than one file descriptor and
		 * create more than one smbXsrv_connection
		 * structure for the same tcp connection,
		 * which means the client would see more
		 * than one SMB2 negprot response to its
		 * single SMB2 netprot request and we
		 * as server get the session keys and
		 * message id validation wrong
		 */
		goto watch_again;
	}

	server_id_set_disconnected(&state->sent_server_id);

	/*
	 * If last_server_id is set, we expect
	 * smbXsrv_client_global_verify_record()
	 * to detect the already dead global->server_id
	 * as state->db_rec is still locked and its
	 * value didn't change.
	 */
	SMB_ASSERT(last_server_id.pid == 0);
	last_server_id = global->server_id;

	TALLOC_FREE(state->filter_subreq);
	if (procid_is_local(&global->server_id)) {
		subreq = messaging_filtered_read_send(state,
						      state->ev,
						      client->msg_ctx,
						      smb2srv_client_mc_negprot_filter,
						      NULL);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, smb2srv_client_mc_negprot_done, req);
		state->filter_subreq = subreq;
	}

	if (procid_is_local(&global->server_id)) {
		status = smb2srv_client_connection_pass(state->smb2req,
							global);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			/*
			 * We remembered last_server_id = global->server_id
			 * above, so we'll treat it as dead in the
			 * next round to smbXsrv_client_global_verify_record().
			 */
			goto verify_again;
		}
		state->sent_server_id = global->server_id;
		if (tevent_req_nterror(req, status)) {
			return;
		}
	} else {
		status = smb2srv_client_connection_drop(state->smb2req,
							global);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			/*
			 * We remembered last_server_id = global->server_id
			 * above, so we'll treat it as dead in the
			 * next round to smbXsrv_client_global_verify_record().
			 */
			goto verify_again;
		}
		state->sent_server_id = global->server_id;
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

watch_again:

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

	subreq = dbwrap_watched_watch_send(state,
					   state->ev,
					   state->db_rec,
					   state->watch_instance,
					   global->server_id);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smb2srv_client_mc_negprot_watched, req);

	TALLOC_FREE(global);
	TALLOC_FREE(state->db_rec);
	return;
}

static bool smb2srv_client_mc_negprot_filter(struct messaging_rec *rec, void *private_data)
{
	if (rec->msg_type != MSG_SMBXSRV_CONNECTION_PASSED) {
		return false;
	}

	if (rec->num_fds != 0) {
		return false;
	}

	return true;
}

static void smb2srv_client_mc_negprot_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2srv_client_mc_negprot_state *state =
		tevent_req_data(req,
		struct smb2srv_client_mc_negprot_state);
	struct smbXsrv_connection *xconn = state->smb2req->xconn;
	struct smbXsrv_client *client = xconn->client;
	struct messaging_rec *rec = NULL;
	struct smbXsrv_connection_passB passed_blob;
	enum ndr_err_code ndr_err;
	struct smbXsrv_connection_pass0 *passed_info0 = NULL;
	NTSTATUS status;
	int ret;

	SMB_ASSERT(state->filter_subreq == subreq);
	state->filter_subreq = NULL;

	ret = messaging_filtered_read_recv(subreq, state, &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(ret);
		DBG_ERR("messaging_filtered_read_recv() - %s\n",
			nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}

	DBG_DEBUG("MSG_SMBXSRV_CONNECTION_PASSED: received...\n");

	ndr_err = ndr_pull_struct_blob(&rec->buf, rec, &passed_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_connection_passB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("ndr_pull_struct_blob - %s\n", nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &passed_blob);
	}

	if (passed_blob.version != SMBXSRV_VERSION_0) {
		DBG_ERR("ignore invalid version %u\n", passed_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &passed_blob);
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	passed_info0 = passed_blob.info.info0;
	if (passed_info0 == NULL) {
		DBG_ERR("ignore NULL info %u\n", passed_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &passed_blob);
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	if (!GUID_equal(&xconn->smb2.client.guid, &passed_info0->client_guid)) {
		struct GUID_txt_buf buf1, buf2;

		DBG_ERR("client's client_guid [%s] != passed guid [%s]\n",
			GUID_buf_string(&xconn->smb2.client.guid,
					&buf1),
			GUID_buf_string(&passed_info0->client_guid,
					&buf2));
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &passed_blob);
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	if (client->global->initial_connect_time !=
	    passed_info0->xconn_connect_time)
	{
		DBG_ERR("client's initial connect time [%s] (%llu) != "
			"passed xconn connect time [%s] (%llu)\n",
			nt_time_string(talloc_tos(),
				       client->global->initial_connect_time),
			(unsigned long long)client->global->initial_connect_time,
			nt_time_string(talloc_tos(),
				       passed_info0->xconn_connect_time),
			(unsigned long long)passed_info0->xconn_connect_time);
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &passed_blob);
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	if (passed_info0->negotiate_request.length != 0) {
		DBG_ERR("negotiate_request.length[%zu]\n",
			passed_info0->negotiate_request.length);
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &passed_blob);
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	tevent_req_nterror(req, NT_STATUS_MESSAGE_RETRIEVED);
}

static void smb2srv_client_mc_negprot_watched(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2srv_client_mc_negprot_state *state =
		tevent_req_data(req,
		struct smb2srv_client_mc_negprot_state);
	NTSTATUS status;
	uint64_t instance = 0;

	status = dbwrap_watched_watch_recv(subreq, &instance, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->watch_instance = instance;

	smb2srv_client_mc_negprot_next(req);
}

NTSTATUS smb2srv_client_mc_negprot_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS smbXsrv_client_global_remove(struct smbXsrv_client_global0 *global)
{
	TDB_DATA key;
	NTSTATUS status;

	/*
	 * TODO: if we use other versions than '0'
	 * we would add glue code here, that would be able to
	 * store the information in the old format.
	 */

	if (global->db_rec == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = dbwrap_record_get_key(global->db_rec);

	status = dbwrap_record_delete(global->db_rec);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("key '%s' delete - %s\n",
			tdb_data_dbg(key),
			nt_errstr(status));
		TALLOC_FREE(global->db_rec);
		return status;
	}
	global->stored = false;
	DBG_DEBUG("key '%s' delete\n", tdb_data_dbg(key));

	TALLOC_FREE(global->db_rec);

	return NT_STATUS_OK;
}

static int smbXsrv_client_destructor(struct smbXsrv_client *client)
{
	NTSTATUS status;

	status = smbXsrv_client_remove(client);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smbXsrv_client_remove() failed: %s\n",
			nt_errstr(status));
	}

	TALLOC_FREE(client->global);

	return 0;
}

static bool smbXsrv_client_connection_pass_filter(struct messaging_rec *rec, void *private_data);
static void smbXsrv_client_connection_pass_loop(struct tevent_req *subreq);
static bool smbXsrv_client_connection_drop_filter(struct messaging_rec *rec, void *private_data);
static void smbXsrv_client_connection_drop_loop(struct tevent_req *subreq);

NTSTATUS smbXsrv_client_create(TALLOC_CTX *mem_ctx,
			       struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       NTTIME now,
			       struct smbXsrv_client **_client)
{
	struct smbXsrv_client_table *table;
	struct smbXsrv_client *client = NULL;
	struct smbXsrv_client_global0 *global = NULL;
	NTSTATUS status;
	struct tevent_req *subreq = NULL;

	status = smbXsrv_client_table_create(mem_ctx,
					     msg_ctx,
					     1, /* max_clients */
					     &table);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (table->local.num_clients >= table->local.max_clients) {
		TALLOC_FREE(table);
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	client = talloc_zero(mem_ctx, struct smbXsrv_client);
	if (client == NULL) {
		TALLOC_FREE(table);
		return NT_STATUS_NO_MEMORY;
	}
	client->raw_ev_ctx = ev_ctx;
	client->msg_ctx = msg_ctx;

	client->server_multi_channel_enabled =
		smbXsrv_server_multi_channel_enabled();
	if (client->server_multi_channel_enabled) {
		client->next_channel_id = 1;
	}
	client->table = talloc_move(client, &table);
	table = client->table;

	global = talloc_zero(client, struct smbXsrv_client_global0);
	if (global == NULL) {
		TALLOC_FREE(client);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(global, smbXsrv_client_global_destructor);
	client->global = global;

	global->initial_connect_time = now;

	global->server_id = messaging_server_id(client->msg_ctx);

	table->local.num_clients += 1;

	talloc_set_destructor(client, smbXsrv_client_destructor);

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		struct smbXsrv_clientB client_blob = {
			.version = SMBXSRV_VERSION_0,
			.info.info0 = client,
		};
		struct GUID_txt_buf buf;

		DBG_DEBUG("client_guid[%s] created\n",
			  GUID_buf_string(&global->client_guid, &buf));
		NDR_PRINT_DEBUG(smbXsrv_clientB, &client_blob);
	}

	subreq = messaging_filtered_read_send(client,
					client->raw_ev_ctx,
					client->msg_ctx,
					smbXsrv_client_connection_pass_filter,
					client);
	if (subreq == NULL) {
		TALLOC_FREE(client);
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smbXsrv_client_connection_pass_loop, client);
	client->connection_pass_subreq = subreq;

	subreq = messaging_filtered_read_send(client,
					client->raw_ev_ctx,
					client->msg_ctx,
					smbXsrv_client_connection_drop_filter,
					client);
	if (subreq == NULL) {
		TALLOC_FREE(client);
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smbXsrv_client_connection_drop_loop, client);
	client->connection_drop_subreq = subreq;

	*_client = client;
	return NT_STATUS_OK;
}

static NTSTATUS smb2srv_client_connection_passed(struct smbXsrv_client *client,
				const struct smbXsrv_connection_pass0 *recv_info0)
{
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	struct smbXsrv_connection_pass0 passed_info0;
	struct smbXsrv_connection_passB passed_blob;
	struct iovec iov;

	/*
	 * We echo back the message with a cleared negotiate_request
	 */
	passed_info0 = *recv_info0;
	passed_info0.negotiate_request = data_blob_null;

	ZERO_STRUCT(passed_blob);
	passed_blob.version = smbXsrv_version_global_current();
	passed_blob.info.info0 = &passed_info0;

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &passed_blob);
	}

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &passed_blob,
			(ndr_push_flags_fn_t)ndr_push_smbXsrv_connection_passB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	iov.iov_base = blob.data;
	iov.iov_len = blob.length;

	status = messaging_send_iov(client->msg_ctx,
				    recv_info0->src_server_id,
				    MSG_SMBXSRV_CONNECTION_PASSED,
				    &iov, 1,
				    NULL, 0);
	data_blob_free(&blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static bool smbXsrv_client_connection_pass_filter(struct messaging_rec *rec, void *private_data)
{
	if (rec->msg_type != MSG_SMBXSRV_CONNECTION_PASS) {
		return false;
	}

	if (rec->num_fds != 1) {
		return false;
	}

	return true;
}

static void smbXsrv_client_connection_pass_loop(struct tevent_req *subreq)
{
	struct smbXsrv_client *client =
		tevent_req_callback_data(subreq,
		struct smbXsrv_client);
	struct smbXsrv_connection *xconn = NULL;
	int ret;
	struct messaging_rec *rec = NULL;
	struct smbXsrv_connection_passB pass_blob;
	enum ndr_err_code ndr_err;
	struct smbXsrv_connection_pass0 *pass_info0 = NULL;
	NTSTATUS status;
	int sock_fd = -1;
	uint64_t seq_low;

	client->connection_pass_subreq = NULL;

	ret = messaging_filtered_read_recv(subreq, talloc_tos(), &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		goto next;
	}

	if (rec->num_fds != 1) {
		DBG_ERR("MSG_SMBXSRV_CONNECTION_PASS: num_fds[%u]\n",
			rec->num_fds);
		goto next;
	}

	sock_fd = rec->fds[0];
	DBG_DEBUG("MSG_SMBXSRV_CONNECTION_PASS: got sock_fd[%d]\n", sock_fd);

	ndr_err = ndr_pull_struct_blob(&rec->buf, rec, &pass_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_connection_passB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("ndr_pull_struct_blob - %s\n", nt_errstr(status));
		goto next;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
	}

	if (pass_blob.version != SMBXSRV_VERSION_0) {
		DBG_ERR("ignore invalid version %u\n", pass_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
		goto next;
	}

	pass_info0 = pass_blob.info.info0;
	if (pass_info0 == NULL) {
		DBG_ERR("ignore NULL info %u\n", pass_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
		goto next;
	}

	if (!GUID_equal(&client->global->client_guid, &pass_info0->client_guid))
	{
		struct GUID_txt_buf buf1, buf2;

		DBG_WARNING("client's client_guid [%s] != passed guid [%s]\n",
			    GUID_buf_string(&client->global->client_guid,
					    &buf1),
			    GUID_buf_string(&pass_info0->client_guid,
					    &buf2));
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
		}
		goto next;
	}

	if (client->global->initial_connect_time !=
	    pass_info0->client_connect_time)
	{
		DBG_WARNING("client's initial connect time [%s] (%llu) != "
			"passed initial connect time [%s] (%llu)\n",
			nt_time_string(talloc_tos(),
				       client->global->initial_connect_time),
			(unsigned long long)client->global->initial_connect_time,
			nt_time_string(talloc_tos(),
				       pass_info0->client_connect_time),
			(unsigned long long)pass_info0->client_connect_time);
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
		}
		goto next;
	}

	if (pass_info0->negotiate_request.length < SMB2_HDR_BODY) {
		DBG_WARNING("negotiate_request.length[%zu]\n",
			    pass_info0->negotiate_request.length);
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
		}
		goto next;
	}

	status = smb2srv_client_connection_passed(client, pass_info0);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * We hit a race where, the client dropped the connection
		 * while the socket was passed to us and the origin
		 * process already existed.
		 */
		DBG_DEBUG("smb2srv_client_connection_passed() ignore %s\n",
			  nt_errstr(status));
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		const char *r = "smb2srv_client_connection_passed() failed";
		DBG_ERR("%s => %s\n", r, nt_errstr(status));
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
		exit_server_cleanly(r);
		return;
	}

	status = smbd_add_connection(client,
				     sock_fd,
				     pass_info0->transport_type,
				     pass_info0->xconn_connect_time,
				     &xconn);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED)) {
		rec->num_fds = 0;
		smbd_server_connection_terminate(xconn, nt_errstr(status));
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("smbd_add_connection => %s\n", nt_errstr(status));
		NDR_PRINT_DEBUG(smbXsrv_connection_passB, &pass_blob);
		goto next;
	}
	rec->num_fds = 0;

	/*
	 * Set seq_low to mid received in negprot
	 */
	seq_low = BVAL(pass_info0->negotiate_request.data,
		       SMB2_HDR_MESSAGE_ID);

	xconn->smb2.client.guid_verified = true;
	smbd_smb2_process_negprot(xconn, seq_low,
				  pass_info0->negotiate_request.data,
				  pass_info0->negotiate_request.length);

next:
	if (rec != NULL) {
		uint8_t fd_idx;

		for (fd_idx = 0; fd_idx < rec->num_fds; fd_idx++) {
			sock_fd = rec->fds[fd_idx];
			close(sock_fd);
		}
		rec->num_fds = 0;

		TALLOC_FREE(rec);
	}

	subreq = messaging_filtered_read_send(client,
					client->raw_ev_ctx,
					client->msg_ctx,
					smbXsrv_client_connection_pass_filter,
					client);
	if (subreq == NULL) {
		const char *r;
		r = "messaging_read_send(MSG_SMBXSRV_CONNECTION_PASS failed";
		exit_server_cleanly(r);
		return;
	}
	tevent_req_set_callback(subreq, smbXsrv_client_connection_pass_loop, client);
	client->connection_pass_subreq = subreq;
}

static bool smbXsrv_client_connection_drop_filter(struct messaging_rec *rec, void *private_data)
{
	if (rec->msg_type != MSG_SMBXSRV_CONNECTION_DROP) {
		return false;
	}

	if (rec->num_fds != 0) {
		return false;
	}

	return true;
}

static void smbXsrv_client_connection_drop_loop(struct tevent_req *subreq)
{
	struct smbXsrv_client *client =
		tevent_req_callback_data(subreq,
		struct smbXsrv_client);
	int ret;
	struct messaging_rec *rec = NULL;
	struct smbXsrv_connection_dropB drop_blob;
	enum ndr_err_code ndr_err;
	struct smbXsrv_connection_drop0 *drop_info0 = NULL;
	struct server_id_buf src_server_id_buf = {};
	NTSTATUS status;

	client->connection_drop_subreq = NULL;

	ret = messaging_filtered_read_recv(subreq, talloc_tos(), &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		goto next;
	}

	if (rec->num_fds != 0) {
		DBG_ERR("MSG_SMBXSRV_CONNECTION_DROP: num_fds[%u]\n",
			rec->num_fds);
		goto next;
	}

	ndr_err = ndr_pull_struct_blob(&rec->buf, rec, &drop_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_connection_dropB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_WARNING("ndr_pull_struct_blob - %s\n", nt_errstr(status));
		goto next;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(smbXsrv_connection_dropB, &drop_blob);
	}

	if (drop_blob.version != SMBXSRV_VERSION_0) {
		DBG_ERR("ignore invalid version %u\n", drop_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_connection_dropB, &drop_blob);
		goto next;
	}

	drop_info0 = drop_blob.info.info0;
	if (drop_info0 == NULL) {
		DBG_ERR("ignore NULL info %u\n", drop_blob.version);
		NDR_PRINT_DEBUG(smbXsrv_connection_dropB, &drop_blob);
		goto next;
	}

	if (!GUID_equal(&client->global->client_guid, &drop_info0->client_guid))
	{
		struct GUID_txt_buf buf1, buf2;

		DBG_WARNING("client's client_guid [%s] != dropped guid [%s]\n",
			    GUID_buf_string(&client->global->client_guid,
					    &buf1),
			    GUID_buf_string(&drop_info0->client_guid,
					    &buf2));
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_connection_dropB, &drop_blob);
		}
		goto next;
	}

	if (client->global->initial_connect_time !=
	    drop_info0->client_connect_time)
	{
		DBG_WARNING("client's initial connect time [%s] (%llu) != "
			"dropped initial connect time [%s] (%llu)\n",
			nt_time_string(talloc_tos(),
				       client->global->initial_connect_time),
			(unsigned long long)client->global->initial_connect_time,
			nt_time_string(talloc_tos(),
				       drop_info0->client_connect_time),
			(unsigned long long)drop_info0->client_connect_time);
		if (DEBUGLVL(DBGLVL_WARNING)) {
			NDR_PRINT_DEBUG(smbXsrv_connection_dropB, &drop_blob);
		}
		goto next;
	}

	/*
	 * Disconnect all client connections, which means we will tear down all
	 * sessions, tcons and non-durable opens. At the end we will remove our
	 * smbXsrv_client_global.tdb record, which will wake up the watcher on
	 * the other node in order to let it take over the client.
	 *
	 * The client will have to reopen all sessions, tcons and durable opens.
	 */
	smbd_server_disconnect_client(client,
		server_id_str_buf(drop_info0->src_server_id, &src_server_id_buf));
	return;

next:
	if (rec != NULL) {
		int sock_fd;
		uint8_t fd_idx;

		for (fd_idx = 0; fd_idx < rec->num_fds; fd_idx++) {
			sock_fd = rec->fds[fd_idx];
			close(sock_fd);
		}
		rec->num_fds = 0;

		TALLOC_FREE(rec);
	}

	subreq = messaging_filtered_read_send(client,
					client->raw_ev_ctx,
					client->msg_ctx,
					smbXsrv_client_connection_drop_filter,
					client);
	if (subreq == NULL) {
		const char *r;
		r = "messaging_read_send(MSG_SMBXSRV_CONNECTION_DROP failed";
		exit_server_cleanly(r);
		return;
	}
	tevent_req_set_callback(subreq, smbXsrv_client_connection_drop_loop, client);
	client->connection_drop_subreq = subreq;
}

NTSTATUS smbXsrv_client_remove(struct smbXsrv_client *client)
{
	struct smbXsrv_client_table *table = client->table;
	NTSTATUS status;

	if (client->global->db_rec != NULL) {
		struct GUID_txt_buf buf;
		DBG_ERR("client_guid[%s]: Called with db_rec != NULL'\n",
			GUID_buf_string(&client->global->client_guid,
					&buf));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (!client->global->stored) {
		return NT_STATUS_OK;
	}

	TALLOC_FREE(client->connection_pass_subreq);
	TALLOC_FREE(client->connection_drop_subreq);

	client->global->db_rec = smbXsrv_client_global_fetch_locked(
					table->global.db_ctx,
					&client->global->client_guid,
					client->global /* TALLOC_CTX */);
	if (client->global->db_rec == NULL) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	status = smbXsrv_client_global_remove(client->global);
	if (!NT_STATUS_IS_OK(status)) {
		struct GUID_txt_buf buf;
		DBG_ERR("client_guid[%s] store failed - %s\n",
			GUID_buf_string(&client->global->client_guid, &buf),
			nt_errstr(status));
		return status;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		struct smbXsrv_clientB client_blob = {
			.version = SMBXSRV_VERSION_0,
			.info.info0 = client,
		};
		struct GUID_txt_buf buf;

		DBG_DEBUG("client_guid[%s] removed\n",
			  GUID_buf_string(&client->global->client_guid, &buf));
		NDR_PRINT_DEBUG(smbXsrv_clientB, &client_blob);
	}

	return NT_STATUS_OK;
}
