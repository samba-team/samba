/*
   Unix SMB/CIFS implementation.
   Implementation of a reliable server_exists()
   Copyright (C) Volker Lendecke 2010

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
#include "serverid.h"
#include "util_tdb.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/param/param.h"
#include "ctdbd_conn.h"
#include "messages.h"

struct serverid_key {
	pid_t pid;
	uint32_t task_id;
	uint32_t vnn;
};

struct serverid_data {
	uint64_t unique_id;
	uint32_t msg_flags;
};

static struct db_context *serverid_db(void)
{
	static struct db_context *db;

	if (db != NULL) {
		return db;
	}
	db = db_open(NULL, lock_path("serverid.tdb"), 0,
		     TDB_DEFAULT|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
		     O_RDWR|O_CREAT, 0644, DBWRAP_LOCK_ORDER_2,
		     DBWRAP_FLAG_NONE);
	return db;
}

bool serverid_parent_init(TALLOC_CTX *mem_ctx)
{
	struct db_context *db;

	db = serverid_db();
	if (db == NULL) {
		DEBUG(1, ("could not open serverid.tdb: %s\n",
			  strerror(errno)));
		return false;
	}

	return true;
}

static void serverid_fill_key(const struct server_id *id,
			      struct serverid_key *key)
{
	ZERO_STRUCTP(key);
	key->pid = id->pid;
	key->task_id = id->task_id;
	key->vnn = id->vnn;
}

bool serverid_register(const struct server_id id, uint32_t msg_flags)
{
	struct db_context *db;
	struct serverid_key key;
	struct serverid_data data;
	struct db_record *rec;
	TDB_DATA tdbkey, tdbdata;
	NTSTATUS status;
	bool ret = false;

	db = serverid_db();
	if (db == NULL) {
		return false;
	}

	serverid_fill_key(&id, &key);
	tdbkey = make_tdb_data((uint8_t *)&key, sizeof(key));

	rec = dbwrap_fetch_locked(db, talloc_tos(), tdbkey);
	if (rec == NULL) {
		DEBUG(1, ("Could not fetch_lock serverid.tdb record\n"));
		return false;
	}

	ZERO_STRUCT(data);
	data.unique_id = id.unique_id;
	data.msg_flags = msg_flags;

	tdbdata = make_tdb_data((uint8_t *)&data, sizeof(data));
	status = dbwrap_record_store(rec, tdbdata, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Storing serverid.tdb record failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	if (lp_clustering() &&
	    ctdb_serverids_exist_supported(messaging_ctdbd_connection()))
	{
		register_with_ctdbd(messaging_ctdbd_connection(), id.unique_id);
	}

	ret = true;
done:
	TALLOC_FREE(rec);
	return ret;
}

bool serverid_deregister(struct server_id id)
{
	struct db_context *db;
	struct serverid_key key;
	struct db_record *rec;
	TDB_DATA tdbkey;
	NTSTATUS status;
	bool ret = false;

	db = serverid_db();
	if (db == NULL) {
		return false;
	}

	serverid_fill_key(&id, &key);
	tdbkey = make_tdb_data((uint8_t *)&key, sizeof(key));

	rec = dbwrap_fetch_locked(db, talloc_tos(), tdbkey);
	if (rec == NULL) {
		DEBUG(1, ("Could not fetch_lock serverid.tdb record\n"));
		return false;
	}

	status = dbwrap_record_delete(rec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Deleting serverid.tdb record failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}
	ret = true;
done:
	TALLOC_FREE(rec);
	return ret;
}

struct serverid_exists_state {
	const struct server_id *id;
	bool exists;
};

static void server_exists_parse(TDB_DATA key, TDB_DATA data, void *priv)
{
	struct serverid_exists_state *state =
		(struct serverid_exists_state *)priv;

	if (data.dsize != sizeof(struct serverid_data)) {
		state->exists = false;
		return;
	}

	/*
	 * Use memcmp, not direct compare. data.dptr might not be
	 * aligned.
	 */
	state->exists = (memcmp(&state->id->unique_id, data.dptr,
				sizeof(state->id->unique_id)) == 0);
}

bool serverid_exists(const struct server_id *id)
{
	bool result = false;
	bool ok = false;

	ok = serverids_exist(id, 1, &result);
	if (!ok) {
		return false;
	}

	return result;
}

bool serverids_exist(const struct server_id *ids, int num_ids, bool *results)
{
	int *todo_idx = NULL;
	struct server_id *todo_ids = NULL;
	bool *todo_results = NULL;
	int todo_num = 0;
	int *remote_idx = NULL;
	int remote_num = 0;
	int *verify_idx = NULL;
	int verify_num = 0;
	int t, idx;
	bool result = false;
	struct db_context *db;

	db = serverid_db();
	if (db == NULL) {
		return false;
	}

	todo_idx = talloc_array(talloc_tos(), int, num_ids);
	if (todo_idx == NULL) {
		goto fail;
	}
	todo_ids = talloc_array(talloc_tos(), struct server_id, num_ids);
	if (todo_ids == NULL) {
		goto fail;
	}
	todo_results = talloc_array(talloc_tos(), bool, num_ids);
	if (todo_results == NULL) {
		goto fail;
	}

	remote_idx = talloc_array(talloc_tos(), int, num_ids);
	if (remote_idx == NULL) {
		goto fail;
	}
	verify_idx = talloc_array(talloc_tos(), int, num_ids);
	if (verify_idx == NULL) {
		goto fail;
	}

	for (idx=0; idx<num_ids; idx++) {
		results[idx] = false;

		if (server_id_is_disconnected(&ids[idx])) {
			continue;
		}

		if (procid_is_me(&ids[idx])) {
			results[idx] = true;
			continue;
		}

		if (procid_is_local(&ids[idx])) {
			bool exists = process_exists_by_pid(ids[idx].pid);

			if (!exists) {
				continue;
			}

			if (ids[idx].unique_id == SERVERID_UNIQUE_ID_NOT_TO_VERIFY) {
				results[idx] = true;
				continue;
			}

			verify_idx[verify_num] = idx;
			verify_num += 1;
			continue;
		}

		if (!lp_clustering()) {
			continue;
		}

		remote_idx[remote_num] = idx;
		remote_num += 1;
	}

	if (remote_num != 0 &&
	    ctdb_serverids_exist_supported(messaging_ctdbd_connection()))
	{
		int old_remote_num = remote_num;

		remote_num = 0;
		todo_num = 0;

		for (t=0; t<old_remote_num; t++) {
			idx = remote_idx[t];

			if (ids[idx].unique_id == SERVERID_UNIQUE_ID_NOT_TO_VERIFY) {
				remote_idx[remote_num] = idx;
				remote_num += 1;
				continue;
			}

			todo_idx[todo_num] = idx;
			todo_ids[todo_num] = ids[idx];
			todo_results[todo_num] = false;
			todo_num += 1;
		}

		/*
		 * Note: this only uses CTDB_CONTROL_CHECK_SRVIDS
		 * to verify that the server_id still exists,
		 * which means only the server_id.unique_id and
		 * server_id.vnn are verified, while server_id.pid
		 * is not verified at all.
		 *
		 * TODO: do we want to verify server_id.pid somehow?
		 */
		if (!ctdb_serverids_exist(messaging_ctdbd_connection(),
					  todo_ids, todo_num, todo_results))
		{
			goto fail;
		}

		for (t=0; t<todo_num; t++) {
			idx = todo_idx[t];

			results[idx] = todo_results[t];
		}
	}

	if (remote_num != 0) {
		todo_num = 0;

		for (t=0; t<remote_num; t++) {
			idx = remote_idx[t];
			todo_idx[todo_num] = idx;
			todo_ids[todo_num] = ids[idx];
			todo_results[todo_num] = false;
			todo_num += 1;
		}

		if (!ctdb_processes_exist(messaging_ctdbd_connection(),
					  todo_ids, todo_num,
					  todo_results)) {
			goto fail;
		}

		for (t=0; t<todo_num; t++) {
			idx = todo_idx[t];

			if (!todo_results[t]) {
				continue;
			}

			if (ids[idx].unique_id == SERVERID_UNIQUE_ID_NOT_TO_VERIFY) {
				results[idx] = true;
				continue;
			}

			verify_idx[verify_num] = idx;
			verify_num += 1;
		}
	}

	for (t=0; t<verify_num; t++) {
		struct serverid_exists_state state;
		struct serverid_key key;
		TDB_DATA tdbkey;
		NTSTATUS status;

		idx = verify_idx[t];

		serverid_fill_key(&ids[idx], &key);
		tdbkey = make_tdb_data((uint8_t *)&key, sizeof(key));

		state.id = &ids[idx];
		state.exists = false;
		status = dbwrap_parse_record(db, tdbkey, server_exists_parse, &state);
		if (!NT_STATUS_IS_OK(status)) {
			results[idx] = false;
			continue;
		}
		results[idx] = state.exists;
	}

	result = true;
fail:
	TALLOC_FREE(verify_idx);
	TALLOC_FREE(remote_idx);
	TALLOC_FREE(todo_results);
	TALLOC_FREE(todo_ids);
	TALLOC_FREE(todo_idx);
	return result;
}

static bool serverid_rec_parse(const struct db_record *rec,
			       struct server_id *id, uint32_t *msg_flags)
{
	struct serverid_key key;
	struct serverid_data data;
	TDB_DATA tdbkey;
	TDB_DATA tdbdata;

	tdbkey = dbwrap_record_get_key(rec);
	tdbdata = dbwrap_record_get_value(rec);

	if (tdbkey.dsize != sizeof(key)) {
		DEBUG(1, ("Found invalid key length %d in serverid.tdb\n",
			  (int)tdbkey.dsize));
		return false;
	}
	if (tdbdata.dsize != sizeof(data)) {
		DEBUG(1, ("Found invalid value length %d in serverid.tdb\n",
			  (int)tdbdata.dsize));
		return false;
	}

	memcpy(&key, tdbkey.dptr, sizeof(key));
	memcpy(&data, tdbdata.dptr, sizeof(data));

	id->pid = key.pid;
	id->task_id = key.task_id;
	id->vnn = key.vnn;
	id->unique_id = data.unique_id;
	*msg_flags = data.msg_flags;
	return true;
}

struct serverid_traverse_read_state {
	int (*fn)(const struct server_id *id, uint32_t msg_flags,
		  void *private_data);
	void *private_data;
};

static int serverid_traverse_read_fn(struct db_record *rec, void *private_data)
{
	struct serverid_traverse_read_state *state =
		(struct serverid_traverse_read_state *)private_data;
	struct server_id id;
	uint32_t msg_flags;

	if (!serverid_rec_parse(rec, &id, &msg_flags)) {
		return 0;
	}
	return state->fn(&id, msg_flags,state->private_data);
}

bool serverid_traverse_read(int (*fn)(const struct server_id *id,
				      uint32_t msg_flags, void *private_data),
			    void *private_data)
{
	struct db_context *db;
	struct serverid_traverse_read_state state;
	NTSTATUS status;

	db = serverid_db();
	if (db == NULL) {
		return false;
	}
	state.fn = fn;
	state.private_data = private_data;

	status = dbwrap_traverse_read(db, serverid_traverse_read_fn, &state,
				      NULL);
	return NT_STATUS_IS_OK(status);
}

struct serverid_traverse_state {
	int (*fn)(struct db_record *rec, const struct server_id *id,
		  uint32_t msg_flags, void *private_data);
	void *private_data;
};

static int serverid_traverse_fn(struct db_record *rec, void *private_data)
{
	struct serverid_traverse_state *state =
		(struct serverid_traverse_state *)private_data;
	struct server_id id;
	uint32_t msg_flags;

	if (!serverid_rec_parse(rec, &id, &msg_flags)) {
		return 0;
	}
	return state->fn(rec, &id, msg_flags, state->private_data);
}

bool serverid_traverse(int (*fn)(struct db_record *rec,
				 const struct server_id *id,
				 uint32_t msg_flags, void *private_data),
			    void *private_data)
{
	struct db_context *db;
	struct serverid_traverse_state state;
	NTSTATUS status;

	db = serverid_db();
	if (db == NULL) {
		return false;
	}
	state.fn = fn;
	state.private_data = private_data;

	status = dbwrap_traverse(db, serverid_traverse_fn, &state, NULL);
	return NT_STATUS_IS_OK(status);
}

uint64_t serverid_get_random_unique_id(void)
{
	uint64_t unique_id = SERVERID_UNIQUE_ID_NOT_TO_VERIFY;

	while (unique_id == SERVERID_UNIQUE_ID_NOT_TO_VERIFY) {
		generate_random_buffer((uint8_t *)&unique_id,
				       sizeof(unique_id));
	}

	return unique_id;
}
