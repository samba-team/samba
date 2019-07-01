/*
 * Map names to server_ids
 *
 * Copyright Volker Lendecke <vl@samba.org> 2014
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
#include "lib/util/server_id.h"
#include "lib/util/server_id_db.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/strv.h"
#include "lib/util/util_tdb.h"
#include "lib/util/samba_util.h"

static TDB_DATA talloc_tdb_data(void *ptr)
{
	return (TDB_DATA) { .dptr = ptr, .dsize = talloc_get_size(ptr) };
}

struct server_id_db {
	struct server_id pid;
	struct tdb_wrap *tdb;
	char *names;
};

static int server_id_db_destructor(struct server_id_db *db);

struct server_id_db *server_id_db_init(TALLOC_CTX *mem_ctx,
				       struct server_id pid,
				       const char *base_path,
				       int hash_size, int tdb_flags)
{
	struct server_id_db *db;
	size_t pathlen = strlen(base_path) + 11;
	char path[pathlen];

	db = talloc(mem_ctx, struct server_id_db);
	if (db == NULL) {
		return NULL;
	}
	db->pid = pid;
	db->names = NULL;

	snprintf(path, pathlen, "%s/names.tdb", base_path);

	db->tdb = tdb_wrap_open(db, path, hash_size, tdb_flags,
				O_RDWR|O_CREAT, 0660);
	if (db->tdb == NULL) {
		TALLOC_FREE(db);
		return NULL;
	}

	talloc_set_destructor(db, server_id_db_destructor);

	return db;
}

void server_id_db_reinit(struct server_id_db *db, struct server_id pid)
{
	db->pid = pid;
	TALLOC_FREE(db->names);
}

struct server_id server_id_db_pid(struct server_id_db *db)
{
	return db->pid;
}

static int server_id_db_destructor(struct server_id_db *db)
{
	char *name = NULL;

	while ((name = strv_next(db->names, name)) != NULL) {
		server_id_db_remove(db, name);
	}

	return 0;
}

int server_id_db_add(struct server_id_db *db, const char *name)
{
	struct tdb_context *tdb = db->tdb->tdb;
	TDB_DATA key;
	char *n;
	int ret;

	n = strv_find(db->names, name);
	if (n != NULL) {
		return EEXIST;
	}

	ret = strv_add(db, &db->names, name);
	if (ret != 0) {
		return ret;
	}

	key = string_term_tdb_data(name);

	{
		size_t idlen = server_id_str_buf_unique(db->pid, NULL, 0);
		char idbuf[idlen];

		server_id_str_buf_unique(db->pid, idbuf, idlen);

		ret = tdb_append(
			tdb, key,
			(TDB_DATA) { .dptr = (uint8_t *)idbuf, .dsize = idlen });
	}

	if (ret != 0) {
		enum TDB_ERROR err = tdb_error(tdb);
		strv_delete(&db->names, strv_find(db->names, name));
		return map_unix_error_from_tdb(err);
	}

	return 0;
}

int server_id_db_prune_name(struct server_id_db *db, const char *name,
			    struct server_id server)
{
	struct tdb_context *tdb = db->tdb->tdb;
	size_t idbuf_len = server_id_str_buf_unique(server, NULL, 0);
	char idbuf[idbuf_len];
	TDB_DATA key;
	uint8_t *data;
	size_t datalen;
	char *ids, *id;
	int ret;

	key = string_term_tdb_data(name);
	server_id_str_buf_unique(server, idbuf, idbuf_len);

	ret = tdb_chainlock(tdb, key);
	if (ret == -1) {
		enum TDB_ERROR err = tdb_error(tdb);
		return map_unix_error_from_tdb(err);
	}

	ret = tdb_fetch_talloc(tdb, key, db, &data);
	if (ret != 0) {
		tdb_chainunlock(tdb, key);
		return ret;
	}

	datalen = talloc_get_size(data);
	if ((datalen == 0) || (data[datalen-1] != '\0')) {
		tdb_chainunlock(tdb, key);
		TALLOC_FREE(data);
		return EINVAL;
	}

	ids = (char *)data;

	id = strv_find(ids, idbuf);
	if (id == NULL) {
		tdb_chainunlock(tdb, key);
		TALLOC_FREE(data);
		return ENOENT;
	}

	strv_delete(&ids, id);

	if (talloc_get_size(ids) == 0) {
		ret = tdb_delete(tdb, key);
	} else {
		ret = tdb_store(tdb, key, talloc_tdb_data(ids), TDB_MODIFY);
	}
	TALLOC_FREE(data);

	tdb_chainunlock(tdb, key);

	if (ret == -1) {
		enum TDB_ERROR err = tdb_error(tdb);
		return map_unix_error_from_tdb(err);
	}

	return 0;
}

int server_id_db_remove(struct server_id_db *db, const char *name)
{
	char *n;
	int ret;

	n = strv_find(db->names, name);
	if (n == NULL) {
		return ENOENT;
	}

	ret = server_id_db_prune_name(db, name, db->pid);
	if (ret != 0) {
		return ret;
	}

	strv_delete(&db->names, n);
	return 0;
}

int server_id_db_lookup(struct server_id_db *db, const char *name,
			TALLOC_CTX *mem_ctx, unsigned *pnum_servers,
			struct server_id **pservers)
{
	struct tdb_context *tdb = db->tdb->tdb;
	TDB_DATA key;
	uint8_t *data;
	size_t datalen;
	char *ids, *id;
	unsigned num_servers;
	struct server_id *servers;
	int i, ret;

	key = string_term_tdb_data(name);

	ret = tdb_fetch_talloc(tdb, key, mem_ctx, &data);
	if (ret != 0) {
		return ret;
	}

	datalen = talloc_get_size(data);
	if ((datalen == 0) || (data[datalen-1] != '\0')) {
		TALLOC_FREE(data);
		return EINVAL;
	}

	ids = (char *)data;
	num_servers = strv_count(ids);

	servers = talloc_array(mem_ctx, struct server_id, num_servers);
	if (servers == NULL) {
		TALLOC_FREE(data);
		return ENOMEM;
	}

	i = 0;

	for (id = ids; id != NULL; id = strv_next(ids, id)) {
		servers[i++] = server_id_from_string(NONCLUSTER_VNN, id);
	}

	TALLOC_FREE(data);

	*pnum_servers = num_servers;
	*pservers = servers;

	return 0;
}

bool server_id_db_lookup_one(struct server_id_db *db, const char *name,
			     struct server_id *server)
{
	int ret;
	unsigned num_servers;
	struct server_id *servers;

	ret = server_id_db_lookup(db, name, db, &num_servers, &servers);
	if (ret != 0) {
		return false;
	}
	if (num_servers == 0) {
		TALLOC_FREE(servers);
		return false;
	}
	*server = servers[0];
	TALLOC_FREE(servers);
	return true;
}

struct server_id_db_traverse_state {
	TALLOC_CTX *mem_ctx;
	int (*fn)(const char *name,
		  unsigned num_servers,
		  const struct server_id *servers,
		  void *private_data);
	void *private_data;
};

static int server_id_db_traverse_fn(struct tdb_context *tdb,
				    TDB_DATA key, TDB_DATA data,
				    void *private_data)
{
	struct server_id_db_traverse_state *state = private_data;
	const char *name;
	char *ids, *id;
	unsigned num_servers;
	struct server_id *servers;
	int i, ret;

	if (key.dsize == 0) {
		return 0;
	}
	if (key.dptr[key.dsize-1] != '\0') {
		return 0;
	}
	name = (const char *)key.dptr;

	ids = (char *)talloc_memdup(state->mem_ctx, data.dptr, data.dsize);
	if (ids == NULL) {
		return 0;
	}

	num_servers = strv_count(ids);
	servers = talloc_array(ids, struct server_id, num_servers);

	i = 0;

	for (id = ids; id != NULL; id = strv_next(ids, id)) {
		servers[i++] = server_id_from_string(NONCLUSTER_VNN, id);
	}

	ret = state->fn(name, num_servers, servers, state->private_data);

	TALLOC_FREE(ids);

	return ret;
}

int server_id_db_traverse_read(struct server_id_db *db,
			       int (*fn)(const char *name,
					 unsigned num_servers,
					 const struct server_id *servers,
					 void *private_data),
			       void *private_data)
{
	struct server_id_db_traverse_state state;
	int ret;

	state = (struct server_id_db_traverse_state) {
		.fn = fn, .private_data = private_data,
		.mem_ctx = talloc_new(db)
	};

	if (state.mem_ctx == NULL) {
		return ENOMEM;
	}

	ret = tdb_traverse_read(db->tdb->tdb, server_id_db_traverse_fn,
				&state);
	TALLOC_FREE(state.mem_ctx);
	return ret;
}
