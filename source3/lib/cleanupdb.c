/*
   Unix SMB/CIFS implementation.
   Implementation of reliable cleanup events
   Copyright (C) Ralph Boehme 2016

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

#include "cleanupdb.h"

struct cleanup_key {
	pid_t pid;
};

struct cleanup_rec {
	bool unclean;
};

static struct tdb_wrap *cleanup_db(void)
{
	static struct tdb_wrap *db;
	char *db_path = NULL;
	int tdbflags = TDB_INCOMPATIBLE_HASH | TDB_CLEAR_IF_FIRST |
		TDB_MUTEX_LOCKING;

	if (db != NULL) {
		return db;
	}

	db_path = lock_path(talloc_tos(), "smbd_cleanupd.tdb");
	if (db_path == NULL) {
		return NULL;
	}

	db = tdb_wrap_open(NULL, db_path, 0, tdbflags,
			   O_CREAT | O_RDWR, 0644);
	if (db == NULL) {
		DBG_ERR("Failed to open smbd_cleanupd.tdb\n");
	}

	TALLOC_FREE(db_path);
	return db;
}

bool cleanupdb_store_child(const pid_t pid, const bool unclean)
{
	struct tdb_wrap *db;
	struct cleanup_key key = { .pid = pid };
	struct cleanup_rec rec = { .unclean = unclean };
	TDB_DATA tdbkey = { .dptr = (uint8_t *)&key, .dsize = sizeof(key) };
	TDB_DATA tdbdata = { .dptr = (uint8_t *)&rec, .dsize = sizeof(rec) };
	int result;

	db = cleanup_db();
	if (db == NULL) {
		return false;
	}

	result = tdb_store(db->tdb, tdbkey, tdbdata, TDB_REPLACE);
	if (result != 0) {
		DBG_ERR("tdb_store failed for pid %d\n", (int)pid);
		return false;
	}

	return true;
}

bool cleanupdb_delete_child(const pid_t pid)
{
	struct tdb_wrap *db;
	struct cleanup_key key = { .pid = pid };
	TDB_DATA tdbkey = { .dptr = (uint8_t *)&key, .dsize = sizeof(key) };
	int result;

	db = cleanup_db();
	if (db == NULL) {
		return false;
	}

	result = tdb_delete(db->tdb, tdbkey);
	if (result != 0) {
		DBG_ERR("tdb_delete failed for pid %d\n", (int)pid);
		return false;
	}

	return true;
}

struct cleanup_read_state {
	int (*fn)(const pid_t pid, const bool cleanup, void *private_data);
	void *private_data;
};

static int cleanup_traverse_fn(struct tdb_context *tdb,
			       TDB_DATA key, TDB_DATA value,
			       void *private_data)
{
	struct cleanup_read_state *state =
		(struct cleanup_read_state *)private_data;
	struct cleanup_key ckey;
	struct cleanup_rec rec;
	int result;

	if (key.dsize != sizeof(struct cleanup_key)) {
		DBG_ERR("Found invalid key length %zu in cleanup.tdb\n",
			key.dsize);
		return -1;
	}
	memcpy(&ckey, key.dptr, sizeof(struct cleanup_key));

	if (value.dsize != sizeof(struct cleanup_rec)) {
		DBG_ERR("Found invalid value length %zu in cleanup.tdb\n",
			value.dsize);
		return -1;
	}
	memcpy(&rec, value.dptr, sizeof(struct cleanup_rec));

	result = state->fn(ckey.pid, rec.unclean, state->private_data);
	if (result != 0) {
		return -1;
	}

	return 0;
}

int cleanupdb_traverse_read(int (*fn)(const pid_t pid,
				      const bool cleanup,
				      void *private_data),
			    void *private_data)
{
	struct tdb_wrap *db;
	struct cleanup_read_state state;
	int result;

	db = cleanup_db();
	if (db == NULL) {
		return -1;
	}

	state = (struct cleanup_read_state) {
		.fn = fn,
		.private_data = private_data
	};

	result = tdb_traverse_read(db->tdb, cleanup_traverse_fn, &state);
	if (result < 0) {
		DBG_ERR("tdb_traverse_read failed\n");
		return -1;
	}

	return result;
}
