/*
   Using tdb as a hash table

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
#include "system/filesys.h"

#include <talloc.h>
#include <tdb.h>

#include "common/db_hash.h"

struct db_hash_context {
	struct tdb_context *db;
};


static int db_hash_destructor(struct db_hash_context *dh)
{
	if (dh->db != NULL) {
		tdb_close(dh->db);
		dh->db = NULL;
	}
	return 0;
}

int db_hash_init(TALLOC_CTX *mem_ctx, const char *name, int hash_size,
		 enum db_hash_type type, struct db_hash_context **result)
{
	struct db_hash_context *dh;
	int tdb_flags = TDB_INTERNAL | TDB_DISALLOW_NESTING;

	dh = talloc_zero(mem_ctx, struct db_hash_context);
	if (dh == NULL) {
		return ENOMEM;
	}

	if (type == DB_HASH_COMPLEX) {
		tdb_flags |= TDB_INCOMPATIBLE_HASH;
	}

	dh->db = tdb_open(name, hash_size, tdb_flags, O_RDWR|O_CREAT, 0);
	if (dh->db == NULL) {
		talloc_free(dh);
		return ENOMEM;
	}

	talloc_set_destructor(dh, db_hash_destructor);
	*result = dh;
	return 0;
}

static int db_hash_map_tdb_error(struct db_hash_context *dh)
{
	enum TDB_ERROR tdb_err;
	int ret;

	tdb_err = tdb_error(dh->db);
	switch (tdb_err) {
		case TDB_SUCCESS:
			ret = 0; break;
		case TDB_ERR_OOM:
			ret = ENOMEM; break;
		case TDB_ERR_EXISTS:
			ret = EEXIST; break;
		case TDB_ERR_NOEXIST:
			ret = ENOENT; break;
		case TDB_ERR_EINVAL:
			ret = EINVAL; break;
		default:
			ret = EIO; break;
	}
	return ret;
}

int db_hash_insert(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen,
		   uint8_t *databuf, size_t datalen)
{
	TDB_DATA key, data;
	int ret;

	if (dh == NULL) {
		return EINVAL;
	}

	key.dptr = keybuf;
	key.dsize = keylen;

	data.dptr = databuf;
	data.dsize = datalen;

	ret = tdb_store(dh->db, key, data, TDB_INSERT);
	if (ret != 0) {
		ret = db_hash_map_tdb_error(dh);
	}
	return ret;
}

int db_hash_add(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen,
		uint8_t *databuf, size_t datalen)
{
	TDB_DATA key, data;
	int ret;

	if (dh == NULL) {
		return EINVAL;
	}

	key.dptr = keybuf;
	key.dsize = keylen;

	data.dptr = databuf;
	data.dsize = datalen;

	ret = tdb_store(dh->db, key, data, TDB_REPLACE);
	if (ret != 0) {
		ret = db_hash_map_tdb_error(dh);
	}
	return ret;
}

int db_hash_delete(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen)
{
	TDB_DATA key;
	int ret;

	key.dptr = keybuf;
	key.dsize = keylen;

	if (dh == NULL) {
		return EINVAL;
	}

	ret = tdb_delete(dh->db, key);
	if (ret != 0) {
		ret = db_hash_map_tdb_error(dh);
	}
	return ret;
}

struct db_hash_fetch_state {
	db_hash_record_parser_fn parser;
	void *private_data;
};

static int db_hash_fetch_parser(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct db_hash_fetch_state *state =
		(struct db_hash_fetch_state *)private_data;
	int ret;

	ret = state->parser(key.dptr, key.dsize, data.dptr, data.dsize,
			    state->private_data);
	return ret;
}

int db_hash_fetch(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen,
		  db_hash_record_parser_fn parser, void *private_data)
{
	struct db_hash_fetch_state state;
	TDB_DATA key;
	int ret;

	if (dh == NULL || parser == NULL) {
		return EINVAL;
	}

	state.parser = parser;
	state.private_data = private_data;

	key.dptr = keybuf;
	key.dsize = keylen;

	ret = tdb_parse_record(dh->db, key, db_hash_fetch_parser, &state);
	if (ret == -1) {
		return ENOENT;
	}
	return ret;
}

int db_hash_exists(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen)
{
	TDB_DATA key;
	int ret;

	if (dh == NULL) {
		return EINVAL;
	}

	key.dptr = keybuf;
	key.dsize = keylen;

	ret = tdb_exists(dh->db, key);
	if (ret == 1) {
		/* Key found */
		ret = 0;
	} else {
		ret = db_hash_map_tdb_error(dh);
		if (ret == 0) {
			ret = ENOENT;
		}
	}
	return ret;
}

struct db_hash_traverse_state {
	db_hash_record_parser_fn parser;
	void *private_data;
};

static int db_hash_traverse_parser(struct tdb_context *tdb,
				   TDB_DATA key, TDB_DATA data,
				   void *private_data)
{
	struct db_hash_traverse_state *state =
		(struct db_hash_traverse_state *)private_data;

	return state->parser(key.dptr, key.dsize, data.dptr, data.dsize,
			     state->private_data);
}

int db_hash_traverse(struct db_hash_context *dh,
		     db_hash_record_parser_fn parser, void *private_data,
		     int *count)
{
	struct db_hash_traverse_state state;
	int ret;

	if (dh == NULL) {
		return EINVAL;
	}

	/* Special case, for counting records */
	if (parser == NULL) {
		ret = tdb_traverse_read(dh->db, NULL, NULL);
	} else {
		state.parser = parser;
		state.private_data = private_data;

		ret = tdb_traverse_read(dh->db, db_hash_traverse_parser, &state);
	}

	if (ret == -1) {
		ret = db_hash_map_tdb_error(dh);
	} else {
		if (count != NULL) {
			*count = ret;
		}
		ret = 0;
	}

	return ret;
}

int db_hash_traverse_update(struct db_hash_context *dh,
			    db_hash_record_parser_fn parser,
			    void *private_data, int *count)
{
	struct db_hash_traverse_state state;
	int ret;

	if (dh == NULL || parser == NULL) {
		return EINVAL;
	}

	state.parser = parser;
	state.private_data = private_data;

	ret = tdb_traverse(dh->db, db_hash_traverse_parser, &state);
	if (ret == -1) {
		ret = db_hash_map_tdb_error(dh);
	} else {
		if (count != NULL) {
			*count = ret;
		}
		ret = 0;
	}

	return ret;
}
