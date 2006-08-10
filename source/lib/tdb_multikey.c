/* 
 *  Unix SMB/CIFS implementation.
 *  TDB multi-key wrapper
 *  Copyright (C) Volker Lendecke 2006
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

static struct { enum TDB_ERROR t; NTSTATUS n; } tdb_to_ntstatus_map[] = {
	{ TDB_ERR_CORRUPT, NT_STATUS_INTERNAL_DB_CORRUPTION },
	{ TDB_ERR_IO, NT_STATUS_UNEXPECTED_IO_ERROR },
	{ TDB_ERR_LOCK, NT_STATUS_FILE_LOCK_CONFLICT },
	{ TDB_ERR_OOM, NT_STATUS_NO_MEMORY },
	{ TDB_ERR_EXISTS, NT_STATUS_OBJECTID_EXISTS },
	{ TDB_ERR_NOLOCK, NT_STATUS_NOT_LOCKED },
	{ TDB_ERR_LOCK_TIMEOUT, NT_STATUS_IO_TIMEOUT },
	{ TDB_ERR_NOEXIST, NT_STATUS_NOT_FOUND },
	{ TDB_ERR_EINVAL, NT_STATUS_INVALID_PARAMETER },
	{ TDB_ERR_RDONLY, NT_STATUS_ACCESS_DENIED },
	{ 0, NT_STATUS_OK },
};	

NTSTATUS map_ntstatus_from_tdb(struct tdb_context *t)
{
	enum TDB_ERROR err = tdb_error(t);
	int i = 0;

	while (tdb_to_ntstatus_map[i].t != 0) {
		if (tdb_to_ntstatus_map[i].t == err) {
			return tdb_to_ntstatus_map[i].n;
		}
		i += 1;
	}

	return NT_STATUS_INTERNAL_ERROR;
}

#define KEY_VERSION (1)
#define PRIMARY_KEY_LENGTH (24)

/*
 * Check that the keying version is acceptable. Change operations are very
 * expensive under transactions anyway, so we do this upon every change to
 * avoid damage when someone changes the key format while we have the db open.
 *
 * To be called only within a transaction, we don't do locking here.
 */

static BOOL tdb_check_keyversion(struct tdb_context *tdb)
{
	const char *versionkey = "KEYVERSION";
	TDB_DATA key, data;
	NTSTATUS status;
	unsigned long version;
	char *endptr;

	key.dptr = CONST_DISCARD(char *, versionkey);
	key.dsize = strlen(versionkey)+1;

	data = tdb_fetch(tdb, key);
	if (data.dptr == NULL) {
		char *vstr;
		int res;

		asprintf(&vstr, "%d", KEY_VERSION);
		if (vstr == NULL) {
			DEBUG(0, ("asprintf failed\n"));
			return False;
		}
		data.dptr = vstr;
		data.dsize = strlen(vstr)+1;

		res = tdb_store(tdb, key, data, TDB_INSERT);
		SAFE_FREE(vstr);

		if (res < 0) {
			status = map_ntstatus_from_tdb(tdb);
			DEBUG(5, ("Could not store key: %s\n",
				  nt_errstr(status)));
			return False;
		}

		return True;
	}

	/*
	 * We have a key, check it
	 */

	SMB_ASSERT(data.dsize > 0);
	if (data.dptr[data.dsize-1] != '\0') {
		DEBUG(1, ("Key field not NUL terminated\n"));
		SAFE_FREE(data.dptr);
		return False;
	}

	version = strtoul(data.dptr, &endptr, 10);
	if (endptr != data.dptr+data.dsize-1) {
		DEBUG(1, ("Invalid version string\n"));
		SAFE_FREE(data.dptr);
		return False;
	}
	SAFE_FREE(data.dptr);

	if (version != KEY_VERSION) {
		DEBUG(1, ("Wrong key version: %ld, expected %d\n",
			  version, KEY_VERSION));
		return False;
	}

	return True;
}

/*
 * Find a record according to a key and value expected in that key. The
 * primary_key is returned for later reference in tdb_idx_update or
 * tdb_idx_delete.
 */

NTSTATUS tdb_find_keyed(TALLOC_CTX *ctx, struct tdb_context *tdb,
			int keynumber, const char *value,
			TDB_DATA *result, char **primary_key)
{
	TDB_DATA key, prim, data;
	NTSTATUS status;

	prim.dptr = data.dptr = NULL;

	key.dsize = talloc_asprintf_len(ctx, &key.dptr, "KEY/%d/%s", keynumber,
					value);
	if (key.dptr == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	key.dsize += 1;

	prim = tdb_fetch(tdb, key);
	if (prim.dptr == NULL) {
		status = NT_STATUS_NOT_FOUND;
		goto fail;
	}

	data = tdb_fetch(tdb, prim);
	if (data.dptr == NULL) {
		DEBUG(1, ("Did not find record %s for key %s\n",
			  prim.dptr, key.dptr));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	if (primary_key != NULL) {
		*primary_key = talloc_strndup(ctx, prim.dptr, prim.dsize);
		if (*primary_key == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}
	
	/*
	 * The following copy will be removed when tdb_fetch takes a
	 * TALLOC_CTX as parameter.
	 */

	result->dptr = (char *)talloc_memdup(ctx, data.dptr, data.dsize);
	if (result->dptr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	result->dsize = data.dsize;

	status = NT_STATUS_OK;

 fail:
	TALLOC_FREE(key.dptr);
	SAFE_FREE(prim.dptr);
	SAFE_FREE(data.dptr);
	return status;
}

/*
 * Store all the key entries for a data entry. Best called within a tdb
 * transaction.
 */

static NTSTATUS set_keys(struct tdb_context *tdb,
			 char **(*getkeys)(TALLOC_CTX *mem_ctx, TDB_DATA data,
					   void *private_data),
			 TDB_DATA primary_key, TDB_DATA user_data,
			 void *private_data)
{
	int i;
	char **keys = getkeys(NULL, user_data, private_data);

	if (keys == NULL) {
		DEBUG(5, ("Could not get keys\n"));
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; keys[i] != NULL; i++) {
		NTSTATUS status;
		TDB_DATA key;

		key.dsize = talloc_asprintf_len(keys, &key.dptr, "KEY/%d/%s",
						i, keys[i]);
		if (key.dptr == NULL) {
			DEBUG(0, ("talloc_asprintf failed\n"));
			TALLOC_FREE(keys);
			return NT_STATUS_NO_MEMORY;
		}
		key.dsize += 1;

		if (tdb_store(tdb, key, primary_key, TDB_INSERT) < 0) {
			status = map_ntstatus_from_tdb(tdb);
			DEBUG(5, ("Could not store key %d: %s\n", i,
				  nt_errstr(status)));
			TALLOC_FREE(keys);
			return status;
		}
	}

	TALLOC_FREE(keys);
	return NT_STATUS_OK;
}

/*
 * Delete all the key entries for a data entry. Best called within a tdb
 * transaction.
 */

static NTSTATUS del_keys(struct tdb_context *tdb,
			 char **(*getkeys)(TALLOC_CTX *mem_ctx, TDB_DATA data,
					   void *private_data),
			 TDB_DATA primary_key, void *private_data)
{
	TDB_DATA data;
	int i;
	char **keys;

	/*
	 * We need the data record to be able to fetch all the keys, so pull
	 * the user data
	 */

	data = tdb_fetch(tdb, primary_key);
	if (data.dptr == NULL) {
		DEBUG(5, ("Could not find record for key %s\n",
			  primary_key.dptr));
		return NT_STATUS_NOT_FOUND;
	}

	keys = getkeys(NULL, data, private_data);
	if (keys == NULL) {
		DEBUG(5, ("Could not get keys\n"));
		return NT_STATUS_NO_MEMORY;
	}

	SAFE_FREE(data.dptr);

	for (i=0; keys[i] != NULL; i++) {
		NTSTATUS status;
		TDB_DATA key;

		key.dsize = talloc_asprintf_len(keys, &key.dptr, "KEY/%d/%s",
						i, keys[i]);
		if (key.dptr == NULL) {
			DEBUG(0, ("talloc_asprintf failed\n"));
			TALLOC_FREE(keys);
			return NT_STATUS_NO_MEMORY;
		}
		key.dsize += 1;

		if (tdb_delete(tdb, key) < 0) {
			status = map_ntstatus_from_tdb(tdb);
			DEBUG(5, ("Could not delete key %d: %s\n", i,
				  nt_errstr(status)));
			TALLOC_FREE(keys);
			return status;
		}
	}

	TALLOC_FREE(keys);
	return NT_STATUS_OK;
}

/*
 * Generate a unique primary key
 */

static TDB_DATA new_primary_key(struct tdb_context *tdb)
{
	TDB_DATA key;
	int i;

	/*
	 * Generate a new primary key, the for loop is for the very unlikely
	 * collisions.
	 */

	for (i=0; i<20; i++) {
		TDB_DATA data;
		asprintf(&key.dptr, "KEYPRIM/%s", generate_random_str(16));
		if (key.dptr == NULL) {
			DEBUG(0, ("talloc_asprintf failed\n"));
			return key;
		}

#ifdef DEVELOPER
		SMB_ASSERT(strlen(key.dptr) == PRIMARY_KEY_LENGTH);
#endif
		key.dsize = PRIMARY_KEY_LENGTH+1;

		data = tdb_fetch(tdb, key);
		if (data.dptr == NULL) {
			return key;
		}
		SAFE_FREE(key.dptr);
		SAFE_FREE(data.dptr);
	}

	DEBUG(0, ("Did not find a unique key string!\n"));
	key.dptr = NULL;
	key.dsize = 0;
	return key;
}

/*
 * Add a new record to the database
 */

NTSTATUS tdb_add_keyed(struct tdb_context *tdb,
		       char **(*getkeys)(TALLOC_CTX *mem_ctx, TDB_DATA data,
					 void *private_data),
		       TDB_DATA data, void *private_data)
{
	NTSTATUS status = NT_STATUS_OK;
	TDB_DATA key;

	key.dptr = NULL;

	if (tdb_transaction_start(tdb) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		DEBUG(5, ("Could not start transaction: %s\n",
			  nt_errstr(status)));
		return status;
	}

	if (!tdb_check_keyversion(tdb)) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	key = new_primary_key(tdb);
	if (key.dptr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (tdb_store(tdb, key, data, TDB_INSERT) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		DEBUG(5, ("Could not store record: %s\n", nt_errstr(status)));
		goto fail;
	}

	status = set_keys(tdb, getkeys, key, data, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("set_keys failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	if (tdb_transaction_commit(tdb) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		DEBUG(5, ("tdb_transaction_commit failed: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	SAFE_FREE(key.dptr);
	return NT_STATUS_OK;

 fail:
	if (tdb_transaction_cancel(tdb) < 0) {
		smb_panic("tdb_cancel_transaction failed\n");
	}

	SAFE_FREE(key.dptr);
	return status;
}

/*
 * Delete a record from the database, given its primary key
 */

NTSTATUS tdb_del_keyed(struct tdb_context *tdb,
		       char **(*getkeys)(TALLOC_CTX *mem_ctx, TDB_DATA data,
					 void *private_data),
		       const char *primary_key, void *private_data)
{
	NTSTATUS status = NT_STATUS_OK;
	TDB_DATA key;

	if ((primary_key == NULL) ||
	    (strlen(primary_key) != PRIMARY_KEY_LENGTH) ||
	    (strncmp(primary_key, "KEYPRIM/", 7) != 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (tdb_transaction_start(tdb) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		DEBUG(5, ("Could not start transaction: %s\n",
			  nt_errstr(status)));
		return status;
	}

	if (!tdb_check_keyversion(tdb)) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	key.dptr = CONST_DISCARD(char *, primary_key);
	key.dsize = PRIMARY_KEY_LENGTH+1;

	status = del_keys(tdb, getkeys, key, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("del_keys failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	if (tdb_delete(tdb, key) < 0) {
		DEBUG(5, ("Could not delete record %s\n", primary_key));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	if (tdb_transaction_commit(tdb) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		DEBUG(5, ("tdb_transaction_commit failed: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	return NT_STATUS_OK;

 fail:
	if (tdb_transaction_cancel(tdb) < 0) {
		smb_panic("tdb_cancel_transaction failed\n");
	}

	return status;
}

/*
 * Update a record that has previously been fetched and then changed.
 */

NTSTATUS tdb_update_keyed(struct tdb_context *tdb, const char *primary_key,
			  char **(*getkeys)(TALLOC_CTX *mem_ctx,
					    TDB_DATA data, void *private_data),
			  TDB_DATA data, void *private_data)
{
	NTSTATUS status = NT_STATUS_OK;
	TDB_DATA key;

	if ((primary_key == NULL) ||
	    (strlen(primary_key) != PRIMARY_KEY_LENGTH) ||
	    (strncmp(primary_key, "KEYPRIM/", 8) != 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (tdb_transaction_start(tdb) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		DEBUG(5, ("Could not start transaction: %s\n",
			  nt_errstr(status)));
		return status;
	}

	if (!tdb_check_keyversion(tdb)) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	key.dptr = CONST_DISCARD(char *, primary_key);
	key.dsize = PRIMARY_KEY_LENGTH+1;

	status = del_keys(tdb, getkeys, key, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("del_keys failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	if (tdb_store(tdb, key, data, TDB_REPLACE) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		DEBUG(5, ("Could not store new record: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	status = set_keys(tdb, getkeys, key, data, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("set_keys failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	if (tdb_transaction_commit(tdb) < 0) {
		status = map_ntstatus_from_tdb(tdb);
		DEBUG(5, ("tdb_transaction_commit failed: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	return NT_STATUS_OK;

 fail:
	if (tdb_transaction_cancel(tdb) < 0) {
		smb_panic("tdb_cancel_transaction failed\n");
	}

	return status;
}

static int iterator_destructor(void *p)
{
	struct tdb_keyed_iterator *i = (struct tdb_keyed_iterator *)p;
	SAFE_FREE(i->key.dptr);
	return 0;
}

struct tdb_keyed_iterator *tdb_enum_keyed(TALLOC_CTX *mem_ctx,
					  struct tdb_context *tdb)
{
	struct tdb_keyed_iterator *result = TALLOC_P(
		mem_ctx, struct tdb_keyed_iterator);

	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return result;
	}

	result->tdb = tdb;
	result->key = tdb_firstkey(tdb);
	talloc_set_destructor(result, iterator_destructor);
	return result;
}

BOOL tdb_next_keyed(struct tdb_keyed_iterator *it, TDB_DATA *data)
{
	if (it->key.dptr == NULL) {
		return False;
	}

	while (True) {
		TDB_DATA tmp;

		if ((it->key.dsize == PRIMARY_KEY_LENGTH+1) &&
		    (strncmp(it->key.dptr, "KEYPRIM/", 8) == 0)) {

			*data = tdb_fetch(it->tdb, it->key);

			tmp = tdb_nextkey(it->tdb, it->key);
			SAFE_FREE(it->key.dptr);
			it->key = tmp;

			return (data->dptr != NULL);
		}

		tmp = tdb_nextkey(it->tdb, it->key);
		SAFE_FREE(it->key.dptr);
		it->key = tmp;

		if (it->key.dptr == NULL) {
			return False;
		}
	}
}
