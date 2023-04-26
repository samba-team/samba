/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c)  Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "wspd_db.h"
#include "smbd/proto.h"
#include "lib/util/memcache.h"
#include "librpc/gen_ndr/ndr_wsp_data.h"

struct entryid_record {
	uint32_t id;
	uint32_t refcount;
};

static uint32_t find_entryid_handle_for_urn(struct memcache *cache,
		const char *urn)
{
	DATA_BLOB key = data_blob_null;
	struct entryid_record *entry_record = NULL;

	key = data_blob_string_const_null(urn);

	entry_record = memcache_lookup_talloc(cache,
					      WSP_UID_ENTRYID_TALLOC,
					      key);
	if (entry_record != NULL) {
		return entry_record->id;
	}
	return 0;
}

struct index_db_item {
	struct index_db_item *prev, *next;
	struct memcache *index_db;
	const char *index_name;
};

struct index_db_item *index_db_map = NULL;

static struct memcache *get_global_id_db(const char *index)
{
	struct index_db_item *item = NULL;

	for (item = index_db_map; item; item = item->next) {
		if (strequal(index, item->index_name)) {
			/* found index_db */
			return item->index_db;
		}
	}

	item = talloc_zero(NULL, struct index_db_item);
	if (item == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	item->index_name = talloc_strdup(item, index);
	if (item->index_name == NULL) {
		DBG_ERR("out of memory\n");
		TALLOC_FREE(item);
		return NULL;
	}

	item->index_db = memcache_init(NULL, 0);
	if (item->index_db == NULL) {
		DBG_ERR("out of memory\n");
		TALLOC_FREE(item);
		return NULL;
	}

	DLIST_ADD_END(index_db_map, item);
	return item->index_db;
}

struct urn_holder {
	const char *urn;
	struct memcache *id_db;
};

/*
 * I was assuming that once all clients servicing queries that
 * returned results with entry id(s) are gone then the entryid
 * for the entry id(s) associated with those results are no
 * longer valid. This doesn't seem to be case in windows,
 * although MS-WSP states ids can be recycled (and in windows
 * id(s) don't exist until returned by a query) In windows
 * running query that uses an EntryID already retrieved
 * will return results (regardless of whether there is any current
 * open searches)
 * We can't really match that behaviour here because it is the backend
 * (most likely opensearch/elasticsearch) that manages the primary
 * id -> document mapping. We don't monitor the index(s) and
 * there doesn't seem to be an api to 'get' notifications when
 * documents are deleted from the index.
 * So it seems reasonable to group the memory caches by 'session' id,
 * although multiple sessions are supported in a single SMB connection
 * it is unlikely that an entryid returned to a client would be shared
 * between different sessions (and we don't see this in Windows
 * using the search ribbon). By using the 'session' specific in memory
 * caches we at least should reduce the memory footprint as well as we will
 * delete the 'session' specific memory cache when all connections to
 * that 'session' are gone.
 * In a single process model when the 'session' mem cache is deleted
 * we scan the backing tdb database to remove any entries used by the
 * session cache that are no longer referenced by anyone.
 * If we move to a multi process model this will become far more complicated
 * With multi workers the same clients connections from the same 'session'
 * could exist in different workers and the EntryID records themselves
 * in the backing tdb would similarly be shared shared by other 'session'
 * clients also existing in multiple workers. In this case it might be
 * easier just continue maintain the same memcache but when the memcache
 * is deleted instead of scanning the backing tdb for the EntryIDs used
 * by that session (to delete those not used anymore), we would just do
 * nother and leave it to next start/restart to refresh and cleanout the tdb,
 */
static int destructor_urn_value(struct urn_holder *holder)
{
	DATA_BLOB urn_key = {0};
	DATA_BLOB entryid_key = {0};
	struct memcache *id_cache = holder->id_db;
	struct entryid_record *entry_record = NULL;
	int id;

	urn_key = data_blob_string_const_null(holder->urn);
	entry_record = memcache_lookup_talloc(id_cache,
			WSP_UID_ENTRYID_TALLOC,
			urn_key);
	if (entry_record == NULL) {
		return 0;
	}

	id = entry_record->id;
	entryid_key = data_blob_const(&id, sizeof(id));
	SMB_ASSERT(entry_record->refcount > 0);
	entry_record->refcount -= 1;

	DBG_DEBUG("entry_record id 0x%x (%u) refcount = %d\n",
		  entry_record->id,
		  entry_record->id,
		  entry_record->refcount);

	/* remove or modify record */
	if (entry_record->refcount == 0) {
		memcache_delete(id_cache,
				WSP_UID_ENTRYID_TALLOC, urn_key);
		memcache_delete(id_cache,
				WSP_ENTRYID_UID_TALLOC, entryid_key);
	}
        return 0;
}

static int destructor_entryid_handle(uint32_t *id)
{
	DBG_DEBUG("%p(%"PRIu32")\n", id, *id);
	return 0;
}

static bool add_urn_to_cache_value(struct memcache *id_cache,
		struct memcache *index_cache,
		const char *urn,
		uint32_t entryid)
{
	/*
	 * we assume that there has already been a call to
	 * find_entry_id_for_urn (or maybe this method should do that??)
	 */
	DATA_BLOB id_key = data_blob_null;
	DATA_BLOB urn_key = data_blob_null;
	struct urn_holder *holder = NULL;
	uint32_t *talloc_entryid = NULL;

	talloc_entryid = talloc_zero(id_cache, uint32_t);
	if (talloc_entryid == NULL) {
		return false;
	}

	*talloc_entryid = entryid;
	talloc_set_destructor(talloc_entryid, destructor_entryid_handle);
	DBG_DEBUG("created id %u with %p\n", *talloc_entryid, talloc_entryid);

	id_key = data_blob_const(&entryid, sizeof(uint32_t));
	urn_key = data_blob_string_const_null(urn);

	memcache_add_talloc(id_cache,
			WSP_UID_ENTRYID_TALLOC,
			urn_key,
			&talloc_entryid);

	holder = talloc_zero(NULL, struct urn_holder);
	if (holder == NULL) {
		TALLOC_FREE(talloc_entryid);
		return false;
	}

	holder->urn = urn;
	holder->id_db = index_cache;

	talloc_set_destructor(holder, destructor_urn_value);

	/* reverse lookup */
	memcache_add_talloc(id_cache,
			WSP_ENTRYID_UID_TALLOC,
			id_key,
			&holder);
	return true;
}

static NTSTATUS store_or_update_url_rec(struct memcache *cache,
					const char *urn,
			                uint32_t *id)
{
	DATA_BLOB key = data_blob_null;
	struct entryid_record *entry_record = NULL;
	uint32_t gen_id = 0;
	int attempts = 256;

	if (id == 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = data_blob_string_const_null(urn);

	/* allocate id */
	while (attempts-- > 0) {
		DATA_BLOB idkey = data_blob_null;
		gen_id = generate_random();

		if (gen_id > INT32_MAX) {
			gen_id -= INT32_MAX;
		}
		if (gen_id == 0) {
			gen_id++;
		}
		if (gen_id == INT32_MAX) {
			gen_id--;
		}
		idkey = data_blob_const(&gen_id, sizeof(gen_id));
		if (memcache_lookup_talloc(cache,
					    WSP_ENTRYID_UID_TALLOC,
					    idkey))
		{
			continue;
		}
		entry_record = talloc_zero(NULL, struct entryid_record);
		if (entry_record == NULL) {
			DBG_ERR("out of memory\n");
			return NT_STATUS_NO_MEMORY;
		}
		entry_record->id = gen_id;
		memcache_add_talloc(cache,
				    WSP_UID_ENTRYID_TALLOC,
				    key,
				    &entry_record);
		break;
	}
	if (attempts == 0) {
		DBG_ERR("Failed to find random id\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	*id = gen_id;
	return NT_STATUS_OK;
}

static bool find_entry_record_for_urn(struct memcache *id_cache,
			const char *urn,
			struct entryid_record **entryid)
{
	DATA_BLOB urn_key = {};
	struct entryid_record *val = NULL;

	urn_key = data_blob_string_const_null(urn);
	val = memcache_lookup_talloc(id_cache,
			WSP_UID_ENTRYID_TALLOC,
			urn_key);
	if (val == NULL) {
		return false;
	}
	*entryid = val;
	return true;
}

uint32_t get_or_create_entry_id(struct memcache *lcl_cache,
		const char *index,
		const char *urn)
{
	struct entryid_record *entry_record = NULL;
	struct memcache *index_cache = NULL;
	uint32_t id;
	NTSTATUS status;
	bool ok;

	/*
	 * use a a global id db (in the future we could split this
	 * out per share to in order to have the full MAX_INT32
	 * number of ids per share rather covering all shares
	 */
	index_cache = get_global_id_db(index);
	if (index_cache == NULL) {
		id = 0;
		goto out;
	}
	/* check local cache first */
	id = find_entryid_handle_for_urn(lcl_cache, urn);
	if (id != 0) {
		goto out;
	}

	if (!find_entry_record_for_urn(index_cache, urn, &entry_record)) {
		DATA_BLOB idkey;
		const char *talloc_urn = NULL;

		status = store_or_update_url_rec(index_cache, urn, &id);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to store of update url %s\n",
				urn);
			goto out;
		}
		if (!find_entry_record_for_urn(index_cache,
					       urn, &entry_record))
		{
			DBG_ERR("Failed to retrieve entry_record for "
				" just created entry_record by %s\n",
				urn);
			goto out;
		}
		/* store the path for id in index cache */
		idkey = data_blob_const(&id, sizeof(id));
		talloc_urn = talloc_strdup(NULL, urn);
		if (talloc_urn == NULL) {
			DBG_ERR("Out of memory\n");
			return 0;
		}
		urn = talloc_urn;
		memcache_add_talloc(index_cache,
				    WSP_ENTRYID_UID_TALLOC,
				    idkey,
				    &talloc_urn);
	} else {
		id = entry_record->id;
	}

	entry_record->refcount += 1;

	DBG_DEBUG("refcount for id %u is %u\n",
		  entry_record->id,
		  entry_record->refcount);

	/*
	 * now we need to store the forward and reverse lookups
	 * to the local cache
	 */
	ok = add_urn_to_cache_value(lcl_cache, index_cache, urn, id);
	if (!ok) {
		DBG_ERR("Failed to add urn %s:%u to cache\n",
			urn, id);
		return 0;
	}
out:
	DBG_DEBUG("returning for entryid %u (%d) for urn %s\n",
			id, id, urn);
	return id;
}


static bool lcl_find_urn_for_entryid_handle(struct memcache *id_cache,
			uint32_t entryid,
			const char **urn)
{
	DATA_BLOB id_key = data_blob_null;
	struct urn_holder *val = NULL;

	id_key = data_blob_const(&entryid, sizeof(uint32_t));

	val = memcache_lookup_talloc(id_cache,
			WSP_ENTRYID_UID_TALLOC,
			id_key);
	if (val == NULL) {
		return false;
	}

	*urn = val->urn;
	return true;
}

static bool find_urn_for_entryid_handle(struct memcache *id_cache,
			uint32_t entryid,
			const char **urn)
{
	DATA_BLOB id_key = data_blob_null;
	char *val = NULL;

	id_key = data_blob_const(&entryid, sizeof(uint32_t));

	val = memcache_lookup_talloc(id_cache,
			WSP_ENTRYID_UID_TALLOC,
			id_key);
	if (val == NULL) {
		return false;
	}
	*urn = val;
	return true;
}

const char *get_path_for_id(struct memcache *lcl_cache,
		const char *index,
		uint32_t id)
{
	struct memcache *index_cache = NULL;
	const char *urn = NULL;
	struct entryid_record *entry_record = NULL;
	DATA_BLOB key = {};

	/*
	 * use a a global id db (in the future we could split this
	 * out per share to in order to have the full MAX_INT32
	 * number of ids per share rather covering all shares
	 */
	index_cache = get_global_id_db(index);
	if (index_cache == NULL) {
		goto out;
	}

	/* try local cache first */
	lcl_find_urn_for_entryid_handle(lcl_cache, id, &urn);
	if (urn != NULL) {
		return urn;
	}

	find_urn_for_entryid_handle(index_cache, id, &urn);
	if (urn == NULL) {
		DBG_ERR("no entry for id %d\n", id);
		return NULL;
	}
	/* need to store in local cache */
	add_urn_to_cache_value(lcl_cache,
			       index_cache,
			       urn,
			       id);
	/* and increase the refcount */
	key = data_blob_string_const_null(urn);
	entry_record = memcache_lookup_talloc(index_cache,
					      WSP_UID_ENTRYID_TALLOC,
					      key);
	if (entry_record == NULL) {
		DBG_ERR("cache corruption missing value for urn	%s\n",
			urn);
		return NULL;
	}
	entry_record->refcount += 1;
out:
	return urn;

}

uint32_t generate_handle(void)
{
	static uint32_t generator = 0;

	++generator;
	return generator;
}
