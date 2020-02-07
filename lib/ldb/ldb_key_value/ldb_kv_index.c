/*
   ldb database library

   Copyright (C) Andrew Tridgell  2004-2009

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb key value backend - indexing
 *
 *  Description: indexing routines for ldb key value backend
 *
 *  Author: Andrew Tridgell
 */

/*

LDB Index design and choice of key:
=======================================

LDB has index records held as LDB objects with a special record like:

dn: @INDEX:attr:value

value may be base64 encoded, if it is deemed not printable:

dn: @INDEX:attr::base64-value

In each record, there is two possible formats:

The original format is:
-----------------------

dn: @INDEX:NAME:DNSUPDATEPROXY
@IDXVERSION: 2
@IDX: CN=DnsUpdateProxy,CN=Users,DC=addom,DC=samba,DC=example,DC=com

In this format, @IDX is multi-valued, one entry for each match

The corrosponding entry is stored in a TDB record with key:

DN=CN=DNSUPDATEPROXY,CN=USERS,DC=ADDOM,DC=SAMBA,DC=EXAMPLE,DC=COM

(This allows a scope BASE search to directly find the record via
a simple casefold of the DN).

The original mixed-case DN is stored in the entry iself.


The new 'GUID index' format is:
-------------------------------

dn: @INDEX:NAME:DNSUPDATEPROXY
@IDXVERSION: 3
@IDX: <binary GUID>[<binary GUID>[...]]

The binary guid is 16 bytes, as bytes and not expanded as hexidecimal
or pretty-printed.  The GUID is chosen from the message to be stored
by the @IDXGUID attribute on @INDEXLIST.

If there are multiple values the @IDX value simply becomes longer,
in multiples of 16.

The corrosponding entry is stored in a TDB record with key:

GUID=<binary GUID>

This allows a very quick translation between the fixed-length index
values and the TDB key, while seperating entries from other data
in the TDB, should they be unlucky enough to start with the bytes of
the 'DN=' prefix.

Additionally, this allows a scope BASE search to directly find the
record via a simple match on a GUID= extended DN, controlled via
@IDX_DN_GUID on @INDEXLIST

Exception for special @ DNs:

@BASEINFO, @INDEXLIST and all other special DNs are stored as per the
original format, as they are never referenced in an index and are used
to bootstrap the database.


Control points for choice of index mode
---------------------------------------

The choice of index and TDB key mode is made based (for example, from
Samba) on entries in the @INDEXLIST DN:

dn: @INDEXLIST
@IDXGUID: objectGUID
@IDX_DN_GUID: GUID

By default, the original DN format is used.


Control points for choosing indexed attributes
----------------------------------------------

@IDXATTR controls if an attribute is indexed

dn: @INDEXLIST
@IDXATTR: samAccountName
@IDXATTR: nETBIOSName


C Override functions
--------------------

void ldb_schema_set_override_GUID_index(struct ldb_context *ldb,
                                        const char *GUID_index_attribute,
                                        const char *GUID_index_dn_component)

This is used, particularly in combination with the below, instead of
the @IDXGUID and @IDX_DN_GUID values in @INDEXLIST.

void ldb_schema_set_override_indexlist(struct ldb_context *ldb,
                                       bool one_level_indexes);
void ldb_schema_attribute_set_override_handler(struct ldb_context *ldb,
                                               ldb_attribute_handler_override_fn_t override,
                                               void *private_data);

When the above two functions are called in combination, the @INDEXLIST
values are not read from the DB, so
ldb_schema_set_override_GUID_index() must be called.

*/

#include "ldb_kv.h"
#include "../ldb_tdb/ldb_tdb.h"
#include "ldb_private.h"
#include "lib/util/binsearch.h"
#include "lib/util/attr.h"

struct dn_list {
	unsigned int count;
	struct ldb_val *dn;
	/*
	 * Do not optimise the intersection of this list,
	 * we must never return an entry not in this
	 * list.  This allows the index for
	 * SCOPE_ONELEVEL to be trusted.
	 */
	bool strict;
};

struct ldb_kv_idxptr {
	/*
	 * In memory tdb to cache the index updates performed during a
	 * transaction.  This improves the performance of operations like
	 * re-index and join
	 */
	struct tdb_context *itdb;
	int error;
};

enum key_truncation {
	KEY_NOT_TRUNCATED,
	KEY_TRUNCATED,
};

static int ldb_kv_write_index_dn_guid(struct ldb_module *module,
				      const struct ldb_message *msg,
				      int add);
static int ldb_kv_index_dn_base_dn(struct ldb_module *module,
				   struct ldb_kv_private *ldb_kv,
				   struct ldb_dn *base_dn,
				   struct dn_list *dn_list,
				   enum key_truncation *truncation);

static void ldb_kv_dn_list_sort(struct ldb_kv_private *ldb_kv,
				struct dn_list *list);

/* we put a @IDXVERSION attribute on index entries. This
   allows us to tell if it was written by an older version
*/
#define LDB_KV_INDEXING_VERSION 2

#define LDB_KV_GUID_INDEXING_VERSION 3

static unsigned ldb_kv_max_key_length(struct ldb_kv_private *ldb_kv)
{
	if (ldb_kv->max_key_length == 0) {
		return UINT_MAX;
	}
	return ldb_kv->max_key_length;
}

/* enable the idxptr mode when transactions start */
int ldb_kv_index_transaction_start(
	struct ldb_module *module,
	size_t cache_size)
{
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	ldb_kv->idxptr = talloc_zero(ldb_kv, struct ldb_kv_idxptr);
	if (ldb_kv->idxptr == NULL) {
		return ldb_oom(ldb_module_get_ctx(module));
	}

	ldb_kv->idxptr->itdb = tdb_open(
		NULL,
		cache_size,
		TDB_INTERNAL,
		O_RDWR,
		0);
	if (ldb_kv->idxptr->itdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

/*
  see if two ldb_val structures contain exactly the same data
  return -1 or 1 for a mismatch, 0 for match
*/
static int ldb_val_equal_exact_for_qsort(const struct ldb_val *v1,
					 const struct ldb_val *v2)
{
	if (v1->length > v2->length) {
		return -1;
	}
	if (v1->length < v2->length) {
		return 1;
	}
	return memcmp(v1->data, v2->data, v1->length);
}

/*
  see if two ldb_val structures contain exactly the same data
  return -1 or 1 for a mismatch, 0 for match
*/
static int ldb_val_equal_exact_ordered(const struct ldb_val v1,
				       const struct ldb_val *v2)
{
	if (v1.length > v2->length) {
		return -1;
	}
	if (v1.length < v2->length) {
		return 1;
	}
	return memcmp(v1.data, v2->data, v1.length);
}


/*
  find a entry in a dn_list, using a ldb_val. Uses a case sensitive
  binary-safe comparison for the 'dn' returns -1 if not found

  This is therefore safe when the value is a GUID in the future
 */
static int ldb_kv_dn_list_find_val(struct ldb_kv_private *ldb_kv,
				   const struct dn_list *list,
				   const struct ldb_val *v)
{
	unsigned int i;
	struct ldb_val *exact = NULL, *next = NULL;

	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		for (i=0; i<list->count; i++) {
			if (ldb_val_equal_exact(&list->dn[i], v) == 1) {
				return i;
			}
		}
		return -1;
	}

	BINARY_ARRAY_SEARCH_GTE(list->dn, list->count,
				*v, ldb_val_equal_exact_ordered,
				exact, next);
	if (exact == NULL) {
		return -1;
	}
	/* Not required, but keeps the compiler quiet */
	if (next != NULL) {
		return -1;
	}

	i = exact - list->dn;
	return i;
}

/*
  find a entry in a dn_list. Uses a case sensitive comparison with the dn
  returns -1 if not found
 */
static int ldb_kv_dn_list_find_msg(struct ldb_kv_private *ldb_kv,
				   struct dn_list *list,
				   const struct ldb_message *msg)
{
	struct ldb_val v;
	const struct ldb_val *key_val;
	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		const char *dn_str = ldb_dn_get_linearized(msg->dn);
		v.data = discard_const_p(unsigned char, dn_str);
		v.length = strlen(dn_str);
	} else {
		key_val = ldb_msg_find_ldb_val(
		    msg, ldb_kv->cache->GUID_index_attribute);
		if (key_val == NULL) {
			return -1;
		}
		v = *key_val;
	}
	return ldb_kv_dn_list_find_val(ldb_kv, list, &v);
}

/*
  this is effectively a cast function, but with lots of paranoia
  checks and also copes with CPUs that are fussy about pointer
  alignment
 */
static struct dn_list *ldb_kv_index_idxptr(struct ldb_module *module,
					   TDB_DATA rec)
{
	struct dn_list *list;
	if (rec.dsize != sizeof(void *)) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Bad data size for idxptr %u", (unsigned)rec.dsize);
		return NULL;
	}
	/* note that we can't just use a cast here, as rec.dptr may
	   not be aligned sufficiently for a pointer. A cast would cause
	   platforms like some ARM CPUs to crash */
	memcpy(&list, rec.dptr, sizeof(void *));
	list = talloc_get_type(list, struct dn_list);
	if (list == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Bad type '%s' for idxptr",
				       talloc_get_name(list));
		return NULL;
	}
	return list;
}

enum dn_list_will_be_read_only {
	DN_LIST_MUTABLE = 0,
	DN_LIST_WILL_BE_READ_ONLY = 1,
};

/*
  return the @IDX list in an index entry for a dn as a
  struct dn_list
 */
static int ldb_kv_dn_list_load(struct ldb_module *module,
			       struct ldb_kv_private *ldb_kv,
			       struct ldb_dn *dn,
			       struct dn_list *list,
			       enum dn_list_will_be_read_only read_only)
{
	struct ldb_message *msg;
	int ret, version;
	struct ldb_message_element *el;
	TDB_DATA rec = {0};
	struct dn_list *list2;
	bool from_primary_cache = false;
	TDB_DATA key = {0};

	list->dn = NULL;
	list->count = 0;
	list->strict = false;

	/*
	 * See if we have an in memory index cache
	 */
	if (ldb_kv->idxptr == NULL) {
		goto normal_index;
	}

	key.dptr = discard_const_p(unsigned char, ldb_dn_get_linearized(dn));
	key.dsize = strlen((char *)key.dptr);

	/*
	 * Have we cached this index record?
	 * If we have a nested transaction cache try that first.
	 * then try the transaction cache.
	 * if the record is not cached it will need to be read from disk.
	 */
	if (ldb_kv->nested_idx_ptr != NULL) {
		rec = tdb_fetch(ldb_kv->nested_idx_ptr->itdb, key);
	}
	if (rec.dptr == NULL) {
		from_primary_cache = true;
		rec = tdb_fetch(ldb_kv->idxptr->itdb, key);
	}
	if (rec.dptr == NULL) {
		goto normal_index;
	}

	/* we've found an in-memory index entry */
	list2 = ldb_kv_index_idxptr(module, rec);
	if (list2 == NULL) {
		free(rec.dptr);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	free(rec.dptr);

	/*
	 * If this is a read only transaction the indexes will not be
	 * changed so we don't need a copy in the event of a rollback
	 *
	 * In this case make an early return
	 */
	if (read_only == DN_LIST_WILL_BE_READ_ONLY) {
		*list = *list2;
		return LDB_SUCCESS;
	}

	/*
	 * record was read from the sub transaction cache, so we have
	 * already copied the primary cache record
	 */
	if (!from_primary_cache) {
		*list = *list2;
		return LDB_SUCCESS;
	}

	/*
	 * No index sub transaction active, so no need to cache a copy
	 */
	if (ldb_kv->nested_idx_ptr == NULL) {
		*list = *list2;
		return LDB_SUCCESS;
	}

	/*
	 * There is an active index sub transaction, and the record was
	 * found in the primary index transaction cache.  A copy of the
	 * record needs be taken to prevent the original entry being
	 * altered, until the index sub transaction is committed.
	 */

	{
		struct ldb_val *dns = NULL;
		size_t x = 0;

		dns = talloc_array(
			list,
			struct ldb_val,
			list2->count);
		if (dns == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		for (x = 0; x < list2->count; x++) {
			dns[x].length = list2->dn[x].length;
			dns[x].data = talloc_memdup(
				dns,
				list2->dn[x].data,
				list2->dn[x].length);
			if (dns[x].data == NULL) {
				TALLOC_FREE(dns);
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		list->dn = dns;
		list->count = list2->count;
	}
	return LDB_SUCCESS;

	/*
	 * Index record not found in the caches, read it from the
	 * database.
	 */
normal_index:
	msg = ldb_msg_new(list);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_search_dn1(module,
				dn,
				msg,
				LDB_UNPACK_DATA_FLAG_NO_DN |
				/*
				 * The entry point ldb_kv_search_indexed is
				 * only called from the read-locked
				 * ldb_kv_search.
				 */
				LDB_UNPACK_DATA_FLAG_READ_LOCKED);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}

	el = ldb_msg_find_element(msg, LDB_KV_IDX);
	if (!el) {
		talloc_free(msg);
		return LDB_SUCCESS;
	}

	version = ldb_msg_find_attr_as_int(msg, LDB_KV_IDXVERSION, 0);

	/*
	 * we avoid copying the strings by stealing the list.  We have
	 * to steal msg onto el->values (which looks odd) because
	 * the memory is allocated on msg, not on each value.
	 */
	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		/* check indexing version number */
		if (version != LDB_KV_INDEXING_VERSION) {
			ldb_debug_set(ldb_module_get_ctx(module),
				      LDB_DEBUG_ERROR,
				      "Wrong DN index version %d "
				      "expected %d for %s",
				      version, LDB_KV_INDEXING_VERSION,
				      ldb_dn_get_linearized(dn));
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		talloc_steal(el->values, msg);
		list->dn = talloc_steal(list, el->values);
		list->count = el->num_values;
	} else {
		unsigned int i;
		if (version != LDB_KV_GUID_INDEXING_VERSION) {
			/* This is quite likely during the DB startup
			   on first upgrade to using a GUID index */
			ldb_debug_set(ldb_module_get_ctx(module),
				      LDB_DEBUG_ERROR,
				      "Wrong GUID index version %d "
				      "expected %d for %s",
				      version, LDB_KV_GUID_INDEXING_VERSION,
				      ldb_dn_get_linearized(dn));
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (el->num_values == 0) {
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if ((el->values[0].length % LDB_KV_GUID_SIZE) != 0) {
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		list->count = el->values[0].length / LDB_KV_GUID_SIZE;
		list->dn = talloc_array(list, struct ldb_val, list->count);
		if (list->dn == NULL) {
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/*
		 * The actual data is on msg.
		 */
		talloc_steal(list->dn, msg);
		for (i = 0; i < list->count; i++) {
			list->dn[i].data
				= &el->values[0].data[i * LDB_KV_GUID_SIZE];
			list->dn[i].length = LDB_KV_GUID_SIZE;
		}
	}

	/* We don't need msg->elements any more */
	talloc_free(msg->elements);
	return LDB_SUCCESS;
}

int ldb_kv_key_dn_from_idx(struct ldb_module *module,
			   struct ldb_kv_private *ldb_kv,
			   TALLOC_CTX *mem_ctx,
			   struct ldb_dn *dn,
			   struct ldb_val *ldb_key)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret;
	int index = 0;
	enum key_truncation truncation = KEY_NOT_TRUNCATED;
	struct dn_list *list = talloc(mem_ctx, struct dn_list);
	if (list == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_index_dn_base_dn(module, ldb_kv, dn, list, &truncation);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(list);
		return ret;
	}

	if (list->count == 0) {
		TALLOC_FREE(list);
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	if (list->count > 1 && truncation == KEY_NOT_TRUNCATED)  {
		const char *dn_str = ldb_dn_get_linearized(dn);
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       __location__
				       ": Failed to read DN index "
				       "against %s for %s: too many "
				       "values (%u > 1)",
				       ldb_kv->cache->GUID_index_attribute,
				       dn_str,
				       list->count);
		TALLOC_FREE(list);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (list->count > 0 && truncation == KEY_TRUNCATED)  {
		/*
		 * DN key has been truncated, need to inspect the actual
		 * records to locate the actual DN
		 */
		unsigned int i;
		index = -1;
		for (i=0; i < list->count; i++) {
			uint8_t guid_key[LDB_KV_GUID_KEY_SIZE];
			struct ldb_val key = {
				.data = guid_key,
				.length = sizeof(guid_key)
			};
			const int flags = LDB_UNPACK_DATA_FLAG_NO_ATTRS;
			struct ldb_message *rec = ldb_msg_new(ldb);
			if (rec == NULL) {
				TALLOC_FREE(list);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			ret = ldb_kv_idx_to_key(
			    module, ldb_kv, ldb, &list->dn[i], &key);
			if (ret != LDB_SUCCESS) {
				TALLOC_FREE(list);
				TALLOC_FREE(rec);
				return ret;
			}

			ret =
			    ldb_kv_search_key(module, ldb_kv, key, rec, flags);
			if (key.data != guid_key) {
				TALLOC_FREE(key.data);
			}
			if (ret == LDB_ERR_NO_SUCH_OBJECT) {
				/*
				 * the record has disappeared?
				 * yes, this can happen
				 */
				TALLOC_FREE(rec);
				continue;
			}

			if (ret != LDB_SUCCESS) {
				/* an internal error */
				TALLOC_FREE(rec);
				TALLOC_FREE(list);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			/*
			 * We found the actual DN that we wanted from in the
			 * multiple values that matched the index
			 * (due to truncation), so return that.
			 *
			 */
			if (ldb_dn_compare(dn, rec->dn) == 0) {
				index = i;
				TALLOC_FREE(rec);
				break;
			}
		}

		/*
		 * We matched the index but the actual DN we wanted
		 * was not here.
		 */
		if (index == -1) {
			TALLOC_FREE(list);
			return LDB_ERR_NO_SUCH_OBJECT;
		}
	}

	/* The ldb_key memory is allocated by the caller */
	ret = ldb_kv_guid_to_key(&list->dn[index], ldb_key);
	TALLOC_FREE(list);

	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}



/*
  save a dn_list into a full @IDX style record
 */
static int ldb_kv_dn_list_store_full(struct ldb_module *module,
				     struct ldb_kv_private *ldb_kv,
				     struct ldb_dn *dn,
				     struct dn_list *list)
{
	struct ldb_message *msg;
	int ret;

	msg = ldb_msg_new(module);
	if (!msg) {
		return ldb_module_oom(module);
	}

	msg->dn = dn;

	if (list->count == 0) {
		ret = ldb_kv_delete_noindex(module, msg);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			ret = LDB_SUCCESS;
		}
		TALLOC_FREE(msg);
		return ret;
	}

	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		ret = ldb_msg_add_fmt(msg, LDB_KV_IDXVERSION, "%u",
				      LDB_KV_INDEXING_VERSION);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(msg);
			return ldb_module_oom(module);
		}
	} else {
		ret = ldb_msg_add_fmt(msg, LDB_KV_IDXVERSION, "%u",
				      LDB_KV_GUID_INDEXING_VERSION);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(msg);
			return ldb_module_oom(module);
		}
	}

	if (list->count > 0) {
		struct ldb_message_element *el;

		ret = ldb_msg_add_empty(msg, LDB_KV_IDX, LDB_FLAG_MOD_ADD, &el);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(msg);
			return ldb_module_oom(module);
		}

		if (ldb_kv->cache->GUID_index_attribute == NULL) {
			el->values = list->dn;
			el->num_values = list->count;
		} else {
			struct ldb_val v;
			unsigned int i;
			el->values = talloc_array(msg,
						  struct ldb_val, 1);
			if (el->values == NULL) {
				TALLOC_FREE(msg);
				return ldb_module_oom(module);
			}

			v.data = talloc_array_size(el->values,
						   list->count,
						   LDB_KV_GUID_SIZE);
			if (v.data == NULL) {
				TALLOC_FREE(msg);
				return ldb_module_oom(module);
			}

			v.length = talloc_get_size(v.data);

			for (i = 0; i < list->count; i++) {
				if (list->dn[i].length !=
				    LDB_KV_GUID_SIZE) {
					TALLOC_FREE(msg);
					return ldb_module_operr(module);
				}
				memcpy(&v.data[LDB_KV_GUID_SIZE*i],
				       list->dn[i].data,
				       LDB_KV_GUID_SIZE);
			}
			el->values[0] = v;
			el->num_values = 1;
		}
	}

	ret = ldb_kv_store(module, msg, TDB_REPLACE);
	TALLOC_FREE(msg);
	return ret;
}

/*
  save a dn_list into the database, in either @IDX or internal format
 */
static int ldb_kv_dn_list_store(struct ldb_module *module,
				struct ldb_dn *dn,
				struct dn_list *list)
{
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	TDB_DATA rec = {0};
	TDB_DATA key = {0};

	int ret = LDB_SUCCESS;
	struct dn_list *list2 = NULL;
	struct ldb_kv_idxptr *idxptr = NULL;

	key.dptr = discard_const_p(unsigned char, ldb_dn_get_linearized(dn));
	if (key.dptr == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	key.dsize = strlen((char *)key.dptr);

	/*
	 * If there is an index sub transaction active, update the
	 * sub transaction index cache.  Otherwise update the
	 * primary index cache
	 */
	if (ldb_kv->nested_idx_ptr != NULL) {
		idxptr = ldb_kv->nested_idx_ptr;
	} else {
		idxptr = ldb_kv->idxptr;
	}
	/*
	 * Get the cache entry for the index
	 *
	 * As the value in the cache is a pointer to a dn_list we update
	 * the dn_list directly.
	 *
	 */
	rec = tdb_fetch(idxptr->itdb, key);
	if (rec.dptr != NULL) {
		list2 = ldb_kv_index_idxptr(module, rec);
		if (list2 == NULL) {
			free(rec.dptr);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		free(rec.dptr);
		/* Now put the updated pointer back in the cache */
		if (list->dn == NULL) {
			list2->dn = NULL;
			list2->count = 0;
		} else {
			list2->dn = talloc_steal(list2, list->dn);
			list2->count = list->count;
		}
		return LDB_SUCCESS;
	}

	list2 = talloc(idxptr, struct dn_list);
	if (list2 == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	list2->dn = talloc_steal(list2, list->dn);
	list2->count = list->count;

	rec.dptr = (uint8_t *)&list2;
	rec.dsize = sizeof(void *);


	/*
	 * This is not a store into the main DB, but into an in-memory
	 * TDB, so we don't need a guard on ltdb->read_only
	 *
	 * Also as we directly update the in memory dn_list for existing
	 * cache entries we must be adding a new entry to the cache.
	 */
	ret = tdb_store(idxptr->itdb, key, rec, TDB_INSERT);
	if (ret != 0) {
		return ltdb_err_map( tdb_error(idxptr->itdb));
	}
	return LDB_SUCCESS;
}

/*
  traverse function for storing the in-memory index entries on disk
 */
static int ldb_kv_index_traverse_store(_UNUSED_ struct tdb_context *tdb,
				       TDB_DATA key,
				       TDB_DATA data,
				       void *state)
{
	struct ldb_module *module = state;
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	struct ldb_dn *dn;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_val v;
	struct dn_list *list;

	list = ldb_kv_index_idxptr(module, data);
	if (list == NULL) {
		ldb_kv->idxptr->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	v.data = key.dptr;
	v.length = strnlen((char *)key.dptr, key.dsize);

	dn = ldb_dn_from_ldb_val(module, ldb, &v);
	if (dn == NULL) {
		ldb_asprintf_errstring(ldb, "Failed to parse index key %*.*s as an LDB DN", (int)v.length, (int)v.length, (const char *)v.data);
		ldb_kv->idxptr->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	ldb_kv->idxptr->error =
	    ldb_kv_dn_list_store_full(module, ldb_kv, dn, list);
	talloc_free(dn);
	if (ldb_kv->idxptr->error != 0) {
		return -1;
	}
	return 0;
}

/* cleanup the idxptr mode when transaction commits */
int ldb_kv_index_transaction_commit(struct ldb_module *module)
{
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	int ret;

	struct ldb_context *ldb = ldb_module_get_ctx(module);

	ldb_reset_err_string(ldb);

	if (ldb_kv->idxptr->itdb) {
		tdb_traverse(
		    ldb_kv->idxptr->itdb, ldb_kv_index_traverse_store, module);
		tdb_close(ldb_kv->idxptr->itdb);
	}

	ret = ldb_kv->idxptr->error;
	if (ret != LDB_SUCCESS) {
		if (!ldb_errstring(ldb)) {
			ldb_set_errstring(ldb, ldb_strerror(ret));
		}
		ldb_asprintf_errstring(ldb, "Failed to store index records in transaction commit: %s", ldb_errstring(ldb));
	}

	talloc_free(ldb_kv->idxptr);
	ldb_kv->idxptr = NULL;
	return ret;
}

/* cleanup the idxptr mode when transaction cancels */
int ldb_kv_index_transaction_cancel(struct ldb_module *module)
{
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	if (ldb_kv->idxptr && ldb_kv->idxptr->itdb) {
		tdb_close(ldb_kv->idxptr->itdb);
	}
	TALLOC_FREE(ldb_kv->idxptr);
	if (ldb_kv->nested_idx_ptr && ldb_kv->nested_idx_ptr->itdb) {
		tdb_close(ldb_kv->nested_idx_ptr->itdb);
	}
	TALLOC_FREE(ldb_kv->nested_idx_ptr);
	return LDB_SUCCESS;
}


/*
  return the dn key to be used for an index
  the caller is responsible for freeing
*/
static struct ldb_dn *ldb_kv_index_key(struct ldb_context *ldb,
				       struct ldb_kv_private *ldb_kv,
				       const char *attr,
				       const struct ldb_val *value,
				       const struct ldb_schema_attribute **ap,
				       enum key_truncation *truncation)
{
	struct ldb_dn *ret;
	struct ldb_val v;
	const struct ldb_schema_attribute *a = NULL;
	char *attr_folded = NULL;
	const char *attr_for_dn = NULL;
	int r;
	bool should_b64_encode;

	unsigned int max_key_length = ldb_kv_max_key_length(ldb_kv);
	size_t key_len = 0;
	size_t attr_len = 0;
	const size_t indx_len = sizeof(LDB_KV_INDEX) - 1;
	unsigned frmt_len = 0;
	const size_t additional_key_length = 4;
	unsigned int num_separators = 3; /* Estimate for overflow check */
	const size_t min_data = 1;
	const size_t min_key_length = additional_key_length
		+ indx_len + num_separators + min_data;
	struct ldb_val empty;

	/*
	 * Accept a NULL value as a request for a key with no value.  This is
	 * different from passing an empty value, which might be given
	 * significance by some canonicalise functions.
	 */
	bool empty_val = value == NULL;
	if (empty_val) {
		empty.length = 0;
		empty.data = discard_const_p(unsigned char, "");
		value = &empty;
	}

	if (attr[0] == '@') {
		attr_for_dn = attr;
		v = *value;
		if (ap != NULL) {
			*ap = NULL;
		}
	} else {
		attr_folded = ldb_attr_casefold(ldb, attr);
		if (!attr_folded) {
			return NULL;
		}

		attr_for_dn = attr_folded;

		a = ldb_schema_attribute_by_name(ldb, attr);
		if (ap) {
			*ap = a;
		}

		if (empty_val) {
			v = *value;
		} else {
			ldb_attr_handler_t fn;
			if (a->syntax->index_format_fn &&
			    ldb_kv->cache->GUID_index_attribute != NULL) {
				fn = a->syntax->index_format_fn;
			} else {
				fn = a->syntax->canonicalise_fn;
			}
			r = fn(ldb, ldb, value, &v);
			if (r != LDB_SUCCESS) {
				const char *errstr = ldb_errstring(ldb);
				/* canonicalisation can be refused. For
				   example, a attribute that takes wildcards
				   will refuse to canonicalise if the value
				   contains a wildcard */
				ldb_asprintf_errstring(ldb,
						       "Failed to create "
						       "index key for "
						       "attribute '%s':%s%s%s",
						       attr, ldb_strerror(r),
						       (errstr?":":""),
						       (errstr?errstr:""));
				talloc_free(attr_folded);
				return NULL;
			}
		}
	}
	attr_len = strlen(attr_for_dn);

	/*
	 * Check if there is any hope this will fit into the DB.
	 * Overflow here is not actually critical the code below
	 * checks again to make the printf and the DB does another
	 * check for too long keys
	 */
	if (max_key_length - attr_len < min_key_length) {
		ldb_asprintf_errstring(
			ldb,
			__location__ ": max_key_length "
			"is too small (%u) < (%u)",
			max_key_length,
			(unsigned)(min_key_length + attr_len));
		talloc_free(attr_folded);
		return NULL;
	}

	/*
	 * ltdb_key_dn() makes something 4 bytes longer, it adds a leading
	 * "DN=" and a trailing string terminator
	 */
	max_key_length -= additional_key_length;

	/*
	 * We do not base 64 encode a DN in a key, it has already been
	 * casefold and lineraized, that is good enough.  That already
	 * avoids embedded NUL etc.
	 */
	if (ldb_kv->cache->GUID_index_attribute != NULL) {
		if (strcmp(attr, LDB_KV_IDXDN) == 0) {
			should_b64_encode = false;
		} else if (strcmp(attr, LDB_KV_IDXONE) == 0) {
			/*
			 * We can only change the behaviour for IDXONE
			 * when the GUID index is enabled
			 */
			should_b64_encode = false;
		} else {
			should_b64_encode
				= ldb_should_b64_encode(ldb, &v);
		}
	} else {
		should_b64_encode = ldb_should_b64_encode(ldb, &v);
	}

	if (should_b64_encode) {
		size_t vstr_len = 0;
		char *vstr = ldb_base64_encode(ldb, (char *)v.data, v.length);
		if (!vstr) {
			talloc_free(attr_folded);
			return NULL;
		}
		vstr_len = strlen(vstr);
		/*
		 * Overflow here is not critical as we only use this
		 * to choose the printf truncation
		 */
		key_len = num_separators + indx_len + attr_len + vstr_len;
		if (key_len > max_key_length) {
			size_t excess = key_len - max_key_length;
			frmt_len = vstr_len - excess;
			*truncation = KEY_TRUNCATED;
			/*
			* Truncated keys are placed in a separate key space
			* from the non truncated keys
			* Note: the double hash "##" is not a typo and
			* indicates that the following value is base64 encoded
			*/
			ret = ldb_dn_new_fmt(ldb, ldb, "%s#%s##%.*s",
					     LDB_KV_INDEX, attr_for_dn,
					     frmt_len, vstr);
		} else {
			frmt_len = vstr_len;
			*truncation = KEY_NOT_TRUNCATED;
			/*
			 * Note: the double colon "::" is not a typo and
			 * indicates that the following value is base64 encoded
			 */
			ret = ldb_dn_new_fmt(ldb, ldb, "%s:%s::%.*s",
					     LDB_KV_INDEX, attr_for_dn,
					     frmt_len, vstr);
		}
		talloc_free(vstr);
	} else {
		/* Only need two seperators */
		num_separators = 2;

		/*
		 * Overflow here is not critical as we only use this
		 * to choose the printf truncation
		 */
		key_len = num_separators + indx_len + attr_len + (int)v.length;
		if (key_len > max_key_length) {
			size_t excess = key_len - max_key_length;
			frmt_len = v.length - excess;
			*truncation = KEY_TRUNCATED;
			/*
			 * Truncated keys are placed in a separate key space
			 * from the non truncated keys
			 */
			ret = ldb_dn_new_fmt(ldb, ldb, "%s#%s#%.*s",
					     LDB_KV_INDEX, attr_for_dn,
					     frmt_len, (char *)v.data);
		} else {
			frmt_len = v.length;
			*truncation = KEY_NOT_TRUNCATED;
			ret = ldb_dn_new_fmt(ldb, ldb, "%s:%s:%.*s",
					     LDB_KV_INDEX, attr_for_dn,
					     frmt_len, (char *)v.data);
		}
	}

	if (value != NULL && v.data != value->data && !empty_val) {
		talloc_free(v.data);
	}
	talloc_free(attr_folded);

	return ret;
}

/*
  see if a attribute value is in the list of indexed attributes
*/
static bool ldb_kv_is_indexed(struct ldb_module *module,
			      struct ldb_kv_private *ldb_kv,
			      const char *attr)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	unsigned int i;
	struct ldb_message_element *el;

	if ((ldb_kv->cache->GUID_index_attribute != NULL) &&
	    (ldb_attr_cmp(attr, ldb_kv->cache->GUID_index_attribute) == 0)) {
		/* Implicity covered, this is the index key */
		return false;
	}
	if (ldb->schema.index_handler_override) {
		const struct ldb_schema_attribute *a
			= ldb_schema_attribute_by_name(ldb, attr);

		if (a == NULL) {
			return false;
		}

		if (a->flags & LDB_ATTR_FLAG_INDEXED) {
			return true;
		} else {
			return false;
		}
	}

	if (!ldb_kv->cache->attribute_indexes) {
		return false;
	}

	el = ldb_msg_find_element(ldb_kv->cache->indexlist, LDB_KV_IDXATTR);
	if (el == NULL) {
		return false;
	}

	/* TODO: this is too expensive! At least use a binary search */
	for (i=0; i<el->num_values; i++) {
		if (ldb_attr_cmp((char *)el->values[i].data, attr) == 0) {
			return true;
		}
	}
	return false;
}

/*
  in the following logic functions, the return value is treated as
  follows:

     LDB_SUCCESS: we found some matching index values

     LDB_ERR_NO_SUCH_OBJECT: we know for sure that no object matches

     LDB_ERR_OPERATIONS_ERROR: indexing could not answer the call,
                               we'll need a full search
 */

/*
  return a list of dn's that might match a simple indexed search (an
  equality search only)
 */
static int ldb_kv_index_dn_simple(struct ldb_module *module,
				  struct ldb_kv_private *ldb_kv,
				  const struct ldb_parse_tree *tree,
				  struct dn_list *list)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn;
	int ret;
	enum key_truncation truncation = KEY_NOT_TRUNCATED;

	ldb = ldb_module_get_ctx(module);

	list->count = 0;
	list->dn = NULL;

	/* if the attribute isn't in the list of indexed attributes then
	   this node needs a full search */
	if (!ldb_kv_is_indexed(module, ldb_kv, tree->u.equality.attr)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* the attribute is indexed. Pull the list of DNs that match the
	   search criterion */
	dn = ldb_kv_index_key(ldb,
			      ldb_kv,
			      tree->u.equality.attr,
			      &tree->u.equality.value,
			      NULL,
			      &truncation);
	/*
	 * We ignore truncation here and allow multi-valued matches
	 * as ltdb_search_indexed will filter out the wrong one in
	 * ltdb_index_filter() which calls ldb_match_message().
	 */
	if (!dn) return LDB_ERR_OPERATIONS_ERROR;

	ret = ldb_kv_dn_list_load(module, ldb_kv, dn, list,
				  DN_LIST_WILL_BE_READ_ONLY);
	talloc_free(dn);
	return ret;
}

static bool list_union(struct ldb_context *ldb,
		       struct ldb_kv_private *ldb_kv,
		       struct dn_list *list,
		       struct dn_list *list2);

/*
  return a list of dn's that might match a leaf indexed search
 */
static int ldb_kv_index_dn_leaf(struct ldb_module *module,
				struct ldb_kv_private *ldb_kv,
				const struct ldb_parse_tree *tree,
				struct dn_list *list)
{
	if (ldb_kv->disallow_dn_filter &&
	    (ldb_attr_cmp(tree->u.equality.attr, "dn") == 0)) {
		/* in AD mode we do not support "(dn=...)" search filters */
		list->dn = NULL;
		list->count = 0;
		return LDB_SUCCESS;
	}
	if (tree->u.equality.attr[0] == '@') {
		/* Do not allow a indexed search against an @ */
		list->dn = NULL;
		list->count = 0;
		return LDB_SUCCESS;
	}
	if (ldb_attr_dn(tree->u.equality.attr) == 0) {
		enum key_truncation truncation = KEY_NOT_TRUNCATED;
		bool valid_dn = false;
		struct ldb_dn *dn
			= ldb_dn_from_ldb_val(list,
					      ldb_module_get_ctx(module),
					      &tree->u.equality.value);
		if (dn == NULL) {
			/* If we can't parse it, no match */
			list->dn = NULL;
			list->count = 0;
			return LDB_SUCCESS;
		}

		valid_dn = ldb_dn_validate(dn);
		if (valid_dn == false) {
			/* If we can't parse it, no match */
			list->dn = NULL;
			list->count = 0;
			return LDB_SUCCESS;
		}

		/*
		 * Re-use the same code we use for a SCOPE_BASE
		 * search
		 *
		 * We can't call TALLOC_FREE(dn) as this must belong
		 * to list for the memory to remain valid.
		 */
		return ldb_kv_index_dn_base_dn(
		    module, ldb_kv, dn, list, &truncation);
		/*
		 * We ignore truncation here and allow multi-valued matches
		 * as ltdb_search_indexed will filter out the wrong one in
		 * ltdb_index_filter() which calls ldb_match_message().
		 */

	} else if ((ldb_kv->cache->GUID_index_attribute != NULL) &&
		   (ldb_attr_cmp(tree->u.equality.attr,
				 ldb_kv->cache->GUID_index_attribute) == 0)) {
		int ret;
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		list->dn = talloc_array(list, struct ldb_val, 1);
		if (list->dn == NULL) {
			ldb_module_oom(module);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		/*
		 * We need to go via the canonicalise_fn() to
		 * ensure we get the index in binary, rather
		 * than a string
		 */
		ret = ldb_kv->GUID_index_syntax->canonicalise_fn(
		    ldb, list->dn, &tree->u.equality.value, &list->dn[0]);
		if (ret != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		list->count = 1;
		return LDB_SUCCESS;
	}

	return ldb_kv_index_dn_simple(module, ldb_kv, tree, list);
}


/*
  list intersection
  list = list & list2
*/
static bool list_intersect(struct ldb_kv_private *ldb_kv,
			   struct dn_list *list,
			   const struct dn_list *list2)
{
	const struct dn_list *short_list, *long_list;
	struct dn_list *list3;
	unsigned int i;

	if (list->count == 0) {
		/* 0 & X == 0 */
		return true;
	}
	if (list2->count == 0) {
		/* X & 0 == 0 */
		list->count = 0;
		list->dn = NULL;
		return true;
	}

	/*
	 * In both of the below we check for strict and in that
	 * case do not optimise the intersection of this list,
	 * we must never return an entry not in this
	 * list.  This allows the index for
	 * SCOPE_ONELEVEL to be trusted.
	 */

	/* the indexing code is allowed to return a longer list than
	   what really matches, as all results are filtered by the
	   full expression at the end - this shortcut avoids a lot of
	   work in some cases */
	if (list->count < 2 && list2->count > 10 && list2->strict == false) {
		return true;
	}
	if (list2->count < 2 && list->count > 10 && list->strict == false) {
		list->count = list2->count;
		list->dn = list2->dn;
		/* note that list2 may not be the parent of list2->dn,
		   as list2->dn may be owned by ltdb->idxptr. In that
		   case we expect this reparent call to fail, which is
		   OK */
		talloc_reparent(list2, list, list2->dn);
		return true;
	}

	if (list->count > list2->count) {
		short_list = list2;
		long_list = list;
	} else {
		short_list = list;
		long_list = list2;
	}

	list3 = talloc_zero(list, struct dn_list);
	if (list3 == NULL) {
		return false;
	}

	list3->dn = talloc_array(list3, struct ldb_val,
				 MIN(list->count, list2->count));
	if (!list3->dn) {
		talloc_free(list3);
		return false;
	}
	list3->count = 0;

	for (i=0;i<short_list->count;i++) {
		/* For the GUID index case, this is a binary search */
		if (ldb_kv_dn_list_find_val(
			ldb_kv, long_list, &short_list->dn[i]) != -1) {
			list3->dn[list3->count] = short_list->dn[i];
			list3->count++;
		}
	}

	list->strict |= list2->strict;
	list->dn = talloc_steal(list, list3->dn);
	list->count = list3->count;
	talloc_free(list3);

	return true;
}


/*
  list union
  list = list | list2
*/
static bool list_union(struct ldb_context *ldb,
		       struct ldb_kv_private *ldb_kv,
		       struct dn_list *list,
		       struct dn_list *list2)
{
	struct ldb_val *dn3;
	unsigned int i = 0, j = 0, k = 0;

	if (list2->count == 0) {
		/* X | 0 == X */
		return true;
	}

	if (list->count == 0) {
		/* 0 | X == X */
		list->count = list2->count;
		list->dn = list2->dn;
		/* note that list2 may not be the parent of list2->dn,
		   as list2->dn may be owned by ltdb->idxptr. In that
		   case we expect this reparent call to fail, which is
		   OK */
		talloc_reparent(list2, list, list2->dn);
		return true;
	}

	/*
	 * Sort the lists (if not in GUID DN mode) so we can do
	 * the de-duplication during the merge
	 *
	 * NOTE: This can sort the in-memory index values, as list or
	 * list2 might not be a copy!
	 */
	ldb_kv_dn_list_sort(ldb_kv, list);
	ldb_kv_dn_list_sort(ldb_kv, list2);

	dn3 = talloc_array(list, struct ldb_val, list->count + list2->count);
	if (!dn3) {
		ldb_oom(ldb);
		return false;
	}

	while (i < list->count || j < list2->count) {
		int cmp;
		if (i >= list->count) {
			cmp = 1;
		} else if (j >= list2->count) {
			cmp = -1;
		} else {
			cmp = ldb_val_equal_exact_ordered(list->dn[i],
							  &list2->dn[j]);
		}

		if (cmp < 0) {
			/* Take list */
			dn3[k] = list->dn[i];
			i++;
			k++;
		} else if (cmp > 0) {
			/* Take list2 */
			dn3[k] = list2->dn[j];
			j++;
			k++;
		} else {
			/* Equal, take list */
			dn3[k] = list->dn[i];
			i++;
			j++;
			k++;
		}
	}

	list->dn = dn3;
	list->count = k;

	return true;
}

static int ldb_kv_index_dn(struct ldb_module *module,
			   struct ldb_kv_private *ldb_kv,
			   const struct ldb_parse_tree *tree,
			   struct dn_list *list);

/*
  process an OR list (a union)
 */
static int ldb_kv_index_dn_or(struct ldb_module *module,
			      struct ldb_kv_private *ldb_kv,
			      const struct ldb_parse_tree *tree,
			      struct dn_list *list)
{
	struct ldb_context *ldb;
	unsigned int i;

	ldb = ldb_module_get_ctx(module);

	list->dn = NULL;
	list->count = 0;

	for (i=0; i<tree->u.list.num_elements; i++) {
		struct dn_list *list2;
		int ret;

		list2 = talloc_zero(list, struct dn_list);
		if (list2 == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = ldb_kv_index_dn(
		    module, ldb_kv, tree->u.list.elements[i], list2);

		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			/* X || 0 == X */
			talloc_free(list2);
			continue;
		}

		if (ret != LDB_SUCCESS) {
			/* X || * == * */
			talloc_free(list2);
			return ret;
		}

		if (!list_union(ldb, ldb_kv, list, list2)) {
			talloc_free(list2);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	if (list->count == 0) {
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	return LDB_SUCCESS;
}


/*
  NOT an index results
 */
static int ldb_kv_index_dn_not(_UNUSED_ struct ldb_module *module,
			       _UNUSED_ struct ldb_kv_private *ldb_kv,
			       _UNUSED_ const struct ldb_parse_tree *tree,
			       _UNUSED_ struct dn_list *list)
{
	/* the only way to do an indexed not would be if we could
	   negate the not via another not or if we knew the total
	   number of database elements so we could know that the
	   existing expression covered the whole database.

	   instead, we just give up, and rely on a full index scan
	   (unless an outer & manages to reduce the list)
	*/
	return LDB_ERR_OPERATIONS_ERROR;
}

/*
 * These things are unique, so avoid a full scan if this is a search
 * by GUID, DN or a unique attribute
 */
static bool ldb_kv_index_unique(struct ldb_context *ldb,
				struct ldb_kv_private *ldb_kv,
				const char *attr)
{
	const struct ldb_schema_attribute *a;
	if (ldb_kv->cache->GUID_index_attribute != NULL) {
		if (ldb_attr_cmp(attr, ldb_kv->cache->GUID_index_attribute) ==
		    0) {
			return true;
		}
	}
	if (ldb_attr_dn(attr) == 0) {
		return true;
	}

	a = ldb_schema_attribute_by_name(ldb, attr);
	if (a->flags & LDB_ATTR_FLAG_UNIQUE_INDEX) {
		return true;
	}
	return false;
}

/*
  process an AND expression (intersection)
 */
static int ldb_kv_index_dn_and(struct ldb_module *module,
			       struct ldb_kv_private *ldb_kv,
			       const struct ldb_parse_tree *tree,
			       struct dn_list *list)
{
	struct ldb_context *ldb;
	unsigned int i;
	bool found;

	ldb = ldb_module_get_ctx(module);

	list->dn = NULL;
	list->count = 0;

	/* in the first pass we only look for unique simple
	   equality tests, in the hope of avoiding having to look
	   at any others */
	for (i=0; i<tree->u.list.num_elements; i++) {
		const struct ldb_parse_tree *subtree = tree->u.list.elements[i];
		int ret;

		if (subtree->operation != LDB_OP_EQUALITY ||
		    !ldb_kv_index_unique(
			ldb, ldb_kv, subtree->u.equality.attr)) {
			continue;
		}

		ret = ldb_kv_index_dn(module, ldb_kv, subtree, list);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			/* 0 && X == 0 */
			return LDB_ERR_NO_SUCH_OBJECT;
		}
		if (ret == LDB_SUCCESS) {
			/* a unique index match means we can
			 * stop. Note that we don't care if we return
			 * a few too many objects, due to later
			 * filtering */
			return LDB_SUCCESS;
		}
	}

	/* now do a full intersection */
	found = false;

	for (i=0; i<tree->u.list.num_elements; i++) {
		const struct ldb_parse_tree *subtree = tree->u.list.elements[i];
		struct dn_list *list2;
		int ret;

		list2 = talloc_zero(list, struct dn_list);
		if (list2 == NULL) {
			return ldb_module_oom(module);
		}

		ret = ldb_kv_index_dn(module, ldb_kv, subtree, list2);

		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			/* X && 0 == 0 */
			list->dn = NULL;
			list->count = 0;
			talloc_free(list2);
			return LDB_ERR_NO_SUCH_OBJECT;
		}

		if (ret != LDB_SUCCESS) {
			/* this didn't adding anything */
			talloc_free(list2);
			continue;
		}

		if (!found) {
			talloc_reparent(list2, list, list->dn);
			list->dn = list2->dn;
			list->count = list2->count;
			found = true;
		} else if (!list_intersect(ldb_kv, list, list2)) {
			talloc_free(list2);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (list->count == 0) {
			list->dn = NULL;
			return LDB_ERR_NO_SUCH_OBJECT;
		}

		if (list->count < 2) {
			/* it isn't worth loading the next part of the tree */
			return LDB_SUCCESS;
		}
	}

	if (!found) {
		/* none of the attributes were indexed */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

struct ldb_kv_ordered_index_context {
	struct ldb_module *module;
	int error;
	struct dn_list *dn_list;
};

static int traverse_range_index(_UNUSED_ struct ldb_kv_private *ldb_kv,
				_UNUSED_ struct ldb_val key,
				struct ldb_val data,
				void *state)
{

	struct ldb_context *ldb;
	struct ldb_kv_ordered_index_context *ctx =
	    (struct ldb_kv_ordered_index_context *)state;
	struct ldb_module *module = ctx->module;
	struct ldb_message_element *el = NULL;
	struct ldb_message *msg = NULL;
	int version;
	size_t dn_array_size, additional_length;
	unsigned int i;

	ldb = ldb_module_get_ctx(module);

	msg = ldb_msg_new(module);

	ctx->error = ldb_unpack_data_flags(ldb, &data, msg,
					   LDB_UNPACK_DATA_FLAG_NO_DN);

	if (ctx->error != LDB_SUCCESS) {
		talloc_free(msg);
		return ctx->error;
	}

	el = ldb_msg_find_element(msg, LDB_KV_IDX);
	if (!el) {
		talloc_free(msg);
		return LDB_SUCCESS;
	}

	version = ldb_msg_find_attr_as_int(msg, LDB_KV_IDXVERSION, 0);

	/*
	 * we avoid copying the strings by stealing the list.  We have
	 * to steal msg onto el->values (which looks odd) because
	 * the memory is allocated on msg, not on each value.
	 */
	if (version != LDB_KV_GUID_INDEXING_VERSION) {
		/* This is quite likely during the DB startup
		   on first upgrade to using a GUID index */
		ldb_debug_set(ldb_module_get_ctx(module),
			      LDB_DEBUG_ERROR, __location__
			      ": Wrong GUID index version %d expected %d",
			      version, LDB_KV_GUID_INDEXING_VERSION);
		talloc_free(msg);
		ctx->error = LDB_ERR_OPERATIONS_ERROR;
		return ctx->error;
	}

	if (el->num_values == 0) {
		talloc_free(msg);
		ctx->error = LDB_ERR_OPERATIONS_ERROR;
		return ctx->error;
	}

	if ((el->values[0].length % LDB_KV_GUID_SIZE) != 0
	    || el->values[0].length == 0) {
		talloc_free(msg);
		ctx->error = LDB_ERR_OPERATIONS_ERROR;
		return ctx->error;
	}

	dn_array_size = talloc_array_length(ctx->dn_list->dn);

	additional_length = el->values[0].length / LDB_KV_GUID_SIZE;

	if (ctx->dn_list->count + additional_length < ctx->dn_list->count) {
		talloc_free(msg);
		ctx->error = LDB_ERR_OPERATIONS_ERROR;
		return ctx->error;
	}

	if ((ctx->dn_list->count + additional_length) >= dn_array_size) {
		size_t new_array_length;

		if (dn_array_size * 2 < dn_array_size) {
			talloc_free(msg);
			ctx->error = LDB_ERR_OPERATIONS_ERROR;
			return ctx->error;
		}

		new_array_length = MAX(ctx->dn_list->count + additional_length,
				       dn_array_size * 2);

		ctx->dn_list->dn = talloc_realloc(ctx->dn_list,
						  ctx->dn_list->dn,
						  struct ldb_val,
						  new_array_length);
	}

	if (ctx->dn_list->dn == NULL) {
		talloc_free(msg);
		ctx->error = LDB_ERR_OPERATIONS_ERROR;
		return ctx->error;
	}

	/*
	 * The actual data is on msg.
	 */
	talloc_steal(ctx->dn_list->dn, msg);
	for (i = 0; i < additional_length; i++) {
		ctx->dn_list->dn[i + ctx->dn_list->count].data
			= &el->values[0].data[i * LDB_KV_GUID_SIZE];
		ctx->dn_list->dn[i + ctx->dn_list->count].length = LDB_KV_GUID_SIZE;

	}

	ctx->dn_list->count += additional_length;

	talloc_free(msg->elements);

	return LDB_SUCCESS;
}

/*
 * >= and <= indexing implemented using lexicographically sorted keys
 *
 * We only run this in GUID indexing mode and when there is no write
 * transaction (only implicit read locks are being held). Otherwise, we would
 * have to deal with the in-memory index cache.
 *
 * We rely on the implementation of index_format_fn on a schema syntax which
 * will can help us to construct keys which can be ordered correctly, and we
 * terminate using schema agnostic start and end keys.
 *
 * index_format_fn must output values which can be memcmp-able to produce the
 * correct ordering as defined by the schema syntax class.
 */
static int ldb_kv_index_dn_ordered(struct ldb_module *module,
				   struct ldb_kv_private *ldb_kv,
				   const struct ldb_parse_tree *tree,
				   struct dn_list *list, bool ascending)
{
	enum key_truncation truncation = KEY_NOT_TRUNCATED;
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	struct ldb_val ldb_key = { 0 }, ldb_key2 = { 0 };
	struct ldb_val start_key, end_key;
	struct ldb_dn *key_dn = NULL;
	const struct ldb_schema_attribute *a = NULL;

	struct ldb_kv_ordered_index_context ctx;
	int ret;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	if (!ldb_kv_is_indexed(module, ldb_kv, tree->u.comparison.attr)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* bail out if we're in a transaction, full search instead. */
	if (ldb_kv->kv_ops->transaction_active(ldb_kv)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ldb_kv->disallow_dn_filter &&
	    (ldb_attr_cmp(tree->u.comparison.attr, "dn") == 0)) {
		/* in AD mode we do not support "(dn=...)" search filters */
		list->dn = NULL;
		list->count = 0;
		return LDB_SUCCESS;
	}
	if (tree->u.comparison.attr[0] == '@') {
		/* Do not allow a indexed search against an @ */
		list->dn = NULL;
		list->count = 0;
		return LDB_SUCCESS;
	}

	a = ldb_schema_attribute_by_name(ldb, tree->u.comparison.attr);

	/*
	 * If there's no index format function defined for this attr, then
	 * the lexicographic order in the database doesn't correspond to the
	 * attr's ordering, so we can't use the iterate_range op.
	 */
	if (a->syntax->index_format_fn == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	key_dn = ldb_kv_index_key(ldb, ldb_kv, tree->u.comparison.attr,
				  &tree->u.comparison.value,
				  NULL, &truncation);
	if (!key_dn) {
		return LDB_ERR_OPERATIONS_ERROR;
	} else if (truncation == KEY_TRUNCATED) {
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  __location__
			  ": ordered index violation: key dn truncated: %s\n",
			  ldb_dn_get_linearized(key_dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ldb_key = ldb_kv_key_dn(tmp_ctx, key_dn);
	talloc_free(key_dn);
	if (ldb_key.data == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	key_dn = ldb_kv_index_key(ldb, ldb_kv, tree->u.comparison.attr,
				  NULL, NULL, &truncation);
	if (!key_dn) {
		return LDB_ERR_OPERATIONS_ERROR;
	} else if (truncation == KEY_TRUNCATED) {
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  __location__
			  ": ordered index violation: key dn truncated: %s\n",
			  ldb_dn_get_linearized(key_dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_key2 = ldb_kv_key_dn(tmp_ctx, key_dn);
	talloc_free(key_dn);
	if (ldb_key2.data == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * In order to avoid defining a start and end key for the search, we
	 * notice that each index key is of the form:
	 *
	 *     DN=@INDEX:<ATTRIBUTE>:<VALUE>\0.
	 *
	 * We can simply make our start key DN=@INDEX:<ATTRIBUTE>: and our end
	 * key DN=@INDEX:<ATTRIBUTE>; to return all index entries for a
	 * particular attribute.
	 *
	 * Our LMDB backend uses the default memcmp for key comparison.
	 */

	/* Eliminate NUL byte at the end of the empty key */
	ldb_key2.length--;

	if (ascending) {
		/* : becomes ; for pseudo end-key */
		ldb_key2.data[ldb_key2.length-1]++;
		start_key = ldb_key;
		end_key = ldb_key2;
	} else {
		start_key = ldb_key2;
		end_key = ldb_key;
	}

	ctx.module = module;
	ctx.error = 0;
	ctx.dn_list = list;
	ctx.dn_list->count = 0;
	ctx.dn_list->dn = talloc_zero_array(ctx.dn_list, struct ldb_val, 2);

	ret = ldb_kv->kv_ops->iterate_range(ldb_kv, start_key, end_key,
					    traverse_range_index, &ctx);

	if (ret != LDB_SUCCESS || ctx.error != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	TYPESAFE_QSORT(ctx.dn_list->dn, ctx.dn_list->count,
		       ldb_val_equal_exact_for_qsort);

	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}

static int ldb_kv_index_dn_greater(struct ldb_module *module,
				   struct ldb_kv_private *ldb_kv,
				   const struct ldb_parse_tree *tree,
				   struct dn_list *list)
{
	return ldb_kv_index_dn_ordered(module,
				       ldb_kv,
				       tree,
				       list, true);
}

static int ldb_kv_index_dn_less(struct ldb_module *module,
				   struct ldb_kv_private *ldb_kv,
				   const struct ldb_parse_tree *tree,
				   struct dn_list *list)
{
	return ldb_kv_index_dn_ordered(module,
				       ldb_kv,
				       tree,
				       list, false);
}

/*
  return a list of matching objects using a one-level index
 */
static int ldb_kv_index_dn_attr(struct ldb_module *module,
				struct ldb_kv_private *ldb_kv,
				const char *attr,
				struct ldb_dn *dn,
				struct dn_list *list,
				enum key_truncation *truncation)
{
	struct ldb_context *ldb;
	struct ldb_dn *key;
	struct ldb_val val;
	int ret;

	ldb = ldb_module_get_ctx(module);

	/* work out the index key from the parent DN */
	val.data = (uint8_t *)((uintptr_t)ldb_dn_get_casefold(dn));
	if (val.data == NULL) {
		const char *dn_str = ldb_dn_get_linearized(dn);
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       __location__
				       ": Failed to get casefold DN "
				       "from: %s",
				       dn_str);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	val.length = strlen((char *)val.data);
	key = ldb_kv_index_key(ldb, ldb_kv, attr, &val, NULL, truncation);
	if (!key) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_dn_list_load(module, ldb_kv, key, list,
				  DN_LIST_WILL_BE_READ_ONLY);
	talloc_free(key);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (list->count == 0) {
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	return LDB_SUCCESS;
}

/*
  return a list of matching objects using a one-level index
 */
static int ldb_kv_index_dn_one(struct ldb_module *module,
			       struct ldb_kv_private *ldb_kv,
			       struct ldb_dn *parent_dn,
			       struct dn_list *list,
			       enum key_truncation *truncation)
{
	int ret = ldb_kv_index_dn_attr(
	    module, ldb_kv, LDB_KV_IDXONE, parent_dn, list, truncation);
	if (ret == LDB_SUCCESS) {
		/*
		 * Ensure we do not shortcut on intersection for this
		 * list.  We must never be lazy and return an entry
		 * not in this list.  This allows the index for
		 * SCOPE_ONELEVEL to be trusted.
		 */

		list->strict = true;
	}
	return ret;
}

/*
  return a list of matching objects using the DN index
 */
static int ldb_kv_index_dn_base_dn(struct ldb_module *module,
				   struct ldb_kv_private *ldb_kv,
				   struct ldb_dn *base_dn,
				   struct dn_list *dn_list,
				   enum key_truncation *truncation)
{
	const struct ldb_val *guid_val = NULL;
	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		dn_list->dn = talloc_array(dn_list, struct ldb_val, 1);
		if (dn_list->dn == NULL) {
			return ldb_module_oom(module);
		}
		dn_list->dn[0].data = discard_const_p(unsigned char,
						      ldb_dn_get_linearized(base_dn));
		if (dn_list->dn[0].data == NULL) {
			talloc_free(dn_list->dn);
			return ldb_module_oom(module);
		}
		dn_list->dn[0].length = strlen((char *)dn_list->dn[0].data);
		dn_list->count = 1;

		return LDB_SUCCESS;
	}

	if (ldb_kv->cache->GUID_index_dn_component != NULL) {
		guid_val = ldb_dn_get_extended_component(
		    base_dn, ldb_kv->cache->GUID_index_dn_component);
	}

	if (guid_val != NULL) {
		dn_list->dn = talloc_array(dn_list, struct ldb_val, 1);
		if (dn_list->dn == NULL) {
			return ldb_module_oom(module);
		}
		dn_list->dn[0].data = guid_val->data;
		dn_list->dn[0].length = guid_val->length;
		dn_list->count = 1;

		return LDB_SUCCESS;
	}

	return ldb_kv_index_dn_attr(
	    module, ldb_kv, LDB_KV_IDXDN, base_dn, dn_list, truncation);
}

/*
  return a list of dn's that might match a indexed search or
  an error. return LDB_ERR_NO_SUCH_OBJECT for no matches, or LDB_SUCCESS for matches
 */
static int ldb_kv_index_dn(struct ldb_module *module,
			   struct ldb_kv_private *ldb_kv,
			   const struct ldb_parse_tree *tree,
			   struct dn_list *list)
{
	int ret = LDB_ERR_OPERATIONS_ERROR;

	switch (tree->operation) {
	case LDB_OP_AND:
		ret = ldb_kv_index_dn_and(module, ldb_kv, tree, list);
		break;

	case LDB_OP_OR:
		ret = ldb_kv_index_dn_or(module, ldb_kv, tree, list);
		break;

	case LDB_OP_NOT:
		ret = ldb_kv_index_dn_not(module, ldb_kv, tree, list);
		break;

	case LDB_OP_EQUALITY:
		ret = ldb_kv_index_dn_leaf(module, ldb_kv, tree, list);
		break;

	case LDB_OP_GREATER:
		ret = ldb_kv_index_dn_greater(module, ldb_kv, tree, list);
		break;

	case LDB_OP_LESS:
		ret = ldb_kv_index_dn_less(module, ldb_kv, tree, list);
		break;

	case LDB_OP_SUBSTRING:
	case LDB_OP_PRESENT:
	case LDB_OP_APPROX:
	case LDB_OP_EXTENDED:
		/* we can't index with fancy bitops yet */
		ret = LDB_ERR_OPERATIONS_ERROR;
		break;
	}

	return ret;
}

/*
  filter a candidate dn_list from an indexed search into a set of results
  extracting just the given attributes
*/
static int ldb_kv_index_filter(struct ldb_kv_private *ldb_kv,
			       const struct dn_list *dn_list,
			       struct ldb_kv_context *ac,
			       uint32_t *match_count,
			       enum key_truncation scope_one_truncation)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_message *msg;
	struct ldb_message *filtered_msg;
	unsigned int i;
	unsigned int num_keys = 0;
	uint8_t previous_guid_key[LDB_KV_GUID_KEY_SIZE] = {};
	struct ldb_val *keys = NULL;

	/*
	 * We have to allocate the key list (rather than just walk the
	 * caller supplied list) as the callback could change the list
	 * (by modifying an indexed attribute hosted in the in-memory
	 * index cache!)
	 */
	keys = talloc_array(ac, struct ldb_val, dn_list->count);
	if (keys == NULL) {
		return ldb_module_oom(ac->module);
	}

	if (ldb_kv->cache->GUID_index_attribute != NULL) {
		/*
		 * We speculate that the keys will be GUID based and so
		 * pre-fill in enough space for a GUID (avoiding a pile of
		 * small allocations)
		 */
		struct guid_tdb_key {
			uint8_t guid_key[LDB_KV_GUID_KEY_SIZE];
		} *key_values = NULL;

		key_values = talloc_array(keys,
					  struct guid_tdb_key,
					  dn_list->count);

		if (key_values == NULL) {
			talloc_free(keys);
			return ldb_module_oom(ac->module);
		}
		for (i = 0; i < dn_list->count; i++) {
			keys[i].data = key_values[i].guid_key;
			keys[i].length = sizeof(key_values[i].guid_key);
		}
	} else {
		for (i = 0; i < dn_list->count; i++) {
			keys[i].data = NULL;
			keys[i].length = 0;
		}
	}

	for (i = 0; i < dn_list->count; i++) {
		int ret;

		ret = ldb_kv_idx_to_key(
		    ac->module, ldb_kv, keys, &dn_list->dn[i], &keys[num_keys]);
		if (ret != LDB_SUCCESS) {
			talloc_free(keys);
			return ret;
		}

		if (ldb_kv->cache->GUID_index_attribute != NULL) {
			/*
			 * If we are in GUID index mode, then the dn_list is
			 * sorted.  If we got a duplicate, forget about it, as
			 * otherwise we would send the same entry back more
			 * than once.
			 *
			 * This is needed in the truncated DN case, or if a
			 * duplicate was forced in via
			 * LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK
			 */

			if (memcmp(previous_guid_key,
				   keys[num_keys].data,
				   sizeof(previous_guid_key)) == 0) {
				continue;
			}

			memcpy(previous_guid_key,
			       keys[num_keys].data,
			       sizeof(previous_guid_key));
		}
		num_keys++;
	}


	/*
	 * Now that the list is a safe copy, send the callbacks
	 */
	for (i = 0; i < num_keys; i++) {
		int ret;
		bool matched;
		msg = ldb_msg_new(ac);
		if (!msg) {
			talloc_free(keys);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret =
		    ldb_kv_search_key(ac->module,
				      ldb_kv,
				      keys[i],
				      msg,
				      LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC |
				      /*
				       * The entry point ldb_kv_search_indexed is
				       * only called from the read-locked
				       * ldb_kv_search.
				       */
				      LDB_UNPACK_DATA_FLAG_READ_LOCKED);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			/*
			 * the record has disappeared? yes, this can
			 * happen if the entry is deleted by something
			 * operating in the callback (not another
			 * process, as we have a read lock)
			 */
			talloc_free(msg);
			continue;
		}

		if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_OBJECT) {
			/* an internal error */
			talloc_free(keys);
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/*
		 * We trust the index for LDB_SCOPE_ONELEVEL
		 * unless the index key has been truncated.
		 *
		 * LDB_SCOPE_BASE is not passed in by our only caller.
		 */
		if (ac->scope == LDB_SCOPE_ONELEVEL &&
		    ldb_kv->cache->one_level_indexes &&
		    scope_one_truncation == KEY_NOT_TRUNCATED) {
			ret = ldb_match_message(ldb, msg, ac->tree,
						ac->scope, &matched);
		} else {
			ret = ldb_match_msg_error(ldb, msg,
						  ac->tree, ac->base,
						  ac->scope, &matched);
		}

		if (ret != LDB_SUCCESS) {
			talloc_free(keys);
			talloc_free(msg);
			return ret;
		}
		if (!matched) {
			talloc_free(msg);
			continue;
		}

		filtered_msg = ldb_msg_new(ac);
		if (filtered_msg == NULL) {
			TALLOC_FREE(keys);
			TALLOC_FREE(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		filtered_msg->dn = talloc_steal(filtered_msg, msg->dn);

		/* filter the attributes that the user wants */
		ret = ldb_kv_filter_attrs(ldb, msg, ac->attrs, filtered_msg);

		talloc_free(msg);

		if (ret == -1) {
			TALLOC_FREE(filtered_msg);
			talloc_free(keys);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = ldb_module_send_entry(ac->req, filtered_msg, NULL);
		if (ret != LDB_SUCCESS) {
			/* Regardless of success or failure, the msg
			 * is the callbacks responsiblity, and should
			 * not be talloc_free()'ed */
			ac->request_terminated = true;
			talloc_free(keys);
			return ret;
		}

		(*match_count)++;
	}

	TALLOC_FREE(keys);
	return LDB_SUCCESS;
}

/*
  sort a DN list
 */
static void ldb_kv_dn_list_sort(struct ldb_kv_private *ltdb,
				struct dn_list *list)
{
	if (list->count < 2) {
		return;
	}

	/* We know the list is sorted when using the GUID index */
	if (ltdb->cache->GUID_index_attribute != NULL) {
		return;
	}

	TYPESAFE_QSORT(list->dn, list->count,
		       ldb_val_equal_exact_for_qsort);
}

/*
  search the database with a LDAP-like expression using indexes
  returns -1 if an indexed search is not possible, in which
  case the caller should call ltdb_search_full()
*/
int ldb_kv_search_indexed(struct ldb_kv_context *ac, uint32_t *match_count)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(ac->module), struct ldb_kv_private);
	struct dn_list *dn_list;
	int ret;
	enum ldb_scope index_scope;
	enum key_truncation scope_one_truncation = KEY_NOT_TRUNCATED;

	/* see if indexing is enabled */
	if (!ldb_kv->cache->attribute_indexes &&
	    !ldb_kv->cache->one_level_indexes && ac->scope != LDB_SCOPE_BASE) {
		/* fallback to a full search */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dn_list = talloc_zero(ac, struct dn_list);
	if (dn_list == NULL) {
		return ldb_module_oom(ac->module);
	}

	/*
	 * For the purposes of selecting the switch arm below, if we
	 * don't have a one-level index then treat it like a subtree
	 * search
	 */
	if (ac->scope == LDB_SCOPE_ONELEVEL &&
	    !ldb_kv->cache->one_level_indexes) {
		index_scope = LDB_SCOPE_SUBTREE;
	} else {
		index_scope = ac->scope;
	}

	switch (index_scope) {
	case LDB_SCOPE_BASE:
		/*
		 * The only caller will have filtered the operation out
		 * so we should never get here
		 */
		return ldb_operr(ldb);

	case LDB_SCOPE_ONELEVEL:

		/*
		 * First, load all the one-level child objects (regardless of
		 * whether they match the search filter or not). The database
		 * maintains a one-level index, so retrieving this is quick.
		 */
		ret = ldb_kv_index_dn_one(ac->module,
					  ldb_kv,
					  ac->base,
					  dn_list,
					  &scope_one_truncation);
		if (ret != LDB_SUCCESS) {
			talloc_free(dn_list);
			return ret;
		}

		/*
		 * If we have too many children, running ldb_kv_index_filter()
		 * over all the child objects can be quite expensive. So next
		 * we do a separate indexed query using the search filter.
		 *
		 * This should be quick, but it may return objects that are not
		 * the direct one-level child objects we're interested in.
		 *
		 * We only do this in the GUID index mode, which is
		 * O(n*log(m)) otherwise the intersection below will
		 * be too costly at O(n*m).
		 *
		 * We don't set a heuristic for 'too many' but instead
		 * do it always and rely on the index lookup being
		 * fast enough in the small case.
		 */
		if (ldb_kv->cache->GUID_index_attribute != NULL) {
			struct dn_list *indexed_search_result
				= talloc_zero(ac, struct dn_list);
			if (indexed_search_result == NULL) {
				talloc_free(dn_list);
				return ldb_module_oom(ac->module);
			}

			if (!ldb_kv->cache->attribute_indexes) {
				talloc_free(indexed_search_result);
				talloc_free(dn_list);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			/*
			 * Try to do an indexed database search
			 */
			ret = ldb_kv_index_dn(
			    ac->module, ldb_kv, ac->tree,
			    indexed_search_result);

			/*
			 * We can stop if we're sure the object doesn't exist
			 */
			if (ret == LDB_ERR_NO_SUCH_OBJECT) {
				talloc_free(indexed_search_result);
				talloc_free(dn_list);
				return LDB_ERR_NO_SUCH_OBJECT;
			}

			/*
			 * Once we have a successful search result, we
			 * intersect it with the one-level children (dn_list).
			 * This should give us exactly the result we're after
			 * (we still need to run ldb_kv_index_filter() to
			 * handle potential index truncation cases).
			 *
			 * The indexed search may fail because we don't support
			 * indexing on that type of search operation, e.g.
			 * matching against '*'. In which case we fall through
			 * and run ldb_kv_index_filter() over all the one-level
			 * children (which is still better than bailing out here
			 * and falling back to a full DB scan).
			 */
			if (ret == LDB_SUCCESS) {
				if (!list_intersect(ldb_kv,
						    dn_list,
						    indexed_search_result)) {
					talloc_free(indexed_search_result);
					talloc_free(dn_list);
					return LDB_ERR_OPERATIONS_ERROR;
				}
			}
		}
		break;

	case LDB_SCOPE_SUBTREE:
	case LDB_SCOPE_DEFAULT:
		if (!ldb_kv->cache->attribute_indexes) {
			talloc_free(dn_list);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		/*
		 * Here we load the index for the tree.  We have no
		 * index for the subtree.
		 */
		ret = ldb_kv_index_dn(ac->module, ldb_kv, ac->tree, dn_list);
		if (ret != LDB_SUCCESS) {
			talloc_free(dn_list);
			return ret;
		}
		break;
	}

	/*
	 * It is critical that this function do the re-filter even
	 * on things found by the index as the index can over-match
	 * in cases of truncation (as well as when it decides it is
	 * not worth further filtering)
	 *
	 * If this changes, then the index code above would need to
	 * pass up a flag to say if any index was truncated during
	 * processing as the truncation here refers only to the
	 * SCOPE_ONELEVEL index.
	 */
	ret = ldb_kv_index_filter(
	    ldb_kv, dn_list, ac, match_count, scope_one_truncation);
	talloc_free(dn_list);
	return ret;
}

/**
 * @brief Add a DN in the index list of a given attribute name/value pair
 *
 * This function will add the DN in the index list for the index for
 * the given attribute name and value.
 *
 * @param[in]  module       A ldb_module structure
 *
 * @param[in]  dn           The string representation of the DN as it
 *                          will be stored in the index entry
 *
 * @param[in]  el           A ldb_message_element array, one of the entry
 *                          referred by the v_idx is the attribute name and
 *                          value pair which will be used to construct the
 *                          index name
 *
 * @param[in]  v_idx        The index of element in the el array to use
 *
 * @return                  An ldb error code
 */
static int ldb_kv_index_add1(struct ldb_module *module,
			     struct ldb_kv_private *ldb_kv,
			     const struct ldb_message *msg,
			     struct ldb_message_element *el,
			     int v_idx)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn_key;
	int ret;
	const struct ldb_schema_attribute *a;
	struct dn_list *list;
	unsigned alloc_len;
	enum key_truncation truncation = KEY_TRUNCATED;


	ldb = ldb_module_get_ctx(module);

	list = talloc_zero(module, struct dn_list);
	if (list == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dn_key = ldb_kv_index_key(
	    ldb, ldb_kv, el->name, &el->values[v_idx], &a, &truncation);
	if (!dn_key) {
		talloc_free(list);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/*
	 * Samba only maintains unique indexes on the objectSID and objectGUID
	 * so if a unique index key exceeds the maximum length there is a
	 * problem.
	 */
	if ((truncation == KEY_TRUNCATED) && (a != NULL &&
		(a->flags & LDB_ATTR_FLAG_UNIQUE_INDEX ||
		(el->flags & LDB_FLAG_INTERNAL_FORCE_UNIQUE_INDEX)))) {

		ldb_asprintf_errstring(
		    ldb,
		    __location__ ": unique index key on %s in %s, "
				 "exceeds maximum key length of %u (encoded).",
		    el->name,
		    ldb_dn_get_linearized(msg->dn),
		    ldb_kv->max_key_length);
		talloc_free(list);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	talloc_steal(list, dn_key);

	ret = ldb_kv_dn_list_load(module, ldb_kv, dn_key, list,
				  DN_LIST_MUTABLE);
	if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(list);
		return ret;
	}

	/*
	 * Check for duplicates in the @IDXDN DN -> GUID record
	 *
	 * This is very normal, it just means a duplicate DN creation
	 * was attempted, so don't set the error string or print scary
	 * messages.
	 */
	if (list->count > 0 &&
	    ldb_attr_cmp(el->name, LDB_KV_IDXDN) == 0 &&
	    truncation == KEY_NOT_TRUNCATED) {

		talloc_free(list);
		return LDB_ERR_CONSTRAINT_VIOLATION;

	} else if (list->count > 0
		   && ldb_attr_cmp(el->name, LDB_KV_IDXDN) == 0) {

		/*
		 * At least one existing entry in the DN->GUID index, which
		 * arises when the DN indexes have been truncated
		 *
		 * So need to pull the DN's to check if it's really a duplicate
		 */
		unsigned int i;
		for (i=0; i < list->count; i++) {
			uint8_t guid_key[LDB_KV_GUID_KEY_SIZE];
			struct ldb_val key = {
				.data = guid_key,
				.length = sizeof(guid_key)
			};
			const int flags = LDB_UNPACK_DATA_FLAG_NO_ATTRS;
			struct ldb_message *rec = ldb_msg_new(ldb);
			if (rec == NULL) {
				return LDB_ERR_OPERATIONS_ERROR;
			}

			ret = ldb_kv_idx_to_key(
			    module, ldb_kv, ldb, &list->dn[i], &key);
			if (ret != LDB_SUCCESS) {
				TALLOC_FREE(list);
				TALLOC_FREE(rec);
				return ret;
			}

			ret =
			    ldb_kv_search_key(module, ldb_kv, key, rec, flags);
			if (key.data != guid_key) {
				TALLOC_FREE(key.data);
			}
			if (ret == LDB_ERR_NO_SUCH_OBJECT) {
				/*
				 * the record has disappeared?
				 * yes, this can happen
				 */
				talloc_free(rec);
				continue;
			}

			if (ret != LDB_SUCCESS) {
				/* an internal error */
				TALLOC_FREE(rec);
				TALLOC_FREE(list);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			/*
			 * The DN we are trying to add to the DB and index
			 * is already here, so we must deny the addition
			 */
			if (ldb_dn_compare(msg->dn, rec->dn) == 0) {
				TALLOC_FREE(rec);
				TALLOC_FREE(list);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		}
	}

	/*
	 * Check for duplicates in unique indexes
	 *
	 * We don't need to do a loop test like the @IDXDN case
	 * above as we have a ban on long unique index values
	 * at the start of this function.
	 */
	if (list->count > 0 &&
	    ((a != NULL
	      && (a->flags & LDB_ATTR_FLAG_UNIQUE_INDEX ||
		  (el->flags & LDB_FLAG_INTERNAL_FORCE_UNIQUE_INDEX))))) {
		/*
		 * We do not want to print info about a possibly
		 * confidential DN that the conflict was with in the
		 * user-visible error string
		 */

		if (ldb_kv->cache->GUID_index_attribute == NULL) {
			ldb_debug(ldb, LDB_DEBUG_WARNING,
				  __location__
				  ": unique index violation on %s in %s, "
				  "conflicts with %*.*s in %s",
				  el->name, ldb_dn_get_linearized(msg->dn),
				  (int)list->dn[0].length,
				  (int)list->dn[0].length,
				  list->dn[0].data,
				  ldb_dn_get_linearized(dn_key));
		} else {
			/* This can't fail, gives a default at worst */
			const struct ldb_schema_attribute *attr =
			    ldb_schema_attribute_by_name(
				ldb, ldb_kv->cache->GUID_index_attribute);
			struct ldb_val v;
			ret = attr->syntax->ldif_write_fn(ldb, list,
							  &list->dn[0], &v);
			if (ret == LDB_SUCCESS) {
				ldb_debug(ldb,
					  LDB_DEBUG_WARNING,
					  __location__
					  ": unique index violation on %s in "
					  "%s, conflicts with %s %*.*s in %s",
					  el->name,
					  ldb_dn_get_linearized(msg->dn),
					  ldb_kv->cache->GUID_index_attribute,
					  (int)v.length,
					  (int)v.length,
					  v.data,
					  ldb_dn_get_linearized(dn_key));
			}
		}
		ldb_asprintf_errstring(ldb,
				       __location__ ": unique index violation "
				       "on %s in %s",
				       el->name,
				       ldb_dn_get_linearized(msg->dn));
		talloc_free(list);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* overallocate the list a bit, to reduce the number of
	 * realloc trigered copies */
	alloc_len = ((list->count+1)+7) & ~7;
	list->dn = talloc_realloc(list, list->dn, struct ldb_val, alloc_len);
	if (list->dn == NULL) {
		talloc_free(list);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		const char *dn_str = ldb_dn_get_linearized(msg->dn);
		list->dn[list->count].data
			= (uint8_t *)talloc_strdup(list->dn, dn_str);
		if (list->dn[list->count].data == NULL) {
			talloc_free(list);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		list->dn[list->count].length = strlen(dn_str);
	} else {
		const struct ldb_val *key_val;
		struct ldb_val *exact = NULL, *next = NULL;
		key_val = ldb_msg_find_ldb_val(
		    msg, ldb_kv->cache->GUID_index_attribute);
		if (key_val == NULL) {
			talloc_free(list);
			return ldb_module_operr(module);
		}

		if (key_val->length != LDB_KV_GUID_SIZE) {
			talloc_free(list);
			return ldb_module_operr(module);
		}

		BINARY_ARRAY_SEARCH_GTE(list->dn, list->count,
					*key_val, ldb_val_equal_exact_ordered,
					exact, next);

		/*
		 * Give a warning rather than fail, this could be a
		 * duplicate value in the record allowed by a caller
		 * forcing in the value with
		 * LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK
		 */
		if (exact != NULL && truncation == KEY_NOT_TRUNCATED) {
			/* This can't fail, gives a default at worst */
			const struct ldb_schema_attribute *attr =
			    ldb_schema_attribute_by_name(
				ldb, ldb_kv->cache->GUID_index_attribute);
			struct ldb_val v;
			ret = attr->syntax->ldif_write_fn(ldb, list,
							  exact, &v);
			if (ret == LDB_SUCCESS) {
				ldb_debug(ldb,
					  LDB_DEBUG_WARNING,
					  __location__
					  ": duplicate attribute value in %s "
					  "for index on %s, "
					  "duplicate of %s %*.*s in %s",
					  ldb_dn_get_linearized(msg->dn),
					  el->name,
					  ldb_kv->cache->GUID_index_attribute,
					  (int)v.length,
					  (int)v.length,
					  v.data,
					  ldb_dn_get_linearized(dn_key));
			}
		}

		if (next == NULL) {
			next = &list->dn[list->count];
		} else {
			memmove(&next[1], next,
				sizeof(*next) * (list->count - (next - list->dn)));
		}
		*next = ldb_val_dup(list->dn, key_val);
		if (next->data == NULL) {
			talloc_free(list);
			return ldb_module_operr(module);
		}
	}
	list->count++;

	ret = ldb_kv_dn_list_store(module, dn_key, list);

	talloc_free(list);

	return ret;
}

/*
  add index entries for one elements in a message
 */
static int ldb_kv_index_add_el(struct ldb_module *module,
			       struct ldb_kv_private *ldb_kv,
			       const struct ldb_message *msg,
			       struct ldb_message_element *el)
{
	unsigned int i;
	for (i = 0; i < el->num_values; i++) {
		int ret = ldb_kv_index_add1(module, ldb_kv, msg, el, i);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

/*
  add index entries for all elements in a message
 */
static int ldb_kv_index_add_all(struct ldb_module *module,
				struct ldb_kv_private *ldb_kv,
				const struct ldb_message *msg)
{
	struct ldb_message_element *elements = msg->elements;
	unsigned int i;
	const char *dn_str;
	int ret;

	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	dn_str = ldb_dn_get_linearized(msg->dn);
	if (dn_str == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_write_index_dn_guid(module, msg, 1);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!ldb_kv->cache->attribute_indexes) {
		/* no indexed fields */
		return LDB_SUCCESS;
	}

	for (i = 0; i < msg->num_elements; i++) {
		if (!ldb_kv_is_indexed(module, ldb_kv, elements[i].name)) {
			continue;
		}
		ret = ldb_kv_index_add_el(module, ldb_kv, msg, &elements[i]);
		if (ret != LDB_SUCCESS) {
			struct ldb_context *ldb = ldb_module_get_ctx(module);
			ldb_asprintf_errstring(ldb,
					       __location__ ": Failed to re-index %s in %s - %s",
					       elements[i].name, dn_str,
					       ldb_errstring(ldb));
			return ret;
		}
	}

	return LDB_SUCCESS;
}


/*
  insert a DN index for a message
*/
static int ldb_kv_modify_index_dn(struct ldb_module *module,
				  struct ldb_kv_private *ldb_kv,
				  const struct ldb_message *msg,
				  struct ldb_dn *dn,
				  const char *index,
				  int add)
{
	struct ldb_message_element el;
	struct ldb_val val;
	int ret;

	val.data = (uint8_t *)((uintptr_t)ldb_dn_get_casefold(dn));
	if (val.data == NULL) {
		const char *dn_str = ldb_dn_get_linearized(dn);
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       __location__ ": Failed to modify %s "
						    "against %s in %s: failed "
						    "to get casefold DN",
				       index,
				       ldb_kv->cache->GUID_index_attribute,
				       dn_str);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	val.length = strlen((char *)val.data);
	el.name = index;
	el.values = &val;
	el.num_values = 1;

	if (add) {
		ret = ldb_kv_index_add1(module, ldb_kv, msg, &el, 0);
	} else { /* delete */
		ret = ldb_kv_index_del_value(module, ldb_kv, msg, &el, 0);
	}

	if (ret != LDB_SUCCESS) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		const char *dn_str = ldb_dn_get_linearized(dn);
		ldb_asprintf_errstring(ldb,
				       __location__ ": Failed to modify %s "
						    "against %s in %s - %s",
				       index,
				       ldb_kv->cache->GUID_index_attribute,
				       dn_str,
				       ldb_errstring(ldb));
		return ret;
	}
	return ret;
}

/*
  insert a one level index for a message
*/
static int ldb_kv_index_onelevel(struct ldb_module *module,
				 const struct ldb_message *msg,
				 int add)
{
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	struct ldb_dn *pdn;
	int ret;

	/* We index for ONE Level only if requested */
	if (!ldb_kv->cache->one_level_indexes) {
		return LDB_SUCCESS;
	}

	pdn = ldb_dn_get_parent(module, msg->dn);
	if (pdn == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret =
	    ldb_kv_modify_index_dn(module, ldb_kv, msg, pdn, LDB_KV_IDXONE, add);

	talloc_free(pdn);

	return ret;
}

/*
  insert a one level index for a message
*/
static int ldb_kv_write_index_dn_guid(struct ldb_module *module,
				      const struct ldb_message *msg,
				      int add)
{
	int ret;
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);

	/* We index for DN only if using a GUID index */
	if (ldb_kv->cache->GUID_index_attribute == NULL) {
		return LDB_SUCCESS;
	}

	ret = ldb_kv_modify_index_dn(
	    module, ldb_kv, msg, msg->dn, LDB_KV_IDXDN, add);

	if (ret == LDB_ERR_CONSTRAINT_VIOLATION) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Entry %s already exists",
				       ldb_dn_get_linearized(msg->dn));
		ret = LDB_ERR_ENTRY_ALREADY_EXISTS;
	}
	return ret;
}

/*
  add the index entries for a new element in a record
  The caller guarantees that these element values are not yet indexed
*/
int ldb_kv_index_add_element(struct ldb_module *module,
			     struct ldb_kv_private *ldb_kv,
			     const struct ldb_message *msg,
			     struct ldb_message_element *el)
{
	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}
	if (!ldb_kv_is_indexed(module, ldb_kv, el->name)) {
		return LDB_SUCCESS;
	}
	return ldb_kv_index_add_el(module, ldb_kv, msg, el);
}

/*
  add the index entries for a new record
*/
int ldb_kv_index_add_new(struct ldb_module *module,
			 struct ldb_kv_private *ldb_kv,
			 const struct ldb_message *msg)
{
	int ret;

	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	ret = ldb_kv_index_add_all(module, ldb_kv, msg);
	if (ret != LDB_SUCCESS) {
		/*
		 * Because we can't trust the caller to be doing
		 * transactions properly, clean up any index for this
		 * entry rather than relying on a transaction
		 * cleanup
		 */

		ldb_kv_index_delete(module, msg);
		return ret;
	}

	ret = ldb_kv_index_onelevel(module, msg, 1);
	if (ret != LDB_SUCCESS) {
		/*
		 * Because we can't trust the caller to be doing
		 * transactions properly, clean up any index for this
		 * entry rather than relying on a transaction
		 * cleanup
		 */
		ldb_kv_index_delete(module, msg);
		return ret;
	}
	return ret;
}


/*
  delete an index entry for one message element
*/
int ldb_kv_index_del_value(struct ldb_module *module,
			   struct ldb_kv_private *ldb_kv,
			   const struct ldb_message *msg,
			   struct ldb_message_element *el,
			   unsigned int v_idx)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn_key;
	const char *dn_str;
	int ret, i;
	unsigned int j;
	struct dn_list *list;
	struct ldb_dn *dn = msg->dn;
	enum key_truncation truncation = KEY_NOT_TRUNCATED;

	ldb = ldb_module_get_ctx(module);

	dn_str = ldb_dn_get_linearized(dn);
	if (dn_str == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (dn_str[0] == '@') {
		return LDB_SUCCESS;
	}

	dn_key = ldb_kv_index_key(
	    ldb, ldb_kv, el->name, &el->values[v_idx], NULL, &truncation);
	/*
	 * We ignore key truncation in ltdb_index_add1() so
	 * match that by ignoring it here as well
	 *
	 * Multiple values are legitimate and accepted
	 */
	if (!dn_key) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	list = talloc_zero(dn_key, struct dn_list);
	if (list == NULL) {
		talloc_free(dn_key);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_kv_dn_list_load(module, ldb_kv, dn_key, list,
				  DN_LIST_MUTABLE);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* it wasn't indexed. Did we have an earlier error? If we did then
		   its gone now */
		talloc_free(dn_key);
		return LDB_SUCCESS;
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(dn_key);
		return ret;
	}

	/*
	 * Find one of the values matching this message to remove
	 */
	i = ldb_kv_dn_list_find_msg(ldb_kv, list, msg);
	if (i == -1) {
		/* nothing to delete */
		talloc_free(dn_key);
		return LDB_SUCCESS;
	}

	j = (unsigned int) i;
	if (j != list->count - 1) {
		memmove(&list->dn[j], &list->dn[j+1], sizeof(list->dn[0])*(list->count - (j+1)));
	}
	list->count--;
	if (list->count == 0) {
		talloc_free(list->dn);
		list->dn = NULL;
	} else {
		list->dn = talloc_realloc(list, list->dn, struct ldb_val, list->count);
	}

	ret = ldb_kv_dn_list_store(module, dn_key, list);

	talloc_free(dn_key);

	return ret;
}

/*
  delete the index entries for a element
  return -1 on failure
*/
int ldb_kv_index_del_element(struct ldb_module *module,
			     struct ldb_kv_private *ldb_kv,
			     const struct ldb_message *msg,
			     struct ldb_message_element *el)
{
	const char *dn_str;
	int ret;
	unsigned int i;

	if (!ldb_kv->cache->attribute_indexes) {
		/* no indexed fields */
		return LDB_SUCCESS;
	}

	dn_str = ldb_dn_get_linearized(msg->dn);
	if (dn_str == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (dn_str[0] == '@') {
		return LDB_SUCCESS;
	}

	if (!ldb_kv_is_indexed(module, ldb_kv, el->name)) {
		return LDB_SUCCESS;
	}
	for (i = 0; i < el->num_values; i++) {
		ret = ldb_kv_index_del_value(module, ldb_kv, msg, el, i);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

/*
  delete the index entries for a record
  return -1 on failure
*/
int ldb_kv_index_delete(struct ldb_module *module,
			const struct ldb_message *msg)
{
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	int ret;
	unsigned int i;

	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	ret = ldb_kv_index_onelevel(module, msg, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_kv_write_index_dn_guid(module, msg, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!ldb_kv->cache->attribute_indexes) {
		/* no indexed fields */
		return LDB_SUCCESS;
	}

	for (i = 0; i < msg->num_elements; i++) {
		ret = ldb_kv_index_del_element(
		    module, ldb_kv, msg, &msg->elements[i]);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}


/*
  traversal function that deletes all @INDEX records in the in-memory
  TDB.

  This does not touch the actual DB, that is done at transaction
  commit, which in turn greatly reduces DB churn as we will likely
  be able to do a direct update into the old record.
*/
static int delete_index(struct ldb_kv_private *ldb_kv,
			struct ldb_val key,
			_UNUSED_ struct ldb_val data,
			void *state)
{
	struct ldb_module *module = state;
	const char *dnstr = "DN=" LDB_KV_INDEX ":";
	struct dn_list list;
	struct ldb_dn *dn;
	struct ldb_val v;
	int ret;

	if (strncmp((char *)key.data, dnstr, strlen(dnstr)) != 0) {
		return 0;
	}
	/* we need to put a empty list in the internal tdb for this
	 * index entry */
	list.dn = NULL;
	list.count = 0;

	/* the offset of 3 is to remove the DN= prefix. */
	v.data = key.data + 3;
	v.length = strnlen((char *)key.data, key.length) - 3;

	dn = ldb_dn_from_ldb_val(ldb_kv, ldb_module_get_ctx(module), &v);

	/*
	 * This does not actually touch the DB quite yet, just
         * the in-memory index cache
	 */
	ret = ldb_kv_dn_list_store(module, dn, &list);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Unable to store null index for %s\n",
						ldb_dn_get_linearized(dn));
		talloc_free(dn);
		return -1;
	}
	talloc_free(dn);
	return 0;
}

/*
  traversal function that adds @INDEX records during a re index TODO wrong comment
*/
static int re_key(struct ldb_kv_private *ldb_kv,
		  struct ldb_val key,
		  struct ldb_val val,
		  void *state)
{
	struct ldb_context *ldb;
	struct ldb_kv_reindex_context *ctx =
	    (struct ldb_kv_reindex_context *)state;
	struct ldb_module *module = ldb_kv->module;
	struct ldb_message *msg;
	int ret;
	struct ldb_val key2;
	bool is_record;

	ldb = ldb_module_get_ctx(module);

	is_record = ldb_kv_key_is_normal_record(key);
	if (is_record == false) {
		return 0;
	}

	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return -1;
	}

	ret = ldb_unpack_data(ldb, &val, msg);
	if (ret != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid data for index %s\n",
						ldb_dn_get_linearized(msg->dn));
		ctx->error = ret;
		talloc_free(msg);
		return -1;
	}

	if (msg->dn == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Refusing to re-index as GUID "
			  "key %*.*s with no DN\n",
			  (int)key.length, (int)key.length,
			  (char *)key.data);
		talloc_free(msg);
		return -1;
	}

	/* check if the DN key has changed, perhaps due to the case
	   insensitivity of an element changing, or a change from DN
	   to GUID keys */
	key2 = ldb_kv_key_msg(module, msg, msg);
	if (key2.data == NULL) {
		/* probably a corrupt record ... darn */
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid DN in re_index: %s",
						ldb_dn_get_linearized(msg->dn));
		talloc_free(msg);
		return 0;
	}
	if (key.length != key2.length ||
	    (memcmp(key.data, key2.data, key.length) != 0)) {
		ldb_kv->kv_ops->update_in_iterate(
		    ldb_kv, key, key2, val, ctx);
	}
	talloc_free(key2.data);

	talloc_free(msg);

	ctx->count++;
	if (ctx->count % 10000 == 0) {
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "Reindexing: re-keyed %u records so far",
			  ctx->count);
	}

	return 0;
}

/*
  traversal function that adds @INDEX records during a re index
*/
static int re_index(struct ldb_kv_private *ldb_kv,
		    struct ldb_val key,
		    struct ldb_val val,
		    void *state)
{
	struct ldb_context *ldb;
	struct ldb_kv_reindex_context *ctx =
	    (struct ldb_kv_reindex_context *)state;
	struct ldb_module *module = ldb_kv->module;
	struct ldb_message *msg;
	int ret;
	bool is_record;

	ldb = ldb_module_get_ctx(module);

	is_record = ldb_kv_key_is_normal_record(key);
	if (is_record == false) {
		return 0;
	}

	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return -1;
	}

	ret = ldb_unpack_data(ldb, &val, msg);
	if (ret != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid data for index %s\n",
						ldb_dn_get_linearized(msg->dn));
		ctx->error = ret;
		talloc_free(msg);
		return -1;
	}

	if (msg->dn == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Refusing to re-index as GUID "
			  "key %*.*s with no DN\n",
			  (int)key.length, (int)key.length,
			  (char *)key.data);
		talloc_free(msg);
		return -1;
	}

	ret = ldb_kv_index_onelevel(module, msg, 1);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Adding special ONE LEVEL index failed (%s)!",
						ldb_dn_get_linearized(msg->dn));
		talloc_free(msg);
		return -1;
	}

	ret = ldb_kv_index_add_all(module, ldb_kv, msg);

	if (ret != LDB_SUCCESS) {
		ctx->error = ret;
		talloc_free(msg);
		return -1;
	}

	talloc_free(msg);

	ctx->count++;
	if (ctx->count % 10000 == 0) {
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "Reindexing: re-indexed %u records so far",
			  ctx->count);
	}

	return 0;
}

/*
 * Convert the 4-byte pack format version to a number that's slightly
 * more intelligible to a user e.g. version 0, 1, 2, etc.
 */
static uint32_t displayable_pack_version(uint32_t version) {
	if (version < LDB_PACKING_FORMAT_NODN) {
		return version; /* unknown - can't convert */
	}

	return (version - LDB_PACKING_FORMAT_NODN);
}

static int re_pack(struct ldb_kv_private *ldb_kv,
		   _UNUSED_ struct ldb_val key,
		   struct ldb_val val,
		   void *state)
{
	struct ldb_context *ldb;
	struct ldb_message *msg;
	struct ldb_module *module = ldb_kv->module;
	struct ldb_kv_repack_context *ctx =
	    (struct ldb_kv_repack_context *)state;
	int ret;

	ldb = ldb_module_get_ctx(module);

	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return -1;
	}

	ret = ldb_unpack_data(ldb, &val, msg);
	if (ret != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Repack: unpack failed: %s\n",
			  ldb_dn_get_linearized(msg->dn));
		ctx->error = ret;
		talloc_free(msg);
		return -1;
	}

	ret = ldb_kv_store(module, msg, TDB_MODIFY);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Repack: store failed: %s\n",
			  ldb_dn_get_linearized(msg->dn));
		ctx->error = ret;
		talloc_free(msg);
		return -1;
	}

	/*
	 * Warn the user that we're repacking the first time we see a normal
	 * record. This means we never warn if we're repacking a database with
	 * only @ records. This is because during database initialisation,
	 * we might repack as initial settings are written out, and we don't
	 * want to spam the log.
	 */
	if ((!ctx->normal_record_seen) && (!ldb_dn_is_special(msg->dn))) {
		ldb_debug(ldb, LDB_DEBUG_ALWAYS_LOG,
			  "Repacking database from v%u to v%u format "
			  "(first record %s)",
			  displayable_pack_version(ctx->old_version),
			  displayable_pack_version(ldb_kv->pack_format_version),
			  ldb_dn_get_linearized(msg->dn));
		ctx->normal_record_seen = true;
	}

	ctx->count++;
	if (ctx->count % 10000 == 0) {
		ldb_debug(ldb, LDB_DEBUG_WARNING,
			  "Repack: re-packed %u records so far",
			  ctx->count);
	}

	talloc_free(msg);
	return 0;
}

int ldb_kv_repack(struct ldb_module *module)
{
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_kv_repack_context ctx;
	int ret;

	ctx.old_version = ldb_kv->pack_format_version;
	ctx.count = 0;
	ctx.error = LDB_SUCCESS;
	ctx.normal_record_seen = false;

	ldb_kv->pack_format_version = ldb_kv->target_pack_format_version;

	/* Iterate all database records and repack them in the new format */
	ret = ldb_kv->kv_ops->iterate(ldb_kv, re_pack, &ctx);
	if (ret < 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Repack traverse failed: %s",
			  ldb_errstring(ldb));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ctx.error != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Repack failed: %s",
			  ldb_errstring(ldb));
		return ctx.error;
	}

	return LDB_SUCCESS;
}

/*
  force a complete reindex of the database
*/
int ldb_kv_reindex(struct ldb_module *module)
{
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	int ret;
	struct ldb_kv_reindex_context ctx;
	size_t index_cache_size = 0;

	/*
	 * Only triggered after a modification, but make clear we do
	 * not re-index a read-only DB
	 */
	if (ldb_kv->read_only) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (ldb_kv_cache_reload(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Ensure we read (and so remove) the entries from the real
	 * DB, no values stored so far are any use as we want to do a
	 * re-index
	 */
	ldb_kv_index_transaction_cancel(module);
	if (ldb_kv->nested_idx_ptr != NULL) {
		ldb_kv_index_sub_transaction_cancel(ldb_kv);
	}

	/*
	 * Calculate the size of the index cache needed for
	 * the re-index. If specified always use the
	 * ldb_kv->index_transaction_cache_size otherwise use the maximum
	 * of the size estimate or the DEFAULT_INDEX_CACHE_SIZE
	 */
	if (ldb_kv->index_transaction_cache_size > 0) {
		index_cache_size = ldb_kv->index_transaction_cache_size;
	} else {
		index_cache_size = ldb_kv->kv_ops->get_size(ldb_kv);
		if (index_cache_size < DEFAULT_INDEX_CACHE_SIZE) {
			index_cache_size = DEFAULT_INDEX_CACHE_SIZE;
		}
	}

	/*
	 * Note that we don't start an index sub transaction for re-indexing
	 */
	ret = ldb_kv_index_transaction_start(module, index_cache_size);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* first traverse the database deleting any @INDEX records by
	 * putting NULL entries in the in-memory tdb
	 */
	ret = ldb_kv->kv_ops->iterate(ldb_kv, delete_index, module);
	if (ret < 0) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(ldb, "index deletion traverse failed: %s",
				       ldb_errstring(ldb));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ctx.error = 0;
	ctx.count = 0;

	ret = ldb_kv->kv_ops->iterate(ldb_kv, re_key, &ctx);
	if (ret < 0) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(ldb, "key correction traverse failed: %s",
				       ldb_errstring(ldb));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ctx.error != LDB_SUCCESS) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(ldb, "reindexing failed: %s", ldb_errstring(ldb));
		return ctx.error;
	}

	ctx.error = 0;
	ctx.count = 0;

	/* now traverse adding any indexes for normal LDB records */
	ret = ldb_kv->kv_ops->iterate(ldb_kv, re_index, &ctx);
	if (ret < 0) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(ldb, "reindexing traverse failed: %s",
				       ldb_errstring(ldb));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ctx.error != LDB_SUCCESS) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(ldb, "reindexing failed: %s", ldb_errstring(ldb));
		return ctx.error;
	}

	if (ctx.count > 10000) {
		ldb_debug(ldb_module_get_ctx(module),
			  LDB_DEBUG_WARNING,
			  "Reindexing: re_index successful on %s, "
			  "final index write-out will be in transaction commit",
			  ldb_kv->kv_ops->name(ldb_kv));
	}
	return LDB_SUCCESS;
}

/*
 * Copy the contents of the nested transaction index cache record to the
 * transaction index cache.
 *
 * During this 'commit' of the subtransaction to the main transaction
 * (cache), care must be taken to free any existing index at the top
 * level because otherwise we would leak memory.
 */
static int ldb_kv_sub_transaction_traverse(
	struct tdb_context *tdb,
	TDB_DATA key,
	TDB_DATA data,
	void *state)
{
	struct ldb_module *module = state;
	struct ldb_kv_private *ldb_kv = talloc_get_type(
	    ldb_module_get_private(module), struct ldb_kv_private);
	TDB_DATA rec = {0};
	struct dn_list *index_in_subtransaction = NULL;
	struct dn_list *index_in_top_level = NULL;
	int ret = 0;

	/*
	 * This unwraps the pointer in the DB into a pointer in
	 * memory, we are abusing TDB as a hash map, not a linearised
	 * database store
	 */
	index_in_subtransaction = ldb_kv_index_idxptr(module, data);
	if (index_in_subtransaction == NULL) {
		ldb_kv->idxptr->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	/*
	 * Do we already have an entry in the primary transaction cache
	 * If so free it's dn_list and replace it with the dn_list from
	 * the secondary cache
	 *
	 * The TDB and so the fetched rec contains NO DATA, just a
	 * pointer to data held in memory.
	 */
	rec = tdb_fetch(ldb_kv->idxptr->itdb, key);
	if (rec.dptr != NULL) {
		index_in_top_level = ldb_kv_index_idxptr(module, rec);
		free(rec.dptr);
		if (index_in_top_level == NULL) {
			abort();
		}
		/*
		 * We had this key at the top level.  However we made a copy
		 * at the sub-transaction level so that we could possibly
		 * roll back.  We have to free the top level index memory
		 * otherwise we would leak
		 */
		if (index_in_top_level->count > 0) {
			TALLOC_FREE(index_in_top_level->dn);
		}
		index_in_top_level->dn
			= talloc_steal(index_in_top_level,
				       index_in_subtransaction->dn);
		index_in_top_level->count = index_in_subtransaction->count;
		return 0;
	}

	index_in_top_level = talloc(ldb_kv->idxptr, struct dn_list);
	if (index_in_top_level == NULL) {
		ldb_kv->idxptr->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}
	index_in_top_level->dn
		= talloc_steal(index_in_top_level,
			       index_in_subtransaction->dn);
	index_in_top_level->count = index_in_subtransaction->count;

	rec.dptr = (uint8_t *)&index_in_top_level;
	rec.dsize = sizeof(void *);


	/*
	 * This is not a store into the main DB, but into an in-memory
	 * TDB, so we don't need a guard on ltdb->read_only
	 */
	ret = tdb_store(ldb_kv->idxptr->itdb, key, rec, TDB_INSERT);
	if (ret != 0) {
		ldb_kv->idxptr->error = ltdb_err_map(
		    tdb_error(ldb_kv->idxptr->itdb));
		return -1;
	}
	return 0;
}

/*
 * Initialise the index cache for a sub transaction.
 */
int ldb_kv_index_sub_transaction_start(struct ldb_kv_private *ldb_kv)
{
	ldb_kv->nested_idx_ptr = talloc_zero(ldb_kv, struct ldb_kv_idxptr);
	if (ldb_kv->nested_idx_ptr == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * We use a tiny hash size for the sub-database (11).
	 *
	 * The sub-transaction is only for one record at a time, we
	 * would use a linked list but that would make the code even
	 * more complex when manipulating the index, as it would have
	 * to know if we were in a nested transaction (normal
	 * operations) or the top one (a reindex).
	 */
	ldb_kv->nested_idx_ptr->itdb =
		tdb_open(NULL, 11, TDB_INTERNAL, O_RDWR, 0);
	if (ldb_kv->nested_idx_ptr->itdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return LDB_SUCCESS;
}

/*
 * Clear the contents of the nested transaction index cache when the nested
 * transaction is cancelled.
 */
int ldb_kv_index_sub_transaction_cancel(struct ldb_kv_private *ldb_kv)
{
	if (ldb_kv->nested_idx_ptr != NULL) {
		tdb_close(ldb_kv->nested_idx_ptr->itdb);
		TALLOC_FREE(ldb_kv->nested_idx_ptr);
	}
	return LDB_SUCCESS;
}

/*
 * Commit a nested transaction,
 * Copy the contents of the nested transaction index cache to the
 * transaction index cache.
 */
int ldb_kv_index_sub_transaction_commit(struct ldb_kv_private *ldb_kv)
{
	int ret = 0;

	if (ldb_kv->nested_idx_ptr == NULL) {
		return LDB_SUCCESS;
	}
	if (ldb_kv->nested_idx_ptr->itdb == NULL) {
		return LDB_SUCCESS;
	}
	tdb_traverse(
	    ldb_kv->nested_idx_ptr->itdb,
	    ldb_kv_sub_transaction_traverse,
	    ldb_kv->module);
	tdb_close(ldb_kv->nested_idx_ptr->itdb);
	ldb_kv->nested_idx_ptr->itdb = NULL;

	ret = ldb_kv->nested_idx_ptr->error;
	if (ret != LDB_SUCCESS) {
		struct ldb_context *ldb = ldb_module_get_ctx(ldb_kv->module);
		if (!ldb_errstring(ldb)) {
			ldb_set_errstring(ldb, ldb_strerror(ret));
		}
		ldb_asprintf_errstring(
			ldb,
			__location__": Failed to update index records in "
			"sub transaction commit: %s",
			ldb_errstring(ldb));
	}
	TALLOC_FREE(ldb_kv->nested_idx_ptr);
	return ret;
}
