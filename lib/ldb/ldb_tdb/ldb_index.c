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
 *  Component: ldb tdb backend - indexing
 *
 *  Description: indexing routines for ldb tdb backend
 *
 *  Author: Andrew Tridgell
 */

/*

LDB Index design and choice of TDB key:
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

#include "ldb_tdb.h"
#include "ldb_private.h"
#include "lib/util/binsearch.h"

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

struct ltdb_idxptr {
	struct tdb_context *itdb;
	int error;
};

static int ltdb_write_index_dn_guid(struct ldb_module *module,
				    const struct ldb_message *msg,
				    int add);
static int ltdb_index_dn_base_dn(struct ldb_module *module,
				 struct ltdb_private *ltdb,
				 struct ldb_dn *base_dn,
				 struct dn_list *dn_list);

static void ltdb_dn_list_sort(struct ltdb_private *ltdb,
			      struct dn_list *list);

/* we put a @IDXVERSION attribute on index entries. This
   allows us to tell if it was written by an older version
*/
#define LTDB_INDEXING_VERSION 2

#define LTDB_GUID_INDEXING_VERSION 3

/* enable the idxptr mode when transactions start */
int ltdb_index_transaction_start(struct ldb_module *module)
{
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);
	ltdb->idxptr = talloc_zero(ltdb, struct ltdb_idxptr);
	if (ltdb->idxptr == NULL) {
		return ldb_oom(ldb_module_get_ctx(module));
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
static int ltdb_dn_list_find_val(struct ltdb_private *ltdb,
				 const struct dn_list *list,
				 const struct ldb_val *v)
{
	unsigned int i;
	struct ldb_val *exact = NULL, *next = NULL;

	if (ltdb->cache->GUID_index_attribute == NULL) {
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
static int ltdb_dn_list_find_msg(struct ltdb_private *ltdb,
				 struct dn_list *list,
				 const struct ldb_message *msg)
{
	struct ldb_val v;
	const struct ldb_val *key_val;
	if (ltdb->cache->GUID_index_attribute == NULL) {
		const char *dn_str = ldb_dn_get_linearized(msg->dn);
		v.data = discard_const_p(unsigned char, dn_str);
		v.length = strlen(dn_str);
	} else {
		key_val = ldb_msg_find_ldb_val(msg,
					       ltdb->cache->GUID_index_attribute);
		if (key_val == NULL) {
			return -1;
		}
		v = *key_val;
	}
	return ltdb_dn_list_find_val(ltdb, list, &v);
}

/*
  this is effectively a cast function, but with lots of paranoia
  checks and also copes with CPUs that are fussy about pointer
  alignment
 */
static struct dn_list *ltdb_index_idxptr(struct ldb_module *module, TDB_DATA rec, bool check_parent)
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
	if (check_parent && list->dn && talloc_parent(list->dn) != list) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "Bad parent '%s' for idxptr",
				       talloc_get_name(talloc_parent(list->dn)));
		return NULL;
	}
	return list;
}

/*
  return the @IDX list in an index entry for a dn as a
  struct dn_list
 */
static int ltdb_dn_list_load(struct ldb_module *module,
			     struct ltdb_private *ltdb,
			     struct ldb_dn *dn, struct dn_list *list)
{
	struct ldb_message *msg;
	int ret, version;
	struct ldb_message_element *el;
	TDB_DATA rec;
	struct dn_list *list2;
	TDB_DATA key;

	list->dn = NULL;
	list->count = 0;

	/* see if we have any in-memory index entries */
	if (ltdb->idxptr == NULL ||
	    ltdb->idxptr->itdb == NULL) {
		goto normal_index;
	}

	key.dptr = discard_const_p(unsigned char, ldb_dn_get_linearized(dn));
	key.dsize = strlen((char *)key.dptr);

	rec = tdb_fetch(ltdb->idxptr->itdb, key);
	if (rec.dptr == NULL) {
		goto normal_index;
	}

	/* we've found an in-memory index entry */
	list2 = ltdb_index_idxptr(module, rec, true);
	if (list2 == NULL) {
		free(rec.dptr);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	free(rec.dptr);

	*list = *list2;
	return LDB_SUCCESS;

normal_index:
	msg = ldb_msg_new(list);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_search_dn1(module, dn, msg,
			      LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC
			      |LDB_UNPACK_DATA_FLAG_NO_DN);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return ret;
	}

	el = ldb_msg_find_element(msg, LTDB_IDX);
	if (!el) {
		talloc_free(msg);
		return LDB_SUCCESS;
	}

	version = ldb_msg_find_attr_as_int(msg, LTDB_IDXVERSION, 0);

	/*
	 * we avoid copying the strings by stealing the list.  We have
	 * to steal msg onto el->values (which looks odd) because we
	 * asked for the memory to be allocated on msg, not on each
	 * value with LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC above
	 */
	if (ltdb->cache->GUID_index_attribute == NULL) {
		/* check indexing version number */
		if (version != LTDB_INDEXING_VERSION) {
			ldb_debug_set(ldb_module_get_ctx(module),
				      LDB_DEBUG_ERROR,
				      "Wrong DN index version %d "
				      "expected %d for %s",
				      version, LTDB_INDEXING_VERSION,
				      ldb_dn_get_linearized(dn));
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		talloc_steal(el->values, msg);
		list->dn = talloc_steal(list, el->values);
		list->count = el->num_values;
	} else {
		unsigned int i;
		if (version != LTDB_GUID_INDEXING_VERSION) {
			/* This is quite likely during the DB startup
			   on first upgrade to using a GUID index */
			ldb_debug_set(ldb_module_get_ctx(module),
				      LDB_DEBUG_ERROR,
				      "Wrong GUID index version %d "
				      "expected %d for %s",
				      version, LTDB_GUID_INDEXING_VERSION,
				      ldb_dn_get_linearized(dn));
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (el->num_values != 1) {
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if ((el->values[0].length % LTDB_GUID_SIZE) != 0) {
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		list->count = el->values[0].length / LTDB_GUID_SIZE;
		list->dn = talloc_array(list, struct ldb_val, list->count);
		if (list->dn == NULL) {
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/*
		 * The actual data is on msg, due to
		 * LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC
		 */
		talloc_steal(list->dn, msg);
		for (i = 0; i < list->count; i++) {
			list->dn[i].data
				= &el->values[0].data[i * LTDB_GUID_SIZE];
			list->dn[i].length = LTDB_GUID_SIZE;
		}
	}

	/* We don't need msg->elements any more */
	talloc_free(msg->elements);
	return LDB_SUCCESS;
}

int ltdb_key_dn_from_idx(struct ldb_module *module,
			 struct ltdb_private *ltdb,
			 TALLOC_CTX *mem_ctx,
			 struct ldb_dn *dn,
			 TDB_DATA *tdb_key)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret;
	struct dn_list *list = talloc(mem_ctx, struct dn_list);
	if (list == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_index_dn_base_dn(module, ltdb, dn, list);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(list);
		return ret;
	}

	if (list->count == 0) {
		TALLOC_FREE(list);
		return LDB_ERR_NO_SUCH_OBJECT;
	}
	if (list->count > 1) {
		const char *dn_str = ldb_dn_get_linearized(dn);
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       __location__
				       ": Failed to read DN index "
				       "against %s for %s: too many "
				       "values (%u > 1)",
				       ltdb->cache->GUID_index_attribute,
				       dn_str, list->count);
		TALLOC_FREE(list);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* The tdb_key memory is allocated by the caller */
	ret = ltdb_guid_to_key(module, ltdb,
			       &list->dn[0], tdb_key);
	TALLOC_FREE(list);

	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}



/*
  save a dn_list into a full @IDX style record
 */
static int ltdb_dn_list_store_full(struct ldb_module *module,
				   struct ltdb_private *ltdb,
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
		ret = ltdb_delete_noindex(module, msg);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			ret = LDB_SUCCESS;
		}
		talloc_free(msg);
		return ret;
	}

	if (ltdb->cache->GUID_index_attribute == NULL) {
		ret = ldb_msg_add_fmt(msg, LTDB_IDXVERSION, "%u",
				      LTDB_INDEXING_VERSION);
		if (ret != LDB_SUCCESS) {
			talloc_free(msg);
			return ldb_module_oom(module);
		}
	} else {
		ret = ldb_msg_add_fmt(msg, LTDB_IDXVERSION, "%u",
				      LTDB_GUID_INDEXING_VERSION);
		if (ret != LDB_SUCCESS) {
			talloc_free(msg);
			return ldb_module_oom(module);
		}
	}

	if (list->count > 0) {
		struct ldb_message_element *el;

		ret = ldb_msg_add_empty(msg, LTDB_IDX, LDB_FLAG_MOD_ADD, &el);
		if (ret != LDB_SUCCESS) {
			talloc_free(msg);
			return ldb_module_oom(module);
		}

		if (ltdb->cache->GUID_index_attribute == NULL) {
			el->values = list->dn;
			el->num_values = list->count;
		} else {
			struct ldb_val v;
			unsigned int i;
			el->values = talloc_array(msg,
						  struct ldb_val, 1);
			if (el->values == NULL) {
				talloc_free(msg);
				return ldb_module_oom(module);
			}

			v.data = talloc_array_size(el->values,
						   list->count,
						   LTDB_GUID_SIZE);
			if (v.data == NULL) {
				talloc_free(msg);
				return ldb_module_oom(module);
			}

			v.length = talloc_get_size(v.data);

			for (i = 0; i < list->count; i++) {
				if (list->dn[i].length !=
				    LTDB_GUID_SIZE) {
					talloc_free(msg);
					return ldb_module_operr(module);
				}
				memcpy(&v.data[LTDB_GUID_SIZE*i],
				       list->dn[i].data,
				       LTDB_GUID_SIZE);
			}
			el->values[0] = v;
			el->num_values = 1;
		}
	}

	ret = ltdb_store(module, msg, TDB_REPLACE);
	talloc_free(msg);
	return ret;
}

/*
  save a dn_list into the database, in either @IDX or internal format
 */
static int ltdb_dn_list_store(struct ldb_module *module, struct ldb_dn *dn,
			      struct dn_list *list)
{
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);
	TDB_DATA rec, key;
	int ret;
	struct dn_list *list2;

	if (ltdb->idxptr == NULL) {
		return ltdb_dn_list_store_full(module, ltdb,
					       dn, list);
	}

	if (ltdb->idxptr->itdb == NULL) {
		ltdb->idxptr->itdb = tdb_open(NULL, 1000, TDB_INTERNAL, O_RDWR, 0);
		if (ltdb->idxptr->itdb == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	key.dptr = discard_const_p(unsigned char, ldb_dn_get_linearized(dn));
	if (key.dptr == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	key.dsize = strlen((char *)key.dptr);

	rec = tdb_fetch(ltdb->idxptr->itdb, key);
	if (rec.dptr != NULL) {
		list2 = ltdb_index_idxptr(module, rec, false);
		if (list2 == NULL) {
			free(rec.dptr);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		free(rec.dptr);
		list2->dn = talloc_steal(list2, list->dn);
		list2->count = list->count;
		return LDB_SUCCESS;
	}

	list2 = talloc(ltdb->idxptr, struct dn_list);
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
	 */
	ret = tdb_store(ltdb->idxptr->itdb, key, rec, TDB_INSERT);
	if (ret != 0) {
		return ltdb_err_map(tdb_error(ltdb->idxptr->itdb));
	}
	return LDB_SUCCESS;
}

/*
  traverse function for storing the in-memory index entries on disk
 */
static int ltdb_index_traverse_store(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	struct ldb_module *module = state;
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);
	struct ldb_dn *dn;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_val v;
	struct dn_list *list;

	list = ltdb_index_idxptr(module, data, true);
	if (list == NULL) {
		ltdb->idxptr->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	v.data = key.dptr;
	v.length = strnlen((char *)key.dptr, key.dsize);

	dn = ldb_dn_from_ldb_val(module, ldb, &v);
	if (dn == NULL) {
		ldb_asprintf_errstring(ldb, "Failed to parse index key %*.*s as an LDB DN", (int)v.length, (int)v.length, (const char *)v.data);
		ltdb->idxptr->error = LDB_ERR_OPERATIONS_ERROR;
		return -1;
	}

	ltdb->idxptr->error = ltdb_dn_list_store_full(module, ltdb,
						      dn, list);
	talloc_free(dn);
	if (ltdb->idxptr->error != 0) {
		return -1;
	}
	return 0;
}

/* cleanup the idxptr mode when transaction commits */
int ltdb_index_transaction_commit(struct ldb_module *module)
{
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);
	int ret;

	struct ldb_context *ldb = ldb_module_get_ctx(module);

	ldb_reset_err_string(ldb);

	if (ltdb->idxptr->itdb) {
		tdb_traverse(ltdb->idxptr->itdb, ltdb_index_traverse_store, module);
		tdb_close(ltdb->idxptr->itdb);
	}

	ret = ltdb->idxptr->error;
	if (ret != LDB_SUCCESS) {
		if (!ldb_errstring(ldb)) {
			ldb_set_errstring(ldb, ldb_strerror(ret));
		}
		ldb_asprintf_errstring(ldb, "Failed to store index records in transaction commit: %s", ldb_errstring(ldb));
	}

	talloc_free(ltdb->idxptr);
	ltdb->idxptr = NULL;
	return ret;
}

/* cleanup the idxptr mode when transaction cancels */
int ltdb_index_transaction_cancel(struct ldb_module *module)
{
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);
	if (ltdb->idxptr && ltdb->idxptr->itdb) {
		tdb_close(ltdb->idxptr->itdb);
	}
	talloc_free(ltdb->idxptr);
	ltdb->idxptr = NULL;
	return LDB_SUCCESS;
}


/*
  return the dn key to be used for an index
  the caller is responsible for freeing
*/
static struct ldb_dn *ltdb_index_key(struct ldb_context *ldb,
				     struct ltdb_private *ltdb,
				     const char *attr, const struct ldb_val *value,
				     const struct ldb_schema_attribute **ap)
{
	struct ldb_dn *ret;
	struct ldb_val v;
	const struct ldb_schema_attribute *a = NULL;
	char *attr_folded = NULL;
	const char *attr_for_dn = NULL;
	int r;
	bool should_b64_encode;

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
		r = a->syntax->canonicalise_fn(ldb, ldb, value, &v);
		if (r != LDB_SUCCESS) {
			const char *errstr = ldb_errstring(ldb);
			/* canonicalisation can be refused. For
			   example, a attribute that takes wildcards
			   will refuse to canonicalise if the value
			   contains a wildcard */
			ldb_asprintf_errstring(ldb,
					       "Failed to create index "
					       "key for attribute '%s':%s%s%s",
					       attr, ldb_strerror(r),
					       (errstr?":":""),
					       (errstr?errstr:""));
			talloc_free(attr_folded);
			return NULL;
		}
	}

	/*
	 * We do not base 64 encode a DN in a key, it has already been
	 * casefold and lineraized, that is good enough.  That already
	 * avoids embedded NUL etc.
	 */
	if (ltdb->cache->GUID_index_attribute != NULL) {
		if (strcmp(attr, LTDB_IDXDN) == 0) {
			should_b64_encode = false;
		} else if (strcmp(attr, LTDB_IDXONE) == 0) {
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
		char *vstr = ldb_base64_encode(ldb, (char *)v.data, v.length);
		if (!vstr) {
			talloc_free(attr_folded);
			return NULL;
		}
		ret = ldb_dn_new_fmt(ldb, ldb, "%s:%s::%s", LTDB_INDEX,
				     attr_for_dn, vstr);
		talloc_free(vstr);
	} else {
		ret = ldb_dn_new_fmt(ldb, ldb, "%s:%s:%.*s", LTDB_INDEX,
				     attr_for_dn,
				     (int)v.length, (char *)v.data);
	}

	if (v.data != value->data) {
		talloc_free(v.data);
	}
	talloc_free(attr_folded);

	return ret;
}

/*
  see if a attribute value is in the list of indexed attributes
*/
static bool ltdb_is_indexed(struct ldb_module *module,
			    struct ltdb_private *ltdb,
			    const char *attr)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	unsigned int i;
	struct ldb_message_element *el;

	if ((ltdb->cache->GUID_index_attribute != NULL) &&
	    (ldb_attr_cmp(attr,
			  ltdb->cache->GUID_index_attribute) == 0)) {
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

	if (!ltdb->cache->attribute_indexes) {
		return false;
	}

	el = ldb_msg_find_element(ltdb->cache->indexlist, LTDB_IDXATTR);
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
static int ltdb_index_dn_simple(struct ldb_module *module,
				struct ltdb_private *ltdb,
				const struct ldb_parse_tree *tree,
				struct dn_list *list)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn;
	int ret;

	ldb = ldb_module_get_ctx(module);

	list->count = 0;
	list->dn = NULL;

	/* if the attribute isn't in the list of indexed attributes then
	   this node needs a full search */
	if (!ltdb_is_indexed(module, ltdb, tree->u.equality.attr)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* the attribute is indexed. Pull the list of DNs that match the
	   search criterion */
	dn = ltdb_index_key(ldb, ltdb,
			    tree->u.equality.attr,
			    &tree->u.equality.value, NULL);
	if (!dn) return LDB_ERR_OPERATIONS_ERROR;

	ret = ltdb_dn_list_load(module, ltdb, dn, list);
	talloc_free(dn);
	return ret;
}


static bool list_union(struct ldb_context *ldb,
		       struct ltdb_private *ltdb,
		       struct dn_list *list, struct dn_list *list2);

/*
  return a list of dn's that might match a leaf indexed search
 */
static int ltdb_index_dn_leaf(struct ldb_module *module,
			      struct ltdb_private *ltdb,
			      const struct ldb_parse_tree *tree,
			      struct dn_list *list)
{
	if (ltdb->disallow_dn_filter &&
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
		return ltdb_index_dn_base_dn(module, ltdb, dn, list);

	} else if ((ltdb->cache->GUID_index_attribute != NULL) &&
		   (ldb_attr_cmp(tree->u.equality.attr,
				 ltdb->cache->GUID_index_attribute) == 0)) {
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
		ret = ltdb->GUID_index_syntax->canonicalise_fn(ldb,
							       list->dn,
							       &tree->u.equality.value,
							       &list->dn[0]);
		if (ret != LDB_SUCCESS) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		list->count = 1;
		return LDB_SUCCESS;
	}

	return ltdb_index_dn_simple(module, ltdb, tree, list);
}


/*
  list intersection
  list = list & list2
*/
static bool list_intersect(struct ldb_context *ldb,
			   struct ltdb_private *ltdb,
			   struct dn_list *list, const struct dn_list *list2)
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
		if (ltdb_dn_list_find_val(ltdb, long_list,
					  &short_list->dn[i]) != -1) {
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
		       struct ltdb_private *ltdb,
		       struct dn_list *list, struct dn_list *list2)
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
	ltdb_dn_list_sort(ltdb, list);
	ltdb_dn_list_sort(ltdb, list2);

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

static int ltdb_index_dn(struct ldb_module *module,
			 struct ltdb_private *ltdb,
			 const struct ldb_parse_tree *tree,
			 struct dn_list *list);


/*
  process an OR list (a union)
 */
static int ltdb_index_dn_or(struct ldb_module *module,
			    struct ltdb_private *ltdb,
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

		ret = ltdb_index_dn(module, ltdb,
				    tree->u.list.elements[i], list2);

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

		if (!list_union(ldb, ltdb, list, list2)) {
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
static int ltdb_index_dn_not(struct ldb_module *module,
			     struct ltdb_private *ltdb,
			     const struct ldb_parse_tree *tree,
			     struct dn_list *list)
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
static bool ltdb_index_unique(struct ldb_context *ldb,
			      struct ltdb_private *ltdb,
			      const char *attr)
{
	const struct ldb_schema_attribute *a;
	if (ltdb->cache->GUID_index_attribute != NULL) {
		if (ldb_attr_cmp(attr, ltdb->cache->GUID_index_attribute) == 0) {
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
static int ltdb_index_dn_and(struct ldb_module *module,
			     struct ltdb_private *ltdb,
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
		    !ltdb_index_unique(ldb, ltdb,
				       subtree->u.equality.attr)) {
			continue;
		}

		ret = ltdb_index_dn(module, ltdb, subtree, list);
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

		ret = ltdb_index_dn(module, ltdb, subtree, list2);

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
		} else if (!list_intersect(ldb, ltdb,
					   list, list2)) {
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

/*
  return a list of matching objects using a one-level index
 */
static int ltdb_index_dn_attr(struct ldb_module *module,
			      struct ltdb_private *ltdb,
			      const char *attr,
			      struct ldb_dn *dn,
			      struct dn_list *list)
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
	key = ltdb_index_key(ldb, ltdb, attr, &val, NULL);
	if (!key) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_dn_list_load(module, ltdb, key, list);
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
static int ltdb_index_dn_one(struct ldb_module *module,
			     struct ltdb_private *ltdb,
			     struct ldb_dn *parent_dn,
			     struct dn_list *list)
{
	/* Ensure we do not shortcut on intersection for this list */
	list->strict = true;
	return ltdb_index_dn_attr(module, ltdb,
				  LTDB_IDXONE, parent_dn, list);
}

/*
  return a list of matching objects using the DN index
 */
static int ltdb_index_dn_base_dn(struct ldb_module *module,
				 struct ltdb_private *ltdb,
				 struct ldb_dn *base_dn,
				 struct dn_list *dn_list)
{
	const struct ldb_val *guid_val = NULL;
	if (ltdb->cache->GUID_index_attribute == NULL) {
		dn_list->dn = talloc_array(dn_list, struct ldb_val, 1);
		if (dn_list->dn == NULL) {
			return ldb_module_oom(module);
		}
		dn_list->dn[0].data = discard_const_p(unsigned char,
						      ldb_dn_get_linearized(base_dn));
		if (dn_list->dn[0].data == NULL) {
			return ldb_module_oom(module);
		}
		dn_list->dn[0].length = strlen((char *)dn_list->dn[0].data);
		dn_list->count = 1;

		return LDB_SUCCESS;
	}

	if (ltdb->cache->GUID_index_dn_component != NULL) {
		guid_val = ldb_dn_get_extended_component(base_dn,
							 ltdb->cache->GUID_index_dn_component);
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

	return ltdb_index_dn_attr(module, ltdb,
				  LTDB_IDXDN, base_dn, dn_list);
}

/*
  return a list of dn's that might match a indexed search or
  an error. return LDB_ERR_NO_SUCH_OBJECT for no matches, or LDB_SUCCESS for matches
 */
static int ltdb_index_dn(struct ldb_module *module,
			 struct ltdb_private *ltdb,
			 const struct ldb_parse_tree *tree,
			 struct dn_list *list)
{
	int ret = LDB_ERR_OPERATIONS_ERROR;

	switch (tree->operation) {
	case LDB_OP_AND:
		ret = ltdb_index_dn_and(module, ltdb, tree, list);
		break;

	case LDB_OP_OR:
		ret = ltdb_index_dn_or(module, ltdb, tree, list);
		break;

	case LDB_OP_NOT:
		ret = ltdb_index_dn_not(module, ltdb, tree, list);
		break;

	case LDB_OP_EQUALITY:
		ret = ltdb_index_dn_leaf(module, ltdb, tree, list);
		break;

	case LDB_OP_SUBSTRING:
	case LDB_OP_GREATER:
	case LDB_OP_LESS:
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
static int ltdb_index_filter(struct ltdb_private *ltdb,
			     const struct dn_list *dn_list,
			     struct ltdb_context *ac,
			     uint32_t *match_count)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_message *msg;
	struct ldb_message *filtered_msg;
	unsigned int i;
	unsigned int num_keys = 0;
	uint8_t previous_guid_key[LTDB_GUID_KEY_SIZE] = {};
	TDB_DATA *keys = NULL;

	/*
	 * We have to allocate the key list (rather than just walk the
	 * caller supplied list) as the callback could change the list
	 * (by modifying an indexed attribute hosted in the in-memory
	 * index cache!)
	 */
	keys = talloc_array(ac, TDB_DATA, dn_list->count);
	if (keys == NULL) {
		return ldb_module_oom(ac->module);
	}

	if (ltdb->cache->GUID_index_attribute != NULL) {
		/*
		 * We speculate that the keys will be GUID based and so
		 * pre-fill in enough space for a GUID (avoiding a pile of
		 * small allocations)
		 */
		struct guid_tdb_key {
			uint8_t guid_key[LTDB_GUID_KEY_SIZE];
		} *key_values = NULL;

		key_values = talloc_array(keys,
					  struct guid_tdb_key,
					  dn_list->count);

		if (key_values == NULL) {
			talloc_free(keys);
			return ldb_module_oom(ac->module);
		}
		for (i = 0; i < dn_list->count; i++) {
			keys[i].dptr = key_values[i].guid_key;
			keys[i].dsize = sizeof(key_values[i].guid_key);
		}
	} else {
		for (i = 0; i < dn_list->count; i++) {
			keys[i].dptr = NULL;
			keys[i].dsize = 0;
		}
	}

	for (i = 0; i < dn_list->count; i++) {
		int ret;

		ret = ltdb_idx_to_key(ac->module,
				      ltdb,
				      keys,
				      &dn_list->dn[i],
				      &keys[num_keys]);
		if (ret != LDB_SUCCESS) {
			talloc_free(keys);
			return ret;
		}

		if (ltdb->cache->GUID_index_attribute != NULL) {
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
				   keys[num_keys].dptr,
				   sizeof(previous_guid_key)) == 0) {
				continue;
			}

			memcpy(previous_guid_key,
			       keys[num_keys].dptr,
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

		ret = ltdb_search_key(ac->module, ltdb,
				      keys[i], msg,
				      LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC|
				      LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC);
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

		/* We trust the index for SCOPE_ONELEVEL and SCOPE_BASE */
		if ((ac->scope == LDB_SCOPE_ONELEVEL
		     && ltdb->cache->one_level_indexes)
		    || ac->scope == LDB_SCOPE_BASE) {
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

		/* filter the attributes that the user wants */
		ret = ltdb_filter_attrs(ac, msg, ac->attrs, &filtered_msg);

		talloc_free(msg);

		if (ret == -1) {
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
static void ltdb_dn_list_sort(struct ltdb_private *ltdb,
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
int ltdb_search_indexed(struct ltdb_context *ac, uint32_t *match_count)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(ac->module), struct ltdb_private);
	struct dn_list *dn_list;
	int ret;
	enum ldb_scope index_scope;

	/* see if indexing is enabled */
	if (!ltdb->cache->attribute_indexes &&
	    !ltdb->cache->one_level_indexes &&
	    ac->scope != LDB_SCOPE_BASE) {
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
	    !ltdb->cache->one_level_indexes) {
		index_scope = LDB_SCOPE_SUBTREE;
	} else {
		index_scope = ac->scope;
	}

	switch (index_scope) {
	case LDB_SCOPE_BASE:
		/*
		 * If we ever start to also load the index values for
		 * the tree, we must ensure we strictly intersect with
		 * this list, as we trust the BASE index
		 */
		ret = ltdb_index_dn_base_dn(ac->module, ltdb,
					    ac->base, dn_list);
		if (ret != LDB_SUCCESS) {
			talloc_free(dn_list);
			return ret;
		}
		break;

	case LDB_SCOPE_ONELEVEL:
		/*
		 * If we ever start to also load the index values for
		 * the tree, we must ensure we strictly intersect with
		 * this list, as we trust the ONELEVEL index
		 */
		ret = ltdb_index_dn_one(ac->module, ltdb, ac->base, dn_list);
		if (ret != LDB_SUCCESS) {
			talloc_free(dn_list);
			return ret;
		}

		/*
		 * If we have too many matches, running the filter
		 * tree over the SCOPE_ONELEVEL can be quite expensive
		 * so we now check the filter tree index as well.
		 *
		 * We only do this in the GUID index mode, which is
		 * O(n*log(m)) otherwise the intersection below will
		 * be too costly at O(n*m).
		 *
		 * We don't set a heuristic for 'too many' but instead
		 * do it always and rely on the index lookup being
		 * fast enough in the small case.
		 */
		if (ltdb->cache->GUID_index_attribute != NULL) {
			struct dn_list *idx_one_tree_list
				= talloc_zero(ac, struct dn_list);
			if (idx_one_tree_list == NULL) {
				return ldb_module_oom(ac->module);
			}

			if (!ltdb->cache->attribute_indexes) {
				talloc_free(idx_one_tree_list);
				talloc_free(dn_list);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			/*
			 * Here we load the index for the tree.
			 *
			 * We only care if this is successful, if the
			 * index can't trim the result list down then
			 * the ONELEVEL index is still good enough.
			 */
			ret = ltdb_index_dn(ac->module, ltdb, ac->tree,
					    idx_one_tree_list);
			if (ret == LDB_SUCCESS) {
				if (!list_intersect(ldb, ltdb,
						    dn_list,
						    idx_one_tree_list)) {
					talloc_free(idx_one_tree_list);
					talloc_free(dn_list);
					return LDB_ERR_OPERATIONS_ERROR;
				}
			}
		}
		break;

	case LDB_SCOPE_SUBTREE:
	case LDB_SCOPE_DEFAULT:
		if (!ltdb->cache->attribute_indexes) {
			talloc_free(dn_list);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		/*
		 * Here we load the index for the tree.  We have no
		 * index for the subtree.
		 */
		ret = ltdb_index_dn(ac->module, ltdb, ac->tree, dn_list);
		if (ret != LDB_SUCCESS) {
			talloc_free(dn_list);
			return ret;
		}
		break;
	}

	ret = ltdb_index_filter(ltdb, dn_list, ac, match_count);
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
static int ltdb_index_add1(struct ldb_module *module,
			   struct ltdb_private *ltdb,
			   const struct ldb_message *msg,
			   struct ldb_message_element *el, int v_idx)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn_key;
	int ret;
	const struct ldb_schema_attribute *a;
	struct dn_list *list;
	unsigned alloc_len;

	ldb = ldb_module_get_ctx(module);

	list = talloc_zero(module, struct dn_list);
	if (list == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dn_key = ltdb_index_key(ldb, ltdb,
				el->name, &el->values[v_idx], &a);
	if (!dn_key) {
		talloc_free(list);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	talloc_steal(list, dn_key);

	ret = ltdb_dn_list_load(module, ltdb, dn_key, list);
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
	    ldb_attr_cmp(el->name, LTDB_IDXDN) == 0) {
		talloc_free(list);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/*
	 * Check for duplicates in unique indexes
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

		if (ltdb->cache->GUID_index_attribute == NULL) {
			ldb_debug(ldb, LDB_DEBUG_WARNING,
				  __location__
				  ": unique index violation on %s in %s, "
				  "conficts with %*.*s in %s",
				  el->name, ldb_dn_get_linearized(msg->dn),
				  (int)list->dn[0].length,
				  (int)list->dn[0].length,
				  list->dn[0].data,
				  ldb_dn_get_linearized(dn_key));
		} else {
			/* This can't fail, gives a default at worst */
			const struct ldb_schema_attribute *attr
				= ldb_schema_attribute_by_name(
					ldb,
					ltdb->cache->GUID_index_attribute);
			struct ldb_val v;
			ret = attr->syntax->ldif_write_fn(ldb, list,
							  &list->dn[0], &v);
			if (ret == LDB_SUCCESS) {
				ldb_debug(ldb, LDB_DEBUG_WARNING,
					  __location__
					  ": unique index violation on %s in "
					  "%s, conficts with %s %*.*s in %s",
					  el->name,
					  ldb_dn_get_linearized(msg->dn),
					  ltdb->cache->GUID_index_attribute,
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

	if (ltdb->cache->GUID_index_attribute == NULL) {
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
		key_val = ldb_msg_find_ldb_val(msg,
					       ltdb->cache->GUID_index_attribute);
		if (key_val == NULL) {
			talloc_free(list);
			return ldb_module_operr(module);
		}

		if (key_val->length != LTDB_GUID_SIZE) {
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
		if (exact != NULL) {
			/* This can't fail, gives a default at worst */
			const struct ldb_schema_attribute *attr
				= ldb_schema_attribute_by_name(
					ldb,
					ltdb->cache->GUID_index_attribute);
			struct ldb_val v;
			ret = attr->syntax->ldif_write_fn(ldb, list,
							  exact, &v);
			if (ret == LDB_SUCCESS) {
				ldb_debug(ldb, LDB_DEBUG_WARNING,
					  __location__
					  ": duplicate attribute value in %s "
					  "for index on %s, "
					  "duplicate of %s %*.*s in %s",
					  ldb_dn_get_linearized(msg->dn),
					  el->name,
					  ltdb->cache->GUID_index_attribute,
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

	ret = ltdb_dn_list_store(module, dn_key, list);

	talloc_free(list);

	return ret;
}

/*
  add index entries for one elements in a message
 */
static int ltdb_index_add_el(struct ldb_module *module,
			     struct ltdb_private *ltdb,
			     const struct ldb_message *msg,
			     struct ldb_message_element *el)
{
	unsigned int i;
	for (i = 0; i < el->num_values; i++) {
		int ret = ltdb_index_add1(module, ltdb,
					  msg, el, i);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

/*
  add index entries for all elements in a message
 */
static int ltdb_index_add_all(struct ldb_module *module,
			      struct ltdb_private *ltdb,
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

	ret = ltdb_write_index_dn_guid(module, msg, 1);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!ltdb->cache->attribute_indexes) {
		/* no indexed fields */
		return LDB_SUCCESS;
	}

	for (i = 0; i < msg->num_elements; i++) {
		if (!ltdb_is_indexed(module, ltdb, elements[i].name)) {
			continue;
		}
		ret = ltdb_index_add_el(module, ltdb,
					msg, &elements[i]);
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
static int ltdb_modify_index_dn(struct ldb_module *module,
				struct ltdb_private *ltdb,
				const struct ldb_message *msg,
				struct ldb_dn *dn,
				const char *index, int add)
{
	struct ldb_message_element el;
	struct ldb_val val;
	int ret;

	val.data = (uint8_t *)((uintptr_t)ldb_dn_get_casefold(dn));
	if (val.data == NULL) {
		const char *dn_str = ldb_dn_get_linearized(dn);
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       __location__
				       ": Failed to modify %s "
				       "against %s in %s: failed "
				       "to get casefold DN",
				       index,
				       ltdb->cache->GUID_index_attribute,
				       dn_str);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	val.length = strlen((char *)val.data);
	el.name = index;
	el.values = &val;
	el.num_values = 1;

	if (add) {
		ret = ltdb_index_add1(module, ltdb, msg, &el, 0);
	} else { /* delete */
		ret = ltdb_index_del_value(module, ltdb, msg, &el, 0);
	}

	if (ret != LDB_SUCCESS) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		const char *dn_str = ldb_dn_get_linearized(dn);
		ldb_asprintf_errstring(ldb,
				       __location__
				       ": Failed to modify %s "
				       "against %s in %s - %s",
				       index,
				       ltdb->cache->GUID_index_attribute,
				       dn_str, ldb_errstring(ldb));
		return ret;
	}
	return ret;
}

/*
  insert a one level index for a message
*/
static int ltdb_index_onelevel(struct ldb_module *module,
			       const struct ldb_message *msg, int add)
{
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module),
						    struct ltdb_private);
	struct ldb_dn *pdn;
	int ret;

	/* We index for ONE Level only if requested */
	if (!ltdb->cache->one_level_indexes) {
		return LDB_SUCCESS;
	}

	pdn = ldb_dn_get_parent(module, msg->dn);
	if (pdn == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ltdb_modify_index_dn(module, ltdb,
				   msg, pdn, LTDB_IDXONE, add);

	talloc_free(pdn);

	return ret;
}

/*
  insert a one level index for a message
*/
static int ltdb_write_index_dn_guid(struct ldb_module *module,
				    const struct ldb_message *msg,
				    int add)
{
	int ret;
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module),
						    struct ltdb_private);

	/* We index for DN only if using a GUID index */
	if (ltdb->cache->GUID_index_attribute == NULL) {
		return LDB_SUCCESS;
	}

	ret = ltdb_modify_index_dn(module, ltdb, msg, msg->dn,
				   LTDB_IDXDN, add);

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
int ltdb_index_add_element(struct ldb_module *module,
			   struct ltdb_private *ltdb,
			   const struct ldb_message *msg,
			   struct ldb_message_element *el)
{
	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}
	if (!ltdb_is_indexed(module, ltdb, el->name)) {
		return LDB_SUCCESS;
	}
	return ltdb_index_add_el(module, ltdb, msg, el);
}

/*
  add the index entries for a new record
*/
int ltdb_index_add_new(struct ldb_module *module,
		       struct ltdb_private *ltdb,
		       const struct ldb_message *msg)
{
	int ret;

	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	ret = ltdb_index_add_all(module, ltdb, msg);
	if (ret != LDB_SUCCESS) {
		/*
		 * Because we can't trust the caller to be doing
		 * transactions properly, clean up any index for this
		 * entry rather than relying on a transaction
		 * cleanup
		 */

		ltdb_index_delete(module, msg);
		return ret;
	}

	ret = ltdb_index_onelevel(module, msg, 1);
	if (ret != LDB_SUCCESS) {
		/*
		 * Because we can't trust the caller to be doing
		 * transactions properly, clean up any index for this
		 * entry rather than relying on a transaction
		 * cleanup
		 */
		ltdb_index_delete(module, msg);
		return ret;
	}
	return ret;
}


/*
  delete an index entry for one message element
*/
int ltdb_index_del_value(struct ldb_module *module,
			 struct ltdb_private *ltdb,
			 const struct ldb_message *msg,
			 struct ldb_message_element *el, unsigned int v_idx)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn_key;
	const char *dn_str;
	int ret, i;
	unsigned int j;
	struct dn_list *list;
	struct ldb_dn *dn = msg->dn;

	ldb = ldb_module_get_ctx(module);

	dn_str = ldb_dn_get_linearized(dn);
	if (dn_str == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (dn_str[0] == '@') {
		return LDB_SUCCESS;
	}

	dn_key = ltdb_index_key(ldb, ltdb,
				el->name, &el->values[v_idx], NULL);
	if (!dn_key) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	list = talloc_zero(dn_key, struct dn_list);
	if (list == NULL) {
		talloc_free(dn_key);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ltdb_dn_list_load(module, ltdb, dn_key, list);
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

	i = ltdb_dn_list_find_msg(ltdb, list, msg);
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

	ret = ltdb_dn_list_store(module, dn_key, list);

	talloc_free(dn_key);

	return ret;
}

/*
  delete the index entries for a element
  return -1 on failure
*/
int ltdb_index_del_element(struct ldb_module *module,
			   struct ltdb_private *ltdb,
			   const struct ldb_message *msg,
			   struct ldb_message_element *el)
{
	const char *dn_str;
	int ret;
	unsigned int i;

	if (!ltdb->cache->attribute_indexes) {
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

	if (!ltdb_is_indexed(module, ltdb, el->name)) {
		return LDB_SUCCESS;
	}
	for (i = 0; i < el->num_values; i++) {
		ret = ltdb_index_del_value(module, ltdb, msg, el, i);
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
int ltdb_index_delete(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);
	int ret;
	unsigned int i;

	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	ret = ltdb_index_onelevel(module, msg, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ltdb_write_index_dn_guid(module, msg, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!ltdb->cache->attribute_indexes) {
		/* no indexed fields */
		return LDB_SUCCESS;
	}

	for (i = 0; i < msg->num_elements; i++) {
		ret = ltdb_index_del_element(module, ltdb,
					     msg, &msg->elements[i]);
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
static int delete_index(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	struct ldb_module *module = state;
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);
	const char *dnstr = "DN=" LTDB_INDEX ":";
	struct dn_list list;
	struct ldb_dn *dn;
	struct ldb_val v;
	int ret;

	if (strncmp((char *)key.dptr, dnstr, strlen(dnstr)) != 0) {
		return 0;
	}
	/* we need to put a empty list in the internal tdb for this
	 * index entry */
	list.dn = NULL;
	list.count = 0;

	/* the offset of 3 is to remove the DN= prefix. */
	v.data = key.dptr + 3;
	v.length = strnlen((char *)key.dptr, key.dsize) - 3;

	dn = ldb_dn_from_ldb_val(ltdb, ldb_module_get_ctx(module), &v);

	/*
	 * This does not actually touch the DB quite yet, just
         * the in-memory index cache
	 */
	ret = ltdb_dn_list_store(module, dn, &list);
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

struct ltdb_reindex_context {
	struct ldb_module *module;
	int error;
	uint32_t count;
};

/*
  traversal function that adds @INDEX records during a re index
*/
static int re_key(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	struct ldb_context *ldb;
	struct ltdb_reindex_context *ctx = (struct ltdb_reindex_context *)state;
	struct ldb_module *module = ctx->module;
	struct ldb_message *msg;
	unsigned int nb_elements_in_db;
	const struct ldb_val val = {
		.data = data.dptr,
		.length = data.dsize,
	};
	int ret;
	TDB_DATA key2;
	bool is_record;
	
	ldb = ldb_module_get_ctx(module);

	if (key.dsize > 4 &&
	    memcmp(key.dptr, "DN=@", 4) == 0) {
		return 0;
	}

	is_record = ltdb_key_is_record(key);
	if (is_record == false) {
		return 0;
	}
	
	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return -1;
	}

	ret = ldb_unpack_data_only_attr_list_flags(ldb, &val,
						   msg,
						   NULL, 0,
						   LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC,
						   &nb_elements_in_db);
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
			  (int)key.dsize, (int)key.dsize,
			  (char *)key.dptr);
		talloc_free(msg);
		return -1;
	}
	
	/* check if the DN key has changed, perhaps due to the case
	   insensitivity of an element changing, or a change from DN
	   to GUID keys */
	key2 = ltdb_key_msg(module, msg, msg);
	if (key2.dptr == NULL) {
		/* probably a corrupt record ... darn */
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid DN in re_index: %s",
						ldb_dn_get_linearized(msg->dn));
		talloc_free(msg);
		return 0;
	}
	if (key.dsize != key2.dsize ||
	    (memcmp(key.dptr, key2.dptr, key.dsize) != 0)) {
		int tdb_ret;
		tdb_ret = tdb_delete(tdb, key);
		if (tdb_ret != 0) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Failed to delete %*.*s "
				  "for rekey as %*.*s: %s",
				  (int)key.dsize, (int)key.dsize,
				  (const char *)key.dptr,
				  (int)key2.dsize, (int)key2.dsize,
				  (const char *)key.dptr,
				  tdb_errorstr(tdb));
			ctx->error = ltdb_err_map(tdb_error(tdb));
			return -1;
		}
		tdb_ret = tdb_store(tdb, key2, data, 0);
		if (tdb_ret != 0) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Failed to rekey %*.*s as %*.*s: %s",
				  (int)key.dsize, (int)key.dsize,
				  (const char *)key.dptr,
				  (int)key2.dsize, (int)key2.dsize,
				  (const char *)key.dptr,
				  tdb_errorstr(tdb));
			ctx->error = ltdb_err_map(tdb_error(tdb));
			return -1;
		}
	}
	talloc_free(key2.dptr);

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
static int re_index(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	struct ldb_context *ldb;
	struct ltdb_reindex_context *ctx = (struct ltdb_reindex_context *)state;
	struct ldb_module *module = ctx->module;
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module),
						    struct ltdb_private);
	struct ldb_message *msg;
	unsigned int nb_elements_in_db;
	const struct ldb_val val = {
		.data = data.dptr,
		.length = data.dsize,
	};
	int ret;
	bool is_record;
	
	ldb = ldb_module_get_ctx(module);

	if (key.dsize > 4 &&
	    memcmp(key.dptr, "DN=@", 4) == 0) {
		return 0;
	}

	is_record = ltdb_key_is_record(key);
	if (is_record == false) {
		return 0;
	}
	
	msg = ldb_msg_new(module);
	if (msg == NULL) {
		return -1;
	}

	ret = ldb_unpack_data_only_attr_list_flags(ldb, &val,
						   msg,
						   NULL, 0,
						   LDB_UNPACK_DATA_FLAG_NO_DATA_ALLOC,
						   &nb_elements_in_db);
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
			  (int)key.dsize, (int)key.dsize,
			  (char *)key.dptr);
		talloc_free(msg);
		return -1;
	}

	ret = ltdb_index_onelevel(module, msg, 1);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Adding special ONE LEVEL index failed (%s)!",
						ldb_dn_get_linearized(msg->dn));
		talloc_free(msg);
		return -1;
	}

	ret = ltdb_index_add_all(module, ltdb, msg);

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
  force a complete reindex of the database
*/
int ltdb_reindex(struct ldb_module *module)
{
	struct ltdb_private *ltdb = talloc_get_type(ldb_module_get_private(module), struct ltdb_private);
	int ret;
	struct ltdb_reindex_context ctx;

	/*
	 * Only triggered after a modification, but make clear we do
	 * not re-index a read-only DB
	 */
	if (ltdb->read_only) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	if (ltdb_cache_reload(module) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Ensure we read (and so remove) the entries from the real
	 * DB, no values stored so far are any use as we want to do a
	 * re-index
	 */
	ltdb_index_transaction_cancel(module);

	ret = ltdb_index_transaction_start(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* first traverse the database deleting any @INDEX records by
	 * putting NULL entries in the in-memory tdb
	 */
	ret = tdb_traverse(ltdb->tdb, delete_index, module);
	if (ret < 0) {
		struct ldb_context *ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(ldb, "index deletion traverse failed: %s",
				       ldb_errstring(ldb));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ctx.module = module;
	ctx.error = 0;
	ctx.count = 0;

	/* now traverse adding any indexes for normal LDB records */
	ret = tdb_traverse(ltdb->tdb, re_key, &ctx);
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
	ret = tdb_traverse(ltdb->tdb, re_index, &ctx);
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
			  LDB_DEBUG_WARNING, "Reindexing: re_index successful on %s, "
			  "final index write-out will be in transaction commit",
			  tdb_name(ltdb->tdb));
	}
	return LDB_SUCCESS;
}
