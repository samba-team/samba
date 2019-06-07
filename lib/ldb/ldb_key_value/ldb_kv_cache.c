/*
   ldb database library

   Copyright (C) Andrew Tridgell  2004

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
 *  Component: ldb key value cache functions
 *
 *  Description: cache special records in a ldb/tdb
 *
 *  Author: Andrew Tridgell
 */

#include "ldb_kv.h"
#include "ldb_private.h"

#define LDB_KV_FLAG_CASE_INSENSITIVE (1<<0)
#define LDB_KV_FLAG_INTEGER          (1<<1)
#define LDB_KV_FLAG_UNIQUE_INDEX     (1<<2)
#define LDB_KV_FLAG_ORDERED_INTEGER  (1<<3)

/* valid attribute flags */
static const struct {
	const char *name;
	int value;
} ldb_kv_valid_attr_flags[] = {
	{ "CASE_INSENSITIVE", LDB_KV_FLAG_CASE_INSENSITIVE },
	{ "INTEGER", LDB_KV_FLAG_INTEGER },
	{ "ORDERED_INTEGER", LDB_KV_FLAG_ORDERED_INTEGER },
	{ "HIDDEN", 0 },
	{ "UNIQUE_INDEX",  LDB_KV_FLAG_UNIQUE_INDEX},
	{ "NONE", 0 },
	{ NULL, 0 }
};

/*
  de-register any special handlers for @ATTRIBUTES
*/
static void ldb_kv_attributes_unload(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	ldb_schema_attribute_remove_flagged(ldb, LDB_ATTR_FLAG_FROM_DB);

}

/*
  add up the attrib flags for a @ATTRIBUTES element
*/
static int ldb_kv_attributes_flags(struct ldb_message_element *el, unsigned *v)
{
	unsigned int i;
	unsigned value = 0;
	for (i=0;i<el->num_values;i++) {
		unsigned int j;
		for (j = 0; ldb_kv_valid_attr_flags[j].name; j++) {
			if (strcmp(ldb_kv_valid_attr_flags[j].name,
				   (char *)el->values[i].data) == 0) {
				value |= ldb_kv_valid_attr_flags[j].value;
				break;
			}
		}
		if (ldb_kv_valid_attr_flags[j].name == NULL) {
			return -1;
		}
	}
	*v = value;
	return 0;
}

static int ldb_schema_attribute_compare(const void *p1, const void *p2)
{
	const struct ldb_schema_attribute *sa1 = (const struct ldb_schema_attribute *)p1;
	const struct ldb_schema_attribute *sa2 = (const struct ldb_schema_attribute *)p2;
	return ldb_attr_cmp(sa1->name, sa2->name);
}

/*
  register any special handlers from @ATTRIBUTES
*/
static int ldb_kv_attributes_load(struct ldb_module *module)
{
	struct ldb_schema_attribute *attrs;
	struct ldb_context *ldb;
	struct ldb_message *attrs_msg = NULL;
	struct ldb_dn *dn;
	unsigned int i;
	unsigned int num_loaded_attrs = 0;
	int r;

	ldb = ldb_module_get_ctx(module);

	if (ldb->schema.attribute_handler_override) {
		/* we skip loading the @ATTRIBUTES record when a module is supplying
		   its own attribute handling */
		return 0;
	}

	attrs_msg = ldb_msg_new(module);
	if (attrs_msg == NULL) {
		goto failed;
	}

	dn = ldb_dn_new(module, ldb, LDB_KV_ATTRIBUTES);
	if (dn == NULL) goto failed;

	r = ldb_kv_search_dn1(module,
			      dn,
			      attrs_msg,
			      LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC |
				  LDB_UNPACK_DATA_FLAG_NO_DN);
	talloc_free(dn);
	if (r != LDB_SUCCESS && r != LDB_ERR_NO_SUCH_OBJECT) {
		goto failed;
	}
	if (r == LDB_ERR_NO_SUCH_OBJECT || attrs_msg->num_elements == 0) {
		TALLOC_FREE(attrs_msg);
		return 0;
	}

	attrs = talloc_array(attrs_msg,
			     struct ldb_schema_attribute,
			     attrs_msg->num_elements
			     + ldb->schema.num_attributes);
	if (attrs == NULL) {
		goto failed;
	}

	memcpy(attrs,
	       ldb->schema.attributes,
	       sizeof(ldb->schema.attributes[0]) * ldb->schema.num_attributes);

	/* mapping these flags onto ldap 'syntaxes' isn't strictly correct,
	   but its close enough for now */
	for (i=0;i<attrs_msg->num_elements;i++) {
		unsigned flags = 0, attr_flags = 0;
		const char *syntax;
		const struct ldb_schema_syntax *s;
		const struct ldb_schema_attribute *a =
			ldb_schema_attribute_by_name(ldb,
						     attrs_msg->elements[i].name);
		if (a != NULL && a->flags & LDB_ATTR_FLAG_FIXED) {
			/* Must already be set in the array, and kept */
			continue;
		}

		if (ldb_kv_attributes_flags(&attrs_msg->elements[i], &flags) !=
		    0) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Invalid @ATTRIBUTES element for '%s'",
				  attrs_msg->elements[i].name);
			goto failed;
		}

		if (flags & LDB_KV_FLAG_UNIQUE_INDEX) {
			attr_flags = LDB_ATTR_FLAG_UNIQUE_INDEX;
		}
		flags &= ~LDB_KV_FLAG_UNIQUE_INDEX;

		/* These are not currently flags, each is exclusive */
		if (flags == LDB_KV_FLAG_CASE_INSENSITIVE) {
			syntax = LDB_SYNTAX_DIRECTORY_STRING;
		} else if (flags == LDB_KV_FLAG_INTEGER) {
			syntax = LDB_SYNTAX_INTEGER;
		} else if (flags == LDB_KV_FLAG_ORDERED_INTEGER) {
			syntax = LDB_SYNTAX_ORDERED_INTEGER;
		} else if (flags == 0) {
			syntax = LDB_SYNTAX_OCTET_STRING;
		} else {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Invalid flag combination 0x%x for '%s' "
				  "in @ATTRIBUTES",
				  flags, attrs_msg->elements[i].name);
			goto failed;
		}

		s = ldb_standard_syntax_by_name(ldb, syntax);
		if (s == NULL) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Invalid attribute syntax '%s' for '%s' "
				  "in @ATTRIBUTES",
				  syntax, attrs_msg->elements[i].name);
			goto failed;
		}

		attr_flags |= LDB_ATTR_FLAG_ALLOCATED | LDB_ATTR_FLAG_FROM_DB;

		r = ldb_schema_attribute_fill_with_syntax(ldb,
							  attrs,
							  attrs_msg->elements[i].name,
							  attr_flags, s,
							  &attrs[num_loaded_attrs + ldb->schema.num_attributes]);
		if (r != 0) {
			goto failed;
		}
		num_loaded_attrs++;
	}

	attrs = talloc_realloc(attrs_msg,
			       attrs, struct ldb_schema_attribute,
			       num_loaded_attrs + ldb->schema.num_attributes);
	if (attrs == NULL) {
		goto failed;
	}
	TYPESAFE_QSORT(attrs, num_loaded_attrs + ldb->schema.num_attributes,
		       ldb_schema_attribute_compare);
	talloc_unlink(ldb, ldb->schema.attributes);
	ldb->schema.attributes = talloc_steal(ldb, attrs);
	ldb->schema.num_attributes = num_loaded_attrs + ldb->schema.num_attributes;
	TALLOC_FREE(attrs_msg);

	return 0;
failed:
	TALLOC_FREE(attrs_msg);
	return -1;
}

/*
  register any index records we find for the DB
*/
static int ldb_kv_index_load(struct ldb_module *module,
			     struct ldb_kv_private *ldb_kv)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *indexlist_dn;
	int r, lmdb_subdb_version;

	if (ldb->schema.index_handler_override) {
		/*
		 * we skip loading the @INDEXLIST record when a module is
		 * supplying its own attribute handling
		 */
		ldb_kv->cache->attribute_indexes = true;
		ldb_kv->cache->one_level_indexes =
		    ldb->schema.one_level_indexes;
		ldb_kv->cache->GUID_index_attribute =
		    ldb->schema.GUID_index_attribute;
		ldb_kv->cache->GUID_index_dn_component =
		    ldb->schema.GUID_index_dn_component;
		return 0;
	}

	talloc_free(ldb_kv->cache->indexlist);

	ldb_kv->cache->indexlist = ldb_msg_new(ldb_kv->cache);
	if (ldb_kv->cache->indexlist == NULL) {
		return -1;
	}
	ldb_kv->cache->one_level_indexes = false;
	ldb_kv->cache->attribute_indexes = false;

	indexlist_dn = ldb_dn_new(ldb_kv, ldb, LDB_KV_INDEXLIST);
	if (indexlist_dn == NULL) {
		return -1;
	}

	r = ldb_kv_search_dn1(module,
			      indexlist_dn,
			      ldb_kv->cache->indexlist,
			      LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC |
				  LDB_UNPACK_DATA_FLAG_NO_DN);
	TALLOC_FREE(indexlist_dn);

	if (r != LDB_SUCCESS && r != LDB_ERR_NO_SUCH_OBJECT) {
		return -1;
	}

	if (ldb_msg_find_element(ldb_kv->cache->indexlist, LDB_KV_IDXONE) !=
	    NULL) {
		ldb_kv->cache->one_level_indexes = true;
	}
	if (ldb_msg_find_element(ldb_kv->cache->indexlist, LDB_KV_IDXATTR) !=
	    NULL) {
		ldb_kv->cache->attribute_indexes = true;
	}
	ldb_kv->cache->GUID_index_attribute = ldb_msg_find_attr_as_string(
	    ldb_kv->cache->indexlist, LDB_KV_IDXGUID, NULL);
	ldb_kv->cache->GUID_index_dn_component = ldb_msg_find_attr_as_string(
	    ldb_kv->cache->indexlist, LDB_KV_IDX_DN_GUID, NULL);

	lmdb_subdb_version = ldb_msg_find_attr_as_int(
	    ldb_kv->cache->indexlist, LDB_KV_IDX_LMDB_SUBDB, 0);

	if (lmdb_subdb_version != 0) {
		ldb_set_errstring(ldb,
				  "FATAL: This ldb_mdb database has "
				  "been written in a new version of LDB "
				  "using a sub-database index that "
				  "is not understood by ldb "
				  LDB_VERSION);
		return -1;
	}

	return 0;
}

/*
  initialise the baseinfo record
*/
static int ldb_kv_baseinfo_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct ldb_message *msg;
	struct ldb_message_element el;
	struct ldb_val val;
	int ret;
	/* the initial sequence number must be different from the one
	   set in ltdb_cache_free(). Thanks to Jon for pointing this
	   out. */
	const char *initial_sequence_number = "1";

	ldb = ldb_module_get_ctx(module);

	ldb_kv->sequence_number = atof(initial_sequence_number);

	msg = ldb_msg_new(ldb_kv);
	if (msg == NULL) {
		goto failed;
	}

	msg->num_elements = 1;
	msg->elements = &el;
	msg->dn = ldb_dn_new(msg, ldb, LDB_KV_BASEINFO);
	if (!msg->dn) {
		goto failed;
	}
	el.name = talloc_strdup(msg, LDB_KV_SEQUENCE_NUMBER);
	if (!el.name) {
		goto failed;
	}
	el.values = &val;
	el.num_values = 1;
	el.flags = 0;
	val.data = (uint8_t *)talloc_strdup(msg, initial_sequence_number);
	if (!val.data) {
		goto failed;
	}
	val.length = 1;

	ret = ldb_kv_store(module, msg, TDB_INSERT);

	talloc_free(msg);

	return ret;

failed:
	talloc_free(msg);
	errno = ENOMEM;
	return LDB_ERR_OPERATIONS_ERROR;
}

/*
  free any cache records
 */
static void ldb_kv_cache_free(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);

	ldb_kv->sequence_number = 0;
	talloc_free(ldb_kv->cache);
	ldb_kv->cache = NULL;
}

/*
  force a cache reload
*/
int ldb_kv_cache_reload(struct ldb_module *module)
{
	ldb_kv_attributes_unload(module);
	ldb_kv_cache_free(module);
	return ldb_kv_cache_load(module);
}
static int get_pack_format_version(struct ldb_val key,
				   struct ldb_val data,
				   void *private_data)
{
	uint32_t *v = (uint32_t *) private_data;
	return ldb_unpack_get_format(&data, v);
}

/*
  load the cache records
*/
int ldb_kv_cache_load(struct ldb_module *module)
{
	struct ldb_context *ldb;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct ldb_dn *baseinfo_dn = NULL, *options_dn = NULL;
	uint64_t seq;
	struct ldb_message *baseinfo = NULL, *options = NULL;
	const struct ldb_schema_attribute *a;
	bool have_write_txn = false;
	int r;
	struct ldb_val key;

	ldb = ldb_module_get_ctx(module);

	/* a very fast check to avoid extra database reads */
	if (ldb_kv->cache != NULL && !ldb_kv->kv_ops->has_changed(ldb_kv)) {
		return 0;
	}

	if (ldb_kv->cache == NULL) {
		ldb_kv->cache = talloc_zero(ldb_kv, struct ldb_kv_cache);
		if (ldb_kv->cache == NULL)
			goto failed;
	}

	baseinfo = ldb_msg_new(ldb_kv->cache);
	if (baseinfo == NULL) goto failed;

	baseinfo_dn = ldb_dn_new(baseinfo, ldb, LDB_KV_BASEINFO);
	if (baseinfo_dn == NULL) goto failed;

	r = ldb_kv->kv_ops->lock_read(module);
	if (r != LDB_SUCCESS) {
		goto failed;
	}

	key = ldb_kv_key_dn(baseinfo, baseinfo_dn);
	if (!key.data) {
		goto failed_and_unlock;
	}

	/* Read packing format from first 4 bytes of @BASEINFO record */
	r = ldb_kv->kv_ops->fetch_and_parse(ldb_kv, key,
					    get_pack_format_version,
					    &ldb_kv->pack_format_version);

	/* possibly initialise the baseinfo */
	if (r == LDB_ERR_NO_SUCH_OBJECT) {

		/* Give up the read lock, try again with a write lock */
		r = ldb_kv->kv_ops->unlock_read(module);
		if (r != LDB_SUCCESS) {
			goto failed;
		}

		if (ldb_kv->kv_ops->begin_write(ldb_kv) != 0) {
			goto failed;
		}

		have_write_txn = true;

		/*
		 * We need to write but haven't figured out packing format yet.
		 * Just go with version 1 and we'll repack if we got it wrong.
		 */
		ldb_kv->pack_format_version = LDB_PACKING_FORMAT;
		ldb_kv->target_pack_format_version = LDB_PACKING_FORMAT;

		/* error handling for ltdb_baseinfo_init() is by
		   looking for the record again. */
		ldb_kv_baseinfo_init(module);

	} else if (r != LDB_SUCCESS) {
		goto failed_and_unlock;
	}

	/* OK now we definitely have a @BASEINFO record so fetch it */
	r = ldb_kv_search_dn1(module, baseinfo_dn, baseinfo, 0);
	if (r != LDB_SUCCESS) {
		goto failed_and_unlock;
	}

	/* Ignore the result, and update the sequence number */
	ldb_kv->kv_ops->has_changed(ldb_kv);

	/* if the current internal sequence number is the same as the one
	   in the database then assume the rest of the cache is OK */
	seq = ldb_msg_find_attr_as_uint64(baseinfo, LDB_KV_SEQUENCE_NUMBER, 0);
	if (seq == ldb_kv->sequence_number) {
		goto done;
	}
	ldb_kv->sequence_number = seq;

	/* Read an interpret database options */

	options = ldb_msg_new(ldb_kv->cache);
	if (options == NULL) goto failed_and_unlock;

	options_dn = ldb_dn_new(options, ldb, LDB_KV_OPTIONS);
	if (options_dn == NULL) goto failed_and_unlock;

	r = ldb_kv_search_dn1(module, options_dn, options, 0);
	talloc_free(options_dn);
	if (r != LDB_SUCCESS && r != LDB_ERR_NO_SUCH_OBJECT) {
		goto failed_and_unlock;
	}

	/* set flags if they do exist */
	if (r == LDB_SUCCESS) {
		ldb_kv->check_base =
		    ldb_msg_find_attr_as_bool(options, LDB_KV_CHECK_BASE, false);
		ldb_kv->disallow_dn_filter = ldb_msg_find_attr_as_bool(
		    options, LDB_KV_DISALLOW_DN_FILTER, false);
	} else {
		ldb_kv->check_base = false;
		ldb_kv->disallow_dn_filter = false;
	}

	/*
	 * ltdb_attributes_unload() calls internally talloc_free() on
	 * any non-fixed elemnts in ldb->schema.attributes.
	 *
	 * NOTE WELL: This is per-ldb, not per module, so overwrites
	 * the handlers across all databases when used under Samba's
	 * partition module.
	 */
	ldb_kv_attributes_unload(module);

	if (ldb_kv_index_load(module, ldb_kv) == -1) {
		goto failed_and_unlock;
	}

	/*
	 * NOTE WELL: This is per-ldb, not per module, so overwrites
	 * the handlers across all databases when used under Samba's
	 * partition module.
	 */
	if (ldb_kv_attributes_load(module) == -1) {
		goto failed_and_unlock;
	}

	/*
	 * Initialise packing version and GUID index syntax, and force the
	 * two to travel together, ie a GUID indexed database must use V2
	 * packing format and a DN indexed database must use V1.
	 */
	ldb_kv->GUID_index_syntax = NULL;
	if (ldb_kv->cache->GUID_index_attribute != NULL) {
		ldb_kv->target_pack_format_version = LDB_PACKING_FORMAT_V2;

		/*
		 * Now the attributes are loaded, set the guid_index_syntax.
		 * This can't fail, it will return a default at worst
		 */
		a = ldb_schema_attribute_by_name(
		    ldb, ldb_kv->cache->GUID_index_attribute);
		ldb_kv->GUID_index_syntax = a->syntax;
	} else {
		ldb_kv->target_pack_format_version = LDB_PACKING_FORMAT;
	}

done:
	if (have_write_txn) {
		if (ldb_kv->kv_ops->finish_write(ldb_kv) != 0) {
			goto failed;
		}
	} else {
		ldb_kv->kv_ops->unlock_read(module);
	}

	talloc_free(options);
	talloc_free(baseinfo);
	return 0;

failed_and_unlock:
	if (have_write_txn) {
		ldb_kv->kv_ops->abort_write(ldb_kv);
	} else {
		ldb_kv->kv_ops->unlock_read(module);
	}

failed:
	talloc_free(options);
	talloc_free(baseinfo);
	return -1;
}


/*
  increase the sequence number to indicate a database change
*/
int ldb_kv_increase_sequence_number(struct ldb_module *module)
{
	struct ldb_context *ldb;
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct ldb_message *msg;
	struct ldb_message_element el[2];
	struct ldb_val val;
	struct ldb_val val_time;
	time_t t = time(NULL);
	char *s = NULL;
	int ret;

	ldb = ldb_module_get_ctx(module);

	msg = ldb_msg_new(ldb_kv);
	if (msg == NULL) {
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	s = talloc_asprintf(msg, "%llu", ldb_kv->sequence_number + 1);
	if (!s) {
		talloc_free(msg);
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg->num_elements = ARRAY_SIZE(el);
	msg->elements = el;
	msg->dn = ldb_dn_new(msg, ldb, LDB_KV_BASEINFO);
	if (msg->dn == NULL) {
		talloc_free(msg);
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}
	el[0].name = talloc_strdup(msg, LDB_KV_SEQUENCE_NUMBER);
	if (el[0].name == NULL) {
		talloc_free(msg);
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}
	el[0].values = &val;
	el[0].num_values = 1;
	el[0].flags = LDB_FLAG_MOD_REPLACE;
	val.data = (uint8_t *)s;
	val.length = strlen(s);

	el[1].name = talloc_strdup(msg, LDB_KV_MOD_TIMESTAMP);
	if (el[1].name == NULL) {
		talloc_free(msg);
		errno = ENOMEM;
		return LDB_ERR_OPERATIONS_ERROR;
	}
	el[1].values = &val_time;
	el[1].num_values = 1;
	el[1].flags = LDB_FLAG_MOD_REPLACE;

	s = ldb_timestring(msg, t);
	if (s == NULL) {
		talloc_free(msg);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	val_time.data = (uint8_t *)s;
	val_time.length = strlen(s);

	ret = ldb_kv_modify_internal(module, msg, NULL);

	talloc_free(msg);

	if (ret == LDB_SUCCESS) {
		ldb_kv->sequence_number += 1;
	}

	/* updating the tdb_seqnum here avoids us reloading the cache
	   records due to our own modification */
	ldb_kv->kv_ops->has_changed(ldb_kv);

	return ret;
}

int ldb_kv_check_at_attributes_values(const struct ldb_val *value)
{
	unsigned int i;

	for (i = 0; ldb_kv_valid_attr_flags[i].name != NULL; i++) {
		if ((strcmp(ldb_kv_valid_attr_flags[i].name,
			    (char *)value->data) == 0)) {
			return 0;
		}
	}

	return -1;
}
