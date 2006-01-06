/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Stefan Metzmacher  2004
   

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb tdb backend
 *
 *  Description: core functions for tdb backend
 *
 *  Author: Andrew Tridgell
 *  Author: Stefan Metzmacher
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_tdb/ldb_tdb.h"


/*
  map a tdb error code to a ldb error code
*/
static int ltdb_err_map(enum TDB_ERROR tdb_code)
{
	switch (tdb_code) {
	case TDB_SUCCESS:
		return LDB_SUCCESS;
	case TDB_ERR_CORRUPT:
	case TDB_ERR_OOM:
	case TDB_ERR_EINVAL:
		return LDB_ERR_OPERATIONS_ERROR;
	case TDB_ERR_IO:
		return LDB_ERR_PROTOCOL_ERROR;
	case TDB_ERR_LOCK:
	case TDB_ERR_NOLOCK:
		return LDB_ERR_BUSY;
	case TDB_ERR_LOCK_TIMEOUT:
		return LDB_ERR_TIME_LIMIT_EXCEEDED;
	case TDB_ERR_EXISTS:
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	case TDB_ERR_NOEXIST:
		return LDB_ERR_NO_SUCH_OBJECT;
	case TDB_ERR_RDONLY:
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
	return LDB_ERR_OTHER;
}


/*
  form a TDB_DATA for a record key
  caller frees

  note that the key for a record can depend on whether the 
  dn refers to a case sensitive index record or not
*/
struct TDB_DATA ltdb_key(struct ldb_module *module, const struct ldb_dn *dn)
{
	struct ldb_context *ldb = module->ldb;
	TDB_DATA key;
	char *key_str = NULL;
	char *dn_folded = NULL;

	/*
	  most DNs are case insensitive. The exception is index DNs for
	  case sensitive attributes

	  there are 3 cases dealt with in this code:

	  1) if the dn doesn't start with @ then uppercase the attribute
             names and the attributes values of case insensitive attributes
	  2) if the dn starts with @ then leave it alone - the indexing code handles
	     the rest
	*/

	dn_folded = ldb_dn_linearize_casefold(ldb, dn);
	if (!dn_folded) {
		goto failed;
	}

	key_str = talloc_asprintf(ldb, "DN=%s", dn_folded);

	talloc_free(dn_folded);

	if (!key_str) {
		goto failed;
	}

	key.dptr = (uint8_t *)key_str;
	key.dsize = strlen(key_str) + 1;

	return key;

failed:
	errno = ENOMEM;
	key.dptr = NULL;
	key.dsize = 0;
	return key;
}

/*
  check special dn's have valid attributes
  currently only @ATTRIBUTES is checked
*/
int ltdb_check_special_dn(struct ldb_module *module, const struct ldb_message *msg)
{
	int i, j;
 
	if (! ldb_dn_is_special(msg->dn) ||
	    ! ldb_dn_check_special(msg->dn, LTDB_ATTRIBUTES)) {
		return 0;
	}

	/* we have @ATTRIBUTES, let's check attributes are fine */
	/* should we check that we deny multivalued attributes ? */
	for (i = 0; i < msg->num_elements; i++) {
		for (j = 0; j < msg->elements[i].num_values; j++) {
			if (ltdb_check_at_attributes_values(&msg->elements[i].values[j]) != 0) {
				char *err_string = talloc_strdup(module, "Invalid attribute value in an @ATTRIBUTES entry");
				if (err_string) {
					ldb_set_errstring(module, err_string);
				}
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}
		}
	}

	return 0;
}


/*
  we've made a modification to a dn - possibly reindex and 
  update sequence number
*/
static int ltdb_modified(struct ldb_module *module, const struct ldb_dn *dn)
{
	int ret = 0;

	if (ldb_dn_is_special(dn) &&
	    (ldb_dn_check_special(dn, LTDB_INDEXLIST) ||
	     ldb_dn_check_special(dn, LTDB_ATTRIBUTES)) ) {
		ret = ltdb_reindex(module);
	}

	if (ret == 0 &&
	    !(ldb_dn_is_special(dn) &&
	      ldb_dn_check_special(dn, LTDB_BASEINFO)) ) {
		ret = ltdb_increase_sequence_number(module);
	}

	return ret;
}

/*
  store a record into the db
*/
int ltdb_store(struct ldb_module *module, const struct ldb_message *msg, int flgs)
{
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA tdb_key, tdb_data;
	int ret;

	tdb_key = ltdb_key(module, msg->dn);
	if (!tdb_key.dptr) {
		return LDB_ERR_OTHER;
	}

	ret = ltdb_pack_data(module, msg, &tdb_data);
	if (ret == -1) {
		talloc_free(tdb_key.dptr);
		return LDB_ERR_OTHER;
	}

	ret = tdb_store(ltdb->tdb, tdb_key, tdb_data, flgs);
	if (ret == -1) {
		ret = ltdb_err_map(tdb_error(ltdb->tdb));
		goto done;
	}
	
	ret = ltdb_index_add(module, msg);
	if (ret == -1) {
		tdb_delete(ltdb->tdb, tdb_key);
	}

done:
	talloc_free(tdb_key.dptr);
	talloc_free(tdb_data.dptr);

	return ret;
}


/*
  add a record to the database
*/
static int ltdb_add(struct ldb_module *module, const struct ldb_message *msg)
{
	int ret;

	ret = ltdb_check_special_dn(module, msg);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	
	if (ltdb_cache_load(module) != 0) {
		return LDB_ERR_OTHER;
	}

	ret = ltdb_store(module, msg, TDB_INSERT);

	if (ret == LDB_SUCCESS) {
		ltdb_modified(module, msg->dn);
	}

	return ret;
}


/*
  delete a record from the database, not updating indexes (used for deleting
  index records)
*/
int ltdb_delete_noindex(struct ldb_module *module, const struct ldb_dn *dn)
{
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA tdb_key;
	int ret;

	tdb_key = ltdb_key(module, dn);
	if (!tdb_key.dptr) {
		return LDB_ERR_OTHER;
	}

	ret = tdb_delete(ltdb->tdb, tdb_key);
	talloc_free(tdb_key.dptr);

	if (ret != 0) {
		ret = ltdb_err_map(tdb_error(ltdb->tdb));
	}

	return ret;
}

/*
  delete a record from the database
*/
static int ltdb_delete(struct ldb_module *module, const struct ldb_dn *dn)
{
	struct ldb_message *msg = NULL;
	int ret = LDB_ERR_OTHER;

	if (ltdb_cache_load(module) != 0) {
		goto failed;
	}

	msg = talloc(module, struct ldb_message);
	if (msg == NULL) {
		goto failed;
	}

	/* in case any attribute of the message was indexed, we need
	   to fetch the old record */
	ret = ltdb_search_dn1(module, dn, msg);
	if (ret != 1) {
		/* not finding the old record is an error */
		ret = LDB_ERR_NO_SUCH_OBJECT;
		goto failed;
	}

	ret = ltdb_delete_noindex(module, dn);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	/* remove any indexed attributes */
	ret = ltdb_index_del(module, msg);
	if (ret == LDB_SUCCESS) {
		ltdb_modified(module, dn);
	} else
		ret = LDB_ERR_OTHER;

	talloc_free(msg);
	return ret;

failed:
	talloc_free(msg);
	return ret;
}


/*
  find an element by attribute name. At the moment this does a linear search, it should
  be re-coded to use a binary search once all places that modify records guarantee
  sorted order

  return the index of the first matching element if found, otherwise -1
*/
static int find_element(const struct ldb_message *msg, const char *name)
{
	unsigned int i;
	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, name) == 0) {
			return i;
		}
	}
	return -1;
}


/*
  add an element to an existing record. Assumes a elements array that we
  can call re-alloc on, and assumed that we can re-use the data pointers from the 
  passed in additional values. Use with care!

  returns 0 on success, -1 on failure (and sets errno)
*/
static int msg_add_element(struct ldb_context *ldb,
			   struct ldb_message *msg, struct ldb_message_element *el)
{
	struct ldb_message_element *e2;
	unsigned int i;

	e2 = talloc_realloc(msg, msg->elements, struct ldb_message_element, 
			      msg->num_elements+1);
	if (!e2) {
		errno = ENOMEM;
		return -1;
	}

	msg->elements = e2;

	e2 = &msg->elements[msg->num_elements];

	e2->name = el->name;
	e2->flags = el->flags;
	e2->values = NULL;
	if (el->num_values != 0) {
		e2->values = talloc_array(msg->elements, struct ldb_val, el->num_values);
		if (!e2->values) {
			errno = ENOMEM;
			return -1;
		}
	}
	for (i=0;i<el->num_values;i++) {
		e2->values[i] = el->values[i];
	}
	e2->num_values = el->num_values;

	msg->num_elements++;

	return 0;
}

/*
  delete all elements having a specified attribute name
*/
static int msg_delete_attribute(struct ldb_module *module,
				struct ldb_context *ldb,
				struct ldb_message *msg, const char *name)
{
	char *dn;
	unsigned int i, j;

	dn = ldb_dn_linearize(ldb, msg->dn);
	if (dn == NULL) {
		return -1;
	}

	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, name) == 0) {
			for (j=0;j<msg->elements[i].num_values;j++) {
				ltdb_index_del_value(module, dn, &msg->elements[i], j);
			}
			talloc_free(msg->elements[i].values);
			if (msg->num_elements > (i+1)) {
				memmove(&msg->elements[i], 
					&msg->elements[i+1], 
					sizeof(struct ldb_message_element)*
					(msg->num_elements - (i+1)));
			}
			msg->num_elements--;
			i--;
			msg->elements = talloc_realloc(msg, msg->elements, 
							 struct ldb_message_element, 
							 msg->num_elements);
		}
	}

	talloc_free(dn);
	return 0;
}

/*
  delete all elements matching an attribute name/value 

  return 0 on success, -1 on failure
*/
static int msg_delete_element(struct ldb_module *module,
			      struct ldb_message *msg, 
			      const char *name,
			      const struct ldb_val *val)
{
	struct ldb_context *ldb = module->ldb;
	unsigned int i;
	int found;
	struct ldb_message_element *el;
	const struct ldb_attrib_handler *h;

	found = find_element(msg, name);
	if (found == -1) {
		return -1;
	}

	el = &msg->elements[found];

	h = ldb_attrib_handler(ldb, el->name);

	for (i=0;i<el->num_values;i++) {
		if (h->comparison_fn(ldb, ldb, &el->values[i], val) == 0) {
			if (i<el->num_values-1) {
				memmove(&el->values[i], &el->values[i+1],
					sizeof(el->values[i])*(el->num_values-(i+1)));
			}
			el->num_values--;
			if (el->num_values == 0) {
				return msg_delete_attribute(module, ldb, msg, name);
			}
			return 0;
		}
	}

	return -1;
}


/*
  modify a record - internal interface

  yuck - this is O(n^2). Luckily n is usually small so we probably
  get away with it, but if we ever have really large attribute lists 
  then we'll need to look at this again
*/
int ltdb_modify_internal(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_context *ldb = module->ldb;
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA tdb_key, tdb_data;
	struct ldb_message *msg2;
	unsigned i, j;
	int ret;

	tdb_key = ltdb_key(module, msg->dn);
	if (!tdb_key.dptr) {
		return LDB_ERR_OTHER;
	}

	tdb_data = tdb_fetch(ltdb->tdb, tdb_key);
	if (!tdb_data.dptr) {
		talloc_free(tdb_key.dptr);
		return ltdb_err_map(tdb_error(ltdb->tdb));
	}

	msg2 = talloc(tdb_key.dptr, struct ldb_message);
	if (msg2 == NULL) {
		talloc_free(tdb_key.dptr);
		return LDB_ERR_OTHER;
	}

	ret = ltdb_unpack_data(module, &tdb_data, msg2);
	if (ret == -1) {
		talloc_free(tdb_key.dptr);
		free(tdb_data.dptr);
		return LDB_ERR_OTHER;
	}

	if (!msg2->dn) {
		msg2->dn = msg->dn;
	}

	for (i=0;i<msg->num_elements;i++) {
		struct ldb_message_element *el = &msg->elements[i];
		struct ldb_message_element *el2;
		struct ldb_val *vals;
		char *err_string;
		char *dn;

		switch (msg->elements[i].flags & LDB_FLAG_MOD_MASK) {

		case LDB_FLAG_MOD_ADD:
			/* add this element to the message. fail if it
			   already exists */
			ret = find_element(msg2, el->name);

			if (ret == -1) {
				if (msg_add_element(ldb, msg2, el) != 0) {
					ret = LDB_ERR_OTHER;
					goto failed;
				}
				continue;
			}

			el2 = &msg2->elements[ret];

			/* An attribute with this name already exists, add all
			 * values if they don't already exist. */

			for (j=0;j<el->num_values;j++) {
				if (ldb_msg_find_val(el2, &el->values[j])) {
					err_string = talloc_strdup(module, "Type or value exists");
					if (err_string) ldb_set_errstring(module, err_string);
					ret = LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
					goto failed;
				}
			}

		        vals = talloc_realloc(msg2->elements, el2->values, struct ldb_val,
						el2->num_values + el->num_values);

			if (vals == NULL)
				goto failed;

			for (j=0;j<el->num_values;j++) {
				vals[el2->num_values + j] =
					ldb_val_dup(vals, &el->values[j]);
			}

			el2->values = vals;
			el2->num_values += el->num_values;

			break;

		case LDB_FLAG_MOD_REPLACE:
			/* replace all elements of this attribute name with the elements
			   listed. The attribute not existing is not an error */
			msg_delete_attribute(module, ldb, msg2, msg->elements[i].name);

			/* add the replacement element, if not empty */
			if (msg->elements[i].num_values != 0 &&
			    msg_add_element(ldb, msg2, &msg->elements[i]) != 0) {
				goto failed;
			}
			break;

		case LDB_FLAG_MOD_DELETE:

			dn = ldb_dn_linearize(msg2, msg->dn);
			if (dn == NULL) goto failed;

			/* we could be being asked to delete all
			   values or just some values */
			if (msg->elements[i].num_values == 0) {
				if (msg_delete_attribute(module, ldb, msg2, 
							 msg->elements[i].name) != 0) {
					err_string = talloc_asprintf(module, "No such attribute: %s", msg->elements[i].name);
					if (err_string) ldb_set_errstring(module, err_string);
					ret = LDB_ERR_NO_SUCH_ATTRIBUTE;
					goto failed;
				}
				break;
			}
			for (j=0;j<msg->elements[i].num_values;j++) {
				if (msg_delete_element(module,
						       msg2, 
						       msg->elements[i].name,
						       &msg->elements[i].values[j]) != 0) {
					err_string = talloc_asprintf(module, "No such attribute: %s", msg->elements[i].name);
					if (err_string) ldb_set_errstring(module, err_string);
					ret = LDB_ERR_NO_SUCH_ATTRIBUTE;
					goto failed;
				}
				if (ltdb_index_del_value(module, dn, &msg->elements[i], j) != 0) {
					goto failed;
				}
			}
			break;
		default:
			err_string = talloc_asprintf(module, "Invalid ldb_modify flags on %s: 0x%x", 
						     msg->elements[i].name, 
						     msg->elements[i].flags & LDB_FLAG_MOD_MASK);
			if (err_string) ldb_set_errstring(module, err_string);
			ret = LDB_ERR_PROTOCOL_ERROR;
			goto failed;
		}
	}

	/* we've made all the mods - save the modified record back into the database */
	ret = ltdb_store(module, msg2, TDB_MODIFY);

	talloc_free(tdb_key.dptr);
	free(tdb_data.dptr);
	return ret;

failed:
	talloc_free(tdb_key.dptr);
	free(tdb_data.dptr);
	return ret;
}

/*
  modify a record
*/
static int ltdb_modify(struct ldb_module *module, const struct ldb_message *msg)
{
	int ret;

	ret = ltdb_check_special_dn(module, msg);
	if (ret != 0) {
		return ret;
	}
	
	if (ltdb_cache_load(module) != 0) {
		return -1;
	}

	ret = ltdb_modify_internal(module, msg);

	if (ret == LDB_SUCCESS) {
		ltdb_modified(module, msg->dn);
	}

	return ret;
}

/*
  rename a record
*/
static int ltdb_rename(struct ldb_module *module, const struct ldb_dn *olddn, const struct ldb_dn *newdn)
{
	struct ldb_message *msg;
	char *error_str;
	int ret = LDB_ERR_OTHER;

	if (ltdb_cache_load(module) != 0) {
		return ret;
	}

	msg = talloc(module, struct ldb_message);
	if (msg == NULL) {
		goto failed;
	}

	/* in case any attribute of the message was indexed, we need
	   to fetch the old record */
	ret = ltdb_search_dn1(module, olddn, msg);
	if (ret != 1) {
		/* not finding the old record is an error */
		ret = LDB_ERR_NO_SUCH_OBJECT;
		goto failed;
	}

	msg->dn = ldb_dn_copy(msg, newdn);
	if (!msg->dn) {
		ret = LDB_ERR_OTHER;
		goto failed;
	}

	ret = ltdb_add(module, msg);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	ret = ltdb_delete(module, olddn);
	error_str = talloc_strdup(module, ldb_errstring(module->ldb));
	if (ret != LDB_SUCCESS) {
		ltdb_delete(module, newdn);
	}

	ldb_set_errstring(module, error_str);

	talloc_free(msg);

	return ret;

failed:
	talloc_free(msg);
	return ret;
}

static int ltdb_start_trans(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;

	if (tdb_transaction_start(ltdb->tdb) != 0) {
		return ltdb_err_map(tdb_error(ltdb->tdb));
	}

	return LDB_SUCCESS;
}

static int ltdb_end_trans(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;

	if (tdb_transaction_commit(ltdb->tdb) != 0) {
		return ltdb_err_map(tdb_error(ltdb->tdb));
	}

	return LDB_SUCCESS;
}

static int ltdb_del_trans(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;

	if (tdb_transaction_cancel(ltdb->tdb) != 0) {
		return ltdb_err_map(tdb_error(ltdb->tdb));
	}

	return LDB_SUCCESS;
}

static int ltdb_request(struct ldb_module *module, struct ldb_request *req)
{
	/* check for oustanding critical controls and return an error if found */

	if (check_critical_controls(req->controls)) {
		return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
	}
	
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return ltdb_search_bytree(module,
					  req->op.search.base,
					  req->op.search.scope, 
					  req->op.search.tree, 
					  req->op.search.attrs, 
					  &req->op.search.res);

	case LDB_REQ_ADD:
		return ltdb_add(module, req->op.add.message);

	case LDB_REQ_MODIFY:
		return ltdb_modify(module, req->op.mod.message);

	case LDB_REQ_DELETE:
		return ltdb_delete(module, req->op.del.dn);

	case LDB_REQ_RENAME:
		return ltdb_rename(module,
					req->op.rename.olddn,
					req->op.rename.newdn);

	default:
		return LDB_ERR_OPERATIONS_ERROR;

	}
}

static int ltdb_init_2(struct ldb_module *module)
{
	return LDB_SUCCESS;
}

static const struct ldb_module_ops ltdb_ops = {
	.name              = "tdb",
	.request           = ltdb_request,
	.start_transaction = ltdb_start_trans,
	.end_transaction   = ltdb_end_trans,
	.del_transaction   = ltdb_del_trans,
	.second_stage_init = ltdb_init_2
};


/*
  connect to the database
*/
int ltdb_connect(struct ldb_context *ldb, const char *url, 
		 unsigned int flags, const char *options[])
{
	const char *path;
	int tdb_flags, open_flags;
	struct ltdb_private *ltdb;

	/* parse the url */
	if (strchr(url, ':')) {
		if (strncmp(url, "tdb://", 6) != 0) {
			ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid tdb URL '%s'", url);
			return -1;
		}
		path = url+6;
	} else {
		path = url;
	}

	tdb_flags = TDB_DEFAULT;

	/* check for the 'nosync' option */
	if (flags & LDB_FLG_NOSYNC) {
		tdb_flags |= TDB_NOSYNC;
	}

	if (flags & LDB_FLG_RDONLY) {
		open_flags = O_RDONLY;
	} else {
		open_flags = O_CREAT | O_RDWR;
	}

	ltdb = talloc_zero(ldb, struct ltdb_private);
	if (!ltdb) {
		ldb_oom(ldb);
		return -1;
	}

	/* note that we use quite a large default hash size */
	ltdb->tdb = ltdb_wrap_open(ltdb, path, 10000, tdb_flags, open_flags, 0666);
	if (!ltdb->tdb) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Unable to open tdb '%s'\n", path);
		talloc_free(ltdb);
		return -1;
	}

	ltdb->sequence_number = 0;

	ldb->modules = talloc(ldb, struct ldb_module);
	if (!ldb->modules) {
		ldb_oom(ldb);
		talloc_free(ltdb);
		return -1;
	}
	ldb->modules->ldb = ldb;
	ldb->modules->prev = ldb->modules->next = NULL;
	ldb->modules->private_data = ltdb;
	ldb->modules->ops = &ltdb_ops;

	return 0;
}
