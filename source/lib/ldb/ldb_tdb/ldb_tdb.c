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
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_tdb/ldb_tdb.h"

#define LDBLOCK	"INT_LDBLOCK"

/*
  form a TDB_DATA for a record key
  caller frees

  note that the key for a record can depend on whether the 
  dn refers to a case sensitive index record or not
*/
struct TDB_DATA ltdb_key(struct ldb_module *module, const char *dn)
{
	struct ldb_context *ldb = module->ldb;
	TDB_DATA key;
	char *key_str = NULL;
	char *dn_folded = NULL;
	const char *prefix = LTDB_INDEX ":";
	const char *s;
	int flags;

	/*
	  most DNs are case insensitive. The exception is index DNs for
	  case sensitive attributes

	  there are 3 cases dealt with in this code:

	  1) if the dn doesn't start with @INDEX: then uppercase whole dn
	  2) if the dn starts with @INDEX:attr and 'attr' is a case insensitive
	     attribute then uppercase whole dn
	  3) if the dn starts with @INDEX:attr and 'attr' is a case sensitive
	     attribute then uppercase up to the value of the attribute, but 
	     not the value itself
	*/
	if (strncmp(dn, prefix, strlen(prefix)) == 0 &&
	    (s = strchr(dn+strlen(prefix), ':'))) {
		char *attr_name, *attr_name_folded;
		attr_name = ldb_strndup(ldb, dn+strlen(prefix), (s-(dn+strlen(prefix))));
		if (!attr_name) {
			goto failed;
		}
		flags = ltdb_attribute_flags(module, attr_name);
		
		if (flags & LTDB_FLAG_CASE_INSENSITIVE) {
			dn_folded = ldb_casefold(ldb, dn);
		} else {
			attr_name_folded = ldb_casefold(ldb, attr_name);
			if (!attr_name_folded) {
				goto failed;
			}
			ldb_asprintf(ldb, &dn_folded, "%s:%s:%s",
				 prefix, attr_name_folded,
				 s+1);
			ldb_free(ldb, attr_name_folded);
		}
		ldb_free(ldb, attr_name);
	} else {
		dn_folded = ldb_casefold(ldb, dn);
	}

	if (!dn_folded) {
		goto failed;
	}

	ldb_asprintf(ldb, &key_str, "DN=%s", dn_folded);
	ldb_free(ldb, dn_folded);

	if (!key_str) {
		goto failed;
	}

	key.dptr = key_str;
	key.dsize = strlen(key_str)+1;

	return key;

failed:
	errno = ENOMEM;
	key.dptr = NULL;
	key.dsize = 0;
	return key;
}

/*
  lock the database for write - currently a single lock is used
*/
static int ltdb_lock(struct ldb_module *module, const char *lockname)
{
	struct ldb_context *ldb = module->ldb;
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA key;
	int ret;

	if (lockname == NULL) {
		return -1;
	}

	key = ltdb_key(module, lockname);
	if (!key.dptr) {
		return -1;
	}

	ret = tdb_chainlock(ltdb->tdb, key);

	ldb_free(ldb, key.dptr);

	return ret;
}

/*
  unlock the database after a ltdb_lock()
*/
static int ltdb_unlock(struct ldb_module *module, const char *lockname)
{
	struct ldb_context *ldb = module->ldb;
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA key;

	if (lockname == NULL) {
		return -1;
	}

	key = ltdb_key(module, lockname);
	if (!key.dptr) {
		return -1;
	}

	tdb_chainunlock(ltdb->tdb, key);

	ldb_free(ldb, key.dptr);

	return 0;
}


/*
  we've made a modification to a dn - possibly reindex and 
  update sequence number
*/
static int ltdb_modified(struct ldb_module *module, const char *dn)
{
	int ret = 0;

	if (strcmp(dn, LTDB_INDEXLIST) == 0 ||
	    strcmp(dn, LTDB_ATTRIBUTES) == 0) {
		ret = ltdb_reindex(module);
	}

	if (ret == 0 &&
	    strcmp(dn, LTDB_BASEINFO) != 0) {
		ret = ltdb_increase_sequence_number(module);
	}

	return ret;
}

/*
  store a record into the db
*/
int ltdb_store(struct ldb_module *module, const struct ldb_message *msg, int flgs)
{
	struct ldb_context *ldb = module->ldb;
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA tdb_key, tdb_data;
	int ret;

	tdb_key = ltdb_key(module, msg->dn);
	if (!tdb_key.dptr) {
		return -1;
	}

	ret = ltdb_pack_data(module, msg, &tdb_data);
	if (ret == -1) {
		ldb_free(ldb, tdb_key.dptr);
		return -1;
	}

	ret = tdb_store(ltdb->tdb, tdb_key, tdb_data, flgs);
	if (ret == -1) {
		goto done;
	}
	
	ret = ltdb_index_add(module, msg);
	if (ret == -1) {
		tdb_delete(ltdb->tdb, tdb_key);
	}

done:
	ldb_free(ldb, tdb_key.dptr);
	ldb_free(ldb, tdb_data.dptr);

	return ret;
}


/*
  add a record to the database
*/
static int ltdb_add(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ltdb_private *ltdb = module->private_data;
	int ret;

	ltdb->last_err_string = NULL;

	if (ltdb_lock(module, LDBLOCK) != 0) {
		return -1;
	}

	if (ltdb_cache_load(module) != 0) {
		ltdb_unlock(module, LDBLOCK);
		return -1;
	}
	
	ret = ltdb_store(module, msg, TDB_INSERT);

	if (ret == 0) {
		ltdb_modified(module, msg->dn);
	}

	ltdb_unlock(module, LDBLOCK);
	return ret;
}


/*
  delete a record from the database, not updating indexes (used for deleting
  index records)
*/
int ltdb_delete_noindex(struct ldb_module *module, const char *dn)
{
	struct ldb_context *ldb = module->ldb;
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA tdb_key;
	int ret;

	tdb_key = ltdb_key(module, dn);
	if (!tdb_key.dptr) {
		return -1;
	}

	ret = tdb_delete(ltdb->tdb, tdb_key);
	ldb_free(ldb, tdb_key.dptr);

	return ret;
}

/*
  delete a record from the database
*/
static int ltdb_delete(struct ldb_module *module, const char *dn)
{
	struct ltdb_private *ltdb = module->private_data;
	int ret;
	struct ldb_message msg;

	ltdb->last_err_string = NULL;

	if (ltdb_lock(module, LDBLOCK) != 0) {
		return -1;
	}

	if (ltdb_cache_load(module) != 0) {
		ltdb_unlock(module, LDBLOCK);
		return -1;
	}

	/* in case any attribute of the message was indexed, we need
	   to fetch the old record */
	ret = ltdb_search_dn1(module, dn, &msg);
	if (ret != 1) {
		/* not finding the old record is an error */
		goto failed;
	}

	ret = ltdb_delete_noindex(module, dn);
	if (ret == -1) {
		ltdb_search_dn1_free(module, &msg);
		goto failed;
	}

	/* remove any indexed attributes */
	ret = ltdb_index_del(module, &msg);

	ltdb_search_dn1_free(module, &msg);

	if (ret == 0) {
		ltdb_modified(module, dn);
	}

	ltdb_unlock(module, LDBLOCK);
	return ret;

failed:
	ltdb_unlock(module, LDBLOCK);
	return -1;
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

	e2 = ldb_realloc_p(ldb, msg->elements, struct ldb_message_element, 
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
		e2->values = ldb_malloc_array_p(ldb, struct ldb_val, el->num_values);
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
	unsigned int i, j, count=0;
	struct ldb_message_element *el2;

	el2 = ldb_malloc_array_p(ldb, struct ldb_message_element, msg->num_elements);
	if (!el2) {
		errno = ENOMEM;
		return -1;
	}

	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, name) != 0) {
			el2[count++] = msg->elements[i];
		} else {
			for (j=0;j<msg->elements[i].num_values;j++) {
				ltdb_index_del_value(module, msg->dn, &msg->elements[i], j);
			}
			ldb_free(ldb, msg->elements[i].values);
		}
	}

	msg->num_elements = count;
	ldb_free(ldb, msg->elements);
	msg->elements = el2;

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

	found = find_element(msg, name);
	if (found == -1) {
		return -1;
	}

	el = &msg->elements[found];

	for (i=0;i<el->num_values;i++) {
		if (ltdb_val_equal(module, msg->elements[i].name, &el->values[i], val)) {
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
	struct ldb_message msg2;
	unsigned i, j;
	int ret;

	tdb_key = ltdb_key(module, msg->dn);
	if (!tdb_key.dptr) {
		return -1;
	}

	tdb_data = tdb_fetch(ltdb->tdb, tdb_key);
	if (!tdb_data.dptr) {
		ldb_free(ldb, tdb_key.dptr);
		return -1;
	}

	ret = ltdb_unpack_data(module, &tdb_data, &msg2);
	if (ret == -1) {
		ldb_free(ldb, tdb_key.dptr);
		free(tdb_data.dptr);
		return -1;
	}

	if (!msg2.dn) {
		msg2.dn = msg->dn;
	}

	for (i=0;i<msg->num_elements;i++) {
		switch (msg->elements[i].flags & LDB_FLAG_MOD_MASK) {

		case LDB_FLAG_MOD_ADD:
			/* add this element to the message. fail if it
			   already exists */
			ret = find_element(&msg2, msg->elements[i].name);
			if (ret != -1) {
				for (j=0;j<msg->elements[i].num_values;j++) {
					if (ldb_msg_find_val(&msg2.elements[ret], 
							     &msg->elements[i].values[j])) {
						ltdb->last_err_string = "Type or value exists";
						goto failed;
					}
				}
			}
			if (msg_add_element(ldb, &msg2, &msg->elements[i]) != 0) {
				goto failed;
			}
			break;

		case LDB_FLAG_MOD_REPLACE:
			/* replace all elements of this attribute name with the elements
			   listed. The attribute not existing is not an error */
			msg_delete_attribute(module, ldb, &msg2, msg->elements[i].name);

			/* add the replacement element, if not empty */
			if (msg->elements[i].num_values != 0 &&
			    msg_add_element(ldb, &msg2, &msg->elements[i]) != 0) {
				goto failed;
			}
			break;

		case LDB_FLAG_MOD_DELETE:
			/* we could be being asked to delete all
			   values or just some values */
			if (msg->elements[i].num_values == 0) {
				if (msg_delete_attribute(module, ldb, &msg2, 
							 msg->elements[i].name) != 0) {
					ltdb->last_err_string = "No such attribute";
					goto failed;
				}
				break;
			}
			for (j=0;j<msg->elements[i].num_values;j++) {
				if (msg_delete_element(module,
						       &msg2, 
						       msg->elements[i].name,
						       &msg->elements[i].values[j]) != 0) {
					ltdb->last_err_string = "No such attribute";
					goto failed;
				}
				if (ltdb_index_del_value(module, msg->dn, &msg->elements[i], j) != 0) {
					goto failed;
				}
			}
			break;
		}
	}

	/* we've made all the mods - save the modified record back into the database */
	ret = ltdb_store(module, &msg2, TDB_MODIFY);

	ldb_free(ldb, tdb_key.dptr);
	free(tdb_data.dptr);
	ltdb_unpack_data_free(module, &msg2);
	return ret;

failed:
	ldb_free(ldb, tdb_key.dptr);
	free(tdb_data.dptr);
	ltdb_unpack_data_free(module, &msg2);
	return -1;
}

/*
  modify a record
*/
static int ltdb_modify(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ltdb_private *ltdb = module->private_data;
	int ret;

	ltdb->last_err_string = NULL;

	if (ltdb_lock(module, LDBLOCK) != 0) {
		return -1;
	}

	if (ltdb_cache_load(module) != 0) {
		ltdb_unlock(module, LDBLOCK);
		return -1;
	}

	ret = ltdb_modify_internal(module, msg);

	if (ret == 0) {
		ltdb_modified(module, msg->dn);
	}

	ltdb_unlock(module, LDBLOCK);

	return ret;
}

/*
  rename a record
*/
static int ltdb_rename(struct ldb_module *module, const char *olddn, const char *newdn)
{
	struct ldb_context *ldb = module->ldb;
	struct ltdb_private *ltdb = module->private_data;
	int ret;
	struct ldb_message msg;
	const char *error_str;

	ltdb->last_err_string = NULL;

	if (ltdb_lock(module, LDBLOCK) != 0) {
		return -1;
	}

	/* in case any attribute of the message was indexed, we need
	   to fetch the old record */
	ret = ltdb_search_dn1(module, olddn, &msg);
	if (ret != 1) {
		/* not finding the old record is an error */
		goto failed;
	}

	msg.dn = ldb_strdup(ldb,newdn);
	if (!msg.dn) {
		ltdb_search_dn1_free(module, &msg);
		goto failed;
	}

	ret = ltdb_add(module, &msg);
	if (ret == -1) {
		ldb_free(ldb, msg.dn);
		ltdb_search_dn1_free(module, &msg);
		goto failed;
	}
	ldb_free(ldb, msg.dn);
	ltdb_search_dn1_free(module, &msg);

	ret = ltdb_delete(module, olddn);
	error_str = ltdb->last_err_string;
	if (ret == -1) {
		ltdb_delete(module, newdn);
	}

	ltdb->last_err_string = error_str;

	ltdb_unlock(module, LDBLOCK);

	return ret;
failed:
	ltdb_unlock(module, LDBLOCK);
	return -1;
}

/*
  close database
*/
static int ltdb_close(struct ldb_module *module)
{
	struct ldb_context *ldb = module->ldb;
	struct ltdb_private *ltdb = module->private_data;
	int ret;

	ltdb->last_err_string = NULL;

	ltdb_cache_free(module);
	ldb_set_alloc(ldb, NULL, NULL);

	ret = tdb_close(ltdb->tdb);
	ldb_free(ldb, ltdb);
	free(ldb);
	return ret;
}
		      

/*
  return extended error information
*/
static const char *ltdb_errstring(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;
	if (ltdb->last_err_string) {
		return ltdb->last_err_string;
	}
	return tdb_errorstr(ltdb->tdb);
}


static const struct ldb_module_ops ltdb_ops = {
	"tdb",
	ltdb_close, 
	ltdb_search,
	ltdb_search_free,
	ltdb_add,
	ltdb_modify,
	ltdb_delete,
	ltdb_rename,
	ltdb_lock,
	ltdb_unlock,
	ltdb_errstring,
	ltdb_cache_free
};


/*
  connect to the database
*/
struct ldb_context *ltdb_connect(const char *url, 
				 unsigned int flags, 
				 const char *options[])
{
	const char *path;
	int tdb_flags, open_flags;
	struct ltdb_private *ltdb;
	TDB_CONTEXT *tdb;
	struct ldb_context *ldb;

	ldb = calloc(1, sizeof(struct ldb_context));
	if (!ldb) {
		errno = ENOMEM;
		return NULL;
	}

	/* parse the url */
	if (strchr(url, ':')) {
		if (strncmp(url, "tdb://", 6) != 0) {
			errno = EINVAL;
			return NULL;
		}
		path = url+6;
	} else {
		path = url;
	}

	tdb_flags = TDB_DEFAULT;

	if (flags & LDB_FLG_RDONLY) {
		open_flags = O_RDONLY;
	} else {
		open_flags = O_CREAT | O_RDWR;
	}

	/* note that we use quite a large default hash size */
	tdb = tdb_open(path, 10000, tdb_flags, open_flags, 0666);
	if (!tdb) {
		free(ldb);
		return NULL;
	}

	ltdb = ldb_malloc_p(ldb, struct ltdb_private);
	if (!ltdb) {
		tdb_close(tdb);
		free(ldb);
		errno = ENOMEM;
		return NULL;
	}

	ltdb->tdb = tdb;
	ltdb->sequence_number = 0;

	memset(&ltdb->cache, 0, sizeof(ltdb->cache));

	ldb->modules = ldb_malloc_p(ldb, struct ldb_module);
	if (!ldb->modules) {
		tdb_close(tdb);
		free(ldb);
		errno = ENOMEM;
		return NULL;
	}
	ldb->modules->ldb = ldb;
	ldb->modules->prev = ldb->modules->next = NULL;
	ldb->modules->private_data = ltdb;
	ldb->modules->ops = &ltdb_ops;

	return ldb;
}
