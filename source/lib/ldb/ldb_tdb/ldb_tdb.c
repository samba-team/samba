/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

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
 */

#include "includes.h"
#include "ldb/ldb_tdb/ldb_tdb.h"

/*
  form a TDB_DATA for a record key
  caller frees
*/
struct TDB_DATA ltdb_key(const char *dn)
{
	TDB_DATA key;
	char *key_str = NULL;

	asprintf(&key_str, "DN=%s", dn);
	if (!key_str) {
		errno = ENOMEM;
		key.dptr = NULL;
		key.dsize = 0;
		return key;
	}

	key.dptr = key_str;
	key.dsize = strlen(key_str)+1;

	return key;
}

/*
  lock the database for write - currently a single lock is used
*/
static int ltdb_lock(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;
	TDB_DATA key;
	int ret;

	key = ltdb_key("LDBLOCK");
	if (!key.dptr) {
		return -1;
	}

	ret = tdb_chainlock(ltdb->tdb, key);

	free(key.dptr);

	return ret;
}

/*
  unlock the database after a ltdb_lock()
*/
static void ltdb_unlock(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;
	TDB_DATA key;

	key = ltdb_key("LDBLOCK");
	if (!key.dptr) {
		return;
	}

	tdb_chainunlock(ltdb->tdb, key);

	free(key.dptr);
}

/*
  store a record into the db
*/
int ltdb_store(struct ldb_context *ldb, const struct ldb_message *msg, int flgs)
{
	struct ltdb_private *ltdb = ldb->private_data;
	TDB_DATA tdb_key, tdb_data;
	int ret;

	tdb_key = ltdb_key(msg->dn);
	if (!tdb_key.dptr) {
		return -1;
	}

	ret = ltdb_pack_data(ldb, msg, &tdb_data);
	if (ret == -1) {
		free(tdb_key.dptr);
		return -1;
	}

	ret = tdb_store(ltdb->tdb, tdb_key, tdb_data, flgs);
	if (ret == -1) {
		goto done;
	}
	
	ret = ltdb_index_add(ldb, msg);
	if (ret == -1) {
		tdb_delete(ltdb->tdb, tdb_key);
	}

done:
	free(tdb_key.dptr);
	free(tdb_data.dptr);

	return ret;
}


/*
  add a record to the database
*/
static int ltdb_add(struct ldb_context *ldb, const struct ldb_message *msg)
{
	int ret;

	if (ltdb_lock(ldb) != 0) {
		return -1;
	}
	
	ret = ltdb_store(ldb, msg, TDB_INSERT);

	if (strcmp(msg->dn, "@INDEXLIST") == 0) {
		ltdb_reindex(ldb);
	}

	ltdb_unlock(ldb);

	return ret;
}


/*
  delete a record from the database, not updating indexes (used for deleting
  index records)
*/
int ltdb_delete_noindex(struct ldb_context *ldb, const char *dn)
{
	struct ltdb_private *ltdb = ldb->private_data;
	TDB_DATA tdb_key;
	int ret;

	tdb_key = ltdb_key(dn);
	if (!tdb_key.dptr) {
		return -1;
	}

	ret = tdb_delete(ltdb->tdb, tdb_key);
	free(tdb_key.dptr);

	return ret;
}

/*
  delete a record from the database
*/
static int ltdb_delete(struct ldb_context *ldb, const char *dn)
{
	int ret;
	struct ldb_message msg;

	if (ltdb_lock(ldb) != 0) {
		return -1;
	}

	/* in case any attribute of the message was indexed, we need
	   to fetch the old record */
	ret = ltdb_search_dn1(ldb, dn, &msg);
	if (ret != 1) {
		/* not finding the old record is an error */
		goto failed;
	}

	ret = ltdb_delete_noindex(ldb, dn);
	if (ret == -1) {
		ltdb_search_dn1_free(ldb, &msg);
		goto failed;
	}

	/* remove any indexed attributes */
	ret = ltdb_index_del(ldb, &msg);

	ltdb_search_dn1_free(ldb, &msg);

	if (strcmp(dn, "@INDEXLIST") == 0) {
		ltdb_reindex(ldb);
	}

	ltdb_unlock(ldb);
	return ret;

failed:
	ltdb_unlock(ldb);
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
	int i;
	for (i=0;i<msg->num_elements;i++) {
		if (strcmp(msg->elements[i].name, name) == 0) {
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
static int msg_add_element(struct ldb_message *msg, struct ldb_message_element *el)
{
	struct ldb_message_element *e2;
	int i;

	e2 = realloc_p(msg->elements, struct ldb_message_element, 
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
		e2->values = malloc_array_p(struct ldb_val, el->num_values);
		if (!e2->values) {
			free(e2->name);
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
static int msg_delete_attribute(struct ldb_message *msg, const char *name)
{
	int i, count=0;
	struct ldb_message_element *el2;

	el2 = malloc_array_p(struct ldb_message_element, msg->num_elements);
	if (!el2) {
		errno = ENOMEM;
		return -1;
	}

	for (i=0;i<msg->num_elements;i++) {
		if (strcmp(msg->elements[i].name, name) != 0) {
			el2[count++] = msg->elements[i];
		} else {
			if (msg->elements[i].values) free(msg->elements[i].values);
		}
	}

	msg->num_elements = count;
	if (msg->elements) free(msg->elements);
	msg->elements = el2;

	return 0;
}

/*
  delete all elements matching an attribute name/value 

  return 0 on success, -1 on failure
*/
static int msg_delete_element(struct ldb_message *msg, 
			      const char *name,
			      const struct ldb_val *val)
{
	int i;
	struct ldb_message_element *el;

	i = find_element(msg, name);
	if (i == -1) {
		return -1;
	}

	el = &msg->elements[i];

	for (i=0;i<el->num_values;i++) {
		if (ldb_val_equal(&el->values[i], val)) {
			if (i<el->num_values-1) {
				memmove(&el->values[i], &el->values[i+1],
					sizeof(el->values[i])*el->num_values-(i+1));
			}
			el->num_values--;
			return 0;
		}
	}
	
	return -1;
}

/*
  modify a record

  yuck - this is O(n^2). Luckily n is usually small so we probably
  get away with it, but if we ever have really large attribute lists 
  then we'll need to look at this again
*/
static int ltdb_modify(struct ldb_context *ldb, const struct ldb_message *msg)
{
	struct ltdb_private *ltdb = ldb->private_data;
	TDB_DATA tdb_key, tdb_data;
	struct ldb_message msg2;
	int ret, i, j;

	if (ltdb_lock(ldb) != 0) {
		return -1;
	}

	tdb_key = ltdb_key(msg->dn);
	if (!tdb_key.dptr) {
		goto unlock_fail;
	}

	tdb_data = tdb_fetch(ltdb->tdb, tdb_key);
	if (!tdb_data.dptr) {
		free(tdb_key.dptr);
		goto unlock_fail;
	}

	ret = ltdb_unpack_data(ldb, &tdb_data, &msg2);
	if (ret == -1) {
		free(tdb_key.dptr);
		free(tdb_data.dptr);
		goto unlock_fail;
	}

	msg2.dn = msg->dn;

	for (i=0;i<msg->num_elements;i++) {
		switch (msg->elements[i].flags & LDB_FLAG_MOD_MASK) {

		case LDB_FLAG_MOD_ADD:
			/* add this element to the message. fail if it
			   already exists */
			ret = find_element(&msg2, msg->elements[i].name);
			if (ret != -1) {
				errno = EEXIST;
				goto failed;
			}
			if (msg_add_element(&msg2, &msg->elements[i]) != 0) {
				goto failed;
			}
			break;

		case LDB_FLAG_MOD_REPLACE:
			/* replace all elements of this attribute name with the elements
			   listed */
			if (msg_delete_attribute(&msg2, msg->elements[i].name) != 0) {
				goto failed;
			}
			/* add the replacement element */
			if (msg_add_element(&msg2, &msg->elements[i]) != 0) {
				goto failed;
			}
			break;

		case LDB_FLAG_MOD_DELETE:
			/* we could be being asked to delete all
			   values or just some values */
			if (msg->elements[i].num_values == 0) {
				if (msg_delete_attribute(&msg2, 
							  msg->elements[i].name) != 0) {
					goto failed;
				}
				break;
			}
			for (j=0;j<msg->elements[i].num_values;j++) {
				if (msg_delete_element(&msg2, 
							msg->elements[i].name,
							&msg->elements[i].values[j]) != 0) {
					goto failed;
				}
			}
			break;
		}
	}

	/* we've made all the mods - save the modified record back into the database */
	ret = ltdb_store(ldb, &msg2, TDB_MODIFY);

	if (strcmp(msg2.dn, "@INDEXLIST") == 0) {
		ltdb_reindex(ldb);
	}

	free(tdb_key.dptr);
	free(tdb_data.dptr);
	ltdb_unpack_data_free(&msg2);
	ltdb_unlock(ldb);

	return ret;

failed:
	free(tdb_key.dptr);
	free(tdb_data.dptr);
	ltdb_unpack_data_free(&msg2);

unlock_fail:
	ltdb_unlock(ldb);
	
	return -1;
}

/*
  close database
*/
static int ltdb_close(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;
	int ret;
	ret = tdb_close(ltdb->tdb);
	free(ltdb);
	free(ldb);
	return ret;
}
		      

/*
  return extended error information
*/
static const char *ltdb_errstring(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;
	return tdb_errorstr(ltdb->tdb);
}


static const struct ldb_backend_ops ltdb_ops = {
	ltdb_close, 
	ltdb_search,
	ltdb_search_free,
	ltdb_add,
	ltdb_modify,
	ltdb_delete,
	ltdb_errstring
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

	/* parse the url */
	if (strncmp(url, "tdb://", 6) != 0) {
		errno = EINVAL;
		return NULL;
	}

	path = url+6;

	tdb_flags = TDB_DEFAULT;

	if (flags & LDB_FLG_RDONLY) {
		open_flags = O_RDONLY;
	} else {
		open_flags = O_CREAT | O_RDWR;
	}

	/* note that we use quite a large default hash size */
	tdb = tdb_open(path, 10000, tdb_flags, open_flags, 0666);
	if (!tdb) {
		return NULL;
	}

	ltdb = malloc_p(struct ltdb_private);
	if (!ltdb) {
		tdb_close(tdb);
		errno = ENOMEM;
		return NULL;
	}

	ltdb->tdb = tdb;
	

	ldb = malloc_p(struct ldb_context);
	if (!ldb) {
		tdb_close(tdb);
		free(ltdb);
		errno = ENOMEM;
		return NULL;
	}

	ldb->private_data = ltdb;
	ldb->ops = &ltdb_ops;

	return ldb;
}
