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
#include "ldb_tdb/ldb_tdb.h"

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
  store a record into the db
*/
int ltdb_store(struct ldb_context *ldb, const struct ldb_message *msg, int flgs)
{
	struct ltdb_private *ltdb = ldb->private;
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
	return ltdb_store(ldb, msg, TDB_INSERT);
}


/*
  delete a record from the database, not updating indexes (used for deleting
  index records)
*/
int ltdb_delete_noindex(struct ldb_context *ldb, const char *dn)
{
	struct ltdb_private *ltdb = ldb->private;
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

	/* in case any attribute of the message was indexed, we need
	   to fetch the old record */
	ret = ltdb_search_dn1(ldb, dn, &msg);
	if (ret != 1) {
		/* not finding the old record is an error */
		return -1;
	}

	ret = ltdb_delete_noindex(ldb, dn);
	if (ret == -1) {
		ltdb_search_dn1_free(ldb, &msg);
		return -1;
	}

	/* remove any indexed attributes */
	ret = ltdb_index_del(ldb, &msg);

	ltdb_search_dn1_free(ldb, &msg);

	return ret;
}


/*
  modify a record
*/
static int ltdb_modify(struct ldb_context *ldb, const struct ldb_message *msg)
{
	struct ltdb_private *ltdb = ldb->private;
	TDB_DATA tdb_key, tdb_data;
	struct ldb_message msg2;
	int ret;

	tdb_key = ltdb_key(msg->dn);
	if (!tdb_key.dptr) {
		return -1;
	}

	tdb_data = tdb_fetch(ltdb->tdb, tdb_key);
	if (!tdb_data.dptr) {
		free(tdb_key.dptr);
		return -1;
	}

	ret = ltdb_unpack_data(ldb, &tdb_data, &msg2);
	if (ret == -1) {
		free(tdb_key.dptr);
		free(tdb_data.dptr);
		return -1;
	}

#if 0
	for (i=0;i<msg->num_elements;i++) {
		switch (msg->elements[i].flags & LDB_FLAG_MOD_MASK) {
		case LDB_FLAG_MOD_ADD:
			ret = find_element(&msg2, msg->elements[i].name);
			if (ret != -1) {
				errno = EEXIST;
				goto failed;
			}
			
		}
	}

failed:
#endif

	free(tdb_key.dptr);
	free(tdb_data.dptr);
	if (msg2.elements) free(msg2.elements);
	
	return -1;
}

/*
  close database
*/
static int ltdb_close(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private;
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
	struct ltdb_private *ltdb = ldb->private;
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

	tdb = tdb_open(path, 0, tdb_flags, open_flags, 0666);
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

	ldb->private = ltdb;
	ldb->ops = &ltdb_ops;

	return ldb;
}
