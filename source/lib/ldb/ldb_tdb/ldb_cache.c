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
 *  Component: ldb tdb cache functions
 *
 *  Description: cache special records in a ldb/tdb
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/ldb_tdb/ldb_tdb.h"

/*
  initialise the baseinfo record
*/
static int ltdb_baseinfo_init(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;
	struct ldb_message msg;
	struct ldb_message_element el;
	struct ldb_val val;
	int ret;

	ltdb->sequence_number = 0;

	msg.num_elements = 1;
	msg.elements = &el;
	msg.dn = strdup(LTDB_BASEINFO);
	if (!msg.dn) {
		errno = ENOMEM;
		return -1;
	}
	el.name = strdup(LTDB_SEQUENCE_NUMBER);
	if (!el.name) {
		free(msg.dn);
		errno = ENOMEM;
		return -1;
	}
	el.values = &val;
	el.num_values = 1;
	el.flags = 0;
	val.data = strdup("0");
	if (!val.data) {
		free(el.name);
		free(msg.dn);
		errno = ENOMEM;
		return -1;
	}
	val.length = 1;
	
	ret = ltdb_store(ldb, &msg, TDB_INSERT);

	free(msg.dn);
	free(el.name);
	free(val.data);

	return ret;
}

/*
  free any cache records
 */
void ltdb_cache_free(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;

	ltdb->sequence_number = 0;
	ltdb_search_dn1_free(ldb, &ltdb->cache.baseinfo);
	ltdb_search_dn1_free(ldb, &ltdb->cache.indexlist);
	ltdb_search_dn1_free(ldb, &ltdb->cache.subclasses);
	ltdb_search_dn1_free(ldb, &ltdb->cache.attributes);

	if (ltdb->cache.last_attribute.name) free(ltdb->cache.last_attribute.name);
	memset(&ltdb->cache, 0, sizeof(ltdb->cache));
}

/*
  load the cache records
*/
int ltdb_cache_load(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;
	double seq;

	ltdb_search_dn1_free(ldb, &ltdb->cache.baseinfo);
	
	if (ltdb_search_dn1(ldb, LTDB_BASEINFO, &ltdb->cache.baseinfo) == -1) {
		return -1;
	}
	
	/* possibly initialise the baseinfo */
	if (!ltdb->cache.baseinfo.dn) {
		if (ltdb_baseinfo_init(ldb) != 0) {
			return -1;
		}
		if (ltdb_search_dn1(ldb, LTDB_BASEINFO, &ltdb->cache.baseinfo) != 1) {
			return -1;
		}
	}

	/* if the current internal sequence number is the same as the one
	   in the database then assume the rest of the cache is OK */
	seq = ldb_msg_find_double(&ltdb->cache.baseinfo, LTDB_SEQUENCE_NUMBER, 0);
	if (seq == ltdb->sequence_number) {
		return 0;
	}
	ltdb->sequence_number = seq;

	if (ltdb->cache.last_attribute.name) free(ltdb->cache.last_attribute.name);
	memset(&ltdb->cache.last_attribute, 0, sizeof(ltdb->cache.last_attribute));

	ltdb_search_dn1_free(ldb, &ltdb->cache.indexlist);
	ltdb_search_dn1_free(ldb, &ltdb->cache.subclasses);
	ltdb_search_dn1_free(ldb, &ltdb->cache.attributes);

	if (ltdb_search_dn1(ldb, LTDB_INDEXLIST, &ltdb->cache.indexlist) == -1) {
		return -1;
	}
	if (ltdb_search_dn1(ldb, LTDB_SUBCLASSES, &ltdb->cache.subclasses) == -1) {
		return -1;
	}
	if (ltdb_search_dn1(ldb, LTDB_ATTRIBUTES, &ltdb->cache.attributes) == -1) {
		return -1;
	}

	return 0;
}


/*
  increase the sequence number to indicate a database change
*/
int ltdb_increase_sequence_number(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;
	struct ldb_message msg;
	struct ldb_message_element el;
	struct ldb_val val;
	char *s = NULL;
	int ret;

	asprintf(&s, "%.0f", ltdb->sequence_number+1);
	if (!s) {
		errno = ENOMEM;
		return -1;
	}

	msg.num_elements = 1;
	msg.elements = &el;
	msg.dn = strdup(LTDB_BASEINFO);
	el.name = strdup(LTDB_SEQUENCE_NUMBER);
	el.values = &val;
	el.num_values = 1;
	el.flags = LDB_FLAG_MOD_REPLACE;
	val.data = s;
	val.length = strlen(s);

	ret = ltdb_modify_internal(ldb, &msg);

	free(s);
	free(msg.dn);
	free(el.name);

	if (ret == 0) {
		ltdb->sequence_number += 1;
	}

	return ret;
}


/*
  return the attribute flags from the @ATTRIBUTES record 
  for the given attribute
*/
int ltdb_attribute_flags(struct ldb_context *ldb, const char *attr_name)
{
	struct ltdb_private *ltdb = ldb->private_data;
	const char *attrs;
	const struct {
		const char *name;
		int value;
	} names[] = {
		{ "CASE_INSENSITIVE", LTDB_FLAG_CASE_INSENSITIVE },
		{ "INTEGER", LTDB_FLAG_INTEGER },
		{ "WILDCARD", LTDB_FLAG_WILDCARD },
		{ NULL, 0}
	};
	size_t len;
	int i, ret=0;

	if (ltdb->cache.last_attribute.name &&
	    ldb_attr_cmp(ltdb->cache.last_attribute.name, attr_name) == 0) {
		return ltdb->cache.last_attribute.flags;
	}

	/* objectclass is a special default case */
	if (ldb_attr_cmp(attr_name, LTDB_OBJECTCLASS) == 0) {
		ret = LTDB_FLAG_OBJECTCLASS | LTDB_FLAG_CASE_INSENSITIVE;
	}

	attrs = ldb_msg_find_string(&ltdb->cache.attributes, attr_name, NULL);

	if (!attrs) {
		return ret;
	}

	/* we avoid using strtok and friends due to their nasty
	   interface. This is a little trickier, but much nicer
	   from a C interface point of view */
	while ((len = strcspn(attrs, " ,")) > 0) {
		for (i=0;names[i].name;i++) {
			if (strncmp(names[i].name, attrs, len) == 0 &&
			    names[i].name[len] == 0) {
				ret |= names[i].value;
			}
		}
		attrs += len;
		attrs += strspn(attrs, " ,");
	}

	if (ltdb->cache.last_attribute.name) free(ltdb->cache.last_attribute.name);

	ltdb->cache.last_attribute.name = strdup(attr_name);
	ltdb->cache.last_attribute.flags = ret;
	
	return ret;
}
