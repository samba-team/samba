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
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_tdb/ldb_tdb.h"

/*
  initialise the baseinfo record
*/
static int ltdb_baseinfo_init(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;
	struct ldb_message *msg;
	struct ldb_message_element el;
	struct ldb_val val;
	int ret;
	/* the initial sequence number must be different from the one
	   set in ltdb_cache_free(). Thanks to Jon for pointing this
	   out. */
	const char *initial_sequence_number = "1";

	ltdb->sequence_number = atof(initial_sequence_number);

	msg = talloc_p(ltdb, struct ldb_message);
	if (msg == NULL) {
		goto failed;
	}

	msg->num_elements = 1;
	msg->elements = &el;
	msg->dn = talloc_strdup(msg, LTDB_BASEINFO);
	if (!msg->dn) {
		goto failed;
	}
	el.name = talloc_strdup(msg, LTDB_SEQUENCE_NUMBER);
	if (!el.name) {
		goto failed;
	}
	el.values = &val;
	el.num_values = 1;
	el.flags = 0;
	val.data = talloc_strdup(msg, initial_sequence_number);
	if (!val.data) {
		goto failed;
	}
	val.length = 1;
	
	ret = ltdb_store(module, msg, TDB_INSERT);

	talloc_free(msg);

	return ret;

failed:
	talloc_free(msg);
	errno = ENOMEM;
	return -1;
}

/*
  free any cache records
 */
static void ltdb_cache_free(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;

	ltdb->sequence_number = 0;
	talloc_free(ltdb->cache);
	ltdb->cache = NULL;
}

/*
  force a cache reload
*/
int ltdb_cache_reload(struct ldb_module *module)
{
	ltdb_cache_free(module);
	return ltdb_cache_load(module);
}

/*
  load the cache records
*/
int ltdb_cache_load(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;
	double seq;

	if (ltdb->cache == NULL) {
		ltdb->cache = talloc_zero_p(ltdb, struct ltdb_cache);
		if (ltdb->cache == NULL) goto failed;
		ltdb->cache->indexlist = talloc_zero_p(ltdb->cache, struct ldb_message);
		ltdb->cache->subclasses = talloc_zero_p(ltdb->cache, struct ldb_message);
		ltdb->cache->attributes = talloc_zero_p(ltdb->cache, struct ldb_message);
		if (ltdb->cache->indexlist == NULL ||
		    ltdb->cache->subclasses == NULL ||
		    ltdb->cache->attributes == NULL) {
			goto failed;
		}
	}

	talloc_free(ltdb->cache->baseinfo);
	ltdb->cache->baseinfo = talloc_p(ltdb->cache, struct ldb_message);
	if (ltdb->cache->baseinfo == NULL) goto failed;
	
	if (ltdb_search_dn1(module, LTDB_BASEINFO, ltdb->cache->baseinfo) == -1) {
		goto failed;
	}
	
	/* possibly initialise the baseinfo */
	if (!ltdb->cache->baseinfo->dn) {
		if (ltdb_baseinfo_init(module) != 0) {
			goto failed;
		}
		if (ltdb_search_dn1(module, LTDB_BASEINFO, ltdb->cache->baseinfo) != 1) {
			goto failed;
		}
	}

	/* if the current internal sequence number is the same as the one
	   in the database then assume the rest of the cache is OK */
	seq = ldb_msg_find_double(ltdb->cache->baseinfo, LTDB_SEQUENCE_NUMBER, 0);
	if (seq == ltdb->sequence_number) {
		goto done;
	}
	ltdb->sequence_number = seq;

	talloc_free(ltdb->cache->last_attribute.name);
	memset(&ltdb->cache->last_attribute, 0, sizeof(ltdb->cache->last_attribute));

	talloc_free(ltdb->cache->indexlist);
	talloc_free(ltdb->cache->subclasses);
	talloc_free(ltdb->cache->attributes);

	ltdb->cache->indexlist = talloc_zero_p(ltdb->cache, struct ldb_message);
	ltdb->cache->subclasses = talloc_zero_p(ltdb->cache, struct ldb_message);
	ltdb->cache->attributes = talloc_zero_p(ltdb->cache, struct ldb_message);
	if (ltdb->cache->indexlist == NULL ||
	    ltdb->cache->subclasses == NULL ||
	    ltdb->cache->attributes == NULL) {
		goto failed;
	}
	    
	if (ltdb_search_dn1(module, LTDB_INDEXLIST, ltdb->cache->indexlist) == -1) {
		goto failed;
	}
	if (ltdb_search_dn1(module, LTDB_SUBCLASSES, ltdb->cache->subclasses) == -1) {
		goto failed;
	}
	if (ltdb_search_dn1(module, LTDB_ATTRIBUTES, ltdb->cache->attributes) == -1) {
		goto failed;
	}

done:
	return 0;

failed:
	return -1;
}


/*
  increase the sequence number to indicate a database change
*/
int ltdb_increase_sequence_number(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;
	struct ldb_message *msg;
	struct ldb_message_element el;
	struct ldb_val val;
	char *s = NULL;
	int ret;

	msg = talloc_p(ltdb, struct ldb_message);
	if (msg == NULL) {
		errno = ENOMEM;
		return -1;
	}

	s = talloc_asprintf(msg, "%.0f", ltdb->sequence_number+1);
	if (!s) {
		errno = ENOMEM;
		return -1;
	}

	msg->num_elements = 1;
	msg->elements = &el;
	msg->dn = talloc_strdup(msg, LTDB_BASEINFO);
	el.name = talloc_strdup(msg, LTDB_SEQUENCE_NUMBER);
	el.values = &val;
	el.num_values = 1;
	el.flags = LDB_FLAG_MOD_REPLACE;
	val.data = s;
	val.length = strlen(s);

	ret = ltdb_modify_internal(module, msg);

	talloc_free(msg);

	if (ret == 0) {
		ltdb->sequence_number += 1;
	}

	return ret;
}


/*
  return the attribute flags from the @ATTRIBUTES record 
  for the given attribute
*/
int ltdb_attribute_flags(struct ldb_module *module, const char *attr_name)
{
	struct ltdb_private *ltdb = module->private_data;
	const char *attrs;
	const struct {
		const char *name;
		int value;
	} names[] = {
		{ "CASE_INSENSITIVE", LTDB_FLAG_CASE_INSENSITIVE },
		{ "INTEGER", LTDB_FLAG_INTEGER },
		{ "WILDCARD", LTDB_FLAG_WILDCARD },
		{ "HIDDEN", LTDB_FLAG_HIDDEN },
		{ NULL, 0}
	};
	size_t len;
	int i, ret=0;

	if (ltdb->cache->last_attribute.name &&
	    ldb_attr_cmp(ltdb->cache->last_attribute.name, attr_name) == 0) {
		return ltdb->cache->last_attribute.flags;
	}

	/* objectclass is a special default case */
	if (ldb_attr_cmp(attr_name, LTDB_OBJECTCLASS) == 0) {
		ret = LTDB_FLAG_OBJECTCLASS | LTDB_FLAG_CASE_INSENSITIVE;
	}

	attrs = ldb_msg_find_string(ltdb->cache->attributes, attr_name, NULL);

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

	talloc_free(ltdb->cache->last_attribute.name);

	ltdb->cache->last_attribute.name = talloc_strdup(ltdb->cache, attr_name);
	ltdb->cache->last_attribute.flags = ret;

	return ret;
}
