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
 *  Component: ldb tdb backend - indexing
 *
 *  Description: indexing routines for ldb tdb backend
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/ldb_tdb/ldb_tdb.h"

struct dn_list {
	unsigned int count;
	char **dn;
};

/*
  free a struct dn_list
*/
static void dn_list_free(struct dn_list *list)
{
	int i;
	for (i=0;i<list->count;i++) {
		free(list->dn[i]);
	}
	if (list->dn) free(list->dn);
}

/*
  return the dn key to be used for an index
  caller frees
*/
static char *ldb_dn_key(const char *attr, const struct ldb_val *value)
{
	char *ret = NULL;

	if (ldb_should_b64_encode(value)) {
		char *vstr = ldb_base64_encode(value->data, value->length);
		if (!vstr) return NULL;
		asprintf(&ret, "%s:%s::%s", LTDB_INDEX, attr, vstr);
		free(vstr);
		return ret;
	}

	asprintf(&ret, "%s:%s:%s", LTDB_INDEX, attr, (char *)value->data);
	return ret;
}

/*
  see if a attribute value is in the list of indexed attributes
*/
static int ldb_msg_find_idx(const struct ldb_message *msg, const char *attr,
			    int *v_idx)
{
	int i, j;
	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, LTDB_IDXATTR) == 0) {
			const struct ldb_message_element *el = 
				&msg->elements[i];
			for (j=0;j<el->num_values;j++) {
				if (ldb_attr_cmp((char *)el->values[j].data, attr) == 0) {
					if (v_idx) {
						*v_idx = j;
					}
					return i;
				}
			}
		}
	}
	return -1;
}

/*
  return a list of dn's that might match a simple indexed search or
 */
static int ltdb_index_dn_simple(struct ldb_context *ldb, 
				struct ldb_parse_tree *tree,
				const struct ldb_message *index_list,
				struct dn_list *list)
{
	char *dn = NULL;
	int ret, i, j;
	struct ldb_message msg;

	list->count = 0;
	list->dn = NULL;

	/*
	  if the value is a wildcard then we can't do a match via indexing
	*/
	if (ltdb_has_wildcard(ldb, tree->u.simple.attr, &tree->u.simple.value)) {
		return -1;
	}

	/* if the attribute isn't in the list of indexed attributes then
	   this node needs a full search */
	if (ldb_msg_find_idx(index_list, tree->u.simple.attr, NULL) == -1) {
		return -1;
	}

	/* the attribute is indexed. Pull the list of DNs that match the 
	   search criterion */
	dn = ldb_dn_key(tree->u.simple.attr, &tree->u.simple.value);
	if (!dn) return -1;

	ret = ltdb_search_dn1(ldb, dn, &msg);
	free(dn);
	if (ret == 0 || ret == -1) {
		return ret;
	}

	for (i=0;i<msg.num_elements;i++) {
		struct ldb_message_element *el;

		if (strcmp(msg.elements[i].name, LTDB_IDX) != 0) {
			continue;
		}

		el = &msg.elements[i];

		list->dn = malloc_array_p(char *, el->num_values);
		if (!list->dn) {
			break;		
		}

		for (j=0;j<el->num_values;j++) {
			list->dn[list->count] = 
				strdup((char *)el->values[j].data);
			if (!list->dn[list->count]) {
				dn_list_free(list);
				ltdb_search_dn1_free(ldb, &msg);
				return -1;
			}
			list->count++;
		}
	}

	ltdb_search_dn1_free(ldb, &msg);

	qsort(list->dn, list->count, sizeof(char *), (comparison_fn_t) strcmp);

	return 1;
}

/*
  list intersection
  list = list & list2
  relies on the lists being sorted
*/
static int list_intersect(struct dn_list *list, const struct dn_list *list2)
{
	struct dn_list list3;
	int i;

	if (list->count == 0 || list2->count == 0) {
		/* 0 & X == 0 */
		dn_list_free(list);
		return 0;
	}

	list3.dn = malloc_array_p(char *, list->count);
	if (!list3.dn) {
		dn_list_free(list);
		return -1;
	}
	list3.count = 0;

	for (i=0;i<list->count;i++) {
		if (list_find(list->dn[i], list2->dn, list2->count, 
			      sizeof(char *), (comparison_fn_t)strcmp) != -1) {
			list3.dn[list3.count] = list->dn[i];
			list3.count++;
		} else {
			free(list->dn[i]);
		}		
	}

	free(list->dn);
	list->dn = list3.dn;
	list->count = list3.count;

	return 0;
}


/*
  list union
  list = list | list2
  relies on the lists being sorted
*/
static int list_union(struct dn_list *list, const struct dn_list *list2)
{
	int i;
	char **d;
	unsigned int count = list->count;

	if (list->count == 0 && list2->count == 0) {
		/* 0 | 0 == 0 */
		dn_list_free(list);
		return 0;
	}

	d = realloc_p(list->dn, char *, list->count + list2->count);
	if (!d) {
		dn_list_free(list);
		return -1;
	}
	list->dn = d;

	for (i=0;i<list2->count;i++) {
		if (list_find(list2->dn[i], list->dn, count, 
			      sizeof(char *), (comparison_fn_t)strcmp) == -1) {
			list->dn[list->count] = strdup(list2->dn[i]);
			if (!list->dn[list->count]) {
				dn_list_free(list);
				return -1;
			}
			list->count++;
		}		
	}

	if (list->count != count) {
		qsort(list->dn, list->count, sizeof(char *), (comparison_fn_t)strcmp);
	}

	return 0;
}

static int ltdb_index_dn(struct ldb_context *ldb, 
			 struct ldb_parse_tree *tree,
			 const struct ldb_message *index_list,
			 struct dn_list *list);


/*
  OR two index results
 */
static int ltdb_index_dn_or(struct ldb_context *ldb, 
			    struct ldb_parse_tree *tree,
			    const struct ldb_message *index_list,
			    struct dn_list *list)
{
	int ret, i;
	
	ret = -1;
	list->dn = NULL;
	list->count = 0;

	for (i=0;i<tree->u.list.num_elements;i++) {
		struct dn_list list2;
		int v;
		v = ltdb_index_dn(ldb, tree->u.list.elements[i], index_list, &list2);

		if (v == 0) {
			/* 0 || X == X */
			if (ret == -1) {
				ret = 0;
			}
			continue;
		}

		if (v == -1) {
			/* 1 || X == 1 */
			dn_list_free(list);
			return -1;
		}

		if (ret == -1) {
			ret = 1;
			*list = list2;
		} else {
			if (list_union(list, &list2) == -1) {
				dn_list_free(&list2);
				return -1;
			}
			dn_list_free(&list2);
		}
	}

	if (list->count == 0) {
		dn_list_free(list);
		return 0;
	}

	return ret;
}


/*
  NOT an index results
 */
static int ltdb_index_dn_not(struct ldb_context *ldb, 
			     struct ldb_parse_tree *tree,
			     const struct ldb_message *index_list,
			     struct dn_list *list)
{
	/* the only way to do an indexed not would be if we could
	   negate the not via another not or if we knew the total
	   number of database elements so we could know that the
	   existing expression covered the whole database. 
	   
	   instead, we just give up, and rely on a full index scan
	   (unless an outer & manages to reduce the list)
	*/
	return -1;
}

/*
  AND two index results
 */
static int ltdb_index_dn_and(struct ldb_context *ldb, 
			     struct ldb_parse_tree *tree,
			     const struct ldb_message *index_list,
			     struct dn_list *list)
{
	int ret, i;
	
	ret = -1;
	list->dn = NULL;
	list->count = 0;

	for (i=0;i<tree->u.list.num_elements;i++) {
		struct dn_list list2;
		int v;
		v = ltdb_index_dn(ldb, tree->u.list.elements[i], index_list, &list2);

		if (v == 0) {
			/* 0 && X == 0 */
			dn_list_free(list);
			return 0;
		}

		if (v == -1) {
			continue;
		}

		if (ret == -1) {
			ret = 1;
			*list = list2;
		} else {
			if (list_intersect(list, &list2) == -1) {
				dn_list_free(&list2);
				return -1;
			}
			dn_list_free(&list2);
		}

		if (list->count == 0) {
			if (list->dn) free(list->dn);
			return 0;
		}
	}

	return ret;
}

/*
  return a list of dn's that might match a indexed search or
  -1 if an error. return 0 for no matches, or 1 for matches
 */
static int ltdb_index_dn(struct ldb_context *ldb, 
			 struct ldb_parse_tree *tree,
			 const struct ldb_message *index_list,
			 struct dn_list *list)
{
	int ret;

	switch (tree->operation) {
	case LDB_OP_SIMPLE:
		ret = ltdb_index_dn_simple(ldb, tree, index_list, list);
		break;

	case LDB_OP_AND:
		ret = ltdb_index_dn_and(ldb, tree, index_list, list);
		break;

	case LDB_OP_OR:
		ret = ltdb_index_dn_or(ldb, tree, index_list, list);
		break;

	case LDB_OP_NOT:
		ret = ltdb_index_dn_not(ldb, tree, index_list, list);
		break;
	}

	return ret;
}

/*
  filter a candidate dn_list from an indexed search into a set of results
  extracting just the given attributes
*/
static int ldb_index_filter(struct ldb_context *ldb, struct ldb_parse_tree *tree,
			    const char *base,
			    enum ldb_scope scope,
			    const struct dn_list *dn_list, 
			    char * const attrs[], struct ldb_message ***res)
{
	int i;
	unsigned int count = 0;

	for (i=0;i<dn_list->count;i++) {
		struct ldb_message msg;
		int ret;
		ret = ltdb_search_dn1(ldb, dn_list->dn[i], &msg);
		if (ret == 0) {
			/* the record has disappeared? yes, this can happen */
			continue;
		}

		if (ret == -1) {
			/* an internal error */
			return -1;
		}

		if (ldb_message_match(ldb, &msg, tree, base, scope) == 1) {
			ret = ltdb_add_attr_results(ldb, &msg, attrs, &count, res);
		}
		ltdb_search_dn1_free(ldb, &msg);
		if (ret != 0) {
			return -1;
		}
	}

	return count;
}

/*
  search the database with a LDAP-like expression using indexes
  returns -1 if an indexed search is not possible, in which
  case the caller should call ltdb_search_full() 
*/
int ltdb_search_indexed(struct ldb_context *ldb, 
			const char *base,
			enum ldb_scope scope,
			struct ldb_parse_tree *tree,
			char * const attrs[], struct ldb_message ***res)
{
	struct ltdb_private *ltdb = ldb->private_data;
	struct dn_list dn_list;
	int ret;

	if (ltdb->cache.indexlist.num_elements == 0) {
		/* no index list? must do full search */
		return -1;
	}

	ret = ltdb_index_dn(ldb, tree, &ltdb->cache.indexlist, &dn_list);

	if (ret == 1) {
		/* we've got a candidate list - now filter by the full tree
		   and extract the needed attributes */
		ret = ldb_index_filter(ldb, tree, base, scope, &dn_list, 
				       attrs, res);
		dn_list_free(&dn_list);
	}

	return ret;
}

/*
  add a index element where this is the first indexed DN for this value
*/
static int ltdb_index_add1_new(struct ldb_context *ldb, 
			       struct ldb_message *msg,
			       struct ldb_message_element *el,
			       char *dn)
{
	struct ldb_message_element *el2;

	/* add another entry */
	el2 = realloc_p(msg->elements, struct ldb_message_element, msg->num_elements+1);
	if (!el2) {
		return -1;
	}

	msg->elements = el2;
	msg->elements[msg->num_elements].name = LTDB_IDX;
	msg->elements[msg->num_elements].num_values = 0;
	msg->elements[msg->num_elements].values = malloc_p(struct ldb_val);
	if (!msg->elements[msg->num_elements].values) {
		return -1;
	}
	msg->elements[msg->num_elements].values[0].length = strlen(dn);
	msg->elements[msg->num_elements].values[0].data = dn;
	msg->elements[msg->num_elements].num_values = 1;
	msg->num_elements++;

	return 0;
}


/*
  add a index element where this is not the first indexed DN for this
  value
*/
static int ltdb_index_add1_add(struct ldb_context *ldb, 
			       struct ldb_message *msg,
			       struct ldb_message_element *el,
			       int idx,
			       char *dn)
{
	struct ldb_val *v2;

	v2 = realloc_p(msg->elements[idx].values,
		       struct ldb_val, 
		       msg->elements[idx].num_values+1);
	if (!v2) {
		return -1;
	}
	msg->elements[idx].values = v2;

	msg->elements[idx].values[msg->elements[idx].num_values].length = strlen(dn);
	msg->elements[idx].values[msg->elements[idx].num_values].data = dn;
	msg->elements[idx].num_values++;

	return 0;
}

/*
  add an index entry for one message element
*/
static int ltdb_index_add1(struct ldb_context *ldb, char *dn, 
			   struct ldb_message_element *el, int v_idx)
{
	struct ldb_message msg;
	char *dn_key;
	int ret, i;

	dn_key = ldb_dn_key(el->name, &el->values[v_idx]);
	if (!dn_key) {
		return -1;
	}

	ret = ltdb_search_dn1(ldb, dn_key, &msg);
	if (ret == -1) {
		free(dn_key);
		return -1;
	}

	if (ret == 0) {
		msg.dn = strdup(dn_key);
		if (!msg.dn) {
			free(dn_key);
			errno = ENOMEM;
			return -1;
		}
		msg.num_elements = 0;
		msg.elements = NULL;
		msg.private_data = NULL;
	}

	free(dn_key);

	for (i=0;i<msg.num_elements;i++) {
		if (strcmp(LTDB_IDX, msg.elements[i].name) == 0) {
			break;
		}
	}

	if (i == msg.num_elements) {
		ret = ltdb_index_add1_new(ldb, &msg, el, dn);
	} else {
		ret = ltdb_index_add1_add(ldb, &msg, el, i, dn);
	}

	if (ret == 0) {
		ret = ltdb_store(ldb, &msg, TDB_REPLACE);
	}

	ltdb_search_dn1_free(ldb, &msg);

	return ret;
}

/*
  add the index entries for a new record
  return -1 on failure
*/
int ltdb_index_add(struct ldb_context *ldb, const struct ldb_message *msg)
{
	struct ltdb_private *ltdb = ldb->private_data;
	int ret, i, j;

	if (ltdb->cache.indexlist.num_elements == 0) {
		/* no indexed fields */
		return 0;
	}

	for (i=0;i<msg->num_elements;i++) {
		ret = ldb_msg_find_idx(&ltdb->cache.indexlist, msg->elements[i].name, NULL);
		if (ret == -1) {
			continue;
		}
		for (j=0;j<msg->elements[i].num_values;j++) {
			ret = ltdb_index_add1(ldb, msg->dn, &msg->elements[i], j);
			if (ret == -1) {
				return -1;
			}
		}
	}

	return 0;
}


/*
  delete an index entry for one message element
*/
static int ltdb_index_del1(struct ldb_context *ldb, const char *dn, 
			   struct ldb_message_element *el, int v_idx)
{
	struct ldb_message msg;
	char *dn_key;
	int ret, i, j;

	dn_key = ldb_dn_key(el->name, &el->values[v_idx]);
	if (!dn_key) {
		return -1;
	}

	ret = ltdb_search_dn1(ldb, dn_key, &msg);
	if (ret == -1) {
		free(dn_key);
		return -1;
	}

	if (ret == 0) {
		/* it wasn't indexed. Did we have an earlier error? If we did then
		   its gone now */
		ltdb_search_dn1_free(ldb, &msg);
		return 0;
	}

	i = ldb_msg_find_idx(&msg, dn, &j);
	if (i == -1) {
		/* it ain't there. hmmm */
		ltdb_search_dn1_free(ldb, &msg);
		return 0;
	}

	if (j != msg.elements[i].num_values - 1) {
		memmove(&msg.elements[i].values[j], 
			&msg.elements[i].values[j+1], 
			(msg.elements[i].num_values-1) * 
			sizeof(msg.elements[i].values[0]));
	}
	msg.elements[i].num_values--;

	if (msg.elements[i].num_values == 0) {
		ret = ltdb_delete_noindex(ldb, dn_key);
	} else {
		ret = ltdb_store(ldb, &msg, TDB_REPLACE);
	}

	ltdb_search_dn1_free(ldb, &msg);

	return ret;
}

/*
  delete the index entries for a record
  return -1 on failure
*/
int ltdb_index_del(struct ldb_context *ldb, const struct ldb_message *msg)
{
	struct ltdb_private *ltdb = ldb->private_data;
	int ret, i, j;

	/* find the list of indexed fields */	
	if (ltdb->cache.indexlist.num_elements == 0) {
		/* no indexed fields */
		return 0;
	}

	for (i=0;i<msg->num_elements;i++) {
		ret = ldb_msg_find_idx(&ltdb->cache.indexlist, msg->elements[i].name, NULL);
		if (ret == -1) {
			continue;
		}
		for (j=0;j<msg->elements[i].num_values;j++) {
			ret = ltdb_index_del1(ldb, msg->dn, &msg->elements[i], j);
			if (ret == -1) {
				return -1;
			}
		}
	}

	return 0;
}


/*
  traversal function that deletes all @INDEX records
*/
static int delete_index(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	const char *dn = "DN=" LTDB_INDEX ":";
	if (strncmp(key.dptr, dn, strlen(dn)) == 0) {
		return tdb_delete(tdb, key);
	}
	return 0;
}

/*
  traversal function that adds @INDEX records during a re index
*/
static int re_index(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	struct ldb_context *ldb = state;
	struct ldb_message msg;
	int ret;

	if (strncmp(key.dptr, "DN=@", 4) == 0 ||
	    strncmp(key.dptr, "DN=", 3) != 0) {
		return 0;
	}

	ret = ltdb_unpack_data(ldb, &data, &msg);
	if (ret != 0) {
		return -1;
	}

	if (!msg.dn) {
		msg.dn = key.dptr+3;
	}

	ret = ltdb_index_add(ldb, &msg);

	ltdb_unpack_data_free(&msg);

	return ret;
}

/*
  force a complete reindex of the database
*/
int ltdb_reindex(struct ldb_context *ldb)
{
	struct ltdb_private *ltdb = ldb->private_data;
	int ret;

	ltdb_cache_free(ldb);

	if (ltdb_cache_load(ldb) != 0) {
		return -1;
	}

	/* first traverse the database deleting any @INDEX records */
	ret = tdb_traverse(ltdb->tdb, delete_index, NULL);
	if (ret == -1) {
		errno = EIO;
		return -1;
	}

	/* now traverse adding any indexes for normal LDB records */
	ret = tdb_traverse(ltdb->tdb, re_index, ldb);
	if (ret == -1) {
		errno = EIO;
		return -1;
	}

	return 0;
}
