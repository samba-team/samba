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
 *  Component: ldb message component utility functions
 *
 *  Description: functions for manipulating ldb_message structures
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"

/*
  create a new ldb_message in a given memory context (NULL for top level)
*/
struct ldb_message *ldb_msg_new(void *mem_ctx)
{
	return talloc_zero_p(mem_ctx, struct ldb_message);
}

/*
  find an element in a message by attribute name
*/
struct ldb_message_element *ldb_msg_find_element(const struct ldb_message *msg, 
						 const char *attr_name)
{
	unsigned int i;
	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, attr_name) == 0) {
			return &msg->elements[i];
		}
	}
	return NULL;
}

/*
  see if two ldb_val structures contain exactly the same data
  return 1 for a match, 0 for a mis-match
*/
int ldb_val_equal_exact(const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (v1->length != v2->length) return 0;

	if (v1->length == 0) return 1;

	if (memcmp(v1->data, v2->data, v1->length) == 0) {
		return 1;
	}

	return 0;
}

/*
  find a value in an element
  assumes case sensitive comparison
*/
struct ldb_val *ldb_msg_find_val(const struct ldb_message_element *el, 
				 struct ldb_val *val)
{
	unsigned int i;
	for (i=0;i<el->num_values;i++) {
		if (ldb_val_equal_exact(val, &el->values[i])) {
			return &el->values[i];
		}
	}
	return NULL;
}

/*
  duplicate a ldb_val structure
*/
struct ldb_val ldb_val_dup(TALLOC_CTX *mem_ctx, 
			   const struct ldb_val *v)
{
	struct ldb_val v2;
	v2.length = v->length;
	if (v->length == 0) {
		v2.data = NULL;
		return v2;
	}

	/* the +1 is to cope with buggy C library routines like strndup
	   that look one byte beyond */
	v2.data = talloc_array_p(mem_ctx, char, v->length+1);
	if (!v2.data) {
		v2.length = 0;
		return v2;
	}

	memcpy(v2.data, v->data, v->length);
	((char *)v2.data)[v->length] = 0;
	return v2;
}

/*
  add an empty element to a message
*/
int ldb_msg_add_empty(struct ldb_context *ldb,
		      struct ldb_message *msg, const char *attr_name, int flags)
{
	struct ldb_message_element *els;

	els = talloc_realloc_p(msg, msg->elements, 
			       struct ldb_message_element, msg->num_elements+1);
	if (!els) {
		errno = ENOMEM;
		return -1;
	}

	els[msg->num_elements].values = NULL;
	els[msg->num_elements].num_values = 0;
	els[msg->num_elements].flags = flags;
	els[msg->num_elements].name = talloc_strdup(els, attr_name);
	if (!els[msg->num_elements].name) {
		return -1;
	}

	msg->elements = els;
	msg->num_elements++;

	return 0;
}

/*
  add an empty element to a message
*/
int ldb_msg_add(struct ldb_context *ldb,
		struct ldb_message *msg, 
		const struct ldb_message_element *el, 
		int flags)
{
	if (ldb_msg_add_empty(ldb, msg, el->name, flags) != 0) {
		return -1;
	}

	msg->elements[msg->num_elements-1] = *el;
	msg->elements[msg->num_elements-1].flags = flags;

	return 0;
}

/*
  add a value to a message
*/
int ldb_msg_add_value(struct ldb_context *ldb,
		      struct ldb_message *msg, 
		      const char *attr_name,
		      struct ldb_val *val)
{
	struct ldb_message_element *el;
	struct ldb_val *vals;

	el = ldb_msg_find_element(msg, attr_name);
	if (!el) {
		ldb_msg_add_empty(ldb, msg, attr_name, 0);
		el = ldb_msg_find_element(msg, attr_name);
	}
	if (!el) {
		return -1;
	}

	vals = talloc_realloc_p(msg, el->values, struct ldb_val, el->num_values+1);
	if (!vals) {
		errno = ENOMEM;
		return -1;
	}
	el->values = vals;
	el->values[el->num_values] = *val;
	el->num_values++;

	return 0;
}


/*
  add a string element to a message
*/
int ldb_msg_add_string(struct ldb_context *ldb, struct ldb_message *msg, 
		       const char *attr_name, char *str)
{
	struct ldb_val val;

	val.data = str;
	val.length = strlen(str);

	return ldb_msg_add_value(ldb, msg, attr_name, &val);
}

/*
  compare two ldb_message_element structures
  assumes case senistive comparison
*/
int ldb_msg_element_compare(struct ldb_message_element *el1, 
			    struct ldb_message_element *el2)
{
	unsigned int i;

	if (el1->num_values != el2->num_values) {
		return el1->num_values - el2->num_values;
	}

	for (i=0;i<el1->num_values;i++) {
		if (!ldb_msg_find_val(el2, &el1->values[i])) {
			return -1;
		}
	}

	return 0;
}

/*
  compare two ldb_message_element structures
  comparing by element name
*/
int ldb_msg_element_compare_name(struct ldb_message_element *el1, 
				 struct ldb_message_element *el2)
{
	return ldb_attr_cmp(el1->name, el2->name);
}

/*
  convenience functions to return common types from a message
  these return the first value if the attribute is multi-valued
*/
const struct ldb_val *ldb_msg_find_ldb_val(const struct ldb_message *msg, const char *attr_name)
{
	struct ldb_message_element *el = ldb_msg_find_element(msg, attr_name);
	if (!el || el->num_values == 0) {
		return NULL;
	}
	return &el->values[0];
}

int ldb_msg_find_int(const struct ldb_message *msg, 
		     const char *attr_name,
		     int default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return default_value;
	}
	return strtol(v->data, NULL, 0);
}

unsigned int ldb_msg_find_uint(const struct ldb_message *msg, 
			       const char *attr_name,
			       unsigned int default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return default_value;
	}
	return strtoul(v->data, NULL, 0);
}

int64_t ldb_msg_find_int64(const struct ldb_message *msg, 
			   const char *attr_name,
			   int64_t default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return default_value;
	}
	return strtoll(v->data, NULL, 0);
}

uint64_t ldb_msg_find_uint64(const struct ldb_message *msg, 
			     const char *attr_name,
			     uint64_t default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return default_value;
	}
	return strtoull(v->data, NULL, 0);
}

double ldb_msg_find_double(const struct ldb_message *msg, 
			   const char *attr_name,
			   double default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return default_value;
	}
	return strtod(v->data, NULL);
}

const char *ldb_msg_find_string(const struct ldb_message *msg, 
				const char *attr_name,
				const char *default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return default_value;
	}
	return v->data;
}


/*
  sort the elements of a message by name
*/
void ldb_msg_sort_elements(struct ldb_message *msg)
{
	qsort(msg->elements, msg->num_elements, sizeof(struct ldb_message_element), 
	      (comparison_fn_t)ldb_msg_element_compare_name);
}


/*
  free a message created using ldb_msg_copy
*/
void ldb_msg_free(struct ldb_context *ldb, struct ldb_message *msg)
{
	talloc_free(msg);
}

/*
  copy a message, allocating new memory for all parts
*/
struct ldb_message *ldb_msg_copy(struct ldb_context *ldb, 
				 const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	int i, j;

	msg2 = talloc_p(ldb, struct ldb_message);
	if (msg2 == NULL) return NULL;

	msg2->elements = NULL;
	msg2->num_elements = 0;
	msg2->private_data = NULL;

	msg2->dn = talloc_strdup(msg2, msg->dn);
	if (msg2->dn == NULL) goto failed;

	msg2->elements = talloc_array_p(msg2, struct ldb_message_element, msg->num_elements);
	if (msg2->elements == NULL) goto failed;

	for (i=0;i<msg->num_elements;i++) {
		struct ldb_message_element *el1 = &msg->elements[i];
		struct ldb_message_element *el2 = &msg2->elements[i];

		el2->flags = el1->flags;
		el2->num_values = 0;
		el2->values = NULL;
		el2->name = talloc_strdup(msg2->elements, el1->name);
		if (el2->name == NULL) goto failed;
		el2->values = talloc_array_p(msg2->elements, struct ldb_val, el1->num_values);
		for (j=0;j<el1->num_values;j++) {
			el2->values[j] = ldb_val_dup(ldb, &el1->values[j]);
			if (el2->values[j].data == NULL &&
			    el1->values[j].length != 0) {
				goto failed;
			}
			el2->values[j].data = talloc_steal(el2->values, el2->values[j].data);
			el2->num_values++;
		}

		msg2->num_elements++;
	}

	return msg2;

failed:
	talloc_free(msg2);
	return NULL;
}


/*
  canonicalise a message, merging elements of the same name
*/
struct ldb_message *ldb_msg_canonicalize(struct ldb_context *ldb, 
					 const struct ldb_message *msg)
{
	int i;
	struct ldb_message *msg2;

	msg2 = ldb_msg_copy(ldb, msg);
	if (msg2 == NULL) return NULL;

	ldb_msg_sort_elements(msg2);

	for (i=1;i<msg2->num_elements;i++) {
		struct ldb_message_element *el1 = &msg2->elements[i-1];
		struct ldb_message_element *el2 = &msg2->elements[i];
		if (ldb_msg_element_compare_name(el1, el2) == 0) {
			el1->values = talloc_realloc_p(msg2->elements, el1->values, struct ldb_val, 
						       el1->num_values + el2->num_values);
			if (el1->values == NULL) {
				return NULL;
			}
			memcpy(el1->values + el1->num_values,
			       el2->values,
			       sizeof(struct ldb_val) * el2->num_values);
			el1->num_values += el2->num_values;
			talloc_free(el2->name);
			talloc_free(el2->values);
			if (i+1<msg2->num_elements) {
				memmove(el2, el2+1, sizeof(struct ldb_message_element) * 
					(msg2->num_elements - (i+1)));
			}
			msg2->num_elements--;
			i--;
		}
	}

	return msg2;
}
