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
  add an empty element to a message
*/
int ldb_msg_add_empty(struct ldb_context *ldb,
		      struct ldb_message *msg, const char *attr_name, int flags)
{
	struct ldb_message_element *els;

	els = ldb_realloc_p(ldb, msg->elements, 
			    struct ldb_message_element, msg->num_elements+1);
	if (!els) {
		errno = ENOMEM;
		return -1;
	}

	els[msg->num_elements].values = NULL;
	els[msg->num_elements].num_values = 0;
	els[msg->num_elements].flags = flags;
	els[msg->num_elements].name = ldb_strdup(ldb, attr_name);
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

	vals = ldb_realloc_p(ldb, el->values, struct ldb_val, el->num_values+1);
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
