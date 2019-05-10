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
 *  Component: ldb pack/unpack
 *
 *  Description: pack/unpack routines for ldb messages as key/value blobs
 *
 *  Author: Andrew Tridgell
 */

#include "ldb_private.h"

/* use a portable integer format */
static void put_uint32(uint8_t *p, int ofs, unsigned int val)
{
	p += ofs;
	p[0] = val&0xFF;
	p[1] = (val>>8)  & 0xFF;
	p[2] = (val>>16) & 0xFF;
	p[3] = (val>>24) & 0xFF;
}

static unsigned int pull_uint32(uint8_t *p, int ofs)
{
	p += ofs;
	return p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
}

static int attribute_storable_values(const struct ldb_message_element *el)
{
	if (el->num_values == 0) return 0;

	if (ldb_attr_cmp(el->name, "distinguishedName") == 0) return 0;

	return el->num_values;
}

/*
  pack a ldb message into a linear buffer in a ldb_val

  note that this routine avoids saving elements with zero values,
  as these are equivalent to having no element

  caller frees the data buffer after use
*/
int ldb_pack_data(struct ldb_context *ldb,
		  const struct ldb_message *message,
		  struct ldb_val *data)
{
	unsigned int i, j, real_elements=0;
	size_t size, dn_len, attr_len, value_len;
	const char *dn;
	uint8_t *p;
	size_t len;

	dn = ldb_dn_get_linearized(message->dn);
	if (dn == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/* work out how big it needs to be */
	size = 8;

	size += 1;

	dn_len = strlen(dn);
	if (size + dn_len < size) {
		errno = ENOMEM;
		return -1;
	}
	size += dn_len;

	/*
	 * First calcuate the buffer size we need, and check for
	 * overflows
	 */
	for (i=0;i<message->num_elements;i++) {
		if (attribute_storable_values(&message->elements[i]) == 0) {
			continue;
		}

		real_elements++;

		if (size + 5 < size) {
			errno = ENOMEM;
			return -1;
		}
		size += 5;

		attr_len = strlen(message->elements[i].name);
		if (size + attr_len < size) {
			errno = ENOMEM;
			return -1;
		}
		size += attr_len;

		for (j=0;j<message->elements[i].num_values;j++) {
			if (size + 5 < size) {
				errno = ENOMEM;
				return -1;
			}
			size += 5;

			value_len = message->elements[i].values[j].length;
			if (size + value_len < size) {
				errno = ENOMEM;
				return -1;
			}
			size += value_len;
		}
	}

	/* allocate it */
	data->data = talloc_array(ldb, uint8_t, size);
	if (!data->data) {
		errno = ENOMEM;
		return -1;
	}
	data->length = size;

	p = data->data;
	put_uint32(p, 0, LDB_PACKING_FORMAT);
	put_uint32(p, 4, real_elements);
	p += 8;

	/* the dn needs to be packed so we can be case preserving
	   while hashing on a case folded dn */
	len = dn_len;
	memcpy(p, dn, len+1);
	p += len + 1;

	for (i=0;i<message->num_elements;i++) {
		if (attribute_storable_values(&message->elements[i]) == 0) {
			continue;
		}
		len = strlen(message->elements[i].name);
		memcpy(p, message->elements[i].name, len+1);
		p += len + 1;
		put_uint32(p, 0, message->elements[i].num_values);
		p += 4;
		for (j=0;j<message->elements[i].num_values;j++) {
			put_uint32(p, 0, message->elements[i].values[j].length);
			memcpy(p+4, message->elements[i].values[j].data,
			       message->elements[i].values[j].length);
			p[4+message->elements[i].values[j].length] = 0;
			p += 4 + message->elements[i].values[j].length + 1;
		}
	}

	return 0;
}

/*
 * Unpack a ldb message from a linear buffer in ldb_val
 *
 * Providing a list of attributes to this function allows selective unpacking.
 * Giving a NULL list (or a list_size of 0) unpacks all the attributes.
 */
int ldb_unpack_data_flags(struct ldb_context *ldb,
			  const struct ldb_val *data,
			  struct ldb_message *message,
			  unsigned int flags)
{
	uint8_t *p;
	size_t remaining;
	size_t dn_len;
	unsigned int i, j;
	uint32_t format;
	unsigned int nelem = 0;
	size_t len;
	struct ldb_val *ldb_val_single_array = NULL;

	message->elements = NULL;

	p = data->data;
	if (data->length < 8) {
		errno = EIO;
		goto failed;
	}

	if (ldb_unpack_get_format(data, &format) != LDB_SUCCESS) {
		errno = EIO;
		goto failed;
	}
	message->num_elements = pull_uint32(p, 4);
	p += 8;

	remaining = data->length - 8;

	switch (format) {
	case LDB_PACKING_FORMAT_NODN:
		message->dn = NULL;
		break;

	case LDB_PACKING_FORMAT:
		/*
		 * With this check, we know that the DN at p is \0
		 * terminated.
		 */
		dn_len = strnlen((char *)p, remaining);
		if (dn_len == remaining) {
			errno = EIO;
			goto failed;
		}
		if (flags & LDB_UNPACK_DATA_FLAG_NO_DN) {
			message->dn = NULL;
		} else {
			struct ldb_val blob;
			blob.data = discard_const_p(uint8_t, p);
			blob.length = dn_len;
			message->dn = ldb_dn_from_ldb_val(message, ldb, &blob);
			if (message->dn == NULL) {
				errno = ENOMEM;
				goto failed;
			}
		}
		/*
		 * Redundant: by definition, remaining must be more
		 * than one less than dn_len, as otherwise it would be
		 * == dn_len
		 */
		if (remaining < dn_len + 1) {
			errno = EIO;
			goto failed;
		}
		remaining -= dn_len + 1;
		p += dn_len + 1;
		break;

	default:
		errno = EIO;
		goto failed;
	}

	
	if (flags & LDB_UNPACK_DATA_FLAG_NO_ATTRS) {
		return 0;
	}
	
	if (message->num_elements == 0) {
		return 0;
	}

	if (message->num_elements > remaining / 6) {
		errno = EIO;
		goto failed;
	}

	message->elements = talloc_zero_array(message, struct ldb_message_element,
					      message->num_elements);
	if (!message->elements) {
		errno = ENOMEM;
		goto failed;
	}

	/*
	 * In typical use, most values are single-valued.  This makes
	 * it quite expensive to allocate an array of ldb_val for each
	 * of these, just to then hold the pointer to the data buffer
	 * So with LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC we allocate this
	 * ahead of time and use it for the single values where possible.
	 * (This is used the the normal search case, but not in the
	 * index case because of caller requirements).
	 */
	if (flags & LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC) {
		ldb_val_single_array = talloc_array(message->elements, struct ldb_val,
						    message->num_elements);
		if (ldb_val_single_array == NULL) {
			errno = ENOMEM;
			goto failed;
		}
	}

	for (i=0;i<message->num_elements;i++) {
		const char *attr = NULL;
		size_t attr_len;
		struct ldb_message_element *element = NULL;

		if (remaining < 10) {
			errno = EIO;
			goto failed;
		}
		/*
		 * With this check, we know that the attribute name at
		 * p is \0 terminated.
		 */
		attr_len = strnlen((char *)p, remaining-6);
		if (attr_len == remaining-6) {
			errno = EIO;
			goto failed;
		}
		if (attr_len == 0) {
			errno = EIO;
			goto failed;
		}
		attr = (char *)p;

		element = &message->elements[nelem];
		element->name = attr;
		element->flags = 0;

		if (remaining < (attr_len + 1)) {
			errno = EIO;
			goto failed;
		}
		remaining -= attr_len + 1;
		p += attr_len + 1;
		element->num_values = pull_uint32(p, 0);
		element->values = NULL;
		if ((flags & LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC) && element->num_values == 1) {
			element->values = &ldb_val_single_array[nelem];
		} else if (element->num_values != 0) {
			element->values = talloc_array(message->elements,
						       struct ldb_val,
						       element->num_values);
			if (!element->values) {
				errno = ENOMEM;
				goto failed;
			}
		}
		p += 4;
		if (remaining < 4) {
			errno = EIO;
			goto failed;
		}
		remaining -= 4;
		for (j = 0; j < element->num_values; j++) {
			if (remaining < 5) {
				errno = EIO;
				goto failed;
			}
			remaining -= 5;

			len = pull_uint32(p, 0);
			if (remaining < len) {
				errno = EIO;
				goto failed;
			}
			if (len + 1 < len) {
				errno = EIO;
				goto failed;
			}

			element->values[j].length = len;
			element->values[j].data = p + 4;
			remaining -= len;
			p += len+4+1;
		}
		nelem++;
	}
	/*
	 * Adapt the number of elements to the real number of unpacked elements,
	 * it means that we overallocated elements array.
	 */
	message->num_elements = nelem;

	/*
	 * Shrink the allocated size.  On current talloc behaviour
	 * this will help if we skipped 32 or more attributes.
	 */
	message->elements = talloc_realloc(message, message->elements,
					   struct ldb_message_element,
					   message->num_elements);

	if (remaining != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: %zu bytes unread in ldb_unpack_data_flags",
			  remaining);
	}

	return 0;

failed:
	talloc_free(message->elements);
	return -1;
}

int ldb_unpack_get_format(const struct ldb_val *data,
			  uint32_t *pack_format_version)
{
	if (data->length < 4) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*pack_format_version = pull_uint32(data->data, 0);
	return LDB_SUCCESS;
}

/*
 * Unpack a ldb message from a linear buffer in ldb_val
 *
 * Free with ldb_unpack_data_free()
 */
int ldb_unpack_data(struct ldb_context *ldb,
		    const struct ldb_val *data,
		    struct ldb_message *message)
{
	return ldb_unpack_data_flags(ldb, data, message, 0);
}

/*
  add the special distinguishedName element
*/
static int msg_add_distinguished_name(struct ldb_message *msg)
{
	const char *dn_attr = "distinguishedName";
	char *dn = NULL;

	if (ldb_msg_find_element(msg, dn_attr)) {
		/*
		 * This should not happen, but this is
		 * existing behaviour...
		 */
		return LDB_SUCCESS;
	}

	dn = ldb_dn_alloc_linearized(msg, msg->dn);
	if (dn == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_msg_add_steal_string(msg, dn_attr, dn);
}

/*
 * filter the specified list of attributes from msg,
 * adding requested attributes, and perhaps all for *,
 * but not the DN to filtered_msg.
 */
int ldb_filter_attrs(struct ldb_context *ldb,
		     const struct ldb_message *msg,
		     const char *const *attrs,
		     struct ldb_message *filtered_msg)
{
	unsigned int i;
	bool keep_all = false;
	bool add_dn = false;
	uint32_t num_elements;
	uint32_t elements_size;

	if (attrs) {
		/* check for special attrs */
		for (i = 0; attrs[i]; i++) {
			int cmp = strcmp(attrs[i], "*");
			if (cmp == 0) {
				keep_all = true;
				break;
			}
			cmp = ldb_attr_cmp(attrs[i], "distinguishedName");
			if (cmp == 0) {
				add_dn = true;
			}
		}
	} else {
		keep_all = true;
	}

	if (keep_all) {
		add_dn = true;
		elements_size = msg->num_elements + 1;

	/* Shortcuts for the simple cases */
	} else if (add_dn && i == 1) {
		if (msg_add_distinguished_name(filtered_msg) != 0) {
			goto failed;
		}
		return 0;
	} else if (i == 0) {
		return 0;

	/* Otherwise we are copying at most as many element as we have attributes */
	} else {
		elements_size = i;
	}

	filtered_msg->elements = talloc_array(filtered_msg,
					      struct ldb_message_element,
					      elements_size);
	if (filtered_msg->elements == NULL) goto failed;

	num_elements = 0;

	for (i = 0; i < msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i];
		struct ldb_message_element *el2 = &filtered_msg->elements[num_elements];
		unsigned int j;

		if (keep_all == false) {
			bool found = false;
			for (j = 0; attrs[j]; j++) {
				int cmp = ldb_attr_cmp(el->name, attrs[j]);
				if (cmp == 0) {
					found = true;
					break;
				}
			}
			if (found == false) {
				continue;
			}
		}
		*el2 = *el;
		el2->name = talloc_strdup(filtered_msg->elements,
					  el->name);
		if (el2->name == NULL) {
			goto failed;
		}
		el2->values = talloc_array(filtered_msg->elements,
					   struct ldb_val, el->num_values);
		if (el2->values == NULL) {
			goto failed;
		}
		for (j=0;j<el->num_values;j++) {
			el2->values[j] = ldb_val_dup(el2->values, &el->values[j]);
			if (el2->values[j].data == NULL && el->values[j].length != 0) {
				goto failed;
			}
		}
		num_elements++;

		/* Pidginhole principle: we can't have more elements
		 * than the number of attributes if they are unique in
		 * the DB */
		if (num_elements > elements_size) {
			goto failed;
		}
	}

	filtered_msg->num_elements = num_elements;

	if (add_dn) {
		if (msg_add_distinguished_name(filtered_msg) != 0) {
			goto failed;
		}
	}

	if (filtered_msg->num_elements > 0) {
		filtered_msg->elements
			= talloc_realloc(filtered_msg,
					 filtered_msg->elements,
					 struct ldb_message_element,
					 filtered_msg->num_elements);
		if (filtered_msg->elements == NULL) {
			goto failed;
		}
	} else {
		talloc_free(filtered_msg->elements);
		filtered_msg->elements = NULL;
	}

	return 0;
failed:
	return -1;
}
