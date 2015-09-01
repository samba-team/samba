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

/* change this if the data format ever changes */
#define LDB_PACKING_FORMAT 0x26011967

/* old packing formats */
#define LDB_PACKING_FORMAT_NODN 0x26011966

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

static bool ldb_consume_element_data(uint8_t **pp, size_t *premaining)
{
	unsigned int remaining = *premaining;
	uint8_t *p = *pp;
	uint32_t num_values = pull_uint32(p, 0);
	uint32_t len;
	int j;

	p += 4;
	if (remaining < 4) {
		return false;
	}
	remaining -= 4;
	for (j = 0; j < num_values; j++) {
		len = pull_uint32(p, 0);
		if (remaining < 5) {
			return false;
		}
		remaining -= 5;
		if (len > remaining) {
			return false;
		}
		remaining -= len;
		p += len + 4 + 1;
	}

	*premaining = remaining;
	*pp = p;
	return true;
}

/*
 * Unpack a ldb message from a linear buffer in ldb_val
 *
 * Providing a list of attributes to this function allows selective unpacking.
 * Giving a NULL list (or a list_size of 0) unpacks all the attributes.
 *
 * Free with ldb_unpack_data_free()
 */
int ldb_unpack_data_only_attr_list(struct ldb_context *ldb,
				   const struct ldb_val *data,
				   struct ldb_message *message,
				   const char * const *list,
				   unsigned int list_size,
				   unsigned int *nb_elements_in_db)
{
	uint8_t *p;
	size_t remaining;
	size_t dn_len;
	unsigned int i, j;
	unsigned format;
	unsigned int nelem = 0;
	size_t len;
	unsigned int found = 0;

	if (list == NULL) {
		list_size = 0;
	}

	message->elements = NULL;

	p = data->data;
	if (data->length < 8) {
		errno = EIO;
		goto failed;
	}

	format = pull_uint32(p, 0);
	message->num_elements = pull_uint32(p, 4);
	p += 8;
	if (nb_elements_in_db) {
		*nb_elements_in_db = message->num_elements;
	}

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
		message->dn = ldb_dn_new(message, ldb, (char *)p);
		if (message->dn == NULL) {
			errno = ENOMEM;
			goto failed;
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

		/*
		 * The general idea is to reduce allocations by skipping over
		 * attributes that we do not actually care about.
		 *
		 * This is a bit expensive but normally the list is pretty small
		 * also the cost of freeing unused attributes is quite important
		 * and can dwarf the cost of looping.
		 */
		if (list_size != 0) {
			bool keep = false;
			int h;

			/*
			 * We know that p has a \0 terminator before the
			 * end of the buffer due to the check above.
			 */
			for (h = 0; h < list_size && found < list_size; h++) {
				if (ldb_attr_cmp(attr, list[h]) == 0) {
					keep = true;
					found++;
					break;
				}
			}

			if (!keep) {
				if (remaining < (attr_len + 1)) {
					errno = EIO;
					goto failed;
				}
				remaining -= attr_len + 1;
				p += attr_len + 1;
				if (!ldb_consume_element_data(&p, &remaining)) {
					errno = EIO;
					goto failed;
				}
				continue;
			}
		}
		element = &message->elements[nelem];
		element->name = talloc_memdup(message->elements, attr, attr_len+1);

		if (element->name == NULL) {
			errno = ENOMEM;
			goto failed;
		}
		element->flags = 0;

		if (remaining < (attr_len + 1)) {
			errno = EIO;
			goto failed;
		}
		remaining -= attr_len + 1;
		p += attr_len + 1;
		element->num_values = pull_uint32(p, 0);
		element->values = NULL;
		if (element->num_values != 0) {
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
			element->values[j].data = talloc_size(element->values, len+1);
			if (element->values[j].data == NULL) {
				errno = ENOMEM;
				goto failed;
			}
			memcpy(element->values[j].data, p + 4,
			       len);
			element->values[j].data[len] = 0;

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
			  "Error: %zu bytes unread in ldb_unpack_data_only_attr_list",
			  remaining);
	}

	return 0;

failed:
	talloc_free(message->elements);
	return -1;
}

int ldb_unpack_data(struct ldb_context *ldb,
		    const struct ldb_val *data,
		    struct ldb_message *message)
{
	return ldb_unpack_data_only_attr_list(ldb, data, message, NULL, 0, NULL);
}
