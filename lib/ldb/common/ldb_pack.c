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

/*
 * These macros are from byte_array.h via libssh
 * TODO: This will be replaced with use of the byte_array.h header when it
 * becomes available.
 *
 * Macros for handling integer types in byte arrays
 *
 * This file is originally from the libssh.org project
 *
 * Copyright (c) 2018 Andreas Schneider <asn@cryptomilk.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#define _DATA_BYTE_CONST(data, pos) \
	((uint8_t)(((const uint8_t *)(data))[(pos)]))
#define PULL_LE_U8(data, pos) \
	(_DATA_BYTE_CONST(data, pos))
#define PULL_LE_U16(data, pos) \
	((uint16_t)PULL_LE_U8(data, pos) |\
	((uint16_t)(PULL_LE_U8(data, (pos) + 1))) << 8)
#define PULL_LE_U32(data, pos) \
	((uint32_t)(PULL_LE_U16(data, pos) |\
	((uint32_t)PULL_LE_U16(data, (pos) + 2)) << 16))

#define _DATA_BYTE(data, pos) \
	(((uint8_t *)(data))[(pos)])
#define PUSH_LE_U8(data, pos, val) \
	(_DATA_BYTE(data, pos) = ((uint8_t)(val)))
#define PUSH_LE_U16(data, pos, val) \
	(PUSH_LE_U8((data), (pos), (uint8_t)((uint16_t)(val) & 0xff)),\
		    PUSH_LE_U8((data), (pos) + 1,\
			       (uint8_t)((uint16_t)(val) >> 8)))
#define PUSH_LE_U32(data, pos, val) \
	(PUSH_LE_U16((data), (pos), (uint16_t)((uint32_t)(val) & 0xffff)),\
	 PUSH_LE_U16((data), (pos) + 2, (uint16_t)((uint32_t)(val) >> 16)))

#define U32_LEN 4
#define U16_LEN 2
#define U8_LEN 1
#define NULL_PAD_BYTE_LEN 1

static int attribute_storable_values(const struct ldb_message_element *el)
{
	if (el->num_values == 0) return 0;

	if (ldb_attr_cmp(el->name, "distinguishedName") == 0) return 0;

	return el->num_values;
}

static int ldb_pack_data_v1(struct ldb_context *ldb,
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
	size = U32_LEN * 2 + NULL_PAD_BYTE_LEN;

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

		if (size + U32_LEN + NULL_PAD_BYTE_LEN < size) {
			errno = ENOMEM;
			return -1;
		}
		size += U32_LEN + NULL_PAD_BYTE_LEN;

		attr_len = strlen(message->elements[i].name);
		if (size + attr_len < size) {
			errno = ENOMEM;
			return -1;
		}
		size += attr_len;

		for (j=0;j<message->elements[i].num_values;j++) {
			if (size + U32_LEN + NULL_PAD_BYTE_LEN < size) {
				errno = ENOMEM;
				return -1;
			}
			size += U32_LEN + NULL_PAD_BYTE_LEN;

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
	PUSH_LE_U32(p, 0, LDB_PACKING_FORMAT);
	p += U32_LEN;
	PUSH_LE_U32(p, 0, real_elements);
	p += U32_LEN;

	/* the dn needs to be packed so we can be case preserving
	   while hashing on a case folded dn */
	len = dn_len;
	memcpy(p, dn, len+NULL_PAD_BYTE_LEN);
	p += len + NULL_PAD_BYTE_LEN;

	for (i=0;i<message->num_elements;i++) {
		if (attribute_storable_values(&message->elements[i]) == 0) {
			continue;
		}
		len = strlen(message->elements[i].name);
		memcpy(p, message->elements[i].name, len+NULL_PAD_BYTE_LEN);
		p += len + NULL_PAD_BYTE_LEN;
		PUSH_LE_U32(p, 0, message->elements[i].num_values);
		p += U32_LEN;
		for (j=0;j<message->elements[i].num_values;j++) {
			PUSH_LE_U32(p, 0,
				    message->elements[i].values[j].length);
			p += U32_LEN;
			memcpy(p, message->elements[i].values[j].data,
			       message->elements[i].values[j].length);
			p[message->elements[i].values[j].length] = 0;
			p += message->elements[i].values[j].length +
				NULL_PAD_BYTE_LEN;
		}
	}

	return 0;
}

/*
 * New pack version designed based on performance profiling of version 1.
 * The approach is to separate value data from the rest of the record's data.
 * This improves performance because value data is not needed during unpacking
 * or filtering of the message's attribute list. During filtering we only copy
 * attributes which are present in the attribute list, however at the parse
 * stage we need to point to all attributes as they may be referenced in the
 * search expression.
 * With this new format, we don't lose time loading data (eg via
 * talloc_memdup()) that is never needed (for the vast majority of attributes
 * are are never found in either the search expression or attribute list).
 * Additional changes include adding a canonicalized DN (for later
 * optimizations) and variable width length fields for faster unpacking.
 * The pack and unpack performance improvement is tested in the torture
 * test torture_ldb_pack_format_perf.
 *
 * Layout:
 *
 * Version (4 bytes)
 * Number of Elements (4 bytes)
 * DN length (4 bytes)
 * DN with null terminator (DN length + 1 bytes)
 * Canonicalized DN length (4 bytes)
 * Canonicalized DN with null terminator (Canonicalized DN length + 1 bytes)
 * Number of bytes from here to value data section (4 bytes)
 * # For each element:
 * 	Element name length (4 bytes)
 * 	Element name with null terminator (Element name length + 1 bytes)
 * 	Number of values (4 bytes)
 * 	Width of value lengths
 * 	# For each value:
 * 		Value data length (#bytes given by width field above)
 * # For each element:
 * 	# For each value:
 *	 	Value data (#bytes given by corresponding length above)
 */
static int ldb_pack_data_v2(struct ldb_context *ldb,
			    const struct ldb_message *message,
			    struct ldb_val *data)
{
	unsigned int i, j, real_elements=0;
	size_t size, dn_len, dn_canon_len, attr_len, value_len;
	const char *dn, *dn_canon;
	uint8_t *p, *q;
	size_t len;
	size_t max_val_len;
	uint8_t val_len_width;

	/*
	 * First half of this function will calculate required size for
	 * packed data. Initial size is 20 = 5 * 4.  5 fixed fields are:
	 * version, num elements, dn len, canon dn len, attr section len
	 */
	size = U32_LEN * 5;

	/*
	 * Get linearized and canonicalized form of the DN and add the lengths
	 * of each to size, plus 1 for null terminator.
	 */
	dn = ldb_dn_get_linearized(message->dn);
	if (dn == NULL) {
		errno = ENOMEM;
		return -1;
	}

	dn_len = strlen(dn) + NULL_PAD_BYTE_LEN;
	if (size + dn_len < size) {
		errno = ENOMEM;
		return -1;
	}
	size += dn_len;

	if (ldb_dn_is_special(message->dn)) {
		dn_canon_len = NULL_PAD_BYTE_LEN;
		dn_canon = discard_const_p(char, "\0");
	} else {
		dn_canon = ldb_dn_canonical_string(message->dn, message->dn);
		if (dn_canon == NULL) {
			errno = ENOMEM;
			return -1;
		}

		dn_canon_len = strlen(dn_canon) + NULL_PAD_BYTE_LEN;
		if (size + dn_canon_len < size) {
			errno = ENOMEM;
			return -1;
		}
	}
	size += dn_canon_len;

	/* Add the size required by each element */
	for (i=0;i<message->num_elements;i++) {
		if (attribute_storable_values(&message->elements[i]) == 0) {
			continue;
		}

		real_elements++;

		/*
		 * Add length of element name + 9 for:
		 * 1 for null terminator
		 * 4 for element name length field
		 * 4 for number of values field
		 */
		attr_len = strlen(message->elements[i].name);
		if (size + attr_len + U32_LEN * 2 + NULL_PAD_BYTE_LEN < size) {
			errno = ENOMEM;
			return -1;
		}
		size += attr_len + U32_LEN * 2 + NULL_PAD_BYTE_LEN;

		/*
		 * Find the max value length, so we can calculate the width
		 * required for the value length fields.
		 */
		max_val_len = 0;
		for (j=0;j<message->elements[i].num_values;j++) {
			value_len = message->elements[i].values[j].length;
			if (value_len > max_val_len) {
				max_val_len = value_len;
			}

			if (size + value_len + NULL_PAD_BYTE_LEN < size) {
				errno = ENOMEM;
				return -1;
			}
			size += value_len + NULL_PAD_BYTE_LEN;
		}

		if (max_val_len <= UCHAR_MAX) {
			val_len_width = U8_LEN;
		} else if (max_val_len <= USHRT_MAX) {
			val_len_width = U16_LEN;
		} else if (max_val_len <= UINT_MAX) {
		        val_len_width = U32_LEN;
		} else {
			errno = EMSGSIZE;
			return -1;
		}

		/* Total size required for val lengths (re-using variable) */
		max_val_len = (val_len_width*message->elements[i].num_values);

		/* Add one for storing the width */
		max_val_len += U8_LEN;
		if (size + max_val_len < size) {
			errno = ENOMEM;
			return -1;
		}
		size += max_val_len;
	}

	/* Allocate */
	data->data = talloc_array(ldb, uint8_t, size);
	if (!data->data) {
		errno = ENOMEM;
		return -1;
	}
	data->length = size;

	/* Packing format version and number of element */
	p = data->data;
	PUSH_LE_U32(p, 0, LDB_PACKING_FORMAT_V2);
	p += U32_LEN;
	PUSH_LE_U32(p, 0, real_elements);
	p += U32_LEN;

	/* Pack DN and Canonicalized DN */
	PUSH_LE_U32(p, 0, dn_len-NULL_PAD_BYTE_LEN);
	p += U32_LEN;
	memcpy(p, dn, dn_len);
	p += dn_len;

	PUSH_LE_U32(p, 0, dn_canon_len-NULL_PAD_BYTE_LEN);
	p += U32_LEN;
	memcpy(p, dn_canon, dn_canon_len);
	p += dn_canon_len;

	/*
	 * Save pointer at this point and leave a U32_LEN gap for
	 * storing the size of the attribute names and value lengths
	 * section
	 */
	q = p;
	p += U32_LEN;

	for (i=0;i<message->num_elements;i++) {
		if (attribute_storable_values(&message->elements[i]) == 0) {
			continue;
		}

		/* Length of el name */
		len = strlen(message->elements[i].name);
		PUSH_LE_U32(p, 0, len);
		p += U32_LEN;

		/*
		 * Even though we have the element name's length, put a null
		 * terminator at the end so if any code uses the name
		 * directly, it'll be safe to do things requiring null
		 * termination like strlen
		 */
		memcpy(p, message->elements[i].name, len+NULL_PAD_BYTE_LEN);
		p += len + NULL_PAD_BYTE_LEN;
		/* Num values */
		PUSH_LE_U32(p, 0, message->elements[i].num_values);
		p += U32_LEN;

		/*
		 * Calculate value length width again. It's faster to
		 * calculate it again than do the array management to
		 * store the result during size calculation.
		 */
		max_val_len = 0;
		for (j=0;j<message->elements[i].num_values;j++) {
			value_len = message->elements[i].values[j].length;
			if (value_len > max_val_len) {
				max_val_len = value_len;
			}
		}

		if (max_val_len <= UCHAR_MAX) {
			val_len_width = U8_LEN;
		} else if (max_val_len <= USHRT_MAX) {
			val_len_width = U16_LEN;
		} else if (max_val_len <= UINT_MAX) {
		        val_len_width = U32_LEN;
		} else {
			errno = EMSGSIZE;
			return -1;
		}

		/* Pack the width */
		*p = val_len_width & 0xFF;
		p += U8_LEN;

		/*
		 * Pack each value's length using the minimum number of bytes
		 * required, which we just calculated. We repeat the loop
		 * for each case here so the compiler can inline code.
		 */
		if (val_len_width == U8_LEN) {
			for (j=0;j<message->elements[i].num_values;j++) {
				PUSH_LE_U8(p, 0,
					message->elements[i].values[j].length);
				p += U8_LEN;
			}
		} else if (val_len_width == U16_LEN) {
			for (j=0;j<message->elements[i].num_values;j++) {
				PUSH_LE_U16(p, 0,
					message->elements[i].values[j].length);
				p += U16_LEN;
			}
		} else if (val_len_width == U32_LEN) {
			for (j=0;j<message->elements[i].num_values;j++) {
				PUSH_LE_U32(p, 0,
					message->elements[i].values[j].length);
				p += U32_LEN;
			}
		}
	}

	/*
	 * We've finished packing the attr names and value lengths
	 * section, so store the size in the U32_LEN gap we left
	 * earlier
	 */
	PUSH_LE_U32(q, 0, p-q);

	/* Now pack the values */
	for (i=0;i<message->num_elements;i++) {
		if (attribute_storable_values(&message->elements[i]) == 0) {
			continue;
		}
		for (j=0;j<message->elements[i].num_values;j++) {
			memcpy(p, message->elements[i].values[j].data,
			       message->elements[i].values[j].length);

			/*
			 * Even though we have the data length, put a null
			 * terminator at the end of each value's data so if
			 * any code uses the data directly, it'll  be safe to
			 * do things requiring null termination like strlen.
			 */
			p[message->elements[i].values[j].length] = 0;
			p += message->elements[i].values[j].length +
				NULL_PAD_BYTE_LEN;
		}
	}

	/*
	 * If we didn't end up at the end of the data here, something has
	 * gone very wrong.
	 */
	if (p != data->data + size) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/*
  pack a ldb message into a linear buffer in a ldb_val

  note that this routine avoids saving elements with zero values,
  as these are equivalent to having no element

  caller frees the data buffer after use
*/
int ldb_pack_data(struct ldb_context *ldb,
		  const struct ldb_message *message,
		  struct ldb_val *data,
		  uint32_t pack_format_version) {

	if (pack_format_version == LDB_PACKING_FORMAT) {
		return ldb_pack_data_v1(ldb, message, data);
	} else if (pack_format_version == LDB_PACKING_FORMAT_V2) {
		return ldb_pack_data_v2(ldb, message, data);
	} else {
		errno = EINVAL;
		return -1;
	}
}

/*
 * Unpack a ldb message from a linear buffer in ldb_val
 */
static int ldb_unpack_data_flags_v1(struct ldb_context *ldb,
				    const struct ldb_val *data,
				    struct ldb_message *message,
				    unsigned int flags,
				    unsigned format)
{
	uint8_t *p;
	size_t remaining;
	size_t dn_len;
	unsigned int i, j;
	unsigned int nelem = 0;
	size_t len;
	struct ldb_val *ldb_val_single_array = NULL;

	message->elements = NULL;

	p = data->data;

	/* Format (U32, already read) + U32 for num_elements */
	if (data->length < U32_LEN * 2) {
		errno = EIO;
		goto failed;
	}

	/* Skip first 4 bytes, format already read */
	p += U32_LEN;
	message->num_elements = PULL_LE_U32(p, 0);
	p += U32_LEN;

	remaining = data->length - U32_LEN * 2;

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
		if (remaining < dn_len + NULL_PAD_BYTE_LEN) {
			errno = EIO;
			goto failed;
		}
		remaining -= dn_len + NULL_PAD_BYTE_LEN;
		p += dn_len + NULL_PAD_BYTE_LEN;
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

		/*
		 * Sanity check: Element must be at least the size of empty
		 * attr name and value and NULL terms for each.
		 */
		if (remaining < U32_LEN * 2 + NULL_PAD_BYTE_LEN * 2) {
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

		if (remaining < (attr_len + NULL_PAD_BYTE_LEN)) {
			errno = EIO;
			goto failed;
		}
		remaining -= attr_len + NULL_PAD_BYTE_LEN;
		p += attr_len + NULL_PAD_BYTE_LEN;
		element->num_values = PULL_LE_U32(p, 0);
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
		p += U32_LEN;
		if (remaining < U32_LEN) {
			errno = EIO;
			goto failed;
		}
		remaining -= U32_LEN;
		for (j = 0; j < element->num_values; j++) {
			/*
			 * Sanity check: Value must be at least the size of
			 * empty val and NULL terminator.
			 */
			if (remaining < U32_LEN + NULL_PAD_BYTE_LEN) {
				errno = EIO;
				goto failed;
			}
			remaining -= U32_LEN + NULL_PAD_BYTE_LEN;

			len = PULL_LE_U32(p, 0);
			if (remaining < len) {
				errno = EIO;
				goto failed;
			}
			if (len + NULL_PAD_BYTE_LEN < len) {
				errno = EIO;
				goto failed;
			}

			element->values[j].length = len;
			element->values[j].data = p + U32_LEN;
			remaining -= len;
			p += len + U32_LEN + NULL_PAD_BYTE_LEN;
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

/*
 * Unpack a ldb message from a linear buffer in ldb_val
 */
static int ldb_unpack_data_flags_v2(struct ldb_context *ldb,
				    const struct ldb_val *data,
				    struct ldb_message *message,
				    unsigned int flags)
{
	uint8_t *p, *q, *end_p, *value_section_p;
	unsigned int i, j;
	unsigned int nelem = 0;
	size_t len;
	struct ldb_val *ldb_val_single_array = NULL;
	uint8_t val_len_width;

	message->elements = NULL;

	p = data->data;
	end_p = p + data->length;

	/* Skip first 4 bytes, format already read */
	p += U32_LEN;

	/* First fields are fixed: num_elements, DN length */
	if (p + U32_LEN * 2 > end_p) {
		errno = EIO;
		goto failed;
	}

	message->num_elements = PULL_LE_U32(p, 0);
	p += U32_LEN;

	len = PULL_LE_U32(p, 0);
	p += U32_LEN;

	if (p + len + NULL_PAD_BYTE_LEN > end_p) {
		errno = EIO;
		goto failed;
	}

	if (flags & LDB_UNPACK_DATA_FLAG_NO_DN) {
		message->dn = NULL;
	} else {
		struct ldb_val blob;
		blob.data = discard_const_p(uint8_t, p);
		blob.length = len;
		message->dn = ldb_dn_from_ldb_val(message, ldb, &blob);
		if (message->dn == NULL) {
			errno = ENOMEM;
			goto failed;
		}
	}

	p += len + NULL_PAD_BYTE_LEN;

	if (*(p-NULL_PAD_BYTE_LEN) != '\0') {
		errno = EINVAL;
		goto failed;
	}

	/* Now skip the canonicalized DN and its length */
	len = PULL_LE_U32(p, 0) + NULL_PAD_BYTE_LEN;
	p += U32_LEN;

	if (p + len > end_p) {
		errno = EIO;
		goto failed;
	}

	p += len;

	if (*(p-NULL_PAD_BYTE_LEN) != '\0') {
		errno = EINVAL;
		goto failed;
	}

	if (flags & LDB_UNPACK_DATA_FLAG_NO_ATTRS) {
		return 0;
	}

	if (message->num_elements == 0) {
		return 0;
	}

	/*
	 * Sanity check (17 bytes is the minimum element size)
	 */
	if (message->num_elements > (end_p - p) / 17) {
		errno = EIO;
		goto failed;
	}

	message->elements = talloc_zero_array(message,
					      struct ldb_message_element,
					      message->num_elements);
	if (!message->elements) {
		errno = ENOMEM;
		goto failed;
	}

	/*
	 * In typical use, most values are single-valued.  This makes
	 * it quite expensive to allocate an array of ldb_val for each
	 * of these, just to then hold the pointer to the data buffer.
	 * So with LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC we allocate this
	 * ahead of time and use it for the single values where possible.
	 * (This is used the the normal search case, but not in the
	 * index case because of caller requirements).
	 */
	if (flags & LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC) {
		ldb_val_single_array = talloc_array(message->elements,
						    struct ldb_val,
						    message->num_elements);
		if (ldb_val_single_array == NULL) {
			errno = ENOMEM;
			goto failed;
		}
	}

	q = p + PULL_LE_U32(p, 0);
	value_section_p = q;
	p += U32_LEN;

	for (i=0;i<message->num_elements;i++) {
		const char *attr = NULL;
		size_t attr_len;
		struct ldb_message_element *element = NULL;

		/* Sanity check: minimum element size */
		if (p + (U32_LEN * 2) + /* attr name len, num values */
			(U8_LEN * 2) + /* value length width, one val length */
			(NULL_PAD_BYTE_LEN * 2) /* null for attr name + val */
			> value_section_p) {
			errno = EIO;
			goto failed;
		}

		attr_len = PULL_LE_U32(p, 0);
		p += U32_LEN;

		if (attr_len == 0) {
			errno = EIO;
			goto failed;
		}
		attr = (char *)p;

		p += attr_len + NULL_PAD_BYTE_LEN;
		/*
		 * num_values, val_len_width
		 *
		 * val_len_width is the width specifier
		 * for the variable length encoding
		 */
		if (p + U32_LEN + U8_LEN > value_section_p) {
			errno = EIO;
			goto failed;
		}

		if (*(p-NULL_PAD_BYTE_LEN) != '\0') {
			errno = EINVAL;
			goto failed;
		}

		element = &message->elements[nelem];
		element->name = attr;
		element->flags = 0;

		element->num_values = PULL_LE_U32(p, 0);
		element->values = NULL;
		if ((flags & LDB_UNPACK_DATA_FLAG_NO_VALUES_ALLOC) &&
		    element->num_values == 1) {
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

		p += U32_LEN;

		/*
		 * Here we read how wide the remaining lengths are
		 * which avoids storing and parsing a lot of leading
		 * 0s
		 */
		val_len_width = *p;
		p += U8_LEN;

		if (p + val_len_width * element->num_values >
		    value_section_p) {
			errno = EIO;
			goto failed;
		}

		/*
		 * This is structured weird for compiler optimization
		 * purposes, but we need to pull the array of widths
		 * with different macros depending on how wide the
		 * biggest one is (specified by val_len_width)
		 */
		if (val_len_width == U8_LEN) {
			for (j = 0; j < element->num_values; j++) {
				element->values[j].length = PULL_LE_U8(p, 0);
				p += U8_LEN;
			}
		} else if (val_len_width == U16_LEN) {
			for (j = 0; j < element->num_values; j++) {
				element->values[j].length = PULL_LE_U16(p, 0);
				p += U16_LEN;
			}
		} else if (val_len_width == U32_LEN) {
			for (j = 0; j < element->num_values; j++) {
				element->values[j].length = PULL_LE_U32(p, 0);
				p += U32_LEN;
			}
		} else {
			errno = ERANGE;
			goto failed;
		}

		for (j = 0; j < element->num_values; j++) {
			len = element->values[j].length;
			if (len + NULL_PAD_BYTE_LEN < len) {
				errno = EIO;
				goto failed;
			}
			if (q + len + NULL_PAD_BYTE_LEN > end_p) {
				errno = EIO;
				goto failed;
			}

			element->values[j].data = q;
			q += len + NULL_PAD_BYTE_LEN;
		}
		nelem++;
	}

	/*
	 * If p isn't now pointing at the beginning of the value section,
	 * something went very wrong.
	 */
	if (p != value_section_p) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: Data corruption in ldb_unpack_data_flags");
		errno = EIO;
		goto failed;
	}

	/*
	 * Adapt the number of elements to the real number of unpacked
	 * elements it means that we overallocated elements array.
	 */
	message->num_elements = nelem;

	/*
	 * Shrink the allocated size.  On current talloc behaviour
	 * this will help if we skipped 32 or more attributes.
	 */
	message->elements = talloc_realloc(message, message->elements,
					   struct ldb_message_element,
					   message->num_elements);

	if (q != end_p) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Error: %zu bytes unread in ldb_unpack_data_flags",
			  end_p - q);
		errno = EIO;
		goto failed;
	}

	return 0;

failed:
	talloc_free(message->elements);
	return -1;
}

int ldb_unpack_get_format(const struct ldb_val *data,
			  uint32_t *pack_format_version)
{
	if (data->length < U32_LEN) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*pack_format_version = PULL_LE_U32(data->data, 0);
	return LDB_SUCCESS;
}

/*
 * Unpack a ldb message from a linear buffer in ldb_val
 */
int ldb_unpack_data_flags(struct ldb_context *ldb,
			  const struct ldb_val *data,
			  struct ldb_message *message,
			  unsigned int flags)
{
	unsigned format;

	if (data->length < U32_LEN) {
		errno = EIO;
		return -1;
	}

	format = PULL_LE_U32(data->data, 0);
	if (format == LDB_PACKING_FORMAT_V2) {
		return ldb_unpack_data_flags_v2(ldb, data, message, flags);
	}

	/*
	 * The v1 function we're about to call takes either LDB_PACKING_FORMAT
	 * or LDB_PACKING_FORMAT_NODN packing format versions, and will error
	 * if given some other version, so we don't need to do any further
	 * checks on 'format'.
	 */
	return ldb_unpack_data_flags_v1(ldb, data, message, flags, format);
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

	/*
	 * Otherwise we are copying at most as many elements as we
	 * have attributes
	 */
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

		/*
		 * el2 is assigned after the Pigeonhole principle
		 * check below for clarity
		 */
		struct ldb_message_element *el2 = NULL;
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

		/*
		 * Pigeonhole principle: we can't have more elements
		 * than the number of attributes if they are unique in
		 * the DB.
		 */
		if (num_elements >= elements_size) {
			goto failed;
		}

		el2 = &filtered_msg->elements[num_elements];

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
		TALLOC_FREE(filtered_msg->elements);
	}

	return 0;
failed:
	TALLOC_FREE(filtered_msg->elements);
	return -1;
}
