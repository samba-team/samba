/*
   Unix SMB/CIFS implementation.
   SMB Extended attribute buffer handling
   Copyright (C) Jeremy Allison                 2005-2013
   Copyright (C) Tim Prouty			2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/util_ea.h"

/****************************************************************************
 Read one EA list entry from the buffer.
****************************************************************************/

struct ea_list *read_ea_list_entry(TALLOC_CTX *ctx, const char *pdata, size_t data_size, size_t *pbytes_used)
{
	struct ea_list *eal = talloc_zero(ctx, struct ea_list);
	uint16_t val_len;
	unsigned int namelen;
	size_t converted_size;

	if (!eal) {
		return NULL;
	}

	if (data_size < 6) {
		return NULL;
	}

	eal->ea.flags = CVAL(pdata,0);
	namelen = CVAL(pdata,1);
	val_len = SVAL(pdata,2);

	if (4 + namelen + 1 + val_len > data_size) {
		return NULL;
	}

	/* Ensure the name is null terminated. */
	if (pdata[namelen + 4] != '\0') {
		return NULL;
	}
	if (!pull_ascii_talloc(ctx, &eal->ea.name, pdata + 4, &converted_size)) {
		DEBUG(0,("read_ea_list_entry: pull_ascii_talloc failed: %s",
			strerror(errno)));
	}
	if (!eal->ea.name) {
		return NULL;
	}

	eal->ea.value = data_blob_talloc(eal, NULL, (size_t)val_len + 1);
	if (!eal->ea.value.data) {
		return NULL;
	}

	memcpy(eal->ea.value.data, pdata + 4 + namelen + 1, val_len);

	/* Ensure we're null terminated just in case we print the value. */
	eal->ea.value.data[val_len] = '\0';
	/* But don't count the null. */
	eal->ea.value.length--;

	if (pbytes_used) {
		*pbytes_used = 4 + namelen + 1 + val_len;
	}

	DEBUG(10,("read_ea_list_entry: read ea name %s\n", eal->ea.name));
	dump_data(10, eal->ea.value.data, eal->ea.value.length);

	return eal;
}

/****************************************************************************
 Read a list of EA names and data from an incoming data buffer. Create an ea_list with them.
****************************************************************************/

struct ea_list *read_nttrans_ea_list(TALLOC_CTX *ctx, const char *pdata, size_t data_size)
{
	struct ea_list *ea_list_head = NULL;
	size_t offset = 0;

	if (data_size < 4) {
		return NULL;
	}

	while (offset + 4 <= data_size) {
		size_t next_offset = IVAL(pdata,offset);
		struct ea_list *eal = read_ea_list_entry(ctx, pdata + offset + 4, data_size - offset - 4, NULL);

		if (!eal) {
			return NULL;
		}

		DLIST_ADD_END(ea_list_head, eal);
		if (next_offset == 0) {
			break;
		}

		/* Integer wrap protection for the increment. */
		if (offset + next_offset < offset) {
			break;
		}

		offset += next_offset;

		/* Integer wrap protection for while loop. */
		if (offset + 4 < offset) {
			break;
		}

	}

	return ea_list_head;
}
