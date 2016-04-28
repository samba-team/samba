/*
   CTDB protocol marshalling

   Copyright (C) Amitay Isaacs  2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "protocol_api.h"

#define CTDB_DS_ALIGNMENT 8

int ctdb_allocate_pkt(TALLOC_CTX *mem_ctx, size_t length,
		      uint8_t **buf, size_t *buflen)
{
	size_t new_length;

	if (buf == NULL || buflen == NULL) {
		return EINVAL;
	}

	new_length = (length + CTDB_DS_ALIGNMENT-1) & ~(CTDB_DS_ALIGNMENT-1);

	*buflen = new_length;
	*buf = talloc_zero_size(mem_ctx, new_length);
	if (*buf == NULL) {
		return ENOMEM;
	}

	return 0;
}
