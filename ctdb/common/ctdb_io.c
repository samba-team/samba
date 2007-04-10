/* 
   ctdb database library
   Utility functions to read/write blobs of data from a file descriptor
   and handle the case where we might need multiple read/writes to get all the
   data.

   Copyright (C) Andrew Tridgell  2006

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

#include "includes.h"
#include "lib/tdb/include/tdb.h"
#include "lib/events/events.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "ctdb.h"


/* read a record from the file descriptor.
   if the file descriptor has been closed  the user specifies ctx will be destryoed.
 */
void ctdb_read_pdu(int fd, TALLOC_CTX *ctx, struct ctdb_partial *partial, partial_cb_fn_t func, void *args)
{
	int num_ready = 0;
	ssize_t nread;
	uint8_t *data, *data_base;

	if (ioctl(fd, FIONREAD, &num_ready) != 0 ||
	    num_ready == 0) {
		/* the descriptor has been closed */
		func(NULL, 0, args);
		return;
	}


	partial->data = talloc_realloc_size(ctx, partial->data, 
					       num_ready + partial->length);

	if (partial->data == NULL) {
		func(NULL, 0, args);
		return;
	}

	nread = read(fd, partial->data+partial->length, num_ready);
	if (nread <= 0) {
		func(NULL, 0, args);
		return;
	}


	data = partial->data;
	nread += partial->length;

	partial->data = NULL;
	partial->length = 0;

	if (nread >= 4 && *(uint32_t *)data == nread) {
		/* it is the responsibility of the incoming packet function to free 'data' */
		func(data, nread, args);
		return;
	}

	data_base = data;

	while (nread >= 4 && *(uint32_t *)data <= nread) {
		/* we have at least one packet */
		uint8_t *d2;
		uint32_t len;
		len = *(uint32_t *)data;
		d2 = talloc_memdup(ctx, data, len);
		if (d2 == NULL) {
			/* sigh */
			func(NULL, 0, args);
			return;
		}
		func(d2, len, args);
		data += len;
		nread -= len;		
	}

	if (nread > 0) {
		/* we have only part of a packet */
		if (data_base == data) {
			partial->data = data;
			partial->length = nread;
		} else {
			partial->data = talloc_memdup(ctx, data, nread);
			if (partial->data == NULL) {
				func(NULL, 0, args);
				return;
			}
			partial->length = nread;
			talloc_free(data_base);
		}
		return;
	}

	talloc_free(data_base);
}

