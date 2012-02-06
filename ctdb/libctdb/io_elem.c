/*
   Simple queuing of input and output records for libctdb

   Copyright (C) Rusty Russell 2010

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
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "libctdb_private.h"
#include "io_elem.h"
#include <tdb.h>
#include <netinet/in.h>
#include <dlinklist.h>
#include <ctdb_protocol.h> // For CTDB_DS_ALIGNMENT and ctdb_req_header

struct io_elem {
	struct io_elem *next, *prev;
	size_t len, off;
	char *data;
};

struct io_elem *new_io_elem(size_t len)
{
	struct io_elem *elem;
	size_t ask = len;

	len = (len + (CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);

	elem = malloc(sizeof(*elem));
	if (!elem)
		return NULL;
	elem->data = malloc(len);
	if (!elem->data) {
		free(elem);
		return NULL;
	}

	/* stamp out any padding to keep valgrind happy */
	if (ask != len) {
		memset(elem->data + ask, 0, len-ask);
	}
	elem->len = len;
	elem->off = 0;
	elem->next = NULL;
	elem->prev = NULL;
	return elem;
}

void free_io_elem(struct io_elem *io)
{
	free(io->data);
	free(io);
}

bool io_elem_finished(const struct io_elem *io)
{
	return io->off == io->len;
}

void io_elem_init_req_header(struct io_elem *io,
			     uint32_t operation,
			     uint32_t destnode,
			     uint32_t reqid)
{
	struct ctdb_req_header *hdr = io_elem_data(io, NULL);

	hdr->length = io->len;
	hdr->ctdb_magic = CTDB_MAGIC;
	hdr->ctdb_version = CTDB_VERSION;
	/* Generation and srcnode only used for inter-ctdbd communication. */
	hdr->generation = 0;
	hdr->destnode = destnode;
	hdr->srcnode = 0;
	hdr->operation = operation;
	hdr->reqid = reqid;
}

/* Access to raw data: if len is non-NULL it is filled in. */
void *io_elem_data(const struct io_elem *io, size_t *len)
{
	if (len)
		*len = io->len;
	return io->data;
}

/* Returns -1 if we hit an error.  Errno will be set. */
int read_io_elem(int fd, struct io_elem *io)
{
	ssize_t ret;

	ret = read(fd, io->data + io->off, io->len - io->off);
	if (ret < 0)
		return ret;

	io->off += ret;
	if (io_elem_finished(io)) {
		struct ctdb_req_header *hdr = (void *)io->data;

		/* Finished.  But maybe this was just header? */
		if (io->len == sizeof(*hdr) && hdr->length > io->len) {
			int reret;
			void *newdata;
			/* Enlarge and re-read. */
			io->len = hdr->length;
			newdata = realloc(io->data, io->len);
			if (!newdata)
				return -1;
			io->data = newdata;
			/* Try reading again immediately. */
			reret = read_io_elem(fd, io);
			if (reret >= 0)
				reret += ret;
			return reret;
		}
	}
	return ret;
}

/* Returns -1 if we hit an error.  Errno will be set. */
int write_io_elem(int fd, struct io_elem *io)
{
	ssize_t ret;

	ret = write(fd, io->data + io->off, io->len - io->off);
	if (ret < 0)
		return ret;

	io->off += ret;
	return ret;
}

void io_elem_reset(struct io_elem *io)
{
	io->off = 0;
}

void io_elem_queue(struct ctdb_connection *ctdb, struct io_elem *io)
{
	DLIST_ADD_END(ctdb->inqueue, io, struct io_elem);
}

void io_elem_dequeue(struct ctdb_connection *ctdb, struct io_elem *io)
{
	DLIST_REMOVE(ctdb->inqueue, io);
}

