/* 
   Unix SMB/CIFS implementation.
   libndr interface
   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
  this provides the core routines for MSNDR parsing functions
*/

#include "includes.h"

/*
  initialise a ndr parse structure from a data blob
*/
struct ndr_parse *ndr_parse_init_blob(DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	struct ndr_parse *ndr;

	ndr = talloc(mem_ctx, sizeof(*ndr));
	if (!ndr) return NULL;

	ndr->data = blob->data;
	ndr->data_size = blob->length;
	ndr->offset = 0;
	ndr->mem_ctx = mem_ctx;

	return ndr;
}


/* limit the remaining size of the current ndr parse structure to the
   given size, starting at the given offset 

   this is used when a ndr packet has an explicit size on the wire, and we
   need to make sure that we don't use more data than is indicated

   the 'ofs' parameter indicates how many bytes back from the current
   offset in the buffer the 'size' number of bytes starts
*/
NTSTATUS ndr_parse_limit_size(struct ndr_parse *ndr, uint32 size, uint32 ofs)
{
	uint32 new_size;
	new_size = ndr->offset + size - ofs;

	if (new_size > ndr->data_size) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	ndr->data_size = new_size;

	return NT_STATUS_OK;
}


/*
  advance by 'size' bytes
*/
NTSTATUS ndr_parse_advance(struct ndr_parse *ndr, uint32 size)
{
	ndr->offset += size;
	if (ndr->offset > ndr->data_size) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	return NT_STATUS_OK;
}

/*
  set the parse offset to 'ofs'
*/
NTSTATUS ndr_parse_set_offset(struct ndr_parse *ndr, uint32 ofs)
{
	ndr->offset = ofs;
	if (ndr->offset > ndr->data_size) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	return NT_STATUS_OK;
}

/* save the offset/size of the current ndr state */
void ndr_parse_save(struct ndr_parse *ndr, struct ndr_parse_save *save)
{
	save->offset = ndr->offset;
	save->data_size = ndr->data_size;
}

/* restore the size/offset of a ndr structure */
void ndr_parse_restore(struct ndr_parse *ndr, struct ndr_parse_save *save)
{
	ndr->offset = save->offset;
	ndr->data_size = save->data_size;
}
