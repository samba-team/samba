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
  this provides the core routines for NDR parsing functions

  see http://www.opengroup.org/onlinepubs/9629399/chap14.htm for details
  of NDR encoding rules
*/

#include "includes.h"

#define NDR_BASE_MARSHALL_SIZE 1024

/*
  initialise a ndr parse structure from a data blob
*/
struct ndr_pull *ndr_pull_init_blob(DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	struct ndr_pull *ndr;

	ndr = talloc(mem_ctx, sizeof(*ndr));
	if (!ndr) return NULL;

	ndr->flags = 0;
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
NTSTATUS ndr_pull_limit_size(struct ndr_pull *ndr, uint32 size, uint32 ofs)
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
NTSTATUS ndr_pull_advance(struct ndr_pull *ndr, uint32 size)
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
NTSTATUS ndr_pull_set_offset(struct ndr_pull *ndr, uint32 ofs)
{
	ndr->offset = ofs;
	if (ndr->offset > ndr->data_size) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	return NT_STATUS_OK;
}

/* save the offset/size of the current ndr state */
void ndr_pull_save(struct ndr_pull *ndr, struct ndr_pull_save *save)
{
	save->offset = ndr->offset;
	save->data_size = ndr->data_size;
}

/* restore the size/offset of a ndr structure */
void ndr_pull_restore(struct ndr_pull *ndr, struct ndr_pull_save *save)
{
	ndr->offset = save->offset;
	ndr->data_size = save->data_size;
}




/* create a ndr_push structure, ready for some marshalling */
struct ndr_push *ndr_push_init(void)
{
	struct ndr_push *ndr;
	TALLOC_CTX *mem_ctx = talloc_init("ndr_push_init");
	if (!mem_ctx) return NULL;

	ndr = talloc(mem_ctx, sizeof(*ndr));
	if (!ndr) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	ndr->mem_ctx = mem_ctx;
	ndr->flags = 0;
	ndr->alloc_size = NDR_BASE_MARSHALL_SIZE;
	ndr->data = talloc(ndr->mem_ctx, ndr->alloc_size);
	if (!ndr->data) {
		ndr_push_free(ndr);
		return NULL;
	}
	ndr->offset = 0;
	
	return ndr;
}

/* free a ndr_push structure */
void ndr_push_free(struct ndr_push *ndr)
{
	talloc_destroy(ndr->mem_ctx);
}


/* return a DATA_BLOB structure for the current ndr_push marshalled data */
DATA_BLOB ndr_push_blob(struct ndr_push *ndr)
{
	DATA_BLOB blob;
	blob.data = ndr->data;
	blob.length = ndr->offset;
	return blob;
}


/*
  expand the available space in the buffer to 'size'
*/
NTSTATUS ndr_push_expand(struct ndr_push *ndr, uint32 size)
{
	if (ndr->alloc_size >= size) {
		return NT_STATUS_OK;
	}

	ndr->alloc_size = size;
	ndr->data = talloc_realloc(ndr->mem_ctx, ndr->data, ndr->alloc_size);
	if (!ndr->data) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/*
  set the push offset to 'ofs'
*/
NTSTATUS ndr_push_set_offset(struct ndr_push *ndr, uint32 ofs)
{
	NDR_CHECK(ndr_push_expand(ndr, ofs));
	ndr->offset = ofs;
	return NT_STATUS_OK;
}

/*
  push a generic array
*/
NTSTATUS ndr_push_array(struct ndr_push *ndr, int ndr_flags, void *base, 
			size_t elsize, uint32 count, 
			NTSTATUS (*push_fn)(struct ndr_push *, int, void *))
{
	int i;
	char *p = base;
	NDR_CHECK(ndr_push_uint32(ndr, count));
	if (!(ndr_flags & NDR_SCALARS)) goto buffers;
	for (i=0;i<count;i++) {
		NDR_CHECK(push_fn(ndr, NDR_SCALARS, p));
		p += elsize;
	}
	if (!(ndr_flags & NDR_BUFFERS)) goto done;
buffers:
	p = base;
	for (i=0;i<count;i++) {
		NDR_CHECK(push_fn(ndr, NDR_BUFFERS, p));
		p += elsize;
	}
done:
	return NT_STATUS_OK;
}

/*
  pull a generic array
*/
NTSTATUS ndr_pull_array(struct ndr_pull *ndr, int ndr_flags, void *base, 
			size_t elsize, uint32 count, 
			NTSTATUS (*pull_fn)(struct ndr_pull *, int, void *))
{
	int i;
	uint32 max_count;
	char *p;
	p = base;
	NDR_CHECK(ndr_pull_uint32(ndr, &max_count));
	if (max_count != count) {
		/* maybe we can cope with this? */
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!(ndr_flags & NDR_SCALARS)) goto buffers;
	for (i=0;i<count;i++) {
		NDR_CHECK(pull_fn(ndr, NDR_SCALARS, p));
		p += elsize;
	}
	if (!(ndr_flags & NDR_BUFFERS)) goto done;
buffers:
	p = base;
	for (i=0;i<count;i++) {
		NDR_CHECK(pull_fn(ndr, NDR_BUFFERS, p));
		p += elsize;
	}
done:
	return NT_STATUS_OK;
}


/*
  print a generic array
*/
void ndr_print_array(struct ndr_print *ndr, const char *name, void *base, 
		     size_t elsize, uint32 count, 
		     void (*print_fn)(struct ndr_print *, const char *, void *))
{
	int i;
	char *p = base;
	ndr->print(ndr, "%s: ARRAY(%d)", name, count);
	ndr->depth++;
	for (i=0;i<count;i++) {
		char *idx=NULL;
		asprintf(&idx, "[%d]", i);
		if (idx) {
			print_fn(ndr, idx, p);
			free(idx);
		}
		p += elsize;
	}
	ndr->depth--;
}



static void ndr_print_debug_helper(struct ndr_print *ndr, const char *format, ...)
{
	va_list ap;
	char *s = NULL;
	int i;

	va_start(ap, format);
	vasprintf(&s, format, ap);
	va_end(ap);

	for (i=0;i<ndr->depth;i++) {
		DEBUG(0,("    "));
	}

	DEBUG(0,("%s\n", s));
	free(s);
}

/*
  a useful helper function for printing idl structures via DEBUG()
*/
void ndr_print_debug(void (*fn)(struct ndr_print *, const char *, void *),
		     const char *name,
		     void *ptr)
{
	struct ndr_print ndr;

	ndr.mem_ctx = talloc_init("ndr_print_debug");
	if (!ndr.mem_ctx) return;
	ndr.print = ndr_print_debug_helper;
	ndr.depth = 1;
	fn(&ndr, name, ptr);
	talloc_destroy(ndr.mem_ctx);
}

/*
  a useful helper function for printing idl unions via DEBUG()
*/
void ndr_print_union_debug(void (*fn)(struct ndr_print *, const char *, uint16, void *),
			   const char *name,
			   uint16 level,
			   void *ptr)
{
	struct ndr_print ndr;

	ndr.mem_ctx = talloc_init("ndr_print_debug");
	if (!ndr.mem_ctx) return;
	ndr.print = ndr_print_debug_helper;
	ndr.depth = 1;
	fn(&ndr, name, level, ptr);
	talloc_destroy(ndr.mem_ctx);
}
