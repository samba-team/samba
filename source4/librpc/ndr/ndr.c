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
  work out the number of bytes needed to align on a n byte boundary
*/
size_t ndr_align_size(uint32_t offset, size_t n)
{
	if ((offset & (n-1)) == 0) return 0;
	return n - (offset & (n-1));
}

/*
  initialise a ndr parse structure from a data blob
*/
struct ndr_pull *ndr_pull_init_blob(const DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	struct ndr_pull *ndr;

	ndr = talloc(mem_ctx, sizeof(*ndr));
	if (!ndr) return NULL;

	ndr->flags = 0;
	ndr->data = blob->data;
	ndr->data_size = blob->length;
	ndr->offset = 0;
	ndr->ptr_count = 0;
	ndr->relative_list = NULL;

	return ndr;
}

/*
  create an ndr sub-context based on an existing context. The new context starts
  at the current offset, with the given size limit
*/
NTSTATUS ndr_pull_subcontext(struct ndr_pull *ndr, struct ndr_pull *ndr2, uint32_t size)
{
	NDR_PULL_NEED_BYTES(ndr, size);
	*ndr2 = *ndr;
	ndr2->data += ndr2->offset;
	ndr2->offset = 0;
	ndr2->data_size = size;
	ndr2->flags = ndr->flags;
	return NT_STATUS_OK;
}


/*
  advance by 'size' bytes
*/
NTSTATUS ndr_pull_advance(struct ndr_pull *ndr, uint32_t size)
{
	ndr->offset += size;
	if (ndr->offset > ndr->data_size) {
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, 
				      "ndr_pull_advance by %u failed",
				      size);
	}
	return NT_STATUS_OK;
}

/*
  set the parse offset to 'ofs'
*/
NTSTATUS ndr_pull_set_offset(struct ndr_pull *ndr, uint32_t ofs)
{
	ndr->offset = ofs;
	if (ndr->offset > ndr->data_size) {
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, 
				      "ndr_pull_set_offset %u failed",
				      ofs);
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
struct ndr_push *ndr_push_init_ctx(TALLOC_CTX *mem_ctx)
{
	struct ndr_push *ndr;

	ndr = talloc(mem_ctx, sizeof(*ndr));
	if (!ndr) {
		return NULL;
	}

	ndr->flags = 0;
	ndr->alloc_size = NDR_BASE_MARSHALL_SIZE;
	ndr->data = talloc(ndr, ndr->alloc_size);
	if (!ndr->data) {
		return NULL;
	}
	ndr->offset = 0;
	ndr->ptr_count = 0;
	ndr->relative_list = NULL;

	return ndr;
}


/* create a ndr_push structure, ready for some marshalling */
struct ndr_push *ndr_push_init(void)
{
	struct ndr_push *ndr;
	TALLOC_CTX *mem_ctx = talloc_init("ndr_push_init");
	if (!mem_ctx) return NULL;
	ndr = ndr_push_init_ctx(mem_ctx);
	if (!ndr) {
		talloc_destroy(mem_ctx);
	}
	return ndr;
}

/* free a ndr_push structure */
void ndr_push_free(struct ndr_push *ndr)
{
	talloc_destroy(ndr);
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
NTSTATUS ndr_push_expand(struct ndr_push *ndr, uint32_t size)
{
	if (ndr->alloc_size >= size) {
		return NT_STATUS_OK;
	}

	ndr->alloc_size += NDR_BASE_MARSHALL_SIZE;
	if (size > ndr->alloc_size) {
		ndr->alloc_size = size;
	}
	ndr->data = talloc_realloc(ndr->data, ndr->alloc_size);
	if (!ndr->data) {
		return ndr_push_error(ndr, NDR_ERR_ALLOC, "Failed to push_expand to %u",
				      ndr->alloc_size);
	}

	return NT_STATUS_OK;
}

/*
  set the push offset to 'ofs'
*/
NTSTATUS ndr_push_set_offset(struct ndr_push *ndr, uint32_t ofs)
{
	NDR_CHECK(ndr_push_expand(ndr, ofs));
	ndr->offset = ofs;
	return NT_STATUS_OK;
}

/*
  push a generic array
*/
NTSTATUS ndr_push_array(struct ndr_push *ndr, int ndr_flags, void *base, 
			size_t elsize, uint32_t count, 
			NTSTATUS (*push_fn)(struct ndr_push *, int, void *))
{
	int i;
	char *p = base;
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
  pull a constant sized array
*/
NTSTATUS ndr_pull_array(struct ndr_pull *ndr, int ndr_flags, void *base, 
			size_t elsize, uint32_t count, 
			NTSTATUS (*pull_fn)(struct ndr_pull *, int, void *))
{
	int i;
	char *p;
	p = base;
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
		     size_t elsize, uint32_t count, 
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



void ndr_print_debug_helper(struct ndr_print *ndr, const char *format, ...)
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
	struct ndr_print *ndr;

	ndr = talloc_p(NULL, struct ndr_print);
	if (!ndr) return;
	ndr->print = ndr_print_debug_helper;
	ndr->depth = 1;
	ndr->flags = 0;
	fn(ndr, name, ptr);
	talloc_free(ndr);
}


/*
  a useful helper function for printing idl unions via DEBUG()
*/
void ndr_print_union_debug(void (*fn)(struct ndr_print *, const char *, uint32_t, void *),
			   const char *name,
			   uint32_t level,
			   void *ptr)
{
	struct ndr_print *ndr;

	ndr = talloc_p(NULL, struct ndr_print);
	if (!ndr) return;
	ndr->print = ndr_print_debug_helper;
	ndr->depth = 1;
	ndr->flags = 0;
	fn(ndr, name, level, ptr);
	talloc_free(ndr);
}

/*
  a useful helper function for printing idl function calls via DEBUG()
*/
void ndr_print_function_debug(void (*fn)(struct ndr_print *, const char *, int , void *),
			      const char *name,
			      int flags,
			      void *ptr)
{
	struct ndr_print *ndr;

	ndr = talloc_p(NULL, struct ndr_print);
	if (!ndr) return;
	ndr->print = ndr_print_debug_helper;
	ndr->depth = 1;
	ndr->flags = 0;
	fn(ndr, name, flags, ptr);
	talloc_free(ndr);
}


static NTSTATUS ndr_map_error(enum ndr_err_code err)
{
	switch (err) {
	case NDR_ERR_BUFSIZE:
		return NT_STATUS_BUFFER_TOO_SMALL;
	case NDR_ERR_ALLOC:
		return NT_STATUS_NO_MEMORY;
	}

	/* we should all error codes to different status codes */
	return NT_STATUS_INVALID_PARAMETER;
}

/*
  return and possibly log an NDR error
*/
NTSTATUS ndr_pull_error(struct ndr_pull *ndr, 
			enum ndr_err_code err, const char *format, ...) _PRINTF_ATTRIBUTE(3,4)
{
	char *s=NULL;
	va_list ap;

	va_start(ap, format);
	vasprintf(&s, format, ap);
	va_end(ap);

	DEBUG(3,("ndr_pull_error(%u): %s\n", err, s));

	free(s);

	return ndr_map_error(err);
}

/*
  return and possibly log an NDR error
*/
NTSTATUS ndr_push_error(struct ndr_push *ndr, enum ndr_err_code err, const char *format, ...)
{
	char *s=NULL;
	va_list ap;

	va_start(ap, format);
	vasprintf(&s, format, ap);
	va_end(ap);

	DEBUG(3,("ndr_push_error(%u): %s\n", err, s));

	free(s);

	return ndr_map_error(err);
}


/*
  handle subcontext buffers, which in midl land are user-marshalled, but
  we use magic in pidl to make them easier to cope with
*/
static NTSTATUS ndr_pull_subcontext_header(struct ndr_pull *ndr, 
					   size_t sub_size,
					   struct ndr_pull *ndr2)
{
	switch (sub_size) {
	case 0: {
		uint32_t size = ndr->data_size - ndr->offset;
		if (size == 0) return NT_STATUS_OK;
		NDR_CHECK(ndr_pull_subcontext(ndr, ndr2, size));
		break;
	}

	case 2: {
		uint16_t size;
		NDR_CHECK(ndr_pull_uint16(ndr, &size));
		if (size == 0) return NT_STATUS_OK;
		NDR_CHECK(ndr_pull_subcontext(ndr, ndr2, size));
		break;
	}

	case 4: {
		uint32_t size;
		NDR_CHECK(ndr_pull_uint32(ndr, &size));
		if (size == 0) return NT_STATUS_OK;
		NDR_CHECK(ndr_pull_subcontext(ndr, ndr2, size));
		break;
	}
	default:
		return ndr_pull_error(ndr, NDR_ERR_SUBCONTEXT, "Bad subcontext size %d", 
				      sub_size);
	}
	return NT_STATUS_OK;
}

/*
  handle subcontext buffers, which in midl land are user-marshalled, but
  we use magic in pidl to make them easier to cope with
*/
NTSTATUS ndr_pull_subcontext_fn(struct ndr_pull *ndr, 
				size_t sub_size,
				void *base,
				NTSTATUS (*fn)(struct ndr_pull *, void *))
{
	struct ndr_pull *ndr2;
	NDR_ALLOC(ndr, ndr2);
	NDR_CHECK(ndr_pull_subcontext_header(ndr, sub_size, ndr2));
	NDR_CHECK(fn(ndr2, base));
	if (sub_size) {
		NDR_CHECK(ndr_pull_advance(ndr, ndr2->data_size));
	} else {
		NDR_CHECK(ndr_pull_advance(ndr, ndr2->offset));
	}
	return NT_STATUS_OK;
}


NTSTATUS ndr_pull_subcontext_flags_fn(struct ndr_pull *ndr, 
				      size_t sub_size,
				      void *base,
				      NTSTATUS (*fn)(struct ndr_pull *, int , void *))
{
	struct ndr_pull *ndr2;
	NDR_ALLOC(ndr, ndr2);
	NDR_CHECK(ndr_pull_subcontext_header(ndr, sub_size, ndr2));
	NDR_CHECK(fn(ndr2, NDR_SCALARS|NDR_BUFFERS, base));
	if (sub_size) {
		NDR_CHECK(ndr_pull_advance(ndr, ndr2->data_size));
	} else {
		NDR_CHECK(ndr_pull_advance(ndr, ndr2->offset));
	}
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_subcontext_union_fn(struct ndr_pull *ndr, 
				      size_t sub_size,
				      uint32_t level,
				      void *base,
				      NTSTATUS (*fn)(struct ndr_pull *, int , uint32_t , void *))
{
	struct ndr_pull *ndr2;

	NDR_ALLOC(ndr, ndr2);
	NDR_CHECK(ndr_pull_subcontext_header(ndr, sub_size, ndr2));
	NDR_CHECK(fn(ndr2, NDR_SCALARS|NDR_BUFFERS, level, base));
	if (sub_size) {
		NDR_CHECK(ndr_pull_advance(ndr, ndr2->data_size));
	} else {
		NDR_CHECK(ndr_pull_advance(ndr, ndr2->offset));
	}
	return NT_STATUS_OK;
}


/*
  push a subcontext header 
*/
static NTSTATUS ndr_push_subcontext_header(struct ndr_push *ndr, 
					   size_t sub_size,
					   struct ndr_push *ndr2)
{
	switch (sub_size) {
	case 0: 
		break;

	case 2: 
		NDR_CHECK(ndr_push_uint16(ndr, ndr2->offset));
		break;

	case 4: 
		NDR_CHECK(ndr_push_uint32(ndr, ndr2->offset));
		break;

	default:
		return ndr_push_error(ndr, NDR_ERR_SUBCONTEXT, "Bad subcontext size %d", 
				      sub_size);
	}
	return NT_STATUS_OK;
}

/*
  handle subcontext buffers, which in midl land are user-marshalled, but
  we use magic in pidl to make them easier to cope with
*/
NTSTATUS ndr_push_subcontext_fn(struct ndr_push *ndr, 
				size_t sub_size,
				void *base,
				NTSTATUS (*fn)(struct ndr_push *, void *))
{
	struct ndr_push *ndr2;

	ndr2 = ndr_push_init_ctx(ndr);
	if (!ndr2) return NT_STATUS_NO_MEMORY;

	ndr2->flags = ndr->flags;
	NDR_CHECK(fn(ndr2, base));
	NDR_CHECK(ndr_push_subcontext_header(ndr, sub_size, ndr2));
	NDR_CHECK(ndr_push_bytes(ndr, ndr2->data, ndr2->offset));
	return NT_STATUS_OK;
}

/*
  handle subcontext buffers for function that take a flags arg
*/
NTSTATUS ndr_push_subcontext_flags_fn(struct ndr_push *ndr, 
				      size_t sub_size,
				      void *base,
				      NTSTATUS (*fn)(struct ndr_push *, int, void *))
{
	struct ndr_push *ndr2;

	ndr2 = ndr_push_init_ctx(ndr);
	if (!ndr2) return NT_STATUS_NO_MEMORY;

	ndr2->flags = ndr->flags;
	NDR_CHECK(fn(ndr2, NDR_SCALARS|NDR_BUFFERS, base));
	NDR_CHECK(ndr_push_subcontext_header(ndr, sub_size, ndr2));
	NDR_CHECK(ndr_push_bytes(ndr, ndr2->data, ndr2->offset));
	return NT_STATUS_OK;
}

/*
  handle subcontext buffers for function that take a union
*/
NTSTATUS ndr_push_subcontext_union_fn(struct ndr_push *ndr, 
				      size_t sub_size,
				      uint32_t level,
				      void *base,
				      NTSTATUS (*fn)(struct ndr_push *, int, uint32_t, void *))
{
	struct ndr_push *ndr2;

	ndr2 = ndr_push_init_ctx(ndr);
	if (!ndr2) return NT_STATUS_NO_MEMORY;

	ndr2->flags = ndr->flags;
	NDR_CHECK(fn(ndr2, NDR_SCALARS|NDR_BUFFERS, level, base));
	NDR_CHECK(ndr_push_subcontext_header(ndr, sub_size, ndr2));
	NDR_CHECK(ndr_push_bytes(ndr, ndr2->data, ndr2->offset));
	return NT_STATUS_OK;
}


/*
  mark the start of a structure
*/
NTSTATUS ndr_pull_struct_start(struct ndr_pull *ndr)
{
	return NT_STATUS_OK;
}

/*
  mark the end of a structure
*/
void ndr_pull_struct_end(struct ndr_pull *ndr)
{
}

/*
  mark the start of a structure
*/
NTSTATUS ndr_push_struct_start(struct ndr_push *ndr)
{
	return NT_STATUS_OK;
}

/*
  mark the end of a structure
*/
void ndr_push_struct_end(struct ndr_push *ndr)
{
}


/*
  pull a relative structure
*/
NTSTATUS ndr_pull_relative(struct ndr_pull *ndr, const void **buf, size_t size, 
			   NTSTATUS (*fn)(struct ndr_pull *, int ndr_flags, void *))
{
	struct ndr_pull *ndr2;
	uint32_t ofs;
	struct ndr_pull_save save;
	void *p;

	NDR_ALLOC(ndr, ndr2);
	NDR_CHECK(ndr_pull_uint32(ndr, &ofs));
	if (ofs == 0) {
		(*buf) = NULL;
		return NT_STATUS_OK;
	}
	ndr_pull_save(ndr, &save);
        /* the old way of handling relative pointers appears to be
	   wrong, and there doesn't seem to be anything relying on it,
	   but I am keeping the code around in case I missed a
	   critical use for it (tridge, august 2004) */
	NDR_CHECK(ndr_pull_set_offset(ndr, ofs));
	NDR_CHECK(ndr_pull_subcontext(ndr, ndr2, ndr->data_size - ndr->offset));
	/* strings must be allocated by the backend functions */
	if (ndr->flags & LIBNDR_STRING_FLAGS) {
		NDR_CHECK(fn(ndr2, NDR_SCALARS|NDR_BUFFERS, &p));
	} else {
		NDR_ALLOC_SIZE(ndr, p, size);
		NDR_CHECK(fn(ndr2, NDR_SCALARS|NDR_BUFFERS, p));
	}
	(*buf) = p;
	ndr_pull_restore(ndr, &save);
	talloc_free(ndr2);
	return NT_STATUS_OK;
}


/*
  store a token in the ndr context, for later retrieval
*/
static NTSTATUS ndr_token_store(TALLOC_CTX *mem_ctx, 
				struct ndr_token_list **list, 
				const void *key, 
				uint32_t value)
{
	struct ndr_token_list *tok;
	tok = talloc_p(mem_ctx, struct ndr_token_list);
	if (tok == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tok->key = key;
	tok->value = value;
	DLIST_ADD((*list), tok);
	return NT_STATUS_OK;
}

/*
  retrieve a token from a ndr context
*/
static uint32_t ndr_token_retrieve(struct ndr_token_list **list, const void *key)
{
	struct ndr_token_list *tok;
	for (tok=*list;tok;tok=tok->next) {
		if (tok->key == key) {
			DLIST_REMOVE((*list), tok);
			return tok->value;
		}
	}
	return 0;
}


/*
  pull a relative object - stage1
  called during SCALARS processing
*/
NTSTATUS ndr_pull_relative1(struct ndr_pull *ndr, const void *p, uint32_t rel_offset)
{
	return ndr_token_store(ndr, &ndr->relative_list, p, rel_offset);
}

/*
  pull a relative object - stage2
  called during BUFFERS processing
*/
NTSTATUS ndr_pull_relative2(struct ndr_pull *ndr, const void *p)
{
	uint32_t rel_offset;
	rel_offset = ndr_token_retrieve(&ndr->relative_list, p);
	if (rel_offset == 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	return ndr_pull_set_offset(ndr, rel_offset);
}

/*
  push a relative object - stage1
  this is called during SCALARS processing
*/
NTSTATUS ndr_push_relative1(struct ndr_push *ndr, const void *p)
{
	if (p == NULL) {
		NDR_CHECK(ndr_push_uint32(ndr, 0));
		return NT_STATUS_OK;
	}
	NDR_CHECK(ndr_push_align(ndr, 4));
	NDR_CHECK(ndr_token_store(ndr, &ndr->relative_list, p, ndr->offset));
	return ndr_push_uint32(ndr, 0xFFFFFFFF);
}

/*
  push a relative object - stage2
  this is called during buffers processing
*/
NTSTATUS ndr_push_relative2(struct ndr_push *ndr, const void *p)
{
	struct ndr_push_save save;
	if (p == NULL) {
		return NT_STATUS_OK;
	}
	NDR_CHECK(ndr_push_align(ndr, 4));
	ndr_push_save(ndr, &save);
	ndr->offset = ndr_token_retrieve(&ndr->relative_list, p);
	if (ndr->offset == 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	NDR_CHECK(ndr_push_uint32(ndr, save.offset));
	ndr_push_restore(ndr, &save);
	return NT_STATUS_OK;
}


/*
  pull a union from a blob using NDR
*/
NTSTATUS ndr_pull_union_blob(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, uint32_t level, void *p,
			     NTSTATUS (*fn)(struct ndr_pull *, int ndr_flags, uint32_t, void *))
{
	struct ndr_pull *ndr;
	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	return fn(ndr, NDR_SCALARS|NDR_BUFFERS, level, p);
}

/*
  pull a struct from a blob using NDR
*/
NTSTATUS ndr_pull_struct_blob(const DATA_BLOB *blob, TALLOC_CTX *mem_ctx, void *p,
			      NTSTATUS (*fn)(struct ndr_pull *, int , void *))
{
	struct ndr_pull *ndr;
	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	return fn(ndr, NDR_SCALARS|NDR_BUFFERS, p);
}

/*
  push a struct to a blob using NDR
*/
NTSTATUS ndr_push_struct_blob(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, void *p,
			      NTSTATUS (*fn)(struct ndr_push *, int , void *))
{
	NTSTATUS status;
	struct ndr_push *ndr;
	ndr = ndr_push_init_ctx(mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	status = fn(ndr, NDR_SCALARS|NDR_BUFFERS, p);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*blob = ndr_push_blob(ndr);

	return NT_STATUS_OK;
}
