/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling basic types

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

#include "includes.h"

/*
  parse a uint8
*/
NTSTATUS ndr_pull_uint8(struct ndr_pull *ndr, uint8 *v)
{
	NDR_PULL_NEED_BYTES(ndr, 1);
	*v = CVAL(ndr->data, ndr->offset);
	ndr->offset += 1;
	return NT_STATUS_OK;
}


/*
  parse a uint16
*/
NTSTATUS ndr_pull_uint16(struct ndr_pull *ndr, uint16 *v)
{
	NDR_PULL_ALIGN(ndr, 2);
	NDR_PULL_NEED_BYTES(ndr, 2);
	*v = SVAL(ndr->data, ndr->offset);
	ndr->offset += 2;
	return NT_STATUS_OK;
}


/*
  parse a uint32
*/
NTSTATUS ndr_pull_uint32(struct ndr_pull *ndr, uint32 *v)
{
	NDR_PULL_ALIGN(ndr, 4);
	NDR_PULL_NEED_BYTES(ndr, 4);
	*v = IVAL(ndr->data, ndr->offset);
	ndr->offset += 4;
	return NT_STATUS_OK;
}

/*
  parse a HYPER_T
*/
NTSTATUS ndr_pull_HYPER_T(struct ndr_pull *ndr, HYPER_T *v)
{
	NDR_PULL_ALIGN(ndr, 8);
	NDR_PULL_NEED_BYTES(ndr, 8);
	v->low = IVAL(ndr->data, ndr->offset);
	v->high = IVAL(ndr->data, ndr->offset+4);
	ndr->offset += 8;
	return NT_STATUS_OK;
}

/*
  pull a NTSTATUS
*/
NTSTATUS ndr_pull_NTSTATUS(struct ndr_pull *ndr, NTSTATUS *status)
{
	uint32 v;
	NDR_CHECK(ndr_pull_uint32(ndr, &v));
	*status = NT_STATUS(v);
	return NT_STATUS_OK;
}

/*
  pull a WERROR
*/
NTSTATUS ndr_pull_WERROR(struct ndr_pull *ndr, WERROR *status)
{
	uint32 v;
	NDR_CHECK(ndr_pull_uint32(ndr, &v));
	*status = W_ERROR(v);
	return NT_STATUS_OK;
}

/*
  parse a set of bytes
*/
NTSTATUS ndr_pull_bytes(struct ndr_pull *ndr, char *data, uint32 n)
{
	NDR_PULL_NEED_BYTES(ndr, n);
	memcpy(data, ndr->data + ndr->offset, n);
	ndr->offset += n;
	return NT_STATUS_OK;
}

/*
  pull an array of uint8
*/
NTSTATUS ndr_pull_array_uint8(struct ndr_pull *ndr, int ndr_flags, char *data, uint32 n)
{
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	return ndr_pull_bytes(ndr, data, n);
}


/*
  pull an array of uint16
*/
NTSTATUS ndr_pull_array_uint16(struct ndr_pull *ndr, int ndr_flags, uint16 *data, uint32 n)
{
	uint32 i;
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	for (i=0;i<n;i++) {
		NDR_CHECK(ndr_pull_uint16(ndr, &data[i]));
	}
	return NT_STATUS_OK;
}

/*
  pull a const array of uint32
*/
NTSTATUS ndr_pull_array_uint32(struct ndr_pull *ndr, int ndr_flags, uint32 *data, uint32 n)
{
	uint32 i;
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	for (i=0;i<n;i++) {
		NDR_CHECK(ndr_pull_uint32(ndr, &data[i]));
	}
	return NT_STATUS_OK;
}

/*
  parse a GUID
*/
NTSTATUS ndr_pull_GUID(struct ndr_pull *ndr, int ndr_flags, GUID *guid)
{
	if (ndr_flags & NDR_SCALARS) {
		return ndr_pull_bytes(ndr, guid->info, GUID_SIZE);
	}
	return NT_STATUS_OK;
}


/*
  push a uint8
*/
NTSTATUS ndr_push_uint8(struct ndr_push *ndr, uint8 v)
{
	NDR_PUSH_NEED_BYTES(ndr, 1);
	SCVAL(ndr->data, ndr->offset, v);
	ndr->offset += 1;
	return NT_STATUS_OK;
}

/*
  push a uint16
*/
NTSTATUS ndr_push_uint16(struct ndr_push *ndr, uint16 v)
{
	NDR_PUSH_ALIGN(ndr, 2);
	NDR_PUSH_NEED_BYTES(ndr, 2);
	SSVAL(ndr->data, ndr->offset, v);
	ndr->offset += 2;
	return NT_STATUS_OK;
}

/*
  push a uint32
*/
NTSTATUS ndr_push_uint32(struct ndr_push *ndr, uint32 v)
{
	NDR_PUSH_ALIGN(ndr, 4);
	NDR_PUSH_NEED_BYTES(ndr, 4);
	SIVAL(ndr->data, ndr->offset, v);
	ndr->offset += 4;
	return NT_STATUS_OK;
}

/*
  push a HYPER_T
*/
NTSTATUS ndr_push_HYPER_T(struct ndr_push *ndr, HYPER_T v)
{
	NDR_PUSH_ALIGN(ndr, 8);
	NDR_PUSH_NEED_BYTES(ndr, 8);
	SIVAL(ndr->data, ndr->offset, v.low);
	SIVAL(ndr->data, ndr->offset+4, v.high);
	ndr->offset += 8;
	return NT_STATUS_OK;
}

NTSTATUS ndr_push_align(struct ndr_push *ndr, size_t size)
{
	NDR_PUSH_ALIGN(ndr, size);
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_align(struct ndr_pull *ndr, size_t size)
{
	NDR_PULL_ALIGN(ndr, size);
	return NT_STATUS_OK;
}

/*
  push some bytes
*/
NTSTATUS ndr_push_bytes(struct ndr_push *ndr, const char *data, uint32 n)
{
	NDR_PUSH_NEED_BYTES(ndr, n);
	memcpy(ndr->data + ndr->offset, data, n);
	ndr->offset += n;
	return NT_STATUS_OK;
}

/*
  push an array of uint8
*/
NTSTATUS ndr_push_array_uint8(struct ndr_push *ndr, int ndr_flags, const char *data, uint32 n)
{
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	return ndr_push_bytes(ndr, data, n);
}

/*
  push an array of uint32
*/
NTSTATUS ndr_push_array_uint32(struct ndr_push *ndr, int ndr_flags, const uint32 *data, uint32 n)
{
	int i;
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	for (i=0;i<n;i++) {
		NDR_CHECK(ndr_push_uint32(ndr, data[i]));
	}
	return NT_STATUS_OK;
}

/*
  save the current position
 */
void ndr_push_save(struct ndr_push *ndr, struct ndr_push_save *save)
{
	save->offset = ndr->offset;
}

/*
  restore the position
 */
void ndr_push_restore(struct ndr_push *ndr, struct ndr_push_save *save)
{
	ndr->offset = save->offset;
}

/*
  this is used when a packet has a 4 byte length field. We remember the start position
  and come back to it later to fill in the size
*/
NTSTATUS ndr_push_length4_start(struct ndr_push *ndr, struct ndr_push_save *save)
{
	NDR_PUSH_ALIGN(ndr, 4);
	ndr_push_save(ndr, save);
	return ndr_push_uint32(ndr, 0);
}

NTSTATUS ndr_push_length4_end(struct ndr_push *ndr, struct ndr_push_save *save)
{
	struct ndr_push_save save2;
	ndr_push_save(ndr, &save2);
	ndr_push_restore(ndr, save);
	NDR_CHECK(ndr_push_uint32(ndr, save2.offset - ndr->offset));
	ndr_push_restore(ndr, &save2);
	return NT_STATUS_OK;
}

/*
  push a 1 if a pointer is non-NULL, otherwise 0
*/
NTSTATUS ndr_push_ptr(struct ndr_push *ndr, const void *p)
{
	return ndr_push_uint32(ndr, p?0xaabbccdd:0);
}

/*
  push a comformant, variable ucs2 string onto the wire from a C string
*/
NTSTATUS ndr_push_unistr(struct ndr_push *ndr, const char *s)
{
	char *ws;
	ssize_t len;
	len = push_ucs2_talloc(ndr->mem_ctx, (smb_ucs2_t **)&ws, s);
	if (len == -1) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	NDR_CHECK(ndr_push_uint32(ndr, len/2));
	NDR_CHECK(ndr_push_uint32(ndr, 0));
	NDR_CHECK(ndr_push_uint32(ndr, len/2));
	NDR_CHECK(ndr_push_bytes(ndr, ws, len));
	return NT_STATUS_OK;
}

/*
  push a comformant, variable ucs2 string onto the wire from a C string
  don't send the null
*/
NTSTATUS ndr_push_unistr_noterm(struct ndr_push *ndr, const char *s)
{
	char *ws;
	ssize_t len;
	len = push_ucs2_talloc(ndr->mem_ctx, (smb_ucs2_t **)&ws, s);
	if (len == -1) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	NDR_CHECK(ndr_push_uint32(ndr, len/2 - 1));
	NDR_CHECK(ndr_push_uint32(ndr, 0));
	NDR_CHECK(ndr_push_uint32(ndr, len/2 - 1));
	NDR_CHECK(ndr_push_bytes(ndr, ws, len - 2));
	return NT_STATUS_OK;
}

/*
  pull a comformant, variable ucs2 string from the wire into a C string
*/
NTSTATUS ndr_pull_unistr(struct ndr_pull *ndr, const char **s)
{
	char *ws, *as=NULL;
	uint32 len1, ofs, len2;

	NDR_CHECK(ndr_pull_uint32(ndr, &len1));
	NDR_CHECK(ndr_pull_uint32(ndr, &ofs));
	NDR_CHECK(ndr_pull_uint32(ndr, &len2));
	if (len2 > len1) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	NDR_ALLOC_N(ndr, ws, (len1+1)*2);
	NDR_CHECK(ndr_pull_bytes(ndr, ws, len2*2));
	SSVAL(ws, len1*2, 0);
	SSVAL(ws, len2*2, 0);
	pull_ucs2_talloc(ndr->mem_ctx, &as, (const smb_ucs2_t *)ws);
	if (!as) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	*s = as;
	return NT_STATUS_OK;
}

/*
  pull a comformant, variable ucs2 string from the wire into a C string
*/
NTSTATUS ndr_pull_unistr_noterm(struct ndr_pull *ndr, const char **s)
{
	return ndr_pull_unistr(ndr, s);
}

/*
  push a 4 byte offset pointer, remembering where we are so we can later fill
  in the correct value
*/
NTSTATUS ndr_push_offset(struct ndr_push *ndr, struct ndr_push_save *ofs)
{
	NDR_PUSH_ALIGN(ndr, 4);
	ndr_push_save(ndr, ofs);
	return ndr_push_uint32(ndr, 0);
}

/*
  fill in the correct offset in a saved offset pointer
  the offset is taken relative to 'save'
*/
NTSTATUS ndr_push_offset_ptr(struct ndr_push *ndr, 
			     struct ndr_push_save *ofs, 
			     struct ndr_push_save *save)
{
	struct ndr_push_save save2;
	ndr_push_save(ndr, &save2);
	ndr_push_restore(ndr, ofs);
	NDR_CHECK(ndr_push_uint32(ndr, save2.offset - save->offset));
	ndr_push_restore(ndr, &save2);
	return NT_STATUS_OK;
}


/*
  push a GUID
*/
NTSTATUS ndr_push_GUID(struct ndr_push *ndr, int ndr_flags, GUID *guid)
{
	if (ndr_flags & NDR_SCALARS) {
		return ndr_push_bytes(ndr, guid->info, GUID_SIZE);
	}
	return NT_STATUS_OK;
}

/*
  push a NTTIME
*/
NTSTATUS ndr_push_NTTIME(struct ndr_push *ndr, NTTIME t)
{
	NDR_CHECK(ndr_push_uint32(ndr, t.low));
	NDR_CHECK(ndr_push_uint32(ndr, t.high));
	return NT_STATUS_OK;
}

/*
  pull a NTTIME
*/
NTSTATUS ndr_pull_NTTIME(struct ndr_pull *ndr, NTTIME *t)
{
	NDR_CHECK(ndr_pull_uint32(ndr, &t->low));
	NDR_CHECK(ndr_pull_uint32(ndr, &t->high));
	return NT_STATUS_OK;
}


void ndr_print_struct(struct ndr_print *ndr, const char *name, const char *type)
{
	ndr->print(ndr, "%s: struct %s", name, type);
}

void ndr_print_uint8(struct ndr_print *ndr, const char *name, uint8 v)
{
	ndr->print(ndr, "%-25s: 0x%02x (%u)", name, v, v);
}

void ndr_print_uint16(struct ndr_print *ndr, const char *name, uint16 v)
{
	ndr->print(ndr, "%-25s: 0x%04x (%u)", name, v, v);
}

void ndr_print_uint32(struct ndr_print *ndr, const char *name, uint32 v)
{
	ndr->print(ndr, "%-25s: 0x%08x (%u)", name, v, v);
}

void ndr_print_HYPER_T(struct ndr_print *ndr, const char *name, HYPER_T v)
{
	ndr->print(ndr, "%-25s: 0x%08x%08x", name, v.high, v.low);
}

void ndr_print_ptr(struct ndr_print *ndr, const char *name, const void *p)
{
	if (p) {
		ndr->print(ndr, "%-25s: *", name);
	} else {
		ndr->print(ndr, "%-25s: NULL", name);
	}
}

void ndr_print_unistr(struct ndr_print *ndr, const char *name, const char *s)
{
	if (s) {
		ndr->print(ndr, "%-25s: '%s'", name, s);
	} else {
		ndr->print(ndr, "%-25s: NULL", name);
	}
}

void ndr_print_unistr_noterm(struct ndr_print *ndr, const char *name, const char *s)
{
	ndr_print_unistr(ndr, name, s);
}

void ndr_print_NTTIME(struct ndr_print *ndr, const char *name, NTTIME t)
{
	ndr->print(ndr, "%-25s: %s", name, nt_time_string(ndr->mem_ctx, &t));
}

void ndr_print_union(struct ndr_print *ndr, const char *name, uint16 level, const char *type)
{
	ndr->print(ndr, "%-25s: union %s(case %u)", name, type, level);
}

void ndr_print_bad_level(struct ndr_print *ndr, const char *name, uint16 level)
{
	ndr->print(ndr, "UNKNOWN LEVEL %u", level);
}

void ndr_print_array_uint32(struct ndr_print *ndr, const char *name, 
			    const uint32 *data, uint32 count)
{
	int i;

	ndr->print(ndr, "%s: ARRAY(%d)", name, count);
	ndr->depth++;
	for (i=0;i<count;i++) {
		char *idx=NULL;
		asprintf(&idx, "[%d]", i);
		if (idx) {
			ndr_print_uint32(ndr, idx, data[i]);
			free(idx);
		}
	}
	ndr->depth--;	
}

void ndr_print_array_uint8(struct ndr_print *ndr, const char *name, 
			   const uint8 *data, uint32 count)
{
	int i;

	ndr->print(ndr, "%s: ARRAY(%d)", name, count);
	ndr->depth++;
	for (i=0;i<count;i++) {
		char *idx=NULL;
		asprintf(&idx, "[%d]", i);
		if (idx) {
			ndr_print_uint8(ndr, idx, data[i]);
			free(idx);
		}
	}
	ndr->depth--;	
}

void ndr_print_GUID(struct ndr_print *ndr, const char *name, const struct GUID *guid)
{
	ndr->print(ndr, "%-25s: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", 
		   name,
		   IVAL(guid->info, 0), SVAL(guid->info, 4), SVAL(guid->info, 6),
		   guid->info[8], guid->info[9],
		   guid->info[10], guid->info[11], guid->info[12], guid->info[13], 
		   guid->info[14], guid->info[15]);
}


/*
  pull a null terminated UCS2 string
*/
NTSTATUS ndr_pull_nstring(struct ndr_pull *ndr, int ndr_flags, const char **s)
{
	int ret;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}

	ret = convert_string_talloc(ndr->mem_ctx, CH_UCS2, CH_UNIX, 
				    ndr->data+ndr->offset, 
				    ndr->data_size - ndr->offset,
				    (const void **)s);
	if (ret == -1) {
		return ndr_pull_error(ndr, NDR_ERR_CHARCNV, "Bad character conversion");
	}
	ndr->offset += ret;
	return NT_STATUS_OK;
}

/*
  push a spoolss style "relative string"
*/
NTSTATUS ndr_push_nstring(struct ndr_push *ndr, int ndr_flags, const char **s)
{
	uint32 len;
	int ret;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}

	len = 2*(strlen_m(*s)+1);
	NDR_PUSH_NEED_BYTES(ndr, len);
	ret = push_ucs2(NULL, ndr->data + ndr->offset, *s, len, STR_TERMINATE);
	if (ret == -1) {
		return ndr_push_error(ndr, NDR_ERR_CHARCNV, "Bad string conversion");
	}
	ndr->offset += len;
	return NT_STATUS_OK;
}

void ndr_print_nstring(struct ndr_print *ndr, const char *name, const char **s)
{
	ndr_print_unistr(ndr, name, *s);
}


/*
  push a DATA_BLOB onto the wire. 
*/
NTSTATUS ndr_push_DATA_BLOB(struct ndr_push *ndr, DATA_BLOB blob)
{
	NDR_CHECK(ndr_push_uint32(ndr, blob.length));
	NDR_CHECK(ndr_push_bytes(ndr, blob.data, blob.length));
	return NT_STATUS_OK;
}

/*
  pull a DATA_BLOB from the wire. 
*/
NTSTATUS ndr_pull_DATA_BLOB(struct ndr_pull *ndr, DATA_BLOB *blob)
{
	uint32 length;
	NDR_CHECK(ndr_pull_uint32(ndr, &length));
	NDR_PULL_NEED_BYTES(ndr, length);
	*blob = data_blob_talloc(ndr->mem_ctx, ndr->data+ndr->offset, length);
	ndr->offset += length;
	return NT_STATUS_OK;
}


/*
  parse a policy handle
*/
NTSTATUS ndr_pull_policy_handle(struct ndr_pull *ndr, 
				struct policy_handle *r)
{
	NDR_CHECK(ndr_pull_bytes(ndr, r->data, 20));
	return NT_STATUS_OK;
}

/*
  push a policy handle
*/
NTSTATUS ndr_push_policy_handle(struct ndr_push *ndr, 
				struct policy_handle *r)
{
	NDR_CHECK(ndr_push_bytes(ndr, r->data, 20));
	return NT_STATUS_OK;
}
