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

#define NDR_PULL_NEED_BYTES(ndr, n) do { \
	if ((n) > ndr->data_size || ndr->offset + (n) > ndr->data_size) { \
		return NT_STATUS_BUFFER_TOO_SMALL; \
	} \
} while(0)

#define NDR_PULL_ALIGN(ndr, n) do { \
	ndr->offset = (ndr->offset + (n-1)) & ~(n-1); \
	if (ndr->offset >= ndr->data_size) { \
		return NT_STATUS_BUFFER_TOO_SMALL; \
	} \
} while(0)

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
	if (ndr->flags & LIBNDR_FLAG_BIGENDIAN) {
		*v = RSVAL(ndr->data, ndr->offset);
	} else {
		*v = SVAL(ndr->data, ndr->offset);
	}
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
	if (ndr->flags & LIBNDR_FLAG_BIGENDIAN) {
		*v = RIVAL(ndr->data, ndr->offset);
	} else {
		*v = IVAL(ndr->data, ndr->offset);
	}
	ndr->offset += 4;
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
NTSTATUS ndr_pull_array_uint8(struct ndr_pull *ndr, char *data, uint32 n)
{
	uint32 len;
	NDR_CHECK(ndr_pull_uint32(ndr, &len));
	if (len != n) {
		return NT_STATUS_INVALID_PARAMETER;
	}	
	return ndr_pull_bytes(ndr, data, len);
}


/*
  parse a GUID
*/
NTSTATUS ndr_pull_guid(struct ndr_pull *ndr, GUID *guid)
{
	int i;
	NDR_PULL_NEED_BYTES(ndr, GUID_SIZE);
	for (i=0;i<GUID_SIZE;i++) {
		guid->info[i] = CVAL(ndr->data, ndr->offset + i);
	}
	ndr->offset += i;
	return NT_STATUS_OK;
}


#define NDR_PUSH_NEED_BYTES(ndr, n) NDR_CHECK(ndr_push_expand(ndr, ndr->offset+(n)))

#define NDR_PUSH_ALIGN(ndr, n) do { \
	uint32 _pad = (ndr->offset & (n-1)); \
	while (_pad--) NDR_CHECK(ndr_push_uint8(ndr, 0)); \
} while(0)

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
  align to a uint32
*/
NTSTATUS ndr_push_align_uint32(struct ndr_push *ndr)
{
	NDR_PUSH_ALIGN(ndr, 4);
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
NTSTATUS ndr_push_array_uint8(struct ndr_push *ndr, const char *data, uint32 n)
{
	NDR_CHECK(ndr_push_uint32(ndr, n));
	return ndr_push_bytes(ndr, data, n);
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
NTSTATUS ndr_push_guid(struct ndr_push *ndr, GUID *guid)
{
	return ndr_push_bytes(ndr, guid->info, GUID_SIZE);
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


void ndr_print_struct(struct ndr_print *ndr, const char *name)
{
	ndr->print(ndr, "%s:", name);
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

void ndr_print_ptr(struct ndr_print *ndr, const char *name, const void *p)
{
	if (p) {
		ndr->print(ndr, "%-25s: *", name);
	} else {
		ndr->print(ndr, "%-25s: NULL", name);
	}
}

void ndr_print_unistr_noterm(struct ndr_print *ndr, const char *name, const char *s)
{
	ndr->print(ndr, "%-25s: '%s'", name, s);
}

void ndr_print_unistr(struct ndr_print *ndr, const char *name, const char *s)
{
	ndr->print(ndr, "%-25s: '%s'", name, s);
}

void ndr_print_NTTIME(struct ndr_print *ndr, const char *name, NTTIME t)
{
	ndr->print(ndr, "%-25s: %s", name, nt_time_string(ndr->mem_ctx, &t));
}
