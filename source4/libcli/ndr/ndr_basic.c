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
  parse a u8
*/
NTSTATUS ndr_pull_u8(struct ndr_pull *ndr, uint8 *v)
{
	NDR_PULL_NEED_BYTES(ndr, 1);
	*v = CVAL(ndr->data, ndr->offset);
	ndr->offset += 1;
	return NT_STATUS_OK;
}


/*
  parse a u16
*/
NTSTATUS ndr_pull_u16(struct ndr_pull *ndr, uint16 *v)
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
  parse a u32
*/
NTSTATUS ndr_pull_u32(struct ndr_pull *ndr, uint32 *v)
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
NTSTATUS ndr_pull_status(struct ndr_pull *ndr, NTSTATUS *status)
{
	uint32 v;
	NDR_CHECK(ndr_pull_u32(ndr, &v));
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
	ndr->offset = (ndr->offset + (n-1)) & ~(n-1); \
	NDR_CHECK(ndr_push_expand(ndr, ndr->offset)); \
} while(0)

/*
  push a u8
*/
NTSTATUS ndr_push_u8(struct ndr_push *ndr, uint8 v)
{
	NDR_PUSH_NEED_BYTES(ndr, 1);
	SCVAL(ndr->data, ndr->offset, v);
	ndr->offset += 1;
	return NT_STATUS_OK;
}

/*
  push a u16
*/
NTSTATUS ndr_push_u16(struct ndr_push *ndr, uint16 v)
{
	NDR_PUSH_ALIGN(ndr, 2);
	NDR_PUSH_NEED_BYTES(ndr, 2);
	SSVAL(ndr->data, ndr->offset, v);
	ndr->offset += 2;
	return NT_STATUS_OK;
}

/*
  push a u32
*/
NTSTATUS ndr_push_u32(struct ndr_push *ndr, uint32 v)
{
	NDR_PUSH_ALIGN(ndr, 4);
	NDR_PUSH_NEED_BYTES(ndr, 4);
	SIVAL(ndr->data, ndr->offset, v);
	ndr->offset += 4;
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
  this is used when a packet has a 4 byte length field. We remember the start position
  and come back to it later to fill in the size
*/
NTSTATUS ndr_push_length4_start(struct ndr_push *ndr, struct ndr_push_save *save)
{
	save->offset = ndr->offset;
	return ndr_push_u32(ndr, 0);
}

NTSTATUS ndr_push_length4_end(struct ndr_push *ndr, struct ndr_push_save *save)
{
	uint32 offset = ndr->offset;
	ndr->offset = save->offset;
	NDR_CHECK(ndr_push_u32(ndr, offset - save->offset));
	ndr->offset = offset;
	return NT_STATUS_OK;
}

/*
  push a 1 if a pointer is non-NULL, otherwise 0
*/
NTSTATUS ndr_push_ptr(struct ndr_push *ndr, const void *p)
{
	return ndr_push_u32(ndr, p?1:0);
}

/*
  push a comformant, variable ucs2 string onto the wire from a C string
*/
NTSTATUS ndr_push_unistr(struct ndr_push *ndr, const char *s)
{
	smb_ucs2_t *ws;
	ssize_t len;
	int i;
	len = push_ucs2_talloc(ndr->mem_ctx, &ws, s);
	if (len == -1) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	NDR_CHECK(ndr_push_u32(ndr, len));
	NDR_CHECK(ndr_push_u32(ndr, 0));
	NDR_CHECK(ndr_push_u32(ndr, len-2));
	NDR_PUSH_NEED_BYTES(ndr, len);
	for (i=0;i<len;i+=2) {
		SSVAL(ndr->data, ndr->offset + i, ws[i]);
	}
	ndr->offset += i;
	return NT_STATUS_OK;
}

