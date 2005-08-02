/* 
   Unix SMB/CIFS implementation.

   TDR (Trivial Data Representation) helper functions
     Based loosely on ndr.c by Andrew Tridgell.

   Copyright (C) Jelmer Vernooij 2005
   
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
#include "system/network.h"

#define TDR_BASE_MARSHALL_SIZE 1024

#define TDR_PUSH_NEED_BYTES(tdr, n) TDR_CHECK(tdr_push_expand(tdr, tdr->offset+(n)))

#define TDR_PULL_NEED_BYTES(tdr, n) do { \
	if ((n) > tdr->length || tdr->offset + (n) > tdr->length) { \
		return NT_STATUS_BUFFER_TOO_SMALL; \
	} \
} while(0)

#define TDR_BE(tdr) ((tdr)->flags & TDR_FLAG_BIGENDIAN)

#define TDR_SVAL(tdr, ofs) (TDR_BE(tdr)?RSVAL(tdr->data,ofs):SVAL(tdr->data,ofs))
#define TDR_IVAL(tdr, ofs) (TDR_BE(tdr)?RIVAL(tdr->data,ofs):IVAL(tdr->data,ofs))
#define TDR_IVALS(tdr, ofs) (TDR_BE(tdr)?RIVALS(tdr->data,ofs):IVALS(tdr->data,ofs))
#define TDR_SSVAL(tdr, ofs, v) do { if (TDR_BE(tdr))  { RSSVAL(tdr->data,ofs,v); } else SSVAL(tdr->data,ofs,v); } while (0)
#define TDR_SIVAL(tdr, ofs, v) do { if (TDR_BE(tdr))  { RSIVAL(tdr->data,ofs,v); } else SIVAL(tdr->data,ofs,v); } while (0)
#define TDR_SIVALS(tdr, ofs, v) do { if (TDR_BE(tdr))  { RSIVALS(tdr->data,ofs,v); } else SIVALS(tdr->data,ofs,v); } while (0)

struct tdr_pull *tdr_pull_init(TALLOC_CTX *mem_ctx, DATA_BLOB *blob)
{
	struct tdr_pull *tdr = talloc(mem_ctx, struct tdr_pull);
	tdr->data = blob->data;
	tdr->length = blob->length;
	tdr->offset = 0;
	tdr->flags = 0;
	return tdr;
}

struct tdr_push *tdr_push_init(TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct tdr_push);
}

struct tdr_print *tdr_print_init(TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct tdr_print);
}

/*
  expand the available space in the buffer to 'size'
*/
NTSTATUS tdr_push_expand(struct tdr_push *tdr, uint32_t size)
{
	if (tdr->alloc_size >= size) {
		return NT_STATUS_OK;
	}

	tdr->alloc_size += TDR_BASE_MARSHALL_SIZE;
	if (size > tdr->alloc_size) {
		tdr->length = size;
	}
	tdr->data = talloc_realloc(tdr, tdr->data, uint8_t, tdr->alloc_size);
	return NT_STATUS_NO_MEMORY;
}


NTSTATUS tdr_pull_uint8(struct tdr_pull *tdr, uint8_t *v)
{
	TDR_PULL_NEED_BYTES(tdr, 1);
	SCVAL(tdr->data, tdr->offset, *v);
	tdr->offset += 1;
	return NT_STATUS_OK;
}

NTSTATUS tdr_push_uint8(struct tdr_push *tdr, const uint8_t *v)
{
	TDR_PUSH_NEED_BYTES(tdr, 1);
	SCVAL(tdr->data, tdr->offset, *v);
	tdr->offset += 1;
	return NT_STATUS_OK;
}

NTSTATUS tdr_print_uint8(struct tdr_print *tdr, const char *name, uint8_t *v)
{
	tdr->print(tdr, "%-25s: 0x%02x (%u)", name, *v, *v);
	return NT_STATUS_OK;
}

NTSTATUS tdr_pull_uint16(struct tdr_pull *tdr, uint16_t *v)
{
	TDR_PULL_NEED_BYTES(tdr, 2);
	*v = TDR_SVAL(tdr, tdr->offset);
	tdr->offset += 2;
	return NT_STATUS_OK;
}

NTSTATUS tdr_push_uint16(struct tdr_push *tdr, const uint16_t *v)
{
	TDR_PUSH_NEED_BYTES(tdr, 2);
	TDR_SSVAL(tdr, tdr->offset, *v);
	tdr->offset += 2;
	return NT_STATUS_OK;
}

NTSTATUS tdr_print_uint16(struct tdr_print *tdr, const char *name, uint16_t *v)
{
	tdr->print(tdr, "%-25s: 0x%02x (%u)", name, *v, *v);
	return NT_STATUS_OK;
}

NTSTATUS tdr_pull_uint32(struct tdr_pull *tdr, uint16_t *v)
{
	TDR_PULL_NEED_BYTES(tdr, 4);
	*v = TDR_IVAL(tdr, tdr->offset);
	tdr->offset += 4;
	return NT_STATUS_OK;
}

NTSTATUS tdr_push_uint32(struct tdr_push *tdr, const uint16_t *v)
{
	TDR_PUSH_NEED_BYTES(tdr, 4);
	TDR_SIVAL(tdr, tdr->offset, *v);
	tdr->offset += 4;
	return NT_STATUS_OK;
}

NTSTATUS tdr_print_uint32(struct tdr_print *tdr, const char *name, uint32_t *v)
{
	tdr->print(tdr, "%-25s: 0x%02x (%u)", name, *v, *v);
	return NT_STATUS_OK;
}

NTSTATUS tdr_pull_charset(struct tdr_pull *tdr, char **v, uint32_t length, uint32_t el_size, int chset)
{
	int ret;
	if (length == -1) {
		switch (chset) {
		case CH_DOS:
			length = ascii_len_n((const char*)tdr->data+tdr->offset, tdr->length-tdr->offset);
			break;
		case CH_UTF16:
			length = utf16_len_n(tdr->data+tdr->offset, tdr->length-tdr->offset);
		default:
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	
	TDR_PULL_NEED_BYTES(tdr, el_size*length);
	
	ret = convert_string_talloc(tdr, chset, CH_UNIX, tdr->data+tdr->offset, el_size*length, (void **)v);

	if (ret == -1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

NTSTATUS tdr_push_charset(struct tdr_push *tdr, const char **v, uint32_t length, uint32_t el_size, int chset)
{
	int ret;
	TDR_PUSH_NEED_BYTES(tdr, el_size*length);

	ret = convert_string(CH_UNIX, chset, *v, length, tdr->data+tdr->offset, el_size*length);

	if (ret == -1) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	tdr->offset += ret;
						 
	return NT_STATUS_OK;
}

NTSTATUS tdr_print_charset(struct tdr_print *tdr, const char *name, const char **v, uint32_t length, uint32_t el_size, int chset)
{
	tdr->print(tdr, "%-25s: %s", name, *v);
	return NT_STATUS_OK;
}

/*
  pull a ipv4address
*/
NTSTATUS tdr_pull_ipv4address(struct tdr_pull *tdr, const char **address)
{
	struct ipv4_addr in;
	TDR_CHECK(tdr_pull_uint32(tdr, &in.addr));
	in.addr = htonl(in.addr);
	*address = talloc_strdup(tdr, sys_inet_ntoa(in));
	NT_STATUS_HAVE_NO_MEMORY(*address);
	return NT_STATUS_OK;
}

/*
  push a ipv4address
*/
NTSTATUS tdr_push_ipv4address(struct tdr_push *tdr, const char **address)
{
	uint32_t addr = htonl(interpret_addr(*address));
	TDR_CHECK(tdr_push_uint32(tdr, &addr));
	return NT_STATUS_OK;
}

/*
  print a ipv4address
*/
NTSTATUS tdr_print_ipv4address(struct tdr_print *tdr, const char *name, 
			   const char **address)
{
	tdr->print(tdr, "%-25s: %s", name, *address);
	return NT_STATUS_OK;
}
