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
  push a NTSTATUS
*/
NTSTATUS ndr_push_NTSTATUS(struct ndr_push *ndr, NTSTATUS status)
{
	return ndr_push_uint32(ndr, NT_STATUS_V(status));
}

void ndr_print_NTSTATUS(struct ndr_print *ndr, const char *name, NTSTATUS *r)
{
	ndr->print(ndr, "%-25s: %s", name, nt_errstr(*r));
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
  push a WERROR
*/
NTSTATUS ndr_push_WERROR(struct ndr_push *ndr, WERROR status)
{
	return ndr_push_uint32(ndr, W_ERROR_V(status));
}

void ndr_print_WERROR(struct ndr_print *ndr, const char *name, WERROR *r)
{
	ndr->print(ndr, "%-25s: %s", name, win_errstr(*r));
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
	uint32 ptr = 0;
	if (p) {
		/* we do this to ensure that we generate unique ref ids,
		   which means we can handle the case where a MS programmer
		   forgot to mark a pointer as unique */
		ndr->ptr_count++;
		ptr = ndr->ptr_count;
	}
	return ndr_push_uint32(ndr, ptr);
}


/*
  pull a general string from the wire
*/
NTSTATUS ndr_pull_string(struct ndr_pull *ndr, int ndr_flags, const char **s)
{
	char *as=NULL;
	uint32 len1, ofs, len2;
	uint16 len3;
	int ret;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}

	switch (ndr->flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, &len1));
		NDR_CHECK(ndr_pull_uint32(ndr, &ofs));
		NDR_CHECK(ndr_pull_uint32(ndr, &len2));
		if (len2 > len1) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, 
					      "Bad string lengths len1=%u ofs=%u len2=%u\n", 
					      len1, ofs, len2);
		}
		if (len2 == 0) {
			*s = talloc_strdup(ndr->mem_ctx, "");
			break;
		}
		NDR_PULL_NEED_BYTES(ndr, len2*2);
		ret = convert_string_talloc(ndr->mem_ctx, CH_UCS2, CH_UNIX, 
					    ndr->data+ndr->offset, 
					    len2*2,
					    (const void **)&as);
		if (ret == -1) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		NDR_CHECK(ndr_pull_advance(ndr, len2*2));
		*s = as;
		break;

	case LIBNDR_FLAG_STR_SIZE4:
		NDR_CHECK(ndr_pull_uint32(ndr, &len1));
		NDR_PULL_NEED_BYTES(ndr, len1*2);
		if (len1 == 0) {
			*s = talloc_strdup(ndr->mem_ctx, "");
			break;
		}
		ret = convert_string_talloc(ndr->mem_ctx, CH_UCS2, CH_UNIX, 
					    ndr->data+ndr->offset, 
					    len1*2,
					    (const void **)&as);
		if (ret == -1) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		NDR_CHECK(ndr_pull_advance(ndr, len1*2));
		*s = as;
		break;

	case LIBNDR_FLAG_STR_NULLTERM:
		len1 = strnlen_w(ndr->data+ndr->offset, 
				 (ndr->data_size - ndr->offset)/2);
		if (len1*2+2 <= ndr->data_size - ndr->offset) {
			len1++;
		}
		ret = convert_string_talloc(ndr->mem_ctx, CH_UCS2, CH_UNIX, 
					    ndr->data+ndr->offset, 
					    len1*2,
					    (const void **)s);
		if (ret == -1) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		NDR_CHECK(ndr_pull_advance(ndr, len1*2));
		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
		NDR_CHECK(ndr_pull_uint32(ndr, &len1));
		NDR_CHECK(ndr_pull_uint32(ndr, &ofs));
		NDR_CHECK(ndr_pull_uint32(ndr, &len2));
		if (len2 > len1) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, 
					      "Bad ascii string lengths len1=%u ofs=%u len2=%u\n", 
					      len1, ofs, len2);
		}
		NDR_ALLOC_N(ndr, as, (len2+1));
		NDR_CHECK(ndr_pull_bytes(ndr, as, len2));
		as[len2] = 0;
		(*s) = as;
		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_LEN4:
		NDR_CHECK(ndr_pull_uint32(ndr, &ofs));
		NDR_CHECK(ndr_pull_uint32(ndr, &len2));
		NDR_ALLOC_N(ndr, as, (len2+1));
		NDR_CHECK(ndr_pull_bytes(ndr, as, len2));
		as[len2] = 0;
		(*s) = as;
		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_SIZE2:
		NDR_CHECK(ndr_pull_uint16(ndr, &len3));
		NDR_ALLOC_N(ndr, as, (len3+1));
		NDR_CHECK(ndr_pull_bytes(ndr, as, len3));
		as[len3] = 0;
		(*s) = as;
		break;

	default:
		return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	return NT_STATUS_OK;
}


/*
  push a general string onto the wire
*/
NTSTATUS ndr_push_string(struct ndr_push *ndr, int ndr_flags, const char *s)
{
	ssize_t s_len, c_len;
	int ret;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	
	s_len = s?strlen(s):0;
	c_len = s?strlen_m(s):0;

	switch (ndr->flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
		NDR_CHECK(ndr_push_uint32(ndr, c_len+1));
		NDR_CHECK(ndr_push_uint32(ndr, 0));
		NDR_CHECK(ndr_push_uint32(ndr, c_len+1));
		NDR_PUSH_NEED_BYTES(ndr, c_len*2 + 2);
		ret = convert_string(CH_UNIX, CH_UCS2, 
				     s, s_len+1,
				     ndr->data+ndr->offset, c_len*2 + 2);
		if (ret == -1) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr->offset += c_len*2 + 2;
		break;

	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_push_uint32(ndr, c_len));
		NDR_CHECK(ndr_push_uint32(ndr, 0));
		NDR_CHECK(ndr_push_uint32(ndr, c_len));
		NDR_PUSH_NEED_BYTES(ndr, c_len*2);
		ret = convert_string(CH_UNIX, CH_UCS2, 
				     s, s_len,
				     ndr->data+ndr->offset, c_len*2);
		if (ret == -1) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr->offset += c_len*2;
		break;

	case LIBNDR_FLAG_STR_SIZE4:
		NDR_CHECK(ndr_push_uint32(ndr, c_len + 1));
		NDR_PUSH_NEED_BYTES(ndr, c_len*2 + 2);
		ret = convert_string(CH_UNIX, CH_UCS2, 
				     s, s_len + 1,
				     ndr->data+ndr->offset, c_len*2 + 2);
		if (ret == -1) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr->offset += c_len*2 + 2;
		break;

	case LIBNDR_FLAG_STR_NULLTERM:
		NDR_PUSH_NEED_BYTES(ndr, c_len*2 + 2);
		ret = convert_string(CH_UNIX, CH_UCS2, 
				     s, s_len+1,
				     ndr->data+ndr->offset, c_len*2 + 2);
		if (ret == -1) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr->offset += c_len*2 + 2;
		break;
		
	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
		NDR_CHECK(ndr_push_uint32(ndr, c_len+1));
		NDR_CHECK(ndr_push_uint32(ndr, 0));
		NDR_CHECK(ndr_push_uint32(ndr, c_len+1));
		NDR_PUSH_NEED_BYTES(ndr, c_len + 1);
		ret = convert_string(CH_UNIX, CH_DOS, 
				     s, s_len + 1,
				     ndr->data+ndr->offset, c_len + 1);
		if (ret == -1) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr->offset += c_len + 1;
		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_LEN4:
		NDR_CHECK(ndr_push_uint32(ndr, 0));
		NDR_CHECK(ndr_push_uint32(ndr, c_len+1));
		NDR_PUSH_NEED_BYTES(ndr, c_len + 1);
		ret = convert_string(CH_UNIX, CH_DOS, 
				     s, s_len + 1,
				     ndr->data+ndr->offset, c_len + 1);
		if (ret == -1) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr->offset += c_len + 1;
		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_SIZE2:
		NDR_CHECK(ndr_push_uint16(ndr, c_len+1));
		NDR_PUSH_NEED_BYTES(ndr, c_len + 1);
		ret = convert_string(CH_UNIX, CH_DOS, 
				     s, s_len + 1,
				     ndr->data+ndr->offset, c_len + 1);
		if (ret == -1) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr->offset += c_len + 1;
		break;

	default:
		return ndr_push_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	return NT_STATUS_OK;
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

void ndr_print_string(struct ndr_print *ndr, const char *name, const char *s)
{
	if (s) {
		ndr->print(ndr, "%-25s: '%s'", name, s);
	} else {
		ndr->print(ndr, "%-25s: NULL", name);
	}
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

const char *GUID_string(TALLOC_CTX *mem_ctx, const struct GUID *guid)
{
	return talloc_asprintf(mem_ctx, 
			       "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			       IVAL(guid->info, 0), SVAL(guid->info, 4), 
			       SVAL(guid->info, 6),
			       guid->info[8], guid->info[9],
			       guid->info[10], guid->info[11], 
			       guid->info[12], guid->info[13], 
			       guid->info[14], guid->info[15]);
}

void ndr_print_GUID(struct ndr_print *ndr, const char *name, const struct GUID *guid)
{
	ndr->print(ndr, "%-25s: %s", GUID_string(ndr->mem_ctx, guid));
}

void ndr_print_DATA_BLOB(struct ndr_print *ndr, const char *name, DATA_BLOB r)
{
	ndr->print(ndr, "%-25s: DATA_BLOB length=%u", name, r.length);
}


/*
  push a DATA_BLOB onto the wire. 
*/
NTSTATUS ndr_push_DATA_BLOB(struct ndr_push *ndr, DATA_BLOB blob)
{
	if (ndr->flags & LIBNDR_ALIGN_FLAGS) {
		if (ndr->flags & LIBNDR_FLAG_ALIGN2) {
			blob.length = NDR_ALIGN(ndr, 2);
		} else if (ndr->flags & LIBNDR_FLAG_ALIGN4) {
			blob.length = NDR_ALIGN(ndr, 4);
		} else if (ndr->flags & LIBNDR_FLAG_ALIGN8) {
			blob.length = NDR_ALIGN(ndr, 8);
		}
		NDR_PUSH_ALLOC_SIZE(ndr, blob.data, blob.length);
		data_blob_clear(&blob);
	} else if (!(ndr->flags & LIBNDR_FLAG_REMAINING)) {
		NDR_CHECK(ndr_push_uint32(ndr, blob.length));
	}
	NDR_CHECK(ndr_push_bytes(ndr, blob.data, blob.length));
	return NT_STATUS_OK;
}

/*
  pull a DATA_BLOB from the wire. 
*/
NTSTATUS ndr_pull_DATA_BLOB(struct ndr_pull *ndr, DATA_BLOB *blob)
{
	uint32 length;

	if (ndr->flags & LIBNDR_ALIGN_FLAGS) {
		if (ndr->flags & LIBNDR_FLAG_ALIGN2) {
			length = NDR_ALIGN(ndr, 2);
		} else if (ndr->flags & LIBNDR_FLAG_ALIGN4) {
			length = NDR_ALIGN(ndr, 4);
		} else if (ndr->flags & LIBNDR_FLAG_ALIGN8) {
			length = NDR_ALIGN(ndr, 8);
		}
		if (ndr->data_size - ndr->offset < length) {
			length = ndr->data_size - ndr->offset;
		}
	} else if (ndr->flags & LIBNDR_FLAG_REMAINING) {
		length = ndr->data_size - ndr->offset;
	} else {
		NDR_CHECK(ndr_pull_uint32(ndr, &length));
	}
	NDR_PULL_NEED_BYTES(ndr, length);
	*blob = data_blob_talloc(ndr->mem_ctx, ndr->data+ndr->offset, length);
	ndr->offset += length;
	return NT_STATUS_OK;
}


void ndr_print_policy_handle(struct ndr_print *ndr, const char *name, struct policy_handle *r)
{
	ndr->print(ndr, "%-25s: policy_handle %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
		   name, 
		   r->data[0], r->data[1], r->data[2], r->data[3], r->data[4], 
		   r->data[5], r->data[6], r->data[7], r->data[8], r->data[9], 
		   r->data[10], r->data[11], r->data[12], r->data[13], r->data[14], 
		   r->data[15], r->data[16], r->data[17], r->data[18], r->data[19]);
}
