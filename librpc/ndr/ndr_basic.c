/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling basic types

   Copyright (C) Andrew Tridgell 2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "librpc/ndr/libndr.h"
#include "lib/util/util_net.h"
#include "lib/util/debug.h"
#include "lib/util/util.h"
#include "lib/util/bytearray.h"

#define NDR_PULL_U16(ndr, ofs) \
	(NDR_BE(ndr) ? PULL_BE_U16(ndr->data,ofs) : PULL_LE_U16(ndr->data,ofs))

#define NDR_PULL_U32(ndr, ofs) \
	(NDR_BE(ndr) ? PULL_BE_U32(ndr->data,ofs) : PULL_LE_U32(ndr->data,ofs))

#define NDR_PULL_I32(ndr, ofs) \
	(int32_t)(NDR_BE(ndr) ? PULL_BE_U32(ndr->data,ofs) : PULL_LE_U32(ndr->data,ofs))

#define NDR_PULL_I64(ndr, ofs) \
	(NDR_BE(ndr) ? PULL_BE_I64((ndr)->data, ofs) : PULL_LE_I64((ndr)->data, ofs))

#define NDR_PUSH_U16(ndr, ofs, v) \
	do { \
		if (NDR_BE(ndr)) { \
			PUSH_BE_U16(ndr->data, ofs, v); \
		} else { \
			PUSH_LE_U16(ndr->data, ofs, v); \
		} \
	} while (0)

#define NDR_PUSH_U32(ndr, ofs, v) \
	do { \
		if (NDR_BE(ndr)) { \
			PUSH_BE_U32(ndr->data, ofs, v); \
		} else { \
			PUSH_LE_U32(ndr->data, ofs, v); \
		} \
	} while (0)

#define NDR_PUSH_I32(ndr, ofs, v) \
	do { \
		if (NDR_BE(ndr)) { \
			PUSH_BE_U32(ndr->data, ofs, v); \
		} else { \
			PUSH_LE_U32(ndr->data, ofs, v); \
		} \
	} while (0)

#define NDR_PUSH_I64(ndr, ofs, v) \
	do { \
		if (NDR_BE(ndr)) { \
			PUSH_BE_I64((ndr)->data, ofs, v);	\
		} else { \
			PUSH_LE_I64((ndr)->data, ofs, v);	\
		} \
	} while (0)

static void ndr_dump_data(struct ndr_print *ndr, const uint8_t *buf, int len);

/*
  check for data leaks from the server by looking for non-zero pad bytes
  these could also indicate that real structure elements have been
  mistaken for padding in the IDL
*/
_PUBLIC_ void ndr_check_padding(struct ndr_pull *ndr, size_t n)
{
	size_t ofs2 = (ndr->offset + (n-1)) & ~(n-1);
	size_t i;
	for (i=ndr->offset;i<ofs2;i++) {
		if (ndr->data[i] != 0) {
			break;
		}
	}
	if (i<ofs2) {
		DEBUG(0,("WARNING: Non-zero padding to %zu: ", n));
		for (i=ndr->offset;i<ofs2;i++) {
			DEBUG(0,("%02x ", ndr->data[i]));
		}
		DEBUG(0,("\n"));
	}

}

/*
  parse a int8_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_int8(struct ndr_pull *ndr, ndr_flags_type ndr_flags, int8_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_NEED_BYTES(ndr, 1);
	*v = (int8_t)PULL_BE_U8(ndr->data, ndr->offset);
	ndr->offset += 1;
	return NDR_ERR_SUCCESS;
}

/*
  parse a uint8_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_uint8(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint8_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_NEED_BYTES(ndr, 1);
	*v = PULL_BE_U8(ndr->data, ndr->offset);
	ndr->offset += 1;
	return NDR_ERR_SUCCESS;
}

/*
  parse a int16_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_int16(struct ndr_pull *ndr, ndr_flags_type ndr_flags, int16_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, 2);
	NDR_PULL_NEED_BYTES(ndr, 2);
	*v = (uint16_t)NDR_PULL_U16(ndr, ndr->offset);
	ndr->offset += 2;
	return NDR_ERR_SUCCESS;
}

/*
  parse a uint16_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_uint16(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint16_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, 2);
	NDR_PULL_NEED_BYTES(ndr, 2);
	*v = NDR_PULL_U16(ndr, ndr->offset);
	ndr->offset += 2;
	return NDR_ERR_SUCCESS;
}

/*
  parse a uint1632_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_uint1632(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint16_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (unlikely(ndr->flags & LIBNDR_FLAG_NDR64)) {
		uint32_t v32 = 0;
		enum ndr_err_code err = ndr_pull_uint32(ndr, ndr_flags, &v32);
		*v = v32;
		if (unlikely(v32 != *v)) {
			DEBUG(0,(__location__ ": non-zero upper 16 bits 0x%08"PRIx32"\n", v32));
			return NDR_ERR_NDR64;
		}
		return err;
	}
	return ndr_pull_uint16(ndr, ndr_flags, v);
}

/*
  parse a int32_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_int32(struct ndr_pull *ndr, ndr_flags_type ndr_flags, int32_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, 4);
	NDR_PULL_NEED_BYTES(ndr, 4);
	*v = NDR_PULL_I32(ndr, ndr->offset);
	ndr->offset += 4;
	return NDR_ERR_SUCCESS;
}

/*
  parse a uint32_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_uint32(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint32_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, 4);
	NDR_PULL_NEED_BYTES(ndr, 4);
	*v = NDR_PULL_U32(ndr, ndr->offset);
	ndr->offset += 4;
	return NDR_ERR_SUCCESS;
}

/*
  parse a arch dependent uint32/uint64
*/
_PUBLIC_ enum ndr_err_code ndr_pull_uint3264(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint32_t *v)
{
	uint64_t v64 = 0;
	enum ndr_err_code err;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (likely(!(ndr->flags & LIBNDR_FLAG_NDR64))) {
		return ndr_pull_uint32(ndr, ndr_flags, v);
	}
	err = ndr_pull_hyper(ndr, ndr_flags, &v64);
	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		return err;
	}
	*v = (uint32_t)v64;
	if (unlikely(v64 != *v)) {
		DEBUG(0,(__location__ ": non-zero upper 32 bits 0x%016"PRIx64"\n",
			 v64));
		return ndr_pull_error(ndr, NDR_ERR_NDR64, __location__ ": non-zero upper 32 bits 0x%016"PRIx64"\n",
			 v64);
	}
	return err;
}

/*
  parse a double
*/
_PUBLIC_ enum ndr_err_code ndr_pull_double(struct ndr_pull *ndr, ndr_flags_type ndr_flags, double *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, 8);
	NDR_PULL_NEED_BYTES(ndr, 8);
	memcpy(v, ndr->data+ndr->offset, 8);
	ndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

/*
  parse a pointer referent identifier stored in 2 bytes
*/
_PUBLIC_ enum ndr_err_code ndr_pull_relative_ptr_short(struct ndr_pull *ndr, uint16_t *v)
{
	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, v));
	if (*v != 0) {
		ndr->ptr_count++;
	}
	*(v) -= ndr->relative_rap_convert;
	return NDR_ERR_SUCCESS;
}

/*
  parse a pointer referent identifier
*/
_PUBLIC_ enum ndr_err_code ndr_pull_generic_ptr(struct ndr_pull *ndr, uint32_t *v)
{
	NDR_CHECK(ndr_pull_uint3264(ndr, NDR_SCALARS, v));
	if (*v != 0) {
		ndr->ptr_count++;
	}
	return NDR_ERR_SUCCESS;
}

/*
  parse a ref pointer referent identifier
*/
_PUBLIC_ enum ndr_err_code ndr_pull_ref_ptr(struct ndr_pull *ndr, uint32_t *v)
{
	NDR_CHECK(ndr_pull_uint3264(ndr, NDR_SCALARS, v));
	/* ref pointers always point to data */
	*v = 1;
	return NDR_ERR_SUCCESS;
}

/*
  parse a udlong
*/
_PUBLIC_ enum ndr_err_code ndr_pull_udlong(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint64_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, 4);
	NDR_PULL_NEED_BYTES(ndr, 8);
	*v = NDR_PULL_U32(ndr, ndr->offset);
	*v |= (uint64_t)(NDR_PULL_U32(ndr, ndr->offset+4)) << 32;
	ndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

/*
  parse a udlongr
*/
_PUBLIC_ enum ndr_err_code ndr_pull_udlongr(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint64_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, 4);
	NDR_PULL_NEED_BYTES(ndr, 8);
	*v = ((uint64_t)NDR_PULL_U32(ndr, ndr->offset)) << 32;
	*v |= NDR_PULL_U32(ndr, ndr->offset+4);
	ndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

/*
  parse a dlong
*/
_PUBLIC_ enum ndr_err_code ndr_pull_dlong(struct ndr_pull *ndr, ndr_flags_type ndr_flags, int64_t *v)
{
	return ndr_pull_udlong(ndr, ndr_flags, (uint64_t *)v);
}

/*
  parse a hyper
*/
_PUBLIC_ enum ndr_err_code ndr_pull_hyper(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint64_t *v)
{
	NDR_PULL_ALIGN(ndr, 8);
	if (NDR_BE(ndr)) {
		return ndr_pull_udlongr(ndr, ndr_flags, v);
	}
	return ndr_pull_udlong(ndr, ndr_flags, v);
}

/*
  parse an int64
*/
_PUBLIC_ enum ndr_err_code ndr_pull_int64(struct ndr_pull *ndr, ndr_flags_type ndr_flags, int64_t *v)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, 8);
	NDR_PULL_NEED_BYTES(ndr, 8);
	*v = NDR_PULL_I64(ndr, ndr->offset);
	ndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

/*
  parse a pointer
*/
_PUBLIC_ enum ndr_err_code ndr_pull_pointer(struct ndr_pull *ndr, ndr_flags_type ndr_flags, void* *v)
{
	uintptr_t h;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PULL_ALIGN(ndr, sizeof(h));
	NDR_PULL_NEED_BYTES(ndr, sizeof(h));
	memcpy(&h, ndr->data+ndr->offset, sizeof(h));
	ndr->offset += sizeof(h);
	*v = (void *)h;
	return NDR_ERR_SUCCESS;
}

/*
  pull a NTSTATUS
*/
_PUBLIC_ enum ndr_err_code ndr_pull_NTSTATUS(struct ndr_pull *ndr, ndr_flags_type ndr_flags, NTSTATUS *status)
{
	uint32_t v;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &v));
	*status = NT_STATUS(v);
	return NDR_ERR_SUCCESS;
}

/*
  push a NTSTATUS
*/
_PUBLIC_ enum ndr_err_code ndr_push_NTSTATUS(struct ndr_push *ndr, ndr_flags_type ndr_flags, NTSTATUS status)
{
	return ndr_push_uint32(ndr, ndr_flags, NT_STATUS_V(status));
}

_PUBLIC_ void ndr_print_NTSTATUS(struct ndr_print *ndr, const char *name, NTSTATUS r)
{
	ndr->print(ndr, "%-25s: %s", name, nt_errstr(r));
}

/*
  pull a WERROR
*/
_PUBLIC_ enum ndr_err_code ndr_pull_WERROR(struct ndr_pull *ndr, ndr_flags_type ndr_flags, WERROR *status)
{
	uint32_t v;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &v));
	*status = W_ERROR(v);
	return NDR_ERR_SUCCESS;
}

/*
  pull a HRESULT
*/
_PUBLIC_ enum ndr_err_code ndr_pull_HRESULT(struct ndr_pull *ndr, ndr_flags_type ndr_flags, HRESULT *status)
{
	uint32_t v;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &v));
	*status = HRES_ERROR(v);
	return NDR_ERR_SUCCESS;
}

/*
  parse a uint8_t enum
*/
_PUBLIC_ enum ndr_err_code ndr_pull_enum_uint8(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint8_t *v)
{
	return ndr_pull_uint8(ndr, ndr_flags, v);
}

/*
  parse a uint16_t enum
*/
_PUBLIC_ enum ndr_err_code ndr_pull_enum_uint16(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint16_t *v)
{
	return ndr_pull_uint16(ndr, ndr_flags, v);
}

/*
  parse a uint1632_t enum (uint32_t on NDR64)
*/
_PUBLIC_ enum ndr_err_code ndr_pull_enum_uint1632(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint16_t *v)
{
	if (unlikely(ndr->flags & LIBNDR_FLAG_NDR64)) {
		uint32_t v32;
		NDR_CHECK(ndr_pull_uint32(ndr, ndr_flags, &v32));
		*v = v32;
		if (v32 != *v) {
			DEBUG(0,(__location__ ": non-zero upper 16 bits 0x%08"PRIx32"\n", v32));
			return NDR_ERR_NDR64;
		}
		return NDR_ERR_SUCCESS;
	}
	return ndr_pull_uint16(ndr, ndr_flags, v);
}

/*
  parse a uint32_t enum
*/
_PUBLIC_ enum ndr_err_code ndr_pull_enum_uint32(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint32_t *v)
{
	return ndr_pull_uint32(ndr, ndr_flags, v);
}

/*
  push a uint8_t enum
*/
_PUBLIC_ enum ndr_err_code ndr_push_enum_uint8(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint8_t v)
{
	return ndr_push_uint8(ndr, ndr_flags, v);
}

/*
  push a uint16_t enum
*/
_PUBLIC_ enum ndr_err_code ndr_push_enum_uint16(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint16_t v)
{
	return ndr_push_uint16(ndr, ndr_flags, v);
}

/*
  push a uint32_t enum
*/
_PUBLIC_ enum ndr_err_code ndr_push_enum_uint32(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint32_t v)
{
	return ndr_push_uint32(ndr, ndr_flags, v);
}

/*
  push a uint1632_t enum
*/
_PUBLIC_ enum ndr_err_code ndr_push_enum_uint1632(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint16_t v)
{
	if (unlikely(ndr->flags & LIBNDR_FLAG_NDR64)) {
		return ndr_push_uint32(ndr, ndr_flags, v);
	}
	return ndr_push_uint16(ndr, ndr_flags, v);
}

/*
  push a WERROR
*/
_PUBLIC_ enum ndr_err_code ndr_push_WERROR(struct ndr_push *ndr, ndr_flags_type ndr_flags, WERROR status)
{
	return ndr_push_uint32(ndr, NDR_SCALARS, W_ERROR_V(status));
}

_PUBLIC_ void ndr_print_WERROR(struct ndr_print *ndr, const char *name, WERROR r)
{
	ndr->print(ndr, "%-25s: %s", name, win_errstr(r));
}

/*
  push a HRESULT
*/
_PUBLIC_ enum ndr_err_code ndr_push_HRESULT(struct ndr_push *ndr, ndr_flags_type ndr_flags, HRESULT status)
{
	return ndr_push_uint32(ndr, NDR_SCALARS, HRES_ERROR_V(status));
}

_PUBLIC_ void ndr_print_HRESULT(struct ndr_print *ndr, const char *name, HRESULT r)
{
	ndr->print(ndr, "%-25s: %s", name, hresult_errstr(r));
}


/*
  parse a set of bytes
*/
_PUBLIC_ enum ndr_err_code ndr_pull_bytes(struct ndr_pull *ndr, uint8_t *data, uint32_t n)
{
	NDR_PULL_NEED_BYTES(ndr, n);
	memcpy(data, ndr->data + ndr->offset, n);
	ndr->offset += n;
	return NDR_ERR_SUCCESS;
}

/*
  pull an array of uint8
*/
_PUBLIC_ enum ndr_err_code ndr_pull_array_uint8(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uint8_t *data, uint32_t n)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}
	return ndr_pull_bytes(ndr, data, n);
}

/*
  push a int8_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_int8(struct ndr_push *ndr, ndr_flags_type ndr_flags, int8_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_NEED_BYTES(ndr, 1);
	PUSH_BE_U8(ndr->data, ndr->offset, (uint8_t)v);
	ndr->offset += 1;
	return NDR_ERR_SUCCESS;
}

/*
  push a uint8_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_uint8(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint8_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_NEED_BYTES(ndr, 1);
	PUSH_BE_U8(ndr->data, ndr->offset, v);
	ndr->offset += 1;
	return NDR_ERR_SUCCESS;
}

/*
  push a int16_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_int16(struct ndr_push *ndr, ndr_flags_type ndr_flags, int16_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, 2);
	NDR_PUSH_NEED_BYTES(ndr, 2);
	NDR_PUSH_U16(ndr, ndr->offset, (uint16_t)v);
	ndr->offset += 2;
	return NDR_ERR_SUCCESS;
}

/*
  push a uint16_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_uint16(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint16_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, 2);
	NDR_PUSH_NEED_BYTES(ndr, 2);
	NDR_PUSH_U16(ndr, ndr->offset, v);
	ndr->offset += 2;
	return NDR_ERR_SUCCESS;
}

/*
  push a uint1632
*/
_PUBLIC_ enum ndr_err_code ndr_push_uint1632(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint16_t v)
{
	if (unlikely(ndr->flags & LIBNDR_FLAG_NDR64)) {
		return ndr_push_uint32(ndr, ndr_flags, v);
	}
	return ndr_push_uint16(ndr, ndr_flags, v);
}

/*
  push a int32_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_int32(struct ndr_push *ndr, ndr_flags_type ndr_flags, int32_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, 4);
	NDR_PUSH_NEED_BYTES(ndr, 4);
	NDR_PUSH_I32(ndr, ndr->offset, v);
	ndr->offset += 4;
	return NDR_ERR_SUCCESS;
}

/*
  push a uint32_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_uint32(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint32_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, 4);
	NDR_PUSH_NEED_BYTES(ndr, 4);
	NDR_PUSH_U32(ndr, ndr->offset, v);
	ndr->offset += 4;
	return NDR_ERR_SUCCESS;
}

/*
  push a uint3264
*/
_PUBLIC_ enum ndr_err_code ndr_push_uint3264(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint32_t v)
{
	if (unlikely(ndr->flags & LIBNDR_FLAG_NDR64)) {
		return ndr_push_hyper(ndr, ndr_flags, v);
	}
	return ndr_push_uint32(ndr, ndr_flags, v);
}

/*
  push a udlong
*/
_PUBLIC_ enum ndr_err_code ndr_push_udlong(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint64_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, 4);
	NDR_PUSH_NEED_BYTES(ndr, 8);
	NDR_PUSH_U32(ndr, ndr->offset, (v & 0xFFFFFFFF));
	NDR_PUSH_U32(ndr, ndr->offset+4, (v>>32));
	ndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

/*
  push a udlongr
*/
_PUBLIC_ enum ndr_err_code ndr_push_udlongr(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint64_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, 4);
	NDR_PUSH_NEED_BYTES(ndr, 8);
	NDR_PUSH_U32(ndr, ndr->offset, (v>>32));
	NDR_PUSH_U32(ndr, ndr->offset+4, (v & 0xFFFFFFFF));
	ndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

/*
  push a dlong
*/
_PUBLIC_ enum ndr_err_code ndr_push_dlong(struct ndr_push *ndr, ndr_flags_type ndr_flags, int64_t v)
{
	return ndr_push_udlong(ndr, NDR_SCALARS, (uint64_t)v);
}

/*
  push a hyper
*/
_PUBLIC_ enum ndr_err_code ndr_push_hyper(struct ndr_push *ndr, ndr_flags_type ndr_flags, uint64_t v)
{
	NDR_PUSH_ALIGN(ndr, 8);
	if (NDR_BE(ndr)) {
		return ndr_push_udlongr(ndr, NDR_SCALARS, v);
	}
	return ndr_push_udlong(ndr, NDR_SCALARS, v);
}

/*
  push an int64
*/
_PUBLIC_ enum ndr_err_code ndr_push_int64(struct ndr_push *ndr, ndr_flags_type ndr_flags, int64_t v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, 8);
	NDR_PUSH_NEED_BYTES(ndr, 8);
	NDR_PUSH_I64(ndr, ndr->offset, v);
	ndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

/*
  push a double
*/
_PUBLIC_ enum ndr_err_code ndr_push_double(struct ndr_push *ndr, ndr_flags_type ndr_flags, double v)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, 8);
	NDR_PUSH_NEED_BYTES(ndr, 8);
	memcpy(ndr->data+ndr->offset, &v, 8);
	ndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

/*
  push a pointer
*/
_PUBLIC_ enum ndr_err_code ndr_push_pointer(struct ndr_push *ndr, ndr_flags_type ndr_flags, void* v)
{
	uintptr_t h = (intptr_t)v;
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_PUSH_ALIGN(ndr, sizeof(h));
	NDR_PUSH_NEED_BYTES(ndr, sizeof(h));
	memcpy(ndr->data+ndr->offset, &h, sizeof(h));
	ndr->offset += sizeof(h);
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_align(struct ndr_push *ndr, size_t size)
{
	/* this is a nasty hack to make pidl work with NDR64 */
	if (size == 5) {
		if (ndr->flags & LIBNDR_FLAG_NDR64) {
			size = 8;
		} else {
			size = 4;
		}
	} else if (size == 3) {
		if (ndr->flags & LIBNDR_FLAG_NDR64) {
			size = 4;
		} else {
			size = 2;
		}
	}
	NDR_PUSH_ALIGN(ndr, size);
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_align(struct ndr_pull *ndr, size_t size)
{
	/* this is a nasty hack to make pidl work with NDR64 */
	if (size == 5) {
		if (ndr->flags & LIBNDR_FLAG_NDR64) {
			size = 8;
		} else {
			size = 4;
		}
	} else if (size == 3) {
		if (ndr->flags & LIBNDR_FLAG_NDR64) {
			size = 4;
		} else {
			size = 2;
		}
	}
	NDR_PULL_ALIGN(ndr, size);
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_union_align(struct ndr_push *ndr, size_t size)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (ndr->flags & LIBNDR_FLAG_NDR64) {
		return ndr_push_align(ndr, size);
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_union_align(struct ndr_pull *ndr, size_t size)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (ndr->flags & LIBNDR_FLAG_NDR64) {
		return ndr_pull_align(ndr, size);
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_trailer_align(struct ndr_push *ndr, size_t size)
{
	/* MS-RPCE section 2.2.5.3.4.1 */
	if (ndr->flags & LIBNDR_FLAG_NDR64) {
		return ndr_push_align(ndr, size);
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_trailer_align(struct ndr_pull *ndr, size_t size)
{
	/* MS-RPCE section 2.2.5.3.4.1 */
	if (ndr->flags & LIBNDR_FLAG_NDR64) {
		return ndr_pull_align(ndr, size);
	}
	return NDR_ERR_SUCCESS;
}

/*
  push some bytes
*/
_PUBLIC_ enum ndr_err_code ndr_push_bytes(struct ndr_push *ndr, const uint8_t *data, uint32_t n)
{
	if (unlikely(n == 0)) {
		return NDR_ERR_SUCCESS;
	}
	if (unlikely(data == NULL)) {
		return NDR_ERR_INVALID_POINTER;
	}
	NDR_PUSH_NEED_BYTES(ndr, n);
	memcpy(ndr->data + ndr->offset, data, n);
	ndr->offset += n;
	return NDR_ERR_SUCCESS;
}

/*
  push some zero bytes
*/
_PUBLIC_ enum ndr_err_code ndr_push_zero(struct ndr_push *ndr, uint32_t n)
{
	NDR_PUSH_NEED_BYTES(ndr, n);
	memset(ndr->data + ndr->offset, 0, n);
	ndr->offset += n;
	return NDR_ERR_SUCCESS;
}

/*
  push an array of uint8
*/
_PUBLIC_ enum ndr_err_code ndr_push_array_uint8(struct ndr_push *ndr, ndr_flags_type ndr_flags, const uint8_t *data, uint32_t n)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}
	return ndr_push_bytes(ndr, data, n);
}

/*
  push a unique non-zero value if a pointer is non-NULL, otherwise 0
*/
_PUBLIC_ enum ndr_err_code ndr_push_unique_ptr(struct ndr_push *ndr, const void *p)
{
	uint32_t ptr = 0;
	if (p) {
		ptr = ndr->ptr_count * 4;
		ptr |= 0x00020000;
		ndr->ptr_count++;
	}
	return ndr_push_uint3264(ndr, NDR_SCALARS, ptr);
}

/*
  push a 'simple' full non-zero value if a pointer is non-NULL, otherwise 0
*/
_PUBLIC_ enum ndr_err_code ndr_push_full_ptr(struct ndr_push *ndr, const void *p)
{
	enum ndr_err_code ret = NDR_ERR_SUCCESS;
	uint32_t ptr = 0;
	if (p) {
		/* Check if the pointer already exists and has an id */
		ret = ndr_token_peek(&ndr->full_ptr_list, p, &ptr);
		if (ret == NDR_ERR_TOKEN) {
			ndr->ptr_count++;
			ptr = ndr->ptr_count;
			ret = ndr_token_store(ndr, &ndr->full_ptr_list, p, ptr);
			if (ret != NDR_ERR_SUCCESS) {
				return ret;
			}
		} else if (ret != NDR_ERR_SUCCESS) {
			return ret;
		}
	}
	return ndr_push_uint3264(ndr, NDR_SCALARS, ptr);
}

/*
  push always a 0, if a pointer is NULL it's a fatal error
*/
_PUBLIC_ enum ndr_err_code ndr_push_ref_ptr(struct ndr_push *ndr)
{
	return ndr_push_uint3264(ndr, NDR_SCALARS, 0xAEF1AEF1);
}


/*
  push a NTTIME
*/
_PUBLIC_ enum ndr_err_code ndr_push_NTTIME(struct ndr_push *ndr, ndr_flags_type ndr_flags, NTTIME t)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_push_udlong(ndr, ndr_flags, t));
	return NDR_ERR_SUCCESS;
}

/*
  pull a NTTIME
*/
_PUBLIC_ enum ndr_err_code ndr_pull_NTTIME(struct ndr_pull *ndr, ndr_flags_type ndr_flags, NTTIME *t)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_pull_udlong(ndr, ndr_flags, t));
	return NDR_ERR_SUCCESS;
}

/*
  push a NTTIME_1sec
*/
_PUBLIC_ enum ndr_err_code ndr_push_NTTIME_1sec(struct ndr_push *ndr, ndr_flags_type ndr_flags, NTTIME t)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	t /= 10000000;
	NDR_CHECK(ndr_push_hyper(ndr, ndr_flags, t));
	return NDR_ERR_SUCCESS;
}

/*
  pull a NTTIME_1sec
*/
_PUBLIC_ enum ndr_err_code ndr_pull_NTTIME_1sec(struct ndr_pull *ndr, ndr_flags_type ndr_flags, NTTIME *t)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_pull_hyper(ndr, ndr_flags, t));
	(*t) *= 10000000;
	return NDR_ERR_SUCCESS;
}

/*
  pull a NTTIME_hyper
*/
_PUBLIC_ enum ndr_err_code ndr_pull_NTTIME_hyper(struct ndr_pull *ndr, ndr_flags_type ndr_flags, NTTIME *t)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_pull_hyper(ndr, ndr_flags, t));
	return NDR_ERR_SUCCESS;
}

/*
  push a NTTIME_hyper
*/
_PUBLIC_ enum ndr_err_code ndr_push_NTTIME_hyper(struct ndr_push *ndr, ndr_flags_type ndr_flags, NTTIME t)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_push_hyper(ndr, ndr_flags, t));
	return NDR_ERR_SUCCESS;
}

/*
  push a time_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_time_t(struct ndr_push *ndr, ndr_flags_type ndr_flags, time_t t)
{
	return ndr_push_uint32(ndr, ndr_flags, t);
}

/*
  pull a time_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_time_t(struct ndr_pull *ndr, ndr_flags_type ndr_flags, time_t *t)
{
	uint32_t tt;
	NDR_CHECK(ndr_pull_uint32(ndr, ndr_flags, &tt));
	*t = tt;
	return NDR_ERR_SUCCESS;
}


/*
  push a uid_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_uid_t(struct ndr_push *ndr, ndr_flags_type ndr_flags, uid_t u)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	return ndr_push_hyper(ndr, NDR_SCALARS, (uint64_t)u);
}

/*
  pull a uid_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_uid_t(struct ndr_pull *ndr, ndr_flags_type ndr_flags, uid_t *u)
{
	uint64_t uu = 0;
	NDR_CHECK(ndr_pull_hyper(ndr, ndr_flags, &uu));
	*u = (uid_t)uu;
	if (unlikely(uu != *u)) {
		DEBUG(0,(__location__ ": uid_t pull doesn't fit 0x%016"PRIx64"\n",
			 uu));
		return NDR_ERR_NDR64;
	}
	return NDR_ERR_SUCCESS;
}


/*
  push a gid_t
*/
_PUBLIC_ enum ndr_err_code ndr_push_gid_t(struct ndr_push *ndr, ndr_flags_type ndr_flags, gid_t g)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	return ndr_push_hyper(ndr, NDR_SCALARS, (uint64_t)g);
}

/*
  pull a gid_t
*/
_PUBLIC_ enum ndr_err_code ndr_pull_gid_t(struct ndr_pull *ndr, ndr_flags_type ndr_flags, gid_t *g)
{
	uint64_t gg = 0;
	NDR_CHECK(ndr_pull_hyper(ndr, ndr_flags, &gg));
	*g = (gid_t)gg;
	if (unlikely(gg != *g)) {
		DEBUG(0,(__location__ ": gid_t pull doesn't fit 0x%016"PRIx64"\n",
			 gg));
		return NDR_ERR_NDR64;
	}
	return NDR_ERR_SUCCESS;
}


/*
  pull a ipv4address
*/
_PUBLIC_ enum ndr_err_code ndr_pull_ipv4address(struct ndr_pull *ndr, ndr_flags_type ndr_flags, const char **address)
{
	uint32_t addr;
	struct in_addr in;
	NDR_CHECK(ndr_pull_uint32(ndr, ndr_flags, &addr));
	in.s_addr = htonl(addr);
	*address = talloc_strdup(ndr->current_mem_ctx, inet_ntoa(in));
	NDR_ERR_HAVE_NO_MEMORY(*address);
	return NDR_ERR_SUCCESS;
}

/*
  push a ipv4address
*/
_PUBLIC_ enum ndr_err_code ndr_push_ipv4address(struct ndr_push *ndr, ndr_flags_type ndr_flags, const char *address)
{
	uint32_t addr;
	if (!is_ipaddress_v4(address)) {
		return ndr_push_error(ndr, NDR_ERR_IPV4ADDRESS,
				      "Invalid IPv4 address: '%s'",
				      address);
	}
	addr = inet_addr(address);
	NDR_CHECK(ndr_push_uint32(ndr, ndr_flags, htonl(addr)));
	return NDR_ERR_SUCCESS;
}

/*
  print a ipv4address
*/
_PUBLIC_ void ndr_print_ipv4address(struct ndr_print *ndr, const char *name,
			   const char *address)
{
	ndr->print(ndr, "%-25s: %s", name, address);
}

/*
  pull a ipv6address
*/
#define IPV6_BYTES 16
#define IPV6_ADDR_STR_LEN 39
_PUBLIC_ enum ndr_err_code ndr_pull_ipv6address(struct ndr_pull *ndr, ndr_flags_type ndr_flags, const char **address)
{
	uint8_t addr[IPV6_BYTES];
	char *addr_str = talloc_strdup(ndr->current_mem_ctx, "");
	int i;
	NDR_ERR_HAVE_NO_MEMORY(addr_str);
	NDR_CHECK(ndr_pull_array_uint8(ndr, ndr_flags, addr, IPV6_BYTES));
	for (i = 0; i < IPV6_BYTES; ++i) {
		addr_str = talloc_asprintf_append(addr_str, "%02x", addr[i]);
		NDR_ERR_HAVE_NO_MEMORY(addr_str);
		/* We need a ':' every second byte but the last one */
		if (i%2 == 1 && i != (IPV6_BYTES - 1)) {
			addr_str = talloc_strdup_append(addr_str, ":");
			NDR_ERR_HAVE_NO_MEMORY(addr_str);
		}
	}
	*address = addr_str;
	NDR_ERR_HAVE_NO_MEMORY(*address);
	return NDR_ERR_SUCCESS;
}

/*
  push a ipv6address
*/
_PUBLIC_ enum ndr_err_code ndr_push_ipv6address(struct ndr_push *ndr, ndr_flags_type ndr_flags, const char *address)
{
#ifdef AF_INET6
	uint8_t addr[IPV6_BYTES];
	int ret;

	if (!is_ipaddress(address)) {
		return ndr_push_error(ndr, NDR_ERR_IPV6ADDRESS,
				      "Invalid IPv6 address: '%s'",
				      address);
	}
	ret = inet_pton(AF_INET6, address, addr);
	if (ret <= 0) {
		return NDR_ERR_IPV6ADDRESS;
	}

	NDR_CHECK(ndr_push_array_uint8(ndr, ndr_flags, addr, IPV6_BYTES));

	return NDR_ERR_SUCCESS;
#else
	return NDR_ERR_IPV6ADDRESS;
#endif
}

/*
  print a ipv6address
*/
_PUBLIC_ void ndr_print_ipv6address(struct ndr_print *ndr, const char *name,
			   const char *address)
{
	ndr->print(ndr, "%-25s: %s", name, address);
}
#undef IPV6_BYTES

_PUBLIC_ void ndr_print_struct(struct ndr_print *ndr, const char *name, const char *type)
{
	ndr->print(ndr, "%s: struct %s", name, type);
}

_PUBLIC_ void ndr_print_null(struct ndr_print *ndr)
{
	ndr->print(ndr, "UNEXPECTED NULL POINTER");
}

_PUBLIC_ void ndr_print_enum(struct ndr_print *ndr, const char *name, const char *type,
		    const char *val, uint32_t value)
{
	if (ndr->flags & LIBNDR_PRINT_ARRAY_HEX) {
		ndr->print(ndr, "%-25s: %s (0x%"PRIX32")", name, val?val:"UNKNOWN_ENUM_VALUE", value);
	} else {
		ndr->print(ndr, "%-25s: %s (%"PRIu32")", name, val?val:"UNKNOWN_ENUM_VALUE", value);
	}
}

_PUBLIC_ void ndr_print_bitmap_flag(struct ndr_print *ndr, size_t size, const char *flag_name, uint64_t flag, uint64_t value)
{
	if (flag == 0) {
		return;
	}

	/* this is an attempt to support multi-bit bitmap masks */
	value &= flag;

	while (!(flag & 1)) {
		flag >>= 1;
		value >>= 1;
	}
	if (flag == 1) {
		ndr->print(ndr, "   %"PRIu64": %-25s", value, flag_name);
	} else {
		ndr->print(ndr, "0x%02"PRIx64": %-25s (%"PRIu64")", value, flag_name, value);
	}
}

_PUBLIC_ void ndr_print_int8(struct ndr_print *ndr, const char *name, int8_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: %"PRId8, name, v);
}

_PUBLIC_ void ndr_print_uint8(struct ndr_print *ndr, const char *name, uint8_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: 0x%02"PRIx8" (%"PRIu8")", name, v, v);
}

_PUBLIC_ void ndr_print_int16(struct ndr_print *ndr, const char *name, int16_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: %"PRId16, name, v);
}

_PUBLIC_ void ndr_print_uint16(struct ndr_print *ndr, const char *name, uint16_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: 0x%04"PRIx16" (%"PRIu16")", name, v, v);
}

_PUBLIC_ void ndr_print_int32(struct ndr_print *ndr, const char *name, int32_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: %"PRId32, name, v);
}

_PUBLIC_ void ndr_print_uint32(struct ndr_print *ndr, const char *name, uint32_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: 0x%08"PRIx32" (%"PRIu32")", name, v, v);
}

_PUBLIC_ void ndr_print_int3264(struct ndr_print *ndr, const char *name, int32_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: %"PRId32, name, v);
}

_PUBLIC_ void ndr_print_uint3264(struct ndr_print *ndr, const char *name, uint32_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: 0x%08"PRIx32" (%"PRIu32")", name, v, v);
}

_PUBLIC_ void ndr_print_udlong(struct ndr_print *ndr, const char *name, uint64_t v)
{
	ndr->print(ndr, "%-25s: 0x%016"PRIx64" (%"PRIu64")", name, v, v);
}

_PUBLIC_ void ndr_print_udlongr(struct ndr_print *ndr, const char *name, uint64_t v)
{
	ndr_print_udlong(ndr, name, v);
}

_PUBLIC_ void ndr_print_dlong(struct ndr_print *ndr, const char *name, int64_t v)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	ndr->print(ndr, "%-25s: 0x%016"PRIx64" (%"PRId64")", name, v, v);
}

_PUBLIC_ void ndr_print_double(struct ndr_print *ndr, const char *name, double v)
{
	ndr->print(ndr, "%-25s: %f", name, v);
}

_PUBLIC_ void ndr_print_hyper(struct ndr_print *ndr, const char *name, uint64_t v)
{
	ndr_print_dlong(ndr, name, v);
}

_PUBLIC_ void ndr_print_int64(struct ndr_print *ndr, const char *name, int64_t v)
{
	ndr_print_dlong(ndr, name, v);
}

_PUBLIC_ void ndr_print_pointer(struct ndr_print *ndr, const char *name, void *v)
{
	ndr->print(ndr, "%-25s: %p", name, v);
}

_PUBLIC_ void ndr_print_ptr(struct ndr_print *ndr, const char *name, const void *p)
{
	if (p) {
		ndr->print(ndr, "%-25s: *", name);
	} else {
		ndr->print(ndr, "%-25s: NULL", name);
	}
}

_PUBLIC_ void ndr_print_NTTIME(struct ndr_print *ndr, const char *name, NTTIME t)
{
	ndr->print(ndr, "%-25s: %s", name, nt_time_string(ndr, t));
}

_PUBLIC_ void ndr_print_NTTIME_1sec(struct ndr_print *ndr, const char *name, NTTIME t)
{
	/* this is a standard NTTIME here
	 * as it's already converted in the pull/push code
	 */
	ndr_print_NTTIME(ndr, name, t);
}

_PUBLIC_ void ndr_print_NTTIME_hyper(struct ndr_print *ndr, const char *name, NTTIME t)
{
	ndr_print_NTTIME(ndr, name, t);
}

_PUBLIC_ void ndr_print_time_t(struct ndr_print *ndr, const char *name, time_t t)
{
	if (t == (time_t)-1 || t == 0) {
		ndr->print(ndr, "%-25s: (time_t)%" PRIi64, name, (int64_t)t);
	} else {
		ndr->print(ndr, "%-25s: %s", name, timestring(ndr, t));
	}
}

_PUBLIC_ void ndr_print_uid_t(struct ndr_print *ndr, const char *name, uid_t u)
{
	ndr_print_dlong(ndr, name, u);
}

_PUBLIC_ void ndr_print_gid_t(struct ndr_print *ndr, const char *name, gid_t g)
{
	ndr_print_dlong(ndr, name, g);
}

_PUBLIC_ void ndr_print_union(struct ndr_print *ndr, const char *name, int level, const char *type)
{
	if (ndr->flags & LIBNDR_PRINT_ARRAY_HEX) {
		ndr->print(ndr, "%-25s: union %s(case 0x%X)", name, type, level);
	} else {
		ndr->print(ndr, "%-25s: union %s(case %d)", name, type, level);
	}
}

_PUBLIC_ void ndr_print_bad_level(struct ndr_print *ndr, const char *name, uint16_t level)
{
	ndr->print(ndr, "UNKNOWN LEVEL %"PRIu16, level);
}

_PUBLIC_ void ndr_print_array_uint8(struct ndr_print *ndr, const char *name,
			   const uint8_t *data, uint32_t count)
{
	uint32_t i;
#define _ONELINE_LIMIT 32

	if (data == NULL) {
		ndr->print(ndr, "%s: ARRAY(%"PRIu32") : NULL", name, count);
		return;
	}

	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%s: ARRAY(%"PRIu32"): <REDACTED SECRET VALUES>", name, count);
		return;
	}

	if (count <= _ONELINE_LIMIT && (ndr->flags & LIBNDR_PRINT_ARRAY_HEX)) {
		char s[(_ONELINE_LIMIT + 1) * 2];
		for (i=0;i<count;i++) {
			snprintf(&s[i*2], 3, "%02"PRIx8, data[i]);
		}
		s[i*2] = 0;
		ndr->print(ndr, "%-25s: %s", name, s);
		return;
	}

	ndr->print(ndr, "%s: ARRAY(%"PRIu32")", name, count);
	if (count > _ONELINE_LIMIT && (ndr->flags & LIBNDR_PRINT_ARRAY_HEX)) {
		ndr_dump_data(ndr, data, count);
		return;
	}

	ndr->depth++;
	for (i=0;i<count;i++) {
		char *idx=NULL;
		if (asprintf(&idx, "[%"PRIu32"]", i) != -1) {
			ndr_print_uint8(ndr, idx, data[i]);
			free(idx);
		}
	}
	ndr->depth--;
#undef _ONELINE_LIMIT
}

static void ndr_print_dump_data_cb(const char *buf, void *private_data)
{
	struct ndr_print *ndr = (struct ndr_print *)private_data;

	ndr->print(ndr, "%s", buf);
}

/*
  ndr_print version of dump_data()
 */
static void ndr_dump_data(struct ndr_print *ndr, const uint8_t *buf, int len)
{
	if (NDR_HIDE_SECRET(ndr)) {
		return;
	}
	ndr->no_newline = true;
	dump_data_cb(buf, len, true, ndr_print_dump_data_cb, ndr);
	ndr->no_newline = false;
}


_PUBLIC_ void ndr_print_DATA_BLOB(struct ndr_print *ndr, const char *name, DATA_BLOB r)
{
	ndr->print(ndr, "%-25s: DATA_BLOB length=%zu", name, r.length);
	if (r.length) {
		ndr_dump_data(ndr, r.data, r.length);
	}
}


/*
 * Push a DATA_BLOB onto the wire.
 * 1) When called with LIBNDR_FLAG_ALIGN* alignment flags set, push padding
 *    bytes _only_. The length is determined by the alignment required and the
 *    current ndr offset.
 * 2) When called with the LIBNDR_FLAG_REMAINING flag, push the byte array to
 *    the ndr buffer.
 * 3) Otherwise, push a uint3264 length _and_ a corresponding byte array to the
 *    ndr buffer.
 */
_PUBLIC_ enum ndr_err_code ndr_push_DATA_BLOB(struct ndr_push *ndr, ndr_flags_type ndr_flags, DATA_BLOB blob)
{
	static const uint8_t padding[8] = { 0, };

	if (ndr->flags & LIBNDR_FLAG_REMAINING) {
		/* nothing to do */
	} else if (ndr->flags & (LIBNDR_ALIGN_FLAGS & ~LIBNDR_FLAG_NOALIGN)) {
		blob.data = discard_const_p(uint8_t, padding);
		if (ndr->flags & LIBNDR_FLAG_ALIGN2) {
			blob.length = NDR_ALIGN(ndr, 2);
		} else if (ndr->flags & LIBNDR_FLAG_ALIGN4) {
			blob.length = NDR_ALIGN(ndr, 4);
		} else if (ndr->flags & LIBNDR_FLAG_ALIGN8) {
			blob.length = NDR_ALIGN(ndr, 8);
		} else {
			return ndr_push_error(ndr,
					      NDR_ERR_LENGTH,
					      "Invalid align flags");
		}
	} else {
		NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, blob.length));
	}
	NDR_CHECK(ndr_push_bytes(ndr, blob.data, blob.length));
	return NDR_ERR_SUCCESS;
}

/*
 * Pull a DATA_BLOB from the wire.
 * 1) when called with LIBNDR_FLAG_ALIGN* alignment flags set, pull padding
 *    bytes _only_. The length is determined by the alignment required and the
 *    current ndr offset.
 * 2) When called with the LIBNDR_FLAG_REMAINING flag, pull all remaining bytes
 *    from the ndr buffer.
 * 3) Otherwise, pull a uint3264 length _and_ a corresponding byte array from the
 *    ndr buffer.
 */
_PUBLIC_ enum ndr_err_code ndr_pull_DATA_BLOB(struct ndr_pull *ndr, ndr_flags_type ndr_flags, DATA_BLOB *blob)
{
	uint32_t length = 0;

	if (ndr->flags & LIBNDR_FLAG_REMAINING) {
		length = ndr->data_size - ndr->offset;
	} else if (ndr->flags & (LIBNDR_ALIGN_FLAGS & ~LIBNDR_FLAG_NOALIGN)) {
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
	} else {
		NDR_CHECK(ndr_pull_uint3264(ndr, NDR_SCALARS, &length));
	}
	if (length == 0) {
		/* skip the talloc for an empty blob */
		blob->data = NULL;
		blob->length = 0;
		return NDR_ERR_SUCCESS;
	}
	NDR_PULL_NEED_BYTES(ndr, length);
	*blob = data_blob_talloc(ndr->current_mem_ctx, ndr->data+ndr->offset, length);
	ndr->offset += length;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ uint32_t ndr_size_DATA_BLOB(int ret, const DATA_BLOB *data, ndr_flags_type flags)
{
	if (!data) return ret;
	return ret + data->length;
}

_PUBLIC_ void ndr_print_bool(struct ndr_print *ndr, const char *name, const bool b)
{
	ndr->print(ndr, "%-25s: %s", name, b?"true":"false");
}

_PUBLIC_ NTSTATUS ndr_map_error2ntstatus(enum ndr_err_code ndr_err)
{
	switch (ndr_err) {
	case NDR_ERR_SUCCESS:
		return NT_STATUS_OK;
	case NDR_ERR_BUFSIZE:
		return NT_STATUS_BUFFER_TOO_SMALL;
	case NDR_ERR_TOKEN:
		return NT_STATUS_INTERNAL_ERROR;
	case NDR_ERR_ALLOC:
		return NT_STATUS_NO_MEMORY;
	case NDR_ERR_ARRAY_SIZE:
		return NT_STATUS_ARRAY_BOUNDS_EXCEEDED;
	case NDR_ERR_INVALID_POINTER:
		return NT_STATUS_INVALID_PARAMETER_MIX;
	case NDR_ERR_UNREAD_BYTES:
		return NT_STATUS_PORT_MESSAGE_TOO_LONG;
	default:
		break;
	}

	/* we should map all error codes to different status codes */
	return NT_STATUS_INVALID_PARAMETER;
}

_PUBLIC_ int ndr_map_error2errno(enum ndr_err_code ndr_err)
{
	switch (ndr_err) {
	case NDR_ERR_SUCCESS:
		return 0;
	case NDR_ERR_BUFSIZE:
		return ENOSPC;
	case NDR_ERR_TOKEN:
		return EINVAL;
	case NDR_ERR_ALLOC:
		return ENOMEM;
	case NDR_ERR_ARRAY_SIZE:
		return EMSGSIZE;
	case NDR_ERR_INVALID_POINTER:
		return EINVAL;
	case NDR_ERR_UNREAD_BYTES:
		return EOVERFLOW;
	default:
		break;
	}

	/* we should map all error codes to different status codes */
	return EINVAL;
}

_PUBLIC_ enum ndr_err_code ndr_push_timespec(struct ndr_push *ndr,
					     ndr_flags_type ndr_flags,
					     const struct timespec *t)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_push_hyper(ndr, ndr_flags, t->tv_sec));
	NDR_CHECK(ndr_push_uint32(ndr, ndr_flags, t->tv_nsec));
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_timespec(struct ndr_pull *ndr,
					     ndr_flags_type ndr_flags,
					     struct timespec *t)
{
	uint64_t secs = 0;
	uint32_t nsecs = 0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_pull_hyper(ndr, ndr_flags, &secs));
	NDR_CHECK(ndr_pull_uint32(ndr, ndr_flags, &nsecs));
	t->tv_sec = secs;
	t->tv_nsec = nsecs;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_timespec(struct ndr_print *ndr, const char *name,
				 const struct timespec *t)
{
	char *str = timestring(ndr, t->tv_sec);
	ndr->print(ndr, "%-25s: %s.%ld", name, str, t->tv_nsec);
	TALLOC_FREE(str);
}

_PUBLIC_ enum ndr_err_code ndr_push_timeval(struct ndr_push *ndr,
					    ndr_flags_type ndr_flags,
					    const struct timeval *t)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_push_hyper(ndr, ndr_flags, t->tv_sec));
	NDR_CHECK(ndr_push_uint32(ndr, ndr_flags, t->tv_usec));
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_timeval(struct ndr_pull *ndr,
					    ndr_flags_type ndr_flags,
					    struct timeval *t)
{
	uint64_t secs = 0;
	uint32_t usecs = 0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	NDR_CHECK(ndr_pull_hyper(ndr, ndr_flags, &secs));
	NDR_CHECK(ndr_pull_uint32(ndr, ndr_flags, &usecs));
	t->tv_sec = secs;
	t->tv_usec = usecs;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_timeval(struct ndr_print *ndr, const char *name,
				const struct timeval *t)
{
	ndr->print(ndr, "%-25s: %s.%ld", name, timestring(ndr, t->tv_sec),
		   (long)t->tv_usec);
}

_PUBLIC_ void ndr_print_libndr_flags(struct ndr_print *ndr, const char *name,
				       libndr_flags flags)
{
	ndr->print(ndr, "%-25s: 0x%016"PRI_LIBNDR_FLAGS" (%"PRI_LIBNDR_FLAGS_DECIMAL")", name, flags, flags);
}
