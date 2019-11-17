/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling special NEGOEX structures

   Copyright (C) Stefan Metzmacher 2015

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
#include "includes.h"
#include "librpc/gen_ndr/ndr_negoex.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/ndr/ndr_negoex.h"

void ndr_print_negoex_BYTE_VECTOR(struct ndr_print *ndr, const char *name, const struct negoex_BYTE_VECTOR *r)
{
	ndr_print_struct(ndr, name, "negoex_BYTE_VECTOR");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	ndr_print_DATA_BLOB(ndr, "blob", r->blob);
	ndr->depth--;
}

enum ndr_err_code ndr_push_negoex_BYTE_VECTOR(struct ndr_push *ndr, int ndr_flags, const struct negoex_BYTE_VECTOR *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 5));
		NDR_CHECK(ndr_push_relative_ptr1(ndr, r->blob.data));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->blob.length));
		NDR_CHECK(ndr_push_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->blob.data) {
			NDR_CHECK(ndr_push_relative_ptr2_start(ndr, r->blob.data));
#if 0
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, r->blob.length));
#endif
			NDR_CHECK(ndr_push_array_uint8(ndr, NDR_SCALARS, r->blob.data, r->blob.length));
			NDR_CHECK(ndr_push_relative_ptr2_end(ndr, r->blob.data));
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_negoex_BYTE_VECTOR(struct ndr_pull *ndr, int ndr_flags, struct negoex_BYTE_VECTOR *r)
{
	uint32_t _ptr_data;
	uint32_t size_data_1 = 0;
	TALLOC_CTX *_mem_save_data_0 = NULL;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	r->_dummy = NULL;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_data));
		if (_ptr_data) {
			NDR_PULL_ALLOC(ndr, r->blob.data);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->blob.data, _ptr_data));
		} else {
			r->blob.data = NULL;
		}
		r->blob.length = 0;
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &size_data_1));
		r->_length = size_data_1;
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->blob.data) {
			uint32_t _relative_save_offset;
			_relative_save_offset = ndr->offset;
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->blob.data));
			_mem_save_data_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->blob.data, 0);
#if 0
			NDR_CHECK(ndr_pull_array_size(ndr, &r->blob.data));
			size_data_1 = ndr_get_array_size(ndr, &r->blob.data);
#else
			size_data_1 = r->_length;
#endif
			NDR_PULL_ALLOC_N(ndr, r->blob.data, size_data_1);
			NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->blob.data, size_data_1));
			r->blob.length = size_data_1;
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_data_0, 0);
			if (ndr->offset > ndr->relative_highest_offset) {
				ndr->relative_highest_offset = ndr->offset;
			}
			ndr->offset = _relative_save_offset;
		}
#if 0
		if (r->blob.data) {
			NDR_CHECK(ndr_check_array_size(ndr, (void*)&r->blob.data, r->blob.length));
		}
#endif
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_negoex_AUTH_SCHEME_VECTOR(struct ndr_push *ndr, int ndr_flags, const struct negoex_AUTH_SCHEME_VECTOR *r)
{
	uint32_t cntr_array_1;
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 5));
		NDR_CHECK(ndr_push_relative_ptr1(ndr, r->array));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		NDR_CHECK(ndr_push_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->array) {
			NDR_CHECK(ndr_push_relative_ptr2_start(ndr, r->array));
#if 0
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, r->count));
#endif
			for (cntr_array_1 = 0; cntr_array_1 < (r->count); cntr_array_1++) {
				NDR_CHECK(ndr_push_negoex_AUTH_SCHEME(ndr, NDR_SCALARS, &r->array[cntr_array_1]));
			}
			NDR_CHECK(ndr_push_relative_ptr2_end(ndr, r->array));
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_negoex_AUTH_SCHEME_VECTOR(struct ndr_pull *ndr, int ndr_flags, struct negoex_AUTH_SCHEME_VECTOR *r)
{
	uint32_t _ptr_array;
	uint32_t size_array_1 = 0;
	uint32_t cntr_array_1;
	TALLOC_CTX *_mem_save_array_0 = NULL;
	TALLOC_CTX *_mem_save_array_1 = NULL;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_array));
		if (_ptr_array) {
			NDR_PULL_ALLOC(ndr, r->array);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->array, _ptr_array));
		} else {
			r->array = NULL;
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->array) {
			uint32_t _relative_save_offset;
			_relative_save_offset = ndr->offset;
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->array));
			_mem_save_array_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->array, 0);
#if 0
			NDR_CHECK(ndr_pull_array_size(ndr, &r->array));
			size_array_1 = ndr_get_array_size(ndr, &r->array);
#else
			size_array_1 = r->count;
#endif
			NDR_PULL_ALLOC_N(ndr, r->array, size_array_1);
			_mem_save_array_1 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->array, 0);
			for (cntr_array_1 = 0; cntr_array_1 < (size_array_1); cntr_array_1++) {
				NDR_CHECK(ndr_pull_negoex_AUTH_SCHEME(ndr, NDR_SCALARS, &r->array[cntr_array_1]));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_array_1, 0);
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_array_0, 0);
			if (ndr->offset > ndr->relative_highest_offset) {
				ndr->relative_highest_offset = ndr->offset;
			}
			ndr->offset = _relative_save_offset;
		}
#if 0
		if (r->array) {
			NDR_CHECK(ndr_check_array_size(ndr, (void*)&r->array, r->count));
		}
#endif
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_negoex_EXTENSION_VECTOR(struct ndr_push *ndr, int ndr_flags, const struct negoex_EXTENSION_VECTOR *r)
{
	uint32_t cntr_array_1;
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 5));
		NDR_CHECK(ndr_push_relative_ptr1(ndr, r->array));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		NDR_CHECK(ndr_push_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->array) {
			NDR_CHECK(ndr_push_relative_ptr2_start(ndr, r->array));
#if 0
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, r->count));
#endif
			for (cntr_array_1 = 0; cntr_array_1 < (r->count); cntr_array_1++) {
				NDR_CHECK(ndr_push_negoex_EXTENSION(ndr, NDR_SCALARS, &r->array[cntr_array_1]));
			}
			for (cntr_array_1 = 0; cntr_array_1 < (r->count); cntr_array_1++) {
				NDR_CHECK(ndr_push_negoex_EXTENSION(ndr, NDR_BUFFERS, &r->array[cntr_array_1]));
			}
			NDR_CHECK(ndr_push_relative_ptr2_end(ndr, r->array));
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_negoex_EXTENSION_VECTOR(struct ndr_pull *ndr, int ndr_flags, struct negoex_EXTENSION_VECTOR *r)
{
	uint32_t _ptr_array;
	uint32_t size_array_1 = 0;
	uint32_t cntr_array_1;
	TALLOC_CTX *_mem_save_array_0 = NULL;
	TALLOC_CTX *_mem_save_array_1 = NULL;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_array));
		if (_ptr_array) {
			NDR_PULL_ALLOC(ndr, r->array);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->array, _ptr_array));
		} else {
			r->array = NULL;
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->array) {
			uint32_t _relative_save_offset;
			_relative_save_offset = ndr->offset;
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->array));
			_mem_save_array_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->array, 0);
#if 0
			NDR_CHECK(ndr_pull_array_size(ndr, &r->array));
			size_array_1 = ndr_get_array_size(ndr, &r->array);
#else
			size_array_1 = r->count;
#endif
			NDR_PULL_ALLOC_N(ndr, r->array, size_array_1);
			_mem_save_array_1 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->array, 0);
			for (cntr_array_1 = 0; cntr_array_1 < (size_array_1); cntr_array_1++) {
				NDR_CHECK(ndr_pull_negoex_EXTENSION(ndr, NDR_SCALARS, &r->array[cntr_array_1]));
			}
			for (cntr_array_1 = 0; cntr_array_1 < (size_array_1); cntr_array_1++) {
				NDR_CHECK(ndr_pull_negoex_EXTENSION(ndr, NDR_BUFFERS, &r->array[cntr_array_1]));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_array_1, 0);
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_array_0, 0);
			if (ndr->offset > ndr->relative_highest_offset) {
				ndr->relative_highest_offset = ndr->offset;
			}
			ndr->offset = _relative_save_offset;
		}
#if 0
		if (r->array) {
			NDR_CHECK(ndr_check_array_size(ndr, (void*)&r->array, r->count));
		}
#endif
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_negoex_ALERT_VECTOR(struct ndr_push *ndr, int ndr_flags, const struct negoex_ALERT_VECTOR *r)
{
	uint32_t cntr_array_1;
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 5));
		NDR_CHECK(ndr_push_relative_ptr1(ndr, r->array));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		NDR_CHECK(ndr_push_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->array) {
			NDR_CHECK(ndr_push_relative_ptr2_start(ndr, r->array));
#if 0
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, r->count));
#endif
			for (cntr_array_1 = 0; cntr_array_1 < (r->count); cntr_array_1++) {
				NDR_CHECK(ndr_push_negoex_ALERT(ndr, NDR_SCALARS, &r->array[cntr_array_1]));
			}
			for (cntr_array_1 = 0; cntr_array_1 < (r->count); cntr_array_1++) {
				NDR_CHECK(ndr_push_negoex_ALERT(ndr, NDR_BUFFERS, &r->array[cntr_array_1]));
			}
			NDR_CHECK(ndr_push_relative_ptr2_end(ndr, r->array));
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_negoex_ALERT_VECTOR(struct ndr_pull *ndr, int ndr_flags, struct negoex_ALERT_VECTOR *r)
{
	uint32_t _ptr_array;
	uint32_t size_array_1 = 0;
	uint32_t cntr_array_1;
	TALLOC_CTX *_mem_save_array_0 = NULL;
	TALLOC_CTX *_mem_save_array_1 = NULL;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_array));
		if (_ptr_array) {
			NDR_PULL_ALLOC(ndr, r->array);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->array, _ptr_array));
		} else {
			r->array = NULL;
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->array) {
			uint32_t _relative_save_offset;
			_relative_save_offset = ndr->offset;
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->array));
			_mem_save_array_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->array, 0);
#if 0
			NDR_CHECK(ndr_pull_array_size(ndr, &r->array));
			size_array_1 = ndr_get_array_size(ndr, &r->array);
#else
			size_array_1 = r->count;
#endif
			NDR_PULL_ALLOC_N(ndr, r->array, size_array_1);
			_mem_save_array_1 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->array, 0);
			for (cntr_array_1 = 0; cntr_array_1 < (size_array_1); cntr_array_1++) {
				NDR_CHECK(ndr_pull_negoex_ALERT(ndr, NDR_SCALARS, &r->array[cntr_array_1]));
			}
			for (cntr_array_1 = 0; cntr_array_1 < (size_array_1); cntr_array_1++) {
				NDR_CHECK(ndr_pull_negoex_ALERT(ndr, NDR_BUFFERS, &r->array[cntr_array_1]));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_array_1, 0);
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_array_0, 0);
			if (ndr->offset > ndr->relative_highest_offset) {
				ndr->relative_highest_offset = ndr->offset;
			}
			ndr->offset = _relative_save_offset;
		}
#if 0
		if (r->array) {
			NDR_CHECK(ndr_check_array_size(ndr, (void*)&r->array, r->count));
		}
#endif
	}
	return NDR_ERR_SUCCESS;
}

size_t ndr_negoex_MESSAGE_header_length(const struct negoex_MESSAGE *r)
{
	size_t size = 0;

	size += 8;  /* signature */
	size += 4;  /* type */
	size += 4;  /* sequence_number */
	size += 4;  /* header_length */
	size += 4;  /* message_length */
	size += 16; /* conversation_id */

	switch (r->type) {
	case NEGOEX_MESSAGE_TYPE_INITIATOR_NEGO:
	case NEGOEX_MESSAGE_TYPE_ACCEPTOR_NEGO:
		size += 32; /* random */
		size += 8;  /* protocol_version */
		size += 8;  /* auth_schemes */
		size += 8;  /* extensions */
		break;

	case NEGOEX_MESSAGE_TYPE_INITIATOR_META_DATA:
	case NEGOEX_MESSAGE_TYPE_ACCEPTOR_META_DATA:
	case NEGOEX_MESSAGE_TYPE_CHALLENGE:
	case NEGOEX_MESSAGE_TYPE_AP_REQUEST:
		size += 16; /* auth_scheme */
		size += 8;  /* exchange */
		break;

	case NEGOEX_MESSAGE_TYPE_VERIFY:
		size += 16; /* auth_scheme */
		size += 4;  /* checksum.header_length */
		size += 4;  /* checksum.scheme */
		size += 4;  /* checksum.type */
		size += 8;  /* checksum.value */
		break;

	case NEGOEX_MESSAGE_TYPE_ALERT:
		size += 16; /* auth_scheme */
		size += 4;  /* status */
		size += 8;  /* alerts */
		break;
	}

	return size;
}

enum ndr_err_code ndr_pull_negoex_MESSAGE(struct ndr_pull *ndr, int ndr_flags, struct negoex_MESSAGE *r)
{
	uint32_t _save_relative_base_offset = ndr_pull_get_relative_base_offset(ndr);
	uint32_t size_signature_0 = 0;
	uint32_t start_data_size = ndr->data_size;
	uint32_t saved_offset = 0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_setup_relative_base_offset1(ndr, r, ndr->offset));
		size_signature_0 = 8;
		NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->signature, size_signature_0, sizeof(uint8_t), CH_DOS));
		NDR_CHECK(ndr_pull_negoex_MESSAGE_TYPE(ndr, NDR_SCALARS, &r->type));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->sequence_number));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->header_length));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->message_length));
		saved_offset = ndr->offset;
		ndr->offset = ndr->relative_base_offset;
		NDR_PULL_NEED_BYTES(ndr, r->message_length);
		ndr->data_size = ndr->offset + r->message_length;
		ndr->offset = saved_offset;
		NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &r->conversation_id));
		NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->p, r->type));
		NDR_CHECK(ndr_pull_negoex_PAYLOAD(ndr, NDR_SCALARS, &r->p));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
		ndr->offset = ndr->data_size;
		ndr->data_size = start_data_size;
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_pull_setup_relative_base_offset2(ndr, r));
		saved_offset = ndr->offset;
		ndr->offset = ndr->relative_base_offset;
		NDR_PULL_NEED_BYTES(ndr, r->message_length);
		ndr->data_size = ndr->offset + r->message_length;
		ndr->offset = saved_offset;
		NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->p, r->type));
		NDR_CHECK(ndr_pull_negoex_PAYLOAD(ndr, NDR_BUFFERS, &r->p));
		ndr->offset = ndr->data_size;
		ndr->data_size = start_data_size;
	}
	ndr_pull_restore_relative_base_offset(ndr, _save_relative_base_offset);
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_negoex_MESSAGE_ARRAY(struct ndr_push *ndr, int ndr_flags, const struct negoex_MESSAGE_ARRAY *r)
{
	uint32_t cntr_messages_0;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
		NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
		if (ndr_flags & NDR_SCALARS) {
			NDR_CHECK(ndr_push_align(ndr, 5));
			for (cntr_messages_0 = 0; cntr_messages_0 < (r->count); cntr_messages_0++) {
				NDR_CHECK(ndr_push_negoex_MESSAGE(ndr, NDR_SCALARS|NDR_BUFFERS, &r->messages[cntr_messages_0]));
			}
			NDR_CHECK(ndr_push_trailer_align(ndr, 5));
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_negoex_MESSAGE_ARRAY(struct ndr_pull *ndr, int ndr_flags, struct negoex_MESSAGE_ARRAY *r)
{
	uint32_t size_messages_0 = 0;
	uint32_t cntr_messages_0;
	TALLOC_CTX *_mem_save_messages_0 = NULL;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
		NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
		if (ndr_flags & NDR_SCALARS) {
			uint32_t saved_offset = ndr->offset;
			uint32_t available = 0;
			NDR_CHECK(ndr_pull_align(ndr, 5));
			r->count = 0;
			available = ndr->data_size - ndr->offset;
			while (available > 0) {
				uint32_t length;

				/*
				 * The common header is 40 bytes
				 * and message_length is at offset 20
				 */
				NDR_PULL_NEED_BYTES(ndr, 40);
				ndr->offset += 20;
				NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &length));
				ndr->offset -= 24;
				if (length < 40) {
					/*
					 * let the pull function catch the error
					 */
					length = 40;
				}
				NDR_PULL_NEED_BYTES(ndr, length);
				ndr->offset += length;
				available -= length;
				r->count++;
			}
			ndr->offset = saved_offset;
			size_messages_0 = r->count;
			NDR_PULL_ALLOC_N(ndr, r->messages, size_messages_0);
			_mem_save_messages_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->messages, 0);
			for (cntr_messages_0 = 0; cntr_messages_0 < (size_messages_0); cntr_messages_0++) {
				NDR_CHECK(ndr_pull_negoex_MESSAGE(ndr, NDR_SCALARS|NDR_BUFFERS, &r->messages[cntr_messages_0]));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_messages_0, 0);
			NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}
