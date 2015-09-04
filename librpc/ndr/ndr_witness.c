/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling witness structures

   Copyright (C) Guenther Deschner 2015

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
#include "librpc/gen_ndr/ndr_witness.h"

_PUBLIC_ enum ndr_err_code ndr_push_witness_notifyResponse(struct ndr_push *ndr, int ndr_flags, const struct witness_notifyResponse *r)
{
	uint32_t cntr_messages_0;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_PRINT_ARRAY_HEX);
		NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
		if (ndr_flags & NDR_SCALARS) {
			NDR_CHECK(ndr_push_align(ndr, 4));
			NDR_CHECK(ndr_push_witness_notifyResponse_type(ndr, NDR_SCALARS, r->type));
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_size_witness_notifyResponse(r, ndr->flags) - 20));
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->num));
			NDR_CHECK(ndr_push_unique_ptr(ndr, r->messages));
			if (r->messages) {
				uint32_t _flags_save_witness_notifyResponse_message = ndr->flags;
				ndr_set_flags(&ndr->flags, LIBNDR_FLAG_REMAINING);
					{
						struct ndr_push *_ndr_messages;
						NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_messages, 4, ndr_size_witness_notifyResponse(r, ndr->flags) - 20));
						for (cntr_messages_0 = 0; cntr_messages_0 < (r->num); cntr_messages_0++) {
							NDR_CHECK(ndr_push_set_switch_value(_ndr_messages, &r->messages[cntr_messages_0], r->type));
							NDR_CHECK(ndr_push_witness_notifyResponse_message(_ndr_messages, NDR_SCALARS, &r->messages[cntr_messages_0]));
						}
						NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_messages, 4, ndr_size_witness_notifyResponse(r, ndr->flags) - 20));
					}
				ndr->flags = _flags_save_witness_notifyResponse_message;
			}
			NDR_CHECK(ndr_push_trailer_align(ndr, 4));
		}
		if (ndr_flags & NDR_BUFFERS) {
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_witness_notifyResponse(struct ndr_pull *ndr, int ndr_flags, struct witness_notifyResponse *r)
{
	uint32_t _flags_save_STRUCT = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_PRINT_ARRAY_HEX);
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_witness_notifyResponse_type(ndr, NDR_SCALARS, &r->type));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->length));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->num));
		{
			uint32_t _flags_save_witness_notifyResponse_message = ndr->flags;
			uint32_t _ptr_messages;
			ndr_set_flags(&ndr->flags, LIBNDR_FLAG_REMAINING);
			NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_messages));
			if (_ptr_messages) {
				NDR_PULL_ALLOC(ndr, r->messages);
			} else {
				r->messages = NULL;
			}
			if (r->messages) {
				uint32_t size_messages_0 = 0;
				uint32_t cntr_messages_0;
				TALLOC_CTX *_mem_save_messages_0;

				size_messages_0 = r->num;
				NDR_PULL_ALLOC_N(ndr, r->messages, size_messages_0);
				_mem_save_messages_0 = NDR_PULL_GET_MEM_CTX(ndr);
				NDR_PULL_SET_MEM_CTX(ndr, r->messages, 0);
				{
					struct ndr_pull *_ndr_messages;
					NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_messages, 4, r->length));
					for (cntr_messages_0 = 0; cntr_messages_0 < (size_messages_0); cntr_messages_0++) {
						NDR_CHECK(ndr_pull_set_switch_value(_ndr_messages, &r->messages[cntr_messages_0], r->type));
						NDR_CHECK(ndr_pull_witness_notifyResponse_message(_ndr_messages, NDR_SCALARS, &r->messages[cntr_messages_0]));
					}
					NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_messages, 4, r->length));
				}
				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_messages_0, 0);
			}
			ndr->flags = _flags_save_witness_notifyResponse_message;
		}
		NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	ndr->flags = _flags_save_STRUCT;

	return NDR_ERR_SUCCESS;
}
