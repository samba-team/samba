/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling special ntlmssp structures

   Copyright (C) Guenther Deschner 2009

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
#include "../librpc/ndr/ndr_ntlmssp.h"
#include "../librpc/gen_ndr/ndr_ntlmssp.h"

_PUBLIC_ size_t ndr_ntlmssp_string_length(uint32_t negotiate_flags, const char *s)
{
	if (!s) {
		return 0;
	}

	if (negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		return strlen(s) * 2;
	}

	return strlen(s);
}

_PUBLIC_ uint32_t ndr_ntlmssp_negotiated_string_flags(uint32_t negotiate_flags)
{
	uint32_t flags = LIBNDR_FLAG_STR_NOTERM |
			 LIBNDR_FLAG_STR_CHARLEN |
			 LIBNDR_FLAG_REMAINING;

	if (!(negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
		flags |= LIBNDR_FLAG_STR_ASCII;
	}

	return flags;
}

_PUBLIC_ enum ndr_err_code ndr_push_AV_PAIR_LIST(struct ndr_push *ndr, int ndr_flags, const struct AV_PAIR_LIST *r)
{
	uint32_t cntr_pair_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		for (cntr_pair_0 = 0; cntr_pair_0 < r->count; cntr_pair_0++) {
			NDR_CHECK(ndr_push_AV_PAIR(ndr, NDR_SCALARS, &r->pair[cntr_pair_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		for (cntr_pair_0 = 0; cntr_pair_0 < r->count; cntr_pair_0++) {
			NDR_CHECK(ndr_push_AV_PAIR(ndr, NDR_BUFFERS, &r->pair[cntr_pair_0]));
		}
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_AV_PAIR_LIST(struct ndr_pull *ndr, int ndr_flags, struct AV_PAIR_LIST *r)
{
	uint32_t cntr_pair_0;
	TALLOC_CTX *_mem_save_pair_0;
	if (ndr_flags & NDR_SCALARS) {
		uint32_t offset = 0;
		NDR_CHECK(ndr_pull_align(ndr, 4));
		r->count = 0;
		if (ndr->data_size > 0) {
			NDR_PULL_NEED_BYTES(ndr, 4);
		}
		while (offset + 4 <= ndr->data_size) {
			uint16_t length;
			uint16_t type;
			type = SVAL(ndr->data + offset, 0);
			if (type == MsvAvEOL) {
				r->count++;
				break;
			}
			length = SVAL(ndr->data + offset, 2);
			offset += length + 4;
			r->count++;
		}
		NDR_PULL_ALLOC_N(ndr, r->pair, r->count);
		_mem_save_pair_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->pair, 0);
		for (cntr_pair_0 = 0; cntr_pair_0 < r->count; cntr_pair_0++) {
			NDR_CHECK(ndr_pull_AV_PAIR(ndr, NDR_SCALARS, &r->pair[cntr_pair_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_pair_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
		_mem_save_pair_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->pair, 0);
		for (cntr_pair_0 = 0; cntr_pair_0 < r->count; cntr_pair_0++) {
			NDR_CHECK(ndr_pull_AV_PAIR(ndr, NDR_BUFFERS, &r->pair[cntr_pair_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_pair_0, 0);
	}
	return NDR_ERR_SUCCESS;
}
