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

#include "includes.h"

NTSTATUS ndr_push_dom_sid(struct ndr_push *ndr, int ndr_flags, const struct dom_sid *r)
{
	uint32_t cntr_sub_auths_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->sid_rev_num));
		NDR_CHECK(ndr_push_int8(ndr, NDR_SCALARS, r->num_auths));
		NDR_CHECK(ndr_push_array_uint8(ndr, NDR_SCALARS, r->id_auth, 6));
		for (cntr_sub_auths_0 = 0; cntr_sub_auths_0 < r->num_auths; cntr_sub_auths_0++) {
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->sub_auths[cntr_sub_auths_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_dom_sid(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *r)
{
	uint32_t cntr_sub_auths_0;
	TALLOC_CTX *_mem_save_sub_auths_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->sid_rev_num));
		NDR_CHECK(ndr_pull_int8(ndr, NDR_SCALARS, &r->num_auths));
		if (r->num_auths < 0 || r->num_auths > 15) {
			return ndr_pull_error(ndr, NDR_ERR_RANGE, "value out of range");
		}
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->id_auth, 6));
		NDR_PULL_ALLOC_N(ndr, r->sub_auths, r->num_auths);
		_mem_save_sub_auths_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->sub_auths, 0);
		for (cntr_sub_auths_0 = 0; cntr_sub_auths_0 < r->num_auths; cntr_sub_auths_0++) {
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->sub_auths[cntr_sub_auths_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sub_auths_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NT_STATUS_OK;
}

/*
  convert a dom_sid to a string
*/
char *dom_sid_string(TALLOC_CTX *mem_ctx, const struct dom_sid *sid)
{
	int i, ofs, maxlen;
	uint32_t ia;
	char *ret;
	
	if (!sid) {
		return talloc_strdup(mem_ctx, "(NULL SID)");
	}

	maxlen = sid->num_auths * 11 + 25;
	ret = talloc_size(mem_ctx, maxlen);
	if (!ret) return talloc_strdup(mem_ctx, "(SID ERR)");

	ia = (sid->id_auth[5]) +
		(sid->id_auth[4] << 8 ) +
		(sid->id_auth[3] << 16) +
		(sid->id_auth[2] << 24);

	ofs = snprintf(ret, maxlen, "S-%u-%lu", 
		       (unsigned int)sid->sid_rev_num, (unsigned long)ia);

	for (i = 0; i < sid->num_auths; i++) {
		ofs += snprintf(ret + ofs, maxlen - ofs, "-%lu", (unsigned long)sid->sub_auths[i]);
	}
	
	return ret;
}
