/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling security descriptors
   and related structures

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
  parse a dom_sid2 - this is a dom_sid but with an extra copy of the num_auths field
*/
NTSTATUS ndr_pull_dom_sid2(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *sid)
{
	uint32_t num_auths;
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &num_auths));
	NDR_CHECK(ndr_pull_dom_sid(ndr, ndr_flags, sid));
	if (sid->num_auths != num_auths) {
		return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, 
				      "Bad array size %u should exceed %u", 
				      num_auths, sid->num_auths);
	}
	return NT_STATUS_OK;
}

/*
  parse a dom_sid2 - this is a dom_sid but with an extra copy of the num_auths field
*/
NTSTATUS ndr_push_dom_sid2(struct ndr_push *ndr, int ndr_flags, const struct dom_sid *sid)
{
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, sid->num_auths));
	return ndr_push_dom_sid(ndr, ndr_flags, sid);
}

/*
  parse a dom_sid28 - this is a dom_sid in a fixed 28 byte buffer, so we need to ensure there are only upto 5 sub_auth
*/
NTSTATUS ndr_pull_dom_sid28(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *sid)
{
	NTSTATUS status;
	struct ndr_pull *subndr;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}

	subndr = talloc_zero(ndr, struct ndr_pull);
	NT_STATUS_HAVE_NO_MEMORY(subndr);
	subndr->flags		= ndr->flags;
	subndr->current_mem_ctx	= ndr->current_mem_ctx;

	subndr->data		= ndr->data + ndr->offset;
	subndr->data_size	= 28;
	subndr->offset		= 0;

	NDR_CHECK(ndr_pull_advance(ndr, 28));

	status = ndr_pull_dom_sid(subndr, ndr_flags, sid);
	if (!NT_STATUS_IS_OK(status)) {
		/* handle a w2k bug which send random data in the buffer */
		ZERO_STRUCTP(sid);
	}

	return NT_STATUS_OK;
}

/*
  push a dom_sid28 - this is a dom_sid in a 28 byte fixed buffer
*/
NTSTATUS ndr_push_dom_sid28(struct ndr_push *ndr, int ndr_flags, const struct dom_sid *sid)
{
	uint32_t old_offset;
	uint32_t padding;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}

	if (sid->num_auths > 5) {
		return ndr_push_error(ndr, NDR_ERR_RANGE, 
				      "dom_sid28 allows only upto 5 sub auth [%u]", 
				      sid->num_auths);
	}

	old_offset = ndr->offset;
	NDR_CHECK(ndr_push_dom_sid(ndr, ndr_flags, sid));

	padding = 28 - (ndr->offset - old_offset);

	if (padding > 0) {
		NDR_CHECK(ndr_push_zero(ndr, padding));
	}

	return NT_STATUS_OK;
}

