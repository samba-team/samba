/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling miscellaneous rpc structures

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
  parse a policy handle
*/
NTSTATUS ndr_pull_policy_handle(struct ndr_pull *ndr, 
				struct policy_handle *r)
{
	NDR_CHECK(ndr_pull_bytes(ndr, r->data, 20));
	return NT_STATUS_OK;
}

/*
  push a policy handle
*/
NTSTATUS ndr_push_policy_handle(struct ndr_push *ndr, 
				struct policy_handle *r)
{
	NDR_CHECK(ndr_push_bytes(ndr, r->data, 20));
	return NT_STATUS_OK;
}


/*
  push a buffer of bytes
*/
NTSTATUS ndr_push_uint8_buf(struct ndr_push *ndr, int ndr_flags,
			    struct uint8_buf *buf)
{
	NDR_CHECK(ndr_push_uint32(ndr, buf->size));
	NDR_CHECK(ndr_push_bytes(ndr, buf->data, buf->size));
	return NT_STATUS_OK;
}

/*
  pull a buffer of bytes
*/
NTSTATUS ndr_pull_uint8_buf(struct ndr_pull *ndr, int ndr_flags, 
			    struct uint8_buf *buf)
{
	NDR_CHECK(ndr_pull_uint32(ndr, &buf->size));
	NDR_ALLOC_SIZE(ndr, buf->data, buf->size);
	NDR_CHECK(ndr_pull_bytes(ndr, buf->data, buf->size));
	return NT_STATUS_OK;
}
