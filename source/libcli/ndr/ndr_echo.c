/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling rpcecho pipe

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
  parse a addone
*/
NTSTATUS ndr_pull_rpcecho_addone(struct ndr_pull *ndr, 
				 struct rpcecho_addone *r)
{
	NDR_CHECK(ndr_pull_u32(ndr, &r->out.data));
	return NT_STATUS_OK;
}


/*
  push a addone
*/
NTSTATUS ndr_push_rpcecho_addone(struct ndr_push *ndr, 
				 struct rpcecho_addone *r)
{
	NDR_CHECK(ndr_push_u32(ndr, r->in.data));
	return NT_STATUS_OK;
}


/*
  parse a echodata
*/
NTSTATUS ndr_pull_rpcecho_echodata(struct ndr_pull *ndr, 
				   struct rpcecho_echodata *r)
{
	NDR_CHECK(ndr_pull_u32(ndr, &r->out.len));
	NDR_CHECK(ndr_pull_bytes(ndr, &r->out.data, r->out.len));
	return NT_STATUS_OK;
}

/*
  push a echodata
*/
NTSTATUS ndr_push_rpcecho_echodata(struct ndr_push *ndr, 
				   struct rpcecho_echodata *r)
{
	NDR_CHECK(ndr_push_u32(ndr, r->in.len));
	NDR_CHECK(ndr_push_u32(ndr, r->in.len));
	NDR_CHECK(ndr_push_bytes(ndr, r->in.data, r->in.len));
	return NT_STATUS_OK;
}
