/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling lsa pipe

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

NTSTATUS ndr_push_lsa_QosInfo(struct ndr_push *ndr,
			      struct lsa_QosInfo *r)
{
	struct ndr_push_save length;

	NDR_CHECK(ndr_push_length4_start(ndr, &length));
	NDR_CHECK(ndr_push_u16(ndr, r->impersonation_level));
	NDR_CHECK(ndr_push_u8(ndr, r->context_mode));
	NDR_CHECK(ndr_push_u8(ndr, r->effective_only));
	NDR_CHECK(ndr_push_length4_end(ndr, &length));

	return NT_STATUS_OK;
}

NTSTATUS ndr_push_lsa_ObjectAttribute(struct ndr_push *ndr,
				      struct lsa_ObjectAttribute *r)
{
	struct ndr_push_save length;

	NDR_CHECK(ndr_push_length4_start(ndr, &length));
	NDR_CHECK(ndr_push_ptr(ndr, r->root_dir));
	NDR_CHECK(ndr_push_ptr(ndr, r->object_name));
	NDR_CHECK(ndr_push_u32(ndr, r->attributes));
	NDR_CHECK(ndr_push_ptr(ndr, r->sec_desc));
	NDR_CHECK(ndr_push_ptr(ndr, r->sec_qos));

	if (r->root_dir)    NDR_CHECK(ndr_push_u8(ndr, r->root_dir[0]));
	if (r->object_name) NDR_CHECK(ndr_push_unistr(ndr, r->object_name));
	if (r->sec_desc)    NDR_CHECK(ndr_push_security_descriptor(ndr, r->sec_desc));
	if (r->sec_qos)     NDR_CHECK(ndr_push_lsa_QosInfo(ndr, r->sec_qos));

	NDR_CHECK(ndr_push_length4_end(ndr, &length));

	return NT_STATUS_OK;
}

/*
  push a openpolicy
*/
NTSTATUS ndr_push_lsa_OpenPolicy(struct ndr_push *ndr, 
				 struct lsa_OpenPolicy *r)
{
	NDR_CHECK(ndr_push_ptr(ndr, r->in.system_name));
	NDR_CHECK(ndr_push_u16(ndr, r->in.system_name[0]));
	NDR_CHECK(ndr_push_lsa_ObjectAttribute(ndr, r->in.attr));
	NDR_CHECK(ndr_push_u32(ndr, r->in.desired_access));
	return NT_STATUS_OK;
}


/*
  parse a openpolicy
*/
NTSTATUS ndr_pull_lsa_OpenPolicy(struct ndr_pull *ndr,
				 struct lsa_OpenPolicy *r)
{
	NDR_CHECK(ndr_pull_policy_handle(ndr, &r->out.handle));
	NDR_CHECK(ndr_pull_status(ndr, &r->out.status));
	return NT_STATUS_OK;
}
