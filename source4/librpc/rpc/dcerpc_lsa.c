/* 
   Unix SMB/CIFS implementation.
   raw dcerpc operations

   Copyright (C) Tim Potter 2004
   
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

NTSTATUS lsa_OpenPolicy(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			struct policy_handle *handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	uint16 system_name = '\\';

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = &system_name;
	r.in.attr = &attr;
	r.in.desired_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;	

	return dcerpc_lsa_OpenPolicy(p, mem_ctx, &r);
}

NTSTATUS lsa_OpenPolicy2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = "\\";
	r.in.attr = &attr;
	r.in.desired_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	return dcerpc_lsa_OpenPolicy2(p, mem_ctx, &r);
}

