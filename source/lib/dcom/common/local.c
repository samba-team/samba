/*
   Unix SMB/CIFS implementation.
   Implementation of some of the local COM calls. Interfaces:
    - IUnknown

   Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>

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
#include "dlinklist.h"
#include "librpc/gen_ndr/ndr_dcom.h"

NTSTATUS dcerpc_IUnknown_AddRef(struct dcom_interface *p, TALLOC_CTX *mem_ctx, struct IUnknown_AddRef *rr) 
{
	struct RemAddRef r;
	struct REMINTERFACEREF ref;
	
	/* This is rather inefficient, but we'll patch it up later */
	r.in.cInterfaceRefs = 1;
	r.in.InterfaceRefs = &ref;

	return dcerpc_RemAddRef(p, mem_ctx, &r);
}

NTSTATUS dcerpc_IUnknown_Release(struct dcom_interface *p, TALLOC_CTX *mem_ctx, struct IUnknown_Release *rr)
{
	struct RemRelease r;
	struct REMINTERFACEREF ref;

	return NT_STATUS_NOT_SUPPORTED;
	
	p->private_references--;

	/* Only do the remote version of this call when all local references have 
	 * been released */
	if (p->private_references == 0) {
		NTSTATUS status;
		r.in.cInterfaceRefs = 1;
		r.in.InterfaceRefs = &ref;

		status = dcerpc_RemRelease(p, mem_ctx, &r);
		
		if (NT_STATUS_IS_OK(status)) {
			talloc_destroy(p);	
		}

		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_IUnknown_QueryInterface(struct dcom_interface *o, TALLOC_CTX *mem_ctx, struct IUnknown_QueryInterface *rr)
{
	/* FIXME: Ask local server for interface pointer. Local server can then 
	 * call RemQueryInterface if necessary */
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS dcerpc_IClassFactory_CreateInstance(struct dcom_interface *o, TALLOC_CTX *mem_ctx, struct IClassFactory_CreateInstance *rr)
{
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS dcerpc_IClassFactory_LockServer(struct dcom_interface *o, TALLOC_CTX *mem_ctx, struct IClassFactory_LockServer *rr)
{
	return NT_STATUS_NOT_SUPPORTED;
}
