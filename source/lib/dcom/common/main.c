/*
   Unix SMB/CIFS implementation.
   Main DCOM functionality
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
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_remact.h"

static WERROR dcom_binding_from_oxid(TALLOC_CTX *mem_ctx, HYPER_T oxid, struct dcerpc_binding *bd)
{
	/* FIXME */
	return WERR_NOT_SUPPORTED;
}

static WERROR dcom_tower_from_oxid(TALLOC_CTX *mem_ctx, HYPER_T oxid, struct epm_tower *bd)
{
	/* FIXME */
	return WERR_NOT_SUPPORTED;
}

static WERROR dcom_get_class_object (struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct GUID clsid)
{
	struct RemoteActivation r;
	NTSTATUS status;
	struct GUID iids[2];
	uint16 protseq[3] = { EPM_PROTOCOL_TCP, EPM_PROTOCOL_NCALRPC, EPM_PROTOCOL_UUID };

	ZERO_STRUCT(r.in);
	r.in.this.version.MajorVersion = 5;
	r.in.this.version.MinorVersion = 1;
	uuid_generate_random(&r.in.this.cid);
	r.in.Clsid = clsid;
	r.in.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
	r.in.num_protseqs = 3;
	r.in.protseq = protseq;
	r.in.Interfaces = 1;
	GUID_from_string(DCERPC_IUNKNOWN_UUID, &iids[0]);
	r.in.pIIDs = iids;
	r.in.Mode = MODE_GET_CLASS_OBJECT;

	status = dcerpc_RemoteActivation(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "RemoteActivation: %s\n", nt_errstr(status));
		return ntstatus_to_werror(status);
	}

	if(!W_ERROR_IS_OK(r.out.result)) { return r.out.result; }
	if(!W_ERROR_IS_OK(r.out.hr)) { return r.out.hr; }
	if(!W_ERROR_IS_OK(r.out.results[0])) { return r.out.results[0]; }

	return WERR_OK;
}

static WERROR dcom_create_instance (struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct GUID clsid) 
{
	return WERR_NOT_SUPPORTED;
}

static uint32 IUnknown_AddRef(void) 
{
	/* FIXME: Tell local server we're adding a reference to this interface on this object. Local server can then call RemAddRef() if necessary */
	return 0;
}

static uint32 IUnknown_Release(void)
{
	/* FIXME: Tell local server we're releasing a reference to this interface on this object. Local server can then call RemRelease() if necessary */
	return 0;
}

static WERROR IUnknown_QueryInterface(struct GUID *riid, void **data)
{
	/* FIXME: Ask local server for interface pointer. Local server can then 
	 * call RemQueryInterface if necessary */
	return WERR_NOT_SUPPORTED;
}
