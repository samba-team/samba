/* 
   Unix SMB/CIFS implementation.

   endpoint server for the IRemoteActivation pipe

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "librpc/gen_ndr/ndr_remact.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"

struct dcom_interface_pointer *dcom_interface_pointer_by_ipid(struct GUID *ipid)
{
	/* FIXME */
	return NULL;
}

/* 
  RemoteActivation 
*/
static WERROR RemoteActivation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct RemoteActivation *r)
{
	struct CreateInstance *cr;
	/*struct Release *ur;*/
	struct dcom_interface_p *o;
	int i;

	/* FIXME: CoGetClassObject() */
	/* FIXME: IClassFactory::CreateInstance() */
	/* FIXME: IUnknown::Release() */
	
	ZERO_STRUCT(r->out);
	r->out.ServerVersion.MajorVersion = COM_MAJOR_VERSION;
	r->out.ServerVersion.MinorVersion = COM_MINOR_VERSION;

	r->out.AuthnHint = DCERPC_AUTH_LEVEL_DEFAULT;
	r->out.pdsaOxidBindings = dcom_server_generate_dual_string(mem_ctx, dce_call);
	
	/* FIXME: Loop thru given interfaces and set r->out.results and 
	 * r->out.interfaces */
	r->out.ifaces = talloc_array_p(mem_ctx, struct pMInterfacePointer, r->in.Interfaces);
	r->out.results = talloc_array_p(mem_ctx, WERROR, r->in.Interfaces);
	r->out.hr = cr->out.result;

	for (i = 0; i < r->in.Interfaces; i++) {
		struct QueryInterface rr;
		rr.in.iid = &r->in.pIIDs[i];
		dcom_IUnknown_QueryInterface(o, mem_ctx, &rr);
		ZERO_STRUCT(r->out.ifaces[i]);	
		r->out.results[i] = rr.out.result;
	}

	/* FIXME: */
	r->out.pOxid = 0;
	ZERO_STRUCT(r->out.ipidRemUnknown);
	
	return WERR_OK;
}


NTSTATUS dcerpc_server_dcom_init(void)
{
	NTSTATUS status;
	status = dcerpc_server_IOXIDResolver_init();
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	status = dcerpc_server_IRemoteActivation_init();
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_remact_s.c"
