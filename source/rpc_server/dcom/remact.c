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
#include "rpc_server/dcom/dcom.h"

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
	/* FIXME: CoGetClassObject() */
	/* FIXME: IClassFactory::CreateInstance() */
	/* FIXME: Register newly created object with dcerpc subsystem */
	/* FIXME: IClassFactory::Release() */
	
	ZERO_STRUCT(r->out);
	r->out.ServerVersion.MajorVersion = COM_MAJOR_VERSION;
	r->out.ServerVersion.MinorVersion = COM_MINOR_VERSION;

	/* FIXME: */
	r->out.hr = WERR_NOT_SUPPORTED;
	r->out.pOxid = 0;
	r->out.AuthnHint = 0;
	/* FIXME: Loop thru given interfaces and set r->out.results and 
	 * r->out.interfaces */
	
	return WERR_NOT_SUPPORTED;
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
