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

#define DCOM_NEGOTIATED_PROTOCOLS { EPM_PROTOCOL_TCP, EPM_PROTOCOL_SMB, EPM_PROTOCOL_NCALRPC }

static NTSTATUS dcom_connect(struct dcerpc_pipe **p, const char *server, const char *domain, const char *user, const char *pass)
{
	struct dcerpc_binding bd;
	enum dcerpc_transport_t available_transports[] = { NCACN_IP_TCP, NCACN_NP };
	int i;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_init("dcom_connect");

	/* Allow server name to contain a binding string */
	if (NT_STATUS_IS_OK(dcerpc_parse_binding(mem_ctx, server, &bd))) {
		status = dcerpc_pipe_connect_b(p, &bd, DCERPC_IREMOTEACTIVATION_UUID, DCERPC_IREMOTEACTIVATION_VERSION, domain, user, pass);
		talloc_destroy(mem_ctx);
		return status;
	}
	talloc_destroy(mem_ctx);

	ZERO_STRUCT(bd);
	bd.host = server;
	
	if (server == NULL) { 
		bd.transport = NCALRPC; 
		return dcerpc_pipe_connect_b(p, &bd, DCERPC_IREMOTEACTIVATION_UUID, DCERPC_IREMOTEACTIVATION_VERSION, domain, user, pass);
	}

	for (i = 0; i < ARRAY_SIZE(available_transports); i++)
	{
		bd.transport = available_transports[i];
		
		status = dcerpc_pipe_connect_b(p, &bd, DCERPC_IREMOTEACTIVATION_UUID, DCERPC_IREMOTEACTIVATION_VERSION, domain, user, pass);

		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	
	return status;
}

static WERROR dcom_connect_oxid(TALLOC_CTX *mem_ctx, struct dcerpc_pipe **p, HYPER_T oxid)
{
	/* FIXME */
	return WERR_NOT_SUPPORTED;
}

NTSTATUS dcerpc_IUnknown_AddRef(struct dcerpc_pipe *p, struct GUID *o, TALLOC_CTX *mem_ctx, struct IUnknown_AddRef *r) 
{
	/* FIXME: Tell local server we're adding a reference to this interface on this object. Local server can then call RemAddRef() if necessary */
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS dcerpc_IUnknown_Release(struct dcerpc_pipe *p, struct GUID *o, TALLOC_CTX *mem_ctx, struct IUnknown_Release *r)
{
	/* FIXME: Tell local server we're releasing a reference to this interface on this object. Local server can then call RemRelease() if necessary */
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS dcerpc_IUnknown_QueryInterface(struct dcerpc_pipe *p, struct GUID *o, TALLOC_CTX *mem_ctx, struct IUnknown_QueryInterface *r)
{
	/* FIXME: Ask local server for interface pointer. Local server can then 
	 * call RemQueryInterface if necessary */
	return NT_STATUS_NOT_SUPPORTED;
}

WERROR dcom_create_object(TALLOC_CTX *mem_ctx, struct GUID *clsid, const char *server, int num_ifaces, struct GUID *iid, struct dcom_interface **ip, const char *domain, const char *user, const char *pass)
{
	struct RemoteActivation r;
	int i;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	uint16 protseq[] = DCOM_NEGOTIATED_PROTOCOLS;

	status = dcom_connect(&p, server, domain, user, pass);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Unable to connect to %s - %s\n", server, nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	ZERO_STRUCT(r.in);
	r.in.this.version.MajorVersion = 5;
	r.in.this.version.MinorVersion = 1;
	uuid_generate_random(&r.in.this.cid);
	r.in.Clsid = *clsid;
	r.in.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
	r.in.num_protseqs = ARRAY_SIZE(protseq);
	r.in.protseq = protseq;
	r.in.Interfaces = num_ifaces;
	r.in.pIIDs = iid;
	r.out.ifaces = talloc_array_p(mem_ctx, struct pMInterfacePointer, num_ifaces);
	
	status = dcerpc_RemoteActivation(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Error while running RemoteActivation %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	if(!W_ERROR_IS_OK(r.out.result)) { return r.out.result; }
	if(!W_ERROR_IS_OK(r.out.hr)) { return r.out.hr; }
	if(!W_ERROR_IS_OK(r.out.results[0])) { return r.out.results[0]; }

	*ip = talloc_array_p(mem_ctx, struct dcom_interface, num_ifaces);
	for (i = 0; i < num_ifaces; i++) {
		(*ip)[i].object = r.out.ifaces[i].p->obj;
		(*ip)[i].pipe = NULL; /* FIXME */
	}

	return WERR_OK;
}

WERROR dcom_get_class_object(TALLOC_CTX *mem_ctx, struct GUID *clsid, const char *server, struct GUID *iid, struct dcom_interface *ip, const char *domain, const char *user, const char *pass)
{
	struct RemoteActivation r;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	struct pMInterfacePointer pm;
	uint16 protseq[] = DCOM_NEGOTIATED_PROTOCOLS;

	status = dcom_connect(&p, server, domain, user, pass);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Unable to connect to %s - %s\n", server, nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	ZERO_STRUCT(r.in);
	r.in.this.version.MajorVersion = 5;
	r.in.this.version.MinorVersion = 1;
	uuid_generate_random(&r.in.this.cid);
	r.in.Clsid = *clsid;
	r.in.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
	r.in.num_protseqs = ARRAY_SIZE(protseq);
	r.in.protseq = protseq;
	r.in.Interfaces = 1;
	r.in.pIIDs = iid;
	r.in.Mode = MODE_GET_CLASS_OBJECT;
	r.out.ifaces = &pm;

	status = dcerpc_RemoteActivation(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Error while running RemoteActivation - %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	if(!W_ERROR_IS_OK(r.out.result)) { return r.out.result; }
	if(!W_ERROR_IS_OK(r.out.hr)) { return r.out.hr; }
	if(!W_ERROR_IS_OK(r.out.results[0])) { return r.out.results[0]; }

	ip->pipe = NULL; /* FIXME */
	ip->object = pm.p->obj;

	return WERR_OK;
}
