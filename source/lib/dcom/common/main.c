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
#include "dlinklist.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_remact.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"
#include "librpc/gen_ndr/ndr_dcom.h"

#define DCOM_NEGOTIATED_PROTOCOLS { EPM_PROTOCOL_TCP, EPM_PROTOCOL_SMB, EPM_PROTOCOL_NCALRPC }

struct dcom_oxid_mapping {
	struct dcom_oxid_mapping *prev, *next;	
	struct DUALSTRINGARRAY bindings;
	HYPER_T oxid;
	struct dcerpc_pipe *pipe;
};

static NTSTATUS dcerpc_binding_from_STRINGBINDING(TALLOC_CTX *mem_ctx, struct dcerpc_binding *b, struct STRINGBINDING *bd)
{
	char *host, *endpoint;

	ZERO_STRUCTP(b);
	
	b->transport = dcerpc_transport_by_endpoint_protocol(bd->wTowerId);

	if (b->transport == -1) {
		DEBUG(1, ("Can't find transport match endpoint protocol %d\n", bd->wTowerId));
		return NT_STATUS_NOT_SUPPORTED;
	}

	host = talloc_strdup(mem_ctx, bd->NetworkAddr);
	endpoint = strchr(host, '[');

	if (endpoint) {
		*endpoint = '\0';
		endpoint++;

		endpoint[strlen(endpoint)-1] = '\0';
	}

	b->host = host;
	b->endpoint = endpoint;

	return NT_STATUS_OK;
}

static NTSTATUS dcom_connect_host(struct dcom_context *ctx, struct dcerpc_pipe **p, const char *server)
{
	struct dcerpc_binding bd;
	enum dcerpc_transport_t available_transports[] = { NCACN_IP_TCP, NCACN_NP };
	int i;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_init("dcom_connect");

	/* Allow server name to contain a binding string */
	if (NT_STATUS_IS_OK(dcerpc_parse_binding(mem_ctx, server, &bd))) {
		status = dcerpc_pipe_connect_b(p, &bd, 
					DCERPC_IREMOTEACTIVATION_UUID, 
					DCERPC_IREMOTEACTIVATION_VERSION, 
					ctx->domain, ctx->user, ctx->password);

		talloc_destroy(mem_ctx);
		return status;
	}
	talloc_destroy(mem_ctx);

	ZERO_STRUCT(bd);
	bd.host = server;
	
	if (server == NULL) { 
		bd.transport = NCALRPC; 
		return dcerpc_pipe_connect_b(p, &bd, 
					DCERPC_IREMOTEACTIVATION_UUID, 
					DCERPC_IREMOTEACTIVATION_VERSION, 
					ctx->domain, ctx->user, ctx->password);
	}

	for (i = 0; i < ARRAY_SIZE(available_transports); i++)
	{
		bd.transport = available_transports[i];
		
		status = dcerpc_pipe_connect_b(p, &bd, 
						DCERPC_IREMOTEACTIVATION_UUID, 
						DCERPC_IREMOTEACTIVATION_VERSION, 
						ctx->domain, ctx->user, ctx->password);

		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	
	return status;
}

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

WERROR dcom_init(struct dcom_context **ctx, const char *domain, const char *user, const char *pass)
{
	*ctx = talloc_p(NULL, struct dcom_context);
	(*ctx)->oxids = NULL;
	(*ctx)->domain = talloc_strdup(*ctx, domain);
	(*ctx)->user = talloc_strdup(*ctx, user);
	(*ctx)->password = talloc_strdup(*ctx, pass);
	
	return WERR_OK;
}

WERROR dcom_create_object(struct dcom_context *ctx, struct GUID *clsid, const char *server, int num_ifaces, struct GUID *iid, struct dcom_interface **ip, WERROR *results)
{
	struct dcom_oxid_mapping *m;
	struct RemoteActivation r;
	int i;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	uint16 protseq[] = DCOM_NEGOTIATED_PROTOCOLS;

	status = dcom_connect_host(ctx, &p, server);
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
	r.out.ifaces = talloc_array_p(ctx, struct pMInterfacePointer, num_ifaces);
	m = talloc_zero_p(ctx, struct dcom_oxid_mapping);
	r.out.pdsaOxidBindings = &m->bindings;
	
	status = dcerpc_RemoteActivation(p, ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Error while running RemoteActivation %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		return r.out.result; 
	}
	
	if(!W_ERROR_IS_OK(r.out.hr)) { 
		return r.out.hr; 
	}

	*ip = talloc_array_p(ctx, struct dcom_interface, num_ifaces);
	for (i = 0; i < num_ifaces; i++) {
		results[i] = r.out.results[i];
		(*ip)[i].private_references = 1;
		(*ip)[i].objref = &r.out.ifaces[i].p->obj;
		(*ip)[i].pipe = NULL;
		(*ip)[i].ctx = ctx;
	}

	/* Add the OXID data for the returned oxid */
	m->oxid = r.out.pOxid;
	m->bindings = *r.out.pdsaOxidBindings;
	DLIST_ADD(ctx->oxids, m);

	return WERR_OK;
}

WERROR dcom_get_class_object(struct dcom_context *ctx, struct GUID *clsid, const char *server, struct GUID *iid, struct dcom_interface *ip)
{
	struct dcom_oxid_mapping *m;
	struct RemoteActivation r;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	struct pMInterfacePointer pm;
	uint16 protseq[] = DCOM_NEGOTIATED_PROTOCOLS;

	status = dcom_connect_host(ctx, &p, server);
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
	m = talloc_zero_p(ctx, struct dcom_oxid_mapping);
	r.out.pdsaOxidBindings = &m->bindings;

	status = dcerpc_RemoteActivation(p, ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Error while running RemoteActivation - %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	if(!W_ERROR_IS_OK(r.out.result)) { return r.out.result; }
	if(!W_ERROR_IS_OK(r.out.hr)) { return r.out.hr; }
	if(!W_ERROR_IS_OK(r.out.results[0])) { return r.out.results[0]; }
	
	/* Set up the interface data */
	ip->private_references = 1;
	ip->pipe = NULL;
	ip->objref = &pm.p->obj;
	ip->ctx = ctx;
	
	/* Add the OXID data for the returned oxid */
	m->oxid = r.out.pOxid;
	m->bindings = *r.out.pdsaOxidBindings;
	DLIST_ADD(ctx->oxids, m);

	return WERR_OK;
}

static struct dcom_oxid_mapping *oxid_mapping_by_oxid (struct dcom_context *ctx, HYPER_T oxid)
{
	struct dcom_oxid_mapping *m;
	
	for (m = ctx->oxids;m;m = m->next) {
		if (m->oxid	== oxid) {
			return m;
		}
	}

	return NULL;
}

NTSTATUS dcom_get_pipe (struct dcom_interface *iface, struct dcerpc_pipe **p)
{
	struct dcom_oxid_mapping *m;
	struct dcerpc_binding binding;
	struct GUID iid;
	HYPER_T oxid;
	NTSTATUS status;
	
	SMB_ASSERT(iface->objref->signature == OBJREF_SIGNATURE);

	if (iface->objref->flags & OBJREF_HANDLER) {
		DEBUG(0, ("dcom_get_pipe: OBJREF_HANDLER not supported!\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (iface->objref->flags & OBJREF_CUSTOM) {
		DEBUG(0, ("dcom_get_pipe: OBJREF_CUSTOM not supported!\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}

	DEBUG(1, ("DCOM: Connecting to %s\n", GUID_string(NULL, &iface->objref->iid)));

	oxid = iface->objref->u_objref.u_standard.std.oxid;
	iid = iface->objref->iid;

	m = oxid_mapping_by_oxid(iface->ctx, oxid);

	/* Add OXID mapping if none present yet */
	if (!m) {
		struct dcerpc_pipe *po;
		struct ResolveOxid r;
		uint16 protseq[] = DCOM_NEGOTIATED_PROTOCOLS;

		DEBUG(3, ("No binding data present yet, resolving OXID %llu\n", oxid));

		m = talloc_zero_p(iface->ctx, struct dcom_oxid_mapping);
		m->oxid = oxid;	

		/* FIXME: Check other string bindings as well, not just 0 */
		status = dcerpc_binding_from_STRINGBINDING(iface->ctx, &binding, iface->objref->u_objref.u_standard.saResAddr.stringbindings[0]);

		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(1, ("Error parsing string binding"));
			return status;
		}

		status = dcerpc_pipe_connect_b(&po, &binding, DCERPC_IOXIDRESOLVER_UUID, DCERPC_IOXIDRESOLVER_VERSION, iface->ctx->domain, iface->ctx->user, iface->ctx->password);

		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(1, ("Error while connecting to OXID Resolver : %s\n", nt_errstr(status)));
			return status;
		}

		r.in.pOxid = oxid;
		r.in.cRequestedProtseqs = ARRAY_SIZE(protseq);
		r.in.arRequestedProtseqs = protseq;
		r.out.ppdsaOxidBindings = &m->bindings;

		status = dcerpc_ResolveOxid(po, iface->ctx, &r);
		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(1, ("Error while resolving OXID: %s\n", nt_errstr(status)));
			return status;
		}

		dcerpc_pipe_close(po);

		DLIST_ADD(iface->ctx->oxids, m);
	}

	if (m->pipe) {
		*p = m->pipe;
		/* FIXME: Switch to correct IID using an alter context call */
		return NT_STATUS_OK;
	}

	/* FIXME: Check other string bindings as well, not just 0 */
	status = dcerpc_binding_from_STRINGBINDING(iface->ctx, &binding, m->bindings.stringbindings[0]);

	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Error parsing string binding"));
		return status;
	}

	status = dcerpc_pipe_connect_b(&m->pipe, &binding, GUID_string(iface->ctx, &iid) , 0.0, iface->ctx->domain, iface->ctx->user, iface->ctx->password);

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	DEBUG(2, ("Successfully connected to OXID %llx\n", oxid));
	
	*p = m->pipe;
	return NT_STATUS_OK;
}
