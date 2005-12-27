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
#include "system/filesys.h"
#include "dlinklist.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_remact.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/gen_ndr/com_dcom.h"
#include "lib/com/dcom/dcom.h"

#define DCOM_NEGOTIATED_PROTOCOLS { EPM_PROTOCOL_TCP, EPM_PROTOCOL_SMB, EPM_PROTOCOL_NCALRPC }

struct dcom_client_context *dcom_client_init(struct com_context *ctx, struct cli_credentials *credentials)
{
	ctx->dcom = talloc(ctx, struct dcom_client_context);
	ctx->dcom->credentials = credentials;

	return ctx->dcom;
}

static NTSTATUS dcerpc_binding_from_STRINGBINDING(TALLOC_CTX *mem_ctx, struct dcerpc_binding **b_out, struct STRINGBINDING *bd)
{
	char *host, *endpoint;
	struct dcerpc_binding *b;

	b = talloc_zero(mem_ctx, struct dcerpc_binding);
	if (!b) {
		return NT_STATUS_NO_MEMORY;
	}
	
	b->transport = dcerpc_transport_by_endpoint_protocol(bd->wTowerId);

	if (b->transport == -1) {
		DEBUG(1, ("Can't find transport match endpoint protocol %d\n", bd->wTowerId));
		return NT_STATUS_NOT_SUPPORTED;
	}

	host = talloc_strdup(b, bd->NetworkAddr);
	endpoint = strchr(host, '[');

	if (endpoint) {
		*endpoint = '\0';
		endpoint++;

		endpoint[strlen(endpoint)-1] = '\0';
	}

	b->host = host;
	b->endpoint = talloc_strdup(b, endpoint);

	*b_out = b;
	return NT_STATUS_OK;
}

static NTSTATUS dcom_connect_host(struct com_context *ctx, struct dcerpc_pipe **p, const char *server)
{
	struct dcerpc_binding *bd;
	const char * available_transports[] = { "ncacn_ip_tcp", "ncacn_np" };
	int i;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_init("dcom_connect");

	if (server == NULL) { 
		return dcerpc_pipe_connect(ctx, p, "ncalrpc", 
								   &dcerpc_table_IRemoteActivation,
					   			   ctx->dcom->credentials, ctx->event_ctx);
	}

	/* Allow server name to contain a binding string */
	if (NT_STATUS_IS_OK(dcerpc_parse_binding(mem_ctx, server, &bd))) {
		status = dcerpc_pipe_connect_b(ctx, p, bd, 
									   &dcerpc_table_IRemoteActivation,
					       			   ctx->dcom->credentials, ctx->event_ctx);

		talloc_free(mem_ctx);
		return status;
	}

	for (i = 0; i < ARRAY_SIZE(available_transports); i++)
	{
		char *binding = talloc_asprintf(mem_ctx, "%s:%s", available_transports[i], server);
		if (!binding) {
			talloc_free(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		
		status = dcerpc_pipe_connect(ctx, p, binding, 
									 &dcerpc_table_IRemoteActivation,
					     ctx->dcom->credentials, ctx->event_ctx);

		if (NT_STATUS_IS_OK(status)) {
			talloc_free(mem_ctx);
			return status;
		}
	}
	
	talloc_free(mem_ctx);
	return status;
}

struct dcom_object_exporter *object_exporter_by_oxid(struct com_context *ctx, uint64_t oxid)
{
	struct dcom_object_exporter *ox;
	for (ox = ctx->dcom->object_exporters; ox; ox = ox->next) {
		if (ox->oxid == oxid) {
			return ox;
		}
	}

	return NULL; 
}

struct dcom_object_exporter *object_exporter_by_ip(struct com_context *ctx, struct IUnknown *ip)
{
	return NULL; /* FIXME */
}

WERROR dcom_create_object(struct com_context *ctx, struct GUID *clsid, const char *server, int num_ifaces, struct GUID *iid, struct IUnknown ***ip, WERROR *results)
{
	uint16_t protseq[] = DCOM_NEGOTIATED_PROTOCOLS;
	struct dcerpc_pipe *p;
	struct dcom_object_exporter *m;
	NTSTATUS status;
	struct RemoteActivation r;
	struct DUALSTRINGARRAY dualstring;
	int i;

	status = dcom_connect_host(ctx, &p, server);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Unable to connect to %s - %s\n", server, nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	ZERO_STRUCT(r.in);
	r.in.this.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.this.version.MinorVersion = COM_MINOR_VERSION;
	r.in.this.cid = GUID_random();
	r.in.Clsid = *clsid;
	r.in.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
	r.in.num_protseqs = ARRAY_SIZE(protseq);
	r.in.protseq = protseq;
	r.in.Interfaces = num_ifaces;
	r.in.pIIDs = iid;
	r.out.ifaces = talloc_array(ctx, struct MInterfacePointer *, num_ifaces);
	r.out.pdsaOxidBindings = &dualstring;
	
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

	*ip = talloc_array(ctx, struct IUnknown *, num_ifaces);
	for (i = 0; i < num_ifaces; i++) {
		results[i] = r.out.results[i];
		(*ip)[i] = NULL;
		if (W_ERROR_IS_OK(results[i])) {
			status = dcom_IUnknown_from_OBJREF(ctx, &(*ip)[i], &r.out.ifaces[i]->obj);
			if (!NT_STATUS_IS_OK(status)) {
				results[i] = ntstatus_to_werror(status);
			}
		}
	}

	/* Add the OXID data for the returned oxid */
	m = object_exporter_by_oxid(ctx, r.out.pOxid);
	m->bindings = *r.out.pdsaOxidBindings;
	
	return WERR_OK;
}

WERROR dcom_get_class_object(struct com_context *ctx, struct GUID *clsid, const char *server, struct GUID *iid, struct IUnknown **ip)
{
	struct dcom_object_exporter *m;
	struct RemoteActivation r;
	struct dcerpc_pipe *p;
	struct DUALSTRINGARRAY dualstring;
	NTSTATUS status;
	struct MInterfacePointer pm;
	struct MInterfacePointer *ifaces[1];
	uint16_t protseq[] = DCOM_NEGOTIATED_PROTOCOLS;

	if (!server) {
		return com_get_class_object(ctx, clsid, iid, ip);
	}

	status = dcom_connect_host(ctx, &p, server);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Unable to connect to %s - %s\n", server, nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	ZERO_STRUCT(r.in);
	r.in.this.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.this.version.MinorVersion = COM_MINOR_VERSION;
	r.in.this.cid = GUID_random();
	r.in.Clsid = *clsid;
	r.in.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
	r.in.num_protseqs = ARRAY_SIZE(protseq);
	r.in.protseq = protseq;
	r.in.Interfaces = 1;
	r.in.pIIDs = iid;
	r.in.Mode = MODE_GET_CLASS_OBJECT;
	r.out.ifaces = ifaces;
	ifaces[0] = &pm;
	r.out.pdsaOxidBindings = &dualstring;

	status = dcerpc_RemoteActivation(p, ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Error while running RemoteActivation - %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	if(!W_ERROR_IS_OK(r.out.result)) { return r.out.result; }
	if(!W_ERROR_IS_OK(r.out.hr)) { return r.out.hr; }
	if(!W_ERROR_IS_OK(r.out.results[0])) { return r.out.results[0]; }
	
	/* Set up the interface data */
	dcom_IUnknown_from_OBJREF(ctx, ip, &pm.obj);
	
	/* Add the OXID data for the returned oxid */
	m = object_exporter_by_oxid(ctx, r.out.pOxid);
	m->bindings = *r.out.pdsaOxidBindings;

	return WERR_OK;
}

NTSTATUS dcom_get_pipe(struct IUnknown *iface, struct dcerpc_pipe **pp)
{
	struct dcerpc_binding *binding;
	struct GUID iid;
	uint64_t oxid;
	NTSTATUS status;
	int i;
	struct dcerpc_pipe *p;
	TALLOC_CTX *tmp_ctx;
	const char *uuid;
	struct dcom_object_exporter *ox;

	ox = object_exporter_by_ip(iface->ctx, iface);

	tmp_ctx = talloc_new(NULL);

	p = ox->pipe;
	
	iid = iface->vtable->iid;

	uuid = GUID_string(tmp_ctx, &iid);
	
	if (p) {
		if (!GUID_equal(&p->syntax.uuid, &iid)) {
			struct dcerpc_pipe *p2;
			ox->pipe->syntax.uuid = iid;

			/* interface will always be present, so 
			 * idl_iface_by_uuid can't return NULL */
			status = dcerpc_secondary_context(p, &p2, idl_iface_by_uuid(uuid));

			if (NT_STATUS_IS_OK(status)) {
				p = p2;
			}
		} else {
			p = talloc_reference(NULL, p);
		}
		*pp = p;
		talloc_free(tmp_ctx);
		return status;
	}

	i = 0;
	do {
		status = dcerpc_binding_from_STRINGBINDING(iface->ctx, &binding, 
							   ox->bindings.stringbindings[i]);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Error parsing string binding"));
		} else {
			status = dcerpc_pipe_connect_b(NULL, &p, binding, 
						       idl_iface_by_uuid(uuid),
						       iface->ctx->dcom->credentials,
							   iface->ctx->event_ctx);
		}
		talloc_free(binding);
		i++;
	} while (!NT_STATUS_IS_OK(status) && ox->bindings.stringbindings[i]);

	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Unable to connect to remote host - %s\n", nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}

	DEBUG(2, ("Successfully connected to OXID %llx\n", (long long)oxid));
	
	*pp = p;
	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

NTSTATUS dcom_OBJREF_from_IUnknown(struct OBJREF *o, struct IUnknown *p)
{
	/* FIXME: Cache generated objref objects? */
	ZERO_STRUCTP(o);
	
	o->signature = OBJREF_SIGNATURE;
	
	if (!p) {
		o->flags = OBJREF_NULL;
	} else {
		o->iid = p->vtable->iid;
		/* 
		OBJREF_STANDARD
		OBJREF_CUSTOM
		OBJREF_HANDLER
		*/
	}

	return NT_STATUS_NOT_IMPLEMENTED;	
}

NTSTATUS dcom_IUnknown_from_OBJREF(struct com_context *ctx, struct IUnknown **_p, struct OBJREF *o)
{
	struct IUnknown *p;
	struct dcom_object_exporter *ox;

	switch(o->flags) {
	case OBJREF_NULL: 
		*_p = NULL;
		return NT_STATUS_OK;
		
	case OBJREF_STANDARD:
		p = talloc(ctx, struct IUnknown);
		p->ctx = ctx;	
		p->vtable = dcom_proxy_vtable_by_iid(&o->iid);
		if (!p->vtable) {
			DEBUG(0, ("Unable to find proxy class for interface with IID %s\n", GUID_string(ctx, &o->iid)));
			return NT_STATUS_NOT_SUPPORTED;
		}

		ox = object_exporter_by_oxid(ctx, o->u_objref.u_standard.std.oxid);
		/* FIXME: Add object to list of objects to ping */
		*_p = p;
		return NT_STATUS_OK;
		
	case OBJREF_HANDLER:
		p = talloc(ctx, struct IUnknown);
		p->ctx = ctx;	
		ox = object_exporter_by_oxid(ctx, o->u_objref.u_handler.std.oxid );
		/* FIXME: Add object to list of objects to ping */
/*FIXME		p->vtable = dcom_vtable_by_clsid(&o->u_objref.u_handler.clsid);*/
		/* FIXME: Do the custom unmarshaling call */
	
		*_p = p;
		return NT_STATUS_OK;
		
	case OBJREF_CUSTOM:
		p = talloc(ctx, struct IUnknown);
		p->ctx = ctx;	
		p->vtable = NULL;
		/* FIXME: Do the actual custom unmarshaling call */
		*_p = p;
		return NT_STATUS_NOT_SUPPORTED;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

uint64_t dcom_get_current_oxid(void)
{
	return getpid();
}
