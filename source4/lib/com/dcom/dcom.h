/* 
   Unix SMB/CIFS implementation.
   COM standard objects
   Copyright (C) Jelmer Vernooij					  2004-2005.
   
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

#ifndef _DCOM_H /* _DCOM_H */
#define _DCOM_H 

struct cli_credentials;
struct dcerpc_pipe;

#include "lib/com/com.h"
#include "librpc/gen_ndr/orpc.h"

struct dcom_client_context {
	struct cli_credentials *credentials;
	struct dcom_object_exporter {
		uint64_t oxid;	
		struct DUALSTRINGARRAY bindings;
		struct dcerpc_pipe *pipe;
		struct dcom_object_exporter *prev, *next;
	} *object_exporters;
};

struct dcom_client_context *dcom_client_init(struct com_context *ctx, struct cli_credentials *credentials);
struct dcom_object_exporter *object_exporter_by_oxid(struct com_context *ctx, uint64_t oxid);
struct dcom_object_exporter *object_exporter_by_ip(struct com_context *ctx, struct IUnknown *ip);
WERROR dcom_create_object(struct com_context *ctx, struct GUID *clsid, const char *server, int num_ifaces, struct GUID *iid, struct IUnknown ***ip, WERROR *results);
WERROR dcom_get_class_object(struct com_context *ctx, struct GUID *clsid, const char *server, struct GUID *iid, struct IUnknown **ip);
NTSTATUS dcom_get_pipe(struct IUnknown *iface, struct dcerpc_pipe **pp);
NTSTATUS dcom_OBJREF_from_IUnknown(struct OBJREF *o, struct IUnknown *p);
NTSTATUS dcom_IUnknown_from_OBJREF(struct com_context *ctx, struct IUnknown **_p, struct OBJREF *o);
uint64_t dcom_get_current_oxid(void);

NTSTATUS dcom_register_proxy(struct IUnknown_vtable *proxy_vtable);
struct IUnknown_vtable *dcom_proxy_vtable_by_iid(struct GUID *iid);

#endif /* _DCOM_H */
