/* 
   Unix SMB/CIFS implementation.
   DCOM standard objects
   Copyright (C) Jelmer Vernooij					  2004.
   
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

#include "librpc/ndr/ndr_dcom.h"

struct IUnknown_AddRef;
struct IUnknown_Release;
struct IUnknown_QueryInterface;

struct dcom_context 
{
	struct dcom_object_exporter {
		struct dcom_object_exporter *prev, *next;
		struct STRINGARRAY resolver_address;
		struct DUALSTRINGARRAY bindings;
		HYPER_T oxid;
		struct dcerpc_pipe *pipe;
		struct dcom_object
		{
			struct dcom_object *prev, *next;
			HYPER_T oid;
			void *private_data;
		} *objects;
	} *oxids;
	const char *domain;
	const char *user;
	const char *password;
	uint32_t dcerpc_flags;
};

/* Specific implementation of one or more interfaces */
struct dcom_class
{
	const char *prog_id;
	struct GUID clsid;
	void (*get_class_object) (struct GUID *iid, void **vtable);
};

struct dcom_interface
{
	struct GUID iid;
	int num_methods;
	struct GUID base_iid;
	const void *proxy_vtable;
};

struct dcom_interface_p
{
	struct dcom_context *ctx;
	const struct dcom_interface *interface;
	const void *vtable; /* Points to one of the available implementations */
	struct GUID ipid;
	struct dcom_object *object;
	int objref_flags;
	int orpc_flags;
	struct dcom_object_exporter *ox;
	uint32_t private_references;
};

#endif /* _DCOM_H */
