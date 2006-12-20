/* 
   Unix SMB/CIFS implementation.

   routines for printing some linked list structs in DRSUAPI

   Copyright (C) Stefan (metze) Metzmacher 2005-2006

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

#ifndef _LIBRPC_NDR_NDR_DRSUAPI_H
#define _LIBRPC_NDR_NDR_DRSUAPI_H

void ndr_print_drsuapi_DsReplicaObjectListItem(struct ndr_print *ndr, const char *name, 
					       const struct drsuapi_DsReplicaObjectListItem *r);

void ndr_print_drsuapi_DsReplicaObjectListItemEx(struct ndr_print *ndr, const char *name,
						 const struct drsuapi_DsReplicaObjectListItemEx *r);

NTSTATUS ndr_push_drsuapi_DsReplicaOID(struct ndr_push *ndr, int ndr_flags, const struct drsuapi_DsReplicaOID *r);
NTSTATUS ndr_pull_drsuapi_DsReplicaOID(struct ndr_pull *ndr, int ndr_flags, struct drsuapi_DsReplicaOID *r);
size_t ndr_size_drsuapi_DsReplicaOID_oid(const char *oid, int flags);

#endif /* _LIBRPC_NDR_NDR_DRSUAPI_H */
