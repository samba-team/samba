/* 
   Unix SMB/CIFS implementation.

   routines for printing some linked list structs in DRSUAPI

   Copyright (C) Stefan (metze) Metzmacher 2005

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
#include "librpc/gen_ndr/ndr_drsuapi.h"


void ndr_print_drsuapi_DsGetNCChangesInfo1(struct ndr_print *ndr, const char *name, struct drsuapi_DsGetNCChangesInfo1 *r)
{
	ndr_print_struct(ndr, name, "drsuapi_DsGetNCChangesInfo1");
	ndr->depth++;
	ndr_print_ptr(ndr, "next", r->next);
	ndr_print_drsuapi_DsReplicaObject(ndr, "object", &r->object);
	ndr_print_uint32(ndr, "unknown1", r->unknown1);
	ndr_print_ptr(ndr, "guid", r->guid);
	ndr->depth++;
	if (r->guid) {
		ndr_print_GUID(ndr, "guid", r->guid);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "meta_data_ctr", r->meta_data_ctr);
	ndr->depth++;
	if (r->meta_data_ctr) {
		ndr_print_drsuapi_DsReplicaMetaDataCtr(ndr, "meta_data_ctr", r->meta_data_ctr);
	}
	ndr->depth--;
	ndr->depth--;
	if (r->next) {
		ndr_print_drsuapi_DsGetNCChangesInfo1(ndr, "next", r->next);
	}
}
