/* 
   Unix SMB/CIFS implementation.

   UUID/GUID/policy_handle functions

   Copyright (C) Theodore Ts'o               1996, 1997,
   Copyright (C) Jim McDonough                     2002.
   Copyright (C) Andrew Tridgell                   2003.
   Copyright (C) Stefan (metze) Metzmacher         2004.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

NTSTATUS ndr_push_GUID(struct ndr_push *ndr, int ndr_flags, const struct GUID *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->time_low));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->time_mid));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->time_hi_and_version));
		NDR_CHECK(ndr_push_array_uint8(ndr, NDR_SCALARS, r->clock_seq, 2));
		NDR_CHECK(ndr_push_array_uint8(ndr, NDR_SCALARS, r->node, 6));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_GUID(struct ndr_pull *ndr, int ndr_flags, struct GUID *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->time_low));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->time_mid));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->time_hi_and_version));
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->clock_seq, 2));
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->node, 6));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NT_STATUS_OK;
}

size_t ndr_size_GUID(const struct GUID *r, int flags)
{
	return ndr_size_struct(r, flags, (ndr_push_flags_fn_t)ndr_push_GUID);
}

/**
 * see if a range of memory is all zero. A NULL pointer is considered
 * to be all zero 
 */
bool all_zero(const uint8_t *ptr, size_t size)
{
	int i;
	if (!ptr) return True;
	for (i=0;i<size;i++) {
		if (ptr[i]) return False;
	}
	return True;
}

void ndr_print_GUID(struct ndr_print *ndr, const char *name, const struct GUID *guid)
{
	ndr->print(ndr, "%-25s: %s", name, GUID_string(ndr, guid));
}

NTSTATUS ndr_push_policy_handle(struct ndr_push *ndr, int ndr_flags, const struct policy_handle *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->handle_type));
		NDR_CHECK(ndr_push_GUID(ndr, NDR_SCALARS, &r->uuid));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_policy_handle(struct ndr_pull *ndr, int ndr_flags, struct policy_handle *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->handle_type));
		NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &r->uuid));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NT_STATUS_OK;
}

void ndr_print_policy_handle(struct ndr_print *ndr, const char *name, const struct policy_handle *r)
{
	ndr_print_struct(ndr, name, "policy_handle");
	ndr->depth++;
	ndr_print_uint32(ndr, "handle_type", r->handle_type);
	ndr_print_GUID(ndr, "uuid", &r->uuid);
	ndr->depth--;
}

NTSTATUS ndr_push_server_id(struct ndr_push *ndr, int ndr_flags, const struct server_id *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS,
					  (uint32_t)r->pid));
#ifdef CLUSTER_SUPPORT
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS,
					  (uint32_t)r->vnn));
#endif
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_server_id(struct ndr_pull *ndr, int ndr_flags, struct server_id *r)
{
	if (ndr_flags & NDR_SCALARS) {
		uint32_t pid;
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &pid));
#ifdef CLUSTER_SUPPORT
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->vnn));
#endif
		r->pid = (pid_t)pid;
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NT_STATUS_OK;
}

void ndr_print_server_id(struct ndr_print *ndr, const char *name, const struct server_id *r)
{
	ndr_print_struct(ndr, name, "server_id");
	ndr->depth++;
	ndr_print_uint32(ndr, "id", (uint32_t)r->pid);
#ifdef CLUSTER_SUPPORT
	ndr_print_uint32(ndr, "vnn", (uint32_t)r->vnn);
#endif
	ndr->depth--;
}
