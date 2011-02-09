/* 
   Unix SMB/CIFS implementation.

   libndr interface

   Copyright (C) Andrew Tridgell 2003
   
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
#include "librpc/ndr/util.h"

enum ndr_err_code ndr_push_server_id(struct ndr_push *ndr, int ndr_flags, const struct server_id *r)
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
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_server_id(struct ndr_pull *ndr, int ndr_flags, struct server_id *r)
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
	return NDR_ERR_SUCCESS;
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

_PUBLIC_ void ndr_print_sockaddr_storage(struct ndr_print *ndr, const char *name, const struct sockaddr_storage *ss)
{
	char addr[INET6_ADDRSTRLEN];
	ndr->print(ndr, "%-25s: %s", name, print_sockaddr(addr, sizeof(addr), ss));
}
