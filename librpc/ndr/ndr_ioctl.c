/*
   Unix SMB/CIFS implementation.

   Manually parsed structures for IOCTL/FSCTL

   Copyright (C) Stefan Metzmacher 2014

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
#include "librpc/gen_ndr/ndr_ioctl.h"

_PUBLIC_ void ndr_print_fsctl_net_iface_info(struct ndr_print *ndr, const char *name, const struct fsctl_net_iface_info *r)
{
	ndr_print_struct(ndr, name, "fsctl_net_iface_info");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	ndr_print_ptr(ndr, "next", r->next);
	ndr_print_uint32(ndr, "ifindex", r->ifindex);
	ndr_print_fsctl_net_iface_capability(ndr, "capability", r->capability);
	ndr_print_uint32(ndr, "reserved", (ndr->flags & LIBNDR_PRINT_SET_VALUES)?0:r->reserved);
	ndr_print_hyper(ndr, "linkspeed", r->linkspeed);
	ndr_print_fsctl_sockaddr_storage(ndr, "sockaddr", &r->sockaddr);
	ndr->depth--;
	if (r->next) {
		ndr_print_fsctl_net_iface_info(ndr, "next", r->next);
	}
}
