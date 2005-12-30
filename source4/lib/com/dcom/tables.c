/*
   Unix SMB/CIFS implementation.
   DCOM proxy tables functionality
   Copyright (C) 2005 Jelmer Vernooij <jelmer@samba.org>

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
#include "librpc/gen_ndr/com_dcom.h"

static struct dcom_proxy {
	struct IUnknown_vtable *vtable;
	struct dcom_proxy *prev, *next;
}  *proxies = NULL;

NTSTATUS dcom_register_proxy(struct IUnknown_vtable *proxy_vtable)
{
	struct dcom_proxy *proxy = talloc(talloc_autofree_context(), struct dcom_proxy);

	proxy->vtable = proxy_vtable;
	DLIST_ADD(proxies, proxy);

	return NT_STATUS_OK;
}

struct IUnknown_vtable *dcom_proxy_vtable_by_iid(struct GUID *iid)
{
	struct dcom_proxy *p;
	for (p = proxies; p; p = p->next) {
		if (GUID_equal(&p->vtable->iid, iid)) {
			return p->vtable;
		}
	}
	return NULL;
}
