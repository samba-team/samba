/*
   Unix SMB/CIFS implementation.
   Simple class
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
#include "lib/dcom/common/dcom.h"

static struct dcom_IClassFactory_vtable simple_classobject;

NTSTATUS dcom_simple_init(void)
{
	struct GUID iid;
	struct dcom_class simple_class = {
		"Samba.Simple",
	};

	GUID_from_string(DCERPC_IUNKNOWN_UUID, &iid);

	simple_class.class_object = dcom_new_local_ifacep(talloc_autofree_context(),
							  dcom_interface_by_iid(&iid), 
							  &simple_classobject, NULL);

	GUID_from_string("5e9ddec7-5767-11cf-beab-00aa006c3606", &simple_class.clsid);
	return dcom_register_class(&simple_class);
}
