/* 
   Unix SMB/CIFS implementation.
   Winbind ID Mapping
   Copyright (C) Tim Potter 2000
   Copyright (C) Anthony Liguori <aliguor@us.ibm.com>	2003
   Copyright (C) Simo Sorce 2003

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
#include "idmap.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

static struct {

	const char *name;
	/* Function to create a member of the idmap_methods list */
	NTSTATUS (*reg_meth)(struct idmap_methods **methods);
	struct idmap_methods *methods;
} builtin_idmap_functions[] = {
	{ "tdb", idmap_reg_tdb, NULL },
	/* { "ldap", idmap_reg_ldap, NULL },*/
	{ NULL, NULL, NULL }
};

/* singleton pattern: uberlazy evaluation */
static struct idmap_methods *impl;

static struct idmap_methods *get_impl(const char *name)
{
	int i = 0;
	struct idmap_methods *ret = NULL;

	while (builtin_idmap_functions[i].name && strcmp(builtin_idmap_functions[i].name, name)) {
		i++;
	}

	if (builtin_idmap_functions[i].name) {

		if (!builtin_idmap_functions[i].methods) {
			builtin_idmap_functions[i].reg_meth(&builtin_idmap_functions[i].methods);
		}

		ret = builtin_idmap_functions[i].methods;
	}

	return ret;
}

/* Load idmap backend functions */
BOOL set_impl(void)
{
	if (!impl) {
		DEBUG(3, ("idmap_init: using '%s' as backend\n", lp_idmap_backend()));
		
		impl = get_impl(lp_idmap_backend());
		if (!impl) {
			DEBUG(0, ("set_impl: could not load backend '%s'\n", lp_idmap_backend()));
			return False;
		}
	}
	return True;
}

/* Initialize backend */
NTSTATUS idmap_init(void)
{
	NTSTATUS ret;

	if (!set_impl()) return NT_STATUS_UNSUCCESSFUL;

	ret = impl->init();
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(3, ("idmap_init: init failed!\n"));
	}

	return ret;
}

/* Get ID from SID */
NTSTATUS idmap_get_id_from_sid(id_t *id, int *id_type, DOM_SID *sid)
{
	NTSTATUS ret;

	if (!set_impl()) return NT_STATUS_UNSUCCESSFUL;

	ret = impl->get_id_from_sid(id, id_type, sid);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(3, ("idmap_get_id_from_sid: error fetching id!\n"));
	}

	return ret;
}

/* Get SID from ID */
NTSTATUS idmap_get_sid_from_id(DOM_SID *sid, id_t id, int id_type)
{
	NTSTATUS ret;

	if (!set_impl()) return NT_STATUS_UNSUCCESSFUL;

	ret = impl->get_sid_from_id(sid, id, id_type);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(3, ("idmap_get_sid_from_id: error fetching sid!\n"));
	}

	return ret;
}


/* Close backend */
NTSTATUS idmap_close(void)
{
	NTSTATUS ret;

	if (!set_impl()) return NT_STATUS_UNSUCCESSFUL;

	ret = impl->close();
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(3, ("idmap_close: close failed!\n"));
	}

	return ret;
}

/* Dump backend status */
void idmap_status(void)
{
	if (!set_impl()) return;

	impl->status();
}

