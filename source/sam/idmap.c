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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

static struct {

	const char *name;
	/* Function to create a member of the idmap_methods list */
	NTSTATUS (*reg_meth)(struct idmap_methods **methods);
	struct idmap_methods *methods;

} remote_idmap_functions[] = {

	{ "tdb", idmap_reg_tdb, NULL },
	/* { "ldap", idmap_reg_ldap, NULL },*/
	{ NULL, NULL, NULL }

};

static struct idmap_methods *local_cache;
static struct idmap_methods *remote_repo;

static struct idmap_methods *get_methods(const char *name)
{
	int i = 0;
	struct idmap_methods *ret = NULL;

	while (remote_idmap_functions[i].name && strcmp(remote_idmap_functions[i].name, name)) {
		i++;
	}

	if (remote_idmap_functions[i].name) {

		if (!remote_idmap_functions[i].methods) {
			remote_idmap_functions[i].reg_meth(&remote_idmap_functions[i].methods);
		}

		ret = remote_idmap_functions[i].methods;
	}

	return ret;
}

/* Load idmap backend functions */
BOOL load_methods(void)
{
	if (!local_cache) {
		idmap_reg_tdb(&local_cache);
	}
	
	if (!remote_repo && lp_idmap_backend()) {
		DEBUG(3, ("load_methods: using '%s' as remote backend\n", lp_idmap_backend()));
		
		remote_repo = get_methods(lp_idmap_backend());
		if (!remote_repo) {
			DEBUG(0, ("load_methods: could not load remote backend '%s'\n", lp_idmap_backend()));
			return False;
		}
	}

	idmap_init();

	return True;
}

/* Initialize backend */
NTSTATUS idmap_init(void)
{
	NTSTATUS ret;

	ret = remote_repo->init("idmap.tdb");
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(3, ("idmap_init: init failed!\n"));
	}

	return ret;
}

static NTSTATUS idmap_set_mapping(DOM_SID *sid, unid_t id, int id_type)
{
	NTSTATUS ret;

	if (!load_methods()) return NT_STATUS_UNSUCCESSFUL;

	ret = local_cache->set_mapping(sid, id, id_type);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG (0, ("idmap_set_mapping: Error, unable to modify local cache!\n"));
		return ret;
	}

	/* Being able to update the remote cache is seldomly right.
	   Generally this is a forbidden operation. */
	if (!(id_type & ID_CACHE) && (remote_repo != NULL)) {
		remote_repo->set_mapping(sid, id, id_type);
		if (NT_STATUS_IS_ERR(ret)) {
			DEBUG (0, ("idmap_set_mapping: Error, unable to modify remote cache!\n"));
		}
	}

	return ret;
}

/* Get ID from SID */
NTSTATUS idmap_get_id_from_sid(unid_t *id, int *id_type, DOM_SID *sid)
{
	NTSTATUS ret;
	int loc_type;

	if (!load_methods()) return NT_STATUS_UNSUCCESSFUL;

	loc_type = *id_type;
	if (remote_repo) { /* We have a central remote idmap */
		loc_type |= ID_NOMAP;
	}
	ret = local_cache->get_id_from_sid(id, &loc_type, sid);
	if (NT_STATUS_IS_ERR(ret)) {
		if (remote_repo) {
			ret = remote_repo->get_id_from_sid(id, id_type, sid);
			if (NT_STATUS_IS_ERR(ret)) {
				DEBUG(3, ("idmap_get_id_from_sid: error fetching id!\n"));
			} else {
				loc_type |= ID_CACHE;
				idmap_set_mapping(sid, *id, loc_type);
			}
		}
	} else {
		*id_type = loc_type & ID_TYPEMASK;
	}

	return ret;
}

/* Get SID from ID */
NTSTATUS idmap_get_sid_from_id(DOM_SID *sid, unid_t id, int id_type)
{
	NTSTATUS ret;
	int loc_type;

	if (!load_methods()) return NT_STATUS_UNSUCCESSFUL;

	loc_type = id_type;
	if (remote_repo) {
		loc_type = id_type | ID_NOMAP;
	}
	ret = local_cache->get_sid_from_id(sid, id, loc_type);
	if (NT_STATUS_IS_ERR(ret)) {
		if (remote_repo) {
			ret = remote_repo->get_sid_from_id(sid, id, id_type);
			if (NT_STATUS_IS_ERR(ret)) {
				DEBUG(3, ("idmap_get_sid_from_id: unable to fetch sid!\n"));
			} else {
				loc_type |= ID_CACHE;
				idmap_set_mapping(sid, id, loc_type);
			}
		}
	}

	return ret;
}

/* Close backend */
NTSTATUS idmap_close(void)
{
	NTSTATUS ret;

	if (!load_methods()) return NT_STATUS_UNSUCCESSFUL;

	ret = local_cache->close();
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(3, ("idmap_close: failed to close local cache!\n"));
	}

	if (remote_repo) {
		ret = remote_repo->close();
		if (NT_STATUS_IS_ERR(ret)) {
			DEBUG(3, ("idmap_close: failed to close remote idmap repository!\n"));
		}
	}

	return ret;
}

/* Dump backend status */
void idmap_status(void)
{
	if (load_methods()) {
		local_cache->status();
		remote_repo->status();
	}
}

