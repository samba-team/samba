/* 
   Unix SMB/CIFS implementation.
   ID Mapping
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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.*/

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct idmap_function_entry {
	const char *name;
	struct idmap_methods *methods;
	struct idmap_function_entry *prev,*next;
};

static struct idmap_function_entry *backends = NULL;

static struct idmap_methods *local_map;
static struct idmap_methods *remote_map;

static void lazy_initialize_idmap(void)
{
	static BOOL initialized = False;

	if(!initialized) {
		idmap_init();
		initialized = True;
	}
}

static struct idmap_methods *get_methods(const char *name)
{
	struct idmap_function_entry *entry = backends;

	while(entry) {
		if (strcmp(entry->name, name) == 0) return entry->methods;
		entry = entry->next;
	}

	return NULL;
}

NTSTATUS smb_register_idmap(int version, const char *name, struct idmap_methods *methods)
{
	struct idmap_function_entry *entry;

 	if ((version != SMB_IDMAP_INTERFACE_VERSION)) {
		DEBUG(0, ("Failed to register idmap module.\n"
		          "The module was compiled against SMB_IDMAP_INTERFACE_VERSION %d,\n"
		          "current SMB_IDMAP_INTERFACE_VERSION is %d.\n"
		          "Please recompile against the current version of samba!\n",  
			  version, SMB_IDMAP_INTERFACE_VERSION));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
  	}

	if (!name || !name[0] || !methods) {
		DEBUG(0,("smb_register_idmap() called with NULL pointer or empty name!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (get_methods(name)) {
		DEBUG(0,("idmap module %s already registered!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = smb_xmalloc(sizeof(struct idmap_function_entry));
	entry->name = smb_xstrdup(name);
	entry->methods = methods;

	DLIST_ADD(backends, entry);
	DEBUG(5, ("Successfully added idmap backend '%s'\n", name));
	return NT_STATUS_OK;
}

/* Initialize backend */
BOOL idmap_init(void)
{
	const char *remote_backend = lp_idmap_backend();

	if (!backends)
		static_init_idmap;

	if (!local_map) {
		local_map = get_methods("tdb");

		if (!local_map) {
			DEBUG(0, ("idmap_init: could not find tdb backend!\n"));
			return False;
		}
		
		if (NT_STATUS_IS_ERR(local_map->init( NULL ))) {
			DEBUG(0, ("idmap_init: could not load or create local backend!\n"));
			return False;
		}
	}
	
	if (!remote_map && remote_backend && *remote_backend != 0) {
		fstring params = "";
		char *pparams;
		
		/* get any mode parameters passed in */
		
		if ( (pparams = strchr( remote_backend, ':' )) != NULL ) {
			pparams = '\0';
			pparams++;
			fstrcpy( params, pparams );
		}
		
		DEBUG(3, ("idmap_init: using '%s' as remote backend\n", remote_backend));
		
		if((remote_map = get_methods(remote_backend)) ||
		    (NT_STATUS_IS_OK(smb_probe_module("idmap", remote_backend)) && 
		    (remote_map = get_methods(remote_backend)))) {
			remote_map->init(params);
		} else {
			DEBUG(0, ("idmap_init: could not load remote backend '%s'\n", remote_backend));
			return False;
		}

	}

	return True;
}

NTSTATUS idmap_set_mapping(const DOM_SID *sid, unid_t id, int id_type)
{
	NTSTATUS ret;

	lazy_initialize_idmap();

	ret = local_map->set_mapping(sid, id, id_type);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG (0, ("idmap_set_mapping: Error, unable to modify local cache!\n"));
		DEBUGADD(0, ("Error: %s", nt_errstr(ret)));
		return ret;
	}

	/* Being able to update the remote cache is seldomly right.
	   Generally this is a forbidden operation. */
	if (!(id_type & ID_CACHE) && (remote_map != NULL)) {
		remote_map->set_mapping(sid, id, id_type);
		if (NT_STATUS_IS_ERR(ret)) {
			DEBUG (0, ("idmap_set_mapping: Error, unable to modify remote cache!\n"));
			DEBUGADD(0, ("Error: %s", nt_errstr(ret)));
		}
	}

	return ret;
}

/* Get ID from SID */
NTSTATUS idmap_get_id_from_sid(unid_t *id, int *id_type, const DOM_SID *sid)
{
	NTSTATUS ret;
	int loc_type;

	lazy_initialize_idmap();

	loc_type = *id_type;
	if (remote_map) { /* We have a central remote idmap */
		loc_type |= ID_NOMAP;
	}
	ret = local_map->get_id_from_sid(id, &loc_type, sid);
	if (NT_STATUS_IS_ERR(ret)) {
		if (remote_map) {
			ret = remote_map->get_id_from_sid(id, id_type, sid);
			if (NT_STATUS_IS_ERR(ret)) {
				DEBUG(3, ("idmap_get_id_from_sid: error fetching id!\n"));
				return ret;
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

	lazy_initialize_idmap();

	loc_type = id_type;
	if (remote_map) {
		loc_type = id_type | ID_NOMAP;
	}
	ret = local_map->get_sid_from_id(sid, id, loc_type);
	if (NT_STATUS_IS_ERR(ret)) {
		if (remote_map) {
			ret = remote_map->get_sid_from_id(sid, id, id_type);
			if (NT_STATUS_IS_ERR(ret)) {
				DEBUG(3, ("idmap_get_sid_from_id: unable to fetch sid!\n"));
				return ret;
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

	ret = local_map->close();
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(3, ("idmap_close: failed to close local cache!\n"));
	}

	if (remote_map) {
		ret = remote_map->close();
		if (NT_STATUS_IS_ERR(ret)) {
			DEBUG(3, ("idmap_close: failed to close remote idmap repository!\n"));
		}
	}

	return ret;
}

/* Dump backend status */
void idmap_status(void)
{
	lazy_initialize_idmap();

	local_map->status();
	if (remote_map) remote_map->status();
}
