/* 
   Unix SMB/CIFS implementation.

   idmap Winbind backend

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

/* Get a sid from an id */
static NTSTATUS db_get_sid_from_id(DOM_SID *sid, unid_t id, int id_type) {
	switch (id_type & ID_TYPEMASK) {
		case ID_USERID:
			if (winbind_uid_to_sid(sid, id.uid)) {
				return NT_STATUS_OK;
			}
			break;
		case ID_GROUPID:
			if (winbind_gid_to_sid(sid, id.gid)) {
				return NT_STATUS_OK;
			}
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_UNSUCCESSFUL;
}

/* Get an id from a sid */
static NTSTATUS db_get_id_from_sid(unid_t *id, int *id_type, const DOM_SID *sid) {
	switch (*id_type & ID_TYPEMASK) {
		case ID_USERID:
			if (winbind_sid_to_uid(&((*id).uid), sid)) {
				return NT_STATUS_OK;
			}
			break;
		case ID_GROUPID:
			if (winbind_sid_to_gid(&((*id).gid), sid)) {
				return NT_STATUS_OK;
			}
			break;
		default:
			if (winbind_sid_to_uid(&((*id).uid), sid) ||
			    winbind_sid_to_gid(&((*id).gid), sid)) {
				return NT_STATUS_OK;
			}
	}

	return NT_STATUS_UNSUCCESSFUL;
}	

static NTSTATUS db_set_mapping(DOM_SID *sid, unid_t id, int id_type) {
	return NT_STATUS_UNSUCCESSFUL;
}

/*****************************************************************************
 Initialise idmap database. 
*****************************************************************************/
static NTSTATUS db_init(const char *db_name) {
	return NT_STATUS_OK;
}

/* Close the tdb */
static NTSTATUS db_close(void) {
	return NT_STATUS_OK;
}

static void db_status(void) {
	return;
}

struct idmap_methods winbind_methods = {

	db_init,
	db_get_sid_from_id,
	db_get_id_from_sid,
	db_set_mapping,
	db_close,
	db_status

};

NTSTATUS idmap_reg_winbind(struct idmap_methods **meth)
{
	*meth = &winbind_methods;

	return NT_STATUS_OK;
}

