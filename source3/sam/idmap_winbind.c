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
#include "nsswitch/winbind_nss.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

extern DOM_SID global_sid_NULL;            		/* NULL sid */

NSS_STATUS winbindd_request(int req_type,
                                 struct winbindd_request *request,
                                 struct winbindd_response *response);

/* Get a sid from an id */
static NTSTATUS db_get_sid_from_id(DOM_SID *sid, unid_t id, int id_type)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result, operation;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	switch (id_type & ID_TYPEMASK) {
		case ID_USERID:
			request.data.uid = id.uid;
			operation = WINBINDD_UID_TO_SID;
			DEBUG(10,("db_get_sid_from_id: asking winbindd uid %u -> sid\n",
				(unsigned int)id.uid ));
			break;
		case ID_GROUPID:
			request.data.gid = id.gid;
			operation = WINBINDD_GID_TO_SID;
			DEBUG(10,("db_get_sid_from_id: asking winbindd gid %u -> sid\n",
				(unsigned int)id.gid ));
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	/* Make The Request */
	result = winbindd_request(operation, &request, &response);
	if (result == NSS_STATUS_SUCCESS) {
		DEBUG(10,("db_get_sid_from_id: winbindd replied ok (%s)\n", response.data.sid.sid ));
		if (!string_to_sid(sid, response.data.sid.sid)) {
			return NT_STATUS_INVALID_SID;
		}
		return NT_STATUS_OK;
	} else {
		sid_copy(sid, &global_sid_NULL);
	}

	DEBUG(10,("db_get_sid_from_id: winbindd lookup fail\n"));

	return NT_STATUS_UNSUCCESSFUL;
}

/* Get an id from a sid */
static NTSTATUS db_get_id_from_sid(unid_t *id, int *id_type, const DOM_SID *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int result, operation;
	fstring sid_str;

	if (!id || !id_type) {
		return NT_STATUS_INVALID_PARAMETER;
	}

 	/* setup request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

 	sid_to_string(sid_str, sid);
 	fstrcpy(request.data.sid, sid_str);

	switch (*id_type & ID_TYPEMASK) {
		case ID_USERID:
			operation = WINBINDD_SID_TO_UID;
			DEBUG(10,("db_get_id_from_sid: asking winbindd %s -> uid\n",
				sid_str ));
			break;
		case ID_GROUPID:
			operation = WINBINDD_SID_TO_GID;
			DEBUG(10,("db_get_id_from_sid: asking winbindd %s -> gid\n",
				sid_str ));
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	/* Make The Request */
	result = winbindd_request(operation, &request, &response);

	if (result == NSS_STATUS_SUCCESS) {
		if (operation == WINBINDD_SID_TO_UID) {
			(*id).uid = response.data.uid;
			DEBUG(10,("db_get_id_from_sid: winbindd replied ok (%u)\n", response.data.uid));
		} else {
			(*id).gid = response.data.gid;
			DEBUG(10,("db_get_id_from_sid: winbindd replied ok (%u)\n", response.data.gid ));
		}
		return NT_STATUS_OK;
	}

	DEBUG(10,("db_get_id_from_sid: winbindd lookup fail\n"));

	return NT_STATUS_UNSUCCESSFUL;
}	

static NTSTATUS db_set_mapping(const DOM_SID *sid, unid_t id, int id_type) {
	return NT_STATUS_UNSUCCESSFUL;
}

/*****************************************************************************
 Initialise idmap database. 
*****************************************************************************/
static NTSTATUS db_init( char *params ) {
	return NT_STATUS_OK;
}

/* Close the tdb */
static NTSTATUS db_close(void) {
	return NT_STATUS_OK;
}

static void db_status(void) {
	return;
}

static struct idmap_methods winbind_methods = {
	db_init,
	db_get_sid_from_id,
	db_get_id_from_sid,
	db_set_mapping,
	db_close,
	db_status

};

NTSTATUS idmap_winbind_init(void)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "winbind", &winbind_methods);
}
