/* 
   Unix SMB/CIFS implementation.
   ID Mapping
   Copyright (C) Simo Sorce 2003
   Copyright (C) Jeremy Allison 2006

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

/*****************************************************************
 Returns SID pointer.
*****************************************************************/  

NTSTATUS idmap_uid_to_sid(DOM_SID *sid, uid_t uid, int flags)
{
	unid_t id;

	DEBUG(10,("idmap_uid_to_sid: uid = [%lu]\n", (unsigned long)uid));

	id.uid = uid;
	
	return idmap_get_sid_from_id(sid, id, ID_USERID, flags);
}

/*****************************************************************
 Group mapping is used for gids that maps to Wellknown SIDs
 Returns SID pointer.
*****************************************************************/  

NTSTATUS idmap_gid_to_sid(DOM_SID *sid, gid_t gid, int flags)
{
	unid_t id;

	DEBUG(10,("idmap_gid_to_sid: gid = [%lu]\n", (unsigned long)gid));

	id.gid = gid;

	return idmap_get_sid_from_id(sid, id, ID_GROUPID, flags);
}

/*****************************************************************
 if it is a foreign sid or it is in idmap rid range check idmap,
 otherwise falls back to the legacy algorithmic mapping.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

NTSTATUS idmap_sid_to_uid(const DOM_SID *sid, uid_t *uid, int flags)
{
	NTSTATUS ret;
	enum idmap_type id_type;
	unid_t id;

	DEBUG(10,("idmap_sid_to_uid: sid = [%s]\n", sid_string_static(sid)));

	/* For the LDAP and tdb backends we must *KNOW* what we're looking for.
	   This interface design *SUCKS* ! JRA. */

	id_type = ID_USERID;
	ret = idmap_get_id_from_sid(&id, &id_type, sid, flags);

	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	if (id_type != ID_USERID) {
		return NT_STATUS_NONE_MAPPED;
	}

	DEBUG(10,("idmap_sid_to_uid: uid = [%lu]\n", (unsigned long)id.uid));
	*uid = id.uid;

	return NT_STATUS_OK;
}

/*****************************************************************
 *THE CANONICAL* convert SID to gid function.
 if it is a foreign sid or it is in idmap rid range check idmap,
 otherwise falls back to the legacy algorithmic mapping.
 Group mapping is used for gids that maps to Wellknown SIDs
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

NTSTATUS idmap_sid_to_gid(const DOM_SID *sid, gid_t *gid, int flags)
{
	NTSTATUS ret;
	enum idmap_type id_type;
	unid_t id;

	DEBUG(10,("sid_to_gid: sid = [%s]\n", sid_string_static(sid)));

	/* For the LDAP and tdb backends we must *KNOW* what we're looking for.
	   This interface design *SUCKS* ! JRA. */

	id_type = ID_GROUPID;
	ret = idmap_get_id_from_sid(&id, &id_type, sid, flags);
	
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	if (id_type != ID_GROUPID) {
		return NT_STATUS_NONE_MAPPED;
	}

	DEBUG(10,("idmap_sid_to_gid: gid = [%lu]\n", (unsigned long)id.gid));
	*gid = id.gid;

	return NT_STATUS_OK;
}
