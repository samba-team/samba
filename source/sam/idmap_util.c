/* 
   Unix SMB/CIFS implementation.
   ID Mapping
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

/*****************************************************************
 *THE CANONICAL* convert uid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *uid_to_sid(DOM_SID *psid, uid_t uid)
{
	unid_t id;

	DEBUG(10,("uid_to_sid: uid = [%d]\n", uid));

	id.uid = uid;
	if (NT_STATUS_IS_OK(idmap_get_sid_from_id(psid, id, ID_USERID))) {
		DEBUG(10, ("uid_to_sid: sid = [%s]\n", sid_string_static(psid)));
		return psid;
	}

	/* If mapping is not found in idmap try with traditional method,
	   then stores the result in idmap.
	   We may add a switch in future to allow smooth migrations to
	   idmap-only db  ---Simo */	

	sid_copy(psid, get_global_sam_sid());
	sid_append_rid(psid, fallback_pdb_uid_to_user_rid(uid));

	DEBUG(10,("uid_to_sid: algorithmic %u -> %s\n", (unsigned int)uid, sid_string_static(psid)));

	return psid;
	
}

/*****************************************************************
 *THE CANONICAL* convert gid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *gid_to_sid(DOM_SID *psid, gid_t gid)
{
	GROUP_MAP map;
	unid_t id;

	DEBUG(10,("gid_to_sid: gid = [%d]\n", gid));

		id.gid = gid;
	if (NT_STATUS_IS_OK(idmap_get_sid_from_id(psid, id, ID_GROUPID))) {
		DEBUG(10, ("gid_to_sid: sid = [%s]\n", sid_string_static(psid)));
		return psid;
	}

	/* If mapping is not found in idmap try with traditional method,
	   then stores the result in idmap.
	   We may add a switch in future to allow smooth migrations to
	   idmap-only db  ---Simo */	

	if (pdb_getgrgid(&map, gid, MAPPING_WITHOUT_PRIV)) {
		sid_copy(psid, &map.sid);
	} else {
		sid_copy(psid, get_global_sam_sid());
		sid_append_rid(psid, pdb_gid_to_group_rid(gid));
	}

	DEBUG(10,("gid_to_sid: algorithmic %u -> %s\n", (unsigned int)gid, sid_string_static(psid)));

	return psid;
}

/*****************************************************************
 *THE CANONICAL* convert SID to uid function.
 Tries winbind first - then uses local lookup.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not. sidtype is set by this function.
*****************************************************************/  

BOOL sid_to_uid(const DOM_SID *psid, uid_t *puid, enum SID_NAME_USE *sidtype)
{
	unid_t id;
	int type;

	DEBUG(10,("sid_to_uid: sid = [%s]\n", sid_string_static(psid)));

	*sidtype = SID_NAME_USER;

	type = ID_USERID;
	if (NT_STATUS_IS_OK(idmap_get_id_from_sid(&id, &type, psid))) {
		DEBUG(10,("sid_to_uid: uid = [%d]\n", id.uid));
		*puid = id.uid;
		return True;
	}

	if (sid_compare_domain(get_global_sam_sid(), psid) == 0) {
		BOOL result;
		uint32 rid;

		DEBUG(10,("sid_to_uid: sid is local [%s]\n", sid_string_static(get_global_sam_sid())));

		if (!sid_peek_rid(psid, &rid)) {
			DEBUG(0, ("sid_to_uid: Error extracting RID from SID\n!"));
			return False;
		}
		if (!pdb_rid_is_user(rid)) {
			DEBUG(3, ("sid_to_uid: RID %u is *NOT* a user\n", (unsigned)rid));
			return False;
		}
		*puid = fallback_pdb_user_rid_to_uid(rid);
		return True;
	}
	return False;
}

/*****************************************************************
 *THE CANONICAL* convert SID to gid function.
 Tries winbind first - then uses local lookup.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

BOOL sid_to_gid(const DOM_SID *psid, gid_t *pgid, enum SID_NAME_USE *sidtype)
{
	unid_t id;
	int type;

	DEBUG(10,("sid_to_gid: sid = [%s]\n", sid_string_static(psid)));

	*sidtype = SID_NAME_ALIAS;

	type = ID_GROUPID;
	if (NT_STATUS_IS_OK(idmap_get_id_from_sid(&id, &type, psid))) {
		DEBUG(10,("sid_to_gid: gid = [%d]\n", id.gid));
		*pgid = id.gid;
		return True;
	}

	if (sid_compare_domain(get_global_sam_sid(), psid) == 0) {
		GROUP_MAP map;
		BOOL result;

		if (pdb_getgrsid(&map, *psid, MAPPING_WITHOUT_PRIV)) {
			/* the SID is in the mapping table but not mapped */
			if (map.gid==(gid_t)-1)
				return False;
			
			*pgid = map.gid;
			*sidtype = map.sid_name_use;
			return True;
		} else {
			uint32 rid;

			if (!sid_peek_rid(psid, &rid)) {
				DEBUG(0, ("sid_to_gid: Error extracting RID from SID\n!"));
				return False;
			}
			if (pdb_rid_is_user(rid)) {
				DEBUG(3, ("sid_to_gid: RID %u is *NOT* a group\n", (unsigned)rid));
				return False;
			}
			*pgid = pdb_group_rid_to_gid(rid);
			*sidtype = SID_NAME_ALIAS;	
		}
	}

	return False;
}

