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


/******************************************************************
 * Get the free RID base if idmap is configured, otherwise return 0
 ******************************************************************/

uint32 idmap_get_free_rid_base(void)
{
	uint32 low, high;
	if (idmap_get_free_rid_range(&low, &high)) {
		return low;
	}
	return 0;
}

BOOL idmap_check_ugid_is_in_free_range(uint32 id)
{
	uint32 low, high;

	if (!idmap_get_free_ugid_range(&low, &high)) {
		return False;
	}
	if (id < low || id > high) {
		return False;
	}
	return True;
}

BOOL idmap_check_rid_is_in_free_range(uint32 rid)
{
	uint32 low, high;

	if (!idmap_get_free_rid_range(&low, &high)) {
		return False;
	}
	if (rid < low || rid > high) {
		return False;
	}
	return True;
}

/******************************************************************
 * Get the the non-algorithmic RID range if idmap range are defined
 ******************************************************************/

BOOL idmap_get_free_rid_range(uint32 *low, uint32 *high)
{
	uint32 id_low, id_high;

	if (lp_idmap_only()) {
		*low = BASE_RID;
		*high = (uint32)-1;
	}

	if (!idmap_get_free_ugid_range(&id_low, &id_high)) {
		return False;
	}

	*low = fallback_pdb_uid_to_user_rid(id_low);
	if (fallback_pdb_user_rid_to_uid((uint32)-1) < id_high) {
		*high = (uint32)-1;
	} else {
		*high = fallback_pdb_uid_to_user_rid(id_high);
	}

	return True;
}

BOOL idmap_get_free_ugid_range(uint32 *low, uint32 *high)
{
	uid_t u_low, u_high;
	gid_t g_low, g_high;

	if (!lp_idmap_uid(&u_low, &u_high) || !lp_idmap_gid(&g_low, &g_high)) {
		return False;
	}
	if (u_low < g_low) {
		*low = u_low;
	} else {
		*low = g_low;
	}
	if (u_high < g_high) {
		*high = g_high;
	} else {
		*high = u_high;
	}
	return True;
}

/*****************************************************************
 *THE CANONICAL* convert uid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *uid_to_sid(DOM_SID *sid, uid_t uid)
{
	unid_t id;

	DEBUG(10,("uid_to_sid: uid = [%d]\n", uid));

	if (idmap_check_ugid_is_in_free_range(uid)) {
		id.uid = uid;
		if (NT_STATUS_IS_ERR(idmap_get_sid_from_id(sid, id, ID_USERID))) {
			DEBUG(10, ("uid_to_sid: Failed to map sid = [%s]\n", sid_string_static(sid)));
			return NULL;
		}
	} else {
		sid_copy(sid, get_global_sam_sid());
		sid_append_rid(sid, fallback_pdb_uid_to_user_rid(uid));
		
		DEBUG(10,("uid_to_sid: algorithmic %u -> %s\n", (unsigned int)uid, sid_string_static(sid)));
	}
	return sid;
	
}

/*****************************************************************
 *THE CANONICAL* convert gid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *gid_to_sid(DOM_SID *sid, gid_t gid)
{
	GROUP_MAP map;
	unid_t id;

	DEBUG(10,("gid_to_sid: gid = [%d]\n", gid));

	if (idmap_check_ugid_is_in_free_range(gid)) {
		id.gid = gid;
		if (NT_STATUS_IS_ERR(idmap_get_sid_from_id(sid, id, ID_GROUPID))) {
			DEBUG(10, ("gid_to_sid: Failed to map sid = [%s]\n", sid_string_static(sid)));
			return NULL;
		}
	} else {
		if (pdb_getgrgid(&map, gid, MAPPING_WITHOUT_PRIV)) {
			sid_copy(sid, &map.sid);
		} else {
			sid_copy(sid, get_global_sam_sid());
			sid_append_rid(sid, pdb_gid_to_group_rid(gid));
		}

		DEBUG(10,("gid_to_sid: algorithmic %u -> %s\n", (unsigned int)gid, sid_string_static(sid)));
	}

	return sid;
}

/*****************************************************************
 *THE CANONICAL* convert SID to uid function.
 Tries winbind first - then uses local lookup.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not. sidtype is set by this function.
*****************************************************************/  

BOOL sid_to_uid(const DOM_SID *sid, uid_t *uid)
{
	uint32 rid;
	unid_t id;
	int type;

	DEBUG(10,("sid_to_uid: sid = [%s]\n", sid_string_static(sid)));

	if (sid_peek_check_rid(get_global_sam_sid(), sid, &rid)) {
		if (!idmap_check_rid_is_in_free_range(rid)) {
			if (!fallback_pdb_rid_is_user(rid)) {
				DEBUG(3, ("sid_to_uid: RID %u is *NOT* a user\n", (unsigned)rid));
				return False;
			}
			*uid = fallback_pdb_user_rid_to_uid(rid);
			return True;
		}
	}

	type = ID_USERID;
	if (NT_STATUS_IS_OK(idmap_get_id_from_sid(&id, &type, sid))) {
		DEBUG(10,("sid_to_uid: uid = [%d]\n", id.uid));
		*uid = id.uid;
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

BOOL sid_to_gid(const DOM_SID *sid, gid_t *gid)
{
	uint32 rid;
	unid_t id;
	int type;

	DEBUG(10,("sid_to_gid: sid = [%s]\n", sid_string_static(sid)));

	if (sid_peek_check_rid(get_global_sam_sid(), sid, &rid)) {
		GROUP_MAP map;
		BOOL result;

		if (pdb_getgrsid(&map, *sid, MAPPING_WITHOUT_PRIV)) {
			/* the SID is in the mapping table but not mapped */
			if (map.gid==(gid_t)-1)
				return False;
			
			*gid = map.gid;
			return True;
		} else {
			if (!idmap_check_rid_is_in_free_range(rid)) {
				if (fallback_pdb_rid_is_user(rid)) {
					DEBUG(3, ("sid_to_gid: RID %u is *NOT* a group\n", (unsigned)rid));
					return False;
				}
				*gid = pdb_group_rid_to_gid(rid);
				return True;
			}
		}
	}

	type = ID_GROUPID;
	if (NT_STATUS_IS_OK(idmap_get_id_from_sid(&id, &type, sid))) {
		DEBUG(10,("sid_to_gid: gid = [%d]\n", id.gid));
		*gid = id.gid;
		return True;
	}

	return False;
}

