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

/* if it is a foreign SID or if the SID is in the free range, return true */

BOOL idmap_check_sid_is_in_free_range(const DOM_SID *sid)
{
	if (sid_compare_domain(get_global_sam_sid(), sid) == 0) {
	
		uint32 rid;

		if (sid_peek_rid(sid, &rid)) {
			return idmap_check_rid_is_in_free_range(rid);
		}

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
 check idmap if uid is in idmap range, otherwise falls back to
 the legacy algorithmic mapping.
 A special cache is used for uids that maps to Wellknown SIDs
 Returns SID pointer.
*****************************************************************/  

NTSTATUS uid_to_sid(DOM_SID *sid, uid_t uid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	unid_t id;
	int flags;

	DEBUG(10,("uid_to_sid: uid = [%d]\n", uid));

	flags = ID_USERID;
	if (!lp_idmap_only() && !idmap_check_ugid_is_in_free_range(uid)) {
		flags |= ID_NOMAP;
	}

	id.uid = uid;
	if (NT_STATUS_IS_ERR(ret = idmap_get_sid_from_id(sid, id, flags))) {
		DEBUG(10, ("uid_to_sid: Failed to map uid = [%u]\n", (unsigned int)uid));
		if (flags & ID_NOMAP) {
			sid_copy(sid, get_global_sam_sid());
			sid_append_rid(sid, fallback_pdb_uid_to_user_rid(uid));

			DEBUG(10,("uid_to_sid: Fall back to algorithmic mapping: %u -> %s\n", (unsigned int)uid, sid_string_static(sid)));
			ret = NT_STATUS_OK;
		}
	}

	return ret;
}

/*****************************************************************
 *THE CANONICAL* convert gid_t to SID function.
 check idmap if gid is in idmap range, otherwise falls back to
 the legacy algorithmic mapping.
 Group mapping is used for gids that maps to Wellknown SIDs
 Returns SID pointer.
*****************************************************************/  

NTSTATUS gid_to_sid(DOM_SID *sid, gid_t gid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	GROUP_MAP map;
	unid_t id;
	int flags;

	DEBUG(10,("gid_to_sid: gid = [%d]\n", gid));

	flags = ID_GROUPID;
	if (!lp_idmap_only() && !idmap_check_ugid_is_in_free_range(gid)) {
		flags |= ID_NOMAP;
	}

	id.gid = gid;
	if (NT_STATUS_IS_ERR(ret = idmap_get_sid_from_id(sid, id, flags))) {
		DEBUG(10, ("gid_to_sid: Failed to map gid = [%u]\n", (unsigned int)gid));
		if (flags & ID_NOMAP) {
			sid_copy(sid, get_global_sam_sid());
			sid_append_rid(sid, pdb_gid_to_group_rid(gid));

			DEBUG(10,("gid_to_sid: Fall back to algorithmic mapping: %u -> %s\n", (unsigned int)gid, sid_string_static(sid)));
			ret = NT_STATUS_OK;
		}
	}

	return ret;
}

/*****************************************************************
 *THE CANONICAL* convert SID to uid function.
 if it is a foreign sid or it is in idmap rid range check idmap,
 otherwise falls back to the legacy algorithmic mapping.
 A special cache is used for uids that maps to Wellknown SIDs
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

NTSTATUS sid_to_uid(const DOM_SID *sid, uid_t *uid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	BOOL fallback = False;
	unid_t id;
	int flags;

	DEBUG(10,("sid_to_uid: sid = [%s]\n", sid_string_static(sid)));

	flags = ID_USERID;
	if (!lp_idmap_only()) {
		if (!idmap_check_sid_is_in_free_range(sid)) {
			flags |= ID_NOMAP;
			fallback = True;
		}
	}

	if (NT_STATUS_IS_OK(idmap_get_id_from_sid(&id, &flags, sid))) {

		DEBUG(10,("sid_to_uid: uid = [%d]\n", id.uid));

		*uid = id.uid;
		ret = NT_STATUS_OK;
		
	} else if (fallback) {
		uint32 rid;

		if (!sid_peek_rid(sid, &rid)) {
			DEBUG(10,("sid_to_uid: invalid SID!\n"));
			ret = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

		DEBUG(10,("sid_to_uid: Fall back to algorithmic mapping\n"));

		if (!fallback_pdb_rid_is_user(rid)) {
			DEBUG(3, ("sid_to_uid: SID %s is *NOT* a user\n", sid_string_static(sid)));
			ret = NT_STATUS_UNSUCCESSFUL;
		} else {
			*uid = fallback_pdb_user_rid_to_uid(rid);
			DEBUG(10,("sid_to_uid: mapping: %s -> %u\n", sid_string_static(sid), (unsigned int)(*uid)));
			ret = NT_STATUS_OK;
		}
	}

done:
	return ret;
}

/*****************************************************************
 *THE CANONICAL* convert SID to gid function.
 if it is a foreign sid or it is in idmap rid range check idmap,
 otherwise falls back to the legacy algorithmic mapping.
 Group mapping is used for gids that maps to Wellknown SIDs
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

NTSTATUS sid_to_gid(const DOM_SID *sid, gid_t *gid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	BOOL fallback = False;
	uint32 rid;
	unid_t id;
	int flags;

	DEBUG(10,("sid_to_gid: sid = [%s]\n", sid_string_static(sid)));

	flags = ID_GROUPID;
	if (!lp_idmap_only()) {
		if (!idmap_check_sid_is_in_free_range(sid)) {
			flags |= ID_NOMAP;
			fallback = True;
		}
	}

	if (NT_STATUS_IS_OK(idmap_get_id_from_sid(&id, &flags, sid))) {
		
		DEBUG(10,("sid_to_gid: gid = [%d]\n", id.gid));
		*gid = id.gid;
		ret = NT_STATUS_OK;

	} else if (fallback) {
		uint32 rid;

		if (!sid_peek_rid(sid, &rid)) {
			DEBUG(10,("sid_to_uid: invalid SID!\n"));
			ret = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}

		DEBUG(10,("sid_to_gid: Fall back to algorithmic mapping\n"));

		if (fallback_pdb_rid_is_user(rid)) {
			DEBUG(3, ("sid_to_gid: SID %s is *NOT* a group\n", sid_string_static(sid)));
			ret = NT_STATUS_UNSUCCESSFUL;
		} else {
			*gid = pdb_group_rid_to_gid(rid);
			DEBUG(10,("sid_to_gid: mapping: %s -> %u\n", sid_string_static(sid), (unsigned int)(*gid)));
			ret = NT_STATUS_OK;
		}
	}

done:
	return ret;
}

/* Initialize idmap withWellknown SIDs like Guest, that are necessary
 * to make samba run properly */
BOOL idmap_init_wellknown_sids(void)
{
	const char *guest_account = lp_guestaccount();
	struct passwd *pass;
	GROUP_MAP *map=NULL;
	int num_entries=0;
	DOM_SID sid;
	unid_t id;
	int flags;

	if (!(guest_account && *guest_account)) {
		DEBUG(1, ("NULL guest account!?!?\n"));
		return False;
	}

	pass = getpwnam_alloc(guest_account);
	if (!pass) {
		return False;
	}

	flags = ID_USERID;
	id.uid = pass->pw_uid;
	sid_copy(&sid, get_global_sam_sid());
	sid_append_rid(&sid, DOMAIN_USER_RID_GUEST);
	if (NT_STATUS_IS_ERR(idmap_set_mapping(&sid, id, flags))) {
		passwd_free(&pass);
		return False;
	}

	/* now fill in group mappings */
	if(pdb_enum_group_mapping(SID_NAME_UNKNOWN, &map, &num_entries, ENUM_ONLY_MAPPED, MAPPING_WITHOUT_PRIV)) {
		int i;

		for (i = 0; i < num_entries; i++) {
			id.gid = map[i].gid;
			idmap_set_mapping(&(map[i].sid), id, ID_GROUPID);
		}
	}

	/* check if DOMAIN_GROUP_RID_GUESTS SID is set, if not store the
	 * guest account gid as mapping */
	flags = ID_GROUPID | ID_NOMAP;
	sid_copy(&sid, get_global_sam_sid());
	sid_append_rid(&sid, DOMAIN_GROUP_RID_GUESTS);
	if (NT_STATUS_IS_ERR(idmap_get_id_from_sid(&id, &flags, &sid))) {
		flags = ID_GROUPID;
		id.gid = pass->pw_gid;
		if (NT_STATUS_IS_ERR(idmap_set_mapping(&sid, id, flags))) {
			passwd_free(&pass);
			return False;
		}
	}

	passwd_free(&pass);
	return True;
}
