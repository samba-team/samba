/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Groupname handling
   Copyright (C) Jeremy Allison               1998-2000.
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.
   Copyright (C) Luke Howard                  2000.
   
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

/* 
 * algorithmic implementation of a SURS (sid to uid resolution) table.
 * only does the local SAM, does NOT even do domain membership.
 * repeat: this is for the LOCAL SAM only, not even the BUILTIN domain.
 */

#include "includes.h"

#ifdef WITH_NT5LDAP

#include "sids.h"
#include "ldapdb.h"

extern int DEBUGLEVEL;

#if 0
/*******************************************************************
 converts a RID to a UNIX ID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static BOOL nt5ldap_sursalg_rid_to_unix_id(LDAPDB *hds, uint32 rid, uint32 *id, int type)
{
	BOOL ret;

	if (id == NULL) 
		return False;

	if (!ldapdb_lookup_by_rid(hds, rid))
		return False;

	switch (type)
	{
		case RID_TYPE_USER:
			ret = ldapdb_get_uint32(hds, "uidNumber", id);
			break;
		case RID_TYPE_GROUP:
		case RID_TYPE_ALIAS:
			ret = ldapdb_get_uint32(hds, "gidNumber", id);
			break;
		default:
			ret = False;
	}

	return ret;
}

/*******************************************************************
 converts UNIX uid to an NT User RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static BOOL nt5ldap_sursalg_user_rid_to_uid(LDAPDB *hds, uint32 user_rid, uint32 *id)
{
	return nt5ldap_sursalg_rid_to_unix_id(hds, user_rid, id, RID_TYPE_USER);
}

/*******************************************************************
 converts NT Group RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static BOOL nt5ldap_sursalg_group_rid_to_gid(LDAPDB *hds, uint32 group_rid, uint32 *id)
{
	return nt5ldap_sursalg_rid_to_unix_id(hds, group_rid, id, RID_TYPE_GROUP);
}

/*******************************************************************
 converts NT Alias RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static BOOL nt5ldap_sursalg_alias_rid_to_gid(LDAPDB *hds, uint32 alias_rid, uint32 *id)
{
	return nt5ldap_sursalg_rid_to_unix_id(hds, alias_rid, id, RID_TYPE_ALIAS);
}

/*******************************************************************
 converts NT Group RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 nt5ldap_sursalg_gid_to_group_rid(LDAPDB *hds, uint32 gid)
{
	uint32 ret;

	if (!ldapdb_lookup_by_posix_gid(hds, gid) ||
	    !ldapdb_get_rid(hds, "objectSid", &ret))
		ret = 0xffffffff; /* XXX */

	return ret;
}

/******************************************************************
 converts UNIX gid to an NT Alias RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 nt5ldap_sursalg_gid_to_alias_rid(LDAPDB *hds, uint32 gid)
{
	uint32 ret;

	if (!ldapdb_lookup_by_posix_gid(hds, gid) ||
	    !ldapdb_get_rid(hds, "objectSid", &ret))
		ret = 0xffffffff; /* XXX */

	return ret;
}

/*******************************************************************
 converts UNIX uid to an NT User RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 nt5ldap_sursalg_uid_to_user_rid(LDAPDB *hds, uint32 uid)
{
	uint32 ret;

	if (!ldapdb_lookup_by_posix_uid(hds, uid) ||
	    !ldapdb_get_rid(hds, "objectSid", &ret))
		ret = 0xffffffff; /* XXX */

	return ret;
}
#endif

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
BOOL nt5ldap_sursalg_sam_sid_to_unixid(LDAPDB *hds, DOM_SID *sid, uint32 type, uint32 *id)
{
	BOOL ret;

	if (!ldapdb_lookup_by_sid(hds, sid))
		return False;

	switch (type)
	{
		case RID_TYPE_USER:
			ret = ldapdb_get_uint32(hds, "uidNumber", id);
			break;
		case RID_TYPE_GROUP:
		case RID_TYPE_ALIAS:
			ret = ldapdb_get_uint32(hds, "gidNumber", id);
			break;
		default:
			ret = False;
	}

	/* Fallback to default impl */
	if (!ret)
		ret = sursalg_sam_sid_to_unixid(sid, type, id);

	return ret;
}

/******************************************************************
 converts UNIX gid + SID_NAME_USE type to a SID.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
BOOL nt5ldap_sursalg_unixid_to_sam_sid(LDAPDB *hds, uint32 id, uint32 type, DOM_SID *sid,
				BOOL create)
{
	char *attribute;
	fstring filter;
	char *attrs[] = { "objectSid", NULL };
	BOOL ret;

	switch (type)
	{
		case SID_NAME_USER:
			attribute = "uidNumber";
			break;
		case SID_NAME_ALIAS:
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
			attribute = "gidNumber";
			break;
		default:
			return False;
	}

	slprintf(filter, sizeof(filter)-1, "(&(objectSid=*)(%s=%d))", attribute, id);
	ret = ldapdb_search(hds, NULL, filter, attrs, 1) && ldapdb_get_sid(hds, "objectSid", sid);

	/* Fallback to default impl */
	if (!ret)
		ret = sursalg_unixid_to_sam_sid(id, type, sid, create);

	return ret;
}

#endif /* WITH_NT5LDAP */
