/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Groupname handling
   Copyright (C) Jeremy Allison               1998-2000.
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.
   
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
#include "sids.h"

extern int DEBUGLEVEL;

/*******************************************************************
 converts a RID to a UNIX ID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static BOOL sursalg_rid_to_unix_id(uint32 rid, uint32 *id, int type)
{
	if((id == NULL) || (rid < 1000))
		return False;
	rid -= 1000;
	if((rid % RID_MULTIPLIER) != type)
		return False;
	*id = rid / RID_MULTIPLIER;
	return True;
}

/*******************************************************************
 converts UNIX uid to an NT User RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static BOOL sursalg_user_rid_to_uid(uint32 user_rid, uint32 *id)
{
	return sursalg_rid_to_unix_id(user_rid, id, RID_TYPE_USER);
}

/*******************************************************************
 converts NT Group RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static BOOL sursalg_group_rid_to_gid(uint32 group_rid, uint32 *id)
{
	return sursalg_rid_to_unix_id(group_rid, id, RID_TYPE_GROUP);
}

/*******************************************************************
 converts NT Alias RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static BOOL sursalg_alias_rid_to_gid(uint32 alias_rid, uint32 *id)
{
	return sursalg_rid_to_unix_id(alias_rid, id, RID_TYPE_ALIAS);
}

/*******************************************************************
 converts NT Group RID to a UNIX uid. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 sursalg_gid_to_group_rid(uint32 gid)
{
	uint32 grp_rid = ((((gid)*RID_MULTIPLIER) + 1000) | RID_TYPE_GROUP);
	return grp_rid;
}

/******************************************************************
 converts UNIX gid to an NT Alias RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 sursalg_gid_to_alias_rid(uint32 gid)
{
	uint32 alias_rid = ((((gid)*RID_MULTIPLIER) + 1000) | RID_TYPE_ALIAS);
	return alias_rid;
}

/*******************************************************************
 converts UNIX uid to an NT User RID. NOTE: IS SOMETHING SPECIFIC TO SAMBA
 ********************************************************************/
static uint32 sursalg_uid_to_user_rid(uint32 uid)
{
	uint32 user_rid = ((((uid)*RID_MULTIPLIER) + 1000) | RID_TYPE_USER);
	return user_rid;
}

/******************************************************************
 converts SID + SID_NAME_USE type to a UNIX id.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
BOOL sursalg_sam_sid_to_unixid(DOM_SID *sid, uint32 type, uint32 *id)
{
	DOM_SID tmp_sid;
	uint32 rid;

	sid_copy(&tmp_sid, sid);
	sid_split_rid(&tmp_sid, &rid);
	if (!sid_equal(&global_sam_sid, &tmp_sid))
	{
		return False;
	}

	switch (type)
	{
		case SID_NAME_USER:
		{
			return sursalg_user_rid_to_uid(rid, id);
		}
		case SID_NAME_ALIAS:
		{
			return sursalg_alias_rid_to_gid(rid, id);
		}
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			return sursalg_group_rid_to_gid(rid, id);
		}
	}
	return False;
}

/******************************************************************
 converts UNIX gid + SID_NAME_USE type to a SID.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
BOOL sursalg_unixid_to_sam_sid(uint32 id, uint32 type, DOM_SID *sid,
				BOOL create)
{
	sid_copy(sid, &global_sam_sid);
	switch (type)
	{
		case SID_NAME_USER:
		{
			sid_append_rid(sid, sursalg_uid_to_user_rid(id));
			return True;
		}
		case SID_NAME_ALIAS:
		{
			sid_append_rid(sid, sursalg_gid_to_alias_rid(id));
			return True;
		}
		case SID_NAME_DOM_GRP:
		case SID_NAME_WKN_GRP:
		{
			sid_append_rid(sid, sursalg_gid_to_group_rid(id));
			return True;
		}
	}
	return False;
}

