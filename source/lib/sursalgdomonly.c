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

static int sursalg_rid_posix_type(uint32 rid)
{
	return ((rid-1000) % RID_MULTIPLIER);
}

static uint32 sursalg_rid_posix_id(uint32 rid)
{
	return (rid-1000) / RID_MULTIPLIER;
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
 converts SID to a UNIX id + type.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
BOOL surs_algdomonly_sam_sid_to_unixid(DOM_SID *sid, POSIX_ID *id,
				BOOL create)
{
	DOM_SID tmp_sid;
	uint32 rid;
	int type;

	sid_copy(&tmp_sid, sid);
	sid_split_rid(&tmp_sid, &rid);
	if (!sid_equal(&global_sam_sid, &tmp_sid))
	{
		return False;
	}

	if((id == NULL) || (rid < 1000))
		return False;

	type = sursalg_rid_posix_type(rid);
	id->id = sursalg_rid_posix_id(rid);

	switch (type)
	{
		case RID_TYPE_USER:
		{
			id->type = SURS_POSIX_UID_AS_USR;
			return True;
		}
		case RID_TYPE_ALIAS:
		{
			id->type = SURS_POSIX_GID_AS_ALS;
			return True;
		}
		case RID_TYPE_GROUP:
		{
			id->type = SURS_POSIX_GID_AS_GRP;
			return True;
		}
		default:
		{
			break;
		}
	}
	return False;
}

/******************************************************************
 converts UNIX id + type to a SID.  the Domain SID is,
 and can only be, our own SID.
 ********************************************************************/
BOOL surs_algdomonly_unixid_to_sam_sid(POSIX_ID *id, DOM_SID *sid,
				BOOL create)
{
	sid_copy(sid, &global_sam_sid);
	switch (id->type)
	{
		case SURS_POSIX_UID_AS_USR:
		{
			sid_append_rid(sid, sursalg_uid_to_user_rid(id->id));
			return True;
		}
		case SURS_POSIX_GID_AS_ALS:
		{
			sid_append_rid(sid, sursalg_gid_to_alias_rid(id->id));
			return True;
		}
		case SURS_POSIX_GID_AS_GRP:
		{
			sid_append_rid(sid, sursalg_gid_to_group_rid(id->id));
			return True;
		}
	}
	return False;
}

