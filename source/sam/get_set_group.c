/* 
   Unix SMB/CIFS implementation.
   SAM_USER_HANDLE access routines
   Copyright (C) Andrew Bartlett			2002
   Copyright (C) Stefan (metze) Metzmacher	2002
   Copyright (C) Jelmer Vernooij 			2002
      
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
#define DBGC_CLASS DBGC_SAM

/* sam group get functions */

NTSTATUS sam_get_group_sid(const SAM_GROUP_HANDLE *group, DOM_SID **sid)
{
	if (!group || !sid) return NT_STATUS_UNSUCCESSFUL;

	*sid = &(group->private.sid);

	return NT_STATUS_OK;
}

NTSTATUS sam_get_group_typ(const SAM_GROUP_HANDLE *group, uint32 *typ)
{
	if (!group || !typ) return NT_STATUS_UNSUCCESSFUL;

	*typ = group->private.flags;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_group_name(const SAM_GROUP_HANDLE *group, char **group_name)
{
	if (!group) return NT_STATUS_UNSUCCESSFUL;

	*group_name = group->private.name;

	return NT_STATUS_OK;

}
NTSTATUS sam_get_group_comment(const SAM_GROUP_HANDLE *group, char **comment)
{
	if (!group) return NT_STATUS_UNSUCCESSFUL;

	*comment = group->private.comment;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_group_priv_set(const SAM_GROUP_HANDLE *group, PRIVILEGE_SET *priv_set)
{
	if (!group) return NT_STATUS_UNSUCCESSFUL;

	*priv_set = group->private.privileges;

	return NT_STATUS_OK;
}

/* sam group set functions */

NTSTATUS sam_set_group_sid(SAM_GROUP_HANDLE *group, DOM_SID *sid)
{
	if (!group) return NT_STATUS_UNSUCCESSFUL;

	if (!sid) ZERO_STRUCT(group->private.sid);
	else sid_copy(&(group->private.sid), sid);

	return NT_STATUS_OK;
}

NTSTATUS sam_set_group_typ(SAM_GROUP_HANDLE *group, uint32 typ)
{
	if (!group) return NT_STATUS_UNSUCCESSFUL;

	group->private.flags = typ;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_group_name(SAM_GROUP_HANDLE *group, char *group_name)
{
	if (!group) return NT_STATUS_UNSUCCESSFUL;

	group->private.name = talloc_strdup(group->mem_ctx, group_name);

	return NT_STATUS_OK;
}

NTSTATUS sam_set_group_comment(SAM_GROUP_HANDLE *group, char *comment)
{
	if (!group) return NT_STATUS_UNSUCCESSFUL;

	group->private.comment = talloc_strdup(group->mem_ctx, comment);

	return NT_STATUS_OK;

}

NTSTATUS sam_set_group_priv_set(SAM_GROUP_HANDLE *group, PRIVILEGE_SET *priv_set)
{
	if (!group) return NT_STATUS_UNSUCCESSFUL;

	if (!priv_set) ZERO_STRUCT(group->private.privileges);
	else memcpy(&(group->private.privileges), priv_set, sizeof(PRIVILEGE_SET));

	return NT_STATUS_OK;
}
