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

NTSTATUS sam_get_group_sid(const SAM_GROUP_HANDLE *group, const DOM_SID **sid)
{
	SAM_ASSERT(group && sid);

	*sid = &(group->private.sid);

	return NT_STATUS_OK;
}

NTSTATUS sam_get_group_ctrl(const SAM_GROUP_HANDLE *group, uint32 *group_ctrl)
{
	SAM_ASSERT(group && group_ctrl);

	*group_ctrl = group->private.group_ctrl;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_group_name(const SAM_GROUP_HANDLE *group, const char **group_name)
{
	SAM_ASSERT(group);

	*group_name = group->private.group_name;

	return NT_STATUS_OK;

}
NTSTATUS sam_get_group_comment(const SAM_GROUP_HANDLE *group, const char **group_desc)
{
	SAM_ASSERT(group);

	*group_desc = group->private.group_desc;

	return NT_STATUS_OK;
}

/* sam group set functions */

NTSTATUS sam_set_group_sid(SAM_GROUP_HANDLE *group, const DOM_SID *sid)
{
	SAM_ASSERT(group);

	if (!sid) 
		ZERO_STRUCT(group->private.sid);
	else 
		sid_copy(&(group->private.sid), sid);

	return NT_STATUS_OK;
}

NTSTATUS sam_set_group_group_ctrl(SAM_GROUP_HANDLE *group, uint32 group_ctrl)
{
	SAM_ASSERT(group);

	group->private.group_ctrl = group_ctrl;

	return NT_STATUS_OK;
}

NTSTATUS sam_set_group_name(SAM_GROUP_HANDLE *group, const char *group_name)
{
	SAM_ASSERT(group);

	group->private.group_name = talloc_strdup(group->mem_ctx, group_name);

	return NT_STATUS_OK;
}

NTSTATUS sam_set_group_description(SAM_GROUP_HANDLE *group, const char *group_desc)
{
	SAM_ASSERT(group);

	group->private.group_desc = talloc_strdup(group->mem_ctx, group_desc);

	return NT_STATUS_OK;

}
