/* 
   Unix SMB/CIFS implementation.
   struct samu access routines
   Copyright (C) Jeremy Allison 		1996-2001
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000-2001
   Copyright (C) Andrew Bartlett		2001-2002
   Copyright (C) Stefan (metze) Metzmacher	2002

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "passdb.h"
#include "../libcli/security/security.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

uint32_t pdb_get_user_rid (const struct samu *sampass)
{
	uint32_t u_rid;

	if (sampass)
		if (sid_peek_check_rid(get_global_sam_sid(), pdb_get_user_sid(sampass),&u_rid))
			return u_rid;

	return (0);
}

uint32_t pdb_get_group_rid (struct samu *sampass)
{
	uint32_t g_rid;

	if (sampass)
		if (sid_peek_check_rid(get_global_sam_sid(), pdb_get_group_sid(sampass),&g_rid))
			return g_rid;
	return (0);
}

bool pdb_set_user_sid_from_rid (struct samu *sampass, uint32_t rid, enum pdb_value_state flag)
{
	struct dom_sid u_sid;
	struct dom_sid_buf buf;
	const struct dom_sid *global_sam_sid;

	if (!sampass)
		return False;

	if (!(global_sam_sid = get_global_sam_sid())) {
		DEBUG(1, ("pdb_set_user_sid_from_rid: Could not read global sam sid!\n"));
		return False;
	}

	if (!sid_compose(&u_sid, global_sam_sid, rid)) {
		return False;
	}

	if (!pdb_set_user_sid(sampass, &u_sid, flag))
		return False;

	DEBUG(10, ("pdb_set_user_sid_from_rid:\n\tsetting user sid %s from rid %d\n", 
		   dom_sid_str_buf(&u_sid, &buf), rid));

	return True;
}

bool pdb_set_group_sid_from_rid (struct samu *sampass, uint32_t grid, enum pdb_value_state flag)
{
	struct dom_sid g_sid;
	struct dom_sid_buf buf;
	const struct dom_sid *global_sam_sid;

	if (!sampass)
		return False;

	if (!(global_sam_sid = get_global_sam_sid())) {
		DEBUG(1, ("pdb_set_user_sid_from_rid: Could not read global sam sid!\n"));
		return False;
	}

	if (!sid_compose(&g_sid, global_sam_sid, grid)) {
		return False;
	}

	if (!pdb_set_group_sid(sampass, &g_sid, flag))
		return False;

	DEBUG(10, ("pdb_set_group_sid_from_rid:\n\tsetting group sid %s from rid %d\n", 
		   dom_sid_str_buf(&g_sid, &buf), grid));

	return True;
}

