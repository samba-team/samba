/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tgroupsgell             1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambgroupsge, MA 02139, USA.
 */


#include "includes.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL vuid_io_key(char *desc, vuser_key * r_u, prs_struct * ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "vuid_io_key");
	depth++;

	prs_align(ps);

	prs_uint32("pid ", ps, 0, &r_u->pid);
	prs_uint16("vuid", ps, 0, &r_u->vuid);

	return True;
}

/*******************************************************************
makes a vuser struct.
********************************************************************/
BOOL make_vuid_user_struct(user_struct * r_u,
			   uid_t uid, gid_t gid,
			   const char *name,
			   const char *requested_name,
			   const char *real_name,
			   BOOL guest,
			   uint32 n_groups, const gid_t * groups,
			   const NET_USER_INFO_3 * usr)
{
	int i;

	if (r_u == NULL)
		return False;

	DEBUG(5, ("make_user_struct\n"));

	r_u->uid = uid;
	r_u->gid = gid;

	fstrcpy(r_u->name, name);
	fstrcpy(r_u->requested_name, requested_name);
	fstrcpy(r_u->real_name, real_name);
	r_u->guest = guest;

	r_u->n_groups = n_groups;
	r_u->groups = g_new(uint32, r_u->n_groups);
	if (r_u->groups == NULL && n_groups != 0)
	{
		return False;
	}
	for (i = 0; i < n_groups; i++)
	{
		r_u->groups[i] = (gid_t) groups[i];
	}

	memcpy(&r_u->usr, usr, sizeof(r_u->usr));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL vuid_io_user_struct(char *desc, user_struct * r_u, prs_struct * ps,
			 int depth)
{
	int i;

	uint32 uid = (uint32)r_u->uid;
	uint32 gid = (uint32)r_u->gid;

	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "vuid_io_user_struct");
	depth++;

	prs_align(ps);

	prs_uint32("uid", ps, depth, &uid);
	prs_uint32("gid", ps, depth, &gid);

	r_u->uid = (uid_t)uid;
	r_u->gid = (uid_t)gid;

	prs_align(ps);
	prs_string("name", ps, depth, r_u->name, strlen(r_u->name),
		   sizeof(r_u->name));
	prs_align(ps);
	prs_string("requested_name", ps, depth, r_u->requested_name,
		   strlen(r_u->requested_name), sizeof(r_u->requested_name));
	prs_align(ps);
	prs_string("real_name", ps, depth, r_u->real_name,
		   strlen(r_u->real_name), sizeof(r_u->real_name));
	prs_align(ps);
	prs_uint32("guest", ps, depth, &(r_u->guest));

	prs_uint32("n_groups", ps, depth, &(r_u->n_groups));
	if (r_u->n_groups != 0)
	{
		if (ps->io)
		{
			/* reading */
			r_u->groups = g_new(uint32, r_u->n_groups);
		}
		if (r_u->groups == NULL)
		{
			vuid_free_user_struct(r_u);
			return False;
		}
	}
	for (i = 0; i < r_u->n_groups; i++)
	{
		prs_uint32("", ps, depth, &(r_u->groups[i]));
	}

	net_io_user_info3("usr", &r_u->usr, ps, depth);

	return True;
}



/*******************************************************************
frees a structure.
********************************************************************/
void vuid_free_user_struct(user_struct * r_u)
{
	if (r_u != NULL && r_u->groups != NULL)
	{
		free(r_u->groups);
		r_u->groups = NULL;
	}
	safe_free(r_u);
}
