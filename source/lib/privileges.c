/*
   Unix SMB/CIFS implementation.
   Privileges handling functions
   Copyright (C) Jean François Micouleau	1998-2001
   Copyright (C) Simo Sorce			2002-2003
   
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

/* defines */

#define ALLOC_CHECK(ptr, err, label, str) do { if ((ptr) == NULL) { DEBUG(0, ("%s: out of memory!\n", str)); err = NT_STATUS_NO_MEMORY; goto label; } } while(0)
#define NTSTATUS_CHECK(err, label, str1, str2) do { if (!NT_STATUS_IS_OK(err)) { DEBUG(0, ("%s: %s failed!\n", str1, str2)); } } while(0)

/****************************************************************************
 Check if a user is a mapped group.

   This function will check if the group SID is mapped onto a
   system managed gid or onto a winbind manged sid.
   In the first case it will be threated like a mapped group
   and the backend should take the member list with a getgrgid
   and ignore any user that have been possibly set into the group
   object.

   In the second case, the group is a fully SAM managed group
   served back to the system through winbind. In this case the
   members of a Local group are "unrolled" to cope with the fact
   that unix cannot contain groups inside groups.
   The backend MUST never call any getgr* / getpw* function or
   loops with winbind may happen. 
 ****************************************************************************/

#if 0
NTSTATUS is_mapped_group(BOOL *mapped, const DOM_SID *sid)
{
	NTSTATUS result;
	gid_t id;

	/* look if mapping exist, do not make idmap alloc an uid if SID is not found */
	result = idmap_get_gid_from_sid(&id, sid, False);
	if (NT_STATUS_IS_OK(result)) {
		*mapped = gid_is_in_winbind_range(id);
	} else {
		*mapped = False;
	}

	return result;
}
#endif

/****************************************************************************
 duplicate alloc luid_attr
 ****************************************************************************/
NTSTATUS dupalloc_luid_attr(TALLOC_CTX *mem_ctx, LUID_ATTR **new_la, LUID_ATTR *old_la)
{
	NTSTATUS ret;

	/* don't crash if the source pointer is NULL (since we don't
	   do priviledges now anyways) */

	if ( !old_la )
		return NT_STATUS_OK;

	*new_la = (LUID_ATTR *)talloc(mem_ctx, sizeof(LUID_ATTR));
	ALLOC_CHECK(new_la, ret, done, "dupalloc_luid_attr");

	(*new_la)->luid.high = old_la->luid.high;
	(*new_la)->luid.low = old_la->luid.low;
	(*new_la)->attr = old_la->attr;
	
	ret = NT_STATUS_OK;

done:
	return ret;
}

/****************************************************************************
 initialise a privilege list
 ****************************************************************************/
NTSTATUS init_privilege(PRIVILEGE_SET **priv_set)
{
	NTSTATUS ret;
	TALLOC_CTX *mem_ctx = talloc_init("privilege set");
	ALLOC_CHECK(mem_ctx, ret, done, "init_privilege");

	*priv_set = talloc_zero(mem_ctx, sizeof(PRIVILEGE_SET));
	ALLOC_CHECK(*priv_set, ret, done, "init_privilege");

	(*priv_set)->mem_ctx = mem_ctx;

	ret = NT_STATUS_OK;

done:
	return ret;
}

NTSTATUS init_priv_with_ctx(TALLOC_CTX *mem_ctx, PRIVILEGE_SET **priv_set)
{
	NTSTATUS ret;

	*priv_set = talloc_zero(mem_ctx, sizeof(PRIVILEGE_SET));
	ALLOC_CHECK(*priv_set, ret, done, "init_privilege");

	(*priv_set)->mem_ctx = mem_ctx;
	(*priv_set)->ext_ctx = True;

	ret = NT_STATUS_OK;

done:
	return ret;
}

void reset_privilege(PRIVILEGE_SET *priv_set)
{
	priv_set->count = 0;
	priv_set->control = 0;
	priv_set->set = NULL;
}

void destroy_privilege(PRIVILEGE_SET **priv_set)
{
	reset_privilege(*priv_set);
	if (!((*priv_set)->ext_ctx))
		/* mem_ctx is local, destroy it */
		talloc_destroy((*priv_set)->mem_ctx);
	*priv_set = NULL;
}

/****************************************************************************
 add a privilege to a privilege array
 ****************************************************************************/
NTSTATUS add_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	NTSTATUS ret;
	LUID_ATTR *new_set;

	/* check if the privilege is not already in the list */
	if (NT_STATUS_IS_OK(check_priv_in_privilege(priv_set, set)))
		return NT_STATUS_UNSUCCESSFUL;

	/* we can allocate memory to add the new privilege */

	new_set = (LUID_ATTR *)talloc_realloc(priv_set->mem_ctx, priv_set->set, (priv_set->count + 1) * (sizeof(LUID_ATTR)));
	ALLOC_CHECK(new_set, ret, done, "add_privilege");

	new_set[priv_set->count].luid.high = set.luid.high;
	new_set[priv_set->count].luid.low = set.luid.low;
	new_set[priv_set->count].attr = set.attr;

	priv_set->count++;
	priv_set->set = new_set;

	ret = NT_STATUS_OK;

done:
	return ret;
}

/****************************************************************************
 add all the privileges to a privilege array
 ****************************************************************************/
NTSTATUS add_all_privilege(PRIVILEGE_SET *priv_set)
{
	NTSTATUS result = NT_STATUS_OK;
	LUID_ATTR set;

	set.attr = 0;
	set.luid.high = 0;

	/* TODO: set a proper list of privileges */
	set.luid.low = SE_PRIV_ADD_USERS;
	result = add_privilege(priv_set, set);
	NTSTATUS_CHECK(result, done, "add_all_privilege", "add_privilege");

	set.luid.low = SE_PRIV_ADD_MACHINES;
	result = add_privilege(priv_set, set);
	NTSTATUS_CHECK(result, done, "add_all_privilege", "add_privilege");

	set.luid.low = SE_PRIV_PRINT_OPERATOR;
	result = add_privilege(priv_set, set);
	NTSTATUS_CHECK(result, done, "add_all_privilege", "add_privilege");

	return result;
}

/****************************************************************************
 check if the privilege list is empty
 ****************************************************************************/
NTSTATUS check_empty_privilege(PRIVILEGE_SET *priv_set)
{
	if (!priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	if (priv_set->count == 0)
		return NT_STATUS_OK;

	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
 check if the privilege is in the privilege list
 ****************************************************************************/
NTSTATUS check_priv_in_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	int i;

	if (!priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	/* if the list is empty, obviously we can't have it */
	if (NT_STATUS_IS_OK(check_empty_privilege(priv_set)))
		return NT_STATUS_UNSUCCESSFUL;

	for (i = 0; i < priv_set->count; i++) {
		LUID_ATTR *cur_set;

		cur_set = &priv_set->set[i];
		/* check only the low and high part. Checking the attr field has no meaning */
		if (	(cur_set->luid.low == set.luid.low) &&
			(cur_set->luid.high == set.luid.high)	) {
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
 remove a privilege from a privilege array
 ****************************************************************************/
NTSTATUS remove_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	NTSTATUS ret;
	LUID_ATTR *new_set;
	LUID_ATTR *old_set;
	int i,j;

	if (!priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	/* check if the privilege is in the list */
	if (!NT_STATUS_IS_OK(check_priv_in_privilege(priv_set, set)))
		return NT_STATUS_UNSUCCESSFUL;

	/* special case if it's the only privilege in the list */
	if (priv_set->count == 1) {
		reset_privilege(priv_set);	
		return NT_STATUS_OK;
	}

	/* 
	 * the privilege is there, create a new list,
	 * and copy the other privileges
	 */

	old_set = priv_set->set;

	new_set = (LUID_ATTR *)talloc(priv_set->mem_ctx, (priv_set->count - 1) * (sizeof(LUID_ATTR)));
	ALLOC_CHECK(new_set, ret, done, "remove_privilege");

	for (i=0, j=0; i < priv_set->count; i++) {
		if (	(old_set[i].luid.low == set.luid.low) && 
			(old_set[i].luid.high == set.luid.high)	) {
		    	continue;
		}
		
		new_set[j].luid.low = old_set[i].luid.low;
		new_set[j].luid.high = old_set[i].luid.high;
		new_set[j].attr = old_set[i].attr;

		j++;
	}
	
	if (j != priv_set->count - 1) {
		DEBUG(0,("remove_privilege: mismatch ! difference is not -1\n"));
		DEBUGADD(0,("old count:%d, new count:%d\n", priv_set->count, j));
		return NT_STATUS_INTERNAL_ERROR;
	}
		
	/* ok everything is fine */
	
	priv_set->count--;
	priv_set->set = new_set;
	
	ret = NT_STATUS_OK;

done:
	return ret;
}

/****************************************************************************
 duplicates a privilege array
 the new privilege set must be passed inited
 (use init_privilege or init_priv_with_ctx)
 ****************************************************************************/
NTSTATUS dup_priv_set(PRIVILEGE_SET *new_priv_set, PRIVILEGE_SET *priv_set)
{
	NTSTATUS ret;
	LUID_ATTR *new_set;
	LUID_ATTR *old_set;
	int i;

	if (!new_priv_set || !priv_set)
		return NT_STATUS_INVALID_PARAMETER;

	/* special case if there are no privileges in the list */
	if (priv_set->count == 0) {
		return NT_STATUS_OK;
	}

	/* 
	 * create a new list,
	 * and copy the other privileges
	 */

	old_set = priv_set->set;

	new_set = (LUID_ATTR *)talloc(new_priv_set->mem_ctx, (priv_set->count - 1) * (sizeof(LUID_ATTR)));
	ALLOC_CHECK(new_set, ret, done, "dup_priv_set");

	for (i=0; i < priv_set->count; i++) {
		
		new_set[i].luid.low = old_set[i].luid.low;
		new_set[i].luid.high = old_set[i].luid.high;
		new_set[i].attr = old_set[i].attr;
	}
			
	new_priv_set->count = priv_set->count;
	new_priv_set->control = priv_set->control;
	new_priv_set->set = new_set;
	
	ret = NT_STATUS_OK;

done:
	return ret;
}
