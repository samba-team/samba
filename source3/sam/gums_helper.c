/*
   Unix SMB/CIFS implementation.
   GUMS backends helper functions
   Copyright (C) Simo Sorce 2002
   
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

extern GUMS_FUNCTIONS *gums_storage;

extern DOM_SID global_sid_World;
extern DOM_SID global_sid_Builtin_Administrators;
extern DOM_SID global_sid_Builtin_Power_Users;
extern DOM_SID global_sid_Builtin_Account_Operators;
extern DOM_SID global_sid_Builtin_Server_Operators;
extern DOM_SID global_sid_Builtin_Print_Operators;
extern DOM_SID global_sid_Builtin_Backup_Operators;
extern DOM_SID global_sid_Builtin_Replicator;
extern DOM_SID global_sid_Builtin_Users;
extern DOM_SID global_sid_Builtin_Guests;


/* defines */

#define ALLOC_CHECK(str, ptr, err, label) do { if ((ptr) == NULL) { DEBUG(0, ("%s: out of memory!\n", str)); err = NT_STATUS_NO_MEMORY; goto label; } } while(0)
#define NTSTATUS_CHECK(str1, str2, err, label) do { if (NT_STATUS_IS_ERR(err)) { DEBUG(0, ("%s: %s failed!\n", str1, str2)); } } while(0)

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
NTSTATUS dupalloc_luid_attr(TALLOC_CTX *ctx, LUID_ATTR **new_la, LUID_ATTR old_la)
{
	*new_la = (LUID_ATTR *)talloc(ctx, sizeof(LUID_ATTR));
	if (*new_la == NULL) {
		DEBUG(0,("dupalloc_luid_attr: could not Alloc memory to duplicate LUID_ATTR\n"));
		return NT_STATUS_NO_MEMORY;
	}

	(*new_la)->luid.high = old_la.luid.high;
	(*new_la)->luid.low = old_la.luid.low;
	(*new_la)->attr = old_la.attr;
	
	return NT_STATUS_OK;	
}

/****************************************************************************
 initialise a privilege list
 ****************************************************************************/
void gums_init_privilege(PRIVILEGE_SET *priv_set)
{
	priv_set->count=0;
	priv_set->control=0;
	priv_set->set=NULL;
}

/****************************************************************************
 add a privilege to a privilege array
 ****************************************************************************/
NTSTATUS gums_add_privilege(PRIVILEGE_SET *priv_set, TALLOC_CTX *ctx, LUID_ATTR set)
{
	LUID_ATTR *new_set;

	/* check if the privilege is not already in the list */
	if (gums_check_priv_in_privilege(priv_set, set))
		return NT_STATUS_UNSUCCESSFUL;

	/* we can allocate memory to add the new privilege */

	new_set=(LUID_ATTR *)talloc_realloc(ctx, priv_set->set, (priv_set->count+1)*(sizeof(LUID_ATTR)));
	if (new_set==NULL) {
		DEBUG(0,("add_privilege: could not Realloc memory to add a new privilege\n"));
		return NT_STATUS_NO_MEMORY;
	}

	new_set[priv_set->count].luid.high=set.luid.high;
	new_set[priv_set->count].luid.low=set.luid.low;
	new_set[priv_set->count].attr=set.attr;
	
	priv_set->count++;
	priv_set->set=new_set;
	
	return NT_STATUS_OK;	
}

/****************************************************************************
 add all the privileges to a privilege array
 ****************************************************************************/
NTSTATUS gums_add_all_privilege(PRIVILEGE_SET *priv_set, TALLOC_CTX *ctx)
{
	NTSTATUS result = NT_STATUS_OK;
	LUID_ATTR set;

	set.attr=0;
	set.luid.high=0;
	
	set.luid.low=SE_PRIV_ADD_USERS;
	result = gums_add_privilege(priv_set, ctx, set);
	NTSTATUS_CHECK("add_all_privilege", "add_privilege", result, done);
	
	set.luid.low=SE_PRIV_ADD_MACHINES;
	result = gums_add_privilege(priv_set, ctx, set);
	NTSTATUS_CHECK("add_all_privilege", "add_privilege", result, done);

	set.luid.low=SE_PRIV_PRINT_OPERATOR;
	result = gums_add_privilege(priv_set, ctx, set);
	NTSTATUS_CHECK("add_all_privilege", "add_privilege", result, done);
	
done:
	return result;
}

/****************************************************************************
 check if the privilege list is empty
 ****************************************************************************/
BOOL gums_check_empty_privilege(PRIVILEGE_SET *priv_set)
{
	return (priv_set->count == 0);
}

/****************************************************************************
 check if the privilege is in the privilege list
 ****************************************************************************/
BOOL gums_check_priv_in_privilege(PRIVILEGE_SET *priv_set, LUID_ATTR set)
{
	int i;

	/* if the list is empty, obviously we can't have it */
	if (gums_check_empty_privilege(priv_set))
		return False;

	for (i=0; i<priv_set->count; i++) {
		LUID_ATTR *cur_set;

		cur_set=&priv_set->set[i];
		/* check only the low and high part. Checking the attr field has no meaning */
		if( (cur_set->luid.low==set.luid.low) && (cur_set->luid.high==set.luid.high) )
			return True;
	}

	return False;
}

/****************************************************************************
 remove a privilege from a privilege array
 ****************************************************************************/
NTSTATUS gums_remove_privilege(PRIVILEGE_SET *priv_set, TALLOC_CTX *ctx, LUID_ATTR set)
{
	LUID_ATTR *new_set;
	LUID_ATTR *old_set;
	int i,j;

	/* check if the privilege is in the list */
	if (!gums_check_priv_in_privilege(priv_set, set))
		return NT_STATUS_UNSUCCESSFUL;

	/* special case if it's the only privilege in the list */
	if (priv_set->count==1) {
		gums_init_privilege(priv_set);	
		return NT_STATUS_OK;
	}

	/* 
	 * the privilege is there, create a new list,
	 * and copy the other privileges
	 */

	old_set = priv_set->set;

	new_set=(LUID_ATTR *)talloc(ctx, (priv_set->count - 1) * (sizeof(LUID_ATTR)));
	if (new_set==NULL) {
		DEBUG(0,("remove_privilege: could not malloc memory for new privilege list\n"));
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0, j=0; i<priv_set->count; i++) {
		if ((old_set[i].luid.low == set.luid.low) && 
		    (old_set[i].luid.high == set.luid.high)) {
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
	priv_set->set=new_set;
	
	return NT_STATUS_OK;	
}

/****************************************************************************
 duplicates a privilege array
 ****************************************************************************/
NTSTATUS gums_dup_priv_set(PRIVILEGE_SET **new_priv_set, TALLOC_CTX *mem_ctx, PRIVILEGE_SET *priv_set)
{
	LUID_ATTR *new_set;
	LUID_ATTR *old_set;
	int i;

	*new_priv_set = (PRIVILEGE_SET *)talloc(mem_ctx, sizeof(PRIVILEGE_SET));
	gums_init_privilege(*new_priv_set);	

	/* special case if there are no privileges in the list */
	if (priv_set->count == 0) {
		return NT_STATUS_OK;
	}

	/* 
	 * create a new list,
	 * and copy the other privileges
	 */

	old_set = priv_set->set;

	new_set = (LUID_ATTR *)talloc(mem_ctx, (priv_set->count - 1) * (sizeof(LUID_ATTR)));
	if (new_set==NULL) {
		DEBUG(0,("remove_privilege: could not malloc memory for new privilege list\n"));
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i < priv_set->count; i++) {
		
		new_set[i].luid.low = old_set[i].luid.low;
		new_set[i].luid.high = old_set[i].luid.high;
		new_set[i].attr = old_set[i].attr;
	}
			
	(*new_priv_set)->count = priv_set->count;
	(*new_priv_set)->control = priv_set->control;
	(*new_priv_set)->set = new_set;
	
	return NT_STATUS_OK;	
}

#define ALIAS_DEFAULT_SACL_SA_RIGHTS	0x01050013
#define ALIAS_DEFAULT_DACL_SA_RIGHTS \
		(READ_CONTROL_ACCESS		| \
		SA_RIGHT_ALIAS_LOOKUP_INFO	| \
		SA_RIGHT_ALIAS_GET_MEMBERS)	/* 0x0002000c */

#define ALIAS_DEFAULT_SACL_SEC_ACE_FLAG (SEC_ACE_FLAG_FAILED_ACCESS | SEC_ACE_FLAG_SUCCESSFUL_ACCESS) /* 0xc0 */


#if 0
NTSTATUS create_builtin_alias_default_sec_desc(SEC_DESC **sec_desc, TALLOC_CTX *ctx)
{
	DOM_SID *world = &global_sid_World;
	DOM_SID *admins = &global_sid_Builtin_Administrators;
	SEC_ACCESS sa;
	SEC_ACE sacl_ace;
	SEC_ACE dacl_aces[2];
	SEC_ACL *sacl = NULL;
	SEC_ACL *dacl = NULL;
	size_t psize;

	init_sec_access(&sa, ALIAS_DEFAULT_SACL_SA_RIGHTS);
	init_sec_ace(&sacl_ace, world, SEC_ACE_TYPE_SYSTEM_AUDIT, sa, ALIAS_DEFAULT_SACL_SEC_ACE_FLAG);
	
	sacl = make_sec_acl(ctx, NT4_ACL_REVISION, 1, &sacl_ace);
	if (!sacl) {
		DEBUG(0, ("build_init_sec_desc: Failed to make SEC_ACL.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	init_sec_access(&sa, ALIAS_DEFAULT_DACL_SA_RIGHTS);
	init_sec_ace(&(dacl_aces[0]), world, SEC_ACE_TYPE_ACCESS_ALLOWED, sa, 0);
	init_sec_access(&sa, SA_RIGHT_ALIAS_ALL_ACCESS);
	init_sec_ace(&(dacl_aces[1]), admins, SEC_ACE_TYPE_ACCESS_ALLOWED, sa, 0);

	dacl = make_sec_acl(ctx, NT4_ACL_REVISION, 2, dacl_aces);
	if (!sacl) {
		DEBUG(0, ("build_init_sec_desc: Failed to make SEC_ACL.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	*sec_desc = make_sec_desc(ctx, SEC_DESC_REVISION, admins, admins, sacl, dacl, &psize);
	if (!(*sec_desc)) {
		DEBUG(0,("get_share_security: Failed to make SEC_DESC.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

NTSTATUS sec_desc_add_ace_to_dacl(SEC_DESC *sec_desc, TALLOC_CTX *ctx, DOM_SID *sid, uint32 mask)
{
	NTSTATUS result;
	SEC_ACE *new_aces;
	unsigned num_aces;
	int i;

	num_aces = sec_desc->dacl->num_aces + 1;
	result = sec_ace_add_sid(ctx, &new_aces, sec_desc->dacl->ace, &num_aces, sid, mask);
	if (NT_STATUS_IS_OK(result)) {
		sec_desc->dacl->ace = new_aces;
		sec_desc->dacl->num_aces = num_aces;
		sec_desc->dacl->size = SEC_ACL_HEADER_SIZE;
		for (i = 0; i < num_aces; i++) {
			sec_desc->dacl->size += sec_desc->dacl->ace[i].size;
		}
	}
	return result;
}

NTSTATUS gums_init_builtin_groups(void)
{
	NTSTATUS result;
	GUMS_OBJECT g_obj;
	GUMS_GROUP *g_grp;
	GUMS_PRIVILEGE g_priv;

	/* Build the well known Builtin Local Groups */
	g_obj.type = GUMS_OBJ_GROUP;
	g_obj.version = 1;
	g_obj.seq_num = 0;
	g_obj.mem_ctx = talloc_init("gums_init_backend_acct");
	if (g_obj.mem_ctx == NULL) {
		DEBUG(0, ("gums_init_backend: Out of Memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Administrators * /

	/* alloc group structure */
	g_obj.data.group = (GUMS_GROUP *)talloc(g_obj.mem_ctx, sizeof(GUMS_GROUP));
	ALLOC_CHECK("gums_init_backend", g_obj.data.group, result, done);

	/* make admins sid */
	g_grp = (GUMS_GROUP *)g_obj.data.group;
	sid_copy(g_obj.sid, &global_sid_Builtin_Administrators);

	/* make security descriptor */
	result = create_builtin_alias_default_sec_desc(&(g_obj.sec_desc), g_obj.mem_ctx); 
	NTSTATUS_CHECK("gums_init_backend", "create_builtin_alias_default_sec_desc", result, done);

	/* make privilege set */
	/* From BDC join trace:
		SeSecurityPrivilege
		SeBackupPrivilege
		SeRestorePrivilege
		SeSystemtimePrivilege
		SeShutdownPrivilege
		SeRemoteShutdownPrivilege
		SeTakeOwnershipPrivilege
		SeDebugPrivilege
		SeSystemEnvironmentPrivilege
		SeSystemProfilePrivilege
		SeProfileSingleProcessPrivilege
		SeIncreaseBasePriorityPrivilege
		SeLocalDriverPrivilege
		SeCreatePagefilePrivilege
		SeIncreaseQuotaPrivilege
	 */

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Administrators");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Members can fully administer the computer/domain");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* numebr of group members */
	g_grp->count = 0;
	g_grp->members = NULL;

	/* store Administrators group */
	result = gums_storage->set_object(&g_obj);

	/* Power Users */
	/* Domain Controllers Does NOT have power Users */

	sid_copy(g_obj.sid, &global_sid_Builtin_Power_Users);

	/* make privilege set */
	/* SE_PRIV_??? */

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Power Users");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
/* > */	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Power Users");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* store Power Users group */
	result = gums_storage->set_object(&g_obj);

	/* Account Operators */

	sid_copy(g_obj.sid, &global_sid_Builtin_Account_Operators);

	/* make privilege set */
	/* From BDC join trace:
		SeShutdownPrivilege
	 */

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Account Operators");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Members can administer domain user and group accounts");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* store Account Operators group */
	result = gums_storage->set_object(&g_obj);

	/* Server Operators */

	sid_copy(g_obj.sid, &global_sid_Builtin_Server_Operators);

	/* make privilege set */
	/* From BDC join trace:
		SeBackupPrivilege
		SeRestorePrivilege
		SeSystemtimePrivilege
		SeShutdownPrivilege
		SeRemoteShutdownPrivilege
	 */

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Server Operators");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Members can administer domain servers");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* store Server Operators group */
	result = gums_storage->set_object(&g_obj);

	/* Print Operators */

	sid_copy(g_obj.sid, &global_sid_Builtin_Print_Operators);

	/* make privilege set */
	/* From BDC join trace:
		SeShutdownPrivilege
	 */

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Print Operators");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Members can administer domain printers");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* store Print Operators group */
	result = gums_storage->set_object(&g_obj);

	/* Backup Operators */

	sid_copy(g_obj.sid, &global_sid_Builtin_Backup_Operators);

	/* make privilege set */
	/* From BDC join trace:
		SeBackupPrivilege
		SeRestorePrivilege
		SeShutdownPrivilege
	 */

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Backup Operators");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Members can bypass file security to backup files");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* store Backup Operators group */
	result = gums_storage->set_object(&g_obj);

	/* Replicator */

	sid_copy(g_obj.sid, &global_sid_Builtin_Replicator);

	/* make privilege set */
	/* From BDC join trace:
		SeBackupPrivilege
		SeRestorePrivilege
		SeShutdownPrivilege
	 */

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Replicator");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Supports file replication in a domain");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* store Replicator group */
	result = gums_storage->set_object(&g_obj);

	/* Users */

	sid_copy(g_obj.sid, &global_sid_Builtin_Users);

	/* add ACE to sec dsec dacl */
	sec_desc_add_ace_to_dacl(g_obj.sec_desc, g_obj.mem_ctx, &global_sid_Builtin_Account_Operators, ALIAS_DEFAULT_DACL_SA_RIGHTS);
	sec_desc_add_ace_to_dacl(g_obj.sec_desc, g_obj.mem_ctx, &global_sid_Builtin_Power_Users, ALIAS_DEFAULT_DACL_SA_RIGHTS);

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Users");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Ordinary users");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* store Users group */
	result = gums_storage->set_object(&g_obj);

	/* Guests */

	sid_copy(g_obj.sid, &global_sid_Builtin_Guests);

	/* set name */
	g_obj.name = talloc_strdup(g_obj.mem_ctx, "Guests");
	ALLOC_CHECK("gums_init_backend", g_obj.name, result, done);

	/* set description */
	g_obj.description = talloc_strdup(g_obj.mem_ctx, "Users granted guest access to the computer/domain");
	ALLOC_CHECK("gums_init_backend", g_obj.description, result, done);

	/* store Guests group */
	result = gums_storage->set_object(&g_obj);

	/* set default privileges */
	g_priv.type = GUMS_OBJ_GROUP;
	g_priv.version = 1;
	g_priv.seq_num = 0;
	g_priv.mem_ctx = talloc_init("gums_init_backend_priv");
	if (g_priv.mem_ctx == NULL) {
		DEBUG(0, ("gums_init_backend: Out of Memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

		

done:
	talloc_destroy(g_obj.mem_ctx);
	talloc_destroy(g_priv.mem_ctx);
	return result;
}
#endif

