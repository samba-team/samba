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

PRIVS privs[] = {
	{SE_CREATE_TOKEN,		"SeCreateTokenPrivilege",		"Create Token"},
	{SE_ASSIGN_PRIMARY_TOKEN,	"SeAssignPrimaryTokenPrivilege",	"Assign Primary Token"},
	{SE_LOCK_MEMORY,		"SeLockMemoryPrivilege",		"Lock Memory"},
	{SE_INCREASE_QUOTA,		"SeIncreaseQuotaPrivilege",		"Increase Quota"},
	{SE_UNSOLICITED_INPUT,		"SeUnsolicitedInputPrivilege",		"Unsolicited Input"},
	{SE_MACHINE_ACCOUNT,		"SeMachineAccountPrivilege",		"Can add Machine Accounts to the Domain"},
	{SE_TCB,			"SeTcbPrivilege",			"TCB"},
	{SE_SECURITY,			"SeSecurityPrivilege",			"Security Privilege"},
	{SE_TAKE_OWNERSHIP,		"SeTakeOwnershipPrivilege",		"Take Ownership Privilege"},
	{SE_LOAD_DRIVER,		"SeLocalDriverPrivilege",		"Local Driver Privilege"},
	{SE_SYSTEM_PROFILE,		"SeSystemProfilePrivilege",		"System Profile Privilege"},
	{SE_SYSTEM_TIME,		"SeSystemtimePrivilege",		"System Time"},
	{SE_PROF_SINGLE_PROCESS,	"SeProfileSingleProcessPrivilege",	"Profile Single Process Privilege"},
	{SE_INC_BASE_PRIORITY,		"SeIncreaseBasePriorityPrivilege",	"Increase Base Priority Privilege"},
	{SE_CREATE_PAGEFILE,		"SeCreatePagefilePrivilege",		"Create Pagefile Privilege"},
	{SE_CREATE_PERMANENT,		"SeCreatePermanentPrivilege",		"Create Permanent"},
	{SE_BACKUP,			"SeBackupPrivilege",			"Backup Privilege"},
	{SE_RESTORE,			"SeRestorePrivilege",			"Restore Privilege"},
	{SE_SHUTDOWN,			"SeShutdownPrivilege",			"Shutdown Privilege"},
	{SE_DEBUG,			"SeDebugPrivilege",			"Debug Privilege"},
	{SE_AUDIT,			"SeAuditPrivilege",			"Audit"},
	{SE_SYSTEM_ENVIRONMENT,		"SeSystemEnvironmentPrivilege",		"System Environment Privilege"},
	{SE_CHANGE_NOTIFY,		"SeChangeNotifyPrivilege",		"Change Notify"},
	{SE_REMOTE_SHUTDOWN,		"SeRemoteShutdownPrivilege",		"Remote Shutdown Privilege"},
	{SE_UNDOCK,			"SeUndockPrivilege",			"Undock"},
	{SE_SYNC_AGENT,			"SeSynchronizationAgentPrivilege",	"Synchronization Agent"},
	{SE_ENABLE_DELEGATION,		"SeEnableDelegationPrivilege",		"Enable Delegation"},
	{SE_PRINT_OPERATOR,		"SePrintOperatorPrivilege",		"Printer Operator"},
	{SE_ADD_USERS,			"SeAddUsersPrivilege",			"Add Users"},
	{SE_ALL_PRIVS,			"SeAllPrivileges",			"All Privileges"}
};


/****************************************************************************
 duplicate alloc luid_attr
 ****************************************************************************/
NTSTATUS dupalloc_luid_attr(TALLOC_CTX *mem_ctx, LUID_ATTR **new_la, LUID_ATTR *old_la, int count)
{
	NTSTATUS ret;
	int i;

	/* don't crash if the source pointer is NULL (since we don't
	   do priviledges now anyways) */

	if ( !old_la )
		return NT_STATUS_OK;

	*new_la = (LUID_ATTR *)talloc(mem_ctx, count*sizeof(LUID_ATTR));
	ALLOC_CHECK(new_la, ret, done, "dupalloc_luid_attr");

	for (i=0; i<count; i++) {
		(*new_la)[i].luid.high = old_la[i].luid.high;
		(*new_la)[i].luid.low = old_la[i].luid.low;
		(*new_la)[i].attr = old_la[i].attr;
	}
	
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
	if (priv_set == NULL || *priv_set == NULL)
		return;

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

NTSTATUS add_privilege_by_name(PRIVILEGE_SET *priv_set, const char *name)
{
	int e;

	for (e = 0; privs[e].se_priv != SE_ALL_PRIVS; e++) {
		if (StrCaseCmp(privs[e].priv, name) == 0) {
			LUID_ATTR la;

			la.attr = 0;
			la.luid.high = 0;
			la.luid.low = privs[e].se_priv;

			return add_privilege(priv_set, la);
		}
	}

	DEBUG(1, ("add_privilege_by_name: No Such Privilege Found (%s)\n", name));

	return NT_STATUS_UNSUCCESSFUL;
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
	set.luid.low = SE_ADD_USERS;
	result = add_privilege(priv_set, set);
	NTSTATUS_CHECK(result, done, "add_all_privilege", "add_privilege");

	set.luid.low = SE_MACHINE_ACCOUNT;
	result = add_privilege(priv_set, set);
	NTSTATUS_CHECK(result, done, "add_all_privilege", "add_privilege");

	set.luid.low = SE_PRINT_OPERATOR;
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

	if (new_priv_set == NULL || priv_set == NULL)
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

	new_set = (LUID_ATTR *)talloc(new_priv_set->mem_ctx, (priv_set->count) * (sizeof(LUID_ATTR)));
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


NTSTATUS user_has_privilege(struct current_user *user, uint32 privilege)
{
	LUID_ATTR set;

	set.attr = 0;
	set.luid.high = 0;
	set.luid.low = privilege;

	return check_priv_in_privilege(user->privs, set);
}

BOOL luid_to_privilege_name(const LUID *set, fstring name)
{
	int i;

	if (set->high != 0)
		return False;

	for (i=1; i<PRIV_ALL_INDEX-1; i++) {
		if (set->low == privs[i].se_priv) {
			fstrcpy(name, privs[i].priv);
			return True;
		}
	}
	return False;
}
