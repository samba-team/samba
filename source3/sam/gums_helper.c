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

extern DOM_SID global_sid_World;
extern DOM_SID global_sid_Builtin;
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
#define NTSTATUS_CHECK(err, label, str1, str2) do { if (NT_STATUS_IS_ERR(err)) { DEBUG(0, ("%s: %s\n", str1, str2)); } } while(0)

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

#define ALIAS_DEFAULT_SACL_SA_RIGHTS	0x01050013
#define ALIAS_DEFAULT_DACL_SA_RIGHTS \
		(READ_CONTROL_ACCESS		| \
		SA_RIGHT_ALIAS_LOOKUP_INFO	| \
		SA_RIGHT_ALIAS_GET_MEMBERS)	/* 0x0002000c */

#define ALIAS_DEFAULT_SACL_SEC_ACE_FLAG (SEC_ACE_FLAG_FAILED_ACCESS | SEC_ACE_FLAG_SUCCESSFUL_ACCESS) /* 0xc0 */


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

	*sec_desc = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, admins, admins, sacl, dacl, &psize);
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

NTSTATUS gums_make_domain(DOM_SID *sid, const char *name, const char *description)
{
	NTSTATUS ret;
	GUMS_OBJECT *go;
	GUMS_FUNCTIONS *fns;

	if (!NT_STATUS_IS_OK(ret = get_gums_fns(&fns)))
		return ret;

	if (!NT_STATUS_IS_OK(ret = gums_create_object(&go, GUMS_OBJ_DOMAIN)))
		return ret;

	ret = gums_set_object_sid(go, sid);
	NTSTATUS_CHECK(ret, done, "gums_make_alias", "unable to set sid!");

	ret = gums_set_object_name(go, name);
	NTSTATUS_CHECK(ret, done, "gums_make_alias", "unable to set name!");

	if (description) {
		ret = gums_set_object_description(go, description);
		NTSTATUS_CHECK(ret, done, "gums_make_alias", "unable to set description!");
	}

	/* make security descriptor * /
	ret = create_builtin_alias_default_sec_desc(&((*go).sec_desc), (*go).mem_ctx); 
	NTSTATUS_CHECK(ret, error, "gums_init_backend", "create_builtin_alias_default_sec_desc");
	*/

	ret = fns->set_object(go);

	gums_destroy_object(&go);
	return ret;
}

NTSTATUS gums_make_alias(DOM_SID *sid, const char *name, const char *description)
{
	NTSTATUS ret;
	GUMS_OBJECT *go;
	GUMS_FUNCTIONS *fns;

	if (!NT_STATUS_IS_OK(ret = get_gums_fns(&fns)))
		return ret;

	if (!NT_STATUS_IS_OK(ret = gums_create_object(&go, GUMS_OBJ_ALIAS)))
		return ret;

	ret = gums_set_object_sid(go, sid);
	NTSTATUS_CHECK(ret, done, "gums_make_alias", "unable to set sid!");

	ret = gums_set_object_name(go, name);
	NTSTATUS_CHECK(ret, done, "gums_make_alias", "unable to set name!");

	if (description) {
		ret = gums_set_object_description(go, description);
		NTSTATUS_CHECK(ret, done, "gums_make_alias", "unable to set description!");
	}

	/* make security descriptor * /
	ret = create_builtin_alias_default_sec_desc(&((*go).sec_desc), (*go).mem_ctx); 
	NTSTATUS_CHECK(ret, error, "gums_init_backend", "create_builtin_alias_default_sec_desc");
	*/

	ret = fns->set_object(go);

	gums_destroy_object(&go);
	return ret;
}

NTSTATUS gums_init_domain(DOM_SID *sid, const char *name, const char * description)
{
	NTSTATUS ret;

	/* Add the weelknown Builtin Domain */
	if (!NT_STATUS_IS_OK(ret = gums_make_domain(
					sid,
					name,
					description
					))) {
		return ret;
	}

	/* Add default users and groups */
	/* Administrator
	   Guest
	   Domain Administrators
	   Domain Users
	   Domain Guests
	*/

	return ret;
}

NTSTATUS gums_init_builtin_domain(void)
{
	NTSTATUS ret;

	generate_wellknown_sids();

	/* Add the weelknown Builtin Domain */
	if (!NT_STATUS_IS_OK(ret = gums_make_domain(
					&global_sid_Builtin,
					"BUILTIN",
					"Builtin Domain"
					))) {
		return ret;
	}

	/* Add the well known Builtin Local Groups */

	/* Administrators */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Administrators,
					"Administrators",
					"Members can fully administer the computer/domain"
					))) {
		return ret;
	}
	/* Administrator privilege set */
	/* From BDC join trace:
		SeSecurityPrivilege, SeBackupPrivilege, SeRestorePrivilege,
		SeSystemtimePrivilege, SeShutdownPrivilege,
		SeRemoteShutdownPrivilege, SeTakeOwnershipPrivilege,
		SeDebugPrivilege, SeSystemEnvironmentPrivilege,
		SeSystemProfilePrivilege, SeProfileSingleProcessPrivilege,
		SeIncreaseBasePriorityPrivilege, SeLocalDriverPrivilege,
		SeCreatePagefilePrivilege, SeIncreaseQuotaPrivilege
	 */

	/* Power Users */
	/* Domain Controllers Does NOT have Power Users (?) */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Power_Users,
					"Power Users",
					"Power Users"
					))) {
		return ret;
	}

	/* Power Users privilege set */
	/* (?) */

	/* Account Operators */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Account_Operators,
					"Account Operators",
					"Members can administer domain user and group accounts"
					))) {
		return ret;
	}

	/* make privilege set */
	/* From BDC join trace:
		SeShutdownPrivilege
	 */

	/* Server Operators */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Server_Operators,
					"Server Operators",
					"Members can administer domain servers"
					))) {
		return ret;
	}

	/* make privilege set */
	/* From BDC join trace:
		SeBackupPrivilege, SeRestorePrivilege, SeSystemtimePrivilege,
		SeShutdownPrivilege, SeRemoteShutdownPrivilege
	 */

	/* Print Operators */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Print_Operators,
					"Print Operators",
					"Members can administer domain printers"
					))) {
		return ret;
	}

	/* make privilege set */
	/* From BDC join trace:
		SeShutdownPrivilege
	 */

	/* Backup Operators */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Backup_Operators,
					"Backup Operators",
					"Members can bypass file security to backup files"
					))) {
		return ret;
	}

	/* make privilege set */
	/* From BDC join trace:
		SeBackupPrivilege, SeRestorePrivilege, SeShutdownPrivilege
	 */

	/* Replicator */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Replicator,
					"Replicator",
					"Supports file replication in a domain"
					))) {
		return ret;
	}

	/* make privilege set */
	/* From BDC join trace:
		SeBackupPrivilege, SeRestorePrivilege, SeShutdownPrivilege
	 */

	/* Users */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Users,
					"Users",
					"Ordinary users"
					))) {
		return ret;
	}

	/* Users specific ACEs * /
	sec_desc_add_ace_to_dacl(go->sec_desc, go->mem_ctx, &global_sid_Builtin_Account_Operators, ALIAS_DEFAULT_DACL_SA_RIGHTS);
	sec_desc_add_ace_to_dacl(go->sec_desc, go->mem_ctx, &global_sid_Builtin_Power_Users, ALIAS_DEFAULT_DACL_SA_RIGHTS);
	*/

	/* Guests */
	if (!NT_STATUS_IS_OK(ret = gums_make_alias(
					&global_sid_Builtin_Guests,
					"Guests",
					"Users granted guest access to the computer/domain"
					))) {
		return ret;
	}

	return ret;
}

