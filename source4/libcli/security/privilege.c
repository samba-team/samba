/*
   Unix SMB/CIFS implementation.

   manipulate privileges

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett 2010

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
#include "librpc/gen_ndr/security.h" 
#include "libcli/security/security.h" 


static const struct {
	enum sec_privilege privilege;
	uint64_t privilege_mask;
	const char *name;
	const char *display_name;
} privilege_names[] = {
	{SEC_PRIV_SECURITY,                   
	 SE_SECURITY,
	 "SeSecurityPrivilege",
	"System security"},

	{SEC_PRIV_BACKUP,                     
	 SE_BACKUP,
	 "SeBackupPrivilege",
	 "Backup files and directories"},

	{SEC_PRIV_RESTORE,                    
	 SE_RESTORE,
	 "SeRestorePrivilege",
	"Restore files and directories"},

	{SEC_PRIV_SYSTEMTIME,                 
	 SE_SYSTEMTIME,
	 "SeSystemtimePrivilege",
	"Set the system clock"},

	{SEC_PRIV_SHUTDOWN,                   
	 SE_SHUTDOWN,
	 "SeShutdownPrivilege",
	"Shutdown the system"},

	{SEC_PRIV_REMOTE_SHUTDOWN,            
	 SE_REMOTE_SHUTDOWN,
	 "SeRemoteShutdownPrivilege",
	"Shutdown the system remotely"},

	{SEC_PRIV_TAKE_OWNERSHIP,             
	 SE_TAKE_OWNERSHIP,
	 "SeTakeOwnershipPrivilege",
	"Take ownership of files and directories"},

	{SEC_PRIV_DEBUG,                      
	 SE_DEBUG,
	 "SeDebugPrivilege",
	"Debug processes"},

	{SEC_PRIV_SYSTEM_ENVIRONMENT,         
	 SE_SYSTEM_ENVIRONMENT,
	 "SeSystemEnvironmentPrivilege",
	"Modify system environment"},

	{SEC_PRIV_SYSTEM_PROFILE,             
	 SE_SYSTEM_PROFILE,
	 "SeSystemProfilePrivilege",
	"Profile the system"},

	{SEC_PRIV_PROFILE_SINGLE_PROCESS,     
	 SE_PROFILE_SINGLE_PROCESS,
	 "SeProfileSingleProcessPrivilege",
	"Profile one process"},

	{SEC_PRIV_INCREASE_BASE_PRIORITY,     
	 SE_INCREASE_BASE_PRIORITY,
	 "SeIncreaseBasePriorityPrivilege",
	 "Increase base priority"},

	{SEC_PRIV_LOAD_DRIVER,
	 SE_LOAD_DRIVER,
	 "SeLoadDriverPrivilege",
	"Load drivers"},

	{SEC_PRIV_CREATE_PAGEFILE,            
	 SE_CREATE_PAGEFILE,
	 "SeCreatePagefilePrivilege",
	"Create page files"},

	{SEC_PRIV_INCREASE_QUOTA,
	 SE_INCREASE_QUOTA,
	 "SeIncreaseQuotaPrivilege",
	"Increase quota"},

	{SEC_PRIV_CHANGE_NOTIFY,              
	 SE_CHANGE_NOTIFY,
	 "SeChangeNotifyPrivilege",
	"Register for change notify"},

	{SEC_PRIV_UNDOCK,                     
	 SE_UNDOCK,
	 "SeUndockPrivilege",
	"Undock devices"},

	{SEC_PRIV_MANAGE_VOLUME,              
	 SE_MANAGE_VOLUME,
	 "SeManageVolumePrivilege",
	"Manage system volumes"},

	{SEC_PRIV_IMPERSONATE,                
	 SE_IMPERSONATE,
	 "SeImpersonatePrivilege",
	"Impersonate users"},

	{SEC_PRIV_CREATE_GLOBAL,              
	 SE_CREATE_GLOBAL,
	 "SeCreateGlobalPrivilege",
	"Create global"},

	{SEC_PRIV_ENABLE_DELEGATION,          
	 SE_ENABLE_DELEGATION,
	 "SeEnableDelegationPrivilege",
	"Enable Delegation"},

	{SEC_PRIV_INTERACTIVE_LOGON,          
	 SE_INTERACTIVE_LOGON,
	 "SeInteractiveLogonRight",
	"Interactive logon"},

	{SEC_PRIV_NETWORK_LOGON,
	 SE_NETWORK_LOGON,
	 "SeNetworkLogonRight",
	"Network logon"},

	{SEC_PRIV_REMOTE_INTERACTIVE_LOGON,   
	 SE_REMOTE_INTERACTIVE_LOGON,
	 "SeRemoteInteractiveLogonRight",
	"Remote Interactive logon"},

	{SEC_PRIV_MACHINE_ACCOUNT,
	 SE_MACHINE_ACCOUNT,
	 "SeMachineAccountPrivilege",
	 "Add workstations to domain"},

	/* These last 3 are Samba only */
	{SEC_PRIV_PRINT_OPERATOR,
	 SE_PRINT_OPERATOR,
	 "SePrintOperatorPrivilege",
	 "Manage printers"},

	{SEC_PRIV_ADD_USERS,
	 SE_ADD_USERS,
	 "SeAddUsersPrivilege",
	 "Add users and groups to the domain"},

	{SEC_PRIV_DISK_OPERATOR,
	 SE_DISK_OPERATOR,
	 "SeDiskOperatorPrivilege",
	 "Manage disk shares"},
};


/*
  map a privilege id to the wire string constant
*/
const char *sec_privilege_name(enum sec_privilege privilege)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privilege_names);i++) {
		if (privilege_names[i].privilege == privilege) {
			return privilege_names[i].name;
		}
	}
	return NULL;
}

/*
  map a privilege id to a privilege display name. Return NULL if not found
  
  TODO: this should use language mappings
*/
const char *sec_privilege_display_name(enum sec_privilege privilege, uint16_t *language)
{
	int i;
	if (privilege < 1 || privilege > 64) {
		return NULL;
	}
	for (i=0;i<ARRAY_SIZE(privilege_names);i++) {
		if (privilege_names[i].privilege == privilege) {
			return privilege_names[i].display_name;
		}
	}
	return NULL;
}

/*
  map a privilege name to a privilege id. Return -1 if not found
*/
enum sec_privilege sec_privilege_id(const char *name)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privilege_names);i++) {
		if (strcasecmp(privilege_names[i].name, name) == 0) {
			return privilege_names[i].privilege;
		}
	}
	return -1;
}

/*
  map a privilege name to a privilege id. Return -1 if not found
*/
enum sec_privilege sec_privilege_from_mask(uint64_t mask)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privilege_names);i++) {
		if (privilege_names[i].privilege_mask == mask) {
			return privilege_names[i].privilege;
		}
	}
	return -1;
}

/*
  map a privilege name to a privilege id. Return -1 if not found
*/
enum sec_privilege sec_privilege_from_index(int idx)
{
	if (idx >= 0 && idx<ARRAY_SIZE(privilege_names)) {
		return privilege_names[idx].privilege;
	}
	return -1;
}


/*
  return a privilege mask given a privilege id
*/
static uint64_t sec_privilege_mask(enum sec_privilege privilege)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privilege_names);i++) {
		if (privilege_names[i].privilege == privilege) {
			return privilege_names[i].privilege_mask;
		}
	}

	return 0;
}


/*
  return true if a security_token has a particular privilege bit set
*/
bool security_token_has_privilege(const struct security_token *token, enum sec_privilege privilege)
{
	uint64_t mask;

	mask = sec_privilege_mask(privilege);
	if (mask == 0) {
		return false;
	}

	if (token->privilege_mask & mask) {
		return true;
	}
	return false;
}

/*
  set a bit in the privilege mask
*/
void security_token_set_privilege(struct security_token *token, enum sec_privilege privilege)
{
	/* Relies on the fact that an invalid privilage will return 0, so won't change this */
	token->privilege_mask |= sec_privilege_mask(privilege);
}

void security_token_debug_privileges(int dbg_lev, const struct security_token *token)
{
	DEBUGADD(dbg_lev, (" Privileges (0x%16llX):\n",
			    (unsigned long long) token->privilege_mask));

	if (token->privilege_mask) {
		int i = 0;
		uint64_t mask;
		for (mask = 1; mask != 0; mask = mask << 1) {
			if (token->privilege_mask & mask) {
				enum sec_privilege privilege = sec_privilege_from_mask(mask);
				DEBUGADD(dbg_lev, ("  Privilege[%3lu]: %s\n", (unsigned long)i++, 
					sec_privilege_name(privilege)));
			}
		}
	}
}
