/*
   Unix SMB/CIFS implementation.

   manipulate privileges

   Copyright (C) Andrew Tridgell 2004

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
#include "librpc/gen_ndr/ndr_security.h"


static const struct {
	enum sec_privilege privilege;
	const char *name;
} privilege_names[] = {
	{SEC_PRIV_SECURITY,                   "SeSecurityPrivilege"},
	{SEC_PRIV_BACKUP,                     "SeBackupPrivilege"},
	{SEC_PRIV_RESTORE,                    "SeRestorePrivilege"},
	{SEC_PRIV_SYSTEMTIME,                 "SeSystemtimePrivilege"},
	{SEC_PRIV_SHUTDOWN,                   "SeShutdownPrivilege"},
	{SEC_PRIV_REMOTE_SHUTDOWN,            "SeRemoteShutdownPrivilege"},
	{SEC_PRIV_TAKE_OWNERSHIP,             "SeTakeOwnershipPrivilege"},
	{SEC_PRIV_DEBUG,                      "SeDebugPrivilege"},
	{SEC_PRIV_SYSTEM_ENVIRONMENT,         "SeSystemEnvironmentPrivilege"},
	{SEC_PRIV_SYSTEM_PROFILE,             "SeSystemProfilePrivilege"},
	{SEC_PRIV_PROFILE_SINGLE_PROCESS,     "SeProfileSingleProcessPrivilege"},
	{SEC_PRIV_INCREASE_BASE_PRIORITY,     "SeIncreaseBasePriorityPrivilege"},
	{SEC_PRIV_LOAD_DRIVER,                "SeLoadDriverPrivilege"},
	{SEC_PRIV_CREATE_PAGEFILE,            "SeCreatePagefilePrivilege"},
	{SEC_PRIV_INCREASE_QUOTA,             "SeIncreaseQuotaPrivilege"},
	{SEC_PRIV_CHANGE_NOTIFY,              "SeChangeNotifyPrivilege"},
	{SEC_PRIV_UNDOCK,                     "SeUndockPrivilege"},
	{SEC_PRIV_MANAGE_VOLUME,              "SeManageVolumePrivilege"},
	{SEC_PRIV_IMPERSONATE,                "SeImpersonatePrivilege"},
	{SEC_PRIV_CREATE_GLOBAL,              "SeCreateGlobalPrivilege"},
	{SEC_PRIV_ENABLE_DELEGATION,          "SeEnableDelegationPrivilege"},
	{SEC_PRIV_INTERACTIVE_LOGON,          "SeInteractiveLogonRight"},
	{SEC_PRIV_NETWORK_LOGON,              "SeNetworkLogonRight"},
	{SEC_PRIV_REMOTE_INTERACTIVE_LOGON,   "SeRemoteInteractiveLogonRight"}
};


/*
  map a privilege id to the wire string constant
*/
const char *sec_privilege_name(unsigned int privilege)
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
  map a privilege name to a privilege id. Return -1 if not found
*/
int sec_privilege_id(const char *name)
{
	int i;
	for (i=0;i<ARRAY_SIZE(privilege_names);i++) {
		if (strcasecmp(privilege_names[i].name, name) == 0) {
			return (int)privilege_names[i].privilege;
		}
	}
	return -1;
}


/*
  return True if a security_token has a particular privilege bit set
*/
BOOL sec_privilege_check(const struct security_token *token, unsigned int privilege)
{
	uint64_t mask = 1;
	mask <<= (privilege-1);
	if (token->privilege_mask & mask) {
		return True;
	}
	return False;
}

/*
  set a bit in the privilege mask
*/
void sec_privilege_set(struct security_token *token, unsigned int privilege)
{
	uint64_t mask = 1;
	mask <<= (privilege-1);
	token->privilege_mask |= mask;
}
