/*
   Unix SMB/CIFS implementation.
   Grops and Users Management System initializations.
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

/*#undef DBGC_CLASS
#define DBGC_CLASS DBGC_GUMS*/

#define GMV_MAJOR 0
#define GMV_MINOR 1

#define PRIV_NONE			0
#define PRIV_CREATE_TOKEN		1
#define PRIV_ASSIGNPRIMARYTOKEN		2
#define PRIV_LOCK_MEMORY		3
#define PRIV_INCREASE_QUOTA		4
#define PRIV_MACHINE_ACCOUNT		5
#define PRIV_TCB			6
#define PRIV_SECURITY			7
#define PRIV_TAKE_OWNERSHIP		8
#define PRIV_LOAD_DRIVER		9
#define PRIV_SYSTEM_PROFILE		10
#define PRIV_SYSTEMTIME			11
#define PRIV_PROF_SINGLE_PROCESS	12
#define PRIV_INC_BASE_PRIORITY		13
#define PRIV_CREATE_PAGEFILE		14
#define PRIV_CREATE_PERMANENT		15
#define PRIV_BACKUP			16
#define PRIV_RESTORE			17
#define PRIV_SHUTDOWN			18
#define PRIV_DEBUG			19
#define PRIV_AUDIT			20
#define PRIV_SYSTEM_ENVIRONMENT		21
#define PRIV_CHANGE_NOTIFY		22
#define PRIV_REMOTE_SHUTDOWN		23
#define PRIV_UNDOCK			24
#define PRIV_SYNC_AGENT			25
#define PRIV_ENABLE_DELEGATION		26
#define PRIV_ALL			255


GUMS_FUNCTIONS *gums_storage;
static void *dl_handle;

static PRIVS gums_privs[] = {
	{PRIV_NONE,			"no_privs",				"No privilege"}, /* this one MUST be first */
	{PRIV_CREATE_TOKEN,		"SeCreateToken",			"Create Token"},
	{PRIV_ASSIGNPRIMARYTOKEN,	"SeAssignPrimaryToken",			"Assign Primary Token"},
	{PRIV_LOCK_MEMORY,		"SeLockMemory",				"Lock Memory"},
	{PRIV_INCREASE_QUOTA,		"SeIncreaseQuotaPrivilege",		"Increase Quota Privilege"},
	{PRIV_MACHINE_ACCOUNT,		"SeMachineAccount",			"Machine Account"},
	{PRIV_TCB,			"SeTCB",				"TCB"},
	{PRIV_SECURITY,			"SeSecurityPrivilege",			"Security Privilege"},
	{PRIV_TAKE_OWNERSHIP,		"SeTakeOwnershipPrivilege",		"Take Ownership Privilege"},
	{PRIV_LOAD_DRIVER,		"SeLocalDriverPrivilege",		"Local Driver Privilege"},
	{PRIV_SYSTEM_PROFILE,		"SeSystemProfilePrivilege",		"System Profile Privilege"},
	{PRIV_SYSTEMTIME,		"SeSystemtimePrivilege",		"System Time"},
	{PRIV_PROF_SINGLE_PROCESS,	"SeProfileSingleProcessPrivilege",	"Profile Single Process Privilege"},
	{PRIV_INC_BASE_PRIORITY,	"SeIncreaseBasePriorityPrivilege",	"Increase Base Priority Privilege"},
	{PRIV_CREATE_PAGEFILE,		"SeCreatePagefilePrivilege",		"Create Pagefile Privilege"},
	{PRIV_CREATE_PERMANENT,		"SeCreatePermanent",			"Create Permanent"},
	{PRIV_BACKUP,			"SeBackupPrivilege",			"Backup Privilege"},
	{PRIV_RESTORE,			"SeRestorePrivilege",			"Restore Privilege"},
	{PRIV_SHUTDOWN,			"SeShutdownPrivilege",			"Shutdown Privilege"},
	{PRIV_DEBUG,			"SeDebugPrivilege",			"Debug Privilege"},
	{PRIV_AUDIT,			"SeAudit",				"Audit"},
	{PRIV_SYSTEM_ENVIRONMENT,	"SeSystemEnvironmentPrivilege",		"System Environment Privilege"},
	{PRIV_CHANGE_NOTIFY,		"SeChangeNotify",			"Change Notify"},
	{PRIV_REMOTE_SHUTDOWN,		"SeRemoteShutdownPrivilege",		"Remote Shutdown Privilege"},
	{PRIV_UNDOCK,			"SeUndock",				"Undock"},
	{PRIV_SYNC_AGENT,		"SeSynchronizationAgent",		"Synchronization Agent"},
	{PRIV_ENABLE_DELEGATION,	"SeEnableDelegation",			"Enable Delegation"},
	{PRIV_ALL,			"SaAllPrivs",				"All Privileges"}
};

NTSTATUS gums_init(const char *module_name)
{
	int (*module_version)(int);
	NTSTATUS (*module_init)();
/*	gums_module_init module_init;*/
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	DEBUG(5, ("Opening gums module %s\n", module_name));
	dl_handle = sys_dlopen(module_name, RTLD_NOW);
	if (!dl_handle) {
		DEBUG(0, ("ERROR: Failed to load gums module %s, error: %s\n", module_name, sys_dlerror()));
		return NT_STATUS_UNSUCCESSFUL;
	}

	module_version = sys_dlsym(dl_handle, "gumm_version");
	if (!module_version) {
		DEBUG(0, ("ERROR: Failed to find gums module version!\n"));
		goto error;
	}

	if (module_version(GMV_MAJOR) != GUMS_VERSION_MAJOR) {
		DEBUG(0, ("ERROR: Module's major version does not match gums version!\n"));
		goto error;
	}

	if (module_version(GMV_MINOR) != GUMS_VERSION_MINOR) {
		DEBUG(1, ("WARNING: Module's minor version does not match gums version!\n"));
	}

	module_init = sys_dlsym(dl_handle, "gumm_init");
	if (!module_init) {
		DEBUG(0, ("ERROR: Failed to find gums module's init function!\n"));
		goto error;
	}

	DEBUG(5, ("Initializing module %s\n", module_name));

	ret = module_init(&gums_storage);
	goto done;

error:
	ret = NT_STATUS_UNSUCCESSFUL;
	sys_dlclose(dl_handle);

done:
	return ret;
}

NTSTATUS gums_unload(void)
{
	NTSTATUS ret;
	NTSTATUS (*module_finalize)();

	if (!dl_handle)
		return NT_STATUS_UNSUCCESSFUL;

	module_finalize = sys_dlsym(dl_handle, "gumm_finalize");
	if (!module_finalize) {
		DEBUG(0, ("ERROR: Failed to find gums module's init function!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(5, ("Finalizing module"));

	ret = module_finalize();
	sys_dlclose(dl_handle);

	return ret;
}
