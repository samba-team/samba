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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SAM

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


static GUMS_FUNCTIONS *gums_backend = NULL;

#if 0
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
#endif

static struct gums_init_function_entry *backends = NULL;

static void lazy_initialize_gums(void)
{
	static BOOL initialized = False;
	
	if (initialized)
		return;

	static_init_gums;
	initialized = True;
}

static struct gums_init_function_entry *gums_find_backend_entry(const char *name);

NTSTATUS gums_register_module(int version, const char *name, gums_init_function init_fn)
{
	struct gums_init_function_entry *entry = backends;

	if (version != GUMS_INTERFACE_VERSION) {
		DEBUG(0,("Can't register gums backend!\n"
			 "You tried to register a gums module with"
			 "GUMS_INTERFACE_VERSION %d, while this version"
			 "of samba uses version %d\n", version,
			 GUMS_INTERFACE_VERSION));

		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!name || !init_fn) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5,("Attempting to register gums backend %s\n", name));

	/* Check for duplicates */
	if (gums_find_backend_entry(name)) {
		DEBUG(0,("There already is a gums backend registered"
			 "with the name %s!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = smb_xmalloc(sizeof(struct gums_init_function_entry));
	entry->name = smb_xstrdup(name);
	entry->init_fn = init_fn;

	DLIST_ADD(backends, entry);
	DEBUG(5,("Successfully added gums backend '%s'\n", name));
	return NT_STATUS_OK;
}

static struct gums_init_function_entry *gums_find_backend_entry(const char *name)
{
	struct gums_init_function_entry *entry = backends;

	while (entry) {
		if (strcmp(entry->name, name) == 0)
			return entry;
		entry = entry->next;
	}

	return NULL;
}

NTSTATUS gums_setup_backend(const char *backend)
{

	TALLOC_CTX *mem_ctx;
	char *module_name = smb_xstrdup(backend);
	char *p, *module_data = NULL;
	struct gums_init_function_entry *entry;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	lazy_initialize_gums();

	p = strchr(module_name, ':');
	if (p) {
		*p = 0;
		module_data = p+1;
		trim_string(module_data, " ", " ");
	}

	trim_string(module_name, " ", " ");

	DEBUG(5,("Attempting to find a gums backend to match %s (%s)\n", backend, module_name));

	entry = gums_find_backend_entry(module_name);

	/* Try to find a module that contains this module */
	if (!entry) {
		DEBUG(2,("No builtin backend found, trying to load plugin\n"));
		if(NT_STATUS_IS_OK(smb_probe_module("gums", module_name)) && !(entry = gums_find_backend_entry(module_name))) {
			DEBUG(0,("Plugin is available, but doesn't register gums backend %s\n", module_name));
			SAFE_FREE(module_name);
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	/* No such backend found */
	if(!entry) {
		DEBUG(0,("No builtin nor plugin backend for %s found\n", module_name));
		SAFE_FREE(module_name);
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5,("Found gums backend %s\n", module_name));

	/* free current functions structure if any */
	if (gums_backend) {
		gums_backend->free_private_data(gums_backend->private_data);
		talloc_destroy(gums_backend->mem_ctx);
		gums_backend = NULL;
	}

	/* allocate a new GUMS_FUNCTIONS structure and memory context */
	mem_ctx = talloc_init("gums_backend (%s)", module_name);
	if (!mem_ctx)
		return NT_STATUS_NO_MEMORY;
	gums_backend = talloc(mem_ctx, sizeof(GUMS_FUNCTIONS));
	if (!gums_backend)
		return NT_STATUS_NO_MEMORY;
	gums_backend->mem_ctx = mem_ctx;

	/* init the requested backend module */
	if (NT_STATUS_IS_OK(ret = entry->init_fn(gums_backend, module_data))) {
		DEBUG(5,("gums backend %s has a valid init\n", backend));
	} else {
		DEBUG(0,("gums backend %s did not correctly init (error was %s)\n", backend, nt_errstr(ret)));
	}
	SAFE_FREE(module_name);
	return ret;
}

NTSTATUS get_gums_fns(GUMS_FUNCTIONS **fns)
{
	if (gums_backend != NULL) {
		*fns = gums_backend;
		return NT_STATUS_OK;
	}

	DEBUG(2, ("get_gums_fns: unable to get gums functions! backend uninitialized?\n"));
	return NT_STATUS_UNSUCCESSFUL;
}
