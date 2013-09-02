/* 
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Michael Adam 2008
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   Copyright (C) Andrew Bartlett 2011

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

/*
 *  Load parameters.
 *
 *  This module provides suitable callback functions for the params
 *  module. It builds the internal table of service details which is
 *  then used by the rest of the server.
 *
 * To add a parameter:
 *
 * 1) add it to the global or service structure definition
 * 2) add it to the parm_table
 * 3) add it to the list of available functions (eg: using FN_GLOBAL_STRING())
 * 4) If it's a global then initialise it in init_globals. If a local
 *    (ie. service) parameter then initialise it in the sDefault structure
 *  
 *
 * Notes:
 *   The configuration file is processed sequentially for speed. It is NOT
 *   accessed randomly as happens in 'real' Windows. For this reason, there
 *   is a fair bit of sequence-dependent code here - ie., code which assumes
 *   that certain things happen before others. In particular, the code which
 *   happens at the boundary between sections is delicately poised, so be
 *   careful!
 *
 */

#include "includes.h"
#include "system/filesys.h"
#include "util_tdb.h"
#include "lib/param/loadparm.h"
#include "printing.h"
#include "lib/smbconf/smbconf.h"
#include "lib/smbconf/smbconf_init.h"

#include "ads.h"
#include "../librpc/gen_ndr/svcctl.h"
#include "intl.h"
#include "../libcli/smb/smb_signing.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "../lib/util/bitmap.h"

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_HTTPCONNECTENCRYPT
#include <cups/http.h>
#endif

#ifdef CLUSTER_SUPPORT
#include "ctdb_private.h"
#endif

bool bLoaded = false;

extern userdom_struct current_user_info;

/* the special value for the include parameter
 * to be interpreted not as a file name but to
 * trigger loading of the global smb.conf options
 * from registry. */
#ifndef INCLUDE_REGISTRY_NAME
#define INCLUDE_REGISTRY_NAME "registry"
#endif

static bool in_client = false;		/* Not in the client by default */
static struct smbconf_csn conf_last_csn;

static int config_backend = CONFIG_BACKEND_FILE;

/* some helpful bits */
#define LP_SNUM_OK(i) (((i) >= 0) && ((i) < iNumServices) && (ServicePtrs != NULL) && ServicePtrs[(i)]->valid)
#define VALID(i) (ServicePtrs != NULL && ServicePtrs[i]->valid)

#define USERSHARE_VALID 1
#define USERSHARE_PENDING_DELETE 2

static bool defaults_saved = false;

#define LOADPARM_EXTRA_GLOBALS \
	struct parmlist_entry *param_opt;				\
	char *szRealm;							\
	char *loglevel;							\
	int iminreceivefile;						\
	char *szPrintcapname;						\
	int CupsEncrypt;						\
	int  iPreferredMaster;						\
	char *szLdapMachineSuffix;					\
	char *szLdapUserSuffix;						\
	char *szLdapIdmapSuffix;					\
	char *szLdapGroupSuffix;					\
	char *szStateDir;						\
	char *szCacheDir;						\
	char *szUsershareTemplateShare;					\
	char *szIdmapUID;						\
	char *szIdmapGID;						\
	int winbindMaxDomainConnections;				\
	int ismb2_max_credits;						\
	char *tls_keyfile;						\
	char *tls_certfile;						\
	char *tls_cafile;						\
	char *tls_crlfile;						\
	char *tls_dhpfile;						\
	int bPreferredMaster;

#include "param/param_global.h"

static struct loadparm_global Globals;

/* This is a default service used to prime a services structure */
static struct loadparm_service sDefault =
{
	.valid = true,
	.autoloaded = false,
	.usershare = 0,
	.usershare_last_mod = {0, 0},
	.szService = NULL,
	.szPath = NULL,
	.szUsername = NULL,
	.szInvalidUsers = NULL,
	.szValidUsers = NULL,
	.szAdminUsers = NULL,
	.szCopy = NULL,
	.szInclude = NULL,
	.szPreExec = NULL,
	.szPostExec = NULL,
	.szRootPreExec = NULL,
	.szRootPostExec = NULL,
	.szCupsOptions = NULL,
	.szPrintcommand = NULL,
	.szLpqcommand = NULL,
	.szLprmcommand = NULL,
	.szLppausecommand = NULL,
	.szLpresumecommand = NULL,
	.szQueuepausecommand = NULL,
	.szQueueresumecommand = NULL,
	.szPrintername = NULL,
	.szPrintjobUsername = NULL,
	.szDontdescend = NULL,
	.szHostsallow = NULL,
	.szHostsdeny = NULL,
	.szMagicScript = NULL,
	.szMagicOutput = NULL,
	.szVetoFiles = NULL,
	.szHideFiles = NULL,
	.szVetoOplockFiles = NULL,
	.comment = NULL,
	.force_user = NULL,
	.force_group = NULL,
	.readlist = NULL,
	.writelist = NULL,
	.volume = NULL,
	.fstype = NULL,
	.szVfsObjects = NULL,
	.szMSDfsProxy = NULL,
	.szAioWriteBehind = NULL,
	.szDfree = NULL,
	.iMinPrintSpace = 0,
	.iMaxPrintJobs = 1000,
	.iMaxReportedPrintJobs = 0,
	.iWriteCacheSize = 0,
	.iCreate_mask = 0744,
	.iCreate_force_mode = 0,
	.iDir_mask = 0755,
	.iDir_force_mode = 0,
	.iMaxConnections = 0,
	.iDefaultCase = CASE_LOWER,
	.iPrinting = DEFAULT_PRINTING,
	.iOplockContentionLimit = 2,
	.iCSCPolicy = 0,
	.iBlock_size = 1024,
	.iDfreeCacheTime = 0,
	.bPreexecClose = false,
	.bRootpreexecClose = false,
	.iCaseSensitive = Auto,
	.bCasePreserve = true,
	.bShortCasePreserve = true,
	.bHideDotFiles = true,
	.bHideSpecialFiles = false,
	.bHideUnReadable = false,
	.bHideUnWriteableFiles = false,
	.bBrowseable = true,
	.bAccessBasedShareEnum = false,
	.bAvailable = true,
	.bRead_only = true,
	.bNo_set_dir = true,
	.bGuest_only = false,
	.bAdministrative_share = false,
	.bGuest_ok = false,
	.bPrint_ok = false,
	.bPrintNotifyBackchannel = true,
	.bMap_system = false,
	.bMap_hidden = false,
	.bMap_archive = true,
	.bStoreDosAttributes = false,
	.bDmapiSupport = false,
	.bLocking = true,
	.iStrictLocking = Auto,
	.bPosixLocking = true,
	.bOpLocks = true,
	.bKernelOplocks = false,
	.bLevel2OpLocks = true,
	.bOnlyUser = false,
	.bMangledNames = true,
	.bWidelinks = false,
	.bSymlinks = true,
	.bSyncAlways = false,
	.bStrictAllocate = false,
	.bStrictSync = false,
	.magic_char = '~',
	.copymap = NULL,
	.bDeleteReadonly = false,
	.bFakeOplocks = false,
	.bDeleteVetoFiles = false,
	.bDosFilemode = false,
	.bDosFiletimes = true,
	.bDosFiletimeResolution = false,
	.bFakeDirCreateTimes = false,
	.bBlockingLocks = true,
	.bInheritPerms = false,
	.bInheritACLS = false,
	.bInheritOwner = false,
	.bMSDfsRoot = false,
	.bUseClientDriver = false,
	.bDefaultDevmode = true,
	.bForcePrintername = false,
	.bNTAclSupport = true,
	.bForceUnknownAclUser = false,
	.bUseSendfile = false,
	.bProfileAcls = false,
	.bMap_acl_inherit = false,
	.bAfs_Share = false,
	.bEASupport = false,
	.bAclCheckPermissions = true,
	.bAclMapFullControl = true,
	.bAclGroupControl = false,
	.bAclAllowExecuteAlways = false,
	.bChangeNotify = true,
	.bKernelChangeNotify = true,
	.iallocation_roundup_size = SMB_ROUNDUP_ALLOCATION_SIZE,
	.iAioReadSize = 0,
	.iAioWriteSize = 0,
	.iMap_readonly = MAP_READONLY_YES,
#ifdef BROKEN_DIRECTORY_HANDLING
	.iDirectoryNameCacheSize = 0,
#else
	.iDirectoryNameCacheSize = 100,
#endif
	.ismb_encrypt = SMB_SIGNING_DEFAULT,
	.bKernelShareModes = true,
	.bDurableHandles = true,
	.param_opt = NULL,
	.dummy = ""
};

/* local variables */
static struct loadparm_service **ServicePtrs = NULL;
static int iNumServices = 0;
static int iServiceIndex = 0;
static struct db_context *ServiceHash;
static int *invalid_services = NULL;
static int num_invalid_services = 0;
static bool bInGlobalSection = true;
static bool bGlobalOnly = false;

#define NUMPARAMETERS (sizeof(parm_table) / sizeof(struct parm_struct))

/* prototypes for the special type handlers */
static bool handle_include(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr);
static bool handle_copy(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr);
static bool handle_idmap_backend(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr);
static bool handle_idmap_uid(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr);
static bool handle_idmap_gid(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr);
static bool handle_debug_list(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr );
static bool handle_realm(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr );
static bool handle_netbios_aliases(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr );
static bool handle_charset(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr );
static bool handle_dos_charset(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr );
static bool handle_printing(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr);
static bool handle_ldap_debug_level(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr);

/* these are parameter handlers which are not needed in the
 * source3 code
 */

#define handle_logfile NULL

static void set_allowed_client_auth(void);

static void add_to_file_list(const char *fname, const char *subfname);
static bool lp_set_cmdline_helper(const char *pszParmName, const char *pszParmValue, bool store_values);
static void free_param_opts(struct parmlist_entry **popts);

#include "lib/param/param_table.c"

/* this is used to prevent lots of mallocs of size 1 */
static const char null_string[] = "";

/**
 Set a string value, allocing the space for the string
**/

static bool string_init(char **dest,const char *src)
{
	size_t l;

	if (!src)
		src = "";

	l = strlen(src);

	if (l == 0) {
		*dest = discard_const_p(char, null_string);
	} else {
		(*dest) = SMB_STRDUP(src);
		if ((*dest) == NULL) {
			DEBUG(0,("Out of memory in string_init\n"));
			return false;
		}
	}
	return(true);
}

/**
 Free a string value.
**/

static void string_free(char **s)
{
	if (!s || !(*s))
		return;
	if (*s == null_string)
		*s = NULL;
	SAFE_FREE(*s);
}

/**
 Set a string value, deallocating any existing space, and allocing the space
 for the string
**/

static bool string_set(char **dest,const char *src)
{
	string_free(dest);
	return(string_init(dest,src));
}

/***************************************************************************
 Initialise the sDefault parameter structure for the printer values.
***************************************************************************/

static void init_printer_values(struct loadparm_service *pService)
{
	/* choose defaults depending on the type of printing */
	switch (pService->iPrinting) {
		case PRINT_BSD:
		case PRINT_AIX:
		case PRINT_LPRNT:
		case PRINT_LPROS2:
			string_set(&pService->szLpqcommand, "lpq -P'%p'");
			string_set(&pService->szLprmcommand, "lprm -P'%p' %j");
			string_set(&pService->szPrintcommand, "lpr -r -P'%p' %s");
			break;

		case PRINT_LPRNG:
		case PRINT_PLP:
			string_set(&pService->szLpqcommand, "lpq -P'%p'");
			string_set(&pService->szLprmcommand, "lprm -P'%p' %j");
			string_set(&pService->szPrintcommand, "lpr -r -P'%p' %s");
			string_set(&pService->szQueuepausecommand, "lpc stop '%p'");
			string_set(&pService->szQueueresumecommand, "lpc start '%p'");
			string_set(&pService->szLppausecommand, "lpc hold '%p' %j");
			string_set(&pService->szLpresumecommand, "lpc release '%p' %j");
			break;

		case PRINT_CUPS:
		case PRINT_IPRINT:
			/* set the lpq command to contain the destination printer
			   name only.  This is used by cups_queue_get() */
			string_set(&pService->szLpqcommand, "%p");
			string_set(&pService->szLprmcommand, "");
			string_set(&pService->szPrintcommand, "");
			string_set(&pService->szLppausecommand, "");
			string_set(&pService->szLpresumecommand, "");
			string_set(&pService->szQueuepausecommand, "");
			string_set(&pService->szQueueresumecommand, "");
			break;

		case PRINT_SYSV:
		case PRINT_HPUX:
			string_set(&pService->szLpqcommand, "lpstat -o%p");
			string_set(&pService->szLprmcommand, "cancel %p-%j");
			string_set(&pService->szPrintcommand, "lp -c -d%p %s; rm %s");
			string_set(&pService->szQueuepausecommand, "disable %p");
			string_set(&pService->szQueueresumecommand, "enable %p");
#ifndef HPUX
			string_set(&pService->szLppausecommand, "lp -i %p-%j -H hold");
			string_set(&pService->szLpresumecommand, "lp -i %p-%j -H resume");
#endif /* HPUX */
			break;

		case PRINT_QNX:
			string_set(&pService->szLpqcommand, "lpq -P%p");
			string_set(&pService->szLprmcommand, "lprm -P%p %j");
			string_set(&pService->szPrintcommand, "lp -r -P%p %s");
			break;

#if defined(DEVELOPER) || defined(ENABLE_SELFTEST)

	case PRINT_TEST:
	case PRINT_VLP: {
		const char *tdbfile;
		TALLOC_CTX *tmp_ctx = talloc_stackframe();
		char *tmp;

		tdbfile = talloc_asprintf(
			tmp_ctx, "tdbfile=%s",
			lp_parm_const_string(-1, "vlp", "tdbfile",
					     "/tmp/vlp.tdb"));
		if (tdbfile == NULL) {
			tdbfile="tdbfile=/tmp/vlp.tdb";
		}

		tmp = talloc_asprintf(tmp_ctx, "vlp %s print %%p %%s",
				      tdbfile);
		string_set(&pService->szPrintcommand,
			   tmp ? tmp : "vlp print %p %s");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s lpq %%p",
				      tdbfile);
		string_set(&pService->szLpqcommand,
			   tmp ? tmp : "vlp lpq %p");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s lprm %%p %%j",
				      tdbfile);
		string_set(&pService->szLprmcommand,
			   tmp ? tmp : "vlp lprm %p %j");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s lppause %%p %%j",
				      tdbfile);
		string_set(&pService->szLppausecommand,
			   tmp ? tmp : "vlp lppause %p %j");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s lpresume %%p %%j",
				      tdbfile);
		string_set(&pService->szLpresumecommand,
			   tmp ? tmp : "vlp lpresume %p %j");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s queuepause %%p",
				      tdbfile);
		string_set(&pService->szQueuepausecommand,
			   tmp ? tmp : "vlp queuepause %p");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s queueresume %%p",
				      tdbfile);
		string_set(&pService->szQueueresumecommand,
			   tmp ? tmp : "vlp queueresume %p");
		TALLOC_FREE(tmp_ctx);

		break;
	}
#endif /* DEVELOPER */

	}
}
/**
 *  Function to return the default value for the maximum number of open
 *  file descriptors permitted.  This function tries to consult the
 *  kernel-level (sysctl) and ulimit (getrlimit()) values and goes
 *  the smaller of those.
 */
static int max_open_files(void)
{
	int sysctl_max = MAX_OPEN_FILES;
	int rlimit_max = MAX_OPEN_FILES;

#ifdef HAVE_SYSCTLBYNAME
	{
		size_t size = sizeof(sysctl_max);
		sysctlbyname("kern.maxfilesperproc", &sysctl_max, &size, NULL,
			     0);
	}
#endif

#if (defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE))
	{
		struct rlimit rl;

		ZERO_STRUCT(rl);

		if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
			rlimit_max = rl.rlim_cur;

#if defined(RLIM_INFINITY)
		if(rl.rlim_cur == RLIM_INFINITY)
			rlimit_max = MAX_OPEN_FILES;
#endif
	}
#endif

	if (sysctl_max < MIN_OPEN_FILES_WINDOWS) {
		DEBUG(2,("max_open_files: increasing sysctl_max (%d) to "
			"minimum Windows limit (%d)\n",
			sysctl_max,
			MIN_OPEN_FILES_WINDOWS));
		sysctl_max = MIN_OPEN_FILES_WINDOWS;
	}

	if (rlimit_max < MIN_OPEN_FILES_WINDOWS) {
		DEBUG(2,("rlimit_max: increasing rlimit_max (%d) to "
			"minimum Windows limit (%d)\n",
			rlimit_max,
			MIN_OPEN_FILES_WINDOWS));
		rlimit_max = MIN_OPEN_FILES_WINDOWS;
	}

	return MIN(sysctl_max, rlimit_max);
}

/**
 * Common part of freeing allocated data for one parameter.
 */
static void free_one_parameter_common(void *parm_ptr,
				      struct parm_struct parm)
{
	if ((parm.type == P_STRING) ||
	    (parm.type == P_USTRING))
	{
		string_free((char**)parm_ptr);
	} else if (parm.type == P_LIST) {
		TALLOC_FREE(*((char***)parm_ptr));
	}
}

/**
 * Free the allocated data for one parameter for a share
 * given as a service struct.
 */
static void free_one_parameter(struct loadparm_service *service,
			       struct parm_struct parm)
{
	void *parm_ptr;

	if (parm.p_class != P_LOCAL) {
		return;
	}

	parm_ptr = lp_parm_ptr(service, &parm);

	free_one_parameter_common(parm_ptr, parm);
}

/**
 * Free the allocated parameter data of a share given
 * as a service struct.
 */
static void free_parameters(struct loadparm_service *service)
{
	uint32_t i;

	for (i=0; parm_table[i].label; i++) {
		free_one_parameter(service, parm_table[i]);
	}
}

/**
 * Free the allocated data for one parameter for a given share
 * specified by an snum.
 */
static void free_one_parameter_by_snum(int snum, struct parm_struct parm)
{
	void *parm_ptr;

	if (snum < 0) {
		parm_ptr = lp_parm_ptr(NULL, &parm);
	} else if (parm.p_class != P_LOCAL) {
		return;
	} else {
		parm_ptr = lp_local_ptr_by_snum(snum, &parm);
	}

	free_one_parameter_common(parm_ptr, parm);
}

/**
 * Free the allocated parameter data for a share specified
 * by an snum.
 */
static void free_parameters_by_snum(int snum)
{
	uint32_t i;

	for (i=0; parm_table[i].label; i++) {
		free_one_parameter_by_snum(snum, parm_table[i]);
	}
}

/**
 * Free the allocated global parameters.
 */
static void free_global_parameters(void)
{
	free_param_opts(&Globals.param_opt);
	free_parameters_by_snum(GLOBAL_SECTION_SNUM);
	TALLOC_FREE(Globals.ctx);
}

static int map_parameter(const char *pszParmName);

struct lp_stored_option {
	struct lp_stored_option *prev, *next;
	const char *label;
	const char *value;
};

static struct lp_stored_option *stored_options;

/*
  save options set by lp_set_cmdline() into a list. This list is
  re-applied when we do a globals reset, so that cmdline set options
  are sticky across reloads of smb.conf
 */
static bool store_lp_set_cmdline(const char *pszParmName, const char *pszParmValue)
{
	struct lp_stored_option *entry, *entry_next;
	for (entry = stored_options; entry != NULL; entry = entry_next) {
		entry_next = entry->next;
		if (strcmp(pszParmName, entry->label) == 0) {
			DLIST_REMOVE(stored_options, entry);
			talloc_free(entry);
			break;
		}
	}

	entry = talloc(NULL, struct lp_stored_option);
	if (!entry) {
		return false;
	}

	entry->label = talloc_strdup(entry, pszParmName);
	if (!entry->label) {
		talloc_free(entry);
		return false;
	}

	entry->value = talloc_strdup(entry, pszParmValue);
	if (!entry->value) {
		talloc_free(entry);
		return false;
	}

	DLIST_ADD_END(stored_options, entry, struct lp_stored_option);

	return true;
}

static bool apply_lp_set_cmdline(void)
{
	struct lp_stored_option *entry = NULL;
	for (entry = stored_options; entry != NULL; entry = entry->next) {
		if (!lp_set_cmdline_helper(entry->label, entry->value, false)) {
			DEBUG(0, ("Failed to re-apply cmdline parameter %s = %s\n",
				  entry->label, entry->value));
			return false;
		}
	}
	return true;
}

/***************************************************************************
 Initialise the global parameter structure.
***************************************************************************/

static void init_globals(bool reinit_globals)
{
	static bool done_init = false;
	char *s = NULL;
	int i;

        /* If requested to initialize only once and we've already done it... */
        if (!reinit_globals && done_init) {
                /* ... then we have nothing more to do */
                return;
        }

	if (!done_init) {
		/* The logfile can be set before this is invoked. Free it if so. */
		if (Globals.logfile != NULL) {
			string_free(&Globals.logfile);
			Globals.logfile = NULL;
		}
		done_init = true;
	} else {
		free_global_parameters();
	}

	/* This memset and the free_global_parameters() above will
	 * wipe out smb.conf options set with lp_set_cmdline().  The
	 * apply_lp_set_cmdline() call puts these values back in the
	 * table once the defaults are set */
	ZERO_STRUCT(Globals);

	Globals.ctx = talloc_new(NULL);

	for (i = 0; parm_table[i].label; i++) {
		if ((parm_table[i].type == P_STRING ||
		     parm_table[i].type == P_USTRING))
		{
			string_set((char **)lp_parm_ptr(NULL, &parm_table[i]), "");
		}
	}


	string_set(&sDefault.fstype, FSTYPE_STRING);
	string_set(&sDefault.szPrintjobUsername, "%U");

	init_printer_values(&sDefault);


	DEBUG(3, ("Initialising global parameters\n"));

	/* Must manually force to upper case here, as this does not go via the handler */
	string_set(&Globals.szNetbiosName, myhostname_upper());

	string_set(&Globals.szSMBPasswdFile, get_dyn_SMB_PASSWD_FILE());
	string_set(&Globals.szPrivateDir, get_dyn_PRIVATE_DIR());

	/* use the new 'hash2' method by default, with a prefix of 1 */
	string_set(&Globals.szManglingMethod, "hash2");
	Globals.mangle_prefix = 1;

	string_set(&Globals.szGuestaccount, GUEST_ACCOUNT);

	/* using UTF8 by default allows us to support all chars */
	string_set(&Globals.unix_charset, DEFAULT_UNIX_CHARSET);

	/* Use codepage 850 as a default for the dos character set */
	string_set(&Globals.dos_charset, DEFAULT_DOS_CHARSET);

	/*
	 * Allow the default PASSWD_CHAT to be overridden in local.h.
	 */
	string_set(&Globals.szPasswdChat, DEFAULT_PASSWD_CHAT);

	string_set(&Globals.szWorkgroup, DEFAULT_WORKGROUP);

	string_set(&Globals.szPasswdProgram, "");
	string_set(&Globals.szLockDir, get_dyn_LOCKDIR());
	string_set(&Globals.szStateDir, get_dyn_STATEDIR());
	string_set(&Globals.szCacheDir, get_dyn_CACHEDIR());
	string_set(&Globals.szPidDir, get_dyn_PIDDIR());
	string_set(&Globals.nbt_client_socket_address, "0.0.0.0");
	/*
	 * By default support explicit binding to broadcast
 	 * addresses.
 	 */
	Globals.bNmbdBindExplicitBroadcast = true;

	if (asprintf(&s, "Samba %s", samba_version_string()) < 0) {
		smb_panic("init_globals: ENOMEM");
	}
	string_set(&Globals.szServerString, s);
	SAFE_FREE(s);
#ifdef DEVELOPER
	string_set(&Globals.szPanicAction, "/bin/sleep 999999999");
#endif

	string_set(&Globals.socket_options, DEFAULT_SOCKET_OPTIONS);

	string_set(&Globals.szLogonDrive, "");
	/* %N is the NIS auto.home server if -DAUTOHOME is used, else same as %L */
	string_set(&Globals.szLogonHome, "\\\\%N\\%U");
	string_set(&Globals.szLogonPath, "\\\\%N\\%U\\profile");

	Globals.szNameResolveOrder = (const char **)str_list_make_v3(NULL, "lmhosts wins host bcast", NULL);
	string_set(&Globals.szPasswordServer, "*");

	Globals.AlgorithmicRidBase = BASE_RID;

	Globals.bLoadPrinters = true;
	Globals.PrintcapCacheTime = 750; 	/* 12.5 minutes */

	Globals.ConfigBackend = config_backend;
	Globals.server_role = ROLE_AUTO;

	/* Was 65535 (0xFFFF). 0x4101 matches W2K and causes major speed improvements... */
	/* Discovered by 2 days of pain by Don McCall @ HP :-). */
	Globals.max_xmit = 0x4104;
	Globals.max_mux = 50;	/* This is *needed* for profile support. */
	Globals.lpqcachetime = 30;	/* changed to handle large print servers better -- jerry */
	Globals.bDisableSpoolss = false;
	Globals.iMaxSmbdProcesses = 0;/* no limit specified */
	Globals.pwordlevel = 0;
	Globals.unamelevel = 0;
	Globals.deadtime = 0;
	Globals.getwd_cache = true;
	Globals.bLargeReadwrite = true;
	Globals.max_log_size = 5000;
	Globals.max_open_files = max_open_files();
	Globals.open_files_db_hash_size = SMB_OPEN_DATABASE_TDB_HASH_SIZE;
	Globals.srv_maxprotocol = PROTOCOL_SMB3_00;
	Globals.srv_minprotocol = PROTOCOL_LANMAN1;
	Globals.security = SEC_USER;
	Globals.bEncryptPasswords = true;
	Globals.clientSchannel = Auto;
	Globals.serverSchannel = Auto;
	Globals.bReadRaw = true;
	Globals.bWriteRaw = true;
	Globals.bNullPasswords = false;
	Globals.bObeyPamRestrictions = false;
	Globals.syslog = 1;
	Globals.bSyslogOnly = false;
	Globals.bTimestampLogs = true;
	string_set(&Globals.loglevel, "0");
	Globals.bDebugPrefixTimestamp = false;
	Globals.bDebugHiresTimestamp = true;
	Globals.bDebugPid = false;
	Globals.bDebugUid = false;
	Globals.bDebugClass = false;
	Globals.bEnableCoreFiles = true;
	Globals.max_ttl = 60 * 60 * 24 * 3;	/* 3 days default. */
	Globals.max_wins_ttl = 60 * 60 * 24 * 6;	/* 6 days default. */
	Globals.min_wins_ttl = 60 * 60 * 6;	/* 6 hours default. */
	Globals.machine_password_timeout = 60 * 60 * 24 * 7;	/* 7 days default. */
	Globals.lm_announce = Auto;	/* = Auto: send only if LM clients found */
	Globals.lm_interval = 60;
#if (defined(HAVE_NETGROUP) && defined(WITH_AUTOMOUNT))
	Globals.bNISHomeMap = false;
#ifdef WITH_NISPLUS_HOME
	string_set(&Globals.szNISHomeMapName, "auto_home.org_dir");
#else
	string_set(&Globals.szNISHomeMapName, "auto.home");
#endif
#endif
	Globals.bTimeServer = false;
	Globals.bBindInterfacesOnly = false;
	Globals.bUnixPasswdSync = false;
	Globals.bPamPasswordChange = false;
	Globals.bPasswdChatDebug = false;
	Globals.iPasswdChatTimeout = 2; /* 2 second default. */
	Globals.bNTPipeSupport = true;	/* Do NT pipes by default. */
	Globals.bNTStatusSupport = true; /* Use NT status by default. */
	Globals.bStatCache = true;	/* use stat cache by default */
	Globals.iMaxStatCacheSize = 256; /* 256k by default */
	Globals.restrict_anonymous = 0;
	Globals.bClientLanManAuth = false;	/* Do NOT use the LanMan hash if it is available */
	Globals.bClientPlaintextAuth = false;	/* Do NOT use a plaintext password even if is requested by the server */
	Globals.bLanmanAuth = false;	/* Do NOT use the LanMan hash, even if it is supplied */
	Globals.bNTLMAuth = true;	/* Do use NTLMv1 if it is supplied by the client (otherwise NTLMv2) */
	Globals.bClientNTLMv2Auth = true; /* Client should always use use NTLMv2, as we can't tell that the server supports it, but most modern servers do */
	/* Note, that we will also use NTLM2 session security (which is different), if it is available */

	Globals.map_to_guest = 0;	/* By Default, "Never" */
	Globals.oplock_break_wait_time = 0;	/* By Default, 0 msecs. */
	Globals.enhanced_browsing = true;
	Globals.iLockSpinTime = WINDOWS_MINIMUM_LOCK_TIMEOUT_MS; /* msec. */
#ifdef MMAP_BLACKLIST
	Globals.bUseMmap = false;
#else
	Globals.bUseMmap = true;
#endif
	Globals.bUnicode = true;
	Globals.bUnixExtensions = true;
	Globals.bResetOnZeroVC = false;
	Globals.bLogWriteableFilesOnExit = false;
	Globals.bCreateKrb5Conf = true;
	Globals.winbindMaxDomainConnections = 1;

	/* hostname lookups can be very expensive and are broken on
	   a large number of sites (tridge) */
	Globals.bHostnameLookups = false;

	string_set(&Globals.passdb_backend, "tdbsam");
	string_set(&Globals.szLdapSuffix, "");
	string_set(&Globals.szLdapMachineSuffix, "");
	string_set(&Globals.szLdapUserSuffix, "");
	string_set(&Globals.szLdapGroupSuffix, "");
	string_set(&Globals.szLdapIdmapSuffix, "");

	string_set(&Globals.szLdapAdminDn, "");
	Globals.ldap_ssl = LDAP_SSL_START_TLS;
	Globals.ldap_ssl_ads = false;
	Globals.ldap_deref = -1;
	Globals.ldap_passwd_sync = LDAP_PASSWD_SYNC_OFF;
	Globals.ldap_delete_dn = false;
	Globals.ldap_replication_sleep = 1000; /* wait 1 sec for replication */
	Globals.ldap_follow_referral = Auto;
	Globals.ldap_timeout = LDAP_DEFAULT_TIMEOUT;
	Globals.ldap_connection_timeout = LDAP_CONNECTION_DEFAULT_TIMEOUT;
	Globals.ldap_page_size = LDAP_PAGE_SIZE;

	Globals.ldap_debug_level = 0;
	Globals.ldap_debug_threshold = 10;

	/* This is what we tell the afs client. in reality we set the token 
	 * to never expire, though, when this runs out the afs client will 
	 * forget the token. Set to 0 to get NEVERDATE.*/
	Globals.iAfsTokenLifetime = 604800;
	Globals.cups_connection_timeout = CUPS_DEFAULT_CONNECTION_TIMEOUT;

/* these parameters are set to defaults that are more appropriate
   for the increasing samba install base:

   as a member of the workgroup, that will possibly become a
   _local_ master browser (lm = true).  this is opposed to a forced
   local master browser startup (pm = true).

   doesn't provide WINS server service by default (wsupp = false),
   and doesn't provide domain master browser services by default, either.

*/

	Globals.bMsAddPrinterWizard = true;
	Globals.os_level = 20;
	Globals.bLocalMaster = true;
	Globals.domain_master = Auto;	/* depending on bDomainLogons */
	Globals.bDomainLogons = false;
	Globals.bBrowseList = true;
	Globals.bWINSsupport = false;
	Globals.bWINSproxy = false;

	TALLOC_FREE(Globals.szInitLogonDelayedHosts);
	Globals.InitLogonDelay = 100; /* 100 ms default delay */

	Globals.bWINSdnsProxy = true;

	Globals.bAllowTrustedDomains = true;
	string_set(&Globals.szIdmapBackend, "tdb");

	string_set(&Globals.szTemplateShell, "/bin/false");
	string_set(&Globals.szTemplateHomedir, "/home/%D/%U");
	string_set(&Globals.szWinbindSeparator, "\\");

	string_set(&Globals.szCupsServer, "");
	string_set(&Globals.szIPrintServer, "");

#ifdef CLUSTER_SUPPORT
	string_set(&Globals.ctdbdSocket, CTDB_PATH);
#else
	string_set(&Globals.ctdbdSocket, "");
#endif

	Globals.szClusterAddresses = NULL;
	Globals.clustering = false;
	Globals.ctdb_timeout = 0;
	Globals.ctdb_locktime_warn_threshold = 0;

	Globals.winbind_cache_time = 300;	/* 5 minutes */
	Globals.winbind_reconnect_delay = 30;	/* 30 seconds */
	Globals.winbind_max_clients = 200;
	Globals.bWinbindEnumUsers = false;
	Globals.bWinbindEnumGroups = false;
	Globals.bWinbindUseDefaultDomain = false;
	Globals.bWinbindTrustedDomainsOnly = false;
	Globals.bWinbindNestedGroups = true;
	Globals.winbind_expand_groups = 1;
	Globals.szWinbindNssInfo = (const char **)str_list_make_v3(NULL, "template", NULL);
	Globals.bWinbindRefreshTickets = false;
	Globals.bWinbindOfflineLogon = false;

	Globals.iIdmapCacheTime = 86400 * 7; /* a week by default */
	Globals.iIdmapNegativeCacheTime = 120; /* 2 minutes by default */

	Globals.bPassdbExpandExplicit = false;

	Globals.name_cache_timeout = 660; /* In seconds */

	Globals.bUseSpnego = true;
	Globals.bClientUseSpnego = true;

	Globals.client_signing = SMB_SIGNING_DEFAULT;
	Globals.server_signing = SMB_SIGNING_DEFAULT;

	Globals.bDeferSharingViolations = true;
	Globals.smb_ports = (const char **)str_list_make_v3(NULL, SMB_PORTS, NULL);

	Globals.bEnablePrivileges = true;
	Globals.bHostMSDfs        = true;
	Globals.bASUSupport       = false;

	/* User defined shares. */
	if (asprintf(&s, "%s/usershares", get_dyn_STATEDIR()) < 0) {
		smb_panic("init_globals: ENOMEM");
	}
	string_set(&Globals.szUsersharePath, s);
	SAFE_FREE(s);
	string_set(&Globals.szUsershareTemplateShare, "");
	Globals.iUsershareMaxShares = 0;
	/* By default disallow sharing of directories not owned by the sharer. */
	Globals.bUsershareOwnerOnly = true;
	/* By default disallow guest access to usershares. */
	Globals.bUsershareAllowGuests = false;

	Globals.iKeepalive = DEFAULT_KEEPALIVE;

	/* By default no shares out of the registry */
	Globals.bRegistryShares = false;

	Globals.iminreceivefile = 0;

	Globals.bMapUntrustedToDomain = false;
	Globals.bMulticastDnsRegister = true;

	Globals.ismb2_max_read = DEFAULT_SMB2_MAX_READ;
	Globals.ismb2_max_write = DEFAULT_SMB2_MAX_WRITE;
	Globals.ismb2_max_trans = DEFAULT_SMB2_MAX_TRANSACT;
	Globals.ismb2_max_credits = DEFAULT_SMB2_MAX_CREDITS;

	string_set(&Globals.ncalrpc_dir, get_dyn_NCALRPCDIR());

	/* Now put back the settings that were set with lp_set_cmdline() */
	apply_lp_set_cmdline();
}

/*******************************************************************
 Convenience routine to grab string parameters into talloced memory
 and run standard_sub_basic on them. The buffers can be written to by
 callers without affecting the source string.
********************************************************************/

static char *lp_string(TALLOC_CTX *ctx, const char *s)
{
	char *ret;

	/* The follow debug is useful for tracking down memory problems
	   especially if you have an inner loop that is calling a lp_*()
	   function that returns a string.  Perhaps this debug should be
	   present all the time? */

#if 0
	DEBUG(10, ("lp_string(%s)\n", s));
#endif
	if (!s) {
		return NULL;
	}

	ret = talloc_sub_basic(ctx,
			get_current_username(),
			current_user_info.domain,
			s);
	if (trim_char(ret, '\"', '\"')) {
		if (strchr(ret,'\"') != NULL) {
			TALLOC_FREE(ret);
			ret = talloc_sub_basic(ctx,
					get_current_username(),
					current_user_info.domain,
					s);
		}
	}
	return ret;
}

/*
   In this section all the functions that are used to access the
   parameters from the rest of the program are defined
*/

#define FN_GLOBAL_STRING(fn_name,ptr) \
char *lp_ ## fn_name(TALLOC_CTX *ctx) {return(lp_string((ctx), *(char **)(&Globals.ptr) ? *(char **)(&Globals.ptr) : ""));}
#define FN_GLOBAL_CONST_STRING(fn_name,ptr) \
 const char *lp_ ## fn_name(void) {return(*(const char * const *)(&Globals.ptr) ? *(const char * const *)(&Globals.ptr) : "");}
#define FN_GLOBAL_LIST(fn_name,ptr) \
 const char **lp_ ## fn_name(void) {return(*(const char ***)(&Globals.ptr));}
#define FN_GLOBAL_BOOL(fn_name,ptr) \
 bool lp_ ## fn_name(void) {return(*(bool *)(&Globals.ptr));}
#define FN_GLOBAL_CHAR(fn_name,ptr) \
 char lp_ ## fn_name(void) {return(*(char *)(&Globals.ptr));}
#define FN_GLOBAL_INTEGER(fn_name,ptr) \
 int lp_ ## fn_name(void) {return(*(int *)(&Globals.ptr));}

#define FN_LOCAL_STRING(fn_name,val) \
char *lp_ ## fn_name(TALLOC_CTX *ctx,int i) {return(lp_string((ctx), (LP_SNUM_OK(i) && ServicePtrs[(i)]->val) ? ServicePtrs[(i)]->val : sDefault.val));}
#define FN_LOCAL_CONST_STRING(fn_name,val) \
 const char *lp_ ## fn_name(int i) {return (const char *)((LP_SNUM_OK(i) && ServicePtrs[(i)]->val) ? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_LIST(fn_name,val) \
 const char **lp_ ## fn_name(int i) {return(const char **)(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_BOOL(fn_name,val) \
 bool lp_ ## fn_name(int i) {return(bool)(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_INTEGER(fn_name,val) \
 int lp_ ## fn_name(int i) {return(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}

#define FN_LOCAL_PARM_BOOL(fn_name,val) \
 bool lp_ ## fn_name(const struct share_params *p) {return(bool)(LP_SNUM_OK(p->service)? ServicePtrs[(p->service)]->val : sDefault.val);}
#define FN_LOCAL_PARM_INTEGER(fn_name,val) \
 int lp_ ## fn_name(const struct share_params *p) {return(LP_SNUM_OK(p->service)? ServicePtrs[(p->service)]->val : sDefault.val);}
#define FN_LOCAL_CHAR(fn_name,val) \
 char lp_ ## fn_name(const struct share_params *p) {return(LP_SNUM_OK(p->service)? ServicePtrs[(p->service)]->val : sDefault.val);}


static FN_GLOBAL_BOOL(_readraw, bReadRaw)
static FN_GLOBAL_BOOL(_writeraw, bWriteRaw)

/* If lp_statedir() and lp_cachedir() are explicitely set during the
 * build process or in smb.conf, we use that value.  Otherwise they
 * default to the value of lp_lockdir(). */
const char *lp_statedir(void) {
	if ((strcmp(get_dyn_STATEDIR(), get_dyn_LOCKDIR()) != 0) ||
	    (strcmp(get_dyn_STATEDIR(), Globals.szStateDir) != 0))
		return(*(char **)(&Globals.szStateDir) ?
		       *(char **)(&Globals.szStateDir) : "");
	else
		return(*(char **)(&Globals.szLockDir) ?
		       *(char **)(&Globals.szLockDir) : "");
}
const char *lp_cachedir(void) {
	if ((strcmp(get_dyn_CACHEDIR(), get_dyn_LOCKDIR()) != 0) ||
	    (strcmp(get_dyn_CACHEDIR(), Globals.szCacheDir) != 0))
		return(*(char **)(&Globals.szCacheDir) ?
		       *(char **)(&Globals.szCacheDir) : "");
	else
		return(*(char **)(&Globals.szLockDir) ?
		       *(char **)(&Globals.szLockDir) : "");
}
static FN_GLOBAL_INTEGER(winbind_max_domain_connections_int,
		  winbindMaxDomainConnections)

int lp_winbind_max_domain_connections(void)
{
	if (lp_winbind_offline_logon() &&
	    lp_winbind_max_domain_connections_int() > 1) {
		DEBUG(1, ("offline logons active, restricting max domain "
			  "connections to 1\n"));
		return 1;
	}
	return MAX(1, lp_winbind_max_domain_connections_int());
}

int lp_smb2_max_credits(void)
{
	if (Globals.ismb2_max_credits == 0) {
		Globals.ismb2_max_credits = DEFAULT_SMB2_MAX_CREDITS;
	}
	return Globals.ismb2_max_credits;
}
int lp_cups_encrypt(void)
{
	int result = 0;
#ifdef HAVE_HTTPCONNECTENCRYPT
	switch (Globals.CupsEncrypt) {
		case Auto:
			result = HTTP_ENCRYPT_REQUIRED;
			break;
		case true:
			result = HTTP_ENCRYPT_ALWAYS;
			break;
		case false:
			result = HTTP_ENCRYPT_NEVER;
			break;
	}
#endif
	return result;
}

/* These functions remain in source3/param for now */

FN_GLOBAL_STRING(configfile, szConfigFile)

#include "lib/param/param_functions.c"

FN_LOCAL_STRING(servicename, szService)
FN_LOCAL_CONST_STRING(const_servicename, szService)

/* local prototypes */

static int map_parameter_canonical(const char *pszParmName, bool *inverse);
static const char *get_boolean(bool bool_value);
static int getservicebyname(const char *pszServiceName,
			    struct loadparm_service *pserviceDest);
static void copy_service(struct loadparm_service *pserviceDest,
			 struct loadparm_service *pserviceSource,
			 struct bitmap *pcopymapDest);
static bool do_parameter(const char *pszParmName, const char *pszParmValue,
			 void *userdata);
static bool do_section(const char *pszSectionName, void *userdata);
static void init_copymap(struct loadparm_service *pservice);
static bool hash_a_service(const char *name, int number);
static void free_service_byindex(int iService);
static void show_parameter(int parmIndex);
static bool is_synonym_of(int parm1, int parm2, bool *inverse);

/*
 * This is a helper function for parametrical options support.  It returns a
 * pointer to parametrical option value if it exists or NULL otherwise. Actual
 * parametrical functions are quite simple
 */
static struct parmlist_entry *get_parametrics_by_service(struct loadparm_service *service, const char *type,
							   const char *option)
{
	bool global_section = false;
	char* param_key;
        struct parmlist_entry *data;

	if (service == NULL) {
		data = Globals.param_opt;
		global_section = true;
	} else {
		data = service->param_opt;
	}

	if (asprintf(&param_key, "%s:%s", type, option) == -1) {
		DEBUG(0,("asprintf failed!\n"));
		return NULL;
	}

	while (data) {
		if (strwicmp(data->key, param_key) == 0) {
			string_free(&param_key);
			return data;
		}
		data = data->next;
	}

	if (!global_section) {
		/* Try to fetch the same option but from globals */
		/* but only if we are not already working with Globals */
		data = Globals.param_opt;
		while (data) {
		        if (strwicmp(data->key, param_key) == 0) {
			        string_free(&param_key);
				return data;
			}
			data = data->next;
		}
	}

	string_free(&param_key);

	return NULL;
}

/*
 * This is a helper function for parametrical options support.  It returns a
 * pointer to parametrical option value if it exists or NULL otherwise. Actual
 * parametrical functions are quite simple
 */
static struct parmlist_entry *get_parametrics(int snum, const char *type,
						const char *option)
{
	if (snum >= iNumServices) return NULL;

	if (snum < 0) {
		return get_parametrics_by_service(NULL, type, option);
	} else {
		return get_parametrics_by_service(ServicePtrs[snum], type, option);
	}
}


#define MISSING_PARAMETER(name) \
    DEBUG(0, ("%s(): value is NULL or empty!\n", #name))

/*******************************************************************
convenience routine to return int parameters.
********************************************************************/
static int lp_int(const char *s)
{

	if (!s || !*s) {
		MISSING_PARAMETER(lp_int);
		return (-1);
	}

	return (int)strtol(s, NULL, 0);
}

/*******************************************************************
convenience routine to return unsigned long parameters.
********************************************************************/
static unsigned long lp_ulong(const char *s)
{

	if (!s || !*s) {
		MISSING_PARAMETER(lp_ulong);
		return (0);
	}

	return strtoul(s, NULL, 0);
}

/*******************************************************************
convenience routine to return boolean parameters.
********************************************************************/
static bool lp_bool(const char *s)
{
	bool ret = false;

	if (!s || !*s) {
		MISSING_PARAMETER(lp_bool);
		return false;
	}

	if (!set_boolean(s, &ret)) {
		DEBUG(0,("lp_bool(%s): value is not boolean!\n",s));
		return false;
	}

	return ret;
}

/*******************************************************************
convenience routine to return enum parameters.
********************************************************************/
static int lp_enum(const char *s,const struct enum_list *_enum)
{
	int i;

	if (!s || !*s || !_enum) {
		MISSING_PARAMETER(lp_enum);
		return (-1);
	}

	for (i=0; _enum[i].name; i++) {
		if (strequal(_enum[i].name,s))
			return _enum[i].value;
	}

	DEBUG(0,("lp_enum(%s,enum): value is not in enum_list!\n",s));
	return (-1);
}

#undef MISSING_PARAMETER

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */
char *lp_parm_talloc_string(TALLOC_CTX *ctx, int snum, const char *type, const char *option, const char *def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data == NULL||data->value==NULL) {
		if (def) {
			return lp_string(ctx, def);
		} else {
			return NULL;
		}
	}

	return lp_string(ctx, data->value);
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */
const char *lp_parm_const_string(int snum, const char *type, const char *option, const char *def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data == NULL||data->value==NULL)
		return def;

	return data->value;
}

const char *lp_parm_const_string_service(struct loadparm_service *service, const char *type, const char *option)
{
	struct parmlist_entry *data = get_parametrics_by_service(service, type, option);

	if (data == NULL||data->value==NULL)
		return NULL;

	return data->value;
}


/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

const char **lp_parm_string_list(int snum, const char *type, const char *option, const char **def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data == NULL||data->value==NULL)
		return (const char **)def;

	if (data->list==NULL) {
		data->list = str_list_make_v3(NULL, data->value, NULL);
	}

	return (const char **)data->list;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

int lp_parm_int(int snum, const char *type, const char *option, int def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value)
		return lp_int(data->value);

	return def;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

unsigned long lp_parm_ulong(int snum, const char *type, const char *option, unsigned long def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value)
		return lp_ulong(data->value);

	return def;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

bool lp_parm_bool(int snum, const char *type, const char *option, bool def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value)
		return lp_bool(data->value);

	return def;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

int lp_parm_enum(int snum, const char *type, const char *option,
		 const struct enum_list *_enum, int def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data && data->value && *data->value && _enum)
		return lp_enum(data->value, _enum);

	return def;
}


/***************************************************************************
 Initialise a service to the defaults.
***************************************************************************/

static void init_service(struct loadparm_service *pservice)
{
	memset((char *)pservice, '\0', sizeof(struct loadparm_service));
	copy_service(pservice, &sDefault, NULL);
}


/**
 * free a param_opts structure.
 * param_opts handling should be moved to talloc;
 * then this whole functions reduces to a TALLOC_FREE().
 */

static void free_param_opts(struct parmlist_entry **popts)
{
	struct parmlist_entry *opt, *next_opt;

	if (*popts != NULL) {
		DEBUG(5, ("Freeing parametrics:\n"));
	}
	opt = *popts;
	while (opt != NULL) {
		string_free(&opt->key);
		string_free(&opt->value);
		TALLOC_FREE(opt->list);
		next_opt = opt->next;
		SAFE_FREE(opt);
		opt = next_opt;
	}
	*popts = NULL;
}

/***************************************************************************
 Free the dynamically allocated parts of a service struct.
***************************************************************************/

static void free_service(struct loadparm_service *pservice)
{
	if (!pservice)
		return;

	if (pservice->szService)
		DEBUG(5, ("free_service: Freeing service %s\n",
		       pservice->szService));

	free_parameters(pservice);

	string_free(&pservice->szService);
	TALLOC_FREE(pservice->copymap);

	free_param_opts(&pservice->param_opt);

	ZERO_STRUCTP(pservice);
}


/***************************************************************************
 remove a service indexed in the ServicePtrs array from the ServiceHash
 and free the dynamically allocated parts
***************************************************************************/

static void free_service_byindex(int idx)
{
	if ( !LP_SNUM_OK(idx) ) 
		return;

	ServicePtrs[idx]->valid = false;
	invalid_services[num_invalid_services++] = idx;

	/* we have to cleanup the hash record */

	if (ServicePtrs[idx]->szService) {
		char *canon_name = canonicalize_servicename(
			talloc_tos(),
			ServicePtrs[idx]->szService );

		dbwrap_delete_bystring(ServiceHash, canon_name );
		TALLOC_FREE(canon_name);
	}

	free_service(ServicePtrs[idx]);
	talloc_free_children(ServicePtrs[idx]);
}

/***************************************************************************
 Add a new service to the services array initialising it with the given 
 service. 
***************************************************************************/

static int add_a_service(const struct loadparm_service *pservice, const char *name)
{
	int i;
	struct loadparm_service tservice;
	int num_to_alloc = iNumServices + 1;

	tservice = *pservice;

	/* it might already exist */
	if (name) {
		i = getservicebyname(name, NULL);
		if (i >= 0) {
			return (i);
		}
	}

	/* find an invalid one */
	i = iNumServices;
	if (num_invalid_services > 0) {
		i = invalid_services[--num_invalid_services];
	}

	/* if not, then create one */
	if (i == iNumServices) {
		struct loadparm_service **tsp;
		int *tinvalid;

		tsp = SMB_REALLOC_ARRAY_KEEP_OLD_ON_ERROR(ServicePtrs, struct loadparm_service *, num_to_alloc);
		if (tsp == NULL) {
			DEBUG(0,("add_a_service: failed to enlarge ServicePtrs!\n"));
			return (-1);
		}
		ServicePtrs = tsp;
		ServicePtrs[iNumServices] = talloc(NULL, struct loadparm_service);
		if (!ServicePtrs[iNumServices]) {
			DEBUG(0,("add_a_service: out of memory!\n"));
			return (-1);
		}
		iNumServices++;

		/* enlarge invalid_services here for now... */
		tinvalid = SMB_REALLOC_ARRAY_KEEP_OLD_ON_ERROR(invalid_services, int,
					     num_to_alloc);
		if (tinvalid == NULL) {
			DEBUG(0,("add_a_service: failed to enlarge "
				 "invalid_services!\n"));
			return (-1);
		}
		invalid_services = tinvalid;
	} else {
		free_service_byindex(i);
	}

	ServicePtrs[i]->valid = true;

	init_service(ServicePtrs[i]);
	copy_service(ServicePtrs[i], &tservice, NULL);
	if (name)
		string_set(&ServicePtrs[i]->szService, name);

	DEBUG(8,("add_a_service: Creating snum = %d for %s\n", 
		i, ServicePtrs[i]->szService));

	if (!hash_a_service(ServicePtrs[i]->szService, i)) {
		return (-1);
	}

	return (i);
}

/***************************************************************************
  Convert a string to uppercase and remove whitespaces.
***************************************************************************/

char *canonicalize_servicename(TALLOC_CTX *ctx, const char *src)
{
	char *result;

	if ( !src ) {
		DEBUG(0,("canonicalize_servicename: NULL source name!\n"));
		return NULL;
	}

	result = talloc_strdup(ctx, src);
	SMB_ASSERT(result != NULL);

	if (!strlower_m(result)) {
		TALLOC_FREE(result);
		return NULL;
	}
	return result;
}

/***************************************************************************
  Add a name/index pair for the services array to the hash table.
***************************************************************************/

static bool hash_a_service(const char *name, int idx)
{
	char *canon_name;

	if ( !ServiceHash ) {
		DEBUG(10,("hash_a_service: creating servicehash\n"));
		ServiceHash = db_open_rbt(NULL);
		if ( !ServiceHash ) {
			DEBUG(0,("hash_a_service: open tdb servicehash failed!\n"));
			return false;
		}
	}

	DEBUG(10,("hash_a_service: hashing index %d for service name %s\n",
		idx, name));

	canon_name = canonicalize_servicename(talloc_tos(), name );

	dbwrap_store_bystring(ServiceHash, canon_name,
			      make_tdb_data((uint8 *)&idx, sizeof(idx)),
			      TDB_REPLACE);

	TALLOC_FREE(canon_name);

	return true;
}

/***************************************************************************
 Add a new home service, with the specified home directory, defaults coming
 from service ifrom.
***************************************************************************/

bool lp_add_home(const char *pszHomename, int iDefaultService,
		 const char *user, const char *pszHomedir)
{
	int i;

	if (pszHomename == NULL || user == NULL || pszHomedir == NULL ||
			pszHomedir[0] == '\0') {
		return false;
	}

	i = add_a_service(ServicePtrs[iDefaultService], pszHomename);

	if (i < 0)
		return false;

	if (!(*(ServicePtrs[iDefaultService]->szPath))
	    || strequal(ServicePtrs[iDefaultService]->szPath,
			lp_pathname(talloc_tos(), GLOBAL_SECTION_SNUM))) {
		string_set(&ServicePtrs[i]->szPath, pszHomedir);
	}

	if (!(*(ServicePtrs[i]->comment))) {
		char *comment = NULL;
		if (asprintf(&comment, "Home directory of %s", user) < 0) {
			return false;
		}
		string_set(&ServicePtrs[i]->comment, comment);
		SAFE_FREE(comment);
	}

	/* set the browseable flag from the global default */

	ServicePtrs[i]->bBrowseable = sDefault.bBrowseable;
	ServicePtrs[i]->bAccessBasedShareEnum = sDefault.bAccessBasedShareEnum;

	ServicePtrs[i]->autoloaded = true;

	DEBUG(3, ("adding home's share [%s] for user '%s' at '%s'\n", pszHomename, 
	       user, ServicePtrs[i]->szPath ));

	return true;
}

/***************************************************************************
 Add a new service, based on an old one.
***************************************************************************/

int lp_add_service(const char *pszService, int iDefaultService)
{
	if (iDefaultService < 0) {
		return add_a_service(&sDefault, pszService);
	}

	return (add_a_service(ServicePtrs[iDefaultService], pszService));
}

/***************************************************************************
 Add the IPC service.
***************************************************************************/

static bool lp_add_ipc(const char *ipc_name, bool guest_ok)
{
	char *comment = NULL;
	int i = add_a_service(&sDefault, ipc_name);

	if (i < 0)
		return false;

	if (asprintf(&comment, "IPC Service (%s)",
				Globals.szServerString) < 0) {
		return false;
	}

	string_set(&ServicePtrs[i]->szPath, tmpdir());
	string_set(&ServicePtrs[i]->szUsername, "");
	string_set(&ServicePtrs[i]->comment, comment);
	string_set(&ServicePtrs[i]->fstype, "IPC");
	ServicePtrs[i]->iMaxConnections = 0;
	ServicePtrs[i]->bAvailable = true;
	ServicePtrs[i]->bRead_only = true;
	ServicePtrs[i]->bGuest_only = false;
	ServicePtrs[i]->bAdministrative_share = true;
	ServicePtrs[i]->bGuest_ok = guest_ok;
	ServicePtrs[i]->bPrint_ok = false;
	ServicePtrs[i]->bBrowseable = sDefault.bBrowseable;

	DEBUG(3, ("adding IPC service\n"));

	SAFE_FREE(comment);
	return true;
}

/***************************************************************************
 Add a new printer service, with defaults coming from service iFrom.
***************************************************************************/

bool lp_add_printer(const char *pszPrintername, int iDefaultService)
{
	const char *comment = "From Printcap";
	int i = add_a_service(ServicePtrs[iDefaultService], pszPrintername);

	if (i < 0)
		return false;

	/* note that we do NOT default the availability flag to true - */
	/* we take it from the default service passed. This allows all */
	/* dynamic printers to be disabled by disabling the [printers] */
	/* entry (if/when the 'available' keyword is implemented!).    */

	/* the printer name is set to the service name. */
	string_set(&ServicePtrs[i]->szPrintername, pszPrintername);
	string_set(&ServicePtrs[i]->comment, comment);

	/* set the browseable flag from the gloabl default */
	ServicePtrs[i]->bBrowseable = sDefault.bBrowseable;

	/* Printers cannot be read_only. */
	ServicePtrs[i]->bRead_only = false;
	/* No oplocks on printer services. */
	ServicePtrs[i]->bOpLocks = false;
	/* Printer services must be printable. */
	ServicePtrs[i]->bPrint_ok = true;

	DEBUG(3, ("adding printer service %s\n", pszPrintername));

	return true;
}


/***************************************************************************
 Check whether the given parameter name is valid.
 Parametric options (names containing a colon) are considered valid.
***************************************************************************/

bool lp_parameter_is_valid(const char *pszParmName)
{
	return ((map_parameter(pszParmName) != -1) ||
		(strchr(pszParmName, ':') != NULL));
}

/***************************************************************************
 Check whether the given name is the name of a global parameter.
 Returns true for strings belonging to parameters of class
 P_GLOBAL, false for all other strings, also for parametric options
 and strings not belonging to any option.
***************************************************************************/

bool lp_parameter_is_global(const char *pszParmName)
{
	int num = map_parameter(pszParmName);

	if (num >= 0) {
		return (parm_table[num].p_class == P_GLOBAL);
	}

	return false;
}

/**************************************************************************
 Check whether the given name is the canonical name of a parameter.
 Returns false if it is not a valid parameter Name.
 For parametric options, true is returned.
**************************************************************************/

bool lp_parameter_is_canonical(const char *parm_name)
{
	if (!lp_parameter_is_valid(parm_name)) {
		return false;
	}

	return (map_parameter(parm_name) ==
		map_parameter_canonical(parm_name, NULL));
}

/**************************************************************************
 Determine the canonical name for a parameter.
 Indicate when it is an inverse (boolean) synonym instead of a
 "usual" synonym.
**************************************************************************/

bool lp_canonicalize_parameter(const char *parm_name, const char **canon_parm,
			       bool *inverse)
{
	int num;

	if (!lp_parameter_is_valid(parm_name)) {
		*canon_parm = NULL;
		return false;
	}

	num = map_parameter_canonical(parm_name, inverse);
	if (num < 0) {
		/* parametric option */
		*canon_parm = parm_name;
	} else {
		*canon_parm = parm_table[num].label;
	}

	return true;

}

/**************************************************************************
 Determine the canonical name for a parameter.
 Turn the value given into the inverse boolean expression when
 the synonym is an invers boolean synonym.

 Return true if parm_name is a valid parameter name and
 in case it is an invers boolean synonym, if the val string could
 successfully be converted to the reverse bool.
 Return false in all other cases.
**************************************************************************/

bool lp_canonicalize_parameter_with_value(const char *parm_name,
					  const char *val,
					  const char **canon_parm,
					  const char **canon_val)
{
	int num;
	bool inverse;

	if (!lp_parameter_is_valid(parm_name)) {
		*canon_parm = NULL;
		*canon_val = NULL;
		return false;
	}

	num = map_parameter_canonical(parm_name, &inverse);
	if (num < 0) {
		/* parametric option */
		*canon_parm = parm_name;
		*canon_val = val;
	} else {
		*canon_parm = parm_table[num].label;
		if (inverse) {
			if (!lp_invert_boolean(val, canon_val)) {
				*canon_val = NULL;
				return false;
			}
		} else {
			*canon_val = val;
		}
	}

	return true;
}

/***************************************************************************
 Map a parameter's string representation to something we can use. 
 Returns false if the parameter string is not recognised, else TRUE.
***************************************************************************/

static int map_parameter(const char *pszParmName)
{
	int iIndex;

	if (*pszParmName == '-' && !strequal(pszParmName, "-valid"))
		return (-1);

	for (iIndex = 0; parm_table[iIndex].label; iIndex++)
		if (strwicmp(parm_table[iIndex].label, pszParmName) == 0)
			return (iIndex);

	/* Warn only if it isn't parametric option */
	if (strchr(pszParmName, ':') == NULL)
		DEBUG(1, ("Unknown parameter encountered: \"%s\"\n", pszParmName));
	/* We do return 'fail' for parametric options as well because they are
	   stored in different storage
	 */
	return (-1);
}

/***************************************************************************
 Map a parameter's string representation to the index of the canonical
 form of the parameter (it might be a synonym).
 Returns -1 if the parameter string is not recognised.
***************************************************************************/

static int map_parameter_canonical(const char *pszParmName, bool *inverse)
{
	int parm_num, canon_num;
	bool loc_inverse = false;

	parm_num = map_parameter(pszParmName);
	if ((parm_num < 0) || !(parm_table[parm_num].flags & FLAG_HIDE)) {
		/* invalid, parametric or no canidate for synonyms ... */
		goto done;
	}

	for (canon_num = 0; parm_table[canon_num].label; canon_num++) {
		if (is_synonym_of(parm_num, canon_num, &loc_inverse)) {
			parm_num = canon_num;
			goto done;
		}
	}

done:
	if (inverse != NULL) {
		*inverse = loc_inverse;
	}
	return parm_num;
}

/***************************************************************************
 return true if parameter number parm1 is a synonym of parameter
 number parm2 (parm2 being the principal name).
 set inverse to true if parm1 is P_BOOLREV and parm2 is P_BOOL,
 false otherwise.
***************************************************************************/

static bool is_synonym_of(int parm1, int parm2, bool *inverse)
{
	if ((parm_table[parm1].offset == parm_table[parm2].offset) &&
	    (parm_table[parm1].p_class == parm_table[parm2].p_class) &&
	    (parm_table[parm1].flags & FLAG_HIDE) &&
	    !(parm_table[parm2].flags & FLAG_HIDE))
	{
		if (inverse != NULL) {
			if ((parm_table[parm1].type == P_BOOLREV) &&
			    (parm_table[parm2].type == P_BOOL))
			{
				*inverse = true;
			} else {
				*inverse = false;
			}
		}
		return true;
	}
	return false;
}

/***************************************************************************
 Show one parameter's name, type, [values,] and flags.
 (helper functions for show_parameter_list)
***************************************************************************/

static void show_parameter(int parmIndex)
{
	int enumIndex, flagIndex;
	int parmIndex2;
	bool hadFlag;
	bool hadSyn;
	bool inverse;
	const char *type[] = { "P_BOOL", "P_BOOLREV", "P_CHAR", "P_INTEGER",
		"P_OCTAL", "P_LIST", "P_STRING", "P_USTRING",
		"P_ENUM", "P_SEP"};
	unsigned flags[] = { FLAG_BASIC, FLAG_SHARE, FLAG_PRINT, FLAG_GLOBAL,
		FLAG_WIZARD, FLAG_ADVANCED, FLAG_DEVELOPER, FLAG_DEPRECATED,
		FLAG_HIDE};
	const char *flag_names[] = { "FLAG_BASIC", "FLAG_SHARE", "FLAG_PRINT",
		"FLAG_GLOBAL", "FLAG_WIZARD", "FLAG_ADVANCED", "FLAG_DEVELOPER",
		"FLAG_DEPRECATED", "FLAG_HIDE", NULL};

	printf("%s=%s", parm_table[parmIndex].label,
	       type[parm_table[parmIndex].type]);
	if (parm_table[parmIndex].type == P_ENUM) {
		printf(",");
		for (enumIndex=0;
		     parm_table[parmIndex].enum_list[enumIndex].name;
		     enumIndex++)
		{
			printf("%s%s",
			       enumIndex ? "|" : "",
			       parm_table[parmIndex].enum_list[enumIndex].name);
		}
	}
	printf(",");
	hadFlag = false;
	for (flagIndex=0; flag_names[flagIndex]; flagIndex++) {
		if (parm_table[parmIndex].flags & flags[flagIndex]) {
			printf("%s%s",
				hadFlag ? "|" : "",
				flag_names[flagIndex]);
			hadFlag = true;
		}
	}

	/* output synonyms */
	hadSyn = false;
	for (parmIndex2=0; parm_table[parmIndex2].label; parmIndex2++) {
		if (is_synonym_of(parmIndex, parmIndex2, &inverse)) {
			printf(" (%ssynonym of %s)", inverse ? "inverse " : "",
			       parm_table[parmIndex2].label);
		} else if (is_synonym_of(parmIndex2, parmIndex, &inverse)) {
			if (!hadSyn) {
				printf(" (synonyms: ");
				hadSyn = true;
			} else {
				printf(", ");
			}
			printf("%s%s", parm_table[parmIndex2].label,
			       inverse ? "[i]" : "");
		}
	}
	if (hadSyn) {
		printf(")");
	}

	printf("\n");
}

/***************************************************************************
 Show all parameter's name, type, [values,] and flags.
***************************************************************************/

void show_parameter_list(void)
{
	int classIndex, parmIndex;
	const char *section_names[] = { "local", "global", NULL};

	for (classIndex=0; section_names[classIndex]; classIndex++) {
		printf("[%s]\n", section_names[classIndex]);
		for (parmIndex = 0; parm_table[parmIndex].label; parmIndex++) {
			if (parm_table[parmIndex].p_class == classIndex) {
				show_parameter(parmIndex);
			}
		}
	}
}

/***************************************************************************
 Check if a given string correctly represents a boolean value.
***************************************************************************/

bool lp_string_is_valid_boolean(const char *parm_value)
{
	return set_boolean(parm_value, NULL);
}

/***************************************************************************
 Get the standard string representation of a boolean value ("yes" or "no")
***************************************************************************/

static const char *get_boolean(bool bool_value)
{
	static const char *yes_str = "yes";
	static const char *no_str = "no";

	return (bool_value ? yes_str : no_str);
}

/***************************************************************************
 Provide the string of the negated boolean value associated to the boolean
 given as a string. Returns false if the passed string does not correctly
 represent a boolean.
***************************************************************************/

bool lp_invert_boolean(const char *str, const char **inverse_str)
{
	bool val;

	if (!set_boolean(str, &val)) {
		return false;
	}

	*inverse_str = get_boolean(!val);
	return true;
}

/***************************************************************************
 Provide the canonical string representation of a boolean value given
 as a string. Return true on success, false if the string given does
 not correctly represent a boolean.
***************************************************************************/

bool lp_canonicalize_boolean(const char *str, const char**canon_str)
{
	bool val;

	if (!set_boolean(str, &val)) {
		return false;
	}

	*canon_str = get_boolean(val);
	return true;
}

/***************************************************************************
Find a service by name. Otherwise works like get_service.
***************************************************************************/

static int getservicebyname(const char *pszServiceName, struct loadparm_service *pserviceDest)
{
	int iService = -1;
	char *canon_name;
	TDB_DATA data;
	NTSTATUS status;

	if (ServiceHash == NULL) {
		return -1;
	}

	canon_name = canonicalize_servicename(talloc_tos(), pszServiceName);

	status = dbwrap_fetch_bystring(ServiceHash, canon_name, canon_name,
				       &data);

	if (NT_STATUS_IS_OK(status) &&
	    (data.dptr != NULL) &&
	    (data.dsize == sizeof(iService)))
	{
		iService = *(int *)data.dptr;
	}

	TALLOC_FREE(canon_name);

	if ((iService != -1) && (LP_SNUM_OK(iService))
	    && (pserviceDest != NULL)) {
		copy_service(pserviceDest, ServicePtrs[iService], NULL);
	}

	return (iService);
}

/* Return a pointer to a service by name.  Unlike getservicebyname, it does not copy the service */
struct loadparm_service *lp_service(const char *pszServiceName)
{
	int iService = getservicebyname(pszServiceName, NULL);
	if (iService == -1 || !LP_SNUM_OK(iService)) {
		return NULL;
	}
	return ServicePtrs[iService];
}

struct loadparm_service *lp_servicebynum(int snum)
{
	if ((snum == -1) || !LP_SNUM_OK(snum)) {
		return NULL;
	}
	return ServicePtrs[snum];
}

struct loadparm_service *lp_default_loadparm_service()
{
	return &sDefault;
}


/***************************************************************************
 Copy a service structure to another.
 If pcopymapDest is NULL then copy all fields
***************************************************************************/

/**
 * Add a parametric option to a parmlist_entry,
 * replacing old value, if already present.
 */
static void set_param_opt(struct parmlist_entry **opt_list,
			  const char *opt_name,
			  const char *opt_value,
			  unsigned priority)
{
	struct parmlist_entry *new_opt, *opt;
	bool not_added;

	opt = *opt_list;
	not_added = true;

	/* Traverse destination */
	while (opt) {
		/* If we already have same option, override it */
		if (strwicmp(opt->key, opt_name) == 0) {
			if ((opt->priority & FLAG_CMDLINE) &&
			    !(priority & FLAG_CMDLINE)) {
				/* it's been marked as not to be
				   overridden */
				return;
			}
			string_free(&opt->value);
			TALLOC_FREE(opt->list);
			opt->value = SMB_STRDUP(opt_value);
			opt->priority = priority;
			not_added = false;
			break;
		}
		opt = opt->next;
	}
	if (not_added) {
	    new_opt = SMB_XMALLOC_P(struct parmlist_entry);
	    new_opt->key = SMB_STRDUP(opt_name);
	    new_opt->value = SMB_STRDUP(opt_value);
	    new_opt->list = NULL;
	    new_opt->priority = priority;
	    DLIST_ADD(*opt_list, new_opt);
	}
}

static void copy_service(struct loadparm_service *pserviceDest, struct loadparm_service *pserviceSource,
			 struct bitmap *pcopymapDest)
{
	int i;
	bool bcopyall = (pcopymapDest == NULL);
	struct parmlist_entry *data;

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].p_class == P_LOCAL &&
		    (bcopyall || bitmap_query(pcopymapDest,i))) {
			void *src_ptr = lp_parm_ptr(pserviceSource, &parm_table[i]);
			void *dest_ptr = lp_parm_ptr(pserviceDest, &parm_table[i]);

			switch (parm_table[i].type) {
				case P_BOOL:
				case P_BOOLREV:
					*(bool *)dest_ptr = *(bool *)src_ptr;
					break;

				case P_INTEGER:
				case P_ENUM:
				case P_OCTAL:
				case P_BYTES:
					*(int *)dest_ptr = *(int *)src_ptr;
					break;

				case P_CHAR:
					*(char *)dest_ptr = *(char *)src_ptr;
					break;

				case P_STRING:
					string_set((char **)dest_ptr,
						   *(char **)src_ptr);
					break;

				case P_USTRING:
				{
					char *upper_string = strupper_talloc(talloc_tos(), 
									     *(char **)src_ptr);
					string_set((char **)dest_ptr,
						   upper_string);
					TALLOC_FREE(upper_string);
					break;
				}
				case P_LIST:
					TALLOC_FREE(*((char ***)dest_ptr));
					*((char ***)dest_ptr) = str_list_copy(NULL, 
						      *(const char ***)src_ptr);
					break;
				default:
					break;
			}
		}

	if (bcopyall) {
		init_copymap(pserviceDest);
		if (pserviceSource->copymap)
			bitmap_copy(pserviceDest->copymap,
				    pserviceSource->copymap);
	}

	data = pserviceSource->param_opt;
	while (data) {
		set_param_opt(&pserviceDest->param_opt, data->key, data->value, data->priority);
		data = data->next;
	}
}

/***************************************************************************
Check a service for consistency. Return false if the service is in any way
incomplete or faulty, else true.
***************************************************************************/

bool service_ok(int iService)
{
	bool bRetval;

	bRetval = true;
	if (ServicePtrs[iService]->szService[0] == '\0') {
		DEBUG(0, ("The following message indicates an internal error:\n"));
		DEBUG(0, ("No service name in service entry.\n"));
		bRetval = false;
	}

	/* The [printers] entry MUST be printable. I'm all for flexibility, but */
	/* I can't see why you'd want a non-printable printer service...        */
	if (strwicmp(ServicePtrs[iService]->szService, PRINTERS_NAME) == 0) {
		if (!ServicePtrs[iService]->bPrint_ok) {
			DEBUG(0, ("WARNING: [%s] service MUST be printable!\n",
			       ServicePtrs[iService]->szService));
			ServicePtrs[iService]->bPrint_ok = true;
		}
		/* [printers] service must also be non-browsable. */
		if (ServicePtrs[iService]->bBrowseable)
			ServicePtrs[iService]->bBrowseable = false;
	}

	if (ServicePtrs[iService]->szPath[0] == '\0' &&
	    strwicmp(ServicePtrs[iService]->szService, HOMES_NAME) != 0 &&
	    ServicePtrs[iService]->szMSDfsProxy[0] == '\0'
	    ) {
		DEBUG(0, ("WARNING: No path in service %s - making it unavailable!\n",
			ServicePtrs[iService]->szService));
		ServicePtrs[iService]->bAvailable = false;
	}

	/* If a service is flagged unavailable, log the fact at level 1. */
	if (!ServicePtrs[iService]->bAvailable)
		DEBUG(1, ("NOTE: Service %s is flagged unavailable.\n",
			  ServicePtrs[iService]->szService));

	return (bRetval);
}

static struct smbconf_ctx *lp_smbconf_ctx(void)
{
	sbcErr err;
	static struct smbconf_ctx *conf_ctx = NULL;

	if (conf_ctx == NULL) {
		err = smbconf_init(NULL, &conf_ctx, "registry:");
		if (!SBC_ERROR_IS_OK(err)) {
			DEBUG(1, ("error initializing registry configuration: "
				  "%s\n", sbcErrorString(err)));
			conf_ctx = NULL;
		}
	}

	return conf_ctx;
}

static bool process_smbconf_service(struct smbconf_service *service)
{
	uint32_t count;
	bool ret;

	if (service == NULL) {
		return false;
	}

	ret = do_section(service->name, NULL);
	if (ret != true) {
		return false;
	}
	for (count = 0; count < service->num_params; count++) {
		ret = do_parameter(service->param_names[count],
				   service->param_values[count],
				   NULL);
		if (ret != true) {
			return false;
		}
	}
	if (iServiceIndex >= 0) {
		return service_ok(iServiceIndex);
	}
	return true;
}

/**
 * load a service from registry and activate it
 */
bool process_registry_service(const char *service_name)
{
	sbcErr err;
	struct smbconf_service *service = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct smbconf_ctx *conf_ctx = lp_smbconf_ctx();
	bool ret = false;

	if (conf_ctx == NULL) {
		goto done;
	}

	DEBUG(5, ("process_registry_service: service name %s\n", service_name));

	if (!smbconf_share_exists(conf_ctx, service_name)) {
		/*
		 * Registry does not contain data for this service (yet),
		 * but make sure lp_load doesn't return false.
		 */
		ret = true;
		goto done;
	}

	err = smbconf_get_share(conf_ctx, mem_ctx, service_name, &service);
	if (!SBC_ERROR_IS_OK(err)) {
		goto done;
	}

	ret = process_smbconf_service(service);
	if (!ret) {
		goto done;
	}

	/* store the csn */
	smbconf_changed(conf_ctx, &conf_last_csn, NULL, NULL);

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/*
 * process_registry_globals
 */
static bool process_registry_globals(void)
{
	bool ret;

	add_to_file_list(INCLUDE_REGISTRY_NAME, INCLUDE_REGISTRY_NAME);

	ret = do_parameter("registry shares", "yes", NULL);
	if (!ret) {
		return ret;
	}

	return process_registry_service(GLOBAL_NAME);
}

bool process_registry_shares(void)
{
	sbcErr err;
	uint32_t count;
	struct smbconf_service **service = NULL;
	uint32_t num_shares = 0;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct smbconf_ctx *conf_ctx = lp_smbconf_ctx();
	bool ret = false;

	if (conf_ctx == NULL) {
		goto done;
	}

	err = smbconf_get_config(conf_ctx, mem_ctx, &num_shares, &service);
	if (!SBC_ERROR_IS_OK(err)) {
		goto done;
	}

	ret = true;

	for (count = 0; count < num_shares; count++) {
		if (strequal(service[count]->name, GLOBAL_NAME)) {
			continue;
		}
		ret = process_smbconf_service(service[count]);
		if (!ret) {
			goto done;
		}
	}

	/* store the csn */
	smbconf_changed(conf_ctx, &conf_last_csn, NULL, NULL);

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/**
 * reload those shares from registry that are already
 * activated in the services array.
 */
static bool reload_registry_shares(void)
{
	int i;
	bool ret = true;

	for (i = 0; i < iNumServices; i++) {
		if (!VALID(i)) {
			continue;
		}

		if (ServicePtrs[i]->usershare == USERSHARE_VALID) {
			continue;
		}

		ret = process_registry_service(ServicePtrs[i]->szService);
		if (!ret) {
			goto done;
		}
	}

done:
	return ret;
}


#define MAX_INCLUDE_DEPTH 100

static uint8_t include_depth;

static struct file_lists {
	struct file_lists *next;
	char *name;
	char *subfname;
	time_t modtime;
} *file_lists = NULL;

/*******************************************************************
 Keep a linked list of all config files so we know when one has changed 
 it's date and needs to be reloaded.
********************************************************************/

static void add_to_file_list(const char *fname, const char *subfname)
{
	struct file_lists *f = file_lists;

	while (f) {
		if (f->name && !strcmp(f->name, fname))
			break;
		f = f->next;
	}

	if (!f) {
		f = SMB_MALLOC_P(struct file_lists);
		if (!f)
			return;
		f->next = file_lists;
		f->name = SMB_STRDUP(fname);
		if (!f->name) {
			SAFE_FREE(f);
			return;
		}
		f->subfname = SMB_STRDUP(subfname);
		if (!f->subfname) {
			SAFE_FREE(f->name);
			SAFE_FREE(f);
			return;
		}
		file_lists = f;
		f->modtime = file_modtime(subfname);
	} else {
		time_t t = file_modtime(subfname);
		if (t)
			f->modtime = t;
	}
	return;
}

/**
 * Free the file lists
 */
static void free_file_list(void)
{
	struct file_lists *f;
	struct file_lists *next;

	f = file_lists;
	while( f ) {
		next = f->next;
		SAFE_FREE( f->name );
		SAFE_FREE( f->subfname );
		SAFE_FREE( f );
		f = next;
	}
	file_lists = NULL;
}


/**
 * Utility function for outsiders to check if we're running on registry.
 */
bool lp_config_backend_is_registry(void)
{
	return (lp_config_backend() == CONFIG_BACKEND_REGISTRY);
}

/**
 * Utility function to check if the config backend is FILE.
 */
bool lp_config_backend_is_file(void)
{
	return (lp_config_backend() == CONFIG_BACKEND_FILE);
}

/*******************************************************************
 Check if a config file has changed date.
********************************************************************/

bool lp_file_list_changed(void)
{
	struct file_lists *f = file_lists;

 	DEBUG(6, ("lp_file_list_changed()\n"));

	while (f) {
		time_t mod_time;

		if (strequal(f->name, INCLUDE_REGISTRY_NAME)) {
			struct smbconf_ctx *conf_ctx = lp_smbconf_ctx();

			if (conf_ctx == NULL) {
				return false;
			}
			if (smbconf_changed(conf_ctx, &conf_last_csn, NULL,
					    NULL))
			{
				DEBUGADD(6, ("registry config changed\n"));
				return true;
			}
		} else {
			char *n2 = NULL;
			n2 = talloc_sub_basic(talloc_tos(),
					      get_current_username(),
					      current_user_info.domain,
					      f->name);
			if (!n2) {
				return false;
			}
			DEBUGADD(6, ("file %s -> %s  last mod_time: %s\n",
				     f->name, n2, ctime(&f->modtime)));

			mod_time = file_modtime(n2);

			if (mod_time &&
			    ((f->modtime != mod_time) ||
			     (f->subfname == NULL) ||
			     (strcmp(n2, f->subfname) != 0)))
			{
				DEBUGADD(6,
					 ("file %s modified: %s\n", n2,
					  ctime(&mod_time)));
				f->modtime = mod_time;
				SAFE_FREE(f->subfname);
				f->subfname = SMB_STRDUP(n2);
				TALLOC_FREE(n2);
				return true;
			}
			TALLOC_FREE(n2);
		}
		f = f->next;
	}
	return false;
}


/**
 * Initialize iconv conversion descriptors.
 *
 * This is called the first time it is needed, and also called again
 * every time the configuration is reloaded, because the charset or
 * codepage might have changed.
 **/
static void init_iconv(void)
{
	global_iconv_handle = smb_iconv_handle_reinit(NULL, lp_dos_charset(),
						      lp_unix_charset(),
						      true, global_iconv_handle);
}

static bool handle_charset(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	if (strcmp(*ptr, pszParmValue) != 0) {
		string_set(ptr, pszParmValue);
		init_iconv();
	}
	return true;
}

static bool handle_dos_charset(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	bool is_utf8 = false;
	size_t len = strlen(pszParmValue);

	if (len == 4 || len == 5) {
		/* Don't use StrCaseCmp here as we don't want to
		   initialize iconv. */
		if ((toupper_m(pszParmValue[0]) == 'U') &&
		    (toupper_m(pszParmValue[1]) == 'T') &&
		    (toupper_m(pszParmValue[2]) == 'F')) {
			if (len == 4) {
				if (pszParmValue[3] == '8') {
					is_utf8 = true;
				}
			} else {
				if (pszParmValue[3] == '-' &&
				    pszParmValue[4] == '8') {
					is_utf8 = true;
				}
			}
		}
	}

	if (strcmp(*ptr, pszParmValue) != 0) {
		if (is_utf8) {
			DEBUG(0,("ERROR: invalid DOS charset: 'dos charset' must not "
				"be UTF8, using (default value) %s instead.\n",
				DEFAULT_DOS_CHARSET));
			pszParmValue = DEFAULT_DOS_CHARSET;
		}
		string_set(ptr, pszParmValue);
		init_iconv();
	}
	return true;
}

static bool handle_realm(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	bool ret = true;
	TALLOC_CTX *frame = talloc_stackframe();
	char *realm = strupper_talloc(frame, pszParmValue);
	char *dnsdomain = strlower_talloc(realm, pszParmValue);

	ret &= string_set(&Globals.szRealm, pszParmValue);
	ret &= string_set(&Globals.szRealm_upper, realm);
	ret &= string_set(&Globals.szRealm_lower, dnsdomain);
	TALLOC_FREE(frame);

	return ret;
}

static bool handle_netbios_aliases(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	TALLOC_FREE(Globals.szNetbiosAliases);
	Globals.szNetbiosAliases = (const char **)str_list_make_v3(NULL, pszParmValue, NULL);
	return set_netbios_aliases(Globals.szNetbiosAliases);
}

/***************************************************************************
 Handle the include operation.
***************************************************************************/
static bool bAllowIncludeRegistry = true;

static bool handle_include(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	char *fname;

	if (include_depth >= MAX_INCLUDE_DEPTH) {
		DEBUG(0, ("Error: Maximum include depth (%u) exceeded!\n",
			  include_depth));
		return false;
	}

	if (strequal(pszParmValue, INCLUDE_REGISTRY_NAME)) {
		if (!bAllowIncludeRegistry) {
			return true;
		}
		if (bInGlobalSection) {
			bool ret;
			include_depth++;
			ret = process_registry_globals();
			include_depth--;
			return ret;
		} else {
			DEBUG(1, ("\"include = registry\" only effective "
				  "in %s section\n", GLOBAL_NAME));
			return false;
		}
	}

	fname = talloc_sub_basic(talloc_tos(), get_current_username(),
				 current_user_info.domain,
				 pszParmValue);

	add_to_file_list(pszParmValue, fname);

	string_set(ptr, fname);

	if (file_exist(fname)) {
		bool ret;
		include_depth++;
		ret = pm_process(fname, do_section, do_parameter, NULL);
		include_depth--;
		TALLOC_FREE(fname);
		return ret;
	}

	DEBUG(2, ("Can't find include file %s\n", fname));
	TALLOC_FREE(fname);
	return true;
}

/***************************************************************************
 Handle the interpretation of the copy parameter.
***************************************************************************/

static bool handle_copy(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	bool bRetval;
	int iTemp;
	struct loadparm_service serviceTemp;

	string_set(ptr, pszParmValue);

	init_service(&serviceTemp);

	bRetval = false;

	DEBUG(3, ("Copying service from service %s\n", pszParmValue));

	if ((iTemp = getservicebyname(pszParmValue, &serviceTemp)) >= 0) {
		if (iTemp == iServiceIndex) {
			DEBUG(0, ("Can't copy service %s - unable to copy self!\n", pszParmValue));
		} else {
			copy_service(ServicePtrs[iServiceIndex],
				     &serviceTemp,
				     ServicePtrs[iServiceIndex]->copymap);
			bRetval = true;
		}
	} else {
		DEBUG(0, ("Unable to copy service - source not found: %s\n", pszParmValue));
		bRetval = false;
	}

	free_service(&serviceTemp);
	return (bRetval);
}

static bool handle_ldap_debug_level(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	Globals.ldap_debug_level = lp_int(pszParmValue);
	init_ldap_debugging();
	return true;
}

/***************************************************************************
 Handle idmap/non unix account uid and gid allocation parameters.  The format of these
 parameters is:

 [global]

        idmap uid = 1000-1999
        idmap gid = 700-899

 We only do simple parsing checks here.  The strings are parsed into useful
 structures in the idmap daemon code.

***************************************************************************/

/* Some lp_ routines to return idmap [ug]id information */

static uid_t idmap_uid_low, idmap_uid_high;
static gid_t idmap_gid_low, idmap_gid_high;

bool lp_idmap_uid(uid_t *low, uid_t *high)
{
        if (idmap_uid_low == 0 || idmap_uid_high == 0)
                return false;

        if (low)
                *low = idmap_uid_low;

        if (high)
                *high = idmap_uid_high;

        return true;
}

bool lp_idmap_gid(gid_t *low, gid_t *high)
{
        if (idmap_gid_low == 0 || idmap_gid_high == 0)
                return false;

        if (low)
                *low = idmap_gid_low;

        if (high)
                *high = idmap_gid_high;

        return true;
}

static bool handle_idmap_backend(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	lp_do_parameter(snum, "idmap config * : backend", pszParmValue);

	return true;
}

/* Do some simple checks on "idmap [ug]id" parameter values */

static bool handle_idmap_uid(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	lp_do_parameter(snum, "idmap config * : range", pszParmValue);

	return true;
}

static bool handle_idmap_gid(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	lp_do_parameter(snum, "idmap config * : range", pszParmValue);

	return true;
}

/***************************************************************************
 Handle the DEBUG level list.
***************************************************************************/

static bool handle_debug_list(struct loadparm_context *unused, int snum, const char *pszParmValueIn, char **ptr )
{
	string_set(ptr, pszParmValueIn);
	return debug_parse_levels(pszParmValueIn);
}

/***************************************************************************
 Handle ldap suffixes - default to ldapsuffix if sub-suffixes are not defined.
***************************************************************************/

static const char *append_ldap_suffix(TALLOC_CTX *ctx, const char *str )
{
	const char *suffix_string;

	suffix_string = talloc_asprintf(ctx, "%s,%s", str,
					Globals.szLdapSuffix );
	if ( !suffix_string ) {
		DEBUG(0,("append_ldap_suffix: talloc_asprintf() failed!\n"));
		return "";
	}

	return suffix_string;
}

const char *lp_ldap_machine_suffix(TALLOC_CTX *ctx)
{
	if (Globals.szLdapMachineSuffix[0])
		return append_ldap_suffix(ctx, Globals.szLdapMachineSuffix);

	return lp_string(ctx, Globals.szLdapSuffix);
}

const char *lp_ldap_user_suffix(TALLOC_CTX *ctx)
{
	if (Globals.szLdapUserSuffix[0])
		return append_ldap_suffix(ctx, Globals.szLdapUserSuffix);

	return lp_string(ctx, Globals.szLdapSuffix);
}

const char *lp_ldap_group_suffix(TALLOC_CTX *ctx)
{
	if (Globals.szLdapGroupSuffix[0])
		return append_ldap_suffix(ctx, Globals.szLdapGroupSuffix);

	return lp_string(ctx, Globals.szLdapSuffix);
}

const char *lp_ldap_idmap_suffix(TALLOC_CTX *ctx)
{
	if (Globals.szLdapIdmapSuffix[0])
		return append_ldap_suffix(ctx, Globals.szLdapIdmapSuffix);

	return lp_string(ctx, Globals.szLdapSuffix);
}

/****************************************************************************
 set the value for a P_ENUM
 ***************************************************************************/

static void lp_set_enum_parm( struct parm_struct *parm, const char *pszParmValue,
                              int *ptr )
{
	int i;

	for (i = 0; parm->enum_list[i].name; i++) {
		if ( strequal(pszParmValue, parm->enum_list[i].name)) {
			*ptr = parm->enum_list[i].value;
			return;
		}
	}
	DEBUG(0, ("WARNING: Ignoring invalid value '%s' for parameter '%s'\n",
		  pszParmValue, parm->label));
}

/***************************************************************************
***************************************************************************/

static bool handle_printing(struct loadparm_context *unused, int snum, const char *pszParmValue, char **ptr)
{
	static int parm_num = -1;
	struct loadparm_service *s;

	if ( parm_num == -1 )
		parm_num = map_parameter( "printing" );

	lp_set_enum_parm( &parm_table[parm_num], pszParmValue, (int*)ptr );

	if ( snum < 0 )
		s = &sDefault;
	else
		s = ServicePtrs[snum];

	init_printer_values( s );

	return true;
}


/***************************************************************************
 Initialise a copymap.
***************************************************************************/

static void init_copymap(struct loadparm_service *pservice)
{
	int i;

	TALLOC_FREE(pservice->copymap);

	pservice->copymap = bitmap_talloc(NULL, NUMPARAMETERS);
	if (!pservice->copymap)
		DEBUG(0,
		      ("Couldn't allocate copymap!! (size %d)\n",
		       (int)NUMPARAMETERS));
	else
		for (i = 0; i < NUMPARAMETERS; i++)
			bitmap_set(pservice->copymap, i);
}

/**
  return the parameter pointer for a parameter
*/
void *lp_parm_ptr(struct loadparm_service *service, struct parm_struct *parm)
{
	if (service == NULL) {
		if (parm->p_class == P_LOCAL)
			return (void *)(((char *)&sDefault)+parm->offset);
		else if (parm->p_class == P_GLOBAL)
			return (void *)(((char *)&Globals)+parm->offset);
		else return NULL;
	} else {
		return (void *)(((char *)service) + parm->offset);
	}
}

/***************************************************************************
 Return the local pointer to a parameter given the service number and parameter
***************************************************************************/

void *lp_local_ptr_by_snum(int snum, struct parm_struct *parm)
{
	return lp_parm_ptr(ServicePtrs[snum], parm);
}

/***************************************************************************
 Process a parameter for a particular service number. If snum < 0
 then assume we are in the globals.
***************************************************************************/

bool lp_do_parameter(int snum, const char *pszParmName, const char *pszParmValue)
{
	int parmnum, i;
	void *parm_ptr = NULL;	/* where we are going to store the result */
	struct parmlist_entry **opt_list;

	parmnum = map_parameter(pszParmName);

	if (parmnum < 0) {
		if (strchr(pszParmName, ':') == NULL) {
			DEBUG(0, ("Ignoring unknown parameter \"%s\"\n",
				  pszParmName));
			return true;
		}

		/*
		 * We've got a parametric option
		 */

		opt_list = (snum < 0)
			? &Globals.param_opt : &ServicePtrs[snum]->param_opt;
		set_param_opt(opt_list, pszParmName, pszParmValue, 0);

		return true;
	}

	/* if it's already been set by the command line, then we don't
	   override here */
	if (parm_table[parmnum].flags & FLAG_CMDLINE) {
		return true;
	}

	if (parm_table[parmnum].flags & FLAG_DEPRECATED) {
		DEBUG(1, ("WARNING: The \"%s\" option is deprecated\n",
			  pszParmName));
	}

	/* we might point at a service, the default service or a global */
	if (snum < 0) {
		parm_ptr = lp_parm_ptr(NULL, &parm_table[parmnum]);
	} else {
		if (parm_table[parmnum].p_class == P_GLOBAL) {
			DEBUG(0,
			      ("Global parameter %s found in service section!\n",
			       pszParmName));
			return true;
		}
		parm_ptr = lp_local_ptr_by_snum(snum, &parm_table[parmnum]);
	}

	if (snum >= 0) {
		if (!ServicePtrs[snum]->copymap)
			init_copymap(ServicePtrs[snum]);

		/* this handles the aliases - set the copymap for other entries with
		   the same data pointer */
		for (i = 0; parm_table[i].label; i++) {
			if ((parm_table[i].offset == parm_table[parmnum].offset)
			    && (parm_table[i].p_class == parm_table[parmnum].p_class)) {
				bitmap_clear(ServicePtrs[snum]->copymap, i);
			}
		}
	}

	/* if it is a special case then go ahead */
	if (parm_table[parmnum].special) {
		return parm_table[parmnum].special(NULL, snum, pszParmValue,
						   (char **)parm_ptr);
	}

	/* now switch on the type of variable it is */
	switch (parm_table[parmnum].type)
	{
		case P_BOOL:
			*(bool *)parm_ptr = lp_bool(pszParmValue);
			break;

		case P_BOOLREV:
			*(bool *)parm_ptr = !lp_bool(pszParmValue);
			break;

		case P_INTEGER:
			*(int *)parm_ptr = lp_int(pszParmValue);
			break;

		case P_CHAR:
			*(char *)parm_ptr = *pszParmValue;
			break;

		case P_OCTAL:
			i = sscanf(pszParmValue, "%o", (int *)parm_ptr);
			if ( i != 1 ) {
			    DEBUG ( 0, ("Invalid octal number %s\n", pszParmName ));
			}
			break;

		case P_BYTES:
		{
			uint64_t val;
			if (conv_str_size_error(pszParmValue, &val)) {
				if (val <= INT_MAX) {
					*(int *)parm_ptr = (int)val;
					break;
				}
			}

			DEBUG(0,("lp_do_parameter(%s): value is not "
			    "a valid size specifier!\n", pszParmValue));
			return false;
		}

		case P_LIST:
		case P_CMDLIST:
			TALLOC_FREE(*((char ***)parm_ptr));
			*(char ***)parm_ptr = str_list_make_v3(
				NULL, pszParmValue, NULL);
			break;

		case P_STRING:
			string_set((char **)parm_ptr, pszParmValue);
			break;

		case P_USTRING:
		{
			char *upper_string = strupper_talloc(talloc_tos(), 
							     pszParmValue);
			string_set((char **)parm_ptr, upper_string);
			TALLOC_FREE(upper_string);
			break;
		}
		case P_ENUM:
			lp_set_enum_parm( &parm_table[parmnum], pszParmValue, (int*)parm_ptr );
			break;
		case P_SEP:
			break;
	}

	return true;
}

/***************************************************************************
set a parameter, marking it with FLAG_CMDLINE. Parameters marked as
FLAG_CMDLINE won't be overridden by loads from smb.conf.
***************************************************************************/

static bool lp_set_cmdline_helper(const char *pszParmName, const char *pszParmValue, bool store_values)
{
	int parmnum, i;
	parmnum = map_parameter(pszParmName);
	if (parmnum >= 0) {
		parm_table[parmnum].flags &= ~FLAG_CMDLINE;
		if (!lp_do_parameter(-1, pszParmName, pszParmValue)) {
			return false;
		}
		parm_table[parmnum].flags |= FLAG_CMDLINE;

		/* we have to also set FLAG_CMDLINE on aliases.  Aliases must
		 * be grouped in the table, so we don't have to search the
		 * whole table */
		for (i=parmnum-1;
		     i>=0 && parm_table[i].offset == parm_table[parmnum].offset
			     && parm_table[i].p_class == parm_table[parmnum].p_class;
		     i--) {
			parm_table[i].flags |= FLAG_CMDLINE;
		}
		for (i=parmnum+1;i<NUMPARAMETERS && parm_table[i].offset == parm_table[parmnum].offset
			     && parm_table[i].p_class == parm_table[parmnum].p_class;i++) {
			parm_table[i].flags |= FLAG_CMDLINE;
		}

		if (store_values) {
			store_lp_set_cmdline(pszParmName, pszParmValue);
		}
		return true;
	}

	/* it might be parametric */
	if (strchr(pszParmName, ':') != NULL) {
		set_param_opt(&Globals.param_opt, pszParmName, pszParmValue, FLAG_CMDLINE);
		if (store_values) {
			store_lp_set_cmdline(pszParmName, pszParmValue);
		}
		return true;
	}

	DEBUG(0, ("Ignoring unknown parameter \"%s\"\n",  pszParmName));
	return true;
}

bool lp_set_cmdline(const char *pszParmName, const char *pszParmValue)
{
	return lp_set_cmdline_helper(pszParmName, pszParmValue, true);
}

/***************************************************************************
 Process a parameter.
***************************************************************************/

static bool do_parameter(const char *pszParmName, const char *pszParmValue,
			 void *userdata)
{
	if (!bInGlobalSection && bGlobalOnly)
		return true;

	DEBUGADD(4, ("doing parameter %s = %s\n", pszParmName, pszParmValue));

	return (lp_do_parameter(bInGlobalSection ? -2 : iServiceIndex,
				pszParmName, pszParmValue));
}

/*
  set a option from the commandline in 'a=b' format. Use to support --option
*/
bool lp_set_option(const char *option)
{
	char *p, *s;
	bool ret;

	s = talloc_strdup(NULL, option);
	if (!s) {
		return false;
	}

	p = strchr(s, '=');
	if (!p) {
		talloc_free(s);
		return false;
	}

	*p = 0;

	/* skip white spaces after the = sign */
	do {
		p++;
	} while (*p == ' ');

	ret = lp_set_cmdline(s, p);
	talloc_free(s);
	return ret;
}

/**************************************************************************
 Print a parameter of the specified type.
***************************************************************************/

static void print_parameter(struct parm_struct *p, void *ptr, FILE * f)
{
	/* For the seperation of lists values that we print below */
	const char *list_sep = ", ";
	int i;
	switch (p->type)
	{
		case P_ENUM:
			for (i = 0; p->enum_list[i].name; i++) {
				if (*(int *)ptr == p->enum_list[i].value) {
					fprintf(f, "%s",
						p->enum_list[i].name);
					break;
				}
			}
			break;

		case P_BOOL:
			fprintf(f, "%s", BOOLSTR(*(bool *)ptr));
			break;

		case P_BOOLREV:
			fprintf(f, "%s", BOOLSTR(!*(bool *)ptr));
			break;

		case P_INTEGER:
		case P_BYTES:
			fprintf(f, "%d", *(int *)ptr);
			break;

		case P_CHAR:
			fprintf(f, "%c", *(char *)ptr);
			break;

		case P_OCTAL: {
			int val = *(int *)ptr; 
			if (val == -1) {
				fprintf(f, "-1");
			} else {
				fprintf(f, "0%o", val);
			}
			break;
		}

		case P_CMDLIST:
			list_sep = " ";
			/* fall through */
		case P_LIST:
			if ((char ***)ptr && *(char ***)ptr) {
				char **list = *(char ***)ptr;
				for (; *list; list++) {
					/* surround strings with whitespace in double quotes */
					if (*(list+1) == NULL) {
						/* last item, no extra separator */
						list_sep = "";
					}
					if ( strchr_m( *list, ' ' ) ) {
						fprintf(f, "\"%s\"%s", *list, list_sep);
					} else {
						fprintf(f, "%s%s", *list, list_sep);
					}
				}
			}
			break;

		case P_STRING:
		case P_USTRING:
			if (*(char **)ptr) {
				fprintf(f, "%s", *(char **)ptr);
			}
			break;
		case P_SEP:
			break;
	}
}

/***************************************************************************
 Check if two parameters are equal.
***************************************************************************/

static bool equal_parameter(parm_type type, void *ptr1, void *ptr2)
{
	switch (type) {
		case P_BOOL:
		case P_BOOLREV:
			return (*((bool *)ptr1) == *((bool *)ptr2));

		case P_INTEGER:
		case P_ENUM:
		case P_OCTAL:
		case P_BYTES:
			return (*((int *)ptr1) == *((int *)ptr2));

		case P_CHAR:
			return (*((char *)ptr1) == *((char *)ptr2));

		case P_LIST:
		case P_CMDLIST:
			return str_list_equal(*(const char ***)ptr1, *(const char ***)ptr2);

		case P_STRING:
		case P_USTRING:
		{
			char *p1 = *(char **)ptr1, *p2 = *(char **)ptr2;
			if (p1 && !*p1)
				p1 = NULL;
			if (p2 && !*p2)
				p2 = NULL;
			return (p1 == p2 || strequal(p1, p2));
		}
		case P_SEP:
			break;
	}
	return false;
}

/***************************************************************************
 Initialize any local variables in the sDefault table, after parsing a
 [globals] section.
***************************************************************************/

static void init_locals(void)
{
	/*
	 * We run this check once the [globals] is parsed, to force
	 * the VFS objects and other per-share settings we need for
	 * the standard way a AD DC is operated.  We may change these
	 * as our code evolves, which is why we force these settings.
	 *
	 * We can't do this at the end of lp_load_ex(), as by that
	 * point the services have been loaded and they will already
	 * have "" as their vfs objects.
	 */
	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		const char **vfs_objects = lp_vfs_objects(-1);
		if (!vfs_objects || !vfs_objects[0]) {
			if (lp_parm_const_string(-1, "xattr_tdb", "file", NULL)) {
				lp_do_parameter(-1, "vfs objects", "dfs_samba4 acl_xattr xattr_tdb");
			} else if (lp_parm_const_string(-1, "posix", "eadb", NULL)) {
				lp_do_parameter(-1, "vfs objects", "dfs_samba4 acl_xattr posix_eadb");
			} else {
				lp_do_parameter(-1, "vfs objects", "dfs_samba4 acl_xattr");
			}
		}

		lp_do_parameter(-1, "map hidden", "no");
		lp_do_parameter(-1, "map system", "no");
		lp_do_parameter(-1, "map readonly", "no");
		lp_do_parameter(-1, "map archive", "no");
		lp_do_parameter(-1, "store dos attributes", "yes");
	}
}

/***************************************************************************
 Process a new section (service). At this stage all sections are services.
 Later we'll have special sections that permit server parameters to be set.
 Returns true on success, false on failure.
***************************************************************************/

static bool do_section(const char *pszSectionName, void *userdata)
{
	bool bRetval;
	bool isglobal = ((strwicmp(pszSectionName, GLOBAL_NAME) == 0) ||
			 (strwicmp(pszSectionName, GLOBAL_NAME2) == 0));
	bRetval = false;

	/* if we were in a global section then do the local inits */
	if (bInGlobalSection && !isglobal)
		init_locals();

	/* if we've just struck a global section, note the fact. */
	bInGlobalSection = isglobal;

	/* check for multiple global sections */
	if (bInGlobalSection) {
		DEBUG(3, ("Processing section \"[%s]\"\n", pszSectionName));
		return true;
	}

	if (!bInGlobalSection && bGlobalOnly)
		return true;

	/* if we have a current service, tidy it up before moving on */
	bRetval = true;

	if (iServiceIndex >= 0)
		bRetval = service_ok(iServiceIndex);

	/* if all is still well, move to the next record in the services array */
	if (bRetval) {
		/* We put this here to avoid an odd message order if messages are */
		/* issued by the post-processing of a previous section. */
		DEBUG(2, ("Processing section \"[%s]\"\n", pszSectionName));

		iServiceIndex = add_a_service(&sDefault, pszSectionName);
		if (iServiceIndex < 0) {
			DEBUG(0, ("Failed to add a new service\n"));
			return false;
		}
		/* Clean all parametric options for service */
		/* They will be added during parsing again */
		free_param_opts(&ServicePtrs[iServiceIndex]->param_opt);
	}

	return bRetval;
}


/***************************************************************************
 Determine if a partcular base parameter is currentl set to the default value.
***************************************************************************/

static bool is_default(int i)
{
	if (!defaults_saved)
		return false;
	switch (parm_table[i].type) {
		case P_LIST:
		case P_CMDLIST:
			return str_list_equal((const char **)parm_table[i].def.lvalue, 
					      *(const char ***)lp_parm_ptr(NULL, 
									   &parm_table[i]));
		case P_STRING:
		case P_USTRING:
			return strequal(parm_table[i].def.svalue,
					*(char **)lp_parm_ptr(NULL, 
							      &parm_table[i]));
		case P_BOOL:
		case P_BOOLREV:
			return parm_table[i].def.bvalue ==
				*(bool *)lp_parm_ptr(NULL, 
						     &parm_table[i]);
		case P_CHAR:
			return parm_table[i].def.cvalue ==
				*(char *)lp_parm_ptr(NULL, 
						     &parm_table[i]);
		case P_INTEGER:
		case P_OCTAL:
		case P_ENUM:
		case P_BYTES:
			return parm_table[i].def.ivalue ==
				*(int *)lp_parm_ptr(NULL, 
						    &parm_table[i]);
		case P_SEP:
			break;
	}
	return false;
}

/***************************************************************************
Display the contents of the global structure.
***************************************************************************/

static void dump_globals(FILE *f)
{
	int i;
	struct parmlist_entry *data;

	fprintf(f, "[global]\n");

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].p_class == P_GLOBAL &&
		    !(parm_table[i].flags & FLAG_META) &&
		    (i == 0 || (parm_table[i].offset != parm_table[i - 1].offset))) {
			if (defaults_saved && is_default(i))
				continue;
			fprintf(f, "\t%s = ", parm_table[i].label);
			print_parameter(&parm_table[i], lp_parm_ptr(NULL, 
								    &parm_table[i]),
					f);
			fprintf(f, "\n");
	}
	if (Globals.param_opt != NULL) {
		data = Globals.param_opt;
		while(data) {
			fprintf(f, "\t%s = %s\n", data->key, data->value);
			data = data->next;
		}
        }

}

/***************************************************************************
 Return true if a local parameter is currently set to the global default.
***************************************************************************/

bool lp_is_default(int snum, struct parm_struct *parm)
{
	return equal_parameter(parm->type,
			       lp_parm_ptr(ServicePtrs[snum], parm),
			       lp_parm_ptr(NULL, parm));
}

/***************************************************************************
 Display the contents of a single services record.
***************************************************************************/

static void dump_a_service(struct loadparm_service *pService, FILE * f)
{
	int i;
	struct parmlist_entry *data;

	if (pService != &sDefault)
		fprintf(f, "[%s]\n", pService->szService);

	for (i = 0; parm_table[i].label; i++) {

		if (parm_table[i].p_class == P_LOCAL &&
		    !(parm_table[i].flags & FLAG_META) &&
		    (*parm_table[i].label != '-') &&
		    (i == 0 || (parm_table[i].offset != parm_table[i - 1].offset))) 
		{
			if (pService == &sDefault) {
				if (defaults_saved && is_default(i))
					continue;
			} else {
				if (equal_parameter(parm_table[i].type,
						    lp_parm_ptr(pService, &parm_table[i]),
						    lp_parm_ptr(NULL, &parm_table[i])))
					continue;
			}

			fprintf(f, "\t%s = ", parm_table[i].label);
			print_parameter(&parm_table[i],
					lp_parm_ptr(pService, &parm_table[i]),
					f);
			fprintf(f, "\n");
		}
	}

		if (pService->param_opt != NULL) {
			data = pService->param_opt;
			while(data) {
				fprintf(f, "\t%s = %s\n", data->key, data->value);
				data = data->next;
			}
        	}
}

/***************************************************************************
 Display the contents of a parameter of a single services record.
***************************************************************************/

bool dump_a_parameter(int snum, char *parm_name, FILE * f, bool isGlobal)
{
	int i;
	bool result = false;
	parm_class p_class;
	unsigned flag = 0;
	fstring local_parm_name;
	char *parm_opt;
	const char *parm_opt_value;

	/* check for parametrical option */
	fstrcpy( local_parm_name, parm_name);
	parm_opt = strchr( local_parm_name, ':');

	if (parm_opt) {
		*parm_opt = '\0';
		parm_opt++;
		if (strlen(parm_opt)) {
			parm_opt_value = lp_parm_const_string( snum,
				local_parm_name, parm_opt, NULL);
			if (parm_opt_value) {
				printf( "%s\n", parm_opt_value);
				result = true;
			}
		}
		return result;
	}

	/* check for a key and print the value */
	if (isGlobal) {
		p_class = P_GLOBAL;
		flag = FLAG_GLOBAL;
	} else
		p_class = P_LOCAL;

	for (i = 0; parm_table[i].label; i++) {
		if (strwicmp(parm_table[i].label, parm_name) == 0 &&
		    !(parm_table[i].flags & FLAG_META) &&
		    (parm_table[i].p_class == p_class || parm_table[i].flags & flag) &&
		    (*parm_table[i].label != '-') &&
		    (i == 0 || (parm_table[i].offset != parm_table[i - 1].offset))) 
		{
			void *ptr;

			if (isGlobal) {
				ptr = lp_parm_ptr(NULL, 
						  &parm_table[i]);
			} else {
				ptr = lp_parm_ptr(ServicePtrs[snum], 
						  &parm_table[i]);
			}

			print_parameter(&parm_table[i],
					ptr, f);
			fprintf(f, "\n");
			result = true;
			break;
		}
	}

	return result;
}

/***************************************************************************
 Return info about the requested parameter (given as a string).
 Return NULL when the string is not a valid parameter name.
***************************************************************************/

struct parm_struct *lp_get_parameter(const char *param_name)
{
	int num = map_parameter(param_name);

	if (num < 0) {
		return NULL;
	}

	return &parm_table[num];
}

/***************************************************************************
 Return info about the next parameter in a service.
 snum==GLOBAL_SECTION_SNUM gives the globals.
 Return NULL when out of parameters.
***************************************************************************/

struct parm_struct *lp_next_parameter(int snum, int *i, int allparameters)
{
	if (snum < 0) {
		/* do the globals */
		for (; parm_table[*i].label; (*i)++) {
			if (parm_table[*i].p_class == P_SEPARATOR)
				return &parm_table[(*i)++];

			if ((*parm_table[*i].label == '-'))
				continue;

			if ((*i) > 0
			    && (parm_table[*i].offset ==
				parm_table[(*i) - 1].offset)
			    && (parm_table[*i].p_class ==
				parm_table[(*i) - 1].p_class))
				continue;

			if (is_default(*i) && !allparameters)
				continue;

			return &parm_table[(*i)++];
		}
	} else {
		struct loadparm_service *pService = ServicePtrs[snum];

		for (; parm_table[*i].label; (*i)++) {
			if (parm_table[*i].p_class == P_SEPARATOR)
				return &parm_table[(*i)++];

			if (parm_table[*i].p_class == P_LOCAL &&
			    (*parm_table[*i].label != '-') &&
			    ((*i) == 0 ||
			     (parm_table[*i].offset !=
			      parm_table[(*i) - 1].offset)))
			{
				if (allparameters ||
				    !equal_parameter(parm_table[*i].type,
						     lp_parm_ptr(pService, 
								 &parm_table[*i]),
						     lp_parm_ptr(NULL, 
								 &parm_table[*i])))
				{
					return &parm_table[(*i)++];
				}
			}
		}
	}

	return NULL;
}


#if 0
/***************************************************************************
 Display the contents of a single copy structure.
***************************************************************************/
static void dump_copy_map(bool *pcopymap)
{
	int i;
	if (!pcopymap)
		return;

	printf("\n\tNon-Copied parameters:\n");

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].p_class == P_LOCAL &&
		    parm_table[i].ptr && !pcopymap[i] &&
		    (i == 0 || (parm_table[i].ptr != parm_table[i - 1].ptr)))
		{
			printf("\t\t%s\n", parm_table[i].label);
		}
}
#endif

/***************************************************************************
 Return TRUE if the passed service number is within range.
***************************************************************************/

bool lp_snum_ok(int iService)
{
	return (LP_SNUM_OK(iService) && ServicePtrs[iService]->bAvailable);
}

/***************************************************************************
 Auto-load some home services.
***************************************************************************/

static void lp_add_auto_services(char *str)
{
	char *s;
	char *p;
	int homes;
	char *saveptr;

	if (!str)
		return;

	s = SMB_STRDUP(str);
	if (!s)
		return;

	homes = lp_servicenumber(HOMES_NAME);

	for (p = strtok_r(s, LIST_SEP, &saveptr); p;
	     p = strtok_r(NULL, LIST_SEP, &saveptr)) {
		char *home;

		if (lp_servicenumber(p) >= 0)
			continue;

		home = get_user_home_dir(talloc_tos(), p);

		if (home && home[0] && homes >= 0)
			lp_add_home(p, homes, p, home);

		TALLOC_FREE(home);
	}
	SAFE_FREE(s);
}

/***************************************************************************
 Auto-load one printer.
***************************************************************************/

void lp_add_one_printer(const char *name, const char *comment,
			const char *location, void *pdata)
{
	int printers = lp_servicenumber(PRINTERS_NAME);
	int i;

	if (lp_servicenumber(name) < 0) {
		lp_add_printer(name, printers);
		if ((i = lp_servicenumber(name)) >= 0) {
			string_set(&ServicePtrs[i]->comment, comment);
			ServicePtrs[i]->autoloaded = true;
		}
	}
}

/***************************************************************************
 Have we loaded a services file yet?
***************************************************************************/

bool lp_loaded(void)
{
	return (bLoaded);
}

/***************************************************************************
 Unload unused services.
***************************************************************************/

void lp_killunused(struct smbd_server_connection *sconn,
		   bool (*snumused) (struct smbd_server_connection *, int))
{
	int i;
	for (i = 0; i < iNumServices; i++) {
		if (!VALID(i))
			continue;

		/* don't kill autoloaded or usershare services */
		if ( ServicePtrs[i]->autoloaded ||
				ServicePtrs[i]->usershare == USERSHARE_VALID) {
			continue;
		}

		if (!snumused || !snumused(sconn, i)) {
			free_service_byindex(i);
		}
	}
}

/**
 * Kill all except autoloaded and usershare services - convenience wrapper
 */
void lp_kill_all_services(void)
{
	lp_killunused(NULL, NULL);
}

/***************************************************************************
 Unload a service.
***************************************************************************/

void lp_killservice(int iServiceIn)
{
	if (VALID(iServiceIn)) {
		free_service_byindex(iServiceIn);
	}
}

/***************************************************************************
 Save the curent values of all global and sDefault parameters into the 
 defaults union. This allows swat and testparm to show only the
 changed (ie. non-default) parameters.
***************************************************************************/

static void lp_save_defaults(void)
{
	int i;
	for (i = 0; parm_table[i].label; i++) {
		if (i > 0 && parm_table[i].offset == parm_table[i - 1].offset
		    && parm_table[i].p_class == parm_table[i - 1].p_class)
			continue;
		switch (parm_table[i].type) {
			case P_LIST:
			case P_CMDLIST:
				parm_table[i].def.lvalue = str_list_copy(
					NULL, *(const char ***)lp_parm_ptr(NULL, &parm_table[i]));
				break;
			case P_STRING:
			case P_USTRING:
				parm_table[i].def.svalue = SMB_STRDUP(*(char **)lp_parm_ptr(NULL, &parm_table[i]));
				break;
			case P_BOOL:
			case P_BOOLREV:
				parm_table[i].def.bvalue =
					*(bool *)lp_parm_ptr(NULL, &parm_table[i]);
				break;
			case P_CHAR:
				parm_table[i].def.cvalue =
					*(char *)lp_parm_ptr(NULL, &parm_table[i]);
				break;
			case P_INTEGER:
			case P_OCTAL:
			case P_ENUM:
			case P_BYTES:
				parm_table[i].def.ivalue =
					*(int *)lp_parm_ptr(NULL, &parm_table[i]);
				break;
			case P_SEP:
				break;
		}
	}
	defaults_saved = true;
}

/***********************************************************
 If we should send plaintext/LANMAN passwords in the clinet
************************************************************/

static void set_allowed_client_auth(void)
{
	if (Globals.bClientNTLMv2Auth) {
		Globals.bClientLanManAuth = false;
	}
	if (!Globals.bClientLanManAuth) {
		Globals.bClientPlaintextAuth = false;
	}
}

/***************************************************************************
 JRA.
 The following code allows smbd to read a user defined share file.
 Yes, this is my intent. Yes, I'm comfortable with that...

 THE FOLLOWING IS SECURITY CRITICAL CODE.

 It washes your clothes, it cleans your house, it guards you while you sleep...
 Do not f%^k with it....
***************************************************************************/

#define MAX_USERSHARE_FILE_SIZE (10*1024)

/***************************************************************************
 Check allowed stat state of a usershare file.
 Ensure we print out who is dicking with us so the admin can
 get their sorry ass fired.
***************************************************************************/

static bool check_usershare_stat(const char *fname,
				 const SMB_STRUCT_STAT *psbuf)
{
	if (!S_ISREG(psbuf->st_ex_mode)) {
		DEBUG(0,("check_usershare_stat: file %s owned by uid %u is "
			"not a regular file\n",
			fname, (unsigned int)psbuf->st_ex_uid ));
		return false;
	}

	/* Ensure this doesn't have the other write bit set. */
	if (psbuf->st_ex_mode & S_IWOTH) {
		DEBUG(0,("check_usershare_stat: file %s owned by uid %u allows "
			"public write. Refusing to allow as a usershare file.\n",
			fname, (unsigned int)psbuf->st_ex_uid ));
		return false;
	}

	/* Should be 10k or less. */
	if (psbuf->st_ex_size > MAX_USERSHARE_FILE_SIZE) {
		DEBUG(0,("check_usershare_stat: file %s owned by uid %u is "
			"too large (%u) to be a user share file.\n",
			fname, (unsigned int)psbuf->st_ex_uid,
			(unsigned int)psbuf->st_ex_size ));
		return false;
	}

	return true;
}

/***************************************************************************
 Parse the contents of a usershare file.
***************************************************************************/

enum usershare_err parse_usershare_file(TALLOC_CTX *ctx,
			SMB_STRUCT_STAT *psbuf,
			const char *servicename,
			int snum,
			char **lines,
			int numlines,
			char **pp_sharepath,
			char **pp_comment,
			char **pp_cp_servicename,
			struct security_descriptor **ppsd,
			bool *pallow_guest)
{
	const char **prefixallowlist = lp_usershare_prefix_allow_list();
	const char **prefixdenylist = lp_usershare_prefix_deny_list();
	int us_vers;
	DIR *dp;
	SMB_STRUCT_STAT sbuf;
	char *sharepath = NULL;
	char *comment = NULL;

	*pp_sharepath = NULL;
	*pp_comment = NULL;

	*pallow_guest = false;

	if (numlines < 4) {
		return USERSHARE_MALFORMED_FILE;
	}

	if (strcmp(lines[0], "#VERSION 1") == 0) {
		us_vers = 1;
	} else if (strcmp(lines[0], "#VERSION 2") == 0) {
		us_vers = 2;
		if (numlines < 5) {
			return USERSHARE_MALFORMED_FILE;
		}
	} else {
		return USERSHARE_BAD_VERSION;
	}

	if (strncmp(lines[1], "path=", 5) != 0) {
		return USERSHARE_MALFORMED_PATH;
	}

	sharepath = talloc_strdup(ctx, &lines[1][5]);
	if (!sharepath) {
		return USERSHARE_POSIX_ERR;
	}
	trim_string(sharepath, " ", " ");

	if (strncmp(lines[2], "comment=", 8) != 0) {
		return USERSHARE_MALFORMED_COMMENT_DEF;
	}

	comment = talloc_strdup(ctx, &lines[2][8]);
	if (!comment) {
		return USERSHARE_POSIX_ERR;
	}
	trim_string(comment, " ", " ");
	trim_char(comment, '"', '"');

	if (strncmp(lines[3], "usershare_acl=", 14) != 0) {
		return USERSHARE_MALFORMED_ACL_DEF;
	}

	if (!parse_usershare_acl(ctx, &lines[3][14], ppsd)) {
		return USERSHARE_ACL_ERR;
	}

	if (us_vers == 2) {
		if (strncmp(lines[4], "guest_ok=", 9) != 0) {
			return USERSHARE_MALFORMED_ACL_DEF;
		}
		if (lines[4][9] == 'y') {
			*pallow_guest = true;
		}

		/* Backwards compatible extension to file version #2. */
		if (numlines > 5) {
			if (strncmp(lines[5], "sharename=", 10) != 0) {
				return USERSHARE_MALFORMED_SHARENAME_DEF;
			}
			if (!strequal(&lines[5][10], servicename)) {
				return USERSHARE_BAD_SHARENAME;
			}
			*pp_cp_servicename = talloc_strdup(ctx, &lines[5][10]);
			if (!*pp_cp_servicename) {
				return USERSHARE_POSIX_ERR;
			}
		}
	}

	if (*pp_cp_servicename == NULL) {
		*pp_cp_servicename = talloc_strdup(ctx, servicename);
		if (!*pp_cp_servicename) {
			return USERSHARE_POSIX_ERR;
		}
	}

	if (snum != -1 && (strcmp(sharepath, ServicePtrs[snum]->szPath) == 0)) {
		/* Path didn't change, no checks needed. */
		*pp_sharepath = sharepath;
		*pp_comment = comment;
		return USERSHARE_OK;
	}

	/* The path *must* be absolute. */
	if (sharepath[0] != '/') {
		DEBUG(2,("parse_usershare_file: share %s: path %s is not an absolute path.\n",
			servicename, sharepath));
		return USERSHARE_PATH_NOT_ABSOLUTE;
	}

	/* If there is a usershare prefix deny list ensure one of these paths
	   doesn't match the start of the user given path. */
	if (prefixdenylist) {
		int i;
		for ( i=0; prefixdenylist[i]; i++ ) {
			DEBUG(10,("parse_usershare_file: share %s : checking prefixdenylist[%d]='%s' against %s\n",
				servicename, i, prefixdenylist[i], sharepath ));
			if (memcmp( sharepath, prefixdenylist[i], strlen(prefixdenylist[i])) == 0) {
				DEBUG(2,("parse_usershare_file: share %s path %s starts with one of the "
					"usershare prefix deny list entries.\n",
					servicename, sharepath));
				return USERSHARE_PATH_IS_DENIED;
			}
		}
	}

	/* If there is a usershare prefix allow list ensure one of these paths
	   does match the start of the user given path. */

	if (prefixallowlist) {
		int i;
		for ( i=0; prefixallowlist[i]; i++ ) {
			DEBUG(10,("parse_usershare_file: share %s checking prefixallowlist[%d]='%s' against %s\n",
				servicename, i, prefixallowlist[i], sharepath ));
			if (memcmp( sharepath, prefixallowlist[i], strlen(prefixallowlist[i])) == 0) {
				break;
			}
		}
		if (prefixallowlist[i] == NULL) {
			DEBUG(2,("parse_usershare_file: share %s path %s doesn't start with one of the "
				"usershare prefix allow list entries.\n",
				servicename, sharepath));
			return USERSHARE_PATH_NOT_ALLOWED;
		}
        }

	/* Ensure this is pointing to a directory. */
	dp = opendir(sharepath);

	if (!dp) {
		DEBUG(2,("parse_usershare_file: share %s path %s is not a directory.\n",
			servicename, sharepath));
		return USERSHARE_PATH_NOT_DIRECTORY;
	}

	/* Ensure the owner of the usershare file has permission to share
	   this directory. */

	if (sys_stat(sharepath, &sbuf, false) == -1) {
		DEBUG(2,("parse_usershare_file: share %s : stat failed on path %s. %s\n",
			servicename, sharepath, strerror(errno) ));
		closedir(dp);
		return USERSHARE_POSIX_ERR;
	}

	closedir(dp);

	if (!S_ISDIR(sbuf.st_ex_mode)) {
		DEBUG(2,("parse_usershare_file: share %s path %s is not a directory.\n",
			servicename, sharepath ));
		return USERSHARE_PATH_NOT_DIRECTORY;
	}

	/* Check if sharing is restricted to owner-only. */
	/* psbuf is the stat of the usershare definition file,
	   sbuf is the stat of the target directory to be shared. */

	if (lp_usershare_owner_only()) {
		/* root can share anything. */
		if ((psbuf->st_ex_uid != 0) && (sbuf.st_ex_uid != psbuf->st_ex_uid)) {
			return USERSHARE_PATH_NOT_ALLOWED;
		}
	}

	*pp_sharepath = sharepath;
	*pp_comment = comment;
	return USERSHARE_OK;
}

/***************************************************************************
 Deal with a usershare file.
 Returns:
	>= 0 - snum
	-1 - Bad name, invalid contents.
	   - service name already existed and not a usershare, problem
	    with permissions to share directory etc.
***************************************************************************/

static int process_usershare_file(const char *dir_name, const char *file_name, int snum_template)
{
	SMB_STRUCT_STAT sbuf;
	SMB_STRUCT_STAT lsbuf;
	char *fname = NULL;
	char *sharepath = NULL;
	char *comment = NULL;
	char *cp_service_name = NULL;
	char **lines = NULL;
	int numlines = 0;
	int fd = -1;
	int iService = -1;
	TALLOC_CTX *ctx = talloc_stackframe();
	struct security_descriptor *psd = NULL;
	bool guest_ok = false;
	char *canon_name = NULL;
	bool added_service = false;
	int ret = -1;

	/* Ensure share name doesn't contain invalid characters. */
	if (!validate_net_name(file_name, INVALID_SHARENAME_CHARS, strlen(file_name))) {
		DEBUG(0,("process_usershare_file: share name %s contains "
			"invalid characters (any of %s)\n",
			file_name, INVALID_SHARENAME_CHARS ));
		goto out;
	}

	canon_name = canonicalize_servicename(ctx, file_name);
	if (!canon_name) {
		goto out;
	}

	fname = talloc_asprintf(ctx, "%s/%s", dir_name, file_name);
	if (!fname) {
		goto out;
	}

	/* Minimize the race condition by doing an lstat before we
	   open and fstat. Ensure this isn't a symlink link. */

	if (sys_lstat(fname, &lsbuf, false) != 0) {
		DEBUG(0,("process_usershare_file: stat of %s failed. %s\n",
			fname, strerror(errno) ));
		goto out;
	}

	/* This must be a regular file, not a symlink, directory or
	   other strange filetype. */
	if (!check_usershare_stat(fname, &lsbuf)) {
		goto out;
	}

	{
		TDB_DATA data;
		NTSTATUS status;

		status = dbwrap_fetch_bystring(ServiceHash, canon_name,
					       canon_name, &data);

		iService = -1;

		if (NT_STATUS_IS_OK(status) &&
		    (data.dptr != NULL) &&
		    (data.dsize == sizeof(iService))) {
			memcpy(&iService, data.dptr, sizeof(iService));
		}
	}

	if (iService != -1 &&
	    timespec_compare(&ServicePtrs[iService]->usershare_last_mod,
			     &lsbuf.st_ex_mtime) == 0) {
		/* Nothing changed - Mark valid and return. */
		DEBUG(10,("process_usershare_file: service %s not changed.\n",
			canon_name ));
		ServicePtrs[iService]->usershare = USERSHARE_VALID;
		ret = iService;
		goto out;
	}

	/* Try and open the file read only - no symlinks allowed. */
#ifdef O_NOFOLLOW
	fd = open(fname, O_RDONLY|O_NOFOLLOW, 0);
#else
	fd = open(fname, O_RDONLY, 0);
#endif

	if (fd == -1) {
		DEBUG(0,("process_usershare_file: unable to open %s. %s\n",
			fname, strerror(errno) ));
		goto out;
	}

	/* Now fstat to be *SURE* it's a regular file. */
	if (sys_fstat(fd, &sbuf, false) != 0) {
		close(fd);
		DEBUG(0,("process_usershare_file: fstat of %s failed. %s\n",
			fname, strerror(errno) ));
		goto out;
	}

	/* Is it the same dev/inode as was lstated ? */
	if (!check_same_stat(&lsbuf, &sbuf)) {
		close(fd);
		DEBUG(0,("process_usershare_file: fstat of %s is a different file from lstat. "
			"Symlink spoofing going on ?\n", fname ));
		goto out;
	}

	/* This must be a regular file, not a symlink, directory or
	   other strange filetype. */
	if (!check_usershare_stat(fname, &sbuf)) {
		close(fd);
		goto out;
	}

	lines = fd_lines_load(fd, &numlines, MAX_USERSHARE_FILE_SIZE, NULL);

	close(fd);
	if (lines == NULL) {
		DEBUG(0,("process_usershare_file: loading file %s owned by %u failed.\n",
			fname, (unsigned int)sbuf.st_ex_uid ));
		goto out;
	}

	if (parse_usershare_file(ctx, &sbuf, file_name,
			iService, lines, numlines, &sharepath,
			&comment, &cp_service_name,
			&psd, &guest_ok) != USERSHARE_OK) {
		goto out;
	}

	/* Everything ok - add the service possibly using a template. */
	if (iService < 0) {
		const struct loadparm_service *sp = &sDefault;
		if (snum_template != -1) {
			sp = ServicePtrs[snum_template];
		}

		if ((iService = add_a_service(sp, cp_service_name)) < 0) {
			DEBUG(0, ("process_usershare_file: Failed to add "
				"new service %s\n", cp_service_name));
			goto out;
		}

		added_service = true;

		/* Read only is controlled by usershare ACL below. */
		ServicePtrs[iService]->bRead_only = false;
	}

	/* Write the ACL of the new/modified share. */
	if (!set_share_security(canon_name, psd)) {
		 DEBUG(0, ("process_usershare_file: Failed to set share "
			"security for user share %s\n",
			canon_name ));
		goto out;
	}

	/* If from a template it may be marked invalid. */
	ServicePtrs[iService]->valid = true;

	/* Set the service as a valid usershare. */
	ServicePtrs[iService]->usershare = USERSHARE_VALID;

	/* Set guest access. */
	if (lp_usershare_allow_guests()) {
		ServicePtrs[iService]->bGuest_ok = guest_ok;
	}

	/* And note when it was loaded. */
	ServicePtrs[iService]->usershare_last_mod = sbuf.st_ex_mtime;
	string_set(&ServicePtrs[iService]->szPath, sharepath);
	string_set(&ServicePtrs[iService]->comment, comment);

	ret = iService;

  out:

	if (ret == -1 && iService != -1 && added_service) {
		lp_remove_service(iService);
	}

	TALLOC_FREE(lines);
	TALLOC_FREE(ctx);
	return ret;
}

/***************************************************************************
 Checks if a usershare entry has been modified since last load.
***************************************************************************/

static bool usershare_exists(int iService, struct timespec *last_mod)
{
	SMB_STRUCT_STAT lsbuf;
	const char *usersharepath = Globals.szUsersharePath;
	char *fname;

	if (asprintf(&fname, "%s/%s",
				usersharepath,
				ServicePtrs[iService]->szService) < 0) {
		return false;
	}

	if (sys_lstat(fname, &lsbuf, false) != 0) {
		SAFE_FREE(fname);
		return false;
	}

	if (!S_ISREG(lsbuf.st_ex_mode)) {
		SAFE_FREE(fname);
		return false;
	}

	SAFE_FREE(fname);
	*last_mod = lsbuf.st_ex_mtime;
	return true;
}

/***************************************************************************
 Load a usershare service by name. Returns a valid servicenumber or -1.
***************************************************************************/

int load_usershare_service(const char *servicename)
{
	SMB_STRUCT_STAT sbuf;
	const char *usersharepath = Globals.szUsersharePath;
	int max_user_shares = Globals.iUsershareMaxShares;
	int snum_template = -1;

	if (*usersharepath == 0 ||  max_user_shares == 0) {
		return -1;
	}

	if (sys_stat(usersharepath, &sbuf, false) != 0) {
		DEBUG(0,("load_usershare_service: stat of %s failed. %s\n",
			usersharepath, strerror(errno) ));
		return -1;
	}

	if (!S_ISDIR(sbuf.st_ex_mode)) {
		DEBUG(0,("load_usershare_service: %s is not a directory.\n",
			usersharepath ));
		return -1;
	}

	/*
	 * This directory must be owned by root, and have the 't' bit set.
	 * It also must not be writable by "other".
	 */

#ifdef S_ISVTX
	if (sbuf.st_ex_uid != 0 || !(sbuf.st_ex_mode & S_ISVTX) || (sbuf.st_ex_mode & S_IWOTH)) {
#else
	if (sbuf.st_ex_uid != 0 || (sbuf.st_ex_mode & S_IWOTH)) {
#endif
		DEBUG(0,("load_usershare_service: directory %s is not owned by root "
			"or does not have the sticky bit 't' set or is writable by anyone.\n",
			usersharepath ));
		return -1;
	}

	/* Ensure the template share exists if it's set. */
	if (Globals.szUsershareTemplateShare[0]) {
		/* We can't use lp_servicenumber here as we are recommending that
		   template shares have -valid=false set. */
		for (snum_template = iNumServices - 1; snum_template >= 0; snum_template--) {
			if (ServicePtrs[snum_template]->szService &&
					strequal(ServicePtrs[snum_template]->szService,
						Globals.szUsershareTemplateShare)) {
				break;
			}
		}

		if (snum_template == -1) {
			DEBUG(0,("load_usershare_service: usershare template share %s "
				"does not exist.\n",
				Globals.szUsershareTemplateShare ));
			return -1;
		}
	}

	return process_usershare_file(usersharepath, servicename, snum_template);
}

/***************************************************************************
 Load all user defined shares from the user share directory.
 We only do this if we're enumerating the share list.
 This is the function that can delete usershares that have
 been removed.
***************************************************************************/

int load_usershare_shares(struct smbd_server_connection *sconn,
			  bool (*snumused) (struct smbd_server_connection *, int))
{
	DIR *dp;
	SMB_STRUCT_STAT sbuf;
	struct dirent *de;
	int num_usershares = 0;
	int max_user_shares = Globals.iUsershareMaxShares;
	unsigned int num_dir_entries, num_bad_dir_entries, num_tmp_dir_entries;
	unsigned int allowed_bad_entries = ((2*max_user_shares)/10);
	unsigned int allowed_tmp_entries = ((2*max_user_shares)/10);
	int iService;
	int snum_template = -1;
	const char *usersharepath = Globals.szUsersharePath;
	int ret = lp_numservices();
	TALLOC_CTX *tmp_ctx;

	if (max_user_shares == 0 || *usersharepath == '\0') {
		return lp_numservices();
	}

	if (sys_stat(usersharepath, &sbuf, false) != 0) {
		DEBUG(0,("load_usershare_shares: stat of %s failed. %s\n",
			usersharepath, strerror(errno) ));
		return ret;
	}

	/*
	 * This directory must be owned by root, and have the 't' bit set.
	 * It also must not be writable by "other".
	 */

#ifdef S_ISVTX
	if (sbuf.st_ex_uid != 0 || !(sbuf.st_ex_mode & S_ISVTX) || (sbuf.st_ex_mode & S_IWOTH)) {
#else
	if (sbuf.st_ex_uid != 0 || (sbuf.st_ex_mode & S_IWOTH)) {
#endif
		DEBUG(0,("load_usershare_shares: directory %s is not owned by root "
			"or does not have the sticky bit 't' set or is writable by anyone.\n",
			usersharepath ));
		return ret;
	}

	/* Ensure the template share exists if it's set. */
	if (Globals.szUsershareTemplateShare[0]) {
		/* We can't use lp_servicenumber here as we are recommending that
		   template shares have -valid=false set. */
		for (snum_template = iNumServices - 1; snum_template >= 0; snum_template--) {
			if (ServicePtrs[snum_template]->szService &&
					strequal(ServicePtrs[snum_template]->szService,
						Globals.szUsershareTemplateShare)) {
				break;
			}
		}

		if (snum_template == -1) {
			DEBUG(0,("load_usershare_shares: usershare template share %s "
				"does not exist.\n",
				Globals.szUsershareTemplateShare ));
			return ret;
		}
	}

	/* Mark all existing usershares as pending delete. */
	for (iService = iNumServices - 1; iService >= 0; iService--) {
		if (VALID(iService) && ServicePtrs[iService]->usershare) {
			ServicePtrs[iService]->usershare = USERSHARE_PENDING_DELETE;
		}
	}

	dp = opendir(usersharepath);
	if (!dp) {
		DEBUG(0,("load_usershare_shares:: failed to open directory %s. %s\n",
			usersharepath, strerror(errno) ));
		return ret;
	}

	for (num_dir_entries = 0, num_bad_dir_entries = 0, num_tmp_dir_entries = 0;
			(de = readdir(dp));
			num_dir_entries++ ) {
		int r;
		const char *n = de->d_name;

		/* Ignore . and .. */
		if (*n == '.') {
			if ((n[1] == '\0') || (n[1] == '.' && n[2] == '\0')) {
				continue;
			}
		}

		if (n[0] == ':') {
			/* Temporary file used when creating a share. */
			num_tmp_dir_entries++;
		}

		/* Allow 20% tmp entries. */
		if (num_tmp_dir_entries > allowed_tmp_entries) {
			DEBUG(0,("load_usershare_shares: too many temp entries (%u) "
				"in directory %s\n",
				num_tmp_dir_entries, usersharepath));
			break;
		}

		r = process_usershare_file(usersharepath, n, snum_template);
		if (r == 0) {
			/* Update the services count. */
			num_usershares++;
			if (num_usershares >= max_user_shares) {
				DEBUG(0,("load_usershare_shares: max user shares reached "
					"on file %s in directory %s\n",
					n, usersharepath ));
				break;
			}
		} else if (r == -1) {
			num_bad_dir_entries++;
		}

		/* Allow 20% bad entries. */
		if (num_bad_dir_entries > allowed_bad_entries) {
			DEBUG(0,("load_usershare_shares: too many bad entries (%u) "
				"in directory %s\n",
				num_bad_dir_entries, usersharepath));
			break;
		}

		/* Allow 20% bad entries. */
		if (num_dir_entries > max_user_shares + allowed_bad_entries) {
			DEBUG(0,("load_usershare_shares: too many total entries (%u) "
			"in directory %s\n",
			num_dir_entries, usersharepath));
			break;
		}
	}

	closedir(dp);

	/* Sweep through and delete any non-refreshed usershares that are
	   not currently in use. */
	tmp_ctx = talloc_stackframe();
	for (iService = iNumServices - 1; iService >= 0; iService--) {
		if (VALID(iService) && (ServicePtrs[iService]->usershare == USERSHARE_PENDING_DELETE)) {
			char *servname;

			if (snumused && snumused(sconn, iService)) {
				continue;
			}

			servname = lp_servicename(tmp_ctx, iService);

			/* Remove from the share ACL db. */
			DEBUG(10,("load_usershare_shares: Removing deleted usershare %s\n",
				  servname ));
			delete_share_security(servname);
			free_service_byindex(iService);
		}
	}
	talloc_free(tmp_ctx);

	return lp_numservices();
}

/********************************************************
 Destroy global resources allocated in this file
********************************************************/

void gfree_loadparm(void)
{
	int i;

	free_file_list();

	/* Free resources allocated to services */

	for ( i = 0; i < iNumServices; i++ ) {
		if ( VALID(i) ) {
			free_service_byindex(i);
		}
	}

	SAFE_FREE( ServicePtrs );
	iNumServices = 0;

	/* Now release all resources allocated to global
	   parameters and the default service */

	free_global_parameters();
}


/***************************************************************************
 Allow client apps to specify that they are a client
***************************************************************************/
static void lp_set_in_client(bool b)
{
    in_client = b;
}


/***************************************************************************
 Determine if we're running in a client app
***************************************************************************/
static bool lp_is_in_client(void)
{
    return in_client;
}

/***************************************************************************
 Load the services array from the services file. Return true on success,
 false on failure.
***************************************************************************/

static bool lp_load_ex(const char *pszFname,
		       bool global_only,
		       bool save_defaults,
		       bool add_ipc,
		       bool initialize_globals,
		       bool allow_include_registry,
		       bool load_all_shares)
{
	char *n2 = NULL;
	bool bRetval;

	bRetval = false;

	DEBUG(3, ("lp_load_ex: refreshing parameters\n"));

	bInGlobalSection = true;
	bGlobalOnly = global_only;
	bAllowIncludeRegistry = allow_include_registry;

	init_globals(initialize_globals);

	free_file_list();

	if (save_defaults) {
		init_locals();
		lp_save_defaults();
	}

	if (!initialize_globals) {
		free_param_opts(&Globals.param_opt);
		apply_lp_set_cmdline();
	}

	lp_do_parameter(-1, "idmap config * : backend", Globals.szIdmapBackend);

	/* We get sections first, so have to start 'behind' to make up */
	iServiceIndex = -1;

	if (lp_config_backend_is_file()) {
		n2 = talloc_sub_basic(talloc_tos(), get_current_username(),
					current_user_info.domain,
					pszFname);
		if (!n2) {
			smb_panic("lp_load_ex: out of memory");
		}

		add_to_file_list(pszFname, n2);

		bRetval = pm_process(n2, do_section, do_parameter, NULL);
		TALLOC_FREE(n2);

		/* finish up the last section */
		DEBUG(4, ("pm_process() returned %s\n", BOOLSTR(bRetval)));
		if (bRetval) {
			if (iServiceIndex >= 0) {
				bRetval = service_ok(iServiceIndex);
			}
		}

		if (lp_config_backend_is_registry()) {
			/* config backend changed to registry in config file */
			/*
			 * We need to use this extra global variable here to
			 * survive restart: init_globals uses this as a default
			 * for ConfigBackend. Otherwise, init_globals would
			 *  send us into an endless loop here.
			 */
			config_backend = CONFIG_BACKEND_REGISTRY;
			/* start over */
			DEBUG(1, ("lp_load_ex: changing to config backend "
				  "registry\n"));
			init_globals(true);
			lp_kill_all_services();
			return lp_load_ex(pszFname, global_only, save_defaults,
					  add_ipc, initialize_globals,
					  allow_include_registry,
					  load_all_shares);
		}
	} else if (lp_config_backend_is_registry()) {
		bRetval = process_registry_globals();
	} else {
		DEBUG(0, ("Illegal config  backend given: %d\n",
			  lp_config_backend()));
		bRetval = false;
	}

	if (bRetval && lp_registry_shares()) {
		if (load_all_shares) {
			bRetval = process_registry_shares();
		} else {
			bRetval = reload_registry_shares();
		}
	}

	{
		char *serv = lp_auto_services(talloc_tos());
		lp_add_auto_services(serv);
		TALLOC_FREE(serv);
	}

	if (add_ipc) {
		/* When 'restrict anonymous = 2' guest connections to ipc$
		   are denied */
		lp_add_ipc("IPC$", (lp_restrict_anonymous() < 2));
		if ( lp_enable_asu_support() ) {
			lp_add_ipc("ADMIN$", false);
		}
	}

	set_allowed_client_auth();

	if (lp_security() == SEC_ADS && strchr(lp_passwordserver(), ':')) {
		DEBUG(1, ("WARNING: The optional ':port' in password server = %s is deprecated\n",
			  lp_passwordserver()));
	}

	bLoaded = true;

	/* Now we check bWINSsupport and set szWINSserver to 127.0.0.1 */
	/* if bWINSsupport is true and we are in the client            */
	if (lp_is_in_client() && Globals.bWINSsupport) {
		lp_do_parameter(GLOBAL_SECTION_SNUM, "wins server", "127.0.0.1");
	}

	init_iconv();

	fault_configure(smb_panic_s3);

	/*
	 * We run this check once the whole smb.conf is parsed, to
	 * force some settings for the standard way a AD DC is
	 * operated.  We may changed these as our code evolves, which
	 * is why we force these settings.
	 */
	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		lp_do_parameter(-1, "passdb backend", "samba_dsdb");

		lp_do_parameter(-1, "rpc_server:default", "external");
		lp_do_parameter(-1, "rpc_server:svcctl", "embedded");
		lp_do_parameter(-1, "rpc_server:srvsvc", "embedded");
		lp_do_parameter(-1, "rpc_server:eventlog", "embedded");
		lp_do_parameter(-1, "rpc_server:ntsvcs", "embedded");
		lp_do_parameter(-1, "rpc_server:winreg", "embedded");
		lp_do_parameter(-1, "rpc_server:spoolss", "embedded");
		lp_do_parameter(-1, "rpc_daemon:spoolssd", "embedded");
		lp_do_parameter(-1, "rpc_server:tcpip", "no");
	}

	bAllowIncludeRegistry = true;

	return (bRetval);
}

bool lp_load(const char *pszFname,
	     bool global_only,
	     bool save_defaults,
	     bool add_ipc,
	     bool initialize_globals)
{
	return lp_load_ex(pszFname,
			  global_only,
			  save_defaults,
			  add_ipc,
			  initialize_globals,
			  true,   /* allow_include_registry */
			  false); /* load_all_shares*/
}

bool lp_load_initial_only(const char *pszFname)
{
	return lp_load_ex(pszFname,
			  true,   /* global only */
			  false,  /* save_defaults */
			  false,  /* add_ipc */
			  true,   /* initialize_globals */
			  false,  /* allow_include_registry */
			  false); /* load_all_shares*/
}

/**
 * most common lp_load wrapper, loading only the globals
 */
bool lp_load_global(const char *file_name)
{
	return lp_load_ex(file_name,
			  true,   /* global_only */
			  false,  /* save_defaults */
			  false,  /* add_ipc */
			  true,   /* initialize_globals */
			  true,   /* allow_include_registry */
			  false); /* load_all_shares*/
}

/**
 * lp_load wrapper, especially for clients
 */
bool lp_load_client(const char *file_name)
{
	lp_set_in_client(true);

	return lp_load_global(file_name);
}

/**
 * lp_load wrapper, loading only globals, but intended
 * for subsequent calls, not reinitializing the globals
 * to default values
 */
bool lp_load_global_no_reinit(const char *file_name)
{
	return lp_load_ex(file_name,
			  true,   /* global_only */
			  false,  /* save_defaults */
			  false,  /* add_ipc */
			  false,  /* initialize_globals */
			  true,   /* allow_include_registry */
			  false); /* load_all_shares*/
}

/**
 * lp_load wrapper, especially for clients, no reinitialization
 */
bool lp_load_client_no_reinit(const char *file_name)
{
	lp_set_in_client(true);

	return lp_load_global_no_reinit(file_name);
}

bool lp_load_with_registry_shares(const char *pszFname,
				  bool global_only,
				  bool save_defaults,
				  bool add_ipc,
				  bool initialize_globals)
{
	return lp_load_ex(pszFname,
			  global_only,
			  save_defaults,
			  add_ipc,
			  initialize_globals,
			  true,  /* allow_include_registry */
			  true); /* load_all_shares*/
}

/***************************************************************************
 Return the max number of services.
***************************************************************************/

int lp_numservices(void)
{
	return (iNumServices);
}

/***************************************************************************
Display the contents of the services array in human-readable form.
***************************************************************************/

void lp_dump(FILE *f, bool show_defaults, int maxtoprint)
{
	int iService;

	if (show_defaults)
		defaults_saved = false;

	dump_globals(f);

	dump_a_service(&sDefault, f);

	for (iService = 0; iService < maxtoprint; iService++) {
		fprintf(f,"\n");
		lp_dump_one(f, show_defaults, iService);
	}
}

/***************************************************************************
Display the contents of one service in human-readable form.
***************************************************************************/

void lp_dump_one(FILE * f, bool show_defaults, int snum)
{
	if (VALID(snum)) {
		if (ServicePtrs[snum]->szService[0] == '\0')
			return;
		dump_a_service(ServicePtrs[snum], f);
	}
}

/***************************************************************************
Return the number of the service with the given name, or -1 if it doesn't
exist. Note that this is a DIFFERENT ANIMAL from the internal function
getservicebyname()! This works ONLY if all services have been loaded, and
does not copy the found service.
***************************************************************************/

int lp_servicenumber(const char *pszServiceName)
{
	int iService;
        fstring serviceName;

        if (!pszServiceName) {
        	return GLOBAL_SECTION_SNUM;
	}

	for (iService = iNumServices - 1; iService >= 0; iService--) {
		if (VALID(iService) && ServicePtrs[iService]->szService) {
			/*
			 * The substitution here is used to support %U is
			 * service names
			 */
			fstrcpy(serviceName, ServicePtrs[iService]->szService);
			standard_sub_basic(get_current_username(),
					   current_user_info.domain,
					   serviceName,sizeof(serviceName));
			if (strequal(serviceName, pszServiceName)) {
				break;
			}
		}
	}

	if (iService >= 0 && ServicePtrs[iService]->usershare == USERSHARE_VALID) {
		struct timespec last_mod;

		if (!usershare_exists(iService, &last_mod)) {
			/* Remove the share security tdb entry for it. */
			delete_share_security(lp_servicename(talloc_tos(), iService));
			/* Remove it from the array. */
			free_service_byindex(iService);
			/* Doesn't exist anymore. */
			return GLOBAL_SECTION_SNUM;
		}

		/* Has it been modified ? If so delete and reload. */
		if (timespec_compare(&ServicePtrs[iService]->usershare_last_mod,
				     &last_mod) < 0) {
			/* Remove it from the array. */
			free_service_byindex(iService);
			/* and now reload it. */
			iService = load_usershare_service(pszServiceName);
		}
	}

	if (iService < 0) {
		DEBUG(7,("lp_servicenumber: couldn't find %s\n", pszServiceName));
		return GLOBAL_SECTION_SNUM;
	}

	return (iService);
}

/*******************************************************************
 A useful volume label function. 
********************************************************************/

const char *volume_label(TALLOC_CTX *ctx, int snum)
{
	char *ret;
	const char *label = lp_volume(ctx, snum);
	if (!*label) {
		label = lp_servicename(ctx, snum);
	}

	/* This returns a 33 byte guarenteed null terminated string. */
	ret = talloc_strndup(ctx, label, 32);
	if (!ret) {
		return "";
	}		
	return ret;
}

/*******************************************************************
 Get the default server type we will announce as via nmbd.
********************************************************************/

int lp_default_server_announce(void)
{
	int default_server_announce = 0;
	default_server_announce |= SV_TYPE_WORKSTATION;
	default_server_announce |= SV_TYPE_SERVER;
	default_server_announce |= SV_TYPE_SERVER_UNIX;

	/* note that the flag should be set only if we have a 
	   printer service but nmbd doesn't actually load the 
	   services so we can't tell   --jerry */

	default_server_announce |= SV_TYPE_PRINTQ_SERVER;

	default_server_announce |= SV_TYPE_SERVER_NT;
	default_server_announce |= SV_TYPE_NT;

	switch (lp_server_role()) {
		case ROLE_DOMAIN_MEMBER:
			default_server_announce |= SV_TYPE_DOMAIN_MEMBER;
			break;
		case ROLE_DOMAIN_PDC:
			default_server_announce |= SV_TYPE_DOMAIN_CTRL;
			break;
		case ROLE_DOMAIN_BDC:
			default_server_announce |= SV_TYPE_DOMAIN_BAKCTRL;
			break;
		case ROLE_STANDALONE:
		default:
			break;
	}
	if (lp_time_server())
		default_server_announce |= SV_TYPE_TIME_SOURCE;

	if (lp_host_msdfs())
		default_server_announce |= SV_TYPE_DFS_SERVER;

	return default_server_announce;
}

/***********************************************************
 If we are PDC then prefer us as DMB
************************************************************/

bool lp_domain_master(void)
{
	if (Globals.domain_master == Auto)
		return (lp_server_role() == ROLE_DOMAIN_PDC);

	return (bool)Globals.domain_master;
}

/***********************************************************
 If we are PDC then prefer us as DMB
************************************************************/

static bool lp_domain_master_true_or_auto(void)
{
	if (Globals.domain_master) /* auto or yes */
		return true;

	return false;
}

/***********************************************************
 If we are DMB then prefer us as LMB
************************************************************/

bool lp_preferred_master(void)
{
	if (Globals.iPreferredMaster == Auto)
		return (lp_local_master() && lp_domain_master());

	return (bool)Globals.iPreferredMaster;
}

/*******************************************************************
 Remove a service.
********************************************************************/

void lp_remove_service(int snum)
{
	ServicePtrs[snum]->valid = false;
	invalid_services[num_invalid_services++] = snum;
}

/*******************************************************************
 Copy a service.
********************************************************************/

void lp_copy_service(int snum, const char *new_name)
{
	do_section(new_name, NULL);
	if (snum >= 0) {
		snum = lp_servicenumber(new_name);
		if (snum >= 0) {
			char *name = lp_servicename(talloc_tos(), snum);
			lp_do_parameter(snum, "copy", name);
		}
	}
}

const char *lp_printername(TALLOC_CTX *ctx, int snum)
{
	const char *ret = lp__printername(talloc_tos(), snum);
	if (ret == NULL || *ret == '\0') {
		ret = lp_const_servicename(snum);
	}

	return ret;
}


/***********************************************************
 Allow daemons such as winbindd to fix their logfile name.
************************************************************/

void lp_set_logfile(const char *name)
{
	string_set(&Globals.logfile, name);
	debug_set_logfile(name);
}

/*******************************************************************
 Return the max print jobs per queue.
********************************************************************/

int lp_maxprintjobs(int snum)
{
	int maxjobs = LP_SNUM_OK(snum) ? ServicePtrs[snum]->iMaxPrintJobs : sDefault.iMaxPrintJobs;
	if (maxjobs <= 0 || maxjobs >= PRINT_MAX_JOBID)
		maxjobs = PRINT_MAX_JOBID - 1;

	return maxjobs;
}

const char *lp_printcapname(void)
{
	if ((Globals.szPrintcapname != NULL) &&
	    (Globals.szPrintcapname[0] != '\0'))
		return Globals.szPrintcapname;

	if (sDefault.iPrinting == PRINT_CUPS) {
		return "cups";
	}

	if (sDefault.iPrinting == PRINT_BSD)
		return "/etc/printcap";

	return PRINTCAP_NAME;
}

static uint32 spoolss_state;

bool lp_disable_spoolss( void )
{
	if ( spoolss_state == SVCCTL_STATE_UNKNOWN )
		spoolss_state = lp__disable_spoolss() ? SVCCTL_STOPPED : SVCCTL_RUNNING;

	return spoolss_state == SVCCTL_STOPPED ? true : false;
}

void lp_set_spoolss_state( uint32 state )
{
	SMB_ASSERT( (state == SVCCTL_STOPPED) || (state == SVCCTL_RUNNING) );

	spoolss_state = state;
}

uint32 lp_get_spoolss_state( void )
{
	return lp_disable_spoolss() ? SVCCTL_STOPPED : SVCCTL_RUNNING;
}

/*******************************************************************
 Ensure we don't use sendfile if server smb signing is active.
********************************************************************/

bool lp_use_sendfile(int snum, struct smb_signing_state *signing_state)
{
	bool sign_active = false;

	/* Using sendfile blows the brains out of any DOS or Win9x TCP stack... JRA. */
	if (get_Protocol() < PROTOCOL_NT1) {
		return false;
	}
	if (signing_state) {
		sign_active = smb_signing_is_active(signing_state);
	}
	return (lp__use_sendfile(snum) &&
			(get_remote_arch() != RA_WIN95) &&
			!sign_active);
}

/*******************************************************************
 Turn off sendfile if we find the underlying OS doesn't support it.
********************************************************************/

void set_use_sendfile(int snum, bool val)
{
	if (LP_SNUM_OK(snum))
		ServicePtrs[snum]->bUseSendfile = val;
	else
		sDefault.bUseSendfile = val;
}

/*******************************************************************
 Turn off storing DOS attributes if this share doesn't support it.
********************************************************************/

void set_store_dos_attributes(int snum, bool val)
{
	if (!LP_SNUM_OK(snum))
		return;
	ServicePtrs[(snum)]->bStoreDosAttributes = val;
}

void lp_set_mangling_method(const char *new_method)
{
	string_set(&Globals.szManglingMethod, new_method);
}

/*******************************************************************
 Global state for POSIX pathname processing.
********************************************************************/

static bool posix_pathnames;

bool lp_posix_pathnames(void)
{
	return posix_pathnames;
}

/*******************************************************************
 Change everything needed to ensure POSIX pathname processing (currently
 not much).
********************************************************************/

void lp_set_posix_pathnames(void)
{
	posix_pathnames = true;
}

/*******************************************************************
 Global state for POSIX lock processing - CIFS unix extensions.
********************************************************************/

bool posix_default_lock_was_set;
static enum brl_flavour posix_cifsx_locktype; /* By default 0 == WINDOWS_LOCK */

enum brl_flavour lp_posix_cifsu_locktype(files_struct *fsp)
{
	if (posix_default_lock_was_set) {
		return posix_cifsx_locktype;
	} else {
		return fsp->posix_open ? POSIX_LOCK : WINDOWS_LOCK;
	}
}

/*******************************************************************
********************************************************************/

void lp_set_posix_default_cifsx_readwrite_locktype(enum brl_flavour val)
{
	posix_default_lock_was_set = true;
	posix_cifsx_locktype = val;
}

int lp_min_receive_file_size(void)
{
	if (Globals.iminreceivefile < 0) {
		return 0;
	}
	return MIN(Globals.iminreceivefile, BUFFER_SIZE);
}

/*******************************************************************
 Safe wide links checks.
 This helper function always verify the validity of wide links,
 even after a configuration file reload.
********************************************************************/

static bool lp_widelinks_internal(int snum)
{
	return (bool)(LP_SNUM_OK(snum)? ServicePtrs[(snum)]->bWidelinks :
			sDefault.bWidelinks);
}

void widelinks_warning(int snum)
{
	if (lp_allow_insecure_widelinks()) {
		return;
	}

	if (lp_unix_extensions() && lp_widelinks_internal(snum)) {
		DEBUG(0,("Share '%s' has wide links and unix extensions enabled. "
			"These parameters are incompatible. "
			"Wide links will be disabled for this share.\n",
			 lp_servicename(talloc_tos(), snum) ));
	}
}

bool lp_widelinks(int snum)
{
	/* wide links is always incompatible with unix extensions */
	if (lp_unix_extensions()) {
		/*
		 * Unless we have "allow insecure widelinks"
		 * turned on.
		 */
		if (!lp_allow_insecure_widelinks()) {
			return false;
		}
	}

	return lp_widelinks_internal(snum);
}

bool lp_writeraw(void)
{
	if (lp_async_smb_echo_handler()) {
		return false;
	}
	return lp__writeraw();
}

bool lp_readraw(void)
{
	if (lp_async_smb_echo_handler()) {
		return false;
	}
	return lp__readraw();
}

int lp_server_role(void)
{
	return lp_find_server_role(lp__server_role(),
				   lp__security(),
				   lp__domain_logons(),
				   lp_domain_master_true_or_auto());
}

int lp_security(void)
{
	return lp_find_security(lp__server_role(),
				lp__security());
}
