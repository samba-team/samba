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
#include "printing.h"
#include "lib/smbconf/smbconf.h"
#include "lib/smbconf/smbconf_init.h"
#include "lib/param/loadparm.h"

#include "ads.h"
#include "../librpc/gen_ndr/svcctl.h"
#include "intl.h"
#include "../libcli/smb/smb_signing.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "../lib/util/bitmap.h"
#include "../source4/dns_server/dns_update.h"

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

#define CONFIG_BACKEND_FILE 0
#define CONFIG_BACKEND_REGISTRY 1

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
	char *szLogLevel;						\
	int iminreceivefile;						\
	char *szPrintcapname;						\
	int CupsEncrypt;						\
	int  iPreferredMaster;						\
	int iDomainMaster;						\
	char *szLdapMachineSuffix;					\
	char *szLdapUserSuffix;						\
	char *szLdapIdmapSuffix;					\
	char *szLdapGroupSuffix;					\
	char *szStateDir;						\
	char *szCacheDir;						\
	char *szSocketAddress;						\
	char *szUsershareTemplateShare;					\
	char *szIdmapUID;						\
	char *szIdmapGID;						\
	int winbindMaxDomainConnections;				\
	int ismb2_max_credits;

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
	.printer_admin = NULL,
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
	.iSecurity_mask = 0777,
	.iSecurity_force_mode = 0,
	.iDir_mask = 0755,
	.iDir_force_mode = 0,
	.iDir_Security_mask = 0777,
	.iDir_Security_force_mode = 0,
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
	.bShareModes = true,
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
	.ismb_encrypt = Auto,
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

static void set_allowed_client_auth(void);

static void add_to_file_list(const char *fname, const char *subfname);
static bool lp_set_cmdline_helper(const char *pszParmName, const char *pszParmValue, bool store_values);
static void free_param_opts(struct parmlist_entry **popts);

#include "lib/param/param_enums.c"

static const struct enum_list enum_printing[] = {
	{PRINT_SYSV, "sysv"},
	{PRINT_AIX, "aix"},
	{PRINT_HPUX, "hpux"},
	{PRINT_BSD, "bsd"},
	{PRINT_QNX, "qnx"},
	{PRINT_PLP, "plp"},
	{PRINT_LPRNG, "lprng"},
	{PRINT_CUPS, "cups"},
	{PRINT_IPRINT, "iprint"},
	{PRINT_LPRNT, "nt"},
	{PRINT_LPROS2, "os2"},
#if defined(DEVELOPER) || defined(ENABLE_BUILD_FARM_HACKS)
	{PRINT_TEST, "test"},
	{PRINT_VLP, "vlp"},
#endif /* DEVELOPER */
	{-1, NULL}
};

static const struct enum_list enum_ldap_sasl_wrapping[] = {
	{0, "plain"},
	{ADS_AUTH_SASL_SIGN, "sign"},
	{ADS_AUTH_SASL_SEAL, "seal"},
	{-1, NULL}
};

static const struct enum_list enum_ldap_ssl[] = {
	{LDAP_SSL_OFF, "no"},
	{LDAP_SSL_OFF, "off"},
	{LDAP_SSL_START_TLS, "start tls"},
	{LDAP_SSL_START_TLS, "start_tls"},
	{-1, NULL}
};

/* LDAP Dereferencing Alias types */
#define SAMBA_LDAP_DEREF_NEVER		0
#define SAMBA_LDAP_DEREF_SEARCHING	1
#define SAMBA_LDAP_DEREF_FINDING	2
#define SAMBA_LDAP_DEREF_ALWAYS		3

static const struct enum_list enum_ldap_deref[] = {
	{SAMBA_LDAP_DEREF_NEVER, "never"},
	{SAMBA_LDAP_DEREF_SEARCHING, "searching"},
	{SAMBA_LDAP_DEREF_FINDING, "finding"},
	{SAMBA_LDAP_DEREF_ALWAYS, "always"},
	{-1, "auto"}
};

static const struct enum_list enum_ldap_passwd_sync[] = {
	{LDAP_PASSWD_SYNC_OFF, "no"},
	{LDAP_PASSWD_SYNC_OFF, "off"},
	{LDAP_PASSWD_SYNC_ON, "yes"},
	{LDAP_PASSWD_SYNC_ON, "on"},
	{LDAP_PASSWD_SYNC_ONLY, "only"},
	{-1, NULL}
};

static const struct enum_list enum_map_readonly[] = {
	{MAP_READONLY_NO, "no"},
	{MAP_READONLY_NO, "false"},
	{MAP_READONLY_NO, "0"},
	{MAP_READONLY_YES, "yes"},
	{MAP_READONLY_YES, "true"},
	{MAP_READONLY_YES, "1"},
	{MAP_READONLY_PERMISSIONS, "permissions"},
	{MAP_READONLY_PERMISSIONS, "perms"},
	{-1, NULL}
};

static const struct enum_list enum_case[] = {
	{CASE_LOWER, "lower"},
	{CASE_UPPER, "upper"},
	{-1, NULL}
};


/* ACL compatibility options. */
static const struct enum_list enum_acl_compat_vals[] = {
    { ACL_COMPAT_AUTO, "auto" },
    { ACL_COMPAT_WINNT, "winnt" },
    { ACL_COMPAT_WIN2K, "win2k" },
    { -1, NULL}
};

/* 
   Do you want session setups at user level security with a invalid
   password to be rejected or allowed in as guest? WinNT rejects them
   but it can be a pain as it means "net view" needs to use a password

   You have 3 choices in the setting of map_to_guest:

   "Never" means session setups with an invalid password
   are rejected. This is the default.

   "Bad User" means session setups with an invalid password
   are rejected, unless the username does not exist, in which case it
   is treated as a guest login

   "Bad Password" means session setups with an invalid password
   are treated as a guest login

   Note that map_to_guest only has an effect in user or server
   level security.
*/

static const struct enum_list enum_map_to_guest[] = {
	{NEVER_MAP_TO_GUEST, "Never"},
	{MAP_TO_GUEST_ON_BAD_USER, "Bad User"},
	{MAP_TO_GUEST_ON_BAD_PASSWORD, "Bad Password"},
        {MAP_TO_GUEST_ON_BAD_UID, "Bad Uid"},
	{-1, NULL}
};

/* Config backend options */

static const struct enum_list enum_config_backend[] = {
	{CONFIG_BACKEND_FILE, "file"},
	{CONFIG_BACKEND_REGISTRY, "registry"},
	{-1, NULL}
};

/* ADS kerberos ticket verification options */

static const struct enum_list enum_kerberos_method[] = {
	{KERBEROS_VERIFY_SECRETS, "default"},
	{KERBEROS_VERIFY_SECRETS, "secrets only"},
	{KERBEROS_VERIFY_SYSTEM_KEYTAB, "system keytab"},
	{KERBEROS_VERIFY_DEDICATED_KEYTAB, "dedicated keytab"},
	{KERBEROS_VERIFY_SECRETS_AND_KEYTAB, "secrets and keytab"},
	{-1, NULL}
};

/* Note: We do not initialise the defaults union - it is not allowed in ANSI C
 *
 * The FLAG_HIDE is explicit. Parameters set this way do NOT appear in any edit
 * screen in SWAT. This is used to exclude parameters as well as to squash all
 * parameters that have been duplicated by pseudonyms.
 *
 * NOTE: To display a parameter in BASIC view set FLAG_BASIC
 *       Any parameter that does NOT have FLAG_ADVANCED will not disply at all
 *	 Set FLAG_SHARE and FLAG_PRINT to specifically display parameters in
 *        respective views.
 *
 * NOTE2: Handling of duplicated (synonym) parameters:
 *	Only the first occurance of a parameter should be enabled by FLAG_BASIC
 *	and/or FLAG_ADVANCED. All duplicates following the first mention should be
 *	set to FLAG_HIDE. ie: Make you must place the parameter that has the preferred
 *	name first, and all synonyms must follow it with the FLAG_HIDE attribute.
 */

#define GLOBAL_VAR(name) offsetof(struct loadparm_global, name)
#define LOCAL_VAR(name) offsetof(struct loadparm_service, name)

static struct parm_struct parm_table[] = {
	{N_("Base Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "dos charset",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(dos_charset),
		.special	= handle_dos_charset,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED
	},
	{
		.label		= "unix charset",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(unix_charset),
		.special	= handle_charset,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED
	},
	{
		.label		= "comment",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(comment),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT
	},
	{
		.label		= "path",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPath),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "directory",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPath),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "workgroup",
		.type		= P_USTRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szWorkgroup),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "realm",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szRealm),
		.special	= handle_realm,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "netbios name",
		.type		= P_USTRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szNetbiosName),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "netbios aliases",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szNetbiosAliases),
		.special	= handle_netbios_aliases,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "netbios scope",
		.type		= P_USTRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szNetbiosScope),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "server string",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szServerString),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},
	{
		.label		= "interfaces",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szInterfaces),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "bind interfaces only",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bBindInterfacesOnly),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "config backend",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ConfigBackend),
		.special	= NULL,
		.enum_list	= enum_config_backend,
		.flags		= FLAG_HIDE|FLAG_ADVANCED|FLAG_META,
	},
	{
		.label		= "server role",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ServerRole),
		.special	= NULL,
		.enum_list	= enum_server_role,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},

	{N_("Security Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "security",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(security),
		.special	= NULL,
		.enum_list	= enum_security,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "auth methods",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(AuthMethods),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "encrypt passwords",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bEncryptPasswords),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "client schannel",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(clientSchannel),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},
	{
		.label		= "server schannel",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(serverSchannel),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},
	{
		.label		= "allow trusted domains",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bAllowTrustedDomains),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "map to guest",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(map_to_guest),
		.special	= NULL,
		.enum_list	= enum_map_to_guest,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "null passwords",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bNullPasswords),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_DEPRECATED,
	},
	{
		.label		= "obey pam restrictions",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bObeyPamRestrictions),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "password server",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPasswordServer),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "smb passwd file",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szSMBPasswdFile),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "private dir",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPrivateDir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "passdb backend",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPassdbBackend),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "algorithmic rid base",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(AlgorithmicRidBase),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "root directory",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szRootdir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "root dir",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szRootdir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "root",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szRootdir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "guest account",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szGuestaccount),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},
	{
		.label		= "enable privileges",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bEnablePrivileges),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_DEPRECATED,
	},

	{
		.label		= "pam password change",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bPamPasswordChange),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "passwd program",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPasswdProgram),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "passwd chat",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPasswdChat),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "passwd chat debug",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bPasswdChatDebug),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "passwd chat timeout",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iPasswdChatTimeout),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "check password script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szCheckPasswordScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "username map",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szUsernameMap),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "password level",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(pwordlevel),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_DEPRECATED,
	},
	{
		.label		= "username level",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(unamelevel),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "unix password sync",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bUnixPasswdSync),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "restrict anonymous",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(restrict_anonymous),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "lanman auth",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bLanmanAuth),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ntlm auth",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bNTLMAuth),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "client NTLMv2 auth",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bClientNTLMv2Auth),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "client lanman auth",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bClientLanManAuth),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "client plaintext auth",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bClientPlaintextAuth),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "client use spnego principal",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(client_use_spnego_principal),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "username",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szUsername),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE | FLAG_DEPRECATED,
	},
	{
		.label		= "user",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szUsername),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "users",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szUsername),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "invalid users",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szInvalidUsers),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "valid users",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szValidUsers),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "admin users",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szAdminUsers),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "read list",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(readlist),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "write list",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(writelist),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "printer admin",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(printer_admin),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_PRINT | FLAG_DEPRECATED,
	},
	{
		.label		= "force user",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(force_user),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "force group",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(force_group),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "group",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(force_group),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "read only",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bRead_only),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "write ok",
		.type		= P_BOOLREV,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bRead_only),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "writeable",
		.type		= P_BOOLREV,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bRead_only),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "writable",
		.type		= P_BOOLREV,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bRead_only),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "acl check permissions",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bAclCheckPermissions),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE | FLAG_DEPRECATED,
	},
	{
		.label		= "acl group control",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bAclGroupControl),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "acl map full control",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bAclMapFullControl),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "create mask",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iCreate_mask),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "create mode",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iCreate_mask),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "force create mode",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iCreate_force_mode),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "security mask",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iSecurity_mask),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "force security mode",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iSecurity_force_mode),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "directory mask",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iDir_mask),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "directory mode",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iDir_mask),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "force directory mode",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iDir_force_mode),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "directory security mask",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iDir_Security_mask),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "force directory security mode",
		.type		= P_OCTAL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iDir_Security_force_mode),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "force unknown acl user",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bForceUnknownAclUser),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "inherit permissions",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bInheritPerms),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "inherit acls",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bInheritACLS),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "inherit owner",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bInheritOwner),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "guest only",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bGuest_only),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "only guest",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bGuest_only),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "administrative share",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bAdministrative_share),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},

	{
		.label		= "guest ok",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bGuest_ok),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "public",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bGuest_ok),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "only user",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bOnlyUser),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_DEPRECATED,
	},
	{
		.label		= "hosts allow",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szHostsallow),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_GLOBAL | FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "allow hosts",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szHostsallow),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "hosts deny",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szHostsdeny),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_GLOBAL | FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "deny hosts",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szHostsdeny),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "preload modules",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPreloadModules),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "dedicated keytab file",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szDedicatedKeytabFile),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "kerberos method",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iKerberosMethod),
		.special	= NULL,
		.enum_list	= enum_kerberos_method,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "map untrusted to domain",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bMapUntrustedToDomain),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},


	{N_("Logging Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "log level",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLogLevel),
		.special	= handle_debug_list,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "debuglevel",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLogLevel),
		.special	= handle_debug_list,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "syslog",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(syslog),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "syslog only",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bSyslogOnly),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "log file",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(logfile),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "max log size",
		.type		= P_BYTES,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(max_log_size),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "debug timestamp",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bTimestampLogs),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "timestamp logs",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bTimestampLogs),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "debug prefix timestamp",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDebugPrefixTimestamp),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "debug hires timestamp",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDebugHiresTimestamp),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "debug pid",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDebugPid),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "debug uid",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDebugUid),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "debug class",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDebugClass),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "enable core files",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bEnableCoreFiles),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{N_("Protocol Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "allocation roundup size",
		.type		= P_BYTES,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iallocation_roundup_size),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "aio read size",
		.type		= P_BYTES,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iAioReadSize),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "aio write size",
		.type		= P_BYTES,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iAioWriteSize),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "aio write behind",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szAioWriteBehind),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "smb ports",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(smb_ports),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "large readwrite",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bLargeReadwrite),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "max protocol",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(srv_maxprotocol),
		.special	= NULL,
		.enum_list	= enum_protocol,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "server max protocol",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(srv_maxprotocol),
		.special	= NULL,
		.enum_list	= enum_protocol,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "protocol",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(srv_maxprotocol),
		.special	= NULL,
		.enum_list	= enum_protocol,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "min protocol",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(srv_minprotocol),
		.special	= NULL,
		.enum_list	= enum_protocol,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "server min protocol",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(srv_minprotocol),
		.special	= NULL,
		.enum_list	= enum_protocol,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "min receivefile size",
		.type		= P_BYTES,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iminreceivefile),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "read raw",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bReadRaw),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "write raw",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWriteRaw),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "disable netbios",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDisableNetbios),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "reset on zero vc",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bResetOnZeroVC),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "log writeable files on exit",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bLogWriteableFilesOnExit),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "acl compatibility",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iAclCompat),
		.special	= NULL,
		.enum_list	= enum_acl_compat_vals,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "defer sharing violations",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDeferSharingViolations),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "ea support",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bEASupport),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "nt acl support",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bNTAclSupport),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "nt pipe support",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bNTPipeSupport),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "nt status support",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bNTStatusSupport),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "profile acls",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bProfileAcls),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},
	{
		.label		= "map acl inherit",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bMap_acl_inherit),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "afs share",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bAfs_Share),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "max mux",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(max_mux),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "max xmit",
		.type		= P_BYTES,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(max_xmit),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "name resolve order",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szNameResolveOrder),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "max ttl",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(max_ttl),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "max wins ttl",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(max_wins_ttl),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "min wins ttl",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(min_wins_ttl),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "time server",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bTimeServer),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "unix extensions",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bUnixExtensions),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "use spnego",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bUseSpnego),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_DEPRECATED,
	},
	{
		.label		= "client signing",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(client_signing),
		.special	= NULL,
		.enum_list	= enum_smb_signing_vals,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "server signing",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(server_signing),
		.special	= NULL,
		.enum_list	= enum_smb_signing_vals,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "smb encrypt",
		.type		= P_ENUM,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(ismb_encrypt),
		.special	= NULL,
		.enum_list	= enum_smb_signing_vals,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "client use spnego",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bClientUseSpnego),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "client ldap sasl wrapping",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(client_ldap_sasl_wrapping),
		.special	= NULL,
		.enum_list	= enum_ldap_sasl_wrapping,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "enable asu support",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bASUSupport),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "svcctl list",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szServicesList),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{N_("Tuning Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "block size",
		.type		= P_BYTES,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iBlock_size),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "deadtime",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(deadtime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "getwd cache",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(getwd_cache),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "keepalive",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iKeepalive),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "change notify",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bChangeNotify),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "directory name cache size",
		.type		= P_INTEGER,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iDirectoryNameCacheSize),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "kernel change notify",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bKernelChangeNotify),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "lpq cache time",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(lpqcachetime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "max smbd processes",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iMaxSmbdProcesses),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "max connections",
		.type		= P_INTEGER,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iMaxConnections),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "paranoid server security",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(paranoid_server_security),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "max disk size",
		.type		= P_BYTES,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(maxdisksize),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "max open files",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(max_open_files),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "min print space",
		.type		= P_INTEGER,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iMinPrintSpace),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "socket options",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szSocketOptions),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "strict allocate",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bStrictAllocate),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "strict sync",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bStrictSync),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "sync always",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bSyncAlways),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "use mmap",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bUseMmap),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "use sendfile",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bUseSendfile),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "hostname lookups",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bHostnameLookups),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "write cache size",
		.type		= P_BYTES,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iWriteCacheSize),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "name cache timeout",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(name_cache_timeout),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ctdbd socket",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ctdbdSocket),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "cluster addresses",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szClusterAddresses),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "clustering",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(clustering),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "ctdb timeout",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ctdb_timeout),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "ctdb locktime warn threshold",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ctdb_locktime_warn_threshold),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "smb2 max read",
		.type		= P_BYTES,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ismb2_max_read),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "smb2 max write",
		.type		= P_BYTES,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ismb2_max_write),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "smb2 max trans",
		.type		= P_BYTES,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ismb2_max_trans),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "smb2 max credits",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ismb2_max_credits),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{N_("Printing Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "max reported print jobs",
		.type		= P_INTEGER,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iMaxReportedPrintJobs),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "max print jobs",
		.type		= P_INTEGER,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iMaxPrintJobs),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "load printers",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bLoadPrinters),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "printcap cache time",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(PrintcapCacheTime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "printcap name",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPrintcapname),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "printcap",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPrintcapname),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "printable",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bPrint_ok),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "print notify backchannel",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bPrintNotifyBackchannel),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "print ok",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bPrint_ok),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "printing",
		.type		= P_ENUM,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iPrinting),
		.special	= handle_printing,
		.enum_list	= enum_printing,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "cups options",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szCupsOptions),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "cups server",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szCupsServer),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label          = "cups encrypt",
		.type           = P_ENUM,
		.p_class        = P_GLOBAL,
		.offset            = GLOBAL_VAR(CupsEncrypt),
		.special        = NULL,
		.enum_list      = enum_bool_auto,
		.flags          = FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{

		.label		= "cups connection timeout",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(cups_connection_timeout),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "iprint server",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szIPrintServer),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "print command",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPrintcommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "disable spoolss",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDisableSpoolss),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "enable spoolss",
		.type		= P_BOOLREV,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDisableSpoolss),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "lpq command",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szLpqcommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "lprm command",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szLprmcommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "lppause command",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szLppausecommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "lpresume command",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szLpresumecommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "queuepause command",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szQueuepausecommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "queueresume command",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szQueueresumecommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT | FLAG_GLOBAL,
	},
	{
		.label		= "addport command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAddPortCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "enumports command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szEnumPortsCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "addprinter command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAddPrinterCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "deleteprinter command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szDeletePrinterCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "show add printer wizard",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bMsAddPrinterWizard),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "os2 driver map",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szOs2DriverMap),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{
		.label		= "printer name",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPrintername),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "printer",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPrintername),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "use client driver",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bUseClientDriver),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "default devmode",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bDefaultDevmode),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "force printername",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bForcePrintername),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},
	{
		.label		= "printjob username",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPrintjobUsername),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_PRINT,
	},

	{N_("Filename Handling"), P_SEP, P_SEPARATOR},

	{
		.label		= "mangling method",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szManglingMethod),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "mangle prefix",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(mangle_prefix),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{
		.label		= "default case",
		.type		= P_ENUM,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iDefaultCase),
		.special	= NULL,
		.enum_list	= enum_case,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "case sensitive",
		.type		= P_ENUM,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iCaseSensitive),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "casesignames",
		.type		= P_ENUM,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iCaseSensitive),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL | FLAG_HIDE,
	},
	{
		.label		= "preserve case",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bCasePreserve),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "short preserve case",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bShortCasePreserve),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "mangling char",
		.type		= P_CHAR,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(magic_char),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "hide dot files",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bHideDotFiles),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "hide special files",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bHideSpecialFiles),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "hide unreadable",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bHideUnReadable),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "hide unwriteable files",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bHideUnWriteableFiles),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "delete veto files",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bDeleteVetoFiles),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "veto files",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szVetoFiles),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "hide files",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szHideFiles),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "veto oplock files",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szVetoOplockFiles),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "map archive",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bMap_archive),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "map hidden",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bMap_hidden),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "map system",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bMap_system),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "map readonly",
		.type		= P_ENUM,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iMap_readonly),
		.special	= NULL,
		.enum_list	= enum_map_readonly,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "mangled names",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bMangledNames),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "max stat cache size",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iMaxStatCacheSize),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "stat cache",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bStatCache),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "store dos attributes",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bStoreDosAttributes),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "dmapi support",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bDmapiSupport),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},


	{N_("Domain Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "machine password timeout",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(machine_password_timeout),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_WIZARD,
	},

	{N_("Logon Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "add user script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAddUserScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "rename user script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szRenameUserScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "delete user script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szDelUserScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "add group script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAddGroupScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "delete group script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szDelGroupScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "add user to group script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAddUserToGroupScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "delete user from group script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szDelUserFromGroupScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "set primary group script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szSetPrimaryGroupScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "add machine script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAddMachineScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "shutdown script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szShutdownScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "abort shutdown script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAbortShutdownScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "username map script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szUsernameMapScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "username map cache time",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iUsernameMapCacheTime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "logon script",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLogonScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "logon path",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLogonPath),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "logon drive",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLogonDrive),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "logon home",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLogonHome),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "domain logons",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bDomainLogons),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{
		.label		= "init logon delayed hosts",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szInitLogonDelayedHosts),
		.special        = NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{
		.label		= "init logon delay",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(InitLogonDelay),
		.special        = NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,

	},

	{N_("Browse Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "os level",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(os_level),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},
	{
		.label		= "lm announce",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(lm_announce),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "lm interval",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(lm_interval),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "preferred master",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iPreferredMaster),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},
	{
		.label		= "prefered master",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iPreferredMaster),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "local master",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bLocalMaster),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},
	{
		.label		= "domain master",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iDomainMaster),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_BASIC | FLAG_ADVANCED,
	},
	{
		.label		= "browse list",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bBrowseList),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "browseable",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bBrowseable),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "browsable",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bBrowseable),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "access based share enum",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bAccessBasedShareEnum),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE
	},
	{
		.label		= "enhanced browsing",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(enhanced_browsing),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{N_("WINS Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "dns proxy",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWINSdnsProxy),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "wins proxy",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWINSproxy),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "wins server",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szWINSservers),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "wins support",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWINSsupport),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD,
	},
	{
		.label		= "wins hook",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szWINSHook),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{N_("Locking Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "blocking locks",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bBlockingLocks),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "csc policy",
		.type		= P_ENUM,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iCSCPolicy),
		.special	= NULL,
		.enum_list	= enum_csc_policy,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "fake oplocks",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bFakeOplocks),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "kernel oplocks",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bKernelOplocks),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "locking",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bLocking),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "lock spin time",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iLockSpinTime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "oplocks",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bOpLocks),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "level2 oplocks",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bLevel2OpLocks),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "oplock break wait time",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(oplock_break_wait_time),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "oplock contention limit",
		.type		= P_INTEGER,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iOplockContentionLimit),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "posix locking",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bPosixLocking),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "strict locking",
		.type		= P_ENUM,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iStrictLocking),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "share modes",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bShareModes),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL | FLAG_DEPRECATED,
	},

	{N_("Ldap Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "ldap admin dn",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLdapAdminDn),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap delete dn",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_delete_dn),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap group suffix",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLdapGroupSuffix),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap idmap suffix",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLdapIdmapSuffix),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap machine suffix",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLdapMachineSuffix),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap passwd sync",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_passwd_sync),
		.special	= NULL,
		.enum_list	= enum_ldap_passwd_sync,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap password sync",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_passwd_sync),
		.special	= NULL,
		.enum_list	= enum_ldap_passwd_sync,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "ldap replication sleep",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_replication_sleep),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap suffix",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLdapSuffix),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap ssl",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_ssl),
		.special	= NULL,
		.enum_list	= enum_ldap_ssl,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap ssl ads",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_ssl_ads),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap deref",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_deref),
		.special	= NULL,
		.enum_list	= enum_ldap_deref,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap follow referral",
		.type		= P_ENUM,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_follow_referral),
		.special	= NULL,
		.enum_list	= enum_bool_auto,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap timeout",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_timeout),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap connection timeout",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_connection_timeout),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap page size",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_page_size),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap user suffix",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLdapUserSuffix),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap debug level",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_debug_level),
		.special	= handle_ldap_debug_level,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ldap debug threshold",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ldap_debug_threshold),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{N_("EventLog Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "eventlog list",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szEventLogs),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL | FLAG_SHARE,
	},

	{N_("Miscellaneous Options"), P_SEP, P_SEPARATOR},

	{
		.label		= "add share command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAddShareCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "change share command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szChangeShareCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "delete share command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szDeleteShareCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "config file",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szConfigFile),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE|FLAG_META,
	},
	{
		.label		= "preload",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAutoServices),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "auto services",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAutoServices),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "lock directory",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLockDir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "lock dir",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLockDir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "state directory",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szStateDir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "cache directory",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szCacheDir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "pid directory",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPidDir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
#ifdef WITH_UTMP
	{
		.label		= "utmp directory",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szUtmpDir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "wtmp directory",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szWtmpDir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "utmp",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bUtmp),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
#endif
	{
		.label		= "default service",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szDefaultService),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "default",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szDefaultService),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "message command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szMsgCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "dfree cache time",
		.type		= P_INTEGER,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(iDfreeCacheTime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "dfree command",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szDfree),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "get quota command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szGetQuota),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "set quota command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szSetQuota),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "remote announce",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szRemoteAnnounce),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "remote browse sync",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szRemoteBrowseSync),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "socket address",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szSocketAddress),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "nmbd bind explicit broadcast",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bNmbdBindExplicitBroadcast),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "homedir map",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szNISHomeMapName),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "afs username map",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szAfsUsernameMap),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "afs token lifetime",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iAfsTokenLifetime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "log nt token command",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szLogNtTokenCommand),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "NIS homedir",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bNISHomeMap),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "-valid",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(valid),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "copy",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szCopy),
		.special	= handle_copy,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "include",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szInclude),
		.special	= handle_include,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE|FLAG_META,
	},
	{
		.label		= "preexec",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPreExec),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "exec",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPreExec),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "preexec close",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bPreexecClose),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "postexec",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szPostExec),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "root preexec",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szRootPreExec),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "root preexec close",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bRootpreexecClose),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "root postexec",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szRootPostExec),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "available",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bAvailable),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT,
	},
	{
		.label		= "registry shares",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bRegistryShares),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "usershare allow guests",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bUsershareAllowGuests),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "usershare max shares",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iUsershareMaxShares),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "usershare owner only",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bUsershareOwnerOnly),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "usershare path",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szUsersharePath),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "usershare prefix allow list",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szUsersharePrefixAllowList),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "usershare prefix deny list",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szUsersharePrefixDenyList),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "usershare template share",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szUsershareTemplateShare),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "volume",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(volume),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "fstype",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(fstype),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "set directory",
		.type		= P_BOOLREV,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bNo_set_dir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "allow insecure wide links",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bAllowInsecureWidelinks),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "wide links",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bWidelinks),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "follow symlinks",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bSymlinks),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "dont descend",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szDontdescend),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "magic script",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szMagicScript),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "magic output",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szMagicOutput),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "delete readonly",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bDeleteReadonly),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "dos filemode",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bDosFilemode),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "dos filetimes",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bDosFiletimes),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "dos filetime resolution",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bDosFiletimeResolution),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE | FLAG_GLOBAL,
	},
	{
		.label		= "fake directory create times",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bFakeDirCreateTimes),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "async smb echo handler",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bAsyncSMBEchoHandler),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "multicast dns register",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bMulticastDnsRegister),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_GLOBAL,
	},
	{
		.label		= "panic action",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szPanicAction),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "perfcount module",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szSMBPerfcountModule),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{N_("VFS module options"), P_SEP, P_SEPARATOR},

	{
		.label		= "vfs objects",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szVfsObjects),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "vfs object",
		.type		= P_LIST,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szVfsObjects),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},


	{N_("MSDFS options"), P_SEP, P_SEPARATOR},

	{
		.label		= "msdfs root",
		.type		= P_BOOL,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(bMSDfsRoot),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "msdfs proxy",
		.type		= P_STRING,
		.p_class	= P_LOCAL,
		.offset		= LOCAL_VAR(szMSDfsProxy),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_SHARE,
	},
	{
		.label		= "host msdfs",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bHostMSDfs),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{N_("Winbind options"), P_SEP, P_SEPARATOR},

	{
		.label		= "passdb expand explicit",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bPassdbExpandExplicit),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "idmap backend",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szIdmapBackend),
		.special	= handle_idmap_backend,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_DEPRECATED,
	},
	{
		.label		= "idmap cache time",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iIdmapCacheTime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "idmap negative cache time",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(iIdmapNegativeCacheTime),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "idmap uid",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szIdmapUID),
		.special	= handle_idmap_uid,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_DEPRECATED,
	},
	{
		.label		= "winbind uid",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szIdmapUID),
		.special	= handle_idmap_uid,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "idmap gid",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szIdmapGID),
		.special	= handle_idmap_gid,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED | FLAG_DEPRECATED,
	},
	{
		.label		= "winbind gid",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szIdmapGID),
		.special	= handle_idmap_gid,
		.enum_list	= NULL,
		.flags		= FLAG_HIDE,
	},
	{
		.label		= "template homedir",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szTemplateHomedir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "template shell",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szTemplateShell),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind separator",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szWinbindSeparator),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind cache time",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(winbind_cache_time),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind reconnect delay",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(winbind_reconnect_delay),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind max clients",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(winbind_max_clients),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind enum users",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindEnumUsers),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind enum groups",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindEnumGroups),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind use default domain",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindUseDefaultDomain),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind trusted domains only",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindTrustedDomainsOnly),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind nested groups",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindNestedGroups),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind expand groups",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(winbind_expand_groups),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind nss info",
		.type		= P_LIST,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(szWinbindNssInfo),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind refresh tickets",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindRefreshTickets),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind offline logon",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindOfflineLogon),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind normalize names",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindNormalizeNames),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind rpc only",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bWinbindRpcOnly),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "create krb5 conf",
		.type		= P_BOOL,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(bCreateKrb5Conf),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "ncalrpc dir",
		.type		= P_STRING,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(ncalrpc_dir),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},
	{
		.label		= "winbind max domain connections",
		.type		= P_INTEGER,
		.p_class	= P_GLOBAL,
		.offset		= GLOBAL_VAR(winbindMaxDomainConnections),
		.special	= NULL,
		.enum_list	= NULL,
		.flags		= FLAG_ADVANCED,
	},

	{NULL,  P_BOOL,  P_NONE,  0,  NULL,  NULL,  0}
};

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
#ifdef HAVE_CUPS
			/* set the lpq command to contain the destination printer
			   name only.  This is used by cups_queue_get() */
			string_set(&pService->szLpqcommand, "%p");
			string_set(&pService->szLprmcommand, "");
			string_set(&pService->szPrintcommand, "");
			string_set(&pService->szLppausecommand, "");
			string_set(&pService->szLpresumecommand, "");
			string_set(&pService->szQueuepausecommand, "");
			string_set(&pService->szQueueresumecommand, "");
#else
			string_set(&pService->szLpqcommand, "lpq -P'%p'");
			string_set(&pService->szLprmcommand, "lprm -P'%p' %j");
			string_set(&pService->szPrintcommand, "lpr -P'%p' %s; rm %s");
			string_set(&pService->szLppausecommand, "lp -i '%p-%j' -H hold");
			string_set(&pService->szLpresumecommand, "lp -i '%p-%j' -H resume");
			string_set(&pService->szQueuepausecommand, "disable '%p'");
			string_set(&pService->szQueueresumecommand, "enable '%p'");
#endif /* HAVE_CUPS */
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

#if defined(DEVELOPER) || defined(ENABLE_BUILD_FARM_HACKS)

	case PRINT_TEST:
	case PRINT_VLP: {
		const char *tdbfile;
		char *tmp;

		tdbfile = talloc_asprintf(
			talloc_tos(), "tdbfile=%s",
			lp_parm_const_string(-1, "vlp", "tdbfile",
					     "/tmp/vlp.tdb"));
		if (tdbfile == NULL) {
			tdbfile="tdbfile=/tmp/vlp.tdb";
		}

		tmp = talloc_asprintf(talloc_tos(), "vlp %s print %%p %%s",
				      tdbfile);
		string_set(&pService->szPrintcommand,
			   tmp ? tmp : "vlp print %p %s");
		TALLOC_FREE(tmp);

		tmp = talloc_asprintf(talloc_tos(), "vlp %s lpq %%p",
				      tdbfile);
		string_set(&pService->szLpqcommand,
			   tmp ? tmp : "vlp lpq %p");
		TALLOC_FREE(tmp);

		tmp = talloc_asprintf(talloc_tos(), "vlp %s lprm %%p %%j",
				      tdbfile);
		string_set(&pService->szLprmcommand,
			   tmp ? tmp : "vlp lprm %p %j");
		TALLOC_FREE(tmp);

		tmp = talloc_asprintf(talloc_tos(), "vlp %s lppause %%p %%j",
				      tdbfile);
		string_set(&pService->szLppausecommand,
			   tmp ? tmp : "vlp lppause %p %j");
		TALLOC_FREE(tmp);

		tmp = talloc_asprintf(talloc_tos(), "vlp %s lpresume %%p %%j",
				      tdbfile);
		string_set(&pService->szLpresumecommand,
			   tmp ? tmp : "vlp lpresume %p %j");
		TALLOC_FREE(tmp);

		tmp = talloc_asprintf(talloc_tos(), "vlp %s queuepause %%p",
				      tdbfile);
		string_set(&pService->szQueuepausecommand,
			   tmp ? tmp : "vlp queuepause %p");
		TALLOC_FREE(tmp);

		tmp = talloc_asprintf(talloc_tos(), "vlp %s queueresume %%p",
				      tdbfile);
		string_set(&pService->szQueueresumecommand,
			   tmp ? tmp : "vlp queueresume %p");
		TALLOC_FREE(tmp);

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
	string_set(&Globals.szSocketAddress, "0.0.0.0");
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

	string_set(&Globals.szSocketOptions, DEFAULT_SOCKET_OPTIONS);

	string_set(&Globals.szLogonDrive, "");
	/* %N is the NIS auto.home server if -DAUTOHOME is used, else same as %L */
	string_set(&Globals.szLogonHome, "\\\\%N\\%U");
	string_set(&Globals.szLogonPath, "\\\\%N\\%U\\profile");

	string_set(&Globals.szNameResolveOrder, "lmhosts wins host bcast");
	string_set(&Globals.szPasswordServer, "*");

	Globals.AlgorithmicRidBase = BASE_RID;

	Globals.bLoadPrinters = true;
	Globals.PrintcapCacheTime = 750; 	/* 12.5 minutes */

	Globals.ConfigBackend = config_backend;
	Globals.ServerRole = ROLE_AUTO;

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
	Globals.srv_maxprotocol = PROTOCOL_SMB2_02;
	Globals.srv_minprotocol = PROTOCOL_CORE;
	Globals.security = SEC_USER;
	Globals.paranoid_server_security = true;
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
	string_set(&Globals.szLogLevel, "0");
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
	Globals.bUnixExtensions = true;
	Globals.bResetOnZeroVC = false;
	Globals.bLogWriteableFilesOnExit = false;
	Globals.bCreateKrb5Conf = true;
	Globals.winbindMaxDomainConnections = 1;

	/* hostname lookups can be very expensive and are broken on
	   a large number of sites (tridge) */
	Globals.bHostnameLookups = false;

	string_set(&Globals.szPassdbBackend, "tdbsam");
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
	Globals.iDomainMaster = Auto;	/* depending on bDomainLogons */
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

	string_set(&Globals.ctdbdSocket, "");
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
	string_set(&Globals.smb_ports, SMB_PORTS);

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
 Convenience routine to grab string parameters into temporary memory
 and run standard_sub_basic on them. The buffers can be written to by
 callers without affecting the source string.
********************************************************************/

static char *lp_string(const char *s)
{
	char *ret;
	TALLOC_CTX *ctx = talloc_tos();

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
 char *lp_ ## fn_name(void) {return(lp_string(*(char **)(&Globals.ptr) ? *(char **)(&Globals.ptr) : ""));}
#define FN_GLOBAL_CONST_STRING(fn_name,ptr) \
 const char *lp_ ## fn_name(void) {return(*(const char **)(&Globals.ptr) ? *(const char **)(&Globals.ptr) : "");}
#define FN_GLOBAL_LIST(fn_name,ptr) \
 const char **lp_ ## fn_name(void) {return(*(const char ***)(&Globals.ptr));}
#define FN_GLOBAL_BOOL(fn_name,ptr) \
 bool lp_ ## fn_name(void) {return(*(bool *)(&Globals.ptr));}
#define FN_GLOBAL_CHAR(fn_name,ptr) \
 char lp_ ## fn_name(void) {return(*(char *)(&Globals.ptr));}
#define FN_GLOBAL_INTEGER(fn_name,ptr) \
 int lp_ ## fn_name(void) {return(*(int *)(&Globals.ptr));}

#define FN_LOCAL_STRING(fn_name,val) \
 char *lp_ ## fn_name(int i) {return(lp_string((LP_SNUM_OK(i) && ServicePtrs[(i)]->val) ? ServicePtrs[(i)]->val : sDefault.val));}
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

FN_GLOBAL_CONST_STRING(smb_ports, smb_ports)
FN_GLOBAL_CONST_STRING(dos_charset, dos_charset)
FN_GLOBAL_CONST_STRING(unix_charset, unix_charset)
FN_GLOBAL_STRING(logfile, logfile)
FN_GLOBAL_STRING(configfile, szConfigFile)
FN_GLOBAL_CONST_STRING(smb_passwd_file, szSMBPasswdFile)
FN_GLOBAL_CONST_STRING(private_dir, szPrivateDir)
FN_GLOBAL_STRING(serverstring, szServerString)
FN_GLOBAL_INTEGER(printcap_cache_time, PrintcapCacheTime)
FN_GLOBAL_STRING(addport_cmd, szAddPortCommand)
FN_GLOBAL_STRING(enumports_cmd, szEnumPortsCommand)
FN_GLOBAL_STRING(addprinter_cmd, szAddPrinterCommand)
FN_GLOBAL_STRING(deleteprinter_cmd, szDeletePrinterCommand)
FN_GLOBAL_STRING(os2_driver_map, szOs2DriverMap)
FN_GLOBAL_CONST_STRING(lockdir, szLockDir)
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
FN_GLOBAL_CONST_STRING(piddir, szPidDir)
FN_GLOBAL_STRING(mangling_method, szManglingMethod)
FN_GLOBAL_INTEGER(mangle_prefix, mangle_prefix)
FN_GLOBAL_CONST_STRING(utmpdir, szUtmpDir)
FN_GLOBAL_CONST_STRING(wtmpdir, szWtmpDir)
FN_GLOBAL_BOOL(utmp, bUtmp)
FN_GLOBAL_STRING(rootdir, szRootdir)
FN_GLOBAL_STRING(perfcount_module, szSMBPerfcountModule)
FN_GLOBAL_STRING(defaultservice, szDefaultService)
FN_GLOBAL_STRING(msg_command, szMsgCommand)
FN_GLOBAL_STRING(get_quota_command, szGetQuota)
FN_GLOBAL_STRING(set_quota_command, szSetQuota)
FN_GLOBAL_STRING(auto_services, szAutoServices)
FN_GLOBAL_STRING(passwd_program, szPasswdProgram)
FN_GLOBAL_STRING(passwd_chat, szPasswdChat)
FN_GLOBAL_CONST_STRING(passwordserver, szPasswordServer)
FN_GLOBAL_CONST_STRING(name_resolve_order, szNameResolveOrder)
FN_GLOBAL_CONST_STRING(workgroup, szWorkgroup)
FN_GLOBAL_CONST_STRING(netbios_name, szNetbiosName)
FN_GLOBAL_CONST_STRING(netbios_scope, szNetbiosScope)
FN_GLOBAL_CONST_STRING(realm, szRealmUpper)
FN_GLOBAL_CONST_STRING(dnsdomain, szDnsDomain)
FN_GLOBAL_CONST_STRING(afs_username_map, szAfsUsernameMap)
FN_GLOBAL_INTEGER(afs_token_lifetime, iAfsTokenLifetime)
FN_GLOBAL_STRING(log_nt_token_command, szLogNtTokenCommand)
FN_GLOBAL_STRING(username_map, szUsernameMap)
FN_GLOBAL_CONST_STRING(logon_script, szLogonScript)
FN_GLOBAL_CONST_STRING(logon_path, szLogonPath)
FN_GLOBAL_CONST_STRING(logon_drive, szLogonDrive)
FN_GLOBAL_CONST_STRING(logon_home, szLogonHome)
FN_GLOBAL_STRING(remote_announce, szRemoteAnnounce)
FN_GLOBAL_STRING(remote_browse_sync, szRemoteBrowseSync)
FN_GLOBAL_BOOL(nmbd_bind_explicit_broadcast, bNmbdBindExplicitBroadcast)
FN_GLOBAL_LIST(wins_server_list, szWINSservers)
FN_GLOBAL_LIST(interfaces, szInterfaces)
FN_GLOBAL_STRING(nis_home_map_name, szNISHomeMapName)
FN_GLOBAL_LIST(netbios_aliases, szNetbiosAliases)
FN_GLOBAL_CONST_STRING(passdb_backend, szPassdbBackend)
FN_GLOBAL_LIST(preload_modules, szPreloadModules)
FN_GLOBAL_STRING(panic_action, szPanicAction)
FN_GLOBAL_STRING(adduser_script, szAddUserScript)
FN_GLOBAL_STRING(renameuser_script, szRenameUserScript)
FN_GLOBAL_STRING(deluser_script, szDelUserScript)

FN_GLOBAL_CONST_STRING(guestaccount, szGuestaccount)
FN_GLOBAL_STRING(addgroup_script, szAddGroupScript)
FN_GLOBAL_STRING(delgroup_script, szDelGroupScript)
FN_GLOBAL_STRING(addusertogroup_script, szAddUserToGroupScript)
FN_GLOBAL_STRING(deluserfromgroup_script, szDelUserFromGroupScript)
FN_GLOBAL_STRING(setprimarygroup_script, szSetPrimaryGroupScript)

FN_GLOBAL_STRING(addmachine_script, szAddMachineScript)

FN_GLOBAL_STRING(shutdown_script, szShutdownScript)
FN_GLOBAL_STRING(abort_shutdown_script, szAbortShutdownScript)
FN_GLOBAL_STRING(username_map_script, szUsernameMapScript)
FN_GLOBAL_INTEGER(username_map_cache_time, iUsernameMapCacheTime)

FN_GLOBAL_STRING(check_password_script, szCheckPasswordScript)

FN_GLOBAL_STRING(wins_hook, szWINSHook)
FN_GLOBAL_CONST_STRING(template_homedir, szTemplateHomedir)
FN_GLOBAL_CONST_STRING(template_shell, szTemplateShell)
FN_GLOBAL_CONST_STRING(winbind_separator, szWinbindSeparator)
FN_GLOBAL_INTEGER(acl_compatibility, iAclCompat)
FN_GLOBAL_BOOL(winbind_enum_users, bWinbindEnumUsers)
FN_GLOBAL_BOOL(winbind_enum_groups, bWinbindEnumGroups)
FN_GLOBAL_BOOL(winbind_use_default_domain, bWinbindUseDefaultDomain)
FN_GLOBAL_BOOL(winbind_trusted_domains_only, bWinbindTrustedDomainsOnly)
FN_GLOBAL_BOOL(winbind_nested_groups, bWinbindNestedGroups)
FN_GLOBAL_INTEGER(winbind_expand_groups, winbind_expand_groups)
FN_GLOBAL_BOOL(winbind_refresh_tickets, bWinbindRefreshTickets)
FN_GLOBAL_BOOL(winbind_offline_logon, bWinbindOfflineLogon)
FN_GLOBAL_BOOL(winbind_normalize_names, bWinbindNormalizeNames)
FN_GLOBAL_BOOL(winbind_rpc_only, bWinbindRpcOnly)
FN_GLOBAL_BOOL(create_krb5_conf, bCreateKrb5Conf)
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

FN_GLOBAL_CONST_STRING(idmap_backend, szIdmapBackend)
FN_GLOBAL_INTEGER(idmap_cache_time, iIdmapCacheTime)
FN_GLOBAL_INTEGER(idmap_negative_cache_time, iIdmapNegativeCacheTime)
FN_GLOBAL_INTEGER(keepalive, iKeepalive)
FN_GLOBAL_BOOL(passdb_expand_explicit, bPassdbExpandExplicit)

FN_GLOBAL_STRING(ldap_suffix, szLdapSuffix)
FN_GLOBAL_STRING(ldap_admin_dn, szLdapAdminDn)
FN_GLOBAL_INTEGER(ldap_ssl, ldap_ssl)
FN_GLOBAL_BOOL(ldap_ssl_ads, ldap_ssl_ads)
FN_GLOBAL_INTEGER(ldap_deref, ldap_deref)
FN_GLOBAL_INTEGER(ldap_follow_referral, ldap_follow_referral)
FN_GLOBAL_INTEGER(ldap_passwd_sync, ldap_passwd_sync)
FN_GLOBAL_BOOL(ldap_delete_dn, ldap_delete_dn)
FN_GLOBAL_INTEGER(ldap_replication_sleep, ldap_replication_sleep)
FN_GLOBAL_INTEGER(ldap_timeout, ldap_timeout)
FN_GLOBAL_INTEGER(ldap_connection_timeout, ldap_connection_timeout)
FN_GLOBAL_INTEGER(ldap_page_size, ldap_page_size)
FN_GLOBAL_INTEGER(ldap_debug_level, ldap_debug_level)
FN_GLOBAL_INTEGER(ldap_debug_threshold, ldap_debug_threshold)
FN_GLOBAL_STRING(add_share_cmd, szAddShareCommand)
FN_GLOBAL_STRING(change_share_cmd, szChangeShareCommand)
FN_GLOBAL_STRING(delete_share_cmd, szDeleteShareCommand)
FN_GLOBAL_STRING(usershare_path, szUsersharePath)
FN_GLOBAL_LIST(usershare_prefix_allow_list, szUsersharePrefixAllowList)
FN_GLOBAL_LIST(usershare_prefix_deny_list, szUsersharePrefixDenyList)

FN_GLOBAL_LIST(eventlog_list, szEventLogs)

FN_GLOBAL_BOOL(registry_shares, bRegistryShares)
FN_GLOBAL_BOOL(usershare_allow_guests, bUsershareAllowGuests)
FN_GLOBAL_BOOL(usershare_owner_only, bUsershareOwnerOnly)
FN_GLOBAL_BOOL(disable_netbios, bDisableNetbios)
FN_GLOBAL_BOOL(reset_on_zero_vc, bResetOnZeroVC)
FN_GLOBAL_BOOL(log_writeable_files_on_exit, bLogWriteableFilesOnExit)
FN_GLOBAL_BOOL(ms_add_printer_wizard, bMsAddPrinterWizard)
FN_GLOBAL_BOOL(dns_proxy, bWINSdnsProxy)
FN_GLOBAL_BOOL(we_are_a_wins_server, bWINSsupport)
FN_GLOBAL_BOOL(wins_proxy, bWINSproxy)
FN_GLOBAL_BOOL(local_master, bLocalMaster)
static FN_GLOBAL_BOOL(domain_logons, bDomainLogons)
FN_GLOBAL_LIST(init_logon_delayed_hosts, szInitLogonDelayedHosts)
FN_GLOBAL_INTEGER(init_logon_delay, InitLogonDelay)
FN_GLOBAL_BOOL(load_printers, bLoadPrinters)
static FN_GLOBAL_BOOL(_readraw, bReadRaw)
FN_GLOBAL_BOOL(large_readwrite, bLargeReadwrite)
static FN_GLOBAL_BOOL(_writeraw, bWriteRaw)
FN_GLOBAL_BOOL(null_passwords, bNullPasswords)
FN_GLOBAL_BOOL(obey_pam_restrictions, bObeyPamRestrictions)
FN_GLOBAL_BOOL(encrypted_passwords, bEncryptPasswords)
FN_GLOBAL_INTEGER(client_schannel, clientSchannel)
FN_GLOBAL_INTEGER(server_schannel, serverSchannel)
FN_GLOBAL_BOOL(syslog_only, bSyslogOnly)
FN_GLOBAL_BOOL(timestamp_logs, bTimestampLogs)
FN_GLOBAL_BOOL(debug_prefix_timestamp, bDebugPrefixTimestamp)
FN_GLOBAL_BOOL(debug_hires_timestamp, bDebugHiresTimestamp)
FN_GLOBAL_BOOL(debug_pid, bDebugPid)
FN_GLOBAL_BOOL(debug_uid, bDebugUid)
FN_GLOBAL_BOOL(debug_class, bDebugClass)
FN_GLOBAL_BOOL(enable_core_files, bEnableCoreFiles)
FN_GLOBAL_BOOL(browse_list, bBrowseList)
FN_GLOBAL_BOOL(nis_home_map, bNISHomeMap)
static FN_GLOBAL_BOOL(time_server, bTimeServer)
FN_GLOBAL_BOOL(bind_interfaces_only, bBindInterfacesOnly)
FN_GLOBAL_BOOL(pam_password_change, bPamPasswordChange)
FN_GLOBAL_BOOL(unix_password_sync, bUnixPasswdSync)
FN_GLOBAL_BOOL(passwd_chat_debug, bPasswdChatDebug)
FN_GLOBAL_INTEGER(passwd_chat_timeout, iPasswdChatTimeout)
FN_GLOBAL_BOOL(nt_pipe_support, bNTPipeSupport)
FN_GLOBAL_BOOL(nt_status_support, bNTStatusSupport)
FN_GLOBAL_BOOL(stat_cache, bStatCache)
FN_GLOBAL_INTEGER(max_stat_cache_size, iMaxStatCacheSize)
FN_GLOBAL_BOOL(allow_trusted_domains, bAllowTrustedDomains)
FN_GLOBAL_BOOL(map_untrusted_to_domain, bMapUntrustedToDomain)
FN_GLOBAL_INTEGER(restrict_anonymous, restrict_anonymous)
FN_GLOBAL_BOOL(lanman_auth, bLanmanAuth)
FN_GLOBAL_BOOL(ntlm_auth, bNTLMAuth)
FN_GLOBAL_BOOL(client_plaintext_auth, bClientPlaintextAuth)
FN_GLOBAL_BOOL(client_lanman_auth, bClientLanManAuth)
FN_GLOBAL_BOOL(client_ntlmv2_auth, bClientNTLMv2Auth)
FN_GLOBAL_BOOL(host_msdfs, bHostMSDfs)
FN_GLOBAL_BOOL(enhanced_browsing, enhanced_browsing)
FN_GLOBAL_BOOL(use_mmap, bUseMmap)
FN_GLOBAL_BOOL(unix_extensions, bUnixExtensions)
FN_GLOBAL_BOOL(use_spnego, bUseSpnego)
FN_GLOBAL_BOOL(client_use_spnego, bClientUseSpnego)
FN_GLOBAL_BOOL(client_use_spnego_principal, client_use_spnego_principal)
FN_GLOBAL_BOOL(hostname_lookups, bHostnameLookups)
FN_GLOBAL_CONST_STRING(dedicated_keytab_file, szDedicatedKeytabFile)
FN_GLOBAL_INTEGER(kerberos_method, iKerberosMethod)
FN_GLOBAL_BOOL(defer_sharing_violations, bDeferSharingViolations)
FN_GLOBAL_BOOL(enable_privileges, bEnablePrivileges)
FN_GLOBAL_BOOL(enable_asu_support, bASUSupport)
FN_GLOBAL_INTEGER(os_level, os_level)
FN_GLOBAL_INTEGER(max_ttl, max_ttl)
FN_GLOBAL_INTEGER(max_wins_ttl, max_wins_ttl)
FN_GLOBAL_INTEGER(min_wins_ttl, min_wins_ttl)
FN_GLOBAL_INTEGER(max_log_size, max_log_size)
FN_GLOBAL_INTEGER(max_open_files, max_open_files)
FN_GLOBAL_INTEGER(open_files_db_hash_size, open_files_db_hash_size)
FN_GLOBAL_INTEGER(maxxmit, max_xmit)
FN_GLOBAL_INTEGER(maxmux, max_mux)
FN_GLOBAL_INTEGER(passwordlevel, pwordlevel)
FN_GLOBAL_INTEGER(usernamelevel, unamelevel)
FN_GLOBAL_INTEGER(deadtime, deadtime)
FN_GLOBAL_BOOL(getwd_cache, getwd_cache)
FN_GLOBAL_INTEGER(srv_maxprotocol, srv_maxprotocol)
FN_GLOBAL_INTEGER(srv_minprotocol, srv_minprotocol)
FN_GLOBAL_INTEGER(security, security)
FN_GLOBAL_LIST(auth_methods, AuthMethods)
FN_GLOBAL_BOOL(paranoid_server_security, paranoid_server_security)
FN_GLOBAL_INTEGER(maxdisksize, maxdisksize)
FN_GLOBAL_INTEGER(lpqcachetime, lpqcachetime)
FN_GLOBAL_INTEGER(max_smbd_processes, iMaxSmbdProcesses)
FN_GLOBAL_BOOL(_disable_spoolss, bDisableSpoolss)
FN_GLOBAL_INTEGER(syslog, syslog)
FN_GLOBAL_INTEGER(lm_announce, lm_announce)
FN_GLOBAL_INTEGER(lm_interval, lm_interval)
FN_GLOBAL_INTEGER(machine_password_timeout, machine_password_timeout)
FN_GLOBAL_INTEGER(map_to_guest, map_to_guest)
FN_GLOBAL_INTEGER(oplock_break_wait_time, oplock_break_wait_time)
FN_GLOBAL_INTEGER(lock_spin_time, iLockSpinTime)
FN_GLOBAL_INTEGER(usershare_max_shares, iUsershareMaxShares)
FN_GLOBAL_CONST_STRING(socket_options, szSocketOptions)
FN_GLOBAL_INTEGER(config_backend, ConfigBackend)
static FN_GLOBAL_INTEGER(_server_role, ServerRole)
FN_GLOBAL_INTEGER(smb2_max_read, ismb2_max_read)
FN_GLOBAL_INTEGER(smb2_max_write, ismb2_max_write)
FN_GLOBAL_INTEGER(smb2_max_trans, ismb2_max_trans)
int lp_smb2_max_credits(void)
{
	if (Globals.ismb2_max_credits == 0) {
		Globals.ismb2_max_credits = DEFAULT_SMB2_MAX_CREDITS;
	}
	return Globals.ismb2_max_credits;
}
FN_GLOBAL_LIST(svcctl_list, szServicesList)
FN_GLOBAL_STRING(cups_server, szCupsServer)
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
FN_GLOBAL_STRING(iprint_server, szIPrintServer)
FN_GLOBAL_INTEGER(cups_connection_timeout, cups_connection_timeout)
static FN_GLOBAL_CONST_STRING(_ctdbd_socket, ctdbdSocket)
FN_GLOBAL_LIST(cluster_addresses, szClusterAddresses)
FN_GLOBAL_BOOL(clustering, clustering)
FN_GLOBAL_INTEGER(ctdb_timeout, ctdb_timeout)
FN_GLOBAL_INTEGER(ctdb_locktime_warn_threshold, ctdb_locktime_warn_threshold)
FN_GLOBAL_BOOL(async_smb_echo_handler, bAsyncSMBEchoHandler)
FN_GLOBAL_BOOL(multicast_dns_register, bMulticastDnsRegister)
FN_GLOBAL_BOOL(allow_insecure_widelinks, bAllowInsecureWidelinks)
FN_GLOBAL_INTEGER(winbind_cache_time, winbind_cache_time)
FN_GLOBAL_INTEGER(winbind_reconnect_delay, winbind_reconnect_delay)
FN_GLOBAL_INTEGER(winbind_max_clients, winbind_max_clients)
FN_GLOBAL_LIST(winbind_nss_info, szWinbindNssInfo)
FN_GLOBAL_INTEGER(algorithmic_rid_base, AlgorithmicRidBase)
FN_GLOBAL_INTEGER(name_cache_timeout, name_cache_timeout)
FN_GLOBAL_INTEGER(client_signing, client_signing)
FN_GLOBAL_INTEGER(server_signing, server_signing)
FN_GLOBAL_INTEGER(client_ldap_sasl_wrapping, client_ldap_sasl_wrapping)

FN_GLOBAL_CONST_STRING(ncalrpc_dir, ncalrpc_dir)

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
/* the returned value is talloced on the talloc_tos() */
char *lp_parm_talloc_string(int snum, const char *type, const char *option, const char *def)
{
	struct parmlist_entry *data = get_parametrics(snum, type, option);

	if (data == NULL||data->value==NULL) {
		if (def) {
			return lp_string(def);
		} else {
			return NULL;
		}
	}

	return lp_string(data->value);
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

	if (popts == NULL) {
		return;
	}

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
		ServicePtrs[iNumServices] = SMB_MALLOC_P(struct loadparm_service);
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

	strlower_m(result);
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
	    || strequal(ServicePtrs[iDefaultService]->szPath, lp_pathname(GLOBAL_SECTION_SNUM))) {
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
	/* No share modes on printer services. */
	ServicePtrs[i]->bShareModes = false;
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

	if (opt_list == NULL) {
		return;
	}

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
	char *realm = strupper_talloc(talloc_tos(), pszParmValue);
	char *dnsdomain = strlower_talloc(talloc_tos(), pszParmValue);

	ret &= string_set(&Globals.szRealm, pszParmValue);
	ret &= string_set(&Globals.szRealmUpper, realm);
	ret &= string_set(&Globals.szDnsDomain, dnsdomain);
	TALLOC_FREE(realm);
	TALLOC_FREE(dnsdomain);

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

static const char *append_ldap_suffix( const char *str )
{
	const char *suffix_string;


	suffix_string = talloc_asprintf(talloc_tos(), "%s,%s", str,
					Globals.szLdapSuffix );
	if ( !suffix_string ) {
		DEBUG(0,("append_ldap_suffix: talloc_asprintf() failed!\n"));
		return "";
	}

	return suffix_string;
}

const char *lp_ldap_machine_suffix(void)
{
	if (Globals.szLdapMachineSuffix[0])
		return append_ldap_suffix(Globals.szLdapMachineSuffix);

	return lp_string(Globals.szLdapSuffix);
}

const char *lp_ldap_user_suffix(void)
{
	if (Globals.szLdapUserSuffix[0])
		return append_ldap_suffix(Globals.szLdapUserSuffix);

	return lp_string(Globals.szLdapSuffix);
}

const char *lp_ldap_group_suffix(void)
{
	if (Globals.szLdapGroupSuffix[0])
		return append_ldap_suffix(Globals.szLdapGroupSuffix);

	return lp_string(Globals.szLdapSuffix);
}

const char *lp_ldap_idmap_suffix(void)
{
	if (Globals.szLdapIdmapSuffix[0])
		return append_ldap_suffix(Globals.szLdapIdmapSuffix);

	return lp_string(Globals.szLdapSuffix);
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
 Initialize any local varients in the sDefault table.
***************************************************************************/

void init_locals(void)
{
	/* None as yet. */
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
	if (lsbuf.st_ex_dev != sbuf.st_ex_dev || lsbuf.st_ex_ino != sbuf.st_ex_ino) {
		close(fd);
		DEBUG(0,("process_usershare_file: fstat of %s is a different file from lstat. "
			"Symlink spoofing going on ?\n", fname ));
		goto out;
	}

	/* This must be a regular file, not a symlink, directory or
	   other strange filetype. */
	if (!check_usershare_stat(fname, &sbuf)) {
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
	for (iService = iNumServices - 1; iService >= 0; iService--) {
		if (VALID(iService) && (ServicePtrs[iService]->usershare == USERSHARE_PENDING_DELETE)) {
			if (snumused && snumused(sconn, iService)) {
				continue;
			}
			/* Remove from the share ACL db. */
			DEBUG(10,("load_usershare_shares: Removing deleted usershare %s\n",
				lp_servicename(iService) ));
			delete_share_security(lp_servicename(iService));
			free_service_byindex(iService);
		}
	}

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

	lp_add_auto_services(lp_auto_services());

	if (add_ipc) {
		/* When 'restrict anonymous = 2' guest connections to ipc$
		   are denied */
		lp_add_ipc("IPC$", (lp_restrict_anonymous() < 2));
		if ( lp_enable_asu_support() ) {
			lp_add_ipc("ADMIN$", false);
		}
	}

	set_allowed_client_auth();

	if (lp_security() == SEC_SERVER) {
		DEBUG(1, ("WARNING: The security=server option is deprecated\n"));
	}

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
			delete_share_security(lp_servicename(iService));
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

const char *volume_label(int snum)
{
	char *ret;
	const char *label = lp_volume(snum);
	if (!*label) {
		label = lp_servicename(snum);
	}

	/* This returns a 33 byte guarenteed null terminated string. */
	ret = talloc_strndup(talloc_tos(), label, 32);
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
	if (Globals.iDomainMaster == Auto)
		return (lp_server_role() == ROLE_DOMAIN_PDC);

	return (bool)Globals.iDomainMaster;
}

/***********************************************************
 If we are PDC then prefer us as DMB
************************************************************/

static bool lp_domain_master_true_or_auto(void)
{
	if (Globals.iDomainMaster) /* auto or yes */
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
		if (snum >= 0)
			lp_do_parameter(snum, "copy", lp_servicename(snum));
	}
}


/***********************************************************
 Set the global name resolution order (used in smbclient).
************************************************************/

void lp_set_name_resolve_order(const char *new_order)
{
	string_set(&Globals.szNameResolveOrder, new_order);
}

const char *lp_printername(int snum)
{
	const char *ret = lp__printername(snum);
	if (ret == NULL || (ret != NULL && *ret == '\0'))
		ret = lp_const_servicename(snum);

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
#ifdef HAVE_CUPS
		return "cups";
#else
		return "lpstat";
#endif
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
 If socket address is an empty character string, it is necessary to 
 define it as "0.0.0.0". 
********************************************************************/

const char *lp_socket_address(void)
{
	char *sock_addr = Globals.szSocketAddress;

	if (sock_addr[0] == '\0'){
		string_set(&Globals.szSocketAddress, "0.0.0.0");
	}
	return  Globals.szSocketAddress;
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
			lp_servicename(snum) ));
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
				   lp_security(),
				   lp_domain_logons(),
				   lp_domain_master_true_or_auto());
}

const char *lp_ctdbd_socket(void)
{
	const char *result = lp__ctdbd_socket();

#ifdef CLUSTER_SUPPORT
	if ((result == NULL) || (*result == '\0')) {
		return CTDB_PATH;
	}
#endif
	return result;
}
