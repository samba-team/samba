/* 
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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

BOOL in_client = False;		/* Not in the client by default */
static BOOL bLoaded = False;

#ifndef GLOBAL_NAME
#define GLOBAL_NAME "global"
#endif

#ifndef PRINTERS_NAME
#define PRINTERS_NAME "printers"
#endif

#ifndef HOMES_NAME
#define HOMES_NAME "homes"
#endif

/* some helpful bits */
#define LP_SNUM_OK(i) (((i) >= 0) && ((i) < iNumServices) && ServicePtrs[(i)]->valid)
#define VALID(i) ServicePtrs[i]->valid

static BOOL do_parameter(const char *, const char *);

static BOOL defaults_saved = False;

struct param_opt {
	struct param_opt *prev, *next;
	char *key;
	char *value;
	int flags;
};

/* 
 * This structure describes global (ie., server-wide) parameters.
 */
typedef struct
{
	char **smb_ports;
	char *dos_charset;
	char *unix_charset;
	char *display_charset;
	char *szPrintcapname;
	char *szLockDir;
	char *szPidDir;
	char *szRootdir;
	char *szDefaultService;
	char *szHostsEquiv;
	char *szServerString;
	char *szAutoServices;
	char *szPasswdProgram;
	char *szPasswdChat;
	char *szLogFile;
	char *szConfigFile;
	char *szSMBPasswdFile;
	char *szSAM_URL;
	char *szSPOOLSS_URL;
	char *szPrivateDir;
	char **szPassdbBackend;
	char **szPreloadModules;
	char *szPasswordServer;
	char *szSocketOptions;
	char *szRealm;
	char *szADSserver;
	char *szLogonScript;
	char *szLogonPath;
	char *szLogonDrive;
	char *szLogonHome;
	char **szWINSservers;
	char **szInterfaces;
	char *szRemoteAnnounce;
	char *szRemoteBrowseSync;
	char *szSocketAddress;
	char *szAnnounceVersion;	/* This is initialised in init_globals */
	char *szWorkgroup;
	char *szNetbiosName;
	char **szNetbiosAliases;
	char *szNetbiosScope;
	char *szDomainOtherSIDs;
	char *szNameResolveOrder;
	char *szPanicAction;
	char *szAddUserScript; 
	char *szAddMachineScript;
	char *szWINSHook;
	char *szWINSPartners;
	char **dcerpc_ep_servers;
	char **server_services;
	char *szWinbindUID;
	char *szWinbindGID;
	char *szNonUnixAccountRange;
	char *szTemplateHomedir;
	char *szTemplateShell;
	char *szWinbindSeparator;
	BOOL bWinbindEnumUsers;
	BOOL bWinbindEnumGroups;
	BOOL bWinbindUseDefaultDomain;
	char *szIDMapBackend;
	char *szGuestaccount;
	int mangled_stack;
	int max_mux;
	int max_xmit;
	int pwordlevel;
	int unamelevel;
	int maxprotocol;
	int minprotocol;
	int security;
	char **AuthMethods;
	BOOL paranoid_server_security;
	int lpqcachetime;
	BOOL bDisableSpoolss;
	int os_level;
	int enhanced_browsing;
	int time_offset;
	int max_ttl;
	int max_wins_ttl;
	int min_wins_ttl;
	int lm_announce;
	int lm_interval;
	int announce_as;	/* This is initialised in init_globals */
	int machine_password_timeout;
	int winbind_cache_time;
	int iLockSpinCount;
	int iLockSpinTime;
	char *szLdapMachineSuffix;
	char *szLdapUserSuffix;
#ifdef WITH_LDAP_SAMCONFIG
	int ldap_port;
	char *szLdapServer;
#endif
	char *socket_options;
	int ldap_ssl;
	char *szLdapSuffix;
	char *szLdapFilter;
	char *szLdapAdminDn;
	BOOL ldap_trust_ids;
	int ldap_passwd_sync; 
	BOOL bDNSproxy;
	BOOL bWINSsupport;
	BOOL bWINSproxy;
	BOOL bLocalMaster;
	BOOL bPreferredMaster;
	BOOL bDomainMaster;
	BOOL bDomainLogons;
	BOOL bEncryptPasswords;
	BOOL bUpdateEncrypt;
	BOOL bNullPasswords;
	BOOL bObeyPamRestrictions;
	BOOL bLoadPrinters;
	BOOL bLargeReadwrite;
	BOOL bReadRaw;
	BOOL bWriteRaw;
	BOOL bTimeServer;
	BOOL bBindInterfacesOnly;
	BOOL bPamPasswordChange;
	BOOL bUnixPasswdSync;
	BOOL bNTSmbSupport;
	BOOL bNTStatusSupport;
	BOOL bAllowTrustedDomains;
	BOOL bLanmanAuth;
	BOOL bNTLMAuth;
	BOOL bUseSpnego;
	BOOL server_signing;
	BOOL client_signing;
	BOOL bClientLanManAuth;
	BOOL bClientNTLMv2Auth;
	BOOL bHostMSDfs;
	BOOL bHideLocalUsers;
	BOOL bUnicode;
	BOOL bUseMmap;
	BOOL bHostnameLookups;
	BOOL bUnixExtensions;
	BOOL bDisableNetbios;
	BOOL bRpcBigEndian;
	int restrict_anonymous;
	int name_cache_timeout;
	struct param_opt *param_opt;
}
global;

static global Globals;

/* 
 * This structure describes a single service. 
 */
typedef struct
{
	BOOL valid;
	BOOL autoloaded;
	char *szService;
	char *szPath;
	char *szUsername;
	char **szInvalidUsers;
	char **szValidUsers;
	char **szAdminUsers;
	char *szCopy;
	char *szInclude;
	char *szPrintcommand;
	char *szLpqcommand;
	char *szLprmcommand;
	char *szLppausecommand;
	char *szLpresumecommand;
	char *szQueuepausecommand;
	char *szQueueresumecommand;
	char *szPrintername;
	char **szHostsallow;
	char **szHostsdeny;
	char *comment;
	char *volume;
	char *fstype;
	char *szMSDfsProxy;
	char *ntvfs_handler;
	int iMinPrintSpace;
	int iMaxPrintJobs;
	int iMaxConnections;
	int iPrinting;
	int iCSCPolicy;
	BOOL bAvailable;
	BOOL bBrowseable;
	BOOL bRead_only;
	BOOL bPrint_ok;
	BOOL bMap_system;
	BOOL bMap_hidden;
	BOOL bMap_archive;
	BOOL bLocking;
	BOOL bStrictLocking;
	BOOL bPosixLocking;
	BOOL bOpLocks;
	BOOL bLevel2OpLocks;
	BOOL bOnlyUser;
	BOOL bGuest_only;
	BOOL bGuest_ok;
	BOOL *copymap;
	BOOL bMSDfsRoot;
	BOOL bShareModes;
	struct param_opt *param_opt;

	char dummy[3];		/* for alignment */
}
service;


/* This is a default service used to prime a services structure */
static service sDefault = {
	True,			/* valid */
	False,			/* not autoloaded */
	NULL,			/* szService */
	NULL,			/* szPath */
	NULL,			/* szUsername */
	NULL,			/* szInvalidUsers */
	NULL,			/* szValidUsers */
	NULL,			/* szAdminUsers */
	NULL,			/* szCopy */
	NULL,			/* szInclude */
	NULL,			/* szPrintcommand */
	NULL,			/* szLpqcommand */
	NULL,			/* szLprmcommand */
	NULL,			/* szLppausecommand */
	NULL,			/* szLpresumecommand */
	NULL,			/* szQueuepausecommand */
	NULL,			/* szQueueresumecommand */
	NULL,			/* szPrintername */
	NULL,			/* szHostsallow */
	NULL,			/* szHostsdeny */
	NULL,			/* comment */
	NULL,			/* volume */
	NULL,			/* fstype */
	NULL,                   /* szMSDfsProxy */
	NULL,                   /* ntvfs_handler */
	0,			/* iMinPrintSpace */
	1000,			/* iMaxPrintJobs */
	0,			/* iMaxConnections */
	DEFAULT_PRINTING,	/* iPrinting */
	0,			/* iCSCPolicy */
	True,			/* bAvailable */
	True,			/* bBrowseable */
	True,			/* bRead_only */
	False,			/* bPrint_ok */
	False,			/* bMap_system */
	False,			/* bMap_hidden */
	True,			/* bMap_archive */
	True,			/* bLocking */
	True,			/* bStrictLocking */
	True,			/* bPosixLocking */
	True,			/* bOpLocks */
	True,			/* bLevel2OpLocks */
	False,			/* bOnlyUser */
	False,			/* bGuest_only */
	False,			/* bGuest_ok */
	NULL,			/* copymap */
	False,			/* bMSDfsRoot */
	True,			/* bShareModes */
	NULL,			/* Parametric options */

	""			/* dummy */
};

/* local variables */
static service **ServicePtrs = NULL;
static int iNumServices = 0;
static int iServiceIndex = 0;
static BOOL bInGlobalSection = True;
static BOOL bGlobalOnly = False;
static int server_role;
static int default_server_announce;

#define NUMPARAMETERS (sizeof(parm_table) / sizeof(struct parm_struct))

/* prototypes for the special type handlers */
static BOOL handle_include(const char *pszParmValue, char **ptr);
static BOOL handle_copy(const char *pszParmValue, char **ptr);
static BOOL handle_winbind_uid(const char *pszParmValue, char **ptr);
static BOOL handle_winbind_gid(const char *pszParmValue, char **ptr);
static BOOL handle_non_unix_account_range(const char *pszParmValue, char **ptr);

static BOOL handle_ldap_machine_suffix ( const char *pszParmValue, char **ptr );
static BOOL handle_ldap_user_suffix ( const char *pszParmValue, char **ptr );
static BOOL handle_ldap_suffix ( const char *pszParmValue, char **ptr );

static void set_server_role(void);
static void set_default_server_announce_type(void);

static const struct enum_list enum_protocol[] = {
	{PROTOCOL_NT1, "NT1"},
	{PROTOCOL_LANMAN2, "LANMAN2"},
	{PROTOCOL_LANMAN1, "LANMAN1"},
	{PROTOCOL_CORE, "CORE"},
	{PROTOCOL_COREPLUS, "COREPLUS"},
	{PROTOCOL_COREPLUS, "CORE+"},
	{-1, NULL}
};

static const struct enum_list enum_security[] = {
	{SEC_SHARE, "SHARE"},
	{SEC_USER, "USER"},
	{SEC_SERVER, "SERVER"},
	{SEC_DOMAIN, "DOMAIN"},
#ifdef HAVE_ADS
	{SEC_ADS, "ADS"},
#endif
	{-1, NULL}
};

static const struct enum_list enum_printing[] = {
	{PRINT_SYSV, "sysv"},
	{PRINT_AIX, "aix"},
	{PRINT_HPUX, "hpux"},
	{PRINT_BSD, "bsd"},
	{PRINT_QNX, "qnx"},
	{PRINT_PLP, "plp"},
	{PRINT_LPRNG, "lprng"},
	{PRINT_SOFTQ, "softq"},
	{PRINT_CUPS, "cups"},
	{PRINT_LPRNT, "nt"},
	{PRINT_LPROS2, "os2"},
#ifdef DEVELOPER
	{PRINT_TEST, "test"},
	{PRINT_VLP, "vlp"},
#endif /* DEVELOPER */
	{-1, NULL}
};

static const struct enum_list enum_ldap_ssl[] = {
#ifdef WITH_LDAP_SAMCONFIG
	{LDAP_SSL_ON, "Yes"},
	{LDAP_SSL_ON, "yes"},
	{LDAP_SSL_ON, "on"},
	{LDAP_SSL_ON, "On"},
#endif
	{LDAP_SSL_OFF, "no"},
	{LDAP_SSL_OFF, "No"},
	{LDAP_SSL_OFF, "off"},
	{LDAP_SSL_OFF, "Off"},
	{LDAP_SSL_START_TLS, "start tls"},
	{LDAP_SSL_START_TLS, "Start_tls"},
	{-1, NULL}
};

static const struct enum_list enum_ldap_passwd_sync[] = {
	{LDAP_PASSWD_SYNC_ON, "Yes"},
	{LDAP_PASSWD_SYNC_ON, "yes"},
	{LDAP_PASSWD_SYNC_ON, "on"},
	{LDAP_PASSWD_SYNC_ON, "On"},
	{LDAP_PASSWD_SYNC_OFF, "no"},
	{LDAP_PASSWD_SYNC_OFF, "No"},
	{LDAP_PASSWD_SYNC_OFF, "off"},
	{LDAP_PASSWD_SYNC_OFF, "Off"},
#ifdef LDAP_EXOP_X_MODIFY_PASSWD	
	{LDAP_PASSWD_SYNC_ONLY, "Only"},
	{LDAP_PASSWD_SYNC_ONLY, "only"},
#endif /* LDAP_EXOP_X_MODIFY_PASSWD */	
	{-1, NULL}
};

/* Types of machine we can announce as. */
#define ANNOUNCE_AS_NT_SERVER 1
#define ANNOUNCE_AS_WIN95 2
#define ANNOUNCE_AS_WFW 3
#define ANNOUNCE_AS_NT_WORKSTATION 4

static const struct enum_list enum_announce_as[] = {
	{ANNOUNCE_AS_NT_SERVER, "NT"},
	{ANNOUNCE_AS_NT_SERVER, "NT Server"},
	{ANNOUNCE_AS_NT_WORKSTATION, "NT Workstation"},
	{ANNOUNCE_AS_WIN95, "win95"},
	{ANNOUNCE_AS_WFW, "WfW"},
	{-1, NULL}
};

static const struct enum_list enum_case[] = {
	{CASE_LOWER, "lower"},
	{CASE_UPPER, "upper"},
	{-1, NULL}
};

static const struct enum_list enum_bool_auto[] = {
	{False, "No"},
	{False, "False"},
	{False, "0"},
	{True, "Yes"},
	{True, "True"},
	{True, "1"},
	{Auto, "Auto"},
	{-1, NULL}
};

/* Client-side offline caching policy types */
#define CSC_POLICY_MANUAL 0
#define CSC_POLICY_DOCUMENTS 1
#define CSC_POLICY_PROGRAMS 2
#define CSC_POLICY_DISABLE 3

static const struct enum_list enum_csc_policy[] = {
	{CSC_POLICY_MANUAL, "manual"},
	{CSC_POLICY_DOCUMENTS, "documents"},
	{CSC_POLICY_PROGRAMS, "programs"},
	{CSC_POLICY_DISABLE, "disable"},
	{-1, NULL}
};

/* SMB signing types. */
static const struct enum_list enum_smb_signing_vals[] = {
	{SMB_SIGNING_OFF, "No"},
	{SMB_SIGNING_OFF, "False"},
	{SMB_SIGNING_OFF, "0"},
	{SMB_SIGNING_OFF, "Off"},
	{SMB_SIGNING_OFF, "disabled"},
	{SMB_SIGNING_SUPPORTED, "Yes"},
	{SMB_SIGNING_SUPPORTED, "True"},
	{SMB_SIGNING_SUPPORTED, "1"},
	{SMB_SIGNING_SUPPORTED, "On"},
	{SMB_SIGNING_SUPPORTED, "enabled"},
	{SMB_SIGNING_SUPPORTED, "auto"},
	{SMB_SIGNING_REQUIRED, "required"},
	{SMB_SIGNING_REQUIRED, "mandatory"},
	{SMB_SIGNING_REQUIRED, "force"},
	{SMB_SIGNING_REQUIRED, "forced"},
	{SMB_SIGNING_REQUIRED, "enforced"},
	{-1, NULL}
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
	{-1, NULL}
};

/* Note: We do not initialise the defaults union - it is not allowed in ANSI C
 *
 * Note: We have a flag called FLAG_DEVELOPER but is not used at this time, it
 * is implied in current control logic. This may change at some later time. A
 * flag value of 0 means - show as development option only.
 *
 * The FLAG_HIDE is explicit. Paramters set this way do NOT appear in any edit
 * screen in SWAT. This is used to exclude parameters as well as to squash all
 * parameters that have been duplicated by pseudonyms.
 */
static struct parm_struct parm_table[] = {
	{"Base Options", P_SEP, P_SEPARATOR},

	{"dos charset", P_STRING, P_GLOBAL, &Globals.dos_charset, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"unix charset", P_STRING, P_GLOBAL, &Globals.unix_charset, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"display charset", P_STRING, P_GLOBAL, &Globals.display_charset, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"comment", P_STRING, P_LOCAL, &sDefault.comment, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"path", P_STRING, P_LOCAL, &sDefault.szPath, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"directory", P_STRING, P_LOCAL, &sDefault.szPath, NULL, NULL, FLAG_HIDE},
	{"workgroup", P_USTRING, P_GLOBAL, &Globals.szWorkgroup, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"realm", P_USTRING, P_GLOBAL, &Globals.szRealm, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"ADS server", P_STRING, P_GLOBAL, &Globals.szADSserver, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"netbios name", P_USTRING, P_GLOBAL, &Globals.szNetbiosName, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"netbios aliases", P_LIST, P_GLOBAL, &Globals.szNetbiosAliases, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"netbios scope", P_USTRING, P_GLOBAL, &Globals.szNetbiosScope, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"server string", P_STRING, P_GLOBAL, &Globals.szServerString, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED  | FLAG_DEVELOPER},
	{"interfaces", P_LIST, P_GLOBAL, &Globals.szInterfaces, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"bind interfaces only", P_BOOL, P_GLOBAL, &Globals.bBindInterfacesOnly, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"ntvfs handler", P_STRING, P_LOCAL, &sDefault.ntvfs_handler, NULL, NULL, FLAG_ADVANCED},
	{"dcerpc endpoint servers", P_LIST, P_GLOBAL, &Globals.dcerpc_ep_servers, NULL, NULL, FLAG_ADVANCED},
	{"server services", P_LIST, P_GLOBAL, &Globals.server_services, NULL, NULL, FLAG_ADVANCED},

	{"Security Options", P_SEP, P_SEPARATOR},
	
	{"security", P_ENUM, P_GLOBAL, &Globals.security, NULL, enum_security, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"auth methods", P_LIST, P_GLOBAL, &Globals.AuthMethods, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"encrypt passwords", P_BOOL, P_GLOBAL, &Globals.bEncryptPasswords, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"update encrypted", P_BOOL, P_GLOBAL, &Globals.bUpdateEncrypt, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_DEVELOPER},
	{"allow trusted domains", P_BOOL, P_GLOBAL, &Globals.bAllowTrustedDomains, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"hosts equiv", P_STRING, P_GLOBAL, &Globals.szHostsEquiv, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"idmap backend", P_STRING, P_GLOBAL, &Globals.szIDMapBackend, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"null passwords", P_BOOL, P_GLOBAL, &Globals.bNullPasswords, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"obey pam restrictions", P_BOOL, P_GLOBAL, &Globals.bObeyPamRestrictions, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"password server", P_STRING, P_GLOBAL, &Globals.szPasswordServer, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"smb passwd file", P_STRING, P_GLOBAL, &Globals.szSMBPasswdFile, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"sam database", P_STRING, P_GLOBAL, &Globals.szSAM_URL, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"spoolss database", P_STRING, P_GLOBAL, &Globals.szSPOOLSS_URL, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"private dir", P_STRING, P_GLOBAL, &Globals.szPrivateDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"passdb backend", P_LIST, P_GLOBAL, &Globals.szPassdbBackend, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"non unix account range", P_STRING, P_GLOBAL, &Globals.szNonUnixAccountRange, handle_non_unix_account_range, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"root directory", P_STRING, P_GLOBAL, &Globals.szRootdir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"root dir", P_STRING, P_GLOBAL, &Globals.szRootdir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"root", P_STRING, P_GLOBAL, &Globals.szRootdir, NULL, NULL, FLAG_HIDE | FLAG_DEVELOPER},
	{"guest account", P_STRING, P_GLOBAL, &Globals.szGuestaccount, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"pam password change", P_BOOL, P_GLOBAL, &Globals.bPamPasswordChange, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"passwd program", P_STRING, P_GLOBAL, &Globals.szPasswdProgram, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"passwd chat", P_STRING, P_GLOBAL, &Globals.szPasswdChat, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"password level", P_INTEGER, P_GLOBAL, &Globals.pwordlevel, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"username level", P_INTEGER, P_GLOBAL, &Globals.unamelevel, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"unix password sync", P_BOOL, P_GLOBAL, &Globals.bUnixPasswdSync, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"restrict anonymous", P_INTEGER, P_GLOBAL, &Globals.restrict_anonymous, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"lanman auth", P_BOOL, P_GLOBAL, &Globals.bLanmanAuth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ntlm auth", P_BOOL, P_GLOBAL, &Globals.bNTLMAuth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"client NTLMv2 auth", P_BOOL, P_GLOBAL, &Globals.bClientNTLMv2Auth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"client lanman auth", P_BOOL, P_GLOBAL, &Globals.bClientLanManAuth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"username", P_STRING, P_LOCAL, &sDefault.szUsername, NULL, NULL, FLAG_GLOBAL | FLAG_SHARE},
	{"user", P_STRING, P_LOCAL, &sDefault.szUsername, NULL, NULL, FLAG_HIDE},
	{"users", P_STRING, P_LOCAL, &sDefault.szUsername, NULL, NULL, FLAG_HIDE},
	
	{"invalid users", P_LIST, P_LOCAL, &sDefault.szInvalidUsers, NULL, NULL, FLAG_GLOBAL | FLAG_SHARE},
	{"valid users", P_LIST, P_LOCAL, &sDefault.szValidUsers, NULL, NULL, FLAG_GLOBAL | FLAG_SHARE},
	{"admin users", P_LIST, P_LOCAL, &sDefault.szAdminUsers, NULL, NULL, FLAG_GLOBAL | FLAG_SHARE},
	
	{"read only", P_BOOL, P_LOCAL, &sDefault.bRead_only, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE},

	{"guest only", P_BOOL, P_LOCAL, &sDefault.bGuest_only, NULL, NULL, FLAG_SHARE},

	{"guest ok", P_BOOL, P_LOCAL, &sDefault.bGuest_ok, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},

	{"only user", P_BOOL, P_LOCAL, &sDefault.bOnlyUser, NULL, NULL, FLAG_SHARE},
	{"hosts allow", P_LIST, P_LOCAL, &sDefault.szHostsallow, NULL, NULL, FLAG_GLOBAL | FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"hosts deny", P_LIST, P_LOCAL, &sDefault.szHostsdeny, NULL, NULL, FLAG_GLOBAL | FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"preload modules", P_LIST, P_GLOBAL, &Globals.szPreloadModules, NULL, NULL, FLAG_BASIC | FLAG_GLOBAL},

	{"Logging Options", P_SEP, P_SEPARATOR},

	{"log level", P_INTEGER, P_GLOBAL, &DEBUGLEVEL, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"debuglevel", P_INTEGER, P_GLOBAL, &DEBUGLEVEL, NULL, NULL, FLAG_HIDE},
	{"log file", P_STRING, P_GLOBAL, &Globals.szLogFile, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"Protocol Options", P_SEP, P_SEPARATOR},
	
	{"smb ports", P_LIST, P_GLOBAL, &Globals.smb_ports, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"large readwrite", P_BOOL, P_GLOBAL, &Globals.bLargeReadwrite, NULL, NULL, FLAG_DEVELOPER},
	{"max protocol", P_ENUM, P_GLOBAL, &Globals.maxprotocol, NULL, enum_protocol, FLAG_DEVELOPER},
	{"min protocol", P_ENUM, P_GLOBAL, &Globals.minprotocol, NULL, enum_protocol, FLAG_DEVELOPER},
	{"unicode", P_BOOL, P_GLOBAL, &Globals.bUnicode, NULL, NULL, FLAG_DEVELOPER},
	{"read raw", P_BOOL, P_GLOBAL, &Globals.bReadRaw, NULL, NULL, FLAG_DEVELOPER},
	{"write raw", P_BOOL, P_GLOBAL, &Globals.bWriteRaw, NULL, NULL, FLAG_DEVELOPER},
	{"disable netbios", P_BOOL, P_GLOBAL, &Globals.bDisableNetbios, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"nt status support", P_BOOL, P_GLOBAL, &Globals.bNTStatusSupport, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"announce version", P_STRING, P_GLOBAL, &Globals.szAnnounceVersion, NULL, NULL, FLAG_DEVELOPER},
	{"announce as", P_ENUM, P_GLOBAL, &Globals.announce_as, NULL, enum_announce_as, FLAG_DEVELOPER},
	{"max mux", P_INTEGER, P_GLOBAL, &Globals.max_mux, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"max xmit", P_INTEGER, P_GLOBAL, &Globals.max_xmit, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"name resolve order", P_STRING, P_GLOBAL, &Globals.szNameResolveOrder, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"max ttl", P_INTEGER, P_GLOBAL, &Globals.max_ttl, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER}, 
	{"max wins ttl", P_INTEGER, P_GLOBAL, &Globals.max_wins_ttl, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"min wins ttl", P_INTEGER, P_GLOBAL, &Globals.min_wins_ttl, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"time server", P_BOOL, P_GLOBAL, &Globals.bTimeServer, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"unix extensions", P_BOOL, P_GLOBAL, &Globals.bUnixExtensions, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"use spnego", P_BOOL, P_GLOBAL, &Globals.bUseSpnego, NULL, NULL, FLAG_DEVELOPER},
	{"server signing", P_ENUM, P_GLOBAL, &Globals.server_signing, NULL, enum_smb_signing_vals, FLAG_ADVANCED}, 
	{"client signing", P_ENUM, P_GLOBAL, &Globals.client_signing, NULL, enum_smb_signing_vals, FLAG_ADVANCED}, 
	{"rpc big endian", P_BOOL, P_GLOBAL, &Globals.bRpcBigEndian, NULL, NULL, FLAG_DEVELOPER},

	{"Tuning Options", P_SEP, P_SEPARATOR},
		
	{"lpq cache time", P_INTEGER, P_GLOBAL, &Globals.lpqcachetime, NULL, NULL, FLAG_DEVELOPER},
	{"max connections", P_INTEGER, P_LOCAL, &sDefault.iMaxConnections, NULL, NULL, FLAG_SHARE},
	{"paranoid server security", P_BOOL, P_GLOBAL, &Globals.paranoid_server_security, NULL, NULL, FLAG_DEVELOPER},
	{"min print space", P_INTEGER, P_LOCAL, &sDefault.iMinPrintSpace, NULL, NULL, FLAG_PRINT},
	
	{"socket options", P_STRING, P_GLOBAL, &Globals.socket_options, NULL, NULL, FLAG_DEVELOPER},
	{"use mmap", P_BOOL, P_GLOBAL, &Globals.bUseMmap, NULL, NULL, FLAG_DEVELOPER},
	{"hostname lookups", P_BOOL, P_GLOBAL, &Globals.bHostnameLookups, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"name cache timeout", P_INTEGER, P_GLOBAL, &Globals.name_cache_timeout, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"Printing Options", P_SEP, P_SEPARATOR},
	
	{"max print jobs", P_INTEGER, P_LOCAL, &sDefault.iMaxPrintJobs, NULL, NULL, FLAG_PRINT},
	{"load printers", P_BOOL, P_GLOBAL, &Globals.bLoadPrinters, NULL, NULL, FLAG_PRINT},
	{"printcap name", P_STRING, P_GLOBAL, &Globals.szPrintcapname, NULL, NULL, FLAG_PRINT | FLAG_DEVELOPER},
	{"printcap", P_STRING, P_GLOBAL, &Globals.szPrintcapname, NULL, NULL, FLAG_HIDE},
	{"printable", P_BOOL, P_LOCAL, &sDefault.bPrint_ok, NULL, NULL, FLAG_PRINT},
	{"print ok", P_BOOL, P_LOCAL, &sDefault.bPrint_ok, NULL, NULL, FLAG_HIDE},
	{"printing", P_ENUM, P_LOCAL, &sDefault.iPrinting, NULL, enum_printing, FLAG_PRINT | FLAG_GLOBAL},
	{"print command", P_STRING, P_LOCAL, &sDefault.szPrintcommand, NULL, NULL, FLAG_PRINT | FLAG_GLOBAL},
	{"disable spoolss", P_BOOL, P_GLOBAL, &Globals.bDisableSpoolss, NULL, NULL, FLAG_PRINT | FLAG_GLOBAL},
	{"lpq command", P_STRING, P_LOCAL, &sDefault.szLpqcommand, NULL, NULL, FLAG_PRINT | FLAG_GLOBAL},
	{"lprm command", P_STRING, P_LOCAL, &sDefault.szLprmcommand, NULL, NULL, FLAG_PRINT | FLAG_GLOBAL},
	{"lppause command", P_STRING, P_LOCAL, &sDefault.szLppausecommand, NULL, NULL, FLAG_PRINT | FLAG_GLOBAL},
	{"lpresume command", P_STRING, P_LOCAL, &sDefault.szLpresumecommand, NULL, NULL, FLAG_PRINT | FLAG_GLOBAL},
	{"queuepause command", P_STRING, P_LOCAL, &sDefault.szQueuepausecommand, NULL, NULL, FLAG_PRINT | FLAG_GLOBAL},
	{"queueresume command", P_STRING, P_LOCAL, &sDefault.szQueueresumecommand, NULL, NULL, FLAG_PRINT | FLAG_GLOBAL},
	
	{"printer name", P_STRING, P_LOCAL, &sDefault.szPrintername, NULL, NULL, FLAG_PRINT},
	{"printer", P_STRING, P_LOCAL, &sDefault.szPrintername, NULL, NULL, FLAG_HIDE},

	{"Filename Handling", P_SEP, P_SEPARATOR},
	
	{"mangled stack", P_INTEGER, P_GLOBAL, &Globals.mangled_stack, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"map system", P_BOOL, P_LOCAL, &sDefault.bMap_system, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"map hidden", P_BOOL, P_LOCAL, &sDefault.bMap_hidden, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"map archive", P_BOOL, P_LOCAL, &sDefault.bMap_archive, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},

	{"Domain Options", P_SEP, P_SEPARATOR},
	
	{"machine password timeout", P_INTEGER, P_GLOBAL, &Globals.machine_password_timeout, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},

	{"Logon Options", P_SEP, P_SEPARATOR},

	{"add user script", P_STRING, P_GLOBAL, &Globals.szAddUserScript, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"add machine script", P_STRING, P_GLOBAL, &Globals.szAddMachineScript, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"logon script", P_STRING, P_GLOBAL, &Globals.szLogonScript, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"logon path", P_STRING, P_GLOBAL, &Globals.szLogonPath, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"logon drive", P_STRING, P_GLOBAL, &Globals.szLogonDrive, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"logon home", P_STRING, P_GLOBAL, &Globals.szLogonHome, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"domain logons", P_BOOL, P_GLOBAL, &Globals.bDomainLogons, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"Browse Options", P_SEP, P_SEPARATOR},
	
	{"os level", P_INTEGER, P_GLOBAL, &Globals.os_level, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_DEVELOPER},
	{"lm announce", P_ENUM, P_GLOBAL, &Globals.lm_announce, NULL, enum_bool_auto, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"lm interval", P_INTEGER, P_GLOBAL, &Globals.lm_interval, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"preferred master", P_ENUM, P_GLOBAL, &Globals.bPreferredMaster, NULL, enum_bool_auto, FLAG_BASIC | FLAG_ADVANCED | FLAG_DEVELOPER},
	{"prefered master", P_ENUM, P_GLOBAL, &Globals.bPreferredMaster, NULL, enum_bool_auto, FLAG_HIDE},
	{"local master", P_BOOL, P_GLOBAL, &Globals.bLocalMaster, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_DEVELOPER},
	{"domain master", P_ENUM, P_GLOBAL, &Globals.bDomainMaster, NULL, enum_bool_auto, FLAG_BASIC | FLAG_ADVANCED | FLAG_DEVELOPER},
	{"browseable", P_BOOL, P_LOCAL, &sDefault.bBrowseable, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"browsable", P_BOOL, P_LOCAL, &sDefault.bBrowseable, NULL, NULL, FLAG_HIDE},
	{"enhanced browsing", P_BOOL, P_GLOBAL, &Globals.enhanced_browsing, NULL, NULL, FLAG_DEVELOPER | FLAG_ADVANCED},

	{"WINS Options", P_SEP, P_SEPARATOR},
	{"dns proxy", P_BOOL, P_GLOBAL, &Globals.bDNSproxy, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"wins proxy", P_BOOL, P_GLOBAL, &Globals.bWINSproxy, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"wins server", P_LIST, P_GLOBAL, &Globals.szWINSservers, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"wins support", P_BOOL, P_GLOBAL, &Globals.bWINSsupport, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"wins hook", P_STRING, P_GLOBAL, &Globals.szWINSHook, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"wins partners", P_STRING, P_GLOBAL, &Globals.szWINSPartners, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},

	{"Locking Options", P_SEP, P_SEPARATOR},
	
	{"csc policy", P_ENUM, P_LOCAL, &sDefault.iCSCPolicy, NULL, enum_csc_policy, FLAG_SHARE | FLAG_GLOBAL},
	{"locking", P_BOOL, P_LOCAL, &sDefault.bLocking, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"lock spin count", P_INTEGER, P_GLOBAL, &Globals.iLockSpinCount, NULL, NULL, FLAG_GLOBAL},
	{"lock spin time", P_INTEGER, P_GLOBAL, &Globals.iLockSpinTime, NULL, NULL, FLAG_GLOBAL},
	
	{"oplocks", P_BOOL, P_LOCAL, &sDefault.bOpLocks, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"level2 oplocks", P_BOOL, P_LOCAL, &sDefault.bLevel2OpLocks, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"posix locking", P_BOOL, P_LOCAL, &sDefault.bPosixLocking, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"strict locking", P_BOOL, P_LOCAL, &sDefault.bStrictLocking, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"share modes", P_BOOL, P_LOCAL,  &sDefault.bShareModes, NULL, NULL, FLAG_SHARE|FLAG_GLOBAL},

	{"Ldap Options", P_SEP, P_SEPARATOR},
	
#ifdef WITH_LDAP_SAMCONFIG
	{"ldap server", P_STRING, P_GLOBAL, &Globals.szLdapServer, NULL, NULL, 0},
	{"ldap port", P_INTEGER, P_GLOBAL, &Globals.ldap_port, NULL, NULL, 0}, 
#endif
	{"ldap suffix", P_STRING, P_GLOBAL, &Globals.szLdapSuffix, handle_ldap_suffix, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ldap machine suffix", P_STRING, P_GLOBAL, &Globals.szLdapMachineSuffix, handle_ldap_machine_suffix, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ldap user suffix", P_STRING, P_GLOBAL, &Globals.szLdapUserSuffix, handle_ldap_user_suffix, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ldap filter", P_STRING, P_GLOBAL, &Globals.szLdapFilter, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ldap admin dn", P_STRING, P_GLOBAL, &Globals.szLdapAdminDn, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ldap ssl", P_ENUM, P_GLOBAL, &Globals.ldap_ssl, NULL, enum_ldap_ssl, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ldap passwd sync", P_ENUM, P_GLOBAL, &Globals.ldap_passwd_sync, NULL, enum_ldap_passwd_sync, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ldap trust ids", P_BOOL, P_GLOBAL, &Globals.ldap_trust_ids, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"Miscellaneous Options", P_SEP, P_SEPARATOR},
	
	{"config file", P_STRING, P_GLOBAL, &Globals.szConfigFile, NULL, NULL, FLAG_HIDE},
	{"preload", P_STRING, P_GLOBAL, &Globals.szAutoServices, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"auto services", P_STRING, P_GLOBAL, &Globals.szAutoServices, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"lock dir", P_STRING, P_GLOBAL, &Globals.szLockDir, NULL, NULL, FLAG_HIDE}, 
	{"lock directory", P_STRING, P_GLOBAL, &Globals.szLockDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"pid directory", P_STRING, P_GLOBAL, &Globals.szPidDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER}, 
	
	{"default service", P_STRING, P_GLOBAL, &Globals.szDefaultService, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"default", P_STRING, P_GLOBAL, &Globals.szDefaultService, NULL, NULL,  FLAG_DEVELOPER},
	{"remote announce", P_STRING, P_GLOBAL, &Globals.szRemoteAnnounce, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"remote browse sync", P_STRING, P_GLOBAL, &Globals.szRemoteBrowseSync, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"socket address", P_STRING, P_GLOBAL, &Globals.szSocketAddress, NULL, NULL, FLAG_DEVELOPER},
	{"time offset", P_INTEGER, P_GLOBAL, &Globals.time_offset, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"-valid", P_BOOL, P_LOCAL, &sDefault.valid, NULL, NULL, FLAG_HIDE},
	
	{"copy", P_STRING, P_LOCAL, &sDefault.szCopy, handle_copy, NULL, FLAG_HIDE},
	{"include", P_STRING, P_LOCAL, &sDefault.szInclude, handle_include, NULL, FLAG_HIDE},
	
	{"available", P_BOOL, P_LOCAL, &sDefault.bAvailable, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT},
	{"volume", P_STRING, P_LOCAL, &sDefault.volume, NULL, NULL, FLAG_SHARE },
	{"fstype", P_STRING, P_LOCAL, &sDefault.fstype, NULL, NULL, FLAG_SHARE},

	{"panic action", P_STRING, P_GLOBAL, &Globals.szPanicAction, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"hide local users", P_BOOL, P_GLOBAL, &Globals.bHideLocalUsers, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"msdfs root", P_BOOL, P_LOCAL, &sDefault.bMSDfsRoot, NULL, NULL, FLAG_SHARE},
	{"msdfs proxy", P_STRING, P_LOCAL, &sDefault.szMSDfsProxy, NULL, NULL, FLAG_SHARE},
	{"host msdfs", P_BOOL, P_GLOBAL, &Globals.bHostMSDfs, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"Winbind options", P_SEP, P_SEPARATOR},

	{"winbind uid", P_STRING, P_GLOBAL, &Globals.szWinbindUID, handle_winbind_uid, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"winbind gid", P_STRING, P_GLOBAL, &Globals.szWinbindGID, handle_winbind_gid, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"template homedir", P_STRING, P_GLOBAL, &Globals.szTemplateHomedir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"template shell", P_STRING, P_GLOBAL, &Globals.szTemplateShell, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"winbind separator", P_STRING, P_GLOBAL, &Globals.szWinbindSeparator, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"winbind cache time", P_INTEGER, P_GLOBAL, &Globals.winbind_cache_time, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"winbind enum users", P_BOOL, P_GLOBAL, &Globals.bWinbindEnumUsers, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"winbind enum groups", P_BOOL, P_GLOBAL, &Globals.bWinbindEnumGroups, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"winbind use default domain", P_BOOL, P_GLOBAL, &Globals.bWinbindUseDefaultDomain, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{NULL, P_BOOL, P_NONE, NULL, NULL, NULL, 0}
};

/***************************************************************************
 Initialise the sDefault parameter structure for the printer values.
***************************************************************************/

static void init_printer_values(void)
{
	/* choose defaults depending on the type of printing */
	switch (sDefault.iPrinting) {
		case PRINT_BSD:
		case PRINT_AIX:
		case PRINT_LPRNT:
		case PRINT_LPROS2:
			string_set(&sDefault.szLpqcommand, "lpq -P'%p'");
			string_set(&sDefault.szLprmcommand, "lprm -P'%p' %j");
			string_set(&sDefault.szPrintcommand,
				   "lpr -r -P'%p' %s");
			break;

		case PRINT_LPRNG:
		case PRINT_PLP:
			string_set(&sDefault.szLpqcommand, "lpq -P'%p'");
			string_set(&sDefault.szLprmcommand, "lprm -P'%p' %j");
			string_set(&sDefault.szPrintcommand,
				   "lpr -r -P'%p' %s");
			string_set(&sDefault.szQueuepausecommand,
				   "lpc stop '%p'");
			string_set(&sDefault.szQueueresumecommand,
				   "lpc start '%p'");
			string_set(&sDefault.szLppausecommand,
				   "lpc hold '%p' %j");
			string_set(&sDefault.szLpresumecommand,
				   "lpc release '%p' %j");
			break;

		case PRINT_CUPS:
#ifdef HAVE_CUPS
			string_set(&sDefault.szLpqcommand, "");
			string_set(&sDefault.szLprmcommand, "");
			string_set(&sDefault.szPrintcommand, "");
			string_set(&sDefault.szLppausecommand, "");
			string_set(&sDefault.szLpresumecommand, "");
			string_set(&sDefault.szQueuepausecommand, "");
			string_set(&sDefault.szQueueresumecommand, "");

	                string_set(&Globals.szPrintcapname, "cups");
#else
			string_set(&sDefault.szLpqcommand,
			           "/usr/bin/lpstat -o '%p'");
			string_set(&sDefault.szLprmcommand,
			           "/usr/bin/cancel '%p-%j'");
			string_set(&sDefault.szPrintcommand,
			           "/usr/bin/lp -d '%p' %s; rm %s");
			string_set(&sDefault.szLppausecommand,
				   "lp -i '%p-%j' -H hold");
			string_set(&sDefault.szLpresumecommand,
				   "lp -i '%p-%j' -H resume");
			string_set(&sDefault.szQueuepausecommand,
			           "/usr/bin/disable '%p'");
			string_set(&sDefault.szQueueresumecommand,
			           "/usr/bin/enable '%p'");
			string_set(&Globals.szPrintcapname, "lpstat");
#endif /* HAVE_CUPS */
			break;

		case PRINT_SYSV:
		case PRINT_HPUX:
			string_set(&sDefault.szLpqcommand, "lpstat -o%p");
			string_set(&sDefault.szLprmcommand, "cancel %p-%j");
			string_set(&sDefault.szPrintcommand,
				   "lp -c -d%p %s; rm %s");
			string_set(&sDefault.szQueuepausecommand,
				   "disable %p");
			string_set(&sDefault.szQueueresumecommand,
				   "enable %p");
#ifndef HPUX
			string_set(&sDefault.szLppausecommand,
				   "lp -i %p-%j -H hold");
			string_set(&sDefault.szLpresumecommand,
				   "lp -i %p-%j -H resume");
#endif /* HPUX */
			break;

		case PRINT_QNX:
			string_set(&sDefault.szLpqcommand, "lpq -P%p");
			string_set(&sDefault.szLprmcommand, "lprm -P%p %j");
			string_set(&sDefault.szPrintcommand, "lp -r -P%p %s");
			break;

		case PRINT_SOFTQ:
			string_set(&sDefault.szLpqcommand, "qstat -l -d%p");
			string_set(&sDefault.szLprmcommand,
				   "qstat -s -j%j -c");
			string_set(&sDefault.szPrintcommand,
				   "lp -d%p -s %s; rm %s");
			string_set(&sDefault.szLppausecommand,
				   "qstat -s -j%j -h");
			string_set(&sDefault.szLpresumecommand,
				   "qstat -s -j%j -r");
			break;
#ifdef DEVELOPER
	case PRINT_TEST:
	case PRINT_VLP:
		string_set(&sDefault.szPrintcommand, "vlp print %p %s");
		string_set(&sDefault.szLpqcommand, "vlp lpq %p");
		string_set(&sDefault.szLprmcommand, "vlp lprm %p %j");
		string_set(&sDefault.szLppausecommand, "vlp lppause %p %j");
		string_set(&sDefault.szLpresumecommand, "vlp lpresum %p %j");
		string_set(&sDefault.szQueuepausecommand, "vlp queuepause %p");
		string_set(&sDefault.szQueueresumecommand, "vlp queueresume %p");
		break;
#endif /* DEVELOPER */

	}
}


/***************************************************************************
 Initialise the global parameter structure.
***************************************************************************/
static void init_globals(void)
{
	pstring s;
	int i;

	DEBUG(3, ("Initialising global parameters\n"));

	for (i = 0; parm_table[i].label; i++) {
		if ((parm_table[i].type == P_STRING ||
		     parm_table[i].type == P_USTRING) &&
		    parm_table[i].ptr &&
		    !(parm_table[i].flags & FLAG_CMDLINE)) {
			string_set(parm_table[i].ptr, "");
		}
	}

	/* options that can be set on the command line must be initialised via
	   the slower do_parameter() to ensure that FLAG_CMDLINE is obeyed */
	do_parameter("socket options", DEFAULT_SOCKET_OPTIONS);
	do_parameter("workgroup", DEFAULT_WORKGROUP);
	do_parameter("netbios name", get_myname());
	do_parameter("max protocol", "NT1");
	do_parameter("name resolve order", "lmhosts wins host bcast");

	init_printer_values();

	string_set(&sDefault.fstype, FSTYPE_STRING);
	string_set(&sDefault.ntvfs_handler, "default");

	Globals.dcerpc_ep_servers = str_list_make("epmapper srvsvc wkssvc rpcecho samr netlogon lsarpc spoolss", NULL);

	Globals.server_services = str_list_make("smb rpc", NULL);

	Globals.AuthMethods = str_list_make("guest sam_ignoredomain", NULL);

	string_set(&Globals.szSMBPasswdFile, dyn_SMB_PASSWD_FILE);
	string_set(&Globals.szPrivateDir, dyn_PRIVATE_DIR);
	asprintf(&Globals.szSAM_URL, "tdb://%s/sam.ldb", dyn_PRIVATE_DIR);
	asprintf(&Globals.szSPOOLSS_URL, "tdb://%s/spoolss.ldb", dyn_PRIVATE_DIR);

	string_set(&Globals.szGuestaccount, GUEST_ACCOUNT);

	/* using UTF8 by default allows us to support all chars */
	string_set(&Globals.unix_charset, "UTF8");

	/* Use codepage 850 as a default for the dos character set */
	string_set(&Globals.dos_charset, "CP850");

	/*
	 * Allow the default PASSWD_CHAT to be overridden in local.h.
	 */
	string_set(&Globals.szPasswdChat, DEFAULT_PASSWD_CHAT);
	
	string_set(&Globals.szPasswdProgram, "");
	string_set(&Globals.szPrintcapname, PRINTCAP_NAME);
	string_set(&Globals.szPidDir, dyn_PIDDIR);
	string_set(&Globals.szLockDir, dyn_LOCKDIR);
	string_set(&Globals.szSocketAddress, "0.0.0.0");
	pstrcpy(s, "Samba ");
	pstrcat(s, SAMBA_VERSION_STRING);
	string_set(&Globals.szServerString, s);
	slprintf(s, sizeof(s) - 1, "%d.%d", DEFAULT_MAJOR_VERSION,
		 DEFAULT_MINOR_VERSION);
	string_set(&Globals.szAnnounceVersion, s);

	string_set(&Globals.szLogonDrive, "");
	/* %N is the NIS auto.home server if -DAUTOHOME is used, else same as %L */
	string_set(&Globals.szLogonHome, "\\\\%N\\%U");
	string_set(&Globals.szLogonPath, "\\\\%N\\%U\\profile");

	string_set(&Globals.szPasswordServer, "*");

	Globals.bLoadPrinters = True;
	Globals.mangled_stack = 50;
	Globals.max_mux = 50;	/* This is *needed* for profile support. */
	Globals.max_xmit = 4356; /* the value w2k3 chooses */
	Globals.lpqcachetime = 10;
	Globals.bDisableSpoolss = False;
	Globals.pwordlevel = 0;
	Globals.unamelevel = 0;
	Globals.bLargeReadwrite = True;
	Globals.minprotocol = PROTOCOL_CORE;
	Globals.security = SEC_USER;
	Globals.paranoid_server_security = True;
	Globals.bEncryptPasswords = True;
	Globals.bUpdateEncrypt = False;
	Globals.bReadRaw = True;
	Globals.bWriteRaw = True;
	Globals.bNullPasswords = False;
	Globals.bObeyPamRestrictions = False;
	Globals.max_ttl = 60 * 60 * 24 * 3;	/* 3 days default. */
	Globals.max_wins_ttl = 60 * 60 * 24 * 6;	/* 6 days default. */
	Globals.min_wins_ttl = 60 * 60 * 6;	/* 6 hours default. */
	Globals.machine_password_timeout = 60 * 60 * 24 * 7;	/* 7 days default. */
	Globals.lm_announce = 2;	/* = Auto: send only if LM clients found */
	Globals.lm_interval = 60;
	Globals.announce_as = ANNOUNCE_AS_NT_SERVER;

	Globals.bTimeServer = False;
	Globals.bBindInterfacesOnly = False;
	Globals.bUnixPasswdSync = False;
	Globals.bPamPasswordChange = False;
	Globals.bUnicode = True;	/* Do unicode on the wire by default */
	Globals.bNTStatusSupport = True; /* Use NT status by default. */
	Globals.restrict_anonymous = 0;
	Globals.bClientLanManAuth = True;	/* Do use the LanMan hash if it is available */
	Globals.bLanmanAuth = True;	/* Do use the LanMan hash if it is available */
	Globals.bNTLMAuth = True;	/* Do use NTLMv1 if it is available (otherwise NTLMv2) */
	
	Globals.enhanced_browsing = True; 
	Globals.iLockSpinCount = 3; /* Try 2 times. */
	Globals.iLockSpinTime = 10; /* usec. */
#ifdef MMAP_BLACKLIST
	Globals.bUseMmap = False;
#else
	Globals.bUseMmap = True;
#endif
	Globals.bUnixExtensions = False;

	/* hostname lookups can be very expensive and are broken on
	   a large number of sites (tridge) */
	Globals.bHostnameLookups = False;

#ifdef WITH_LDAP_SAMCONFIG
	string_set(&Globals.szLdapServer, "localhost");
	Globals.ldap_port = 636;
	Globals.szPassdbBackend = str_list_make("ldapsam guest", NULL);
#else
	Globals.szPassdbBackend = str_list_make("smbpasswd guest", NULL);
#endif /* WITH_LDAP_SAMCONFIG */

	string_set(&Globals.szLdapSuffix, "");
	string_set(&Globals.szLdapMachineSuffix, "");
	string_set(&Globals.szLdapUserSuffix, "");

	string_set(&Globals.szLdapFilter, "(&(uid=%u)(objectclass=sambaAccount))");
	string_set(&Globals.szLdapAdminDn, "");
	Globals.ldap_ssl = LDAP_SSL_ON;
	Globals.ldap_passwd_sync = LDAP_PASSWD_SYNC_OFF;

/* these parameters are set to defaults that are more appropriate
   for the increasing samba install base:

   as a member of the workgroup, that will possibly become a
   _local_ master browser (lm = True).  this is opposed to a forced
   local master browser startup (pm = True).

   doesn't provide WINS server service by default (wsupp = False),
   and doesn't provide domain master browser services by default, either.

*/

	Globals.bPreferredMaster = Auto;	/* depending on bDomainMaster */
	Globals.os_level = 20;
	Globals.bLocalMaster = True;
	Globals.bDomainMaster = Auto;	/* depending on bDomainLogons */
	Globals.bDomainLogons = False;
	Globals.bWINSsupport = False;
	Globals.bWINSproxy = False;

	Globals.bDNSproxy = True;

	Globals.bAllowTrustedDomains = True;

	string_set(&Globals.szTemplateShell, "/bin/false");
	string_set(&Globals.szTemplateHomedir, "/home/%D/%U");
	string_set(&Globals.szWinbindSeparator, "\\");

	Globals.winbind_cache_time = 15;
	Globals.bWinbindEnumUsers = True;
	Globals.bWinbindEnumGroups = True;
	Globals.bWinbindUseDefaultDomain = False;

	string_set(&Globals.szIDMapBackend, "tdb");

	Globals.name_cache_timeout = 660; /* In seconds */

	Globals.bUseSpnego = True;

	Globals.client_signing = SMB_SIGNING_SUPPORTED;
	Globals.server_signing = SMB_SIGNING_SUPPORTED;

	Globals.smb_ports = str_list_make(SMB_PORTS, NULL);
}

static TALLOC_CTX *lp_talloc;

/******************************************************************* a
 Free up temporary memory - called from the main loop.
********************************************************************/

void lp_talloc_free(void)
{
	if (!lp_talloc)
		return;
	talloc_destroy(lp_talloc);
	lp_talloc = NULL;
}

/*******************************************************************
 Convenience routine to grab string parameters into temporary memory
 and run standard_sub_basic on them. The buffers can be written to by
 callers without affecting the source string.
********************************************************************/

static const char *lp_string(const char *s)
{
#if 0  /* until REWRITE done to make thread-safe */
	size_t len = s ? strlen(s) : 0;
	char *ret;
#endif

	/* The follow debug is useful for tracking down memory problems
	   especially if you have an inner loop that is calling a lp_*()
	   function that returns a string.  Perhaps this debug should be
	   present all the time? */

#if 0
	DEBUG(10, ("lp_string(%s)\n", s));
#endif

#if 0  /* until REWRITE done to make thread-safe */
	if (!lp_talloc)
		lp_talloc = talloc_init("lp_talloc");

	ret = (char *)talloc(lp_talloc, len + 100);	/* leave room for substitution */

	if (!ret)
		return NULL;

	if (!s)
		*ret = 0;
	else
		StrnCpy(ret, s, len);

	if (trim_string(ret, "\"", "\"")) {
		if (strchr(ret,'"') != NULL)
			StrnCpy(ret, s, len);
	}

	standard_sub_basic(ret,len+100);
	return (ret);
#endif
	return s;
}

/*
   In this section all the functions that are used to access the 
   parameters from the rest of the program are defined 
*/

#define FN_GLOBAL_STRING(fn_name,ptr) \
 const char *fn_name(void) {return(lp_string(*(char **)(ptr) ? *(char **)(ptr) : ""));}
#define FN_GLOBAL_CONST_STRING(fn_name,ptr) \
 const char *fn_name(void) {return(*(const char **)(ptr) ? *(const char **)(ptr) : "");}
#define FN_GLOBAL_LIST(fn_name,ptr) \
 const char **fn_name(void) {return(*(const char ***)(ptr));}
#define FN_GLOBAL_BOOL(fn_name,ptr) \
 BOOL fn_name(void) {return(*(BOOL *)(ptr));}
#define FN_GLOBAL_CHAR(fn_name,ptr) \
 char fn_name(void) {return(*(char *)(ptr));}
#define FN_GLOBAL_INTEGER(fn_name,ptr) \
 int fn_name(void) {return(*(int *)(ptr));}

#define FN_LOCAL_STRING(fn_name,val) \
 const char *fn_name(int i) {return(lp_string((LP_SNUM_OK(i) && ServicePtrs[(i)]->val) ? ServicePtrs[(i)]->val : sDefault.val));}
#define FN_LOCAL_CONST_STRING(fn_name,val) \
 const char *fn_name(int i) {return (const char *)((LP_SNUM_OK(i) && ServicePtrs[(i)]->val) ? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_LIST(fn_name,val) \
 const char **fn_name(int i) {return(const char **)(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_BOOL(fn_name,val) \
 BOOL fn_name(int i) {return(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_CHAR(fn_name,val) \
 char fn_name(int i) {return(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}
#define FN_LOCAL_INTEGER(fn_name,val) \
 int fn_name(int i) {return(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}

FN_GLOBAL_LIST(lp_smb_ports, &Globals.smb_ports)
FN_GLOBAL_STRING(lp_dos_charset, &Globals.dos_charset)
FN_GLOBAL_STRING(lp_unix_charset, &Globals.unix_charset)
FN_GLOBAL_STRING(lp_display_charset, &Globals.display_charset)
FN_GLOBAL_STRING(lp_logfile, &Globals.szLogFile)
FN_GLOBAL_STRING(lp_configfile, &Globals.szConfigFile)
FN_GLOBAL_STRING(lp_smb_passwd_file, &Globals.szSMBPasswdFile)
FN_GLOBAL_STRING(lp_sam_url, &Globals.szSAM_URL)
FN_GLOBAL_STRING(lp_spoolss_url, &Globals.szSPOOLSS_URL)
FN_GLOBAL_STRING(lp_private_dir, &Globals.szPrivateDir)
FN_GLOBAL_STRING(lp_serverstring, &Globals.szServerString)
FN_GLOBAL_STRING(lp_printcapname, &Globals.szPrintcapname)
FN_GLOBAL_STRING(lp_lockdir, &Globals.szLockDir)
FN_GLOBAL_STRING(lp_piddir, &Globals.szPidDir)
FN_GLOBAL_LIST(lp_dcerpc_endpoint_servers, &Globals.dcerpc_ep_servers)
FN_GLOBAL_LIST(lp_server_services, &Globals.server_services)
FN_GLOBAL_STRING(lp_rootdir, &Globals.szRootdir)
FN_GLOBAL_STRING(lp_defaultservice, &Globals.szDefaultService)
FN_GLOBAL_STRING(lp_hosts_equiv, &Globals.szHostsEquiv)
FN_GLOBAL_STRING(lp_auto_services, &Globals.szAutoServices)
FN_GLOBAL_STRING(lp_passwd_program, &Globals.szPasswdProgram)
FN_GLOBAL_STRING(lp_passwd_chat, &Globals.szPasswdChat)
FN_GLOBAL_STRING(lp_passwordserver, &Globals.szPasswordServer)
FN_GLOBAL_STRING(lp_name_resolve_order, &Globals.szNameResolveOrder)
FN_GLOBAL_STRING(lp_realm, &Globals.szRealm)
FN_GLOBAL_STRING(lp_ads_server, &Globals.szADSserver)
FN_GLOBAL_STRING(lp_socket_options, &Globals.socket_options)
FN_GLOBAL_STRING(lp_workgroup, &Globals.szWorkgroup)
FN_GLOBAL_STRING(lp_netbios_name, &Globals.szNetbiosName)
FN_GLOBAL_STRING(lp_netbios_scope, &Globals.szNetbiosScope)
FN_GLOBAL_CONST_STRING(lp_logon_script, &Globals.szLogonScript)
FN_GLOBAL_CONST_STRING(lp_logon_path, &Globals.szLogonPath)
FN_GLOBAL_CONST_STRING(lp_logon_drive, &Globals.szLogonDrive)
FN_GLOBAL_CONST_STRING(lp_logon_home, &Globals.szLogonHome)
FN_GLOBAL_STRING(lp_remote_announce, &Globals.szRemoteAnnounce)
FN_GLOBAL_STRING(lp_remote_browse_sync, &Globals.szRemoteBrowseSync)
FN_GLOBAL_LIST(lp_wins_server_list, &Globals.szWINSservers)
FN_GLOBAL_LIST(lp_interfaces, &Globals.szInterfaces)
FN_GLOBAL_STRING(lp_socket_address, &Globals.szSocketAddress)
static FN_GLOBAL_STRING(lp_announce_version, &Globals.szAnnounceVersion)
FN_GLOBAL_LIST(lp_netbios_aliases, &Globals.szNetbiosAliases)
FN_GLOBAL_LIST(lp_passdb_backend, &Globals.szPassdbBackend)
FN_GLOBAL_LIST(lp_preload_modules, &Globals.szPreloadModules)
FN_GLOBAL_STRING(lp_panic_action, &Globals.szPanicAction)
FN_GLOBAL_STRING(lp_adduser_script, &Globals.szAddUserScript)

FN_GLOBAL_CONST_STRING(lp_guestaccount, &Globals.szGuestaccount)

FN_GLOBAL_STRING(lp_addmachine_script, &Globals.szAddMachineScript)

FN_GLOBAL_STRING(lp_wins_hook, &Globals.szWINSHook)
FN_GLOBAL_STRING(lp_wins_partners, &Globals.szWINSPartners)
FN_GLOBAL_STRING(lp_template_homedir, &Globals.szTemplateHomedir)
FN_GLOBAL_STRING(lp_template_shell, &Globals.szTemplateShell)
FN_GLOBAL_CONST_STRING(lp_winbind_separator, &Globals.szWinbindSeparator)
FN_GLOBAL_BOOL(lp_winbind_enum_users, &Globals.bWinbindEnumUsers)
FN_GLOBAL_BOOL(lp_winbind_enum_groups, &Globals.bWinbindEnumGroups)
FN_GLOBAL_BOOL(lp_winbind_use_default_domain, &Globals.bWinbindUseDefaultDomain)
FN_GLOBAL_STRING(lp_idmap_backend, &Globals.szIDMapBackend)

#ifdef WITH_LDAP_SAMCONFIG
FN_GLOBAL_STRING(lp_ldap_server, &Globals.szLdapServer)
FN_GLOBAL_INTEGER(lp_ldap_port, &Globals.ldap_port)
#endif
FN_GLOBAL_STRING(lp_ldap_suffix, &Globals.szLdapSuffix)
FN_GLOBAL_STRING(lp_ldap_machine_suffix, &Globals.szLdapMachineSuffix)
FN_GLOBAL_STRING(lp_ldap_user_suffix, &Globals.szLdapUserSuffix)
FN_GLOBAL_STRING(lp_ldap_filter, &Globals.szLdapFilter)
FN_GLOBAL_STRING(lp_ldap_admin_dn, &Globals.szLdapAdminDn)
FN_GLOBAL_INTEGER(lp_ldap_ssl, &Globals.ldap_ssl)
FN_GLOBAL_INTEGER(lp_ldap_passwd_sync, &Globals.ldap_passwd_sync)
FN_GLOBAL_BOOL(lp_ldap_trust_ids, &Globals.ldap_trust_ids)

FN_GLOBAL_BOOL(lp_disable_netbios, &Globals.bDisableNetbios)
FN_GLOBAL_BOOL(lp_dns_proxy, &Globals.bDNSproxy)
FN_GLOBAL_BOOL(lp_wins_support, &Globals.bWINSsupport)
FN_GLOBAL_BOOL(lp_we_are_a_wins_server, &Globals.bWINSsupport)
FN_GLOBAL_BOOL(lp_wins_proxy, &Globals.bWINSproxy)
FN_GLOBAL_BOOL(lp_local_master, &Globals.bLocalMaster)
FN_GLOBAL_BOOL(lp_domain_logons, &Globals.bDomainLogons)
FN_GLOBAL_BOOL(lp_load_printers, &Globals.bLoadPrinters)
FN_GLOBAL_BOOL(lp_readraw, &Globals.bReadRaw)
FN_GLOBAL_BOOL(lp_large_readwrite, &Globals.bLargeReadwrite)
FN_GLOBAL_BOOL(lp_writeraw, &Globals.bWriteRaw)
FN_GLOBAL_BOOL(lp_null_passwords, &Globals.bNullPasswords)
FN_GLOBAL_BOOL(lp_obey_pam_restrictions, &Globals.bObeyPamRestrictions)
FN_GLOBAL_BOOL(lp_encrypted_passwords, &Globals.bEncryptPasswords)
FN_GLOBAL_BOOL(lp_update_encrypted, &Globals.bUpdateEncrypt)
static FN_GLOBAL_BOOL(lp_time_server, &Globals.bTimeServer)
FN_GLOBAL_BOOL(lp_bind_interfaces_only, &Globals.bBindInterfacesOnly)
FN_GLOBAL_BOOL(lp_pam_password_change, &Globals.bPamPasswordChange)
FN_GLOBAL_BOOL(lp_unix_password_sync, &Globals.bUnixPasswdSync)
FN_GLOBAL_BOOL(lp_unicode, &Globals.bUnicode)
FN_GLOBAL_BOOL(lp_nt_status_support, &Globals.bNTStatusSupport)
FN_GLOBAL_BOOL(lp_allow_trusted_domains, &Globals.bAllowTrustedDomains)
FN_GLOBAL_INTEGER(lp_restrict_anonymous, &Globals.restrict_anonymous)
FN_GLOBAL_BOOL(lp_lanman_auth, &Globals.bLanmanAuth)
FN_GLOBAL_BOOL(lp_ntlm_auth, &Globals.bNTLMAuth)
FN_GLOBAL_BOOL(lp_client_lanman_auth, &Globals.bClientLanManAuth)
FN_GLOBAL_BOOL(lp_client_ntlmv2_auth, &Globals.bClientNTLMv2Auth)
FN_GLOBAL_BOOL(lp_host_msdfs, &Globals.bHostMSDfs)
FN_GLOBAL_BOOL(lp_enhanced_browsing, &Globals.enhanced_browsing)
FN_GLOBAL_BOOL(lp_use_mmap, &Globals.bUseMmap)
FN_GLOBAL_BOOL(lp_unix_extensions, &Globals.bUnixExtensions)
FN_GLOBAL_BOOL(lp_use_spnego, &Globals.bUseSpnego)
FN_GLOBAL_BOOL(lp_hostname_lookups, &Globals.bHostnameLookups)
FN_GLOBAL_BOOL(lp_rpc_big_endian, &Globals.bRpcBigEndian)
FN_GLOBAL_INTEGER(lp_os_level, &Globals.os_level)
FN_GLOBAL_INTEGER(lp_max_ttl, &Globals.max_ttl)
FN_GLOBAL_INTEGER(lp_max_wins_ttl, &Globals.max_wins_ttl)
FN_GLOBAL_INTEGER(lp_min_wins_ttl, &Globals.min_wins_ttl)
FN_GLOBAL_INTEGER(lp_time_offset, &Globals.time_offset)
FN_GLOBAL_INTEGER(lp_maxmux, &Globals.max_mux)
FN_GLOBAL_INTEGER(lp_max_xmit, &Globals.max_xmit)
FN_GLOBAL_INTEGER(lp_passwordlevel, &Globals.pwordlevel)
FN_GLOBAL_INTEGER(lp_usernamelevel, &Globals.unamelevel)
FN_GLOBAL_INTEGER(lp_maxprotocol, &Globals.maxprotocol)
FN_GLOBAL_INTEGER(lp_minprotocol, &Globals.minprotocol)
FN_GLOBAL_INTEGER(lp_security, &Globals.security)
FN_GLOBAL_LIST(lp_auth_methods, &Globals.AuthMethods)
FN_GLOBAL_BOOL(lp_paranoid_server_security, &Globals.paranoid_server_security)
FN_GLOBAL_INTEGER(lp_lpqcachetime, &Globals.lpqcachetime)
FN_GLOBAL_INTEGER(lp_disable_spoolss, &Globals.bDisableSpoolss)
static FN_GLOBAL_INTEGER(lp_announce_as, &Globals.announce_as)
FN_GLOBAL_INTEGER(lp_lm_announce, &Globals.lm_announce)
FN_GLOBAL_INTEGER(lp_lm_interval, &Globals.lm_interval)
FN_GLOBAL_INTEGER(lp_machine_password_timeout, &Globals.machine_password_timeout)
FN_GLOBAL_INTEGER(lp_lock_spin_count, &Globals.iLockSpinCount)
FN_GLOBAL_INTEGER(lp_lock_sleep_time, &Globals.iLockSpinTime)
FN_LOCAL_STRING(lp_servicename, szService)
FN_LOCAL_CONST_STRING(lp_const_servicename, szService)
FN_LOCAL_STRING(lp_pathname, szPath)
FN_LOCAL_STRING(lp_username, szUsername)
FN_LOCAL_LIST(lp_invalid_users, szInvalidUsers)
FN_LOCAL_LIST(lp_valid_users, szValidUsers)
FN_LOCAL_LIST(lp_admin_users, szAdminUsers)
FN_LOCAL_STRING(lp_printcommand, szPrintcommand)
FN_LOCAL_STRING(lp_lpqcommand, szLpqcommand)
FN_LOCAL_STRING(lp_lprmcommand, szLprmcommand)
FN_LOCAL_STRING(lp_lppausecommand, szLppausecommand)
FN_LOCAL_STRING(lp_lpresumecommand, szLpresumecommand)
FN_LOCAL_STRING(lp_queuepausecommand, szQueuepausecommand)
FN_LOCAL_STRING(lp_queueresumecommand, szQueueresumecommand)
static FN_LOCAL_STRING(_lp_printername, szPrintername)
FN_LOCAL_LIST(lp_hostsallow, szHostsallow)
FN_LOCAL_LIST(lp_hostsdeny, szHostsdeny)
FN_LOCAL_STRING(lp_comment, comment)
FN_LOCAL_STRING(lp_fstype, fstype)
FN_LOCAL_STRING(lp_msdfs_proxy, szMSDfsProxy)
static FN_LOCAL_STRING(lp_volume, volume)
FN_LOCAL_STRING(lp_ntvfs_handler, ntvfs_handler)
FN_LOCAL_BOOL(lp_msdfs_root, bMSDfsRoot)
FN_LOCAL_BOOL(lp_autoloaded, autoloaded)
FN_LOCAL_BOOL(lp_browseable, bBrowseable)
FN_LOCAL_BOOL(lp_readonly, bRead_only)
FN_LOCAL_BOOL(lp_guest_ok, bGuest_ok)
FN_LOCAL_BOOL(lp_guest_only, bGuest_only)
FN_LOCAL_BOOL(lp_print_ok, bPrint_ok)
FN_LOCAL_BOOL(lp_map_hidden, bMap_hidden)
FN_LOCAL_BOOL(lp_map_archive, bMap_archive)
FN_LOCAL_BOOL(lp_locking, bLocking)
FN_LOCAL_BOOL(lp_strict_locking, bStrictLocking)
FN_LOCAL_BOOL(lp_posix_locking, bPosixLocking)
FN_LOCAL_BOOL(lp_share_modes, bShareModes)
FN_LOCAL_BOOL(lp_oplocks, bOpLocks)
FN_LOCAL_BOOL(lp_level2_oplocks, bLevel2OpLocks)
FN_LOCAL_BOOL(lp_onlyuser, bOnlyUser)
FN_LOCAL_BOOL(lp_map_system, bMap_system)
FN_LOCAL_INTEGER(lp_max_connections, iMaxConnections)
FN_LOCAL_INTEGER(lp_minprintspace, iMinPrintSpace)
FN_LOCAL_INTEGER(lp_printing, iPrinting)
FN_LOCAL_INTEGER(lp_csc_policy, iCSCPolicy)
FN_GLOBAL_INTEGER(lp_winbind_cache_time, &Globals.winbind_cache_time)
FN_GLOBAL_BOOL(lp_hide_local_users, &Globals.bHideLocalUsers)
FN_GLOBAL_INTEGER(lp_name_cache_timeout, &Globals.name_cache_timeout)
FN_GLOBAL_INTEGER(lp_server_signing, &Globals.server_signing)
FN_GLOBAL_INTEGER(lp_client_signing, &Globals.client_signing)

/* local prototypes */

static int map_parameter(const char *pszParmName);
static BOOL set_boolean(BOOL *pb, const char *pszParmValue);
static int getservicebyname(const char *pszServiceName,
			    service * pserviceDest);
static void copy_service(service * pserviceDest,
			 service * pserviceSource, BOOL *pcopymapDest);
static BOOL service_ok(int iService);
static BOOL do_section(const char *pszSectionName);
static void init_copymap(service * pservice);

/* This is a helper function for parametrical options support. */
/* It returns a pointer to parametrical option value if it exists or NULL otherwise */
/* Actual parametrical functions are quite simple */
static const char *get_parametrics(int lookup_service, const char *type, const char *option)
{
	char *vfskey;
        struct param_opt *data;
	
	if (lookup_service >= iNumServices) return NULL;
	
	data = (lookup_service < 0) ? 
		Globals.param_opt : ServicePtrs[lookup_service]->param_opt;
    
	asprintf(&vfskey, "%s:%s", type, option);
	strlower(vfskey);

	while (data) {
		if (strcmp(data->key, vfskey) == 0) {
			free(vfskey);
			return data->value;
		}
		data = data->next;
	}

	if (lookup_service >= 0) {
		/* Try to fetch the same option but from globals */
		/* but only if we are not already working with Globals */
		data = Globals.param_opt;
		while (data) {
			if (strcmp(data->key, vfskey) == 0) {
				free(vfskey);
				return data->value;
			}
			data = data->next;
		}
	}

	free(vfskey);
	
	return NULL;
}


/*******************************************************************
convenience routine to return int parameters.
********************************************************************/
static int lp_int(const char *s)
{

	if (!s) {
		DEBUG(0,("lp_int(%s): is called with NULL!\n",s));
		return (-1);
	}

	return atoi(s); 
}

/*******************************************************************
convenience routine to return unsigned long parameters.
********************************************************************/
static int lp_ulong(const char *s)
{

	if (!s) {
		DEBUG(0,("lp_int(%s): is called with NULL!\n",s));
		return (-1);
	}

	return strtoul(s, NULL, 10);
}

/*******************************************************************
convenience routine to return boolean parameters.
********************************************************************/
static BOOL lp_bool(const char *s)
{
	BOOL ret = False;

	if (!s) {
		DEBUG(0,("lp_bool(%s): is called with NULL!\n",s));
		return False;
	}
	
	if (!set_boolean(&ret,s)) {
		DEBUG(0,("lp_bool(%s): value is not boolean!\n",s));
		return False;
	}

	return ret;
}

/*******************************************************************
convenience routine to return enum parameters.
********************************************************************/
static int lp_enum(const char *s,const struct enum_list *_enum)
{
	int i;

	if (!s || !_enum) {
		DEBUG(0,("lp_enum(%s,enum): is called with NULL!\n",s));
		return False;
	}
	
	for (i=0; _enum[i].name; i++) {
		if (strcasecmp(_enum[i].name,s)==0)
			return _enum[i].value;
	}

	DEBUG(0,("lp_enum(%s,enum): value is not in enum_list!\n",s));
	return (-1);
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */
/* Returned value is allocated in 'lp_talloc' context */

const char *lp_parm_string(int lookup_service, const char *type, const char *option)
{
	const char *value = get_parametrics(lookup_service, type, option);
	
	if (value)
		return lp_string(value);

	return NULL;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */
/* Returned value is allocated in 'lp_talloc' context */

char **lp_parm_string_list(int lookup_service, const char *type, const char *option,
			   const char *separator)
{
	const char *value = get_parametrics(lookup_service, type, option);
	
	if (value)
		return str_list_make(value, separator);

	return NULL;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

int lp_parm_int(int lookup_service, const char *type, const char *option)
{
	const char *value = get_parametrics(lookup_service, type, option);
	
	if (value)
		return lp_int(value);

	return (-1);
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

unsigned long lp_parm_ulong(int lookup_service, const char *type, const char *option)
{
	const char *value = get_parametrics(lookup_service, type, option);
	
	if (value)
		return lp_ulong(value);

	return (0);
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

BOOL lp_parm_bool(int lookup_service, const char *type, const char *option, BOOL default_v)
{
	const char *value = get_parametrics(lookup_service, type, option);
	
	if (value)
		return lp_bool(value);

	return default_v;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

int lp_parm_enum(int lookup_service, const char *type, const char *option,
		 const struct enum_list *_enum)
{
	const char *value = get_parametrics(lookup_service, type, option);
	
	if (value)
		return lp_enum(value, _enum);

	return (-1);
}


/***************************************************************************
 Initialise a service to the defaults.
***************************************************************************/

static void init_service(service * pservice)
{
	memset((char *)pservice, '\0', sizeof(service));
	copy_service(pservice, &sDefault, NULL);
}

/***************************************************************************
 Free the dynamically allocated parts of a service struct.
***************************************************************************/

static void free_service(service *pservice)
{
	int i;
        struct param_opt *data, *pdata;
	if (!pservice)
		return;

	if (pservice->szService)
		DEBUG(5, ("free_service: Freeing service %s\n",
		       pservice->szService));

	string_free(&pservice->szService);
	SAFE_FREE(pservice->copymap);

	for (i = 0; parm_table[i].label; i++) {
		if ((parm_table[i].type == P_STRING ||
		     parm_table[i].type == P_USTRING) &&
		    parm_table[i].class == P_LOCAL)
			string_free((char **)
				    (((char *)pservice) +
				     PTR_DIFF(parm_table[i].ptr, &sDefault)));
		else if (parm_table[i].type == P_LIST &&
			 parm_table[i].class == P_LOCAL)
			     str_list_free((char ***)
			     		    (((char *)pservice) +
					     PTR_DIFF(parm_table[i].ptr, &sDefault)));
	}
				
	DEBUG(5,("Freeing parametrics:\n"));
	data = pservice->param_opt;
	while (data) {
		DEBUG(5,("[%s = %s]\n", data->key, data->value));
		string_free(&data->key);
		string_free(&data->value);
		pdata = data->next;
		SAFE_FREE(data);
		data = pdata;
	}

	ZERO_STRUCTP(pservice);
}

/***************************************************************************
 Add a new service to the services array initialising it with the given 
 service. 
***************************************************************************/

static int add_a_service(const service *pservice, const char *name)
{
	int i;
	service tservice;
	int num_to_alloc = iNumServices + 1;
	struct param_opt *data, *pdata;

	tservice = *pservice;

	/* it might already exist */
	if (name) {
		i = getservicebyname(name, NULL);
		if (i >= 0) {
			/* Clean all parametric options for service */
			/* They will be added during parsing again */
			data = ServicePtrs[i]->param_opt;
			while (data) {
				string_free(&data->key);
				string_free(&data->value);
				pdata = data->next;
				SAFE_FREE(data);
				data = pdata;
			}
			ServicePtrs[i]->param_opt = NULL;
			return (i);
		}
	}

	/* find an invalid one */
	for (i = 0; i < iNumServices; i++)
		if (!ServicePtrs[i]->valid)
			break;

	/* if not, then create one */
	if (i == iNumServices) {
		service **tsp;
		
		tsp = (service **) Realloc(ServicePtrs,
					   sizeof(service *) *
					   num_to_alloc);
					   
		if (!tsp) {
			DEBUG(0,("add_a_service: failed to enlarge ServicePtrs!\n"));
			return (-1);
		}
		else {
			ServicePtrs = tsp;
			ServicePtrs[iNumServices] =
				(service *) malloc(sizeof(service));
		}
		if (!ServicePtrs[iNumServices]) {
			DEBUG(0,("add_a_service: out of memory!\n"));
			return (-1);
		}

		iNumServices++;
	} else
		free_service(ServicePtrs[i]);

	ServicePtrs[i]->valid = True;

	init_service(ServicePtrs[i]);
	copy_service(ServicePtrs[i], &tservice, NULL);
	if (name)
		string_set(&ServicePtrs[i]->szService, name);
	return (i);
}

/***************************************************************************
 Add a new home service, with the specified home directory, defaults coming 
 from service ifrom.
***************************************************************************/

BOOL lp_add_home(const char *pszHomename, int iDefaultService, 
		 const char *user, const char *pszHomedir)
{
	int i;
	pstring newHomedir;

	i = add_a_service(ServicePtrs[iDefaultService], pszHomename);

	if (i < 0)
		return (False);

	if (!(*(ServicePtrs[iDefaultService]->szPath))
	    || strequal(ServicePtrs[iDefaultService]->szPath, lp_pathname(-1))) {
		pstrcpy(newHomedir, pszHomedir);
	} else {
		pstrcpy(newHomedir, lp_pathname(iDefaultService));
		string_sub(newHomedir,"%H", pszHomedir, sizeof(newHomedir)); 
	}

	string_set(&ServicePtrs[i]->szPath, newHomedir);

	if (!(*(ServicePtrs[i]->comment))) {
		pstring comment;
		slprintf(comment, sizeof(comment) - 1,
			 "Home directory of %s", user);
		string_set(&ServicePtrs[i]->comment, comment);
	}
	ServicePtrs[i]->bAvailable = sDefault.bAvailable;
	ServicePtrs[i]->bBrowseable = sDefault.bBrowseable;

	DEBUG(3, ("adding home's share [%s] for user '%s' at '%s'\n", pszHomename, 
	       user, newHomedir));
	
	return (True);
}

/***************************************************************************
 Add a new service, based on an old one.
***************************************************************************/

int lp_add_service(const char *pszService, int iDefaultService)
{
	return (add_a_service(ServicePtrs[iDefaultService], pszService));
}

/***************************************************************************
 Add the IPC service.
***************************************************************************/

static BOOL lp_add_ipc(const char *ipc_name, BOOL guest_ok)
{
	pstring comment;
	int i = add_a_service(&sDefault, ipc_name);

	if (i < 0)
		return (False);

	slprintf(comment, sizeof(comment) - 1,
		 "IPC Service (%s)", Globals.szServerString);

	string_set(&ServicePtrs[i]->szPath, tmpdir());
	string_set(&ServicePtrs[i]->szUsername, "");
	string_set(&ServicePtrs[i]->comment, comment);
	string_set(&ServicePtrs[i]->fstype, "IPC");
	ServicePtrs[i]->iMaxConnections = 0;
	ServicePtrs[i]->bAvailable = True;
	ServicePtrs[i]->bRead_only = True;
	ServicePtrs[i]->bGuest_only = False;
	ServicePtrs[i]->bGuest_ok = guest_ok;
	ServicePtrs[i]->bPrint_ok = False;
	ServicePtrs[i]->bBrowseable = sDefault.bBrowseable;

	DEBUG(3, ("adding IPC service\n"));

	return (True);
}

/***************************************************************************
 Add a new printer service, with defaults coming from service iFrom.
***************************************************************************/

BOOL lp_add_printer(const char *pszPrintername, int iDefaultService)
{
	const char *comment = "From Printcap";
	int i = add_a_service(ServicePtrs[iDefaultService], pszPrintername);

	if (i < 0)
		return (False);

	/* note that we do NOT default the availability flag to True - */
	/* we take it from the default service passed. This allows all */
	/* dynamic printers to be disabled by disabling the [printers] */
	/* entry (if/when the 'available' keyword is implemented!).    */

	/* the printer name is set to the service name. */
	string_set(&ServicePtrs[i]->szPrintername, pszPrintername);
	string_set(&ServicePtrs[i]->comment, comment);
	ServicePtrs[i]->bBrowseable = sDefault.bBrowseable;
	/* Printers cannot be read_only. */
	ServicePtrs[i]->bRead_only = False;
	/* No share modes on printer services. */
	ServicePtrs[i]->bShareModes = False;
	/* No oplocks on printer services. */
	ServicePtrs[i]->bOpLocks = False;
	/* Printer services must be printable. */
	ServicePtrs[i]->bPrint_ok = True;

	DEBUG(3, ("adding printer service %s\n", pszPrintername));

	update_server_announce_as_printserver();

	return (True);
}

/***************************************************************************
 Map a parameter's string representation to something we can use. 
 Returns False if the parameter string is not recognised, else TRUE.
***************************************************************************/

static int map_parameter(const char *pszParmName)
{
	int iIndex;

	if (*pszParmName == '-')
		return (-1);

	for (iIndex = 0; parm_table[iIndex].label; iIndex++)
		if (strwicmp(parm_table[iIndex].label, pszParmName) == 0)
			return (iIndex);

	/* Warn only if it isn't parametric option */
	if (strchr(pszParmName, ':') == NULL)
		DEBUG(0, ("Unknown parameter encountered: \"%s\"\n", pszParmName));
	/* We do return 'fail' for parametric options as well because they are
	   stored in different storage
	 */
	return (-1);
}

/***************************************************************************
 Set a boolean variable from the text value stored in the passed string.
 Returns True in success, False if the passed string does not correctly 
 represent a boolean.
***************************************************************************/

static BOOL set_boolean(BOOL *pb, const char *pszParmValue)
{
	BOOL bRetval;

	bRetval = True;
	if (strwicmp(pszParmValue, "yes") == 0 ||
	    strwicmp(pszParmValue, "true") == 0 ||
	    strwicmp(pszParmValue, "1") == 0)
		*pb = True;
	else if (strwicmp(pszParmValue, "no") == 0 ||
		    strwicmp(pszParmValue, "False") == 0 ||
		    strwicmp(pszParmValue, "0") == 0)
		*pb = False;
	else {
		DEBUG(0,
		      ("ERROR: Badly formed boolean in configuration file: \"%s\".\n",
		       pszParmValue));
		bRetval = False;
	}
	return (bRetval);
}

/***************************************************************************
Find a service by name. Otherwise works like get_service.
***************************************************************************/

static int getservicebyname(const char *pszServiceName, service * pserviceDest)
{
	int iService;

	for (iService = iNumServices - 1; iService >= 0; iService--)
		if (VALID(iService) &&
		    strwicmp(ServicePtrs[iService]->szService, pszServiceName) == 0) {
			if (pserviceDest != NULL)
				copy_service(pserviceDest, ServicePtrs[iService], NULL);
			break;
		}

	return (iService);
}

/***************************************************************************
 Copy a service structure to another.
 If pcopymapDest is NULL then copy all fields
***************************************************************************/

static void copy_service(service * pserviceDest, service * pserviceSource, BOOL *pcopymapDest)
{
	int i;
	BOOL bcopyall = (pcopymapDest == NULL);
	struct param_opt *data, *pdata, *paramo;
	BOOL not_added;

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].ptr && parm_table[i].class == P_LOCAL &&
		    (bcopyall || pcopymapDest[i])) {
			void *def_ptr = parm_table[i].ptr;
			void *src_ptr =
				((char *)pserviceSource) + PTR_DIFF(def_ptr,
								    &sDefault);
			void *dest_ptr =
				((char *)pserviceDest) + PTR_DIFF(def_ptr,
								  &sDefault);

			switch (parm_table[i].type) {
				case P_BOOL:
				case P_BOOLREV:
					*(BOOL *)dest_ptr = *(BOOL *)src_ptr;
					break;

				case P_INTEGER:
				case P_ENUM:
				case P_OCTAL:
					*(int *)dest_ptr = *(int *)src_ptr;
					break;

				case P_CHAR:
					*(char *)dest_ptr = *(char *)src_ptr;
					break;

				case P_STRING:
					string_set(dest_ptr,
						   *(char **)src_ptr);
					break;

				case P_USTRING:
					string_set(dest_ptr,
						   *(char **)src_ptr);
					strupper(*(char **)dest_ptr);
					break;
				case P_LIST:
					str_list_copy((char ***)dest_ptr, *(const char ***)src_ptr);
					break;
				default:
					break;
			}
		}

	if (bcopyall) {
		init_copymap(pserviceDest);
		if (pserviceSource->copymap)
			memcpy((void *)pserviceDest->copymap,
			       (void *)pserviceSource->copymap,
			       sizeof(BOOL) * NUMPARAMETERS);
	}
	
	data = pserviceSource->param_opt;
	while (data) {
		not_added = True;
		pdata = pserviceDest->param_opt;
		/* Traverse destination */
		while (pdata) {
			/* If we already have same option, override it */
			if (strcmp(pdata->key, data->key) == 0) {
				string_free(&pdata->value);
				pdata->value = strdup(data->value);
				not_added = False;
				break;
			}
			pdata = pdata->next;
		}
		if (not_added) {
			paramo = smb_xmalloc(sizeof(*paramo));
			paramo->key = strdup(data->key);
			paramo->value = strdup(data->value);
			DLIST_ADD(pserviceDest->param_opt, paramo);
		}
		data = data->next;
	}
}

/***************************************************************************
Check a service for consistency. Return False if the service is in any way
incomplete or faulty, else True.
***************************************************************************/

static BOOL service_ok(int iService)
{
	BOOL bRetval;

	bRetval = True;
	if (ServicePtrs[iService]->szService[0] == '\0') {
		DEBUG(0, ("The following message indicates an internal error:\n"));
		DEBUG(0, ("No service name in service entry.\n"));
		bRetval = False;
	}

	/* The [printers] entry MUST be printable. I'm all for flexibility, but */
	/* I can't see why you'd want a non-printable printer service...        */
	if (strwicmp(ServicePtrs[iService]->szService, PRINTERS_NAME) == 0) {
		if (!ServicePtrs[iService]->bPrint_ok) {
			DEBUG(0, ("WARNING: [%s] service MUST be printable!\n",
			       ServicePtrs[iService]->szService));
			ServicePtrs[iService]->bPrint_ok = True;
		}
		/* [printers] service must also be non-browsable. */
		if (ServicePtrs[iService]->bBrowseable)
			ServicePtrs[iService]->bBrowseable = False;
	}

	if (ServicePtrs[iService]->szPath[0] == '\0' &&
	    strwicmp(ServicePtrs[iService]->szService, HOMES_NAME) != 0) {
		DEBUG(0, ("No path in service %s - using %s\n",
		       ServicePtrs[iService]->szService, tmpdir()));
		string_set(&ServicePtrs[iService]->szPath, tmpdir());
	}

	/* If a service is flagged unavailable, log the fact at level 0. */
	if (!ServicePtrs[iService]->bAvailable)
		DEBUG(1, ("NOTE: Service %s is flagged unavailable.\n",
			  ServicePtrs[iService]->szService));

	return (bRetval);
}

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
		f = (struct file_lists *)malloc(sizeof(file_lists[0]));
		if (!f)
			return;
		f->next = file_lists;
		f->name = strdup(fname);
		if (!f->name) {
			SAFE_FREE(f);
			return;
		}
		f->subfname = strdup(subfname);
		if (!f->subfname) {
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
}

/*******************************************************************
 Check if a config file has changed date.
********************************************************************/

BOOL lp_file_list_changed(void)
{
	struct file_lists *f = file_lists;
	DEBUG(6, ("lp_file_list_changed()\n"));

	while (f) {
		pstring n2;
		time_t mod_time;

		pstrcpy(n2, f->name);
		standard_sub_basic(n2,sizeof(n2));

		DEBUGADD(6, ("file %s -> %s  last mod_time: %s\n",
			     f->name, n2, ctime(&f->modtime)));

		mod_time = file_modtime(n2);

		if (mod_time && ((f->modtime != mod_time) || (f->subfname == NULL) || (strcmp(n2, f->subfname) != 0))) {
			DEBUGADD(6,
				 ("file %s modified: %s\n", n2,
				  ctime(&mod_time)));
			f->modtime = mod_time;
			SAFE_FREE(f->subfname);
			f->subfname = strdup(n2);
			return (True);
		}
		f = f->next;
	}
	return (False);
}

/***************************************************************************
 Handle the include operation.
***************************************************************************/

static BOOL handle_include(const char *pszParmValue, char **ptr)
{
	pstring fname;
	pstrcpy(fname, pszParmValue);

	standard_sub_basic(fname,sizeof(fname));

	add_to_file_list(pszParmValue, fname);

	string_set(ptr, fname);

	if (file_exist(fname, NULL))
		return (pm_process(fname, do_section, do_parameter));

	DEBUG(2, ("Can't find include file %s\n", fname));

	return (False);
}

/***************************************************************************
 Handle the interpretation of the copy parameter.
***************************************************************************/

static BOOL handle_copy(const char *pszParmValue, char **ptr)
{
	BOOL bRetval;
	int iTemp;
	service serviceTemp;

	string_set(ptr, pszParmValue);

	init_service(&serviceTemp);

	bRetval = False;

	DEBUG(3, ("Copying service from service %s\n", pszParmValue));

	if ((iTemp = getservicebyname(pszParmValue, &serviceTemp)) >= 0) {
		if (iTemp == iServiceIndex) {
			DEBUG(0, ("Can't copy service %s - unable to copy self!\n", pszParmValue));
		} else {
			copy_service(ServicePtrs[iServiceIndex],
				     &serviceTemp,
				     ServicePtrs[iServiceIndex]->copymap);
			bRetval = True;
		}
	} else {
		DEBUG(0, ("Unable to copy service - source not found: %s\n", pszParmValue));
		bRetval = False;
	}

	free_service(&serviceTemp);
	return (bRetval);
}

/***************************************************************************
 Handle winbind/non unix account uid and gid allocation parameters.  The format of these
 parameters is:

 [global]

        winbind uid = 1000-1999
        winbind gid = 700-899

 We only do simple parsing checks here.  The strings are parsed into useful
 structures in the winbind daemon code.

***************************************************************************/

/* Some lp_ routines to return winbind [ug]id information */

static uid_t winbind_uid_low, winbind_uid_high;
static gid_t winbind_gid_low, winbind_gid_high;
static uint32_t non_unix_account_low, non_unix_account_high;

BOOL lp_winbind_uid(uid_t *low, uid_t *high)
{
        if (winbind_uid_low == 0 || winbind_uid_high == 0)
                return False;

        if (low)
                *low = winbind_uid_low;

        if (high)
                *high = winbind_uid_high;

        return True;
}

BOOL lp_winbind_gid(gid_t *low, gid_t *high)
{
        if (winbind_gid_low == 0 || winbind_gid_high == 0)
                return False;

        if (low)
                *low = winbind_gid_low;

        if (high)
                *high = winbind_gid_high;

        return True;
}

BOOL lp_non_unix_account_range(uint32_t *low, uint32_t *high)
{
        if (non_unix_account_low == 0 || non_unix_account_high == 0)
                return False;

        if (low)
                *low = non_unix_account_low;

        if (high)
                *high = non_unix_account_high;

        return True;
}

/* Do some simple checks on "winbind [ug]id" parameter values */

static BOOL handle_winbind_uid(const char *pszParmValue, char **ptr)
{
	uint32_t low, high;

	if (sscanf(pszParmValue, "%u-%u", &low, &high) != 2 || high < low)
		return False;

	/* Parse OK */

	string_set(ptr, pszParmValue);

        winbind_uid_low = low;
        winbind_uid_high = high;

	return True;
}

static BOOL handle_winbind_gid(const char *pszParmValue, char **ptr)
{
	uint32_t low, high;

	if (sscanf(pszParmValue, "%u-%u", &low, &high) != 2 || high < low)
		return False;

	/* Parse OK */

	string_set(ptr, pszParmValue);

        winbind_gid_low = low;
        winbind_gid_high = high;

	return True;
}

/***************************************************************************
 Do some simple checks on "non unix account range" parameter values.
***************************************************************************/

static BOOL handle_non_unix_account_range(const char *pszParmValue, char **ptr)
{
	uint32_t low, high;

	if (sscanf(pszParmValue, "%u-%u", &low, &high) != 2 || high < low)
		return False;

	/* Parse OK */

	string_set(ptr, pszParmValue);

        non_unix_account_low = low;
        non_unix_account_high = high;

	return True;
}

/***************************************************************************
 Handle the ldap machine suffix option.
***************************************************************************/

static BOOL handle_ldap_machine_suffix( const char *pszParmValue, char **ptr)
{
       pstring suffix;
       
       pstrcpy(suffix, pszParmValue);

       if (! *Globals.szLdapSuffix ) {
               string_set( ptr, suffix );
               return True;
       }

       if (! strstr(suffix, Globals.szLdapSuffix) ) {
               if ( *pszParmValue )
                       pstrcat(suffix, ",");
               pstrcat(suffix, Globals.szLdapSuffix);
       }
       string_set( ptr, suffix );
       return True;
}

/***************************************************************************
 Handle the ldap user suffix option.
***************************************************************************/

static BOOL handle_ldap_user_suffix( const char *pszParmValue, char **ptr)
{
       pstring suffix;
       
       pstrcpy(suffix, pszParmValue);

       if (! *Globals.szLdapSuffix ) {
               string_set( ptr, suffix );
               return True;
       }
       
       if (! strstr(suffix, Globals.szLdapSuffix) ) {
               if ( *pszParmValue )
                       pstrcat(suffix, ",");
               pstrcat(suffix, Globals.szLdapSuffix);
       }
       string_set( ptr, suffix );
       return True;
}

/***************************************************************************
 Handle setting ldap suffix and determines whether ldap machine suffix needs
 to be set as well.
***************************************************************************/

static BOOL handle_ldap_suffix( const char *pszParmValue, char **ptr)
{
       pstring suffix;
       pstring user_suffix;
       pstring machine_suffix;	
  	          
       pstrcpy(suffix, pszParmValue);

       if (! *Globals.szLdapMachineSuffix )
               string_set(&Globals.szLdapMachineSuffix, suffix);
       if (! *Globals.szLdapUserSuffix ) 
               string_set(&Globals.szLdapUserSuffix, suffix);
         
       if (! strstr(Globals.szLdapMachineSuffix, suffix)) {
               pstrcpy(machine_suffix, Globals.szLdapMachineSuffix);
               if ( *Globals.szLdapMachineSuffix )
                       pstrcat(machine_suffix, ",");
               pstrcat(machine_suffix, suffix);
               string_set(&Globals.szLdapMachineSuffix, machine_suffix);       
       }

       if (! strstr(Globals.szLdapUserSuffix, suffix)) {
               pstrcpy(user_suffix, Globals.szLdapUserSuffix);
               if ( *Globals.szLdapUserSuffix )
                       pstrcat(user_suffix, ",");
               pstrcat(user_suffix, suffix);   
               string_set(&Globals.szLdapUserSuffix, user_suffix);
       } 

       string_set(ptr, suffix); 

       return True;
}

/***************************************************************************
 Initialise a copymap.
***************************************************************************/

static void init_copymap(service * pservice)
{
	int i;
	SAFE_FREE(pservice->copymap);
	pservice->copymap = (BOOL *)malloc(sizeof(BOOL) * NUMPARAMETERS);
	if (!pservice->copymap)
		DEBUG(0,
		      ("Couldn't allocate copymap!! (size %d)\n",
		       (int)NUMPARAMETERS));
	else
		for (i = 0; i < NUMPARAMETERS; i++)
			pservice->copymap[i] = True;
}

/***************************************************************************
 Return the local pointer to a parameter given the service number and the 
 pointer into the default structure.
***************************************************************************/

void *lp_local_ptr(int snum, void *ptr)
{
	return (void *)(((char *)ServicePtrs[snum]) + PTR_DIFF(ptr, &sDefault));
}


/***************************************************************************
 Process a parametric option
***************************************************************************/
static BOOL lp_do_parameter_parametric(int snum, const char *pszParmName, const char *pszParmValue, int flags)
{
	struct param_opt *paramo, *data;
	char *name;

	while (isspace(*pszParmName)) {
		pszParmName++;
	}

	name = strdup(pszParmName);
	if (!name) return False;

	strlower(name);

	if (snum < 0) {
		data = Globals.param_opt;
	} else {
		data = ServicePtrs[snum]->param_opt;
	}

	/* Traverse destination */
	for (paramo=data; paramo; paramo=paramo->next) {
		/* If we already have the option set, override it unless
		   it was a command line option and the new one isn't */
		if (strcmp(paramo->key, name) == 0) {
			if ((paramo->flags & FLAG_CMDLINE) &&
			    !(flags & FLAG_CMDLINE)) {
				return True;
			}

			free(paramo->value);
			paramo->value = strdup(pszParmValue);
			paramo->flags = flags;
			free(name);
			return True;
		}
	}

	paramo = smb_xmalloc(sizeof(*paramo));
	paramo->key = strdup(name);
	paramo->value = strdup(pszParmValue);
	paramo->flags = flags;
	if (snum < 0) {
		DLIST_ADD(Globals.param_opt, paramo);
	} else {
		DLIST_ADD(ServicePtrs[snum]->param_opt, paramo);
	}

	free(name);
	
	return True;
}

/***************************************************************************
 Process a parameter for a particular service number. If snum < 0
 then assume we are in the globals.
***************************************************************************/
BOOL lp_do_parameter(int snum, const char *pszParmName, const char *pszParmValue)
{
	int parmnum, i;
	void *parm_ptr = NULL;	/* where we are going to store the result */
	void *def_ptr = NULL;

	parmnum = map_parameter(pszParmName);

	if (parmnum < 0) {
		if (strchr(pszParmName, ':')) {
			return lp_do_parameter_parametric(snum, pszParmName, pszParmValue, 0);
		}
		DEBUG(0, ("Ignoring unknown parameter \"%s\"\n", pszParmName));
		return (True);
	}

	if (parm_table[parmnum].flags & FLAG_DEPRECATED) {
		DEBUG(1, ("WARNING: The \"%s\" option is deprecated\n",
			  pszParmName));
	}

	/* if the flag has been set on the command line, then don't allow override,
	   but don't report an error */
	if (parm_table[parmnum].flags & FLAG_CMDLINE) {
		return True;
	}

	def_ptr = parm_table[parmnum].ptr;

	/* we might point at a service, the default service or a global */
	if (snum < 0) {
		parm_ptr = def_ptr;
	} else {
		if (parm_table[parmnum].class == P_GLOBAL) {
			DEBUG(0,
			      ("Global parameter %s found in service section!\n",
			       pszParmName));
			return (True);
		}
		parm_ptr =
			((char *)ServicePtrs[snum]) + PTR_DIFF(def_ptr,
							    &sDefault);
	}

	if (snum >= 0) {
		if (!ServicePtrs[snum]->copymap)
			init_copymap(ServicePtrs[snum]);

		/* this handles the aliases - set the copymap for other entries with
		   the same data pointer */
		for (i = 0; parm_table[i].label; i++)
			if (parm_table[i].ptr == parm_table[parmnum].ptr)
				ServicePtrs[snum]->copymap[i] = False;
	}

	/* if it is a special case then go ahead */
	if (parm_table[parmnum].special) {
		parm_table[parmnum].special(pszParmValue, (char **)parm_ptr);
		return (True);
	}

	/* now switch on the type of variable it is */
	switch (parm_table[parmnum].type)
	{
		case P_BOOL:
			set_boolean(parm_ptr, pszParmValue);
			break;

		case P_BOOLREV:
			set_boolean(parm_ptr, pszParmValue);
			*(BOOL *)parm_ptr = !*(BOOL *)parm_ptr;
			break;

		case P_INTEGER:
			*(int *)parm_ptr = atoi(pszParmValue);
			break;

		case P_CHAR:
			*(char *)parm_ptr = *pszParmValue;
			break;

		case P_OCTAL:
			sscanf(pszParmValue, "%o", (int *)parm_ptr);
			break;

		case P_LIST:
			*(char ***)parm_ptr = str_list_make(pszParmValue, NULL);
			break;

		case P_STRING:
			string_set(parm_ptr, pszParmValue);
			break;

		case P_USTRING:
			string_set(parm_ptr, pszParmValue);
			strupper(*(char **)parm_ptr);
			break;

		case P_ENUM:
			for (i = 0; parm_table[parmnum].enum_list[i].name; i++) {
				if (strequal
				    (pszParmValue,
				     parm_table[parmnum].enum_list[i].name)) {
					*(int *)parm_ptr =
						parm_table[parmnum].
						enum_list[i].value;
					break;
				}
			}
			break;
		case P_SEP:
			break;
	}

	return (True);
}

/***************************************************************************
 Process a parameter.
***************************************************************************/

static BOOL do_parameter(const char *pszParmName, const char *pszParmValue)
{
	if (!bInGlobalSection && bGlobalOnly)
		return (True);

	DEBUGADD(4, ("doing parameter %s = %s\n", pszParmName, pszParmValue));

	return (lp_do_parameter(bInGlobalSection ? -2 : iServiceIndex,
				pszParmName, pszParmValue));
}


/*
  set a parameter from the commandline - this is called from command line parameter
  parsing code. It sets the parameter then marks the parameter as unable to be modified
  by smb.conf processing
*/
BOOL lp_set_cmdline(const char *pszParmName, const char *pszParmValue)
{
	int parmnum = map_parameter(pszParmName);

	if (parmnum < 0 && strchr(pszParmName, ':')) {
		/* set a parametric option */
		return lp_do_parameter_parametric(-1, pszParmName, pszParmValue, FLAG_CMDLINE);
	}

	/* reset the CMDLINE flag in case this has been called before */
	parm_table[parmnum].flags &= ~FLAG_CMDLINE;

	if (!lp_do_parameter(-2, pszParmName, pszParmValue)) {
		return False;
	}

	parm_table[parmnum].flags |= FLAG_CMDLINE;
	return True;
}

/***************************************************************************
 Print a parameter of the specified type.
***************************************************************************/

static void print_parameter(struct parm_struct *p, void *ptr, FILE * f)
{
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
			fprintf(f, "%s", BOOLSTR(*(BOOL *)ptr));
			break;

		case P_BOOLREV:
			fprintf(f, "%s", BOOLSTR(!*(BOOL *)ptr));
			break;

		case P_INTEGER:
			fprintf(f, "%d", *(int *)ptr);
			break;

		case P_CHAR:
			fprintf(f, "%c", *(char *)ptr);
			break;

		case P_OCTAL:
			fprintf(f, "%s", octal_string(*(int *)ptr));
			break;

		case P_LIST:
			if ((char ***)ptr && *(char ***)ptr) {
				char **list = *(char ***)ptr;
				
				for (; *list; list++)
					fprintf(f, "%s%s", *list,
						((*(list+1))?", ":""));
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

static BOOL equal_parameter(parm_type type, void *ptr1, void *ptr2)
{
	switch (type) {
		case P_BOOL:
		case P_BOOLREV:
			return (*((BOOL *)ptr1) == *((BOOL *)ptr2));

		case P_INTEGER:
		case P_ENUM:
		case P_OCTAL:
			return (*((int *)ptr1) == *((int *)ptr2));

		case P_CHAR:
			return (*((char *)ptr1) == *((char *)ptr2));
		
		case P_LIST:
			return str_list_compare(*(char ***)ptr1, *(char ***)ptr2);

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
	return (False);
}

/***************************************************************************
 Process a new section (service). At this stage all sections are services.
 Later we'll have special sections that permit server parameters to be set.
 Returns True on success, False on failure. 
***************************************************************************/

static BOOL do_section(const char *pszSectionName)
{
	BOOL bRetval;
	BOOL isglobal = ((strwicmp(pszSectionName, GLOBAL_NAME) == 0) ||
			 (strwicmp(pszSectionName, GLOBAL_NAME2) == 0));
	bRetval = False;

	/* if we've just struck a global section, note the fact. */
	bInGlobalSection = isglobal;

	/* check for multiple global sections */
	if (bInGlobalSection) {
		DEBUG(3, ("Processing section \"[%s]\"\n", pszSectionName));
		return (True);
	}

	if (!bInGlobalSection && bGlobalOnly)
		return (True);

	/* if we have a current service, tidy it up before moving on */
	bRetval = True;

	if (iServiceIndex >= 0)
		bRetval = service_ok(iServiceIndex);

	/* if all is still well, move to the next record in the services array */
	if (bRetval) {
		/* We put this here to avoid an odd message order if messages are */
		/* issued by the post-processing of a previous section. */
		DEBUG(2, ("Processing section \"[%s]\"\n", pszSectionName));

		if ((iServiceIndex = add_a_service(&sDefault, pszSectionName))
		    < 0) {
			DEBUG(0, ("Failed to add a new service\n"));
			return (False);
		}
	}

	return (bRetval);
}


/***************************************************************************
 Determine if a partcular base parameter is currentl set to the default value.
***************************************************************************/

static BOOL is_default(int i)
{
	if (!defaults_saved)
		return False;
	switch (parm_table[i].type) {
		case P_LIST:
			return str_list_compare (parm_table[i].def.lvalue, 
						*(char ***)parm_table[i].ptr);
		case P_STRING:
		case P_USTRING:
			return strequal(parm_table[i].def.svalue,
					*(char **)parm_table[i].ptr);
		case P_BOOL:
		case P_BOOLREV:
			return parm_table[i].def.bvalue ==
				*(BOOL *)parm_table[i].ptr;
		case P_CHAR:
			return parm_table[i].def.cvalue ==
				*(char *)parm_table[i].ptr;
		case P_INTEGER:
		case P_OCTAL:
		case P_ENUM:
			return parm_table[i].def.ivalue ==
				*(int *)parm_table[i].ptr;
		case P_SEP:
			break;
	}
	return False;
}

/***************************************************************************
Display the contents of the global structure.
***************************************************************************/

static void dump_globals(FILE *f)
{
	int i;
	struct param_opt *data;
	
	fprintf(f, "# Global parameters\n[global]\n");

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].class == P_GLOBAL &&
		    parm_table[i].ptr &&
		    (i == 0 || (parm_table[i].ptr != parm_table[i - 1].ptr))) {
			if (defaults_saved && is_default(i))
				continue;
			fprintf(f, "\t%s = ", parm_table[i].label);
			print_parameter(&parm_table[i], parm_table[i].ptr, f);
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
 Return True if a local parameter is currently set to the global default.
***************************************************************************/

BOOL lp_is_default(int snum, struct parm_struct *parm)
{
	int pdiff = PTR_DIFF(parm->ptr, &sDefault);

	return equal_parameter(parm->type,
			       ((char *)ServicePtrs[snum]) + pdiff,
			       ((char *)&sDefault) + pdiff);
}

/***************************************************************************
 Display the contents of a single services record.
***************************************************************************/

static void dump_a_service(service * pService, FILE * f)
{
	int i;
	struct param_opt *data;
	
	if (pService != &sDefault)
		fprintf(f, "\n[%s]\n", pService->szService);

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].class == P_LOCAL &&
		    parm_table[i].ptr &&
		    (*parm_table[i].label != '-') &&
		    (i == 0 || (parm_table[i].ptr != parm_table[i - 1].ptr))) {
			int pdiff = PTR_DIFF(parm_table[i].ptr, &sDefault);

			if (pService == &sDefault) {
				if (defaults_saved && is_default(i))
					continue;
			} else {
				if (equal_parameter(parm_table[i].type,
						    ((char *)pService) +
						    pdiff,
						    ((char *)&sDefault) +
						    pdiff))
					continue;
			}

			fprintf(f, "\t%s = ", parm_table[i].label);
			print_parameter(&parm_table[i],
					((char *)pService) + pdiff, f);
			fprintf(f, "\n");
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
 Return info about the next service  in a service. snum==-1 gives the globals.
 Return NULL when out of parameters.
***************************************************************************/

struct parm_struct *lp_next_parameter(int snum, int *i, int allparameters)
{
	if (snum == -1) {
		/* do the globals */
		for (; parm_table[*i].label; (*i)++) {
			if (parm_table[*i].class == P_SEPARATOR)
				return &parm_table[(*i)++];

			if (!parm_table[*i].ptr
			    || (*parm_table[*i].label == '-'))
				continue;

			if ((*i) > 0
			    && (parm_table[*i].ptr ==
				parm_table[(*i) - 1].ptr))
				continue;

			return &parm_table[(*i)++];
		}
	} else {
		service *pService = ServicePtrs[snum];

		for (; parm_table[*i].label; (*i)++) {
			if (parm_table[*i].class == P_SEPARATOR)
				return &parm_table[(*i)++];

			if (parm_table[*i].class == P_LOCAL &&
			    parm_table[*i].ptr &&
			    (*parm_table[*i].label != '-') &&
			    ((*i) == 0 ||
			     (parm_table[*i].ptr !=
			      parm_table[(*i) - 1].ptr)))
			{
				int pdiff =
					PTR_DIFF(parm_table[*i].ptr,
						 &sDefault);

				if (allparameters ||
				    !equal_parameter(parm_table[*i].type,
						     ((char *)pService) +
						     pdiff,
						     ((char *)&sDefault) +
						     pdiff))
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
static void dump_copy_map(BOOL *pcopymap)
{
	int i;
	if (!pcopymap)
		return;

	printf("\n\tNon-Copied parameters:\n");

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].class == P_LOCAL &&
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

BOOL lp_snum_ok(int iService)
{
	return (LP_SNUM_OK(iService) && ServicePtrs[iService]->bAvailable);
}

/***************************************************************************
 Auto-load some home services.
***************************************************************************/

static void lp_add_auto_services(const char *str)
{
	return;
}

/***************************************************************************
 Auto-load one printer.
***************************************************************************/

void lp_add_one_printer(char *name, char *comment)
{
	int printers = lp_servicenumber(PRINTERS_NAME);
	int i;

	if (lp_servicenumber(name) < 0) {
		lp_add_printer(name, printers);
		if ((i = lp_servicenumber(name)) >= 0) {
			string_set(&ServicePtrs[i]->comment, comment);
			ServicePtrs[i]->autoloaded = True;
		}
	}
}

/***************************************************************************
 Announce ourselves as a print server.
***************************************************************************/

void update_server_announce_as_printserver(void)
{
	default_server_announce |= SV_TYPE_PRINTQ_SERVER;	
}

/***************************************************************************
 Have we loaded a services file yet?
***************************************************************************/

BOOL lp_loaded(void)
{
	return (bLoaded);
}

/***************************************************************************
 Unload unused services.
***************************************************************************/

void lp_killunused(struct smbsrv_connection *smb, BOOL (*snumused) (struct smbsrv_connection *, int))
{
	int i;
	for (i = 0; i < iNumServices; i++) {
		if (!VALID(i))
			continue;

		if (!snumused || !snumused(smb, i)) {
			ServicePtrs[i]->valid = False;
			free_service(ServicePtrs[i]);
		}
	}
}

/***************************************************************************
 Unload a service.
***************************************************************************/

void lp_killservice(int iServiceIn)
{
	if (VALID(iServiceIn)) {
		ServicePtrs[iServiceIn]->valid = False;
		free_service(ServicePtrs[iServiceIn]);
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
		if (i > 0 && parm_table[i].ptr == parm_table[i - 1].ptr)
			continue;
		switch (parm_table[i].type) {
			case P_LIST:
				str_list_copy(&(parm_table[i].def.lvalue),
					    *(const char ***)parm_table[i].ptr);
				break;
			case P_STRING:
			case P_USTRING:
				if (parm_table[i].ptr) {
					parm_table[i].def.svalue = strdup(*(char **)parm_table[i].ptr);
				} else {
					parm_table[i].def.svalue = NULL;
				}
				break;
			case P_BOOL:
			case P_BOOLREV:
				parm_table[i].def.bvalue =
					*(BOOL *)parm_table[i].ptr;
				break;
			case P_CHAR:
				parm_table[i].def.cvalue =
					*(char *)parm_table[i].ptr;
				break;
			case P_INTEGER:
			case P_OCTAL:
			case P_ENUM:
				parm_table[i].def.ivalue =
					*(int *)parm_table[i].ptr;
				break;
			case P_SEP:
				break;
		}
	}
	defaults_saved = True;
}

/*******************************************************************
 Set the server type we will announce as via nmbd.
********************************************************************/

static void set_server_role(void)
{
	server_role = ROLE_STANDALONE;

	switch (lp_security()) {
		case SEC_SHARE:
			if (lp_domain_logons())
				DEBUG(0, ("Server's Role (logon server) conflicts with share-level security\n"));
			break;
		case SEC_SERVER:
		case SEC_DOMAIN:
		case SEC_ADS:
			if (lp_domain_logons()) {
				server_role = ROLE_DOMAIN_PDC;
				break;
			}
			server_role = ROLE_DOMAIN_MEMBER;
			break;
		case SEC_USER:
			if (lp_domain_logons()) {

				if (Globals.bDomainMaster) /* auto or yes */ 
					server_role = ROLE_DOMAIN_PDC;
				else
					server_role = ROLE_DOMAIN_BDC;
			}
			break;
		default:
			DEBUG(0, ("Server's Role undefined due to unknown security mode\n"));
			break;
	}

	DEBUG(10, ("set_server_role: role = "));

	switch(server_role) {
	case ROLE_STANDALONE:
		DEBUGADD(10, ("ROLE_STANDALONE\n"));
		break;
	case ROLE_DOMAIN_MEMBER:
		DEBUGADD(10, ("ROLE_DOMAIN_MEMBER\n"));
		break;
	case ROLE_DOMAIN_BDC:
		DEBUGADD(10, ("ROLE_DOMAIN_BDC\n"));
		break;
	case ROLE_DOMAIN_PDC:
		DEBUGADD(10, ("ROLE_DOMAIN_PDC\n"));
		break;
	}
}

/***************************************************************************
 Load the services array from the services file. Return True on success, 
 False on failure.
***************************************************************************/

BOOL lp_load(const char *pszFname, BOOL global_only, BOOL save_defaults,
	     BOOL add_ipc)
{
	pstring n2;
	BOOL bRetval;
	struct param_opt *data;

	pstrcpy(n2, pszFname);
	standard_sub_basic(n2,sizeof(n2));

	add_to_file_list(pszFname, n2);

	bRetval = False;

	DEBUG(2, ("lp_load: refreshing parameters from %s\n", pszFname));
	
	bInGlobalSection = True;
	bGlobalOnly = global_only;

	init_globals();

	if (save_defaults)
	{
		lp_save_defaults();
	}

	if (Globals.param_opt != NULL) {
		struct param_opt *next;
		for (data=Globals.param_opt; data; data=next) {
			next = data->next;
			if (data->flags & FLAG_CMDLINE) continue;
			free(data->key);
			free(data->value);
			DLIST_REMOVE(Globals.param_opt, data);
			free(data);
		}
	}
	
	/* We get sections first, so have to start 'behind' to make up */
	iServiceIndex = -1;
	bRetval = pm_process(n2, do_section, do_parameter);

	/* finish up the last section */
	DEBUG(4, ("pm_process() returned %s\n", BOOLSTR(bRetval)));
	if (bRetval)
		if (iServiceIndex >= 0)
			bRetval = service_ok(iServiceIndex);

	lp_add_auto_services(lp_auto_services());

	if (add_ipc) {
		/* When 'restrict anonymous = 2' guest connections to ipc$
		   are denied */
		lp_add_ipc("IPC$", (lp_restrict_anonymous() < 2));
		lp_add_ipc("ADMIN$", False);
	}

	set_server_role();
	set_default_server_announce_type();

	bLoaded = True;

	/* Now we check bWINSsupport and set szWINSserver to 127.0.0.1 */
	/* if bWINSsupport is true and we are in the client            */
	if (in_client && Globals.bWINSsupport) {
		lp_do_parameter(-1, "wins server", "127.0.0.1");
	}

	init_iconv();

	return (bRetval);
}

/***************************************************************************
 Reset the max number of services.
***************************************************************************/

void lp_resetnumservices(void)
{
	iNumServices = 0;
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

void lp_dump(FILE *f, BOOL show_defaults, int maxtoprint)
{
	int iService;

	if (show_defaults)
		defaults_saved = False;

	dump_globals(f);

	dump_a_service(&sDefault, f);

	for (iService = 0; iService < maxtoprint; iService++)
		lp_dump_one(f, show_defaults, iService);
}

/***************************************************************************
Display the contents of one service in human-readable form.
***************************************************************************/

void lp_dump_one(FILE * f, BOOL show_defaults, int snum)
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
 
 
	for (iService = iNumServices - 1; iService >= 0; iService--) {
		if (VALID(iService) && ServicePtrs[iService]->szService) {
			/*
			 * The substitution here is used to support %U is
			 * service names
			 */
			fstrcpy(serviceName, ServicePtrs[iService]->szService);
			standard_sub_basic(serviceName,sizeof(serviceName));
			if (strequal(serviceName, pszServiceName))
				break;
		}
	}

	if (iService < 0)
		DEBUG(7,("lp_servicenumber: couldn't find %s\n", pszServiceName));

	return (iService);
}

/*******************************************************************
 A useful volume label function. 
********************************************************************/
const char *volume_label(int snum)
{
	const char *ret = lp_volume(snum);
	if (!*ret)
		return lp_servicename(snum);
	return (ret);
}


/*******************************************************************
 Set the server type we will announce as via nmbd.
********************************************************************/

static void set_default_server_announce_type(void)
{
	default_server_announce = 0;
	default_server_announce |= SV_TYPE_WORKSTATION;
	default_server_announce |= SV_TYPE_SERVER;
	default_server_announce |= SV_TYPE_SERVER_UNIX;

	switch (lp_announce_as()) {
		case ANNOUNCE_AS_NT_SERVER:
			default_server_announce |= SV_TYPE_SERVER_NT;
			/* fall through... */
		case ANNOUNCE_AS_NT_WORKSTATION:
			default_server_announce |= SV_TYPE_NT;
			break;
		case ANNOUNCE_AS_WIN95:
			default_server_announce |= SV_TYPE_WIN95_PLUS;
			break;
		case ANNOUNCE_AS_WFW:
			default_server_announce |= SV_TYPE_WFW;
			break;
		default:
			break;
	}

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
}

/***********************************************************
 returns role of Samba server
************************************************************/

int lp_server_role(void)
{
	return server_role;
}

/***********************************************************
 If we are PDC then prefer us as DMB
************************************************************/

BOOL lp_domain_master(void)
{
	if (Globals.bDomainMaster == Auto)
		return (lp_server_role() == ROLE_DOMAIN_PDC);

	return Globals.bDomainMaster;
}

/***********************************************************
 If we are DMB then prefer us as LMB
************************************************************/

BOOL lp_preferred_master(void)
{
	if (Globals.bPreferredMaster == Auto)
		return (lp_local_master() && lp_domain_master());

	return Globals.bPreferredMaster;
}

/*******************************************************************
 Remove a service.
********************************************************************/

void lp_remove_service(int snum)
{
	ServicePtrs[snum]->valid = False;
}

/*******************************************************************
 Copy a service.
********************************************************************/

void lp_copy_service(int snum, const char *new_name)
{
	const char *oldname = lp_servicename(snum);
	do_section(new_name);
	if (snum >= 0) {
		snum = lp_servicenumber(new_name);
		if (snum >= 0)
			lp_do_parameter(snum, "copy", oldname);
	}
}


/*******************************************************************
 Get the default server type we will announce as via nmbd.
********************************************************************/

int lp_default_server_announce(void)
{
	return default_server_announce;
}

/*******************************************************************
 Split the announce version into major and minor numbers.
********************************************************************/

int lp_major_announce_version(void)
{
	static BOOL got_major = False;
	static int major_version = DEFAULT_MAJOR_VERSION;
	const char *vers;
	char *p;

	if (got_major)
		return major_version;

	got_major = True;
	if ((vers = lp_announce_version()) == NULL)
		return major_version;

	if ((p = strchr_m(vers, '.')) == 0)
		return major_version;

	*p = '\0';
	major_version = atoi(vers);
	return major_version;
}

int lp_minor_announce_version(void)
{
	static BOOL got_minor = False;
	static int minor_version = DEFAULT_MINOR_VERSION;
	const char *vers;
	char *p;

	if (got_minor)
		return minor_version;

	got_minor = True;
	if ((vers = lp_announce_version()) == NULL)
		return minor_version;

	if ((p = strchr_m(vers, '.')) == 0)
		return minor_version;

	p++;
	minor_version = atoi(p);
	return minor_version;
}

const char *lp_printername(int snum)
{
	const char *ret = _lp_printername(snum);
	if (ret == NULL || (ret != NULL && *ret == '\0'))
		ret = lp_const_servicename(snum);

	return ret;
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
