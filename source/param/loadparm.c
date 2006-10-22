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
#include "version.h"
#include "dynconfig.h"
#include "pstring.h"
#include "system/time.h"
#include "system/locale.h"
#include "system/network.h" /* needed for TCP_NODELAY */
#include "librpc/gen_ndr/svcctl.h"
#include "librpc/gen_ndr/samr.h"
#include "smb_server/smb_server.h"
#include "libcli/raw/signing.h"
#include "lib/util/dlinklist.h"
#include "param/loadparm.h"

static BOOL bLoaded = False;

#define standard_sub_basic(str,len)

/* some helpful bits */
#define LP_SNUM_OK(i) (((i) >= 0) && ((i) < iNumServices) && ServicePtrs[(i)]->valid)
#define VALID(i) ServicePtrs[i]->valid

static BOOL do_parameter(const char *, const char *, void *);
static BOOL do_parameter_var(const char *pszParmName, const char *fmt, ...);

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
	int server_role;

	char **smb_ports;
	char *dos_charset;
	char *unix_charset;
	char *ncalrpc_dir;
	char *display_charset;
	char *szLockDir;
	char *szModulesDir;
	char *szPidDir;
	char *szSetupDir;
	char *szServerString;
	char *szAutoServices;
	char *szPasswdChat;
	char *szConfigFile;
	char *szShareBackend;
	char *szSAM_URL;
	char *szSPOOLSS_URL;
	char *szWINS_CONFIG_URL;
	char *szWINS_URL;
	char *szPrivateDir;
	char **jsInclude;
	char *jsonrpcServicesDir;
	char **szPasswordServers;
	char *szSocketOptions;
	char *szRealm;
	char **szWINSservers;
	char **szInterfaces;
	char *szSocketAddress;
	char *szAnnounceVersion;	/* This is initialised in init_globals */
	char *szWorkgroup;
	char *szNetbiosName;
	char **szNetbiosAliases;
	char *szNetbiosScope;
	char *szDomainOtherSIDs;
	char **szNameResolveOrder;
	char **dcerpc_ep_servers;
	char **server_services;
	char *ntptr_providor;
	char *szWinbindSeparator;
	char *szWinbinddSocketDirectory;
	int bWinbindSealedPipes;
	char *swat_directory;
	int tls_enabled;
	char *tls_keyfile;
	char *tls_certfile;
	char *tls_cafile;
	char *tls_crlfile;
	char *tls_dhpfile;
	int max_mux;
	int max_xmit;
	int pwordlevel;
	int srv_maxprotocol;
	int srv_minprotocol;
	int cli_maxprotocol;
	int cli_minprotocol;
	int security;
	char **AuthMethods;
	int paranoid_server_security;
	int max_wins_ttl;
	int min_wins_ttl;
	int announce_as;	/* This is initialised in init_globals */
	int nbt_port;
	int dgram_port;
	int cldap_port;
	int krb5_port;
	int kpasswd_port;
	int web_port;
	char *socket_options;
	int bWINSsupport;
	int bWINSdnsProxy;
	char *szWINSHook; 
	int bLocalMaster;
	int bPreferredMaster;
	int bEncryptPasswords;
	int bNullPasswords;
	int bObeyPamRestrictions;
	int bLargeReadwrite;
	int bReadRaw;
	int bWriteRaw;
	int bTimeServer;
	int bBindInterfacesOnly;
	int bNTSmbSupport;
	int bNTStatusSupport;
	int bLanmanAuth;
	int bNTLMAuth;
	int bUseSpnego;
	int  server_signing;
	int  client_signing;
	int bClientPlaintextAuth;
	int bClientLanManAuth;
	int bClientNTLMv2Auth;
	int client_use_spnego_principal;
	int bHostMSDfs;
	int bUnicode;
	int bUnixExtensions;
	int bDisableNetbios;
	int bRpcBigEndian;
	struct param_opt *param_opt;
}
global;

static global Globals;

/* 
 * This structure describes a single service. 
 */
typedef struct
{
	int valid;
	char *szService;
	char *szPath;
	char *szCopy;
	char *szInclude;
	char *szPrintername;
	char **szHostsallow;
	char **szHostsdeny;
	char *comment;
	char *volume;
	char *fstype;
	char **ntvfs_handler;
	int iMaxPrintJobs;
	int iMaxConnections;
	int iCSCPolicy;
	int bAvailable;
	int bBrowseable;
	int bRead_only;
	int bPrint_ok;
	int bMap_system;
	int bMap_hidden;
	int bMap_archive;
	int bStrictLocking;
	int *copymap;
	int bMSDfsRoot;
	int bStrictSync;
	int bCIFileSystem;
	struct param_opt *param_opt;

	char dummy[3];		/* for alignment */
}
service;


/* This is a default service used to prime a services structure */
static service sDefault = {
	True,			/* valid */
	NULL,			/* szService */
	NULL,			/* szPath */
	NULL,			/* szCopy */
	NULL,			/* szInclude */
	NULL,			/* szPrintername */
	NULL,			/* szHostsallow */
	NULL,			/* szHostsdeny */
	NULL,			/* comment */
	NULL,			/* volume */
	NULL,			/* fstype */
	NULL,                   /* ntvfs_handler */
	1000,			/* iMaxPrintJobs */
	0,			/* iMaxConnections */
	0,			/* iCSCPolicy */
	True,			/* bAvailable */
	True,			/* bBrowseable */
	True,			/* bRead_only */
	False,			/* bPrint_ok */
	False,			/* bMap_system */
	False,			/* bMap_hidden */
	True,			/* bMap_archive */
	True,			/* bStrictLocking */
	NULL,			/* copymap */
	False,			/* bMSDfsRoot */
	False,			/* bStrictSync */
	False,			/* bCIFileSystem */
	NULL,			/* Parametric options */

	""			/* dummy */
};

/* local variables */
static service **ServicePtrs = NULL;
static int iNumServices = 0;
static int iServiceIndex = 0;
static BOOL bInGlobalSection = True;
static int default_server_announce;

#define NUMPARAMETERS (sizeof(parm_table) / sizeof(struct parm_struct))

/* prototypes for the special type handlers */
static BOOL handle_include(const char *pszParmValue, char **ptr);
static BOOL handle_copy(const char *pszParmValue, char **ptr);

static void set_default_server_announce_type(void);

static const struct enum_list enum_protocol[] = {
	{PROTOCOL_SMB2, "SMB2"},
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
	{SMB_SIGNING_REQUIRED, "required"},
	{SMB_SIGNING_REQUIRED, "mandatory"},
	{SMB_SIGNING_REQUIRED, "force"},
	{SMB_SIGNING_REQUIRED, "forced"},
	{SMB_SIGNING_REQUIRED, "enforced"},
	{SMB_SIGNING_AUTO, "auto"},
	{-1, NULL}
};

static const struct enum_list enum_server_role[] = {
	{ROLE_STANDALONE, "standalone"},
	{ROLE_DOMAIN_MEMBER, "member server"},
	{ROLE_DOMAIN_BDC, "bdc"},
	{ROLE_DOMAIN_PDC, "pdc"},
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

	{"server role", P_ENUM, P_GLOBAL, &Globals.server_role, NULL, enum_server_role, FLAG_BASIC},

	{"dos charset", P_STRING, P_GLOBAL, &Globals.dos_charset, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"unix charset", P_STRING, P_GLOBAL, &Globals.unix_charset, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ncalrpc dir", P_STRING, P_GLOBAL, &Globals.ncalrpc_dir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"display charset", P_STRING, P_GLOBAL, &Globals.display_charset, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"comment", P_STRING, P_LOCAL, &sDefault.comment, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"path", P_STRING, P_LOCAL, &sDefault.szPath, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"directory", P_STRING, P_LOCAL, &sDefault.szPath, NULL, NULL, FLAG_HIDE},
	{"workgroup", P_USTRING, P_GLOBAL, &Globals.szWorkgroup, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"realm", P_STRING, P_GLOBAL, &Globals.szRealm, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"netbios name", P_USTRING, P_GLOBAL, &Globals.szNetbiosName, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"netbios aliases", P_LIST, P_GLOBAL, &Globals.szNetbiosAliases, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"netbios scope", P_USTRING, P_GLOBAL, &Globals.szNetbiosScope, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"server string", P_STRING, P_GLOBAL, &Globals.szServerString, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED  | FLAG_DEVELOPER},
	{"interfaces", P_LIST, P_GLOBAL, &Globals.szInterfaces, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"bind interfaces only", P_BOOL, P_GLOBAL, &Globals.bBindInterfacesOnly, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"ntvfs handler", P_LIST, P_LOCAL, &sDefault.ntvfs_handler, NULL, NULL, FLAG_ADVANCED},
	{"ntptr providor", P_STRING, P_GLOBAL, &Globals.ntptr_providor, NULL, NULL, FLAG_ADVANCED},
	{"dcerpc endpoint servers", P_LIST, P_GLOBAL, &Globals.dcerpc_ep_servers, NULL, NULL, FLAG_ADVANCED},
	{"server services", P_LIST, P_GLOBAL, &Globals.server_services, NULL, NULL, FLAG_ADVANCED},

	{"Security Options", P_SEP, P_SEPARATOR},
	
	{"security", P_ENUM, P_GLOBAL, &Globals.security, NULL, enum_security, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"auth methods", P_LIST, P_GLOBAL, &Globals.AuthMethods, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"encrypt passwords", P_BOOL, P_GLOBAL, &Globals.bEncryptPasswords, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"null passwords", P_BOOL, P_GLOBAL, &Globals.bNullPasswords, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"obey pam restrictions", P_BOOL, P_GLOBAL, &Globals.bObeyPamRestrictions, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"password server", P_LIST, P_GLOBAL, &Globals.szPasswordServers, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"sam database", P_STRING, P_GLOBAL, &Globals.szSAM_URL, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"spoolss database", P_STRING, P_GLOBAL, &Globals.szSPOOLSS_URL, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"wins config database", P_STRING, P_GLOBAL, &Globals.szWINS_CONFIG_URL, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"wins database", P_STRING, P_GLOBAL, &Globals.szWINS_URL, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"private dir", P_STRING, P_GLOBAL, &Globals.szPrivateDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"passwd chat", P_STRING, P_GLOBAL, &Globals.szPasswdChat, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"password level", P_INTEGER, P_GLOBAL, &Globals.pwordlevel, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"lanman auth", P_BOOL, P_GLOBAL, &Globals.bLanmanAuth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"ntlm auth", P_BOOL, P_GLOBAL, &Globals.bNTLMAuth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"client NTLMv2 auth", P_BOOL, P_GLOBAL, &Globals.bClientNTLMv2Auth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"client lanman auth", P_BOOL, P_GLOBAL, &Globals.bClientLanManAuth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"client plaintext auth", P_BOOL, P_GLOBAL, &Globals.bClientPlaintextAuth, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"client use spnego principal", P_BOOL, P_GLOBAL, &Globals.client_use_spnego_principal, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"read only", P_BOOL, P_LOCAL, &sDefault.bRead_only, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE},

	{"hosts allow", P_LIST, P_LOCAL, &sDefault.szHostsallow, NULL, NULL, FLAG_GLOBAL | FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"hosts deny", P_LIST, P_LOCAL, &sDefault.szHostsdeny, NULL, NULL, FLAG_GLOBAL | FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},

	{"Logging Options", P_SEP, P_SEPARATOR},

	{"log level", P_INTEGER, P_GLOBAL, &DEBUGLEVEL, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"debuglevel", P_INTEGER, P_GLOBAL, &DEBUGLEVEL, NULL, NULL, FLAG_HIDE},
	{"log file", P_STRING, P_GLOBAL, &logfile, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"Protocol Options", P_SEP, P_SEPARATOR},
	
	{"smb ports", P_LIST, P_GLOBAL, &Globals.smb_ports, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"nbt port", P_INTEGER, P_GLOBAL, &Globals.nbt_port, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"dgram port", P_INTEGER, P_GLOBAL, &Globals.dgram_port, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"cldap port", P_INTEGER, P_GLOBAL, &Globals.cldap_port, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"krb5 port", P_INTEGER, P_GLOBAL, &Globals.krb5_port, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"kpasswd port", P_INTEGER, P_GLOBAL, &Globals.kpasswd_port, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"web port", P_INTEGER, P_GLOBAL, &Globals.web_port, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"tls enabled", P_BOOL, P_GLOBAL, &Globals.tls_enabled, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"tls keyfile", P_STRING, P_GLOBAL, &Globals.tls_keyfile, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"tls certfile", P_STRING, P_GLOBAL, &Globals.tls_certfile, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"tls cafile", P_STRING, P_GLOBAL, &Globals.tls_cafile, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"tls crlfile", P_STRING, P_GLOBAL, &Globals.tls_crlfile, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"tls dh params file", P_STRING, P_GLOBAL, &Globals.tls_dhpfile, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"swat directory", P_STRING, P_GLOBAL, &Globals.swat_directory, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"large readwrite", P_BOOL, P_GLOBAL, &Globals.bLargeReadwrite, NULL, NULL, FLAG_DEVELOPER},
	{"server max protocol", P_ENUM, P_GLOBAL, &Globals.srv_maxprotocol, NULL, enum_protocol, FLAG_DEVELOPER},
	{"server min protocol", P_ENUM, P_GLOBAL, &Globals.srv_minprotocol, NULL, enum_protocol, FLAG_DEVELOPER},
	{"client max protocol", P_ENUM, P_GLOBAL, &Globals.cli_maxprotocol, NULL, enum_protocol, FLAG_DEVELOPER},
	{"client min protocol", P_ENUM, P_GLOBAL, &Globals.cli_minprotocol, NULL, enum_protocol, FLAG_DEVELOPER},
	{"unicode", P_BOOL, P_GLOBAL, &Globals.bUnicode, NULL, NULL, FLAG_DEVELOPER},
	{"read raw", P_BOOL, P_GLOBAL, &Globals.bReadRaw, NULL, NULL, FLAG_DEVELOPER},
	{"write raw", P_BOOL, P_GLOBAL, &Globals.bWriteRaw, NULL, NULL, FLAG_DEVELOPER},
	{"disable netbios", P_BOOL, P_GLOBAL, &Globals.bDisableNetbios, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"nt status support", P_BOOL, P_GLOBAL, &Globals.bNTStatusSupport, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"announce version", P_STRING, P_GLOBAL, &Globals.szAnnounceVersion, NULL, NULL, FLAG_DEVELOPER},
	{"announce as", P_ENUM, P_GLOBAL, &Globals.announce_as, NULL, enum_announce_as, FLAG_DEVELOPER},
	{"max mux", P_INTEGER, P_GLOBAL, &Globals.max_mux, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"max xmit", P_BYTES, P_GLOBAL, &Globals.max_xmit, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"name resolve order", P_LIST, P_GLOBAL, &Globals.szNameResolveOrder, NULL, NULL, FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"max wins ttl", P_INTEGER, P_GLOBAL, &Globals.max_wins_ttl, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"min wins ttl", P_INTEGER, P_GLOBAL, &Globals.min_wins_ttl, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"time server", P_BOOL, P_GLOBAL, &Globals.bTimeServer, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"unix extensions", P_BOOL, P_GLOBAL, &Globals.bUnixExtensions, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"use spnego", P_BOOL, P_GLOBAL, &Globals.bUseSpnego, NULL, NULL, FLAG_DEVELOPER},
	{"server signing", P_ENUM, P_GLOBAL, &Globals.server_signing, NULL, enum_smb_signing_vals, FLAG_ADVANCED}, 
	{"client signing", P_ENUM, P_GLOBAL, &Globals.client_signing, NULL, enum_smb_signing_vals, FLAG_ADVANCED}, 
	{"rpc big endian", P_BOOL, P_GLOBAL, &Globals.bRpcBigEndian, NULL, NULL, FLAG_DEVELOPER},

	{"Tuning Options", P_SEP, P_SEPARATOR},
		
	{"max connections", P_INTEGER, P_LOCAL, &sDefault.iMaxConnections, NULL, NULL, FLAG_SHARE},
	{"paranoid server security", P_BOOL, P_GLOBAL, &Globals.paranoid_server_security, NULL, NULL, FLAG_DEVELOPER},
	{"socket options", P_STRING, P_GLOBAL, &Globals.socket_options, NULL, NULL, FLAG_DEVELOPER},

	{"strict sync", P_BOOL, P_LOCAL, &sDefault.bStrictSync, NULL, NULL, FLAG_ADVANCED | FLAG_SHARE}, 
	{"case insensitive filesystem", P_BOOL, P_LOCAL, &sDefault.bCIFileSystem, NULL, NULL, FLAG_ADVANCED | FLAG_SHARE}, 

	{"Printing Options", P_SEP, P_SEPARATOR},
	
	{"max print jobs", P_INTEGER, P_LOCAL, &sDefault.iMaxPrintJobs, NULL, NULL, FLAG_PRINT},
	{"printable", P_BOOL, P_LOCAL, &sDefault.bPrint_ok, NULL, NULL, FLAG_PRINT},
	{"print ok", P_BOOL, P_LOCAL, &sDefault.bPrint_ok, NULL, NULL, FLAG_HIDE},
	
	{"printer name", P_STRING, P_LOCAL, &sDefault.szPrintername, NULL, NULL, FLAG_PRINT},
	{"printer", P_STRING, P_LOCAL, &sDefault.szPrintername, NULL, NULL, FLAG_HIDE},

	{"Filename Handling", P_SEP, P_SEPARATOR},
	
	{"map system", P_BOOL, P_LOCAL, &sDefault.bMap_system, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"map hidden", P_BOOL, P_LOCAL, &sDefault.bMap_hidden, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},
	{"map archive", P_BOOL, P_LOCAL, &sDefault.bMap_archive, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},

	{"Domain Options", P_SEP, P_SEPARATOR},
	
	{"Logon Options", P_SEP, P_SEPARATOR},


	{"Browse Options", P_SEP, P_SEPARATOR},
	
	{"preferred master", P_ENUM, P_GLOBAL, &Globals.bPreferredMaster, NULL, enum_bool_auto, FLAG_BASIC | FLAG_ADVANCED | FLAG_DEVELOPER},
	{"prefered master", P_ENUM, P_GLOBAL, &Globals.bPreferredMaster, NULL, enum_bool_auto, FLAG_HIDE},
	{"local master", P_BOOL, P_GLOBAL, &Globals.bLocalMaster, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_DEVELOPER},
	{"browseable", P_BOOL, P_LOCAL, &sDefault.bBrowseable, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT | FLAG_DEVELOPER},
	{"browsable", P_BOOL, P_LOCAL, &sDefault.bBrowseable, NULL, NULL, FLAG_HIDE},

	{"WINS Options", P_SEP, P_SEPARATOR},
	
	{"wins server", P_LIST, P_GLOBAL, &Globals.szWINSservers, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"wins support", P_BOOL, P_GLOBAL, &Globals.bWINSsupport, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"dns proxy", P_BOOL, P_GLOBAL, &Globals.bWINSdnsProxy, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_WIZARD | FLAG_DEVELOPER},
	{"wins hook", P_STRING, P_GLOBAL, &Globals.szWINSHook, NULL, NULL, FLAG_ADVANCED}, 

	{"Locking Options", P_SEP, P_SEPARATOR},
	
	{"csc policy", P_ENUM, P_LOCAL, &sDefault.iCSCPolicy, NULL, enum_csc_policy, FLAG_SHARE | FLAG_GLOBAL},
	
	{"strict locking", P_BOOL, P_LOCAL, &sDefault.bStrictLocking, NULL, NULL, FLAG_SHARE | FLAG_GLOBAL},

	{"Miscellaneous Options", P_SEP, P_SEPARATOR},
	
	{"config file", P_STRING, P_GLOBAL, &Globals.szConfigFile, NULL, NULL, FLAG_HIDE},
	{"share backend", P_STRING, P_GLOBAL, &Globals.szShareBackend, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"preload", P_STRING, P_GLOBAL, &Globals.szAutoServices, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"auto services", P_STRING, P_GLOBAL, &Globals.szAutoServices, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"lock dir", P_STRING, P_GLOBAL, &Globals.szLockDir, NULL, NULL, FLAG_HIDE}, 
	{"lock directory", P_STRING, P_GLOBAL, &Globals.szLockDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"modules dir", P_STRING, P_GLOBAL, &Globals.szModulesDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"pid directory", P_STRING, P_GLOBAL, &Globals.szPidDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER}, 
	{"js include", P_LIST, P_GLOBAL, &Globals.jsInclude, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"jsonrpc services directory", P_STRING, P_GLOBAL, &Globals.jsonrpcServicesDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"setup directory", P_STRING, P_GLOBAL, &Globals.szSetupDir, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	
	{"socket address", P_STRING, P_GLOBAL, &Globals.szSocketAddress, NULL, NULL, FLAG_DEVELOPER},
	{"-valid", P_BOOL, P_LOCAL, &sDefault.valid, NULL, NULL, FLAG_HIDE},
	
	{"copy", P_STRING, P_LOCAL, &sDefault.szCopy, handle_copy, NULL, FLAG_HIDE},
	{"include", P_STRING, P_LOCAL, &sDefault.szInclude, handle_include, NULL, FLAG_HIDE},
	
	{"available", P_BOOL, P_LOCAL, &sDefault.bAvailable, NULL, NULL, FLAG_BASIC | FLAG_ADVANCED | FLAG_SHARE | FLAG_PRINT},
	{"volume", P_STRING, P_LOCAL, &sDefault.volume, NULL, NULL, FLAG_SHARE },
	{"fstype", P_STRING, P_LOCAL, &sDefault.fstype, NULL, NULL, FLAG_SHARE},

	{"panic action", P_STRING, P_GLOBAL, &panic_action, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},

	{"msdfs root", P_BOOL, P_LOCAL, &sDefault.bMSDfsRoot, NULL, NULL, FLAG_SHARE},
	{"host msdfs", P_BOOL, P_GLOBAL, &Globals.bHostMSDfs, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER},
	{"winbind separator", P_STRING, P_GLOBAL, &Globals.szWinbindSeparator, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER },
	{"winbindd socket directory", P_STRING, P_GLOBAL, &Globals.szWinbinddSocketDirectory, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER },
	{"winbind sealed pipes", P_BOOL, P_GLOBAL, &Globals.bWinbindSealedPipes, NULL, NULL, FLAG_ADVANCED | FLAG_DEVELOPER },

	{NULL, P_BOOL, P_NONE, NULL, NULL, NULL, 0}
};


/*
  return the parameter table
*/
struct parm_struct *lp_parm_table(void)
{
	return parm_table;
}

/***************************************************************************
 Initialise the global parameter structure.
***************************************************************************/
static void init_globals(void)
{
	int i;
	char *myname;

	DEBUG(3, ("Initialising global parameters\n"));

	for (i = 0; parm_table[i].label; i++) {
		if ((parm_table[i].type == P_STRING ||
		     parm_table[i].type == P_USTRING) &&
		    parm_table[i].ptr &&
		    !(parm_table[i].flags & FLAG_CMDLINE)) {
			string_set(parm_table[i].ptr, "");
		}
	}

	do_parameter("config file", dyn_CONFIGFILE, NULL);

	do_parameter("share backend", "classic", NULL);
	
	do_parameter("server role", "standalone", NULL);

	/* options that can be set on the command line must be initialised via
	   the slower do_parameter() to ensure that FLAG_CMDLINE is obeyed */
#ifdef TCP_NODELAY
	do_parameter("socket options", "TCP_NODELAY", NULL);
#endif
	do_parameter("workgroup", DEFAULT_WORKGROUP, NULL);
	myname = get_myname();
	do_parameter("netbios name", myname, NULL);
	SAFE_FREE(myname);
	do_parameter("name resolve order", "lmhosts wins host bcast", NULL);

	do_parameter("fstype", FSTYPE_STRING, NULL);
	do_parameter("ntvfs handler", "unixuid default", NULL);
	do_parameter("max connections", "-1", NULL);

	do_parameter("dcerpc endpoint servers", "epmapper srvsvc wkssvc rpcecho samr netlogon lsarpc spoolss drsuapi winreg dssetup unixinfo", NULL);
	do_parameter("server services", "smb rpc nbt wrepl ldap cldap web kdc winbind", NULL);
	do_parameter("ntptr providor", "simple_ldb", NULL);
	do_parameter("auth methods", "anonymous sam_ignoredomain", NULL);
	do_parameter("private dir", dyn_PRIVATE_DIR, NULL);
	do_parameter("sam database", "sam.ldb", NULL);
	do_parameter("spoolss database", "spoolss.ldb", NULL);
	do_parameter("wins config database", "wins_config.ldb", NULL);
	do_parameter("wins database", "wins.ldb", NULL);
	do_parameter("registry:HKEY_LOCAL_MACHINE", "hklm.ldb", NULL);

	/* This hive should be dynamically generated by Samba using
	   data from the sam, but for the moment leave it in a tdb to
	   keep regedt32 from popping up an annoying dialog. */
	do_parameter("registry:HKEY_USERS", "hku.ldb", NULL);
	
	/* using UTF8 by default allows us to support all chars */
	do_parameter("unix charset", "UTF8", NULL);

	/* Use codepage 850 as a default for the dos character set */
	do_parameter("dos charset", "CP850", NULL);

	/*
	 * Allow the default PASSWD_CHAT to be overridden in local.h.
	 */
	do_parameter("passwd chat", DEFAULT_PASSWD_CHAT, NULL);

	do_parameter("pid directory", dyn_PIDDIR, NULL);
	do_parameter("lock dir", dyn_LOCKDIR, NULL);
	do_parameter("modules dir", dyn_MODULESDIR, NULL);
	do_parameter("ncalrpc dir", dyn_NCALRPCDIR, NULL);

	do_parameter("socket address", "0.0.0.0", NULL);
	do_parameter_var("server string", "Samba %s", SAMBA_VERSION_STRING);

	do_parameter_var("announce version", "%d.%d", 
			 DEFAULT_MAJOR_VERSION,
			 DEFAULT_MINOR_VERSION);

	do_parameter("password server", "*", NULL);

	do_parameter("max mux", "50", NULL);
	do_parameter("max xmit", "12288", NULL);
	do_parameter("password level", "0", NULL);
	do_parameter("LargeReadwrite", "True", NULL);
	do_parameter("server min protocol", "CORE", NULL);
	do_parameter("server max protocol", "NT1", NULL);
	do_parameter("client min protocol", "CORE", NULL);
	do_parameter("client max protocol", "NT1", NULL);
	do_parameter("security", "USER", NULL);
	do_parameter("paranoid server security", "True", NULL);
	do_parameter("EncryptPasswords", "True", NULL);
	do_parameter("ReadRaw", "True", NULL);
	do_parameter("WriteRaw", "True", NULL);
	do_parameter("NullPasswords", "False", NULL);
	do_parameter("ObeyPamRestrictions", "False", NULL);
	do_parameter("announce as", "NT SERVER", NULL);

	do_parameter("TimeServer", "False", NULL);
	do_parameter("BindInterfacesOnly", "False", NULL);
	do_parameter("Unicode", "True", NULL);
	do_parameter("ClientLanManAuth", "True", NULL);
	do_parameter("LanmanAuth", "True", NULL);
	do_parameter("NTLMAuth", "True", NULL);
	do_parameter("client use spnego principal", "False", NULL);
	
	do_parameter("UnixExtensions", "False", NULL);

	do_parameter("PreferredMaster", "Auto", NULL);
	do_parameter("LocalMaster", "True", NULL);

	do_parameter("wins support", "False", NULL);
	do_parameter("dns proxy", "True", NULL);

	do_parameter("winbind separator", "\\", NULL);
	do_parameter("winbind sealed pipes", "True", NULL);
	do_parameter("winbindd socket directory", dyn_WINBINDD_SOCKET_DIR, NULL);

	do_parameter("client signing", "Yes", NULL);
	do_parameter("server signing", "auto", NULL);

	do_parameter("use spnego", "True", NULL);

	do_parameter("smb ports", "445 139", NULL);
	do_parameter("nbt port", "137", NULL);
	do_parameter("dgram port", "138", NULL);
	do_parameter("cldap port", "389", NULL);
	do_parameter("krb5 port", "88", NULL);
	do_parameter("kpasswd port", "464", NULL);
	do_parameter("web port", "901", NULL);
	do_parameter("swat directory", dyn_SWATDIR, NULL);
	do_parameter("jsonrpc services directory", dyn_SERVICESDIR, NULL);

	do_parameter("nt status support", "True", NULL);

	do_parameter("max wins ttl", "518400", NULL); /* 6 days */
	do_parameter("min wins ttl", "10", NULL);

	do_parameter("tls enabled", "True", NULL);
	do_parameter("tls keyfile", "tls/key.pem", NULL);
	do_parameter("tls certfile", "tls/cert.pem", NULL);
	do_parameter("tls cafile", "tls/ca.pem", NULL);
	do_parameter_var("js include", "%s", dyn_JSDIR);
	do_parameter_var("setup directory", "%s", dyn_SETUPDIR);

	for (i = 0; parm_table[i].label; i++) {
		if (!(parm_table[i].flags & FLAG_CMDLINE)) {
			parm_table[i].flags |= FLAG_DEFAULT;
		}
	}
}

static TALLOC_CTX *lp_talloc;

/******************************************************************* a
 Free up temporary memory - called from the main loop.
********************************************************************/

void lp_talloc_free(void)
{
	if (!lp_talloc)
		return;
	talloc_free(lp_talloc);
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

	ret = talloc_array(lp_talloc, char, len + 100);	/* leave room for substitution */

	if (!ret)
		return NULL;

	if (!s)
		*ret = 0;
	else
		strlcpy(ret, s, len);

	if (trim_string(ret, "\"", "\"")) {
		if (strchr(ret,'"') != NULL)
			strlcpy(ret, s, len);
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
 BOOL fn_name(void) {return((BOOL)*(int *)(ptr));}
#if 0 /* unused */
#define FN_GLOBAL_CHAR(fn_name,ptr) \
 char fn_name(void) {return(*(char *)(ptr));}
#endif
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
#if 0 /* unused */
#define FN_LOCAL_CHAR(fn_name,val) \
 char fn_name(int i) {return(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}
#endif
#define FN_LOCAL_INTEGER(fn_name,val) \
 int fn_name(int i) {return(LP_SNUM_OK(i)? ServicePtrs[(i)]->val : sDefault.val);}

_PUBLIC_ FN_GLOBAL_INTEGER(lp_server_role, &Globals.server_role)
_PUBLIC_ FN_GLOBAL_LIST(lp_smb_ports, &Globals.smb_ports)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_nbt_port, &Globals.nbt_port)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_dgram_port, &Globals.dgram_port)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_cldap_port, &Globals.cldap_port)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_krb5_port, &Globals.krb5_port)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_kpasswd_port, &Globals.kpasswd_port)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_web_port, &Globals.web_port)
_PUBLIC_ FN_GLOBAL_STRING(lp_dos_charset, &Globals.dos_charset)
_PUBLIC_ FN_GLOBAL_STRING(lp_swat_directory, &Globals.swat_directory)
_PUBLIC_ FN_GLOBAL_BOOL(lp_tls_enabled, &Globals.tls_enabled)
_PUBLIC_ FN_GLOBAL_STRING(lp_tls_keyfile, &Globals.tls_keyfile)
_PUBLIC_ FN_GLOBAL_STRING(lp_tls_certfile, &Globals.tls_certfile)
_PUBLIC_ FN_GLOBAL_STRING(lp_tls_cafile, &Globals.tls_cafile)
_PUBLIC_ FN_GLOBAL_STRING(lp_tls_crlfile, &Globals.tls_crlfile)
_PUBLIC_ FN_GLOBAL_STRING(lp_tls_dhpfile, &Globals.tls_dhpfile)
_PUBLIC_ FN_GLOBAL_STRING(lp_unix_charset, &Globals.unix_charset)
_PUBLIC_ FN_GLOBAL_STRING(lp_display_charset, &Globals.display_charset)
_PUBLIC_ FN_GLOBAL_STRING(lp_configfile, &Globals.szConfigFile)
_PUBLIC_ FN_GLOBAL_STRING(lp_share_backend, &Globals.szShareBackend)
_PUBLIC_ FN_GLOBAL_STRING(lp_sam_url, &Globals.szSAM_URL)
_PUBLIC_ FN_GLOBAL_STRING(lp_spoolss_url, &Globals.szSPOOLSS_URL)
_PUBLIC_ FN_GLOBAL_STRING(lp_wins_config_url, &Globals.szWINS_CONFIG_URL)
_PUBLIC_ FN_GLOBAL_STRING(lp_wins_url, &Globals.szWINS_URL)
_PUBLIC_ FN_GLOBAL_CONST_STRING(lp_winbind_separator, &Globals.szWinbindSeparator)
_PUBLIC_ FN_GLOBAL_CONST_STRING(lp_winbindd_socket_directory, &Globals.szWinbinddSocketDirectory)
_PUBLIC_ FN_GLOBAL_BOOL(lp_winbind_sealed_pipes, &Globals.bWinbindSealedPipes)
_PUBLIC_ FN_GLOBAL_STRING(lp_private_dir, &Globals.szPrivateDir)
_PUBLIC_ FN_GLOBAL_STRING(lp_serverstring, &Globals.szServerString)
_PUBLIC_ FN_GLOBAL_STRING(lp_lockdir, &Globals.szLockDir)
_PUBLIC_ FN_GLOBAL_STRING(lp_modulesdir, &Globals.szModulesDir)
_PUBLIC_ FN_GLOBAL_STRING(lp_setupdir, &Globals.szSetupDir)
_PUBLIC_ FN_GLOBAL_STRING(lp_ncalrpc_dir, &Globals.ncalrpc_dir)
_PUBLIC_ FN_GLOBAL_STRING(lp_piddir, &Globals.szPidDir)
_PUBLIC_ FN_GLOBAL_LIST(lp_dcerpc_endpoint_servers, &Globals.dcerpc_ep_servers)
_PUBLIC_ FN_GLOBAL_LIST(lp_server_services, &Globals.server_services)
_PUBLIC_ FN_GLOBAL_STRING(lp_ntptr_providor, &Globals.ntptr_providor)
_PUBLIC_ FN_GLOBAL_STRING(lp_auto_services, &Globals.szAutoServices)
_PUBLIC_ FN_GLOBAL_STRING(lp_passwd_chat, &Globals.szPasswdChat)
_PUBLIC_ FN_GLOBAL_LIST(lp_passwordserver, &Globals.szPasswordServers)
_PUBLIC_ FN_GLOBAL_LIST(lp_name_resolve_order, &Globals.szNameResolveOrder)
_PUBLIC_ FN_GLOBAL_STRING(lp_realm, &Globals.szRealm)
_PUBLIC_ FN_GLOBAL_STRING(lp_socket_options, &Globals.socket_options)
_PUBLIC_ FN_GLOBAL_STRING(lp_workgroup, &Globals.szWorkgroup)
_PUBLIC_ FN_GLOBAL_STRING(lp_netbios_name, &Globals.szNetbiosName)
_PUBLIC_ FN_GLOBAL_STRING(lp_netbios_scope, &Globals.szNetbiosScope)
_PUBLIC_ FN_GLOBAL_LIST(lp_wins_server_list, &Globals.szWINSservers)
_PUBLIC_ FN_GLOBAL_LIST(lp_interfaces, &Globals.szInterfaces)
_PUBLIC_ FN_GLOBAL_STRING(lp_socket_address, &Globals.szSocketAddress)
_PUBLIC_ FN_GLOBAL_LIST(lp_netbios_aliases, &Globals.szNetbiosAliases)

_PUBLIC_ FN_GLOBAL_BOOL(lp_disable_netbios, &Globals.bDisableNetbios)
_PUBLIC_ FN_GLOBAL_BOOL(lp_wins_support, &Globals.bWINSsupport)
_PUBLIC_ FN_GLOBAL_BOOL(lp_wins_dns_proxy, &Globals.bWINSdnsProxy)
_PUBLIC_ FN_GLOBAL_STRING(lp_wins_hook, &Globals.szWINSHook)
_PUBLIC_ FN_GLOBAL_BOOL(lp_local_master, &Globals.bLocalMaster)
_PUBLIC_ FN_GLOBAL_BOOL(lp_readraw, &Globals.bReadRaw)
_PUBLIC_ FN_GLOBAL_BOOL(lp_large_readwrite, &Globals.bLargeReadwrite)
_PUBLIC_ FN_GLOBAL_BOOL(lp_writeraw, &Globals.bWriteRaw)
_PUBLIC_ FN_GLOBAL_BOOL(lp_null_passwords, &Globals.bNullPasswords)
_PUBLIC_ FN_GLOBAL_BOOL(lp_obey_pam_restrictions, &Globals.bObeyPamRestrictions)
_PUBLIC_ FN_GLOBAL_BOOL(lp_encrypted_passwords, &Globals.bEncryptPasswords)
static FN_GLOBAL_BOOL(lp_time_server, &Globals.bTimeServer)
_PUBLIC_ FN_GLOBAL_BOOL(lp_bind_interfaces_only, &Globals.bBindInterfacesOnly)
_PUBLIC_ FN_GLOBAL_BOOL(lp_unicode, &Globals.bUnicode)
_PUBLIC_ FN_GLOBAL_BOOL(lp_nt_status_support, &Globals.bNTStatusSupport)
_PUBLIC_ FN_GLOBAL_BOOL(lp_lanman_auth, &Globals.bLanmanAuth)
_PUBLIC_ FN_GLOBAL_BOOL(lp_ntlm_auth, &Globals.bNTLMAuth)
_PUBLIC_ FN_GLOBAL_BOOL(lp_client_plaintext_auth, &Globals.bClientPlaintextAuth)
_PUBLIC_ FN_GLOBAL_BOOL(lp_client_lanman_auth, &Globals.bClientLanManAuth)
_PUBLIC_ FN_GLOBAL_BOOL(lp_client_ntlmv2_auth, &Globals.bClientNTLMv2Auth)
_PUBLIC_ FN_GLOBAL_BOOL(lp_client_use_spnego_principal, &Globals.client_use_spnego_principal)
_PUBLIC_ FN_GLOBAL_BOOL(lp_host_msdfs, &Globals.bHostMSDfs)
_PUBLIC_ FN_GLOBAL_BOOL(lp_unix_extensions, &Globals.bUnixExtensions)
_PUBLIC_ FN_GLOBAL_BOOL(lp_use_spnego, &Globals.bUseSpnego)
_PUBLIC_ FN_GLOBAL_BOOL(lp_rpc_big_endian, &Globals.bRpcBigEndian)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_max_wins_ttl, &Globals.max_wins_ttl)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_min_wins_ttl, &Globals.min_wins_ttl)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_maxmux, &Globals.max_mux)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_max_xmit, &Globals.max_xmit)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_passwordlevel, &Globals.pwordlevel)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_srv_maxprotocol, &Globals.srv_maxprotocol)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_srv_minprotocol, &Globals.srv_minprotocol)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_cli_maxprotocol, &Globals.cli_maxprotocol)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_cli_minprotocol, &Globals.cli_minprotocol)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_security, &Globals.security)
_PUBLIC_ FN_GLOBAL_LIST(lp_auth_methods, &Globals.AuthMethods)
_PUBLIC_ FN_GLOBAL_BOOL(lp_paranoid_server_security, &Globals.paranoid_server_security)
static FN_GLOBAL_INTEGER(lp_announce_as, &Globals.announce_as)
_PUBLIC_ FN_GLOBAL_LIST(lp_js_include, &Globals.jsInclude)
_PUBLIC_ FN_GLOBAL_STRING(lp_jsonrpc_services_dir, &Globals.jsonrpcServicesDir)
_PUBLIC_ 
_PUBLIC_ 
_PUBLIC_ FN_LOCAL_STRING(lp_servicename, szService)
_PUBLIC_ FN_LOCAL_CONST_STRING(lp_const_servicename, szService)
_PUBLIC_ FN_LOCAL_STRING(lp_pathname, szPath)
static FN_LOCAL_STRING(_lp_printername, szPrintername)
_PUBLIC_ FN_LOCAL_LIST(lp_hostsallow, szHostsallow)
_PUBLIC_ FN_LOCAL_LIST(lp_hostsdeny, szHostsdeny)
_PUBLIC_ FN_LOCAL_STRING(lp_comment, comment)
_PUBLIC_ FN_LOCAL_STRING(lp_fstype, fstype)
static FN_LOCAL_STRING(lp_volume, volume)
_PUBLIC_ FN_LOCAL_LIST(lp_ntvfs_handler, ntvfs_handler)
_PUBLIC_ FN_LOCAL_BOOL(lp_msdfs_root, bMSDfsRoot)
_PUBLIC_ FN_LOCAL_BOOL(lp_browseable, bBrowseable)
_PUBLIC_ FN_LOCAL_BOOL(lp_readonly, bRead_only)
_PUBLIC_ FN_LOCAL_BOOL(lp_print_ok, bPrint_ok)
_PUBLIC_ FN_LOCAL_BOOL(lp_map_hidden, bMap_hidden)
_PUBLIC_ FN_LOCAL_BOOL(lp_map_archive, bMap_archive)
_PUBLIC_ FN_LOCAL_BOOL(lp_strict_locking, bStrictLocking)
_PUBLIC_ FN_LOCAL_BOOL(lp_strict_sync, bStrictSync)
_PUBLIC_ FN_LOCAL_BOOL(lp_ci_filesystem, bCIFileSystem)
_PUBLIC_ FN_LOCAL_BOOL(lp_map_system, bMap_system)
_PUBLIC_ FN_LOCAL_INTEGER(lp_max_connections, iMaxConnections)
_PUBLIC_ FN_LOCAL_INTEGER(lp_csc_policy, iCSCPolicy)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_server_signing, &Globals.server_signing)
_PUBLIC_ FN_GLOBAL_INTEGER(lp_client_signing, &Globals.client_signing)

/* local prototypes */

static int map_parameter(const char *pszParmName);
static int getservicebyname(const char *pszServiceName,
			    service * pserviceDest);
static void copy_service(service * pserviceDest,
			 service * pserviceSource, int *pcopymapDest);
static BOOL service_ok(int iService);
static BOOL do_section(const char *pszSectionName, void *);
static void init_copymap(service * pservice);

/* This is a helper function for parametrical options support. */
/* It returns a pointer to parametrical option value if it exists or NULL otherwise */
/* Actual parametrical functions are quite simple */
const char *lp_get_parametric(int lookup_service, const char *type, const char *option)
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

	return strtol(s, NULL, 0); 
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

	return strtoul(s, NULL, 0);
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
	
	if (!set_boolean(s, &ret)) {
		DEBUG(0,("lp_bool(%s): value is not boolean!\n",s));
		return False;
	}

	return ret;
}


/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */
/* Returned value is allocated in 'lp_talloc' context */

const char *lp_parm_string(int lookup_service, const char *type, const char *option)
{
	const char *value = lp_get_parametric(lookup_service, type, option);

	if (value)
		return lp_string(value);

	return NULL;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */
/* Returned value is allocated in 'lp_talloc' context */

const char **lp_parm_string_list(int lookup_service, const char *type, const char *option,
				 const char *separator)
{
	const char *value = lp_get_parametric(lookup_service, type, option);
	
	if (value)
		return str_list_make(talloc_autofree_context(), value, separator);

	return NULL;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

int lp_parm_int(int lookup_service, const char *type, const char *option, int default_v)
{
	const char *value = lp_get_parametric(lookup_service, type, option);
	
	if (value)
		return lp_int(value);

	return default_v;
}

/* Return parametric option from a given service. Type is a part of
 * option before ':'.
 * Parametric option has following syntax: 'Type: option = value'.
 */

int lp_parm_bytes(int lookup_service, const char *type, const char *option, int default_v)
{
	uint64_t bval;

	const char *value = lp_get_parametric(lookup_service, type, option);

	if (value && conv_str_size(value, &bval)) {
		if (bval <= INT_MAX) {
			return (int)bval;
		}
	}

	return default_v;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

unsigned long lp_parm_ulong(int lookup_service, const char *type, const char *option, unsigned long default_v)
{
	const char *value = lp_get_parametric(lookup_service, type, option);
	
	if (value)
		return lp_ulong(value);

	return default_v;
}

/* Return parametric option from a given service. Type is a part of option before ':' */
/* Parametric option has following syntax: 'Type: option = value' */

BOOL lp_parm_bool(int lookup_service, const char *type, const char *option, BOOL default_v)
{
	const char *value = lp_get_parametric(lookup_service, type, option);
	
	if (value)
		return lp_bool(value);

	return default_v;
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
		    parm_table[i].class == P_LOCAL) {
			string_free((char **)
				    (((char *)pservice) +
				     PTR_DIFF(parm_table[i].ptr, &sDefault)));
		} else if (parm_table[i].type == P_LIST &&
			   parm_table[i].class == P_LOCAL) {
			char ***listp = (char ***)(((char *)pservice) + 
						   PTR_DIFF(parm_table[i].ptr, &sDefault));
			talloc_free(*listp);
			*listp = NULL;
		}
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
		
		tsp = realloc_p(ServicePtrs, service *,	num_to_alloc);
					   
		if (!tsp) {
			DEBUG(0,("add_a_service: failed to enlarge ServicePtrs!\n"));
			return (-1);
		}
		else {
			ServicePtrs = tsp;
			ServicePtrs[iNumServices] = malloc_p(service);
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

static BOOL lp_add_hidden(const char *name, const char *fstype)
{
	pstring comment;
	int i = add_a_service(&sDefault, name);

	if (i < 0)
		return (False);

	slprintf(comment, sizeof(comment) - 1,
		 "%s Service (%s)", fstype, Globals.szServerString);

	string_set(&ServicePtrs[i]->szPath, tmpdir());
	string_set(&ServicePtrs[i]->comment, comment);
	string_set(&ServicePtrs[i]->fstype, fstype);
	ServicePtrs[i]->iMaxConnections = -1;
	ServicePtrs[i]->bAvailable = True;
	ServicePtrs[i]->bRead_only = True;
	ServicePtrs[i]->bPrint_ok = False;
	ServicePtrs[i]->bBrowseable = False;

	if (strcasecmp(fstype, "IPC") == 0) {
		lp_do_parameter(i, "ntvfs handler", "default");
	}

	DEBUG(3, ("adding hidden service %s\n", name));

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


/*
  return the parameter structure for a parameter
*/
struct parm_struct *lp_parm_struct(const char *name)
{
	int parmnum = map_parameter(name);
	if (parmnum == -1) return NULL;
	return &parm_table[parmnum];
}

/*
  return the parameter pointer for a parameter
*/
void *lp_parm_ptr(int snum, struct parm_struct *parm)
{
	if (snum == -1) {
		return parm->ptr;
	}
	return ((char *)ServicePtrs[snum]) + PTR_DIFF(parm->ptr, &sDefault);
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

static void copy_service(service * pserviceDest, service * pserviceSource, int *pcopymapDest)
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
					*(int *)dest_ptr = *(int *)src_ptr;
					break;

				case P_INTEGER:
				case P_ENUM:
					*(int *)dest_ptr = *(int *)src_ptr;
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
					*(const char ***)dest_ptr = str_list_copy(talloc_autofree_context(), 
										  *(const char ***)src_ptr);
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
			       sizeof(int) * NUMPARAMETERS);
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
			paramo = malloc_p(struct param_opt);
			if (!paramo)
				smb_panic("OOM");
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
			update_server_announce_as_printserver();
		}
		/* [printers] service must also be non-browsable. */
		if (ServicePtrs[iService]->bBrowseable)
			ServicePtrs[iService]->bBrowseable = False;
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
		f = malloc_p(struct file_lists);
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

	if (file_exist(fname))
		return (pm_process(fname, do_section, do_parameter, NULL));

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
 Initialise a copymap.
***************************************************************************/

static void init_copymap(service * pservice)
{
	int i;
	SAFE_FREE(pservice->copymap);
	pservice->copymap = malloc_array_p(int, NUMPARAMETERS);
	if (!pservice->copymap)
		DEBUG(0,
		      ("Couldn't allocate copymap!! (size %d)\n",
		       (int)NUMPARAMETERS));
	else
		for (i = 0; i < NUMPARAMETERS; i++)
			pservice->copymap[i] = True;
}

#if 0 /* not used anywhere */
/***************************************************************************
 Return the local pointer to a parameter given the service number and the 
 pointer into the default structure.
***************************************************************************/

void *lp_local_ptr(int snum, void *ptr)
{
	return (void *)(((char *)ServicePtrs[snum]) + PTR_DIFF(ptr, &sDefault));
}
#endif

/***************************************************************************
 Process a parametric option
***************************************************************************/
static BOOL lp_do_parameter_parametric(int snum, const char *pszParmName, const char *pszParmValue, int flags)
{
	struct param_opt *paramo, *data;
	char *name;

	while (isspace((unsigned char)*pszParmName)) {
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

	paramo = malloc_p(struct param_opt);
	if (!paramo)
		smb_panic("OOM");
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
		case P_BOOL: {
			BOOL b;
			if (!set_boolean(pszParmValue, &b)) {
				DEBUG(0,("lp_do_parameter(%s): value is not boolean!\n", pszParmValue));
				return False;
			}
			*(int *)parm_ptr = b;
			}
			break;

		case P_INTEGER:
			*(int *)parm_ptr = atoi(pszParmValue);
			break;

		case P_BYTES:
		{
			uint64_t val;
			if (conv_str_size(pszParmValue, &val)) {
				if (val <= INT_MAX) {
					*(int *)parm_ptr = (int)val;
					break;
				}
			}

			DEBUG(0,("lp_do_parameter(%s): value is not "
			    "a valid size specifier!\n", pszParmValue));
			return False;
		}

		case P_LIST:
			*(const char ***)parm_ptr = str_list_make(talloc_autofree_context(), 
								  pszParmValue, NULL);
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
			if (!parm_table[parmnum].enum_list[i].name) {
				DEBUG(0,("Unknown enumerated value '%s' for '%s'\n", 
					 pszParmValue, pszParmName));
				return False;
			}
			break;
		case P_SEP:
			break;
	}

	if (parm_table[parmnum].flags & FLAG_DEFAULT) {
		parm_table[parmnum].flags &= ~FLAG_DEFAULT;
		/* we have to also unset FLAG_DEFAULT on aliases */
		for (i=parmnum-1;i>=0 && parm_table[i].ptr == parm_table[parmnum].ptr;i--) {
			parm_table[i].flags &= ~FLAG_DEFAULT;
		}
		for (i=parmnum+1;i<NUMPARAMETERS && parm_table[i].ptr == parm_table[parmnum].ptr;i++) {
			parm_table[i].flags &= ~FLAG_DEFAULT;
		}
	}

	return (True);
}

/***************************************************************************
 Process a parameter.
***************************************************************************/

static BOOL do_parameter(const char *pszParmName, const char *pszParmValue, void *userdata)
{
	return (lp_do_parameter(bInGlobalSection ? -2 : iServiceIndex,
				pszParmName, pszParmValue));
}

/*
  variable argument do parameter
*/
static BOOL do_parameter_var(const char *pszParmName, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);

static BOOL do_parameter_var(const char *pszParmName, const char *fmt, ...)
{
	char *s;
	BOOL ret;
	va_list ap;

	va_start(ap, fmt);	
	s = talloc_vasprintf(NULL, fmt, ap);
	va_end(ap);
	ret = do_parameter(pszParmName, s, NULL);
	talloc_free(s);
	return ret;
}


/*
  set a parameter from the commandline - this is called from command line parameter
  parsing code. It sets the parameter then marks the parameter as unable to be modified
  by smb.conf processing
*/
BOOL lp_set_cmdline(const char *pszParmName, const char *pszParmValue)
{
	int parmnum = map_parameter(pszParmName);
	int i;

	while (isspace((unsigned char)*pszParmValue)) pszParmValue++;


	if (parmnum < 0 && strchr(pszParmName, ':')) {
		/* set a parametric option */
		return lp_do_parameter_parametric(-1, pszParmName, pszParmValue, FLAG_CMDLINE);
	}

	if (parmnum < 0) {
		DEBUG(0,("Unknown option '%s'\n", pszParmName));
		return False;
	}

	/* reset the CMDLINE flag in case this has been called before */
	parm_table[parmnum].flags &= ~FLAG_CMDLINE;

	if (!lp_do_parameter(-2, pszParmName, pszParmValue)) {
		return False;
	}

	parm_table[parmnum].flags |= FLAG_CMDLINE;

	/* we have to also set FLAG_CMDLINE on aliases */
	for (i=parmnum-1;i>=0 && parm_table[i].ptr == parm_table[parmnum].ptr;i--) {
		parm_table[i].flags |= FLAG_CMDLINE;
	}
	for (i=parmnum+1;i<NUMPARAMETERS && parm_table[i].ptr == parm_table[parmnum].ptr;i++) {
		parm_table[i].flags |= FLAG_CMDLINE;
	}

	return True;
}

/*
  set a option from the commandline in 'a=b' format. Use to support --option
*/
BOOL lp_set_option(const char *option)
{
	char *p, *s;
	BOOL ret;

	s = strdup(option);
	if (!s) {
		return False;
	}

	p = strchr(s, '=');
	if (!p) {
		free(s);
		return False;
	}

	*p = 0;

	ret = lp_set_cmdline(s, p+1);
	free(s);
	return ret;
}


#define BOOLSTR(b) ((b) ? "Yes" : "No")

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
			fprintf(f, "%s", BOOLSTR((BOOL)*(int *)ptr));
			break;

		case P_INTEGER:
		case P_BYTES:
			fprintf(f, "%d", *(int *)ptr);
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
			return (*((int *)ptr1) == *((int *)ptr2));

		case P_INTEGER:
		case P_BYTES:
		case P_ENUM:
			return (*((int *)ptr1) == *((int *)ptr2));

		case P_LIST:
			return str_list_equal((const char **)(*(char ***)ptr1), 
					      (const char **)(*(char ***)ptr2));

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

static BOOL do_section(const char *pszSectionName, void *userdata)
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
			return str_list_equal((const char **)parm_table[i].def.lvalue, 
					      (const char **)(*(char ***)parm_table[i].ptr));
		case P_STRING:
		case P_USTRING:
			return strequal(parm_table[i].def.svalue,
					*(char **)parm_table[i].ptr);
		case P_BOOL:
			return parm_table[i].def.bvalue ==
				*(int *)parm_table[i].ptr;
		case P_INTEGER:
		case P_BYTES:
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

static void dump_globals(FILE *f, BOOL show_defaults)
{
	int i;
	struct param_opt *data;
	
	fprintf(f, "# Global parameters\n[global]\n");

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].class == P_GLOBAL &&
		    parm_table[i].ptr &&
		    (i == 0 || (parm_table[i].ptr != parm_table[i - 1].ptr))) {
			if (!show_defaults && (parm_table[i].flags & FLAG_DEFAULT)) 
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

BOOL lp_dump_a_parameter(int snum, char *parm_name, FILE * f, BOOL isGlobal)
{
	service * pService = ServicePtrs[snum];
	struct parm_struct *parm;
	void *ptr;
	
	parm = lp_parm_struct(parm_name);
	if (!parm) {
		return False;
	}
	
	if (isGlobal)
		ptr = parm->ptr;
	else
		ptr = ((char *)pService) +
			PTR_DIFF(parm->ptr, &sDefault);
	
	print_parameter(parm,
			ptr, f);
	fprintf(f, "\n");
	return True;
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
 Load the services array from the services file. Return True on success, 
 False on failure.
***************************************************************************/

BOOL lp_load(void)
{
	pstring n2;
	BOOL bRetval;
	struct param_opt *data;

	bRetval = False;

	bInGlobalSection = True;

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
	
	init_globals();

	pstrcpy(n2, lp_configfile());
	standard_sub_basic(n2,sizeof(n2));
	DEBUG(2, ("lp_load: refreshing parameters from %s\n", n2));
	
	add_to_file_list(lp_configfile(), n2);

	/* We get sections first, so have to start 'behind' to make up */
	iServiceIndex = -1;
	bRetval = pm_process(n2, do_section, do_parameter, NULL);

	/* finish up the last section */
	DEBUG(4, ("pm_process() returned %s\n", BOOLSTR(bRetval)));
	if (bRetval)
		if (iServiceIndex >= 0)
			bRetval = service_ok(iServiceIndex);

	lp_add_auto_services(lp_auto_services());

	lp_add_hidden("IPC$", "IPC");
	lp_add_hidden("ADMIN$", "DISK");

	set_default_server_announce_type();

	bLoaded = True;

	if (!Globals.szWINSservers && Globals.bWINSsupport) {
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

	dump_globals(f, show_defaults);

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

int lp_find_valid_service(const char *pszServiceName)
{
	int iService;

	iService = lp_servicenumber(pszServiceName);

	if (iService >= 0 && !lp_snum_ok(iService)) {
		DEBUG(0,("lp_find_valid_service: Invalid snum %d for '%s'\n",iService, pszServiceName));
		iService = -1;
	}

	if (iService == -1) {
		DEBUG(3,("lp_find_valid_service: failed to find service '%s'\n", pszServiceName));
	}

	return iService;
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

	/* TODO: only announce us as print server when we are a print server */
	default_server_announce |= SV_TYPE_PRINTQ_SERVER;
}

/***********************************************************
 If we are PDC then prefer us as DMB
************************************************************/

BOOL lp_domain_master(void)
{
	return (lp_server_role() == ROLE_DOMAIN_PDC);
}

/***********************************************************
 If we are PDC then prefer us as DMB
************************************************************/

BOOL lp_domain_logons(void)
{
	return (lp_server_role() == ROLE_DOMAIN_PDC) || (lp_server_role() == ROLE_DOMAIN_BDC);
}

/***********************************************************
 If we are DMB then prefer us as LMB
************************************************************/

BOOL lp_preferred_master(void)
{
	return (lp_local_master() && lp_domain_master());
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
	do_section(new_name, NULL);
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
