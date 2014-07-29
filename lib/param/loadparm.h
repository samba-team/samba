/*
   Unix SMB/CIFS implementation.

   type definitions for loadparm

   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James Myers 2003 <myersjj@samba.org>

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

#ifndef _LOADPARM_H
#define _LOADPARM_H

#include "../lib/util/parmlist.h"

/* the following are used by loadparm for option lists */
typedef enum {
	P_BOOL,P_BOOLREV,P_CHAR,P_INTEGER,P_OCTAL,P_LIST,
	P_STRING,P_USTRING,P_ENUM,P_BYTES,P_CMDLIST,P_SEP
} parm_type;

typedef enum {
	P_LOCAL,P_GLOBAL,P_SEPARATOR,P_NONE
} parm_class;

struct enum_list {
	int value;
	const char *name;
};

struct loadparm_service;
struct loadparm_context {
	const char *szConfigFile;
	struct loadparm_global *globals;
	struct loadparm_service **services;
	struct loadparm_service *sDefault;
	struct smb_iconv_handle *iconv_handle;
	int iNumServices;
	struct loadparm_service *currentService;
	bool bInGlobalSection;
	struct file_lists *file_lists;
	unsigned int *flags;
	bool loaded;
	bool refuse_free;
	bool global; /* Is this the global context, which may set
		      * global variables such as debug level etc? */
	const struct loadparm_s3_helpers *s3_fns;
};

struct parm_struct {
	const char *label;
	parm_type type;
	parm_class p_class;
	offset_t offset;
	bool (*special)(struct loadparm_context *lpcfg_ctx,
			struct loadparm_service *, const char *, char **);
	const struct enum_list *enum_list;
	unsigned flags;
	union {
		bool bvalue;
		int ivalue;
		char *svalue;
		char cvalue;
		char **lvalue;
	} def;
};

extern struct parm_struct parm_table[];

struct file_lists {
	struct file_lists *next;
	char *name;
	char *subfname;
	time_t modtime;
};

/* The following flags are used in SWAT */
#define FLAG_BASIC 	0x0001 /* Display only in BASIC view */
#define FLAG_SHARE 	0x0002 /* file sharing options */
#define FLAG_PRINT 	0x0004 /* printing options */
#define FLAG_GLOBAL 	0x0008 /* local options that should be globally settable in SWAT */
#define FLAG_WIZARD 	0x0010 /* Parameters that the wizard will operate on */
#define FLAG_ADVANCED 	0x0020 /* Parameters that will be visible in advanced view */
#define FLAG_DEVELOPER 	0x0040 /* No longer used */
#define FLAG_DEPRECATED 0x1000 /* options that should no longer be used */
#define FLAG_HIDE  	0x2000 /* options that should be hidden in SWAT */
#define FLAG_META	0x8000 /* A meta directive - not a real parameter */
#define FLAG_CMDLINE	0x10000 /* option has been overridden */
#define FLAG_DEFAULT    0x20000 /* this option was a default */

/* This defines the section name in the configuration file that will
   refer to the special "printers" service */
#ifndef PRINTERS_NAME
#define PRINTERS_NAME "printers"
#endif

/* This defines the section name in the configuration file that will
   refer to the special "homes" service */
#ifndef HOMES_NAME
#define HOMES_NAME "homes"
#endif

/* This defines the section name in the configuration file that will contain */
/* global parameters - that is, parameters relating to the whole server, not */
/* just services. This name is then reserved, and may not be used as a       */
/* a service name. It will default to "global" if not defined here.          */
#ifndef GLOBAL_NAME
#define GLOBAL_NAME "global"
#define GLOBAL_NAME2 "globals"
#endif

/* The default workgroup - usually overridden in smb.conf */
#ifndef DEFAULT_WORKGROUP
#define DEFAULT_WORKGROUP "WORKGROUP"
#endif

/* types of configuration backends for loadparm */
#define CONFIG_BACKEND_FILE 0
#define CONFIG_BACKEND_REGISTRY 1

/*
   Do you want session setups at user level security with a invalid
   password to be rejected or allowed in as guest? WinNT rejects them
   but it can be a pain as it means "net view" needs to use a password

   You have 3 choices in the setting of map_to_guest:

   "NEVER_MAP_TO_GUEST" means session setups with an invalid password
   are rejected. This is the default.

   "MAP_TO_GUEST_ON_BAD_USER" means session setups with an invalid password
   are rejected, unless the username does not exist, in which case it
   is treated as a guest login

   "MAP_TO_GUEST_ON_BAD_PASSWORD" means session setups with an invalid password
   are treated as a guest login

   Note that map_to_guest only has an effect in user or server
   level security.
*/

#define NEVER_MAP_TO_GUEST 		0
#define MAP_TO_GUEST_ON_BAD_USER 	1
#define MAP_TO_GUEST_ON_BAD_PASSWORD 	2
#define MAP_TO_GUEST_ON_BAD_UID 	3

/*
 * This should be under the HAVE_KRB5 flag but since they're used
 * in lp_kerberos_method(), they ned to be always available
 * If you add any entries to KERBEROS_VERIFY defines, please modify USE.*KEYTAB macros
 * so they remain accurate.
 */

#define KERBEROS_VERIFY_SECRETS 0
#define KERBEROS_VERIFY_SYSTEM_KEYTAB 1
#define KERBEROS_VERIFY_DEDICATED_KEYTAB 2
#define KERBEROS_VERIFY_SECRETS_AND_KEYTAB 3

/* ACL compatibility */
enum acl_compatibility {ACL_COMPAT_AUTO, ACL_COMPAT_WINNT, ACL_COMPAT_WIN2K};

/* printing types */
enum printing_types {PRINT_BSD,PRINT_SYSV,PRINT_AIX,PRINT_HPUX,
		     PRINT_QNX,PRINT_PLP,PRINT_LPRNG,PRINT_SOFTQ,
		     PRINT_CUPS,PRINT_LPRNT,PRINT_LPROS2,PRINT_IPRINT
#if defined(DEVELOPER) || defined(ENABLE_SELFTEST)
,PRINT_TEST,PRINT_VLP
#endif /* DEVELOPER */
};




/* ads auth control flags */
#define ADS_AUTH_DISABLE_KERBEROS 0x0001
#define ADS_AUTH_NO_BIND          0x0002
#define ADS_AUTH_ANON_BIND        0x0004
#define ADS_AUTH_SIMPLE_BIND      0x0008
#define ADS_AUTH_ALLOW_NTLMSSP    0x0010
#define ADS_AUTH_SASL_SIGN        0x0020
#define ADS_AUTH_SASL_SEAL        0x0040
#define ADS_AUTH_SASL_FORCE       0x0080
#define ADS_AUTH_USER_CREDS       0x0100

/* DNS update settings */
enum dns_update_settings {DNS_UPDATE_OFF, DNS_UPDATE_ON, DNS_UPDATE_SIGNED};

/* LDAP SSL options */
enum ldap_ssl_types {LDAP_SSL_OFF, LDAP_SSL_START_TLS};

/* LDAP PASSWD SYNC methods */
enum ldap_passwd_sync_types {LDAP_PASSWD_SYNC_ON, LDAP_PASSWD_SYNC_OFF, LDAP_PASSWD_SYNC_ONLY};

/* map readonly options */
enum mapreadonly_options {MAP_READONLY_NO, MAP_READONLY_YES, MAP_READONLY_PERMISSIONS};

/* case handling */
enum case_handling {CASE_LOWER,CASE_UPPER};

/*
 * Default passwd chat script.
 */
#ifndef DEFAULT_PASSWD_CHAT
#define DEFAULT_PASSWD_CHAT "*new*password* %n\\n *new*password* %n\\n *changed*"
#endif

/* Max number of jobs per print queue. */
#ifndef PRINT_MAX_JOBID
#define PRINT_MAX_JOBID 10000
#endif

/* the default guest account - allow override via CFLAGS */
#ifndef GUEST_ACCOUNT
#define GUEST_ACCOUNT "nobody"
#endif

/* SMB2 defaults */
#define DEFAULT_SMB2_MAX_READ (8*1024*1024)
#define DEFAULT_SMB2_MAX_WRITE (8*1024*1024)
#define DEFAULT_SMB2_MAX_TRANSACT (8*1024*1024)
#define DEFAULT_SMB2_MAX_CREDITS 8192

#define LOADPARM_EXTRA_LOCALS						\
	bool valid;						        \
	int usershare;							\
	struct timespec usershare_last_mod;				\
	int iMaxPrintJobs;						\
	char *szCopy;							\
	char *szService;						\
	char *szInclude;						\
	bool bWidelinks;						\
	bool bAvailable;							\
	struct parmlist_entry *param_opt;				\
	struct bitmap *copymap;						\
	char dummy[3];		/* for alignment */

#include "lib/param/param_local.h"

#define LOADPARM_EXTRA_GLOBALS \
	struct parmlist_entry *param_opt;				\
	char *realm_original;						\
	int iminreceivefile;						\
	char *szPrintcapname;						\
	int CupsEncrypt;						\
	int  iPreferredMaster;						\
	char *szLdapMachineSuffix;					\
	char *szLdapUserSuffix;						\
	char *szLdapIdmapSuffix;					\
	char *szLdapGroupSuffix;					\
	char *szIdmapUID;						\
	char *szIdmapGID;						\
	char *szIdmapBackend;						\
	int winbindMaxDomainConnections;				\
	int ismb2_max_credits;

const char* server_role_str(uint32_t role);
int lp_find_server_role(int server_role, int security, int domain_logons, int domain_master);
int lp_find_security(int server_role, int security);
bool lp_is_security_and_server_role_valid(int server_role, int security);

struct loadparm_global * get_globals(void);
unsigned int * get_flags(void);
char * lp_string(TALLOC_CTX *, const char *);
int getservicebyname(const char *, struct loadparm_service *);
bool lp_include(struct loadparm_context *, struct loadparm_service *,
	       	const char *, char **);
bool lp_do_section(const char *pszSectionName, void *userdata);
bool store_lp_set_cmdline(const char *pszParmName, const char *pszParmValue);

int num_parameters(void);

#endif /* _LOADPARM_H */
