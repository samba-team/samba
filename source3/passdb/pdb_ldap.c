/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001-2003
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002
   Copyright (C) Stefan (metze) Metzmacher	2002
    
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

/* TODO:
*  persistent connections: if using NSS LDAP, many connections are made
*      however, using only one within Samba would be nice
*  
*  Clean up SSL stuff, compile on OpenLDAP 1.x, 2.x, and Netscape SDK
*
*  Other LDAP based login attributes: accountExpires, etc.
*  (should be the domain of Samba proper, but the sam_password/SAM_ACCOUNT
*  structures don't have fields for some of these attributes)
*
*  SSL is done, but can't get the certificate based authentication to work
*  against on my test platform (Linux 2.4, OpenLDAP 2.x)
*/

/* NOTE: this will NOT work against an Active Directory server
*  due to the fact that the two password fields cannot be retrieved
*  from a server; recommend using security = domain in this situation
*  and/or winbind
*/

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

#include <lber.h>
#include <ldap.h>

#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS 0
#endif

#ifndef SAM_ACCOUNT
#define SAM_ACCOUNT struct sam_passwd
#endif

struct ldapsam_privates {
	/* Former statics */
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	int index;
	
	time_t last_ping;
	/* retrive-once info */
	const char *uri;
	const char *domain_name;
	DOM_SID domain_sid;
	
	/* configuration items */
	int schema_ver;

	BOOL permit_non_unix_accounts;
	
	uint32 low_allocated_user_rid; 
	uint32 high_allocated_user_rid; 

	uint32 low_allocated_group_rid; 
	uint32 high_allocated_group_rid; 

	char *bind_dn;
	char *bind_secret;

	unsigned int num_failures;
};

#define LDAPSAM_DONT_PING_TIME 10	/* ping only all 10 seconds */

static struct ldapsam_privates *static_ldap_state;

/* specify schema versions between 2.2. and 3.0 */

#define SCHEMAVER_SAMBAACCOUNT		1
#define SCHEMAVER_SAMBASAMACCOUNT	2

/* objectclass names */

#define LDAP_OBJ_SAMBASAMACCOUNT	"sambaSamAccount"
#define LDAP_OBJ_SAMBAACCOUNT		"sambaAccount"
#define LDAP_OBJ_GROUPMAP		"sambaGroupMapping"
#define LDAP_OBJ_DOMINFO		"sambaDomain"

#define LDAP_OBJ_ACCOUNT		"account"
#define LDAP_OBJ_POSIXACCOUNT		"posixAccount"
#define LDAP_OBJ_POSIXGROUP		"posixGroup"

/* some generic attributes that get reused a lot */

#define LDAP_ATTRIBUTE_SID		"sambaSID"

/* attribute map table indexes */

#define LDAP_ATTR_LIST_END		0
#define LDAP_ATTR_UID			1
#define LDAP_ATTR_UIDNUMBER		2
#define LDAP_ATTR_GIDNUMBER		3
#define LDAP_ATTR_UNIX_HOME		4
#define LDAP_ATTR_PWD_LAST_SET		5
#define LDAP_ATTR_PWD_CAN_CHANGE	6
#define LDAP_ATTR_PWD_MUST_CHANGE	7
#define LDAP_ATTR_LOGON_TIME		8
#define LDAP_ATTR_LOGOFF_TIME		9
#define LDAP_ATTR_KICKOFF_TIME		10
#define LDAP_ATTR_CN			11
#define LDAP_ATTR_DISPLAY_NAME		12
#define LDAP_ATTR_HOME_PATH		13
#define LDAP_ATTR_LOGON_SCRIPT		14
#define LDAP_ATTR_PROFILE_PATH		15
#define LDAP_ATTR_DESC			16
#define LDAP_ATTR_USER_WKS		17
#define LDAP_ATTR_USER_SID		18
#define LDAP_ATTR_USER_RID		18
#define LDAP_ATTR_PRIMARY_GROUP_SID	19
#define LDAP_ATTR_PRIMARY_GROUP_RID	20
#define LDAP_ATTR_LMPW			21
#define LDAP_ATTR_NTPW			22
#define LDAP_ATTR_DOMAIN		23
#define LDAP_ATTR_OBJCLASS		24
#define LDAP_ATTR_ACB_INFO		25
#define LDAP_ATTR_NEXT_USERRID		26
#define LDAP_ATTR_NEXT_GROUPRID		27
#define LDAP_ATTR_DOM_SID		28
#define LDAP_ATTR_HOME_DRIVE		29
#define LDAP_ATTR_GROUP_SID		30
#define LDAP_ATTR_GROUP_TYPE		31


typedef struct _attrib_map_entry {
	int		attrib;
	const char 	*name;
} ATTRIB_MAP_ENTRY;


/* attributes used by Samba 2.2 */

static ATTRIB_MAP_ENTRY attrib_map_v22[] = {
	{ LDAP_ATTR_UID,		"uid" 		},
	{ LDAP_ATTR_UIDNUMBER,		"uidNumber"	},
	{ LDAP_ATTR_GIDNUMBER,		"gidNumber"	},
	{ LDAP_ATTR_UNIX_HOME,		"homeDirectory"	},
	{ LDAP_ATTR_PWD_LAST_SET,	"pwdLastSet"	},
	{ LDAP_ATTR_PWD_CAN_CHANGE,	"pwdCanChange"	},
	{ LDAP_ATTR_PWD_MUST_CHANGE,	"pwdMustChange"	},
	{ LDAP_ATTR_LOGON_TIME,		"logonTime" 	},
	{ LDAP_ATTR_LOGOFF_TIME,	"logoffTime"	},
	{ LDAP_ATTR_KICKOFF_TIME,	"kickoffTime"	},
	{ LDAP_ATTR_CN,			"cn"		},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"	},
	{ LDAP_ATTR_HOME_PATH,		"smbHome"	},
	{ LDAP_ATTR_HOME_DRIVE,		"homeDrives"	},
	{ LDAP_ATTR_LOGON_SCRIPT,	"scriptPath"	},
	{ LDAP_ATTR_PROFILE_PATH,	"profilePath"	},
	{ LDAP_ATTR_DESC,		"description"	},
	{ LDAP_ATTR_USER_WKS,		"userWorkstations"},
	{ LDAP_ATTR_USER_RID,		"rid"		},
	{ LDAP_ATTR_PRIMARY_GROUP_RID,	"primaryGroupID"},
	{ LDAP_ATTR_LMPW,		"lmPassword"	},
	{ LDAP_ATTR_NTPW,		"ntPassword"	},
	{ LDAP_ATTR_DOMAIN,		"domain"	},
	{ LDAP_ATTR_OBJCLASS,		"objectClass"	},
	{ LDAP_ATTR_ACB_INFO,		"acctFlags"	},
	{ LDAP_ATTR_LIST_END,		NULL 		}
};

/* attributes used by Samba 3.0's sambaSamAccount */

static ATTRIB_MAP_ENTRY attrib_map_v30[] = {
	{ LDAP_ATTR_UID,		"uid" 			},
	{ LDAP_ATTR_UIDNUMBER,		"uidNumber"		},
	{ LDAP_ATTR_GIDNUMBER,		"gidNumber"		},
	{ LDAP_ATTR_UNIX_HOME,		"homeDirectory"		},
	{ LDAP_ATTR_PWD_LAST_SET,	"sambaPwdLastSet"	},
	{ LDAP_ATTR_PWD_CAN_CHANGE,	"sambaPwdCanChange"	},
	{ LDAP_ATTR_PWD_MUST_CHANGE,	"sambaPwdMustChange"	},
	{ LDAP_ATTR_LOGON_TIME,		"sambaLogonTime" 	},
	{ LDAP_ATTR_LOGOFF_TIME,	"sambaLogoffTime"	},
	{ LDAP_ATTR_KICKOFF_TIME,	"sambaKickoffTime"	},
	{ LDAP_ATTR_CN,			"cn"			},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_HOME_DRIVE,		"sambaHoneDrive"	},
	{ LDAP_ATTR_HOME_PATH,		"sambaHomePath"		},
	{ LDAP_ATTR_LOGON_SCRIPT,	"sambaLogonScript"	},
	{ LDAP_ATTR_PROFILE_PATH,	"sambaProfilePath"	},
	{ LDAP_ATTR_DESC,		"description"		},
	{ LDAP_ATTR_USER_WKS,		"sambaUserWorkstations"	},
	{ LDAP_ATTR_USER_SID,		"sambaSID"		},
	{ LDAP_ATTR_PRIMARY_GROUP_SID,	"sambaPrimaryGroupSID"	},
	{ LDAP_ATTR_LMPW,		"sambaLMPassword"	},
	{ LDAP_ATTR_NTPW,		"sambaNTPassword"	},
	{ LDAP_ATTR_DOMAIN,		"sambaDomainName"	},
	{ LDAP_ATTR_OBJCLASS,		"objectClass"		},
	{ LDAP_ATTR_ACB_INFO,		"sambaAcctFlags"	},
	{ LDAP_ATTR_LIST_END,		NULL 			}
};

/* attributes used for alalocating RIDs */

static ATTRIB_MAP_ENTRY dominfo_attr_list[] = {
	{ LDAP_ATTR_DOMAIN,		"sambaDomainName"	},
	{ LDAP_ATTR_NEXT_USERRID,	"sambaNextUserRid"	},
	{ LDAP_ATTR_NEXT_GROUPRID,	"sambaNextGroupRid"	},
	{ LDAP_ATTR_DOM_SID,		"sambaSID"		},
	{ LDAP_ATTR_LIST_END,		NULL			},
};

/* Samba 3.0 group mapping attributes */

static ATTRIB_MAP_ENTRY groupmap_attr_list[] = {
	{ LDAP_ATTR_GIDNUMBER,		"gidNumber"		},
	{ LDAP_ATTR_GROUP_SID,		"sambaSID"		},
	{ LDAP_ATTR_GROUP_TYPE,		"sambaGroupType"	},
	{ LDAP_ATTR_DESC,		"description"		},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_CN,			"cn"			},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

static ATTRIB_MAP_ENTRY groupmap_attr_list_to_delete[] = {
	{ LDAP_ATTR_GROUP_SID,		"sambaSID"		},
	{ LDAP_ATTR_GROUP_TYPE,		"sambaGroupType"	},
	{ LDAP_ATTR_DESC,		"description"		},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

/**********************************************************************
 perform a simple table lookup and return the attribute name 
 **********************************************************************/
 
static const char* get_attr_key2string( ATTRIB_MAP_ENTRY table[], int key )
{
	int i = 0;
	
	while ( table[i].attrib != LDAP_ATTR_LIST_END ) {
		if ( table[i].attrib == key )
			return table[i].name;
		i++;
	}
	
	return NULL;
}

/**********************************************************************
 get the attribute name given a user schame version 
 **********************************************************************/
 
static const char* get_userattr_key2string( int schema_ver, int key )
{
	switch ( schema_ver )
	{
		case SCHEMAVER_SAMBAACCOUNT:
			return get_attr_key2string( attrib_map_v22, key );
			
		case SCHEMAVER_SAMBASAMACCOUNT:
			return get_attr_key2string( attrib_map_v30, key );
			
		default:
			DEBUG(0,("get_userattr_key2string: unknown schema version specified\n"));
			break;
	}
	return NULL;
}

/**********************************************************************
 Return the list of attribute names from a mapping table
 **********************************************************************/

static char** get_attr_list( ATTRIB_MAP_ENTRY table[] )
{
	char **names;
	int i = 0;
	
	while ( table[i].attrib != LDAP_ATTR_LIST_END )
		i++;
	i++;

	names = (char**)malloc( sizeof(char*)*i );
	if ( !names ) {
		DEBUG(0,("get_attr_list: out of memory\n"));
		return NULL;
	}

	i = 0;
	while ( table[i].attrib != LDAP_ATTR_LIST_END ) {
		names[i] = strdup( table[i].name );
		i++;
	}
	names[i] = NULL;
	
	return names;
}

/*********************************************************************
 Cleanup 
 ********************************************************************/

static void free_attr_list( char **list )
{
	int i = 0;

	if ( !list )
		return; 

	while ( list[i] )
		SAFE_FREE( list[i] );

	SAFE_FREE( list );
}

/**********************************************************************
 return the list of attribute names given a user schema version 
 **********************************************************************/

static char** get_userattr_list( int schema_ver )
{
	switch ( schema_ver ) 
	{
		case SCHEMAVER_SAMBAACCOUNT:
			return get_attr_list( attrib_map_v22 );
			
		case SCHEMAVER_SAMBASAMACCOUNT:
			return get_attr_list( attrib_map_v30 );
		default:
			DEBUG(0,("get_userattr_list: unknown schema version specified!\n"));
			break;
	}
	
	return NULL;
}

/*******************************************************************
 find the ldap password
******************************************************************/
static BOOL fetch_ldapsam_pw(char **dn, char** pw)
{
	char *key = NULL;
	size_t size;
	
	*dn = smb_xstrdup(lp_ldap_admin_dn());
	
	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, *dn) < 0) {
		SAFE_FREE(*dn);
		DEBUG(0, ("fetch_ldapsam_pw: asprintf failed!\n"));
	}
	
	*pw=secrets_fetch(key, &size);
	SAFE_FREE(key);

	if (!size) {
		/* Upgrade 2.2 style entry */
		char *p;
	        char* old_style_key = strdup(*dn);
		char *data;
		fstring old_style_pw;
		
		if (!old_style_key) {
			DEBUG(0, ("fetch_ldapsam_pw: strdup failed!\n"));
			return False;
		}

		for (p=old_style_key; *p; p++)
			if (*p == ',') *p = '/';
	
		data=secrets_fetch(old_style_key, &size);
		if (!size && size < sizeof(old_style_pw)) {
			DEBUG(0,("fetch_ldap_pw: neither ldap secret retrieved!\n"));
			SAFE_FREE(old_style_key);
			SAFE_FREE(*dn);
			return False;
		}

		strncpy(old_style_pw, data, size);
		old_style_pw[size] = 0;

		SAFE_FREE(data);

		if (!secrets_store_ldap_pw(*dn, old_style_pw)) {
			DEBUG(0,("fetch_ldap_pw: ldap secret could not be upgraded!\n"));
			SAFE_FREE(old_style_key);
			SAFE_FREE(*dn);
			return False;			
		}
		if (!secrets_delete(old_style_key)) {
			DEBUG(0,("fetch_ldap_pw: old ldap secret could not be deleted!\n"));
		}

		SAFE_FREE(old_style_key);

		*pw = smb_xstrdup(old_style_pw);		
	}
	
	return True;
}
			     
/*******************************************************************
 open a connection to the ldap server.
******************************************************************/
static int ldapsam_open_connection (struct ldapsam_privates *ldap_state, LDAP ** ldap_struct)
{
	int rc = LDAP_SUCCESS;
	int version;
	BOOL ldap_v3 = False;

#ifdef HAVE_LDAP_INITIALIZE
	DEBUG(10, ("ldapsam_open_connection: %s\n", ldap_state->uri));
	
	if ((rc = ldap_initialize(ldap_struct, ldap_state->uri)) != LDAP_SUCCESS) {
		DEBUG(0, ("ldap_initialize: %s\n", ldap_err2string(rc)));
		return rc;
	}
	
#else 

	/* Parse the string manually */

	{
		int port = 0;
		fstring protocol;
		fstring host;
		const char *p = ldap_state->uri; 
		SMB_ASSERT(sizeof(protocol)>10 && sizeof(host)>254);
		
		/* skip leading "URL:" (if any) */
		if ( strncasecmp( p, "URL:", 4 ) == 0 ) {
			p += 4;
		}
		
		sscanf(p, "%10[^:]://%254s[^:]:%d", protocol, host, &port);
		
		if (port == 0) {
			if (strequal(protocol, "ldap")) {
				port = LDAP_PORT;
			} else if (strequal(protocol, "ldaps")) {
				port = LDAPS_PORT;
			} else {
				DEBUG(0, ("unrecognised protocol (%s)!\n", protocol));
			}
		}
		
		if ((*ldap_struct = ldap_init(host, port)) == NULL)	{
			DEBUG(0, ("ldap_init failed !\n"));
			return LDAP_OPERATIONS_ERROR;
		}
		
	        if (strequal(protocol, "ldaps")) {
#ifdef LDAP_OPT_X_TLS
			int tls = LDAP_OPT_X_TLS_HARD;
			if (ldap_set_option (*ldap_struct, LDAP_OPT_X_TLS, &tls) != LDAP_SUCCESS)
			{
				DEBUG(0, ("Failed to setup a TLS session\n"));
			}
			
			DEBUG(3,("LDAPS option set...!\n"));
#else
			DEBUG(0,("ldapsam_open_connection: Secure connection not supported by LDAP client libraries!\n"));
			return LDAP_OPERATIONS_ERROR;
#endif
		}
	}
#endif

	if (ldap_get_option(*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS)
	{
		if (version != LDAP_VERSION3)
		{
			version = LDAP_VERSION3;
			if (ldap_set_option (*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS) {
				ldap_v3 = True;
			}
		} else {
			ldap_v3 = True;
		}
	}

	if (lp_ldap_ssl() == LDAP_SSL_START_TLS) {
#ifdef LDAP_OPT_X_TLS
		if (ldap_v3) {
			if ((rc = ldap_start_tls_s (*ldap_struct, NULL, NULL)) != LDAP_SUCCESS)
			{
				DEBUG(0,("Failed to issue the StartTLS instruction: %s\n",
					 ldap_err2string(rc)));
				return rc;
			}
			DEBUG (3, ("StartTLS issued: using a TLS connection\n"));
		} else {
			
			DEBUG(0, ("Need LDAPv3 for Start TLS\n"));
			return LDAP_OPERATIONS_ERROR;
		}
#else
		DEBUG(0,("ldapsam_open_connection: StartTLS not supported by LDAP client libraries!\n"));
		return LDAP_OPERATIONS_ERROR;
#endif
	}

	DEBUG(2, ("ldapsam_open_connection: connection opened\n"));
	return rc;
}


/*******************************************************************
 a rebind function for authenticated referrals
 This version takes a void* that we can shove useful stuff in :-)
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#else
static int rebindproc_with_state  (LDAP * ld, char **whop, char **credp, 
				   int *methodp, int freeit, void *arg)
{
	struct ldapsam_privates *ldap_state = arg;
	
	/** @TODO Should we be doing something to check what servers we rebind to?
	    Could we get a referral to a machine that we don't want to give our
	    username and password to? */
	
	if (freeit) {
		SAFE_FREE(*whop);
		memset(*credp, '\0', strlen(*credp));
		SAFE_FREE(*credp);
	} else {
		DEBUG(5,("rebind_proc_with_state: Rebinding as \"%s\"\n", 
			  ldap_state->bind_dn));

		*whop = strdup(ldap_state->bind_dn);
		if (!*whop) {
			return LDAP_NO_MEMORY;
		}
		*credp = strdup(ldap_state->bind_secret);
		if (!*credp) {
			SAFE_FREE(*whop);
			return LDAP_NO_MEMORY;
		}
		*methodp = LDAP_AUTH_SIMPLE;
	}
	return 0;
}
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 a rebind function for authenticated referrals
 This version takes a void* that we can shove useful stuff in :-)
 and actually does the connection.
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
static int rebindproc_connect_with_state (LDAP *ldap_struct, 
					  LDAP_CONST char *url, 
					  ber_tag_t request,
					  ber_int_t msgid, void *arg)
{
	struct ldapsam_privates *ldap_state = arg;
	int rc;
	DEBUG(5,("rebindproc_connect_with_state: Rebinding as \"%s\"\n", 
		 ldap_state->bind_dn));
	
	/** @TODO Should we be doing something to check what servers we rebind to?
	    Could we get a referral to a machine that we don't want to give our
	    username and password to? */

	rc = ldap_simple_bind_s(ldap_struct, ldap_state->bind_dn, ldap_state->bind_secret);
	
	return rc;
}
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 Add a rebind function for authenticated referrals
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#else
# if LDAP_SET_REBIND_PROC_ARGS == 2
static int rebindproc (LDAP *ldap_struct, char **whop, char **credp,
		       int *method, int freeit )
{
	return rebindproc_with_state(ldap_struct, whop, credp,
				   method, freeit, static_ldap_state);
	
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 a rebind function for authenticated referrals
 this also does the connection, but no void*.
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
# if LDAP_SET_REBIND_PROC_ARGS == 2
static int rebindproc_connect (LDAP * ld, LDAP_CONST char *url, int request,
			       ber_int_t msgid)
{
	return rebindproc_connect_with_state(ld, url, (ber_tag_t)request, msgid, 
					     static_ldap_state);
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 connect to the ldap server under system privilege.
******************************************************************/
static int ldapsam_connect_system(struct ldapsam_privates *ldap_state, LDAP * ldap_struct)
{
	int rc;
	char *ldap_dn;
	char *ldap_secret;

	/* The rebind proc needs this *HACK*.  We are not multithreaded, so
	   this will work, but it's not nice. */
	static_ldap_state = ldap_state;

	/* get the password */
	if (!fetch_ldapsam_pw(&ldap_dn, &ldap_secret))
	{
		DEBUG(0, ("ldap_connect_system: Failed to retrieve password from secrets.tdb\n"));
		return LDAP_INVALID_CREDENTIALS;
	}

	ldap_state->bind_dn = ldap_dn;
	ldap_state->bind_secret = ldap_secret;

	/* removed the sasl_bind_s "EXTERNAL" stuff, as my testsuite 
	   (OpenLDAP) doesnt' seem to support it */
	   
	DEBUG(10,("ldap_connect_system: Binding to ldap server %s as \"%s\"\n",
		  ldap_state->uri, ldap_dn));

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
# if LDAP_SET_REBIND_PROC_ARGS == 2	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_connect);	
# endif
# if LDAP_SET_REBIND_PROC_ARGS == 3	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_connect_with_state, (void *)ldap_state);	
# endif
#else /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/
# if LDAP_SET_REBIND_PROC_ARGS == 2	
	ldap_set_rebind_proc(ldap_struct, &rebindproc);	
# endif
# if LDAP_SET_REBIND_PROC_ARGS == 3	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_with_state, (void *)ldap_state);	
# endif
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

	rc = ldap_simple_bind_s(ldap_struct, ldap_dn, ldap_secret);

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(ldap_state->num_failures ? 2 : 0,
		      ("failed to bind to server with dn= %s Error: %s\n\t%s\n",
			       ldap_dn ? ld_error : "(unknown)", ldap_err2string(rc),
			       ld_error));
		SAFE_FREE(ld_error);
		ldap_state->num_failures++;
		return rc;
	}

	ldap_state->num_failures = 0;

	DEBUG(3, ("ldap_connect_system: succesful connection to the LDAP server\n"));
	return rc;
}

/**********************************************************************
Connect to LDAP server 
*********************************************************************/
static int ldapsam_open(struct ldapsam_privates *ldap_state)
{
	int rc;
	SMB_ASSERT(ldap_state);
		
#ifndef NO_LDAP_SECURITY
	if (geteuid() != 0) {
		DEBUG(0, ("ldapsam_open: cannot access LDAP when not root..\n"));
		return  LDAP_INSUFFICIENT_ACCESS;
	}
#endif

	if ((ldap_state->ldap_struct != NULL) && ((ldap_state->last_ping + LDAPSAM_DONT_PING_TIME) < time(NULL))) {
		struct sockaddr_un addr;
		socklen_t len = sizeof(addr);
		int sd;
		if (ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_DESC, &sd) == 0 &&
		    getpeername(sd, (struct sockaddr *) &addr, &len) < 0) {
		    	/* the other end has died. reopen. */
		    	ldap_unbind_ext(ldap_state->ldap_struct, NULL, NULL);
		    	ldap_state->ldap_struct = NULL;
		    	ldap_state->last_ping = (time_t)0;
		} else {
			ldap_state->last_ping = time(NULL);
		} 
    	}

	if (ldap_state->ldap_struct != NULL) {
		DEBUG(5,("ldapsam_open: already connected to the LDAP server\n"));
		return LDAP_SUCCESS;
	}

	if ((rc = ldapsam_open_connection(ldap_state, &ldap_state->ldap_struct))) {
		return rc;
	}

	if ((rc = ldapsam_connect_system(ldap_state, ldap_state->ldap_struct))) {
		ldap_unbind_ext(ldap_state->ldap_struct, NULL, NULL);
		ldap_state->ldap_struct = NULL;
		return rc;
	}


	ldap_state->last_ping = time(NULL);
	DEBUG(4,("The LDAP server is succesful connected\n"));

	return LDAP_SUCCESS;
}

/**********************************************************************
Disconnect from LDAP server 
*********************************************************************/
static NTSTATUS ldapsam_close(struct ldapsam_privates *ldap_state)
{
	if (!ldap_state)
		return NT_STATUS_INVALID_PARAMETER;
		
	if (ldap_state->ldap_struct != NULL) {
		ldap_unbind_ext(ldap_state->ldap_struct, NULL, NULL);
		ldap_state->ldap_struct = NULL;
	}
	
	DEBUG(5,("The connection to the LDAP server was closed\n"));
	/* maybe free the results here --metze */
	
	return NT_STATUS_OK;
}

static int ldapsam_retry_open(struct ldapsam_privates *ldap_state, int *attempts)
{
	int rc;

	SMB_ASSERT(ldap_state && attempts);
		
	if (*attempts != 0) {
		unsigned int sleep_time;
		uint8 rand_byte;

		/* Sleep for a random timeout */
		rand_byte = (char)(sys_random());

		sleep_time = (((*attempts)*(*attempts))/2)*rand_byte*2; 
		/* we retry after (0.5, 1, 2, 3, 4.5, 6) seconds
		   on average.  
		 */
		DEBUG(3, ("Sleeping for %u milliseconds before reconnecting\n", 
			  sleep_time));
		msleep(sleep_time);
	}
	(*attempts)++;

	if ((rc = ldapsam_open(ldap_state))) {
		DEBUG(1,("Connection to LDAP Server failed for the %d try!\n",*attempts));
		return rc;
	} 
	
	return LDAP_SUCCESS;		
}


/*********************************************************************
 ********************************************************************/

static int ldapsam_search(struct ldapsam_privates *ldap_state, 
			  const char *base, int scope, const char *filter, 
			  char *attrs[], int attrsonly, 
			  LDAPMessage **res)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	char           *utf8_filter;

	SMB_ASSERT(ldap_state);

	if (push_utf8_allocate(&utf8_filter, filter) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_search_s(ldap_state->ldap_struct, base, scope, 
				   utf8_filter, attrs, attrsonly, res);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}

	SAFE_FREE(utf8_filter);
	return rc;
}

static int ldapsam_modify(struct ldapsam_privates *ldap_state, const char *dn, LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	char           *utf8_dn;

	SMB_ASSERT(ldap_state);

	if (push_utf8_allocate(&utf8_dn, dn) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_modify_s(ldap_state->ldap_struct, utf8_dn, attrs);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
	
	SAFE_FREE(utf8_dn);
	return rc;
}

static int ldapsam_add(struct ldapsam_privates *ldap_state, const char *dn, LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	char           *utf8_dn;
	
	SMB_ASSERT(ldap_state);

	if (push_utf8_allocate(&utf8_dn, dn) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_add_s(ldap_state->ldap_struct, utf8_dn, attrs);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
		
	SAFE_FREE(utf8_dn);
	return rc;
}

static int ldapsam_delete(struct ldapsam_privates *ldap_state, char *dn)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	char           *utf8_dn;
	
	SMB_ASSERT(ldap_state);

	if (push_utf8_allocate(&utf8_dn, dn) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_delete_s(ldap_state->ldap_struct, utf8_dn);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
		
	SAFE_FREE(utf8_dn);
	return rc;
}

#ifdef LDAP_EXOP_X_MODIFY_PASSWD
static int ldapsam_extended_operation(struct ldapsam_privates *ldap_state, LDAP_CONST char *reqoid, struct berval *reqdata, LDAPControl **serverctrls, LDAPControl **clientctrls, char **retoidp, struct berval **retdatap)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_extended_operation_s(ldap_state->ldap_struct, reqoid, reqdata, serverctrls, clientctrls, retoidp, retdatap);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
		
	return rc;
}
#endif

/*******************************************************************
 run the search by name.
******************************************************************/
static int ldapsam_search_suffix (struct ldapsam_privates *ldap_state, const char *filter, 
				char **search_attr, LDAPMessage ** result)
{
	int scope = LDAP_SCOPE_SUBTREE;
	int rc;

	DEBUG(2, ("ldapsam_search_suffix: searching for:[%s]\n", filter));

	rc = ldapsam_search(ldap_state, lp_ldap_suffix(), scope, filter, search_attr, 0, result);

	if (rc != LDAP_SUCCESS)	{
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0,("ldapsam_search_suffix: Problem during the LDAP search: %s (%s)\n", 
			ld_error?ld_error:"(unknown)", ldap_err2string (rc)));
		DEBUG(3,("ldapsam_search_suffix: Query was: %s, %s\n", lp_ldap_suffix(), 
			filter));
		SAFE_FREE(ld_error);
	}
	
	return rc;
}

/*******************************************************************
 generate the LDAP search filter for the objectclass based on the 
 version of the schema we are using 
 ******************************************************************/

static const char* get_objclass_filter( int schema_ver )
{
	static fstring objclass_filter;
	
	switch( schema_ver ) 
	{
		case SCHEMAVER_SAMBAACCOUNT:
			snprintf( objclass_filter, sizeof(objclass_filter)-1, "(objectclass=%s)", LDAP_OBJ_SAMBAACCOUNT );
			break;
		case SCHEMAVER_SAMBASAMACCOUNT:
			snprintf( objclass_filter, sizeof(objclass_filter)-1, "(objectclass=%s)", LDAP_OBJ_SAMBASAMACCOUNT );
			break;
		default:
			DEBUG(0,("ldapsam_search_suffix_by_name(): Invalid schema version specified!\n"));
			break;
	}
	
	return objclass_filter;	
}

/*******************************************************************
 run the search by name.
******************************************************************/
static int ldapsam_search_suffix_by_name (struct ldapsam_privates *ldap_state, const char *user,
			     LDAPMessage ** result, char **attr)
{
	pstring filter;
	char *escape_user = escape_ldap_string_alloc(user);

	if (!escape_user) {
		return LDAP_NO_MEMORY;
	}

	/*
	 * in the filter expression, replace %u with the real name
	 * so in ldap filter, %u MUST exist :-)
	 */
	snprintf(filter, sizeof(filter)-1, "(&%s%s)", lp_ldap_filter(), 
		get_objclass_filter(ldap_state->schema_ver));

	/* 
	 * have to use this here because $ is filtered out
	   * in pstring_sub
	 */
	

	all_string_sub(filter, "%u", escape_user, sizeof(pstring));
	SAFE_FREE(escape_user);

	return ldapsam_search_suffix(ldap_state, filter, attr, result);
}

/*******************************************************************
 run the search by rid.
******************************************************************/
static int ldapsam_search_suffix_by_rid (struct ldapsam_privates *ldap_state, 
					uint32 rid, LDAPMessage ** result, 
					char **attr)
{
	pstring filter;
	int rc;

	/* check if the user rid exists, if not, try searching on the uid */

	snprintf(filter, sizeof(filter)-1, "(&(rid=%i)%s)", rid, 
		get_objclass_filter(ldap_state->schema_ver));
	
	rc = ldapsam_search_suffix(ldap_state, filter, attr, result);
	
	return rc;
}

/*******************************************************************
 run the search by SID.
******************************************************************/
static int ldapsam_search_suffix_by_sid (struct ldapsam_privates *ldap_state, 
					const DOM_SID *sid, LDAPMessage ** result, 
					char **attr)
{
	pstring filter;
	int rc;
	fstring sid_string;

	/* check if the user rid exsists, if not, try searching on the uid */

	snprintf(filter, sizeof(filter)-1, "(&(%s=%s)%s)", 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_SID),
		sid_to_string(sid_string, sid), 
		get_objclass_filter(ldap_state->schema_ver));
		
	rc = ldapsam_search_suffix(ldap_state, filter, attr, result);
	
	return rc;
}

/*******************************************************************
search an attribute and return the first value found.
******************************************************************/
static BOOL get_single_attribute (LDAP * ldap_struct, LDAPMessage * entry,
				  const char *attribute, pstring value)
{
	char **values;
	
	if ( !attribute )
		return False;
		
	value[0] = '\0';

	if ((values = ldap_get_values (ldap_struct, entry, attribute)) == NULL) {
		DEBUG (10, ("get_single_attribute: [%s] = [<does not exist>]\n", attribute));
		
		return False;
	}
	
	if (convert_string(CH_UTF8, CH_UNIX,values[0], -1, value, sizeof(pstring)) == (size_t)-1)
	{
		DEBUG(1, ("get_single_attribute: string conversion of [%s] = [%s] failed!\n", 
			  attribute, values[0]));
		ldap_value_free(values);
		return False;
	}
	
	ldap_value_free(values);
#ifdef DEBUG_PASSWORDS
	DEBUG (100, ("get_single_attribute: [%s] = [%s]\n", attribute, value));
#endif	
	return True;
}

/************************************************************************
Routine to manage the LDAPMod structure array
manage memory used by the array, by each struct, and values

************************************************************************/
static void make_a_mod (LDAPMod *** modlist, int modop, const char *attribute, const char *value)
{
	LDAPMod **mods;
	int i;
	int j;

	mods = *modlist;

	/* sanity checks on the mod values */

	if (attribute == NULL || *attribute == '\0')
		return;	
#if 0	/* commented out after discussion with abartlet.  Do not reenable.
	   left here so other so re-add similar code   --jerry */
       	if (value == NULL || *value == '\0')
		return;
#endif

	if (mods == NULL) 
	{
		mods = (LDAPMod **) malloc(sizeof(LDAPMod *));
		if (mods == NULL)
		{
			DEBUG(0, ("make_a_mod: out of memory!\n"));
			return;
		}
		mods[0] = NULL;
	}

	for (i = 0; mods[i] != NULL; ++i) {
		if (mods[i]->mod_op == modop && !strcasecmp(mods[i]->mod_type, attribute))
			break;
	}

	if (mods[i] == NULL)
	{
		mods = (LDAPMod **) Realloc (mods, (i + 2) * sizeof (LDAPMod *));
		if (mods == NULL)
		{
			DEBUG(0, ("make_a_mod: out of memory!\n"));
			return;
		}
		mods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
		if (mods[i] == NULL)
		{
			DEBUG(0, ("make_a_mod: out of memory!\n"));
			return;
		}
		mods[i]->mod_op = modop;
		mods[i]->mod_values = NULL;
		mods[i]->mod_type = strdup(attribute);
		mods[i + 1] = NULL;
	}

	if (value != NULL)
	{
		char *utf8_value = NULL;

		j = 0;
		if (mods[i]->mod_values != NULL) {
			for (; mods[i]->mod_values[j] != NULL; j++);
		}
		mods[i]->mod_values = (char **)Realloc(mods[i]->mod_values,
					       (j + 2) * sizeof (char *));
					       
		if (mods[i]->mod_values == NULL) {
			DEBUG (0, ("make_a_mod: Memory allocation failure!\n"));
			return;
		}

		if (push_utf8_allocate(&utf8_value, value) == (size_t)-1) {
			DEBUG (0, ("make_a_mod: String conversion failure!\n"));
			return;
		}

		mods[i]->mod_values[j] = utf8_value;

		mods[i]->mod_values[j + 1] = NULL;
	}
	*modlist = mods;
}

/**********************************************************************
  Set attribute to newval in LDAP, regardless of what value the
  attribute had in LDAP before.
*********************************************************************/
static void make_ldap_mod(LDAP *ldap_struct, LDAPMessage *existing,
			  LDAPMod ***mods,
			  const char *attribute, const char *newval)
{
	char **values = NULL;

	if (existing != NULL) {
		values = ldap_get_values(ldap_struct, existing, attribute);
	}

	/* all of our string attributes are case insensitive */
	
	if ((values != NULL) && (values[0] != NULL) &&
	    StrCaseCmp(values[0], newval) == 0) 
	{
		
		/* Believe it or not, but LDAP will deny a delete and
		   an add at the same time if the values are the
		   same... */

		ldap_value_free(values);
		return;
	}

	/* Regardless of the real operation (add or modify)
	   we add the new value here. We rely on deleting
	   the old value, should it exist. */

	if ((newval != NULL) && (strlen(newval) > 0)) {
		make_a_mod(mods, LDAP_MOD_ADD, attribute, newval);
	}

	if (values == NULL) {
		/* There has been no value before, so don't delete it.
		   Here's a possible race: We might end up with
		   duplicate attributes */
		return;
	}

	/* By deleting exactly the value we found in the entry this
	   should be race-free in the sense that the LDAP-Server will
	   deny the complete operation if somebody changed the
	   attribute behind our back. */

	make_a_mod(mods, LDAP_MOD_DELETE, attribute, values[0]);
	ldap_value_free(values);
}

/*******************************************************************
 Delete complete object or objectclass and attrs from
 object found in search_result depending on lp_ldap_delete_dn
******************************************************************/
static NTSTATUS ldapsam_delete_entry(struct ldapsam_privates *ldap_state,
				     LDAPMessage *result,
				     const char *objectclass,
				     char **attrs)
{
	int rc;
	LDAPMessage *entry;
	LDAPMod **mods = NULL;
	char *name, *dn;
	BerElement *ptr = NULL;

	rc = ldap_count_entries(ldap_state->ldap_struct, result);

	if (rc != 1) {
		DEBUG(0, ("Entry must exist exactly once!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	dn    = ldap_get_dn(ldap_state->ldap_struct, entry);

	if (lp_ldap_delete_dn()) {
		NTSTATUS ret = NT_STATUS_OK;
		rc = ldapsam_delete(ldap_state, dn);

		if (rc != LDAP_SUCCESS) {
			DEBUG(0, ("Could not delete object %s\n", dn));
			ret = NT_STATUS_UNSUCCESSFUL;
		}
		ldap_memfree(dn);
		return ret;
	}

	/* Ok, delete only the SAM attributes */
	
	for (name = ldap_first_attribute(ldap_state->ldap_struct, entry, &ptr);
	     name != NULL;
	     name = ldap_next_attribute(ldap_state->ldap_struct, entry, ptr)) 
	{
		char **attrib;

		/* We are only allowed to delete the attributes that
		   really exist. */

		for (attrib = attrs; *attrib != NULL; attrib++) 
		{
			if (StrCaseCmp(*attrib, name) == 0) {
				DEBUG(10, ("deleting attribute %s\n", name));
				make_a_mod(&mods, LDAP_MOD_DELETE, name, NULL);
			}
		}

		ldap_memfree(name);
	}
	
	if (ptr != NULL) {
		ber_free(ptr, 0);
	}
	
	make_a_mod(&mods, LDAP_MOD_DELETE, "objectClass", objectclass);

	rc = ldapsam_modify(ldap_state, dn, mods);
	ldap_mods_free(mods, 1);

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		
		DEBUG(0, ("could not delete attributes for %s, error: %s (%s)\n",
			  dn, ldap_err2string(rc), ld_error?ld_error:"unknown"));
		SAFE_FREE(ld_error);
		ldap_memfree(dn);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ldap_memfree(dn);
	return NT_STATUS_OK;
}
					  
/**********************************************************************
Search for the domain info entry
*********************************************************************/
static int ldapsam_search_domain_info(struct ldapsam_privates *ldap_state,
				      LDAPMessage ** result)
{
	pstring filter;
	int rc;
	char **attr_list;

	snprintf(filter, sizeof(filter)-1, "(&(objectClass=%s)(%s=%s))",
		LDAP_OBJ_DOMINFO,
		get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		ldap_state->domain_name);

	DEBUG(2, ("Searching for:[%s]\n", filter));


	attr_list = get_attr_list( dominfo_attr_list );
	rc = ldapsam_search_suffix(ldap_state, filter, attr_list , result);
	free_attr_list( attr_list );

	if (rc != LDAP_SUCCESS) {
		DEBUG(2,("Problem during LDAPsearch: %s\n", ldap_err2string (rc)));
		DEBUG(2,("Query was: %s, %s\n", lp_ldap_suffix(), filter));
	}
	
	return rc;
}

/**********************************************************************
 If this entry is is the 'allocated' range, extract the RID and return 
 it, so we can find the 'next' rid to allocate.

 Do this, no matter what type of object holds the RID - be it a user,
 group or somthing else.
*********************************************************************/
static uint32 entry_to_rid(struct ldapsam_privates *ldap_state, LDAPMessage *entry, int rid_type) 
{
	pstring sid_string;
	DOM_SID dom_sid;
	uint32 rid;

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		LDAP_ATTRIBUTE_SID, sid_string)) 
	{
		return 0;
	}
	
	if (!string_to_sid(&dom_sid, sid_string)) {
		return 0;
	}

	if (!sid_peek_check_rid(&dom_sid, get_global_sam_sid(), &rid)) {
		/* not our domain, so we don't care */
		return 0;
	}

	switch (rid_type) {
	case USER_RID_TYPE:
		if (rid >= ldap_state->low_allocated_user_rid && 
		    rid <= ldap_state->high_allocated_user_rid) {
			return rid;
		}
		break;
	case GROUP_RID_TYPE:
		if (rid >= ldap_state->low_allocated_group_rid && 
		    rid <= ldap_state->high_allocated_group_rid) {
			return rid;
		}
		break;
	}
	return 0;
}


/**********************************************************************
Connect to LDAP server and find the next available 'allocated' RID.

The search is done 'per type' as we allocate seperate pools for the
EVEN and ODD (user and group) RIDs.  

This is only done once, so that we can fill out the sambaDomain.
*********************************************************************/
static uint32 search_next_allocated_rid(struct ldapsam_privates *ldap_state, int rid_type)
{
	int rc;
	LDAPMessage *result;
	LDAPMessage *entry;
	uint32 top_rid = 0;
	uint32 next_rid;
	uint32 count;
	uint32 rid;
	char *sid_attr[] = {LDAP_ATTRIBUTE_SID, NULL};
	fstring filter;
	
	snprintf( filter, sizeof(filter)-1, "(%s=*)", LDAP_ATTRIBUTE_SID );

	DEBUG(2, ("search_top_allocated_rid: searching for:[%s]\n", filter));

	rc = ldapsam_search_suffix(ldap_state, filter, sid_attr, &result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(3, ("LDAP search failed! cannot find base for NUA RIDs: %s\n", ldap_err2string(rc)));
		DEBUGADD(3, ("Query was: %s, %s\n", lp_ldap_suffix(), filter));

		result = NULL;
		return 0;
	}
	
	count = ldap_count_entries(ldap_state->ldap_struct, result);
	DEBUG(2, ("search_top_allocated_rid: %d entries in the base!\n", count));
	
	if (count == 0) {
		DEBUG(3, ("LDAP search returned no records, assuming no allocated RIDs present!: %s\n", ldap_err2string(rc)));
		DEBUGADD(3, ("Query was: %s, %s\n", lp_ldap_suffix(), filter));
	} else {
		entry = ldap_first_entry(ldap_state->ldap_struct,result);
		
		top_rid = entry_to_rid(ldap_state, entry, rid_type);
		
		while ((entry = ldap_next_entry(ldap_state->ldap_struct, entry))) {
			
			rid = entry_to_rid(ldap_state, entry, rid_type);
			if (((rid & ~RID_TYPE_MASK) == rid_type) && (rid > top_rid)) {
				top_rid = rid;
			}
		}
	}

	switch (rid_type) {
	case USER_RID_TYPE:
		if (top_rid < ldap_state->low_allocated_user_rid) {
			return ldap_state->low_allocated_user_rid;
		}
		break;
	case GROUP_RID_TYPE:
		if (top_rid < ldap_state->low_allocated_group_rid) 
			return ldap_state->low_allocated_group_rid;
		break;
	}

	next_rid = (top_rid & ~RID_TYPE_MASK) + rid_type + RID_MULTIPLIER;

	switch (rid_type) {
	case USER_RID_TYPE:
		if (next_rid > ldap_state->high_allocated_user_rid) {
			return 0;
		}
		break;
	case GROUP_RID_TYPE:
		if (next_rid > ldap_state->high_allocated_group_rid) {
			return 0;
		}
		break;
	}
	return next_rid;
}

/**********************************************************************
 Add the sambaDomain to LDAP, so we don't have to search for this stuff
 again.  This is a once-add operation for now.

 TODO:  Add other attributes, and allow modification.
*********************************************************************/
static NTSTATUS add_new_domain_info(struct ldapsam_privates *ldap_state) 
{
	pstring tmp;
	pstring filter;
	LDAPMod **mods = NULL;
	int rc;
	int ldap_op;
	LDAPMessage *result = NULL;
	char *dn = NULL;
	int num_result;
	char **attr_list;

	uint32 next_allocated_user_rid;
	uint32 next_allocated_group_rid;

	next_allocated_user_rid = search_next_allocated_rid(ldap_state, USER_RID_TYPE);
	if (!next_allocated_user_rid) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	next_allocated_group_rid = search_next_allocated_rid(ldap_state, GROUP_RID_TYPE);
	if (!next_allocated_group_rid) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	slprintf (filter, sizeof (filter) - 1, "(&(%s=%s)(objectclass=%s))", 
		get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		ldap_state->domain_name, LDAP_OBJ_DOMINFO);

	attr_list = get_attr_list( dominfo_attr_list );
	rc = ldapsam_search_suffix(ldap_state, filter, attr_list, &result);
	free_attr_list( attr_list );

	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	num_result = ldap_count_entries(ldap_state->ldap_struct, result);
	
	if (num_result > 1) {
		DEBUG (0, ("More than domain with that name exists: bailing out!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	/* Check if we need to add an entry */
	DEBUG(3,("Adding new domain\n"));
	ldap_op = LDAP_MOD_ADD;
	asprintf (&dn, "%s=%s,%s", get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN),
		ldap_state->domain_name, lp_ldap_suffix());

	/* Free original search */
	ldap_msgfree(result);

	if (!dn)
		return NT_STATUS_NO_MEMORY;

	/* make the changes - the entry *must* not already have samba attributes */
	make_a_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		ldap_state->domain_name);

	sid_to_string(tmp, &ldap_state->domain_sid);
	make_a_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOM_SID), tmp);

	snprintf(tmp, sizeof(tmp)-1, "%i", next_allocated_user_rid);
	make_a_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_USERRID), tmp);

	snprintf(tmp, sizeof(tmp)-1, "%i", next_allocated_group_rid);
	make_a_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_GROUPRID), tmp);

	make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", LDAP_OBJ_DOMINFO);

	switch(ldap_op)
	{
	case LDAP_MOD_ADD: 
		rc = ldapsam_add(ldap_state, dn, mods);
		break;
	case LDAP_MOD_REPLACE: 
		rc = ldapsam_modify(ldap_state, dn, mods);
		break;
	default: 	
		DEBUG(0,("Wrong LDAP operation type: %d!\n", ldap_op));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	if (rc!=LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(1,
		      ("failed to %s domain dn= %s with: %s\n\t%s\n",
		       ldap_op == LDAP_MOD_ADD ? "add" : "modify",
		       dn, ldap_err2string(rc),
		       ld_error?ld_error:"unknown"));
		SAFE_FREE(ld_error);

		ldap_mods_free(mods,1);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2,("added: domain = %s in the LDAP database\n", ldap_state->domain_name));
	ldap_mods_free(mods, 1);
	return NT_STATUS_OK;
}

/**********************************************************************
 Even if the sambaAccount attribute in LDAP tells us that this RID is 
 safe to use, always check before use.  
*********************************************************************/
static BOOL sid_in_use(struct ldapsam_privates *ldap_state, 
		       const DOM_SID *sid, int *error) 
{
	fstring filter;
	fstring sid_string;
	LDAPMessage *result = NULL;
	int count;
	int rc;
	char *sid_attr[] = {LDAP_ATTRIBUTE_SID, NULL};

	slprintf(filter, sizeof(filter)-1, "(%s=%s)", LDAP_ATTRIBUTE_SID, sid_to_string(sid_string, sid));

	rc = ldapsam_search_suffix(ldap_state, filter, sid_attr, &result);

	if (rc != LDAP_SUCCESS)	{
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG(2, ("Failed to check if sid %s is alredy in use: %s\n", 
			  sid_string, ld_error));
		SAFE_FREE(ld_error);

		*error = rc;
		return True;
	}
	
	if ((count = ldap_count_entries(ldap_state->ldap_struct, result)) > 0) {
		DEBUG(3, ("Sid %s already in use - trying next RID\n",
			  sid_string));
		ldap_msgfree(result);
		return True;
	}

	ldap_msgfree(result);

	/* good, sid is not in use */
	return False;
}

/**********************************************************************
 Set the new nextRid attribute, and return one we can use.

 This also checks that this RID is actually free - in case the admin
 manually stole it :-).
*********************************************************************/
static NTSTATUS ldapsam_next_rid(struct ldapsam_privates *ldap_state, uint32 *rid, int rid_type)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	int rc;
	LDAPMessage *result = NULL;
	LDAPMessage *entry  = NULL;
	char *dn;
	LDAPMod **mods = NULL;
	int count;
	fstring old_rid_string;
	fstring next_rid_string;
	uint32 next_rid;
	int attempts = 0;

	if ( ldap_state->schema_ver != SCHEMAVER_SAMBASAMACCOUNT ) {
		DEBUG(0, ("Allocated RIDs require the %s objectclass used by 'ldapsam'\n", 
			LDAP_OBJ_SAMBASAMACCOUNT));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	while (attempts < 10) 
	{
		char *ld_error;
		if (ldapsam_search_domain_info(ldap_state, &result)) {
			return ret;
		}

		if (ldap_count_entries(ldap_state->ldap_struct, result) < 1) {
			DEBUG(3, ("Got no domain info entries for domain %s\n",
				  ldap_state->domain_name));
			ldap_msgfree(result);
			if (NT_STATUS_IS_OK(ret = add_new_domain_info(ldap_state))) {
				continue;
			} else {
				DEBUG(0, ("Adding domain info failed with %s\n", nt_errstr(ret)));
				return ret;
			}
		}
		
		if ((count = ldap_count_entries(ldap_state->ldap_struct, result)) > 1) {
			DEBUG(0, ("Got too many (%d) domain info entries for domain %s\n",
				  count, ldap_state->domain_name));
			ldap_msgfree(result);
			return ret;
		}

		entry = ldap_first_entry(ldap_state->ldap_struct, result);
		if (!entry) {
			ldap_msgfree(result);
			return ret;
		}

		if ((dn = ldap_get_dn(ldap_state->ldap_struct, entry)) == NULL) {
			DEBUG(0, ("Could not get domain info DN\n"));
			ldap_msgfree(result);
			return ret;
		}

		/* yes, we keep 2 seperate counters, to avoid stomping on the two
		   different sets of algorithmic RIDs */

		switch (rid_type) {
		case USER_RID_TYPE:
			if (!get_single_attribute(ldap_state->ldap_struct, entry,
				get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_GROUPRID),
				old_rid_string)) 
			{
				ldap_memfree(dn);
				ldap_msgfree(result);
				return ret;
			}
			break;
		case GROUP_RID_TYPE:
			if (!get_single_attribute(ldap_state->ldap_struct, entry, 
				get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_GROUPRID),
				old_rid_string)) 
			{
				ldap_memfree(dn);
				ldap_msgfree(result);
				return ret;
			}
			break;
		}

		/* This is the core of the whole routine. If we had
                   scheme-style closures, there would be a *lot* less code
                   duplication... */
		*rid = (uint32)atol(old_rid_string);
		next_rid = *rid+RID_MULTIPLIER;

		slprintf(next_rid_string, sizeof(next_rid_string)-1, "%d", next_rid);

		switch (rid_type) {
		case USER_RID_TYPE:
			if (next_rid > ldap_state->high_allocated_user_rid) {
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* Try to make the modification atomically by enforcing the
			   old value in the delete mod. */
			make_ldap_mod(ldap_state->ldap_struct, entry, &mods, 
				get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_USERRID), 
				next_rid_string);
			break;

		case GROUP_RID_TYPE:
			if (next_rid > ldap_state->high_allocated_group_rid) {
				return NT_STATUS_UNSUCCESSFUL;
			}

			/* Try to make the modification atomically by enforcing the
			   old value in the delete mod. */
			make_ldap_mod(ldap_state->ldap_struct, entry, &mods,
				get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_GROUPRID),
				next_rid_string);
			break;
		}

		if ((rc = ldap_modify_s(ldap_state->ldap_struct, dn, mods)) == LDAP_SUCCESS) {
			DOM_SID dom_sid;
			DOM_SID sid;
			pstring domain_sid_string;
			int error = 0;

			if (!get_single_attribute(ldap_state->ldap_struct, result,
				get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOM_SID),
				domain_sid_string)) 
			{
				ldap_mods_free(mods, 1);
				ldap_memfree(dn);
				ldap_msgfree(result);
				return ret;
			}

			if (!string_to_sid(&dom_sid, domain_sid_string)) { 
				ldap_mods_free(mods, 1);
				ldap_memfree(dn);
				ldap_msgfree(result);
				return ret;
			}

			ldap_mods_free(mods, 1);
			mods = NULL;
			ldap_memfree(dn);
			ldap_msgfree(result);

			sid_copy(&sid, &dom_sid);
			sid_append_rid(&sid, *rid);

			/* check RID is not in use */
			if (sid_in_use(ldap_state, &sid, &error)) {
				if (error) {
					return ret;
				}
				continue;
			}

			return NT_STATUS_OK;
		}

		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG(2, ("Failed to modify rid: %s\n", ld_error));
		SAFE_FREE(ld_error);

		ldap_mods_free(mods, 1);
		mods = NULL;

		ldap_memfree(dn);
		dn = NULL;

		ldap_msgfree(result);
		result = NULL;

		{
			/* Sleep for a random timeout */
			unsigned sleeptime = (sys_random()*sys_getpid()*attempts);
			attempts += 1;
			
			sleeptime %= 100;
			msleep(sleeptime);
		}
	}

	DEBUG(0, ("Failed to set new RID\n"));
	return ret;
}

/* New Interface is being implemented here */

/**********************************************************************
Initialize SAM_ACCOUNT from an LDAP query (unix attributes only)
*********************************************************************/
static BOOL get_unix_attributes (struct ldapsam_privates *ldap_state, 
				SAM_ACCOUNT * sampass,
				LDAPMessage * entry,
				gid_t *gid)
{
	pstring  homedir;
	pstring  temp;
	char **ldap_values;
	char **values;

	if ((ldap_values = ldap_get_values (ldap_state->ldap_struct, entry, "objectClass")) == NULL) {
		DEBUG (1, ("get_unix_attributes: no objectClass! \n"));
		return False;
	}

	for (values=ldap_values;*values;values++) {
		if (strcasecmp(*values, LDAP_OBJ_POSIXACCOUNT ) == 0) {
			break;
		}
	}
	
	if (!*values) { /*end of array, no posixAccount */
		DEBUG(10, ("user does not have %s attributes\n", LDAP_OBJ_POSIXACCOUNT));
		ldap_value_free(ldap_values);
		return False;
	}
	ldap_value_free(ldap_values);

	if ( !get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_UNIX_HOME), homedir) ) 
	{
		return False;
	}
	
	if ( !get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_GIDNUMBER), temp) )
	{
		return False;
	}
	
	*gid = (gid_t)atol(temp);

	pdb_set_unix_homedir(sampass, homedir, PDB_SET);
	
	DEBUG(10, ("user has %s attributes\n", LDAP_OBJ_POSIXACCOUNT));
	
	return True;
}


/**********************************************************************
Initialize SAM_ACCOUNT from an LDAP query
(Based on init_sam_from_buffer in pdb_tdb.c)
*********************************************************************/
static BOOL init_sam_from_ldap (struct ldapsam_privates *ldap_state, 
				SAM_ACCOUNT * sampass,
				LDAPMessage * entry)
{
	time_t  logon_time,
			logoff_time,
			kickoff_time,
			pass_last_set_time, 
			pass_can_change_time, 
			pass_must_change_time;
	pstring 	username, 
			domain,
			nt_username,
			fullname,
			homedir,
			dir_drive,
			logon_script,
			profile_path,
			acct_desc,
			munged_dial,
			workstations;
	uint32 		user_rid; 
	uint8 		smblmpwd[LM_HASH_LEN],
			smbntpwd[NT_HASH_LEN];
	uint16 		acct_ctrl = 0, 
			logon_divs;
	uint32 hours_len;
	uint8 		hours[MAX_HOURS_LEN];
	pstring temp;
	uid_t		uid = -1;
	gid_t		gid = getegid();

	/*
	 * do a little initialization
	 */
	username[0] 	= '\0';
	domain[0] 	= '\0';
	nt_username[0] 	= '\0';
	fullname[0] 	= '\0';
	homedir[0] 	= '\0';
	dir_drive[0] 	= '\0';
	logon_script[0] = '\0';
	profile_path[0] = '\0';
	acct_desc[0] 	= '\0';
	munged_dial[0] 	= '\0';
	workstations[0] = '\0';
	 

	if (sampass == NULL || ldap_state == NULL || entry == NULL) {
		DEBUG(0, ("init_sam_from_ldap: NULL parameters found!\n"));
		return False;
	}

	if (ldap_state->ldap_struct == NULL) {
		DEBUG(0, ("init_sam_from_ldap: ldap_state->ldap_struct is NULL!\n"));
		return False;
	}
	
	if (!get_single_attribute(ldap_state->ldap_struct, entry, "uid", username)) {
		DEBUG(1, ("No uid attribute found for this user!\n"));
		return False;
	}

	DEBUG(2, ("Entry found for user: %s\n", username));

	pstrcpy(nt_username, username);

	pstrcpy(domain, ldap_state->domain_name);
	
	pdb_set_username(sampass, username, PDB_SET);

	pdb_set_domain(sampass, domain, PDB_DEFAULT);
	pdb_set_nt_username(sampass, nt_username, PDB_SET);
	
	/* deal with different attributes between the schema first */
	
	if ( ldap_state->schema_ver == SCHEMAVER_SAMBASAMACCOUNT ) 
	{
		if (get_single_attribute(ldap_state->ldap_struct, entry, 
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_SID), temp)) 
		{
			pdb_set_user_sid_from_string(sampass, temp, PDB_SET);
		}
		
		if (!get_single_attribute(ldap_state->ldap_struct, entry, 
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PRIMARY_GROUP_SID), temp)) 
		{
			pdb_set_group_sid_from_string(sampass, temp, PDB_SET);			
		}
		else 
		{
			pdb_set_group_sid_from_rid(sampass, DOMAIN_GROUP_RID_USERS, PDB_DEFAULT);
		}


	} 
	else 
	{
		if (get_single_attribute(ldap_state->ldap_struct, entry,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_RID), temp)) 
		{
			user_rid = (uint32)atol(temp);
			pdb_set_user_sid_from_rid(sampass, user_rid, PDB_SET);
		}
		
		if (!get_single_attribute(ldap_state->ldap_struct, entry, 
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PRIMARY_GROUP_RID), temp)) 
		{
			pdb_set_group_sid_from_rid(sampass, DOMAIN_GROUP_RID_USERS, PDB_DEFAULT);
		} else {
			uint32 group_rid;
			
			group_rid = (uint32)atol(temp);
			
			/* for some reason, we often have 0 as a primary group RID.
			   Make sure that we treat this just as a 'default' value */
			   
			if ( group_rid > 0 )
				pdb_set_group_sid_from_rid(sampass, group_rid, PDB_SET);
			else
				pdb_set_group_sid_from_rid(sampass, DOMAIN_GROUP_RID_USERS, PDB_DEFAULT);
		}
	}

	if (pdb_get_init_flags(sampass,PDB_USERSID) == PDB_DEFAULT) {
		DEBUG(1, ("no %s or %s attribute found for this user %s\n", 
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_SID),
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_RID),
			username));
		return False;
	}


	/* 
	 * If so configured, try and get the values from LDAP 
	 */

	if (lp_ldap_trust_ids() && (get_unix_attributes(ldap_state, sampass, entry, &gid))) 
	{	
		if (pdb_get_init_flags(sampass,PDB_GROUPSID) == PDB_DEFAULT) 
		{
			GROUP_MAP map;
			/* call the mapping code here */
			if(pdb_getgrgid(&map, gid, MAPPING_WITHOUT_PRIV)) {
				pdb_set_group_sid(sampass, &map.sid, PDB_SET);
			} 
			else {
				pdb_set_group_sid_from_rid(sampass, pdb_gid_to_group_rid(gid), PDB_SET);
			}
		}
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PWD_LAST_SET), temp)) 
	{
		/* leave as default */
	} else {
		pass_last_set_time = (time_t) atol(temp);
		pdb_set_pass_last_set_time(sampass, pass_last_set_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_LOGON_TIME), temp)) 
	{
		/* leave as default */
	} else {
		logon_time = (time_t) atol(temp);
		pdb_set_logon_time(sampass, logon_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_LOGOFF_TIME), temp)) 
	{
		/* leave as default */
	} else {
		logoff_time = (time_t) atol(temp);
		pdb_set_logoff_time(sampass, logoff_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_KICKOFF_TIME), temp)) 
	{
		/* leave as default */
	} else {
		kickoff_time = (time_t) atol(temp);
		pdb_set_kickoff_time(sampass, kickoff_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PWD_CAN_CHANGE), temp)) 
	{
		/* leave as default */
	} else {
		pass_can_change_time = (time_t) atol(temp);
		pdb_set_pass_can_change_time(sampass, pass_can_change_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PWD_MUST_CHANGE), temp)) 
	{	
		/* leave as default */
	} else {
		pass_must_change_time = (time_t) atol(temp);
		pdb_set_pass_must_change_time(sampass, pass_must_change_time, PDB_SET);
	}

	/* recommend that 'gecos' and 'displayName' should refer to the same
	 * attribute OID.  userFullName depreciated, only used by Samba
	 * primary rules of LDAP: don't make a new attribute when one is already defined
	 * that fits your needs; using cn then displayName rather than 'userFullName'
	 */

	if (!get_single_attribute(ldap_state->ldap_struct, entry,
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_DISPLAY_NAME), fullname)) 
	{
		if (!get_single_attribute(ldap_state->ldap_struct, entry,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_CN), fullname)) 
		{
			/* leave as default */
		} else {
			pdb_set_fullname(sampass, fullname, PDB_SET);
		}
	} else {
		pdb_set_fullname(sampass, fullname, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_HOME_DRIVE), dir_drive)) 
	{
		pdb_set_dir_drive(sampass, talloc_sub_specified(sampass->mem_ctx, 
								  lp_logon_drive(),
								  username, domain, 
								  uid, gid),
				  PDB_DEFAULT);
	} else {
		pdb_set_dir_drive(sampass, dir_drive, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry,
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_HOME_PATH), homedir)) 
	{
		pdb_set_homedir(sampass, talloc_sub_specified(sampass->mem_ctx, 
								  lp_logon_home(),
								  username, domain, 
								  uid, gid), 
				  PDB_DEFAULT);
	} else {
		pdb_set_homedir(sampass, homedir, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry,
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_LOGON_SCRIPT), logon_script)) 
	{
		pdb_set_logon_script(sampass, talloc_sub_specified(sampass->mem_ctx, 
								     lp_logon_script(),
								     username, domain, 
								     uid, gid), 
				     PDB_DEFAULT);
	} else {
		pdb_set_logon_script(sampass, logon_script, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry,
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PROFILE_PATH), profile_path)) 
	{
		pdb_set_profile_path(sampass, talloc_sub_specified(sampass->mem_ctx, 
								     lp_logon_path(),
								     username, domain, 
								     uid, gid), 
				     PDB_DEFAULT);
	} else {
		pdb_set_profile_path(sampass, profile_path, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_DESC), acct_desc)) 
	{
		/* leave as default */
	} else {
		pdb_set_acct_desc(sampass, acct_desc, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_WKS), workstations)) 
	{
		/* leave as default */;
	} else {
		pdb_set_workstations(sampass, workstations, PDB_SET);
	}

	/* FIXME: hours stuff should be cleaner */
	
	logon_divs = 168;
	hours_len = 21;
	memset(hours, 0xff, hours_len);

	if (!get_single_attribute (ldap_state->ldap_struct, entry, 
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_LMPW), temp)) 
	{
		/* leave as default */
	} else {
		pdb_gethexpwd(temp, smblmpwd);
		memset((char *)temp, '\0', strlen(temp)+1);
		if (!pdb_set_lanman_passwd(sampass, smblmpwd, PDB_SET))
			return False;
		ZERO_STRUCT(smblmpwd);
	}

	if (!get_single_attribute (ldap_state->ldap_struct, entry,
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_NTPW), temp)) 
	{
		/* leave as default */
	} else {
		pdb_gethexpwd(temp, smbntpwd);
		memset((char *)temp, '\0', strlen(temp)+1);
		if (!pdb_set_nt_passwd(sampass, smbntpwd, PDB_SET))
			return False;
		ZERO_STRUCT(smbntpwd);
	}

	if (!get_single_attribute (ldap_state->ldap_struct, entry,
		get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_ACB_INFO), temp)) 
	{
		acct_ctrl |= ACB_NORMAL;
	} else {
		acct_ctrl = pdb_decode_acct_ctrl(temp);

		if (acct_ctrl == 0)
			acct_ctrl |= ACB_NORMAL;

		pdb_set_acct_ctrl(sampass, acct_ctrl, PDB_SET);
	}

	pdb_set_hours_len(sampass, hours_len, PDB_SET);
	pdb_set_logon_divs(sampass, logon_divs, PDB_SET);

	pdb_set_munged_dial(sampass, munged_dial, PDB_SET);
	
	/* pdb_set_unknown_3(sampass, unknown3, PDB_SET); */
	/* pdb_set_unknown_5(sampass, unknown5, PDB_SET); */
	/* pdb_set_unknown_6(sampass, unknown6, PDB_SET); */

	pdb_set_hours(sampass, hours, PDB_SET);

	return True;
}

/**********************************************************************
Initialize SAM_ACCOUNT from an LDAP query
(Based on init_buffer_from_sam in pdb_tdb.c)
*********************************************************************/
static BOOL init_ldap_from_sam (struct ldapsam_privates *ldap_state, 
				LDAPMessage *existing,
				LDAPMod *** mods, SAM_ACCOUNT * sampass,
				BOOL (*need_update)(const SAM_ACCOUNT *,
						    enum pdb_elements))
{
	pstring temp;
	uint32 rid;

	if (mods == NULL || sampass == NULL) {
		DEBUG(0, ("init_ldap_from_sam: NULL parameters found!\n"));
		return False;
	}

	*mods = NULL;

	/* 
	 * took out adding "objectclass: sambaAccount"
	 * do this on a per-mod basis
	 */
	if (need_update(sampass, PDB_USERNAME))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods, 
			      "uid", pdb_get_username(sampass));

	DEBUG(2, ("Setting entry for user: %s\n", pdb_get_username(sampass)));

	if (pdb_get_init_flags(sampass, PDB_USERSID) == PDB_DEFAULT) {
		if (ldap_state->permit_non_unix_accounts) {
			if (!NT_STATUS_IS_OK(ldapsam_next_rid(ldap_state, &rid, USER_RID_TYPE))) {
				DEBUG(0, ("NO user RID specified on account %s, and "
					  "finding next available NUA RID failed, "
					  "cannot store!\n",
					  pdb_get_username(sampass)));
				ldap_mods_free(*mods, 1);
				return False;
			}
		} else {
			DEBUG(0, ("NO user RID specified on account %s, "
				  "cannot store!\n", pdb_get_username(sampass)));
			ldap_mods_free(*mods, 1);
			return False;
		}

		/* now that we have figured out the RID, always store it, as
		   the schema requires it (either as a SID or a RID) */
		   
		if (!pdb_set_user_sid_from_rid(sampass, rid, PDB_CHANGED)) {
			DEBUG(0, ("Could not store RID back onto SAM_ACCOUNT for user %s!\n", 
				  pdb_get_username(sampass)));
			ldap_mods_free(*mods, 1);
			return False;
		}
	}

	/* only update the RID if we actually need to */
	if (need_update(sampass, PDB_USERSID)) 
	{
		fstring sid_string;
		fstring dom_sid_string;
		const DOM_SID *user_sid = pdb_get_user_sid(sampass);
		
		switch ( ldap_state->schema_ver )
		{
			case SCHEMAVER_SAMBAACCOUNT:
				if (!sid_peek_check_rid(get_global_sam_sid(), user_sid, &rid)) {
					DEBUG(1, ("User's SID (%s) is not for this domain (%s), cannot add to LDAP!\n", 
						sid_to_string(sid_string, user_sid), 
						sid_to_string(dom_sid_string, get_global_sam_sid())));
					return False;
				}
				slprintf(temp, sizeof(temp) - 1, "%i", rid);
				make_ldap_mod(ldap_state->ldap_struct, existing, mods,
					get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_RID), 
					temp);
				break;
				
			case SCHEMAVER_SAMBASAMACCOUNT:
				make_ldap_mod(ldap_state->ldap_struct, existing, mods,
					get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_SID), 
					sid_to_string(sid_string, user_sid));				      
				break;
				
			default:
				DEBUG(0,("init_ldap_from_sam: unknown schema version specified\n"));
				break;
		}		
	}

	/* we don't need to store the primary group RID - so leaving it
	   'free' to hang off the unix primary group makes life easier */

	if (need_update(sampass, PDB_GROUPSID)) 
	{
		fstring sid_string;
		fstring dom_sid_string;
		const DOM_SID *group_sid = pdb_get_group_sid(sampass);
		
		switch ( ldap_state->schema_ver )
		{
			case SCHEMAVER_SAMBAACCOUNT:
				if (!sid_peek_check_rid(get_global_sam_sid(), group_sid, &rid)) {
					DEBUG(1, ("User's Primary Group SID (%s) is not for this domain (%s), cannot add to LDAP!\n",
						sid_to_string(sid_string, group_sid),
						sid_to_string(dom_sid_string, get_global_sam_sid())));
					return False;
				}

				slprintf(temp, sizeof(temp) - 1, "%i", rid);
				make_ldap_mod(ldap_state->ldap_struct, existing, mods,
					get_userattr_key2string(ldap_state->schema_ver, 
					LDAP_ATTR_PRIMARY_GROUP_RID), temp);
				break;
				
			case SCHEMAVER_SAMBASAMACCOUNT:
				make_ldap_mod(ldap_state->ldap_struct, existing, mods,
					get_userattr_key2string(ldap_state->schema_ver, 
					LDAP_ATTR_PRIMARY_GROUP_SID), sid_to_string(sid_string, group_sid));
				break;
				
			default:
				DEBUG(0,("init_ldap_from_sam: unknown schema version specified\n"));
				break;
		}
		
	}
	
	/* displayName, cn, and gecos should all be the same
	 *  most easily accomplished by giving them the same OID
	 *  gecos isn't set here b/c it should be handled by the 
	 *  add-user script
	 *  We change displayName only and fall back to cn if
	 *  it does not exist.
	 */

	if (need_update(sampass, PDB_FULLNAME))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_DISPLAY_NAME), 
			pdb_get_fullname(sampass));

	if (need_update(sampass, PDB_ACCTDESC))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_DESC), 
			pdb_get_acct_desc(sampass));

	if (need_update(sampass, PDB_WORKSTATIONS))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_USER_WKS), 
			pdb_get_workstations(sampass));

	if (need_update(sampass, PDB_SMBHOME))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_HOME_PATH), 
			pdb_get_homedir(sampass));
			
	if (need_update(sampass, PDB_DRIVE))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_HOME_DRIVE), 
			pdb_get_dir_drive(sampass));

	if (need_update(sampass, PDB_LOGONSCRIPT))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_LOGON_SCRIPT), 
			pdb_get_logon_script(sampass));

	if (need_update(sampass, PDB_PROFILE))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PROFILE_PATH), 
			pdb_get_profile_path(sampass));

	slprintf(temp, sizeof(temp) - 1, "%li", pdb_get_logon_time(sampass));
	if (need_update(sampass, PDB_LOGONTIME))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_LOGON_TIME), temp);

	slprintf(temp, sizeof(temp) - 1, "%li", pdb_get_logoff_time(sampass));
	if (need_update(sampass, PDB_LOGOFFTIME))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_LOGOFF_TIME), temp);

	slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_kickoff_time(sampass));
	if (need_update(sampass, PDB_KICKOFFTIME))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_KICKOFF_TIME), temp);

	slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_can_change_time(sampass));
	if (need_update(sampass, PDB_CANCHANGETIME))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PWD_CAN_CHANGE), temp);

	slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_must_change_time(sampass));
	if (need_update(sampass, PDB_MUSTCHANGETIME))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PWD_MUST_CHANGE), temp);

	if ((pdb_get_acct_ctrl(sampass)&(ACB_WSTRUST|ACB_SVRTRUST|ACB_DOMTRUST))
		|| (lp_ldap_passwd_sync()!=LDAP_PASSWD_SYNC_ONLY)) 
	{

		pdb_sethexpwd(temp, pdb_get_lanman_passwd(sampass),
			       pdb_get_acct_ctrl(sampass));

		if (need_update(sampass, PDB_LMPASSWD))
			make_ldap_mod(ldap_state->ldap_struct, existing, mods,
				get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_LMPW), 
				temp);

		pdb_sethexpwd (temp, pdb_get_nt_passwd(sampass),
			       pdb_get_acct_ctrl(sampass));

		if (need_update(sampass, PDB_NTPASSWD))
			make_ldap_mod(ldap_state->ldap_struct, existing, mods,
				get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_NTPW), 
				temp);

		slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_last_set_time(sampass));
		if (need_update(sampass, PDB_PASSLASTSET))
			make_ldap_mod(ldap_state->ldap_struct, existing, mods,
				get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_PWD_LAST_SET), 
				temp);
	}

	/* FIXME: Hours stuff goes in LDAP  */

	if (need_update(sampass, PDB_ACCTCTRL))
		make_ldap_mod(ldap_state->ldap_struct, existing, mods,
			get_userattr_key2string(ldap_state->schema_ver, LDAP_ATTR_ACB_INFO), 
			pdb_encode_acct_ctrl (pdb_get_acct_ctrl(sampass), NEW_PW_FORMAT_SPACE_PADDED_LEN));

	return True;
}



/**********************************************************************
Connect to LDAP server for password enumeration
*********************************************************************/
static NTSTATUS ldapsam_setsampwent(struct pdb_methods *my_methods, BOOL update)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	int rc;
	pstring filter;
	char **attr_list;

	snprintf( filter, sizeof(filter)-1, "(&%s%s)", lp_ldap_filter(), 
		get_objclass_filter(ldap_state->schema_ver));
	all_string_sub(filter, "%u", "*", sizeof(pstring));

	attr_list = get_userattr_list(ldap_state->schema_ver);
	rc = ldapsam_search_suffix(ldap_state, filter, attr_list, &ldap_state->result);
	free_attr_list( attr_list );

	if (rc != LDAP_SUCCESS) {
		DEBUG(0, ("LDAP search failed: %s\n", ldap_err2string(rc)));
		DEBUG(3, ("Query was: %s, %s\n", lp_ldap_suffix(), filter));
		ldap_msgfree(ldap_state->result);
		ldap_state->result = NULL;
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2, ("ldapsam_setsampwent: %d entries in the base!\n",
		ldap_count_entries(ldap_state->ldap_struct,
		ldap_state->result)));

	ldap_state->entry = ldap_first_entry(ldap_state->ldap_struct,
				 ldap_state->result);
	ldap_state->index = 0;

	return NT_STATUS_OK;
}

/**********************************************************************
End enumeration of the LDAP password list 
*********************************************************************/
static void ldapsam_endsampwent(struct pdb_methods *my_methods)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	if (ldap_state->result) {
		ldap_msgfree(ldap_state->result);
		ldap_state->result = NULL;
	}
}

/**********************************************************************
Get the next entry in the LDAP password database 
*********************************************************************/
static NTSTATUS ldapsam_getsampwent(struct pdb_methods *my_methods, SAM_ACCOUNT *user)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	BOOL bret = False;

	/* The rebind proc needs this *HACK*.  We are not multithreaded, so
	   this will work, but it's not nice. */
	static_ldap_state = ldap_state;

	while (!bret) {
		if (!ldap_state->entry)
			return ret;
		
		ldap_state->index++;
		bret = init_sam_from_ldap(ldap_state, user, ldap_state->entry);
		
		ldap_state->entry = ldap_next_entry(ldap_state->ldap_struct,
					    ldap_state->entry);	
	}

	return NT_STATUS_OK;
}

/**********************************************************************
Get SAM_ACCOUNT entry from LDAP by username 
*********************************************************************/
static NTSTATUS ldapsam_getsampwnam(struct pdb_methods *my_methods, SAM_ACCOUNT *user, const char *sname)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	LDAPMessage *result;
	LDAPMessage *entry;
	int count;
	char ** attr_list;
	int rc;
	
	attr_list = get_userattr_list( ldap_state->schema_ver );
	rc = ldapsam_search_suffix_by_name(ldap_state, sname, &result, attr_list);
	free_attr_list( attr_list );

	if ( rc != LDAP_SUCCESS ) 
		return NT_STATUS_NO_SUCH_USER;
	
	count = ldap_count_entries(ldap_state->ldap_struct, result);
	
	if (count < 1) {
		DEBUG(4,
		      ("Unable to locate user [%s] count=%d\n", sname,
		       count));
		return NT_STATUS_NO_SUCH_USER;
	} else if (count > 1) {
		DEBUG(1,
		      ("Duplicate entries for this user [%s] Failing. count=%d\n", sname,
		       count));
		return NT_STATUS_NO_SUCH_USER;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	if (entry) {
		if (!init_sam_from_ldap(ldap_state, user, entry)) {
			DEBUG(1,("ldapsam_getsampwnam: init_sam_from_ldap failed for user '%s'!\n", sname));
			ldap_msgfree(result);
			return NT_STATUS_NO_SUCH_USER;
		}
		ldap_msgfree(result);
		ret = NT_STATUS_OK;
	} else {
		ldap_msgfree(result);
	}
	return ret;
}

/**********************************************************************
Get SAM_ACCOUNT entry from LDAP by SID
*********************************************************************/
static NTSTATUS ldapsam_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, const DOM_SID *sid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	LDAPMessage *result;
	LDAPMessage *entry;
	fstring sid_string;
	int count;
	int rc;
	char ** attr_list;
	
	switch ( ldap_state->schema_ver )
	{
		case SCHEMAVER_SAMBASAMACCOUNT:
			attr_list = get_userattr_list(ldap_state->schema_ver);
			rc = ldapsam_search_suffix_by_sid(ldap_state, sid, &result, attr_list);
			free_attr_list( attr_list );

			if ( rc != LDAP_SUCCESS ) 
				return NT_STATUS_NO_SUCH_USER;
			break;
			
		case SCHEMAVER_SAMBAACCOUNT:
		{
			uint32 rid;
			if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid)) {
				return NT_STATUS_NO_SUCH_USER;
			}
		
			attr_list = get_userattr_list(ldap_state->schema_ver);
			rc = ldapsam_search_suffix_by_rid(ldap_state, rid, &result, attr_list );
			free_attr_list( attr_list );

			if ( rc != LDAP_SUCCESS ) 
				return NT_STATUS_NO_SUCH_USER;
		}
		break;
	}
	
	count = ldap_count_entries(ldap_state->ldap_struct, result);
	
	if (count < 1) 
	{
		DEBUG(4,
		      ("Unable to locate SID [%s] count=%d\n", sid_to_string(sid_string, sid),
		       count));
		return NT_STATUS_NO_SUCH_USER;
	}  
	else if (count > 1) 
	{
		DEBUG(1,
		      ("More than one user with SID [%s]. Failing. count=%d\n", sid_to_string(sid_string, sid),
		       count));
		return NT_STATUS_NO_SUCH_USER;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	if (entry) 
	{
		if (!init_sam_from_ldap(ldap_state, user, entry)) {
			DEBUG(1,("ldapsam_getsampwrid: init_sam_from_ldap failed!\n"));
			ldap_msgfree(result);
			return NT_STATUS_NO_SUCH_USER;
		}
		ldap_msgfree(result);
		ret = NT_STATUS_OK;
	} else {
		ldap_msgfree(result);
	}
	return ret;
}	

/********************************************************************
Do the actual modification - also change a plaittext passord if 
it it set.
**********************************************************************/

static NTSTATUS ldapsam_modify_entry(struct pdb_methods *my_methods, 
				     SAM_ACCOUNT *newpwd, char *dn,
				     LDAPMod **mods, int ldap_op, 
				     BOOL (*need_update)(const SAM_ACCOUNT *,
							 enum pdb_elements))
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	int rc;
	
	if (!my_methods || !newpwd || !dn) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	if (!mods) {
		DEBUG(5,("mods is empty: nothing to modify\n"));
		/* may be password change below however */
	} else {
		switch(ldap_op)
		{
			case LDAP_MOD_ADD: 
				make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", LDAP_OBJ_ACCOUNT);
				rc = ldapsam_add(ldap_state, dn, mods);
				break;
			case LDAP_MOD_REPLACE: 
				rc = ldapsam_modify(ldap_state, dn ,mods);
				break;
			default: 	
				DEBUG(0,("Wrong LDAP operation type: %d!\n", ldap_op));
				return NT_STATUS_INVALID_PARAMETER;
		}
		
		if (rc!=LDAP_SUCCESS) {
			char *ld_error = NULL;
			ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
					&ld_error);
			DEBUG(1,
			      ("failed to %s user dn= %s with: %s\n\t%s\n",
			       ldap_op == LDAP_MOD_ADD ? "add" : "modify",
			       dn, ldap_err2string(rc),
			       ld_error?ld_error:"unknown"));
			SAFE_FREE(ld_error);
			return NT_STATUS_UNSUCCESSFUL;
		}  
	}
	
#ifdef LDAP_EXOP_X_MODIFY_PASSWD
	if (!(pdb_get_acct_ctrl(newpwd)&(ACB_WSTRUST|ACB_SVRTRUST|ACB_DOMTRUST)) &&
		(lp_ldap_passwd_sync() != LDAP_PASSWD_SYNC_OFF) &&
		need_update(newpwd, PDB_PLAINTEXT_PW) &&
		(pdb_get_plaintext_passwd(newpwd)!=NULL)) {
		BerElement *ber;
		struct berval *bv;
		char *retoid;
		struct berval *retdata;
		char *utf8_password;
		char *utf8_dn;

		if (push_utf8_allocate(&utf8_password, pdb_get_plaintext_passwd(newpwd)) == (size_t)-1) {
			return NT_STATUS_NO_MEMORY;
		}

		if (push_utf8_allocate(&utf8_dn, dn) == (size_t)-1) {
			return NT_STATUS_NO_MEMORY;
		}

		if ((ber = ber_alloc_t(LBER_USE_DER))==NULL) {
			DEBUG(0,("ber_alloc_t returns NULL\n"));
			SAFE_FREE(utf8_password);
			return NT_STATUS_UNSUCCESSFUL;
		}

		ber_printf (ber, "{");
		ber_printf (ber, "ts", LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID, utf8_dn);
	        ber_printf (ber, "ts", LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW, utf8_password);
	        ber_printf (ber, "N}");

	        if ((rc = ber_flatten (ber, &bv))<0) {
			DEBUG(0,("ber_flatten returns a value <0\n"));
			ber_free(ber,1);
			SAFE_FREE(utf8_dn);
			SAFE_FREE(utf8_password);
			return NT_STATUS_UNSUCCESSFUL;
		}
		
		SAFE_FREE(utf8_dn);
		SAFE_FREE(utf8_password);
		ber_free(ber, 1);

		if ((rc = ldapsam_extended_operation(ldap_state, LDAP_EXOP_X_MODIFY_PASSWD,
						    bv, NULL, NULL, &retoid, &retdata))!=LDAP_SUCCESS) {
			DEBUG(0,("LDAP Password could not be changed for user %s: %s\n",
				pdb_get_username(newpwd),ldap_err2string(rc)));
		} else {
			DEBUG(3,("LDAP Password changed for user %s\n",pdb_get_username(newpwd)));
#ifdef DEBUG_PASSWORD
			DEBUG(100,("LDAP Password changed to %s\n",pdb_get_plaintext_passwd(newpwd)));
#endif    
			ber_bvfree(retdata);
			ber_memfree(retoid);
		}
		ber_bvfree(bv);
	}
#else
	DEBUG(10,("LDAP PASSWORD SYNC is not supported!\n"));
#endif /* LDAP_EXOP_X_MODIFY_PASSWD */
	return NT_STATUS_OK;
}

/**********************************************************************
Delete entry from LDAP for username 
*********************************************************************/
static NTSTATUS ldapsam_delete_sam_account(struct pdb_methods *my_methods, SAM_ACCOUNT * sam_acct)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	const char *sname;
	int rc;
	LDAPMessage *result;
	NTSTATUS ret;
	char **attr_list;
	fstring objclass;

	if (!sam_acct) {
		DEBUG(0, ("sam_acct was NULL!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	sname = pdb_get_username(sam_acct);

	DEBUG (3, ("Deleting user %s from LDAP.\n", sname));

	attr_list= get_userattr_list( ldap_state->schema_ver );
	rc = ldapsam_search_suffix_by_name(ldap_state, sname, &result, attr_list);

	if (rc != LDAP_SUCCESS)  {
		free_attr_list( attr_list );
		return NT_STATUS_NO_SUCH_USER;
	}
	
	switch ( ldap_state->schema_ver )
	{
		case SCHEMAVER_SAMBASAMACCOUNT:
			fstrcpy( objclass, LDAP_OBJ_SAMBASAMACCOUNT );
			break;
			
		case SCHEMAVER_SAMBAACCOUNT:
			fstrcpy( objclass, LDAP_OBJ_SAMBAACCOUNT );
			break;
		default:
			fstrcpy( objclass, "UNKNOWN" );
			DEBUG(0,("ldapsam_delete_sam_account: Unknown schema version specified!\n"));
				break;
	}

	ret = ldapsam_delete_entry(ldap_state, result, objclass, attr_list );
	ldap_msgfree(result);
	free_attr_list( attr_list );

	return ret;
}

/**********************************************************************
  Helper function to determine for update_sam_account whether
  we need LDAP modification.
*********************************************************************/
static BOOL element_is_changed(const SAM_ACCOUNT *sampass,
			       enum pdb_elements element)
{
	return IS_SAM_CHANGED(sampass, element);
}

/**********************************************************************
Update SAM_ACCOUNT 
*********************************************************************/
static NTSTATUS ldapsam_update_sam_account(struct pdb_methods *my_methods, SAM_ACCOUNT * newpwd)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	int rc;
	char *dn;
	LDAPMessage *result;
	LDAPMessage *entry;
	LDAPMod **mods;
	char **attr_list;

	attr_list = get_userattr_list(ldap_state->schema_ver);
	rc = ldapsam_search_suffix_by_name(ldap_state, pdb_get_username(newpwd), &result, attr_list );
	free_attr_list( attr_list );
	if (rc != LDAP_SUCCESS) 
		return NT_STATUS_UNSUCCESSFUL;

	if (ldap_count_entries(ldap_state->ldap_struct, result) == 0) {
		DEBUG(0, ("No user to modify!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	dn = ldap_get_dn(ldap_state->ldap_struct, entry);

	if (!init_ldap_from_sam(ldap_state, entry, &mods, newpwd,
				element_is_changed)) {
		DEBUG(0, ("ldapsam_update_sam_account: init_ldap_from_sam failed!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
        ldap_msgfree(result);
	
	if (mods == NULL) {
		DEBUG(4,("mods is empty: nothing to update for user: %s\n",
			 pdb_get_username(newpwd)));
		ldap_mods_free(mods, 1);
		return NT_STATUS_OK;
	}
	
	ret = ldapsam_modify_entry(my_methods,newpwd,dn,mods,LDAP_MOD_REPLACE, element_is_changed);
	ldap_mods_free(mods,1);

	if (!NT_STATUS_IS_OK(ret)) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0,("failed to modify user with uid = %s, error: %s (%s)\n",
			 pdb_get_username(newpwd), ld_error?ld_error:"(unknwon)", ldap_err2string(rc)));
		SAFE_FREE(ld_error);
		return ret;
	}

	DEBUG(2, ("successfully modified uid = %s in the LDAP database\n",
		  pdb_get_username(newpwd)));
	return NT_STATUS_OK;
}

/**********************************************************************
  Helper function to determine for update_sam_account whether
  we need LDAP modification.
 *********************************************************************/
static BOOL element_is_set_or_changed(const SAM_ACCOUNT *sampass,
				      enum pdb_elements element)
{
	return (IS_SAM_SET(sampass, element) ||
		IS_SAM_CHANGED(sampass, element));
}

/**********************************************************************
Add SAM_ACCOUNT to LDAP 
*********************************************************************/

static NTSTATUS ldapsam_add_sam_account(struct pdb_methods *my_methods, SAM_ACCOUNT * newpwd)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	int rc;
	LDAPMessage 	*result = NULL;
	LDAPMessage 	*entry  = NULL;
	pstring 	dn;
	LDAPMod 	**mods = NULL;
	int 		ldap_op;
	uint32		num_result;
	char 		**attr_list;
	char 		*escape_user;
	const char 	*username = pdb_get_username(newpwd);
	pstring		filter;

	if (!username || !*username) {
		DEBUG(0, ("Cannot add user without a username!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* free this list after the second search or in case we exit on failure */
	
	attr_list = get_userattr_list(ldap_state->schema_ver);
	rc = ldapsam_search_suffix_by_name (ldap_state, username, &result, attr_list);

	if (rc != LDAP_SUCCESS) {
		free_attr_list( attr_list );
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (ldap_count_entries(ldap_state->ldap_struct, result) != 0) {
		DEBUG(0,("User '%s' already in the base, with samba attributes\n", 
			 username));
		ldap_msgfree(result);
		free_attr_list( attr_list );
		return NT_STATUS_UNSUCCESSFUL;
	}
	ldap_msgfree(result);

	/* does the entry already exist but without a samba rttibutes?
	   we don't really care what attributes are returned here */
	   
	escape_user = escape_ldap_string_alloc( username );
	pstrcpy( filter, lp_ldap_filter() );
	all_string_sub( filter, "%u", escape_user, sizeof(filter) );
	SAFE_FREE( escape_user );

	rc = ldapsam_search_suffix(ldap_state, filter, attr_list, &result);
	free_attr_list( attr_list );

	if ( rc != LDAP_SUCCESS )
		return NT_STATUS_UNSUCCESSFUL;

	num_result = ldap_count_entries(ldap_state->ldap_struct, result);
	
	if (num_result > 1) {
		DEBUG (0, ("More than one user with that uid exists: bailing out!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	/* Check if we need to update an existing entry */
	if (num_result == 1) {
		char *tmp;
		
		DEBUG(3,("User exists without samba attributes: adding them\n"));
		ldap_op = LDAP_MOD_REPLACE;
		entry = ldap_first_entry (ldap_state->ldap_struct, result);
		tmp = ldap_get_dn (ldap_state->ldap_struct, entry);
		slprintf (dn, sizeof (dn) - 1, "%s", tmp);
		ldap_memfree (tmp);
	} else {
		/* Check if we need to add an entry */
		DEBUG(3,("Adding new user\n"));
		ldap_op = LDAP_MOD_ADD;
		if (username[strlen(username)-1] == '$') {
                        slprintf (dn, sizeof (dn) - 1, "uid=%s,%s", username, lp_ldap_machine_suffix ());
                } else {
                        slprintf (dn, sizeof (dn) - 1, "uid=%s,%s", username, lp_ldap_user_suffix ());
                }
	}

	if (!init_ldap_from_sam(ldap_state, entry, &mods, newpwd,
				element_is_set_or_changed)) {
		DEBUG(0, ("ldapsam_add_sam_account: init_ldap_from_sam failed!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;		
	}
	
	ldap_msgfree(result);

	if (mods == NULL) {
		DEBUG(0,("mods is empty: nothing to add for user: %s\n",pdb_get_username(newpwd)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	switch ( ldap_state->schema_ver )
	{
		case SCHEMAVER_SAMBAACCOUNT:
			make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", LDAP_OBJ_SAMBAACCOUNT);
			break;
		case SCHEMAVER_SAMBASAMACCOUNT:
			make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", LDAP_OBJ_SAMBASAMACCOUNT);
			break;
		default:
			DEBUG(0,("ldapsam_add_sam_account: invalid schema version specified\n"));
			break;
	}

	ret = ldapsam_modify_entry(my_methods,newpwd,dn,mods,ldap_op, element_is_set_or_changed);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0,("failed to modify/add user with uid = %s (dn = %s)\n",
			 pdb_get_username(newpwd),dn));
		ldap_mods_free(mods,1);
		return ret;
	}

	DEBUG(2,("added: uid == %s in the LDAP database\n", pdb_get_username(newpwd)));
	ldap_mods_free(mods, 1);
	
	return NT_STATUS_OK;
}

/**********************************************************************
 Housekeeping
 *********************************************************************/

static void free_private_data(void **vp) 
{
	struct ldapsam_privates **ldap_state = (struct ldapsam_privates **)vp;

	ldapsam_close(*ldap_state);

	if ((*ldap_state)->bind_secret) {
		memset((*ldap_state)->bind_secret, '\0', strlen((*ldap_state)->bind_secret));
	}

	ldapsam_close(*ldap_state);
		
	SAFE_FREE((*ldap_state)->bind_dn);
	SAFE_FREE((*ldap_state)->bind_secret);

	*ldap_state = NULL;

	/* No need to free any further, as it is talloc()ed */
}

/**********************************************************************
 *********************************************************************/

static int ldapsam_search_one_group (struct ldapsam_privates *ldap_state,
				     const char *filter,
				     LDAPMessage ** result)
{
	int scope = LDAP_SCOPE_SUBTREE;
	int rc;
	char **attr_list;

	DEBUG(2, ("ldapsam_search_one_group: searching for:[%s]\n", filter));


	attr_list = get_attr_list(groupmap_attr_list);
	rc = ldapsam_search(ldap_state, lp_ldap_suffix (), scope,
			    filter, attr_list, 0, result);
	free_attr_list( attr_list );

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0, ("ldapsam_search_one_group: "
			  "Problem during the LDAP search: LDAP error: %s (%s)",
			  ld_error?ld_error:"(unknown)", ldap_err2string(rc)));
		DEBUG(3, ("ldapsam_search_one_group: Query was: %s, %s\n",
			  lp_ldap_suffix(), filter));
		SAFE_FREE(ld_error);
	}

	return rc;
}

/**********************************************************************
 *********************************************************************/

static BOOL init_group_from_ldap(struct ldapsam_privates *ldap_state,
				 GROUP_MAP *map, LDAPMessage *entry)
{
	pstring temp;

	if (ldap_state == NULL || map == NULL || entry == NULL ||
	    ldap_state->ldap_struct == NULL) 
	{
		DEBUG(0, ("init_group_from_ldap: NULL parameters found!\n"));
		return False;
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_attr_key2string(groupmap_attr_list, LDAP_ATTR_GIDNUMBER), temp)) 
	{
		DEBUG(0, ("Mandatory attribute %s not found\n", 
			get_attr_key2string( groupmap_attr_list, LDAP_ATTR_GIDNUMBER)));
		return False;
	}
	DEBUG(2, ("Entry found for group: %s\n", temp));

	map->gid = (gid_t)atol(temp);

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_attr_key2string( groupmap_attr_list, LDAP_ATTR_GROUP_SID), temp)) 
	{
		DEBUG(0, ("Mandatory attribute %s not found\n",
			get_attr_key2string( groupmap_attr_list, LDAP_ATTR_GROUP_SID)));
		return False;
	}
	string_to_sid(&map->sid, temp);

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_attr_key2string( groupmap_attr_list, LDAP_ATTR_GROUP_TYPE), temp)) 
	{
		DEBUG(0, ("Mandatory attribute %s not found\n",
			get_attr_key2string( groupmap_attr_list, LDAP_ATTR_GROUP_TYPE)));
		return False;
	}
	map->sid_name_use = (uint32)atol(temp);

	if ((map->sid_name_use < SID_NAME_USER) ||
	    (map->sid_name_use > SID_NAME_UNKNOWN)) {
		DEBUG(0, ("Unknown Group type: %d\n", map->sid_name_use));
		return False;
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_attr_key2string( groupmap_attr_list, LDAP_ATTR_DISPLAY_NAME), temp)) 
	{
		temp[0] = '\0';
		if (!get_single_attribute(ldap_state->ldap_struct, entry, 
			get_attr_key2string( groupmap_attr_list, LDAP_ATTR_CN), temp)) 
		{
			DEBUG(0, ("Attributes cn not found either "
				  "for gidNumber(%i)\n",map->gid));
			return False;
		}
	}
	fstrcpy(map->nt_name, temp);

	if (!get_single_attribute(ldap_state->ldap_struct, entry, 
		get_attr_key2string( groupmap_attr_list, LDAP_ATTR_DESC), temp)) 
	{
		temp[0] = '\0';
	}
	fstrcpy(map->comment, temp);

	map->systemaccount = 0;
	init_privilege(&map->priv_set);

	return True;
}

/**********************************************************************
 *********************************************************************/

static BOOL init_ldap_from_group(LDAP *ldap_struct,
				 LDAPMessage *existing,
				 LDAPMod ***mods,
				 const GROUP_MAP *map)
{
	pstring tmp;

	if (mods == NULL || map == NULL) {
		DEBUG(0, ("init_ldap_from_group: NULL parameters found!\n"));
		return False;
	}

	*mods = NULL;

	sid_to_string(tmp, &map->sid);
	make_ldap_mod(ldap_struct, existing, mods, 
		get_attr_key2string(groupmap_attr_list, LDAP_ATTR_GROUP_SID), tmp);
	snprintf(tmp, sizeof(tmp)-1, "%i", map->sid_name_use);
	make_ldap_mod(ldap_struct, existing, mods, 
		get_attr_key2string(groupmap_attr_list, LDAP_ATTR_GROUP_TYPE), tmp);

	make_ldap_mod(ldap_struct, existing, mods, 
		get_attr_key2string( groupmap_attr_list, LDAP_ATTR_DISPLAY_NAME), map->nt_name);
	make_ldap_mod(ldap_struct, existing, mods, 
		get_attr_key2string( groupmap_attr_list, LDAP_ATTR_DESC), map->comment);

	return True;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_getgroup(struct pdb_methods *methods,
				 const char *filter,
				 GROUP_MAP *map)
{
	struct ldapsam_privates *ldap_state =
		(struct ldapsam_privates *)methods->private_data;
	LDAPMessage *result;
	LDAPMessage *entry;
	int count;

	if (ldapsam_search_one_group(ldap_state, filter, &result)
	    != LDAP_SUCCESS) {
		return NT_STATUS_NO_SUCH_GROUP;
	}

	count = ldap_count_entries(ldap_state->ldap_struct, result);

	if (count < 1) {
		DEBUG(4, ("Did not find group for filter %s\n", filter));
		return NT_STATUS_NO_SUCH_GROUP;
	}

	if (count > 1) {
		DEBUG(1, ("Duplicate entries for filter %s: count=%d\n",
			  filter, count));
		return NT_STATUS_NO_SUCH_GROUP;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);

	if (!entry) {
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!init_group_from_ldap(ldap_state, map, entry)) {
		DEBUG(1, ("init_group_from_ldap failed for group filter %s\n",
			  filter));
		ldap_msgfree(result);
		return NT_STATUS_NO_SUCH_GROUP;
	}

	ldap_msgfree(result);
	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid, BOOL with_priv)
{
	pstring filter;

	snprintf(filter, sizeof(filter)-1, "(&(objectClass=%s)(%s=%s))",
		LDAP_OBJ_GROUPMAP, 
		get_attr_key2string(groupmap_attr_list, LDAP_ATTR_GROUP_SID),
		sid_string_static(&sid));

	return ldapsam_getgroup(methods, filter, map);
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid, BOOL with_priv)
{
	pstring filter;

	snprintf(filter, sizeof(filter)-1, "(&(objectClass=%s)(%s=%d))",
		LDAP_OBJ_GROUPMAP,
		get_attr_key2string(groupmap_attr_list, LDAP_ATTR_GIDNUMBER),
		gid);

	return ldapsam_getgroup(methods, filter, map);
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 char *name, BOOL with_priv)
{
	pstring filter;

	/* TODO: Escaping of name? */

	snprintf(filter, sizeof(filter)-1, "(&(objectClass=%s)(|(%s=%s)(%s=%s)))",
		LDAP_OBJ_GROUPMAP,
		get_attr_key2string(groupmap_attr_list, LDAP_ATTR_DISPLAY_NAME), name,
		get_attr_key2string(groupmap_attr_list, LDAP_ATTR_CN), name);

	return ldapsam_getgroup(methods, filter, map);
}

/**********************************************************************
 *********************************************************************/

static int ldapsam_search_one_group_by_gid(struct ldapsam_privates *ldap_state,
					   gid_t gid,
					   LDAPMessage **result)
{
	pstring filter;

	snprintf(filter, sizeof(filter)-1, "(&(objectClass=%s)(%s=%i))", 
		LDAP_OBJ_POSIXGROUP,
		get_attr_key2string(groupmap_attr_list, LDAP_ATTR_GIDNUMBER),
		gid);

	return ldapsam_search_one_group(ldap_state, filter, result);
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map)
{
	struct ldapsam_privates *ldap_state =
		(struct ldapsam_privates *)methods->private_data;
	LDAPMessage *result = NULL;
	LDAPMod **mods = NULL;

	char *tmp;
	pstring dn;
	LDAPMessage *entry;

	GROUP_MAP dummy;

	int rc;

	if (NT_STATUS_IS_OK(ldapsam_getgrgid(methods, &dummy,
					     map->gid, False))) {
		DEBUG(0, ("Group %i already exists in LDAP\n", map->gid));
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ldapsam_search_one_group_by_gid(ldap_state, map->gid, &result);
	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (ldap_count_entries(ldap_state->ldap_struct, result) != 1) {
		DEBUG(2, ("Group %i must exist exactly once in LDAP\n",
			  map->gid));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	tmp = ldap_get_dn(ldap_state->ldap_struct, entry);
	pstrcpy(dn, tmp);
	ldap_memfree(tmp);

	if (!init_ldap_from_group(ldap_state->ldap_struct,
				  result, &mods, map)) {
		DEBUG(0, ("init_ldap_from_group failed!\n"));
		ldap_mods_free(mods, 1);
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ldap_msgfree(result);

	if (mods == NULL) {
		DEBUG(0, ("mods is empty\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	make_a_mod(&mods, LDAP_MOD_ADD, "objectClass",
		   "sambaGroupMapping");

	rc = ldapsam_modify(ldap_state, dn, mods);
	ldap_mods_free(mods, 1);

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0, ("failed to add group %i error: %s (%s)\n", map->gid, 
			  ld_error ? ld_error : "(unknown)", ldap_err2string(rc)));
		SAFE_FREE(ld_error);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2, ("successfully modified group %i in LDAP\n", map->gid));
	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map)
{
	struct ldapsam_privates *ldap_state =
		(struct ldapsam_privates *)methods->private_data;
	int rc;
	char *dn;
	LDAPMessage *result;
	LDAPMessage *entry;
	LDAPMod **mods;

	rc = ldapsam_search_one_group_by_gid(ldap_state, map->gid, &result);

	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (ldap_count_entries(ldap_state->ldap_struct, result) == 0) {
		DEBUG(0, ("No group to modify!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	dn = ldap_get_dn(ldap_state->ldap_struct, entry);

	if (!init_ldap_from_group(ldap_state->ldap_struct,
				  result, &mods, map)) {
		DEBUG(0, ("init_ldap_from_group failed\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ldap_msgfree(result);

	if (mods == NULL) {
		DEBUG(4, ("mods is empty: nothing to do\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ldapsam_modify(ldap_state, dn, mods);

	ldap_mods_free(mods, 1);

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0, ("failed to modify group %i error: %s (%s)\n", map->gid, 
			  ld_error ? ld_error : "(unknown)", ldap_err2string(rc)));
		SAFE_FREE(ld_error);
	}

	DEBUG(2, ("successfully modified group %i in LDAP\n", map->gid));
	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)methods->private_data;
	pstring sidstring, filter;
	LDAPMessage *result;
	int rc;
	NTSTATUS ret;
	char **attr_list;

	sid_to_string(sidstring, &sid);
	
	snprintf(filter, sizeof(filter)-1, "(&(objectClass=%s)(%s=%s))", 
		LDAP_OBJ_GROUPMAP, LDAP_ATTRIBUTE_SID, sidstring);

	rc = ldapsam_search_one_group(ldap_state, filter, &result);

	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_NO_SUCH_GROUP;
	}

	attr_list = get_attr_list( groupmap_attr_list_to_delete );
	ret = ldapsam_delete_entry(ldap_state, result, LDAP_OBJ_GROUPMAP, attr_list);
	free_attr_list ( attr_list );

	ldap_msgfree(result);

	return ret;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_setsamgrent(struct pdb_methods *my_methods, BOOL update)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	fstring filter;
	int rc;
	char **attr_list;

	snprintf( filter, sizeof(filter)-1, "(objectclass=%s)", LDAP_OBJ_GROUPMAP);
	attr_list = get_attr_list( groupmap_attr_list );
	rc = ldapsam_search(ldap_state, lp_ldap_suffix(),
			    LDAP_SCOPE_SUBTREE, filter,
			    attr_list, 0, &ldap_state->result);
	free_attr_list( attr_list );

	if (rc != LDAP_SUCCESS) {
		DEBUG(0, ("LDAP search failed: %s\n", ldap_err2string(rc)));
		DEBUG(3, ("Query was: %s, %s\n", lp_ldap_suffix(), filter));
		ldap_msgfree(ldap_state->result);
		ldap_state->result = NULL;
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2, ("ldapsam_setsampwent: %d entries in the base!\n",
		  ldap_count_entries(ldap_state->ldap_struct,
				     ldap_state->result)));

	ldap_state->entry = ldap_first_entry(ldap_state->ldap_struct, ldap_state->result);
	ldap_state->index = 0;

	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static void ldapsam_endsamgrent(struct pdb_methods *my_methods)
{
	ldapsam_endsampwent(my_methods);
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_getsamgrent(struct pdb_methods *my_methods,
				    GROUP_MAP *map)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	BOOL bret = False;

	/* The rebind proc needs this *HACK*.  We are not multithreaded, so
	   this will work, but it's not nice. */
	static_ldap_state = ldap_state;

	while (!bret) {
		if (!ldap_state->entry)
			return ret;
		
		ldap_state->index++;
		bret = init_group_from_ldap(ldap_state, map, ldap_state->entry);
		
		ldap_state->entry = ldap_next_entry(ldap_state->ldap_struct,
					    ldap_state->entry);	
	}

	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS ldapsam_enum_group_mapping(struct pdb_methods *methods,
					   enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **rmap, int *num_entries,
					   BOOL unix_only, BOOL with_priv)
{
	GROUP_MAP map;
	GROUP_MAP *mapt;
	int entries = 0;
	NTSTATUS nt_status;

	*num_entries = 0;
	*rmap = NULL;

	if (!NT_STATUS_IS_OK(ldapsam_setsamgrent(methods, False))) {
		DEBUG(0, ("Unable to open passdb\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	while (NT_STATUS_IS_OK(nt_status = ldapsam_getsamgrent(methods, &map))) {
		if (sid_name_use != SID_NAME_UNKNOWN &&
		    sid_name_use != map.sid_name_use) {
			DEBUG(11,("enum_group_mapping: group %s is not of the requested type\n", map.nt_name));
			continue;
		}
		if (unix_only==ENUM_ONLY_MAPPED && map.gid==-1) {
			DEBUG(11,("enum_group_mapping: group %s is non mapped\n", map.nt_name));
			continue;
		}

		mapt=(GROUP_MAP *)Realloc((*rmap), (entries+1)*sizeof(GROUP_MAP));
		if (!mapt) {
			DEBUG(0,("enum_group_mapping: Unable to enlarge group map!\n"));
			SAFE_FREE(*rmap);
			return NT_STATUS_UNSUCCESSFUL;
		}
		else
			(*rmap) = mapt;

		mapt[entries] = map;

		entries += 1;

	}
	ldapsam_endsamgrent(methods);

	*num_entries = entries;

	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS pdb_init_ldapsam_common(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, 
					const char *location)
{
	NTSTATUS nt_status;
	struct ldapsam_privates *ldap_state;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}

	(*pdb_method)->name = "ldapsam";

	(*pdb_method)->setsampwent = ldapsam_setsampwent;
	(*pdb_method)->endsampwent = ldapsam_endsampwent;
	(*pdb_method)->getsampwent = ldapsam_getsampwent;
	(*pdb_method)->getsampwnam = ldapsam_getsampwnam;
	(*pdb_method)->getsampwsid = ldapsam_getsampwsid;
	(*pdb_method)->add_sam_account = ldapsam_add_sam_account;
	(*pdb_method)->update_sam_account = ldapsam_update_sam_account;
	(*pdb_method)->delete_sam_account = ldapsam_delete_sam_account;

	(*pdb_method)->getgrsid = ldapsam_getgrsid;
	(*pdb_method)->getgrgid = ldapsam_getgrgid;
	(*pdb_method)->getgrnam = ldapsam_getgrnam;
	(*pdb_method)->add_group_mapping_entry = ldapsam_add_group_mapping_entry;
	(*pdb_method)->update_group_mapping_entry = ldapsam_update_group_mapping_entry;
	(*pdb_method)->delete_group_mapping_entry = ldapsam_delete_group_mapping_entry;
	(*pdb_method)->enum_group_mapping = ldapsam_enum_group_mapping;

	/* TODO: Setup private data and free */

	ldap_state = talloc_zero(pdb_context->mem_ctx, sizeof(struct ldapsam_privates));

	if (!ldap_state) {
		DEBUG(0, ("talloc() failed for ldapsam private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (location) {
		ldap_state->uri = talloc_strdup(pdb_context->mem_ctx, location);
	} else {
		ldap_state->uri = "ldap://localhost";
	}

	ldap_state->domain_name = talloc_strdup(pdb_context->mem_ctx, get_global_sam_name());
	if (!ldap_state->domain_name) {
		return NT_STATUS_NO_MEMORY;
	}

	sid_copy(&ldap_state->domain_sid, get_global_sam_sid());

	(*pdb_method)->private_data = ldap_state;

	(*pdb_method)->free_private_data = free_private_data;

	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS pdb_init_ldapsam_compat(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	struct ldapsam_privates *ldap_state;

	if (!NT_STATUS_IS_OK(nt_status = pdb_init_ldapsam_common(pdb_context, pdb_method, location))) {
		return nt_status;
	}

	(*pdb_method)->name = "ldapsam_compat";

	ldap_state = (*pdb_method)->private_data;
	ldap_state->schema_ver = SCHEMAVER_SAMBAACCOUNT;

	if (location) {
		ldap_state->uri = talloc_strdup(pdb_context->mem_ctx, location);
	} else {
#ifndef WITH_LDAP_SAMCONFIG
		ldap_state->uri = "ldap://localhost";
#else
		int ldap_port = lp_ldap_port();
			
		/* remap default port if not using SSL (ie clear or TLS) */
		if ( (lp_ldap_ssl() != LDAP_SSL_ON) && (ldap_port == 636) ) {
			ldap_port = 389;
		}

		ldap_state->uri = talloc_asprintf(pdb_context->mem_ctx, "%s://%s:%d", lp_ldap_ssl() == LDAP_SSL_ON ? "ldaps" : "ldap", lp_ldap_server(), ldap_port);
		if (!ldap_state->uri) {
			return NT_STATUS_NO_MEMORY;
		}
#endif
	}

	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS pdb_init_ldapsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	struct ldapsam_privates *ldap_state;
	uint32 low_idmap_uid, high_idmap_uid;
	uint32 low_idmap_gid, high_idmap_gid;

	if (!NT_STATUS_IS_OK(nt_status = pdb_init_ldapsam_common(pdb_context, pdb_method, location))) {
		return nt_status;
	}

	(*pdb_method)->name = "ldapsam";

	ldap_state = (*pdb_method)->private_data;
	ldap_state->schema_ver = SCHEMAVER_SAMBASAMACCOUNT;	
	ldap_state->permit_non_unix_accounts = False;

	/* check for non-unix account ranges */

	if (lp_idmap_uid(&low_idmap_uid, &high_idmap_uid) 
		&&  lp_idmap_gid(&low_idmap_gid, &high_idmap_gid)) 
	{
		DEBUG(2, ("Enabling non-unix account ranges\n"));

		ldap_state->permit_non_unix_accounts = True;

		ldap_state->low_allocated_user_rid   = fallback_pdb_uid_to_user_rid(low_idmap_uid);
		ldap_state->high_allocated_user_rid  = fallback_pdb_uid_to_user_rid(high_idmap_uid);
		ldap_state->low_allocated_group_rid  = pdb_gid_to_group_rid(low_idmap_gid);
		ldap_state->high_allocated_group_rid = pdb_gid_to_group_rid(high_idmap_gid);
	}

	return NT_STATUS_OK;
}

NTSTATUS pdb_ldap_init(void)
{
	NTSTATUS nt_status;
	if (!NT_STATUS_IS_OK(nt_status = smb_register_passdb(PASSDB_INTERFACE_VERSION, "ldapsam", pdb_init_ldapsam)))
		return nt_status;

	if (!NT_STATUS_IS_OK(nt_status = smb_register_passdb(PASSDB_INTERFACE_VERSION, "ldapsam_compat", pdb_init_ldapsam_compat)))
		return nt_status;

	return NT_STATUS_OK;
}


