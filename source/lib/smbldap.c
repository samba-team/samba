/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001-2003
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002-2003
   Copyright (C) Stefan (metze) Metzmacher	2002-2003
    
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
#include "smbldap.h"

#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS 0
#endif

/* Try not to hit the up or down server forever */

#define SMBLDAP_DONT_PING_TIME 10	/* ping only all 10 seconds */
#define SMBLDAP_NUM_RETRIES 8	        /* retry only 8 times */

#define SMBLDAP_IDLE_TIME 150		/* After 2.5 minutes disconnect */


/* attributes used by Samba 2.2 */

ATTRIB_MAP_ENTRY attrib_map_v22[] = {
	{ LDAP_ATTR_UID,		"uid" 		},
	{ LDAP_ATTR_UIDNUMBER,		LDAP_ATTRIBUTE_UIDNUMBER},
	{ LDAP_ATTR_GIDNUMBER,		LDAP_ATTRIBUTE_GIDNUMBER},
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

ATTRIB_MAP_ENTRY attrib_map_v30[] = {
	{ LDAP_ATTR_UID,		"uid" 			},
	{ LDAP_ATTR_UIDNUMBER,		LDAP_ATTRIBUTE_UIDNUMBER},
	{ LDAP_ATTR_GIDNUMBER,		LDAP_ATTRIBUTE_GIDNUMBER},
	{ LDAP_ATTR_UNIX_HOME,		"homeDirectory"		},
	{ LDAP_ATTR_PWD_LAST_SET,	"sambaPwdLastSet"	},
	{ LDAP_ATTR_PWD_CAN_CHANGE,	"sambaPwdCanChange"	},
	{ LDAP_ATTR_PWD_MUST_CHANGE,	"sambaPwdMustChange"	},
	{ LDAP_ATTR_LOGON_TIME,		"sambaLogonTime" 	},
	{ LDAP_ATTR_LOGOFF_TIME,	"sambaLogoffTime"	},
	{ LDAP_ATTR_KICKOFF_TIME,	"sambaKickoffTime"	},
	{ LDAP_ATTR_CN,			"cn"			},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_HOME_DRIVE,		"sambaHomeDrive"	},
	{ LDAP_ATTR_HOME_PATH,		"sambaHomePath"		},
	{ LDAP_ATTR_LOGON_SCRIPT,	"sambaLogonScript"	},
	{ LDAP_ATTR_PROFILE_PATH,	"sambaProfilePath"	},
	{ LDAP_ATTR_DESC,		"description"		},
	{ LDAP_ATTR_USER_WKS,		"sambaUserWorkstations"	},
	{ LDAP_ATTR_USER_SID,		LDAP_ATTRIBUTE_SID	},
	{ LDAP_ATTR_PRIMARY_GROUP_SID,	"sambaPrimaryGroupSID"	},
	{ LDAP_ATTR_LMPW,		"sambaLMPassword"	},
	{ LDAP_ATTR_NTPW,		"sambaNTPassword"	},
	{ LDAP_ATTR_DOMAIN,		"sambaDomainName"	},
	{ LDAP_ATTR_OBJCLASS,		"objectClass"		},
	{ LDAP_ATTR_ACB_INFO,		"sambaAcctFlags"	},
	{ LDAP_ATTR_MUNGED_DIAL,	"sambaMungedDial"	},
	{ LDAP_ATTR_BAD_PASSWORD_COUNT,	"sambaBadPasswordCount" },
	{ LDAP_ATTR_BAD_PASSWORD_TIME,	"sambaBadPasswordTime" 	},
	{ LDAP_ATTR_LIST_END,		NULL 			}
};

/* attributes used for allocating RIDs */

ATTRIB_MAP_ENTRY dominfo_attr_list[] = {
	{ LDAP_ATTR_DOMAIN,		"sambaDomainName"	},
	{ LDAP_ATTR_NEXT_RID,	        "sambaNextRid"	        },
	{ LDAP_ATTR_NEXT_USERRID,	"sambaNextUserRid"	},
	{ LDAP_ATTR_NEXT_GROUPRID,	"sambaNextGroupRid"	},
	{ LDAP_ATTR_DOM_SID,		LDAP_ATTRIBUTE_SID	},
	{ LDAP_ATTR_ALGORITHMIC_RID_BASE,"sambaAlgorithmicRidBase"},
	{ LDAP_ATTR_OBJCLASS,		"objectClass"		},
	{ LDAP_ATTR_LIST_END,		NULL			},
};

/* Samba 3.0 group mapping attributes */

ATTRIB_MAP_ENTRY groupmap_attr_list[] = {
	{ LDAP_ATTR_GIDNUMBER,		LDAP_ATTRIBUTE_GIDNUMBER},
	{ LDAP_ATTR_GROUP_SID,		LDAP_ATTRIBUTE_SID	},
	{ LDAP_ATTR_GROUP_TYPE,		"sambaGroupType"	},
	{ LDAP_ATTR_SID_LIST,		"sambaSIDList"		},
	{ LDAP_ATTR_DESC,		"description"		},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_CN,			"cn"			},
	{ LDAP_ATTR_OBJCLASS,		"objectClass"		},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

ATTRIB_MAP_ENTRY groupmap_attr_list_to_delete[] = {
	{ LDAP_ATTR_GROUP_SID,		LDAP_ATTRIBUTE_SID	},
	{ LDAP_ATTR_GROUP_TYPE,		"sambaGroupType"	},
	{ LDAP_ATTR_DESC,		"description"		},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_SID_LIST,		"sambaSIDList"		},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

/* idmap_ldap sambaUnixIdPool */

ATTRIB_MAP_ENTRY idpool_attr_list[] = {
	{ LDAP_ATTR_UIDNUMBER,		LDAP_ATTRIBUTE_UIDNUMBER},
	{ LDAP_ATTR_GIDNUMBER,		LDAP_ATTRIBUTE_GIDNUMBER},
	{ LDAP_ATTR_OBJCLASS,		"objectClass"		},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

ATTRIB_MAP_ENTRY sidmap_attr_list[] = {
	{ LDAP_ATTR_SID,		LDAP_ATTRIBUTE_SID	},
	{ LDAP_ATTR_UIDNUMBER,		LDAP_ATTRIBUTE_UIDNUMBER},
	{ LDAP_ATTR_GIDNUMBER,		LDAP_ATTRIBUTE_GIDNUMBER},
	{ LDAP_ATTR_OBJCLASS,		"objectClass"		},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

/**********************************************************************
 perform a simple table lookup and return the attribute name 
 **********************************************************************/
 
 const char* get_attr_key2string( ATTRIB_MAP_ENTRY table[], int key )
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
 Return the list of attribute names from a mapping table
 **********************************************************************/

 char** get_attr_list( ATTRIB_MAP_ENTRY table[] )
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

 void free_attr_list( char **list )
{
	int i = 0;

	if ( !list )
		return; 

	while ( list[i] ) {
		SAFE_FREE( list[i] );
		i+=1;
	}

	SAFE_FREE( list );
}

/*******************************************************************
 find the ldap password
******************************************************************/
static BOOL fetch_ldap_pw(char **dn, char** pw)
{
	char *key = NULL;
	size_t size;
	
	*dn = smb_xstrdup(lp_ldap_admin_dn());
	
	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, *dn) < 0) {
		SAFE_FREE(*dn);
		DEBUG(0, ("fetch_ldap_pw: asprintf failed!\n"));
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
			DEBUG(0, ("fetch_ldap_pw: strdup failed!\n"));
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

		size = MIN(size, sizeof(fstring)-1);
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
 Search an attribute and return the first value found.
******************************************************************/

 BOOL smbldap_get_single_attribute (LDAP * ldap_struct, LDAPMessage * entry,
				    const char *attribute, char *value,
				    int max_len)
{
	char **values;
	
	if ( !attribute )
		return False;
		
	value[0] = '\0';

	if ((values = ldap_get_values (ldap_struct, entry, attribute)) == NULL) {
		DEBUG (10, ("smbldap_get_single_attribute: [%s] = [<does not exist>]\n", attribute));
		
		return False;
	}
	
	if (convert_string(CH_UTF8, CH_UNIX,values[0], -1, value, max_len, False) == (size_t)-1) {
		DEBUG(1, ("smbldap_get_single_attribute: string conversion of [%s] = [%s] failed!\n", 
			  attribute, values[0]));
		ldap_value_free(values);
		return False;
	}
	
	ldap_value_free(values);
#ifdef DEBUG_PASSWORDS
	DEBUG (100, ("smbldap_get_single_attribute: [%s] = [%s]\n", attribute, value));
#endif	
	return True;
}

 BOOL smbldap_get_single_pstring (LDAP * ldap_struct, LDAPMessage * entry,
				  const char *attribute, pstring value)
{
	return smbldap_get_single_attribute(ldap_struct, entry,
					    attribute, value, 
					    sizeof(pstring));
}

/************************************************************************
 Routine to manage the LDAPMod structure array
 manage memory used by the array, by each struct, and values
 ***********************************************************************/

 void smbldap_set_mod (LDAPMod *** modlist, int modop, const char *attribute, const char *value)
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
		if (mods[i]->mod_op == modop && strequal(mods[i]->mod_type, attribute))
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

 void smbldap_make_mod(LDAP *ldap_struct, LDAPMessage *existing,
		      LDAPMod ***mods,
		      const char *attribute, const char *newval)
{
	char oldval[2048]; /* current largest allowed value is mungeddial */
	BOOL existed;

	if (existing != NULL) {
		existed = smbldap_get_single_attribute(ldap_struct, existing, attribute, oldval, sizeof(oldval));
	} else {
		existed = False;
		*oldval = '\0';
	}

	/* all of our string attributes are case insensitive */
	
	if (existed && newval && (StrCaseCmp(oldval, newval) == 0)) {
		
		/* Believe it or not, but LDAP will deny a delete and
		   an add at the same time if the values are the
		   same... */
		return;
	}

	if (existed) {
		/* There has been no value before, so don't delete it.
		 * Here's a possible race: We might end up with
		 * duplicate attributes */
		/* By deleting exactly the value we found in the entry this
		 * should be race-free in the sense that the LDAP-Server will
		 * deny the complete operation if somebody changed the
		 * attribute behind our back. */
		/* This will also allow modifying single valued attributes 
		 * in Novell NDS. In NDS you have to first remove attribute and then
		 * you could add new value */
		
		smbldap_set_mod(mods, LDAP_MOD_DELETE, attribute, oldval);
	}

	/* Regardless of the real operation (add or modify)
	   we add the new value here. We rely on deleting
	   the old value, should it exist. */

	if ((newval != NULL) && (strlen(newval) > 0)) {
		smbldap_set_mod(mods, LDAP_MOD_ADD, attribute, newval);
	}
}

/**********************************************************************
 Some varients of the LDAP rebind code do not pass in the third 'arg' 
 pointer to a void*, so we try and work around it by assuming that the 
 value of the 'LDAP *' pointer is the same as the one we had passed in
 **********************************************************************/

struct smbldap_state_lookup {
	LDAP *ld;
	struct smbldap_state *smbldap_state;
	struct smbldap_state_lookup *prev, *next;
};

static struct smbldap_state_lookup *smbldap_state_lookup_list;

static struct smbldap_state *smbldap_find_state(LDAP *ld) 
{
	struct smbldap_state_lookup *t;

	for (t = smbldap_state_lookup_list; t; t = t->next) {
		if (t->ld == ld) {
			return t->smbldap_state;
		}
	}
	return NULL;
}

static void smbldap_delete_state(struct smbldap_state *smbldap_state) 
{
	struct smbldap_state_lookup *t;

	for (t = smbldap_state_lookup_list; t; t = t->next) {
		if (t->smbldap_state == smbldap_state) {
			DLIST_REMOVE(smbldap_state_lookup_list, t);
			SAFE_FREE(t);
			return;
		}
	}
}

static void smbldap_store_state(LDAP *ld, struct smbldap_state *smbldap_state) 
{
	struct smbldap_state *tmp_ldap_state;
	struct smbldap_state_lookup *t;
	struct smbldap_state_lookup *tmp;
	
	if ((tmp_ldap_state = smbldap_find_state(ld))) {
		SMB_ASSERT(tmp_ldap_state == smbldap_state);
		return;
	}

	t = smb_xmalloc(sizeof(*t));
	ZERO_STRUCTP(t);
	
	DLIST_ADD_END(smbldap_state_lookup_list, t, tmp);
	t->ld = ld;
	t->smbldap_state = smbldap_state;
}

/*******************************************************************
 open a connection to the ldap server.
******************************************************************/
static int smbldap_open_connection (struct smbldap_state *ldap_state)

{
	int rc = LDAP_SUCCESS;
	int version;
	BOOL ldap_v3 = False;
	LDAP **ldap_struct = &ldap_state->ldap_struct;

#ifdef HAVE_LDAP_INITIALIZE
	DEBUG(10, ("smbldap_open_connection: %s\n", ldap_state->uri));
	
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
		if ( strnequal( p, "URL:", 4 ) ) {
			p += 4;
		}
		
		sscanf(p, "%10[^:]://%254[^:/]:%d", protocol, host, &port);
		
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
			DEBUG(0,("smbldap_open_connection: Secure connection not supported by LDAP client libraries!\n"));
			return LDAP_OPERATIONS_ERROR;
#endif
		}
	}
#endif

	/* Store the LDAP pointer in a lookup list */

	smbldap_store_state(*ldap_struct, ldap_state);

	/* Upgrade to LDAPv3 if possible */

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
		DEBUG(0,("smbldap_open_connection: StartTLS not supported by LDAP client libraries!\n"));
		return LDAP_OPERATIONS_ERROR;
#endif
	}

	DEBUG(2, ("smbldap_open_connection: connection opened\n"));
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
	struct smbldap_state *ldap_state = arg;
	
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

	gettimeofday(&(ldap_state->last_rebind),NULL);
		
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
	struct smbldap_state *ldap_state = arg;
	int rc;
	DEBUG(5,("rebindproc_connect_with_state: Rebinding as \"%s\"\n", 
		 ldap_state->bind_dn));
	
	/** @TODO Should we be doing something to check what servers we rebind to?
	    Could we get a referral to a machine that we don't want to give our
	    username and password to? */

	rc = ldap_simple_bind_s(ldap_struct, ldap_state->bind_dn, ldap_state->bind_secret);
	
	gettimeofday(&(ldap_state->last_rebind),NULL);

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
	struct smbldap_state *ldap_state = smbldap_find_state(ldap_struct);

	return rebindproc_with_state(ldap_struct, whop, credp,
				     method, freeit, ldap_state);
	
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
	struct smbldap_state *ldap_state = smbldap_find_state(ld);

	return rebindproc_connect_with_state(ld, url, (ber_tag_t)request, msgid, 
					     ldap_state);
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 connect to the ldap server under system privilege.
******************************************************************/
static int smbldap_connect_system(struct smbldap_state *ldap_state, LDAP * ldap_struct)
{
	int rc;
	char *ldap_dn;
	char *ldap_secret;

	/* get the password */
	if (!fetch_ldap_pw(&ldap_dn, &ldap_secret))
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
			       ldap_dn ? ldap_dn : "(unknown)", ldap_err2string(rc),
			       ld_error ? ld_error : "(unknown)"));
		SAFE_FREE(ld_error);
		ldap_state->num_failures++;
		return rc;
	}

	ldap_state->num_failures = 0;

	DEBUG(3, ("ldap_connect_system: succesful connection to the LDAP server\n"));
	return rc;
}

/**********************************************************************
Connect to LDAP server (called before every ldap operation)
*********************************************************************/
static int smbldap_open(struct smbldap_state *ldap_state)
{
	int rc;
	SMB_ASSERT(ldap_state);
		
#ifndef NO_LDAP_SECURITY
	if (geteuid() != 0) {
		DEBUG(0, ("smbldap_open: cannot access LDAP when not root..\n"));
		return  LDAP_INSUFFICIENT_ACCESS;
	}
#endif

       	if ((ldap_state->ldap_struct != NULL) && ((ldap_state->last_ping + SMBLDAP_DONT_PING_TIME) < time(NULL))) {
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
		DEBUG(11,("smbldap_open: already connected to the LDAP server\n"));
		return LDAP_SUCCESS;
	}

	if ((rc = smbldap_open_connection(ldap_state))) {
		return rc;
	}

	if ((rc = smbldap_connect_system(ldap_state, ldap_state->ldap_struct))) {
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
static NTSTATUS smbldap_close(struct smbldap_state *ldap_state)
{
	if (!ldap_state)
		return NT_STATUS_INVALID_PARAMETER;
		
	if (ldap_state->ldap_struct != NULL) {
		ldap_unbind_ext(ldap_state->ldap_struct, NULL, NULL);
		ldap_state->ldap_struct = NULL;
	}

	smbldap_delete_state(ldap_state);
	
	DEBUG(5,("The connection to the LDAP server was closed\n"));
	/* maybe free the results here --metze */
	
	

	return NT_STATUS_OK;
}

int smbldap_retry_open(struct smbldap_state *ldap_state, int *attempts)
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
		smb_msleep(sleep_time);
	}
	(*attempts)++;

	if ((rc = smbldap_open(ldap_state))) {
		DEBUG(1,("Connection to LDAP Server failed for the %d try!\n",*attempts));
		return rc;
	} 
	
	return LDAP_SUCCESS;		
}


/*********************************************************************
 ********************************************************************/

int smbldap_search(struct smbldap_state *ldap_state, 
		   const char *base, int scope, const char *filter, 
		   char *attrs[], int attrsonly, 
		   LDAPMessage **res)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	char           *utf8_filter;

	SMB_ASSERT(ldap_state);
	
	DEBUG(5,("smbldap_search: base => [%s], filter => [%s], scope => [%d]\n",
		base, filter, scope));

	if (ldap_state->last_rebind.tv_sec > 0) {
		struct timeval	tval;
		int 		tdiff = 0;
		int		sleep_time = 0;

		ZERO_STRUCT(tval);

		gettimeofday(&tval,NULL);

		tdiff = 1000000 *(tval.tv_sec - ldap_state->last_rebind.tv_sec) + 
			(tval.tv_usec - ldap_state->last_rebind.tv_usec);

		sleep_time = ((1000*lp_ldap_replication_sleep())-tdiff)/1000;

		if (sleep_time > 0) {
			/* we wait for the LDAP replication */
			DEBUG(5,("smbldap_search: waiting %d milliseconds for LDAP replication.\n",sleep_time));
			smb_msleep(sleep_time);
			DEBUG(5,("smbldap_search: go on!\n"));
			ZERO_STRUCT(ldap_state->last_rebind);
		}
	}

	if (push_utf8_allocate(&utf8_filter, filter) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < SMBLDAP_NUM_RETRIES)) {
		
		if ((rc = smbldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_search_s(ldap_state->ldap_struct, base, scope, 
				   utf8_filter, attrs, attrsonly, res);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smbldap_close(ldap_state);	
	}

	ldap_state->last_use = time(NULL);

	SAFE_FREE(utf8_filter);
	return rc;
}

int smbldap_modify(struct smbldap_state *ldap_state, const char *dn, LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	char           *utf8_dn;

	SMB_ASSERT(ldap_state);

	DEBUG(5,("smbldap_modify: dn => [%s]\n", dn ));

	if (push_utf8_allocate(&utf8_dn, dn) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < SMBLDAP_NUM_RETRIES)) {
		
		if ((rc = smbldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_modify_s(ldap_state->ldap_struct, utf8_dn, attrs);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smbldap_close(ldap_state);	
	}
	
	ldap_state->last_use = time(NULL);

	SAFE_FREE(utf8_dn);
	return rc;
}

int smbldap_add(struct smbldap_state *ldap_state, const char *dn, LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	char           *utf8_dn;
	
	SMB_ASSERT(ldap_state);

	DEBUG(5,("smbldap_add: dn => [%s]\n", dn ));

	if (push_utf8_allocate(&utf8_dn, dn) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < SMBLDAP_NUM_RETRIES)) {
		
		if ((rc = smbldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_add_s(ldap_state->ldap_struct, utf8_dn, attrs);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smbldap_close(ldap_state);	
	}
		
	ldap_state->last_use = time(NULL);

	SAFE_FREE(utf8_dn);
	return rc;
}

int smbldap_delete(struct smbldap_state *ldap_state, const char *dn)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	char           *utf8_dn;
	
	SMB_ASSERT(ldap_state);

	DEBUG(5,("smbldap_delete: dn => [%s]\n", dn ));

	if (push_utf8_allocate(&utf8_dn, dn) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < SMBLDAP_NUM_RETRIES)) {
		
		if ((rc = smbldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_delete_s(ldap_state->ldap_struct, utf8_dn);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smbldap_close(ldap_state);	
	}
		
	ldap_state->last_use = time(NULL);

	SAFE_FREE(utf8_dn);
	return rc;
}

int smbldap_extended_operation(struct smbldap_state *ldap_state, 
			       LDAP_CONST char *reqoid, struct berval *reqdata, 
			       LDAPControl **serverctrls, LDAPControl **clientctrls, 
			       char **retoidp, struct berval **retdatap)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < SMBLDAP_NUM_RETRIES)) {
		
		if ((rc = smbldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_extended_operation_s(ldap_state->ldap_struct, reqoid, reqdata, 
					       serverctrls, clientctrls, retoidp, retdatap);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smbldap_close(ldap_state);	
	}
		
	ldap_state->last_use = time(NULL);

	return rc;
}

/*******************************************************************
 run the search by name.
******************************************************************/
int smbldap_search_suffix (struct smbldap_state *ldap_state, const char *filter, 
			   char **search_attr, LDAPMessage ** result)
{
	int scope = LDAP_SCOPE_SUBTREE;
	int rc;

	rc = smbldap_search(ldap_state, lp_ldap_suffix(), scope, filter, search_attr, 0, result);

	if (rc != LDAP_SUCCESS)	{
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0,("smbldap_search_suffix: Problem during the LDAP search: %s (%s)\n", 
			ld_error?ld_error:"(unknown)", ldap_err2string (rc)));
		SAFE_FREE(ld_error);
	}
	
	return rc;
}

static void smbldap_idle_fn(void **data, time_t *interval, time_t now)
{
	struct smbldap_state *state = (struct smbldap_state *)(*data);

	if (state->ldap_struct == NULL) {
		DEBUG(10,("ldap connection not connected...\n"));
		return;
	}
		
	if ((state->last_use+SMBLDAP_IDLE_TIME) > now) {
		DEBUG(10,("ldap connection not idle...\n"));
		return;
	}
		
	DEBUG(7,("ldap connection idle...closing connection\n"));
	smbldap_close(state);
}

/**********************************************************************
 Housekeeping
 *********************************************************************/

void smbldap_free_struct(struct smbldap_state **ldap_state) 
{
	smbldap_close(*ldap_state);
	
	if ((*ldap_state)->bind_secret) {
		memset((*ldap_state)->bind_secret, '\0', strlen((*ldap_state)->bind_secret));
	}

	SAFE_FREE((*ldap_state)->bind_dn);
	SAFE_FREE((*ldap_state)->bind_secret);

	smb_unregister_idle_event((*ldap_state)->event_id);

	*ldap_state = NULL;

	/* No need to free any further, as it is talloc()ed */
}


/**********************************************************************
 Intitalise the 'general' ldap structures, on which ldap operations may be conducted
 *********************************************************************/

NTSTATUS smbldap_init(TALLOC_CTX *mem_ctx, const char *location, struct smbldap_state **smbldap_state) 
{
	*smbldap_state = talloc_zero(mem_ctx, sizeof(**smbldap_state));
	if (!*smbldap_state) {
		DEBUG(0, ("talloc() failed for ldapsam private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (location) {
		(*smbldap_state)->uri = talloc_strdup(mem_ctx, location);
	} else {
		(*smbldap_state)->uri = "ldap://localhost";
	}

	(*smbldap_state)->event_id =
		smb_register_idle_event(smbldap_idle_fn, (void *)(*smbldap_state),
					SMBLDAP_IDLE_TIME);

	if ((*smbldap_state)->event_id == SMB_EVENT_ID_INVALID) {
		DEBUG(0,("Failed to register LDAP idle event!\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_OK;
}

/**********************************************************************
 Add the sambaDomain to LDAP, so we don't have to search for this stuff
 again.  This is a once-add operation for now.

 TODO:  Add other attributes, and allow modification.
*********************************************************************/
static NTSTATUS add_new_domain_info(struct smbldap_state *ldap_state, 
                                    const char *domain_name) 
{
	fstring sid_string;
	fstring algorithmic_rid_base_string;
	pstring filter, dn;
	LDAPMod **mods = NULL;
	int rc;
	int ldap_op;
	LDAPMessage *result = NULL;
	int num_result;
	char **attr_list;
	uid_t u_low, u_high;
	gid_t g_low, g_high;
	uint32 rid_low, rid_high;

	slprintf (filter, sizeof (filter) - 1, "(&(%s=%s)(objectclass=%s))", 
		  get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		  domain_name, LDAP_OBJ_DOMINFO);

	attr_list = get_attr_list( dominfo_attr_list );
	rc = smbldap_search_suffix(ldap_state, filter, attr_list, &result);
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

	pstr_sprintf(dn, "%s=%s,%s", get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN),
		domain_name, lp_ldap_suffix());

	/* Free original search */
	ldap_msgfree(result);

	/* make the changes - the entry *must* not already have samba attributes */
	smbldap_set_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		domain_name);

	/* If we don't have an entry, then ask secrets.tdb for what it thinks.  
	   It may choose to make it up */

	sid_to_string(sid_string, get_global_sam_sid());
	smbldap_set_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOM_SID), sid_string);

	slprintf(algorithmic_rid_base_string, sizeof(algorithmic_rid_base_string) - 1, "%i", algorithmic_rid_base());
	smbldap_set_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_ALGORITHMIC_RID_BASE), 
			algorithmic_rid_base_string);
	smbldap_set_mod(&mods, LDAP_MOD_ADD, "objectclass", LDAP_OBJ_DOMINFO);
	
	/* add the sambaNext[User|Group]Rid attributes if the idmap ranges are set.
	   TODO: fix all the places where the line between idmap and normal operations
	   needed by smbd gets fuzzy   --jerry 2003-08-11                              */
	
	if ( lp_idmap_uid(&u_low, &u_high) && lp_idmap_gid(&g_low, &g_high)
		&& get_free_rid_range(&rid_low, &rid_high) ) 
	{
		fstring rid_str;
		
		fstr_sprintf( rid_str, "%i", rid_high|USER_RID_TYPE );
		DEBUG(10,("setting next available user rid [%s]\n", rid_str));
		smbldap_set_mod(&mods, LDAP_MOD_ADD, 
			get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_USERRID), 
			rid_str);
			
		fstr_sprintf( rid_str, "%i", rid_high|GROUP_RID_TYPE );
		DEBUG(10,("setting next available group rid [%s]\n", rid_str));
		smbldap_set_mod(&mods, LDAP_MOD_ADD, 
			get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_GROUPRID), 
			rid_str);
		
        }


	switch(ldap_op)
	{
	case LDAP_MOD_ADD: 
		rc = smbldap_add(ldap_state, dn, mods);
		break;
	case LDAP_MOD_REPLACE: 
		rc = smbldap_modify(ldap_state, dn, mods);
		break;
	default: 	
		DEBUG(0,("Wrong LDAP operation type: %d!\n", ldap_op));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	if (rc!=LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG(1,("failed to %s domain dn= %s with: %s\n\t%s\n",
		       ldap_op == LDAP_MOD_ADD ? "add" : "modify",
		       dn, ldap_err2string(rc),
		       ld_error?ld_error:"unknown"));
		SAFE_FREE(ld_error);

		ldap_mods_free(mods, True);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2,("added: domain = %s in the LDAP database\n", domain_name));
	ldap_mods_free(mods, True);
	return NT_STATUS_OK;
}

/**********************************************************************
Search for the domain info entry
*********************************************************************/
NTSTATUS smbldap_search_domain_info(struct smbldap_state *ldap_state,
                                    LDAPMessage ** result, const char *domain_name,
                                    BOOL try_add)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	pstring filter;
	int rc;
	char **attr_list;
	int count;

	pstr_sprintf(filter, "(&(objectClass=%s)(%s=%s))",
		LDAP_OBJ_DOMINFO,
		get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		domain_name);

	DEBUG(2, ("Searching for:[%s]\n", filter));


	attr_list = get_attr_list( dominfo_attr_list );
	rc = smbldap_search_suffix(ldap_state, filter, attr_list , result);
	free_attr_list( attr_list );

	if (rc != LDAP_SUCCESS) {
		DEBUG(2,("Problem during LDAPsearch: %s\n", ldap_err2string (rc)));
		DEBUG(2,("Query was: %s, %s\n", lp_ldap_suffix(), filter));
	} else if (ldap_count_entries(ldap_state->ldap_struct, *result) < 1) {
		DEBUG(3, ("Got no domain info entries for domain\n"));
		ldap_msgfree(*result);
		*result = NULL;
		if (try_add && NT_STATUS_IS_OK(ret = add_new_domain_info(ldap_state, domain_name))) {
			return smbldap_search_domain_info(ldap_state, result, domain_name, False);
		} 
		else {
			DEBUG(0, ("Adding domain info for %s failed with %s\n", 
				domain_name, nt_errstr(ret)));
			return ret;
		}
	} else if ((count = ldap_count_entries(ldap_state->ldap_struct, *result)) > 1) {
		DEBUG(0, ("Got too many (%d) domain info entries for domain %s\n",
			  count, domain_name));
		ldap_msgfree(*result);
		*result = NULL;
		return ret;
	} else {
		return NT_STATUS_OK;
	}
	
	return ret;
}

/*******************************************************************
 Return a copy of the DN for a LDAPMessage. Convert from utf8 to CH_UNIX.
********************************************************************/

char *smbldap_get_dn(LDAP *ld, LDAPMessage *entry)
{
	char *utf8_dn, *unix_dn;

	utf8_dn = ldap_get_dn(ld, entry);
	if (!utf8_dn) {
		DEBUG (5, ("smbldap_get_dn: ldap_get_dn failed\n"));
		return NULL;
	}
	if (pull_utf8_allocate(&unix_dn, utf8_dn) == (size_t)-1) {
		DEBUG (0, ("smbldap_get_dn: String conversion failure utf8 [%s]\n", utf8_dn));
		return NULL;
	}
	ldap_memfree(utf8_dn);
	return unix_dn;
}

