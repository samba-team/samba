/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Gerald Carter			2001-2003
    
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

ATTRIB_MAP_ENTRY dominfo_attr_list[] = {
	{ LDAP_ATTR_DOMAIN,		"sambaDomainName"	},
	{ LDAP_ATTR_NEXT_USERRID,	"sambaNextUserRid"	},
	{ LDAP_ATTR_NEXT_GROUPRID,	"sambaNextGroupRid"	},
	{ LDAP_ATTR_DOM_SID,		"sambaSID"		},
	{ LDAP_ATTR_LIST_END,		NULL			},
};

/* Samba 3.0 group mapping attributes */

ATTRIB_MAP_ENTRY groupmap_attr_list[] = {
	{ LDAP_ATTR_GIDNUMBER,		LDAP_ATTRIBUTE_GIDNUMBER},
	{ LDAP_ATTR_GROUP_SID,		"sambaSID"		},
	{ LDAP_ATTR_GROUP_TYPE,		"sambaGroupType"	},
	{ LDAP_ATTR_DESC,		"description"		},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_CN,			"cn"			},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

ATTRIB_MAP_ENTRY groupmap_attr_list_to_delete[] = {
	{ LDAP_ATTR_GROUP_SID,		"sambaSID"		},
	{ LDAP_ATTR_GROUP_TYPE,		"sambaGroupType"	},
	{ LDAP_ATTR_DESC,		"description"		},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

/* idmap_ldap samba[U|G]idPool */

ATTRIB_MAP_ENTRY idpool_attr_list[] = {
	{ LDAP_ATTR_UIDNUMBER,		LDAP_ATTRIBUTE_UIDNUMBER},
	{ LDAP_ATTR_GIDNUMBER,		LDAP_ATTRIBUTE_GIDNUMBER},
	{ LDAP_ATTR_LIST_END,		NULL			}	
};

ATTRIB_MAP_ENTRY sidmap_attr_list[] = {
	{ LDAP_ATTR_GROUP_SID,		"sambaSID"		},
	{ LDAP_ATTR_UIDNUMBER,		LDAP_ATTRIBUTE_UIDNUMBER},
	{ LDAP_ATTR_GIDNUMBER,		LDAP_ATTRIBUTE_GIDNUMBER},
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

	while ( list[i] )
		SAFE_FREE( list[i] );

	SAFE_FREE( list );
}

/*******************************************************************
 find the ldap password
******************************************************************/
BOOL fetch_ldap_pw(char **dn, char** pw)
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

