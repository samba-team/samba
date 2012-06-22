/*
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001-2003
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002-2003
   Copyright (C) Stefan (metze) Metzmacher	2002-2003

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

#include "includes.h"
#include "passdb/pdb_ldap_schema.h"

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
	{ LDAP_ATTR_SN,			"sn"			},
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
	{ LDAP_ATTR_PWD_HISTORY,	"sambaPasswordHistory"  },
	{ LDAP_ATTR_MOD_TIMESTAMP,	"modifyTimestamp"	},
	{ LDAP_ATTR_LOGON_HOURS,	"sambaLogonHours"	},
	{ LDAP_ATTR_LIST_END,		NULL 			}
};

ATTRIB_MAP_ENTRY attrib_map_to_delete_v30[] = {
	{ LDAP_ATTR_PWD_LAST_SET,	"sambaPwdLastSet"	},
	{ LDAP_ATTR_PWD_CAN_CHANGE,	"sambaPwdCanChange"	},
	{ LDAP_ATTR_PWD_MUST_CHANGE,	"sambaPwdMustChange"	},
	{ LDAP_ATTR_LOGON_TIME,		"sambaLogonTime" 	},
	{ LDAP_ATTR_LOGOFF_TIME,	"sambaLogoffTime"	},
	{ LDAP_ATTR_KICKOFF_TIME,	"sambaKickoffTime"	},
	{ LDAP_ATTR_DISPLAY_NAME,	"displayName"		},
	{ LDAP_ATTR_HOME_DRIVE,		"sambaHomeDrive"	},
	{ LDAP_ATTR_HOME_PATH,		"sambaHomePath"		},
	{ LDAP_ATTR_LOGON_SCRIPT,	"sambaLogonScript"	},
	{ LDAP_ATTR_PROFILE_PATH,	"sambaProfilePath"	},
	{ LDAP_ATTR_USER_WKS,		"sambaUserWorkstations"	},
	{ LDAP_ATTR_USER_SID,		LDAP_ATTRIBUTE_SID	},
	{ LDAP_ATTR_PRIMARY_GROUP_SID,	"sambaPrimaryGroupSID"	},
	{ LDAP_ATTR_LMPW,		"sambaLMPassword"	},
	{ LDAP_ATTR_NTPW,		"sambaNTPassword"	},
	{ LDAP_ATTR_DOMAIN,		"sambaDomainName"	},
	{ LDAP_ATTR_ACB_INFO,		"sambaAcctFlags"	},
	{ LDAP_ATTR_MUNGED_DIAL,	"sambaMungedDial"	},
	{ LDAP_ATTR_BAD_PASSWORD_COUNT,	"sambaBadPasswordCount" },
	{ LDAP_ATTR_BAD_PASSWORD_TIME,	"sambaBadPasswordTime" 	},
	{ LDAP_ATTR_PWD_HISTORY,	"sambaPasswordHistory"  },
	{ LDAP_ATTR_LOGON_HOURS,	"sambaLogonHours"	},
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

 const char** get_attr_list( TALLOC_CTX *mem_ctx, ATTRIB_MAP_ENTRY table[] )
{
	const char **names;
	int i = 0;

	while ( table[i].attrib != LDAP_ATTR_LIST_END )
		i++;
	i++;

	names = talloc_array( mem_ctx, const char*, i );
	if ( !names ) {
		DEBUG(0,("get_attr_list: out of memory\n"));
		return NULL;
	}

	i = 0;
	while ( table[i].attrib != LDAP_ATTR_LIST_END ) {
		names[i] = talloc_strdup( names, table[i].name );
		i++;
	}
	names[i] = NULL;

	return names;
}
