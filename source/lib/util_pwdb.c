/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Jeremy Allison 1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
      
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
#include "nterr.h"

extern int DEBUGLEVEL;
extern DOM_SID global_sam_sid;
extern fstring global_sam_name;

extern DOM_SID global_member_sid;
extern fstring global_myworkgroup;

extern DOM_SID global_sid_S_1_5_20;

extern pstring global_myname;

typedef struct
{
	uint32 rid;
	char *defaultname;
	char *name;
} rid_name;

/*
 * A list of the rids of well known BUILTIN and Domain users
 * and groups.
 */

static rid_name builtin_alias_rids[] =
{  
    { BUILTIN_ALIAS_RID_ADMINS       , "Administrators"    , NULL },
    { BUILTIN_ALIAS_RID_USERS        , "Users"             , NULL },
    { BUILTIN_ALIAS_RID_GUESTS       , "Guests"            , NULL },
    { BUILTIN_ALIAS_RID_POWER_USERS  , "Power Users"       , NULL },
   
    { BUILTIN_ALIAS_RID_ACCOUNT_OPS  , "Account Operators" , NULL },
    { BUILTIN_ALIAS_RID_SYSTEM_OPS   , "System Operators"  , NULL },
    { BUILTIN_ALIAS_RID_PRINT_OPS    , "Print Operators"   , NULL },
    { BUILTIN_ALIAS_RID_BACKUP_OPS   , "Backup Operators"  , NULL },
    { BUILTIN_ALIAS_RID_REPLICATOR   , "Replicator"        , NULL },
    { 0                              , NULL                , NULL}
};

/* array lookup of well-known Domain RID users. */
static rid_name domain_user_rids[] =
{  
    { DOMAIN_USER_RID_ADMIN         , "Administrator" , NULL },
    { DOMAIN_USER_RID_GUEST         , "Guest"         , NULL },
    { 0                             , NULL            , NULL}
};

/* array lookup of well-known Domain RID groups. */
static rid_name domain_group_rids[] =
{  
    { DOMAIN_GROUP_RID_ADMINS       , "Domain Admins" , NULL },
    { DOMAIN_GROUP_RID_USERS        , "Domain Users"  , NULL },
    { DOMAIN_GROUP_RID_GUESTS       , "Domain Guests" , NULL },
    { 0                             , NULL            , NULL}
};

/*******************************************************************
  make an entry in wk name map
  the name is strdup()ed!
 *******************************************************************/
static BOOL make_alias_entry(rid_name *map, char *defaultname, char *name)
{
	if(isdigit(*defaultname))
	{
		long rid = -1;
		char *s;

		if(*defaultname == '0')
		{
			if(defaultname[1] == 'x')
			{
				s = "%lx";
				defaultname += 2;
			}
			else
			{
				s = "%lo";
			}
		}
		else
		{
			s = "%ld";
		}

		sscanf(defaultname, s, &rid);

		for( ; map->rid; map++)
		{
			if(map->rid == rid) {
				map->name = strdup(name);
				DEBUG(5, ("make_alias_entry: mapping %s (rid 0x%x) to %s\n",
				      map->defaultname, map->rid, map->name));
				return True;
			}
		}
		return False;
	}

	for( ; map->rid; map++)
	{
		if(!StrCaseCmp(map->name, defaultname)) {
			map->name = strdup(name);
			DEBUG(5, ("make_alias_entry: mapping %s (rid 0x%x) to %s\n",
			      map->defaultname, map->rid, map->name));
			return True;
		}
	}
	return False;
}

/*******************************************************************
  reset wk map to default values
 *******************************************************************/
static void reset_wk_map(rid_name *map)
{
	for( ; map->rid; map++)
	{
		if(map->name != NULL && map->name != map->defaultname)
			free(map->name);
		map->name = map->defaultname;
	}
}

/*******************************************************************
  reset all wk maps
 *******************************************************************/
static void reset_wk_maps(void)
{
	DEBUG(4, ("reset_wk_maps: Initializing maps\n"));
	reset_wk_map(builtin_alias_rids);
	reset_wk_map(domain_user_rids);
	reset_wk_map(domain_group_rids);
}

/*******************************************************************
  Load builtin alias map
 *******************************************************************/
static BOOL load_wk_rid_map(void)
{
	static int map_initialized = 0;
	static time_t builtin_rid_file_last_modified = (time_t)0;
	char *builtin_rid_file = lp_builtinrid_file();

	FILE *fp;
	char *s;
	pstring buf;

	if (!map_initialized)
	{
		reset_wk_maps();
		map_initialized = 1;
	}

	if (!*builtin_rid_file)
	{
		return False;
	}

	fp = open_file_if_modified(builtin_rid_file, "r", &builtin_rid_file_last_modified);
	if(!fp)
	{
		DEBUG(0,("load_wk_rid_map: can't open name map %s. Error was %s\n",
			  builtin_rid_file, strerror(errno)));
		 return False;
	}

	reset_wk_maps();
	DEBUG(4,("load_wk_rid_map: Scanning builtin rid map %s\n",builtin_rid_file));

	while ((s = fgets_slash(buf, sizeof(buf), fp)) != NULL)
	{
		pstring defaultname;
		pstring name;

		DEBUG(10,("Read line |%s|\n", s));

		if (!*s || strchr("#;",*s))
			continue;

		if (!next_token(&s,name, "\t\n\r=", sizeof(defaultname)))
			continue;

		if (!next_token(&s,defaultname, "\t\n\r=", sizeof(name)))
			continue;

		trim_string(defaultname, " ", " ");
		trim_string(name, " ", " ");

		if (!*defaultname || !*name)
			continue;

		if(make_alias_entry(builtin_alias_rids, defaultname, name))
			continue;
		if(make_alias_entry(domain_user_rids, defaultname, name))
			continue;
		if(make_alias_entry(domain_group_rids, defaultname, name))
			continue;

		DEBUG(0,("load_wk_rid_map: Unknown alias %s in map %s\n",
		         defaultname, builtin_rid_file));
	}

	fclose(fp);
	return True;
}

/*******************************************************************
 lookup_wk_group_name
 ********************************************************************/
uint32 lookup_wk_group_name(const char *group_name, const char *domain,
				DOM_SID *sid, uint8 *type)
{
	char *grp_name;
	int i = -1; /* start do loop at -1 */
	uint32 rid;
	(*type) = SID_NAME_DOM_GRP;

	if (strequal(domain, global_sam_name))
	{
		sid_copy(sid, &global_sam_sid);
	}
	else if (strequal(domain, "BUILTIN"))
	{
		sid_copy(sid, &global_sid_S_1_5_20);
	}
	else
	{
		return 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}

	load_wk_rid_map();

	do /* find, if it exists, a group rid for the group name */
	{
		i++;
		rid      = domain_group_rids[i].rid;
		grp_name = domain_group_rids[i].name;

		if (strequal(grp_name, group_name))
		{
			sid_append_rid(sid, rid);

			return 0x0;
		}
			
	} while (grp_name != NULL);

	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_wk_user_name
 ********************************************************************/
uint32 lookup_wk_user_name(const char *user_name, const char *domain,
				DOM_SID *sid, uint8 *type)
{
	char *usr_name;
	int i = -1; /* start do loop at -1 */
	(*type) = SID_NAME_USER;

	if (strequal(domain, global_sam_name))
	{
		sid_copy(sid, &global_sam_sid);
	}
	else if (strequal(domain, "BUILTIN"))
	{
		sid_copy(sid, &global_sid_S_1_5_20);
	}
	else
	{
		return 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}

	load_wk_rid_map();

	do /* find, if it exists, a alias rid for the alias name */
	{
		i++;
		usr_name = domain_user_rids[i].name;

	} while (usr_name != NULL && !strequal(usr_name, user_name));

	if (usr_name != NULL)
	{
		sid_append_rid(sid, domain_user_rids[i].rid);
		return 0;
	}

	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_builtin_alias_name
 ********************************************************************/
uint32 lookup_builtin_alias_name(const char *alias_name, const char *domain,
				DOM_SID *sid, uint8 *type)
{
	char *als_name;
	int i = 0;
	uint32 rid;

	if (strequal(domain, "BUILTIN"))
	{
		if (sid != NULL)
		{
			sid_copy(sid, &global_sid_S_1_5_20);
		}
	}
	else
	{
		return 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}

	load_wk_rid_map();

	do /* find, if it exists, a alias rid for the alias name*/
	{
		rid      = builtin_alias_rids[i].rid;
		als_name = builtin_alias_rids[i].name;

		if (strequal(als_name, alias_name))
		{
			if (sid != NULL)
			{
				sid_append_rid(sid, rid);
			}

			if (type != NULL)
			{
				(*type) = SID_NAME_ALIAS;
			}

			return 0x0;
		}
			
		i++;

	} while (als_name != NULL);

	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}
/**********************************************************
 Encode the account control bits into a string.
 length = length of string to encode into (including terminating
 null). length *MUST BE MORE THAN 2* !
 **********************************************************/

char *pwdb_encode_acct_ctrl(uint16 acct_ctrl, size_t length)
{
	static fstring acct_str;
	size_t i = 0;

	acct_str[i++] = '[';

	if (acct_ctrl & ACB_PWNOTREQ ) acct_str[i++] = 'N';
	if (acct_ctrl & ACB_DISABLED ) acct_str[i++] = 'D';
	if (acct_ctrl & ACB_HOMDIRREQ) acct_str[i++] = 'H';
	if (acct_ctrl & ACB_TEMPDUP  ) acct_str[i++] = 'T'; 
	if (acct_ctrl & ACB_NORMAL   ) acct_str[i++] = 'U';
	if (acct_ctrl & ACB_MNS      ) acct_str[i++] = 'M';
	if (acct_ctrl & ACB_WSTRUST  ) acct_str[i++] = 'W';
	if (acct_ctrl & ACB_SVRTRUST ) acct_str[i++] = 'S';
	if (acct_ctrl & ACB_AUTOLOCK ) acct_str[i++] = 'L';
	if (acct_ctrl & ACB_PWNOEXP  ) acct_str[i++] = 'X';
	if (acct_ctrl & ACB_DOMTRUST ) acct_str[i++] = 'I';
	if (acct_ctrl & ACB_PWLOCK   ) acct_str[i++] = 'P';

	for ( ; i < length - 2 ; i++ )
	{
		acct_str[i] = ' ';
	}

	i = length - 2;
	acct_str[i++] = ']';
	acct_str[i++] = '\0';

	return acct_str;
}     

/**********************************************************
 Decode the account control bits from a string.

 this function breaks coding standards minimum line width of 80 chars.
 reason: vertical line-up code clarity - all case statements fit into
 15 lines, which is more important.
 **********************************************************/

uint16 pwdb_decode_acct_ctrl(const char *p)
{
	uint16 acct_ctrl = 0;
	BOOL finished = False;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[') return 0;

	for (p++; *p && !finished; p++)
	{
		switch (*p)
		{
			case 'N': { acct_ctrl |= ACB_PWNOTREQ ; break; /* 'N'o password. */ }
			case 'D': { acct_ctrl |= ACB_DISABLED ; break; /* 'D'isabled. */ }
			case 'H': { acct_ctrl |= ACB_HOMDIRREQ; break; /* 'H'omedir required. */ }
			case 'T': { acct_ctrl |= ACB_TEMPDUP  ; break; /* 'T'emp account. */ } 
			case 'U': { acct_ctrl |= ACB_NORMAL   ; break; /* 'U'ser account (normal). */ } 
			case 'M': { acct_ctrl |= ACB_MNS      ; break; /* 'M'NS logon user account. What is this ? */ } 
			case 'W': { acct_ctrl |= ACB_WSTRUST  ; break; /* 'W'orkstation account. */ } 
			case 'S': { acct_ctrl |= ACB_SVRTRUST ; break; /* 'S'erver account. */ } 
			case 'L': { acct_ctrl |= ACB_AUTOLOCK ; break; /* 'L'ocked account. */ } 
			case 'X': { acct_ctrl |= ACB_PWNOEXP  ; break; /* No 'X'piry on password */ } 
			case 'I': { acct_ctrl |= ACB_DOMTRUST ; break; /* 'I'nterdomain trust account. */ }
			case 'P': { acct_ctrl |= ACB_PWLOCK   ; break; /* 'P'assword cannot be changed remotely */ } 
			case ' ': { break; }
			case ':':
			case '\n':
			case '\0': 
			case ']':
			default:  { finished = True; }
		}
	}

	return acct_ctrl;
}

/*******************************************************************
 gets password-database-format time from a string.
 ********************************************************************/

static time_t get_time_from_string(const char *p)
{
	int i;

	for (i = 0; i < 8; i++)
	{
		if (p[i] == '\0' || !isxdigit((int)(p[i]&0xFF)))
		{
			break;
		}
	}
	if (i == 8)
	{
		/*
		 * p points at 8 characters of hex digits - 
		 * read into a time_t as the seconds since
		 * 1970 that the password was last changed.
		 */
		return (time_t)strtol(p, NULL, 16);
	}
	return (time_t)-1;
}

/*******************************************************************
 gets password last set time
 ********************************************************************/

time_t pwdb_get_last_set_time(const char *p)
{
	if (*p && !StrnCaseCmp(p, "LCT-", 4))
	{
		return get_time_from_string(p + 4);
	}
	return (time_t)-1;
}


/*******************************************************************
 sets password-database-format time in a string.
 ********************************************************************/
static void set_time_in_string(char *p, int max_len, char *type, time_t t)
{
	slprintf(p, max_len, ":%s-%08X:", type, (uint32)t);
}

/*******************************************************************
 sets logon time
 ********************************************************************/
void pwdb_set_logon_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "LNT", t);
}

/*******************************************************************
 sets logoff time
 ********************************************************************/
void pwdb_set_logoff_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "LOT", t);
}

/*******************************************************************
 sets kickoff time
 ********************************************************************/
void pwdb_set_kickoff_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "KOT", t);
}

/*******************************************************************
 sets password can change time
 ********************************************************************/
void pwdb_set_can_change_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "CCT", t);
}

/*******************************************************************
 sets password last set time
 ********************************************************************/
void pwdb_set_must_change_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "MCT", t);
}

/*******************************************************************
 sets password last set time
 ********************************************************************/
void pwdb_set_last_set_time(char *p, int max_len, time_t t)
{
	set_time_in_string(p, max_len, "LCT", t);
}


/*************************************************************
 Routine to set 32 hex password characters from a 16 byte array.
**************************************************************/
void pwdb_sethexpwd(char *p, const char *pwd, uint16 acct_ctrl)
{
	if (pwd != NULL)
	{
		int i;
		for (i = 0; i < 16; i++)
		{
			slprintf(&p[i*2], 33, "%02X", pwd[i]);
		}
	}
	else
	{
		if (IS_BITS_SET_ALL(acct_ctrl, ACB_PWNOTREQ))
		{
			safe_strcpy(p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", 33);
		}
		else
		{
			safe_strcpy(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 33);
		}
	}
}

/*************************************************************
 Routine to get the 32 hex characters and turn them
 into a 16 byte array.
**************************************************************/
BOOL pwdb_gethexpwd(const char *p, char *pwd, uint32 *acct_ctrl)
{
	if (strnequal(p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", 32))
	{
		if (acct_ctrl != NULL)
		{
			*acct_ctrl |= ACB_PWNOTREQ;
		}
		pwd[0] = 0;
		return True;
	}
	else if (strnequal(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32))
	{
		pwd[0] = 0;
		return True;
	}
	else
	{
		return strhex_to_str(pwd, 32, p) == 16;
	}
}


/*************************************************************
 initialise password databases, domain names, domain sid.
**************************************************************/
BOOL pwdb_initialise(BOOL is_server)
{
	get_sam_domain_name();

	if (!init_myworkgroup())
	{
		return False;
	}

	generate_wellknown_sids();

	if (is_server)
	{
		if (!generate_sam_sid(global_sam_name, &global_sam_sid))
		{
			DEBUG(0,("ERROR: Samba cannot create a SAM SID for its domain (%s).\n",
				  global_sam_name));
			return False;
		}
	}
	else
	{
		if (!get_domain_sids(lp_workgroup(), &global_member_sid,
		                      &global_sam_sid))
		{
			return False;
		}
	}

	create_sidmap_table();

	return initialise_password_db();
}

/*************************************************************
 the following functions lookup wk rid's.
 these may be unnecessary...
**************************************************************/
static char *lookup_wk_rid(uint32 rid, rid_name *table)
{
	load_wk_rid_map();
	for( ; table->rid ; table++)
	{
		if(table->rid == rid)
		{
			return table->name;
		}
	}
	return NULL;
}

char *lookup_wk_alias_rid(uint32 rid)
{
	return lookup_wk_rid(rid, builtin_alias_rids);
}

char *lookup_wk_user_rid(uint32 rid)
{
	return lookup_wk_rid(rid, domain_user_rids);
}

char *lookup_wk_group_rid(uint32 rid)
{
	return lookup_wk_rid(rid, domain_group_rids);
}

