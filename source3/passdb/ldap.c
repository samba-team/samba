/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau 1998
   
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

#ifdef USE_LDAP

#include "includes.h"

extern int DEBUGLEVEL;

/*******************************************************************
 open a connection to the ldap serve.
******************************************************************/	
BOOL ldap_open_connection(LDAP **ldap_struct)
{
	if ( (*ldap_struct = ldap_open(lp_ldap_server(),lp_ldap_port()) )== NULL)
	{
		DEBUG(0,("%s: The LDAP server is not responding !\n",timestring()));
		return(False);
	}
	DEBUG(2,("ldap_open_connection: connection opened\n"));
	return (True);
}


/*******************************************************************
 connect anonymously to the ldap server.
 FIXME: later (jfm)
******************************************************************/	
static BOOL ldap_connect_anonymous(LDAP *ldap_struct)
{
	if ( ldap_simple_bind_s(ldap_struct,lp_ldap_root(),lp_ldap_rootpasswd()) != LDAP_SUCCESS)
	{
		DEBUG(0,("%s: Couldn't bind to the LDAP server !\n", timestring() ));
		return(False);
	}
	return (True);
}


/*******************************************************************
 connect to the ldap server under system privileg.
******************************************************************/	
BOOL ldap_connect_system(LDAP *ldap_struct)
{
	if ( ldap_simple_bind_s(ldap_struct,lp_ldap_root(),lp_ldap_rootpasswd()) != LDAP_SUCCESS)
	{
		DEBUG(0,("%s: Couldn't bind to the LDAP server !\n", timestring() ));
		return(False);
	}
	DEBUG(2,("ldap_connect_system: succesfull connection to the LDAP server\n"));
	return (True);
}

/*******************************************************************
 connect to the ldap server under a particular user.
******************************************************************/	
static BOOL ldap_connect_user(LDAP *ldap_struct, char *user, char *password)
{
	if ( ldap_simple_bind_s(ldap_struct,lp_ldap_root(),lp_ldap_rootpasswd()) != LDAP_SUCCESS)
	{
		DEBUG(0,("%s: Couldn't bind to the LDAP server !\n", timestring() ));
		return(False);
	}
	DEBUG(2,("ldap_connect_user: succesfull connection to the LDAP server\n"));
	return (True);
}

/*******************************************************************
 run the search by name.
******************************************************************/	
static BOOL ldap_search_one_user(LDAP *ldap_struct, char *filter, LDAPMessage **result)
{	
	int scope = LDAP_SCOPE_ONELEVEL;
	int rc;
		
	DEBUG(2,("ldap_search_one_user: searching for:[%s]\n", filter));
		
	rc=ldap_search_s(ldap_struct, lp_ldap_suffix(), scope, filter, NULL, 0, result);

	if (rc != LDAP_SUCCESS )
	{
		DEBUG(0,("%s: Problem during the LDAP search\n",timestring()));
		return(False);
	}
	return (True);
}

/*******************************************************************
 run the search by name.
******************************************************************/	
BOOL ldap_search_one_user_by_name(LDAP *ldap_struct, char *user, LDAPMessage **result)
{	
	pstring filter;
	/*
	   in the filter expression, replace %u with the real name
	   so in ldap filter, %u MUST exist :-)
	*/	
	strcpy(filter,lp_ldap_filter());
	string_sub(filter,"%u",user);
	
	if ( !ldap_search_one_user(ldap_struct, filter, result) )
	{
		return(False);
	}
	return (True);
}

/*******************************************************************
 run the search by uid.
******************************************************************/	
BOOL ldap_search_one_user_by_uid(LDAP *ldap_struct, int uid, LDAPMessage **result)
{	
	pstring filter;
	/*
	   in the filter expression, replace %u with the real name
	   so in ldap filter, %u MUST exist :-)
	*/
	snprintf(filter, sizeof(pstring), "uidAccount=%d", uid);
	
	if ( !ldap_search_one_user(ldap_struct, filter, result) )
	{	
		return(False);
	}
	return (True);
}

/*******************************************************************
 search an attribute and return the first value found.
******************************************************************/
void get_single_attribute(LDAP *ldap_struct, LDAPMessage *entry, char *attribute, char *value)
{
	char **valeurs;
	
	if ( (valeurs=ldap_get_values(ldap_struct, entry, attribute)) != NULL) 
	{
		strcpy(value, valeurs[0]);
		ldap_value_free(valeurs);
		DEBUG(3,("get_single_attribute:	[%s]=[%s]\n", attribute, value));	
	}
	else
	{
		value=NULL;
	}
}

/*******************************************************************
 check if the returned entry is a sambaAccount objectclass.
******************************************************************/	
BOOL ldap_check_user(LDAP *ldap_struct, LDAPMessage *entry)
{
	BOOL sambaAccount=False;
	char **valeur;
	int i;

	DEBUG(2,("ldap_check_user: "));
	valeur=ldap_get_values(ldap_struct, entry, "objectclass");
	if (valeur!=NULL)
	{
		for (i=0;valeur[i]!=NULL;i++)
		{
			if (!strcmp(valeur[i],"sambaAccount")) sambaAccount=True;
		}
	}
	DEBUG(2,("%s\n",sambaAccount?"yes":"no"));
	ldap_value_free(valeur);
	return (sambaAccount);
}

/*******************************************************************
 check if the returned entry is a sambaMachine objectclass.
******************************************************************/	
BOOL ldap_check_trust(LDAP *ldap_struct, LDAPMessage *entry)
{
	BOOL sambaMachine=False;
	char **valeur;
	int i;
	
	DEBUG(2,("ldap_check_trust: "));
	valeur=ldap_get_values(ldap_struct, entry, "objectclass");
	if (valeur!=NULL)
	{
		for (i=0;valeur[i]!=NULL;i++)
		{
			if (!strcmp(valeur[i],"sambaMachine")) sambaMachine=True;
		}
	}	
	DEBUG(2,("%s\n",sambaMachine?"yes":"no"));
	ldap_value_free(valeur);	
	return (sambaMachine);
}

/*******************************************************************
 retrieve the user's info and contruct a smb_passwd structure.
******************************************************************/
static void ldap_get_sam_passwd(LDAP *ldap_struct, LDAPMessage *entry, 
                          struct sam_passwd *user)
{	
	static pstring user_name;
	static pstring fullname;
	static pstring home_dir;
	static pstring dir_drive;
	static pstring logon_script;
	static pstring profile_path;
	static pstring acct_desc;
	static pstring workstations;
	static pstring temp;
	
	bzero(user, sizeof(*user));

	user->logon_time            = (time_t)-1;
	user->logoff_time           = (time_t)-1;
	user->kickoff_time          = (time_t)-1;
	user->pass_last_set_time    = (time_t)-1;
	user->pass_can_change_time  = (time_t)-1;
	user->pass_must_change_time = (time_t)-1;

	get_single_attribute(ldap_struct, entry, "logonTime", temp);
	user->pass_last_set_time = (time_t)strtol(temp, NULL, 16);

	get_single_attribute(ldap_struct, entry, "logoffTime", temp);
	user->pass_last_set_time = (time_t)strtol(temp, NULL, 16);

	get_single_attribute(ldap_struct, entry, "kickoffTime", temp);
	user->pass_last_set_time = (time_t)strtol(temp, NULL, 16);

	get_single_attribute(ldap_struct, entry, "pwdLastSet", temp);
	user->pass_last_set_time = (time_t)strtol(temp, NULL, 16);

	get_single_attribute(ldap_struct, entry, "pwdCanChange", temp);
	user->pass_last_set_time = (time_t)strtol(temp, NULL, 16);

	get_single_attribute(ldap_struct, entry, "pwdMustChange", temp);
	user->pass_last_set_time = (time_t)strtol(temp, NULL, 16);

	get_single_attribute(ldap_struct, entry, "cn", user_name);
	user->smb_name = user_name;

	DEBUG(2,("ldap_get_sam_passwd: user: %s\n", user_name));
		
	get_single_attribute(ldap_struct, entry, "userFullName", fullname);
	user->full_name = fullname;

	get_single_attribute(ldap_struct, entry, "homeDirectory", home_dir);
	user->home_dir = home_dir;

	get_single_attribute(ldap_struct, entry, "homeDrive", dir_drive);
	user->dir_drive = dir_drive;

	get_single_attribute(ldap_struct, entry, "scriptPath", logon_script);
	user->logon_script = logon_script;

	get_single_attribute(ldap_struct, entry, "profilePath", profile_path);
	user->profile_path = profile_path;

	get_single_attribute(ldap_struct, entry, "comment", acct_desc);
	user->acct_desc = acct_desc;

	get_single_attribute(ldap_struct, entry, "userWorkstations", workstations);
	user->workstations = workstations;

	
	user->unknown_str = NULL; /* don't know, yet! */
	user->munged_dial = NULL; /* "munged" dial-back telephone number */

	get_single_attribute(ldap_struct, entry, "userPassword", temp);
	nt_lm_owf_gen(temp, user->smb_nt_passwd, user->smb_passwd);
	bzero(temp, sizeof(temp)); /* destroy local copy of the password */
			
	get_single_attribute(ldap_struct, entry, "rid", temp);
	user->user_rid=atoi(temp);

	get_single_attribute(ldap_struct, entry, "primaryGroupID", temp);
	user->group_rid=atoi(temp);

	/* the smb (unix) ids are not stored: they are created */
	user->smb_userid = user_rid_to_uid (user->user_rid);
	user->smb_grpid  = group_rid_to_uid(user->group_rid);

	get_single_attribute(ldap_struct, entry, "userAccountControl", temp);
	user->acct_ctrl=atoi(temp);

	user->unknown_3 = 0xffffff; /* don't know */
	user->logon_divs = 168; /* hours per week */
	user->hours_len = 21; /* 21 times 8 bits = 168 */
	memset(user->hours, 0xff, user->hours_len); /* available at all hours */
	user->unknown_5 = 0x00020000; /* don't know */
	user->unknown_5 = 0x000004ec; /* don't know */

	if (user->acct_ctrl & (ACB_DOMTRUST|ACB_WSTRUST|ACB_SVRTRUST) )
	{
		DEBUG(0,("Inconsistency in the LDAP database\n"));
	}

	if (!(user->acct_ctrl & ACB_NORMAL))
	{
		DEBUG(0,("User's acct_ctrl bits not set to ACT_NORMAL in LDAP database\n"));
		return;
	}

}

/*******************************************************************
 retrieve the user's info and contruct a smb_passwd structure.
******************************************************************/
static void ldap_get_smb_passwd(LDAP *ldap_struct,LDAPMessage *entry, 
                          struct smb_passwd *user)
{	
	static pstring user_name;
	static pstring user_pass;
	static pstring temp;
	static unsigned char smblmpwd[16];
	static unsigned char smbntpwd[16];

	user->smb_name = NULL;
	user->smb_passwd = NULL;
	user->smb_nt_passwd = NULL;
	user->smb_userid = 0;
	user->pass_last_set_time    = (time_t)-1;

	get_single_attribute(ldap_struct, entry, "cn", user_name);
	DEBUG(2,("ldap_get_smb_passwd: user: %s\n",user_name));
		
	get_single_attribute(ldap_struct, entry, "userPassword", user_pass);
	nt_lm_owf_gen(user_pass, smbntpwd, smblmpwd);
	bzero(user_pass, sizeof(user_pass)); /* destroy local copy of the password */
			
	get_single_attribute(ldap_struct, entry, "userAccountControl", temp);
	user->acct_ctrl=decode_acct_ctrl(temp);

	get_single_attribute(ldap_struct, entry, "pwdLastSet", temp);
	user->pass_last_set_time = (time_t)strtol(temp, NULL, 16);

	get_single_attribute(ldap_struct, entry, "rid", temp);

	/* the smb (unix) ids are not stored: they are created */
	user->smb_userid = user_rid_to_uid (atoi(temp));

	if (user->acct_ctrl & (ACB_DOMTRUST|ACB_WSTRUST|ACB_SVRTRUST) )
	{
		DEBUG(0,("Inconsistency in the LDAP database\n"));
			 
	}
	if (user->acct_ctrl & ACB_NORMAL)
	{
		user->smb_name      = user_name;
		user->smb_passwd    = smblmpwd;
		user->smb_nt_passwd = smbntpwd;
	}
}

/*******************************************************************
 retrieve the trust's info and contruct a smb_passwd structure.
******************************************************************/
static void ldap_get_trust(LDAP *ldap_struct,LDAPMessage *entry, 
                             struct smb_passwd *trust)
{	
	static pstring  user_name;
	static unsigned char smbntpwd[16];
	static pstring temp;
	
	get_single_attribute(ldap_struct, entry, "cn", user_name);
	DEBUG(2,("ldap_get_trust: trust: %s\n", user_name));
		
	get_single_attribute(ldap_struct, entry, "trustPassword", temp);
	gethexpwd(temp,smbntpwd);		
			
	get_single_attribute(ldap_struct, entry, "rid", temp);

	/* the smb (unix) ids are not stored: they are created */
	trust->smb_userid = user_rid_to_uid(atoi(temp));

	get_single_attribute(ldap_struct, entry, "trustAccountControl", temp);
	trust->acct_ctrl=decode_acct_ctrl(temp);

	if (trust->acct_ctrl == 0)
	{
		/* by default it's a workstation (or stand-alone server) */
		trust->acct_ctrl = ACB_WSTRUST;
	}

	trust->smb_name      = user_name;
	trust->smb_passwd    = NULL;
	trust->smb_nt_passwd = smbntpwd;
}

/************************************************************************
 Routine to add an entry to the ldap passwd file.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
BOOL add_ldappwd_entry(struct smb_passwd *newpwd)
{
  return True;
}

/************************************************************************
 Routine to search the ldap passwd file for an entry matching the username.
 and then modify its password entry. We can't use the startldappwent()/
 getldappwent()/endldappwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out password or NO PASS

 do not call this function directly.  use passdb.c instead.

************************************************************************/
BOOL mod_ldappwd_entry(struct smb_passwd* pwd, BOOL override)
{
    return False;
}

/***************************************************************
 Start to enumerate the ldap passwd list. Returns a void pointer
 to ensure no modification outside this module.

 do not call this function directly.  use passdb.c instead.

 ****************************************************************/

struct ldap_enum_info
{
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
};

static struct ldap_enum_info ldap_ent;

void *startldappwent(BOOL update)
{
	int scope = LDAP_SCOPE_ONELEVEL;
	int rc;

	char filter[256];

	if (!ldap_open_connection(&ldap_ent.ldap_struct)) /* open a connection to the server */
		return NULL;

	if (!ldap_connect_system(ldap_ent.ldap_struct)) /* connect as system account */
		return NULL;

	/* when the class is known the search is much faster */
	switch (0)
	{
		case 1:
		{
			strcpy(filter, "objectclass=sambaAccount");
			break;
		}
		case 2:
		{
			strcpy(filter, "objectclass=sambaMachine");
			break;
		}
		default:
		{
			strcpy(filter, "(|(objectclass=sambaMachine)(objectclass=sambaAccount))");
			break;
		}
	}

	rc=ldap_search_s(ldap_ent.ldap_struct, lp_ldap_suffix(), scope, filter, NULL, 0, &ldap_ent.result);

	DEBUG(2,("%d entries in the base!\n", ldap_count_entries(ldap_ent.ldap_struct, ldap_ent.result) ));

  	ldap_ent.entry = ldap_first_entry(ldap_ent.ldap_struct, ldap_ent.result);

	return &ldap_ent;
}

/*************************************************************************
 Routine to return the next entry in the ldap passwd list.

 do not call this function directly.  use passdb.c instead.

 *************************************************************************/
struct smb_passwd *getldappwent(void *vp)
{

	struct ldap_enum_info *ldap_vp = (struct ldap_enum_info *)vp;
	ldap_vp->entry = ldap_next_entry(ldap_vp->ldap_struct, ldap_vp->entry);
/*
	make_ldap_sam_user_info_21(ldap_struct, entry, &(pw_buf[(*num_entries)]) );
*/
	return NULL;
}

/***************************************************************
 End enumeration of the ldap passwd list.

 do not call this function directly.  use passdb.c instead.

****************************************************************/
void endldappwent(void *vp)
{
	struct ldap_enum_info *ldap_vp = (struct ldap_enum_info *)vp;
	ldap_msgfree(ldap_vp->result);
	ldap_unbind(ldap_vp->ldap_struct);
}

/*************************************************************************
 Return the current position in the ldap passwd list as an unsigned long.
 This must be treated as an opaque token.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
unsigned long getldappwpos(void *vp)
{
	return 0;
}

/*************************************************************************
 Set the current position in the ldap passwd list from unsigned long.
 This must be treated as an opaque token.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/
BOOL setldappwpos(void *vp, unsigned long tok)
{
	return False;
}

#endif
