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
#include "lber.h"
#include "ldap.h"

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
BOOL ldap_check_machine(LDAP *ldap_struct, LDAPMessage *entry)
{
	BOOL sambaMachine=False;
	char **valeur;
	int i;
	
	DEBUG(2,("ldap_check_machine: "));
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
static void ldap_get_user(LDAP *ldap_struct,LDAPMessage *entry, 
                          struct smb_passwd *ldap_passwd)
{	
	static pstring user_name;
	static unsigned char ldappwd[16];
	static unsigned char smbntpwd[16];
	char **valeur;

	get_single_attribute(ldap_struct, entry, "cn", user_name);
		
	DEBUG(2,("ldap_get_user: user: %s\n",user_name));
		
	if ( (valeur=ldap_get_values(ldap_struct, entry, "uidAccount")) != NULL)
	{
		ldap_passwd->smb_userid=atoi(valeur[0]);
		ldap_value_free(valeur);
	}
			
	if ( (valeur=ldap_get_values(ldap_struct, entry, "userPassword")) != NULL) 
	{
		memset(smbntpwd, '\0', 16);
		E_md4hash((uchar *) valeur[0], smbntpwd);
  		valeur[0][14] = '\0';
  		strupper(valeur[0]);
 		memset(ldappwd, '\0', 16);
  		E_P16((uchar *) valeur[0], ldappwd);		
		ldap_value_free(valeur);		
	}
			
	if ( (valeur=ldap_get_values(ldap_struct,entry, "userAccountControl") ) != NULL)
	{
		ldap_passwd->acct_ctrl=atoi(valeur[0]);
		if (ldap_passwd->acct_ctrl & (ACB_DOMTRUST|ACB_WSTRUST|ACB_SVRTRUST) )
		{
		 	DEBUG(0,("Inconsistency in the LDAP database\n"));
				 
		}
		if (ldap_passwd->acct_ctrl & ACB_NORMAL)
		{
			ldap_passwd->smb_name=user_name;
			ldap_passwd->smb_passwd=ldappwd;
			ldap_passwd->smb_nt_passwd=smbntpwd;
		}
		ldap_value_free(valeur); 
	}
	
	if ( (valeur=ldap_get_values(ldap_struct,entry, "pwdLastSet")) != NULL)
	{	
		ldap_passwd->pass_last_set_time=(time_t)strtol(valeur[0], NULL, 16);
		ldap_value_free(valeur);
	}
}

/*******************************************************************
 retrieve the machine's info and contruct a smb_passwd structure.
******************************************************************/
static void ldap_get_machine(LDAP *ldap_struct,LDAPMessage *entry, 
                             struct smb_passwd *ldap_passwd)
{	
	static pstring  user_name;
	static unsigned char smbntpwd[16];
	char **valeur;
	
	/* by default it's a station */
	ldap_passwd->acct_ctrl = ACB_WSTRUST;

	get_single_attribute(ldap_struct, entry, "cn", user_name);
	DEBUG(2,("ldap_get_machine: machine: %s\n", user_name));
		
	if ( (valeur=ldap_get_values(ldap_struct, entry, "uidAccount")) != NULL)
	{
		ldap_passwd->smb_userid=atoi(valeur[0]);
		ldap_value_free(valeur);
	}
			
	if ( (valeur=ldap_get_values(ldap_struct, entry, "machinePassword")) != NULL) 
	{
		gethexpwd(valeur[0],smbntpwd);		
		ldap_value_free(valeur);		
	}
			
	if ( (valeur=ldap_get_values(ldap_struct,entry, "machineRole") ) != NULL)
	{
		if ( !strcmp(valeur[0],"workstation") )
			ldap_passwd->acct_ctrl=ACB_WSTRUST;
		else
		if  ( !strcmp(valeur[0],"server") )
			ldap_passwd->acct_ctrl=ACB_SVRTRUST;		
		ldap_value_free(valeur); 
	}

	ldap_passwd->smb_name=user_name;
	ldap_passwd->smb_passwd=smbntpwd;
	ldap_passwd->smb_nt_passwd=smbntpwd;
}

/*******************************************************************
 find a user or a machine return a smbpass struct.
******************************************************************/
static struct smb_passwd *get_ldappwd_entry(char *name, int smb_userid)
{
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	BOOL machine=False;

	static struct smb_passwd ldap_passwd;

	bzero(&ldap_passwd, sizeof(ldap_passwd));

	ldap_passwd.smb_name      = NULL;
	ldap_passwd.smb_passwd    = NULL;
	ldap_passwd.smb_nt_passwd = NULL;
	
	ldap_passwd.smb_userid         = -1;
	ldap_passwd.acct_ctrl          = ACB_DISABLED;
	ldap_passwd.pass_last_set_time = (time_t)-1;

	ldap_struct=NULL;

	if (name != NULL)
	{
		DEBUG(10, ("get_ldappwd_entry: search by name: %s\n", name));
	}
	else 
	{
		DEBUG(10, ("get_ldappwd_entry: search by smb_userid: %x\n", smb_userid));
	}

	if (!ldap_open_connection(&ldap_struct))
		return (NULL);
	if (!ldap_connect_system(ldap_struct))
		return (NULL);
		
	if (name != NULL)
	{
		if (!ldap_search_one_user_by_name(ldap_struct, name, &result))
			return (NULL);
	} 
	else
	{
		if (!ldap_search_one_user_by_uid(ldap_struct, smb_userid, &result))
			return (NULL);
	}
	
	if (ldap_count_entries(ldap_struct, result) == 0)
	{
		DEBUG(2,("%s: Non existant user!\n", timestring() ));
		return (NULL);	
	}
		
	if (ldap_count_entries(ldap_struct, result) > 1)
	{
		DEBUG(2,("%s: Strange %d users in the base!\n",
		         timestring(), ldap_count_entries(ldap_struct, result) ));
	}
	/* take the first and unique entry */
	entry=ldap_first_entry(ldap_struct, result);

	if (name != NULL)
	{
		DEBUG(0,("get_ldappwd_entry: Found user: %s\n",name));

		machine = name[strlen(name)-1] == '$';
	}
		
	if (!machine)
	{
		if (ldap_check_user(ldap_struct, entry))
			ldap_get_user(ldap_struct, entry, &ldap_passwd);
	}
	else
	{
		if (ldap_check_machine(ldap_struct, entry))
			ldap_get_machine(ldap_struct, entry, &ldap_passwd);
	}
				
	ldap_msgfree(result);
	result=NULL;
	ldap_unbind(ldap_struct);
		
	return(&ldap_passwd);
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

/************************************************************************
 Routine to search ldap passwd by name.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/

struct smb_passwd *getldappwnam(char *name)
{
  return get_ldappwd_entry(name, 0);
}

/************************************************************************
 Routine to search ldap passwd by uid.

 do not call this function directly.  use passdb.c instead.

*************************************************************************/

struct smb_passwd *getldappwuid(unsigned int uid)
{
	return get_ldappwd_entry(NULL, uid);
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
