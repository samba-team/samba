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
 find a user or a machine return a smbpass struct.
******************************************************************/
struct passwd *Get_ldap_Pwnam(char *user)
{
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	char **valeur;
	BOOL machine=False;
	BOOL sambaAccount=False;
	int i;
	
	static struct passwd ldap_passwd;
	static char pw_name[256];
	static char pw_passwd[256];
	static char pw_gecos[256];
	static char pw_dir[256];
	static char pw_shell[256];
	ldap_passwd.pw_name=pw_name;
	ldap_passwd.pw_passwd=pw_passwd;
	ldap_passwd.pw_gecos=pw_gecos;
	ldap_passwd.pw_dir=pw_dir;
	ldap_passwd.pw_shell=pw_shell;
	
	DEBUG(0,("XXXX XXXX XXXX, ca merde serieux!\n"));

	/* first clear the struct */
	bzero(pw_name,sizeof(pw_name));
	bzero(pw_passwd,sizeof(pw_passwd));
	bzero(pw_gecos,sizeof(pw_gecos));
	bzero(pw_dir,sizeof(pw_dir));
	bzero(pw_shell,sizeof(pw_shell));	
	ldap_passwd.pw_uid=-1;
	ldap_passwd.pw_gid=-1;

	
	ldap_open_connection(&ldap_struct);
	
	/* 
	   to get all the attributes (specially the userPassword )
	   we have to connect under the system administrator account
	*/
	ldap_connect_system(ldap_struct);
	
	ldap_search_one_user(ldap_struct, user, &result);

	if (ldap_count_entries(ldap_struct, result) != 1)
	{
		DEBUG(0,("%s: Strange %d user in the base!\n",
		         timestring(), ldap_count_entries(ldap_struct, result) ));
		return(False);	
	}
	/* take the first and unique entry */
	entry=ldap_first_entry(ldap_struct, result);

	/* check what kind of account it is */
	/* as jeremy doesn't want to split getpwnam in 2 functions :-( */

	if (user[strlen(user)-1]=='$')
	{
		machine=True;
	}

	if (!machine)
	{
		valeur=ldap_get_values(ldap_struct,entry, "objectclass");

		/* check if the entry is a person objectclass*/
		if (valeur!=NULL)
		for (i=0;valeur[i]!=NULL;i++)
		{
			if (!strcmp(valeur[i],"sambaAccount")) sambaAccount=True;
		}
		ldap_value_free(valeur);
				
		if (sambaAccount)
		{
		/* we should have enough info to fill the struct */
			strncpy(ldap_passwd.pw_name,user,strlen(user));

			valeur=ldap_get_values(ldap_struct,entry, "uidAccount");
			if (valeur != NULL)
			{
				ldap_passwd.pw_uid=atoi(valeur[0]);
			}
			ldap_value_free(valeur);
			
			valeur=ldap_get_values(ldap_struct,entry, "gidAccount");
			if (valeur != NULL)
			{
				ldap_passwd.pw_gid=atoi(valeur[0]);
			}
			ldap_value_free(valeur);

			valeur=ldap_get_values(ldap_struct,entry, "userPassword");
			if (valeur != NULL) 
			{
			/*
			 as we have the clear-text password, we have to crypt it !
			 hum hum hum currently pass the clear text password to wait
			*/
			strncpy(ldap_passwd.pw_passwd,valeur[0],strlen(valeur[0]));
			}
			ldap_value_free(valeur);
			
			valeur=ldap_get_values(ldap_struct,entry, "gecos");
			if (valeur != NULL) 
			{
				strncpy(ldap_passwd.pw_gecos,valeur[0],strlen(valeur[0]));
			}
			ldap_value_free(valeur);
			
			valeur=ldap_get_values(ldap_struct,entry, "homeDirectory");
			if (valeur != NULL) 
			{
				strncpy(ldap_passwd.pw_dir,valeur[0],strlen(valeur[0]));
			}
			ldap_value_free(valeur);

			valeur=ldap_get_values(ldap_struct,entry, "loginShell");
			if (valeur != NULL) 
			{
				strncpy(ldap_passwd.pw_shell,valeur[0],strlen(valeur[0]));
			}
			ldap_value_free(valeur);		
		}
	}
	else
	{
	}

	ldap_unbind(ldap_struct);	
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
	static unsigned char smbpwd[16];
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
 		memset(smbpwd, '\0', 16);
  		E_P16((uchar *) valeur[0], smbpwd);		
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
			ldap_passwd->smb_passwd=smbpwd;
			ldap_passwd->smb_nt_passwd=smbntpwd;
		}
		ldap_value_free(valeur); 
	}
	
	if ( (valeur=ldap_get_values(ldap_struct,entry, "pwdLastSet")) != NULL)
	{	
		ldap_passwd->last_change_time=(time_t)strtol(valeur[0], NULL, 16);
		ldap_value_free(valeur);
	}
}

/*************************************************************
 Routine to get the next 32 hex characters and turn them
 into a 16 byte array.
**************************************************************/

static int gethexpwd(char *p, char *pwd)
{
  int i;
  unsigned char   lonybble, hinybble;
  char           *hexchars = "0123456789ABCDEF";
  char           *p1, *p2;

  for (i = 0; i < 32; i += 2) {
    hinybble = toupper(p[i]);
    lonybble = toupper(p[i + 1]);
 
    p1 = strchr(hexchars, hinybble);
    p2 = strchr(hexchars, lonybble);
    if (!p1 || !p2)
      return (False);
    hinybble = PTR_DIFF(p1, hexchars);
    lonybble = PTR_DIFF(p2, hexchars);
 
    pwd[i / 2] = (hinybble << 4) | lonybble;
  }
  return (True);
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
static struct smb_passwd *ldap_get_smbpwd_entry(char *name, int smb_userid)
{
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	BOOL machine=False;

	static struct smb_passwd ldap_passwd;

	ldap_passwd.smb_name      = NULL;
	ldap_passwd.smb_passwd    = NULL;
	ldap_passwd.smb_nt_passwd = NULL;
	
	ldap_passwd.smb_userid       = -1;
	ldap_passwd.acct_ctrl        = ACB_DISABLED;
	ldap_passwd.last_change_time = 0;

	ldap_struct=NULL;

	if (name != NULL)
	{
		DEBUG(10, ("ldap_get_smbpwd_entry: search by name: %s\n", name));
	}
	else 
	{
		DEBUG(10, ("ldap_get_smbpwd_entry: search by smb_userid: %x\n", smb_userid));
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
		DEBUG(0,("ldap_get_smbpwd_entry: Found user: %s\n",name));

		if (name[strlen(name)-1]=='$')
			machine=True;
		else 
			machine=False;
	}
		
	if (machine==False)
	{
		if (ldap_check_user(ldap_struct, entry)==True)
			ldap_get_user(ldap_struct, entry, &ldap_passwd);
	}
	else
	{
		if (ldap_check_machine(ldap_struct, entry)==True)
			ldap_get_machine(ldap_struct, entry, &ldap_passwd);
	}
				
	ldap_msgfree(result);
	result=NULL;
	ldap_unbind(ldap_struct);
		
	return(&ldap_passwd);
}

/************************************************************************
 Routine to search ldap passwd by name.
*************************************************************************/

struct smb_passwd *getldappwnam(char *name)
{
  return ldap_get_smbpwd_entry(name, 0);
}

/************************************************************************
 Routine to search ldap passwd by uid.
*************************************************************************/

struct smb_passwd *getldappwuid(unsigned int uid)
{
  return ldap_get_smbpwd_entry(NULL, uid);
}


#endif
