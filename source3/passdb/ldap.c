/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau 1998
   Copyright (C) Matthew Chapman 1998
   
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

#ifdef WITH_LDAP

#include <lber.h>
#include <ldap.h>

extern int DEBUGLEVEL;

/* Internal state */
LDAP *ldap_struct;
LDAPMessage *ldap_results;
LDAPMessage *ldap_entry;

/* LDAP password */
static pstring ldap_secret;


/*******************************************************************
  Open connections to the LDAP server.
 ******************************************************************/	

BOOL ldap_connect(void)
{
	int err;

	if (!(ldap_struct = ldap_open(lp_ldap_server(), lp_ldap_port()))) {
		DEBUG(0, ("open: %s\n", strerror(errno)));
		return (False);
	}

	err = ldap_simple_bind_s(ldap_struct, lp_ldap_bind_as(), ldap_secret);
	if (err != LDAP_SUCCESS) {
		DEBUG(0, ("bind: %s\n", ldap_err2string(err)));
		return (False);
	}

	DEBUG(2,("Connected to LDAP server\n"));
	return (True);
}

/*******************************************************************
  close connections to the LDAP server.
 ******************************************************************/	

void ldap_disconnect(void)
{
	if(!ldap_struct)
		return;

	if(ldap_results) {
		ldap_msgfree(ldap_results);
		ldap_results = NULL; }

	ldap_unbind(ldap_struct);
	ldap_struct = NULL;
	
	DEBUG(2,("Connection closed\n"));
}


/*******************************************************************
  Search the directory using a given filter.
 ******************************************************************/	

BOOL ldap_search_for(char *filter)
{
	int err;

	DEBUG(2,("Searching in [%s] for [%s]\n", lp_ldap_suffix(), filter));

	err = ldap_search_s(ldap_struct, lp_ldap_suffix(), LDAP_SCOPE_ONELEVEL,
			  filter, NULL, 0, &ldap_results);

	if(err != LDAP_SUCCESS) {
		DEBUG(0, ("search: %s\n", ldap_err2string(err)));
	}

	DEBUG(2, ("%d matching entries found\n",
		  ldap_count_entries(ldap_struct, ldap_results)));

	ldap_entry = ldap_first_entry(ldap_struct, ldap_results);
	return (True);
}

BOOL ldap_search_by_name(const char *user)
{
	fstring filter;

	slprintf(filter, sizeof(filter)-1,
		 "(&(uid=%s)(objectclass=sambaAccount))", user);
	return ldap_search_for(filter);
}

BOOL ldap_search_by_uid(int uid)
{
	fstring filter;
	
	slprintf(filter, sizeof(filter)-1, 
		 "(&(uidNumber=%d)(objectclass=sambaAccount))", uid);
	return ldap_search_for(filter);
}


/*******************************************************************
  Get the first value of an attribute.
 ******************************************************************/

BOOL ldap_get_attribute(char *attribute, char *value)
{
	char **values;
	
	if(!(values = ldap_get_values(ldap_struct, ldap_entry, attribute)))
		return (False);

	pstrcpy(value, values[0]);
	ldap_value_free(values);
	DEBUG(3, ("get: [%s] = [%s]\n", attribute, value));
	
	return (True);
}


/*******************************************************************
  Construct an smb_passwd structure
 ******************************************************************/
struct smb_passwd *ldap_getpw(void)
{
	static struct smb_passwd smbpw;
	static pstring unix_name;
	static pstring nt_name;
	static unsigned char smblmpwd[16];
	static unsigned char smbntpwd[16];
	pstring temp;

	if(!ldap_entry)
		return NULL;

	if(!ldap_get_attribute("uid", unix_name)) {
		DEBUG(0,("Missing uid\n"));
		return NULL; }
	smbpw.unix_name = unix_name;

	DEBUG(2,("Retrieving account [%s]\n",unix_name));

	if(!ldap_get_attribute("uidNumber", temp)) {
		DEBUG(0,("Missing uidNumber\n"));
		return NULL; }
	smbpw.unix_uid = atoi(temp);

        if(!ldap_get_attribute("ntuid", nt_name)) {
		DEBUG(0,("Missing ntuid\n"));
		return NULL; }
	smbpw.nt_name = nt_name;

	if(!ldap_get_attribute("rid", temp)) {
		DEBUG(0,("Missing rid\n"));
		return NULL; }
	smbpw.user_rid = strtol(temp, NULL, 16);

	if(ldap_get_attribute("acctFlags", temp))
		smbpw.acct_ctrl = pwdb_decode_acct_ctrl(temp);
	else
		smbpw.acct_ctrl = ACB_NORMAL;

	if(ldap_get_attribute("lmPassword", temp)) {
		pwdb_gethexpwd(temp, smblmpwd);
		smbpw.smb_passwd = smblmpwd;
	} else {
		smbpw.smb_passwd = NULL;
		smbpw.acct_ctrl |= ACB_DISABLED;
	}

	if(ldap_get_attribute("ntPassword", temp)) {
		pwdb_gethexpwd(temp, smbntpwd);
		smbpw.smb_nt_passwd = smbntpwd;
	} else {
		smbpw.smb_nt_passwd = NULL;
	}

	if(ldap_get_attribute("pwdLastSet", temp))
		smbpw.pass_last_set_time = (time_t)strtol(temp, NULL, 16);
	else
		smbpw.pass_last_set_time = (time_t)(-1);

	return &smbpw;
}


/************************************************************************
  Adds a modification to a LDAPMod queue.
 ************************************************************************/

 void ldap_make_mod(LDAPMod ***modlist,int modop, char *attribute, char *value)
{
	LDAPMod **mods;
	int i;
	int j;

	DEBUG(3, ("set: [%s] = [%s]\n", attribute, value));
	
	mods = *modlist;
	
	if (mods == NULL) {
		mods = (LDAPMod **)malloc(sizeof(LDAPMod *));
		mods[0] = NULL;
	}
	
	for (i = 0; mods[i] != NULL; ++i) {
		if (mods[i]->mod_op == modop && 
		    !strcasecmp(mods[i]->mod_type, attribute)) {
			break;
		}
	}
	
	if (mods[i] == NULL) {
		mods = (LDAPMod **)realloc(mods, (i+2) * sizeof(LDAPMod *));
		mods[i] = (LDAPMod *)malloc(sizeof(LDAPMod));
		mods[i]->mod_op = modop;
		mods[i]->mod_values = NULL;
		mods[i]->mod_type = strdup(attribute);
		mods[i+1] = NULL;
	}

	if (value) {
		j = 0;
		if (mods[i]->mod_values) {
			for (; mods[i]->mod_values[j]; j++);
		}
		mods[i]->mod_values = (char **)realloc(mods[i]->mod_values,
						  (j+2) * sizeof(char *));
		mods[i]->mod_values[j] = strdup(value);
		mods[i]->mod_values[j+1] = NULL;
	}

	*modlist = mods;
}


/************************************************************************
  Queues the necessary modifications to save a smb_passwd structure
 ************************************************************************/

 void ldap_smbpwmods(struct smb_passwd *newpwd, LDAPMod ***mods, int operation)
{
	fstring temp;
	int i;

	*mods = NULL;
	if(operation == LDAP_MOD_ADD) { /* immutable attributes */
	      ldap_make_mod(mods, LDAP_MOD_ADD, "objectclass", "sambaAccount");

	      ldap_make_mod(mods, LDAP_MOD_ADD, "uid", newpwd->unix_name);
	      slprintf(temp, sizeof(temp)-1, "%d", newpwd->unix_uid);
	      ldap_make_mod(mods, LDAP_MOD_ADD, "uidNumber", temp);

	      ldap_make_mod(mods, LDAP_MOD_ADD, "ntuid", newpwd->nt_name);
	      slprintf(temp, sizeof(temp)-1, "%x", newpwd->user_rid);
	      ldap_make_mod(mods, LDAP_MOD_ADD, "rid", temp);
	}

	if (newpwd->smb_passwd) {
	      for( i = 0; i < 16; i++) {
		     slprintf(&temp[2*i], 3, "%02X", newpwd->smb_passwd[i]);
	      }
	      ldap_make_mod(mods, operation, "lmPassword", temp);
	}

	if (newpwd->smb_nt_passwd) {
   	      for( i = 0; i < 16; i++) {
		     slprintf(&temp[2*i], 3, "%02X", newpwd->smb_nt_passwd[i]);
	      }
	      ldap_make_mod(mods, operation, "ntPassword", temp);
	}

	newpwd->pass_last_set_time = time(NULL);
	slprintf(temp, sizeof(temp)-1, "%08X", newpwd->pass_last_set_time);
	ldap_make_mod(mods, operation, "pwdLastSet", temp);

	ldap_make_mod(mods, operation, "acctFlags",
	                    pwdb_encode_acct_ctrl(newpwd->acct_ctrl,
	                           NEW_PW_FORMAT_SPACE_PADDED_LEN));
}


/************************************************************************
  Commit changes to a directory entry.
 *************************************************************************/
 BOOL ldap_makemods(char *attribute, char *value, LDAPMod **mods, BOOL add)
{
	pstring filter;
	char *dn;
	int entries;
	int err = 0;
	BOOL rc;

	slprintf(filter, sizeof(filter)-1, "%s=%s", attribute, value);

	if (!ldap_connect())
		return (False);

	ldap_search_for(filter);

	if (ldap_entry)
	{
		dn = ldap_get_dn(ldap_struct, ldap_entry);
		err = ldap_modify_s(ldap_struct, dn, mods);
		free(dn);
	}
	else if (add)
	{
		pstrcat(filter, ", ");
		pstrcat(filter, lp_ldap_suffix());
		err = ldap_add_s(ldap_struct, filter, mods);
	}

	if (err == LDAP_SUCCESS)
	{
		DEBUG(2,("Updated entry [%s]\n", value));
		rc = True;
	} else {
		DEBUG(0,("update: %s\n", ldap_err2string(err)));
		rc = False;
	}

	ldap_disconnect();
	ldap_mods_free(mods, 1);
	return rc;
}


/************************************************************************
  Return next available RID, starting from 1000
 ************************************************************************/

BOOL ldap_allocaterid(uint32 *rid)
{
	pstring newdn;
	fstring rid_str;
	LDAPMod **mods;
	char *dn;
	int err;

	DEBUG(2, ("Allocating new RID\n"));

	if (!ldap_connect())
		return (False);

	ldap_search_for("(&(id=root)(objectClass=sambaConfig))");

	if (ldap_entry && ldap_get_attribute("nextrid", rid_str))
		*rid = strtol(rid_str, NULL, 16);
	else
		*rid = 1000;

	mods = NULL;
	if(!ldap_entry)
	{
		ldap_make_mod(&mods, LDAP_MOD_ADD, "objectClass",
			      "sambaConfig");
		ldap_make_mod(&mods, LDAP_MOD_ADD, "id", "root");
	}

	slprintf(rid_str, sizeof(fstring)-1, "%x", (*rid) + 1);
	ldap_make_mod(&mods, LDAP_MOD_REPLACE, "nextrid", rid_str);

	if (ldap_entry)
	{
                dn = ldap_get_dn(ldap_struct, ldap_entry);
                err = ldap_modify_s(ldap_struct, dn, mods);
                free(dn);
	} else {
		pstrcpy(newdn, "id=root, ");
		pstrcat(newdn, lp_ldap_suffix());
		ldap_add_s(ldap_struct, newdn, mods);
	}

	ldap_disconnect();

	if(err != LDAP_SUCCESS)
	{
		DEBUG(0,("nextrid update: %s\n", ldap_err2string(err)));
		return (False);
	}

	return (True);
}


/***************************************************************
  Begin/end account enumeration.
 ****************************************************************/

static void *ldap_enumfirst(BOOL update)
{
	if (!ldap_connect())
		return NULL;

	ldap_search_for("objectclass=sambaAccount");

	return ldap_struct;
}

static void ldap_enumclose(void *vp)
{
	ldap_disconnect();
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT ldap_getdbpos(void *vp)
{
	return (SMB_BIG_UINT)((ulong)ldap_entry);
}

static BOOL ldap_setdbpos(void *vp, SMB_BIG_UINT tok)
{
	ldap_entry = (LDAPMessage *)((ulong)tok);
	return (True);
}


/*************************************************************************
  Return smb_passwd information.
 *************************************************************************/

static struct smb_passwd *ldap_getpwbynam(const char *name)
{
	struct smb_passwd *ret;

	if(!ldap_connect())
		return NULL;

	ldap_search_by_name(name);
	ret = ldap_getpw();

	ldap_disconnect();
	return ret;
}

static struct smb_passwd *ldap_getpwbyuid(uid_t userid)
{
	struct smb_passwd *ret;

	if(!ldap_connect())
		return NULL;

	ldap_search_by_uid(userid);
	ret = ldap_getpw();

	ldap_disconnect();
	return ret;
}

static struct smb_passwd *ldap_getcurrentpw(void *vp)
{
	struct smb_passwd *ret;

	ret = ldap_getpw();
	ldap_entry = ldap_next_entry(ldap_struct, ldap_entry);
	return ret;
}


/************************************************************************
  Modify user information given an smb_passwd struct.
 *************************************************************************/
static BOOL ldap_addpw(struct smb_passwd *newpwd)
{
	LDAPMod **mods;

	if (!newpwd || !ldap_allocaterid(&newpwd->user_rid))
		return (False);

	ldap_smbpwmods(newpwd, &mods, LDAP_MOD_ADD);
	return ldap_makemods("uid", newpwd->unix_name, mods, True);
}

static BOOL ldap_modpw(struct smb_passwd *pwd, BOOL override)
{
	LDAPMod **mods;

	if (!pwd)
		return (False);

	ldap_smbpwmods(pwd, &mods, LDAP_MOD_REPLACE);
	return ldap_makemods("uid", pwd->unix_name, mods, False);
}


static struct smb_passdb_ops ldap_ops =
{
	ldap_enumfirst,
	ldap_enumclose,
	ldap_getdbpos,
	ldap_setdbpos,

	ldap_getpwbynam,
	ldap_getpwbyuid,
	ldap_getcurrentpw,
	ldap_addpw,
	ldap_modpw
};

struct smb_passdb_ops *ldap_initialise_password_db(void)
{
	FILE *pwdfile;
	char *pwdfilename;
	char *p;

	pwdfilename = lp_ldap_passwd_file();

	if(pwdfilename[0]) {
		if(pwdfile = sys_fopen(pwdfilename, "r")) {
			fgets(ldap_secret, sizeof(ldap_secret), pwdfile);
			if(p = strchr(ldap_secret, '\n'))
				*p = 0;
			fclose(pwdfile);
		} else {
			DEBUG(0,("Failed to open LDAP passwd file\n"));
		}
	}

	return &ldap_ops;
}

#else
 void ldap_dummy_function(void);
 void ldap_dummy_function(void) { } /* stop some compilers complaining */
#endif
