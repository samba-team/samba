/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP protocol helper functions for SAMBA
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
extern LDAP *ldap_struct;
extern LDAPMessage *ldap_results;
extern LDAPMessage *ldap_entry;


/*******************************************************************
  NT name/RID search functions.
 ******************************************************************/

BOOL ldap_search_by_rid(uint32 rid)
{
        fstring filter;

        slprintf(filter, sizeof(filter)-1,
                 "(&(rid=%x)(objectclass=sambaAccount))", rid);
        return ldap_search_for(filter);
}

BOOL ldap_search_by_ntname(const char *ntname)
{
        fstring filter;

        slprintf(filter, sizeof(filter)-1,
                 "(&(ntuid=%s)(objectclass=sambaAccount))", ntname);
        return ldap_search_for(filter);
}


/*******************************************************************
  Store NTTIMEs as time_t's.
 ******************************************************************/

static void ldap_save_time(LDAPMod ***modlist, int modop, char *attribute,
                        NTTIME *nttime)
{
        fstring tstr;
        time_t t;

        t = nt_time_to_unix(nttime);

        if(t == -1)
                return;

        slprintf(tstr, sizeof(tstr)-1, "%08X", t);
        ldap_make_mod(modlist, modop, attribute, tstr);
}

static void ldap_read_time(char *attribute, NTTIME *nttime)
{
        fstring timestr;
        time_t t;

        if(ldap_get_attribute(attribute, timestr))
        {
                t = (time_t)strtol(timestr, NULL, 16);
                unix_to_nt_time(nttime, t);
        }
}


/*******************************************************************
  Contruct a sam_passwd structure.
 ******************************************************************/

static struct sam_passwd *ldapsam_getsam()
{
	static pstring full_name;
	static pstring acct_desc;
	static pstring home_dir;
	static pstring home_drive;
	static pstring logon_script;
	static pstring profile_path;
	static pstring workstations;
	pstring temp;
	struct sam_passwd *sam21;
	struct smb_passwd *smbpw;

	if(!ldap_entry)
		return NULL;

	smbpw = ldap_getpw();
	sam21 = pwdb_smb_to_sam(smbpw);	

	if(ldap_get_attribute("gidNumber", temp))
		sam21->unix_gid = atoi(temp);
	
	if(ldap_get_attribute("grouprid", temp))
		sam21->group_rid = strtol(temp, NULL, 16);
	
	if(ldap_get_attribute("cn", full_name))
		sam21->full_name = full_name;

	if(ldap_get_attribute("description", acct_desc))
		sam21->acct_desc = acct_desc;

	if(ldap_get_attribute("smbHome", home_dir))
		sam21->home_dir = home_dir;

	if(ldap_get_attribute("homeDrive", home_drive))
		sam21->dir_drive = home_drive;

	if(ldap_get_attribute("script", logon_script))
		sam21->logon_script = logon_script;

	if(ldap_get_attribute("profile", profile_path))
		sam21->profile_path = profile_path;

	if(ldap_get_attribute("workstations", workstations))
		sam21->workstations = workstations;

	ldap_read_time("pwdCanChange", &sam21->pass_can_change_time);
	ldap_read_time("pwdMustChange", &sam21->pass_must_change_time);
	ldap_read_time("logonTime", &sam21->logon_time);
	ldap_read_time("logoffTime", &sam21->logoff_time);
	ldap_read_time("kickoffTime", &sam21->kickoff_time);

        sam21->unknown_3 = 0xffffff; /* don't know */
        sam21->logon_divs = 168; /* hours per week */
        sam21->hours_len = 21; /* 21 times 8 bits = 168 */
        memset(sam21->hours, 0xff, sam21->hours_len); /* all hours */
        sam21->unknown_5 = 0x00020000; /* don't know */
        sam21->unknown_6 = 0x000004ec; /* don't know */
        sam21->unknown_str = NULL;
        sam21->munged_dial = NULL;

	/* XXXX hack to get standard_sub_basic() to use sam logon username */
	/* possibly a better way would be to do a become_user() call */

	sam_logon_in_ssb = True;

	standard_sub_basic(logon_script);
	standard_sub_basic(profile_path);
	standard_sub_basic(home_drive);
	standard_sub_basic(home_dir);
	standard_sub_basic(workstations);

	sam_logon_in_ssb = False;

        ldap_entry = ldap_next_entry(ldap_struct, ldap_entry);
	return sam21;
}


/*******************************************************************
  Contruct a sam_disp_info structure.
  ******************************************************************/

static struct sam_disp_info *ldapsam_getdispinfo()
{
	static struct sam_disp_info dispinfo;
	static pstring nt_name;
	static pstring full_name;
	pstring temp;

	if(!ldap_entry)
		return NULL;
	
	if(!ldap_get_attribute("ntuid", nt_name) &&
			!ldap_get_attribute("uid", nt_name)) {
		DEBUG(0,("Missing uid\n"));
		return NULL; }
	dispinfo.nt_name = nt_name;

	DEBUG(2,("Retrieving account [%s]\n",nt_name));

	if(ldap_get_attribute("rid", temp))
		dispinfo.user_rid = strtol(temp, NULL, 16);
	else {
		DEBUG(0,("Missing rid\n"));
		return NULL; }

	if(ldap_get_attribute("cn", full_name))
		dispinfo.full_name = full_name;
	else
		dispinfo.full_name = NULL;

        ldap_entry = ldap_next_entry(ldap_struct, ldap_entry);
	return &dispinfo;
}


/************************************************************************
  Queues the necessary modifications to save a sam_passwd structure
 ************************************************************************/

static void ldapsam_sammods(struct sam_passwd *newpwd, LDAPMod ***mods,
			   int operation)
{
	struct smb_passwd *smbpw;
	pstring temp;

	smbpw = pwdb_sam_to_smb(newpwd);
	ldap_smbpwmods(smbpw, mods, operation);

	slprintf(temp, sizeof(temp)-1, "%d", newpwd->unix_gid);
	ldap_make_mod(mods, operation, "gidNumber", temp);

	slprintf(temp, sizeof(temp)-1, "%x", newpwd->group_rid);
	ldap_make_mod(mods, operation, "grouprid", temp);

	ldap_make_mod(mods, operation, "cn", newpwd->full_name);
	ldap_make_mod(mods, operation, "description", newpwd->acct_desc);
	ldap_make_mod(mods, operation, "smbHome", newpwd->home_dir);
	ldap_make_mod(mods, operation, "homeDrive", newpwd->dir_drive);
	ldap_make_mod(mods, operation, "script", newpwd->logon_script);
	ldap_make_mod(mods, operation, "profile", newpwd->profile_path);
	ldap_make_mod(mods, operation, "workstations", newpwd->workstations);

	ldap_save_time(mods, operation, "pwdCanChange",
			&newpwd->pass_can_change_time);
	ldap_save_time(mods, operation, "pwdMustChange",
			&newpwd->pass_must_change_time);
	ldap_save_time(mods, operation, "logonTime",
			&newpwd->logon_time);
	ldap_save_time(mods, operation, "logoffTime",
			&newpwd->logoff_time);
	ldap_save_time(mods, operation, "kickoffTime",
			&newpwd->kickoff_time);
}


/***************************************************************
  Begin/end account enumeration.
 ****************************************************************/

static void *ldapsam_enumfirst(BOOL update)
{
	if (!ldap_connect())
		return NULL;

	ldap_search_for("objectclass=sambaAccount");

	return ldap_struct;
}

static void ldapsam_enumclose(void *vp)
{
	ldap_disconnect();
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT ldapsam_getdbpos(void *vp)
{
	return (SMB_BIG_UINT)((ulong)ldap_entry);
}

static BOOL ldapsam_setdbpos(void *vp, SMB_BIG_UINT tok)
{
	ldap_entry = (LDAPMessage *)((ulong)tok);
	return (True);
}


/*************************************************************************
  Return sam_passwd information.
 *************************************************************************/

static struct sam_passwd *ldapsam_getsambynam(const char *name)
{
	struct sam_passwd *ret;

	if(!ldap_connect())
		return NULL;

	ldap_search_by_ntname(name);
	ret = ldapsam_getsam();

	ldap_disconnect();
	return ret;
}

static struct sam_passwd *ldapsam_getsambyuid(uid_t userid)
{
	struct sam_passwd *ret;

	if(!ldap_connect())
	   return NULL;

	ldap_search_by_uid(userid);
	ret = ldapsam_getsam();

	ldap_disconnect();
	return ret;
}

static struct sam_passwd *ldapsam_getsambyrid(uint32 user_rid)
{
	struct sam_passwd *ret;

	if(!ldap_connect())
	   return NULL;

	ldap_search_by_rid(user_rid);
	ret = ldapsam_getsam();

	ldap_disconnect();
	return ret;
}

static struct sam_passwd *ldapsam_getcurrentsam(void *vp)
{
        return ldapsam_getsam();
}


/************************************************************************
  Modify user information given a sam_passwd struct.
 *************************************************************************/

static BOOL ldapsam_addsam(struct sam_passwd *newpwd)
{	
	LDAPMod **mods;

	if (!newpwd || !ldap_allocaterid(&newpwd->user_rid))
		return (False);

	ldapsam_sammods(newpwd, &mods, LDAP_MOD_ADD);
	return ldap_makemods("uid", newpwd->unix_name, mods, True);
}

static BOOL ldapsam_modsam(struct sam_passwd *pwd, BOOL override)
{
	LDAPMod **mods;

	if (!pwd)
		return (False);

	ldapsam_sammods(pwd, &mods, LDAP_MOD_REPLACE);
	return ldap_makemods("uid", pwd->unix_name, mods, False);
}


/*************************************************************************
  Return sam_disp_info information.
 *************************************************************************/

static struct sam_disp_info *ldapsam_getdispbynam(const char *name)
{
	struct sam_disp_info *ret;

	if(!ldap_connect())
	   return NULL;

	ldap_search_by_ntname(name);
	ret = ldapsam_getdispinfo();

	ldap_disconnect();
	return ret;
}

static struct sam_disp_info *ldapsam_getdispbyrid(uint32 user_rid)
{
	struct sam_disp_info *ret;

	if(!ldap_connect())
	   return NULL;

	ldap_search_by_rid(user_rid);
	ret = ldapsam_getdispinfo();

	ldap_disconnect();
	return ret;
}

static struct sam_disp_info *ldapsam_getcurrentdisp(void *vp)
{
	return ldapsam_getdispinfo();
}



static struct sam_passdb_ops ldapsam_ops =
{
	ldapsam_enumfirst,
	ldapsam_enumclose,
	ldapsam_getdbpos,
	ldapsam_setdbpos,

	ldapsam_getsambynam,
	ldapsam_getsambyuid,
	ldapsam_getsambyrid,
	ldapsam_getcurrentsam,
	ldapsam_addsam,
	ldapsam_modsam,

	ldapsam_getdispbynam,
	ldapsam_getdispbyrid,
	ldapsam_getcurrentdisp
};

struct sam_passdb_ops *ldap_initialise_sam_password_db(void)
{
	return &ldapsam_ops;
}

#else
 void sampassldap_dummy_function(void);
 void sampassldap_dummy_function(void) { } /* stop some compilers complaining */
#endif
