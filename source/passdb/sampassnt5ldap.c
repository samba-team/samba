
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

#ifdef WITH_NT5LDAP

#include <lber.h>
#include <ldap.h>
#include "ldapdb.h"

extern int DEBUGLEVEL;
extern DOM_SID global_sam_sid;

/*******************************************************************
  NT name/RID search functions.
 ******************************************************************/

/*******************************************************************
  Contruct a sam_passwd structure.
 ******************************************************************/

struct sam_passwd *
nt5ldapsam_getent (LDAPDB * hds)
{
	static pstring full_name;
	static pstring acct_desc;
	static pstring home_dir;
	static pstring home_drive;
	static pstring logon_script;
	static pstring profile_path;
	static pstring workstations;
	struct sam_passwd *sam21;
	struct smb_passwd *smbpw;
	struct berval *bv;
	pstring temp;

	extern BOOL sam_logon_in_ssb;
	extern pstring samlogon_user;

	if (!ldapdb_peek (hds))
	{
		return NULL;
	}

	smbpw = nt5ldapsmb_getent (hds);
	if (smbpw == NULL)
	{
		return NULL;
	}

	sam21 = pwdb_smb_to_sam (smbpw);

	/* uid/mSSFUName from smbpw */

	/* sAMAccountName from smbpw */

	if (ldapdb_get_pvalue (hds, "displayName", full_name) ||
	    ldapdb_get_pvalue (hds, "cn", full_name))
		sam21->full_name = full_name;

	/* XXX rfc2307 conflict */
	if (ldapdb_get_pvalue (hds, "homeDirectory", home_dir))
		sam21->home_dir = home_dir;

	if (ldapdb_get_pvalue (hds, "homeDrive", home_drive))
		sam21->dir_drive = home_drive;

	if (ldapdb_get_pvalue (hds, "scriptPath", logon_script))
		sam21->logon_script = logon_script;

	if (ldapdb_get_pvalue (hds, "profilePath", profile_path))
		sam21->profile_path = profile_path;

	if (ldapdb_get_pvalue (hds, "description", acct_desc))
		sam21->acct_desc = acct_desc;

	if (ldapdb_get_pvalue (hds, "userWorkstations", workstations))
		sam21->workstations = workstations;

	/* uidNumber from smbpw */

	if (ldapdb_get_pvalue (hds, "gidNumber", temp))
		sam21->unix_gid = atoi (temp);

	/* objectSid from smbpw */

	if (ldapdb_get_pvalue (hds, "primaryGroupId", temp))
		sam21->group_rid = strtol (temp, NULL, 10);

	/* dBCSPwd/unicodePwd from smbpw */

	(void) ldapdb_get_time (hds, "lastLogon", &sam21->logon_time);
	(void) ldapdb_get_time (hds, "lastLogoff", &sam21->logoff_time);
	(void) ldapdb_get_time (hds, "accountExpires", &sam21->pass_must_change_time);
#if 0
	/* not sure about this */
	(void) ldapdb_get_time (hds, "pwdCanChange", &sam21->pass_can_change_time);
	(void) ldapdb_get_time (hds, "kickoffTime", &sam21->kickoff_time);
#endif

	if (ldapdb_get_value_len(hds, "logonHours", &bv))
	{
		if (bv->bv_len <= MAX_HOURS_LEN)
		{
			memcpy(sam21->hours, bv->bv_val, bv->bv_len);
			sam21->hours_len = bv->bv_len;
		}
		ber_bvfree(bv);
	}

	sam21->unknown_3 = 0xffffff;	/* don't know */
	sam21->logon_divs = 168;	/* hours per week */
	sam21->unknown_5 = 0x00020000;	/* don't know */
	sam21->unknown_6 = 0x000004ec;	/* don't know */
	sam21->unknown_str = NULL;
	sam21->munged_dial = NULL;

	/* XXXX hack to get standard_sub_basic() to use sam logon username */
	/* possibly a better way would be to do a become_user() call */

	sam_logon_in_ssb = True;

	pstrcpy (samlogon_user, sam21->unix_name);

	standard_sub_basic (logon_script);
	standard_sub_basic (profile_path);
	standard_sub_basic (home_drive);
	standard_sub_basic (home_dir);
	standard_sub_basic (workstations);

	sam_logon_in_ssb = False;

	return sam21;
}


/*******************************************************************
  Contruct a sam_disp_info structure.
  ******************************************************************/

static struct sam_disp_info *
nt5ldapsam_getdispinfo (LDAPDB * hds)
{
	static struct sam_disp_info dispinfo;
	static pstring nt_name;
	static pstring full_name;

	if (!ldapdb_peek (hds))
	{
		return NULL;
	}

	if (!ldapdb_get_pvalue (hds, "sAMAccountName", nt_name))
	{
		DEBUG (0, ("SAM user missing sAMAccountName\n"));
		return NULL;
	}
	dispinfo.nt_name = nt_name;

	DEBUG (2, ("Retrieving account [%s]\n", nt_name));

	if (!ldapdb_get_rid (hds, "objectSid", &dispinfo.user_rid))
	{
		DEBUG (0, ("SAM user missing objectSid\n"));
		return NULL;
	}

	if (ldapdb_get_pvalue (hds, "displayName", full_name) ||
	    ldapdb_get_pvalue (hds, "cn", full_name))
	{
		dispinfo.full_name = full_name;
	}
	else
	{
		dispinfo.full_name = nt_name;
	}

	return &dispinfo;
}


/************************************************************************
  Queues the necessary modifications to save a sam_passwd structure
 ************************************************************************/

BOOL 
nt5ldapsam_sammods (struct sam_passwd * newpwd, LDAPMod *** mods, int operation)
{
	struct smb_passwd *smbpw;
	pstring temp;
	struct berval *bv;

	smbpw = pwdb_sam_to_smb (newpwd);
	if (!nt5ldapsmb_smbmods (smbpw, mods, operation))
	{
		return False;
	}

	slprintf (temp, sizeof (temp) - 1, "%d", newpwd->unix_gid);
	if (!ldapdb_queue_mod (mods, operation, "gidNumber", temp) ||
	    !ldapdb_queue_mod (mods, operation, "cn", newpwd->full_name) ||
	    !ldapdb_queue_mod (mods, operation, "name", newpwd->full_name) ||
	    !ldapdb_queue_mod (mods, operation, "displayName", newpwd->full_name) ||
	    !ldapdb_queue_mod (mods, operation, "description", newpwd->acct_desc) ||
	    !ldapdb_queue_mod (mods, operation, "homeDirectory", newpwd->home_dir) ||
	    !ldapdb_queue_mod (mods, operation, "homeDrive", newpwd->dir_drive) ||
	    !ldapdb_queue_mod (mods, operation, "scriptPath", newpwd->logon_script) ||
	    !ldapdb_queue_mod (mods, operation, "profilePath", newpwd->profile_path) ||
	    !ldapdb_queue_mod (mods, operation, "userWorkstations", newpwd->workstations) ||
	    !ldapdb_queue_time (mods, operation, "lastLogon", &newpwd->logon_time) ||
	    !ldapdb_queue_time (mods, operation, "lastLogoff", &newpwd->logoff_time) ||
	    !ldapdb_queue_time (mods, operation, "accountExpires", &newpwd->pass_must_change_time))
	{
		return False;
	}

	if (newpwd->hours_len)
	{
		bv = (struct berval *)malloc(sizeof(*bv));
		if (bv == NULL)
		{
			return False;
		}
		bv->bv_len = newpwd->hours_len;
		bv->bv_val = malloc(newpwd->hours_len);
		if (bv->bv_val == NULL)
		{
			free(bv);
			return False;
		}
	
		memcpy(bv->bv_val, newpwd->hours, newpwd->hours_len);
		if (!ldapdb_queue_mod_len(mods, operation, "logonHours", bv))
		{
			ber_bvfree(bv);
			return False;
		}
	}

#if 0
	/* not sure about this */
	if (!ldapdb_queue_time (mods, operation, "pwdCanChange", &newpwd->pass_can_change_time) ||
	    !ldapdb_queue_time (mods, operation, "kickoffTime", &newpwd->kickoff_time))
	{
		return False;
	}
#endif

	return True;
}


/***************************************************************
  Begin/end account enumeration.
 ****************************************************************/

static void *
nt5ldapsam_enumfirst (BOOL update)
{
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_search (hds, NULL, "(objectClass=User)", NULL, LDAP_NO_LIMIT))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	return hds;
}

static void 
nt5ldapsam_enumclose (void *vp)
{
	LDAPDB *hds = (LDAPDB *) vp;

	ldapdb_close (&hds);

	return;
}


/*************************************************************************
  Save/restore the current position in a query
 *************************************************************************/

static SMB_BIG_UINT 
nt5ldapsam_getdbpos (void *vp)
{
	return 0;
}

static BOOL 
nt5ldapsam_setdbpos (void *vp, SMB_BIG_UINT tok)
{
	return False;
}


/*************************************************************************
  Return sam_passwd information.
 *************************************************************************/

static struct sam_passwd *
nt5ldapsam_getsambynam (const char *name)
{
	struct sam_passwd *ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_ntname (hds, name))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsam_getent (hds);

	ldapdb_close (&hds);

	return ret;
}

static struct sam_passwd *
nt5ldapsam_getsambyuid (uid_t userid)
{
	struct sam_passwd *ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_posix_uid (hds, userid))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsam_getent (hds);

	ldapdb_close (&hds);

	return ret;
}

static struct sam_passwd *
nt5ldapsam_getsambyrid (uint32 user_rid)
{
	struct sam_passwd *ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_rid (hds, user_rid))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsam_getent (hds);

	ldapdb_close (&hds);

	return ret;
}

static struct sam_passwd *
nt5ldapsam_getcurrentsam (void *vp)
{
	struct sam_passwd *ret = NULL;

	do
	{
		if ((ret = nt5ldapsam_getent ((LDAPDB *)vp)) != NULL)
			break;
	}
	while (ldapdb_seq((LDAPDB *)vp) == True);

	return ret;
}


/************************************************************************
  Modify user information given a sam_passwd struct.
 *************************************************************************/

static BOOL 
nt5ldapsam_addsam (struct sam_passwd *newpwd)
{
	LDAPMod **mods = NULL;
	char *container, *cname;
	pstring hostname;
	LDAPDB_DECLARE_HANDLE (hds);
	BOOL ret;

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!newpwd || !ldapdb_allocate_rid (hds, &newpwd->user_rid))
	{
		ldapdb_close (&hds);
		return False;
	}

	if (newpwd->unix_name[strlen (newpwd->unix_name) - 2] == '$')
	{
		container = lp_ldap_computers_subcontext ();
		pstrcpy (hostname, newpwd->nt_name);
		hostname[strlen (hostname) - 1] = '\0';
		cname = hostname;
	}
	else
	{
		container = lp_ldap_users_subcontext ();
		cname = newpwd->full_name;
	}

	if (!nt5ldapsam_sammods (newpwd, &mods, LDAP_MOD_ADD))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_update (hds, container, "cn", cname, mods, True);
	}

	ldapdb_close (&hds);

	return ret;
}

static BOOL 
nt5ldapsam_modsam (struct sam_passwd *pwd, BOOL override)
{
	LDAPMod **mods = NULL;
	LDAPDB_DECLARE_HANDLE (hds);
	BOOL ret;

	if (!pwd)
	{
		return False;
	}

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!nt5ldapsam_sammods (pwd, &mods, LDAP_MOD_REPLACE))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_update (hds, NULL, "cn", pwd->full_name, mods, False);
	}

	ldapdb_close (&hds);

	return ret;
}


/*************************************************************************
  Return sam_disp_info information.
 *************************************************************************/

static struct sam_disp_info *
nt5ldapsam_getdispbynam (const char *name)
{
	struct sam_disp_info *ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_ntname (hds, name))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsam_getdispinfo (hds);

	ldapdb_close (&hds);

	return ret;
}

static struct sam_disp_info *
nt5ldapsam_getdispbyrid (uint32 user_rid)
{
	struct sam_disp_info *ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_rid (hds, user_rid))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsam_getdispinfo (hds);

	ldapdb_close (&hds);

	return ret;
}

static struct sam_disp_info *
nt5ldapsam_getcurrentdisp (void *vp)
{
	struct sam_disp_info *ret = NULL;

	do
	{
		if ((ret = nt5ldapsam_getdispinfo ((LDAPDB *)vp)) != NULL)
			break;
	}
	while (ldapdb_seq((LDAPDB *)vp) == True);

	return ret;
}

static struct sam_passdb_ops nt5ldapsam_ops =
{
	nt5ldapsam_enumfirst,
	nt5ldapsam_enumclose,
	nt5ldapsam_getdbpos,
	nt5ldapsam_setdbpos,

	nt5ldapsam_getsambynam,
	nt5ldapsam_getsambyuid,
	nt5ldapsam_getsambyrid,
	nt5ldapsam_getcurrentsam,
	nt5ldapsam_addsam,
	nt5ldapsam_modsam,

	nt5ldapsam_getdispbynam,
	nt5ldapsam_getdispbyrid,
	nt5ldapsam_getcurrentdisp
};

struct sam_passdb_ops *
nt5ldap_initialise_sam_password_db (void)
{
	return &nt5ldapsam_ops;
}

#else
void sampassldap_dummy_function (void);
void 
sampassldap_dummy_function (void)
{
}				/* stop some compilers complaining */
#endif
