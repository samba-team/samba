/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau 1998
   Copyright (C) Matthew Chapman 1998
   Copyright (C) Luke Howard (PADL Software Pty Ltd) 2000

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
#include "sids.h"

extern int DEBUGLEVEL;


/*******************************************************************
Construct an smb_passwd structure
******************************************************************/
struct smb_passwd *
nt5ldapsmb_getent (LDAPDB * hds)
{
	static struct smb_passwd smbpw;
	static pstring unix_name;
	static pstring nt_name;
	static unsigned char smblmpwd[16];
	static unsigned char smbntpwd[16];
	pstring temp;
	NTDS_USER_FLAG_ENUM adac;
	NTTIME nttime;
	struct berval *bv = NULL;

	if (!ldapdb_peek (hds))
	{
		return NULL;
	}

	if (!ldapdb_get_pvalue (hds, "uid", unix_name) &&
	    !ldapdb_get_pvalue (hds, "mSSFUName", unix_name))
	{
		DEBUG (0, ("SMB user missing uid\n"));
		return NULL;
	}
	else
	{
		smbpw.unix_name = unix_name;
	}
	DEBUG (2, ("Retrieving account [%s]\n", unix_name));

	if (!ldapdb_get_pvalue (hds, "uidNumber", temp))
	{
		DEBUG (0, ("Missing uidNumber\n"));
		return NULL;
	}
	else
	{
		smbpw.unix_uid = atoi (temp);
	}

	if (!ldapdb_get_pvalue (hds, "sAMAccountName", nt_name))
	{
		DEBUG (0, ("Missing sAMAccountName\n"));
		return NULL;
	}
	else
	{
		smbpw.nt_name = nt_name;
	}

	if (!ldapdb_get_rid (hds, "objectSid", &smbpw.user_rid))
	{
		DEBUG (0, ("Missing objectSid\n"));
		return NULL;
	}

	if (ldapdb_get_pvalue (hds, "userAccountControl", temp))
	{
		adac = strtol (temp, NULL, 10);
		smbpw.acct_ctrl = pwdb_acct_ctrl_from_ad (adac);
	}
	else
	{
		smbpw.acct_ctrl = ACB_NORMAL;
	}

	if (ldapdb_get_value_len (hds, "dBCSPwd", &bv) &&
	    berval_to_dbcspwd (bv, smblmpwd))
	{
		smbpw.smb_passwd = smblmpwd;
	}
	else
	{
		smbpw.smb_passwd = NULL;
		smbpw.acct_ctrl |= ACB_DISABLED;
	}

	if (bv != NULL)
	{
		ber_bvfree(bv);
		bv = NULL;
	}

	if (ldapdb_get_value_len (hds, "unicodePwd", &bv) &&
	    berval_to_unicodepwd (bv, smblmpwd))
	{
		smbpw.smb_nt_passwd = smbntpwd;
		ber_bvfree (bv);
	}
	else
	{
		smbpw.smb_nt_passwd = NULL;
	}

	if (bv != NULL)
	{
		ber_bvfree(bv);
	}

	if (ldapdb_get_time (hds, "pwdLastSet", &nttime))
	{
		smbpw.pass_last_set_time = nt_time_to_unix (&nttime);
	}
	else
	{
		smbpw.pass_last_set_time = (time_t) (-1);
	}

	return &smbpw;
}

/************************************************************************
Queues the necessary modifications to save a smb_passwd structure
************************************************************************/

BOOL
nt5ldapsmb_smbmods (struct smb_passwd * newpwd, LDAPMod *** mods, int operation)
{
	fstring temp;
	pstring upn, spn, hostname;
	struct berval *bv;
	char *cname;

	*mods = NULL;
	if (operation == LDAP_MOD_ADD)
	{
		BOOL iscomputer = (newpwd->nt_name[strlen (newpwd->nt_name) - 1] == '$');

		/* immutable attributes */
		const char *realm = ldapdb_get_realm_name ();

		if (iscomputer)
		{
			pstrcpy (hostname, newpwd->nt_name);
			hostname[strlen (hostname) - 1] = '\0';

			if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "dNSHostName", hostname))
				return False;

			slprintf (spn, sizeof (spn) - 1, "host/%s", hostname);
			if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "servicePrincipalName", spn))
				return False;

			if (realm)
			{
				slprintf (upn, sizeof (upn) - 1, "%s@%s", spn, realm);
			}

			cname = hostname;
		}
		else
		{
			if (realm)
			{
				slprintf (upn, sizeof (upn) - 1, "%s@%s", newpwd->nt_name, realm);
			}

			cname = newpwd->nt_name;
		}

		if (realm)
		{
#ifdef KRB5_AUTH
			char *p, *q;
#endif /* KRB5_AUTH */

			if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "userPrincipalName", upn))
			{
				return False;
			}

#ifdef KRB5_AUTH
			/*
			 * Stick the Kerberos attributes in for good measure, they come in handy
			 * without Heimdal LDAP backend and LDAP servers that do Kerberos authzn.
			 */
			p = strchr (upn, '@');
			if (p == NULL)
			{
				return False;
			}
			++p;
			for (q = p; *q != '\0'; q++)
			{
				*q = toupper (*q);
			}
			if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "krbName", upn) ||
			    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "krb5PrincipalName", upn) ||
			    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectclass", "kerberosSecurityObject") ||
			    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectclass", "krb5Principal"))
			{
				return False;
			}
#endif /* KRB5_AUTH */
		}

		if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectclass", "top") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectclass", "person") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectclass", "organizationalPerson") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectclass", "posixAccount") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectClass", "securityPrincipal") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectclass", "user"))
		{
			return False;
		}

		if (iscomputer && !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectclass", "computer"))
		{
			return False;
		}

		if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "uid", newpwd->unix_name) ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "mSSFUName", newpwd->unix_name) ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "sAMAccountName", newpwd->nt_name) ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "cn", cname) ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "name", cname) ||
		!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "displayName", cname))
		{
			return False;
		}

		slprintf (temp, sizeof (temp) - 1, "%d", newpwd->unix_uid);
		if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "uidNumber", temp))
			return False;

		if (!rid_to_berval (newpwd->user_rid, &bv))
			return False;

		/* we need to _not_ do this with an NT5 DC because it's auto generated */
		if (!ldapdb_queue_mod_len (mods, LDAP_MOD_ADD, "objectSid", bv))
		{
			ber_bvfree(bv);
			return False;
		}
	}

	if (newpwd->smb_passwd)
	{
		if (!dbcspwd_to_berval (newpwd->smb_passwd, &bv))
		{
			return False;
		}
		if (!ldapdb_queue_mod_len (mods, operation, "dBCSPwd", bv))
		{
			ber_bvfree (bv);
			return False;
		}
	}

	if (newpwd->smb_nt_passwd)
	{
		if (!unicodepwd_to_berval (newpwd->smb_nt_passwd, &bv))
		{
			return False;
		}
		if (!ldapdb_queue_mod_len (mods, operation, "unicodePwd", bv))
		{
			ber_bvfree (bv);
			return False;
		}
	}

	if (!ldapdb_queue_time (mods, operation, "pwdLastSet", NULL))
	{
		return False;
	}

	if (!ldapdb_queue_uint32_mod (mods, operation, "userAccountControl", pwdb_acct_ctrl_to_ad(newpwd->acct_ctrl)))
	{
		return False;
	}

	return True;
}

/*******************************************************************
  Contruct a sam_passwd structure.
 ******************************************************************/
/***************************************************************
Begin/end account enumeration.
****************************************************************/

static void *
nt5ldapsmb_enumfirst (BOOL update)
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
nt5ldapsmb_enumclose (void *vp)
{
	LDAPDB *hds = (LDAPDB *) vp;

	ldapdb_close (&hds);

	return;
}


/*************************************************************************
Save/restore the current position in a query
*************************************************************************/

static SMB_BIG_UINT
nt5ldapsmb_getdbpos (void *vp)
{
	return 0;
}

static BOOL
nt5ldapsmb_setdbpos (void *vp, SMB_BIG_UINT tok)
{
	return False;
}

/*************************************************************************
Return smb_passwd information.
*************************************************************************/

static struct smb_passwd *
nt5ldapsmb_getpwbynam (const char *name)
{
	struct smb_passwd *ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_posix_name (hds, name))
	{
		ldapdb_close (&hds);
		return NULL;
	}

	ret = nt5ldapsmb_getent (hds);
	ldapdb_close (&hds);

	return ret;
}

static struct smb_passwd *
nt5ldapsmb_getpwbyuid (uid_t userid)
{
	struct smb_passwd *ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return NULL;
	}

	if (!ldapdb_lookup_by_posix_uid (hds, userid))
	{
		ldapdb_close (&hds);
		return False;
	}

	ret = nt5ldapsmb_getent (hds);
	ldapdb_close (&hds);

	return ret;
}

static struct smb_passwd *
nt5ldapsmb_getcurrentpw (void *vp)
{
	struct smb_passwd *ret;
	LDAPDB *hds = (LDAPDB *) vp;

	ret = nt5ldapsmb_getent (hds);
	(void) ldapdb_seq (hds);

	return ret;
}


/************************************************************************
Modify user information given an smb_passwd struct.
*************************************************************************/
static BOOL
nt5ldapsmb_addpw (struct smb_passwd *newpwd)
{
	LDAPMod **mods = NULL;
	char *container, *cname;
	pstring hostname;
	BOOL ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!newpwd || !ldapdb_allocate_rid (hds, &newpwd->user_rid))
	{
		ldapdb_close (&hds);
		return False;
	}

	if (newpwd->unix_name[strlen (newpwd->nt_name) - 1] == '$')
	{
		container = lp_ldap_computers_subcontext ();
		pstrcpy (hostname, newpwd->nt_name);
		hostname[strlen (hostname) - 1] = '\0';
		cname = hostname;
	}
	else
	{
		container = lp_ldap_users_subcontext ();
		cname = newpwd->nt_name;
	}

	if (!nt5ldapsmb_smbmods (newpwd, &mods, LDAP_MOD_ADD))
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
nt5ldapsmb_modpw (struct smb_passwd *pwd, BOOL override)
{
	LDAPMod **mods = NULL;
	BOOL ret;
	LDAPDB_DECLARE_HANDLE (hds);

	if (!pwd)
	{
		return False;
	}

	if (!ldapdb_open (&hds))
	{
		return False;
	}

	if (!nt5ldapsmb_smbmods (pwd, &mods, LDAP_MOD_REPLACE))
	{
		ret = False;
	}
	else
	{
		ret = ldapdb_update (hds, NULL, "cn", pwd->unix_name, mods, False);
	}

	ldapdb_close (&hds);
	return ret;
}

static struct smb_passdb_ops nt5ldapsmb_ops =
{
	nt5ldapsmb_enumfirst,
	nt5ldapsmb_enumclose,
	nt5ldapsmb_getdbpos,
	nt5ldapsmb_setdbpos,

	nt5ldapsmb_getpwbynam,
	nt5ldapsmb_getpwbyuid,
	nt5ldapsmb_getcurrentpw,
	nt5ldapsmb_addpw,
	nt5ldapsmb_modpw
};

struct smb_passdb_ops *
nt5ldap_initialise_password_db (void)
{
	if (!ldapdb_init ())
	{
		return NULL;
	}

	return &nt5ldapsmb_ops;
}

#else
void nt5ldapsmb_dummy_function (void);
void
nt5ldapsmb_dummy_function (void)
{
}				/* stop some compilers complaining */
#endif
