/*         
   Unix SMB/Netbios implementation.                  
   Version 2.0.
   Common nt5ldap stuff shared between passdb and samrd
   Copyright (C) Luke Howard 2000

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

/***************************************************************
  Get group and membership information.
 ****************************************************************/

BOOL nt5ldap_make_local_grp(LDAPDB * hds, LOCAL_GRP * group,
		     LOCAL_GRP_MEMBER ** members, int *num_membs, uint32 req_type)
{
	char **values;
	LOCAL_GRP_MEMBER *memblist;
	int i;
	fstring grouptype;

	if (!ldapdb_peek (hds))
	{
		return False;
	}

	if (!ldapdb_get_fvalue (hds, "sAMAccountName", group->name))
	{
		DEBUG (0, ("Missing sAMAccountName\n"));
		return False;
	}

	DEBUG (2, ("Retrieving alias [%s]\n", group->name));

	if (!ldapdb_get_fvalue (hds, "groupType", grouptype))
	{
		uint32 type = strtol (grouptype, NULL, 10);
		if (!(type & (req_type | NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED)))
		{
			DEBUG (0, ("Invalid groupType\n"));
			return False;
		}
	}

	if (!ldapdb_get_rid (hds, "objectSid", &group->rid))
	{
		DEBUG (0, ("Missing objectSid\n"));
		return False;
	}

	if (!ldapdb_get_fvalue (hds, "description", group->comment))
	{
		group->comment[0] = 0;
	}

	if (!members || !num_membs)
	{
		return True;
	}

	if (ldapdb_get_values (hds, "member", &values))
	{
		int ngroups;

		ngroups = ldap_count_values (values);

		memblist = calloc (ngroups, sizeof (LOCAL_GRP_MEMBER));
		if (memblist == NULL)
		{
			return False;
		}

		*num_membs = 0;
		*members = memblist;

		for (i = 0; i < ngroups; i++)
		{
			if (nt5ldap_make_local_grp_member (hds, values[i], &memblist[*num_membs]))
			{
				(*num_membs)++;
			}
		}
		ldap_value_free (values);
	}
	else
	{
		*num_membs = 0;
		*members = NULL;
	}

	return True;
}

/************************************************************************
  Queues the necessary modifications to save a LOCAL_GRP structure
 ************************************************************************/

BOOL 
nt5ldap_local_grp_mods (const LOCAL_GRP * group, LDAPMod *** mods, int operation, uint32 req_type)
{
	struct berval *bv;

	*mods = NULL;

	if (operation == LDAP_MOD_ADD)
	{
		/* immutable attributes */
		fstring temp;

		if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectClass", "top") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectClass", "group") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectClass", "securityPrincipal") ||
		!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "cn", group->name) ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "sAMAccountName", group->name))
		{
			return False;
		}

		slprintf (temp, sizeof (temp) - 1, "%d",
			req_type | NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
		if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "groupType", temp))
		{
			return False;
		}

		/* Put the RID in for good measure. */
		if (!ldapdb_queue_uint32_mod (mods, LDAP_MOD_ADD, "rid", group->rid) ||
		    !rid_to_berval (group->rid, &bv))
		{
			return False;
		}

		if (!ldapdb_queue_mod_len (mods, LDAP_MOD_ADD, "objectSid", bv))
		{
			ber_bvfree (bv);
			return False;
		}
	}

	return ldapdb_queue_mod (mods, operation, "description", group->comment);
}

/************************************************************************
  Create a alias member entry
 ************************************************************************/

BOOL 
nt5ldap_local_grp_member_mods (const DOM_SID * user_sid, LDAPMod *** mods,
		      int operation, pstring member)
{
	if (ldapdb_sid_to_dn (NULL, user_sid, member) == False)
	{
		return False;
	}

	*mods = NULL;

	return ldapdb_queue_mod (mods, operation, "member", member);
}

BOOL 
nt5ldap_make_local_grp_member (LDAPDB * _hds, const char *dn, LOCAL_GRP_MEMBER * member)
{
	char *attrs[] =
	{"sAMAccountName", "userAccountFlags", "objectSid", NULL};
	LDAPDB_DECLARE_HANDLE (hds);
	fstring user;
	fstring domain;

	if (!LDAPDB_OPEN (_hds, &hds))
	{
		ldapdb_close (&hds);
		return False;
	}

	if (!ldapdb_read (hds, dn, attrs) ||
	    !ldapdb_get_sid (hds, "objectSid", &member->sid) ||
	    !ldapdb_get_fvalue (hds, "sAMAccountName", user) ||
	    !map_domain_sid_to_name (&member->sid, domain))
	{
		ldapdb_close (&hds);
		return False;
	}

	slprintf (member->name, sizeof (member->name), "%s\\%s", domain, user);
	member->sid_use = SID_NAME_ALIAS;

	ldapdb_close (&hds);

	return True;
}

BOOL 
nt5ldap_make_domain_grp_member (LDAPDB * _hds, const char *dn, DOMAIN_GRP_MEMBER * member)
{
	char *attrs[] =
	{"sAMAccountName", "userAccountFlags", "objectSid", NULL};
	LDAPDB_DECLARE_HANDLE (hds);
	fstring user;

	if (!LDAPDB_OPEN (_hds, &hds))
	{
		ldapdb_close (&hds);
		return False;
	}

	if (!ldapdb_read (hds, dn, attrs) ||
	    !ldapdb_get_rid (hds, "objectSid", &member->rid) ||
	    !ldapdb_get_fvalue (hds, "sAMAccountName", user))
	{
		ldapdb_close (&hds);
		return False;
	}

	slprintf (member->name, sizeof (member->name), "%s\\%s", global_sam_name, user);
	member->sid_use = SID_NAME_DOM_GRP;
	member->attr = 0x7;

	ldapdb_close (&hds);

	return True;
}

/***************************************************************
  Get group and membership information.
 ****************************************************************/

BOOL
nt5ldap_make_domain_grp (LDAPDB * hds, DOMAIN_GRP * group,
		     DOMAIN_GRP_MEMBER ** members, int *num_membs)
{
	char **values;
	DOMAIN_GRP_MEMBER *memblist;
	int i;
	fstring grouptype;

	if (!ldapdb_peek (hds))
	{
		return False;
	}

	if (!ldapdb_get_fvalue (hds, "sAMAccountName", group->name))
	{
		DEBUG (0, ("Domain group missing sAMAccountName\n"));
		return False;
	}

	DEBUG (2, ("Retrieving domain group [%s]\n", group->name));

	if (!ldapdb_get_fvalue (hds, "groupType", grouptype))
	{
		uint32 type = strtol (grouptype, NULL, 10);
		if (!(type & (NTDS_GROUP_TYPE_GLOBAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED)))
		{
			DEBUG (0, ("Domain group has invalid groupType\n"));
			return False;
		}
	}

	if (!ldapdb_get_rid (hds, "objectSid", &group->rid))
	{
		DEBUG (0, ("Domain group missing objectSid\n"));
		return False;
	}

	if (!ldapdb_get_fvalue (hds, "description", group->comment))
	{
		group->comment[0] = 0;
	}

	group->attr = 0x7;

	if (!members || !num_membs)
	{
		return True;
	}

	if (ldapdb_get_values (hds, "member", &values) == True)
	{
		int ngroups;

		ngroups = ldap_count_values (values);

		memblist = calloc (ngroups, sizeof (DOMAIN_GRP_MEMBER));
		if (memblist == NULL)
		{
			return False;
		}

		*num_membs = 0;
		*members = memblist;

		for (i = 0; i < ngroups; i++)
		{
			if (nt5ldap_make_domain_grp_member (hds, values[i], &memblist[*num_membs]) == TRUE)
			{
				(*num_membs)++;
			}
		}
		ldap_value_free (values);
	}
	else
	{
		*num_membs = 0;
		*members = NULL;
	}

	return True;
}


/************************************************************************
  Queues the necessary modifications to save a DOMAIN_GRP structure
 ************************************************************************/

BOOL 
nt5ldap_domain_grp_mods (const DOMAIN_GRP * group, LDAPMod *** mods,
		      int operation)
{
	struct berval *bv = NULL;

	*mods = NULL;

	if (operation == LDAP_MOD_ADD)
	{
		/* immutable attributes */
		fstring temp;

		if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectClass", "top") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectClass", "group") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "objectClass", "securityPrincipal") ||
		    !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "sAMAccountName", group->name) ||
		  !ldapdb_queue_mod (mods, LDAP_MOD_ADD, "cn", group->name))
		{
			return False;
		}

		slprintf (temp, sizeof (temp) - 1, "%d", NTDS_GROUP_TYPE_GLOBAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);
		if (!ldapdb_queue_mod (mods, LDAP_MOD_ADD, "groupType", temp))
		{
			return False;
		}

		/* Put the RID in for good measure. */
		if (!ldapdb_queue_uint32_mod (mods, LDAP_MOD_ADD, "rid", group->rid) ||
		    !rid_to_berval (group->rid, &bv))
		{
			return False;
		}

		if (!ldapdb_queue_mod_len (mods, LDAP_MOD_ADD, "objectSid", bv))
		{
			ber_bvfree (bv);
			return False;
		}
	}

	return ldapdb_queue_mod (mods, operation, "description", group->comment);
}


/************************************************************************
  Create a group member entry
 ************************************************************************/

BOOL 
nt5ldap_domain_grp_member_mods (uint32 user_rid, LDAPMod *** mods, int operation, pstring member)
{
	if (ldapdb_rid_to_dn (NULL, user_rid, member) == False)
	{
		return False;
	}

	*mods = NULL;

	return ldapdb_queue_mod (mods, operation, "member", member);
}

/*
 * Parse the current entry into a SAM_USER_INFO_21 structure.
 */
BOOL nt5ldap_make_sam_user_info21(LDAPDB *hds, SAM_USER_INFO_21 *usr)
{
	struct berval *bv;
	NTDS_USER_FLAG_ENUM uac;

	if (!ldapdb_peek(hds))
	{
		return False;
	}

	memset(usr, 0, sizeof(*usr));

	(void) ldapdb_get_time(hds, "lastLogon",                      &usr->logon_time);
	(void) ldapdb_get_time(hds, "lastLogoff",                     &usr->logoff_time);
	(void) ldapdb_get_time(hds, "accountExpires",                 &usr->pass_must_change_time);
	(void) ldapdb_get_time(hds, "pwdLastSet",                     &usr->pass_last_set_time);
	/* TODO: kickoff_time */
	/* TODO: pass_must_change_time */

	if (!ldapdb_get_rid(hds, "objectSid", &usr->user_rid))
	{
		DEBUG(0,("SAM account missing objectSid\n"));
		return False;
	}

	(void) ldapdb_get_uint32(hds, "primaryGroupId", &usr->group_rid);

	if (ldapdb_get_uint32(hds, "userAccountControl", &uac))
	{
		usr->acb_info = pwdb_acct_ctrl_from_ad(uac);
	}
	else
	{
		usr->acb_info = ACB_NORMAL;
	}

	if (ldapdb_get_value_len(hds, "dBCSPwd", &bv))
	{
		if (!berval_to_unicodepwd(bv, usr->lm_pwd))
		{
			usr->acb_info |= ACB_DISABLED;
		}
		ber_bvfree(bv);
	}

	if (ldapdb_get_value_len(hds, "unicodePwd", &bv))
	{
		(void) berval_to_unicodepwd(bv, usr->nt_pwd);
		ber_bvfree(bv);
	}

	memset(usr->logon_hrs.hours, 0, sizeof(usr->logon_hrs.hours));
	usr->logon_hrs.len = 0;

	if (ldapdb_get_value_len(hds, "logonHours", &bv))
	{
		if (bv->bv_len <= sizeof(usr->logon_hrs.hours))
		{
			memcpy(usr->logon_hrs.hours, bv->bv_val, bv->bv_len);
			usr->logon_hrs.len = bv->bv_len;
		}
		ber_bvfree(bv);
	}

	usr->unknown_3 = 0x00ffffff;
	usr->logon_divs = 168;
	usr->ptr_logon_hrs = 0;
	usr->unknown_5 = 0x00020000;
	usr->unknown_6 = 0x000004ec;

	if (!ldapdb_get_unistr_value(hds, "sAMAccountName",           &usr->uni_user_name))
	{
		DEBUG(0,("SAM account missing sAMAccountName\n"));
		return False;
	}

	if (!ldapdb_get_unistr_value(hds, "displayName",              &usr->uni_full_name))
	{
		(void) ldapdb_get_unistr_value(hds, "cn",             &usr->uni_full_name);
	}

	(void) ldapdb_get_unistr_value(hds, "homeDirectory",          &usr->uni_home_dir);
	(void) ldapdb_get_unistr_value(hds, "homeDrive",              &usr->uni_dir_drive);
	(void) ldapdb_get_unistr_value(hds, "scriptPath",             &usr->uni_logon_script);
	(void) ldapdb_get_unistr_value(hds, "profilePath",            &usr->uni_profile_path);
	(void) ldapdb_get_unistr_value(hds, "description",            &usr->uni_acct_desc);
	(void) ldapdb_get_unistr_value(hds, "userWorkstations",       &usr->uni_workstations);

	return True;
}

/*
 * Parse a SAM_USER_INFO_21 structure into a set of LDAP modifications. 
 * Doesn't actually commit them to the directory. 
 */
BOOL nt5ldap_sam_user_info21_mods(const SAM_USER_INFO_21 *usr, LDAPMod ***mods, int op, 
	char *rdn, size_t rdnmaxlen, BOOL *iscomputer_p)
{
	const UNISTR2 *c_name;
	UNISTR2 uni_hostname;
	fstring upn, spn, hostname;
	struct berval *bv;

	c_name = NULL;

	if (op == LDAP_MOD_ADD)
	{
		BOOL iscomputer;
		int hostname_len;
		const char *realm = ldapdb_get_realm_name();

		unistr2_to_ascii(hostname, &usr->uni_user_name, sizeof(hostname)-1);
		hostname_len = strlen(hostname);
		iscomputer = (hostname[hostname_len - 1] == '$');

		if (iscomputer)
		{
			/* Chop '$' sign */
			hostname[hostname_len - 1] = '\0';
			slprintf(spn, sizeof(spn)-1, "host/%s", hostname);

			if (!ldapdb_queue_mod(mods, LDAP_MOD_ADD, "dNSHostName",            hostname) ||
			    !ldapdb_queue_mod(mods, LDAP_MOD_ADD, "servicePrincipalName",   spn))
			{
				return False;
			}

			if (realm)
			{
				slprintf(upn, sizeof(upn)-1, "%s@%s", spn, realm);
			}

			ascii_to_unistr(uni_hostname.buffer, hostname, sizeof(uni_hostname.buffer)-1);
			c_name = &uni_hostname;
		}
		else
		{
			if (realm)
			{
				fstring username;

				unistr2_to_ascii(username, &usr->uni_user_name, sizeof(username)-1);
				slprintf(upn, sizeof(upn)-1, "%s@%s", username, realm);
			}
		}

		if (iscomputer_p)
		{
			*iscomputer_p = iscomputer;
		}

		if (realm)
		{
#ifdef KRB5_AUTH
			char *p, *q;
#endif /* KRB5_AUTH */
			if (!ldapdb_queue_mod(mods, LDAP_MOD_ADD, "userPrincipalName", upn))
			{
				return False;
			}

#ifdef KRB5_AUTH
			p = strchr(upn, '@');
			if (p == NULL)
			{
				return False;
			}
			++p;
			for (q = p; *q != '\0'; q++)
			{
				*q = toupper(*q);
			}
			if (!ldapdb_queue_mod(mods, LDAP_MOD_ADD, "krbName",            upn) ||
			    !ldapdb_queue_mod(mods, LDAP_MOD_ADD, "krb5PrincipalName",  upn) ||
			    !ldapdb_queue_mod(mods, LDAP_MOD_ADD, "objectclass",        "kerberosSecurityObject") ||
			    !ldapdb_queue_mod(mods, LDAP_MOD_ADD, "objectclass",        "krb5Principal"))
                        {
                                return False;
                        }
#endif /* KRB5_AUTH */
		}

		if (!ldapdb_queue_mod       (mods, LDAP_MOD_ADD, "objectClass",      "top") ||
		    !ldapdb_queue_mod       (mods, LDAP_MOD_ADD, "objectClass",      "person") ||
		    !ldapdb_queue_mod       (mods, LDAP_MOD_ADD, "objectClass",      "organizationalPerson") ||
		    !ldapdb_queue_mod       (mods, LDAP_MOD_ADD, "objectClass",      "securityPrincipal") ||
		    !ldapdb_queue_mod       (mods, LDAP_MOD_ADD, "objectClass",      "user"))
		{
			return False;
		}

		if (iscomputer && !ldapdb_queue_mod(mods, LDAP_MOD_ADD, "objectClass", "computer"))
		{
			return False;
		}

	        if (!ldapdb_queue_unistr_mod(mods, LDAP_MOD_ADD, "sAMAccountName",   &usr->uni_user_name))
		{
			return False;
		}

		if (!rid_to_berval(usr->user_rid, &bv))
		{
			return False;
		}
		if (!ldapdb_queue_mod_len   (mods, LDAP_MOD_ADD, "objectSid",        bv))
		{
			ber_bvfree(bv);
			return False;
		}

		if (!ldapdb_queue_uint32_mod(mods, LDAP_MOD_ADD, "primaryGroupId",   usr->group_rid))
		{
			return False;
		}

	}

	if (c_name == NULL)
	{	
		c_name = usr->uni_full_name.uni_str_len ? &usr->uni_full_name : &usr->uni_user_name;
	}

	if (rdn)
	{
		unistr2_to_ascii(rdn, c_name, rdnmaxlen);
	}

	if (!ldapdb_queue_unistr_mod(mods, op, "cn",               c_name) ||
	    !ldapdb_queue_unistr_mod(mods, op, "name",             c_name) ||
	    !ldapdb_queue_unistr_mod(mods, op, "displayName",      c_name) ||
	    !ldapdb_queue_unistr_mod(mods, op, "homeDirectory",    &usr->uni_home_dir) ||
	    !ldapdb_queue_unistr_mod(mods, op, "homeDrive",        &usr->uni_dir_drive) ||
	    !ldapdb_queue_unistr_mod(mods, op, "scriptPath",       &usr->uni_logon_script) ||
	    !ldapdb_queue_unistr_mod(mods, op, "profilePath",      &usr->uni_profile_path) ||
	    !ldapdb_queue_unistr_mod(mods, op, "description",      &usr->uni_acct_desc) ||
	    !ldapdb_queue_unistr_mod(mods, op, "userWorkstations", &usr->uni_workstations) ||
	    !ldapdb_queue_time      (mods, op, "lastLogon",        &usr->logon_time) ||
	    !ldapdb_queue_time      (mods, op, "lastLogoff",       &usr->logoff_time) ||
		/* kickoff_time */
	    !ldapdb_queue_time      (mods, op, "pwdLastSet",       &usr->pass_last_set_time) ||
		/* pass_can_change_time */
	    !ldapdb_queue_time      (mods, op, "accountExpires",   &usr->pass_must_change_time))
	{
		return False;
	}

	if (dbcspwd_to_berval(usr->lm_pwd, &bv))
	{
		if (!ldapdb_queue_mod_len(mods, op, "dBCSPwd",     bv))
		{
			ber_bvfree(bv);
			return False;
		}
	}

	if (unicodepwd_to_berval(usr->nt_pwd, &bv))
	{
		if (!ldapdb_queue_mod_len(mods, op, "unicodePwd", bv))
		{
			ber_bvfree(bv);
			return False;
		}
	}

	if (usr->logon_hrs.len)
	{
		bv = (struct berval *)malloc(sizeof(*bv));
		if (bv == NULL)
		{
			return False;
		}
		bv->bv_len = usr->logon_hrs.len;
		bv->bv_val = malloc(usr->logon_hrs.len);
		if (bv->bv_val == NULL)
		{
			free(bv);
			return False;
		}
	
		memcpy(bv->bv_val, usr->logon_hrs.hours, bv->bv_len);
		if (!ldapdb_queue_mod_len(mods, op, "logonHours", bv))
		{
			ber_bvfree(bv);
			return False;
		}
	}

	return ldapdb_queue_uint32_mod(mods, op, "userAccountControl", pwdb_acct_ctrl_to_ad(usr->acb_info));
}


/***************************************************************
  Enumerate RIDs of groups which user is a member of, of type
  given by attribute.
 ****************************************************************/

BOOL 
nt5ldap_make_group_rids (LDAPDB * _hds, const char *dn, uint32 ** rids, int *numrids, uint32 req_type)
{
	LDAPDB_DECLARE_HANDLE (hds);
	pstring filter;
	int i, ngroups;

	if (!LDAPDB_OPEN (_hds, &hds))
	{
		ldapdb_close (&hds);
		return False;
	}

	slprintf (filter, sizeof (filter) - 1, "(&(objectClass=Group)(member=%s)(groupType=%d))",
		  dn, req_type | NTDS_GROUP_TYPE_SECURITY_ENABLED);
	(void) ldapdb_set_synchronous (hds, True);
	if (!ldapdb_search (hds, NULL, filter, NULL, LDAP_NO_LIMIT) ||
	    !ldapdb_count_entries (hds, &ngroups))
	{
		ldapdb_close (&hds);
		return False;
	}

	*rids = (uint32 *) calloc (ngroups, sizeof (uint32));
	if (*rids == NULL)
	{
		ldapdb_close (&hds);
		return False;
	}

	*numrids = 0;
	for (i = 0; i < ngroups; i++)
	{
		if (ldapdb_get_rid (hds, "objectSid", &(*rids)[i]) == True)
		{
			(*numrids)++;
		}
		if (!ldapdb_seq (hds))
		{
			break;
		}
	}
	ldapdb_close (&hds);

	return True;
}
#endif /* WITH_NT5LDAP */

