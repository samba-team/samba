/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - user related function

   Copyright (C) Jim McDonough <jmcd@us.ibm.com>      2003
   
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

#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

#ifdef HAVE_LDAP

#include <lber.h>
#include <ldap.h>

#include "smb_ldap.h"

/* Globals */
static struct smb_ldap_privates *ldap_state;

static const char *attr[] = { "uid", "rid", "domain", "uidNumber", 
			      "gidNumber", NULL };

static const char *pool_attr[] = {"uidNumber", "gidNumber", "cn", NULL};

static const char *group_attr[] = {"gidNumber", "ntSid", NULL};

static long ldap_allocate_id(BOOL is_user)
{
	int rc, count;
	LDAPMessage *result;
	int scope = LDAP_SCOPE_SUBTREE;
	long ret = 0;
	int sanity = 0;

	do {
		rc = smb_ldap_search(ldap_state, lp_ldap_suffix(), scope, is_user?"cn=UID Pool":"cn=GID Pool", pool_attr, 0, &result);

		if (LDAP_SUCCESS != rc) {
			DEBUG(0,("ldap_allocate_id: No ID pool found in directory\n"));
			return 0;
		}
		
		count = ldap_count_entries(ldap_state->ldap_struct, result);
		
		if (1 < count) {
			DEBUG(0,("ldap_allocate_id: Multiple UID pools found in directory?\n"));
			break;
		} else if (1 == count) {
			LDAPMessage *entry = 
				ldap_first_entry(ldap_state->ldap_struct, 
						 result);
			LDAPMod **mods = NULL;
			pstring temp;
			
			if (!smb_ldap_get_single_attribute(ldap_state->ldap_struct, entry, is_user?"uidNumber":"gidNumber", temp)) {
				return False;
			}
			ret = atol(temp);
			smb_ldap_make_a_mod(&mods, LDAP_MOD_DELETE, 
					    is_user?"uidNumber":"gidNumber",
					    temp);
			slprintf(temp, sizeof(temp) - 1, "%ld", ret + 1);
			smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, is_user?"uidNumber":"gidNumber", temp);
			slprintf(temp, sizeof(temp) - 1, "cn=%cID Pool,%s", is_user?'U':'G', lp_ldap_user_suffix());
			rc = smb_ldap_modify(ldap_state, temp, mods);
			ldap_mods_free(mods, 1);
		} else {
			DEBUG(0,("ldap_allocate_id: unexpected number of entries returned\n"));
			break;
		}
	} while (LDAP_NO_SUCH_ATTRIBUTE == rc && ++sanity < 100);

	return ret;
}

/*****************************************************************************
 Initialise idmap database. 
*****************************************************************************/
static BOOL ldap_idmap_init(void)
{
	static struct smb_ldap_privates state;
	ldap_state = &state;

#ifdef WITH_LDAP_SAMCONFIG
	{
		int ldap_port = lp_ldap_port();

		/* remap default port if not using SSL */
		if (lp_ldap_ssl() != LDAP_SSL_ON && ldap_port == 636) {
			ldap_port = 389;
		}

		ldap_state->uri = asprintf("%s://%s:d", 
					   lp_ldap_ssl() == LDAP_SSL_ON ? "ldaps" : "ldap", 
					   lp_ldap_server(), ldap_port);
		if (!ldap_state->uri) {
			DEBUG(0,("Out of memory\n"));
			return False;
		}
	}
#else
	ldap_state->uri = "ldap://localhost";
#endif
	return True;
}

static BOOL ldap_get_sid_from_uid(uid_t uid, DOM_SID * sid)
{
	pstring filter;
	int scope = LDAP_SCOPE_SUBTREE;
	int rc, count;
	LDAPMessage *result;

	slprintf(filter, sizeof(filter) - 1, "uidNumber=%i", uid);

	DEBUG(2, ("ldap_get_sid_from_uid: searching for:[%s]\n", filter));

	rc = smb_ldap_search(ldap_state, lp_ldap_suffix(), scope, filter, attr, 0, &result);
	if (LDAP_SUCCESS != rc) {
		DEBUG(0,("ldap_get_sid_from_uid: user search failed\n"));
		return False;
	}
	
	count = ldap_count_entries(ldap_state->ldap_struct, result);
	if (1 < count) {
		DEBUG(0,("More than one user exists where: %s\n", filter));
		ldap_msgfree(result);
		return False;
	} else if (1 == count) {
		/* we found the user, get the users RID */
		LDAPMessage *entry = ldap_first_entry(ldap_state->ldap_struct, 
						      result);
		pstring temp, domain;
		uint32 rid;
		struct winbindd_domain *wb_dom;

		if (!smb_ldap_get_single_attribute(ldap_state->ldap_struct, entry, "domain", domain)) {
			return False;
		}
		if (!smb_ldap_get_single_attribute(ldap_state->ldap_struct, entry, "rid", temp)) {
			return False;
		}
		rid = (uint32)atol(temp);
		wb_dom = find_domain_from_name(domain);

		if (!wb_dom) {
			DEBUG(0,("ldap_get_sid_from_uid: could not find domain %s\n", domain));
			return False;
		}

		sid_copy(sid, &wb_dom->sid);
		sid_append_rid(sid, rid);
	} else {
		/* 0 entries? that ain't right */
		DEBUG(0,("ldap_get_sid_from_uid: not user entry found for %s\n", filter));
	}

	return True;
}

static BOOL ldap_get_uid_from_sid(DOM_SID *sid, uid_t *uid)
{
	pstring filter;
	int scope = LDAP_SCOPE_SUBTREE;
	int rc, count;
	LDAPMessage *result;
	uint32 rid = 0;
	struct winbindd_domain *wb_dom;
	DOM_SID dom_sid;

	sid_copy(&dom_sid, sid);

	if (!sid_split_rid(&dom_sid, &rid)) {
		DEBUG(0,("ldap_get_uid_from_sid: sid does not contain an rid\n"));
		return False;
	}

	if (!(wb_dom = find_domain_from_sid(&dom_sid))) {
		DEBUG(0,("ldap_get_uid_from_sid: cannot lookup domain from sid\n"));
		return False;
	}

	slprintf(filter, sizeof(filter) - 1, "rid=%d,domain=%s,objectClass=sambaAccount", rid, wb_dom->name);

	DEBUG(2, ("ldap_get_uid_from_sid: searching for:[%s]\n", filter));

	rc = smb_ldap_search(ldap_state, lp_ldap_suffix(), scope, filter, attr, 0, &result);
	if (LDAP_NO_SUCH_OBJECT == rc) {
		LDAPMod **mods = NULL;
		pstring temp;
		fstring dom, name;
		int sid_type;

		winbindd_lookup_name_by_sid(sid, dom, name, 
					    (enum SID_USE_TYPE *)&sid_type);
		slprintf(temp, sizeof(temp) - 1, "%i", rid);
		smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, "rid", temp);

		*uid = ldap_allocate_id(True);
		slprintf(temp, sizeof(temp) - 1, "%i", *uid);
		smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, "uidNumber", temp);

		smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, "uid", name);
		smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, "objectClass", "sambaAccount");
		smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, "objectClass", "account");
		slprintf(temp, sizeof(temp) - 1, "uid=%s,%s", name, lp_ldap_user_suffix());
		rc = smb_ldap_modify(ldap_state, temp, mods);

		ldap_mods_free(mods, 1);
		if (LDAP_SUCCESS != rc) {
			return False;
		}
	} else if (LDAP_SUCCESS == rc) {
		count = ldap_count_entries(ldap_state->ldap_struct, result);
		if (1 < count) {
			DEBUG(0,("More than one user exists where: %s\n", filter));
			ldap_msgfree(result);
			return False;
		} else if (1 == count) {
			/* we found the user, get the idNumber */
			LDAPMessage *entry = ldap_first_entry(ldap_state->ldap_struct, result);
			pstring temp;
			
			if (!smb_ldap_get_single_attribute(ldap_state->ldap_struct, entry, "uidNumber", temp)) {
				return False;
			}
			*uid = atol(temp);
		} else {
			DEBUG(0,("ldap_get_uid_from_sid: zero entries returned?\n"));
			return False;
		}
	} else {
		DEBUG(0,("ldap_get_uid_from_sid: unknown error querying user info\n"));
		return False;
	}
			   
	return True;
}

static BOOL ldap_get_sid_from_gid(gid_t gid, DOM_SID * sid)
{
	pstring filter;
	int scope = LDAP_SCOPE_SUBTREE;
	int rc, count;
	LDAPMessage *result;

	slprintf(filter, sizeof(filter) - 1, "gidNumber=%i,objectClass=sambaGroupMapping", gid);

	DEBUG(2, ("ldap_get_sid_from_gid: searching for:[%s]\n", filter));

	rc = smb_ldap_search(ldap_state, lp_ldap_suffix(), scope, filter, attr, 0, &result);
	if (LDAP_SUCCESS != rc) {
		DEBUG(0,("ldap_get_sid_from_gid: user search failed\n"));
		return False;
	}
	
	count = ldap_count_entries(ldap_state->ldap_struct, result);
	if (1 < count) {
		DEBUG(0,("More than one group exists where: %s\n", filter));
		ldap_msgfree(result);
		return False;
	} else if (1 == count) {
		LDAPMessage *entry = ldap_first_entry(ldap_state->ldap_struct, 
						      result);
		pstring str_sid;

		if (!smb_ldap_get_single_attribute(ldap_state->ldap_struct, entry, "ntSid", str_sid)) {
			return False;
		}

		string_to_sid(sid, str_sid);
	} else {
		/* 0 entries? that ain't right */
		DEBUG(0,("ldap_get_sid_from_gid: not group entry found for %s\n", filter));
	}

	return True;
}

static BOOL ldap_get_gid_from_sid(DOM_SID *sid, gid_t *gid)
{
	pstring filter;
	int scope = LDAP_SCOPE_SUBTREE;
	int rc, count;
	LDAPMessage *result;
	fstring str_sid;

	sid_to_string(str_sid, sid);

	slprintf(filter, sizeof(filter) - 1, "ntSid=%s,objectClass=sambaGroupMapping", str_sid);

	DEBUG(2, ("ldap_get_gid_from_sid: searching for:[%s]\n", filter));

	rc = smb_ldap_search(ldap_state, lp_ldap_suffix(), scope, filter, attr, 0, &result);
	if (LDAP_NO_SUCH_OBJECT == rc) {
		LDAPMod **mods = NULL;
		pstring temp;

		*gid = ldap_allocate_id(False);
		slprintf(temp, sizeof(temp) - 1, "%i", *gid);
		smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, "gidNumber", temp);
		smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, "objectClass", "sambaGroupMapping");
		smb_ldap_make_a_mod(&mods, LDAP_MOD_ADD, "objectClass", "account");
		slprintf(temp, sizeof(temp) - 1, "gidNumber=%i,%s", *gid, lp_ldap_user_suffix());
		rc = smb_ldap_modify(ldap_state, temp, mods);

		ldap_mods_free(mods, 1);
		if (LDAP_SUCCESS != rc) {
			return False;
		}
	} else if (LDAP_SUCCESS == rc) {
		count = ldap_count_entries(ldap_state->ldap_struct, result);
		if (1 < count) {
			DEBUG(0,("More than one group exists where: %s\n", filter));
			ldap_msgfree(result);
			return False;
		} else if (1 == count) {
			LDAPMessage *entry = ldap_first_entry(ldap_state->ldap_struct, result);
			pstring temp;
			
			if (!smb_ldap_get_single_attribute(ldap_state->ldap_struct, entry, "gidNumber", temp)) {
				return False;
			}
			*gid = atol(temp);
		} else {
			DEBUG(0,("ldap_get_gid_from_sid: zero entries returned?\n"));
			return False;
		}
	} else {
		DEBUG(0,("ldap_get_gid_from_sid: unknown error querying user info\n"));
		return False;
	}
			   
	return True;
}

static BOOL ldap_idmap_close(void)
{
	smb_ldap_close(ldap_state);
	ldap_state = 0;
	return True;
}

static void ldap_idmap_status(void)
{
	DEBUG(0, ("winbindd idmap status:\n"));
	DEBUG(0, ("Using LDAP\n"));
}

struct winbindd_idmap_methods ldap_idmap_methods = {
	ldap_idmap_init,

	ldap_get_sid_from_uid,
	ldap_get_sid_from_gid,

	ldap_get_uid_from_sid,
	ldap_get_gid_from_sid,

	ldap_idmap_close,

	ldap_idmap_status
};

#endif

BOOL winbind_idmap_reg_ldap(struct winbindd_idmap_methods **meth)
{
#ifdef HAVE_LDAP
	*meth = &ldap_idmap_methods;

	return True;
#else
	DEBUG(0,("winbind_idmap_reg_ldap: LDAP support not compiled\n"));
	return False;
#endif
}
