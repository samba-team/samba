/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001-2003
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002-2003
   Copyright (C) Stefan (metze) Metzmacher	2002-2003
    
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
#include "smbldap.h"

/**********************************************************************
 Add the sambaDomain to LDAP, so we don't have to search for this stuff
 again.  This is a once-add operation for now.

 TODO:  Add other attributes, and allow modification.
*********************************************************************/
static NTSTATUS add_new_domain_info(struct smbldap_state *ldap_state, 
                                    const char *domain_name) 
{
	fstring sid_string;
	fstring algorithmic_rid_base_string;
	pstring filter, dn;
	LDAPMod **mods = NULL;
	int rc;
	int ldap_op;
	LDAPMessage *result = NULL;
	int num_result;
	char **attr_list;
	uid_t u_low, u_high;
	gid_t g_low, g_high;
	uint32 rid_low, rid_high;

	slprintf (filter, sizeof (filter) - 1, "(&(%s=%s)(objectclass=%s))", 
		  get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		  domain_name, LDAP_OBJ_DOMINFO);

	attr_list = get_attr_list( dominfo_attr_list );
	rc = smbldap_search_suffix(ldap_state, filter, attr_list, &result);
	free_attr_list( attr_list );

	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	num_result = ldap_count_entries(ldap_state->ldap_struct, result);
	
	if (num_result > 1) {
		DEBUG (0, ("More than domain with that name exists: bailing out!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	/* Check if we need to add an entry */
	DEBUG(3,("Adding new domain\n"));
	ldap_op = LDAP_MOD_ADD;

	pstr_sprintf(dn, "%s=%s,%s", get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN),
		domain_name, lp_ldap_suffix());

	/* Free original search */
	ldap_msgfree(result);

	/* make the changes - the entry *must* not already have samba attributes */
	smbldap_set_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		domain_name);

	/* If we don't have an entry, then ask secrets.tdb for what it thinks.  
	   It may choose to make it up */

	sid_to_string(sid_string, get_global_sam_sid());
	smbldap_set_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOM_SID), sid_string);

	slprintf(algorithmic_rid_base_string, sizeof(algorithmic_rid_base_string) - 1, "%i", algorithmic_rid_base());
	smbldap_set_mod(&mods, LDAP_MOD_ADD, get_attr_key2string(dominfo_attr_list, LDAP_ATTR_ALGORITHMIC_RID_BASE), 
			algorithmic_rid_base_string);
	smbldap_set_mod(&mods, LDAP_MOD_ADD, "objectclass", LDAP_OBJ_DOMINFO);
	
	/* add the sambaNext[User|Group]Rid attributes if the idmap ranges are set.
	   TODO: fix all the places where the line between idmap and normal operations
	   needed by smbd gets fuzzy   --jerry 2003-08-11                              */
	
	if ( lp_idmap_uid(&u_low, &u_high) && lp_idmap_gid(&g_low, &g_high)
		&& get_free_rid_range(&rid_low, &rid_high) ) 
	{
		fstring rid_str;
		
		fstr_sprintf( rid_str, "%i", rid_high|USER_RID_TYPE );
		DEBUG(10,("setting next available user rid [%s]\n", rid_str));
		smbldap_set_mod(&mods, LDAP_MOD_ADD, 
			get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_USERRID), 
			rid_str);
			
		fstr_sprintf( rid_str, "%i", rid_high|GROUP_RID_TYPE );
		DEBUG(10,("setting next available group rid [%s]\n", rid_str));
		smbldap_set_mod(&mods, LDAP_MOD_ADD, 
			get_attr_key2string(dominfo_attr_list, LDAP_ATTR_NEXT_GROUPRID), 
			rid_str);
		
        }


	switch(ldap_op)
	{
	case LDAP_MOD_ADD: 
		rc = smbldap_add(ldap_state, dn, mods);
		break;
	case LDAP_MOD_REPLACE: 
		rc = smbldap_modify(ldap_state, dn, mods);
		break;
	default: 	
		DEBUG(0,("Wrong LDAP operation type: %d!\n", ldap_op));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	if (rc!=LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG(1,("failed to %s domain dn= %s with: %s\n\t%s\n",
		       ldap_op == LDAP_MOD_ADD ? "add" : "modify",
		       dn, ldap_err2string(rc),
		       ld_error?ld_error:"unknown"));
		SAFE_FREE(ld_error);

		ldap_mods_free(mods, True);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2,("added: domain = %s in the LDAP database\n", domain_name));
	ldap_mods_free(mods, True);
	return NT_STATUS_OK;
}

/**********************************************************************
Search for the domain info entry
*********************************************************************/
NTSTATUS smbldap_search_domain_info(struct smbldap_state *ldap_state,
                                    LDAPMessage ** result, const char *domain_name,
                                    BOOL try_add)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	pstring filter;
	int rc;
	char **attr_list;
	int count;

	pstr_sprintf(filter, "(&(objectClass=%s)(%s=%s))",
		LDAP_OBJ_DOMINFO,
		get_attr_key2string(dominfo_attr_list, LDAP_ATTR_DOMAIN), 
		domain_name);

	DEBUG(2, ("Searching for:[%s]\n", filter));


	attr_list = get_attr_list( dominfo_attr_list );
	rc = smbldap_search_suffix(ldap_state, filter, attr_list , result);
	free_attr_list( attr_list );

	if (rc != LDAP_SUCCESS) {
		DEBUG(2,("Problem during LDAPsearch: %s\n", ldap_err2string (rc)));
		DEBUG(2,("Query was: %s, %s\n", lp_ldap_suffix(), filter));
	} else if (ldap_count_entries(ldap_state->ldap_struct, *result) < 1) {
		DEBUG(3, ("Got no domain info entries for domain\n"));
		ldap_msgfree(*result);
		*result = NULL;
		if (try_add && NT_STATUS_IS_OK(ret = add_new_domain_info(ldap_state, domain_name))) {
			return smbldap_search_domain_info(ldap_state, result, domain_name, False);
		} 
		else {
			DEBUG(0, ("Adding domain info for %s failed with %s\n", 
				domain_name, nt_errstr(ret)));
			return ret;
		}
	} else if ((count = ldap_count_entries(ldap_state->ldap_struct, *result)) > 1) {
		DEBUG(0, ("Got too many (%d) domain info entries for domain %s\n",
			  count, domain_name));
		ldap_msgfree(*result);
		*result = NULL;
		return ret;
	} else {
		return NT_STATUS_OK;
	}
	
	return ret;
}

