#ifdef USE_LDAP

#include "includes.h"
#include "lber.h"
#include "ldap.h"

extern int DEBUGLEVEL;

/*******************************************************************
 find a user or a machine return a smbpass struct.
******************************************************************/
static void make_ldap_sam_user_info_21(LDAP *ldap_struct, LDAPMessage *entry, SAM_USER_INFO_21 *user)
{
	pstring cn;
	pstring fullname;
	pstring home_dir;
	pstring dir_drive;
	pstring logon_script;
	pstring profile_path;
	pstring acct_desc;
	pstring workstations;
	pstring temp;
	
	if (ldap_check_user(ldap_struct, entry)==True)
	{
		get_single_attribute(ldap_struct, entry, "cn", cn);
		get_single_attribute(ldap_struct, entry, "userFullName", fullname);
		get_single_attribute(ldap_struct, entry, "homeDirectory", home_dir);
		get_single_attribute(ldap_struct, entry, "homeDrive", dir_drive);
		get_single_attribute(ldap_struct, entry, "scriptPath", logon_script);
		get_single_attribute(ldap_struct, entry, "profilePath", profile_path);
		get_single_attribute(ldap_struct, entry, "comment", acct_desc);
		get_single_attribute(ldap_struct, entry, "userWorkstations", workstations);

		get_single_attribute(ldap_struct, entry, "rid", temp);
		user->user_rid=atoi(temp);
		get_single_attribute(ldap_struct, entry, "primaryGroupID", temp);
		user->group_rid=atoi(temp);
		get_single_attribute(ldap_struct, entry, "controlAccessRights", temp);
		user->acb_info=atoi(temp);
		
		make_unistr2(&(user->uni_user_name), cn, strlen(cn));
                make_uni_hdr(&(user->hdr_user_name), strlen(cn), strlen(cn), 1);		
		make_unistr2(&(user->uni_full_name), fullname, strlen(fullname));
                make_uni_hdr(&(user->hdr_full_name), strlen(fullname), strlen(fullname), 1);		
		make_unistr2(&(user->uni_home_dir), home_dir, strlen(home_dir));
                make_uni_hdr(&(user->hdr_home_dir), strlen(home_dir), strlen(home_dir), 1);
		make_unistr2(&(user->uni_dir_drive), dir_drive, strlen(dir_drive));
                make_uni_hdr(&(user->hdr_dir_drive), strlen(dir_drive), strlen(dir_drive), 1);		
		make_unistr2(&(user->uni_logon_script), logon_script, strlen(logon_script));
                make_uni_hdr(&(user->hdr_logon_script), strlen(logon_script), strlen(logon_script), 1);
		make_unistr2(&(user->uni_profile_path), profile_path, strlen(profile_path));
                make_uni_hdr(&(user->hdr_profile_path), strlen(profile_path), strlen(profile_path), 1);
		make_unistr2(&(user->uni_acct_desc), acct_desc, strlen(acct_desc));
                make_uni_hdr(&(user->hdr_acct_desc), strlen(acct_desc), strlen(acct_desc), 1);
		make_unistr2(&(user->uni_workstations), workstations, strlen(workstations));
                make_uni_hdr(&(user->hdr_workstations), strlen(workstations), strlen(workstations), 1);		
	}
}

/*******************************************************************
 find a user or a machine return a smbpass struct.
******************************************************************/
BOOL get_ldap_entries(SAM_USER_INFO_21 *pw_buf,
                      int *total_entries, int *num_entries,
                      int max_num_entries,
                      uint16 acb_mask, int switch_level)
{
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	
	int scope = LDAP_SCOPE_ONELEVEL;
	int rc;

	char filter[256];

	(*num_entries) = 0;
        (*total_entries) = 0;

	if (!ldap_open_connection(&ldap_struct)) /* open a connection to the server */
		return (False);

	if (!ldap_connect_system(ldap_struct)) /* connect as system account */
		return (False);


	/* when the class is known the search is much faster */
	switch (switch_level)
	{
		case 1:  strcpy(filter, "objectclass=sambaAccount");
			 break;
		case 2:  strcpy(filter, "objectclass=sambaMachine");
			 break;
		default: strcpy(filter, "(|(objectclass=sambaMachine)(objectclass=sambaAccount))");
			 break;
	}

	rc=ldap_search_s(ldap_struct, lp_ldap_suffix(), scope, filter, NULL, 0, &result);

	DEBUG(2,("%d entries in the base!\n", ldap_count_entries(ldap_struct, result) ));

	for ( entry = ldap_first_entry(ldap_struct, result); 
	      (entry != NULL) && (*num_entries) < max_num_entries; 
	      entry = ldap_next_entry(ldap_struct, entry) )
	{
		make_ldap_sam_user_info_21(ldap_struct, entry, &(pw_buf[(*num_entries)]) );
	
		if (acb_mask == 0 || IS_BITS_SET_SOME(pw_buf[(*num_entries)].acb_info, acb_mask))
                {
                        DEBUG(5,(" acb_mask %x accepts\n", acb_mask));
                        (*num_entries)++;
                }
                else
                {
                        DEBUG(5,(" acb_mask %x rejects\n", acb_mask));
                }

                (*total_entries)++;
	}
	
	ldap_msgfree(result);
	ldap_unbind(ldap_struct);
	return (*num_entries) > 0;
}

BOOL ldap_get_user_info_21(SAM_USER_INFO_21 *id21, uint32 rid)
{
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;

	if (!ldap_open_connection(&ldap_struct))
		return (False);
	if (!ldap_connect_system(ldap_struct))
		return (False);
		
	if (!ldap_search_one_user_by_uid(ldap_struct, rid, &result))
		return (False);

	if (ldap_count_entries(ldap_struct, result) == 0)
	{
		DEBUG(2,("%s: Non existant user!\n", timestring() ));
		return (False);	
	}
		
	if (ldap_count_entries(ldap_struct, result) > 1)
	{
		DEBUG(2,("%s: Strange %d users in the base!\n",
		         timestring(), ldap_count_entries(ldap_struct, result) ));
	}
	/* take the first and unique entry */
	entry=ldap_first_entry(ldap_struct, result);
	
	make_ldap_sam_user_info_21(ldap_struct, entry, id21);
			
	ldap_msgfree(result);
	ldap_unbind(ldap_struct);
	return(True);	
}

#endif
