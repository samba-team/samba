/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Sander Striker               2000
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"
#include "nterr.h"
#include "rpc_parse.h"
#include "ldapdb.h"
#include "sids.h"

extern int DEBUGLEVEL;

/*******************************************************************
 samr_reply_open_domain
 ********************************************************************/
uint32 _samr_open_domain(const POLICY_HND *connect_pol,
				uint32 ace_perms,
				const DOM_SID *sid,
				POLICY_HND *domain_pol)
{
	LDAPDB *hds = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_nt5ldapsam(get_global_hnd_cache(), connect_pol, &hds))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd_link(get_global_hnd_cache(),
		connect_pol, domain_pol, ace_perms))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!ldapdb_open(&hds))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* associate the domain SID with the (unique) handle. */
	if (!set_nt5ldapdomsid(get_global_hnd_cache(), domain_pol, hds, sid))
	{
		ldapdb_close(&hds);
		close_policy_hnd(get_global_hnd_cache(), domain_pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(5,("_samr_open_domain: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_enum_dom_users
 ********************************************************************/
uint32 _samr_enum_dom_users(  const POLICY_HND *pol, uint32 *start_idx, 
				uint16 acb_mask, uint16 unk_1, uint32 size,
				SAM_ENTRY **sam,
				UNISTR2 **uni_acct_name,
				uint32 *num_sam_users)
{
	LDAPDB *hds = NULL;
	char *attrs[] = {
		"objectSid",
		"sAMAccountName",
		"dBCSPwd",
		"unicodePwd",
		"userAccountFlags"
	};
	int num_sam_entries;

	/* find the domain sid associated with the policy handle */
	if (!get_nt5ldapsid(get_global_hnd_cache(), pol, &hds))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_users:\n"));

	(void) ldapdb_set_synchronous(hds, True);

	if (!ldapdb_search(hds, NULL, "(objectClass=User)", attrs, LDAP_NO_LIMIT))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!ldapdb_count_entries(hds, &num_sam_entries))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	(*sam) = (SAM_ENTRY *)Realloc(NULL, num_sam_entries * sizeof((*sam)[0]));
	if (*sam == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	(*uni_acct_name) = (UNISTR2 *)Realloc(NULL, num_sam_entries * sizeof((*uni_acct_name)[0]));
	if (*uni_acct_name == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	*num_sam_users = 0;

	do
	{
		SAM_USER_INFO_21 pass;

		if (nt5ldap_make_sam_user_info_21(hds, &pass))
		{
			make_sam_entry(&((*sam)[*num_sam_users]), pass.uni_user_name.uni_str_len, pass.user_rid);
			copy_unistr2(&((*uni_acct_name)[*num_sam_users]), &(pass.uni_user_name));
			(*num_sam_users)++;
		}
	}
	while (ldapdb_seq(hds));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_enum_dom_groups
 ********************************************************************/
uint32 _samr_enum_dom_groups(const POLICY_HND *pol,
				uint32 *start_idx, uint32 size,
				SAM_ENTRY **sam,
				UNISTR2 **uni_acct_name,
				uint32 *num_sam_groups)
{
	LDAPDB *hds = NULL;
	char *attrs[] = {
		"objectSid",
		"sAMAccountName",
		"groupType"
	};
	int num_sam_entries;
	fstring filter;

	/* find the domain sid associated with the policy handle */
	if (!get_nt5ldapsid(get_global_hnd_cache(), pol, &hds))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_dom_groups:\n"));

	(void) ldapdb_set_synchronous(hds, True);

	slprintf(filter, sizeof(filter)-1, "(&(objectClass=Group)(groupType=%d))",
		NTDS_GROUP_TYPE_GLOBAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);

	if (!ldapdb_search(hds, NULL, filter, attrs, LDAP_NO_LIMIT))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!ldapdb_count_entries(hds, &num_sam_entries))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	(*sam) = (SAM_ENTRY *)Realloc(NULL, num_sam_entries * sizeof((*sam)[0]));
	if (*sam == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	(*uni_acct_name) = (UNISTR2 *)Realloc(NULL, num_sam_entries * sizeof((*uni_acct_name)[0]));
	if (*uni_acct_name == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	*num_sam_groups = 0;

	do
	{
		DOMAIN_GRP group;

		if (nt5ldap_make_domain_grp(hds, &group, NULL, NULL))
		{
			int len = strlen(group.name);

			make_sam_entry(&((*sam)[*num_sam_groups]), len, group.rid);
			make_unistr2(&((*uni_acct_name)[*num_sam_groups]), group.name, len);
			(*num_sam_groups)++;
		}
	}
	while (ldapdb_seq(hds));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_enum_dom_aliases
 ********************************************************************/
uint32 _samr_enum_dom_aliases(const POLICY_HND *pol,
					uint32 *start_idx, uint32 size,
					SAM_ENTRY **sam,
					UNISTR2 **uni_acct_name,
					uint32 *num_sam_aliases)
{
	LDAPDB *hds = NULL;
	char *attrs[] = {
		"objectSid",
		"sAMAccountName",
		"groupType"
	};
	int num_sam_entries;
	fstring filter;

	/* find the domain sid associated with the policy handle */
	if (!get_nt5ldapsid(get_global_hnd_cache(), pol, &hds))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_aliases:\n"));

	(void) ldapdb_set_synchronous(hds, True);

	slprintf(filter, sizeof(filter)-1, "(&(objectClass=Group)(groupType=%d))",
		NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP | NTDS_GROUP_TYPE_SECURITY_ENABLED);

	if (!ldapdb_search(hds, NULL, "(objectClass=User)", attrs, LDAP_NO_LIMIT))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!ldapdb_count_entries(hds, &num_sam_entries))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	(*sam) = (SAM_ENTRY *)Realloc(NULL, num_sam_entries * sizeof((*sam)[0]));
	if (*sam == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	(*uni_acct_name) = (UNISTR2 *)Realloc(NULL, num_sam_entries * sizeof((*uni_acct_name)[0]));
	if (*uni_acct_name == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	*num_sam_aliases = 0;

	do
	{
		LOCAL_GRP group;

		if (nt5ldap_make_local_grp(hds, &group, NULL, NULL, 0))
		{
			int len = strlen(group.name);

			make_sam_entry(&((*sam)[*num_sam_aliases]), len, group.rid);
			make_unistr2(&((*uni_acct_name)[*num_sam_aliases]), group.name, len);
			(*num_sam_aliases)++;
		}
	}
	while (ldapdb_seq(hds));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_query_dispinfo
 ********************************************************************/
uint32 _samr_query_dispinfo(  const POLICY_HND *domain_pol, uint16 level,
					uint32 start_idx,
					uint32 max_entries,
					uint32 max_size,
					uint32 *data_size,
					uint32 *num_entries,
					SAM_DISPINFO_CTR *ctr)
{
	uint16 acb_mask = ACB_NORMAL;
	int num_sam_entries = 0;
	LDAPDB *hds = NULL;
	DOM_SID sid;
	/* XXX Unifnished */
	SAM_USER_INFO_21 *pass = NULL;
	DOMAIN_GRP *grps = NULL;

	/* find the domain sid associated with the policy handle */
	if (!get_nt5ldapsid(get_global_hnd_cache(), domain_pol, &hds))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid associated with the policy handle */
	if (!get_nt5ldapdomsid(get_global_hnd_cache(), domain_pol, &hds, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));

	(*num_entries) = 0;
	(*data_size) = 0;

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), domain_pol) == -1)
	{
		DEBUG(5,("samr_reply_query_dispinfo: invalid handle\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	/* Now create reply structure */
	switch (level)
	{
		case 0x1:
		{
			ctr->sam.info1 = malloc(sizeof(SAM_DISPINFO_1));
			make_sam_dispinfo_1(ctr->sam.info1,
					    num_entries, data_size,
					    start_idx, pass);
			break;
		}
		case 0x2:
		{
			ctr->sam.info2 = malloc(sizeof(SAM_DISPINFO_2));
			make_sam_dispinfo_2(ctr->sam.info2,
					    num_entries, data_size,
					    start_idx, pass);
			break;
		}
		case 0x3:
		{
			ctr->sam.info3 = malloc(sizeof(SAM_DISPINFO_3));
			make_sam_dispinfo_3(ctr->sam.info3,
					    num_entries, data_size,
					    start_idx, grps);
			break;
		}
		case 0x4:
		{
			ctr->sam.info4 = malloc(sizeof(SAM_DISPINFO_4));
			make_sam_dispinfo_4(ctr->sam.info4,
					    num_entries, data_size,
					    start_idx, pass);
			break;
		}
		case 0x5:
		{
			ctr->sam.info5 = malloc(sizeof(SAM_DISPINFO_5));
			make_sam_dispinfo_5(ctr->sam.info5,
					    num_entries, data_size,
					    start_idx, grps);
			break;
		}
		default:
		{
			ctr->sam.info = NULL;
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));

	if ((*num_entries) < num_sam_entries)
	{
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_lookup_names
 ********************************************************************/
uint32 _samr_lookup_names(const POLICY_HND *dom_pol,
				
			uint32 num_names,
			uint32 flags,
			uint32 ptr,
			const UNISTR2 *uni_name,

			uint32 *num_rids,
			uint32 rid[MAX_SAM_ENTRIES],
			uint32 *num_types,
			uint32 type[MAX_SAM_ENTRIES])
{
	LDAPDB *hds = NULL;
	DOM_SID dom_sid;
	char *attrs[] = { "objectSid", "sAMAccountName", "objectClass", "groupType" };
	int i;
	BOOL found_one = False;

	DEBUG(5,("samr_lookup_names: %d\n", __LINE__));

	if (!get_nt5ldapdomsid(get_global_hnd_cache(), dom_pol, &hds, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	for (i = 0; i < num_names; i++)
	{
		BOOL ok = False;
		fstring name;

		unistr2_to_ascii(name, &uni_name[i], sizeof(name)-1);

		if (ldapdb_lookup_by_ntname(hds, name))
		{
			uint32 gt;

			found_one = True;

			if (!ldapdb_get_rid(hds, "objectSid", &(rid[i])))
			{
				rid[i] = 0xffffffff;
			}
			else if (ldapdb_get_uint32(hds, "groupType", &gt) &&
			    (gt & NTDS_GROUP_TYPE_SECURITY_ENABLED))
			{
				if (gt & NTDS_GROUP_TYPE_BUILTIN_GROUP)
					type[i] = SID_NAME_WKN_GRP;
				else if (gt & NTDS_GROUP_TYPE_GLOBAL_GROUP)
					type[i] = SID_NAME_DOM_GRP;
				else if (gt & NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP)
					type[i] = SID_NAME_ALIAS;
				else
					type[i] = SID_NAME_UNKNOWN;
				ok = True;
			}
			else
			{
				/* presumably a user */
				type[i] = SID_NAME_USER;
				ok = True;
			}
		}

		if (!ok)
		{
			type[i] = SID_NAME_UNKNOWN;
		}
	}

	*num_types = *num_rids = num_names;

	return found_one ? NT_STATUS_NOPROBLEMO : NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 samr_reply_lookup_rids
 ********************************************************************/
uint32 _samr_lookup_rids(const POLICY_HND *dom_pol,
				uint32 num_rids, uint32 flags,
				const uint32 *rids,
				uint32 *num_names,
				UNIHDR **hdr_name, UNISTR2** uni_name,
				uint32 **types)
{
	LDAPDB *hds = NULL;
	DOM_SID dom_sid;
	int i;
	BOOL found_one = False;

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

	if (!get_nt5ldapdomsid(get_global_hnd_cache(), dom_pol, &hds, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	*types = (uint32 *)Realloc(NULL, num_rids * sizeof(**types));
	if (*types == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	*uni_name = (UNISTR2 *)Realloc(NULL, num_rids * sizeof(**uni_name));
	if (*uni_name == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	*hdr_name = (UNIHDR *)Realloc(NULL, num_rids * sizeof(**hdr_name));
	if (*hdr_name == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_rids; i++)
	{
		BOOL ok = False;

		if (ldapdb_lookup_by_rid(hds, rids[i]))
		{
			found_one = True;
			if (ldapdb_get_unistr_value(hds, "sAMAccountName", &((*uni_name)[i])))
			{
				uint32 gt;

				make_uni_hdr(&((*hdr_name)[i]), ((*uni_name)[i]).uni_str_len);
				if (ldapdb_get_uint32(hds, "groupType", &gt) &&
				    (gt & NTDS_GROUP_TYPE_SECURITY_ENABLED))
				{
					if (gt & NTDS_GROUP_TYPE_BUILTIN_GROUP)
						(*types)[i] = SID_NAME_WKN_GRP;
					else if (gt & NTDS_GROUP_TYPE_GLOBAL_GROUP)
						(*types)[i] = SID_NAME_DOM_GRP;
					else if (gt & NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP)
						(*types)[i] = SID_NAME_ALIAS;
					else
						(*types)[i] = SID_NAME_UNKNOWN;
				}
				else
				{
					/* presumably a user */
					(*types)[i] = SID_NAME_USER;
				}
				ok = True;
			}
		}

		if (!ok)
		{
			(*types)[i] = SID_NAME_UNKNOWN;
		}
	}

	*num_names = num_rids;

	return found_one ? NT_STATUS_NOPROBLEMO : NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 _samr_query_dom_info
 ********************************************************************/
uint32 _samr_query_dom_info(const POLICY_HND *domain_pol,
				uint16 switch_value,
				SAM_UNK_CTR *ctr)
{
	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), domain_pol) == -1)
	{
		DEBUG(5,("samr_reply_query_dom_info: invalid handle\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (switch_value)
	{
		case 0x07:
		{
			make_unk_info7(&(ctr->info.inf7));
			break;
		}
		case 0x06:
		{
			make_unk_info6(&(ctr->info.inf6));
			break;
		}
		case 0x03:
		{
			make_unk_info3(&(ctr->info.inf3));
			break;
		}
		case 0x02:
		{
			extern fstring global_sam_name;
			extern pstring global_myname;
			make_unk_info2(&(ctr->info.inf2), global_sam_name, global_myname);
			break;
		}
		case 0x01:
		{
			make_unk_info1(&(ctr->info.inf1));
			break;
		}
		default:
		{
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_set_groupinfo
 ********************************************************************/
uint32 _samr_set_groupinfo(const POLICY_HND *pol,
				uint16 switch_level,
				const GROUP_INFO_CTR* ctr)
{
	return NT_STATUS_ACCESS_DENIED;
}
