/* 
   Unix SMB/CIFS implementation.

   Winbind ADS backend functions

   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003
   Copyright (C) Gerald (Jerry) Carter 2004
   
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
#include "winbindd.h"

#ifdef HAVE_ADS

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/*
  return our ads connections structure for a domain. We keep the connection
  open to make things faster
*/
static ADS_STRUCT *ads_cached_connection(struct winbindd_domain *domain)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;

	if (domain->private) {
		ads = (ADS_STRUCT *)domain->private;

		/* check for a valid structure */

		DEBUG(7, ("Current tickets expire at %d\n, time is now %d\n",
			  (uint32) ads->auth.expire, (uint32) time(NULL)));
		if ( ads->config.realm && (ads->auth.expire > time(NULL))) {
			return ads;
		}
		else {
			/* we own this ADS_STRUCT so make sure it goes away */
			ads->is_mine = True;
			ads_destroy( &ads );
			ads_kdestroy("MEMORY:winbind_ccache");
			domain->private = NULL;
		}	
	}

	/* we don't want this to affect the users ccache */
	setenv("KRB5CCNAME", "MEMORY:winbind_ccache", 1);

	ads = ads_init(domain->alt_name, domain->name, NULL);
	if (!ads) {
		DEBUG(1,("ads_init for domain %s failed\n", domain->name));
		return NULL;
	}

	/* the machine acct password might have change - fetch it every time */
	SAFE_FREE(ads->auth.password);
	ads->auth.password = secrets_fetch_machine_password(lp_workgroup(), NULL, NULL);

	SAFE_FREE(ads->auth.realm);
	ads->auth.realm = strdup(lp_realm());

	status = ads_connect(ads);
	if (!ADS_ERR_OK(status) || !ads->config.realm) {
		extern struct winbindd_methods msrpc_methods, cache_methods;
		DEBUG(1,("ads_connect for domain %s failed: %s\n", 
			 domain->name, ads_errstr(status)));
		ads_destroy(&ads);

		/* if we get ECONNREFUSED then it might be a NT4
                   server, fall back to MSRPC */
		if (status.error_type == ENUM_ADS_ERROR_SYSTEM &&
		    status.err.rc == ECONNREFUSED) {
			DEBUG(1,("Trying MSRPC methods\n"));
			if (domain->methods == &cache_methods) {
				domain->backend = &msrpc_methods;
			} else {
				domain->methods = &msrpc_methods;
			}
		}
		return NULL;
	}

	/* set the flag that says we don't own the memory even 
	   though we do so that ads_destroy() won't destroy the 
	   structure we pass back by reference */

	ads->is_mine = False;

	domain->private = (void *)ads;
	return ads;
}


/* Query display info for a realm. This is the basic user list fn */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 *num_entries, 
			       WINBIND_USERINFO **info)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"userPrincipalName",
			       "sAMAccountName",
			       "name", "objectSid", "primaryGroupID", 
			       "sAMAccountType", NULL};
	int i, count;
	ADS_STATUS rc;
	void *res = NULL;
	void *msg = NULL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	*num_entries = 0;

	DEBUG(3,("ads: query_user_list\n"));

	ads = ads_cached_connection(domain);
	
	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	rc = ads_search_retry(ads, &res, "(objectClass=user)", attrs);
	if (!ADS_ERR_OK(rc) || !res) {
		DEBUG(1,("query_user_list ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(1,("query_user_list: No users found\n"));
		goto done;
	}

	(*info) = talloc_zero(mem_ctx, count * sizeof(**info));
	if (!*info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	i = 0;

	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		char *name, *gecos;
		DOM_SID sid;
		DOM_SID *sid2;
		DOM_SID *group_sid;
		uint32 group;
		uint32 atype;

		if (!ads_pull_uint32(ads, msg, "sAMAccountType", &atype) ||
		    ads_atype_map(atype) != SID_NAME_USER) {
			DEBUG(1,("Not a user account? atype=0x%x\n", atype));
			continue;
		}

		name = ads_pull_username(ads, mem_ctx, msg);
		gecos = ads_pull_string(ads, mem_ctx, msg, "name");
		if (!ads_pull_sid(ads, msg, "objectSid", &sid)) {
			DEBUG(1,("No sid for %s !?\n", name));
			continue;
		}
		if (!ads_pull_uint32(ads, msg, "primaryGroupID", &group)) {
			DEBUG(1,("No primary group for %s !?\n", name));
			continue;
		}

		sid2 = talloc(mem_ctx, sizeof(*sid2));
		if (!sid2) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		sid_copy(sid2, &sid);

		group_sid = rid_to_talloced_sid(domain, mem_ctx, group);

		(*info)[i].acct_name = name;
		(*info)[i].full_name = gecos;
		(*info)[i].user_sid = sid2;
		(*info)[i].group_sid = group_sid;
		i++;
	}

	(*num_entries) = i;
	status = NT_STATUS_OK;

	DEBUG(3,("ads query_user_list gave %d entries\n", (*num_entries)));

done:
	if (res) 
		ads_msgfree(ads, res);

	return status;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"userPrincipalName", "sAMAccountName",
			       "name", "objectSid", 
			       "sAMAccountType", NULL};
	int i, count;
	ADS_STATUS rc;
	void *res = NULL;
	void *msg = NULL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	uint32 group_flags;

	*num_entries = 0;

	DEBUG(3,("ads: enum_dom_groups\n"));

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	rc = ads_search_retry(ads, &res, "(objectCategory=group)", attrs);
	if (!ADS_ERR_OK(rc) || !res) {
		DEBUG(1,("enum_dom_groups ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(1,("enum_dom_groups: No groups found\n"));
		goto done;
	}

	(*info) = talloc_zero(mem_ctx, count * sizeof(**info));
	if (!*info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	i = 0;
	
	group_flags = ATYPE_GLOBAL_GROUP;

	/* only grab domain local groups for our domain */
	if ( domain->native_mode && strequal(lp_realm(), domain->alt_name)  )
		group_flags |= ATYPE_LOCAL_GROUP;

	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		char *name, *gecos;
		DOM_SID sid;
		uint32 rid;
		uint32 account_type;

		if (!ads_pull_uint32(ads, msg, "sAMAccountType", &account_type) || !(account_type & group_flags) ) 
			continue; 
			
		name = ads_pull_username(ads, mem_ctx, msg);
		gecos = ads_pull_string(ads, mem_ctx, msg, "name");
		if (!ads_pull_sid(ads, msg, "objectSid", &sid)) {
			DEBUG(1,("No sid for %s !?\n", name));
			continue;
		}

		if (!sid_peek_check_rid(&domain->sid, &sid, &rid)) {
			DEBUG(1,("No rid for %s !?\n", name));
			continue;
		}

		fstrcpy((*info)[i].acct_name, name);
		fstrcpy((*info)[i].acct_desc, gecos);
		(*info)[i].rid = rid;
		i++;
	}

	(*num_entries) = i;

	status = NT_STATUS_OK;

	DEBUG(3,("ads enum_dom_groups gave %d entries\n", (*num_entries)));

done:
	if (res) 
		ads_msgfree(ads, res);

	return status;
}

/* list all domain local groups */
static NTSTATUS enum_local_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	/*
	 * This is a stub function only as we returned the domain 
	 * local groups in enum_dom_groups() if the domain->native field
	 * was true.  This is a simple performance optimization when
	 * using LDAP.
	 *
	 * if we ever need to enumerate domain local groups separately, 
	 * then this the optimization in enum_dom_groups() will need 
	 * to be split out
	 */
	*num_entries = 0;
	
	return NT_STATUS_OK;
}

/* convert a DN to a name, SID and name type 
   this might become a major speed bottleneck if groups have
   lots of users, in which case we could cache the results
*/
static BOOL dn_lookup(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		      const char *dn,
		      char **name, uint32 *name_type, DOM_SID *sid)
{
	void *res = NULL;
	const char *attrs[] = {"userPrincipalName", "sAMAccountName",
			       "objectSid", "sAMAccountType", NULL};
	ADS_STATUS rc;
	uint32 atype;
	DEBUG(3,("ads: dn_lookup\n"));

	rc = ads_search_retry_dn(ads, &res, dn, attrs);

	if (!ADS_ERR_OK(rc) || !res) {
		goto failed;
	}

	(*name) = ads_pull_username(ads, mem_ctx, res);

	if (!ads_pull_uint32(ads, res, "sAMAccountType", &atype)) {
		goto failed;
	}
	(*name_type) = ads_atype_map(atype);

	if (!ads_pull_sid(ads, res, "objectSid", sid)) {
		goto failed;
	}

	if (res) 
		ads_msgfree(ads, res);

	return True;

failed:
	if (res) 
		ads_msgfree(ads, res);

	return False;
}

/* Lookup user information from a rid */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   const DOM_SID *sid, 
			   WINBIND_USERINFO *info)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"userPrincipalName", 
			       "sAMAccountName",
			       "name", 
			       "primaryGroupID", NULL};
	ADS_STATUS rc;
	int count;
	void *msg = NULL;
	char *ldap_exp;
	char *sidstr;
	uint32 group_rid;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	DOM_SID *sid2;
	fstring sid_string;

	DEBUG(3,("ads: query_user\n"));

	ads = ads_cached_connection(domain);
	
	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	sidstr = sid_binstring(sid);
	asprintf(&ldap_exp, "(objectSid=%s)", sidstr);
	rc = ads_search_retry(ads, &msg, ldap_exp, attrs);
	free(ldap_exp);
	free(sidstr);
	if (!ADS_ERR_OK(rc) || !msg) {
		DEBUG(1,("query_user(sid=%s) ads_search: %s\n", sid_to_string(sid_string, sid), ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, msg);
	if (count != 1) {
		DEBUG(1,("query_user(sid=%s): Not found\n", sid_to_string(sid_string, sid)));
		goto done;
	}

	info->acct_name = ads_pull_username(ads, mem_ctx, msg);
	info->full_name = ads_pull_string(ads, mem_ctx, msg, "name");

	if (!ads_pull_uint32(ads, msg, "primaryGroupID", &group_rid)) {
		DEBUG(1,("No primary group for %s !?\n", sid_to_string(sid_string, sid)));
		goto done;
	}
	
	sid2 = talloc(mem_ctx, sizeof(*sid2));
	if (!sid2) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	sid_copy(sid2, sid);
	
	info->user_sid = sid2;

	info->group_sid = rid_to_talloced_sid(domain, mem_ctx, group_rid);

	status = NT_STATUS_OK;

	DEBUG(3,("ads query_user gave %s\n", info->acct_name));
done:
	if (msg) 
		ads_msgfree(ads, msg);

	return status;
}

/* Lookup groups a user is a member of - alternate method, for when
   tokenGroups are not available. */
static NTSTATUS lookup_usergroups_alt(struct winbindd_domain *domain,
				      TALLOC_CTX *mem_ctx,
				      const char *user_dn, 
				      DOM_SID *primary_group,
				      uint32 *num_groups, DOM_SID ***user_gids)
{
	ADS_STATUS rc;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int count;
	void *res = NULL;
	void *msg = NULL;
	char *ldap_exp;
	ADS_STRUCT *ads;
	const char *group_attrs[] = {"objectSid", NULL};
	char *escaped_dn;

	DEBUG(3,("ads: lookup_usergroups_alt\n"));

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	if (!(escaped_dn = escape_ldap_string_alloc(user_dn))) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* buggy server, no tokenGroups.  Instead lookup what groups this user
	   is a member of by DN search on member*/

	if (!(ldap_exp = talloc_asprintf(mem_ctx, "(&(member=%s)(objectClass=group))", escaped_dn))) {
		DEBUG(1,("lookup_usergroups(dn=%s) asprintf failed!\n", user_dn));
		SAFE_FREE(escaped_dn);
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	SAFE_FREE(escaped_dn);

	rc = ads_search_retry(ads, &res, ldap_exp, group_attrs);
	
	if (!ADS_ERR_OK(rc) || !res) {
		DEBUG(1,("lookup_usergroups ads_search member=%s: %s\n", user_dn, ads_errstr(rc)));
		return ads_ntstatus(rc);
	}
	
	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(5,("lookup_usergroups: No supp groups found\n"));
		
		status = ads_ntstatus(rc);
		goto done;
	}
	
	(*user_gids) = talloc_zero(mem_ctx, sizeof(**user_gids) * (count + 1));
	(*user_gids)[0] = primary_group;
	
	*num_groups = 1;
	
	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		DOM_SID group_sid;
		
		if (!ads_pull_sid(ads, msg, "objectSid", &group_sid)) {
			DEBUG(1,("No sid for this group ?!?\n"));
			continue;
		}
		
		if (sid_equal(&group_sid, primary_group)) continue;
		
		(*user_gids)[*num_groups] = talloc(mem_ctx, sizeof(***user_gids));
		if (!(*user_gids)[*num_groups]) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		sid_copy((*user_gids)[*num_groups], &group_sid);

		(*num_groups)++;
			
	}

	status = NT_STATUS_OK;

	DEBUG(3,("ads lookup_usergroups (alt) for dn=%s\n", user_dn));
done:
	if (res) 
		ads_msgfree(ads, res);

	return status;
}

/* Lookup groups a user is a member of. */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const DOM_SID *sid, 
				  uint32 *num_groups, DOM_SID ***user_gids)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"tokenGroups", "primaryGroupID", NULL};
	ADS_STATUS rc;
	int count;
	LDAPMessage *msg = NULL;
	char *user_dn;
	DOM_SID *sids;
	int i;
	DOM_SID *primary_group;
	uint32 primary_group_rid;
	fstring sid_string;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("ads: lookup_usergroups\n"));
	*num_groups = 0;

	ads = ads_cached_connection(domain);
	
	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	rc = ads_sid_to_dn(ads, mem_ctx, sid, &user_dn);
	if (!ADS_ERR_OK(rc)) {
		status = ads_ntstatus(rc);
		goto done;
	}

	rc = ads_search_retry_dn(ads, (void**)&msg, user_dn, attrs);
	if (!ADS_ERR_OK(rc)) {
		status = ads_ntstatus(rc);
		DEBUG(1,("lookup_usergroups(sid=%s) ads_search tokenGroups: %s\n", 
			 sid_to_string(sid_string, sid), ads_errstr(rc)));
		goto done;
	}
	
	if (!msg) {
		DEBUG(1,("lookup_usergroups(sid=%s) ads_search tokenGroups: NULL msg\n", 
			 sid_to_string(sid_string, sid)));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!ads_pull_uint32(ads, msg, "primaryGroupID", &primary_group_rid)) {
		DEBUG(1,("%s: No primary group for sid=%s !?\n", 
			 domain->name, sid_to_string(sid_string, sid)));
		goto done;
	}

	primary_group = rid_to_talloced_sid(domain, mem_ctx, primary_group_rid);

	count = ads_pull_sids(ads, mem_ctx, msg, "tokenGroups", &sids);

	if (msg) 
		ads_msgfree(ads, msg);

	/* there must always be at least one group in the token, 
	   unless we are talking to a buggy Win2k server */
	if (count == 0) {
		return lookup_usergroups_alt(domain, mem_ctx, user_dn, 
					     primary_group,
					     num_groups, user_gids);
	}

	(*user_gids) = talloc_zero(mem_ctx, sizeof(**user_gids) * (count + 1));
	(*user_gids)[0] = primary_group;
	
	*num_groups = 1;
	
	for (i=0;i<count;i++) {
		if (sid_equal(&sids[i], primary_group)) continue;
		
		(*user_gids)[*num_groups] = talloc(mem_ctx, sizeof(***user_gids));
		if (!(*user_gids)[*num_groups]) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		sid_copy((*user_gids)[*num_groups], &sids[i]);
		(*num_groups)++;
	}

	status = NT_STATUS_OK;
	DEBUG(3,("ads lookup_usergroups for sid=%s\n", sid_to_string(sid_string, sid)));
done:
	return status;
}

/*
  find the members of a group, given a group rid and domain
 */
static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const DOM_SID *group_sid, uint32 *num_names, 
				DOM_SID ***sid_mem, char ***names, 
				uint32 **name_types)
{
	ADS_STATUS rc;
	int count;
	void *res=NULL;
	ADS_STRUCT *ads = NULL;
	char *ldap_exp;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *sidstr;
	char **members;
	int i, num_members;
	fstring sid_string;
	BOOL more_values;
	const char **attrs;
	uint32 first_usn;
	uint32 current_usn;
	int num_retries = 0;

	DEBUG(10,("ads: lookup_groupmem %s sid=%s\n", domain->name, 
		  sid_string_static(group_sid)));

	*num_names = 0;

	ads = ads_cached_connection(domain);
	
	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	sidstr = sid_binstring(group_sid);

	/* search for all members of the group */
	if (!(ldap_exp = talloc_asprintf(mem_ctx, "(objectSid=%s)",sidstr))) {
		SAFE_FREE(sidstr);
		DEBUG(1, ("ads: lookup_groupmem: tallloc_asprintf for ldap_exp failed!\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	SAFE_FREE(sidstr);

	members = NULL;
	num_members = 0;

	attrs = talloc(mem_ctx, 3 * sizeof(*attrs));
	attrs[1] = talloc_strdup(mem_ctx, "usnChanged");
	attrs[2] = NULL;
		
	do {
		if (num_members == 0) 
			attrs[0] = talloc_strdup(mem_ctx, "member");

		DEBUG(10, ("Searching for attrs[0] = %s, attrs[1] = %s\n", attrs[0], attrs[1]));

		rc = ads_search_retry(ads, &res, ldap_exp, attrs);

		if (!ADS_ERR_OK(rc) || !res) {
			DEBUG(1,("ads: lookup_groupmem ads_search: %s\n",
				 ads_errstr(rc)));
			status = ads_ntstatus(rc);
			goto done;
		}

		count = ads_count_replies(ads, res);
		if (count == 0)
			break;

		if (num_members == 0) {
			if (!ads_pull_uint32(ads, res, "usnChanged", &first_usn)) {
				DEBUG(1, ("ads: lookup_groupmem could not pull usnChanged!\n"));
				goto done;
			}
		}

		if (!ads_pull_uint32(ads, res, "usnChanged", &current_usn)) {
			DEBUG(1, ("ads: lookup_groupmem could not pull usnChanged!\n"));
			goto done;
		}

		if (first_usn != current_usn) {
			DEBUG(5, ("ads: lookup_groupmem USN on this record changed"
				  " - restarting search\n"));
			if (num_retries < 5) {
				num_retries++;
				num_members = 0;
				continue;
			} else {
				DEBUG(5, ("ads: lookup_groupmem USN on this record changed"
					  " - restarted search too many times, aborting!\n"));
				status = NT_STATUS_UNSUCCESSFUL;
				goto done;
			}
		}

		members = ads_pull_strings_range(ads, mem_ctx, res,
						 "member",
						 members,
						 &attrs[0],
						 &num_members,
						 &more_values);

		if ((members == NULL) || (num_members == 0))
			break;

	} while (more_values);
		
	/* now we need to turn a list of members into rids, names and name types 
	   the problem is that the members are in the form of distinguised names
	*/

	(*sid_mem) = talloc_zero(mem_ctx, sizeof(**sid_mem) * num_members);
	(*name_types) = talloc_zero(mem_ctx, sizeof(**name_types) * num_members);
	(*names) = talloc_zero(mem_ctx, sizeof(**names) * num_members);

	for (i=0;i<num_members;i++) {
		uint32 name_type;
		char *name;
		DOM_SID sid;

		if (dn_lookup(ads, mem_ctx, members[i], &name, &name_type, &sid)) {
		    (*names)[*num_names] = name;
		    (*name_types)[*num_names] = name_type;
		    (*sid_mem)[*num_names] = talloc(mem_ctx, sizeof(***sid_mem));
		    if (!(*sid_mem)[*num_names]) {
			    status = NT_STATUS_NO_MEMORY;
			    goto done;
		    }
		    sid_copy((*sid_mem)[*num_names], &sid);
		    (*num_names)++;
		}
	}	

	status = NT_STATUS_OK;
	DEBUG(3,("ads lookup_groupmem for sid=%s\n", sid_to_string(sid_string, group_sid)));
done:

	if (res) 
		ads_msgfree(ads, res);

	return status;
}

/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32 *seq)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS rc;

	DEBUG(3,("ads: fetch sequence_number for %s\n", domain->name));

	*seq = DOM_SEQUENCE_NONE;

	ads = ads_cached_connection(domain);
	
	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ads_USN(ads, seq);
	
	if (!ADS_ERR_OK(rc)) {
	
		/* its a dead connection ; don't destroy it 
		   through since ads_USN() has already done 
		   that indirectly */
		   
		domain->private = NULL;
	}
	return ads_ntstatus(rc);
}

/* get a list of trusted domains */
static NTSTATUS trusted_domains(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_domains,
				char ***names,
				char ***alt_names,
				DOM_SID **dom_sids)
{
	NTSTATUS 		result = NT_STATUS_UNSUCCESSFUL;
	struct ds_domain_trust	*domains = NULL;
	int			count = 0;
	int			i;
	struct cli_state	*cli = NULL;
				/* i think we only need our forest and downlevel trusted domains */
	uint32			flags = DS_DOMAIN_IN_FOREST | DS_DOMAIN_DIRECT_OUTBOUND;

	DEBUG(3,("ads: trusted_domains\n"));

	*num_domains = 0;
	*alt_names   = NULL;
	*names       = NULL;
	*dom_sids    = NULL;
		
	if ( !NT_STATUS_IS_OK(result = cm_fresh_connection(domain, PI_NETLOGON, &cli)) ) {
		DEBUG(5, ("trusted_domains: Could not open a connection to %s for PIPE_NETLOGON (%s)\n", 
			  domain->name, nt_errstr(result)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	if ( NT_STATUS_IS_OK(result) )
		result = cli_ds_enum_domain_trusts( cli, mem_ctx, cli->desthost, 
						    flags, &domains, (unsigned int *)&count );
	
	if ( NT_STATUS_IS_OK(result) && count) {
	
		/* Allocate memory for trusted domain names and sids */

		if ( !(*names = (char **)talloc(mem_ctx, sizeof(char *) * count)) ) {
			DEBUG(0, ("trusted_domains: out of memory\n"));
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}

		if ( !(*alt_names = (char **)talloc(mem_ctx, sizeof(char *) * count)) ) {
			DEBUG(0, ("trusted_domains: out of memory\n"));
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}

		if ( !(*dom_sids = (DOM_SID *)talloc(mem_ctx, sizeof(DOM_SID) * count)) ) {
			DEBUG(0, ("trusted_domains: out of memory\n"));
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}

		/* Copy across names and sids */

		for (i = 0; i < count; i++) {
			(*names)[i] = domains[i].netbios_domain;
			(*alt_names)[i] = domains[i].dns_domain;

			sid_copy(&(*dom_sids)[i], &domains[i].sid);
		}

		*num_domains = count;	
	}

done:

	/* remove connection;  This is a special case to the \NETLOGON pipe */
	
	if ( cli )
		cli_shutdown( cli );

	return result;
}

/* find the domain sid for a domain */
static NTSTATUS domain_sid(struct winbindd_domain *domain, DOM_SID *sid)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;

	DEBUG(3,("ads: domain_sid\n"));

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ads_domain_sid(ads, sid);

	if (!ADS_ERR_OK(rc)) {
	
		/* its a dead connection; don't destroy it though
		   since that has already been done indirectly 
		   by ads_domain_sid() */

		domain->private = NULL;
	}

	return ads_ntstatus(rc);
}


/* find alternate names list for the domain - for ADS this is the
   netbios name */
static NTSTATUS alternate_name(struct winbindd_domain *domain)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;
	TALLOC_CTX *ctx;
	const char *workgroup;

	DEBUG(3,("ads: alternate_name\n"));

	ads = ads_cached_connection(domain);
	
	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!(ctx = talloc_init("alternate_name"))) {
		return NT_STATUS_NO_MEMORY;
	}

	rc = ads_workgroup_name(ads, ctx, &workgroup);

	if (ADS_ERR_OK(rc)) {
		fstrcpy(domain->name, workgroup);
		fstrcpy(domain->alt_name, ads->config.realm);
		strupper_m(domain->alt_name);
		strupper_m(domain->name);
	}

	talloc_destroy(ctx);

	return ads_ntstatus(rc);	
}

/* the ADS backend methods are exposed via this structure */
struct winbindd_methods ads_methods = {
	True,
	query_user_list,
	enum_dom_groups,
	enum_local_groups,
	msrpc_name_to_sid,
	msrpc_sid_to_name,
	query_user,
	lookup_usergroups,
	lookup_groupmem,
	sequence_number,
	trusted_domains,
	domain_sid,
	alternate_name
};

#endif
