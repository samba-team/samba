/* 
   Unix SMB/CIFS implementation.

   Winbind ADS backend functions

   Copyright (C) Andrew Tridgell 2001
   
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

#ifdef HAVE_ADS

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* the realm of our primary LDAP server */
static char *primary_realm;


/*
  return our ads connections structure for a domain. We keep the connection
  open to make things faster
*/
static ADS_STRUCT *ads_cached_connection(struct winbindd_domain *domain)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;

	if (domain->private) {
		return (ADS_STRUCT *)domain->private;
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
	ads->auth.password = secrets_fetch_machine_password();

	if (primary_realm) {
		SAFE_FREE(ads->auth.realm);
		ads->auth.realm = strdup(primary_realm);
	}

	status = ads_connect(ads);
	if (!ADS_ERR_OK(status) || !ads->config.realm) {
		extern struct winbindd_methods msrpc_methods;
		DEBUG(1,("ads_connect for domain %s failed: %s\n", 
			 domain->name, ads_errstr(status)));
		ads_destroy(&ads);

		/* if we get ECONNREFUSED then it might be a NT4
                   server, fall back to MSRPC */
		if (status.error_type == ADS_ERROR_SYSTEM &&
		    status.err.rc == ECONNREFUSED) {
			DEBUG(1,("Trying MSRPC methods\n"));
			domain->methods = &msrpc_methods;
		}
		return NULL;
	}

	/* remember our primary realm for trusted domain support */
	if (!primary_realm) {
		primary_realm = strdup(ads->config.realm);
	}

	domain->private = (void *)ads;
	return ads;
}

/* useful utility */
static void sid_from_rid(struct winbindd_domain *domain, uint32 rid, DOM_SID *sid)
{
	sid_copy(sid, &domain->sid);
	sid_append_rid(sid, rid);
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
	if (!ads) goto done;

	rc = ads_search_retry(ads, &res, "(objectCategory=user)", attrs);
	if (!ADS_ERR_OK(rc)) {
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
		uint32 rid, group;
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

		if (!sid_peek_check_rid(&domain->sid, &sid, &rid)) {
			DEBUG(1,("No rid for %s !?\n", name));
			continue;
		}

		(*info)[i].acct_name = name;
		(*info)[i].full_name = gecos;
		(*info)[i].user_rid = rid;
		(*info)[i].group_rid = group;
		i++;
	}

	(*num_entries) = i;
	status = NT_STATUS_OK;

	DEBUG(3,("ads query_user_list gave %d entries\n", (*num_entries)));

done:
	if (res) ads_msgfree(ads, res);

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
	if (!ads) goto done;

	rc = ads_search_retry(ads, &res, "(objectCategory=group)", attrs);
	if (!ADS_ERR_OK(rc)) {
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
	if ( domain->native_mode )
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
	if (res) ads_msgfree(ads, res);

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
	 * ocal groups in enum_dom_groups() if the domain->native field
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

/* convert a single name to a sid in a domain */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	ADS_STRUCT *ads;

	DEBUG(3,("ads: name_to_sid\n"));

	ads = ads_cached_connection(domain);
	if (!ads) 
		return NT_STATUS_UNSUCCESSFUL;

	return ads_name_to_sid(ads, name, sid, type);
}

/* convert a sid to a user or group name */
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    DOM_SID *sid,
			    char **name,
			    enum SID_NAME_USE *type)
{
	ADS_STRUCT *ads = NULL;
	DEBUG(3,("ads: sid_to_name\n"));
	ads = ads_cached_connection(domain);
	if (!ads) 
		return NT_STATUS_UNSUCCESSFUL;

	return ads_sid_to_name(ads, mem_ctx, sid, name, type);
}


/* convert a DN to a name, rid and name type 
   this might become a major speed bottleneck if groups have
   lots of users, in which case we could cache the results
*/
static BOOL dn_lookup(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		      const char *dn,
		      char **name, uint32 *name_type, uint32 *rid)
{
	char *exp;
	void *res = NULL;
	const char *attrs[] = {"userPrincipalName", "sAMAccountName",
			       "objectSid", "sAMAccountType", NULL};
	ADS_STATUS rc;
	uint32 atype;
	DOM_SID sid;
	char *escaped_dn = escape_ldap_string_alloc(dn);

	if (!escaped_dn) {
		return False;
	}

	asprintf(&exp, "(distinguishedName=%s)", dn);
	rc = ads_search_retry(ads, &res, exp, attrs);
	SAFE_FREE(exp);
	SAFE_FREE(escaped_dn);

	if (!ADS_ERR_OK(rc)) {
		goto failed;
	}

	(*name) = ads_pull_username(ads, mem_ctx, res);

	if (!ads_pull_uint32(ads, res, "sAMAccountType", &atype)) {
		goto failed;
	}
	(*name_type) = ads_atype_map(atype);

	if (!ads_pull_sid(ads, res, "objectSid", &sid) || 
	    !sid_peek_rid(&sid, rid)) {
		goto failed;
	}

	if (res) ads_msgfree(ads, res);
	return True;

failed:
	if (res) ads_msgfree(ads, res);
	return False;
}

/* Lookup user information from a rid */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   uint32 user_rid, 
			   WINBIND_USERINFO *info)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"userPrincipalName", 
			       "sAMAccountName",
			       "name", "objectSid", 
			       "primaryGroupID", NULL};
	ADS_STATUS rc;
	int count;
	void *msg = NULL;
	char *exp;
	DOM_SID sid;
	char *sidstr;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("ads: query_user\n"));

	sid_from_rid(domain, user_rid, &sid);

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	sidstr = sid_binstring(&sid);
	asprintf(&exp, "(objectSid=%s)", sidstr);
	rc = ads_search_retry(ads, &msg, exp, attrs);
	free(exp);
	free(sidstr);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("query_user(rid=%d) ads_search: %s\n", user_rid, ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, msg);
	if (count != 1) {
		DEBUG(1,("query_user(rid=%d): Not found\n", user_rid));
		goto done;
	}

	info->acct_name = ads_pull_username(ads, mem_ctx, msg);
	info->full_name = ads_pull_string(ads, mem_ctx, msg, "name");
	if (!ads_pull_sid(ads, msg, "objectSid", &sid)) {
		DEBUG(1,("No sid for %d !?\n", user_rid));
		goto done;
	}
	if (!ads_pull_uint32(ads, msg, "primaryGroupID", &info->group_rid)) {
		DEBUG(1,("No primary group for %d !?\n", user_rid));
		goto done;
	}
	
	if (!sid_peek_check_rid(&domain->sid,&sid, &info->user_rid)) {
		DEBUG(1,("No rid for %d !?\n", user_rid));
		goto done;
	}

	status = NT_STATUS_OK;

	DEBUG(3,("ads query_user gave %s\n", info->acct_name));
done:
	if (msg) ads_msgfree(ads, msg);

	return status;
}


/* Lookup groups a user is a member of. */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  uint32 user_rid, 
				  uint32 *num_groups, uint32 **user_gids)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"distinguishedName", NULL};
	const char *attrs2[] = {"tokenGroups", "primaryGroupID", NULL};
	ADS_STATUS rc;
	int count;
	void *msg = NULL;
	char *exp;
	char *user_dn;
	DOM_SID *sids;
	int i;
	uint32 primary_group;
	DOM_SID sid;
	char *sidstr;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	*num_groups = 0;

	DEBUG(3,("ads: lookup_usergroups\n"));

	(*num_groups) = 0;

	sid_from_rid(domain, user_rid, &sid);

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	sidstr = sid_binstring(&sid);
	asprintf(&exp, "(objectSid=%s)", sidstr);
	rc = ads_search_retry(ads, &msg, exp, attrs);
	free(exp);
	free(sidstr);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("lookup_usergroups(rid=%d) ads_search: %s\n", user_rid, ads_errstr(rc)));
		goto done;
	}

	user_dn = ads_pull_string(ads, mem_ctx, msg, "distinguishedName");

	if (msg) ads_msgfree(ads, msg);

	rc = ads_search_retry_dn(ads, &msg, user_dn, attrs2);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("lookup_usergroups(rid=%d) ads_search tokenGroups: %s\n", user_rid, ads_errstr(rc)));
		goto done;
	}

	if (!ads_pull_uint32(ads, msg, "primaryGroupID", &primary_group)) {
		DEBUG(1,("%s: No primary group for rid=%d !?\n", domain->name, user_rid));
		goto done;
	}

	count = ads_pull_sids(ads, mem_ctx, msg, "tokenGroups", &sids) + 1;
	(*user_gids) = (uint32 *)talloc_zero(mem_ctx, sizeof(uint32) * count);
	(*user_gids)[(*num_groups)++] = primary_group;

	for (i=1;i<count;i++) {
		uint32 rid;
		if (!sid_peek_check_rid(&domain->sid, &sids[i-1], &rid)) continue;
		(*user_gids)[*num_groups] = rid;
		(*num_groups)++;
	}

	status = NT_STATUS_OK;
	DEBUG(3,("ads lookup_usergroups for rid=%d\n", user_rid));
done:
	if (msg) ads_msgfree(ads, msg);

	return status;
}

/*
  find the members of a group, given a group rid and domain
 */
static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 group_rid, uint32 *num_names, 
				uint32 **rid_mem, char ***names, 
				uint32 **name_types)
{
	DOM_SID group_sid;
	ADS_STATUS rc;
	int count;
	void *res=NULL;
	ADS_STRUCT *ads = NULL;
	char *exp;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *sidstr;
	const char *attrs[] = {"member", NULL};
	char **members;
	int i, num_members;

	*num_names = 0;

	ads = ads_cached_connection(domain);
	if (!ads) goto done;

	sid_from_rid(domain, group_rid, &group_sid);
	sidstr = sid_binstring(&group_sid);

	/* search for all members of the group */
	asprintf(&exp, "(objectSid=%s)",sidstr);
	rc = ads_search_retry(ads, &res, exp, attrs);
	free(exp);
	free(sidstr);

	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("query_user_list ads_search: %s\n", ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		status = NT_STATUS_OK;
		goto done;
	}

	members = ads_pull_strings(ads, mem_ctx, res, "member");
	if (!members) {
		/* no members? ok ... */
		status = NT_STATUS_OK;
		goto done;
	}

	/* now we need to turn a list of members into rids, names and name types 
	   the problem is that the members are in the form of distinguised names
	*/
	for (i=0;members[i];i++) /* noop */ ;
	num_members = i;

	(*rid_mem) = talloc_zero(mem_ctx, sizeof(uint32) * num_members);
	(*name_types) = talloc_zero(mem_ctx, sizeof(uint32) * num_members);
	(*names) = talloc_zero(mem_ctx, sizeof(char *) * num_members);

	for (i=0;i<num_members;i++) {
		uint32 name_type, rid;
		char *name;

		if (dn_lookup(ads, mem_ctx, members[i], &name, &name_type, &rid)) {
		    (*names)[*num_names] = name;
		    (*name_types)[*num_names] = name_type;
		    (*rid_mem)[*num_names] = rid;
		    (*num_names)++;
		}
	}	

	status = NT_STATUS_OK;
	DEBUG(3,("ads lookup_groupmem for rid=%d\n", group_rid));
done:
	if (res) ads_msgfree(ads, res);

	return status;
}


/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32 *seq)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS rc;

	*seq = DOM_SEQUENCE_NONE;

	ads = ads_cached_connection(domain);
	if (!ads) return NT_STATUS_UNSUCCESSFUL;

	rc = ads_USN(ads, seq);
	if (!ADS_ERR_OK(rc)) {
		/* its a dead connection */
		ads_destroy(&ads);
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
	ADS_STRUCT *ads;
	ADS_STATUS rc;

	*num_domains = 0;
	*names = NULL;

	ads = ads_cached_connection(domain);
	if (!ads) return NT_STATUS_UNSUCCESSFUL;

	rc = ads_trusted_domains(ads, mem_ctx, num_domains, names, alt_names, dom_sids);

	return ads_ntstatus(rc);
}

/* find the domain sid for a domain */
static NTSTATUS domain_sid(struct winbindd_domain *domain, DOM_SID *sid)
{
	ADS_STRUCT *ads;
	ADS_STATUS rc;

	ads = ads_cached_connection(domain);
	if (!ads) return NT_STATUS_UNSUCCESSFUL;

	rc = ads_domain_sid(ads, sid);

	if (!ADS_ERR_OK(rc)) {
		/* its a dead connection */
		ads_destroy(&ads);
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
	char *workgroup;

	ads = ads_cached_connection(domain);
	if (!ads) return NT_STATUS_UNSUCCESSFUL;

	if (!(ctx = talloc_init("alternate_name"))) {
		return NT_STATUS_NO_MEMORY;
	}

	rc = ads_workgroup_name(ads, ctx, &workgroup);

	if (ADS_ERR_OK(rc)) {
		fstrcpy(domain->name, workgroup);
		fstrcpy(domain->alt_name, ads->config.realm);
		strupper(domain->alt_name);
		strupper(domain->name);
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
	name_to_sid,
	sid_to_name,
	query_user,
	lookup_usergroups,
	lookup_groupmem,
	sequence_number,
	trusted_domains,
	domain_sid,
	alternate_name
};

#endif
