/*
   Unix SMB/CIFS implementation.

   Winbind ADS backend functions

   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003
   Copyright (C) Gerald (Jerry) Carter 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "winbindd.h"
#include "winbindd_ads.h"
#include "libsmb/namequery.h"
#include "rpc_client/rpc_client.h"
#include "../librpc/gen_ndr/ndr_netlogon_c.h"
#include "../libds/common/flags.h"
#include "ads.h"
#include "../libcli/ldap/ldap_ndr.h"
#include "../libcli/security/security.h"
#include "../libds/common/flag_mapping.h"
#include "libsmb/samlogon_cache.h"
#include "passdb.h"

#ifdef HAVE_ADS

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

extern struct winbindd_methods reconnect_methods;
extern struct winbindd_methods msrpc_methods;

#define WINBIND_CCACHE_NAME "MEMORY:winbind_ccache"

/**
 * Check if cached connection can be reused. If the connection cannot
 * be reused the ADS_STRUCT is freed and the pointer is set to NULL.
 */
static void ads_cached_connection_reuse(ADS_STRUCT **adsp)
{

	ADS_STRUCT *ads = *adsp;

	if (ads != NULL) {
		time_t expire;
		time_t now = time(NULL);

		expire = MIN(ads->auth.tgt_expire, ads->auth.tgs_expire);

		DEBUG(7, ("Current tickets expire in %d seconds (at %d, time "
			  "is now %d)\n", (uint32_t)expire - (uint32_t)now,
			  (uint32_t) expire, (uint32_t) now));

		if ( ads->config.realm && (expire > now)) {
			return;
		} else {
			/* we own this ADS_STRUCT so make sure it goes away */
			DEBUG(7,("Deleting expired krb5 credential cache\n"));
			ads->is_mine = True;
			ads_destroy( &ads );
			ads_kdestroy(WINBIND_CCACHE_NAME);
			*adsp = NULL;
		}
	}
}

/**
 * @brief Establish a connection to a DC
 *
 * @param[out]   adsp             ADS_STRUCT that will be created
 * @param[in]    target_realm     Realm of domain to connect to
 * @param[in]    target_dom_name  'workgroup' name of domain to connect to
 * @param[in]    ldap_server      DNS name of server to connect to
 * @param[in]    password         Our machine acount secret
 * @param[in]    auth_realm       Realm of local domain for creating krb token
 * @param[in]    renewable        Renewable ticket time
 *
 * @return ADS_STATUS
 */
static ADS_STATUS ads_cached_connection_connect(ADS_STRUCT **adsp,
						const char *target_realm,
						const char *target_dom_name,
						const char *ldap_server,
						char *password,
						char *auth_realm,
						time_t renewable)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	struct sockaddr_storage dc_ss;
	fstring dc_name;

	if (auth_realm == NULL) {
		return ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	}

	/* we don't want this to affect the users ccache */
	setenv("KRB5CCNAME", WINBIND_CCACHE_NAME, 1);

	ads = ads_init(target_realm,
		       target_dom_name,
		       ldap_server,
		       ADS_SASL_SEAL);
	if (!ads) {
		DEBUG(1,("ads_init for domain %s failed\n", target_dom_name));
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	SAFE_FREE(ads->auth.password);
	SAFE_FREE(ads->auth.realm);

	ads->auth.renewable = renewable;
	ads->auth.password = password;

	ads->auth.flags |= ADS_AUTH_ALLOW_NTLMSSP;

	ads->auth.realm = SMB_STRDUP(auth_realm);
	if (!strupper_m(ads->auth.realm)) {
		ads_destroy(&ads);
		return ADS_ERROR_NT(NT_STATUS_INTERNAL_ERROR);
	}

	/* Setup the server affinity cache.  We don't reaally care
	   about the name.  Just setup affinity and the KRB5_CONFIG
	   file. */
	get_dc_name(ads->server.workgroup, ads->server.realm, dc_name, &dc_ss);

	status = ads_connect(ads);
	if (!ADS_ERR_OK(status)) {
		DEBUG(1,("ads_connect for domain %s failed: %s\n",
			 target_dom_name, ads_errstr(status)));
		ads_destroy(&ads);
		return status;
	}

	/* set the flag that says we don't own the memory even
	   though we do so that ads_destroy() won't destroy the
	   structure we pass back by reference */

	ads->is_mine = False;

	*adsp = ads;

	return status;
}

ADS_STATUS ads_idmap_cached_connection(ADS_STRUCT **adsp, const char *dom_name)
{
	char *ldap_server, *realm, *password;
	struct winbindd_domain *wb_dom;
	ADS_STATUS status;

	if (IS_AD_DC) {
		/*
		 * Make sure we never try to use LDAP against
		 * a trusted domain as AD DC.
		 */
		return ADS_ERROR_NT(NT_STATUS_REQUEST_NOT_ACCEPTED);
	}

	ads_cached_connection_reuse(adsp);
	if (*adsp != NULL) {
		return ADS_SUCCESS;
	}

	/*
	 * At this point we only have the NetBIOS domain name.
	 * Check if we can get server nam and realm from SAF cache
	 * and the domain list.
	 */
	ldap_server = saf_fetch(talloc_tos(), dom_name);
	DEBUG(10, ("ldap_server from saf cache: '%s'\n",
		   ldap_server ? ldap_server : ""));

	wb_dom = find_domain_from_name(dom_name);
	if (wb_dom == NULL) {
		DEBUG(10, ("could not find domain '%s'\n", dom_name));
		return ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	}

	DEBUG(10, ("find_domain_from_name found realm '%s' for "
			  " domain '%s'\n", wb_dom->alt_name, dom_name));

	if (!get_trust_pw_clear(dom_name, &password, NULL, NULL)) {
		TALLOC_FREE(ldap_server);
		return ADS_ERROR_NT(NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
	}

	if (IS_DC) {
		SMB_ASSERT(wb_dom->alt_name != NULL);
		realm = SMB_STRDUP(wb_dom->alt_name);
	} else {
		struct winbindd_domain *our_domain = wb_dom;

		/* always give preference to the alt_name in our
		   primary domain if possible */

		if (!wb_dom->primary) {
			our_domain = find_our_domain();
		}

		if (our_domain->alt_name != NULL) {
			realm = SMB_STRDUP(our_domain->alt_name);
		} else {
			realm = SMB_STRDUP(lp_realm());
		}
	}

	status = ads_cached_connection_connect(
		adsp,			/* Returns ads struct. */
		wb_dom->alt_name,	/* realm to connect to. */
		dom_name,		/* 'workgroup' name for ads_init */
		ldap_server,		/* DNS name to connect to. */
		password,		/* password for auth realm. */
		realm,			/* realm used for krb5 ticket. */
		0);			/* renewable ticket time. */

	SAFE_FREE(realm);
	TALLOC_FREE(ldap_server);

	return status;
}

/*
  return our ads connections structure for a domain. We keep the connection
  open to make things faster
*/
static ADS_STRUCT *ads_cached_connection(struct winbindd_domain *domain)
{
	ADS_STATUS status;
	char *password, *realm;

	if (IS_AD_DC) {
		/*
		 * Make sure we never try to use LDAP against
		 * a trusted domain as AD DC.
		 */
		return NULL;
	}

	DEBUG(10,("ads_cached_connection\n"));
	ads_cached_connection_reuse((ADS_STRUCT **)&domain->private_data);

	if (domain->private_data) {
		return (ADS_STRUCT *)domain->private_data;
	}

	/* the machine acct password might have change - fetch it every time */

	if (!get_trust_pw_clear(domain->name, &password, NULL, NULL)) {
		return NULL;
	}

	if ( IS_DC ) {
		SMB_ASSERT(domain->alt_name != NULL);
		realm = SMB_STRDUP(domain->alt_name);
	}
	else {
		struct winbindd_domain *our_domain = domain;


		/* always give preference to the alt_name in our
		   primary domain if possible */

		if ( !domain->primary )
			our_domain = find_our_domain();

		if (our_domain->alt_name != NULL) {
			realm = SMB_STRDUP( our_domain->alt_name );
		}
		else
			realm = SMB_STRDUP( lp_realm() );
	}

	status = ads_cached_connection_connect(
					(ADS_STRUCT **)&domain->private_data,
					domain->alt_name,
					domain->name, NULL,
					password, realm,
					WINBINDD_PAM_AUTH_KRB5_RENEW_TIME);
	SAFE_FREE(realm);

	if (!ADS_ERR_OK(status)) {
		/* if we get ECONNREFUSED then it might be a NT4
                   server, fall back to MSRPC */
		if (status.error_type == ENUM_ADS_ERROR_SYSTEM &&
		    status.err.rc == ECONNREFUSED) {
			/* 'reconnect_methods' is the MS-RPC backend. */
			DEBUG(1,("Trying MSRPC methods\n"));
			domain->backend = &reconnect_methods;
		}
		return NULL;
	}

	return (ADS_STRUCT *)domain->private_data;
}

/* Query display info for a realm. This is the basic user list fn */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32_t **prids)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = { "sAMAccountType", "objectSid", NULL };
	int count;
	uint32_t *rids = NULL;
	ADS_STATUS rc;
	LDAPMessage *res = NULL;
	LDAPMessage *msg = NULL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("ads: query_user_list\n"));

	if ( !winbindd_can_contact_domain( domain ) ) {
		DEBUG(10,("query_user_list: No incoming trust for domain %s\n",
			  domain->name));		
		return NT_STATUS_OK;
	}

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	rc = ads_search_retry(ads, &res, "(objectCategory=user)", attrs);
	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("query_user_list ads_search: %s\n", ads_errstr(rc)));
		status = ads_ntstatus(rc);
		goto done;
	} else if (!res) {
		DEBUG(1,("query_user_list ads_search returned NULL res\n"));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(1,("query_user_list: No users found\n"));
		goto done;
	}

	rids = talloc_zero_array(mem_ctx, uint32_t, count);
	if (rids == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	count = 0;

	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		struct dom_sid user_sid;
		uint32_t atype;
		bool ok;

		ok = ads_pull_uint32(ads, msg, "sAMAccountType", &atype);
		if (!ok) {
			DBG_INFO("Object lacks sAMAccountType attribute\n");
			continue;
		}
		if (ds_atype_map(atype) != SID_NAME_USER) {
			DBG_INFO("Not a user account? atype=0x%x\n", atype);
			continue;
		}

		if (!ads_pull_sid(ads, msg, "objectSid", &user_sid)) {
			char *dn = ads_get_dn(ads, talloc_tos(), msg);
			DBG_INFO("No sid for %s !?\n", dn);
			TALLOC_FREE(dn);
			continue;
		}

		if (!dom_sid_in_domain(&domain->sid, &user_sid)) {
			struct dom_sid_buf sidstr, domstr;
			DBG_WARNING("Got sid %s in domain %s\n",
				    dom_sid_str_buf(&user_sid, &sidstr),
				    dom_sid_str_buf(&domain->sid, &domstr));
			continue;
		}

		sid_split_rid(&user_sid, &rids[count]);
		count += 1;
	}

	rids = talloc_realloc(mem_ctx, rids, uint32_t, count);
	if (prids != NULL) {
		*prids = rids;
	}

	status = NT_STATUS_OK;

	DBG_NOTICE("ads query_user_list gave %d entries\n", count);

done:
	ads_msgfree(ads, res);
	return status;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32_t *num_entries,
				struct wb_acct_info **info)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"userPrincipalName", "sAMAccountName",
			       "name", "objectSid", NULL};
	int i, count;
	ADS_STATUS rc;
	LDAPMessage *res = NULL;
	LDAPMessage *msg = NULL;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	const char *filter;
	bool enum_dom_local_groups = False;

	*num_entries = 0;

	DEBUG(3,("ads: enum_dom_groups\n"));

	if ( !winbindd_can_contact_domain( domain ) ) {
		DEBUG(10,("enum_dom_groups: No incoming trust for domain %s\n",
			  domain->name));		
		return NT_STATUS_OK;
	}

	/* only grab domain local groups for our domain */
	if ( domain->active_directory && strequal(lp_realm(), domain->alt_name)  ) {
		enum_dom_local_groups = True;
	}

	/* Workaround ADS LDAP bug present in MS W2K3 SP0 and W2K SP4 w/o
	 * rollup-fixes:
	 *
	 * According to Section 5.1(4) of RFC 2251 if a value of a type is it's
	 * default value, it MUST be absent. In case of extensible matching the
	 * "dnattr" boolean defaults to FALSE and so it must be only be present
	 * when set to TRUE. 
	 *
	 * When it is set to FALSE and the OpenLDAP lib (correctly) encodes a
	 * filter using bitwise matching rule then the buggy AD fails to decode
	 * the extensible match. As a workaround set it to TRUE and thereby add
	 * the dnAttributes "dn" field to cope with those older AD versions.
	 * It should not harm and won't put any additional load on the AD since
	 * none of the dn components have a bitmask-attribute.
	 *
	 * Thanks to Ralf Haferkamp for input and testing - Guenther */

	filter = talloc_asprintf(mem_ctx, "(&(objectCategory=group)(&(groupType:dn:%s:=%d)(!(groupType:dn:%s:=%d))))", 
				 ADS_LDAP_MATCHING_RULE_BIT_AND, GROUP_TYPE_SECURITY_ENABLED,
				 ADS_LDAP_MATCHING_RULE_BIT_AND, 
				 enum_dom_local_groups ? GROUP_TYPE_BUILTIN_LOCAL_GROUP : GROUP_TYPE_RESOURCE_GROUP);

	if (filter == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	rc = ads_search_retry(ads, &res, filter, attrs);
	if (!ADS_ERR_OK(rc)) {
		status = ads_ntstatus(rc);
		DEBUG(1,("enum_dom_groups ads_search: %s\n", ads_errstr(rc)));
		goto done;
	} else if (!res) {
		DEBUG(1,("enum_dom_groups ads_search returned NULL res\n"));
		goto done;
	}

	count = ads_count_replies(ads, res);
	if (count == 0) {
		DEBUG(1,("enum_dom_groups: No groups found\n"));
		goto done;
	}

	(*info) = talloc_zero_array(mem_ctx, struct wb_acct_info, count);
	if (!*info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	i = 0;

	for (msg = ads_first_entry(ads, res); msg; msg = ads_next_entry(ads, msg)) {
		char *name, *gecos;
		struct dom_sid sid;
		uint32_t rid;

		name = ads_pull_username(ads, (*info), msg);
		gecos = ads_pull_string(ads, (*info), msg, "name");
		if (!ads_pull_sid(ads, msg, "objectSid", &sid)) {
			DEBUG(1,("No sid for %s !?\n", name));
			continue;
		}

		if (!sid_peek_check_rid(&domain->sid, &sid, &rid)) {
			DEBUG(1,("No rid for %s !?\n", name));
			continue;
		}

		(*info)[i].acct_name = name;
		(*info)[i].acct_desc = gecos;
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
				uint32_t *num_entries,
				struct wb_acct_info **info)
{
	/*
	 * This is a stub function only as we returned the domain 
	 * local groups in enum_dom_groups() if the domain->native field
	 * was true.  This is a simple performance optimization when
	 * using LDAP.
	 *
	 * if we ever need to enumerate domain local groups separately, 
	 * then this optimization in enum_dom_groups() will need
	 * to be split out
	 */
	*num_entries = 0;

	return NT_STATUS_OK;
}

/* convert a single name to a sid in a domain - use rpc methods */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const char *domain_name,
			    const char *name,
			    uint32_t flags,
			    const char **pdom_name,
			    struct dom_sid *sid,
			    enum lsa_SidType *type)
{
	return msrpc_methods.name_to_sid(domain, mem_ctx, domain_name, name,
					 flags, pdom_name, sid, type);
}

/* convert a domain SID to a user or group name - use rpc methods */
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const struct dom_sid *sid,
			    char **domain_name,
			    char **name,
			    enum lsa_SidType *type)
{
	return msrpc_methods.sid_to_name(domain, mem_ctx, sid,
					 domain_name, name, type);
}

/* convert a list of rids to names - use rpc methods */
static NTSTATUS rids_to_names(struct winbindd_domain *domain,
			      TALLOC_CTX *mem_ctx,
			      const struct dom_sid *sid,
			      uint32_t *rids,
			      size_t num_rids,
			      char **domain_name,
			      char ***names,
			      enum lsa_SidType **types)
{
	return msrpc_methods.rids_to_names(domain, mem_ctx, sid,
					   rids, num_rids,
					   domain_name, names, types);
}

/* Lookup groups a user is a member of - alternate method, for when
   tokenGroups are not available. */
static NTSTATUS lookup_usergroups_member(struct winbindd_domain *domain,
					 TALLOC_CTX *mem_ctx,
					 const char *user_dn, 
					 struct dom_sid *primary_group,
					 uint32_t *p_num_groups, struct dom_sid **user_sids)
{
	ADS_STATUS rc;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int count;
	LDAPMessage *res = NULL;
	LDAPMessage *msg = NULL;
	char *ldap_exp;
	ADS_STRUCT *ads;
	const char *group_attrs[] = {"objectSid", NULL};
	char *escaped_dn;
	uint32_t num_groups = 0;

	DEBUG(3,("ads: lookup_usergroups_member\n"));

	if ( !winbindd_can_contact_domain( domain ) ) {
		DEBUG(10,("lookup_usergroups_members: No incoming trust for domain %s\n",
			  domain->name));		
		return NT_STATUS_OK;
	}

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	if (!(escaped_dn = escape_ldap_string(talloc_tos(), user_dn))) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ldap_exp = talloc_asprintf(mem_ctx,
		"(&(member=%s)(objectCategory=group)(groupType:dn:%s:=%d))",
		escaped_dn,
		ADS_LDAP_MATCHING_RULE_BIT_AND,
		GROUP_TYPE_SECURITY_ENABLED);
	if (!ldap_exp) {
		DEBUG(1,("lookup_usergroups(dn=%s) asprintf failed!\n", user_dn));
		TALLOC_FREE(escaped_dn);
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	TALLOC_FREE(escaped_dn);

	rc = ads_search_retry(ads, &res, ldap_exp, group_attrs);

	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("lookup_usergroups ads_search member=%s: %s\n", user_dn, ads_errstr(rc)));
		return ads_ntstatus(rc);
	} else if (!res) {
		DEBUG(1,("lookup_usergroups ads_search returned NULL res\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}


	count = ads_count_replies(ads, res);

	*user_sids = NULL;
	num_groups = 0;

	/* always add the primary group to the sid array */
	status = add_sid_to_array(mem_ctx, primary_group, user_sids,
				  &num_groups);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (count > 0) {
		for (msg = ads_first_entry(ads, res); msg;
		     msg = ads_next_entry(ads, msg)) {
			struct dom_sid group_sid;

			if (!ads_pull_sid(ads, msg, "objectSid", &group_sid)) {
				DEBUG(1,("No sid for this group ?!?\n"));
				continue;
			}

			/* ignore Builtin groups from ADS - Guenther */
			if (sid_check_is_in_builtin(&group_sid)) {
				continue;
			}

			status = add_sid_to_array(mem_ctx, &group_sid,
						  user_sids, &num_groups);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}
		}

	}

	*p_num_groups = num_groups;
	status = (user_sids != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;

	DEBUG(3,("ads lookup_usergroups (member) succeeded for dn=%s\n", user_dn));
done:
	if (res) 
		ads_msgfree(ads, res);

	return status;
}

/* Lookup groups a user is a member of - alternate method, for when
   tokenGroups are not available. */
static NTSTATUS lookup_usergroups_memberof(struct winbindd_domain *domain,
					   TALLOC_CTX *mem_ctx,
					   const char *user_dn,
					   struct dom_sid *primary_group,
					   uint32_t *p_num_groups,
					   struct dom_sid **user_sids)
{
	ADS_STATUS rc;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	ADS_STRUCT *ads;
	const char *attrs[] = {"memberOf", NULL};
	uint32_t num_groups = 0;
	struct dom_sid *group_sids = NULL;
	size_t i;
	char **strings = NULL;
	size_t num_strings = 0, num_sids = 0;


	DEBUG(3,("ads: lookup_usergroups_memberof\n"));

	if ( !winbindd_can_contact_domain( domain ) ) {
		DEBUG(10,("lookup_usergroups_memberof: No incoming trust for "
			  "domain %s\n", domain->name));
		return NT_STATUS_OK;
	}

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ads_search_retry_extended_dn_ranged(ads, mem_ctx, user_dn, attrs,
						 ADS_EXTENDED_DN_HEX_STRING,
						 &strings, &num_strings);

	if (!ADS_ERR_OK(rc)) {
		DEBUG(1,("lookup_usergroups_memberof ads_search "
			"member=%s: %s\n", user_dn, ads_errstr(rc)));
		return ads_ntstatus(rc);
	}

	*user_sids = NULL;
	num_groups = 0;

	/* always add the primary group to the sid array */
	status = add_sid_to_array(mem_ctx, primary_group, user_sids,
				  &num_groups);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	group_sids = talloc_zero_array(mem_ctx, struct dom_sid, num_strings + 1);
	if (!group_sids) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<num_strings; i++) {
		rc = ads_get_sid_from_extended_dn(mem_ctx, strings[i],
						  ADS_EXTENDED_DN_HEX_STRING,
						  &(group_sids)[i]);
		if (!ADS_ERR_OK(rc)) {
			/* ignore members without SIDs */
			if (NT_STATUS_EQUAL(ads_ntstatus(rc),
			    NT_STATUS_NOT_FOUND)) {
				continue;
			}
			else {
				status = ads_ntstatus(rc);
				goto done;
			}
		}
		num_sids++;
	}

	if (i == 0) {
		DEBUG(1,("No memberOf for this user?!?\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<num_sids; i++) {

		/* ignore Builtin groups from ADS - Guenther */
		if (sid_check_is_in_builtin(&group_sids[i])) {
			continue;
		}

		status = add_sid_to_array(mem_ctx, &group_sids[i], user_sids,
					  &num_groups);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

	}

	*p_num_groups = num_groups;
	status = (*user_sids != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;

	DEBUG(3,("ads lookup_usergroups (memberof) succeeded for dn=%s\n",
		user_dn));

done:
	TALLOC_FREE(strings);
	TALLOC_FREE(group_sids);

	return status;
}


/* Lookup groups a user is a member of. */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const struct dom_sid *sid,
				  uint32_t *p_num_groups, struct dom_sid **user_sids)
{
	ADS_STRUCT *ads = NULL;
	const char *attrs[] = {"tokenGroups", "primaryGroupID", NULL};
	ADS_STATUS rc;
	int count;
	LDAPMessage *msg = NULL;
	char *user_dn = NULL;
	struct dom_sid *sids;
	int i;
	struct dom_sid primary_group;
	uint32_t primary_group_rid;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	uint32_t num_groups = 0;
	struct dom_sid_buf buf;

	DEBUG(3,("ads: lookup_usergroups\n"));
	*p_num_groups = 0;

	status = lookup_usergroups_cached(mem_ctx, sid,
					  p_num_groups, user_sids);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	if ( !winbindd_can_contact_domain( domain ) ) {
		DEBUG(10,("lookup_usergroups: No incoming trust for domain %s\n",
			  domain->name));

		/* Tell the cache manager not to remember this one */

		return NT_STATUS_SYNCHRONIZATION_REQUIRED;
	}

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	rc = ads_search_retry_sid(ads, &msg, sid, attrs);

	if (!ADS_ERR_OK(rc)) {
		status = ads_ntstatus(rc);
		DEBUG(1, ("lookup_usergroups(sid=%s) ads_search tokenGroups: "
			  "%s\n",
			  dom_sid_str_buf(sid, &buf),
			  ads_errstr(rc)));
		goto done;
	}

	count = ads_count_replies(ads, msg);
	if (count != 1) {
		status = NT_STATUS_UNSUCCESSFUL;
		DEBUG(1,("lookup_usergroups(sid=%s) ads_search tokenGroups: "
			 "invalid number of results (count=%d)\n", 
			 dom_sid_str_buf(sid, &buf),
			 count));
		goto done;
	}

	if (!msg) {
		DEBUG(1,("lookup_usergroups(sid=%s) ads_search tokenGroups: NULL msg\n", 
			 dom_sid_str_buf(sid, &buf)));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	user_dn = ads_get_dn(ads, mem_ctx, msg);
	if (user_dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (!ads_pull_uint32(ads, msg, "primaryGroupID", &primary_group_rid)) {
		DEBUG(1,("%s: No primary group for sid=%s !?\n", 
			 domain->name,
			 dom_sid_str_buf(sid, &buf)));
		goto done;
	}

	sid_compose(&primary_group, &domain->sid, primary_group_rid);

	count = ads_pull_sids(ads, mem_ctx, msg, "tokenGroups", &sids);

	/* there must always be at least one group in the token, 
	   unless we are talking to a buggy Win2k server */

	/* actually this only happens when the machine account has no read
	 * permissions on the tokenGroup attribute - gd */

	if (count == 0) {

		/* no tokenGroups */

		/* lookup what groups this user is a member of by DN search on
		 * "memberOf" */

		status = lookup_usergroups_memberof(domain, mem_ctx, user_dn,
						    &primary_group,
						    &num_groups, user_sids);
		*p_num_groups = num_groups;
		if (NT_STATUS_IS_OK(status)) {
			goto done;
		}

		/* lookup what groups this user is a member of by DN search on
		 * "member" */

		status = lookup_usergroups_member(domain, mem_ctx, user_dn, 
						  &primary_group,
						  &num_groups, user_sids);
		*p_num_groups = num_groups;
		goto done;
	}

	*user_sids = NULL;
	num_groups = 0;

	status = add_sid_to_array(mem_ctx, &primary_group, user_sids,
				  &num_groups);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	for (i=0;i<count;i++) {

		/* ignore Builtin groups from ADS - Guenther */
		if (sid_check_is_in_builtin(&sids[i])) {
			continue;
		}

		status = add_sid_to_array_unique(mem_ctx, &sids[i],
						 user_sids, &num_groups);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	*p_num_groups = (uint32_t)num_groups;
	status = (*user_sids != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;

	DEBUG(3,("ads lookup_usergroups (tokenGroups) succeeded for sid=%s\n",
		 dom_sid_str_buf(sid, &buf)));
done:
	TALLOC_FREE(user_dn);
	ads_msgfree(ads, msg);
	return status;
}

/* Lookup aliases a user is member of - use rpc methods */
static NTSTATUS lookup_useraliases(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   uint32_t num_sids, const struct dom_sid *sids,
				   uint32_t *num_aliases, uint32_t **alias_rids)
{
	return msrpc_methods.lookup_useraliases(domain, mem_ctx, num_sids, sids,
						num_aliases, alias_rids);
}

static NTSTATUS add_primary_group_members(
	ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, uint32_t rid,
	char ***all_members, size_t *num_all_members)
{
	char *filter;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	ADS_STATUS rc;
	const char *attrs[] = { "dn", NULL };
	LDAPMessage *res = NULL;
	LDAPMessage *msg;
	char **members;
	size_t num_members;
	ads_control args;

	filter = talloc_asprintf(
		mem_ctx, "(&(objectCategory=user)(primaryGroupID=%u))",
		(unsigned)rid);
	if (filter == NULL) {
		goto done;
	}

	args.control = ADS_EXTENDED_DN_OID;
	args.val = ADS_EXTENDED_DN_HEX_STRING;
	args.critical = True;

	rc = ads_do_search_all_args(ads, ads->config.bind_path,
				    LDAP_SCOPE_SUBTREE, filter, attrs, &args,
				    &res);

	if (!ADS_ERR_OK(rc)) {
		status = ads_ntstatus(rc);
		DEBUG(1,("%s: ads_search: %s\n", __func__, ads_errstr(rc)));
		goto done;
	}
	if (res == NULL) {
		DEBUG(1,("%s: ads_search returned NULL res\n", __func__));
		goto done;
	}

	num_members = ads_count_replies(ads, res);

	DEBUG(10, ("%s: Got %ju primary group members\n", __func__,
		   (uintmax_t)num_members));

	if (num_members == 0) {
		status = NT_STATUS_OK;
		goto done;
	}

	members = talloc_realloc(mem_ctx, *all_members, char *,
				 *num_all_members + num_members);
	if (members == NULL) {
		DEBUG(1, ("%s: talloc_realloc failed\n", __func__));
		goto done;
	}
	*all_members = members;

	for (msg = ads_first_entry(ads, res); msg != NULL;
	     msg = ads_next_entry(ads, msg)) {
		char *dn;

		dn = ads_get_dn(ads, members, msg);
		if (dn == NULL) {
			DEBUG(1, ("%s: ads_get_dn failed\n", __func__));
			continue;
		}

		members[*num_all_members] = dn;
		*num_all_members += 1;
	}

	status = NT_STATUS_OK;
done:
	if (res != NULL) {
		ads_msgfree(ads, res);
	}
	TALLOC_FREE(filter);
	return status;
}

/*
  find the members of a group, given a group rid and domain
 */
static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const struct dom_sid *group_sid,
				enum lsa_SidType type,
				uint32_t *num_names,
				struct dom_sid **sid_mem, char ***names,
				uint32_t **name_types)
{
	ADS_STATUS rc;
	ADS_STRUCT *ads = NULL;
	char *ldap_exp;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *sidbinstr;
	char **members = NULL;
	size_t i;
	size_t num_members = 0;
	ads_control args;
	struct dom_sid *sid_mem_nocache = NULL;
	char **names_nocache = NULL;
	enum lsa_SidType *name_types_nocache = NULL;
	char **domains_nocache = NULL;     /* only needed for rpccli_lsa_lookup_sids */
	uint32_t num_nocache = 0;
	TALLOC_CTX *tmp_ctx = NULL;
	uint32_t rid;
	struct dom_sid_buf buf;

	DEBUG(10,("ads: lookup_groupmem %s sid=%s\n", domain->name,
		  dom_sid_str_buf(group_sid, &buf)));

	*num_names = 0;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		DEBUG(1, ("ads: lookup_groupmem: talloc failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (!sid_peek_rid(group_sid, &rid)) {
		DEBUG(1, ("%s: sid_peek_rid failed\n", __func__));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if ( !winbindd_can_contact_domain( domain ) ) {
		DEBUG(10,("lookup_groupmem: No incoming trust for domain %s\n",
			  domain->name));
		return NT_STATUS_OK;
	}

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		goto done;
	}

	if ((sidbinstr = ldap_encode_ndr_dom_sid(talloc_tos(), group_sid)) == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* search for all members of the group */
	ldap_exp = talloc_asprintf(tmp_ctx, "(objectSid=%s)", sidbinstr);
	TALLOC_FREE(sidbinstr);
	if (ldap_exp == NULL) {
		DEBUG(1, ("ads: lookup_groupmem: talloc_asprintf for ldap_exp failed!\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	args.control = ADS_EXTENDED_DN_OID;
	args.val = ADS_EXTENDED_DN_HEX_STRING;
	args.critical = True;

	rc = ads_ranged_search(ads, tmp_ctx, LDAP_SCOPE_SUBTREE, ads->config.bind_path,
			       ldap_exp, &args, "member", &members, &num_members);

	if (!ADS_ERR_OK(rc)) {
		DEBUG(0,("ads_ranged_search failed with: %s\n", ads_errstr(rc)));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	DEBUG(10, ("ads lookup_groupmem: got %d sids via extended dn call\n", (int)num_members));

	status = add_primary_group_members(ads, mem_ctx, rid,
					   &members, &num_members);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("%s: add_primary_group_members failed: %s\n",
			   __func__, nt_errstr(status)));
		goto done;
	}

	DEBUG(10, ("%s: Got %d sids after adding primary group members\n",
		   __func__, (int)num_members));

	/* Now that we have a list of sids, we need to get the
	 * lists of names and name_types belonging to these sids.
	 * even though conceptually not quite clean,  we use the
	 * RPC call lsa_lookup_sids for this since it can handle a
	 * list of sids. ldap calls can just resolve one sid at a time.
	 *
	 * At this stage, the sids are still hidden in the exetended dn
	 * member output format. We actually do a little better than
	 * stated above: In extracting the sids from the member strings,
	 * we try to resolve as many sids as possible from the
	 * cache. Only the rest is passed to the lsa_lookup_sids call. */

	if (num_members) {
		(*sid_mem) = talloc_zero_array(mem_ctx, struct dom_sid, num_members);
		(*names) = talloc_zero_array(mem_ctx, char *, num_members);
		(*name_types) = talloc_zero_array(mem_ctx, uint32_t, num_members);
		(sid_mem_nocache) = talloc_zero_array(tmp_ctx, struct dom_sid, num_members);

		if ((members == NULL) || (*sid_mem == NULL) ||
		    (*names == NULL) || (*name_types == NULL) ||
		    (sid_mem_nocache == NULL))
		{
			DEBUG(1, ("ads: lookup_groupmem: talloc failed\n"));
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}
	else {
		(*sid_mem) = NULL;
		(*names) = NULL;
		(*name_types) = NULL;
	}

	for (i=0; i<num_members; i++) {
		enum lsa_SidType name_type;
		char *name, *domain_name;
		struct dom_sid sid;

	        rc = ads_get_sid_from_extended_dn(tmp_ctx, members[i], args.val,
		    &sid);
		if (!ADS_ERR_OK(rc)) {
			if (NT_STATUS_EQUAL(ads_ntstatus(rc),
			    NT_STATUS_NOT_FOUND)) {
				/* Group members can be objects, like Exchange
				 * Public Folders, that don't have a SID.  Skip
				 * them. */
				continue;
			}
			else {
				status = ads_ntstatus(rc);
				goto done;
			}
		}
		if (lookup_cached_sid(mem_ctx, &sid, &domain_name, &name,
		    &name_type)) {
			DEBUG(10,("ads: lookup_groupmem: got sid %s from "
				  "cache\n",
				  dom_sid_str_buf(&sid, &buf)));
			sid_copy(&(*sid_mem)[*num_names], &sid);
			(*names)[*num_names] = fill_domain_username_talloc(
							*names,
							domain_name,
							name,
							true);

			(*name_types)[*num_names] = name_type;
			(*num_names)++;
		}
		else {
			DEBUG(10, ("ads: lookup_groupmem: sid %s not found in "
				   "cache\n",
				   dom_sid_str_buf(&sid, &buf)));
			sid_copy(&(sid_mem_nocache)[num_nocache], &sid);
			num_nocache++;
		}
	}

	DEBUG(10, ("ads: lookup_groupmem: %d sids found in cache, "
		  "%d left for lsa_lookupsids\n", *num_names, num_nocache));

	/* handle sids not resolved from cache by lsa_lookup_sids */
	if (num_nocache > 0) {

		status = winbindd_lookup_sids(tmp_ctx,
					      domain,
					      num_nocache,
					      sid_mem_nocache,
					      &domains_nocache,
					      &names_nocache,
					      &name_types_nocache);

		if (!(NT_STATUS_IS_OK(status) ||
		      NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED) ||
		      NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)))
		{
			DEBUG(1, ("lsa_lookupsids call failed with %s "
				  "- retrying...\n", nt_errstr(status)));

			status = winbindd_lookup_sids(tmp_ctx,
						      domain,
						      num_nocache,
						      sid_mem_nocache,
						      &domains_nocache,
						      &names_nocache,
						      &name_types_nocache);
		}

		if (NT_STATUS_IS_OK(status) ||
		    NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED))
		{
			/* Copy the entries over from the "_nocache" arrays
			 * to the result arrays, skipping the gaps the
			 * lookup_sids call left. */
			for (i=0; i < num_nocache; i++) {
				if (((names_nocache)[i] != NULL) &&
				    ((name_types_nocache)[i] != SID_NAME_UNKNOWN))
				{
					sid_copy(&(*sid_mem)[*num_names],
						 &sid_mem_nocache[i]);
					(*names)[*num_names] =
						fill_domain_username_talloc(
							*names,
							domains_nocache[i],
							names_nocache[i],
							true);
					(*name_types)[*num_names] = name_types_nocache[i];
					(*num_names)++;
				}
			}
		}
		else if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
			DEBUG(10, ("lookup_groupmem: lsa_lookup_sids could "
				   "not map any SIDs at all.\n"));
			/* Don't handle this as an error here.
			 * There is nothing left to do with respect to the 
			 * overall result... */
		}
		else if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("lookup_groupmem: Error looking up %d "
				   "sids via rpc_lsa_lookup_sids: %s\n",
				   (int)num_members, nt_errstr(status)));
			goto done;
		}
	}

	status = NT_STATUS_OK;
	DEBUG(3,("ads lookup_groupmem for sid=%s succeeded\n",
		 dom_sid_str_buf(group_sid, &buf)));

done:

	TALLOC_FREE(tmp_ctx);

	return status;
}

/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32_t *seq)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS rc;

	DEBUG(3,("ads: fetch sequence_number for %s\n", domain->name));

	if ( !winbindd_can_contact_domain( domain ) ) {
		DEBUG(10,("sequence: No incoming trust for domain %s\n",
			  domain->name));
		*seq = time(NULL);		
		return NT_STATUS_OK;
	}

	if (IS_AD_DC) {
		DEBUG(10,("sequence: Avoid LDAP connection for domain %s\n",
			  domain->name));
		*seq = time(NULL);
		return NT_STATUS_OK;
	}

	*seq = DOM_SEQUENCE_NONE;

	ads = ads_cached_connection(domain);

	if (!ads) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		return NT_STATUS_UNSUCCESSFUL;
	}

	rc = ads_USN(ads, seq);

	if (!ADS_ERR_OK(rc)) {

		/* its a dead connection, destroy it */

		if (domain->private_data) {
			ads = (ADS_STRUCT *)domain->private_data;
			ads->is_mine = True;
			ads_destroy(&ads);
			ads_kdestroy(WINBIND_CCACHE_NAME);
			domain->private_data = NULL;
		}
	}
	return ads_ntstatus(rc);
}

/* find the lockout policy of a domain - use rpc methods */
static NTSTATUS lockout_policy(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       struct samr_DomInfo12 *policy)
{
	return msrpc_methods.lockout_policy(domain, mem_ctx, policy);
}

/* find the password policy of a domain - use rpc methods */
static NTSTATUS password_policy(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				struct samr_DomInfo1 *policy)
{
	return msrpc_methods.password_policy(domain, mem_ctx, policy);
}

/* get a list of trusted domains */
static NTSTATUS trusted_domains(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				struct netr_DomainTrustList *trusts)
{
	NTSTATUS 		result = NT_STATUS_UNSUCCESSFUL;
	WERROR werr;
	uint32_t		i;
	uint32_t		flags;
	struct rpc_pipe_client *cli;
	int ret_count;
	struct dcerpc_binding_handle *b;

	DEBUG(3,("ads: trusted_domains\n"));

	ZERO_STRUCTP(trusts);

	/* If this is our primary domain or a root in our forest,
	   query for all trusts.  If not, then just look for domain
	   trusts in the target forest */

	if (domain->primary || domain_is_forest_root(domain)) {
		flags = NETR_TRUST_FLAG_OUTBOUND |
			NETR_TRUST_FLAG_INBOUND |
			NETR_TRUST_FLAG_IN_FOREST;
	} else {
		flags = NETR_TRUST_FLAG_IN_FOREST;
	}	

	result = cm_connect_netlogon(domain, &cli);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(5, ("trusted_domains: Could not open a connection to %s "
			  "for PIPE_NETLOGON (%s)\n", 
			  domain->name, nt_errstr(result)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	b = cli->binding_handle;

	result = dcerpc_netr_DsrEnumerateDomainTrusts(b, mem_ctx,
						      cli->desthost,
						      flags,
						      trusts,
						      &werr);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (!W_ERROR_IS_OK(werr)) {
		return werror_to_ntstatus(werr);
	}
	if (trusts->count == 0) {
		return NT_STATUS_OK;
	}

	/* Copy across names and sids */

	ret_count = 0;
	for (i = 0; i < trusts->count; i++) {
		struct netr_DomainTrust *trust = &trusts->array[i];
		struct winbindd_domain d;

		ZERO_STRUCT(d);

		/*
		 * drop external trusts if this is not our primary
		 * domain.  This means that the returned number of
		 * domains may be less that the ones actually trusted
		 * by the DC.
		 */

		if ((trust->trust_attributes
		     & LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) &&
		    !domain->primary )
		{
			DEBUG(10,("trusted_domains: Skipping external trusted "
				  "domain %s because it is outside of our "
				  "primary domain\n",
				  trust->netbios_name));
			continue;
		}

		/* add to the trusted domain cache */

		d.name = discard_const_p(char, trust->netbios_name);
		d.alt_name = discard_const_p(char, trust->dns_name);

		if (trust->sid) {
			sid_copy(&d.sid, trust->sid);
		} else {
			sid_copy(&d.sid, &global_sid_NULL);
		}

		if ( domain->primary ) {
			DEBUG(10,("trusted_domains(ads):  Searching "
				  "trusted domain list of %s and storing "
				  "trust flags for domain %s\n",
				  domain->name, d.alt_name));

			d.domain_flags = trust->trust_flags;
			d.domain_type = trust->trust_type;
			d.domain_trust_attribs = trust->trust_attributes;

			wcache_tdc_add_domain( &d );
			ret_count++;
		} else if (domain_is_forest_root(domain)) {
			/* Check if we already have this record. If
			 * we are following our forest root that is not
			 * our primary domain, we want to keep trust
			 * flags from the perspective of our primary
			 * domain not our forest root. */
			struct winbindd_tdc_domain *exist = NULL;

			exist = wcache_tdc_fetch_domain(
				talloc_tos(), trust->netbios_name);
			if (!exist) {
				DEBUG(10,("trusted_domains(ads):  Searching "
					  "trusted domain list of %s and "
					  "storing trust flags for domain "
					  "%s\n", domain->name, d.alt_name));
				d.domain_flags = trust->trust_flags;
				d.domain_type = trust->trust_type;
				d.domain_trust_attribs =
					trust->trust_attributes;

				wcache_tdc_add_domain( &d );
				ret_count++;
			}
			TALLOC_FREE(exist);
		} else {
			/* This gets a little tricky.  If we are
			   following a transitive forest trust, then
			   innerit the flags, type, and attribs from
			   the domain we queried to make sure we don't
			   record the view of the trust from the wrong
			   side.  Always view it from the side of our
			   primary domain.   --jerry */
			struct winbindd_tdc_domain *parent = NULL;

			DEBUG(10,("trusted_domains(ads):  Searching "
				  "trusted domain list of %s and inheriting "
				  "trust flags for domain %s\n",
				  domain->name, d.alt_name));

			parent = wcache_tdc_fetch_domain(talloc_tos(),
							 domain->name);
			if (parent) {
				d.domain_flags = parent->trust_flags;
				d.domain_type  = parent->trust_type;
				d.domain_trust_attribs = parent->trust_attribs;
			} else {
				d.domain_flags = domain->domain_flags;
				d.domain_type  = domain->domain_type;
				d.domain_trust_attribs =
					domain->domain_trust_attribs;
			}
			TALLOC_FREE(parent);

			/*
			 * We need to pass the modified properties
			 * to the caller.
			 */
			trust->trust_flags = d.domain_flags;
			trust->trust_type = d.domain_type;
			trust->trust_attributes = d.domain_trust_attribs;

			wcache_tdc_add_domain( &d );
			ret_count++;
		}
	}
	return result;
}

/* the ADS backend methods are exposed via this structure */
struct winbindd_methods ads_methods = {
	True,
	query_user_list,
	enum_dom_groups,
	enum_local_groups,
	name_to_sid,
	sid_to_name,
	rids_to_names,
	lookup_usergroups,
	lookup_useraliases,
	lookup_groupmem,
	sequence_number,
	lockout_policy,
	password_policy,
	trusted_domains,
};

#endif
