/*
  Unix SMB/CIFS implementation.
  Active Directory SAM backend, for simulate a W2K DC in mixed mode.

  Copyright (C) Stefan (metze) Metzmacher	2002
  Copyright (C) Andrew Bartlett		2002

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


#ifdef HAVE_LDAP

static int sam_ads_debug_level = DBGC_SAM;

#undef DBGC_CLASS
#define DBGC_CLASS sam_ads_debug_level

#define ADS_STATUS_OK ADS_ERROR(0)
#define ADS_STATUS_UNSUCCESSFUL ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL)
#define ADS_STATUS_NOT_IMPLEMENTED ADS_ERROR_NT(NT_STATUS_NOT_IMPLEMENTED)


#define ADS_SUBTREE_BUILTIN	"CN=Builtin,"
#define ADS_SUBTREE_COMPUTERS	"CN=Computers,"
#define	ADS_SUBTREE_DC		"CN=Domain Controllers,"
#define ADS_SUBTREE_USERS 	"CN=Users,"
#define ADS_ROOT_TREE		""
/* Here are private module structs and functions */

struct sam_ads_privates {
	ADS_STRUCT 	*ads_struct;
	TALLOC_CTX	*mem_ctx;
	BOOL            bind_plaintext;
	char            *ads_bind_dn;
	char            *ads_bind_pw;
	char            *ldap_uri;
	/* did we need something more? */
};


/* get only these LDAP attributes, witch we really need for an account */
const char *account_attrs[] = {	"objectSid",
				"objectGUID", 
				"sAMAccountType",
				"sAMAcountName",
				"userPrincipalName",
				"accountExpires",
				"badPasswordTime",
				"badPwdCount",
				"lastLogoff",
				"lastLogon",
				"userWorkstations",
				"dBCSPwd",
				"unicodePwd",
				"pwdLastSet",
				"userAccountControl",
				"profilePath",
				"homeDrive",
				"scriptPath",
				"homeDirectory",
				"cn",
				"primaryGroupID",/* 513 */
				"nsNPAllowDialIn",/* TRUE */
				"userParameters",/* Dial Back number ...*/
				"codePage",/* 0 */
				"countryCode",/* 0 */
				"adminCount",/* 1 or 0 */
				"logonCount",/* 0 */
				"managedObjects",
				"memberOf",/* dn */
				"instanceType",/* 4 */
				"name", /* sync with cn */
				"description",
				/* "nTSecurityDescriptor", */
				NULL};
			
/* get only these LDAP attributes, witch we really need for a group */			
const char *group_attrs[] = {"objectSid",
			     /* "objectGUID", */ 
			     "sAMAccountType",
			     "sAMAcountName",
			     "groupType",
			     /* "member", */
			     "description",
			     "name", /* sync with cn */
			     /* "nTSecurityDescriptor", */
			     NULL};
			

/***************************************************
  return our ads connection. We keep the connection
  open to make things faster
****************************************************/
static ADS_STATUS sam_ads_cached_connection(struct sam_ads_privates *private)
{
	ADS_STRUCT 	*ads_struct;
	ADS_STATUS	ads_status;
	
	if (!private->ads_struct) {
		private->ads_struct = ads_init_simple();
		ads_struct = private->ads_struct;
		ads_struct->server.ldap_uri = smb_xstrdup(private->ldap_uri);
		if ((!private->ads_bind_dn) || (!*private->ads_bind_dn)) {
			ads_struct->auth.flags |= ADS_AUTH_ANON_BIND;
		} else {
			ads_struct->auth.user_name 
				= smb_xstrdup(private->ads_bind_dn);
			if (private->ads_bind_pw) {
				ads_struct->auth.password 
					= smb_xstrdup(private->ads_bind_pw);
			}
		}
		if (private->bind_plaintext) {
			ads_struct->auth.flags |= ADS_AUTH_SIMPLE_BIND;
		}
	} else {
		ads_struct = private->ads_struct;
	}

	if (ads_struct->ld != NULL) {		
		/* connection has been opened. ping server. */
		struct sockaddr_un addr;
		socklen_t len;
		int sd;
		if (ldap_get_option(ads_struct->ld, LDAP_OPT_DESC, &sd) == 0 &&
		    getpeername(sd, (struct sockaddr *) &addr, &len) < 0) {
		    	/* the other end has died. reopen. */
		    	ldap_unbind_ext(ads_struct->ld, NULL, NULL);
		    	ads_struct->ld = NULL;
		}
    	}

	if (ads_struct->ld != NULL) {
		DEBUG(5,("sam_ads_cached_connection: allready connected to the LDAP server\n"));
		return ADS_SUCCESS;
	}

	ads_status = ads_connect(ads_struct);

	ads_status = ads_server_info(ads_struct);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(0,("Can't set server info: %s\n",ads_errstr(ads_status)));
		/* return ads_status; */ /*for now we only warn! */
	}

	DEBUG(2, ("sam_ads_cached_connection: succesful connection to the LDAP server\n"));
	return ADS_SUCCESS;
}

static ADS_STATUS sam_ads_do_search(struct sam_ads_privates *private, const char *bind_path, int scope, const char *exp, const char **attrs, void **res)
{
	ADS_STATUS	ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	
	ads_status = sam_ads_cached_connection(private);
	if (!ADS_ERR_OK(ads_status))
		return ads_status;
		
	return ads_do_search_retry(private->ads_struct, bind_path, scope, exp, attrs, res);		
}

/***********************************************
Initialize SAM_ACCOUNT_HANDLE from an ADS query
************************************************/
/* not ready :-( */
static ADS_STATUS ads_entry2sam_account_handle(ADS_STRUCT *ads_struct, SAM_ACCOUNT_HANDLE *account ,const void *entry)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(ads_struct && account && entry);



	return ads_status;
}


/***********************************************
Initialize SAM_GROUP_ENUM from an ads entry
************************************************/
/* not ready :-( */
static ADS_STATUS ads_entry2sam_group_enum(ADS_STRUCT *ads_struct, TALLOC_CTX *mem_ctx, SAM_GROUP_ENUM **group_enum,const void *entry)
{
	ADS_STATUS 	ads_status = ADS_STATUS_UNSUCCESSFUL;
	SAM_GROUP_ENUM	__group_enum;
	SAM_GROUP_ENUM  *_group_enum = &__group_enum;
	
	SAM_ASSERT(ads_struct && mem_ctx && group_enum && entry);
	
	*group_enum = _group_enum;
	
	DEBUG(3,("sam_ads: ads_entry2sam_account_handle\n"));

	if (!ads_pull_sid((ADS_STRUCT *)ads_struct, &entry, "objectSid", &(_group_enum->sid))) {
		DEBUG(0,("No sid for!?\n"));
		return ADS_STATUS_UNSUCCESSFUL;
	}
	
	if (!(_group_enum->group_name = ads_pull_string((ADS_STRUCT *)ads_struct, mem_ctx, &entry, "sAMAccountName"))) {
		DEBUG(0,("No groupname found"));
		return ADS_STATUS_UNSUCCESSFUL;
	}

	if (!(_group_enum->group_desc = ads_pull_string((ADS_STRUCT *)ads_struct, mem_ctx, &entry, "desciption"))) {
		DEBUG(0,("No description found"));
		return ADS_STATUS_UNSUCCESSFUL;
	}	

	DEBUG(0,("sAMAccountName: %s\ndescription: %s\nobjectSid: %s\n",
		 _group_enum->group_name,
		 _group_enum->group_desc,
		 sid_string_static(&(_group_enum->sid))
		      ));
	
	return ads_status;
}

static ADS_STATUS sam_ads_access_check(const SAM_METHODS *sam_method, const SEC_DESC *sd, const NT_USER_TOKEN *access_token, uint32 access_desired)
{
	ADS_STATUS	ads_status = ADS_ERROR_NT(NT_STATUS_ACCESS_DENIED);
	NTSTATUS	nt_status;
	uint32		acc_granted;

	SAM_ASSERT(sam_method && sd && access_token);	
	/* the steps you need are: 
	   1. get_sec_desc for sid 
	   2. se_map_generic(accessdesired, generic_mapping) 
	   3. se_access_check()	*/

	if (!se_access_check(sd, access_token, access_desired, &acc_granted, &nt_status)) {
		DEBUG(3,("sam_ads_access_check: ACCESS DENIED\n"));
		ads_status = ADS_ERROR_NT(nt_status);
		return ads_status;
	}
	ads_status = ADS_ERROR_NT(nt_status);	
	return ads_status;
}

static ADS_STATUS sam_ads_get_tree_sec_desc(const SAM_METHODS *sam_method, const char *subtree, SEC_DESC **sd)
{
	ADS_STATUS		ads_status = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	struct sam_ads_privates *privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;
	char			*search_path;
	void 			*sec_desc_res;
	void 			*sec_desc_msg;
	const char		*sec_desc_attrs[] = {"nTSecurityDescriptor",NULL};
		
	SAM_ASSERT(sam_method && ads_struct && sd);
	*sd = NULL;
		
	if (subtree) {
		asprintf(&search_path, "%s%s",subtree,ads_struct->config.bind_path);
	} else {
		asprintf(&search_path, "%s","");
	}
	ads_status = sam_ads_do_search(privates, search_path, LDAP_SCOPE_BASE, "(objectClass=*)", sec_desc_attrs, &sec_desc_res);
	SAFE_FREE(search_path);
	if (!ADS_ERR_OK(ads_status))
		return ads_status;
		
	if ((sec_desc_msg = ads_first_entry(ads_struct, sec_desc_res))==NULL) {
		ads_status = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		return ads_status;		
	}		
			
	if (!ads_pull_sd(ads_struct, mem_ctx, sec_desc_msg, sec_desc_attrs[0], sd)) {
		*sd = NULL;
		ads_status = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		return ads_status;
	}	 	
	
	return ads_status;	
}

static ADS_STATUS sam_ads_account_policy_get(const SAM_METHODS *sam_method, int field, uint32 *value)
{
	ADS_STATUS	ads_status = ADS_ERROR_NT(NT_STATUS_NOT_IMPLEMENTED);
	DEBUG(0,("sam_ads: %s needs to be done! %s\n",__FUNCTION__,ads_errstr(ads_status)));

	SAM_ASSERT(sam_method && value);
	
	/* Fix Me */
	switch(field) {
		/* Fix Me */
		default: *value = 0; break;
	}
	
	return ads_status;	
}

/**********************************
Now the functions off the SAM API 
***********************************/

/* General API */
static NTSTATUS sam_ads_get_sec_desc(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, 
			      const DOM_SID *sid, SEC_DESC **sd)
{
	ADS_STATUS		ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	struct sam_ads_privates *privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx;
	char			*sidstr,*filter;
	void 			*sec_desc_res;
	void 			*sec_desc_msg;
	const char		*sec_desc_attrs[] = {"nTSecurityDescriptor",NULL};
	fstring                 sid_str;
	SEC_DESC		*my_sd;

	SAM_ASSERT(sam_method && access_token && sid && sd);	
	
	ads_status = sam_ads_get_tree_sec_desc(sam_method, ADS_ROOT_TREE, &my_sd);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(sam_method, my_sd, access_token, DOMAIN_READ);

	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	sidstr = sid_binstring(sid);
	if (asprintf(&filter, "(objectSid=%s)", sidstr) == -1) {
		SAFE_FREE(sidstr);
		return NT_STATUS_NO_MEMORY;
	}

	SAFE_FREE(sidstr);

	ads_status = sam_ads_do_search(privates,ads_struct->config.bind_path, 
				       LDAP_SCOPE_SUBTREE, filter, sec_desc_attrs,
				       &sec_desc_res);
	SAFE_FREE(filter);

	if (!ADS_ERR_OK(ads_status)) {
		return ads_ntstatus(ads_status);
	}

	sec_desc_msg  = ads_first_entry(ads_struct, sec_desc_res);

	if (!(mem_ctx = talloc_init_named("sec_desc parse in sam_ads"))) {
		DEBUG(1, ("talloc_init_named() failed for sec_desc parse context in sam_ads"));
		ads_msgfree(ads_struct, sec_desc_res);
		return NT_STATUS_NO_MEMORY;
	}

	if (!ads_pull_sd(ads_struct, mem_ctx, sec_desc_msg, sec_desc_attrs[0], sd)) {
		talloc_destroy(mem_ctx);
		ads_msgfree(ads_struct, sec_desc_res);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!ADS_ERR_OK(ads_status)) {
		talloc_destroy(mem_ctx);
		ads_msgfree(ads_struct, sec_desc_res);
		return ads_ntstatus(ads_status);
	}

	if (ads_count_replies(ads_struct, sec_desc_res) != 1) {
		DEBUG(1,("sam_ads_get_sec_desc: duplicate or 0 results for sid %s\n", 
			 sid_to_string(sid_str, sid)));
		talloc_destroy(mem_ctx);
		ads_msgfree(ads_struct, sec_desc_res);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!(sec_desc_msg = ads_first_entry(ads_struct, sec_desc_res))) {
		talloc_destroy(mem_ctx);
		ads_msgfree(ads_struct, sec_desc_res);
		return NT_STATUS_INVALID_PARAMETER;
	}		
			
	if (!ads_pull_sd(ads_struct, mem_ctx, sec_desc_msg, sec_desc_attrs[0], sd)) {
		ads_status = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		talloc_destroy(mem_ctx);
		ads_msgfree(ads_struct, sec_desc_res);
		return ads_ntstatus(ads_status);
	}	 
	
	/* now, were we allowed to see the SD we just got? */

	ads_msgfree(ads_struct, sec_desc_res);
	talloc_destroy(mem_ctx);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_set_sec_desc(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, 
			      const DOM_SID *sid, const SEC_DESC *sd)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

	
static NTSTATUS sam_ads_lookup_sid(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, 
			    TALLOC_CTX *mem_ctx, const DOM_SID *sid, char **name, 
			    enum SID_NAME_USE *type)
{
	struct sam_ads_privates *privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	SAM_ASSERT(sam_method);

	/* Ignoring access_token for now */

	return ads_sid_to_name(ads_struct, mem_ctx, sid, name, type);
}

static NTSTATUS sam_ads_lookup_name(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, 
			     const char *name, DOM_SID *sid, enum SID_NAME_USE *type)
{
	struct sam_ads_privates *privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	SAM_ASSERT(sam_method);

	/* Ignoring access_token for now */

	return ads_name_to_sid(ads_struct, name, sid, type);
}

	
/* Domain API */

static NTSTATUS sam_ads_update_domain(const SAM_METHODS *sam_method, const SAM_DOMAIN_HANDLE *domain)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_domain_handle(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, 
				   const uint32 access_desired, SAM_DOMAIN_HANDLE **domain)
{
	ADS_STATUS		ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	struct sam_ads_privates *privates = (struct sam_ads_privates *)sam_method->private_data;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;	/*Fix me is this right??? */
	SAM_DOMAIN_HANDLE	*dom_handle = NULL;
	SEC_DESC		*sd;
	uint32			acc_granted;
	uint32			tmp_value;

	DEBUG(5,("sam_ads_get_domain_handle: %d\n",__LINE__));
	
	SAM_ASSERT(sam_method && domain);
	
	(*domain) = NULL;

	if ((dom_handle = talloc(mem_ctx, sizeof(SAM_DOMAIN_HANDLE))) == NULL) {
		DEBUG(0,("failed to talloc dom_handle\n"));
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			return ads_ntstatus(ads_status);
	}

	ZERO_STRUCTP(dom_handle);

	dom_handle->mem_ctx = mem_ctx; /*Fix me is this right??? */
	dom_handle->free_fn = NULL;
	dom_handle->current_sam_methods = sam_method;

	/* check if access can be granted as requested */

	ads_status = sam_ads_get_tree_sec_desc(sam_method, ADS_ROOT_TREE, &sd);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(sam_method, sd, access_token, access_desired);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	dom_handle->access_granted = acc_granted;

	/* fill all the values of dom_handle */
	sid_copy(&dom_handle->private.sid, &sam_method->domain_sid);
	dom_handle->private.name       = smb_xstrdup(sam_method->domain_name);
	dom_handle->private.servername = "WHOKNOWS"; /* what is the servername */

	/*Fix me: sam_ads_account_policy_get() return ADS_STATUS! */ 
	ads_status = sam_ads_account_policy_get(sam_method, AP_MAX_PASSWORD_AGE, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for max password age. Useing default\n"));
		tmp_value = MAX_PASSWORD_AGE;
	}
	unix_to_nt_time_abs(&dom_handle->private.max_passwordage,tmp_value);

	ads_status = sam_ads_account_policy_get(sam_method, AP_MIN_PASSWORD_AGE, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for min password age. Useing default\n"));
		tmp_value = 0;
	}
	unix_to_nt_time_abs(&dom_handle->private.min_passwordage, tmp_value);

	ads_status = sam_ads_account_policy_get(sam_method, AP_LOCK_ACCOUNT_DURATION, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for lockout duration. Useing default\n"));
		tmp_value = 0;
	}
	unix_to_nt_time_abs(&dom_handle->private.lockout_duration, tmp_value);

	ads_status = sam_ads_account_policy_get(sam_method, AP_RESET_COUNT_TIME, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for time till locout count is reset. Useing default\n"));
		tmp_value = 0;
	}
	unix_to_nt_time_abs(&dom_handle->private.reset_count, tmp_value);

	ads_status = sam_ads_account_policy_get(sam_method, AP_MIN_PASSWORD_LEN, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for min password length. Useing default\n"));
		tmp_value = 0;
	}
	dom_handle->private.min_passwordlength = (uint16)tmp_value;

	ads_status = sam_ads_account_policy_get(sam_method, AP_PASSWORD_HISTORY, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed password history. Useing default\n"));
		tmp_value = 0;
	}
	dom_handle->private.password_history = (uint16)tmp_value;

	ads_status = sam_ads_account_policy_get(sam_method, AP_BAD_ATTEMPT_LOCKOUT, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for bad attempts till lockout. Useing default\n"));
		tmp_value = 0;
	}
	dom_handle->private.lockout_count = (uint16)tmp_value;

	ads_status = sam_ads_account_policy_get(sam_method, AP_TIME_TO_LOGOUT, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for force logout. Useing default\n"));
		tmp_value = -1;
	}

	ads_status = sam_ads_account_policy_get(sam_method, AP_USER_MUST_LOGON_TO_CHG_PASS, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for user must login to change password. Useing default\n"));
		tmp_value = 0;
	}

	/* should the real values of num_accounts, num_groups and num_aliases be retreved?
	 * I think it is to expensive to bother
	 */
	dom_handle->private.num_accounts = 3;
	dom_handle->private.num_groups   = 4;
	dom_handle->private.num_aliases  = 5;

	*domain = dom_handle;
	
	ads_status = ADS_ERROR_NT(NT_STATUS_OK);
	return ads_ntstatus(ads_status);
}

/* Account API */
static NTSTATUS sam_ads_create_account(const SAM_METHODS *sam_method, 
				const NT_USER_TOKEN *access_token, uint32 access_desired, 
				const char *account_name, uint16 acct_ctrl, SAM_ACCOUNT_HANDLE **account)
{
	ADS_STATUS		ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	struct sam_ads_privates *privates = (struct sam_ads_privates *)sam_method->private_data;
	SEC_DESC		*sd = NULL;

	SAM_ASSERT(sam_method && access_token && account_name && account);

	ads_status = sam_ads_get_tree_sec_desc(sam_method, ADS_SUBTREE_USERS, &sd);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(sam_method, sd, access_token, access_desired);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = ADS_ERROR_NT(sam_init_account(account));
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);	

	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_add_account(const SAM_METHODS *sam_method, const SAM_ACCOUNT_HANDLE *account)
{
	ADS_STATUS		ads_status = ADS_ERROR(LDAP_NO_MEMORY);
	struct sam_ads_privates *privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;
	ADS_MODLIST 		mods;
 	uint16 			acct_ctrl;
 	char 			*new_dn;

	SAM_ASSERT(sam_method && account);

	ads_status = ADS_ERROR_NT(sam_get_account_acct_ctrl(account,&acct_ctrl));
	if (!ADS_ERR_OK(ads_status))
		goto done;
			
	if ((acct_ctrl & ACB_WSTRUST)||(acct_ctrl & ACB_SVRTRUST)) {
		/* Computer account */
		char		*name,*controlstr;
		char		*hostname,*host_upn,*host_spn;
		const char 	*objectClass[] = {"top", "person", "organizationalPerson",
						  "user", "computer", NULL};

		ads_status = ADS_ERROR_NT(sam_get_account_name(account,&name));
		if (!ADS_ERR_OK(ads_status))
			goto done;

		if (!(host_upn = talloc_asprintf(mem_ctx, "%s@%s", name, ads_struct->config.realm))) {
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}

		if (!(new_dn = talloc_asprintf(mem_ctx, "CN=%s,CN=Computers,%s", hostname, 
					       ads_struct->config.bind_path))) {
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}
					
		if (!(controlstr = talloc_asprintf(mem_ctx, "%u", ads_acb2uf(acct_ctrl)))) {
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}
		
		if (!(mods = ads_init_mods(mem_ctx))) {
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}
		
		ads_status = ads_mod_str(mem_ctx, &mods, "cn", hostname);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_strlist(mem_ctx, &mods, "objectClass", objectClass);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "userPrincipalName", host_upn);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "displayName", hostname);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "sAMAccountName", name);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "userAccountControl", controlstr);
		if (!ADS_ERR_OK(ads_status))
			goto done;	

		ads_status = ads_mod_str(mem_ctx, &mods, "servicePrincipalName", host_spn);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "dNSHostName", hostname);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "userAccountControl", controlstr);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		/*	ads_status = ads_mod_str(mem_ctx, &mods, "operatingSystem", "Samba");
			if (!ADS_ERR_OK(ads_status))
			goto done;
		*//*	ads_status = ads_mod_str(mem_ctx, &mods, "operatingSystemVersion", VERSION);
			if (!ADS_ERR_OK(ads_status))
			goto done;
		  */		
		/* End Computer account */
	} else {
		/* User account*/
		char	 	*upn, *controlstr;
		char		*name, *fullname;
		const char 	*objectClass[] = {"top", "person", "organizationalPerson",
						  "user", NULL};

		ads_status = ADS_ERROR_NT(sam_get_account_name(account,&name));
		if (!ADS_ERR_OK(ads_status))
			goto done;

		ads_status = ADS_ERROR_NT(sam_get_account_fullname(account,&fullname));
		if (!ADS_ERR_OK(ads_status))
			goto done;

		if (!(upn = talloc_asprintf(mem_ctx, "%s@%s", name, ads_struct->config.realm))) {
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}

		if (!(new_dn = talloc_asprintf(mem_ctx, "CN=%s,CN=Users,%s", fullname, 
					       ads_struct->config.bind_path))) {
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}
					
		if (!(controlstr = talloc_asprintf(mem_ctx, "%u", ads_acb2uf(acct_ctrl)))) {
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}
		
		if (!(mods = ads_init_mods(mem_ctx))) {
			ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
			goto done;
		}
		
		ads_status = ads_mod_str(mem_ctx, &mods, "cn", fullname);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_strlist(mem_ctx, &mods, "objectClass", objectClass);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "userPrincipalName", upn);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "displayName", fullname);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "sAMAccountName", name);
		if (!ADS_ERR_OK(ads_status))
			goto done;
		ads_status = ads_mod_str(mem_ctx, &mods, "userAccountControl", controlstr);
		if (!ADS_ERR_OK(ads_status))
			goto done;	
	}/* End User account */	

	/* Finally at the account */
	ads_status = ads_gen_add(ads_struct, new_dn, mods);

done:
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_update_account(const SAM_METHODS *sam_method, const SAM_ACCOUNT_HANDLE *account)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_delete_account(const SAM_METHODS *sam_method, const SAM_ACCOUNT_HANDLE *account)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);



	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_enum_accounts(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, uint16 acct_ctrl, uint32 *account_count, SAM_ACCOUNT_ENUM **accounts)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_account_by_sid(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *accountsid, SAM_ACCOUNT_HANDLE **account)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_account_by_name(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *name, SAM_ACCOUNT_HANDLE **account)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}


/* Group API */
static NTSTATUS sam_ads_create_group(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *group_name, uint16 group_ctrl, SAM_GROUP_HANDLE **group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_add_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_update_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_delete_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_enum_groups(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint16 group_ctrl, uint32 *groups_count, SAM_GROUP_ENUM **groups)
{
	ADS_STATUS		ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	struct sam_ads_privates *privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;
	void			*res = NULL;
	void			*msg = NULL;
	char 			*filter = NULL;
	int			i = 0;
	
	/* get only these LDAP attributes, witch we really need for a group */			
	const char *group_enum_attrs[] = {"objectSid",
					  "description",
					  "sAMAcountName",
					  NULL};
	
	SAM_ASSERT(sam_method && access_token && groups_count && groups);
	
	*groups_count = 0;

	DEBUG(3,("ads: enum_dom_groups\n"));

	/* Fix Me: get only group from the wanted Type */
	asprintf(&filter, "(&(objectClass=group)(groupType=%s))", "*");
	ads_status = sam_ads_do_search(privates, ads_struct->config.bind_path, LDAP_SCOPE_SUBTREE, filter, group_enum_attrs, &res);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(1,("enum_groups ads_search: %s\n", ads_errstr(ads_status)));
	}

	*groups_count = ads_count_replies(ads_struct, res);
	if (*groups_count == 0) {
		DEBUG(1,("enum_groups: No groups found\n"));
	}

	(*groups) = talloc_zero(mem_ctx, (*groups_count) * sizeof(**groups));
	if (!*groups) {
		ads_status = ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	for (msg = ads_first_entry(ads_struct, res); msg; msg = ads_next_entry(ads_struct, msg)) {
		uint32 		grouptype;

		if (!ads_pull_uint32(ads_struct, msg, "groupType", &grouptype)) {
			;
		} else {
			(*groups)->group_ctrl = ads_gtype2gcb(grouptype);
		}
	
		if (!((*groups)->group_name = ads_pull_string(ads_struct, mem_ctx, msg, "sAMAccountName"))) {
			;
		}
		
		if (!((*groups)->group_desc = ads_pull_string(ads_struct, mem_ctx, msg, "description"))) {
			;
		}
		
		if (!ads_pull_sid(ads_struct, msg, "objectSid", &((*groups)->sid))) {
			DEBUG(1,("No sid for group %s !?\n", (*groups)->group_name));
			continue;
		}

		i++;
	}

	(*groups_count) = i;

	ads_status = ADS_ERROR_NT(NT_STATUS_OK);

	DEBUG(3,("ads enum_dom_groups gave %d entries\n", (*groups_count)));

	if (res) ads_msgfree(ads_struct, res);

	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_group_by_sid(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_group_by_name(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *name, SAM_GROUP_HANDLE **group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_add_member_to_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_delete_member_from_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_enum_groupmembers(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_groups_of_sid(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const DOM_SID **sids, const uint16 group_ctrl, uint32 *group_count, SAM_GROUP_ENUM **groups)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",__FUNCTION__));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

/**********************************
Free our private data
***********************************/
static void sam_ads_free_private_data(void **vp) 
{
	struct sam_ads_privates **sam_ads_state = (struct sam_ads_privates **)vp;

	if ((*sam_ads_state)->ads_struct->ld) {
		ldap_unbind((*sam_ads_state)->ads_struct->ld);
	}

	ads_destroy(&((*sam_ads_state)->ads_struct));
	
	talloc_destroy((*sam_ads_state)->mem_ctx);
	/* Fix me: maybe we must free some other stuff here */

	*sam_ads_state = NULL;
}



/*****************************************************
Init the ADS SAM backend  
******************************************************/
NTSTATUS sam_init_ads(SAM_METHODS *sam_method, const char *module_params)
{
	ADS_STATUS              ads_status;
	NTSTATUS 		nt_status;
	struct sam_ads_privates *sam_ads_state;
	TALLOC_CTX 		*mem_ctx;
	
	SAM_ASSERT(sam_method && sam_method->parent);
	
	mem_ctx = sam_method->parent->mem_ctx;

	/* Here the SAM API functions of the sam_ads module */

	/* General API */

	sam_method->sam_get_sec_desc = sam_ads_get_sec_desc;
	sam_method->sam_set_sec_desc = sam_ads_set_sec_desc;
	
	sam_method->sam_lookup_sid = sam_ads_lookup_sid;
	sam_method->sam_lookup_name = sam_ads_lookup_name;
	
	/* Domain API */

	sam_method->sam_update_domain = sam_ads_update_domain;
	sam_method->sam_get_domain_handle = sam_ads_get_domain_handle;

	/* Account API */

	sam_method->sam_create_account = sam_ads_create_account;
	sam_method->sam_add_account = sam_ads_add_account;
	sam_method->sam_update_account = sam_ads_update_account;
	sam_method->sam_delete_account = sam_ads_delete_account;
	sam_method->sam_enum_accounts = sam_ads_enum_accounts;

	sam_method->sam_get_account_by_sid = sam_ads_get_account_by_sid;
	sam_method->sam_get_account_by_name = sam_ads_get_account_by_name;

	/* Group API */

	sam_method->sam_create_group = sam_ads_create_group;
	sam_method->sam_add_group = sam_ads_add_group;
	sam_method->sam_update_group = sam_ads_update_group;
	sam_method->sam_delete_group = sam_ads_delete_group;
	sam_method->sam_enum_groups = sam_ads_enum_groups;
	sam_method->sam_get_group_by_sid = sam_ads_get_group_by_sid;
	sam_method->sam_get_group_by_name = sam_ads_get_group_by_name;

	sam_method->sam_add_member_to_group = sam_ads_add_member_to_group;
	sam_method->sam_delete_member_from_group = sam_ads_delete_member_from_group;
	sam_method->sam_enum_groupmembers = sam_ads_enum_groupmembers;

	sam_method->sam_get_groups_of_sid = sam_ads_get_groups_of_sid;

	/*Fix me: use talloc !*/
	sam_ads_state = talloc_zero(mem_ctx, sizeof(struct sam_ads_privates));
	if (!sam_ads_state) {
		DEBUG(0, ("talloc() failed for sam_ads private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	
	if (!(sam_ads_state->mem_ctx = talloc_init_named("sam_ads_method"))) {
		DEBUG(0, ("talloc_init_named() failed for sam_ads_state->mem_ctx\n"));
		return NT_STATUS_NO_MEMORY;
	}

	sam_ads_state->ads_bind_dn = talloc_strdup(sam_ads_state->mem_ctx, lp_parm_string(NULL,"sam_ads","bind as"));
	sam_ads_state->ads_bind_pw = talloc_strdup(sam_ads_state->mem_ctx, lp_parm_string(NULL,"sam_ads","bind pw"));

	sam_ads_state->bind_plaintext = strequal(lp_parm_string(NULL, "sam_ads", "plaintext bind"), "yes");

	if (!sam_ads_state->ads_bind_dn || !sam_ads_state->ads_bind_pw) {
		DEBUG(0, ("talloc_strdup() failed for bind dn or password\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Maybe we should not check the result here? Server down on startup? */

	if (module_params && *module_params) {
		sam_ads_state->ldap_uri = talloc_strdup(sam_ads_state->mem_ctx, module_params);
		if (!sam_ads_state->ldap_uri) {
			DEBUG(0, ("talloc_strdup() failed for bind dn or password\n"));
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		sam_ads_state->ldap_uri = "ldapi://";
	}

	ads_status = sam_ads_cached_connection(sam_ads_state);
	if (!ADS_ERR_OK(ads_status)) {
		return ads_ntstatus(ads_status);
	}

	sam_method->private_data = sam_ads_state;
	sam_method->free_private_data = sam_ads_free_private_data;
	
	sam_ads_debug_level = debug_add_class("sam_ads");
	if (sam_ads_debug_level == -1) {
		sam_ads_debug_level = DBGC_ALL;
		DEBUG(0, ("sam_ads: Couldn't register custom debugging class!\n"));
	} else DEBUG(2, ("sam_ads: Debug class number of 'sam_ads': %d\n", sam_ads_debug_level));
    
	DEBUG(5, ("Initializing sam_ads\n"));
	if (module_params)
		DEBUG(10, ("Module Parameters for Domain %s[%s]: %s\n", sam_method->domain_name, sam_method->domain_name, module_params));
	return NT_STATUS_OK;
}

#else /* HAVE_LDAP */
void sam_ads_dummy(void)
{
	DEBUG(0,("sam_ads: not supported!\n"));
}
#endif /* HAVE_LDAP */
