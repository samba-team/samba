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

#ifndef FIXME
#define FIXME( body ) { DEBUG(0,("FIXME: "));\
			DEBUGADD(0,(body));}
#endif

#define ADS_STATUS_OK ADS_ERROR(0)
#define ADS_STATUS_UNSUCCESSFUL ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL)
#define ADS_STATUS_NOT_IMPLEMENTED ADS_ERROR_NT(NT_STATUS_NOT_IMPLEMENTED)


#define ADS_SUBTREE_BUILTIN	"CN=Builtin,"
#define ADS_SUBTREE_COMPUTERS	"CN=Computers,"
#define	ADS_SUBTREE_DC		"CN=Domain Controllers,"
#define ADS_SUBTREE_USERS 	"CN=Users,"
#define ADS_ROOT_TREE		""
/* Here are private module structs and functions */

typedef struct sam_ads_privates {
	ADS_STRUCT 	*ads_struct;
	TALLOC_CTX	*mem_ctx;
	BOOL            bind_plaintext;
	char            *ads_bind_dn;
	char            *ads_bind_pw;
	char            *ldap_uri;
	/* did we need something more? */
}SAM_ADS_PRIVATES;


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
static ADS_STATUS sam_ads_cached_connection(SAM_ADS_PRIVATES *privates)
{
	ADS_STRUCT 	*ads_struct;
	ADS_STATUS	ads_status;
	
	if (!privates->ads_struct) {
		privates->ads_struct = ads_init_simple();
		ads_struct = privates->ads_struct;
		ads_struct->server.ldap_uri = smb_xstrdup(privates->ldap_uri);
		if ((!privates->ads_bind_dn) || (!*privates->ads_bind_dn)) {
			ads_struct->auth.flags |= ADS_AUTH_ANON_BIND;
		} else {
			ads_struct->auth.user_name 
				= smb_xstrdup(privates->ads_bind_dn);
			if (privates->ads_bind_pw) {
				ads_struct->auth.password 
					= smb_xstrdup(privates->ads_bind_pw);
			}
		}
		if (privates->bind_plaintext) {
			ads_struct->auth.flags |= ADS_AUTH_SIMPLE_BIND;
		}
	} else {
		ads_struct = privates->ads_struct;
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
		/* return ads_status; */ FIXME("for now we only warn!\n");
	}

	DEBUG(2, ("sam_ads_cached_connection: succesful connection to the LDAP server\n"));
	return ADS_SUCCESS;
}

static ADS_STATUS sam_ads_do_search(SAM_ADS_PRIVATES *privates, const char *bind_path, int scope, const char *exp, const char **attrs, void **res)
{
	ADS_STATUS	ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	
	ads_status = sam_ads_cached_connection(privates);
	if (!ADS_ERR_OK(ads_status))
		return ads_status;
		
	return ads_do_search_retry(privates->ads_struct, bind_path, scope, exp, attrs, res);		
}


/*********************************************
here we have to check the update serial number
 - this is the core of the ldap cache
*********************************************/
static ADS_STATUS sam_ads_usn_is_valid(SAM_ADS_PRIVATES *privates, uint32 usn_in, uint32 *usn_out)
{
	ADS_STATUS	ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);

	SAM_ASSERT(privates && privates->ads_struct && usn_out);

	ads_status = ads_USN(privates->ads_struct, usn_out);
	if (!ADS_ERR_OK(ads_status))
		return ads_status;	
	
	if (*usn_out == usn_in)
		return ADS_SUCCESS;
		
	return ads_status;	
}

/***********************************************
Initialize SAM_ACCOUNT_HANDLE from an ADS query
************************************************/
/* not ready :-( */
static ADS_STATUS ads_entry2sam_account_handle(SAM_ADS_PRIVATES *privates, SAM_ACCOUNT_HANDLE *account ,void *msg)
{
	ADS_STATUS	ads_status = ADS_ERROR_NT(NT_STATUS_NO_SUCH_USER);
	NTSTATUS	nt_status = NT_STATUS_NO_SUCH_USER;
	ADS_STRUCT 	*ads_struct = privates->ads_struct;
	TALLOC_CTX	*mem_ctx = account->mem_ctx;
	char		*tmp_str = NULL;
	
	SAM_ASSERT(privates && ads_struct && account && mem_ctx && msg);

	FIXME("should we really use ads_pull_username()(or ads_pull_string())?\n");
	if ((account->private.account_name = ads_pull_username(ads_struct, mem_ctx, msg))==NULL) {
		DEBUG(0,("ads_pull_username failed\n"));
		return ADS_ERROR_NT(NT_STATUS_NO_SUCH_USER);
	}
	
	if ((account->private.full_name = ads_pull_string(ads_struct, mem_ctx, msg,"name"))==NULL) {
		DEBUG(3,("ads_pull_string for 'name' failed - skip\n"));
	}
	
	if ((account->private.acct_desc = ads_pull_string(ads_struct, mem_ctx, msg,"description"))!=NULL) {
		DEBUG(3,("ads_pull_string for 'acct_desc' failed - skip\n"));
	}
	
	if ((account->private.home_dir = ads_pull_string(ads_struct, mem_ctx, msg,"homeDirectory"))!=NULL) {
		DEBUG(3,("ads_pull_string for 'homeDirectory' failed - skip\n"));
	}
	
	if ((account->private.dir_drive = ads_pull_string(ads_struct, mem_ctx, msg,"homeDrive"))!=NULL) {
		DEBUG(3,("ads_pull_string for 'homeDrive' failed - skip\n"));
	}
	
	if ((account->private.profile_path = ads_pull_string(ads_struct, mem_ctx, msg,"profilePath"))!=NULL) {
		DEBUG(3,("ads_pull_string for 'profilePath' failed - skip\n"));
	}
	
	if ((account->private.logon_script = ads_pull_string(ads_struct, mem_ctx, msg,"scriptPath"))!=NULL) {
		DEBUG(3,("ads_pull_string for 'scriptPath' failed - skip\n"));
	}
	
	FIXME("check 'nsNPAllowDialIn' for munged_dial!\n");
	if ((account->private.munged_dial = ads_pull_string(ads_struct, mem_ctx, msg,"userParameters"))!=NULL) {
		DEBUG(3,("ads_pull_string for 'userParameters' failed - skip\n"));
	}
	
	if ((account->private.unix_home_dir = ads_pull_string(ads_struct, mem_ctx, msg,"msSFUHomeDrirectory"))!=NULL) {
		DEBUG(3,("ads_pull_string for 'msSFUHomeDrirectory' failed - skip\n"));
	}

#if 0
	FIXME("use function intern mem_ctx for pwdLastSet\n");
	if ((tmp_str = ads_pull_string(ads_struct, mem_ctx, msg,"pwdLastSet"))!=NULL) {
		DEBUG(3,("ads_pull_string for 'pwdLastSet' failed - skip\n"));
	} else {
		account->private.pass_last_set_time = ads_parse_nttime(tmp_str);
		tmp_str = NULL;
		
	}	
#endif

#if 0
typedef struct sam_account_handle {
	TALLOC_CTX *mem_ctx;
	uint32 access_granted;
	const struct sam_methods *current_sam_methods; /* sam_methods creating this handle */
	void (*free_fn)(struct sam_account_handle **);
	struct sam_account_data {
		uint32 init_flag;
		NTTIME logon_time; /* logon time */
		NTTIME logoff_time; /* logoff time */
		NTTIME kickoff_time; /* kickoff time */
		NTTIME pass_last_set_time; /* password last set time */
		NTTIME pass_can_change_time; /* password can change time */
		NTTIME pass_must_change_time; /* password must change time */
		char * account_name; /* account_name string */
		SAM_DOMAIN_HANDLE * domain; /* domain of account */
		char *full_name; /* account's full name string */
		char *unix_home_dir; /* UNIX home directory string */
		char *home_dir; /* home directory string */
		char *dir_drive; /* home directory drive string */
		char *logon_script; /* logon script string */
		char *profile_path; /* profile path string */
		char *acct_desc; /* account description string */
		char *workstations; /* login from workstations string */
		char *unknown_str; /* don't know what this is, yet. */
		char *munged_dial; /* munged path name and dial-back tel number */
		DOM_SID account_sid; /* Primary Account SID */
		DOM_SID group_sid; /* Primary Group SID */
		DATA_BLOB lm_pw; /* .data is Null if no password */
		DATA_BLOB nt_pw; /* .data is Null if no password */
		char *plaintext_pw; /* if Null not available */
		uint16 acct_ctrl; /* account info (ACB_xxxx bit-mask) */
		uint32 unknown_1; /* 0x00ff ffff */
		uint16 logon_divs; /* 168 - number of hours in a week */
		uint32 hours_len; /* normally 21 bytes */
		uint8 hours[MAX_HOURS_LEN];
		uint32 unknown_2; /* 0x0002 0000 */
		uint32 unknown_3; /* 0x0000 04ec */
	} private;
} SAM_ACCOUNT_HANDLE;
#endif

	return ads_status;
}


/***********************************************
Initialize SAM_GROUP_ENUM from an ads entry
************************************************/
/* not ready :-( */
static ADS_STATUS ads_entry2sam_group_enum(SAM_ADS_PRIVATES *privates, TALLOC_CTX *mem_ctx, SAM_GROUP_ENUM **group_enum,const void *entry)
{
	ADS_STATUS 	ads_status = ADS_STATUS_UNSUCCESSFUL;
	ADS_STRUCT 	*ads_struct = privates->ads_struct;
	SAM_GROUP_ENUM	__group_enum;
	SAM_GROUP_ENUM  *_group_enum = &__group_enum;
	
	SAM_ASSERT(privates && ads_struct && mem_ctx && group_enum && entry);
	
	*group_enum = _group_enum;
	
	DEBUG(3,("sam_ads: ads_entry2sam_account_handle\n"));

	if (!ads_pull_sid(ads_struct, &entry, "objectSid", &(_group_enum->sid))) {
		DEBUG(0,("No sid for!?\n"));
		return ADS_STATUS_UNSUCCESSFUL;
	}
	
	if (!(_group_enum->group_name = ads_pull_string(ads_struct, mem_ctx, &entry, "sAMAccountName"))) {
		DEBUG(0,("No groupname found"));
		return ADS_STATUS_UNSUCCESSFUL;
	}

	if (!(_group_enum->group_desc = ads_pull_string(ads_struct, mem_ctx, &entry, "desciption"))) {
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

static ADS_STATUS sam_ads_access_check(SAM_ADS_PRIVATES *privates, const SEC_DESC *sd, const NT_USER_TOKEN *access_token, uint32 access_desired, uint32 *acc_granted)
{
	ADS_STATUS	ads_status = ADS_ERROR_NT(NT_STATUS_ACCESS_DENIED);
	NTSTATUS	nt_status;
	uint32		my_acc_granted;

	SAM_ASSERT(privates && sd && access_token);
	/* acc_granted can be set to NULL */
	
	/* the steps you need are: 
	   1. get_sec_desc for sid 
	   2. se_map_generic(accessdesired, generic_mapping) 
	   3. se_access_check()	*/

	if (!se_access_check(sd, access_token, access_desired, (acc_granted)?acc_granted:&my_acc_granted, &nt_status)) {
		DEBUG(3,("sam_ads_access_check: ACCESS DENIED\n"));
		ads_status = ADS_ERROR_NT(nt_status);
		return ads_status;
	}
	ads_status = ADS_ERROR_NT(nt_status);	
	return ads_status;
}

static ADS_STATUS sam_ads_get_tree_sec_desc(SAM_ADS_PRIVATES *privates, const char *subtree, SEC_DESC **sd)
{
	ADS_STATUS		ads_status = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;
	char			*search_path;
	void 			*sec_desc_res;
	void 			*sec_desc_msg;
	const char		*sec_desc_attrs[] = {"nTSecurityDescriptor",NULL};
		
	SAM_ASSERT(privates && ads_struct && mem_ctx && sd);
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

static ADS_STATUS sam_ads_account_policy_get(SAM_ADS_PRIVATES *privates, int field, uint32 *value)
{
	ADS_STATUS		ads_status = ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	ADS_STRUCT		*ads_struct = privates->ads_struct;
	void			*ap_res;
	void			*ap_msg;
	const char		*ap_attrs[] = {"minPwdLength",/* AP_MIN_PASSWORD_LEN */
						"pwdHistoryLength",/* AP_PASSWORD_HISTORY */
						"AP_USER_MUST_LOGON_TO_CHG_PASS",/* AP_USER_MUST_LOGON_TO_CHG_PASS */
						"maxPwdAge",/* AP_MAX_PASSWORD_AGE */
						"minPwdAge",/* AP_MIN_PASSWORD_AGE */
						"lockoutDuration",/* AP_LOCK_ACCOUNT_DURATION */
						"AP_RESET_COUNT_TIME",/* AP_RESET_COUNT_TIME */
						"AP_BAD_ATTEMPT_LOCKOUT",/* AP_BAD_ATTEMPT_LOCKOUT */
						"AP_TIME_TO_LOGOUT",/* AP_TIME_TO_LOGOUT */
						NULL};
						/*lockOutObservationWindow 
						lockoutThreshold $ pwdProperties*/
	static uint32		ap[9];
	static uint32		ap_usn = 0;
	uint32			tmp_usn = 0;

	SAM_ASSERT(privates && ads_struct && value);
	
	FIXME("We need to decode all account_policy attributes!\n");
	
	ads_status = sam_ads_usn_is_valid(privates,ap_usn,&tmp_usn);
	if (!ADS_ERR_OK(ads_status)) {
		ads_status = sam_ads_do_search(privates, ads_struct->config.bind_path, LDAP_SCOPE_BASE, "(objectClass=*)", ap_attrs, &ap_res);
		if (!ADS_ERR_OK(ads_status))
			return ads_status; 
		
		if (ads_count_replies(ads_struct, ap_res) != 1) {
			ads_msgfree(ads_struct, ap_res);
			return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
		}

		if (!(ap_msg = ads_first_entry(ads_struct, ap_res))) {
			ads_msgfree(ads_struct, ap_res);
			return ADS_ERROR(LDAP_NO_RESULTS_RETURNED);
		}
		
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[0], &ap[0])) {
			/* AP_MIN_PASSWORD_LEN */
			ap[0] = MINPASSWDLENGTH;/* 5 chars minimum */
		}
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[1], &ap[1])) {
			/* AP_PASSWORD_HISTORY */
			ap[1] = 0;/* don't keep any old password */
		}
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[2], &ap[2])) {
			/* AP_USER_MUST_LOGON_TO_CHG_PASS */
			ap[2] = 0;/* don't force user to logon */
		}
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[3], &ap[3])) {
			/* AP_MAX_PASSWORD_AGE */
			ap[3] = MAX_PASSWORD_AGE;/* 21 days */
		}
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[4], &ap[4])) {
			/* AP_MIN_PASSWORD_AGE */
			ap[4] = 0;/* 0 days */
		}		
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[5], &ap[5])) {
			/* AP_LOCK_ACCOUNT_DURATION */
			ap[5] = 0;/* lockout for 0 minutes */
		}
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[6], &ap[6])) {
			/* AP_RESET_COUNT_TIME */
			ap[6] = 0;/* reset immediatly */
		}
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[7], &ap[7])) {
			/* AP_BAD_ATTEMPT_LOCKOUT */
			ap[7] = 0;/* don't lockout */
		}
		if (!ads_pull_uint32(ads_struct, ap_msg, ap_attrs[8], &ap[8])) {
			/* AP_TIME_TO_LOGOUT */
			ap[8] = -1;/* don't force logout */
		}
		
		ads_msgfree(ads_struct, ap_res);
		ap_usn = tmp_usn;
	}

	switch(field) {
		case AP_MIN_PASSWORD_LEN:
			*value = ap[0];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
		case AP_PASSWORD_HISTORY:
			*value = ap[1];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
		case AP_USER_MUST_LOGON_TO_CHG_PASS:
			*value = ap[2];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
		case AP_MAX_PASSWORD_AGE:
			*value = ap[3];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
		case AP_MIN_PASSWORD_AGE:
			*value = ap[4];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
		case AP_LOCK_ACCOUNT_DURATION:
			*value = ap[5];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
		case AP_RESET_COUNT_TIME:
			*value = ap[6];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
		case AP_BAD_ATTEMPT_LOCKOUT:
			*value = ap[7];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
		case AP_TIME_TO_LOGOUT:
			*value = ap[8];
			ads_status = ADS_ERROR_NT(NT_STATUS_OK);
			break;
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
	SAM_ADS_PRIVATES 	*privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx;
	char			*sidstr,*filter;
	void 			*sec_desc_res;
	void 			*sec_desc_msg;
	const char		*sec_desc_attrs[] = {"nTSecurityDescriptor",NULL};
	fstring                 sid_str;
	SEC_DESC		*my_sd;

	SAM_ASSERT(sam_method && access_token && sid && sd);	
	
	ads_status = sam_ads_get_tree_sec_desc(privates, ADS_ROOT_TREE, &my_sd);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(privates, my_sd, access_token, GENERIC_RIGHTS_DOMAIN_READ, NULL);

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

	if (!(mem_ctx = talloc_init_named("sec_desc parse in sam_ads"))) {
		DEBUG(1, ("talloc_init_named() failed for sec_desc parse context in sam_ads"));
		ads_msgfree(ads_struct, sec_desc_res);
		return NT_STATUS_NO_MEMORY;
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
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

	
static NTSTATUS sam_ads_lookup_sid(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, 
			    TALLOC_CTX *mem_ctx, const DOM_SID *sid, char **name, 
			    enum SID_NAME_USE *type)
{
	ADS_STATUS		ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	SAM_ADS_PRIVATES	*privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	SEC_DESC		*my_sd;

	SAM_ASSERT(sam_method && access_token && mem_ctx && sid && name && type);

	ads_status = sam_ads_get_tree_sec_desc(privates, ADS_ROOT_TREE, &my_sd);	
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(privates, my_sd, access_token, GENERIC_RIGHTS_DOMAIN_READ, NULL);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	return ads_sid_to_name(ads_struct, mem_ctx, sid, name, type);
}

static NTSTATUS sam_ads_lookup_name(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, 
			     const char *name, DOM_SID *sid, enum SID_NAME_USE *type)
{
	ADS_STATUS		ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	SAM_ADS_PRIVATES	*privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	SEC_DESC		*my_sd;

	SAM_ASSERT(sam_method && access_token && name && sid && type);

	ads_status = sam_ads_get_tree_sec_desc(privates, ADS_ROOT_TREE, &my_sd);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(privates, my_sd, access_token, GENERIC_RIGHTS_DOMAIN_READ, NULL);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	return ads_name_to_sid(ads_struct, name, sid, type);
}

	
/* Domain API */

static NTSTATUS sam_ads_update_domain(const SAM_METHODS *sam_method, const SAM_DOMAIN_HANDLE *domain)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_domain_handle(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, 
				   const uint32 access_desired, SAM_DOMAIN_HANDLE **domain)
{
	ADS_STATUS		ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	SAM_ADS_PRIVATES	*privates = (struct sam_ads_privates *)sam_method->private_data;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;	/*Fix me is this right??? */
	SAM_DOMAIN_HANDLE	*dom_handle = NULL;
	SEC_DESC		*sd;
	uint32			acc_granted;
	uint32			tmp_value;

	DEBUG(5,("sam_ads_get_domain_handle: %d\n",__LINE__));
	
	SAM_ASSERT(sam_method && access_token && domain);
	
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

	ads_status = sam_ads_get_tree_sec_desc(privates, ADS_ROOT_TREE, &sd);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(privates, sd, access_token, access_desired, &acc_granted);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	dom_handle->access_granted = acc_granted;

	/* fill all the values of dom_handle */
	sid_copy(&dom_handle->private.sid, &sam_method->domain_sid);
	dom_handle->private.name       = smb_xstrdup(sam_method->domain_name);
	dom_handle->private.servername = "WHOKNOWS"; /* what is the servername */

	/*Fix me: sam_ads_account_policy_get() return ADS_STATUS! */ 
	ads_status = sam_ads_account_policy_get(privates, AP_MAX_PASSWORD_AGE, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for max password age. Useing default\n"));
		tmp_value = MAX_PASSWORD_AGE;
	}
	unix_to_nt_time_abs(&dom_handle->private.max_passwordage,tmp_value);

	ads_status = sam_ads_account_policy_get(privates, AP_MIN_PASSWORD_AGE, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for min password age. Useing default\n"));
		tmp_value = 0;
	}
	unix_to_nt_time_abs(&dom_handle->private.min_passwordage, tmp_value);

	ads_status = sam_ads_account_policy_get(privates, AP_LOCK_ACCOUNT_DURATION, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for lockout duration. Useing default\n"));
		tmp_value = 0;
	}
	unix_to_nt_time_abs(&dom_handle->private.lockout_duration, tmp_value);

	ads_status = sam_ads_account_policy_get(privates, AP_RESET_COUNT_TIME, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for time till locout count is reset. Useing default\n"));
		tmp_value = 0;
	}
	unix_to_nt_time_abs(&dom_handle->private.reset_count, tmp_value);

	ads_status = sam_ads_account_policy_get(privates, AP_MIN_PASSWORD_LEN, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for min password length. Useing default\n"));
		tmp_value = 0;
	}
	dom_handle->private.min_passwordlength = (uint16)tmp_value;

	ads_status = sam_ads_account_policy_get(privates, AP_PASSWORD_HISTORY, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed password history. Useing default\n"));
		tmp_value = 0;
	}
	dom_handle->private.password_history = (uint16)tmp_value;

	ads_status = sam_ads_account_policy_get(privates, AP_BAD_ATTEMPT_LOCKOUT, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for bad attempts till lockout. Useing default\n"));
		tmp_value = 0;
	}
	dom_handle->private.lockout_count = (uint16)tmp_value;

	ads_status = sam_ads_account_policy_get(privates, AP_TIME_TO_LOGOUT, &tmp_value);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(4,("sam_ads_account_policy_get failed for force logout. Useing default\n"));
		tmp_value = -1;
	}

	ads_status = sam_ads_account_policy_get(privates, AP_USER_MUST_LOGON_TO_CHG_PASS, &tmp_value);
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
	SAM_ADS_PRIVATES	*privates = (struct sam_ads_privates *)sam_method->private_data;
	SEC_DESC		*sd = NULL;
	uint32			acc_granted;

	SAM_ASSERT(sam_method && privates && access_token && account_name && account);

	ads_status = sam_ads_get_tree_sec_desc(privates, ADS_SUBTREE_USERS, &sd);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(privates, sd, access_token, access_desired, &acc_granted);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = ADS_ERROR_NT(sam_init_account(account));
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);	

	(*account)->access_granted = acc_granted;

	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_add_account(const SAM_METHODS *sam_method, const SAM_ACCOUNT_HANDLE *account)
{
	ADS_STATUS		ads_status = ADS_ERROR(LDAP_NO_MEMORY);
	SAM_ADS_PRIVATES	*privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;
	ADS_MODLIST 		mods;
 	uint16 			acct_ctrl;
 	char 			*new_dn;
 	SEC_DESC		*sd;
 	uint32			acc_granted;

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
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_delete_account(const SAM_METHODS *sam_method, const SAM_ACCOUNT_HANDLE *account)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);



	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_enum_accounts(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, uint16 acct_ctrl, uint32 *account_count, SAM_ACCOUNT_ENUM **accounts)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

#if 0
static NTSTATUS sam_ads_get_account_by_sid(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *account_sid, SAM_ACCOUNT_HANDLE **account)
{
	ADS_STATUS		ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	SAM_ADS_PRIVATES	*privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;
	SEC_DESC		*sd = NULL;
	uint32			acc_granted;
		
	SAM_ASSERT(sam_method && privates && ads_struct && access_token && account_sid && account);

	ads_status = ADS_ERROR_NT(sam_ads_get_sec_desc(sam_method, access_token, account_sid, &my_sd));
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(privates, sd, access_token, access_desired, &acc_granted);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = ADS_ERROR_NT(sam_init_account(account));
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);	

	(*account)->access_granted = acc_granted;

	return ads_ntstatus(ads_status);
}
#else
static NTSTATUS sam_ads_get_account_by_sid(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *account_sid, SAM_ACCOUNT_HANDLE **account)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}
#endif

#if 0
static NTSTATUS sam_ads_get_account_by_name(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *account_name, SAM_ACCOUNT_HANDLE **account)
{
	ADS_STATUS	ads_status = ADS_ERROR_NT(NT_STATUS_UNSUCCESSFUL);
	SAM_ADS_PRIVATES	*privates = (struct sam_ads_privates *)sam_method->private_data;
	ADS_STRUCT 		*ads_struct = privates->ads_struct;
	TALLOC_CTX		*mem_ctx = privates->mem_ctx;
	SEC_DESC		*sd = NULL;
	uint32			acc_granted;
	
	SAM_ASSERT(sam_method && privates && ads_struct && access_token && account_name && account);

	ads_status = sam_ads_get_tree_sec_desc(privates, ADS_ROOT_TREE, &sd);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = sam_ads_access_check(privates, sd, access_token, access_desired, &acc_granted);
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);

	ads_status = ADS_ERROR_NT(sam_init_account(account));
	if (!ADS_ERR_OK(ads_status))
		return ads_ntstatus(ads_status);	

	(*account)->access_granted = acc_granted;

	return ads_ntstatus(ads_status);
}
#else
static NTSTATUS sam_ads_get_account_by_name(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *account_name, SAM_ACCOUNT_HANDLE **account)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}
#endif

/* Group API */
static NTSTATUS sam_ads_create_group(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *group_name, uint16 group_ctrl, SAM_GROUP_HANDLE **group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_add_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_update_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_delete_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_enum_groups(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint16 group_ctrl, uint32 *groups_count, SAM_GROUP_ENUM **groups)
{
	ADS_STATUS		ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	SAM_ADS_PRIVATES	*privates = (struct sam_ads_privates *)sam_method->private_data;
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

	FIXME("get only group from the wanted Type!\n");
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
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_group_by_name(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *name, SAM_GROUP_HANDLE **group)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_add_member_to_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_delete_member_from_group(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_enum_groupmembers(const SAM_METHODS *sam_method, const SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

static NTSTATUS sam_ads_get_groups_of_sid(const SAM_METHODS *sam_method, const NT_USER_TOKEN *access_token, const DOM_SID **sids, const uint16 group_ctrl, uint32 *group_count, SAM_GROUP_ENUM **groups)
{
	ADS_STATUS	ads_status = ADS_STATUS_NOT_IMPLEMENTED;
	DEBUG(0,("sam_ads: %s was called!\n",FUNCTION_MACRO));
	SAM_ASSERT(sam_method);
	return ads_ntstatus(ads_status);
}

/**********************************
Free our private data
***********************************/
static void sam_ads_free_private_data(void **vp) 
{
	SAM_ADS_PRIVATES **sam_ads_state = (SAM_ADS_PRIVATES **)vp;

	if ((*sam_ads_state)->ads_struct->ld) {
		ldap_unbind((*sam_ads_state)->ads_struct->ld);
	}

	ads_destroy(&((*sam_ads_state)->ads_struct));
	
	talloc_destroy((*sam_ads_state)->mem_ctx);
	FIXME("maybe we must free some other stuff here\n");

	*sam_ads_state = NULL;
}



/*****************************************************
Init the ADS SAM backend  
******************************************************/
NTSTATUS sam_init_ads(SAM_METHODS *sam_method, const char *module_params)
{
	ADS_STATUS              ads_status;
	SAM_ADS_PRIVATES	*sam_ads_state;
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

	sam_ads_state = talloc_zero(mem_ctx, sizeof(SAM_ADS_PRIVATES));
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
