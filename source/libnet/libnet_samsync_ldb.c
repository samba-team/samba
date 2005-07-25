/* 
   Unix SMB/CIFS implementation.
   
   Extract the user/system database from a remote SamSync server

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Andrew Tridgell 2004
   
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
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "dlinklist.h"
#include "lib/ldb/include/ldb.h"

struct samsync_ldb_secret {
	struct samsync_ldb_secret *prev, *next;
	DATA_BLOB secret;
	char *name;
	NTTIME mtime;
};

struct samsync_ldb_trusted_domain {
	struct samsync_ldb_trusted_domain *prev, *next;
        struct dom_sid *sid;
	char *name;
};

struct samsync_ldb_state {
	struct dom_sid *dom_sid[3];
	struct ldb_context *sam_ldb;
	char *base_dn[3];
	struct samsync_ldb_secret *secrets;
	struct samsync_ldb_trusted_domain *trusted_domains;
};

static NTSTATUS samsync_ldb_handle_domain(TALLOC_CTX *mem_ctx,
					  struct samsync_ldb_state *state,
					  struct creds_CredentialState *creds,
					  enum netr_SamDatabaseID database,
					  struct netr_DELTA_ENUM *delta) 
{
	struct netr_DELTA_DOMAIN *domain = delta->delta_union.domain;
	const char *domain_name = domain->domain_name.string;
	struct ldb_message *msg;
	int ret;
	
	if (database == SAM_DATABASE_DOMAIN) {
		const char *domain_attrs[] =  {"nETBIOSName", "nCName", NULL};
		struct ldb_message **msgs_domain;
		int ret_domain;
		ret_domain = gendb_search(state->sam_ldb, mem_ctx, NULL, &msgs_domain, domain_attrs,
					  "(&(&(nETBIOSName=%s)(objectclass=crossRef))(ncName=*))", 
					  domain_name);
		if (ret_domain == -1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		
		if (ret_domain != 1) {
			return NT_STATUS_NO_SUCH_DOMAIN;		
		}

		state->base_dn[database]
			= talloc_steal(state, samdb_result_string(msgs_domain[0], 
								  "nCName", NULL));
		
		state->dom_sid[database]
			= talloc_steal(state, 
				       samdb_search_dom_sid(state->sam_ldb, state,
							    state->base_dn[database], "objectSid", 
							    "dn=%s", state->base_dn[database]));
	} else if (database == SAM_DATABASE_BUILTIN) {
			/* work out the builtin_dn - useful for so many calls its worth
			   fetching here */
		state->base_dn[database]
			= talloc_steal(state, 
				       samdb_search_string(state->sam_ldb, mem_ctx, NULL,
							   "dn", "objectClass=builtinDomain"));
		state->dom_sid[database]
			= dom_sid_parse_talloc(state, SID_BUILTIN);
	} else {
		/* PRIVs DB */
		return NT_STATUS_INVALID_PARAMETER;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = talloc_reference(mem_ctx, state->base_dn[database]);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	samdb_msg_add_string(state->sam_ldb, mem_ctx, 
			     msg, "oEMInformation", domain->comment.string);

	samdb_msg_add_uint64(state->sam_ldb, mem_ctx, 
			     msg, "forceLogff", domain->force_logoff_time);

	samdb_msg_add_uint(state->sam_ldb, mem_ctx, 
			  msg, "minPwdLen", domain->min_password_length);

	samdb_msg_add_int64(state->sam_ldb, mem_ctx, 
			  msg, "maxPwdAge", domain->max_password_age);

	samdb_msg_add_int64(state->sam_ldb, mem_ctx, 
			  msg, "minPwdAge", domain->min_password_age);

	samdb_msg_add_uint(state->sam_ldb, mem_ctx, 
			  msg, "pwdHistoryLength", domain->password_history_length);

	samdb_msg_add_uint64(state->sam_ldb, mem_ctx, 
			     msg, "modifiedCountAtLastProm", 
			     domain->sequence_num);

	samdb_msg_add_uint64(state->sam_ldb, mem_ctx, 
			     msg, "creationTime", domain->domain_create_time);

	/* TODO: Account lockout, password properties */
	
	ret = samdb_replace(state->sam_ldb, mem_ctx, msg);

	if (ret) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	return NT_STATUS_OK;
}

static NTSTATUS samsync_ldb_handle_user(TALLOC_CTX *mem_ctx,
					struct samsync_ldb_state *state,
					struct creds_CredentialState *creds,
					enum netr_SamDatabaseID database,
					struct netr_DELTA_ENUM *delta) 
{
	uint32_t rid = delta->delta_id_union.rid;
	struct netr_DELTA_USER *user = delta->delta_union.user;
	const char *container, *obj_class;
	char *cn_name;
	int cn_name_len;

	struct ldb_message *msg;
	struct ldb_message **msgs;
	int ret;
	uint32_t acb;
	BOOL add = False;
	const char *attrs[] = { NULL };

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the user, by rid */
	ret = gendb_search(state->sam_ldb, mem_ctx, state->base_dn[database], &msgs, attrs,
			   "(&(objectClass=user)(objectSid=%s))", 
			   ldap_encode_ndr_dom_sid(mem_ctx, dom_sid_add_rid(mem_ctx, state->dom_sid[database], rid))); 

	if (ret == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else if (ret == 0) {
		add = True;
	} else if (ret > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else {
		msg->dn = talloc_steal(mem_ctx, msgs[0]->dn);
	}


	cn_name   = talloc_strdup(mem_ctx, user->account_name.string);
	NT_STATUS_HAVE_NO_MEMORY(cn_name);
	cn_name_len = strlen(cn_name);

#define ADD_OR_DEL(type, attrib, field) do {\
	if (user->field) { \
		samdb_msg_add_ ## type(state->sam_ldb, mem_ctx, msg, \
				     attrib, user->field); \
	} else if (!add) { \
		samdb_msg_add_delete(state->sam_ldb, mem_ctx, msg,  \
				     attrib); \
	} \
        } while (0);

        ADD_OR_DEL(string, "samAccountName", account_name.string);
        ADD_OR_DEL(string, "displayName", full_name.string);

	if (samdb_msg_add_dom_sid(state->sam_ldb, mem_ctx, msg, 
				  "objectSid", dom_sid_add_rid(mem_ctx, state->dom_sid[database], rid))) {
		return NT_STATUS_NO_MEMORY; 
	}

        ADD_OR_DEL(uint, "primaryGroupID", primary_gid);
        ADD_OR_DEL(string, "homeDirectory", home_directory.string);
        ADD_OR_DEL(string, "homeDrive", home_drive.string);
        ADD_OR_DEL(string, "scriptPath", logon_script.string);
	ADD_OR_DEL(string, "description", description.string);
	ADD_OR_DEL(string, "userWorkstations", workstations.string);

	ADD_OR_DEL(uint64, "lastLogon", last_logon);
	ADD_OR_DEL(uint64, "lastLogoff", last_logoff);

	/* TODO: Logon hours */

	ADD_OR_DEL(uint, "badPwdCount", bad_password_count);
	ADD_OR_DEL(uint, "logonCount", logon_count);

	ADD_OR_DEL(uint64, "pwdLastSet", last_password_change);
	ADD_OR_DEL(uint64, "accountExpires", acct_expiry);
	
	if (samdb_msg_add_acct_flags(state->sam_ldb, mem_ctx, msg, 
				     "userAccountConrol", user->acct_flags) != 0) { 
		return NT_STATUS_NO_MEMORY; 
	} 
	
	/* Passwords */
	samdb_msg_add_delete(state->sam_ldb, mem_ctx, msg,  
				"unicodePwd"); 
	if (user->lm_password_present) {
		samdb_msg_add_hash(state->sam_ldb, mem_ctx, msg,  
				   "lmPwdHash", &user->lmpassword);
	} else {
		samdb_msg_add_delete(state->sam_ldb, mem_ctx, msg,  
				     "lmPwdHash"); 
	}
	if (user->nt_password_present) {
		samdb_msg_add_hash(state->sam_ldb, mem_ctx, msg,  
				   "ntPwdHash", &user->ntpassword);
	} else {
		samdb_msg_add_delete(state->sam_ldb, mem_ctx, msg,  
				     "ntPwdHash"); 
	}
	    
	ADD_OR_DEL(string, "comment", comment.string);
	ADD_OR_DEL(string, "userParameters", parameters.string);
	ADD_OR_DEL(uint, "countryCode", country_code);
	ADD_OR_DEL(uint, "codePage", code_page);

        ADD_OR_DEL(string, "profilePath", profile_path.string);

	acb = user->acct_flags;
	if (acb & (ACB_WSTRUST)) {
		cn_name[cn_name_len - 1] = '\0';
		container = "Computers";
		obj_class = "computer";
		
	} else if (acb & ACB_SVRTRUST) {
		if (cn_name[cn_name_len - 1] != '$') {
			return NT_STATUS_FOOBAR;		
		}
		cn_name[cn_name_len - 1] = '\0';
		container = "Domain Controllers";
		obj_class = "computer";
	} else {
		container = "Users";
		obj_class = "user";
	}
	if (add) {
		samdb_msg_add_string(state->sam_ldb, mem_ctx, msg, 
				     "objectClass", obj_class);
		msg->dn = talloc_asprintf(mem_ctx, "CN=%s,CN=%s,%s",
					  cn_name, container, state->base_dn[database]);
		if (!msg->dn) {
			return NT_STATUS_NO_MEMORY;		
		}

		ret = samdb_add(state->sam_ldb, mem_ctx, msg);
		if (ret != 0) {
			DEBUG(0,("Failed to create user record %s\n", msg->dn));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else {
		ret = samdb_replace(state->sam_ldb, mem_ctx, msg);
		if (ret != 0) {
			DEBUG(0,("Failed to modify user record %s\n", msg->dn));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS samsync_ldb_handle_group(TALLOC_CTX *mem_ctx,
					 struct samsync_ldb_state *state,
					 struct creds_CredentialState *creds,
					 enum netr_SamDatabaseID database,
					 struct netr_DELTA_ENUM *delta) 
{
	uint32_t rid = delta->delta_id_union.rid;
	struct netr_DELTA_GROUP *group = delta->delta_union.group;
	const char *groupname = group->group_name.string;

	return NT_STATUS_OK;
}

static NTSTATUS libnet_samsync_ldb_fn(TALLOC_CTX *mem_ctx, 		
				  void *private, 			
				  struct creds_CredentialState *creds,
				  enum netr_SamDatabaseID database,
				  struct netr_DELTA_ENUM *delta,
				  char **error_string)
{
	NTSTATUS nt_status = NT_STATUS_OK;
	struct samsync_ldb_state *state = private;

	*error_string = NULL;
	switch (delta->delta_type) {
	case NETR_DELTA_DOMAIN:
	{
		nt_status = samsync_ldb_handle_domain(mem_ctx, 
						      state,
						      creds,
						      database,
						      delta);
		break;
	}
	case NETR_DELTA_USER:
	{
		nt_status = samsync_ldb_handle_user(mem_ctx, 
						    state,
						    creds,
						    database,
						    delta);
		break;
	}
	case NETR_DELTA_GROUP:
	{
		nt_status = samsync_ldb_handle_group(mem_ctx, 
						     state,
						     creds,
						     database,
						     delta);
		break;
	}
	default:
		/* Can't dump them all right now */
		break;
	}
	return nt_status;
}

static NTSTATUS libnet_samsync_ldb_netlogon(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_samsync_ldb *r)
{
	NTSTATUS nt_status;
	struct libnet_SamSync r2;
	struct samsync_ldb_state *state = talloc(mem_ctx, struct samsync_ldb_state);

	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}

	state->secrets = NULL;
	state->trusted_domains = NULL;

	state->sam_ldb = samdb_connect(state);

	

	r2.error_string = NULL;
	r2.delta_fn = libnet_samsync_ldb_fn;
	r2.fn_ctx = state;
	r2.machine_account = NULL; /* TODO:  Create a machine account, fill this in, and the delete it */
	nt_status = libnet_SamSync_netlogon(ctx, state, &r2);
	r->error_string = r2.error_string;

	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(state);
		return nt_status;
	}
	talloc_free(state);
	return nt_status;
}



static NTSTATUS libnet_samsync_ldb_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_samsync_ldb *r)
{
	NTSTATUS nt_status;
	struct libnet_samsync_ldb r2;
	r2.level = LIBNET_SAMSYNC_LDB_NETLOGON;
	r2.error_string = NULL;
	nt_status = libnet_samsync_ldb(ctx, mem_ctx, &r2);
	r->error_string = r2.error_string;
	
	return nt_status;
}

NTSTATUS libnet_samsync_ldb(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_samsync_ldb *r)
{
	switch (r->level) {
	case LIBNET_SAMSYNC_LDB_GENERIC:
		return libnet_samsync_ldb_generic(ctx, mem_ctx, r);
	case LIBNET_SAMSYNC_LDB_NETLOGON:
		return libnet_samsync_ldb_netlogon(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}
