/* 
   Unix SMB/CIFS implementation.

   test suite for netlogon rpc operations

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003-2004
   Copyright (C) Tim Potter      2003
   
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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "auth/auth.h"
#include "dlinklist.h"
#include "lib/crypto/crypto.h"
#include "system/time.h"

#define TEST_MACHINE_NAME "samsynctest"
#define TEST_MACHINE_NAME2 "samsynctest2"

/*
  try a netlogon SamLogon
*/
static NTSTATUS test_SamLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct creds_CredentialState *creds, 
			      const char *domain, const char *account_name,
			      const char *workstation, 
			      struct samr_Password *lm_hash, 
			      struct samr_Password *nt_hash, 
			      struct netr_SamInfo3 **info3)
{
	NTSTATUS status;
	struct netr_LogonSamLogon r;
	struct netr_Authenticator auth, auth2;
	struct netr_NetworkInfo ninfo;

	ninfo.identity_info.domain_name.string = domain;
	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.account_name.string = account_name;
	ninfo.identity_info.workstation.string = workstation;
	generate_random_buffer(ninfo.challenge, 
			       sizeof(ninfo.challenge));
	if (nt_hash) {
		ninfo.nt.length = 24;
		ninfo.nt.data = talloc(mem_ctx, 24);
		SMBOWFencrypt(nt_hash->hash, ninfo.challenge, ninfo.nt.data);
	} else {
		ninfo.nt.length = 0;
		ninfo.nt.data = NULL;
	}
	
	if (lm_hash) {
		ninfo.lm.length = 24;
		ninfo.lm.data = talloc(mem_ctx, 24);
		SMBOWFencrypt(lm_hash->hash, ninfo.challenge, ninfo.lm.data);
	} else {
		ninfo.lm.length = 0;
		ninfo.lm.data = NULL;
	}

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.workstation = workstation;
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;

	ZERO_STRUCT(auth2);
	creds_client_authenticator(creds, &auth);
	
	r.in.validation_level = 3;
	
	status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &r);

	if (!creds_client_check(creds, &r.out.return_authenticator->cred)) {
		printf("Credential chaining failed\n");
	}

	if (info3) {
		*info3 = r.out.validation.sam3;
	}

	return status;
}

struct samsync_state {
/* we remember the sequence numbers so we can easily do a DatabaseDelta */
	uint64_t seq_num[3];
	char *domain_name[2];
	struct samsync_secret *secrets;
	struct samsync_trusted_domain *trusted_domains;
	struct creds_CredentialState *creds;
	struct creds_CredentialState *creds_netlogon_wksta;
	struct policy_handle *connect_handle;
	struct policy_handle *domain_handle[2];
	struct dom_sid *sid[2];
	struct dcerpc_pipe *p;
	struct dcerpc_pipe *p_netlogon_wksta;
	struct dcerpc_pipe *p_samr;
	struct dcerpc_pipe *p_lsa;
	struct policy_handle *lsa_handle;
};

struct samsync_secret {
	struct samsync_secret *prev, *next;
	DATA_BLOB secret;
	char *name;
};

struct samsync_trusted_domain {
	struct samsync_trusted_domain *prev, *next;
        struct dom_sid *sid;
	char *name;
};

static struct policy_handle *samsync_open_domain(TALLOC_CTX *mem_ctx, 
						 struct samsync_state *samsync_state, 
						 const char *domain, 
						 struct dom_sid **sid)
{
	struct samr_String name;
	struct samr_OpenDomain o;
	struct samr_LookupDomain l;
	struct policy_handle *domain_handle = talloc_p(mem_ctx, struct policy_handle);
	NTSTATUS nt_status;

	name.string = domain;
	l.in.connect_handle = samsync_state->connect_handle;
	l.in.domain = &name;

	nt_status = dcerpc_samr_LookupDomain(samsync_state->p_samr, mem_ctx, &l);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(nt_status));
		return NULL;
	}

	o.in.connect_handle = samsync_state->connect_handle;
	o.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	o.in.sid = l.out.sid;
	o.out.domain_handle = domain_handle;
	
	if (sid) {
		*sid = l.out.sid;
	}

	nt_status = dcerpc_samr_OpenDomain(samsync_state->p_samr, mem_ctx, &o);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("OpenDomain failed - %s\n", nt_errstr(nt_status));
		return NULL;
	}

	return domain_handle;
}

static struct sec_desc_buf *samsync_query_samr_sec_desc(TALLOC_CTX *mem_ctx, 
							struct samsync_state *samsync_state, 
							struct policy_handle *handle) 
{
	struct samr_QuerySecurity r;
	NTSTATUS status;

	r.in.handle = handle;
	r.in.sec_info = 0x7;

	status = dcerpc_samr_QuerySecurity(samsync_state->p_samr, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SAMR QuerySecurity failed - %s\n", nt_errstr(status));
		return NULL;
	}

	return r.out.sdbuf;
}

static struct sec_desc_buf *samsync_query_lsa_sec_desc(TALLOC_CTX *mem_ctx, 
						       struct samsync_state *samsync_state, 
						       struct policy_handle *handle) 
{
	struct lsa_QuerySecurity r;
	NTSTATUS status;

	r.in.handle = handle;
	r.in.sec_info = 0x7;

	status = dcerpc_lsa_QuerySecurity(samsync_state->p_lsa, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LSA QuerySecurity failed - %s\n", nt_errstr(status));
		return NULL;
	}

	return r.out.sdbuf;
}

#define TEST_UINT64_EQUAL(i1, i2) do {\
	if (i1 != i2) {\
              printf("uint64 mismatch: " #i1 ": 0x%08x%08x (%lld) != " #i2 ": 0x%08x%08x (%lld)\n", \
		     (uint32_t)(i1 >> 32), (uint32_t)(i1 & 0xFFFFFFFF), i1, \
                     (uint32_t)(i2 >> 32), (uint32_t)(i2 & 0xFFFFFFFF), i2);\
	      ret = False;\
	} \
} while (0)
#define TEST_INT_EQUAL(i1, i2) do {\
	if (i1 != i2) {\
	      printf("integer mismatch: " #i1 ":%d != " #i2 ": %d\n", \
		     i1, i2);\
	      ret = False;\
	} \
} while (0)
#define TEST_TIME_EQUAL(t1, t2) do {\
	if (t1 != t2) {\
	      printf("NTTIME mismatch: " #t1 ":%s != " #t2 ": %s\n", \
		     nt_time_string(mem_ctx, t1),  nt_time_string(mem_ctx, t2));\
	      ret = False;\
	} \
} while (0)

#define TEST_STRING_EQUAL(s1, s2) do {\
	if (!((!s1.string || s1.string[0]=='\0') && (!s2.string || s2.string[0]=='\0')) \
	    && strcmp_safe(s1.string, s2.string) != 0) {\
	      printf("string mismatch: " #s1 ":%s != " #s2 ": %s\n", \
		     s1.string, s2.string);\
	      ret = False;\
	} \
} while (0)

/* The ~SEC_DESC_SACL_PRESENT is because we don't, as administrator,
 * get back the SACL part of the SD when we ask over SAMR */

#define TEST_SEC_DESC_EQUAL(sd1, pipe, handle) do {\
        struct sec_desc_buf *sdbuf = samsync_query_ ##pipe## _sec_desc(mem_ctx, samsync_state, \
						            handle); \
	if (!sdbuf || !sdbuf->sd) { \
                printf("Could not obtain security descriptor to match " #sd1 "\n");\
	        ret = False; \
        } else {\
		if (!security_descriptor_mask_equal(sd1.sd, sdbuf->sd, \
 			    ~SEC_DESC_SACL_PRESENT)) {\
			printf("Security Descriptor Mismatch for %s:\n", #sd1);\
		        ndr_print_debug((ndr_print_fn_t)ndr_print_security_descriptor, "SamSync", sd1.sd);\
		        ndr_print_debug((ndr_print_fn_t)ndr_print_security_descriptor, "SamR", sdbuf->sd);\
			ret = False;\
		}\
	}\
} while (0)

static BOOL samsync_handle_domain(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
			   int database_id, struct netr_DELTA_ENUM *delta) 
{
	struct netr_DELTA_DOMAIN *domain = delta->delta_union.domain;
	struct dom_sid *dom_sid;
	struct samr_QueryDomainInfo q[14]; /* q[0] will be unused simple for clarity */
	uint16_t levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13};
	NTSTATUS nt_status;
	int i;
	BOOL ret = True;
	
	samsync_state->seq_num[database_id] = 
		domain->sequence_num;
	switch (database_id) {
	case SAM_DATABASE_DOMAIN:
		break;
	case SAM_DATABASE_BUILTIN:
		if (StrCaseCmp("BUILTIN", domain->domain_name.string) != 0) {
			printf("BUILTIN domain has different name: %s\n", domain->domain_name.string);
		}
		break;
	case SAM_DATABASE_PRIVS:
		printf("DOMAIN entry on privs DB!\n");
		return False;
		break;
	}
	
	if (!samsync_state->domain_name[database_id]) {
		samsync_state->domain_name[database_id] = 
			talloc_reference(samsync_state, domain->domain_name.string);
	} else {
		if (StrCaseCmp(samsync_state->domain_name[database_id], domain->domain_name.string) != 0) {
			printf("Domain has name varies!: %s != %s\n", samsync_state->domain_name[database_id], 
			       domain->domain_name.string);
			return False;
		}
	}

	if (!samsync_state->domain_handle[database_id]) {
		samsync_state->domain_handle[database_id]
			= samsync_open_domain(mem_ctx, samsync_state, samsync_state->domain_name[database_id], 
					      &dom_sid);
	}
	if (samsync_state->domain_handle[database_id]) {
		samsync_state->sid[database_id] = talloc_reference(samsync_state, dom_sid);
	}

	printf("\tsequence_nums[%d/%s]=%llu\n",
	       database_id, domain->domain_name.string,
	       samsync_state->seq_num[database_id]);

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		q[levels[i]].in.domain_handle = samsync_state->domain_handle[database_id];
		q[levels[i]].in.level = levels[i];

		nt_status = dcerpc_samr_QueryDomainInfo(samsync_state->p_samr, mem_ctx, &q[levels[i]]);

		if (!NT_STATUS_IS_OK(nt_status)) {
			printf("QueryDomainInfo level %u failed - %s\n", 
			       q[levels[i]].in.level, nt_errstr(nt_status));
			return False;
		}
	}

	TEST_STRING_EQUAL(q[5].out.info->info5.domain_name, domain->domain_name);
	
	TEST_STRING_EQUAL(q[2].out.info->info2.comment, domain->comment);
	TEST_STRING_EQUAL(q[4].out.info->info4.comment, domain->comment);
	TEST_TIME_EQUAL(q[2].out.info->info2.force_logoff_time, domain->force_logoff_time);
	TEST_TIME_EQUAL(q[3].out.info->info3.force_logoff_time, domain->force_logoff_time);

	TEST_TIME_EQUAL(q[1].out.info->info1.min_password_length, domain->min_password_length);
	TEST_TIME_EQUAL(q[1].out.info->info1.password_history_length, domain->password_history_length);
	TEST_TIME_EQUAL(q[1].out.info->info1.max_password_age, domain->max_password_age);
	TEST_TIME_EQUAL(q[1].out.info->info1.min_password_age, domain->min_password_age);

	TEST_UINT64_EQUAL(q[8].out.info->info8.sequence_num, 
			domain->sequence_num);
	TEST_TIME_EQUAL(q[8].out.info->info8.domain_create_time, 
			domain->domain_create_time);
	TEST_TIME_EQUAL(q[13].out.info->info13.domain_create_time, 
			domain->domain_create_time);

	TEST_SEC_DESC_EQUAL(domain->sdbuf, samr, samsync_state->domain_handle[database_id]);

	return ret;
}

static BOOL samsync_handle_policy(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
			   int database_id, struct netr_DELTA_ENUM *delta) 
{
	struct netr_DELTA_POLICY *policy = delta->delta_union.policy;

	samsync_state->seq_num[database_id] = 
		policy->sequence_num;
	
	if (!samsync_state->domain_name[SAM_DATABASE_DOMAIN]) {
		samsync_state->domain_name[SAM_DATABASE_DOMAIN] = 
			talloc_reference(samsync_state, policy->primary_domain_name.string);
	} else {
		if (StrCaseCmp(samsync_state->domain_name[SAM_DATABASE_DOMAIN], policy->primary_domain_name.string) != 0) {
			printf("PRIMARY domain has name varies between DOMAIN and POLICY!: %s != %s\n", samsync_state->domain_name[SAM_DATABASE_DOMAIN], 
			       policy->primary_domain_name.string);
			return False;
		}
	}

	if (!dom_sid_equal(samsync_state->sid[SAM_DATABASE_DOMAIN], policy->sid)) {
		printf("Domain SID from POLICY (%s) does not match domain sid from SAMR (%s)\n", 
		       dom_sid_string(mem_ctx, policy->sid), dom_sid_string(mem_ctx, samsync_state->sid[SAM_DATABASE_DOMAIN]));
		return False;
	}

	printf("\tsequence_nums[%d/PRIVS]=%llu\n",
	       database_id, 
	       samsync_state->seq_num[database_id]);
	return True;
}

static BOOL samsync_handle_user(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
				int database_id, struct netr_DELTA_ENUM *delta) 
{
	uint32 rid = delta->delta_id_union.rid;
	struct netr_DELTA_USER *user = delta->delta_union.user;
	struct netr_SamInfo3 *info3;
	struct samr_Password lm_hash;
	struct samr_Password nt_hash;
	struct samr_Password *lm_hash_p = NULL;
	struct samr_Password *nt_hash_p = NULL;
	const char *domain = samsync_state->domain_name[database_id];
	const char *username = user->account_name.string;
	NTSTATUS nt_status;
	BOOL ret = True;

	struct samr_OpenUser r;
	struct samr_QueryUserInfo q;
	struct policy_handle user_handle;

	if (!samsync_state->domain_name || !samsync_state->domain_handle[database_id]) {
		printf("SamSync needs domain information before the users\n");
		return False;
	}

	r.in.domain_handle = samsync_state->domain_handle[database_id];
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.user_handle = &user_handle;

	nt_status = dcerpc_samr_OpenUser(samsync_state->p_samr, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("OpenUser(%u) failed - %s\n", rid, nt_errstr(nt_status));
		return False;
	}

	q.in.user_handle = &user_handle;
	q.in.level = 21;

	TEST_SEC_DESC_EQUAL(user->sdbuf, samr, &user_handle);

	nt_status = dcerpc_samr_QueryUserInfo(samsync_state->p_samr, mem_ctx, &q);
	if (!test_samr_handle_Close(samsync_state->p_samr, mem_ctx, &user_handle)) {
		return False;
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("QueryUserInfo level %u failed - %s\n", 
		       q.in.level, nt_errstr(nt_status));
		return False;
	}

	TEST_STRING_EQUAL(q.out.info->info21.account_name, user->account_name);
	TEST_STRING_EQUAL(q.out.info->info21.full_name, user->full_name);
	TEST_INT_EQUAL(q.out.info->info21.rid, user->rid);
	TEST_INT_EQUAL(q.out.info->info21.primary_gid, user->primary_gid);
	TEST_STRING_EQUAL(q.out.info->info21.home_directory, user->home_directory);
	TEST_STRING_EQUAL(q.out.info->info21.home_drive, user->home_drive);
	TEST_STRING_EQUAL(q.out.info->info21.logon_script, user->logon_script);
	TEST_STRING_EQUAL(q.out.info->info21.description, user->description);
	TEST_STRING_EQUAL(q.out.info->info21.workstations, user->workstations);

	TEST_TIME_EQUAL(q.out.info->info21.last_logon, user->last_logon);
	TEST_TIME_EQUAL(q.out.info->info21.last_logoff, user->last_logoff);


	TEST_INT_EQUAL(q.out.info->info21.logon_hours.units_per_week, 
		       user->logon_hours.units_per_week);
	if (ret) {
		if (memcmp(q.out.info->info21.logon_hours.bitmap, user->logon_hours.bitmap, 
			   q.out.info->info21.logon_hours.units_per_week/8) != 0) {
			printf("Logon hours mismatch\n");
			ret = False;
		}
	}

	TEST_INT_EQUAL(q.out.info->info21.bad_password_count,
		       user->bad_password_count);
	TEST_INT_EQUAL(q.out.info->info21.logon_count,
		       user->logon_count);

	TEST_TIME_EQUAL(q.out.info->info21.last_password_change,
		       user->last_password_change);
	TEST_TIME_EQUAL(q.out.info->info21.acct_expiry,
		       user->acct_expiry);

	TEST_INT_EQUAL(q.out.info->info21.acct_flags, user->acct_flags);
	TEST_INT_EQUAL(q.out.info->info21.nt_password_set, user->nt_password_present);
	TEST_INT_EQUAL(q.out.info->info21.lm_password_set, user->lm_password_present);
	TEST_INT_EQUAL(q.out.info->info21.password_expired, user->password_expired);

	TEST_STRING_EQUAL(q.out.info->info21.comment, user->comment);
	TEST_STRING_EQUAL(q.out.info->info21.parameters, user->parameters);

	TEST_INT_EQUAL(q.out.info->info21.country_code, user->country_code);
	TEST_INT_EQUAL(q.out.info->info21.code_page, user->code_page);

	TEST_STRING_EQUAL(q.out.info->info21.profile_path, user->profile_path);

	if (user->lm_password_present) {
		sam_rid_crypt(rid, user->lmpassword.hash, lm_hash.hash, 0);
		lm_hash_p = &lm_hash;
	}
	if (user->nt_password_present) {
		sam_rid_crypt(rid, user->ntpassword.hash, nt_hash.hash, 0);
		nt_hash_p = &nt_hash;
	}

	if (user->user_private_info.SensitiveData) {
		DATA_BLOB data;
		struct netr_USER_KEYS keys;
		data.data = user->user_private_info.SensitiveData;
		data.length = user->user_private_info.DataLength;
		creds_arcfour_crypt(samsync_state->creds, data.data, data.length);
#if 0		
		printf("Sensitive Data for %s:\n", username);
		dump_data(0, data.data, data.length);
#endif
		nt_status = ndr_pull_struct_blob(&data, mem_ctx, &keys, (ndr_pull_flags_fn_t)ndr_pull_netr_USER_KEYS);
		if (NT_STATUS_IS_OK(nt_status)) {
			if (keys.keys.keys2.lmpassword.length == 16) {
				sam_rid_crypt(rid, keys.keys.keys2.lmpassword.pwd.hash, lm_hash.hash, 0);
				lm_hash_p = &lm_hash;
			}
			if (keys.keys.keys2.ntpassword.length == 16) {
				sam_rid_crypt(rid, keys.keys.keys2.ntpassword.pwd.hash, nt_hash.hash, 0);
				nt_hash_p = &nt_hash;
			}
		}
		
	}

	nt_status = test_SamLogon(samsync_state->p, mem_ctx, samsync_state->creds, 
				  domain,
				  username, 
				  TEST_MACHINE_NAME,
				  lm_hash_p,
				  nt_hash_p,
				  &info3);

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_DISABLED)) {
		if (user->acct_flags & ACB_DISABLED) {
			return True;
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT)) {
		if (user->acct_flags & ACB_WSTRUST) {
			return True;
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT)) {
		if (user->acct_flags & ACB_SVRTRUST) {
			return True;
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT)) {
		if (user->acct_flags & ACB_DOMTRUST) {
			return True;
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT)) {
		if (user->acct_flags & ACB_DOMTRUST) {
			return True;
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_LOCKED_OUT)) {
		if (user->acct_flags & ACB_AUTOLOCK) {
			return True;
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD)) {
		if (!lm_hash_p && !nt_hash_p) {
			return True;
		}
	} else if (NT_STATUS_IS_OK(nt_status)) {
		TEST_INT_EQUAL(user->rid, info3->base.rid);
		TEST_INT_EQUAL(user->primary_gid, info3->base.primary_gid);
		TEST_INT_EQUAL(user->acct_flags, info3->base.acct_flags);
		TEST_STRING_EQUAL(user->account_name, info3->base.account_name);
		TEST_STRING_EQUAL(user->full_name, info3->base.full_name);
		TEST_STRING_EQUAL(user->logon_script, info3->base.logon_script);
		TEST_STRING_EQUAL(user->profile_path, info3->base.profile_path);
		TEST_STRING_EQUAL(user->home_directory, info3->base.home_directory);
		TEST_STRING_EQUAL(user->home_drive, info3->base.home_drive);
		TEST_STRING_EQUAL(user->logon_script, info3->base.logon_script);


		TEST_TIME_EQUAL(user->last_logon, info3->base.last_logon);
		TEST_TIME_EQUAL(user->acct_expiry, info3->base.acct_expiry);
		TEST_TIME_EQUAL(user->last_password_change, info3->base.last_password_change);

		/* Does the concept of a logoff time ever really
		 * exist? (not in any sensible way, according to the
		 * doco I read -- abartlet) */

		/* This copes with the two different versions of 0 I see */
		if (!((user->last_logoff == 0) 
		      && (info3->base.last_logoff == 0x7fffffffffffffffLL))) {
			TEST_TIME_EQUAL(user->last_logoff, info3->base.last_logoff);
		}
		return ret;
	} else {
		printf("Could not validate password for user %s\\%s: %s\n",
		       domain, username, nt_errstr(nt_status));
		return False;
	} 
	return False;
}

static BOOL samsync_handle_alias(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
				 int database_id, struct netr_DELTA_ENUM *delta) 
{
	uint32 rid = delta->delta_id_union.rid;
	struct netr_DELTA_ALIAS *alias = delta->delta_union.alias;
	NTSTATUS nt_status;
	BOOL ret = True;

	struct samr_OpenAlias r;
	struct samr_QueryAliasInfo q;
	struct policy_handle alias_handle;

	if (!samsync_state->domain_name || !samsync_state->domain_handle[database_id]) {
		printf("SamSync needs domain information before the users\n");
		return False;
	}

	r.in.domain_handle = samsync_state->domain_handle[database_id];
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.alias_handle = &alias_handle;

	nt_status = dcerpc_samr_OpenAlias(samsync_state->p_samr, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("OpenUser(%u) failed - %s\n", rid, nt_errstr(nt_status));
		return False;
	}

	q.in.alias_handle = &alias_handle;
	q.in.level = 1;

	TEST_SEC_DESC_EQUAL(alias->sdbuf, samr, &alias_handle);

	nt_status = dcerpc_samr_QueryAliasInfo(samsync_state->p_samr, mem_ctx, &q);
	if (!test_samr_handle_Close(samsync_state->p_samr, mem_ctx, &alias_handle)) {
		return False;
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("QueryAliasInfo level %u failed - %s\n", 
		       q.in.level, nt_errstr(nt_status));
		return False;
	}

	TEST_STRING_EQUAL(q.out.info->all.name, alias->alias_name);
	TEST_STRING_EQUAL(q.out.info->all.description, alias->description);
	return ret;
}

static BOOL samsync_handle_group(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
				 int database_id, struct netr_DELTA_ENUM *delta) 
{
	uint32 rid = delta->delta_id_union.rid;
	struct netr_DELTA_GROUP *group = delta->delta_union.group;
	NTSTATUS nt_status;
	BOOL ret = True;

	struct samr_OpenGroup r;
	struct samr_QueryGroupInfo q;
	struct policy_handle group_handle;

	if (!samsync_state->domain_name || !samsync_state->domain_handle[database_id]) {
		printf("SamSync needs domain information before the users\n");
		return False;
	}

	r.in.domain_handle = samsync_state->domain_handle[database_id];
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.group_handle = &group_handle;

	nt_status = dcerpc_samr_OpenGroup(samsync_state->p_samr, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("OpenUser(%u) failed - %s\n", rid, nt_errstr(nt_status));
		return False;
	}

	q.in.group_handle = &group_handle;
	q.in.level = 1;

	TEST_SEC_DESC_EQUAL(group->sdbuf, samr, &group_handle);

	nt_status = dcerpc_samr_QueryGroupInfo(samsync_state->p_samr, mem_ctx, &q);
	if (!test_samr_handle_Close(samsync_state->p_samr, mem_ctx, &group_handle)) {
		return False;
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("QueryGroupInfo level %u failed - %s\n", 
		       q.in.level, nt_errstr(nt_status));
		return False;
	}

	TEST_STRING_EQUAL(q.out.info->all.name, group->group_name);
	TEST_INT_EQUAL(q.out.info->all.attributes, group->attributes);
	TEST_STRING_EQUAL(q.out.info->all.description, group->description);
	return ret;
}

static BOOL samsync_handle_secret(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
				  int database_id, struct netr_DELTA_ENUM *delta) 
{
	struct netr_DELTA_SECRET *secret = delta->delta_union.secret;
	const char *name = delta->delta_id_union.name;
	struct samsync_secret *new = talloc_p(samsync_state, struct samsync_secret);
	struct lsa_QuerySecret q;
	struct lsa_OpenSecret o;
	struct policy_handle sec_handle;
	struct lsa_DATA_BUF_PTR bufp1;
	NTTIME new_mtime;
	BOOL ret = True;
	DATA_BLOB lsa_blob1, lsa_blob_out, session_key;
	NTSTATUS status;

	creds_arcfour_crypt(samsync_state->creds, secret->current_cipher.cipher_data, 
			    secret->current_cipher.maxlen); 

	creds_arcfour_crypt(samsync_state->creds, secret->old_cipher.cipher_data, 
			    secret->old_cipher.maxlen); 

	new->name = talloc_reference(new, name);
	new->secret = data_blob_talloc(new, secret->current_cipher.cipher_data, secret->current_cipher.maxlen);

	DLIST_ADD(samsync_state->secrets, new);

	o.in.handle = samsync_state->lsa_handle;
	o.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	o.in.name.string = name;
	o.out.sec_handle = &sec_handle;

	status = dcerpc_lsa_OpenSecret(samsync_state->p_lsa, mem_ctx, &o);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenSecret failed - %s\n", nt_errstr(status));
		return False;
	}

	TEST_SEC_DESC_EQUAL(secret->sdbuf, lsa, &sec_handle);

	status = dcerpc_fetch_session_key(samsync_state->p_lsa, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_fetch_session_key failed - %s\n", nt_errstr(status));
		return False;
	}


	ZERO_STRUCT(new_mtime);

	/* fetch the secret back again */
	q.in.handle = &sec_handle;
	q.in.new_val = &bufp1;
	q.in.new_mtime = &new_mtime;
	q.in.old_val = NULL;
	q.in.old_mtime = NULL;

	bufp1.buf = NULL;

	status = dcerpc_lsa_QuerySecret(samsync_state->p_lsa, mem_ctx, &q);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecret failed - %s\n", nt_errstr(status));
		return False;
	}

	if (q.out.new_val->buf == NULL) {
		/* probably just not available due to ACLs */
	} else {
		lsa_blob1.data = q.out.new_val->buf->data;
		lsa_blob1.length = q.out.new_val->buf->length;

		lsa_blob_out = sess_decrypt_blob(mem_ctx, &lsa_blob1, &session_key);
		
		if (new->secret.length != lsa_blob_out.length) {
			printf("Returned secret %s doesn't match: %d != %d\n",
			       new->name, new->secret.length, lsa_blob_out.length);
			ret = False;
		}

		if (memcmp(lsa_blob_out.data, 
			   new->secret.data, new->secret.length) != 0) {
			printf("Returned secret %s doesn't match: \n",
			       new->name);
			DEBUG(1, ("SamSync Secret:\n"));
			dump_data(1, new->secret.data, new->secret.length);
			DEBUG(1, ("LSA Secret:\n"));
			dump_data(1, lsa_blob_out.data, lsa_blob_out.length);
			ret = False;
		}
	}

	return ret;
}

static BOOL samsync_handle_trusted_domain(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
					  int database_id, struct netr_DELTA_ENUM *delta) 
{
	NTSTATUS status;
	BOOL ret = True;
	struct netr_DELTA_TRUSTED_DOMAIN *trusted_domain = delta->delta_union.trusted_domain;
	struct dom_sid *dom_sid = delta->delta_id_union.sid;

	struct samsync_trusted_domain *new = talloc_p(samsync_state, struct samsync_trusted_domain);
	struct lsa_OpenTrustedDomain t;
	struct policy_handle trustdom_handle;
	struct lsa_QueryInfoTrustedDomain q;
	union lsa_TrustedDomainInfo info[4];
	int levels [] = {1, 3};
	int i;

	new->name = talloc_reference(new, trusted_domain->domain_name.string);
	new->sid = talloc_reference(new, dom_sid);

	t.in.handle = samsync_state->lsa_handle;
	t.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	t.in.sid = dom_sid;
	t.out.trustdom_handle = &trustdom_handle;

	status = dcerpc_lsa_OpenTrustedDomain(samsync_state->p_lsa, mem_ctx, &t);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenTrustedDomain failed - %s\n", nt_errstr(status));
		return False;
	}
	
	for (i=0; i< ARRAY_SIZE(levels); i++) {
		q.in.trustdom_handle = &trustdom_handle;
		q.in.level = levels[i];
		q.out.info = &info[levels[i]];
		status = dcerpc_lsa_QueryInfoTrustedDomain(samsync_state->p_lsa, mem_ctx, &q);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryInfoTrustedDomain level %d failed - %s\n", 
			       levels[i], nt_errstr(status));
			return False;
		}
	}

	TEST_STRING_EQUAL(info[1].info1.domain_name, trusted_domain->domain_name);
	TEST_INT_EQUAL(info[3].info3.flags, trusted_domain->flags);
	TEST_SEC_DESC_EQUAL(trusted_domain->sdbuf, lsa, &trustdom_handle);

	DLIST_ADD(samsync_state->trusted_domains, new);

	return ret;
}

static BOOL samsync_handle_account(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
					  int database_id, struct netr_DELTA_ENUM *delta) 
{
	NTSTATUS status;
	BOOL ret = True;
	struct netr_DELTA_ACCOUNT *account = delta->delta_union.account;
	struct dom_sid *dom_sid = delta->delta_id_union.sid;

	struct lsa_OpenAccount a;
	struct policy_handle acct_handle;
	struct lsa_EnumPrivsAccount e;
	struct lsa_LookupPrivName r;

	int i, j;

	BOOL *found_priv_in_lsa;

	a.in.handle = samsync_state->lsa_handle;
	a.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	a.in.sid = dom_sid;
	a.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_OpenAccount(samsync_state->p_lsa, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenTrustedDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	TEST_SEC_DESC_EQUAL(account->sdbuf, lsa, &acct_handle);

	found_priv_in_lsa = talloc_zero_array_p(mem_ctx, BOOL, account->privilege_entries);

	e.in.handle = &acct_handle;

	status = dcerpc_lsa_EnumPrivsAccount(samsync_state->p_lsa, mem_ctx, &e);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivsAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!e.out.privs) {
		return account->privilege_entries != 0;
	}

	if ((account->privilege_entries && !e.out.privs)) {
		return False;
	}

	TEST_INT_EQUAL(account->privilege_entries, e.out.privs->count);
	
	for (i=0;i< e.out.privs->count; i++) {
		r.in.handle = samsync_state->lsa_handle;
		r.in.luid = &e.out.privs->set[i].luid;
		
		status = dcerpc_lsa_LookupPrivName(samsync_state->p_lsa, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("\nLookupPrivName failed - %s\n", nt_errstr(status));
			return False;
		}
		
		if (!r.out.name) {
			printf("\nLookupPrivName failed to return a name\n");
			return False;
		}
		for (j=0;j<account->privilege_entries; j++) {
			if (strcmp(r.out.name->string, account->privilege_name[j].string) == 0) {
				found_priv_in_lsa[j] = True;
				break;
			}
		}
	}
	for (j=0;j<account->privilege_entries; j++) {
		if (!found_priv_in_lsa[j]) {
			printf("Privilage %s on account %s not found in LSA\n", account->privilege_name[j].string, 
			       dom_sid_string(mem_ctx, dom_sid));
			ret = False;
		}
	}
	return ret;
}

/*
  try a netlogon DatabaseSync
*/
static BOOL test_DatabaseSync(struct samsync_state *samsync_state,
			      TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DatabaseSync r;
	const uint32_t database_ids[] = {SAM_DATABASE_DOMAIN, SAM_DATABASE_BUILTIN, SAM_DATABASE_PRIVS}; 
	int i, d;
	BOOL ret = True;
	struct samsync_trusted_domain *t;
	struct samsync_secret *s;
	
	const char *domain, *username;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(samsync_state->p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.sync_context = 0;
		r.in.database_id = database_ids[i];

		printf("Testing DatabaseSync of id %d\n", r.in.database_id);

		do {
			creds_client_authenticator(samsync_state->creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync(samsync_state->p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseSync - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(samsync_state->creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sync_context = r.out.sync_context;

			for (d=0; d < r.out.delta_enum_array->num_deltas; d++) {
				switch (r.out.delta_enum_array->delta_enum[d].delta_type) {
				case NETR_DELTA_DOMAIN:
					ret &= samsync_handle_domain(mem_ctx, samsync_state, 
								     r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				case NETR_DELTA_GROUP:
					ret &= samsync_handle_group(mem_ctx, samsync_state, 
								    r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				case NETR_DELTA_USER:
					ret &= samsync_handle_user(mem_ctx, samsync_state, 
								   r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				case NETR_DELTA_ALIAS:
					ret &= samsync_handle_alias(mem_ctx, samsync_state, 
								    r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				case NETR_DELTA_POLICY:
					ret &= samsync_handle_policy(mem_ctx, samsync_state, 
								     r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				case NETR_DELTA_TRUSTED_DOMAIN:
					ret &= samsync_handle_trusted_domain(mem_ctx, samsync_state, 
									     r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				case NETR_DELTA_ACCOUNT:
					ret &= samsync_handle_account(mem_ctx, samsync_state, 
								     r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				case NETR_DELTA_SECRET:
					ret &= samsync_handle_secret(mem_ctx, samsync_state, 
								     r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				}
			}
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
		
	}

	domain = samsync_state->domain_name[SAM_DATABASE_DOMAIN];
	if (!domain) {
		printf("Never got a DOMAIN object in samsync!\n");
		return False;
	}
	
	username = talloc_asprintf(mem_ctx, "%s$", domain);
	for (t=samsync_state->trusted_domains; t; t=t->next) {
		char *secret_name = talloc_asprintf(mem_ctx, "G$$%s", t->name);
		for (s=samsync_state->secrets; s; s=s->next) {
			if (StrCaseCmp(s->name, secret_name) == 0) {
				NTSTATUS nt_status;
				struct samr_Password nt_hash;
				mdfour(nt_hash.hash, s->secret.data, s->secret.length);
				
				printf("Checking password for %s\\%s\n", t->name, username);
				nt_status = test_SamLogon(samsync_state->p_netlogon_wksta, mem_ctx, samsync_state->creds_netlogon_wksta, 
							  t->name,
							  username, 
							  TEST_MACHINE_NAME2,
							  NULL, 
							  &nt_hash,
							  NULL);
				if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_LOGON_SERVERS)) {
					printf("Verifiction of trust password to %s failed: %s (the trusted domain is not available)\n", 
					       t->name, nt_errstr(nt_status));
					
					break;
				}
				if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT)) {
					printf("Verifiction of trust password to %s: should have failed (nologon interdomain trust account), instead: %s\n", 
					       t->name, nt_errstr(nt_status));
					ret = False;
				}
				
				/* break it */
				nt_hash.hash[0]++;
				nt_status = test_SamLogon(samsync_state->p_netlogon_wksta, mem_ctx, samsync_state->creds_netlogon_wksta, 
							  t->name,
							  username, 
							  TEST_MACHINE_NAME2,
							  NULL,
							  &nt_hash,
							  NULL);
				
				if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD)) {
					printf("Verifiction of trust password to %s: should have failed (wrong password), instead: %s\n", 
					       t->name, nt_errstr(nt_status));
					ret = False;
					ret = False;
				}
				
				break;
			}
		}
	}
	return ret;
}


/*
  try a netlogon DatabaseDeltas
*/
static BOOL test_DatabaseDeltas(struct samsync_state *samsync_state, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DatabaseDeltas r;
	const uint32_t database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(samsync_state->p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.database_id = database_ids[i];
		r.in.sequence_num = samsync_state->seq_num[i];

		if (r.in.sequence_num == 0) continue;

		r.in.sequence_num -= 1;


		printf("Testing DatabaseDeltas of id %d at %llu\n", 
		       r.in.database_id, r.in.sequence_num);

		do {
			creds_client_authenticator(samsync_state->creds, &r.in.credential);

			status = dcerpc_netr_DatabaseDeltas(samsync_state->p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseDeltas - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(samsync_state->creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sequence_num++;
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
	}

	return ret;
}


/*
  try a netlogon DatabaseSync2
*/
static BOOL test_DatabaseSync2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_DatabaseSync2 r;
	const uint32_t database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.sync_context = 0;
		r.in.database_id = database_ids[i];
		r.in.restart_state = 0;

		printf("Testing DatabaseSync2 of id %d\n", r.in.database_id);

		do {
			creds_client_authenticator(creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync2(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseSync2 - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sync_context = r.out.sync_context;
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
	}

	return ret;
}



BOOL torture_rpc_samsync(void)
{
        NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct test_join *join_ctx;
	struct test_join *join_ctx2;
	const char *machine_password;
	const char *machine_password2;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding b;
	struct dcerpc_binding b_netlogon_wksta;
	struct samr_Connect c;
	struct samr_SetDomainInfo s;
	struct policy_handle *domain_policy;

	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;

	struct samsync_state *samsync_state;

	mem_ctx = talloc_init("torture_rpc_netlogon");

	join_ctx = torture_join_domain(TEST_MACHINE_NAME, lp_workgroup(), ACB_SVRTRUST, 
				       &machine_password);
	if (!join_ctx) {
		printf("Failed to join as BDC\n");
		return False;
	}
	
	join_ctx2 = torture_join_domain(TEST_MACHINE_NAME2, lp_workgroup(), ACB_WSTRUST, 
				       &machine_password2);
	if (!join_ctx2) {
		printf("Failed to join as member\n");
		return False;
	}
	
	samsync_state = talloc_zero_p(mem_ctx, struct samsync_state);

	samsync_state->p_samr = torture_join_samr_pipe(join_ctx);
	samsync_state->connect_handle = talloc_zero_p(samsync_state, struct policy_handle);
	samsync_state->lsa_handle = talloc_zero_p(samsync_state, struct policy_handle);
	c.in.system_name = NULL;
	c.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	c.out.connect_handle = samsync_state->connect_handle;

	status = dcerpc_samr_Connect(samsync_state->p_samr, mem_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		printf("samr_Connect failed\n");
		ret = False;
		goto failed;
	}

	domain_policy = samsync_open_domain(mem_ctx, samsync_state, lp_workgroup(), NULL);
	if (!domain_policy) {
		printf("samrsync_open_domain failed\n");
		ret = False;
		goto failed;
	}
	
	s.in.domain_handle = domain_policy;
	s.in.level = 4;
	s.in.info = talloc_p(mem_ctx, union samr_DomainInfo);
	
	s.in.info->info4.comment.string
		= talloc_asprintf(mem_ctx, 
				  "Tortured by Samba4: %s", 
				  timestring(mem_ctx, time(NULL)));
	status = dcerpc_samr_SetDomainInfo(samsync_state->p_samr, mem_ctx, &s);

	if (!test_samr_handle_Close(samsync_state->p_samr, mem_ctx, domain_policy)) {
		ret = False;
		goto failed;
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("SetDomainInfo level %u failed - %s\n", 
		       s.in.level, nt_errstr(status));
		ret = False;
		goto failed;
	}
	

	status = torture_rpc_connection(&samsync_state->p_lsa, 
					DCERPC_LSARPC_NAME,
					DCERPC_LSARPC_UUID,
					DCERPC_LSARPC_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
		goto failed;
	}

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = "\\";
	r.in.attr = &attr;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = samsync_state->lsa_handle;

	status = dcerpc_lsa_OpenPolicy2(samsync_state->p_lsa, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy2 failed - %s\n", nt_errstr(status));
		ret = False;
		goto failed;
	}

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		ret = False;
		goto failed;
	}

	b.flags &= ~DCERPC_AUTH_OPTIONS;
	b.flags |= DCERPC_SCHANNEL_BDC | DCERPC_SIGN | DCERPC_SCHANNEL_128;

	status = dcerpc_pipe_connect_b(&samsync_state->p, &b, 
				       DCERPC_NETLOGON_UUID,
				       DCERPC_NETLOGON_VERSION,
				       lp_workgroup(), 
				       TEST_MACHINE_NAME,
				       machine_password);

	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
		goto failed;
	}

	status = dcerpc_schannel_creds(samsync_state->p->security_state.generic_state, mem_ctx, &samsync_state->creds);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}



	status = dcerpc_parse_binding(mem_ctx, binding, &b_netlogon_wksta);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		ret = False;
		goto failed;
	}

	b_netlogon_wksta.flags &= ~DCERPC_AUTH_OPTIONS;
	b_netlogon_wksta.flags |= DCERPC_SCHANNEL_WORKSTATION | DCERPC_SIGN | DCERPC_SCHANNEL_128;

	status = dcerpc_pipe_connect_b(&samsync_state->p_netlogon_wksta, &b_netlogon_wksta, 
				       DCERPC_NETLOGON_UUID,
				       DCERPC_NETLOGON_VERSION,
				       lp_workgroup(), 
				       TEST_MACHINE_NAME2,
				       machine_password2);

	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
		goto failed;
	}

	status = dcerpc_schannel_creds(samsync_state->p_netlogon_wksta->security_state.generic_state, mem_ctx, &samsync_state->creds_netlogon_wksta);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}

	if (!test_DatabaseSync(samsync_state, mem_ctx)) {
		ret = False;
	}

	if (!test_DatabaseDeltas(samsync_state, mem_ctx)) {
		ret = False;
	}

	if (!test_DatabaseSync2(samsync_state->p, mem_ctx, samsync_state->creds)) {
		ret = False;
	}
failed:
	torture_rpc_close(samsync_state->p);

	torture_leave_domain(join_ctx);
	torture_leave_domain(join_ctx2);

	talloc_destroy(mem_ctx);

	return ret;
}
