/* 
   Unix SMB/CIFS implementation.

   test suite for netlogon rpc operations

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003-2004
   Copyright (C) Tim Potter      2003
   
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
#include "torture/torture.h"
#include "auth/auth.h"
#include "lib/util/dlinklist.h"
#include "lib/crypto/crypto.h"
#include "system/time.h"
#include "torture/rpc/rpc.h"
#include "auth/gensec/schannel_proto.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_security.h"

#define TEST_MACHINE_NAME "samsynctest"
#define TEST_WKSTA_MACHINE_NAME "samsynctest2"
#define TEST_USER_NAME "samsynctestuser"

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
		ninfo.nt.data = talloc_size(mem_ctx, 24);
		SMBOWFencrypt(nt_hash->hash, ninfo.challenge, ninfo.nt.data);
	} else {
		ninfo.nt.length = 0;
		ninfo.nt.data = NULL;
	}
	
	if (lm_hash) {
		ninfo.lm.length = 24;
		ninfo.lm.data = talloc_size(mem_ctx, 24);
		SMBOWFencrypt(lm_hash->hash, ninfo.challenge, ninfo.lm.data);
	} else {
		ninfo.lm.length = 0;
		ninfo.lm.data = NULL;
	}

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = workstation;
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
	const char *domain_name[2];
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
	const char *name;
	NTTIME mtime;
};

struct samsync_trusted_domain {
	struct samsync_trusted_domain *prev, *next;
        struct dom_sid *sid;
	const char *name;
};

static struct policy_handle *samsync_open_domain(TALLOC_CTX *mem_ctx, 
						 struct samsync_state *samsync_state, 
						 const char *domain, 
						 struct dom_sid **sid)
{
	struct lsa_String name;
	struct samr_OpenDomain o;
	struct samr_LookupDomain l;
	struct policy_handle *domain_handle = talloc(mem_ctx, struct policy_handle);
	NTSTATUS nt_status;

	name.string = domain;
	l.in.connect_handle = samsync_state->connect_handle;
	l.in.domain_name = &name;

	nt_status = dcerpc_samr_LookupDomain(samsync_state->p_samr, mem_ctx, &l);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(nt_status));
		return NULL;
	}

	o.in.connect_handle = samsync_state->connect_handle;
	o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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
              printf("%s: uint64 mismatch: " #i1 ": 0x%016llx (%lld) != " #i2 ": 0x%016llx (%lld)\n", \
		     __location__, \
		     (long long)i1, (long long)i1, \
		     (long long)i2, (long long)i2);\
	      ret = False;\
	} \
} while (0)
#define TEST_INT_EQUAL(i1, i2) do {\
	if (i1 != i2) {\
	      printf("%s: integer mismatch: " #i1 ": 0x%08x (%d) != " #i2 ": 0x%08x (%d)\n", \
		     __location__, i1, i1, i2, i2);			\
	      ret = False;\
	} \
} while (0)
#define TEST_TIME_EQUAL(t1, t2) do {\
	if (t1 != t2) {\
	      printf("%s: NTTIME mismatch: " #t1 ":%s != " #t2 ": %s\n", \
		     __location__, nt_time_string(mem_ctx, t1),  nt_time_string(mem_ctx, t2));\
	      ret = False;\
	} \
} while (0)

#define TEST_STRING_EQUAL(s1, s2) do {\
	if (!((!s1.string || s1.string[0]=='\0') && (!s2.string || s2.string[0]=='\0')) \
	    && strcmp_safe(s1.string, s2.string) != 0) {\
	      printf("%s: string mismatch: " #s1 ":%s != " #s2 ": %s\n", \
		     __location__, s1.string, s2.string);\
	      ret = False;\
	} \
} while (0)

#define TEST_SID_EQUAL(s1, s2) do {\
	if (!dom_sid_equal(s1, s2)) {\
	      printf("%s: dom_sid mismatch: " #s1 ":%s != " #s2 ": %s\n", \
		     __location__, dom_sid_string(mem_ctx, s1), dom_sid_string(mem_ctx, s2));\
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
		if (strcasecmp_m("BUILTIN", domain->domain_name.string) != 0) {
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
		if (strcasecmp_m(samsync_state->domain_name[database_id], domain->domain_name.string) != 0) {
			printf("Domain has name varies!: %s != %s\n", samsync_state->domain_name[database_id], 
			       domain->domain_name.string);
			return False;
		}
	}

	if (!samsync_state->domain_handle[database_id]) {
		samsync_state->domain_handle[database_id]
			= talloc_reference(samsync_state, 
					   samsync_open_domain(mem_ctx, samsync_state, samsync_state->domain_name[database_id], 
							       &dom_sid));
	}
	if (samsync_state->domain_handle[database_id]) {
		samsync_state->sid[database_id] = talloc_reference(samsync_state, dom_sid);
	}

	printf("\tsequence_nums[%d/%s]=%llu\n",
	       database_id, domain->domain_name.string,
	       (long long)samsync_state->seq_num[database_id]);

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
		if (strcasecmp_m(samsync_state->domain_name[SAM_DATABASE_DOMAIN], policy->primary_domain_name.string) != 0) {
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
	       (long long)samsync_state->seq_num[database_id]);
	return True;
}

static BOOL samsync_handle_user(TALLOC_CTX *mem_ctx, struct samsync_state *samsync_state,
				int database_id, struct netr_DELTA_ENUM *delta) 
{
	uint32_t rid = delta->delta_id_union.rid;
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

	struct samr_GetGroupsForUser getgroups;
	if (!samsync_state->domain_name || !samsync_state->domain_handle[database_id]) {
		printf("SamSync needs domain information before the users\n");
		return False;
	}

	r.in.domain_handle = samsync_state->domain_handle[database_id];
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("QueryUserInfo level %u failed - %s\n", 
		       q.in.level, nt_errstr(nt_status));
		ret = False;
	}

	getgroups.in.user_handle = &user_handle;
	
	nt_status = dcerpc_samr_GetGroupsForUser(samsync_state->p_samr, mem_ctx, &getgroups);
	if (!NT_STATUS_IS_OK(nt_status)) {
		printf("GetGroupsForUser failed - %s\n",
		       nt_errstr(nt_status));
		ret = False;
	}

	if (!test_samr_handle_Close(samsync_state->p_samr, mem_ctx, &user_handle)) {
		printf("samr_handle_Close failed - %s\n", 
		       nt_errstr(nt_status));
		ret = False;
	}
	if (!ret) {
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
		if (memcmp(q.out.info->info21.logon_hours.bits, user->logon_hours.bits, 
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

	TEST_INT_EQUAL((q.out.info->info21.acct_flags & ~ACB_PW_EXPIRED), user->acct_flags);
	if (user->acct_flags & ACB_PWNOEXP) {
		if (q.out.info->info21.acct_flags & ACB_PW_EXPIRED) {
			printf("ACB flags mismatch: both expired and no expiry!\n");
			ret = False;
		}
		if (q.out.info->info21.force_password_change != (NTTIME)0x7FFFFFFFFFFFFFFFULL) {
			printf("ACB flags mismatch: no password expiry, but force password change 0x%016llx (%lld) != 0x%016llx (%lld)\n",
			       (unsigned long long)q.out.info->info21.force_password_change, 
			       (unsigned long long)q.out.info->info21.force_password_change,
			       (unsigned long long)0x7FFFFFFFFFFFFFFFULL, (unsigned long long)0x7FFFFFFFFFFFFFFFULL
				);
			ret = False;
		}
	}

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
		} else {
			printf("Failed to parse Sensitive Data for %s:\n", username);
#if 0
			dump_data(0, data.data, data.length);
#endif
			return False;
		}
	}

	if (nt_hash_p) {
		DATA_BLOB nt_hash_blob = data_blob_const(nt_hash_p, 16);
		DEBUG(100,("ACCOUNT [%s\\%-25s] NTHASH %s\n", samsync_state->domain_name[0], username, data_blob_hex_string(mem_ctx, &nt_hash_blob)));
	}
	if (lm_hash_p) {
		DATA_BLOB lm_hash_blob = data_blob_const(lm_hash_p, 16);
		DEBUG(100,("ACCOUNT [%s\\%-25s] LMHASH %s\n", samsync_state->domain_name[0], username, data_blob_hex_string(mem_ctx, &lm_hash_blob)));
	}

	nt_status = test_SamLogon(samsync_state->p_netlogon_wksta, mem_ctx, samsync_state->creds_netlogon_wksta, 
				  domain,
				  username, 
				  TEST_WKSTA_MACHINE_NAME,
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
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_PASSWORD_EXPIRED)) {
		if (q.out.info->info21.acct_flags & ACB_PW_EXPIRED) {
			return True;
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD)) {
		if (!lm_hash_p && !nt_hash_p) {
			return True;
		}
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_PASSWORD_MUST_CHANGE)) {
		/* We would need to know the server's current time to test this properly */
		return True;
	} else if (NT_STATUS_IS_OK(nt_status)) {
		TEST_INT_EQUAL(user->rid, info3->base.rid);
		TEST_INT_EQUAL(user->primary_gid, info3->base.primary_gid);
		/* this is 0x0 from NT4 sp6 */
		if (info3->base.acct_flags) {
			TEST_INT_EQUAL(user->acct_flags, info3->base.acct_flags);
		}
		/* this is NULL from NT4 sp6 */
		if (info3->base.account_name.string) {
			TEST_STRING_EQUAL(user->account_name, info3->base.account_name);
		}
		/* this is NULL from Win2k3 */
		if (info3->base.full_name.string) {
			TEST_STRING_EQUAL(user->full_name, info3->base.full_name);
		}
		TEST_STRING_EQUAL(user->logon_script, info3->base.logon_script);
		TEST_STRING_EQUAL(user->profile_path, info3->base.profile_path);
		TEST_STRING_EQUAL(user->home_directory, info3->base.home_directory);
		TEST_STRING_EQUAL(user->home_drive, info3->base.home_drive);
		TEST_STRING_EQUAL(user->logon_script, info3->base.logon_script);


		TEST_TIME_EQUAL(user->last_logon, info3->base.last_logon);
		TEST_TIME_EQUAL(user->acct_expiry, info3->base.acct_expiry);
		TEST_TIME_EQUAL(user->last_password_change, info3->base.last_password_change);
		TEST_TIME_EQUAL(q.out.info->info21.force_password_change, info3->base.force_password_change);

		/* Does the concept of a logoff time ever really
		 * exist? (not in any sensible way, according to the
		 * doco I read -- abartlet) */

		/* This copes with the two different versions of 0 I see */
		/* with NT4 sp6 we have the || case */
		if (!((user->last_logoff == 0) 
		      || (info3->base.last_logoff == 0x7fffffffffffffffLL))) {
			TEST_TIME_EQUAL(user->last_logoff, info3->base.last_logoff);
		}

		TEST_INT_EQUAL(getgroups.out.rids->count, info3->base.groups.count);
		if (getgroups.out.rids->count == info3->base.groups.count) {
			int i, j;
			int count = getgroups.out.rids->count;
			BOOL *matched = talloc_zero_array(mem_ctx, BOOL, getgroups.out.rids->count);
				
			for (i = 0; i < count; i++) {
				for (j = 0; j < count; j++) {
					if ((getgroups.out.rids->rids[i].rid == 
					     info3->base.groups.rids[j].rid)
					    && (getgroups.out.rids->rids[i].attributes == 
						info3->base.groups.rids[j].attributes)) {
							matched[i] = True;
						}
				}
			}

			for (i = 0; i < getgroups.out.rids->count; i++) {
				if (matched[i] == False) {
					ret = False;
					printf("Could not find group RID %u found in getgroups in NETLOGON reply\n",
					       getgroups.out.rids->rids[i].rid); 
				}
			}
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
	uint32_t rid = delta->delta_id_union.rid;
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
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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
	uint32_t rid = delta->delta_id_union.rid;
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
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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
	struct samsync_secret *new = talloc(samsync_state, struct samsync_secret);
	struct samsync_secret *old = talloc(mem_ctx, struct samsync_secret);
	struct lsa_QuerySecret q;
	struct lsa_OpenSecret o;
	struct policy_handle sec_handle;
	struct lsa_DATA_BUF_PTR bufp1;
	struct lsa_DATA_BUF_PTR bufp2;
	NTTIME new_mtime;
	NTTIME old_mtime;
	BOOL ret = True;
	DATA_BLOB lsa_blob1, lsa_blob_out, session_key;
	NTSTATUS status;

	creds_arcfour_crypt(samsync_state->creds, secret->current_cipher.cipher_data, 
			    secret->current_cipher.maxlen); 

	creds_arcfour_crypt(samsync_state->creds, secret->old_cipher.cipher_data, 
			    secret->old_cipher.maxlen); 

	new->name = talloc_reference(new, name);
	new->secret = data_blob_talloc(new, secret->current_cipher.cipher_data, secret->current_cipher.maxlen);
	new->mtime = secret->current_cipher_set_time;

	new = talloc_reference(samsync_state, new);
	DLIST_ADD(samsync_state->secrets, new);

	old->name = talloc_reference(old, name);
	old->secret = data_blob_const(secret->old_cipher.cipher_data, secret->old_cipher.maxlen);
	old->mtime = secret->old_cipher_set_time;

	o.in.handle = samsync_state->lsa_handle;
	o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	o.in.name.string = name;
	o.out.sec_handle = &sec_handle;

	status = dcerpc_lsa_OpenSecret(samsync_state->p_lsa, mem_ctx, &o);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenSecret failed - %s\n", nt_errstr(status));
		return False;
	}

/*
  We would like to do this, but it is NOT_SUPPORTED on win2k3
  TEST_SEC_DESC_EQUAL(secret->sdbuf, lsa, &sec_handle);
*/
	status = dcerpc_fetch_session_key(samsync_state->p_lsa, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_fetch_session_key failed - %s\n", nt_errstr(status));
		return False;
	}


	ZERO_STRUCT(new_mtime);
	ZERO_STRUCT(old_mtime);

	/* fetch the secret back again */
	q.in.sec_handle = &sec_handle;
	q.in.new_val = &bufp1;
	q.in.new_mtime = &new_mtime;
	q.in.old_val = &bufp2;
	q.in.old_mtime = &old_mtime;

	bufp1.buf = NULL;
	bufp2.buf = NULL;

	status = dcerpc_lsa_QuerySecret(samsync_state->p_lsa, mem_ctx, &q);
	if (NT_STATUS_EQUAL(NT_STATUS_ACCESS_DENIED, status)) {
		/* some things are just off limits */
		return True;
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecret failed - %s\n", nt_errstr(status));
		return False;
	}

	if (q.out.old_val->buf == NULL) {
		/* probably just not available due to ACLs */
	} else {
		lsa_blob1.data = q.out.old_val->buf->data;
		lsa_blob1.length = q.out.old_val->buf->length;

		status = sess_decrypt_blob(mem_ctx, &lsa_blob1, &session_key, &lsa_blob_out);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Failed to decrypt secrets OLD blob: %s\n", nt_errstr(status));
			return False;
		}

		if (!q.out.old_mtime) {
			printf("OLD mtime not available on LSA for secret %s\n", old->name);
			ret = False;
		}
		if (old->mtime != *q.out.old_mtime) {
			printf("OLD mtime on secret %s does not match between SAMSYNC (%s) and LSA (%s)\n", 
			       old->name, nt_time_string(mem_ctx, old->mtime), 
			       nt_time_string(mem_ctx, *q.out.old_mtime)); 
			ret = False;
		}

		if (old->secret.length != lsa_blob_out.length) {
			printf("Returned secret %s doesn't match: %d != %d\n",
			       old->name, (int)old->secret.length, (int)lsa_blob_out.length);
			ret = False;
		} else if (memcmp(lsa_blob_out.data, 
			   old->secret.data, old->secret.length) != 0) {
			printf("Returned secret %s doesn't match: \n",
			       old->name);
			DEBUG(1, ("SamSync Secret:\n"));
			dump_data(1, old->secret.data, old->secret.length);
			DEBUG(1, ("LSA Secret:\n"));
			dump_data(1, lsa_blob_out.data, lsa_blob_out.length);
			ret = False;
		}

	}

	if (q.out.new_val->buf == NULL) {
		/* probably just not available due to ACLs */
	} else {
		lsa_blob1.data = q.out.new_val->buf->data;
		lsa_blob1.length = q.out.new_val->buf->length;

		status = sess_decrypt_blob(mem_ctx, &lsa_blob1, &session_key, &lsa_blob_out);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Failed to decrypt secrets OLD blob\n");
			return False;
		}
		
		if (!q.out.new_mtime) {
			printf("NEW mtime not available on LSA for secret %s\n", new->name);
			ret = False;
		}
		if (new->mtime != *q.out.new_mtime) {
			printf("NEW mtime on secret %s does not match between SAMSYNC (%s) and LSA (%s)\n", 
			       new->name, nt_time_string(mem_ctx, new->mtime), 
			       nt_time_string(mem_ctx, *q.out.new_mtime)); 
			ret = False;
		}

		if (new->secret.length != lsa_blob_out.length) {
			printf("Returned secret %s doesn't match: %d != %d\n",
			       new->name, (int)new->secret.length, (int)lsa_blob_out.length);
			ret = False;
		} else if (memcmp(lsa_blob_out.data, 
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

	struct samsync_trusted_domain *new = talloc(samsync_state, struct samsync_trusted_domain);
	struct lsa_OpenTrustedDomain t;
	struct policy_handle trustdom_handle;
	struct lsa_QueryTrustedDomainInfo q;
	union lsa_TrustedDomainInfo *info[9];
	int levels [] = {1, 3, 8};
	int i;

	new->name = talloc_reference(new, trusted_domain->domain_name.string);
	new->sid = talloc_reference(new, dom_sid);

	t.in.handle = samsync_state->lsa_handle;
	t.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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
		status = dcerpc_lsa_QueryTrustedDomainInfo(samsync_state->p_lsa, mem_ctx, &q);
		if (!NT_STATUS_IS_OK(status)) {
			if (q.in.level == 8 && NT_STATUS_EQUAL(status,NT_STATUS_INVALID_PARAMETER)) {
				info[levels[i]] = NULL;
				continue;
			}
			printf("QueryInfoTrustedDomain level %d failed - %s\n", 
			       levels[i], nt_errstr(status));
			return False;
		}
		info[levels[i]]  = q.out.info;
	}

	if (info[8]) {
		TEST_SID_EQUAL(info[8]->full_info.info_ex.sid, dom_sid);
		TEST_STRING_EQUAL(info[8]->full_info.info_ex.netbios_name, trusted_domain->domain_name);
	}
	TEST_STRING_EQUAL(info[1]->name.netbios_name, trusted_domain->domain_name);
	TEST_INT_EQUAL(info[3]->posix_offset.posix_offset, trusted_domain->posix_offset);
/*
  We would like to do this, but it is NOT_SUPPORTED on win2k3
	TEST_SEC_DESC_EQUAL(trusted_domain->sdbuf, lsa, &trustdom_handle);
*/
	new = talloc_reference(samsync_state, new);
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
	a.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	a.in.sid = dom_sid;
	a.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_OpenAccount(samsync_state->p_lsa, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenTrustedDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	TEST_SEC_DESC_EQUAL(account->sdbuf, lsa, &acct_handle);

	found_priv_in_lsa = talloc_zero_array(mem_ctx, BOOL, account->privilege_entries);

	e.in.handle = &acct_handle;

	status = dcerpc_lsa_EnumPrivsAccount(samsync_state->p_lsa, mem_ctx, &e);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivsAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if ((account->privilege_entries && !e.out.privs)) {
		printf("Account %s has privileges in SamSync, but not LSA\n",
		       dom_sid_string(mem_ctx, dom_sid));
		return False;
	}

	if (!account->privilege_entries && e.out.privs && e.out.privs->count) {
		printf("Account %s has privileges in LSA, but not SamSync\n",
		       dom_sid_string(mem_ctx, dom_sid));
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
	TALLOC_CTX *loop_ctx, *delta_ctx, *trustdom_ctx;
	struct netr_DatabaseSync r;
	const enum netr_SamDatabaseID database_ids[] = {SAM_DATABASE_DOMAIN, SAM_DATABASE_BUILTIN, SAM_DATABASE_PRIVS}; 
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
			loop_ctx = talloc_named(mem_ctx, 0, "DatabaseSync loop context");
			creds_client_authenticator(samsync_state->creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync(samsync_state->p, loop_ctx, &r);
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
				delta_ctx = talloc_named(loop_ctx, 0, "DatabaseSync delta context");
				switch (r.out.delta_enum_array->delta_enum[d].delta_type) {
				case NETR_DELTA_DOMAIN:
					if (!samsync_handle_domain(delta_ctx, samsync_state, 
								   r.in.database_id, &r.out.delta_enum_array->delta_enum[d])) {
						printf("Failed to handle DELTA_DOMAIN\n");
						ret = False;
					}
					break;
				case NETR_DELTA_GROUP:
					if (!samsync_handle_group(delta_ctx, samsync_state, 
								  r.in.database_id, &r.out.delta_enum_array->delta_enum[d])) {
						printf("Failed to handle DELTA_USER\n");
						ret = False;
					}
					break;
				case NETR_DELTA_USER:
					if (!samsync_handle_user(delta_ctx, samsync_state, 
								 r.in.database_id, &r.out.delta_enum_array->delta_enum[d])) {
						printf("Failed to handle DELTA_USER\n");
						ret = False;
					}
					break;
				case NETR_DELTA_ALIAS:
					if (!samsync_handle_alias(delta_ctx, samsync_state, 
								  r.in.database_id, &r.out.delta_enum_array->delta_enum[d])) {
						printf("Failed to handle DELTA_ALIAS\n");
						ret = False;
					}
					break;
				case NETR_DELTA_POLICY:
					if (!samsync_handle_policy(delta_ctx, samsync_state, 
								   r.in.database_id, &r.out.delta_enum_array->delta_enum[d])) {
						printf("Failed to handle DELTA_POLICY\n");
						ret = False;
					}
					break;
				case NETR_DELTA_TRUSTED_DOMAIN:
					if (!samsync_handle_trusted_domain(delta_ctx, samsync_state, 
									   r.in.database_id, &r.out.delta_enum_array->delta_enum[d])) {
						printf("Failed to handle DELTA_TRUSTED_DOMAIN\n");
						ret = False;
					}
					break;
				case NETR_DELTA_ACCOUNT:
					if (!samsync_handle_account(delta_ctx, samsync_state, 
								    r.in.database_id, &r.out.delta_enum_array->delta_enum[d])) {
						printf("Failed to handle DELTA_ACCOUNT\n");
						ret = False;
					}
					break;
				case NETR_DELTA_SECRET:
					if (!samsync_handle_secret(delta_ctx, samsync_state, 
								   r.in.database_id, &r.out.delta_enum_array->delta_enum[d])) {
						printf("Failed to handle DELTA_SECRET\n");
						ret = False;
					}
					break;
				case NETR_DELTA_GROUP_MEMBER:
				case NETR_DELTA_ALIAS_MEMBER:
					/* These are harder to cross-check, and we expect them */
					break;
				case NETR_DELTA_DELETE_GROUP:
				case NETR_DELTA_RENAME_GROUP:
				case NETR_DELTA_DELETE_USER:
				case NETR_DELTA_RENAME_USER:
				case NETR_DELTA_DELETE_ALIAS:
				case NETR_DELTA_RENAME_ALIAS:
				case NETR_DELTA_DELETE_TRUST:
				case NETR_DELTA_DELETE_ACCOUNT:
				case NETR_DELTA_DELETE_SECRET:
				case NETR_DELTA_DELETE_GROUP2:
				case NETR_DELTA_DELETE_USER2:
				case NETR_DELTA_MODIFY_COUNT:
				default:
					printf("Uxpected delta type %d\n", r.out.delta_enum_array->delta_enum[d].delta_type);
					ret = False;
					break;
				}
				talloc_free(delta_ctx);
			}
			talloc_free(loop_ctx);
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
		
	}

	domain = samsync_state->domain_name[SAM_DATABASE_DOMAIN];
	if (!domain) {
		printf("Never got a DOMAIN object in samsync!\n");
		return False;
	}

	trustdom_ctx = talloc_named(mem_ctx, 0, "test_DatabaseSync Trusted domains context");
	
	username = talloc_asprintf(trustdom_ctx, "%s$", domain);
	for (t=samsync_state->trusted_domains; t; t=t->next) {
		char *secret_name = talloc_asprintf(trustdom_ctx, "G$$%s", t->name);
		for (s=samsync_state->secrets; s; s=s->next) {
			if (strcasecmp_m(s->name, secret_name) == 0) {
				NTSTATUS nt_status;
				struct samr_Password nt_hash;
				mdfour(nt_hash.hash, s->secret.data, s->secret.length);
				
				printf("Checking password for %s\\%s\n", t->name, username);
				nt_status = test_SamLogon(samsync_state->p_netlogon_wksta, trustdom_ctx, samsync_state->creds_netlogon_wksta, 
							  t->name,
							  username, 
							  TEST_WKSTA_MACHINE_NAME,
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
				nt_status = test_SamLogon(samsync_state->p_netlogon_wksta, trustdom_ctx, samsync_state->creds_netlogon_wksta, 
							  t->name,
							  username, 
							  TEST_WKSTA_MACHINE_NAME,
							  NULL,
							  &nt_hash,
							  NULL);
				
				if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD)) {
					printf("Verifiction of trust password to %s: should have failed (wrong password), instead: %s\n", 
					       t->name, nt_errstr(nt_status));
					ret = False;
				}
				
				break;
			}
		}
	}
	talloc_free(trustdom_ctx);
	return ret;
}


/*
  try a netlogon DatabaseDeltas
*/
static BOOL test_DatabaseDeltas(struct samsync_state *samsync_state, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	TALLOC_CTX *loop_ctx;
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

		/* this shows that the bdc doesn't need to do a single call for
		 * each seqnumber, and the pdc doesn't need to know about old values
		 * -- metze
		 */
		r.in.sequence_num -= 10;


		printf("Testing DatabaseDeltas of id %d at %llu\n", 
		       r.in.database_id, (long long)r.in.sequence_num);

		do {
			loop_ctx = talloc_named(mem_ctx, 0, "test_DatabaseDeltas loop context");
			creds_client_authenticator(samsync_state->creds, &r.in.credential);

			status = dcerpc_netr_DatabaseDeltas(samsync_state->p, loop_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES) &&
			    !NT_STATUS_EQUAL(status, NT_STATUS_SYNCHRONIZATION_REQUIRED)) {
				printf("DatabaseDeltas - %s\n", nt_errstr(status));
				ret = False;
			}

			if (!creds_client_check(samsync_state->creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sequence_num++;
			talloc_free(loop_ctx);
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
	TALLOC_CTX *loop_ctx;
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
			loop_ctx = talloc_named(mem_ctx, 0, "test_DatabaseSync2 loop context");
			creds_client_authenticator(creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync2(p, loop_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseSync2 - %s\n", nt_errstr(status));
				ret = False;
			}

			if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sync_context = r.out.sync_context;
			talloc_free(loop_ctx);
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
	}

	return ret;
}



BOOL torture_rpc_samsync(struct torture_context *torture)
{
        NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct test_join *join_ctx;
	struct test_join *join_ctx2;
	struct test_join *user_ctx;
	const char *machine_password;
	const char *wksta_machine_password;
	const char *binding = torture_setting_string(torture, "binding", NULL);
	struct dcerpc_binding *b;
	struct dcerpc_binding *b_netlogon_wksta;
	struct samr_Connect c;
	struct samr_SetDomainInfo s;
	struct policy_handle *domain_policy;

	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	struct cli_credentials *credentials;
	struct cli_credentials *credentials_wksta;

	struct samsync_state *samsync_state;

	char *test_machine_account;

	char *test_wksta_machine_account;

	mem_ctx = talloc_init("torture_rpc_netlogon");
	
	test_machine_account = talloc_asprintf(mem_ctx, "%s$", TEST_MACHINE_NAME);
	join_ctx = torture_create_testuser(torture, test_machine_account, lp_workgroup(), ACB_SVRTRUST, 
					   &machine_password);
	if (!join_ctx) {
		talloc_free(mem_ctx);
		printf("Failed to join as BDC\n");
		return False;
	}
	
	test_wksta_machine_account = talloc_asprintf(mem_ctx, "%s$", TEST_WKSTA_MACHINE_NAME);
	join_ctx2 = torture_create_testuser(torture, test_wksta_machine_account, lp_workgroup(), ACB_WSTRUST, 
					    &wksta_machine_password);
	if (!join_ctx2) {
		talloc_free(mem_ctx);
		printf("Failed to join as member\n");
		return False;
	}
	
	user_ctx = torture_create_testuser(torture, TEST_USER_NAME,
					   lp_workgroup(),
					   ACB_NORMAL, NULL);
	if (!user_ctx) {
		talloc_free(mem_ctx);
		printf("Failed to create test account\n");
		return False;
	}

	samsync_state = talloc_zero(mem_ctx, struct samsync_state);

	samsync_state->p_samr = torture_join_samr_pipe(join_ctx);
	samsync_state->connect_handle = talloc_zero(samsync_state, struct policy_handle);
	samsync_state->lsa_handle = talloc_zero(samsync_state, struct policy_handle);
	c.in.system_name = NULL;
	c.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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
	s.in.info = talloc(mem_ctx, union samr_DomainInfo);
	
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
	

	status = torture_rpc_connection(torture,
					&samsync_state->p_lsa, 
					&ndr_table_lsarpc);

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
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
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

	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= DCERPC_SCHANNEL | DCERPC_SIGN;

	credentials = cli_credentials_init(mem_ctx);

	cli_credentials_set_workstation(credentials, TEST_MACHINE_NAME, CRED_SPECIFIED);
	cli_credentials_set_domain(credentials, lp_workgroup(), CRED_SPECIFIED);
	cli_credentials_set_username(credentials, test_machine_account, CRED_SPECIFIED);
	cli_credentials_set_password(credentials, machine_password, CRED_SPECIFIED);
	cli_credentials_set_secure_channel_type(credentials,
						SEC_CHAN_BDC);

	status = dcerpc_pipe_connect_b(samsync_state,
				       &samsync_state->p, b, 
					   &ndr_table_netlogon,
				       credentials, NULL);
	
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect to server as a BDC: %s\n", nt_errstr(status));
		ret = False;
		goto failed;
	}

	status = dcerpc_schannel_creds(samsync_state->p->conn->security_state.generic_state, 
				       samsync_state, &samsync_state->creds);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}



	status = dcerpc_parse_binding(mem_ctx, binding, &b_netlogon_wksta);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		ret = False;
		goto failed;
	}

	b_netlogon_wksta->flags &= ~DCERPC_AUTH_OPTIONS;
	b_netlogon_wksta->flags |= DCERPC_SCHANNEL | DCERPC_SIGN;

	credentials_wksta = cli_credentials_init(mem_ctx);

	cli_credentials_set_workstation(credentials_wksta, TEST_WKSTA_MACHINE_NAME, CRED_SPECIFIED);
	cli_credentials_set_domain(credentials_wksta, lp_workgroup(), CRED_SPECIFIED);
	cli_credentials_set_username(credentials_wksta, test_wksta_machine_account, CRED_SPECIFIED);
	cli_credentials_set_password(credentials_wksta, wksta_machine_password, CRED_SPECIFIED);
	cli_credentials_set_secure_channel_type(credentials_wksta,
						SEC_CHAN_WKSTA);

	status = dcerpc_pipe_connect_b(samsync_state, 
				       &samsync_state->p_netlogon_wksta, 
				       b_netlogon_wksta, 
					   &ndr_table_netlogon,
				       credentials_wksta, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect to server as a Workstation: %s\n", nt_errstr(status));
		ret = False;
		goto failed;
	}

	status = dcerpc_schannel_creds(samsync_state->p_netlogon_wksta->conn->security_state.generic_state, 
				       samsync_state, &samsync_state->creds_netlogon_wksta);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to obtail schanel creds!\n");
		ret = False;
	}

	if (!test_DatabaseSync(samsync_state, mem_ctx)) {
		printf("DatabaseSync failed\n");
		ret = False;
	}

	if (!test_DatabaseDeltas(samsync_state, mem_ctx)) {
		printf("DatabaseDeltas failed\n");
		ret = False;
	}

	if (!test_DatabaseSync2(samsync_state->p, mem_ctx, samsync_state->creds)) {
		printf("DatabaseSync2 failed\n");
		ret = False;
	}
failed:

	torture_leave_domain(join_ctx);
	torture_leave_domain(join_ctx2);
	torture_leave_domain(user_ctx);

	talloc_free(mem_ctx);

	return ret;
}
