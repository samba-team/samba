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

#define TEST_MACHINE_NAME "samsynctest"

/*
  try a netlogon SamLogon
*/
static NTSTATUS test_SamLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct creds_CredentialState *creds, 
			      const char *domain, const char *username,
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
	ninfo.identity_info.account_name.string = username;
	ninfo.identity_info.workstation.string = TEST_MACHINE_NAME;
	generate_random_buffer(ninfo.challenge, 
			       sizeof(ninfo.challenge));
	if (nt_hash) {
		ninfo.nt.length = 24;
		ninfo.nt.data = talloc(mem_ctx, 24);
		SMBOWFencrypt(nt_hash->hash, ninfo.challenge, ninfo.nt.data);
	}
	
	if (lm_hash) {
		ninfo.lm.length = 24;
		ninfo.lm.data = talloc(mem_ctx, 24);
		SMBOWFencrypt(lm_hash->hash, ninfo.challenge, ninfo.lm.data);
	}

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.workstation = TEST_MACHINE_NAME;
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

	*info3 = r.out.validation.sam3;

	return status;
}

struct samsync_state {
	uint64_t seq_num;
	char *domain_name;
};

static struct samsync_state *samsync_state;

static BOOL samsync_handle_domain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct creds_CredentialState *creds,
			   int database_id, struct netr_DELTA_ENUM *delta) 
{
	struct netr_DELTA_DOMAIN *domain = delta->delta_union.domain;

	samsync_state[database_id].seq_num = 
		domain->sequence_num;

	samsync_state[database_id].domain_name = 
		talloc_reference(samsync_state, domain->DomainName.string);

	printf("\tsequence_nums[%d/%s]=%llu\n",
	       database_id, samsync_state[database_id].domain_name,
	       samsync_state[database_id].seq_num);
	return True;
}

static BOOL samsync_handle_user(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct creds_CredentialState *creds,
			 int database_id, struct netr_DELTA_ENUM *delta) 
{
	uint32 rid = delta->delta_id_union.rid;
	struct netr_DELTA_USER *user = delta->delta_union.user;
	struct netr_SamInfo3 *info3;
	struct samr_Password lm_hash;
	struct samr_Password nt_hash;
	const char *domain = samsync_state[database_id].domain_name
		? samsync_state[database_id].domain_name
		: lp_workgroup();
	const char *username = user->account_name.string;


	NTSTATUS nt_status;

	if (user->lmpassword_present) {
		sam_rid_crypt(rid, user->lmpassword.hash, lm_hash.hash, 0);
	}
	if (user->ntpassword_present) {
		sam_rid_crypt(rid, user->ntpassword.hash, nt_hash.hash, 0);
	}

	if (!user->lmpassword_present && !user->lmpassword_present) {
		printf("NO password set for %s\n", 
		       user->account_name.string);
		return True;
	}

	nt_status = test_SamLogon(p, mem_ctx, creds, 
				  domain,
				  username, 
				  user->lmpassword_present ? &lm_hash : NULL,
				  user->ntpassword_present ? &nt_hash : NULL,
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
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_OK)) {
		if (user->acct_flags != info3->base.acct_flags) {
			printf("Account flags mismatch: %d != %d\n", 
			       user->acct_flags, info3->base.acct_flags);
			return False;
		}
		if (strcmp(user->full_name.string, info3->base.full_name.string) != 0) {
			printf("Full name mismatch: %s != %s\n", 
			       user->full_name.string, info3->base.full_name.string);
			return False;
		}
		return True;
	} else {
		printf("Could not validate password for user %s\\%s: %s\n",
		       domain, username, nt_errstr(nt_status));
		return False;
	} 
	return False;
}

/* we remember the sequence numbers so we can easily do a DatabaseDelta */
static uint64_t sequence_nums[3];

/*
  try a netlogon DatabaseSync
*/
static BOOL test_DatabaseSync(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_DatabaseSync r;
	const uint32_t database_ids[] = {SAM_DATABASE_DOMAIN, SAM_DATABASE_BUILTIN, SAM_DATABASE_PRIVS}; 
	int i, d;
	BOOL ret = True;
	
	samsync_state = talloc_zero_array_p(mem_ctx, struct samsync_state, 3);

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.sync_context = 0;
		r.in.database_id = database_ids[i];

		printf("Testing DatabaseSync of id %d\n", r.in.database_id);

		do {
			creds_client_authenticator(creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseSync - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sync_context = r.out.sync_context;

			for (d=0; d < r.out.delta_enum_array->num_deltas; d++) {
				switch (r.out.delta_enum_array->delta_enum[d].delta_type) {
				case NETR_DELTA_DOMAIN:
					ret &= samsync_handle_domain(p, mem_ctx, creds, 
								     r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				case NETR_DELTA_USER:
					ret &= samsync_handle_user(p, mem_ctx, creds, 
								   r.in.database_id, &r.out.delta_enum_array->delta_enum[d]);
					break;
				}
			}
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
	}

	return ret;
}


/*
  try a netlogon DatabaseDeltas
*/
static BOOL test_DatabaseDeltas(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_DatabaseDeltas r;
	const uint32_t database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.database_id = database_ids[i];
		r.in.sequence_num = sequence_nums[r.in.database_id];

		if (r.in.sequence_num == 0) continue;

		r.in.sequence_num -= 1;


		printf("Testing DatabaseDeltas of id %d at %llu\n", 
		       r.in.database_id, r.in.sequence_num);

		do {
			creds_client_authenticator(creds, &r.in.credential);

			status = dcerpc_netr_DatabaseDeltas(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseDeltas - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
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
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct test_join *join_ctx;
	const char *machine_password;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding b;
	struct creds_CredentialState *creds;

	mem_ctx = talloc_init("torture_rpc_netlogon");

	join_ctx = torture_join_domain(TEST_MACHINE_NAME, lp_workgroup(), ACB_SVRTRUST, 
				       &machine_password);
	if (!join_ctx) {
		printf("Failed to join as BDC\n");
		return False;
	}

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		return False;
	}

	b.flags &= ~DCERPC_AUTH_OPTIONS;
	b.flags |= DCERPC_SCHANNEL_BDC | DCERPC_SEAL | DCERPC_SCHANNEL_128;

	status = dcerpc_pipe_connect_b(&p, &b, 
				       DCERPC_NETLOGON_UUID,
				       DCERPC_NETLOGON_VERSION,
				       lp_workgroup(), 
				       TEST_MACHINE_NAME,
				       machine_password);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	status = dcerpc_schannel_creds(p->security_state.generic_state, mem_ctx, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if (!test_DatabaseSync(p, mem_ctx, creds)) {
		ret = False;
	}

	if (!test_DatabaseDeltas(p, mem_ctx, creds)) {
		ret = False;
	}

	if (!test_DatabaseSync2(p, mem_ctx, creds)) {
		ret = False;
	}
	talloc_destroy(mem_ctx);

	torture_rpc_close(p);

	torture_leave_domain(join_ctx);

	return ret;
}
