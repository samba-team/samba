/* 
   Unix SMB/CIFS implementation.
   test suite for lsa rpc operations

   Copyright (C) Andrew Tridgell 2003
   
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

static void init_lsa_Name(struct lsa_Name *name, const char *s)
{
	name->name = s;
}

static BOOL test_OpenPolicy(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	NTSTATUS status;
	uint16_t system_name = '\\';

	printf("\ntesting OpenPolicy\n");

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

	r.in.system_name = &system_name;
	r.in.attr = &attr;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_OpenPolicy2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	NTSTATUS status;

	printf("\ntesting OpenPolicy2\n");

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
	r.out.handle = handle;

	status = dcerpc_lsa_OpenPolicy2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy2 failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_LookupNames(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle,
			    struct lsa_TransNameArray *tnames)
{
	struct lsa_LookupNames r;
	struct lsa_TransSidArray sids;
	struct lsa_Name *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc(mem_ctx, tnames->count * sizeof(names[0]));
	for (i=0;i<tnames->count;i++) {
		init_lsa_Name(&names[i], tnames->names[i].name.name);
	}

	r.in.handle = handle;
	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.out.count = &count;
	r.out.sids = &sids;

	status = dcerpc_lsa_LookupNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	return True;
}


static BOOL test_LookupSids(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids r;
	struct lsa_TransNameArray names;
	uint32_t count = sids->num_sids;
	NTSTATUS status;

	printf("\nTesting LookupSids\n");

	names.count = 0;
	names.names = NULL;

	r.in.handle = handle;
	r.in.sids = sids;
	r.in.names = &names;
	r.in.level = 1;
	r.in.count = &count;
	r.out.count = &count;
	r.out.names = &names;

	status = dcerpc_lsa_LookupSids(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupSids failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	if (!test_LookupNames(p, mem_ctx, handle, &names)) {
		return False;
	}

	return True;
}

static BOOL test_many_LookupSids(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	struct lsa_LookupSids r;
	struct lsa_TransNameArray names;
	uint32_t count;
	NTSTATUS status;
	struct lsa_SidArray sids;
	int i;

	printf("\nTesting LookupSids with lots of SIDs\n");

	names.count = 0;
	names.names = NULL;

	sids.num_sids = 1000;

	sids.sids = talloc_array_p(mem_ctx, struct lsa_SidPtr, sids.num_sids);

	for (i=0; i<sids.num_sids; i++) {
		const char *sidstr = "S-1-5-32-545";
		sids.sids[i].sid = dom_sid_parse_talloc(mem_ctx, sidstr);
	}

	count = sids.num_sids;

	r.in.handle = handle;
	r.in.sids = &sids;
	r.in.names = &names;
	r.in.level = 1;
	r.in.count = &names.count;
	r.out.count = &count;
	r.out.names = &names;

	status = dcerpc_lsa_LookupSids(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupSids failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	if (!test_LookupNames(p, mem_ctx, handle, &names)) {
		return False;
	}

	return True;
}

static BOOL test_LookupPrivName(struct dcerpc_pipe *p, 
				TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle,
				struct lsa_LUID *luid)
{
	NTSTATUS status;
	struct lsa_LookupPrivName r;

	r.in.handle = handle;
	r.in.luid = luid;

	status = dcerpc_lsa_LookupPrivName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("\nLookupPrivName failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_EnumPrivsAccount(struct dcerpc_pipe *p, 
				  TALLOC_CTX *mem_ctx, 				  
				  struct policy_handle *handle,
				  struct policy_handle *acct_handle)
{
	NTSTATUS status;
	struct lsa_EnumPrivsAccount r;

	printf("Testing EnumPrivsAccount\n");

	r.in.handle = acct_handle;

	status = dcerpc_lsa_EnumPrivsAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivsAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.privs) {
		int i;
		for (i=0;i<r.out.privs->count;i++) {
			test_LookupPrivName(p, mem_ctx, handle, 
					    &r.out.privs->set[i].luid);
		}
	}

	return True;
}

static BOOL test_Delete(struct dcerpc_pipe *p, 
		       TALLOC_CTX *mem_ctx, 
		       struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_Delete r;

	printf("\ntesting Delete\n");

	r.in.handle = handle;
	status = dcerpc_lsa_Delete(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Delete failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	return True;
}


static BOOL test_CreateAccount(struct dcerpc_pipe *p, 
			       TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_CreateAccount r;
	struct dom_sid2 *newsid;
	struct policy_handle acct_handle;

	newsid = dom_sid_parse_talloc(mem_ctx, "S-1-5-12349876-4321-2854");

	printf("Testing CreateAccount\n");

	r.in.handle = handle;
	r.in.sid = newsid;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_CreateAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_Delete(p, mem_ctx, &acct_handle)) {
		return False;
	}

	return True;
}


static BOOL test_CreateTrustedDomain(struct dcerpc_pipe *p, 
				     TALLOC_CTX *mem_ctx, 
				     struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_CreateTrustedDomain r;
	struct lsa_TrustInformation trustinfo;
	struct dom_sid *domsid;
	struct policy_handle dom_handle;

	printf("Testing CreateTrustedDomain\n");

	domsid = dom_sid_parse_talloc(mem_ctx, "S-1-5-21-97398-379795-12345");

	trustinfo.sid = domsid;
	init_lsa_Name(&trustinfo.name, "torturedomain");

	r.in.handle = handle;
	r.in.info = &trustinfo;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.dom_handle = &dom_handle;

	status = dcerpc_lsa_CreateTrustedDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateTrustedDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_Delete(p, mem_ctx, &dom_handle)) {
		return False;
	}

	return True;
}

static BOOL test_CreateSecret(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_CreateSecret r;
	struct lsa_OpenSecret r2;
	struct lsa_SetSecret r3;
	struct lsa_QuerySecret r4;
	struct policy_handle sec_handle, sec_handle2;
	struct lsa_Delete d;
	struct lsa_DATA_BUF buf1;
	struct lsa_DATA_BUF_PTR bufp1;
	DATA_BLOB enc_key;
	BOOL ret = True;
	DATA_BLOB session_key;
	NTTIME old_mtime, new_mtime;
	DATA_BLOB blob1, blob2;
	const char *secret1 = "abcdef12345699qwerty";
	char *secret2;
	char *secname;

	printf("Testing CreateSecret\n");

	asprintf(&secname, "torturesecret-%u", (uint_t)random());

	init_lsa_Name(&r.in.name, secname);

	r.in.handle = handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.sec_handle = &sec_handle;

	status = dcerpc_lsa_CreateSecret(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateSecret failed - %s\n", nt_errstr(status));
		return False;
	}

	r2.in.handle = handle;
	r2.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r2.in.name = r.in.name;
	r2.out.sec_handle = &sec_handle2;

	printf("Testing OpenSecret\n");

	status = dcerpc_lsa_OpenSecret(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenSecret failed - %s\n", nt_errstr(status));
		ret = False;
	}

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_fetch_session_key failed - %s\n", nt_errstr(status));
		ret = False;
	}

	enc_key = sess_encrypt_string(secret1, &session_key);

	r3.in.handle = &sec_handle;
	r3.in.new_val = &buf1;
	r3.in.old_val = NULL;
	r3.in.new_val->data = enc_key.data;
	r3.in.new_val->length = enc_key.length;
	r3.in.new_val->size = enc_key.length;

	printf("Testing SetSecret\n");

	status = dcerpc_lsa_SetSecret(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetSecret failed - %s\n", nt_errstr(status));
		ret = False;
	}

	data_blob_free(&enc_key);

	ZERO_STRUCT(new_mtime);
	ZERO_STRUCT(old_mtime);

	/* fetch the secret back again */
	r4.in.handle = &sec_handle;
	r4.in.new_val = &bufp1;
	r4.in.new_mtime = &new_mtime;
	r4.in.old_val = NULL;
	r4.in.old_mtime = NULL;

	bufp1.buf = NULL;

	status = dcerpc_lsa_QuerySecret(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecret failed - %s\n", nt_errstr(status));
		ret = False;
	}

	blob1.data = r4.out.new_val->buf->data;
	blob1.length = r4.out.new_val->buf->length;

	blob2 = data_blob(NULL, blob1.length);

	secret2 = sess_decrypt_string(&blob1, &session_key);

	printf("returned secret '%s'\n", secret2);

	if (strcmp(secret1, secret2) != 0) {
		printf("Returned secret doesn't match\n");
		ret = False;
	}

	if (!test_Delete(p, mem_ctx, &sec_handle)) {
		ret = False;
	}

	d.in.handle = &sec_handle2;
	status = dcerpc_lsa_Delete(p, mem_ctx, &d);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		printf("Second delete expected INVALID_HANDLE - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_EnumAccountRights(struct dcerpc_pipe *p, 
				   TALLOC_CTX *mem_ctx, 
				   struct policy_handle *acct_handle,
				   struct dom_sid *sid)
{
	NTSTATUS status;
	struct lsa_EnumAccountRights r;
	struct lsa_RightSet rights;

	printf("Testing EnumAccountRights\n");

	r.in.handle = acct_handle;
	r.in.sid = sid;
	r.out.rights = &rights;

	status = dcerpc_lsa_EnumAccountRights(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccountRights failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_QuerySecObj(struct dcerpc_pipe *p, 
			     TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle,
			     struct policy_handle *acct_handle)
{
	NTSTATUS status;
	struct lsa_QuerySecObj r;

	printf("Testing QuerySecObj\n");

	r.in.handle = acct_handle;
	r.in.sec_info = 7;

	status = dcerpc_lsa_QuerySecObj(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecObj failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_OpenAccount(struct dcerpc_pipe *p, 
			     TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle,
			     struct dom_sid *sid)
{
	NTSTATUS status;
	struct lsa_OpenAccount r;
	struct policy_handle acct_handle;

	printf("Testing OpenAccount\n");

	r.in.handle = handle;
	r.in.sid = sid;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_OpenAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_EnumPrivsAccount(p, mem_ctx, handle, &acct_handle)) {
		return False;
	}

	if (!test_QuerySecObj(p, mem_ctx, handle, &acct_handle)) {
		return False;
	}

	return True;
}

static BOOL test_EnumAccounts(struct dcerpc_pipe *p, 
			  TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_EnumAccounts r;
	struct lsa_SidArray sids1, sids2;
	uint32_t resume_handle = 0;
	int i;

	printf("\ntesting EnumAccounts\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.num_entries = 100;
	r.out.resume_handle = &resume_handle;
	r.out.sids = &sids1;

	resume_handle = 0;
	status = dcerpc_lsa_EnumAccounts(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccounts failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_LookupSids(p, mem_ctx, handle, &sids1)) {
		return False;
	}

	printf("testing all accounts\n");
	for (i=0;i<sids1.num_sids;i++) {
		test_OpenAccount(p, mem_ctx, handle, sids1.sids[i].sid);
		test_EnumAccountRights(p, mem_ctx, handle, sids1.sids[i].sid);
	}
	printf("\n");

	if (sids1.num_sids < 3) {
		return True;
	}
	
	printf("trying EnumAccounts partial listing (asking for 1 at 2)\n");
	resume_handle = 2;
	r.in.num_entries = 1;
	r.out.sids = &sids2;

	status = dcerpc_lsa_EnumAccounts(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccounts failed - %s\n", nt_errstr(status));
		return False;
	}

	if (sids2.num_sids != 1) {
		printf("Returned wrong number of entries (%d)\n", sids2.num_sids);
		return False;
	}

	return True;
}


static BOOL test_EnumPrivs(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_EnumPrivs r;
	struct lsa_PrivArray privs1;
	uint32_t resume_handle = 0;

	printf("\ntesting EnumPrivs\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_count = 1000;
	r.out.resume_handle = &resume_handle;
	r.out.privs = &privs1;

	resume_handle = 0;
	status = dcerpc_lsa_EnumPrivs(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivs failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_EnumTrustDom(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	struct lsa_EnumTrustDom r;
	NTSTATUS status;
	uint32_t resume_handle = 0;
	struct lsa_DomainList domains;

	printf("\nTesting EnumTrustDom\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.num_entries = 1000;
	r.out.domains = &domains;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_lsa_EnumTrustDom(p, mem_ctx, &r);

	/* NO_MORE_ENTRIES is allowed */
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		return True;
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumTrustDom failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_QueryInfoPolicy(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	struct lsa_QueryInfoPolicy r;
	NTSTATUS status;
	int i;
	BOOL ret = True;
	printf("\nTesting QueryInfoPolicy\n");

	for (i=1;i<13;i++) {
		r.in.handle = handle;
		r.in.level = i;

		printf("\ntrying QueryInfoPolicy level %d\n", i);

		status = dcerpc_lsa_QueryInfoPolicy(p, mem_ctx, &r);

		if ((i == 9 || i == 10 || i == 11) &&
		    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			printf("server failed level %u (OK)\n", i);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryInfoPolicy failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
	}

	return ret;
}

static BOOL test_QueryInfoPolicy2(struct dcerpc_pipe *p, 
				  TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	struct lsa_QueryInfoPolicy2 r;
	NTSTATUS status;
	int i;
	BOOL ret = True;
	printf("\nTesting QueryInfoPolicy2\n");

	for (i=1;i<13;i++) {
		r.in.handle = handle;
		r.in.level = i;

		printf("\ntrying QueryInfoPolicy2 level %d\n", i);

		status = dcerpc_lsa_QueryInfoPolicy2(p, mem_ctx, &r);

		if ((i == 9 || i == 10 || i == 11) &&
		    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			printf("server failed level %u (OK)\n", i);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryInfoPolicy2 failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
	}

	return ret;
}

static BOOL test_Close(struct dcerpc_pipe *p, 
		       TALLOC_CTX *mem_ctx, 
		       struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_Close r;
	struct policy_handle handle2;

	printf("\ntesting Close\n");

	r.in.handle = handle;
	r.out.handle = &handle2;

	status = dcerpc_lsa_Close(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_lsa_Close(p, mem_ctx, &r);
	/* its really a fault - we need a status code for rpc fault */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	return True;
}

BOOL torture_rpc_lsa(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle handle;

	mem_ctx = talloc_init("torture_rpc_lsa");

	status = torture_rpc_connection(&p, 
					DCERPC_LSARPC_NAME, 
					DCERPC_LSARPC_UUID, 
					DCERPC_LSARPC_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if (!test_OpenPolicy(p, mem_ctx)) {
		ret = False;
	}

	if (!test_OpenPolicy2(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_many_LookupSids(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_CreateAccount(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_CreateSecret(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_CreateTrustedDomain(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumAccounts(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumPrivs(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumTrustDom(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_QueryInfoPolicy(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_QueryInfoPolicy2(p, mem_ctx, &handle)) {
		ret = False;
	}
	
#if 0
	if (!test_Delete(p, mem_ctx, &handle)) {
		ret = False;
	}
#endif
	
	if (!test_Close(p, mem_ctx, &handle)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
