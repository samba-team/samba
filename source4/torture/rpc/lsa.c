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

/*
  these really shouldn't be here ....
*/
static char *lsa_sid_string_talloc(TALLOC_CTX *mem_ctx, struct dom_sid *sid)
{
	int i, ofs, maxlen;
	uint32 ia;
	char *ret;
	
	if (!sid) {
		return talloc_asprintf(mem_ctx, "(NULL SID)");
	}

	maxlen = sid->num_auths * 11 + 25;
	ret = talloc(mem_ctx, maxlen);
	if (!ret) return NULL;

	ia = (sid->id_auth[5]) +
		(sid->id_auth[4] << 8 ) +
		(sid->id_auth[3] << 16) +
		(sid->id_auth[2] << 24);

	ofs = snprintf(ret, maxlen, "S-%u-%lu", 
		       (unsigned int)sid->sid_rev_num, (unsigned long)ia);

	for (i = 0; i < sid->num_auths; i++) {
		ofs += snprintf(ret + ofs, maxlen - ofs, "-%lu", (unsigned long)sid->sub_auths[i]);
	}

	return ret;
}

static int dom_sid_compare(struct dom_sid *sid1, struct dom_sid *sid2)
{
	int i;

	if (sid1 == sid2) return 0;
	if (!sid1) return -1;
	if (!sid2) return 1;

	/* Compare most likely different rids, first: i.e start at end */
	if (sid1->num_auths != sid2->num_auths)
		return sid1->num_auths - sid2->num_auths;

	for (i = sid1->num_auths-1; i >= 0; --i)
		if (sid1->sub_auths[i] != sid2->sub_auths[i])
			return sid1->sub_auths[i] - sid2->sub_auths[i];

	if (sid1->sid_rev_num != sid2->sid_rev_num)
		return sid1->sid_rev_num - sid2->sid_rev_num;

	for (i = 0; i < 6; i++)
		if (sid1->id_auth[i] != sid2->id_auth[i])
			return sid1->id_auth[i] - sid2->id_auth[i];

	return 0;
}

static BOOL test_OpenPolicy(struct dcerpc_pipe *p)
{
	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_QosInfo qos;
	NTSTATUS status;

	printf("\ntesting OpenPolicy\n");

	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	status = dcerpc_lsa_OpenPolicy(p, 
				       "\\",
				       &attr,
				       SEC_RIGHTS_MAXIMUM_ALLOWED,
				       &handle);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_OpenPolicy2(struct dcerpc_pipe *p, struct policy_handle *handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	NTSTATUS status;

	printf("\ntesting OpenPolicy2\n");

	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	status = dcerpc_lsa_OpenPolicy2(p, 
					"\\",
					&attr,
					SEC_RIGHTS_MAXIMUM_ALLOWED,
					handle);
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
	uint32 count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames\n");

	sids.count = 0;
	sids.sids = NULL;

	names = talloc(mem_ctx, tnames->count * sizeof(names[0]));
	for (i=0;i<tnames->count;i++) {
		names[i].name_len = 2*strlen(tnames->names[i].name.name);
		names[i].name_size = 2*strlen(tnames->names[i].name.name);
		names[i].name = tnames->names[i].name.name;
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
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.domains) {
		printf("lookup gave %d domains (max_count=%d)\n", 
		       r.out.domains->count,
		       r.out.domains->max_count);
		for (i=0;i<r.out.domains->count;i++) {
			printf("name='%s' sid=%s\n", 
			       r.out.domains->domains[i].name.name,
			       lsa_sid_string_talloc(mem_ctx, r.out.domains->domains[i].sid));
		}
	}

	printf("lookup gave %d sids (sids.count=%d)\n", count, sids.count);
	for (i=0;i<sids.count;i++) {
		printf("sid_type=%d rid=%d sid_index=%d\n", 
		       sids.sids[i].sid_type,
		       sids.sids[i].rid,
		       sids.sids[i].sid_index);
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
	uint32 count = sids->num_sids;
	NTSTATUS status;
	int i;

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
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupSids failed - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.domains) {
		printf("lookup gave %d domains (max_count=%d)\n", 
		       r.out.domains->count,
		       r.out.domains->max_count);
		for (i=0;i<r.out.domains->count;i++) {
			printf("name='%s' sid=%s\n", 
			       r.out.domains->domains[i].name.name,
			       lsa_sid_string_talloc(mem_ctx, r.out.domains->domains[i].sid));
		}
	}

	printf("lookup gave %d names (names.count=%d)\n", count, names.count);
	for (i=0;i<names.count;i++) {
		printf("type=%d sid_index=%d name='%s'\n", 
		       names.names[i].sid_type,
		       names.names[i].sid_index,
		       names.names[i].name.name);
	}

	printf("\n");

	if (!test_LookupNames(p, mem_ctx, handle, &names)) {
		return False;
	}

	return True;
}

static BOOL test_EnumSids(struct dcerpc_pipe *p, 
			  TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_SidArray sids1, sids2;
	uint32 resume_handle;
	int i;

	printf("\ntesting EnumSids\n");

	resume_handle = 0;
	status = dcerpc_lsa_EnumSids(p, mem_ctx, handle, &resume_handle, 100, &sids1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumSids failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("Got %d sids resume_handle=%u\n", sids1.num_sids, resume_handle);

	for (i=0;i<sids1.num_sids;i++) {
		printf("%s\n", lsa_sid_string_talloc(mem_ctx, sids1.sids[i].sid));
	}

	if (!test_LookupSids(p, mem_ctx, handle, &sids1)) {
		return False;
	}
	
	if (sids1.num_sids < 3) {
		return True;
	}
	
	printf("trying EnumSids partial listing (asking for 1 at 2)\n");
	resume_handle = 2;
	status = dcerpc_lsa_EnumSids(p, mem_ctx, handle, &resume_handle, 1, &sids2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumSids failed - %s\n", nt_errstr(status));
		return False;
	}

	if (sids2.num_sids != 1) {
		printf("Returned wrong number of entries (%d)\n", sids2.num_sids);
		return False;
	}

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

	status = torture_rpc_connection(&p, "lsarpc");
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	if (!test_OpenPolicy(p)) {
		ret = False;
	}

	if (!test_OpenPolicy2(p, &handle)) {
		ret = False;
	}

	if (!test_EnumSids(p, mem_ctx, &handle)) {
		ret = False;
	}
	
        torture_rpc_close(p);

	return ret;
}
