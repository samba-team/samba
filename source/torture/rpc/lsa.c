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
  this really shouldn't be here ....
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


static BOOL test_EnumSids(struct dcerpc_pipe *p, 
			  TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct dom_sid **sids;
	uint32 num_entries = 100;
	int i;

	printf("\ntesting EnumSids\n");

	status = dcerpc_lsa_EnumSids(p, mem_ctx, handle, 0, &num_entries, &sids);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumSids failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("Got %d sids\n", num_entries);

	for (i=0;i<num_entries;i++) {
		printf("%s\n", lsa_sid_string_talloc(mem_ctx, sids[i]));
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
