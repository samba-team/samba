/* 
   Unix SMB/CIFS implementation.
   test suite for samr rpc operations

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003
   
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

#define TEST_USERNAME "samrtorturetest"
#define TEST_ALIASNAME "samrtorturetestalias"
#define TEST_MACHINENAME "samrtorturetestmach$"
#define TEST_DOMAINNAME "samrtorturetestdom$"


static BOOL test_QueryUserInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle);

static BOOL test_QueryAliasInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle);

static void init_samr_Name(struct samr_Name *name, const char *s)
{
	name->name = s;
}

static BOOL test_Close(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		       struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_Close r;

	r.in.handle = handle;
	r.out.handle = handle;

	status = dcerpc_samr_Close(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close handle failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_QuerySecurity(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QuerySecurity r;
	struct samr_SetSecurity s;

	r.in.handle = handle;
	r.in.sec_info = 7;

	status = dcerpc_samr_QuerySecurity(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecurity failed - %s\n", nt_errstr(status));
		return False;
	}

	s.in.handle = handle;
	s.in.sec_info = 7;
	s.in.sdbuf = r.out.sdbuf;

	status = dcerpc_samr_SetSecurity(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetSecurity failed - %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_samr_QuerySecurity(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecurity failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_SetUserInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	struct samr_QueryUserInfo q;
	struct samr_QueryUserInfo q0;
	union samr_UserInfo u;
	BOOL ret = True;

	s.in.handle = handle;
	s.in.info = &u;
	q.in.handle = handle;
	q.out.info = &u;
	q0 = q;

#define TESTCALL(call, r) \
		status = dcerpc_samr_ ##call(p, mem_ctx, &r); \
		if (!NT_STATUS_IS_OK(status)) { \
			printf(#call " level %u failed - %s (line %d)\n", \
			       r.in.level, nt_errstr(status), __LINE__); \
			ret = False; \
			break; \
		}

#define STRING_EQUAL(s1, s2, field) \
		if ((s1 && !s2) || (s2 && !s1) || strcmp(s1, s2)) { \
			printf("Failed to set %s to '%s' (line %d)\n", \
			       #field, s2, __LINE__); \
			ret = False; \
			break; \
		}

#define INT_EQUAL(i1, i2, field) \
		if (i1 != i2) { \
			printf("Failed to set %s to %u (line %d)\n", \
			       #field, i2, __LINE__); \
			ret = False; \
			break; \
		}

#define TEST_USERINFO_NAME(lvl1, field1, lvl2, field2, value) do { \
		printf("field test %d/%s vs %d/%s\n", lvl1, #field1, lvl2, #field2); \
		q.in.level = lvl1; \
		TESTCALL(QueryUserInfo, q) \
		s.in.level = lvl1; \
		u = *q.out.info; \
		init_samr_Name(&u.info ## lvl1.field1, value); \
		TESTCALL(SetUserInfo, s) \
		init_samr_Name(&u.info ## lvl1.field1, ""); \
		TESTCALL(QueryUserInfo, q); \
		u = *q.out.info; \
		STRING_EQUAL(u.info ## lvl1.field1.name, value, field1); \
		q.in.level = lvl2; \
		TESTCALL(QueryUserInfo, q) \
		u = *q.out.info; \
		STRING_EQUAL(u.info ## lvl2.field2.name, value, field2); \
	} while (0)

#define TEST_USERINFO_INT(lvl1, field1, lvl2, field2, value) do { \
		printf("field test %d/%s vs %d/%s\n", lvl1, #field1, lvl2, #field2); \
		q.in.level = lvl1; \
		TESTCALL(QueryUserInfo, q) \
		s.in.level = lvl1; \
		u = *q.out.info; \
		u.info ## lvl1.field1 = value; \
		TESTCALL(SetUserInfo, s) \
		u.info ## lvl1.field1 = 0; \
		TESTCALL(QueryUserInfo, q); \
		u = *q.out.info; \
		INT_EQUAL(u.info ## lvl1.field1, value, field1); \
		q.in.level = lvl2; \
		TESTCALL(QueryUserInfo, q) \
		u = *q.out.info; \
		INT_EQUAL(u.info ## lvl2.field2, value, field1); \
	} while (0)

	q0.in.level = 12;
	do { TESTCALL(QueryUserInfo, q0) } while (0);

	TEST_USERINFO_NAME(2, comment,  1, comment, "xx2-1 comment");
	TEST_USERINFO_NAME(2, comment, 21, comment, "xx2-21 comment");

	TEST_USERINFO_NAME(6, full_name,  1, full_name, "xx6-1 full_name");
	TEST_USERINFO_NAME(6, full_name,  3, full_name, "xx6-3 full_name");
	TEST_USERINFO_NAME(6, full_name,  5, full_name, "xx6-5 full_name");
	TEST_USERINFO_NAME(6, full_name,  6, full_name, "xx6-6 full_name");
	TEST_USERINFO_NAME(6, full_name,  8, full_name, "xx6-8 full_name");
	TEST_USERINFO_NAME(6, full_name, 21, full_name, "xx6-21 full_name");
	TEST_USERINFO_NAME(8, full_name, 21, full_name, "xx7-21 full_name");

	TEST_USERINFO_NAME(11, logon_script, 3, logon_script, "xx11-3 logon_script");
	TEST_USERINFO_NAME(11, logon_script, 5, logon_script, "xx11-5 logon_script");
	TEST_USERINFO_NAME(11, logon_script, 21, logon_script, "xx11-21 logon_script");

	TEST_USERINFO_NAME(12, profile,  3, profile, "xx12-3 profile");
	TEST_USERINFO_NAME(12, profile,  5, profile, "xx12-5 profile");
	TEST_USERINFO_NAME(12, profile, 21, profile, "xx12-21 profile");

	TEST_USERINFO_NAME(13, description,  1, description, "xx13-1 description");
	TEST_USERINFO_NAME(13, description,  5, description, "xx13-5 description");
	TEST_USERINFO_NAME(13, description, 21, description, "xx13-21 description");

	TEST_USERINFO_NAME(14, workstations,  3, workstations, "testworkstation3");
	TEST_USERINFO_NAME(14, workstations,  5, workstations, "testworkstation5");
	TEST_USERINFO_NAME(14, workstations, 21, workstations, "testworkstation21");

	TEST_USERINFO_NAME(20, callback, 21, callback, "xx20-21 callback");

	TEST_USERINFO_INT(2, country_code, 21, country_code, __LINE__);
	TEST_USERINFO_INT(2, code_page, 21, code_page, __LINE__);

	TEST_USERINFO_INT(4, logon_hours.bitmap[3],  3, logon_hours.bitmap[3], __LINE__);
	TEST_USERINFO_INT(4, logon_hours.bitmap[3],  5, logon_hours.bitmap[3], __LINE__);
	TEST_USERINFO_INT(4, logon_hours.bitmap[3], 21, logon_hours.bitmap[3], __LINE__);

#if 0
	/* these fail with win2003 - it appears you can't set the primary gid?
	   the set succeeds, but the gid isn't changed. Very weird! */
	TEST_USERINFO_INT(9, primary_gid,  1, primary_gid, 513);
	TEST_USERINFO_INT(9, primary_gid,  3, primary_gid, 513);
	TEST_USERINFO_INT(9, primary_gid,  5, primary_gid, 513);
	TEST_USERINFO_INT(9, primary_gid, 21, primary_gid, 513);
#endif
	return ret;
}

static BOOL test_SetAliasInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_SetAliasInfo r;
	struct samr_QueryAliasInfo q;
	uint16 levels[] = {2, 3};
	int i;
	BOOL ret = True;

	/* Ignoring switch level 1, as that includes the number of members for the alias
	 * and setting this to a wrong value might have negative consequences
	 */

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing SetAliasInfo level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];
		switch (r.in.level) {
		    case 2 : init_samr_Name(&r.in.info.name,TEST_ALIASNAME); break;
		    case 3 : init_samr_Name(&r.in.info.description,
				"Test Description, should test I18N as well"); break;
		}

		status = dcerpc_samr_SetAliasInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetAliasInfo level %u failed - %s\n",
			       levels[i], nt_errstr(status));
			ret = False;
		}

		q.in.handle = handle;
		q.in.level = levels[i];

		status = dcerpc_samr_QueryAliasInfo(p, mem_ctx, &q);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryAliasInfo level %u failed - %s\n",
			       levels[i], nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}

static BOOL test_GetGroupsForUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				  struct policy_handle *user_handle)
{
	struct samr_GetGroupsForUser r;
	NTSTATUS status;
	BOOL ret = True;

	printf("testing GetGroupsForUser\n");

	r.in.handle = user_handle;

	status = dcerpc_samr_GetGroupsForUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetGroupsForUser failed - %s\n",nt_errstr(status));
		ret = False;
	}

	return ret;

}
static BOOL test_GetUserPwInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_GetUserPwInfo r;
	BOOL ret = True;

	printf("Testing GetUserPwInfo\n");

	r.in.handle = handle;

	status = dcerpc_samr_GetUserPwInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetUserPwInfo failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_GetMembersInAlias(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				  struct policy_handle *alias_handle)
{
	struct samr_GetMembersInAlias r;
	struct lsa_SidArray sids;
	NTSTATUS status;
	BOOL     ret = True;

	printf("Testing GetMembersInAlias\n");

	r.in.handle = alias_handle;
	r.out.sids = &sids;

	status = dcerpc_samr_GetMembersInAlias(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetMembersInAlias failed - %s\n",
		       nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_AddMemberToAlias(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				  struct policy_handle *alias_handle,
				  struct policy_handle *domain_handle,
				  const struct dom_sid *domain_sid)
{
	struct samr_AddAliasMem r;
	struct samr_DelAliasMem d;
	NTSTATUS status;
	BOOL ret = True;
	struct dom_sid *sid;

	sid = dom_sid_add_rid(mem_ctx, domain_sid, 512);

	printf("testing AddAliasMem\n");
	r.in.handle = alias_handle;
	r.in.sid = sid;

	status = dcerpc_samr_AddAliasMem(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddAliasMem failed - %s\n", nt_errstr(status));
		ret = False;
	}

	d.in.handle = alias_handle;
	d.in.sid = sid;

	status = dcerpc_samr_DelAliasMem(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DelAliasMem failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_user_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	BOOL ret = True;

	if (!test_QuerySecurity(p, mem_ctx, handle)) {
		ret = False;
	}

	if (!test_QueryUserInfo(p, mem_ctx, handle)) {
		ret = False;
	}

	if (!test_SetUserInfo(p, mem_ctx, handle)) {
		ret = False;
	}	

	if (!test_GetUserPwInfo(p, mem_ctx, handle)) {
		ret = False;
	}

	return ret;
}

static BOOL test_alias_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			   struct policy_handle *alias_handle,
			   struct policy_handle *domain_handle,
			   const struct dom_sid *domain_sid)
{
	BOOL ret = True;

	if (!test_QuerySecurity(p, mem_ctx, alias_handle)) {
		ret = False;
	}

	if (!test_QueryAliasInfo(p, mem_ctx, alias_handle)) {
		ret = False;
	}

	if (!test_SetAliasInfo(p, mem_ctx, alias_handle)) {
		ret = False;
	}

	if (!test_AddMemberToAlias(p, mem_ctx, alias_handle, 
				   domain_handle, domain_sid)) {
		ret = False;
	}

	return ret;
}

static BOOL test_DeleteUser_byname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				   struct policy_handle *handle, const char *name)
{
	NTSTATUS status;
	struct samr_LookupNames n;
	struct samr_OpenUser r;
	struct samr_DeleteUser d;
	struct policy_handle acct_handle;
	struct samr_Name sname;

	init_samr_Name(&sname, name);

	n.in.handle = handle;
	n.in.num_names = 1;
	n.in.names = &sname;
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	r.in.handle = handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = n.out.rids.ids[0];
	r.out.acct_handle = &acct_handle;
	status = dcerpc_samr_OpenUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	d.in.handle = &acct_handle;
	d.out.handle = &acct_handle;
	status = dcerpc_samr_DeleteUser(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	return True;

failed:
	printf("DeleteUser_byname(%s) failed - %s\n", name, nt_errstr(status));
	return False;
}

static BOOL test_DeleteAlias_byname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				   struct policy_handle *domain_handle, const char *name)
{
	NTSTATUS status;
	struct samr_LookupNames n;
	struct samr_OpenAlias r;
	struct samr_DeleteDomAlias d;
	struct policy_handle alias_handle;
	struct samr_Name sname;

	printf("testing DeleteAlias_byname\n");
	init_samr_Name(&sname, name);

	n.in.handle = domain_handle;
	n.in.num_names = 1;
	n.in.names = &sname;
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	r.in.handle = domain_handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = n.out.rids.ids[0];
	r.out.acct_handle = &alias_handle;
	status = dcerpc_samr_OpenAlias(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	d.in.handle = &alias_handle;
	d.out.handle = &alias_handle;
	status = dcerpc_samr_DeleteDomAlias(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	return True;

failed:
	printf("DeleteUser_byname(%s) failed - %s\n", name, nt_errstr(status));
	return False;
}

static BOOL test_DeleteAlias(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				     struct policy_handle *alias_handle)
{
    	struct samr_DeleteDomAlias d;
	NTSTATUS status;
	BOOL ret;
	printf("Testing DeleteAlias\n");

	d.in.handle = alias_handle;
	d.out.handle = alias_handle;

	status = dcerpc_samr_DeleteDomAlias(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteAlias failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_CreateAlias(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *domain_handle, 
			     struct policy_handle *alias_handle, 
			     const struct dom_sid *domain_sid)
{
	NTSTATUS status;
	struct samr_CreateDomAlias r;
	struct samr_Name name;
	uint32 rid;
	BOOL ret = True;

	init_samr_Name(&name, TEST_ALIASNAME);
	r.in.handle = domain_handle;
	r.in.aliasname = &name;
	r.in.access_mask = SEC_RIGHT_MAXIMUM_ALLOWED;
	r.out.acct_handle = alias_handle;
	r.out.rid = &rid;

	printf("Testing CreateAlias (%s)\n", r.in.aliasname->name);

	status = dcerpc_samr_CreateDomAlias(p, mem_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("Server refused create of '%s'\n", r.in.aliasname->name);
		return True;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_ALIAS_EXISTS)) {
		if (!test_DeleteAlias_byname(p, mem_ctx, domain_handle, r.in.aliasname->name)) {
			return False;
		}
		status = dcerpc_samr_CreateDomAlias(p, mem_ctx, &r);
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateAlias failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_alias_ops(p, mem_ctx, alias_handle, domain_handle, domain_sid)) {
		ret = False;
	}

	return ret;
}

static BOOL test_CreateUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *domain_handle, struct policy_handle *user_handle)
{
	NTSTATUS status;
	struct samr_CreateUser r;
	struct samr_QueryUserInfo q;
	uint32 rid;

	/* This call creates a 'normal' account - check that it really does */
	const uint32 acct_flags = ACB_NORMAL;
	struct samr_Name name;
	BOOL ret = True;

	init_samr_Name(&name, TEST_USERNAME);

	r.in.handle = domain_handle;
	r.in.username = &name;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.acct_handle = user_handle;
	r.out.rid = &rid;

	printf("Testing CreateUser(%s)\n", r.in.username->name);

	status = dcerpc_samr_CreateUser(p, mem_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("Server refused create of '%s'\n", r.in.username->name);
		ZERO_STRUCTP(user_handle);
		return True;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
		if (!test_DeleteUser_byname(p, mem_ctx, domain_handle, r.in.username->name)) {
			return False;
		}
		status = dcerpc_samr_CreateUser(p, mem_ctx, &r);
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateUser failed - %s\n", nt_errstr(status));
		return False;
	}


	q.in.handle = user_handle;
	q.in.level = 16;

	status = dcerpc_samr_QueryUserInfo(p, mem_ctx, &q);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QueryUserInfo level %u failed - %s\n", 
		       q.in.level, nt_errstr(status));
		ret = False;
	} else {
		if ((q.out.info->info16.acct_flags & acct_flags) != acct_flags) {
			printf("QuerUserInfo level 16 failed, it returned 0x%08x (%u) when we expected flags of 0x%08x (%u)\n",
			       q.out.info->info16.acct_flags, q.out.info->info16.acct_flags, 
			       acct_flags, acct_flags);
			ret = False;
		}
	}

	if (!test_user_ops(p, mem_ctx, user_handle)) {
		ret = False;
	}

	return ret;
}


static BOOL test_DeleteUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *user_handle)
{
    	struct samr_DeleteUser d;
	NTSTATUS status;
	BOOL ret;

	printf("Testing DeleteUser\n");

	d.in.handle = user_handle;
	d.out.handle = user_handle;

	status = dcerpc_samr_DeleteUser(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteUser failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_CreateUser2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_CreateUser2 r;
	struct samr_QueryUserInfo q;
	struct samr_DeleteUser d;
	struct policy_handle acct_handle;
	uint32 rid;
	struct samr_Name name;
	BOOL ret = True;
	int i;

	struct {
		uint32 acct_flags;
		const char *account_name;
		NTSTATUS nt_status;
	} account_types[] = {
		{ ACB_NORMAL, TEST_USERNAME, NT_STATUS_OK },
		{ ACB_NORMAL | ACB_DISABLED, TEST_USERNAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_NORMAL | ACB_PWNOEXP, TEST_USERNAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_WSTRUST, TEST_MACHINENAME, NT_STATUS_OK },
		{ ACB_WSTRUST | ACB_DISABLED, TEST_MACHINENAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_WSTRUST | ACB_PWNOEXP, TEST_MACHINENAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_SVRTRUST, TEST_MACHINENAME, NT_STATUS_OK },
		{ ACB_SVRTRUST | ACB_DISABLED, TEST_MACHINENAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_SVRTRUST | ACB_PWNOEXP, TEST_MACHINENAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_DOMTRUST, TEST_DOMAINNAME, NT_STATUS_OK },
		{ ACB_DOMTRUST | ACB_DISABLED, TEST_DOMAINNAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_DOMTRUST | ACB_PWNOEXP, TEST_DOMAINNAME, NT_STATUS_INVALID_PARAMETER },
		{ 0, TEST_USERNAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_DISABLED, TEST_USERNAME, NT_STATUS_INVALID_PARAMETER },
		{ 0, NULL, NT_STATUS_INVALID_PARAMETER }
	};

	for (i = 0; account_types[i].account_name; i++) {
		uint32 acct_flags = account_types[i].acct_flags;
		uint32 access_granted;

		init_samr_Name(&name, account_types[i].account_name);

		r.in.handle = handle;
		r.in.username = &name;
		r.in.acct_flags = acct_flags;
		r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
		r.out.acct_handle = &acct_handle;
		r.out.access_granted = &access_granted;
		r.out.rid = &rid;
		
		printf("Testing CreateUser2(%s)\n", r.in.username->name);
		
		status = dcerpc_samr_CreateUser2(p, mem_ctx, &r);
		
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			printf("Server refused create of '%s'\n", r.in.username->name);
			continue;

		} else if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			if (!test_DeleteUser_byname(p, mem_ctx, handle, r.in.username->name)) {
				return False;
			}
			status = dcerpc_samr_CreateUser2(p, mem_ctx, &r);

		}
		if (!NT_STATUS_EQUAL(status, account_types[i].nt_status)) {
			printf("CreateUser2 failed gave incorrect error return - %s (should be %s)\n", 
			       nt_errstr(status), nt_errstr(account_types[i].nt_status));
			ret = False;
		}
		
		if (NT_STATUS_IS_OK(status)) {
			q.in.handle = &acct_handle;
			q.in.level = 16;
			
			status = dcerpc_samr_QueryUserInfo(p, mem_ctx, &q);
			if (!NT_STATUS_IS_OK(status)) {
				printf("QueryUserInfo level %u failed - %s\n", 
				       q.in.level, nt_errstr(status));
				ret = False;
			} else {
				if ((q.out.info->info16.acct_flags & acct_flags) != acct_flags) {
					printf("QuerUserInfo level 16 failed, it returned 0x%08x when we expected flags of 0x%08x\n",
					       q.out.info->info16.acct_flags, 
					       acct_flags);
					ret = False;
				}
			}
		
			if (!test_user_ops(p, mem_ctx, &acct_handle)) {
				ret = False;
			}

			printf("Testing DeleteUser (createuser2 test)\n");
		
			d.in.handle = &acct_handle;
			d.out.handle = &acct_handle;
			
			status = dcerpc_samr_DeleteUser(p, mem_ctx, &d);
			if (!NT_STATUS_IS_OK(status)) {
				printf("DeleteUser failed - %s\n", nt_errstr(status));
				ret = False;
			}
		}
	}

	return ret;
}

static BOOL test_QueryAliasInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryAliasInfo r;
	uint16 levels[] = {1, 2, 3};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryAliasInfo level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];

		status = dcerpc_samr_QueryAliasInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryAliasInfo level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}

static BOOL test_QueryGroupInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryGroupInfo r;
	uint16 levels[] = {1, 2, 3, 4};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryGroupInfo level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];

		status = dcerpc_samr_QueryGroupInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryGroupInfo level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}

static BOOL test_QueryUserInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryUserInfo r;
	uint16 levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			   11, 12, 13, 14, 16, 17, 20, 21};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryUserInfo level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];

		status = dcerpc_samr_QueryUserInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryUserInfo level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}

static BOOL test_OpenUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle, uint32 rid)
{
	NTSTATUS status;
	struct samr_OpenUser r;
	struct policy_handle acct_handle;
	BOOL ret = True;

	printf("Testing OpenUser(%u)\n", rid);

	r.in.handle = handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_samr_OpenUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenUser(%u) failed - %s\n", rid, nt_errstr(status));
		return False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_QueryUserInfo(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_GetUserPwInfo(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_GetGroupsForUser(p,mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_Close(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	return ret;
}

static BOOL test_OpenGroup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle, uint32 rid)
{
	NTSTATUS status;
	struct samr_OpenGroup r;
	struct policy_handle acct_handle;
	BOOL ret = True;

	printf("Testing OpenGroup(%u)\n", rid);

	r.in.handle = handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_samr_OpenGroup(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenGroup(%u) failed - %s\n", rid, nt_errstr(status));
		return False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_QueryGroupInfo(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_Close(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	return ret;
}

static BOOL test_OpenAlias(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle, uint32 rid)
{
	NTSTATUS status;
	struct samr_OpenAlias r;
	struct policy_handle acct_handle;
	BOOL ret = True;

	printf("Testing OpenAlias(%u)\n", rid);

	r.in.handle = handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_samr_OpenAlias(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenAlias(%u) failed - %s\n", rid, nt_errstr(status));
		return False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_QueryAliasInfo(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_GetMembersInAlias(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	if (!test_Close(p, mem_ctx, &acct_handle)) {
		ret = False;
	}

	return ret;
}

static BOOL test_EnumDomainUsers(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_EnumDomainUsers r;
	uint32 resume_handle=0;
	int i;
	BOOL ret = True;
	struct samr_LookupNames n;
	struct samr_LookupRids  lr ;

	printf("Testing EnumDomainUsers\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.acct_flags = 0;
	r.in.max_size = (uint32)-1;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_samr_EnumDomainUsers(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumDomainUsers failed - %s\n", nt_errstr(status));
		return False;
	}
	
	if (!r.out.sam) {
		return False;
	}

	if (r.out.sam->count == 0) {
		return True;
	}

	for (i=0;i<r.out.sam->count;i++) {
		if (!test_OpenUser(p, mem_ctx, handle, r.out.sam->entries[i].idx)) {
			ret = False;
		}
	}

	printf("Testing LookupNames\n");
	n.in.handle = handle;
	n.in.num_names = r.out.sam->count;
	n.in.names = talloc(mem_ctx, r.out.sam->count * sizeof(struct samr_Name));
	for (i=0;i<r.out.sam->count;i++) {
		n.in.names[i] = r.out.sam->entries[i].name;
	}
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		ret = False;
	}


	printf("Testing LookupRids\n");
	lr.in.handle = handle;
	lr.in.num_rids = r.out.sam->count;
	lr.in.rids = talloc(mem_ctx, r.out.sam->count * sizeof(uint32));
	for (i=0;i<r.out.sam->count;i++) {
		lr.in.rids[i] = r.out.sam->entries[i].idx;
	}
	status = dcerpc_samr_LookupRids(p, mem_ctx, &lr);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupRids failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;	
}

static BOOL test_EnumDomainGroups(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_EnumDomainGroups r;
	uint32 resume_handle=0;
	int i;
	BOOL ret = True;

	printf("Testing EnumDomainGroups\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_size = (uint32)-1;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_samr_EnumDomainGroups(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumDomainGroups failed - %s\n", nt_errstr(status));
		return False;
	}
	
	if (!r.out.sam) {
		return False;
	}

	for (i=0;i<r.out.sam->count;i++) {
		if (!test_OpenGroup(p, mem_ctx, handle, r.out.sam->entries[i].idx)) {
			ret = False;
		}
	}

	return ret;
}

static BOOL test_EnumDomainAliases(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				   struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_EnumDomainAliases r;
	uint32 resume_handle=0;
	int i;
	BOOL ret = True;

	printf("Testing EnumDomainAliases\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_size = (uint32)-1;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_samr_EnumDomainAliases(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumDomainAliases failed - %s\n", nt_errstr(status));
		return False;
	}
	
	if (!r.out.sam) {
		return False;
	}

	for (i=0;i<r.out.sam->count;i++) {
		if (!test_OpenAlias(p, mem_ctx, handle, r.out.sam->entries[i].idx)) {
			ret = False;
		}
	}

	return ret;	
}

static BOOL test_QueryDisplayInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryDisplayInfo r;
	BOOL ret = True;
	uint16 levels[] = {1, 2, 3, 4, 5};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDisplayInfo level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];
		r.in.start_idx = 0;
		r.in.max_entries = 1000;
		r.in.buf_size = (uint32)-1;

		status = dcerpc_samr_QueryDisplayInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDisplayInfo level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}
	}
	
	return ret;	
}

static BOOL test_QueryDomainInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryDomainInfo r;
	uint16 levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDomainInfo level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];

		status = dcerpc_samr_QueryDomainInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDomainInfo level %u failed - %s\n", 
			       r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
	}

	return True;	
}

static BOOL test_OpenDomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle, struct dom_sid *sid)
{
	NTSTATUS status;
	struct samr_OpenDomain r;
	struct policy_handle domain_handle;
	struct policy_handle user_handle;
	struct policy_handle alias_handle;
	BOOL ret = True;

	ZERO_STRUCT(user_handle);
	ZERO_STRUCT(alias_handle);

	printf("Testing OpenDomain\n");

	r.in.handle = handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.sid = sid;
	r.out.domain_handle = &domain_handle;

	status = dcerpc_samr_OpenDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_CreateUser2(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_CreateUser(p, mem_ctx, &domain_handle, &user_handle)) {
		ret = False;
	}

	if (!test_CreateAlias(p, mem_ctx, &domain_handle, &alias_handle, sid)) {
		ret = False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_QueryDomainInfo(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_EnumDomainUsers(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_EnumDomainGroups(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_EnumDomainAliases(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_QueryDisplayInfo(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!policy_handle_empty(&user_handle) &&
	    !test_DeleteUser(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	if (!policy_handle_empty(&alias_handle) &&
	    !test_DeleteAlias(p,mem_ctx, &alias_handle)) {
		ret = False;
	}

	if (!test_Close(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	return ret;
}

static BOOL test_LookupDomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle, struct samr_Name *domain)
{
	NTSTATUS status;
	struct samr_LookupDomain r;

	printf("Testing LookupDomain(%s)\n", domain->name);

	r.in.handle = handle;
	r.in.domain = domain;

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_OpenDomain(p, mem_ctx, handle, r.out.sid)) {
		return False;
	}

	return True;	
}


static BOOL test_EnumDomains(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_EnumDomains r;
	uint32 resume_handle = 0;
	int i;
	BOOL ret = True;

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.buf_size = (uint32)-1;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_samr_EnumDomains(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumDomains failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!r.out.sam) {
		return False;
	}

	for (i=0;i<r.out.sam->count;i++) {
		if (!test_LookupDomain(p, mem_ctx, handle, 
				       &r.out.sam->entries[i].name)) {
			ret = False;
		}
	}

	return ret;
}


static BOOL test_Connect(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_Connect r;
	struct samr_Connect2 r2;
	struct samr_Connect4 r4;
	struct samr_Connect5 r5;
	BOOL ret = True;

	r.in.system_name = 0;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	status = dcerpc_samr_Connect(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect failed - %s\n", nt_errstr(status));
		ret = False;
	}

	r2.in.system_name = "";
	r2.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r2.out.handle = handle;

	status = dcerpc_samr_Connect2(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect2 failed - %s\n", nt_errstr(status));
		ret = False;
	}

	r4.in.system_name = "";
	r4.in.unknown = 0;
	r4.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r4.out.handle = handle;

	status = dcerpc_samr_Connect4(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect4 failed - %s\n", nt_errstr(status));
		ret = False;
	}

	r5.in.system_name = "";
	r5.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r5.in.unknown0 = 1; /*Magic values I took from a WinXP pro workstation       */
	r5.in.unknown1 = 1; /*tests failed with NT_STATUS_NET_WRITE_FAULT if         */
	r5.in.unknown2 = 3; /*unknown0 and unknown1 where something other than 1     */
	r5.in.unknown3 = 0; /*unkown2 and unknown3 could be varied and had no effect */
	r5.out.handle = handle;

	status = dcerpc_samr_Connect5(p, mem_ctx, &r5);
	if (!NT_STATUS_IS_OK(status)) {
		/*This fails for a Win2000pro machine, but succeeds for
		  WinXPpro  --  Kai
		 */
		printf("Connect5 failed - %s\n", nt_errstr(status));
		/*ret = False; Should this test fail? */
	}

	return ret;
}


BOOL torture_rpc_samr(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle handle;

	mem_ctx = talloc_init("torture_rpc_samr");

	status = torture_rpc_connection(&p, 
					DCERPC_SAMR_NAME,
					DCERPC_SAMR_UUID,
					DCERPC_SAMR_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

	if (!test_Connect(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumDomains(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_Close(p, mem_ctx, &handle)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
