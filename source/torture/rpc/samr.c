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
#define TEST_GROUPNAME "samrtorturetestgroup"
#define TEST_MACHINENAME "samrtorturetestmach$"
#define TEST_DOMAINNAME "samrtorturetestdom$"


static BOOL test_QueryUserInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle);

static BOOL test_QueryUserInfo2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
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

static BOOL test_Shutdown(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		       struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_Shutdown r;

	if (lp_parm_int(-1, "torture", "dangerous") != 1) {
		printf("samr_Shutdown disabled - enable dangerous tests to use\n");
		return True;
	}

	r.in.handle = handle;

	printf("testing samr_Shutdown\n");

	status = dcerpc_samr_Shutdown(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("samr_Shutdown failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_SetDsrmPassword(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_SetDsrmPassword r;
	struct samr_Name name;
	struct samr_Hash hash;

	if (lp_parm_int(-1, "torture", "dangerous") != 1) {
		printf("samr_SetDsrmPassword disabled - enable dangerous tests to use\n");
		return True;
	}

	E_md4hash("TeSTDSRM123", hash.hash);

	init_samr_Name(&name, "Administrator");

	r.in.name = &name;
	r.in.unknown = 0;
	r.in.hash = &hash;

	printf("testing samr_SetDsrmPassword\n");

	status = dcerpc_samr_SetDsrmPassword(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		printf("samr_SetDsrmPassword failed - %s\n", nt_errstr(status));
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
	struct samr_SetUserInfo2 s2;
	struct samr_QueryUserInfo q;
	struct samr_QueryUserInfo q0;
	union samr_UserInfo u;
	BOOL ret = True;

	s.in.handle = handle;
	s.in.info = &u;

	s2.in.handle = handle;
	s2.in.info = &u;

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

#define TEST_USERINFO_NAME(lvl1, field1, lvl2, field2, value, fpval) do { \
		printf("field test %d/%s vs %d/%s\n", lvl1, #field1, lvl2, #field2); \
		q.in.level = lvl1; \
		TESTCALL(QueryUserInfo, q) \
		s.in.level = lvl1; \
		s2.in.level = lvl1; \
		u = *q.out.info; \
		if (lvl1 == 21) { \
			ZERO_STRUCT(u.info21); \
			u.info21.fields_present = fpval; \
		} \
		init_samr_Name(&u.info ## lvl1.field1, value); \
		TESTCALL(SetUserInfo, s) \
		TESTCALL(SetUserInfo2, s2) \
		init_samr_Name(&u.info ## lvl1.field1, ""); \
		TESTCALL(QueryUserInfo, q); \
		u = *q.out.info; \
		STRING_EQUAL(u.info ## lvl1.field1.name, value, field1); \
		q.in.level = lvl2; \
		TESTCALL(QueryUserInfo, q) \
		u = *q.out.info; \
		STRING_EQUAL(u.info ## lvl2.field2.name, value, field2); \
	} while (0)

#define TEST_USERINFO_INT(lvl1, field1, lvl2, field2, value, fpval) do { \
		printf("field test %d/%s vs %d/%s\n", lvl1, #field1, lvl2, #field2); \
		q.in.level = lvl1; \
		TESTCALL(QueryUserInfo, q) \
		s.in.level = lvl1; \
		s2.in.level = lvl1; \
		u = *q.out.info; \
		if (lvl1 == 21) { \
			uint8 *bitmap = u.info21.logon_hours.bitmap; \
			ZERO_STRUCT(u.info21); \
			if (fpval == SAMR_FIELD_LOGON_HOURS) { \
				u.info21.logon_hours.units_per_week = 168; \
				u.info21.logon_hours.bitmap = bitmap; \
			} \
			u.info21.fields_present = fpval; \
		} \
		u.info ## lvl1.field1 = value; \
		TESTCALL(SetUserInfo, s) \
		TESTCALL(SetUserInfo2, s2) \
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

	TEST_USERINFO_NAME(2, comment,  1, comment, "xx2-1 comment", 0);
	TEST_USERINFO_NAME(2, comment, 21, comment, "xx2-21 comment", 0);
	TEST_USERINFO_NAME(21, comment, 21, comment, "xx21-21 comment", 
			   SAMR_FIELD_COMMENT);

	TEST_USERINFO_NAME(6, full_name,  1, full_name, "xx6-1 full_name", 0);
	TEST_USERINFO_NAME(6, full_name,  3, full_name, "xx6-3 full_name", 0);
	TEST_USERINFO_NAME(6, full_name,  5, full_name, "xx6-5 full_name", 0);
	TEST_USERINFO_NAME(6, full_name,  6, full_name, "xx6-6 full_name", 0);
	TEST_USERINFO_NAME(6, full_name,  8, full_name, "xx6-8 full_name", 0);
	TEST_USERINFO_NAME(6, full_name, 21, full_name, "xx6-21 full_name", 0);
	TEST_USERINFO_NAME(8, full_name, 21, full_name, "xx8-21 full_name", 0);
	TEST_USERINFO_NAME(21, full_name, 21, full_name, "xx21-21 full_name", 
			   SAMR_FIELD_NAME);

	TEST_USERINFO_NAME(11, logon_script, 3, logon_script, "xx11-3 logon_script", 0);
	TEST_USERINFO_NAME(11, logon_script, 5, logon_script, "xx11-5 logon_script", 0);
	TEST_USERINFO_NAME(11, logon_script, 21, logon_script, "xx11-21 logon_script", 0);
	TEST_USERINFO_NAME(21, logon_script, 21, logon_script, "xx21-21 logon_script", 
			   SAMR_FIELD_LOGON_SCRIPT);

	TEST_USERINFO_NAME(12, profile,  3, profile, "xx12-3 profile", 0);
	TEST_USERINFO_NAME(12, profile,  5, profile, "xx12-5 profile", 0);
	TEST_USERINFO_NAME(12, profile, 21, profile, "xx12-21 profile", 0);
	TEST_USERINFO_NAME(21, profile, 21, profile, "xx21-21 profile", 
			   SAMR_FIELD_PROFILE);

	TEST_USERINFO_NAME(13, description,  1, description, "xx13-1 description", 0);
	TEST_USERINFO_NAME(13, description,  5, description, "xx13-5 description", 0);
	TEST_USERINFO_NAME(13, description, 21, description, "xx13-21 description", 0);
	TEST_USERINFO_NAME(21, description, 21, description, "xx21-21 description", 
			   SAMR_FIELD_DESCRIPTION);

	TEST_USERINFO_NAME(14, workstations,  3, workstations, "14workstation3", 0);
	TEST_USERINFO_NAME(14, workstations,  5, workstations, "14workstation4", 0);
	TEST_USERINFO_NAME(14, workstations, 21, workstations, "14workstation21", 0);
	TEST_USERINFO_NAME(21, workstations, 21, workstations, "21workstation21", 
			   SAMR_FIELD_WORKSTATION);

	TEST_USERINFO_NAME(20, callback, 21, callback, "xx20-21 callback", 0);
	TEST_USERINFO_NAME(21, callback, 21, callback, "xx21-21 callback", 
			   SAMR_FIELD_CALLBACK);

	TEST_USERINFO_INT(2, country_code, 21, country_code, __LINE__, 0);
	TEST_USERINFO_INT(21, country_code, 21, country_code, __LINE__, 
			  SAMR_FIELD_COUNTRY_CODE);

	TEST_USERINFO_INT(2, code_page, 21, code_page, __LINE__, 0);
	TEST_USERINFO_INT(21, code_page, 21, code_page, __LINE__, 
			  SAMR_FIELD_CODE_PAGE);

	TEST_USERINFO_INT(4, logon_hours.bitmap[3],  3, logon_hours.bitmap[3], 1, 0);
	TEST_USERINFO_INT(4, logon_hours.bitmap[3],  5, logon_hours.bitmap[3], 2, 0);
	TEST_USERINFO_INT(4, logon_hours.bitmap[3], 21, logon_hours.bitmap[3], 3, 0);
	TEST_USERINFO_INT(21, logon_hours.bitmap[3], 21, logon_hours.bitmap[3], 4, 
			  SAMR_FIELD_LOGON_HOURS);

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

/*
  generate a random password for password change tests
*/
static char *samr_rand_pass(TALLOC_CTX *mem_ctx)
{
	size_t len = 8 + (random() % 6);
	char *s = generate_random_str(len);
	printf("Generated password '%s'\n", s);
	return talloc_strdup(mem_ctx, s);
}

static BOOL test_SetUserPass(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	BOOL ret = True;
	DATA_BLOB session_key;
	char *newpass = samr_rand_pass(mem_ctx);

	s.in.handle = handle;
	s.in.info = &u;
	s.in.level = 24;

	encode_pw_buffer(u.info24.password.data, newpass, STR_UNICODE);
	u.info24.pw_len = strlen(newpass);

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	SamOEMhashBlob(u.info24.password.data, 516, &session_key);

	printf("Testing SetUserInfo level 24 (set password)\n");

	status = dcerpc_samr_SetUserInfo(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u failed - %s\n",
		       s.in.level, nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	return ret;
}


static BOOL test_SetUserPass_23(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	BOOL ret = True;
	DATA_BLOB session_key;
	char *newpass = samr_rand_pass(mem_ctx);

	s.in.handle = handle;
	s.in.info = &u;
	s.in.level = 23;

	ZERO_STRUCT(u);

	u.info23.info.fields_present = SAMR_FIELD_PASSWORD;

	encode_pw_buffer(u.info23.password.data, newpass, STR_UNICODE);

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	SamOEMhashBlob(u.info23.password.data, 516, &session_key);

	printf("Testing SetUserInfo level 23 (set password)\n");

	status = dcerpc_samr_SetUserInfo(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u failed - %s\n",
		       s.in.level, nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	return ret;
}


static BOOL test_SetUserPassEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	BOOL ret = True;
	DATA_BLOB session_key;
	DATA_BLOB confounded_session_key = data_blob_talloc(mem_ctx, NULL, 16);
	uint8 confounder[16];
	char *newpass = samr_rand_pass(mem_ctx);	
	struct MD5Context ctx;

	s.in.handle = handle;
	s.in.info = &u;
	s.in.level = 26;

	encode_pw_buffer(u.info26.password.data, newpass, STR_UNICODE);
	u.info26.pw_len = strlen(newpass);

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	generate_random_buffer((unsigned char *)confounder, 16, False);

	MD5Init(&ctx);
	MD5Update(&ctx, confounder, 16);
	MD5Update(&ctx, session_key.data, session_key.length);
	MD5Final(confounded_session_key.data, &ctx);

	SamOEMhashBlob(u.info26.password.data, 516, &confounded_session_key);
	memcpy(&u.info26.password.data[516], confounder, 16);

	printf("Testing SetUserInfo level 26 (set password ex)\n");

	status = dcerpc_samr_SetUserInfo(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u failed - %s\n",
		       s.in.level, nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	return ret;
}

static BOOL test_SetUserPass_25(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	BOOL ret = True;
	DATA_BLOB session_key;
	DATA_BLOB confounded_session_key = data_blob_talloc(mem_ctx, NULL, 16);
	uint8 confounder[16];
	char *newpass = samr_rand_pass(mem_ctx);	
	struct MD5Context ctx;

	s.in.handle = handle;
	s.in.info = &u;
	s.in.level = 25;

	ZERO_STRUCT(u);

	u.info25.info.fields_present = SAMR_FIELD_PASSWORD;

	encode_pw_buffer(u.info25.password.data, newpass, STR_UNICODE);

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	generate_random_buffer((unsigned char *)confounder, 16, False);

	MD5Init(&ctx);
	MD5Update(&ctx, confounder, 16);
	MD5Update(&ctx, session_key.data, session_key.length);
	MD5Final(confounded_session_key.data, &ctx);

	SamOEMhashBlob(u.info25.password.data, 516, &confounded_session_key);
	memcpy(&u.info25.password.data[516], confounder, 16);

	printf("Testing SetUserInfo level 25 (set password ex)\n");

	status = dcerpc_samr_SetUserInfo(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u failed - %s\n",
		       s.in.level, nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

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

static BOOL test_GetDomPwInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct samr_Name *domain_name)
{
	NTSTATUS status;
	struct samr_GetDomPwInfo r;
	BOOL ret = True;

	printf("Testing GetDomPwInfo\n");

	r.in.name = domain_name;

	status = dcerpc_samr_GetDomPwInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetDomPwInfo failed - %s\n", nt_errstr(status));
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

static NTSTATUS test_LookupName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				struct policy_handle *domain_handle, const char *name,
				uint32 *rid)
{
	NTSTATUS status;
	struct samr_LookupNames n;
	struct samr_Name sname[2];

	init_samr_Name(&sname[0], name);

	n.in.handle = domain_handle;
	n.in.num_names = 1;
	n.in.names = sname;
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (NT_STATUS_IS_OK(status)) {
		*rid = n.out.rids.ids[0];
	} else {
		return status;
	}

	init_samr_Name(&sname[1], "xxNONAMExx");
	n.in.num_names = 2;
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (!NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupNames[2] failed - %s\n", nt_errstr(status));		
		return status;
	}

	init_samr_Name(&sname[1], "xxNONAMExx");
	n.in.num_names = 0;
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames[0] failed - %s\n", nt_errstr(status));		
	}

	return status;
}

static NTSTATUS test_OpenUser_byname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				     struct policy_handle *domain_handle,
				     const char *name, struct policy_handle *user_handle)
{
	NTSTATUS status;
	struct samr_OpenUser r;
	uint32 rid;

	status = test_LookupName(p, mem_ctx, domain_handle, name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	r.in.handle = domain_handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.acct_handle = user_handle;
	status = dcerpc_samr_OpenUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenUser_byname(%s) failed - %s\n", name, nt_errstr(status));
	}

	return status;
}


static BOOL test_ChangePasswordUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				    struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_ChangePasswordUser r;
	BOOL ret = True;
	struct samr_Hash hash1, hash2, hash3, hash4, hash5, hash6;
	struct policy_handle user_handle;
	char *oldpass = *password;
	char *newpass = samr_rand_pass(mem_ctx);	
	uint8 old_nt_hash[16], new_nt_hash[16];
	uint8 old_lm_hash[16], new_lm_hash[16];

	status = test_OpenUser_byname(p, mem_ctx, handle, TEST_USERNAME, &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	printf("Testing ChangePasswordUser\n");

	E_md4hash(oldpass, old_nt_hash);
	E_md4hash(newpass, new_nt_hash);
	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	E_old_pw_hash(new_lm_hash, old_lm_hash, hash1.hash);
	E_old_pw_hash(old_lm_hash, new_lm_hash, hash2.hash);
	E_old_pw_hash(new_nt_hash, old_nt_hash, hash3.hash);
	E_old_pw_hash(old_nt_hash, new_nt_hash, hash4.hash);
	E_old_pw_hash(old_lm_hash, new_nt_hash, hash5.hash);
	E_old_pw_hash(old_nt_hash, new_lm_hash, hash6.hash);

	r.in.handle = &user_handle;
	r.in.lm_present = 1;
	r.in.old_lm_crypted = &hash1;
	r.in.new_lm_crypted = &hash2;
	r.in.nt_present = 1;
	r.in.old_nt_crypted = &hash3;
	r.in.new_nt_crypted = &hash4;
	r.in.cross1_present = 1;
	r.in.nt_cross = &hash5;
	r.in.cross2_present = 1;
	r.in.lm_cross = &hash6;

	status = dcerpc_samr_ChangePasswordUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ChangePasswordUser failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	if (!test_Close(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	return ret;
}


static BOOL test_OemChangePasswordUser2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
					struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_OemChangePasswordUser2 r;
	BOOL ret = True;
	struct samr_Hash lm_verifier;
	struct samr_CryptPassword lm_pass;
	struct samr_AsciiName server, account;
	char *oldpass = *password;
	char *newpass = samr_rand_pass(mem_ctx);	
	uint8 old_lm_hash[16], new_lm_hash[16];

	printf("Testing OemChangePasswordUser2\n");

	server.name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	account.name = TEST_USERNAME;

	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	encode_pw_buffer(lm_pass.data, newpass, STR_ASCII);
	SamOEMhash(lm_pass.data, old_lm_hash, 516);
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	r.in.server = &server;
	r.in.account = &account;
	r.in.password = &lm_pass;
	r.in.hash = &lm_verifier;

	status = dcerpc_samr_OemChangePasswordUser2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OemChangePasswordUser2 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	return ret;
}


static BOOL test_ChangePasswordUser2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				     struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_ChangePasswordUser2 r;
	BOOL ret = True;
	struct samr_Name server, account;
	struct samr_CryptPassword nt_pass, lm_pass;
	struct samr_Hash nt_verifier, lm_verifier;
	char *oldpass = *password;
	char *newpass = samr_rand_pass(mem_ctx);	
	uint8 old_nt_hash[16], new_nt_hash[16];
	uint8 old_lm_hash[16], new_lm_hash[16];

	printf("Testing ChangePasswordUser2\n");

	server.name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	init_samr_Name(&account, TEST_USERNAME);

	E_md4hash(oldpass, old_nt_hash);
	E_md4hash(newpass, new_nt_hash);

	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	encode_pw_buffer(lm_pass.data, newpass, STR_ASCII|STR_TERMINATE);
	SamOEMhash(lm_pass.data, old_lm_hash, 516);
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	encode_pw_buffer(nt_pass.data, newpass, STR_UNICODE);
	SamOEMhash(nt_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, nt_verifier.hash);

	r.in.server = &server;
	r.in.account = &account;
	r.in.nt_password = &nt_pass;
	r.in.nt_verifier = &nt_verifier;
	r.in.lm_change = 1;
	r.in.lm_password = &lm_pass;
	r.in.lm_verifier = &lm_verifier;

	status = dcerpc_samr_ChangePasswordUser2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ChangePasswordUser2 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	return ret;
}


static BOOL test_ChangePasswordUser3(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				     struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_ChangePasswordUser3 r;
	BOOL ret = True;
	struct samr_Name server, account;
	struct samr_CryptPassword nt_pass, lm_pass;
	struct samr_Hash nt_verifier, lm_verifier;
	char *oldpass = *password;
	char *newpass = samr_rand_pass(mem_ctx);
	uint8 old_nt_hash[16], new_nt_hash[16];
	uint8 old_lm_hash[16], new_lm_hash[16];

	printf("Testing ChangePasswordUser3\n");

	server.name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	init_samr_Name(&account, TEST_USERNAME);

	E_md4hash(oldpass, old_nt_hash);
	E_md4hash(newpass, new_nt_hash);

	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	encode_pw_buffer(lm_pass.data, newpass, STR_UNICODE);
	SamOEMhash(lm_pass.data, old_lm_hash, 516);
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	encode_pw_buffer(nt_pass.data, newpass, STR_UNICODE);
	SamOEMhash(nt_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, nt_verifier.hash);

	r.in.server = &server;
	r.in.account = &account;
	r.in.nt_password = &nt_pass;
	r.in.nt_verifier = &nt_verifier;
	r.in.lm_change = 1;
	r.in.lm_password = &lm_pass;
	r.in.lm_verifier = &lm_verifier;
	r.in.password3 = NULL;

	status = dcerpc_samr_ChangePasswordUser3(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ChangePasswordUser3 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
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
	struct samr_AddAliasMember r;
	struct samr_DeleteAliasMember d;
	NTSTATUS status;
	BOOL ret = True;
	struct dom_sid *sid;

	sid = dom_sid_add_rid(mem_ctx, domain_sid, 512);

	printf("testing AddAliasMember\n");
	r.in.handle = alias_handle;
	r.in.sid = sid;

	status = dcerpc_samr_AddAliasMember(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddAliasMember failed - %s\n", nt_errstr(status));
		ret = False;
	}

	d.in.handle = alias_handle;
	d.in.sid = sid;

	status = dcerpc_samr_DeleteAliasMember(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DelAliasMember failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_AddMultipleMembersToAlias(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
					   struct policy_handle *alias_handle)
{
	struct samr_AddMultipleMembersToAlias a;
	struct samr_RemoveMultipleMembersFromAlias r;
	NTSTATUS status;
	BOOL ret = True;
	struct lsa_SidArray sids;

	printf("testing AddMultipleMembersToAlias\n");
	a.in.handle = alias_handle;
	a.in.sids = &sids;

	sids.num_sids = 3;
	sids.sids = talloc_array_p(mem_ctx, struct lsa_SidPtr, 3);

	sids.sids[0].sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1-2-3-1");
	sids.sids[1].sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1-2-3-2");
	sids.sids[2].sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1-2-3-3");

	status = dcerpc_samr_AddMultipleMembersToAlias(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddMultipleMembersToAlias failed - %s\n", nt_errstr(status));
		ret = False;
	}


	printf("testing RemoveMultipleMembersFromAlias\n");
	r.in.handle = alias_handle;
	r.in.sids = &sids;

	status = dcerpc_samr_RemoveMultipleMembersFromAlias(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RemoveMultipleMembersFromAlias failed - %s\n", nt_errstr(status));
		ret = False;
	}

	/* strange! removing twice doesn't give any error */
	status = dcerpc_samr_RemoveMultipleMembersFromAlias(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RemoveMultipleMembersFromAlias failed - %s\n", nt_errstr(status));
		ret = False;
	}

	/* but removing an alias that isn't there does */
	sids.sids[2].sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1-2-3-4");

	status = dcerpc_samr_RemoveMultipleMembersFromAlias(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_NOT_FOUND, status)) {
		printf("RemoveMultipleMembersFromAlias failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_TestPrivateFunctionsUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
					    struct policy_handle *user_handle)
{
    	struct samr_TestPrivateFunctionsUser r;
	NTSTATUS status;
	BOOL ret = True;

	printf("Testing TestPrivateFunctionsUser\n");

	r.in.handle = user_handle;

	status = dcerpc_samr_TestPrivateFunctionsUser(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_NOT_IMPLEMENTED, status)) {
		printf("TestPrivateFunctionsUser failed - %s\n", nt_errstr(status));
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

	if (!test_QueryUserInfo2(p, mem_ctx, handle)) {
		ret = False;
	}

	if (!test_SetUserInfo(p, mem_ctx, handle)) {
		ret = False;
	}	

	if (!test_GetUserPwInfo(p, mem_ctx, handle)) {
		ret = False;
	}

	if (!test_TestPrivateFunctionsUser(p, mem_ctx, handle)) {
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

	if (!test_AddMultipleMembersToAlias(p, mem_ctx, alias_handle)) {
		ret = False;
	}

	return ret;
}


BOOL test_DeleteUser_byname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle, const char *name)
{
	NTSTATUS status;
	struct samr_DeleteUser d;
	struct policy_handle acct_handle;
	uint32 rid;

	status = test_LookupName(p, mem_ctx, handle, name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = test_OpenUser_byname(p, mem_ctx, handle, name, &acct_handle);
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


static BOOL test_DeleteGroup_byname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				    struct policy_handle *handle, const char *name)
{
	NTSTATUS status;
	struct samr_OpenGroup r;
	struct samr_DeleteDomainGroup d;
	struct policy_handle group_handle;
	uint32 rid;

	status = test_LookupName(p, mem_ctx, handle, name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	r.in.handle = handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.acct_handle = &group_handle;
	status = dcerpc_samr_OpenGroup(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	d.in.handle = &group_handle;
	d.out.handle = &group_handle;
	status = dcerpc_samr_DeleteDomainGroup(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	return True;

failed:
	printf("DeleteGroup_byname(%s) failed - %s\n", name, nt_errstr(status));
	return False;
}


static BOOL test_DeleteAlias_byname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				   struct policy_handle *domain_handle, const char *name)
{
	NTSTATUS status;
	struct samr_OpenAlias r;
	struct samr_DeleteDomAlias d;
	struct policy_handle alias_handle;
	uint32 rid;

	printf("testing DeleteAlias_byname\n");

	status = test_LookupName(p, mem_ctx, domain_handle, name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	r.in.handle = domain_handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
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
	BOOL ret = True;
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

static BOOL test_ChangePassword(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *domain_handle, char **password)
{
	BOOL ret = True;

	if (!*password) {
		return False;
	}

	if (!test_ChangePasswordUser(p, mem_ctx, domain_handle, password)) {
		ret = False;
	}

	if (!test_ChangePasswordUser2(p, mem_ctx, domain_handle, password)) {
		ret = False;
	}

	if (!test_OemChangePasswordUser2(p, mem_ctx, domain_handle, password)) {
		ret = False;
	}

	if (!test_ChangePasswordUser3(p, mem_ctx, domain_handle, password)) {
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
	char *password = NULL;

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

	if (!test_SetUserPass(p, mem_ctx, user_handle, &password)) {
		ret = False;
	}	

	if (!test_SetUserPass_23(p, mem_ctx, user_handle, &password)) {
		ret = False;
	}	

	if (!test_SetUserPassEx(p, mem_ctx, user_handle, &password)) {
		ret = False;
	}	

	if (!test_SetUserPass_25(p, mem_ctx, user_handle, &password)) {
		ret = False;
	}	

	/* we change passwords twice - this has the effect of verifying
	   they were changed correctly */
	if (!test_ChangePassword(p, mem_ctx, domain_handle, &password)) {
		ret = False;
	}	

	if (!test_ChangePassword(p, mem_ctx, domain_handle, &password)) {
		ret = False;
	}	


	return ret;
}


static BOOL test_DeleteUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *user_handle)
{
    	struct samr_DeleteUser d;
	NTSTATUS status;
	BOOL ret = True;

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


static BOOL test_SetGroupInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryGroupInfo r;
	struct samr_SetGroupInfo s;
	uint16 levels[] = {1, 2, 3, 4};
	uint16 set_ok[] = {0, 1, 1, 1};
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

		printf("Testing SetGroupInfo level %u\n", levels[i]);

		s.in.handle = handle;
		s.in.level = levels[i];
		s.in.info = r.out.info;

		if (s.in.level == 4) {
			init_samr_Name(&s.in.info->description, "test description");
		}

		status = dcerpc_samr_SetGroupInfo(p, mem_ctx, &s);
		if (set_ok[i]) {
			if (!NT_STATUS_IS_OK(status)) {
				printf("SetGroupInfo level %u failed - %s\n", 
				       r.in.level, nt_errstr(status));
				ret = False;
				continue;
			}
		} else {
			if (!NT_STATUS_EQUAL(NT_STATUS_INVALID_INFO_CLASS, status)) {
				printf("SetGroupInfo level %u gave %s - should have been NT_STATUS_INVALID_INFO_CLASS\n", 
				       r.in.level, nt_errstr(status));
				ret = False;
				continue;
			}
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

static BOOL test_QueryUserInfo2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryUserInfo2 r;
	uint16 levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			   11, 12, 13, 14, 16, 17, 20, 21};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryUserInfo2 level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];

		status = dcerpc_samr_QueryUserInfo2(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryUserInfo2 level %u failed - %s\n", 
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

	if (!test_QueryUserInfo2(p, mem_ctx, &acct_handle)) {
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

static BOOL test_GetDisplayEnumerationIndex(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
					    struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_GetDisplayEnumerationIndex r;
	BOOL ret = True;
	uint16 levels[] = {1, 2, 3, 4, 5};
	uint16 ok_lvl[] = {1, 1, 1, 0, 0};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing GetDisplayEnumerationIndex level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];
		init_samr_Name(&r.in.name, TEST_USERNAME);

		status = dcerpc_samr_GetDisplayEnumerationIndex(p, mem_ctx, &r);

		if (ok_lvl[i] && 
		    !NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(NT_STATUS_NO_MORE_ENTRIES, status)) {
			printf("GetDisplayEnumerationIndex level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}

		init_samr_Name(&r.in.name, "zzzzzzzz");

		status = dcerpc_samr_GetDisplayEnumerationIndex(p, mem_ctx, &r);
		
		if (ok_lvl[i] && !NT_STATUS_EQUAL(NT_STATUS_NO_MORE_ENTRIES, status)) {
			printf("GetDisplayEnumerationIndex level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}
	}
	
	return ret;	
}

static BOOL test_GetDisplayEnumerationIndex2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
					     struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_GetDisplayEnumerationIndex2 r;
	BOOL ret = True;
	uint16 levels[] = {1, 2, 3, 4, 5};
	uint16 ok_lvl[] = {1, 1, 1, 0, 0};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing GetDisplayEnumerationIndex2 level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];
		init_samr_Name(&r.in.name, TEST_USERNAME);

		status = dcerpc_samr_GetDisplayEnumerationIndex2(p, mem_ctx, &r);
		if (ok_lvl[i] && 
		    !NT_STATUS_IS_OK(status) && 
		    !NT_STATUS_EQUAL(NT_STATUS_NO_MORE_ENTRIES, status)) {
			printf("GetDisplayEnumerationIndex2 level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}

		init_samr_Name(&r.in.name, "zzzzzzzz");

		status = dcerpc_samr_GetDisplayEnumerationIndex2(p, mem_ctx, &r);
		if (ok_lvl[i] && !NT_STATUS_EQUAL(NT_STATUS_NO_MORE_ENTRIES, status)) {
			printf("GetDisplayEnumerationIndex2 level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
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

static BOOL test_QueryDisplayInfo2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryDisplayInfo2 r;
	BOOL ret = True;
	uint16 levels[] = {1, 2, 3, 4, 5};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDisplayInfo2 level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];
		r.in.start_idx = 0;
		r.in.max_entries = 1000;
		r.in.buf_size = (uint32)-1;

		status = dcerpc_samr_QueryDisplayInfo2(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDisplayInfo2 level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}
	}
	
	return ret;	
}

static BOOL test_QueryDisplayInfo3(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryDisplayInfo3 r;
	BOOL ret = True;
	uint16 levels[] = {1, 2, 3, 4, 5};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDisplayInfo3 level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];
		r.in.start_idx = 0;
		r.in.max_entries = 1000;
		r.in.buf_size = (uint32)-1;

		status = dcerpc_samr_QueryDisplayInfo3(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDisplayInfo3 level %u failed - %s\n", 
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
	struct samr_SetDomainInfo s;
	uint16 levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13};
	uint16 set_ok[] = {1, 0, 1, 1, 0, 1, 1, 0, 1,  0,  1,  0};
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

		printf("Testing SetDomainInfo level %u\n", levels[i]);

		s.in.handle = handle;
		s.in.level = levels[i];
		s.in.info = r.out.info;

		status = dcerpc_samr_SetDomainInfo(p, mem_ctx, &s);
		if (set_ok[i]) {
			if (!NT_STATUS_IS_OK(status)) {
				printf("SetDomainInfo level %u failed - %s\n", 
				       r.in.level, nt_errstr(status));
				ret = False;
				continue;
			}
		} else {
			if (!NT_STATUS_EQUAL(NT_STATUS_INVALID_INFO_CLASS, status)) {
				printf("SetDomainInfo level %u gave %s - should have been NT_STATUS_INVALID_INFO_CLASS\n", 
				       r.in.level, nt_errstr(status));
				ret = False;
				continue;
			}
		}

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


static BOOL test_QueryDomainInfo2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryDomainInfo2 r;
	uint16 levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDomainInfo2 level %u\n", levels[i]);

		r.in.handle = handle;
		r.in.level = levels[i];

		status = dcerpc_samr_QueryDomainInfo2(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDomainInfo2 level %u failed - %s\n", 
			       r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
	}

	return True;	
}

void add_string_to_array(TALLOC_CTX *mem_ctx,
			 const char *str, const char ***strings, int *num)
{
	*strings = talloc_realloc(mem_ctx, *strings,
				  ((*num)+1) * sizeof(**strings));

	if (*strings == NULL)
		return;

	(*strings)[*num] = str;
	*num += 1;

	return;
}

/* Test whether querydispinfo level 5 and enumdomgroups return the same
   set of group names. */
static BOOL test_GroupList(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle)
{
	struct samr_EnumDomainGroups q1;
	struct samr_QueryDisplayInfo q2;
	NTSTATUS status;
	uint32 resume_handle=0;
	int i;
	BOOL ret = True;

	int num_names = 0;
	const char **names = NULL;

	printf("Testing coherency of querydispinfo vs enumdomgroups\n");

	q1.in.handle = handle;
	q1.in.resume_handle = &resume_handle;
	q1.in.max_size = 5;
	q1.out.resume_handle = &resume_handle;

	status = STATUS_MORE_ENTRIES;
	while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		status = dcerpc_samr_EnumDomainGroups(p, mem_ctx, &q1);

		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES))
			break;

		for (i=0; i<q1.out.sam->count; i++) {
			add_string_to_array(mem_ctx,
					    q1.out.sam->entries[i].name.name,
					    &names, &num_names);
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumDomainGroups failed - %s\n", nt_errstr(status));
		return False;
	}
	
	if (!q1.out.sam) {
		return False;
	}

	q2.in.handle = handle;
	q2.in.level = 5;
	q2.in.start_idx = 0;
	q2.in.max_entries = 5;
	q2.in.buf_size = (uint32)-1;

	status = STATUS_MORE_ENTRIES;
	while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		status = dcerpc_samr_QueryDisplayInfo(p, mem_ctx, &q2);

		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES))
			break;

		for (i=0; i<q2.out.info.info5.count; i++) {
			char *name;
			size_t namelen;
			int j;
			BOOL found = False;

			/* Querydisplayinfo returns ascii -- convert */

			namelen = convert_string_allocate(CH_DISPLAY, CH_UNIX,
							  q2.out.info.info5.entries[i].account_name.name,
							  q2.out.info.info5.entries[i].account_name.name_len,
							  (void **)&name);
			name = realloc(name, namelen+1);
			name[namelen] = 0;

			for (j=0; j<num_names; j++) {
				if (names[j] == NULL)
					continue;
				/* Hmm. No strequal in samba4 */
				if (strequal(names[j], name)) {
					names[j] = NULL;
					found = True;
					break;
				}
			}

			if (!found) {
				printf("QueryDisplayInfo gave name [%s] that EnumDomainGroups did not\n",
				       name);
				ret = False;
			}
		}
		q2.in.start_idx += q2.out.info.info5.count;
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("QueryDisplayInfo level 5 failed - %s\n",
		       nt_errstr(status));
		ret = False;
	}

	for (i=0; i<num_names; i++) {
		if (names[i] != NULL) {
			printf("EnumDomainGroups gave name [%s] that QueryDisplayInfo did not\n",
			       names[i]);
			ret = False;
		}
	}

	return ret;
}

static BOOL test_DeleteDomainGroup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				   struct policy_handle *group_handle)
{
    	struct samr_DeleteDomainGroup d;
	NTSTATUS status;
	BOOL ret = True;

	printf("Testing DeleteDomainGroup\n");

	d.in.handle = group_handle;
	d.out.handle = group_handle;

	status = dcerpc_samr_DeleteDomainGroup(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteDomainGroup failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_TestPrivateFunctionsDomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
					    struct policy_handle *domain_handle)
{
    	struct samr_TestPrivateFunctionsDomain r;
	NTSTATUS status;
	BOOL ret = True;

	printf("Testing TestPrivateFunctionsDomain\n");

	r.in.handle = domain_handle;

	status = dcerpc_samr_TestPrivateFunctionsDomain(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_NOT_IMPLEMENTED, status)) {
		printf("TestPrivateFunctionsDomain failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_RidToSid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct policy_handle *domain_handle)
{
    	struct samr_RidToSid r;
	NTSTATUS status;
	BOOL ret = True;

	printf("Testing RidToSid\n");

	r.in.handle = domain_handle;
	r.in.rid = 512;

	status = dcerpc_samr_RidToSid(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RidToSid failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_GetBootKeyInformation(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				       struct policy_handle *domain_handle)
{
    	struct samr_GetBootKeyInformation r;
	NTSTATUS status;
	BOOL ret = True;

	printf("Testing GetBootKeyInformation\n");

	r.in.handle = domain_handle;

	status = dcerpc_samr_GetBootKeyInformation(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		/* w2k3 seems to fail this sometimes and pass it sometimes */
		printf("GetBootKeyInformation (ignored) - %s\n", nt_errstr(status));
	}

	return ret;
}

static BOOL test_AddGroupMember(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *domain_handle,
				struct policy_handle *group_handle)
{
	NTSTATUS status;
	struct samr_AddGroupMember r;
	struct samr_DeleteGroupMember d;
	struct samr_QueryGroupMember q;
	struct samr_SetMemberAttributesOfGroup s;
	BOOL ret = True;
	uint32 rid;

	status = test_LookupName(p, mem_ctx, domain_handle, TEST_USERNAME, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	r.in.handle = group_handle;
	r.in.rid = rid;
	r.in.flags = 0; /* ??? */

	printf("Testing AddGroupMember and DeleteGroupMember\n");

	d.in.handle = group_handle;
	d.in.rid = rid;

	status = dcerpc_samr_DeleteGroupMember(p, mem_ctx, &d);
	if (!NT_STATUS_EQUAL(NT_STATUS_MEMBER_NOT_IN_GROUP, status)) {
		printf("DeleteGroupMember gave %s - should be NT_STATUS_MEMBER_NOT_IN_GROUP\n", 
		       nt_errstr(status));
		return False;
	}

	status = dcerpc_samr_AddGroupMember(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddGroupMember failed - %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_samr_AddGroupMember(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_MEMBER_IN_GROUP, status)) {
		printf("AddGroupMember gave %s - should be NT_STATUS_MEMBER_IN_GROUP\n", 
		       nt_errstr(status));
		return False;
	}

	/* this one is quite strange. I am using random inputs in the
	   hope of triggering an error that might give us a clue */
	s.in.handle = group_handle;
	s.in.unknown1 = random();
	s.in.unknown2 = random();

	status = dcerpc_samr_SetMemberAttributesOfGroup(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetMemberAttributesOfGroup failed - %s\n", nt_errstr(status));
		return False;
	}

	q.in.handle = group_handle;

	status = dcerpc_samr_QueryGroupMember(p, mem_ctx, &q);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QueryGroupMember failed - %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_samr_DeleteGroupMember(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteGroupMember failed - %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_samr_AddGroupMember(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddGroupMember failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}


static BOOL test_CreateDomainGroup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				   struct policy_handle *domain_handle, struct policy_handle *group_handle)
{
	NTSTATUS status;
	struct samr_CreateDomainGroup r;
	uint32 rid;
	struct samr_Name name;
	BOOL ret = True;

	init_samr_Name(&name, TEST_GROUPNAME);

	r.in.handle = domain_handle;
	r.in.name = &name;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.group_handle = group_handle;
	r.out.rid = &rid;

	printf("Testing CreateDomainGroup(%s)\n", r.in.name->name);

	status = dcerpc_samr_CreateDomainGroup(p, mem_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("Server refused create of '%s'\n", r.in.name->name);
		ZERO_STRUCTP(group_handle);
		return True;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_GROUP_EXISTS)) {
		if (!test_DeleteGroup_byname(p, mem_ctx, domain_handle, r.in.name->name)) {
			return False;
		}
		status = dcerpc_samr_CreateDomainGroup(p, mem_ctx, &r);
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateDomainGroup failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_AddGroupMember(p, mem_ctx, domain_handle, group_handle)) {
		ret = False;
	}

	if (!test_SetGroupInfo(p, mem_ctx, group_handle)) {
		ret = False;
	}

	return ret;
}


/*
  its not totally clear what this does. It seems to accept any sid you like.
*/
static BOOL test_RemoveMemberFromForeignDomain(struct dcerpc_pipe *p, 
					       TALLOC_CTX *mem_ctx, 
					       struct policy_handle *domain_handle)
{
	NTSTATUS status;
	struct samr_RemoveMemberFromForeignDomain r;

	r.in.handle = domain_handle;
	r.in.sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-12-34-56-78-9");

	status = dcerpc_samr_RemoveMemberFromForeignDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RemoveMemberFromForeignDomain failed - %s\n", nt_errstr(status));
		return False;
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
	struct policy_handle group_handle;
	BOOL ret = True;

	ZERO_STRUCT(user_handle);
	ZERO_STRUCT(alias_handle);
	ZERO_STRUCT(group_handle);
	ZERO_STRUCT(domain_handle);

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

	if (!test_RemoveMemberFromForeignDomain(p, mem_ctx, &domain_handle)) {
		ret = False;
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

	if (!test_CreateDomainGroup(p, mem_ctx, &domain_handle, &group_handle)) {
		ret = False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_QueryDomainInfo(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_QueryDomainInfo2(p, mem_ctx, &domain_handle)) {
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

	if (!test_QueryDisplayInfo2(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_QueryDisplayInfo3(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_GetDisplayEnumerationIndex(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_GetDisplayEnumerationIndex2(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_GroupList(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_TestPrivateFunctionsDomain(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_RidToSid(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!test_GetBootKeyInformation(p, mem_ctx, &domain_handle)) {
		ret = False;
	}

	if (!policy_handle_empty(&user_handle) &&
	    !test_DeleteUser(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	if (!policy_handle_empty(&alias_handle) &&
	    !test_DeleteAlias(p, mem_ctx, &alias_handle)) {
		ret = False;
	}

	if (!policy_handle_empty(&group_handle) &&
	    !test_DeleteDomainGroup(p, mem_ctx, &group_handle)) {
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
	struct samr_Name n2;
	BOOL ret = True;

	printf("Testing LookupDomain(%s)\n", domain->name);

	/* check for correct error codes */
	r.in.handle = handle;
	r.in.domain = &n2;
	n2.name = NULL;

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status)) {
		printf("failed: LookupDomain expected NT_STATUS_INVALID_PARAMETER - %s\n", nt_errstr(status));
		ret = False;
	}

	n2.name = "xxNODOMAINxx";

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_NO_SUCH_DOMAIN, status)) {
		printf("failed: LookupDomain expected NT_STATUS_NO_SUCH_DOMAIN - %s\n", nt_errstr(status));
		ret = False;
	}

	r.in.handle = handle;
	r.in.domain = domain;

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(status));
		ret = False;
	}

	if (!test_GetDomPwInfo(p, mem_ctx, domain)) {
		ret = False;
	}

	if (!test_OpenDomain(p, mem_ctx, handle, r.out.sid)) {
		ret = False;
	}

	return ret;
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

	status = dcerpc_samr_EnumDomains(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumDomains failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}


static BOOL test_Connect(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_Connect r;
	struct samr_Connect2 r2;
	struct samr_Connect3 r3;
	struct samr_Connect4 r4;
	struct samr_Connect5 r5;
	union samr_ConnectInfo info;
	BOOL ret = True;

	printf("testing samr_Connect\n");

	r.in.system_name = 0;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	status = dcerpc_samr_Connect(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect failed - %s\n", nt_errstr(status));
		ret = False;
	}

	printf("testing samr_Connect2\n");

	r2.in.system_name = NULL;
	r2.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r2.out.handle = handle;

	status = dcerpc_samr_Connect2(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect2 failed - %s\n", nt_errstr(status));
		ret = False;
	}

	printf("testing samr_Connect3\n");

	r3.in.system_name = NULL;
	r3.in.unknown = 0;
	r3.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r3.out.handle = handle;

	status = dcerpc_samr_Connect3(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect3 failed - %s\n", nt_errstr(status));
		ret = False;
	}

	printf("testing samr_Connect4\n");

	r4.in.system_name = "";
	r4.in.unknown = 0;
	r4.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r4.out.handle = handle;

	status = dcerpc_samr_Connect4(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect4 failed - %s\n", nt_errstr(status));
		ret = False;
	}

	printf("testing samr_Connect5\n");

	info.info1.unknown1 = 0;
	info.info1.unknown2 = 0;

	r5.in.system_name = "";
	r5.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r5.in.level = 1;
	r5.in.info = &info;
	r5.out.info = &info;
	r5.out.handle = handle;

	status = dcerpc_samr_Connect5(p, mem_ctx, &r5);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect5 failed - %s\n", nt_errstr(status));
		ret = False;
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

	if (!test_Connect(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumDomains(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_SetDsrmPassword(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_Shutdown(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_Close(p, mem_ctx, &handle)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}

