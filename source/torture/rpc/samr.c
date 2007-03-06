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
#include "torture/torture.h"
#include "system/time.h"
#include "librpc/gen_ndr/lsa.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "lib/crypto/crypto.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/security/security.h"
#include "torture/rpc/rpc.h"

#define TEST_ACCOUNT_NAME "samrtorturetest"
#define TEST_ALIASNAME "samrtorturetestalias"
#define TEST_GROUPNAME "samrtorturetestgroup"
#define TEST_MACHINENAME "samrtestmach$"
#define TEST_DOMAINNAME "samrtestdom$"

enum torture_samr_choice {
	TORTURE_SAMR_PASSWORDS,
	TORTURE_SAMR_USER_ATTRIBUTES,
	TORTURE_SAMR_OTHER
};

static BOOL test_QueryUserInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle);

static BOOL test_QueryUserInfo2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle);

static BOOL test_QueryAliasInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle);

static BOOL test_ChangePassword(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				const char *acct_name, 
				struct policy_handle *domain_handle, char **password);

static void init_lsa_String(struct lsa_String *string, const char *s)
{
	string->string = s;
}

BOOL test_samr_handle_Close(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
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

	if (!lp_parm_bool(-1, "torture", "dangerous", False)) {
		printf("samr_Shutdown disabled - enable dangerous tests to use\n");
		return True;
	}

	r.in.connect_handle = handle;

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
	struct lsa_String string;
	struct samr_Password hash;

	if (!lp_parm_bool(-1, "torture", "dangerous", False)) {
		printf("samr_SetDsrmPassword disabled - enable dangerous tests to use\n");
		return True;
	}

	E_md4hash("TeSTDSRM123", hash.hash);

	init_lsa_String(&string, "Administrator");

	r.in.name = &string;
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

	if (r.out.sdbuf == NULL) {
		return False;
	}

	s.in.handle = handle;
	s.in.sec_info = 7;
	s.in.sdbuf = r.out.sdbuf;

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping SetSecurity test against Samba4\n");
		return True;
	}

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
			     struct policy_handle *handle, uint32_t base_acct_flags,
			     const char *base_account_name)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	struct samr_SetUserInfo2 s2;
	struct samr_QueryUserInfo q;
	struct samr_QueryUserInfo q0;
	union samr_UserInfo u;
	BOOL ret = True;
	const char *test_account_name;

	uint32_t user_extra_flags = 0;
	if (base_acct_flags == ACB_NORMAL) {
		/* When created, accounts are expired by default */
		user_extra_flags = ACB_PW_EXPIRED;
	}

	s.in.user_handle = handle;
	s.in.info = &u;

	s2.in.user_handle = handle;
	s2.in.info = &u;

	q.in.user_handle = handle;
	q.out.info = &u;
	q0 = q;

#define TESTCALL(call, r) \
		status = dcerpc_samr_ ##call(p, mem_ctx, &r); \
		if (!NT_STATUS_IS_OK(status)) { \
			printf(#call " level %u failed - %s (%s)\n", \
			       r.in.level, nt_errstr(status), __location__); \
			ret = False; \
			break; \
		}

#define STRING_EQUAL(s1, s2, field) \
		if ((s1 && !s2) || (s2 && !s1) || strcmp(s1, s2)) { \
			printf("Failed to set %s to '%s' (%s)\n", \
			       #field, s2, __location__); \
			ret = False; \
			break; \
		}

#define INT_EQUAL(i1, i2, field) \
		if (i1 != i2) { \
			printf("Failed to set %s to 0x%x - got 0x%x (%s)\n", \
			       #field, i2, i1, __location__); \
			ret = False; \
			break; \
		}

#define TEST_USERINFO_STRING(lvl1, field1, lvl2, field2, value, fpval) do { \
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
		init_lsa_String(&u.info ## lvl1.field1, value); \
		TESTCALL(SetUserInfo, s) \
		TESTCALL(SetUserInfo2, s2) \
		init_lsa_String(&u.info ## lvl1.field1, ""); \
		TESTCALL(QueryUserInfo, q); \
		u = *q.out.info; \
		STRING_EQUAL(u.info ## lvl1.field1.string, value, field1); \
		q.in.level = lvl2; \
		TESTCALL(QueryUserInfo, q) \
		u = *q.out.info; \
		STRING_EQUAL(u.info ## lvl2.field2.string, value, field2); \
	} while (0)

#define TEST_USERINFO_INT_EXP(lvl1, field1, lvl2, field2, value, exp_value, fpval) do { \
		printf("field test %d/%s vs %d/%s\n", lvl1, #field1, lvl2, #field2); \
		q.in.level = lvl1; \
		TESTCALL(QueryUserInfo, q) \
		s.in.level = lvl1; \
		s2.in.level = lvl1; \
		u = *q.out.info; \
		if (lvl1 == 21) { \
			uint8_t *bits = u.info21.logon_hours.bits; \
			ZERO_STRUCT(u.info21); \
			if (fpval == SAMR_FIELD_LOGON_HOURS) { \
				u.info21.logon_hours.units_per_week = 168; \
				u.info21.logon_hours.bits = bits; \
			} \
			u.info21.fields_present = fpval; \
		} \
		u.info ## lvl1.field1 = value; \
		TESTCALL(SetUserInfo, s) \
		TESTCALL(SetUserInfo2, s2) \
		u.info ## lvl1.field1 = 0; \
		TESTCALL(QueryUserInfo, q); \
		u = *q.out.info; \
		INT_EQUAL(u.info ## lvl1.field1, exp_value, field1); \
		q.in.level = lvl2; \
		TESTCALL(QueryUserInfo, q) \
		u = *q.out.info; \
		INT_EQUAL(u.info ## lvl2.field2, exp_value, field1); \
	} while (0)

#define TEST_USERINFO_INT(lvl1, field1, lvl2, field2, value, fpval) do { \
        TEST_USERINFO_INT_EXP(lvl1, field1, lvl2, field2, value, value, fpval); \
        } while (0)

	q0.in.level = 12;
	do { TESTCALL(QueryUserInfo, q0) } while (0);

	TEST_USERINFO_STRING(2, comment,  1, comment, "xx2-1 comment", 0);
	TEST_USERINFO_STRING(2, comment, 21, comment, "xx2-21 comment", 0);
	TEST_USERINFO_STRING(21, comment, 21, comment, "xx21-21 comment", 
			   SAMR_FIELD_COMMENT);

	test_account_name = talloc_asprintf(mem_ctx, "%sxx7-1", base_account_name);
	TEST_USERINFO_STRING(7, account_name,  1, account_name, base_account_name, 0);
	test_account_name = talloc_asprintf(mem_ctx, "%sxx7-3", base_account_name);
	TEST_USERINFO_STRING(7, account_name,  3, account_name, base_account_name, 0);
	test_account_name = talloc_asprintf(mem_ctx, "%sxx7-5", base_account_name);
	TEST_USERINFO_STRING(7, account_name,  5, account_name, base_account_name, 0);
	test_account_name = talloc_asprintf(mem_ctx, "%sxx7-6", base_account_name);
	TEST_USERINFO_STRING(7, account_name,  6, account_name, base_account_name, 0);
	test_account_name = talloc_asprintf(mem_ctx, "%sxx7-7", base_account_name);
	TEST_USERINFO_STRING(7, account_name,  7, account_name, base_account_name, 0);
	test_account_name = talloc_asprintf(mem_ctx, "%sxx7-21", base_account_name);
	TEST_USERINFO_STRING(7, account_name, 21, account_name, base_account_name, 0);
	test_account_name = base_account_name;
	TEST_USERINFO_STRING(21, account_name, 21, account_name, base_account_name, 
			   SAMR_FIELD_ACCOUNT_NAME);

	TEST_USERINFO_STRING(6, full_name,  1, full_name, "xx6-1 full_name", 0);
	TEST_USERINFO_STRING(6, full_name,  3, full_name, "xx6-3 full_name", 0);
	TEST_USERINFO_STRING(6, full_name,  5, full_name, "xx6-5 full_name", 0);
	TEST_USERINFO_STRING(6, full_name,  6, full_name, "xx6-6 full_name", 0);
	TEST_USERINFO_STRING(6, full_name,  8, full_name, "xx6-8 full_name", 0);
	TEST_USERINFO_STRING(6, full_name, 21, full_name, "xx6-21 full_name", 0);
	TEST_USERINFO_STRING(8, full_name, 21, full_name, "xx8-21 full_name", 0);
	TEST_USERINFO_STRING(21, full_name, 21, full_name, "xx21-21 full_name", 
			   SAMR_FIELD_FULL_NAME);

	TEST_USERINFO_STRING(11, logon_script, 3, logon_script, "xx11-3 logon_script", 0);
	TEST_USERINFO_STRING(11, logon_script, 5, logon_script, "xx11-5 logon_script", 0);
	TEST_USERINFO_STRING(11, logon_script, 21, logon_script, "xx11-21 logon_script", 0);
	TEST_USERINFO_STRING(21, logon_script, 21, logon_script, "xx21-21 logon_script", 
			   SAMR_FIELD_LOGON_SCRIPT);

	TEST_USERINFO_STRING(12, profile_path,  3, profile_path, "xx12-3 profile_path", 0);
	TEST_USERINFO_STRING(12, profile_path,  5, profile_path, "xx12-5 profile_path", 0);
	TEST_USERINFO_STRING(12, profile_path, 21, profile_path, "xx12-21 profile_path", 0);
	TEST_USERINFO_STRING(21, profile_path, 21, profile_path, "xx21-21 profile_path", 
			   SAMR_FIELD_PROFILE_PATH);

	TEST_USERINFO_STRING(10, home_directory, 3, home_directory, "xx10-3 home_directory", 0);
	TEST_USERINFO_STRING(10, home_directory, 5, home_directory, "xx10-5 home_directory", 0);
	TEST_USERINFO_STRING(10, home_directory, 21, home_directory, "xx10-21 home_directory", 0);
	TEST_USERINFO_STRING(21, home_directory, 21, home_directory, "xx21-21 home_directory",
			     SAMR_FIELD_HOME_DIRECTORY);
	TEST_USERINFO_STRING(21, home_directory, 10, home_directory, "xx21-10 home_directory",
			     SAMR_FIELD_HOME_DIRECTORY);

	TEST_USERINFO_STRING(10, home_drive, 3, home_drive, "xx10-3 home_drive", 0);
	TEST_USERINFO_STRING(10, home_drive, 5, home_drive, "xx10-5 home_drive", 0);
	TEST_USERINFO_STRING(10, home_drive, 21, home_drive, "xx10-21 home_drive", 0);
	TEST_USERINFO_STRING(21, home_drive, 21, home_drive, "xx21-21 home_drive",
			     SAMR_FIELD_HOME_DRIVE);
	TEST_USERINFO_STRING(21, home_drive, 10, home_drive, "xx21-10 home_drive",
			     SAMR_FIELD_HOME_DRIVE);
	
	TEST_USERINFO_STRING(13, description,  1, description, "xx13-1 description", 0);
	TEST_USERINFO_STRING(13, description,  5, description, "xx13-5 description", 0);
	TEST_USERINFO_STRING(13, description, 21, description, "xx13-21 description", 0);
	TEST_USERINFO_STRING(21, description, 21, description, "xx21-21 description", 
			   SAMR_FIELD_DESCRIPTION);

	TEST_USERINFO_STRING(14, workstations,  3, workstations, "14workstation3", 0);
	TEST_USERINFO_STRING(14, workstations,  5, workstations, "14workstation4", 0);
	TEST_USERINFO_STRING(14, workstations, 21, workstations, "14workstation21", 0);
	TEST_USERINFO_STRING(21, workstations, 21, workstations, "21workstation21", 
			   SAMR_FIELD_WORKSTATIONS);

	TEST_USERINFO_STRING(20, parameters, 21, parameters, "xx20-21 parameters", 0);
	TEST_USERINFO_STRING(21, parameters, 21, parameters, "xx21-21 parameters", 
			   SAMR_FIELD_PARAMETERS);

	TEST_USERINFO_INT(2, country_code, 21, country_code, __LINE__, 0);
	TEST_USERINFO_INT(21, country_code, 21, country_code, __LINE__, 
			  SAMR_FIELD_COUNTRY_CODE);

	TEST_USERINFO_INT(2, code_page, 21, code_page, __LINE__, 0);
	TEST_USERINFO_INT(21, code_page, 21, code_page, __LINE__, 
			  SAMR_FIELD_CODE_PAGE);

	TEST_USERINFO_INT(4, logon_hours.bits[3],  3, logon_hours.bits[3], 1, 0);
	TEST_USERINFO_INT(4, logon_hours.bits[3],  5, logon_hours.bits[3], 2, 0);
	TEST_USERINFO_INT(4, logon_hours.bits[3], 21, logon_hours.bits[3], 3, 0);
	TEST_USERINFO_INT(21, logon_hours.bits[3], 21, logon_hours.bits[3], 4, 
			  SAMR_FIELD_LOGON_HOURS);

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping Set Account Flag tests against Samba4\n");
		return ret;
	}

	TEST_USERINFO_INT_EXP(16, acct_flags, 5, acct_flags, 
			      (base_acct_flags  | ACB_DISABLED | ACB_HOMDIRREQ), 
			      (base_acct_flags  | ACB_DISABLED | ACB_HOMDIRREQ | user_extra_flags), 
			      0);
	TEST_USERINFO_INT_EXP(16, acct_flags, 5, acct_flags, 
			      (base_acct_flags  | ACB_DISABLED), 
			      (base_acct_flags  | ACB_DISABLED | user_extra_flags), 
			      0);
	
	/* Setting PWNOEXP clears the magic ACB_PW_EXPIRED flag */
	TEST_USERINFO_INT_EXP(16, acct_flags, 5, acct_flags, 
			      (base_acct_flags  | ACB_DISABLED | ACB_PWNOEXP), 
			      (base_acct_flags  | ACB_DISABLED | ACB_PWNOEXP), 
			      0);
	TEST_USERINFO_INT_EXP(16, acct_flags, 21, acct_flags, 
			      (base_acct_flags | ACB_DISABLED | ACB_HOMDIRREQ), 
			      (base_acct_flags | ACB_DISABLED | ACB_HOMDIRREQ | user_extra_flags), 
			      0);


	/* The 'autolock' flag doesn't stick - check this */
	TEST_USERINFO_INT_EXP(16, acct_flags, 21, acct_flags, 
			      (base_acct_flags | ACB_DISABLED | ACB_AUTOLOCK), 
			      (base_acct_flags | ACB_DISABLED | user_extra_flags), 
			      0);
#if 0
	/* Removing the 'disabled' flag doesn't stick - check this */
	TEST_USERINFO_INT_EXP(16, acct_flags, 21, acct_flags, 
			      (base_acct_flags), 
			      (base_acct_flags | ACB_DISABLED | user_extra_flags), 
			      0);
#endif
	/* The 'store plaintext' flag does stick */
	TEST_USERINFO_INT_EXP(16, acct_flags, 21, acct_flags, 
			      (base_acct_flags | ACB_DISABLED | ACB_ENC_TXT_PWD_ALLOWED), 
			      (base_acct_flags | ACB_DISABLED | ACB_ENC_TXT_PWD_ALLOWED | user_extra_flags), 
			      0);
	/* The 'use DES' flag does stick */
	TEST_USERINFO_INT_EXP(16, acct_flags, 21, acct_flags, 
			      (base_acct_flags | ACB_DISABLED | ACB_USE_DES_KEY_ONLY), 
			      (base_acct_flags | ACB_DISABLED | ACB_USE_DES_KEY_ONLY | user_extra_flags), 
			      0);
	/* The 'don't require kerberos pre-authentication flag does stick */
	TEST_USERINFO_INT_EXP(16, acct_flags, 21, acct_flags, 
			      (base_acct_flags | ACB_DISABLED | ACB_DONT_REQUIRE_PREAUTH), 
			      (base_acct_flags | ACB_DISABLED | ACB_DONT_REQUIRE_PREAUTH | user_extra_flags), 
			      0);
	/* The 'no kerberos PAC required' flag sticks */
	TEST_USERINFO_INT_EXP(16, acct_flags, 21, acct_flags, 
			      (base_acct_flags | ACB_DISABLED | ACB_NO_AUTH_DATA_REQD), 
			      (base_acct_flags | ACB_DISABLED | ACB_NO_AUTH_DATA_REQD | user_extra_flags), 
			      0);

	TEST_USERINFO_INT_EXP(21, acct_flags, 21, acct_flags, 
			      (base_acct_flags | ACB_DISABLED), 
			      (base_acct_flags | ACB_DISABLED | user_extra_flags), 
			      SAMR_FIELD_ACCT_FLAGS);

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
static char *samr_rand_pass(TALLOC_CTX *mem_ctx, int min_len)
{
	size_t len = MAX(8, min_len) + (random() % 6);
	char *s = generate_random_str(mem_ctx, len);
	printf("Generated password '%s'\n", s);
	return s;
}

/*
  generate a random password for password change tests (fixed length)
*/
static char *samr_rand_pass_fixed_len(TALLOC_CTX *mem_ctx, int len)
{
	char *s = generate_random_str(mem_ctx, len);
	printf("Generated password '%s'\n", s);
	return s;
}

static BOOL test_SetUserPass(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	BOOL ret = True;
	DATA_BLOB session_key;
	char *newpass;
	struct samr_GetUserPwInfo pwp;
	int policy_min_pw_len = 0;
	pwp.in.user_handle = handle;

	status = dcerpc_samr_GetUserPwInfo(p, mem_ctx, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}
	newpass = samr_rand_pass(mem_ctx, policy_min_pw_len);

	s.in.user_handle = handle;
	s.in.info = &u;
	s.in.level = 24;

	encode_pw_buffer(u.info24.password.data, newpass, STR_UNICODE);
	/* w2k3 ignores this length */
	u.info24.pw_len = strlen_m(newpass) * 2;

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	arcfour_crypt_blob(u.info24.password.data, 516, &session_key);

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
				struct policy_handle *handle, uint32_t fields_present,
				char **password)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	BOOL ret = True;
	DATA_BLOB session_key;
	char *newpass;
	struct samr_GetUserPwInfo pwp;
	int policy_min_pw_len = 0;
	pwp.in.user_handle = handle;

	status = dcerpc_samr_GetUserPwInfo(p, mem_ctx, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}
	newpass = samr_rand_pass(mem_ctx, policy_min_pw_len);

	s.in.user_handle = handle;
	s.in.info = &u;
	s.in.level = 23;

	ZERO_STRUCT(u);

	u.info23.info.fields_present = fields_present;

	encode_pw_buffer(u.info23.password.data, newpass, STR_UNICODE);

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	arcfour_crypt_blob(u.info23.password.data, 516, &session_key);

	printf("Testing SetUserInfo level 23 (set password)\n");

	status = dcerpc_samr_SetUserInfo(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u failed - %s\n",
		       s.in.level, nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	encode_pw_buffer(u.info23.password.data, newpass, STR_UNICODE);

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	/* This should break the key nicely */
	session_key.length--;
	arcfour_crypt_blob(u.info23.password.data, 516, &session_key);

	printf("Testing SetUserInfo level 23 (set password) with wrong password\n");

	status = dcerpc_samr_SetUserInfo(p, mem_ctx, &s);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		printf("SetUserInfo level %u should have failed with WRONG_PASSWORD- %s\n",
		       s.in.level, nt_errstr(status));
		ret = False;
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
	uint8_t confounder[16];
	char *newpass;
	struct MD5Context ctx;
	struct samr_GetUserPwInfo pwp;
	int policy_min_pw_len = 0;
	pwp.in.user_handle = handle;

	status = dcerpc_samr_GetUserPwInfo(p, mem_ctx, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}
	newpass = samr_rand_pass(mem_ctx, policy_min_pw_len);

	s.in.user_handle = handle;
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

	generate_random_buffer((uint8_t *)confounder, 16);

	MD5Init(&ctx);
	MD5Update(&ctx, confounder, 16);
	MD5Update(&ctx, session_key.data, session_key.length);
	MD5Final(confounded_session_key.data, &ctx);

	arcfour_crypt_blob(u.info26.password.data, 516, &confounded_session_key);
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

	/* This should break the key nicely */
	confounded_session_key.data[0]++;

	arcfour_crypt_blob(u.info26.password.data, 516, &confounded_session_key);
	memcpy(&u.info26.password.data[516], confounder, 16);

	printf("Testing SetUserInfo level 26 (set password ex) with wrong session key\n");

	status = dcerpc_samr_SetUserInfo(p, mem_ctx, &s);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		printf("SetUserInfo level %u should have failed with WRONG_PASSWORD- %s\n",
		       s.in.level, nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	return ret;
}

static BOOL test_SetUserPass_25(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle, uint32_t fields_present,
				char **password)
{
	NTSTATUS status;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	BOOL ret = True;
	DATA_BLOB session_key;
	DATA_BLOB confounded_session_key = data_blob_talloc(mem_ctx, NULL, 16);
	struct MD5Context ctx;
	uint8_t confounder[16];
	char *newpass;
	struct samr_GetUserPwInfo pwp;
	int policy_min_pw_len = 0;
	pwp.in.user_handle = handle;

	status = dcerpc_samr_GetUserPwInfo(p, mem_ctx, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}
	newpass = samr_rand_pass(mem_ctx, policy_min_pw_len);

	s.in.user_handle = handle;
	s.in.info = &u;
	s.in.level = 25;

	ZERO_STRUCT(u);

	u.info25.info.fields_present = fields_present;

	encode_pw_buffer(u.info25.password.data, newpass, STR_UNICODE);

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	generate_random_buffer((uint8_t *)confounder, 16);

	MD5Init(&ctx);
	MD5Update(&ctx, confounder, 16);
	MD5Update(&ctx, session_key.data, session_key.length);
	MD5Final(confounded_session_key.data, &ctx);

	arcfour_crypt_blob(u.info25.password.data, 516, &confounded_session_key);
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

	/* This should break the key nicely */
	confounded_session_key.data[0]++;

	arcfour_crypt_blob(u.info25.password.data, 516, &confounded_session_key);
	memcpy(&u.info25.password.data[516], confounder, 16);

	printf("Testing SetUserInfo level 25 (set password ex) with wrong session key\n");

	status = dcerpc_samr_SetUserInfo(p, mem_ctx, &s);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		printf("SetUserInfo level %u should have failed with WRONG_PASSWORD- %s\n",
		       s.in.level, nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_SetAliasInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_SetAliasInfo r;
	struct samr_QueryAliasInfo q;
	uint16_t levels[] = {2, 3};
	int i;
	BOOL ret = True;

	/* Ignoring switch level 1, as that includes the number of members for the alias
	 * and setting this to a wrong value might have negative consequences
	 */

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing SetAliasInfo level %u\n", levels[i]);

		r.in.alias_handle = handle;
		r.in.level = levels[i];
		r.in.info  = talloc(mem_ctx, union samr_AliasInfo);
		switch (r.in.level) {
		    case ALIASINFONAME: init_lsa_String(&r.in.info->name,TEST_ALIASNAME); break;
		    case ALIASINFODESCRIPTION: init_lsa_String(&r.in.info->description,
				"Test Description, should test I18N as well"); break;
		}

		status = dcerpc_samr_SetAliasInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetAliasInfo level %u failed - %s\n",
			       levels[i], nt_errstr(status));
			ret = False;
		}

		q.in.alias_handle = handle;
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

	r.in.user_handle = user_handle;

	status = dcerpc_samr_GetGroupsForUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetGroupsForUser failed - %s\n",nt_errstr(status));
		ret = False;
	}

	return ret;

}

static BOOL test_GetDomPwInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct lsa_String *domain_name)
{
	NTSTATUS status;
	struct samr_GetDomPwInfo r;
	BOOL ret = True;

	r.in.domain_name = domain_name;
	printf("Testing GetDomPwInfo with name %s\n", r.in.domain_name->string);

	status = dcerpc_samr_GetDomPwInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetDomPwInfo failed - %s\n", nt_errstr(status));
		ret = False;
	}

	r.in.domain_name->string = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	printf("Testing GetDomPwInfo with name %s\n", r.in.domain_name->string);

	status = dcerpc_samr_GetDomPwInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetDomPwInfo failed - %s\n", nt_errstr(status));
		ret = False;
	}

	r.in.domain_name->string = "\\\\__NONAME__";
	printf("Testing GetDomPwInfo with name %s\n", r.in.domain_name->string);

	status = dcerpc_samr_GetDomPwInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetDomPwInfo failed - %s\n", nt_errstr(status));
		ret = False;
	}

	r.in.domain_name->string = "\\\\Builtin";
	printf("Testing GetDomPwInfo with name %s\n", r.in.domain_name->string);

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

	r.in.user_handle = handle;

	status = dcerpc_samr_GetUserPwInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetUserPwInfo failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static NTSTATUS test_LookupName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				struct policy_handle *domain_handle, const char *name,
				uint32_t *rid)
{
	NTSTATUS status;
	struct samr_LookupNames n;
	struct lsa_String sname[2];

	init_lsa_String(&sname[0], name);

	n.in.domain_handle = domain_handle;
	n.in.num_names = 1;
	n.in.names = sname;
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (NT_STATUS_IS_OK(status)) {
		*rid = n.out.rids.ids[0];
	} else {
		return status;
	}

	init_lsa_String(&sname[1], "xxNONAMExx");
	n.in.num_names = 2;
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (!NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupNames[2] failed - %s\n", nt_errstr(status));		
		return status;
	}

	init_lsa_String(&sname[1], "xxNONAMExx");
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
	uint32_t rid;

	status = test_LookupName(p, mem_ctx, domain_handle, name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	r.in.domain_handle = domain_handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.user_handle = user_handle;
	status = dcerpc_samr_OpenUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenUser_byname(%s -> %d) failed - %s\n", name, rid, nt_errstr(status));
	}

	return status;
}

#if 0
static BOOL test_ChangePasswordNT3(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				   struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_ChangePasswordUser r;
	BOOL ret = True;
	struct samr_Password hash1, hash2, hash3, hash4, hash5, hash6;
	struct policy_handle user_handle;
	char *oldpass = "test";
	char *newpass = "test2";
	uint8_t old_nt_hash[16], new_nt_hash[16];
	uint8_t old_lm_hash[16], new_lm_hash[16];

	status = test_OpenUser_byname(p, mem_ctx, handle, "testuser", &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	printf("Testing ChangePasswordUser for user 'testuser'\n");

	printf("old password: %s\n", oldpass);
	printf("new password: %s\n", newpass);

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
	}

	if (!test_samr_handle_Close(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	return ret;
}
#endif

static BOOL test_ChangePasswordUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				    const char *acct_name, 
				    struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_ChangePasswordUser r;
	BOOL ret = True;
	struct samr_Password hash1, hash2, hash3, hash4, hash5, hash6;
	struct policy_handle user_handle;
	char *oldpass;
	uint8_t old_nt_hash[16], new_nt_hash[16];
	uint8_t old_lm_hash[16], new_lm_hash[16];
	BOOL changed = True;

	char *newpass;
	struct samr_GetUserPwInfo pwp;
	int policy_min_pw_len = 0;

	status = test_OpenUser_byname(p, mem_ctx, handle, acct_name, &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	pwp.in.user_handle = &user_handle;

	status = dcerpc_samr_GetUserPwInfo(p, mem_ctx, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}
	newpass = samr_rand_pass(mem_ctx, policy_min_pw_len);

	printf("Testing ChangePasswordUser\n");

	if (!*password) {
		printf("Failing ChangePasswordUser as old password was NULL.  Previous test failed?\n");
		return False;
	}

	oldpass = *password;

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

	r.in.user_handle = &user_handle;
	r.in.lm_present = 1;
	r.in.old_lm_crypted = &hash1;
	r.in.new_lm_crypted = &hash2;
	r.in.nt_present = 1;
	r.in.old_nt_crypted = &hash3;
	r.in.new_nt_crypted = &hash4;
	r.in.cross1_present = 1;
	r.in.nt_cross = &hash5;
	r.in.cross2_present = 0;
	r.in.lm_cross = NULL;

	status = dcerpc_samr_ChangePasswordUser(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED)) {
		printf("ChangePasswordUser failed: expected NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED, got %s\n", nt_errstr(status));
		ret = False;
	}

	
	r.in.user_handle = &user_handle;
	r.in.lm_present = 1;
	r.in.old_lm_crypted = &hash1;
	r.in.new_lm_crypted = &hash2;
	r.in.nt_present = 1;
	r.in.old_nt_crypted = &hash3;
	r.in.new_nt_crypted = &hash4;
	r.in.cross1_present = 0;
	r.in.nt_cross = NULL;
	r.in.cross2_present = 1;
	r.in.lm_cross = &hash6;

	status = dcerpc_samr_ChangePasswordUser(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED)) {
		printf("ChangePasswordUser failed: expected NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED, got %s\n", nt_errstr(status));
		ret = False;
	}

	r.in.user_handle = &user_handle;
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
	if (NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION)) {
		printf("ChangePasswordUser returned: %s perhaps min password age? (not fatal)\n", nt_errstr(status));
	} else 	if (!NT_STATUS_IS_OK(status)) {
		printf("ChangePasswordUser failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		changed = True;
		*password = newpass;
	}

	r.in.user_handle = &user_handle;
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

	if (changed) {
		status = dcerpc_samr_ChangePasswordUser(p, mem_ctx, &r);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
			printf("ChangePasswordUser failed: expected NT_STATUS_WRONG_PASSWORD because we already changed the password, got %s\n", nt_errstr(status));
			ret = False;
		}
	}

	if (!test_samr_handle_Close(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	return ret;
}


static BOOL test_OemChangePasswordUser2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
					const char *acct_name,
					struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_OemChangePasswordUser2 r;
	BOOL ret = True;
	struct samr_Password lm_verifier;
	struct samr_CryptPassword lm_pass;
	struct lsa_AsciiString server, account, account_bad;
	char *oldpass;
	char *newpass;
	uint8_t old_lm_hash[16], new_lm_hash[16];

	struct samr_GetDomPwInfo dom_pw_info;
	int policy_min_pw_len = 0;

	struct lsa_String domain_name;

	domain_name.string = "";
	dom_pw_info.in.domain_name = &domain_name;

	printf("Testing OemChangePasswordUser2\n");

	if (!*password) {
		printf("Failing OemChangePasswordUser2 as old password was NULL.  Previous test failed?\n");
		return False;
	}

	oldpass = *password;

	status = dcerpc_samr_GetDomPwInfo(p, mem_ctx, &dom_pw_info);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = dom_pw_info.out.info.min_password_length;
	}

	newpass = samr_rand_pass(mem_ctx, policy_min_pw_len);

	server.string = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	account.string = acct_name;

	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	encode_pw_buffer(lm_pass.data, newpass, STR_ASCII);
	arcfour_crypt(lm_pass.data, old_lm_hash, 516);
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	r.in.server = &server;
	r.in.account = &account;
	r.in.password = &lm_pass;
	r.in.hash = &lm_verifier;

	/* Break the verification */
	lm_verifier.hash[0]++;

	status = dcerpc_samr_OemChangePasswordUser2(p, mem_ctx, &r);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		printf("ChangePasswordUser3 failed, should have returned WRONG_PASSWORD (or at least 'PASSWORD_RESTRICTON') for invalid password verifier - %s\n",
			nt_errstr(status));
		ret = False;
	}

	encode_pw_buffer(lm_pass.data, newpass, STR_ASCII);
	/* Break the old password */
	old_lm_hash[0]++;
	arcfour_crypt(lm_pass.data, old_lm_hash, 516);
	/* unbreak it for the next operation */
	old_lm_hash[0]--;
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	r.in.server = &server;
	r.in.account = &account;
	r.in.password = &lm_pass;
	r.in.hash = &lm_verifier;

	status = dcerpc_samr_OemChangePasswordUser2(p, mem_ctx, &r);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		printf("ChangePasswordUser3 failed, should have returned WRONG_PASSWORD (or at least 'PASSWORD_RESTRICTON') for invalidly encrpted password - %s\n",
			nt_errstr(status));
		ret = False;
	}

	encode_pw_buffer(lm_pass.data, newpass, STR_ASCII);
	arcfour_crypt(lm_pass.data, old_lm_hash, 516);

	r.in.server = &server;
	r.in.account = &account;
	r.in.password = &lm_pass;
	r.in.hash = NULL;

	status = dcerpc_samr_OemChangePasswordUser2(p, mem_ctx, &r);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		printf("ChangePasswordUser3 failed, should have returned WRONG_PASSWORD (or at least 'PASSWORD_RESTRICTON') for no supplied validation hash - %s\n",
			nt_errstr(status));
		ret = False;
	}

	/* This shouldn't be a valid name */
	account_bad.string = TEST_ACCOUNT_NAME "XX";
	r.in.account = &account_bad;

	status = dcerpc_samr_OemChangePasswordUser2(p, mem_ctx, &r);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		printf("ChangePasswordUser3 failed, should have returned WRONG_PASSWORD for invalid user - %s\n",
			nt_errstr(status));
		ret = False;
	}

	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	encode_pw_buffer(lm_pass.data, newpass, STR_ASCII);
	arcfour_crypt(lm_pass.data, old_lm_hash, 516);
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	r.in.server = &server;
	r.in.account = &account;
	r.in.password = &lm_pass;
	r.in.hash = &lm_verifier;

	status = dcerpc_samr_OemChangePasswordUser2(p, mem_ctx, &r);
	if (NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION)) {
		printf("OemChangePasswordUser2 returned: %s perhaps min password age? (not fatal)\n", nt_errstr(status));
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("OemChangePasswordUser2 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	return ret;
}


static BOOL test_ChangePasswordUser2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				     const char *acct_name,
				     struct policy_handle *handle, char **password)
{
	NTSTATUS status;
	struct samr_ChangePasswordUser2 r;
	BOOL ret = True;
	struct lsa_String server, account;
	struct samr_CryptPassword nt_pass, lm_pass;
	struct samr_Password nt_verifier, lm_verifier;
	char *oldpass;
	char *newpass;
	uint8_t old_nt_hash[16], new_nt_hash[16];
	uint8_t old_lm_hash[16], new_lm_hash[16];

	struct samr_GetDomPwInfo dom_pw_info;
	int policy_min_pw_len = 0;

	struct lsa_String domain_name;


	domain_name.string = "";
	dom_pw_info.in.domain_name = &domain_name;

	printf("Testing ChangePasswordUser2\n");

	if (!*password) {
		printf("Failing ChangePasswordUser3 as old password was NULL.  Previous test failed?\n");
		return False;
	}
	oldpass = *password;

	status = dcerpc_samr_GetDomPwInfo(p, mem_ctx, &dom_pw_info);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = dom_pw_info.out.info.min_password_length;
	}

	newpass = samr_rand_pass(mem_ctx, policy_min_pw_len);

	server.string = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	init_lsa_String(&account, acct_name);

	E_md4hash(oldpass, old_nt_hash);
	E_md4hash(newpass, new_nt_hash);

	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	encode_pw_buffer(lm_pass.data, newpass, STR_ASCII|STR_TERMINATE);
	arcfour_crypt(lm_pass.data, old_lm_hash, 516);
	E_old_pw_hash(new_nt_hash, old_lm_hash, lm_verifier.hash);

	encode_pw_buffer(nt_pass.data, newpass, STR_UNICODE);
	arcfour_crypt(nt_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, nt_verifier.hash);

	r.in.server = &server;
	r.in.account = &account;
	r.in.nt_password = &nt_pass;
	r.in.nt_verifier = &nt_verifier;
	r.in.lm_change = 1;
	r.in.lm_password = &lm_pass;
	r.in.lm_verifier = &lm_verifier;

	status = dcerpc_samr_ChangePasswordUser2(p, mem_ctx, &r);
	if (NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION)) {
		printf("ChangePasswordUser2 returned: %s perhaps min password age? (not fatal)\n", nt_errstr(status));
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("ChangePasswordUser2 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		*password = newpass;
	}

	return ret;
}


BOOL test_ChangePasswordUser3(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      const char *account_string,
			      int policy_min_pw_len,
			      char **password,
			      const char *newpass,
			      NTTIME last_password_change,
			      BOOL handle_reject_reason)
{
	NTSTATUS status;
	struct samr_ChangePasswordUser3 r;
	BOOL ret = True;
	struct lsa_String server, account, account_bad;
	struct samr_CryptPassword nt_pass, lm_pass;
	struct samr_Password nt_verifier, lm_verifier;
	char *oldpass;
	uint8_t old_nt_hash[16], new_nt_hash[16];
	uint8_t old_lm_hash[16], new_lm_hash[16];
	NTTIME t;

	printf("Testing ChangePasswordUser3\n");

	if (newpass == NULL) {
		do {
			if (policy_min_pw_len == 0) {
				newpass = samr_rand_pass(mem_ctx, policy_min_pw_len);
			} else {
				newpass = samr_rand_pass_fixed_len(mem_ctx, policy_min_pw_len);
			}
		} while (check_password_quality(newpass) == False);
	} else {
		printf("Using password '%s'\n", newpass);
	}

	if (!*password) {
		printf("Failing ChangePasswordUser3 as old password was NULL.  Previous test failed?\n");
		return False;
	}

	oldpass = *password;
	server.string = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	init_lsa_String(&account, account_string);

	E_md4hash(oldpass, old_nt_hash);
	E_md4hash(newpass, new_nt_hash);

	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	encode_pw_buffer(lm_pass.data, newpass, STR_UNICODE);
	arcfour_crypt(lm_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_lm_hash, lm_verifier.hash);

	encode_pw_buffer(nt_pass.data, newpass, STR_UNICODE);
	arcfour_crypt(nt_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, nt_verifier.hash);
	
	/* Break the verification */
	nt_verifier.hash[0]++;

	r.in.server = &server;
	r.in.account = &account;
	r.in.nt_password = &nt_pass;
	r.in.nt_verifier = &nt_verifier;
	r.in.lm_change = 1;
	r.in.lm_password = &lm_pass;
	r.in.lm_verifier = &lm_verifier;
	r.in.password3 = NULL;

	status = dcerpc_samr_ChangePasswordUser3(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION) &&
	    (!NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD))) {
		printf("ChangePasswordUser3 failed, should have returned WRONG_PASSWORD (or at least 'PASSWORD_RESTRICTON') for invalid password verifier - %s\n",
			nt_errstr(status));
		ret = False;
	}
	
	encode_pw_buffer(lm_pass.data, newpass, STR_UNICODE);
	arcfour_crypt(lm_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_lm_hash, lm_verifier.hash);

	encode_pw_buffer(nt_pass.data, newpass, STR_UNICODE);
	/* Break the NT hash */
	old_nt_hash[0]++;
	arcfour_crypt(nt_pass.data, old_nt_hash, 516);
	/* Unbreak it again */
	old_nt_hash[0]--;
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
	if (!NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION) &&
	    (!NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD))) {
		printf("ChangePasswordUser3 failed, should have returned WRONG_PASSWORD (or at least 'PASSWORD_RESTRICTON') for invalidly encrpted password - %s\n",
			nt_errstr(status));
		ret = False;
	}
	
	/* This shouldn't be a valid name */
	init_lsa_String(&account_bad, talloc_asprintf(mem_ctx, "%sXX", account_string));

	r.in.account = &account_bad;
	status = dcerpc_samr_ChangePasswordUser3(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		printf("ChangePasswordUser3 failed, should have returned WRONG_PASSWORD for invalid username - %s\n",
			nt_errstr(status));
		ret = False;
	}

	E_md4hash(oldpass, old_nt_hash);
	E_md4hash(newpass, new_nt_hash);

	E_deshash(oldpass, old_lm_hash);
	E_deshash(newpass, new_lm_hash);

	encode_pw_buffer(lm_pass.data, newpass, STR_UNICODE);
	arcfour_crypt(lm_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_lm_hash, lm_verifier.hash);

	encode_pw_buffer(nt_pass.data, newpass, STR_UNICODE);
	arcfour_crypt(nt_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, nt_verifier.hash);

	r.in.server = &server;
	r.in.account = &account;
	r.in.nt_password = &nt_pass;
	r.in.nt_verifier = &nt_verifier;
	r.in.lm_change = 1;
	r.in.lm_password = &lm_pass;
	r.in.lm_verifier = &lm_verifier;
	r.in.password3 = NULL;

	unix_to_nt_time(&t, time(NULL));

	status = dcerpc_samr_ChangePasswordUser3(p, mem_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION) && 
	   r.out.dominfo && r.out.reject && handle_reject_reason) {

		if (r.out.dominfo->password_properties & DOMAIN_REFUSE_PASSWORD_CHANGE ) {

			if (r.out.reject && (r.out.reject->reason != SAMR_REJECT_OTHER)) {
				printf("expected SAMR_REJECT_OTHER (%d), got %d\n", 
					SAMR_REJECT_OTHER, r.out.reject->reason);
				return False;
			}
		}

		/* We tested the order of precendence which is as follows:
		
		* pwd min_age 
		* pwd length
		* pwd complexity
		* pwd history

		Guenther */

		if ((r.out.dominfo->min_password_age > 0) && !null_nttime(last_password_change) && 
			   (last_password_change + r.out.dominfo->min_password_age > t)) {

			if (r.out.reject->reason != SAMR_REJECT_OTHER) {
				printf("expected SAMR_REJECT_OTHER (%d), got %d\n", 
					SAMR_REJECT_OTHER, r.out.reject->reason);
				return False;
			}

		} else if ((r.out.dominfo->min_password_length > 0) && 
			   (strlen(newpass) < r.out.dominfo->min_password_length)) {

			if (r.out.reject->reason != SAMR_REJECT_TOO_SHORT) {
				printf("expected SAMR_REJECT_TOO_SHORT (%d), got %d\n", 
					SAMR_REJECT_TOO_SHORT, r.out.reject->reason);
				return False;
			}

		} else if ((r.out.dominfo->password_history_length > 0) && 
			    strequal(oldpass, newpass)) {

			if (r.out.reject->reason != SAMR_REJECT_IN_HISTORY) {
				printf("expected SAMR_REJECT_IN_HISTORY (%d), got %d\n", 
					SAMR_REJECT_IN_HISTORY, r.out.reject->reason);
				return False;
			}
		} else if (r.out.dominfo->password_properties & DOMAIN_PASSWORD_COMPLEX) {

			if (r.out.reject->reason != SAMR_REJECT_COMPLEXITY) {
				printf("expected SAMR_REJECT_COMPLEXITY (%d), got %d\n", 
					SAMR_REJECT_COMPLEXITY, r.out.reject->reason);
				return False;
			}

		}

		if (r.out.reject->reason == SAMR_REJECT_TOO_SHORT) {
			/* retry with adjusted size */
			return test_ChangePasswordUser3(p, mem_ctx, account_string, 
							r.out.dominfo->min_password_length, 
							password, NULL, 0, False); 

		}

	} else if (!NT_STATUS_IS_OK(status)) {
		printf("ChangePasswordUser3 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		*password = talloc_strdup(mem_ctx, newpass);
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

	r.in.alias_handle = alias_handle;
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
				  const struct dom_sid *domain_sid)
{
	struct samr_AddAliasMember r;
	struct samr_DeleteAliasMember d;
	NTSTATUS status;
	BOOL ret = True;
	struct dom_sid *sid;

	sid = dom_sid_add_rid(mem_ctx, domain_sid, 512);

	printf("testing AddAliasMember\n");
	r.in.alias_handle = alias_handle;
	r.in.sid = sid;

	status = dcerpc_samr_AddAliasMember(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddAliasMember failed - %s\n", nt_errstr(status));
		ret = False;
	}

	d.in.alias_handle = alias_handle;
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
	a.in.alias_handle = alias_handle;
	a.in.sids = &sids;

	sids.num_sids = 3;
	sids.sids = talloc_array(mem_ctx, struct lsa_SidPtr, 3);

	sids.sids[0].sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1-2-3-1");
	sids.sids[1].sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1-2-3-2");
	sids.sids[2].sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1-2-3-3");

	status = dcerpc_samr_AddMultipleMembersToAlias(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddMultipleMembersToAlias failed - %s\n", nt_errstr(status));
		ret = False;
	}


	printf("testing RemoveMultipleMembersFromAlias\n");
	r.in.alias_handle = alias_handle;
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

	r.in.user_handle = user_handle;

	status = dcerpc_samr_TestPrivateFunctionsUser(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_NOT_IMPLEMENTED, status)) {
		printf("TestPrivateFunctionsUser failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}


static BOOL test_user_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *user_handle, 
			  struct policy_handle *domain_handle, 
			  uint32_t base_acct_flags, 
			  const char *base_acct_name, enum torture_samr_choice which_ops)
{
	TALLOC_CTX *user_ctx;
	char *password = NULL;

	BOOL ret = True;
	int i;
	const uint32_t password_fields[] = {
		SAMR_FIELD_PASSWORD,
		SAMR_FIELD_PASSWORD2,
		SAMR_FIELD_PASSWORD | SAMR_FIELD_PASSWORD2,
		0
	};
	
	user_ctx = talloc_named(mem_ctx, 0, "test_user_ops per-user context");
	switch (which_ops) {
	case TORTURE_SAMR_USER_ATTRIBUTES:
		if (!test_QuerySecurity(p, user_ctx, user_handle)) {
			ret = False;
		}

		if (!test_QueryUserInfo(p, user_ctx, user_handle)) {
			ret = False;
		}

		if (!test_QueryUserInfo2(p, user_ctx, user_handle)) {
			ret = False;
		}

		if (!test_SetUserInfo(p, user_ctx, user_handle, base_acct_flags,
				      base_acct_name)) {
			ret = False;
		}	

		if (!test_GetUserPwInfo(p, user_ctx, user_handle)) {
			ret = False;
		}

		if (!test_TestPrivateFunctionsUser(p, user_ctx, user_handle)) {
			ret = False;
		}

		if (!test_SetUserPass(p, user_ctx, user_handle, &password)) {
			ret = False;
		}
		break;
	case TORTURE_SAMR_PASSWORDS:
		for (i = 0; password_fields[i]; i++) {
			if (!test_SetUserPass_23(p, user_ctx, user_handle, password_fields[i], &password)) {
				ret = False;
			}	
		
			/* check it was set right */
			if (!test_ChangePasswordUser3(p, user_ctx, base_acct_name, 0, &password, NULL, 0, False)) {
				ret = False;
			}
		}		

		for (i = 0; password_fields[i]; i++) {
			if (!test_SetUserPass_25(p, user_ctx, user_handle, password_fields[i], &password)) {
				ret = False;
			}	
		
			/* check it was set right */
			if (!test_ChangePasswordUser3(p, user_ctx, base_acct_name, 0, &password, NULL, 0, False)) {
				ret = False;
			}
		}		

		if (!test_SetUserPassEx(p, user_ctx, user_handle, &password)) {
			ret = False;
		}	

		if (!test_ChangePassword(p, user_ctx, base_acct_name, domain_handle, &password)) {
			ret = False;
		}	
		break;
	case TORTURE_SAMR_OTHER:
		/* We just need the account to exist */
		break;
	}
	talloc_free(user_ctx);
	return ret;
}

static BOOL test_alias_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			   struct policy_handle *alias_handle,
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

	if (!test_AddMemberToAlias(p, mem_ctx, alias_handle, domain_sid)) {
		ret = False;
	}

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping MultipleMembers Alias tests against Samba4\n");
		return ret;
	}

	if (!test_AddMultipleMembersToAlias(p, mem_ctx, alias_handle)) {
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

	d.in.user_handle = user_handle;
	d.out.user_handle = user_handle;

	status = dcerpc_samr_DeleteUser(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteUser failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

BOOL test_DeleteUser_byname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle, const char *name)
{
	NTSTATUS status;
	struct samr_DeleteUser d;
	struct policy_handle user_handle;
	uint32_t rid;

	status = test_LookupName(p, mem_ctx, handle, name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = test_OpenUser_byname(p, mem_ctx, handle, name, &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	d.in.user_handle = &user_handle;
	d.out.user_handle = &user_handle;
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
	uint32_t rid;

	status = test_LookupName(p, mem_ctx, handle, name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	r.in.domain_handle = handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.group_handle = &group_handle;
	status = dcerpc_samr_OpenGroup(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	d.in.group_handle = &group_handle;
	d.out.group_handle = &group_handle;
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
	uint32_t rid;

	printf("testing DeleteAlias_byname\n");

	status = test_LookupName(p, mem_ctx, domain_handle, name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	r.in.domain_handle = domain_handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.alias_handle = &alias_handle;
	status = dcerpc_samr_OpenAlias(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	d.in.alias_handle = &alias_handle;
	d.out.alias_handle = &alias_handle;
	status = dcerpc_samr_DeleteDomAlias(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	return True;

failed:
	printf("DeleteAlias_byname(%s) failed - %s\n", name, nt_errstr(status));
	return False;
}

static BOOL test_DeleteAlias(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				     struct policy_handle *alias_handle)
{
    	struct samr_DeleteDomAlias d;
	NTSTATUS status;
	BOOL ret = True;
	printf("Testing DeleteAlias\n");

	d.in.alias_handle = alias_handle;
	d.out.alias_handle = alias_handle;

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
	struct lsa_String name;
	uint32_t rid;
	BOOL ret = True;

	init_lsa_String(&name, TEST_ALIASNAME);
	r.in.domain_handle = domain_handle;
	r.in.alias_name = &name;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.alias_handle = alias_handle;
	r.out.rid = &rid;

	printf("Testing CreateAlias (%s)\n", r.in.alias_name->string);

	status = dcerpc_samr_CreateDomAlias(p, mem_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("Server refused create of '%s'\n", r.in.alias_name->string);
		return True;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_ALIAS_EXISTS)) {
		if (!test_DeleteAlias_byname(p, mem_ctx, domain_handle, r.in.alias_name->string)) {
			return False;
		}
		status = dcerpc_samr_CreateDomAlias(p, mem_ctx, &r);
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateAlias failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_alias_ops(p, mem_ctx, alias_handle, domain_sid)) {
		ret = False;
	}

	return ret;
}

static BOOL test_ChangePassword(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				const char *acct_name,
				struct policy_handle *domain_handle, char **password)
{
	BOOL ret = True;

	if (!*password) {
		return False;
	}

	if (!test_ChangePasswordUser(p, mem_ctx, acct_name, domain_handle, password)) {
		ret = False;
	}

	if (!test_ChangePasswordUser2(p, mem_ctx, acct_name, domain_handle, password)) {
		ret = False;
	}

	if (!test_OemChangePasswordUser2(p, mem_ctx, acct_name, domain_handle, password)) {
		ret = False;
	}

	/* test what happens when setting the old password again */
	if (!test_ChangePasswordUser3(p, mem_ctx, acct_name, 0, password, *password, 0, True)) {
		ret = False;
	}

	{
		char simple_pass[9];
		char *v = generate_random_str(mem_ctx, 1);

		ZERO_STRUCT(simple_pass);
		memset(simple_pass, *v, sizeof(simple_pass) - 1);

		/* test what happens when picking a simple password */
		if (!test_ChangePasswordUser3(p, mem_ctx, acct_name, 0, password, simple_pass, 0, True)) {
			ret = False;
		}
	}

	/* set samr_SetDomainInfo level 1 with min_length 5 */
	{
		struct samr_QueryDomainInfo r;
		struct samr_SetDomainInfo s;
		uint16_t len_old, len;
		uint32_t pwd_prop_old;
		NTSTATUS status;

		len = 5;

		r.in.domain_handle = domain_handle;
		r.in.level = 1;

		printf("testing samr_QueryDomainInfo level 1\n");
		status = dcerpc_samr_QueryDomainInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			return False;
		}

		s.in.domain_handle = domain_handle;
		s.in.level = 1;
		s.in.info = r.out.info;

		/* remember the old min length, so we can reset it */
		len_old = s.in.info->info1.min_password_length;
		s.in.info->info1.min_password_length = len;
		pwd_prop_old = s.in.info->info1.password_properties;
		/* turn off password complexity checks for this test */
		s.in.info->info1.password_properties &= ~DOMAIN_PASSWORD_COMPLEX;

		printf("testing samr_SetDomainInfo level 1\n");
		status = dcerpc_samr_SetDomainInfo(p, mem_ctx, &s);
		if (!NT_STATUS_IS_OK(status)) {
			return False;
		}

		printf("calling test_ChangePasswordUser3 with too short password\n");

		if (!test_ChangePasswordUser3(p, mem_ctx, acct_name, len - 1, password, NULL, 0, True)) {
			ret = False;
		}

		s.in.info->info1.min_password_length = len_old;
		s.in.info->info1.password_properties = pwd_prop_old;
		
		printf("testing samr_SetDomainInfo level 1\n");
		status = dcerpc_samr_SetDomainInfo(p, mem_ctx, &s);
		if (!NT_STATUS_IS_OK(status)) {
			return False;
		}

	}

	{
		NTSTATUS status;
		struct samr_OpenUser r;
		struct samr_QueryUserInfo q;
		struct samr_LookupNames n;
		struct policy_handle user_handle;

		n.in.domain_handle = domain_handle;
		n.in.num_names = 1;
		n.in.names = talloc_array(mem_ctx, struct lsa_String, 1);
		n.in.names[0].string = acct_name; 

		status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LookupNames failed - %s\n", nt_errstr(status));
			return False;
		}

		r.in.domain_handle = domain_handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.in.rid = n.out.rids.ids[0];
		r.out.user_handle = &user_handle;

		status = dcerpc_samr_OpenUser(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("OpenUser(%u) failed - %s\n", n.out.rids.ids[0], nt_errstr(status));
			return False;
		}

		q.in.user_handle = &user_handle;
		q.in.level = 5;

		status = dcerpc_samr_QueryUserInfo(p, mem_ctx, &q);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryUserInfo failed - %s\n", nt_errstr(status));
			return False;
		}

		printf("calling test_ChangePasswordUser3 with too early password change\n");

		if (!test_ChangePasswordUser3(p, mem_ctx, acct_name, 0, password, NULL, 
					      q.out.info->info5.last_password_change, True)) {
			ret = False;
		}
	}

	/* we change passwords twice - this has the effect of verifying
	   they were changed correctly for the final call */
	if (!test_ChangePasswordUser3(p, mem_ctx, acct_name, 0, password, NULL, 0, True)) {
		ret = False;
	}

	if (!test_ChangePasswordUser3(p, mem_ctx, acct_name, 0, password, NULL, 0, True)) {
		ret = False;
	}

	return ret;
}

static BOOL test_CreateUser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *domain_handle, 
			    struct policy_handle *user_handle_out, 
			    enum torture_samr_choice which_ops)
{

	TALLOC_CTX *user_ctx;

	NTSTATUS status;
	struct samr_CreateUser r;
	struct samr_QueryUserInfo q;
	struct samr_DeleteUser d;
	uint32_t rid;

	/* This call creates a 'normal' account - check that it really does */
	const uint32_t acct_flags = ACB_NORMAL;
	struct lsa_String name;
	BOOL ret = True;

	struct policy_handle user_handle;
	user_ctx = talloc_named(mem_ctx, 0, "test_CreateUser2 per-user context");
	init_lsa_String(&name, TEST_ACCOUNT_NAME);

	r.in.domain_handle = domain_handle;
	r.in.account_name = &name;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.user_handle = &user_handle;
	r.out.rid = &rid;

	printf("Testing CreateUser(%s)\n", r.in.account_name->string);

	status = dcerpc_samr_CreateUser(p, user_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("Server refused create of '%s': %s\n", r.in.account_name->string, nt_errstr(status));
		talloc_free(user_ctx);
		return True;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
		if (!test_DeleteUser_byname(p, user_ctx, domain_handle, r.in.account_name->string)) {
			talloc_free(user_ctx);
			return False;
		}
		status = dcerpc_samr_CreateUser(p, user_ctx, &r);
	}
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(user_ctx);
		printf("CreateUser failed - %s\n", nt_errstr(status));
		return False;
	} else {
		q.in.user_handle = &user_handle;
		q.in.level = 16;
		
		status = dcerpc_samr_QueryUserInfo(p, user_ctx, &q);
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
		
		if (!test_user_ops(p, user_ctx, &user_handle, domain_handle, 
				   acct_flags, name.string, which_ops)) {
			ret = False;
		}
		
		if (user_handle_out) {
			*user_handle_out = user_handle;
		} else {
			printf("Testing DeleteUser (createuser test)\n");
			
			d.in.user_handle = &user_handle;
			d.out.user_handle = &user_handle;
			
			status = dcerpc_samr_DeleteUser(p, user_ctx, &d);
			if (!NT_STATUS_IS_OK(status)) {
				printf("DeleteUser failed - %s\n", nt_errstr(status));
				ret = False;
			}
		}
		
	}

	talloc_free(user_ctx);
	
	return ret;
}


static BOOL test_CreateUser2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *domain_handle, enum torture_samr_choice which_ops)
{
	NTSTATUS status;
	struct samr_CreateUser2 r;
	struct samr_QueryUserInfo q;
	struct samr_DeleteUser d;
	struct policy_handle user_handle;
	uint32_t rid;
	struct lsa_String name;
	BOOL ret = True;
	int i;

	struct {
		uint32_t acct_flags;
		const char *account_name;
		NTSTATUS nt_status;
	} account_types[] = {
		{ ACB_NORMAL, TEST_ACCOUNT_NAME, NT_STATUS_OK },
		{ ACB_NORMAL | ACB_DISABLED, TEST_ACCOUNT_NAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_NORMAL | ACB_PWNOEXP, TEST_ACCOUNT_NAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_WSTRUST, TEST_MACHINENAME, NT_STATUS_OK },
		{ ACB_WSTRUST | ACB_DISABLED, TEST_MACHINENAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_WSTRUST | ACB_PWNOEXP, TEST_MACHINENAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_SVRTRUST, TEST_MACHINENAME, NT_STATUS_OK },
		{ ACB_SVRTRUST | ACB_DISABLED, TEST_MACHINENAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_SVRTRUST | ACB_PWNOEXP, TEST_MACHINENAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_DOMTRUST, TEST_DOMAINNAME, NT_STATUS_OK },
		{ ACB_DOMTRUST | ACB_DISABLED, TEST_DOMAINNAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_DOMTRUST | ACB_PWNOEXP, TEST_DOMAINNAME, NT_STATUS_INVALID_PARAMETER },
		{ 0, TEST_ACCOUNT_NAME, NT_STATUS_INVALID_PARAMETER },
		{ ACB_DISABLED, TEST_ACCOUNT_NAME, NT_STATUS_INVALID_PARAMETER },
		{ 0, NULL, NT_STATUS_INVALID_PARAMETER }
	};

	for (i = 0; account_types[i].account_name; i++) {
		TALLOC_CTX *user_ctx;
		uint32_t acct_flags = account_types[i].acct_flags;
		uint32_t access_granted;
		user_ctx = talloc_named(mem_ctx, 0, "test_CreateUser2 per-user context");
		init_lsa_String(&name, account_types[i].account_name);

		r.in.domain_handle = domain_handle;
		r.in.account_name = &name;
		r.in.acct_flags = acct_flags;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.user_handle = &user_handle;
		r.out.access_granted = &access_granted;
		r.out.rid = &rid;
		
		printf("Testing CreateUser2(%s, 0x%x)\n", r.in.account_name->string, acct_flags);
		
		status = dcerpc_samr_CreateUser2(p, user_ctx, &r);
		
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			talloc_free(user_ctx);
			printf("Server refused create of '%s'\n", r.in.account_name->string);
			continue;

		} else if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			if (!test_DeleteUser_byname(p, user_ctx, domain_handle, r.in.account_name->string)) {
				talloc_free(user_ctx);
				ret = False;
				continue;
			}
			status = dcerpc_samr_CreateUser2(p, user_ctx, &r);

		}
		if (!NT_STATUS_EQUAL(status, account_types[i].nt_status)) {
			printf("CreateUser2 failed gave incorrect error return - %s (should be %s)\n", 
			       nt_errstr(status), nt_errstr(account_types[i].nt_status));
			ret = False;
		}
		
		if (NT_STATUS_IS_OK(status)) {
			q.in.user_handle = &user_handle;
			q.in.level = 16;
			
			status = dcerpc_samr_QueryUserInfo(p, user_ctx, &q);
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
		
			if (!test_user_ops(p, user_ctx, &user_handle, domain_handle, 
					   acct_flags, name.string, which_ops)) {
				ret = False;
			}

			printf("Testing DeleteUser (createuser2 test)\n");
		
			d.in.user_handle = &user_handle;
			d.out.user_handle = &user_handle;
			
			status = dcerpc_samr_DeleteUser(p, user_ctx, &d);
			if (!NT_STATUS_IS_OK(status)) {
				printf("DeleteUser failed - %s\n", nt_errstr(status));
				ret = False;
			}
		}
		talloc_free(user_ctx);
	}

	return ret;
}

static BOOL test_QueryAliasInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryAliasInfo r;
	uint16_t levels[] = {1, 2, 3};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryAliasInfo level %u\n", levels[i]);

		r.in.alias_handle = handle;
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
	uint16_t levels[] = {1, 2, 3, 4, 5};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryGroupInfo level %u\n", levels[i]);

		r.in.group_handle = handle;
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

static BOOL test_QueryGroupMember(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryGroupMember r;
	BOOL ret = True;

	printf("Testing QueryGroupMember\n");

	r.in.group_handle = handle;

	status = dcerpc_samr_QueryGroupMember(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QueryGroupInfo failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}


static BOOL test_SetGroupInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryGroupInfo r;
	struct samr_SetGroupInfo s;
	uint16_t levels[] = {1, 2, 3, 4};
	uint16_t set_ok[] = {0, 1, 1, 1};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryGroupInfo level %u\n", levels[i]);

		r.in.group_handle = handle;
		r.in.level = levels[i];

		status = dcerpc_samr_QueryGroupInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryGroupInfo level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}

		printf("Testing SetGroupInfo level %u\n", levels[i]);

		s.in.group_handle = handle;
		s.in.level = levels[i];
		s.in.info = r.out.info;

#if 0
		/* disabled this, as it changes the name only from the point of view of samr, 
		   but leaves the name from the point of view of w2k3 internals (and ldap). This means
		   the name is still reserved, so creating the old name fails, but deleting by the old name
		   also fails */
		if (s.in.level == 2) {
			init_lsa_String(&s.in.info->string, "NewName");
		}
#endif

		if (s.in.level == 4) {
			init_lsa_String(&s.in.info->description, "test description");
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
	uint16_t levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			   11, 12, 13, 14, 16, 17, 20, 21};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryUserInfo level %u\n", levels[i]);

		r.in.user_handle = handle;
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
	uint16_t levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			   11, 12, 13, 14, 16, 17, 20, 21};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryUserInfo2 level %u\n", levels[i]);

		r.in.user_handle = handle;
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
			  struct policy_handle *handle, uint32_t rid)
{
	NTSTATUS status;
	struct samr_OpenUser r;
	struct policy_handle user_handle;
	BOOL ret = True;

	printf("Testing OpenUser(%u)\n", rid);

	r.in.domain_handle = handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.user_handle = &user_handle;

	status = dcerpc_samr_OpenUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenUser(%u) failed - %s\n", rid, nt_errstr(status));
		return False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	if (!test_QueryUserInfo(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	if (!test_QueryUserInfo2(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	if (!test_GetUserPwInfo(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	if (!test_GetGroupsForUser(p,mem_ctx, &user_handle)) {
		ret = False;
	}

	if (!test_samr_handle_Close(p, mem_ctx, &user_handle)) {
		ret = False;
	}

	return ret;
}

static BOOL test_OpenGroup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle, uint32_t rid)
{
	NTSTATUS status;
	struct samr_OpenGroup r;
	struct policy_handle group_handle;
	BOOL ret = True;

	printf("Testing OpenGroup(%u)\n", rid);

	r.in.domain_handle = handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.group_handle = &group_handle;

	status = dcerpc_samr_OpenGroup(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenGroup(%u) failed - %s\n", rid, nt_errstr(status));
		return False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &group_handle)) {
		ret = False;
	}

	if (!test_QueryGroupInfo(p, mem_ctx, &group_handle)) {
		ret = False;
	}

	if (!test_QueryGroupMember(p, mem_ctx, &group_handle)) {
		ret = False;
	}

	if (!test_samr_handle_Close(p, mem_ctx, &group_handle)) {
		ret = False;
	}

	return ret;
}

static BOOL test_OpenAlias(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle, uint32_t rid)
{
	NTSTATUS status;
	struct samr_OpenAlias r;
	struct policy_handle alias_handle;
	BOOL ret = True;

	printf("Testing OpenAlias(%u)\n", rid);

	r.in.domain_handle = handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.alias_handle = &alias_handle;

	status = dcerpc_samr_OpenAlias(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenAlias(%u) failed - %s\n", rid, nt_errstr(status));
		return False;
	}

	if (!test_QuerySecurity(p, mem_ctx, &alias_handle)) {
		ret = False;
	}

	if (!test_QueryAliasInfo(p, mem_ctx, &alias_handle)) {
		ret = False;
	}

	if (!test_GetMembersInAlias(p, mem_ctx, &alias_handle)) {
		ret = False;
	}

	if (!test_samr_handle_Close(p, mem_ctx, &alias_handle)) {
		ret = False;
	}

	return ret;
}

static BOOL test_EnumDomainUsers(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_EnumDomainUsers r;
	uint32_t resume_handle=0;
	int i;
	BOOL ret = True;
	struct samr_LookupNames n;
	struct samr_LookupRids  lr ;

	printf("Testing EnumDomainUsers\n");

	r.in.domain_handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.acct_flags = 0;
	r.in.max_size = (uint32_t)-1;
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
	n.in.domain_handle = handle;
	n.in.num_names = r.out.sam->count;
	n.in.names = talloc_array(mem_ctx, struct lsa_String, r.out.sam->count);
	for (i=0;i<r.out.sam->count;i++) {
		n.in.names[i].string = r.out.sam->entries[i].name.string;
	}
	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		ret = False;
	}


	printf("Testing LookupRids\n");
	lr.in.domain_handle = handle;
	lr.in.num_rids = r.out.sam->count;
	lr.in.rids = talloc_array(mem_ctx, uint32_t, r.out.sam->count);
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

/*
  try blasting the server with a bunch of sync requests
*/
static BOOL test_EnumDomainUsers_async(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				       struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_EnumDomainUsers r;
	uint32_t resume_handle=0;
	int i;
#define ASYNC_COUNT 100
	struct rpc_request *req[ASYNC_COUNT];

	if (!lp_parm_bool(-1, "torture", "dangerous", False)) {
		printf("samr async test disabled - enable dangerous tests to use\n");
		return True;
	}

	printf("Testing EnumDomainUsers_async\n");

	r.in.domain_handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.acct_flags = 0;
	r.in.max_size = (uint32_t)-1;
	r.out.resume_handle = &resume_handle;

	for (i=0;i<ASYNC_COUNT;i++) {
		req[i] = dcerpc_samr_EnumDomainUsers_send(p, mem_ctx, &r);
	}

	for (i=0;i<ASYNC_COUNT;i++) {
		status = dcerpc_ndr_request_recv(req[i]);
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumDomainUsers[%d] failed - %s\n", 
			       i, nt_errstr(status));
			return False;
		}
	}
	
	printf("%d async requests OK\n", i);

	return True;
}

static BOOL test_EnumDomainGroups(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_EnumDomainGroups r;
	uint32_t resume_handle=0;
	int i;
	BOOL ret = True;

	printf("Testing EnumDomainGroups\n");

	r.in.domain_handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_size = (uint32_t)-1;
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
	uint32_t resume_handle=0;
	int i;
	BOOL ret = True;

	printf("Testing EnumDomainAliases\n");

	r.in.domain_handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.acct_flags = (uint32_t)-1;
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
	uint16_t levels[] = {1, 2, 3, 4, 5};
	uint16_t ok_lvl[] = {1, 1, 1, 0, 0};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing GetDisplayEnumerationIndex level %u\n", levels[i]);

		r.in.domain_handle = handle;
		r.in.level = levels[i];
		init_lsa_String(&r.in.name, TEST_ACCOUNT_NAME);

		status = dcerpc_samr_GetDisplayEnumerationIndex(p, mem_ctx, &r);

		if (ok_lvl[i] && 
		    !NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(NT_STATUS_NO_MORE_ENTRIES, status)) {
			printf("GetDisplayEnumerationIndex level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}

		init_lsa_String(&r.in.name, "zzzzzzzz");

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
	uint16_t levels[] = {1, 2, 3, 4, 5};
	uint16_t ok_lvl[] = {1, 1, 1, 0, 0};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing GetDisplayEnumerationIndex2 level %u\n", levels[i]);

		r.in.domain_handle = handle;
		r.in.level = levels[i];
		init_lsa_String(&r.in.name, TEST_ACCOUNT_NAME);

		status = dcerpc_samr_GetDisplayEnumerationIndex2(p, mem_ctx, &r);
		if (ok_lvl[i] && 
		    !NT_STATUS_IS_OK(status) && 
		    !NT_STATUS_EQUAL(NT_STATUS_NO_MORE_ENTRIES, status)) {
			printf("GetDisplayEnumerationIndex2 level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}

		init_lsa_String(&r.in.name, "zzzzzzzz");

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
	uint16_t levels[] = {1, 2, 3, 4, 5};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDisplayInfo level %u\n", levels[i]);

		r.in.domain_handle = handle;
		r.in.level = levels[i];
		r.in.start_idx = 0;
		r.in.max_entries = 1000;
		r.in.buf_size = (uint32_t)-1;

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
	uint16_t levels[] = {1, 2, 3, 4, 5};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDisplayInfo2 level %u\n", levels[i]);

		r.in.domain_handle = handle;
		r.in.level = levels[i];
		r.in.start_idx = 0;
		r.in.max_entries = 1000;
		r.in.buf_size = (uint32_t)-1;

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
	uint16_t levels[] = {1, 2, 3, 4, 5};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDisplayInfo3 level %u\n", levels[i]);

		r.in.domain_handle = handle;
		r.in.level = levels[i];
		r.in.start_idx = 0;
		r.in.max_entries = 1000;
		r.in.buf_size = (uint32_t)-1;

		status = dcerpc_samr_QueryDisplayInfo3(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDisplayInfo3 level %u failed - %s\n", 
			       levels[i], nt_errstr(status));
			ret = False;
		}
	}
	
	return ret;	
}


static BOOL test_QueryDisplayInfo_continue(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
					   struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryDisplayInfo r;
	BOOL ret = True;

	printf("Testing QueryDisplayInfo continuation\n");

	r.in.domain_handle = handle;
	r.in.level = 1;
	r.in.start_idx = 0;
	r.in.max_entries = 1;
	r.in.buf_size = (uint32_t)-1;

	do {
		status = dcerpc_samr_QueryDisplayInfo(p, mem_ctx, &r);
		if (NT_STATUS_IS_OK(status) && r.out.returned_size != 0) {
			if (r.out.info.info1.entries[0].idx != r.in.start_idx + 1) {
				printf("expected idx %d but got %d\n",
				       r.in.start_idx + 1,
				       r.out.info.info1.entries[0].idx);
				break;
			}
		}
		if (!NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES) &&
		    !NT_STATUS_IS_OK(status)) {
			printf("QueryDisplayInfo level %u failed - %s\n", 
			       r.in.level, nt_errstr(status));
			ret = False;
			break;
		}
		r.in.start_idx++;
	} while ((NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES) ||
		  NT_STATUS_IS_OK(status)) &&
		 r.out.returned_size != 0);
	
	return ret;	
}

static BOOL test_QueryDomainInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryDomainInfo r;
	struct samr_SetDomainInfo s;
	uint16_t levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13};
	uint16_t set_ok[] = {1, 0, 1, 1, 0, 1, 1, 0, 1,  0,  1,  0};
	int i;
	BOOL ret = True;
	const char *domain_comment = talloc_asprintf(mem_ctx, 
				  "Tortured by Samba4 RPC-SAMR: %s", 
				  timestring(mem_ctx, time(NULL)));

	s.in.domain_handle = handle;
	s.in.level = 4;
	s.in.info = talloc(mem_ctx, union samr_DomainInfo);
	
	s.in.info->info4.comment.string = domain_comment;
	status = dcerpc_samr_SetDomainInfo(p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetDomainInfo level %u (set comment) failed - %s\n", 
		       r.in.level, nt_errstr(status));
		return False;
	}

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDomainInfo level %u\n", levels[i]);

		r.in.domain_handle = handle;
		r.in.level = levels[i];

		status = dcerpc_samr_QueryDomainInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDomainInfo level %u failed - %s\n", 
			       r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}

		switch (levels[i]) {
		case 2:
			if (strcmp(r.out.info->info2.comment.string, domain_comment) != 0) {
				printf("QueryDomainInfo level %u returned different comment (%s, expected %s)\n",
				       levels[i], r.out.info->info2.comment.string, domain_comment);
				ret = False;
			}
			if (!r.out.info->info2.primary.string) {
				printf("QueryDomainInfo level %u returned no PDC name\n",
				       levels[i]);
				ret = False;
			} else if (r.out.info->info2.role == SAMR_ROLE_DOMAIN_PDC) {
				if (dcerpc_server_name(p) && strcasecmp_m(dcerpc_server_name(p), r.out.info->info2.primary.string) != 0) {
					printf("QueryDomainInfo level %u returned different PDC name (%s) compared to server name (%s), despite claiming to be the PDC\n",
					       levels[i], r.out.info->info2.primary.string, dcerpc_server_name(p));
				}
			}
			break;
		case 4:
			if (strcmp(r.out.info->info4.comment.string, domain_comment) != 0) {
				printf("QueryDomainInfo level %u returned different comment (%s, expected %s)\n",
				       levels[i], r.out.info->info4.comment.string, domain_comment);
				ret = False;
			}
			break;
		case 6:
			if (!r.out.info->info6.primary.string) {
				printf("QueryDomainInfo level %u returned no PDC name\n",
				       levels[i]);
				ret = False;
			}
			break;
		case 11:
			if (strcmp(r.out.info->info11.info2.comment.string, domain_comment) != 0) {
				printf("QueryDomainInfo level %u returned different comment (%s, expected %s)\n",
				       levels[i], r.out.info->info11.info2.comment.string, domain_comment);
				ret = False;
			}
			break;
		}

		printf("Testing SetDomainInfo level %u\n", levels[i]);

		s.in.domain_handle = handle;
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

	return ret;	
}


static BOOL test_QueryDomainInfo2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_QueryDomainInfo2 r;
	uint16_t levels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13};
	int i;
	BOOL ret = True;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		printf("Testing QueryDomainInfo2 level %u\n", levels[i]);

		r.in.domain_handle = handle;
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

/* Test whether querydispinfo level 5 and enumdomgroups return the same
   set of group names. */
static BOOL test_GroupList(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle)
{
	struct samr_EnumDomainGroups q1;
	struct samr_QueryDisplayInfo q2;
	NTSTATUS status;
	uint32_t resume_handle=0;
	int i;
	BOOL ret = True;

	int num_names = 0;
	const char **names = NULL;

	printf("Testing coherency of querydispinfo vs enumdomgroups\n");

	q1.in.domain_handle = handle;
	q1.in.resume_handle = &resume_handle;
	q1.in.max_size = 5;
	q1.out.resume_handle = &resume_handle;

	status = STATUS_MORE_ENTRIES;
	while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		status = dcerpc_samr_EnumDomainGroups(p, mem_ctx, &q1);

		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES))
			break;

		for (i=0; i<q1.out.num_entries; i++) {
			add_string_to_array(mem_ctx,
					    q1.out.sam->entries[i].name.string,
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

	q2.in.domain_handle = handle;
	q2.in.level = 5;
	q2.in.start_idx = 0;
	q2.in.max_entries = 5;
	q2.in.buf_size = (uint32_t)-1;

	status = STATUS_MORE_ENTRIES;
	while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		status = dcerpc_samr_QueryDisplayInfo(p, mem_ctx, &q2);

		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES))
			break;

		for (i=0; i<q2.out.info.info5.count; i++) {
			int j;
			const char *name = q2.out.info.info5.entries[i].account_name.string;
			BOOL found = False;
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

	d.in.group_handle = group_handle;
	d.out.group_handle = group_handle;

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

	r.in.domain_handle = domain_handle;

	status = dcerpc_samr_TestPrivateFunctionsDomain(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_NOT_IMPLEMENTED, status)) {
		printf("TestPrivateFunctionsDomain failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_RidToSid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct dom_sid *domain_sid,
			  struct policy_handle *domain_handle)
{
    	struct samr_RidToSid r;
	NTSTATUS status;
	BOOL ret = True;
	struct dom_sid *calc_sid;
	int rids[] = { 0, 42, 512, 10200 };
	int i;

	for (i=0;i<ARRAY_SIZE(rids);i++) {
	
		printf("Testing RidToSid\n");
		
		calc_sid = dom_sid_dup(mem_ctx, domain_sid);
		r.in.domain_handle = domain_handle;
		r.in.rid = rids[i];
		
		status = dcerpc_samr_RidToSid(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("RidToSid for %d failed - %s\n", rids[i], nt_errstr(status));
			ret = False;
		} else {
			calc_sid = dom_sid_add_rid(calc_sid, calc_sid, rids[i]);

			if (!dom_sid_equal(calc_sid, r.out.sid)) {
				printf("RidToSid for %d failed - got %s, expected %s\n", rids[i], 
				       dom_sid_string(mem_ctx, r.out.sid), 
				       dom_sid_string(mem_ctx, calc_sid));
				ret = False;
			}
		}
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

	r.in.domain_handle = domain_handle;

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
	uint32_t rid;

	status = test_LookupName(p, mem_ctx, domain_handle, TEST_ACCOUNT_NAME, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		printf("test_AddGroupMember looking up name " TEST_ACCOUNT_NAME " failed - %s\n", nt_errstr(status));
		return False;
	}

	r.in.group_handle = group_handle;
	r.in.rid = rid;
	r.in.flags = 0; /* ??? */

	printf("Testing AddGroupMember and DeleteGroupMember\n");

	d.in.group_handle = group_handle;
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

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping SetMemberAttributesOfGroup test against Samba4\n");
	} else {
		/* this one is quite strange. I am using random inputs in the
		   hope of triggering an error that might give us a clue */

		s.in.group_handle = group_handle;
		s.in.unknown1 = random();
		s.in.unknown2 = random();

		status = dcerpc_samr_SetMemberAttributesOfGroup(p, mem_ctx, &s);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetMemberAttributesOfGroup failed - %s\n", nt_errstr(status));
			return False;
		}
	}

	q.in.group_handle = group_handle;

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
	uint32_t rid;
	struct lsa_String name;
	BOOL ret = True;

	init_lsa_String(&name, TEST_GROUPNAME);

	r.in.domain_handle = domain_handle;
	r.in.name = &name;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.group_handle = group_handle;
	r.out.rid = &rid;

	printf("Testing CreateDomainGroup(%s)\n", r.in.name->string);

	status = dcerpc_samr_CreateDomainGroup(p, mem_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("Server refused create of '%s'\n", r.in.name->string);
		ZERO_STRUCTP(group_handle);
		return True;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_GROUP_EXISTS)) {
		if (!test_DeleteGroup_byname(p, mem_ctx, domain_handle, r.in.name->string)) {
			
			printf("CreateDomainGroup failed: Could not delete domain group %s - %s\n", r.in.name->string, 
			       nt_errstr(status));
			return False;
		}
		status = dcerpc_samr_CreateDomainGroup(p, mem_ctx, &r);
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
		if (!test_DeleteUser_byname(p, mem_ctx, domain_handle, r.in.name->string)) {
			
			printf("CreateDomainGroup failed: Could not delete user %s - %s\n", r.in.name->string, 
			       nt_errstr(status));
			return False;
		}
		status = dcerpc_samr_CreateDomainGroup(p, mem_ctx, &r);
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateDomainGroup failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_AddGroupMember(p, mem_ctx, domain_handle, group_handle)) {
		printf("CreateDomainGroup failed - %s\n", nt_errstr(status));
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

	r.in.domain_handle = domain_handle;
	r.in.sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-12-34-56-78");

	status = dcerpc_samr_RemoveMemberFromForeignDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RemoveMemberFromForeignDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}



static BOOL test_Connect(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct policy_handle *handle);

static BOOL test_OpenDomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle, struct dom_sid *sid,
			    enum torture_samr_choice which_ops)
{
	NTSTATUS status;
	struct samr_OpenDomain r;
	struct policy_handle domain_handle;
	struct policy_handle alias_handle;
	struct policy_handle user_handle;
	struct policy_handle group_handle;
	BOOL ret = True;

	ZERO_STRUCT(alias_handle);
	ZERO_STRUCT(user_handle);
	ZERO_STRUCT(group_handle);
	ZERO_STRUCT(domain_handle);

	printf("Testing OpenDomain\n");

	r.in.connect_handle = handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.sid = sid;
	r.out.domain_handle = &domain_handle;

	status = dcerpc_samr_OpenDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	/* run the domain tests with the main handle closed - this tests
	   the servers reference counting */
	ret &= test_samr_handle_Close(p, mem_ctx, handle);

	switch (which_ops) {
	case TORTURE_SAMR_USER_ATTRIBUTES:
	case TORTURE_SAMR_PASSWORDS:
		ret &= test_CreateUser(p, mem_ctx, &domain_handle, NULL, which_ops);
		ret &= test_CreateUser2(p, mem_ctx, &domain_handle, which_ops);
		break;
	case TORTURE_SAMR_OTHER:
		ret &= test_CreateUser(p, mem_ctx, &domain_handle, &user_handle, which_ops);
		ret &= test_QuerySecurity(p, mem_ctx, &domain_handle);
		ret &= test_RemoveMemberFromForeignDomain(p, mem_ctx, &domain_handle);
		ret &= test_CreateAlias(p, mem_ctx, &domain_handle, &alias_handle, sid);
		ret &= test_CreateDomainGroup(p, mem_ctx, &domain_handle, &group_handle);
		ret &= test_QueryDomainInfo(p, mem_ctx, &domain_handle);
		ret &= test_QueryDomainInfo2(p, mem_ctx, &domain_handle);
		ret &= test_EnumDomainUsers(p, mem_ctx, &domain_handle);
		ret &= test_EnumDomainUsers_async(p, mem_ctx, &domain_handle);
		ret &= test_EnumDomainGroups(p, mem_ctx, &domain_handle);
		ret &= test_EnumDomainAliases(p, mem_ctx, &domain_handle);
		ret &= test_QueryDisplayInfo(p, mem_ctx, &domain_handle);
		ret &= test_QueryDisplayInfo2(p, mem_ctx, &domain_handle);
		ret &= test_QueryDisplayInfo3(p, mem_ctx, &domain_handle);
		ret &= test_QueryDisplayInfo_continue(p, mem_ctx, &domain_handle);
		
		if (lp_parm_bool(-1, "torture", "samba4", False)) {
			printf("skipping GetDisplayEnumerationIndex test against Samba4\n");
		} else {
			ret &= test_GetDisplayEnumerationIndex(p, mem_ctx, &domain_handle);
			ret &= test_GetDisplayEnumerationIndex2(p, mem_ctx, &domain_handle);
		}
		ret &= test_GroupList(p, mem_ctx, &domain_handle);
		ret &= test_TestPrivateFunctionsDomain(p, mem_ctx, &domain_handle);
		ret &= test_RidToSid(p, mem_ctx, sid, &domain_handle);
		ret &= test_GetBootKeyInformation(p, mem_ctx, &domain_handle);
		break;
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

	ret &= test_samr_handle_Close(p, mem_ctx, &domain_handle);

	/* reconnect the main handle */
	ret &= test_Connect(p, mem_ctx, handle);

	if (!ret) {
		printf("Testing domain %s failed!\n", dom_sid_string(mem_ctx, sid));
	}

	return ret;
}

static BOOL test_LookupDomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle, const char *domain,
			      enum torture_samr_choice which_ops)
{
	NTSTATUS status;
	struct samr_LookupDomain r;
	struct lsa_String n1;
	struct lsa_String n2;
	BOOL ret = True;

	printf("Testing LookupDomain(%s)\n", domain);

	/* check for correct error codes */
	r.in.connect_handle = handle;
	r.in.domain_name = &n2;
	n2.string = NULL;

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status)) {
		printf("failed: LookupDomain expected NT_STATUS_INVALID_PARAMETER - %s\n", nt_errstr(status));
		ret = False;
	}

	init_lsa_String(&n2, "xxNODOMAINxx");

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(NT_STATUS_NO_SUCH_DOMAIN, status)) {
		printf("failed: LookupDomain expected NT_STATUS_NO_SUCH_DOMAIN - %s\n", nt_errstr(status));
		ret = False;
	}

	r.in.connect_handle = handle;

	init_lsa_String(&n1, domain);
	r.in.domain_name = &n1;

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(status));
		ret = False;
	}

	if (!test_GetDomPwInfo(p, mem_ctx, &n1)) {
		ret = False;
	}

	if (!test_OpenDomain(p, mem_ctx, handle, r.out.sid, which_ops)) {
		ret = False;
	}

	return ret;
}


static BOOL test_EnumDomains(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle, enum torture_samr_choice which_ops)
{
	NTSTATUS status;
	struct samr_EnumDomains r;
	uint32_t resume_handle = 0;
	int i;
	BOOL ret = True;

	r.in.connect_handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.buf_size = (uint32_t)-1;
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
				       r.out.sam->entries[i].name.string, which_ops)) {
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
	struct policy_handle h;
	BOOL ret = True, got_handle = False;

	printf("testing samr_Connect\n");

	r.in.system_name = 0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.connect_handle = &h;

	status = dcerpc_samr_Connect(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		got_handle = True;
		*handle = h;
	}

	printf("testing samr_Connect2\n");

	r2.in.system_name = NULL;
	r2.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r2.out.connect_handle = &h;

	status = dcerpc_samr_Connect2(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect2 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		if (got_handle) {
			test_samr_handle_Close(p, mem_ctx, handle);
		}
		got_handle = True;
		*handle = h;
	}

	printf("testing samr_Connect3\n");

	r3.in.system_name = NULL;
	r3.in.unknown = 0;
	r3.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r3.out.connect_handle = &h;

	status = dcerpc_samr_Connect3(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect3 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		if (got_handle) {
			test_samr_handle_Close(p, mem_ctx, handle);
		}
		got_handle = True;
		*handle = h;
	}

	printf("testing samr_Connect4\n");

	r4.in.system_name = "";
	r4.in.unknown = 0;
	r4.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r4.out.connect_handle = &h;

	status = dcerpc_samr_Connect4(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect4 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		if (got_handle) {
			test_samr_handle_Close(p, mem_ctx, handle);
		}
		got_handle = True;
		*handle = h;
	}

	printf("testing samr_Connect5\n");

	info.info1.unknown1 = 0;
	info.info1.unknown2 = 0;

	r5.in.system_name = "";
	r5.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r5.in.level = 1;
	r5.in.info = &info;
	r5.out.info = &info;
	r5.out.connect_handle = &h;

	status = dcerpc_samr_Connect5(p, mem_ctx, &r5);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect5 failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		if (got_handle) {
			test_samr_handle_Close(p, mem_ctx, handle);
		}
		got_handle = True;
		*handle = h;
	}

	return ret;
}


BOOL torture_rpc_samr(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	BOOL ret = True;
	struct policy_handle handle;

	status = torture_rpc_connection(torture, &p, &dcerpc_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	ret &= test_Connect(p, torture, &handle);

	ret &= test_QuerySecurity(p, torture, &handle);

	ret &= test_EnumDomains(p, torture, &handle, TORTURE_SAMR_OTHER);

	ret &= test_SetDsrmPassword(p, torture, &handle);

	ret &= test_Shutdown(p, torture, &handle);

	ret &= test_samr_handle_Close(p, torture, &handle);

	return ret;
}


BOOL torture_rpc_samr_users(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	BOOL ret = True;
	struct policy_handle handle;

	status = torture_rpc_connection(torture, &p, &dcerpc_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	ret &= test_Connect(p, torture, &handle);

	ret &= test_QuerySecurity(p, torture, &handle);

	ret &= test_EnumDomains(p, torture, &handle, TORTURE_SAMR_USER_ATTRIBUTES);

	ret &= test_SetDsrmPassword(p, torture, &handle);

	ret &= test_Shutdown(p, torture, &handle);

	ret &= test_samr_handle_Close(p, torture, &handle);

	return ret;
}


BOOL torture_rpc_samr_passwords(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	BOOL ret = True;
	struct policy_handle handle;

	status = torture_rpc_connection(torture, &p, &dcerpc_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	ret &= test_Connect(p, torture, &handle);

	ret &= test_EnumDomains(p, torture, &handle, TORTURE_SAMR_PASSWORDS);

	ret &= test_samr_handle_Close(p, torture, &handle);

	return ret;
}

