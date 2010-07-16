/*
   Unix SMB/CIFS implementation.
   test suite for RAP sam operations

   Copyright (C) Guenther Deschner 2010

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
#include "libcli/libcli.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smbtorture.h"
#include "torture/util.h"
#include "../librpc/gen_ndr/rap.h"
#include "torture/rap/proto.h"
#include "param/param.h"
#include "../lib/crypto/crypto.h"
#include "../libcli/auth/libcli_auth.h"
#include "torture/rpc/torture_rpc.h"

#define TEST_RAP_USER "torture_rap_user"

static char *samr_rand_pass(TALLOC_CTX *mem_ctx, int min_len)
{
	size_t len = MAX(8, min_len);
	char *s = generate_random_password(mem_ctx, len, len+6);
	printf("Generated password '%s'\n", s);
	return s;
}

static bool test_userpasswordset2_args(struct torture_context *tctx,
				       struct smbcli_state *cli,
				       const char *username,
				       const char **password)
{
	struct rap_NetUserPasswordSet2 r;
	char *newpass = samr_rand_pass(tctx, 8);

	ZERO_STRUCT(r);

	r.in.UserName = username;

	memcpy(r.in.OldPassword, *password, MIN(strlen(*password), 16));
	memcpy(r.in.NewPassword, newpass, MIN(strlen(newpass), 16));
	r.in.EncryptedPassword = 0;
	r.in.RealPasswordLength = strlen(newpass);

	torture_comment(tctx, "Testing rap_NetUserPasswordSet2(%s)\n", r.in.UserName);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netuserpasswordset2(cli->tree, lpcfg_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netuserpasswordset2 failed");
	if (!W_ERROR_IS_OK(W_ERROR(r.out.status))) {
		torture_warning(tctx, "RAP NetUserPasswordSet2 gave: %s\n",
			win_errstr(W_ERROR(r.out.status)));
	} else {
		*password = newpass;
	}

	return true;
}

static bool test_userpasswordset2_crypt_args(struct torture_context *tctx,
					     struct smbcli_state *cli,
					     const char *username,
					     const char **password)
{
	struct rap_NetUserPasswordSet2 r;
	char *newpass = samr_rand_pass(tctx, 8);

	r.in.UserName = username;

	E_deshash(*password, r.in.OldPassword);
	E_deshash(newpass, r.in.NewPassword);

	r.in.RealPasswordLength = strlen(newpass);
	r.in.EncryptedPassword = 1;

	torture_comment(tctx, "Testing rap_NetUserPasswordSet2(%s)\n", r.in.UserName);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netuserpasswordset2(cli->tree, lpcfg_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netuserpasswordset2 failed");
	if (!W_ERROR_IS_OK(W_ERROR(r.out.status))) {
		torture_warning(tctx, "RAP NetUserPasswordSet2 gave: %s\n",
			win_errstr(W_ERROR(r.out.status)));
	} else {
		*password = newpass;
	}

	return true;
}

static bool test_userpasswordset2(struct torture_context *tctx,
				  struct smbcli_state *cli)
{
	struct test_join *join_ctx;
	const char *password;
	bool ret = true;

	join_ctx = torture_create_testuser_max_pwlen(tctx, TEST_RAP_USER,
						     torture_setting_string(tctx, "workgroup", NULL),
						     ACB_NORMAL,
						     &password, 14);
	if (join_ctx == NULL) {
		torture_fail(tctx, "failed to create user\n");
	}

	ret &= test_userpasswordset2_args(tctx, cli, TEST_RAP_USER, &password);
	ret &= test_userpasswordset2_crypt_args(tctx, cli, TEST_RAP_USER, &password);

	torture_leave_domain(tctx, join_ctx);

	return ret;
}

static bool test_oemchangepassword_args(struct torture_context *tctx,
					struct smbcli_state *cli,
					const char *username,
					const char **password)
{
	struct rap_NetOEMChangePassword r;

	const char *oldpass = *password;
	char *newpass = samr_rand_pass(tctx, 9);
	uint8_t old_pw_hash[16];
	uint8_t new_pw_hash[16];

	r.in.UserName = username;

	E_deshash(oldpass, old_pw_hash);
	E_deshash(newpass, new_pw_hash);

	encode_pw_buffer(r.in.crypt_password, newpass, STR_ASCII);
	arcfour_crypt(r.in.crypt_password, old_pw_hash, 516);
	E_old_pw_hash(new_pw_hash, old_pw_hash, r.in.password_hash);

	torture_comment(tctx, "Testing rap_NetOEMChangePassword(%s)\n", r.in.UserName);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netoemchangepassword(cli->tree, lpcfg_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netoemchangepassword failed");
	if (!W_ERROR_IS_OK(W_ERROR(r.out.status))) {
		torture_warning(tctx, "RAP NetOEMChangePassword gave: %s\n",
			win_errstr(W_ERROR(r.out.status)));
	} else {
		*password = newpass;
	}

	return true;
}

static bool test_oemchangepassword(struct torture_context *tctx,
				   struct smbcli_state *cli)
{

	struct test_join *join_ctx;
	const char *password;
	bool ret;

	join_ctx = torture_create_testuser_max_pwlen(tctx, TEST_RAP_USER,
						     torture_setting_string(tctx, "workgroup", NULL),
						     ACB_NORMAL,
						     &password, 14);
	if (join_ctx == NULL) {
		torture_fail(tctx, "failed to create user\n");
	}

	ret = test_oemchangepassword_args(tctx, cli, TEST_RAP_USER, &password);

	torture_leave_domain(tctx, join_ctx);

	return ret;
}

static bool test_usergetinfo_byname(struct torture_context *tctx,
				    struct smbcli_state *cli,
				    const char *UserName)
{
	struct rap_NetUserGetInfo r;
	int i;
	uint16_t levels[] = { 0, 1, 2, 10, 11 };

	for (i=0; i < ARRAY_SIZE(levels); i++) {

		r.in.UserName = UserName;
		r.in.level = levels[i];
		r.in.bufsize = 8192;

		torture_comment(tctx,
			"Testing rap_NetUserGetInfo(%s) level %d\n", r.in.UserName, r.in.level);

		torture_assert_ntstatus_ok(tctx,
			smbcli_rap_netusergetinfo(cli->tree, tctx, &r),
			"smbcli_rap_netusergetinfo failed");
		torture_assert_werr_ok(tctx, W_ERROR(r.out.status),
			"smbcli_rap_netusergetinfo failed");
	}

	return true;
}

static bool test_usergetinfo(struct torture_context *tctx,
			     struct smbcli_state *cli)
{

	struct test_join *join_ctx;
	const char *password;
	bool ret;

	join_ctx = torture_create_testuser_max_pwlen(tctx, TEST_RAP_USER,
						     torture_setting_string(tctx, "workgroup", NULL),
						     ACB_NORMAL,
						     &password, 14);
	if (join_ctx == NULL) {
		torture_fail(tctx, "failed to create user\n");
	}

	ret = test_usergetinfo_byname(tctx, cli, TEST_RAP_USER);

	torture_leave_domain(tctx, join_ctx);

	return ret;
}

struct torture_suite *torture_rap_sam(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "SAM");

	torture_suite_add_1smb_test(suite, "userpasswordset2", test_userpasswordset2);
	torture_suite_add_1smb_test(suite, "oemchangepassword", test_oemchangepassword);
	torture_suite_add_1smb_test(suite, "usergetinfo", test_usergetinfo);

	return suite;
}
