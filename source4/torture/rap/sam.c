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

static bool test_userpasswordset2(struct torture_context *tctx,
				  struct smbcli_state *cli)
{
	struct rap_NetUserPasswordSet2 r;

	r.in.UserName = "gd";
	r.in.OldPassword = "secret";
	r.in.NewPassword = "newpwd";
	r.in.EncryptedPassword = 0;
	r.in.RealPasswordLength = strlen(r.in.NewPassword);

	torture_comment(tctx, "Testing rap_NetUserPasswordSet2(%s)\n", r.in.UserName);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netuserpasswordset2(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netuserpasswordset2 failed");

	return true;
}

static bool test_oemchangepassword(struct torture_context *tctx,
				   struct smbcli_state *cli)
{
	struct rap_NetOEMChangePassword r;

	const char *oldpass = "secret";
	const char *newpass = "newpwd";
	uint8_t old_pw_hash[16];
	uint8_t new_pw_hash[16];

	r.in.UserName = "gd";

	E_deshash(oldpass, old_pw_hash);
	E_deshash(newpass, new_pw_hash);

	encode_pw_buffer(r.in.crypt_password, newpass, STR_ASCII);
	arcfour_crypt(r.in.crypt_password, old_pw_hash, 516);
	E_old_pw_hash(new_pw_hash, old_pw_hash, r.in.password_hash);

	torture_comment(tctx, "Testing rap_NetOEMChangePassword(%s)\n", r.in.UserName);

	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netoemchangepassword(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"smbcli_rap_netoemchangepassword failed");

	return true;
}

struct torture_suite *torture_rap_sam(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "SAM");

	torture_suite_add_1smb_test(suite, "userpasswordset2", test_userpasswordset2);
	torture_suite_add_1smb_test(suite, "oemchangepassword", test_oemchangepassword);

	return suite;
}
