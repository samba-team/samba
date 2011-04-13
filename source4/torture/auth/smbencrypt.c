/*
   Unix SMB/CIFS implementation.

   tests for smbencrypt code

   Copyright (C) Andrew Tridgell 2011
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2011

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
#include "libcli/auth/libcli_auth.h"
#include "torture/torture.h"
#include "torture/auth/proto.h"

static bool torture_deshash(struct torture_context *tctx)
{
	struct {
		const char *input;
		uint8_t output[16];
		bool should_pass;
	} testcases[] = {
		{ "",
		  { 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
		    0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE }, true},
		{ "abcdefgh",
		  { 0xE0, 0xC5, 0x10, 0x19, 0x9C, 0xC6, 0x6A, 0xBD,
		    0x5A, 0xCD, 0xCD, 0x7C, 0x24, 0x7F, 0xA8, 0x3A }, true},
		{ "0123456789abc",
		  { 0x56, 0x45, 0xF1, 0x3F, 0x50, 0x08, 0x82, 0xB2,
		    0x50, 0x79, 0x8A, 0xE6, 0x33, 0x38, 0xAF, 0xE9 }, true},
		{ "0123456789abcd",
		  { 0x56, 0x45, 0xF1, 0x3F, 0x50, 0x08, 0x82, 0xB2,
		    0x1A, 0xC3, 0x88, 0x4B, 0x83, 0x32, 0x45, 0x40 }, true},
		{ "0123456789abcde",
		  { 0x56, 0x45, 0xF1, 0x3F, 0x50, 0x08, 0x82, 0xB2,
		    0x1A, 0xC3, 0x88, 0x4B, 0x83, 0x32, 0x45, 0x40 }, false},
	};
	int i;
	for (i=0; i<ARRAY_SIZE(testcases); i++) {
		uint8_t res[16];
		bool ret;
		ret = E_deshash(testcases[i].input, res);
		torture_assert(tctx, ret == testcases[i].should_pass,
			       "E_deshash bad result");
		torture_assert_mem_equal(tctx, res, testcases[i].output, 16, "E_deshash bad return data");
	}
	return true;
}

struct torture_suite *torture_smbencrypt(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "smbencrypt");

	torture_suite_add_simple_test(suite, "deshash check", torture_deshash);

	return suite;
}
