/* 
   Unix SMB/CIFS implementation.
   test suite for winreg ndr operations

   Copyright (C) Jelmer Vernooij 2007
   
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
#include "torture/ndr/ndr.h"
#include "librpc/gen_ndr/ndr_winreg.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"

static const uint8_t winreg_closekey_data[] = { 
        0x00, 0x00, 0x00, 0x00, 0x1d, 0xd8, 0xd7, 0xaa, 0x8d, 0x6c, 0x3f, 0x48, 
        0xa7, 0x1e, 0x02, 0x6a, 0x47, 0xf6, 0x7b, 0xae
};

static bool winreg_closekey_check(struct torture_context *tctx, 
								  struct winreg_CloseKey *ck)
{
	torture_assert(tctx, ck->in.handle != NULL, "handle invalid");
	torture_assert_int_equal(tctx, ck->in.handle->handle_type, 0, "handle type");
	return true;
}

struct torture_suite *ndr_winreg_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "winreg");

	torture_suite_add_ndr_pull_fn_test(suite, winreg_CloseKey, winreg_closekey_data, NDR_IN, winreg_closekey_check );

	return suite;
}
