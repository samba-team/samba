/*
 * Unix SMB/CIFS implementation.
 *
 * test SMB2 multichannel operations
 *
 * Copyright (C) Guenther Deschner, 2016
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect status %s - should be %s\n", \
			 __location__, nt_errstr(status), nt_errstr(correct)); \
		return false; \
	} } while (0)

static bool test_session_bind(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	/* TODO */

	return true;
}

struct torture_suite *torture_smb2_multichannel_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "multichannel");

	torture_suite_add_1smb2_test(suite, "session-bind", test_session_bind);

	suite->description = talloc_strdup(suite, "SMB2 Multichannel tests");

	return suite;
}
