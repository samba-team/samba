/*
   Unix SMB/CIFS implementation.

   Test DFS blobs.

   Copyright (C) Matthieu Patou <mat@matws.net> 2009

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
#include "torture/ndr/ndr.h"
#include "librpc/gen_ndr/ndr_dfsblobs.h"

static const uint8_t dfs_get_ref_in[] = {
	0x03, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x32, 0x00,
	0x4b, 0x00, 0x33, 0x00, 0x00, 0x00 };

static const uint8_t dfs_get_ref_out[] = {
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x03, 0x00, 0x22, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x58, 0x02, 0x00, 0x00, 0x22, 0x00,
	0x01, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x57, 0x00,
	0x32, 0x00, 0x4b, 0x00, 0x33, 0x00, 0x00, 0x00,
	0x5c, 0x00, 0x57, 0x00, 0x32, 0x00, 0x4b, 0x00,
	0x33, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x30, 0x00,
	0x31, 0x00, 0x00, 0x00 };

struct torture_suite *ndr_dfsblob_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "dfsblob");

	torture_suite_add_ndr_pull_fn_test(suite, dfs_GetDFSReferral_in, dfs_get_ref_in, NDR_IN, NULL);
	torture_suite_add_ndr_pull_fn_test(suite, dfs_referral_resp, dfs_get_ref_out, NDR_BUFFERS|NDR_SCALARS, NULL);

	return suite;
}
