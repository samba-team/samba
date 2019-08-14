/*
 * Tests for mdssvc packets (un)marshalling
 *
 * Copyright Ralph Boehme <slow@samba.org> 2019
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

#include "replace.h"
#include <talloc.h>
#include "libcli/util/ntstatus.h"
#include "lib/util/samba_util.h"
#include "lib/torture/torture.h"
#include "lib/util/data_blob.h"
#include "torture/local/proto.h"
#include "mdssvc/marshalling.h"

static const unsigned char mdspkt_empty_cnid_fm[] = {
	0x34, 0x33, 0x32, 0x31, 0x33, 0x30, 0x64, 0x6d,
	0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x84, 0x01, 0x00, 0x00, 0x00,
	0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x87, 0x08, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x0a, 0x03, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00,
	0x07, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00
};

static const char *mdspkt_empty_cnid_fm_dump =
"DALLOC_CTX(#1): {\n"
"	sl_array_t(#3): {\n"
"		uint64_t: 0x0023\n"
"		CNIDs: unkn1: 0x0, unkn2: 0x0\n"
"			DALLOC_CTX(#0): {\n"
"			}\n"
"		sl_filemeta_t(#0): {\n"
"		}\n"
"	}\n"
"}\n";

static bool test_mdspkt_empty_cnid_fm(struct torture_context *tctx)
{
	DALLOC_CTX *d = NULL;
	sl_cnids_t *cnids = NULL;
	char *dstr = NULL;
	size_t ncnids;
	bool ret = true;

	d = dalloc_new(tctx);
	torture_assert_not_null_goto(tctx, d, ret, done,
				     "dalloc_new failed\n");

	ret = sl_unpack(d,
			(const char *)mdspkt_empty_cnid_fm,
			sizeof(mdspkt_empty_cnid_fm));
	torture_assert_goto(tctx, ret, ret, done, "sl_unpack failed\n");

	cnids = dalloc_get(d, "DALLOC_CTX", 0, "sl_cnids_t", 1);
	torture_assert_not_null_goto(tctx, cnids, ret, done,
				     "dalloc_get cnids failed\n");

	ncnids = dalloc_size(cnids->ca_cnids);
	torture_assert_int_equal_goto(tctx, ncnids, 0, ret, done,
				      "Wrong number of CNIDs\n");

	dstr = dalloc_dump(d, 0);
	torture_assert_not_null_goto(tctx, dstr, ret, done,
				     "dalloc_dump failed\n");

	torture_assert_str_equal_goto(tctx, dstr, mdspkt_empty_cnid_fm_dump,
				      ret, done, "Bad dump\n");

done:
	TALLOC_FREE(d);
	return ret;
}

struct torture_suite *torture_local_mdspkt(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite =
		torture_suite_create(mem_ctx, "mdspkt");

	torture_suite_add_simple_test(suite,
				      "empty_cnid_fm",
				      test_mdspkt_empty_cnid_fm);

	return suite;
}
