/*
   Unix SMB/CIFS implementation.
   test suite for drsblobs ndr operations

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
#include "torture/ndr/ndr.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"

static const uint8_t forest_trust_info_data_out[] = {
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x3e, 0xca, 0xca, 0x01, 0x00, 0xaf, 0xd5, 0x9b,
	0x00, 0x07, 0x00, 0x00, 0x00, 0x66, 0x32, 0x2e, 0x74, 0x65, 0x73, 0x74,
	0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xca, 0xca, 0x01,
	0x00, 0xaf, 0xd5, 0x9b, 0x02, 0x18, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x68, 0x4a, 0x64,
	0x28, 0xac, 0x88, 0xa2, 0x74, 0x17, 0x3e, 0x2d, 0x8f, 0x07, 0x00, 0x00,
	0x00, 0x66, 0x32, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x02, 0x00, 0x00, 0x00,
	0x46, 0x32
};

static bool forest_trust_info_check_out(struct torture_context *tctx,
					struct ForestTrustInfo *r)
{
	torture_assert_int_equal(tctx, r->version, 1, "version");
	torture_assert_int_equal(tctx, r->count, 2, "count");
	torture_assert_int_equal(tctx, r->records[0].record_size, 0x00000018, "record size");
	torture_assert_int_equal(tctx, r->records[0].record.flags, 0, "record flags");
	torture_assert_u64_equal(tctx, r->records[0].record.timestamp, 0x9BD5AF0001CACA3E, "record timestamp");
	torture_assert_int_equal(tctx, r->records[0].record.type, FOREST_TRUST_TOP_LEVEL_NAME, "record type");
	torture_assert_int_equal(tctx, r->records[0].record.data.name.size, 7, "record name size");
	torture_assert_str_equal(tctx, r->records[0].record.data.name.string, "f2.test", "record name string");
	torture_assert_int_equal(tctx, r->records[1].record_size, 0x0000003a, "record size");
	torture_assert_int_equal(tctx, r->records[1].record.flags, 0, "record flags");
	torture_assert_u64_equal(tctx, r->records[1].record.timestamp, 0x9BD5AF0001CACA3E, "record timestamp");
	torture_assert_int_equal(tctx, r->records[1].record.type, FOREST_TRUST_DOMAIN_INFO, "record type");
	torture_assert_int_equal(tctx, r->records[1].record.data.info.sid_size, 0x00000018, "record info sid_size");
	torture_assert_sid_equal(tctx, &r->records[1].record.data.info.sid, dom_sid_parse_talloc(tctx, "S-1-5-21-677661288-1956808876-2402106903"), "record info sid");
	torture_assert_int_equal(tctx, r->records[1].record.data.info.dns_name.size, 7, "record name size");
	torture_assert_str_equal(tctx, r->records[1].record.data.info.dns_name.string, "f2.test", "record info dns_name string");
	torture_assert_int_equal(tctx, r->records[1].record.data.info.netbios_name.size, 2, "record info netbios_name size");
	torture_assert_str_equal(tctx, r->records[1].record.data.info.netbios_name.string, "F2", "record info netbios_name string");

	return true;
}

struct torture_suite *ndr_drsblobs_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "drsblobs");

	torture_suite_add_ndr_pull_fn_test(suite, ForestTrustInfo, forest_trust_info_data_out, NDR_IN, forest_trust_info_check_out);

	return suite;
}
