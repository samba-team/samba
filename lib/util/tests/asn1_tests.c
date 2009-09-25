/*
   Unix SMB/CIFS implementation.

   util_asn1 testing

   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2009

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
#include "torture/torture.h"
#include "../asn1.h"

struct oid_data {
	const char *oid;	/* String OID */
	const char *bin_oid;	/* Binary OID represented as string */
};

/* Data for successfull OIDs conversions */
struct oid_data oid_data_ok[] = {
	{
		.oid = "2.5.4.0",
		.bin_oid = "550400"
	},
	{
		.oid = "2.5.4.1",
		.bin_oid = "550401"
	},
	{
		.oid = "2.5.4.130",
		.bin_oid = "55048102"
	},
	{
		.oid = "2.5.130.4",
		.bin_oid = "55810204"
	},
	{
		.oid = "2.5.4.16387",
		.bin_oid = "5504818003"
	},
	{
		.oid = "2.5.16387.4",
		.bin_oid = "5581800304"
	},
	{
		.oid = "2.5.2097155.4",
		.bin_oid = "558180800304"
	},
	{
		.oid = "2.5.4.130.16387.2097155.268435459",
		.bin_oid = "55048102818003818080038180808003"
	},
};



/* Testing ber_write_OID_String() function */
static bool test_ber_write_OID_String(struct torture_context *tctx)
{
	int i;
	char *hex_str;
	DATA_BLOB blob;
	TALLOC_CTX *mem_ctx;
	struct oid_data *data = oid_data_ok;

	mem_ctx = talloc_new(NULL);

	for (i = 0; i < ARRAY_SIZE(oid_data_ok); i++) {
		torture_assert(tctx, ber_write_OID_String(&blob, data[i].oid),
				"ber_write_OID_String failed");

		hex_str = hex_encode_talloc(mem_ctx, blob.data, blob.length);
		torture_assert(tctx, hex_str, "No memory!");

		torture_assert(tctx, strequal(data[i].bin_oid, hex_str),
				talloc_asprintf(mem_ctx,
						"Failed: oid=%s, bin_oid:%s",
						data[i].oid, data[i].bin_oid));
	}

	talloc_free(mem_ctx);

	return true;
}



/* LOCAL-ASN1 test suite creation */
struct torture_suite *torture_local_util_asn1(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "ASN1");

	torture_suite_add_simple_test(suite, "ber_write_OID_String",
				      test_ber_write_OID_String);

	return suite;
}
