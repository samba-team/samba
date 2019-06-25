/*
   Unix SMB/CIFS implementation.

   test suite for DCE/RPC verification trailer parsing

   Copyright (C) David Disseldorp 2014

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
#include <unistd.h>

#include "librpc/gen_ndr/security.h"
#include "lib/param/param.h"
#include "lib/util/dlinklist.h"
#include "libcli/resolve/resolve.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/rpc/rpc_common.h"
#include "torture/torture.h"
#include "torture/local/proto.h"

/* VT blob obtained from an FSRVP request */
uint8_t test_vt[] = {0x8a, 0xe3, 0x13, 0x71, 0x02, 0xf4, 0x36, 0x71,
		     0x02, 0x40, 0x28, 0x00, 0x3c, 0x65, 0xe0, 0xa8,
		     0x44, 0x27, 0x89, 0x43, 0xa6, 0x1d, 0x73, 0x73,
		     0xdf, 0x8b, 0x22, 0x92, 0x01, 0x00, 0x00, 0x00,
		     0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49,
		     0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
		     0x01, 0x00, 0x00, 0x00};

const char *vt_abstr_syntax = "a8e0653c-2744-4389-a61d-7373df8b2292/0x00000001";
const char *vt_trans_syntax = "71710533-beba-4937-8319-b5dbef9ccc36/0x00000001";

static bool test_verif_trailer_pctx(struct torture_context *tctx)
{
	DATA_BLOB blob;
	bool ok;
	struct dcerpc_sec_vt_pcontext pctx;
	struct dcerpc_sec_verification_trailer *vt = NULL;
	struct ndr_pull *ndr;
	enum ndr_err_code ndr_err;
	struct ndr_print *ndr_print;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	torture_assert(tctx, mem_ctx != NULL, "mem");

	blob.data = test_vt;
	blob.length = ARRAY_SIZE(test_vt);

	ndr = ndr_pull_init_blob(&blob, mem_ctx);
	torture_assert(tctx, ndr != NULL, "ndr");

	ndr_err = ndr_pop_dcerpc_sec_verification_trailer(ndr, mem_ctx, &vt);
	torture_assert(tctx, NDR_ERR_CODE_IS_SUCCESS(ndr_err), "ndr");

	ndr_print = talloc_zero(mem_ctx, struct ndr_print);
	torture_assert(tctx, ndr_print != NULL, "mem");
	ndr_print->print = ndr_print_printf_helper;
	ndr_print->depth = 1;

	ndr_print_dcerpc_sec_verification_trailer(ndr_print,
						  "Verification Trailer", vt);

	ZERO_STRUCT(pctx);
	ok = ndr_syntax_id_from_string(vt_abstr_syntax, &pctx.abstract_syntax);
	torture_assert(tctx, ok, "vt_abstr_syntax");
	ok = ndr_syntax_id_from_string(vt_trans_syntax, &pctx.transfer_syntax);
	torture_assert(tctx, ok, "vt_trans_syntax");

	ok = dcerpc_sec_verification_trailer_check(vt, NULL, &pctx, NULL);
	torture_assert(tctx, ok, "VT check");

	talloc_free(mem_ctx);

	return true;
}

struct torture_suite *torture_local_verif_trailer(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx,
							   "verif_trailer");

	torture_suite_add_simple_test(suite,
				      "pctx",
				      test_verif_trailer_pctx);

	return suite;
}
