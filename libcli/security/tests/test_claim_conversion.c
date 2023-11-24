/*
 * Unit tests for conditional ACE SDDL.
 *
 *  Copyright (C) Catalyst.NET Ltd 2023
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
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmocka.h"

#include "lib/util/attr.h"
#include "includes.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"
#include "librpc/gen_ndr/conditional_ace.h"
#include "libcli/security/claims-conversions.h"
#include "librpc/gen_ndr/ndr_claims.h"

#define debug_message(...) print_message(__VA_ARGS__)

#define debug_fail(x, ...) print_message("\033[1;31m" x "\033[0m", __VA_ARGS__)
#define debug_ok(x, ...) print_message("\033[1;32m" x "\033[0m", __VA_ARGS__)

#define assert_ntstatus_equal(got, expected, comment)	  \
	do { NTSTATUS __got = got, __expected = expected;		\
		if (!NT_STATUS_EQUAL(__got, __expected)) {		\
			print_message(": "#got" was %s, expected %s: %s", \
				      nt_errstr(__got),			\
				      nt_errstr(__expected), comment);	\
			fail();						\
		}							\
	} while(0)



static DATA_BLOB datablob_from_file(TALLOC_CTX *mem_ctx,
				    const char *filename)
{
	DATA_BLOB b = {0};
	FILE *fh = fopen(filename, "rb");
	int ret;
	struct stat s;
	size_t len;
	if (fh == NULL) {
		debug_message("could not open '%s'\n", filename);
		return b;
	}
	ret = fstat(fileno(fh), &s);
	if (ret != 0) {
		fclose(fh);
		return b;
	}
	b.data = talloc_array(mem_ctx, uint8_t, s.st_size);
	if (b.data == NULL) {
		fclose(fh);
		return b;
	}
	len = fread(b.data, 1, s.st_size, fh);
	if (ferror(fh) || len != s.st_size) {
		TALLOC_FREE(b.data);
	} else {
		b.length = len;
	}
	fclose(fh);
	return b;
}


static void _test_one_ndr_dump(void **state, const char *name)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct CLAIMS_SET claims_set;
	DATA_BLOB blob;
	NTSTATUS status;
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *out_claims = NULL;
	uint32_t out_n_claims = 0;
	enum ndr_err_code ndr_err;
	char filename[200];
	snprintf(filename, sizeof(filename),
		 "libcli/security/tests/data/ndr_dumps/%s", name);

	blob = datablob_from_file(tmp_ctx, filename);
	ndr_err = ndr_pull_struct_blob(
		&blob, tmp_ctx, &claims_set,
		(ndr_pull_flags_fn_t)ndr_pull_CLAIMS_SET);
	assert_int_equal(ndr_err, NDR_ERR_SUCCESS);

	status = token_claims_to_claims_v1(tmp_ctx,
					   &claims_set,
					   &out_claims,
					   &out_n_claims);
	assert_ntstatus_equal(status, NT_STATUS_OK, "sigh\n");
}



static void test_fileb5iJt4(void **state)
{
	_test_one_ndr_dump(state, "fileb5iJt4");
}

static void test_fileb8cNVS(void **state)
{
	_test_one_ndr_dump(state, "fileb8cNVS");
}

static void test_filebI7h5H(void **state)
{
	_test_one_ndr_dump(state, "filebI7h5H");
}

static void test_filebNdBgt(void **state)
{
	_test_one_ndr_dump(state, "filebNdBgt");
}

static void test_filebOjK4H(void **state)
{
	_test_one_ndr_dump(state, "filebOjK4H");
}

static void test_filebzCPTH(void **state)
{
	_test_one_ndr_dump(state, "filebzCPTH");
}




int main(_UNUSED_ int argc, _UNUSED_ const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_fileb5iJt4),
		cmocka_unit_test(test_fileb8cNVS),
		cmocka_unit_test(test_filebI7h5H),
		cmocka_unit_test(test_filebNdBgt),
		cmocka_unit_test(test_filebOjK4H),
		cmocka_unit_test(test_filebzCPTH),
	};
	if (isatty(1)) {
		/*
		 * interactive testers can set debug level
		 * -- just give it a number.
		 */
		int debug_level = DBGLVL_WARNING;
		if (argc > 1) {
			debug_level = atoi(argv[1]);
		}
		debuglevel_set(debug_level);

	} else {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}
