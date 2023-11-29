/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Catalyst.Net Ltd 2023
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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <talloc.h>

#include "lib/replace/replace.h"
#include "lib/util/genrand.h"
#include "lib/crypto/gnutls_helpers.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "lib/crypto/gnutls_helpers.h"

static void test_sp800_108_sha256(void **state)
{
	NTSTATUS status;
	static const uint8_t key[] = {152, 203, 215, 84,  113, 216, 118, 177,
				      81,  128, 50,  160, 148, 132, 82,	 244,
				      65,  179, 164, 219, 209, 14,  33,	 131,
				      178, 193, 80,  248, 126, 23,  66,	 227,
				      45,  221, 171, 12,  247, 15,  62,	 179,
				      164, 217, 123, 179, 106, 118, 228, 74,
				      12,  2,	241, 229, 139, 55,  237, 155,
				      220, 122, 200, 245, 129, 222, 37,	 15};
	static const uint8_t context[] = {114, 233, 112, 1,   53,  160, 76,
					  175, 153, 59,	 224, 82,  213, 189,
					  18,  22,  106, 1,   0,   0,	255,
					  255, 255, 255, 255, 255, 255, 255};
	static const uint8_t label[] = {'K', 0, 'D', 0, 'S', 0, ' ', 0,
					's', 0, 'e', 0, 'r', 0, 'v', 0,
					'i', 0, 'c', 0, 'e', 0, 0,   0};
	static const uint8_t expected[] = {219, 94,  173, 243, 157, 13,	 49,
					   57,	54,  3,	  127, 239, 193, 4,
					   220, 218, 252, 33,  105, 76,	 18,
					   140, 166, 177, 95,  65,  164, 18,
					   52,	169, 9,	  194};
	uint8_t out[sizeof expected];

	status = samba_gnutls_sp800_108_derive_key(key,
						   sizeof key,
						   label,
						   sizeof label,
						   context,
						   sizeof context,
						   GNUTLS_MAC_SHA256,
						   out,
						   sizeof out);
	assert_true(NT_STATUS_IS_OK(status));
	assert_memory_equal(expected, out, sizeof out);
}

static void test_sp800_108_sha512(void **state)
{
	NTSTATUS status;
	static const uint8_t key[] = {152, 203, 215, 84,  113, 216, 118, 177,
				      81,  128, 50,  160, 148, 132, 82,	 244,
				      65,  179, 164, 219, 209, 14,  33,	 131,
				      178, 193, 80,  248, 126, 23,  66,	 227,
				      45,  221, 171, 12,  247, 15,  62,	 179,
				      164, 217, 123, 179, 106, 118, 228, 74,
				      12,  2,	241, 229, 139, 55,  237, 155,
				      220, 122, 200, 245, 129, 222, 37,	 15};
	static const uint8_t context[] = {114, 233, 112, 1,   53,  160, 76,
					  175, 153, 59,	 224, 82,  213, 189,
					  18,  22,  106, 1,   0,   0,	255,
					  255, 255, 255, 255, 255, 255, 255};
	static const uint8_t label[] = {'K', 0, 'D', 0, 'S', 0, ' ', 0,
					's', 0, 'e', 0, 'r', 0, 'v', 0,
					'i', 0, 'c', 0, 'e', 0, 0,   0};
	static const uint8_t expected[] = {
		7,   24,  223, 124, 39,	 199, 153, 162, 178, 37,  249, 182, 253,
		103, 255, 46,  60,  102, 61,  116, 186, 74,  221, 37,  242, 137,
		234, 58,  125, 105, 64,	 127, 42,  175, 82,  141, 104, 210, 231,
		17,  116, 215, 15,  144, 200, 234, 66,	162, 196, 216, 48,  111,
		239, 86,  93,  32,  81,	 206, 12,  145, 136, 185, 81,  56};
	uint8_t out[sizeof expected];

	status = samba_gnutls_sp800_108_derive_key(key,
						   sizeof key,
						   label,
						   sizeof label,
						   context,
						   sizeof context,
						   GNUTLS_MAC_SHA512,
						   out,
						   sizeof out);
	assert_true(NT_STATUS_IS_OK(status));
	assert_memory_equal(expected, out, sizeof out);
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sp800_108_sha256),
		cmocka_unit_test(test_sp800_108_sha512),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}
