/*
 * Unit tests for source4/kdc/sdb_to_hdb.c
 *
 * Copyright (C) Gary Lockyer 2025
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

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 *
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include "../../../third_party/cmocka/cmocka.h"

#include "../sdb_to_hdb.c"
#include "hdb_asn1.h"

/*
 * Test that an empty sdb_pub_key is handled without error and that
 * the expected value is generated
 */
static void empty_key(void **state)
{
	uint8_t empty_key[] = {
		0x30, 0x1a, /* Sequence 26 bytes, 2 elements */
		0x30, 0x0d, /* Sequence 13 bytes, 2 elements */
		0x06, 0x09, /* OID 9 bytes, 1.2.840.113549.1.1.1 */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
		0x05, 0x00, /* Null */
		0x03, 0x09, 0x00, /* Bit string 9 bytes, zero unused bits */
		0x30, 0x06, /* Sequence 6 bytes, 2 elements */
		0x02, 0x01, 0x00, /* Integer 1 byte, value 0, Modulus */
		0x02, 0x01, 0x00, /* Integer 1 byte, value 0, Exponent */
	};
	struct sdb_pub_key in = {};
	struct HDB_Ext_KeyTrust_val out = {};
	int ret = 0;

	ret = sdb_pub_key_to_hdb_key_trust_val(&in, &out);

	assert_int_equal(0, ret);
	assert_int_equal(sizeof(empty_key), out.pub_key.length);
	assert_memory_equal(empty_key,
			    out.pub_key.data,
			    sizeof(empty_key));

	free(out.pub_key.data);
}

/*
 * Test that modulus and exponent with the leading bit set,
 * are handled correctly
 */
static void test_leading_bit_handling(void **state)
{
	uint8_t expected_key[] = {
		0x30, 0x1c, /* Sequence 281 bytes, 2 elements */
		0x30, 0x0d, /* Sequence 13 bytes, 2 elements */
		0x06, 0x09, /* OID 9 bytes, 1.2.840.113549.1.1.1 */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
		0x05, 0x00, /* Null */
		0x03, 0x0b, 0x00, /* Bit string 11 bytes, zero unused bits */
		0x30, 0x08, /* Sequence 8 bytes, 2 elements */
		0x02, 0x02, 0x00, 0x80, /* Integer 2 byte, value 0, Modulus */
		0x02, 0x02, 0x00, 0x81, /* Integer 2 byte, value 0, Exponent */
		/*
		 * As the modulus and exponent have the leading bit set
		 * They should get encoded with a leading 0 byte
		 */
	};
	uint8_t modulus[] = {0x80};
	uint8_t exponent[] = {0x81};
	struct sdb_pub_key in = {};
	struct HDB_Ext_KeyTrust_val out = {};

	int ret = 0;
	in.bit_size = 8;

	in.modulus.data = &modulus;
	in.modulus.length = sizeof(modulus);

	in.exponent.data = &exponent;
	in.exponent.length = sizeof(exponent);


	ret = sdb_pub_key_to_hdb_key_trust_val(&in, &out);

	assert_int_equal(0, ret);
	assert_int_equal(sizeof(expected_key), out.pub_key.length);
	assert_memory_equal(expected_key,
			    out.pub_key.data,
			    sizeof(expected_key));

	free(out.pub_key.data);
}
/*
 * Test that modulus and exponent with the leading bit not set,
 * are handled correctly
 */
static void test_no_leading_bit(void **state)
{
	uint8_t expected_key[] = {
		0x30, 0x1c, /* Sequence 281 bytes, 2 elements */
		0x30, 0x0d, /* Sequence 13 bytes, 2 elements */
		0x06, 0x09, /* OID 9 bytes, 1.2.840.113549.1.1.1 */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
		0x05, 0x00, /* Null */
		0x03, 0x0b, 0x00, /* Bit string 11 bytes, zero unused bits */
		0x30, 0x08, /* Sequence 8 bytes, 2 elements */
		0x02, 0x02, 0x78, 0x9a, /* Integer 2 byte, value 0, Modulus */
		0x02, 0x02, 0x65, 0x43, /* Integer 2 byte, value 0, Exponent */
	};
	uint8_t modulus[] = {0x78, 0x9a};
	uint8_t exponent[] = {0x65, 0x43};
	struct sdb_pub_key in = {};
	struct HDB_Ext_KeyTrust_val out = {};

	int ret = 0;
	in.bit_size = 8;

	in.modulus.data = &modulus;
	in.modulus.length = sizeof(modulus);

	in.exponent.data = &exponent;
	in.exponent.length = sizeof(exponent);


	ret = sdb_pub_key_to_hdb_key_trust_val(&in, &out);

	assert_int_equal(0, ret);
	assert_int_equal(sizeof(expected_key), out.pub_key.length);
	assert_memory_equal(expected_key,
			    out.pub_key.data,
			    sizeof(expected_key));

	free(out.pub_key.data);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(empty_key),
		cmocka_unit_test(test_leading_bit_handling),
		cmocka_unit_test(test_no_leading_bit),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
