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
#include <stdint.h>

#include <cmocka.h>

#include "../sdb_to_hdb.c"
#include "hdb_asn1.h"
#include "util/data_blob.h"

#define assert_empty(a)\
	_assert_int_equal((0), (a)->length, __FILE__, __LINE__);\
	_assert_true(!(cast_ptr_to_largest_integral_type(a)), #a, \
	__FILE__, __LINE__)

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

/*
 * Ensure that sdb_cert_mapping_to_hdb_key_trust_val handles an
 * empty sdb_certificate_mapping
 */
static void cert_map_empty_sdb_mapping(void **state)
{
	struct sdb_certificate_mapping m = {};
	struct HDB_Ext_CertificateMapping h = {};
	int ret = 0;

	ret = sdb_cert_mapping_to_hdb_key_trust_val(&m, &h);

	assert_int_equal(0, ret);
	assert_false(h.strong_mapping);
	assert_null(h.serial_number);
	assert_null(h.rfc822);
	assert_null(h.ski);
	assert_null(h.issuer_name);
	assert_null(h.subject_name);
	assert_null(h.public_key);

	free_HDB_Ext_CertificateMapping(&h);
}

/*
 * Ensure that sdb_cert_mapping_to_hdb_key_trust_val correctly maps the
 * subject_name
 */
static void cert_map_subject_name_mapping(void **state)
{
	struct sdb_certificate_mapping m = {};
	struct HDB_Ext_CertificateMapping h = {};
	int ret = 0;
	DATA_BLOB subject_name = data_blob_string_const("DN=SubjectName");

	m.subject_name.data = subject_name.data;
	m.subject_name.length = subject_name.length;
	m.strong_mapping = FALSE;

	ret = sdb_cert_mapping_to_hdb_key_trust_val(&m, &h);

	assert_int_equal(0, ret);

	assert_non_null(h.subject_name);
	assert_memory_equal(
		subject_name.data, h.subject_name->data, subject_name.length);
	assert_int_equal(subject_name.length, h.subject_name->length);

	assert_false(h.strong_mapping);

	assert_null(h.serial_number);
	assert_null(h.rfc822);
	assert_null(h.ski);
	assert_null(h.issuer_name);
	assert_null(h.public_key);

	free_HDB_Ext_CertificateMapping(&h);
}

/*
 * Ensure that sdb_cert_mapping_to_hdb_key_trust_val correctly maps the
 * issuer_name
 */
static void cert_map_issuer_name_mapping(void **state)
{
	struct sdb_certificate_mapping m = {};
	struct HDB_Ext_CertificateMapping h = {};
	int ret = 0;
	DATA_BLOB issuer_name =
		data_blob_string_const("DC=local,DC=samba,CN=Things");

	m.issuer_name.data = issuer_name.data;
	m.issuer_name.length = issuer_name.length;
	m.strong_mapping = TRUE;

	ret = sdb_cert_mapping_to_hdb_key_trust_val(&m, &h);

	assert_int_equal(0, ret);

	assert_non_null(h.issuer_name);
	assert_memory_equal(
		issuer_name.data, h.issuer_name->data, issuer_name.length);
	assert_int_equal(issuer_name.length, h.issuer_name->length);

	assert_true(h.strong_mapping);

	assert_null(h.serial_number);
	assert_null(h.rfc822);
	assert_null(h.ski);
	assert_null(h.subject_name);
	assert_null(h.public_key);

	free_HDB_Ext_CertificateMapping(&h);
}


/*
 * Ensure that sdb_cert_mapping_to_hdb_key_trust_val correctly maps the
 * serial_number
 */
static void cert_map_serial_number_mapping(void **state)
{
	struct sdb_certificate_mapping m = {};
	struct HDB_Ext_CertificateMapping h = {};
	int ret = 0;
	DATA_BLOB serial_number =
		data_blob_string_const("1234BACXXXXXX");

	m.serial_number.data = serial_number.data;
	m.serial_number.length = serial_number.length;

	ret = sdb_cert_mapping_to_hdb_key_trust_val(&m, &h);

	assert_int_equal(0, ret);

	assert_non_null(h.serial_number);
	assert_memory_equal(
		serial_number.data, h.serial_number->data, serial_number.length);
	assert_int_equal(serial_number.length, h.serial_number->length);

	assert_false(h.strong_mapping);

	assert_null(h.rfc822);
	assert_null(h.ski);
	assert_null(h.issuer_name);
	assert_null(h.subject_name);
	assert_null(h.public_key);

	free_HDB_Ext_CertificateMapping(&h);
}

/*
 * Ensure that sdb_cert_mapping_to_hdb_key_trust_val correctly maps the
 * public_key
 */
static void cert_map_public_key_mapping(void **state)
{
	struct sdb_certificate_mapping m = {};
	struct HDB_Ext_CertificateMapping h = {};
	int ret = 0;
	DATA_BLOB public_key =
		data_blob_string_const("abcdefghij");

	m.public_key.data = public_key.data;
	m.public_key.length = public_key.length;

	ret = sdb_cert_mapping_to_hdb_key_trust_val(&m, &h);

	assert_int_equal(0, ret);

	assert_non_null(h.public_key);
	assert_memory_equal(
		public_key.data, h.public_key->data, public_key.length);
	assert_int_equal(public_key.length, h.public_key->length);

	assert_false(h.strong_mapping);

	assert_null(h.serial_number);
	assert_null(h.rfc822);
	assert_null(h.ski);
	assert_null(h.issuer_name);
	assert_null(h.subject_name);

	free_HDB_Ext_CertificateMapping(&h);
}

/*
 * Ensure that sdb_cert_mapping_to_hdb_key_trust_val correctly maps the
 * RFC822 (email address)
 */
static void cert_map_RFC822_mapping(void **state)
{
	struct sdb_certificate_mapping m = {};
	struct HDB_Ext_CertificateMapping h = {};
	int ret = 0;
	DATA_BLOB rfc822 =
		data_blob_string_const("test@test.org");

	m.rfc822.data = rfc822.data;
	m.rfc822.length = rfc822.length;

	ret = sdb_cert_mapping_to_hdb_key_trust_val(&m, &h);

	assert_int_equal(0, ret);

	assert_non_null(h.rfc822);
	assert_memory_equal(
		rfc822.data, h.rfc822->data, rfc822.length);
	assert_int_equal(rfc822.length, h.rfc822->length);

	assert_false(h.strong_mapping);

	assert_null(h.serial_number);
	assert_null(h.ski);
	assert_null(h.issuer_name);
	assert_null(h.subject_name);
	assert_null(h.public_key);

	free_HDB_Ext_CertificateMapping(&h);
}

/*
 * Ensure that sdb_cert_mapping_to_hdb_key_trust_val correctly maps the
 * SKI (Subject Key Identifier)
 */
static void cert_map_ski_mapping(void **state)
{
	struct sdb_certificate_mapping m = {};
	struct HDB_Ext_CertificateMapping h = {};
	int ret = 0;
	DATA_BLOB ski =
		data_blob_string_const("cdef123455");

	m.ski.data = ski.data;
	m.ski.length = ski.length;

	ret = sdb_cert_mapping_to_hdb_key_trust_val(&m, &h);

	assert_int_equal(0, ret);

	assert_non_null(h.ski);
	assert_memory_equal(
		ski.data, h.ski->data, ski.length);
	assert_int_equal(ski.length, h.ski->length);

	assert_false(h.strong_mapping);

	assert_null(h.serial_number);
	assert_null(h.rfc822);
	assert_null(h.issuer_name);
	assert_null(h.subject_name);
	assert_null(h.public_key);

	free_HDB_Ext_CertificateMapping(&h);
}

/*
 * Ensure that sdb_cert_mapping_to_hdb_key_trust_val correctly maps
 * all values if provided
 */
static void cert_map_all(void **state)
{
	struct sdb_certificate_mapping m = {};
	struct HDB_Ext_CertificateMapping h = {};
	int ret = 0;
	DATA_BLOB issuer_name =
		data_blob_string_const("DC=local,DC=samba,CN=Things");
	DATA_BLOB subject_name = data_blob_string_const("DN=SubjectName");
	DATA_BLOB serial_number =
		data_blob_string_const("1234BACXXXXXX");
	DATA_BLOB public_key =
		data_blob_string_const("abcdefghij");
	DATA_BLOB rfc822 =
		data_blob_string_const("test@test.org");
	DATA_BLOB ski =
		data_blob_string_const("cdef123455");

	m.ski.data = ski.data;
	m.ski.length = ski.length;

	m.rfc822.data = rfc822.data;
	m.rfc822.length = rfc822.length;

	m.public_key.data = public_key.data;
	m.public_key.length = public_key.length;

	m.serial_number.data = serial_number.data;
	m.serial_number.length = serial_number.length;

	m.subject_name.data = subject_name.data;
	m.subject_name.length = subject_name.length;

	m.issuer_name.data = issuer_name.data;
	m.issuer_name.length = issuer_name.length;

	ret = sdb_cert_mapping_to_hdb_key_trust_val(&m, &h);

	assert_int_equal(0, ret);

	assert_memory_equal(
		issuer_name.data, h.issuer_name->data, issuer_name.length);
	assert_int_equal(issuer_name.length, h.issuer_name->length);

	assert_memory_equal(
		serial_number.data, h.serial_number->data, serial_number.length);
	assert_int_equal(serial_number.length, h.serial_number->length);

	assert_memory_equal(
		rfc822.data, h.rfc822->data, rfc822.length);
	assert_int_equal(rfc822.length, h.rfc822->length);

	assert_memory_equal(
		ski.data, h.ski->data, ski.length);
	assert_int_equal(ski.length, h.ski->length);

	assert_memory_equal(
		subject_name.data, h.subject_name->data, subject_name.length);
	assert_int_equal(subject_name.length, h.subject_name->length);

	assert_memory_equal(
		public_key.data, h.public_key->data, public_key.length);
	assert_int_equal(public_key.length, h.public_key->length);

	free_HDB_Ext_CertificateMapping(&h);
}

static void cert_mappings_empty_sdb(void **state)
{
	struct sdb_certificate_mappings m = {};
	HDB_Ext_CertificateMappings h = {};
	int ret = 0;

	ret = sdb_certificate_mappings_to_hdb_ext(&m, &h);
	assert_int_equal(0, ret);

	assert_null(h.mappings);
	assert_int_equal(0, h.valid_certificate_start);
	assert_int_equal(0, h.enforcement_mode);

	free_HDB_Ext_CertificateMappings(&h);
}


static void cert_mappings_one_mapping(void **state)
{
	struct sdb_certificate_mappings m = {};
	struct sdb_certificate_mapping cm = {};
	HDB_Ext_CertificateMappings h = {};
	int ret = 0;

	DATA_BLOB ski =
		data_blob_string_const("cdef123455");

	cm.ski.data = ski.data;
	cm.ski.length = ski.length;
	cm.strong_mapping = TRUE;

	m.enforcement_mode = 2;
	m.valid_certificate_start = 100;

	m.len = 1;
	m.mappings = &cm;


	ret = sdb_certificate_mappings_to_hdb_ext(&m, &h);
	assert_int_equal(0, ret);

	assert_non_null(h.mappings);
	assert_int_equal(100, h.valid_certificate_start);
	assert_int_equal(2, h.enforcement_mode);

	free_HDB_Ext_CertificateMappings(&h);
}

static void cert_mappings_two_mappings(void **state)
{
	struct sdb_certificate_mappings m = {};
	struct sdb_certificate_mapping cm1 = {};
	struct sdb_certificate_mapping cm2 = {};
	HDB_Ext_CertificateMappings h = {};
	struct sdb_certificate_mapping mappings[] = {cm1, cm2};
	int ret = 0;

	DATA_BLOB ski =
		data_blob_string_const("cdef123455");
	DATA_BLOB rfc822 =
		data_blob_string_const("test@test.org");

	cm1.ski.data = ski.data;
	cm1.ski.length = ski.length;
	cm1.strong_mapping = TRUE;

	cm2.rfc822.data = rfc822.data;
	cm2.rfc822.length = rfc822.length;
	cm2.strong_mapping = FALSE;

	m.enforcement_mode = 2;
	m.valid_certificate_start = 100;

	m.len = 2;
	m.mappings = mappings;


	ret = sdb_certificate_mappings_to_hdb_ext(&m, &h);
	assert_int_equal(0, ret);

	assert_non_null(h.mappings);
	assert_int_equal(100, h.valid_certificate_start);
	assert_int_equal(2, h.enforcement_mode);

	free_HDB_Ext_CertificateMappings(&h);
}
int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(empty_key),
		cmocka_unit_test(test_leading_bit_handling),
		cmocka_unit_test(test_no_leading_bit),
		cmocka_unit_test(cert_map_empty_sdb_mapping),
		cmocka_unit_test(cert_map_subject_name_mapping),
		cmocka_unit_test(cert_map_issuer_name_mapping),
		cmocka_unit_test(cert_map_serial_number_mapping),
		cmocka_unit_test(cert_map_public_key_mapping),
		cmocka_unit_test(cert_map_RFC822_mapping),
		cmocka_unit_test(cert_map_ski_mapping),
		cmocka_unit_test(cert_map_all),
		cmocka_unit_test(cert_mappings_empty_sdb),
		cmocka_unit_test(cert_mappings_one_mapping),
		cmocka_unit_test(cert_mappings_two_mappings),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
