/*
 * Unit tests for source4/rpc_server/dnsserver/dnsutils.c
 *
 *  Copyright (C) Catalyst.NET Ltd 2018
 *  Copyright (C) Andrew Bartlett 2019
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


#include "../repl_decrypt.c"


/*
 * test encryption and decryption including RID obfustincation
 */
static void test_drsuapi_rid_encrypt_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	uint8_t test_data[] = { 0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04 };
	const uint32_t rid = 514;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB plaintext = data_blob_const(test_data,
					     sizeof(test_data));
	DATA_BLOB encrypted;
	DATA_BLOB decrypted;

	werr = drsuapi_encrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &plaintext,
					       &encrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_OK));
	assert_int_not_equal(encrypted.length, plaintext.length);

	werr = drsuapi_decrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &encrypted,
					       &decrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_OK));

	assert_int_equal(decrypted.length, plaintext.length);

	assert_memory_equal(decrypted.data, plaintext.data, plaintext.length);
	TALLOC_FREE(mem_ctx);
}

/*
 * test encryption and decryption failing RID obfustincation (data length)
 */
static void test_drsuapi_bad_len_rid_encrypt_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	uint8_t test_data[] = { 0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04, 0x05 };
	const uint32_t rid = 514;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB plaintext = data_blob_const(test_data,
					     sizeof(test_data));
	DATA_BLOB encrypted;

	werr = drsuapi_encrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &plaintext,
					       &encrypted);

	assert_int_equal(W_ERROR_V(werr),
			 W_ERROR_V(WERR_DS_DRA_INVALID_PARAMETER));
	TALLOC_FREE(mem_ctx);
}

/*
 * test encryption and decryption failing RID obfustincation (zero rid)
 */
static void test_drsuapi_zero_rid_encrypt_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	uint8_t test_data[] = { 0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04 };
	const uint32_t rid = 0;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB plaintext = data_blob_const(test_data,
					     sizeof(test_data));
	DATA_BLOB encrypted;

	werr = drsuapi_encrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &plaintext,
					       &encrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_DS_DRA_INVALID_PARAMETER));
	TALLOC_FREE(mem_ctx);
}

/*
 * test encryption and decryption without RID obfustication
 */
static void test_drsuapi_encrypt_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	/* Ensures we can cope with odd lengths */
	uint8_t test_data[] = { 0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04, 0x05 };


	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB plaintext = data_blob_const(test_data,
					     sizeof(test_data));
	DATA_BLOB encrypted;
	DATA_BLOB decrypted;

	werr = drsuapi_encrypt_attribute_value(mem_ctx,
					       &key_blob,
					       false,
					       0,
					       &plaintext,
					       &encrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_OK));
	assert_int_not_equal(encrypted.length, plaintext.length);

	werr = drsuapi_decrypt_attribute_value(mem_ctx,
					       &key_blob,
					       false,
					       0,
					       &encrypted,
					       &decrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_OK));

	assert_int_equal(decrypted.length, plaintext.length);

	assert_memory_equal(decrypted.data, plaintext.data, plaintext.length);
	TALLOC_FREE(mem_ctx);
}

/*
 * test decryption of fixed buffer
 */
static void test_drsuapi_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	/* Ensures we can cope with odd lengths */
	uint8_t test_data[] = { 0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04, 0x05 };

	uint8_t encrypted_test_data[] = { 0xFF, 0x5C, 0x58, 0x3F,
					  0xD4, 0x41, 0xCA, 0xB0,
					  0x14, 0xFE, 0xFB, 0xA6,
					  0xB0, 0x32, 0x45, 0x45,
					  0x9D, 0x76, 0x75, 0xD2,
					  0xFB, 0x34, 0x77, 0xBD,
					  0x8C, 0x1E, 0x09, 0x1A,
					  0xF1, 0xAB, 0xD3, 0x0E,
					  0xBE, 0x80, 0xAB, 0x19, 0xFC };

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB plaintext = data_blob_const(test_data,
					     sizeof(test_data));
	const DATA_BLOB encrypted
		= data_blob_const(encrypted_test_data,
				  sizeof(encrypted_test_data));
	DATA_BLOB decrypted;

	werr = drsuapi_decrypt_attribute_value(mem_ctx,
					       &key_blob,
					       false,
					       0,
					       &encrypted,
					       &decrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_OK));

	assert_int_equal(decrypted.length, plaintext.length);

	assert_memory_equal(decrypted.data, plaintext.data, plaintext.length);
	TALLOC_FREE(mem_ctx);
}

/*
 * test decryption of fixed buffer (rid decrypt)
 */
static void test_drsuapi_rid_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	/* Ensures we can cope with odd lengths */
	uint8_t test_data[] = { 0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04 };

	uint8_t encrypted_test_data[] = {0x95, 0xB2, 0xE8, 0x02,
					 0x05, 0x5E, 0xFD, 0x3D,
					 0x7D, 0x17, 0xB9, 0x76,
					 0x4D, 0x91, 0xED, 0x59,
					 0x98, 0x79, 0x7A, 0xFC,
					 0x38, 0x73, 0x28, 0x55,
					 0x62, 0x27, 0x99, 0x3B,
					 0xD0, 0x18, 0xBD, 0x23,
					 0x5D, 0x98, 0xFE, 0xA8};

	const uint32_t rid = 514;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB plaintext = data_blob_const(test_data,
					     sizeof(test_data));
	const DATA_BLOB encrypted
		= data_blob_const(encrypted_test_data,
				  sizeof(encrypted_test_data));
	DATA_BLOB decrypted;

	werr = drsuapi_decrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &encrypted,
					       &decrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_OK));

	assert_int_equal(decrypted.length, plaintext.length);

	assert_memory_equal(decrypted.data, plaintext.data, plaintext.length);

	TALLOC_FREE(mem_ctx);
}

/*
 * test decryption of fixed buffer (rid decrypt)
 */
static void test_drsuapi_bad_len_rid_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	uint8_t encrypted_test_data[] = { 0xFF, 0x5C, 0x58, 0x3F,
					  0xD4, 0x41, 0xCA, 0xB0,
					  0x14, 0xFE, 0xFB, 0xA6,
					  0xB0, 0x32, 0x45, 0x45,
					  0x9D, 0x76, 0x75, 0xD2,
					  0xFB, 0x34, 0x77, 0xBD,
					  0x8C, 0x1E, 0x09, 0x1A,
					  0xF1, 0xAB, 0xD3, 0x0E,
					  0xBE, 0x80, 0xAB, 0x19, 0xFC };

	const uint32_t rid = 514;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB encrypted
		= data_blob_const(encrypted_test_data,
				  sizeof(encrypted_test_data));
	DATA_BLOB decrypted;

	werr = drsuapi_decrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &encrypted,
					       &decrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_DS_DRA_INVALID_PARAMETER));

	TALLOC_FREE(mem_ctx);
}

/*
 * test decryption of fixed buffer (rid decrypt)
 */
static void test_drsuapi_zero_rid_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	uint8_t encrypted_test_data[] = { 0x01, 0x02, 0x03, 0x04,
					  0x01, 0x02, 0x03, 0x04,
					  0x01, 0x02, 0x03, 0x04,
					  0x01, 0x02, 0x03, 0x04, 0x05 };
	const uint32_t rid = 0;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB encrypted
		= data_blob_const(encrypted_test_data,
				  sizeof(encrypted_test_data));
	DATA_BLOB decrypted;

	werr = drsuapi_decrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &encrypted,
					       &decrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_DS_DRA_INVALID_PARAMETER));

	TALLOC_FREE(mem_ctx);
}

/*
 * test decryption of fixed buffer (bad crc)
 */
static void test_drsuapi_bad_crc_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	uint8_t encrypted_test_data[] = { 0xFF, 0x5C, 0x58, 0x3F,
					  0xD4, 0x41, 0xCA, 0xB0,
					  0x14, 0xFE, 0xFB, 0xA6,
					  0xB0, 0x32, 0x45, 0x45,
					  0x9D, 0x76, 0x75, 0xD2,
					  0xFB, 0x34, 0x77, 0xBD,
					  0x8C, 0x1E, 0x09, 0x1A,
					  0xF1, 0xAB, 0xD3, 0x0E,
					  0xBE, 0x80, 0xAB, 0x19, 0xFF };

	const uint32_t rid = 514;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB encrypted
		= data_blob_const(encrypted_test_data,
				  sizeof(encrypted_test_data));
	DATA_BLOB decrypted;

	werr = drsuapi_decrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &encrypted,
					       &decrypted);

	assert_int_equal(W_ERROR_V(werr), HRES_ERROR_V(HRES_SEC_E_DECRYPT_FAILURE));

	TALLOC_FREE(mem_ctx);
}

/*
 * test decryption of short buffer
 */
static void test_drsuapi_short_decrypt_attribute_value(void **state)
{
	uint8_t key[] = { 0xa1, 0xb2, 0xc3, 0xd4,
			  0xe1, 0xf2, 0x03, 0x14,
			  0x21, 0x32, 0x43, 0x54,
			  0x61, 0x72, 0x83, 0x94 };

	uint8_t encrypted_test_data[] = { 0x01, 0x02, 0x03, 0x04,
					  0x01, 0x02, 0x03, 0x04,
					  0x01, 0x02, 0x03, 0x04,
					  0x01, 0x02, 0x03, 0x04, 0x05 };
	const uint32_t rid = 514;

	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	WERROR werr;

	const DATA_BLOB key_blob = data_blob_const(key, sizeof(key));
	const DATA_BLOB encrypted
		= data_blob_const(encrypted_test_data,
				  sizeof(encrypted_test_data));
	DATA_BLOB decrypted;

	werr = drsuapi_decrypt_attribute_value(mem_ctx,
					       &key_blob,
					       true,
					       rid,
					       &encrypted,
					       &decrypted);

	assert_int_equal(W_ERROR_V(werr), W_ERROR_V(WERR_DS_DRA_INVALID_PARAMETER));

	TALLOC_FREE(mem_ctx);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(
			test_drsuapi_rid_encrypt_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_bad_len_rid_encrypt_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_zero_rid_encrypt_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_encrypt_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_bad_crc_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_rid_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_zero_rid_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_bad_len_rid_decrypt_attribute_value),
		cmocka_unit_test(
			test_drsuapi_short_decrypt_attribute_value),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
