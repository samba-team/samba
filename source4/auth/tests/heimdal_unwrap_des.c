/*
 * Unit tests for third_party/heimdal/lib/gssapi/krb5/unwrap.c
 *
 * Copyright (C) Catalyst.NET Ltd 2022
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
#include <stdint.h>
#include <setjmp.h>

#include <cmocka.h>

#include "includes.h"
#include "replace.h"

#include "../../../third_party/heimdal/lib/gssapi/gssapi/gssapi.h"
#include "gsskrb5_locl.h"

/******************************************************************************
 * Helper functions
 ******************************************************************************/

const uint8_t *valid_range_begin;
const uint8_t *valid_range_end;
const uint8_t *invalid_range_end;

/*
 * 'array_len' is the size of the passed in array. 'buffer_len' is the size to
 * report in the resulting buffer.
 */
static const gss_buffer_desc get_input_buffer(TALLOC_CTX *mem_ctx,
					      const uint8_t array[],
					      const size_t array_len,
					      const size_t buffer_len)
{
	gss_buffer_desc buf;

	/* Add some padding to catch invalid memory accesses. */
	const size_t padding = 0x100;
	const size_t padded_len = array_len + padding;

	uint8_t *data = talloc_size(mem_ctx, padded_len);
	assert_non_null(data);

	memcpy(data, array, array_len);
	memset(data + array_len, 0, padding);

	assert_in_range(buffer_len, 0, array_len);

	buf.value = data;
	buf.length = buffer_len;

	valid_range_begin = buf.value;
	valid_range_end = valid_range_begin + buf.length;
	invalid_range_end = valid_range_begin + padded_len;

	return buf;
}

static void assert_mem_in_valid_range(const uint8_t *ptr, const size_t len)
{
	/* Ensure we've set up the range pointers properly. */
	assert_non_null(valid_range_begin);
	assert_non_null(valid_range_end);
	assert_non_null(invalid_range_end);

	/*
	 * Ensure the length isn't excessively large (a symptom of integer
	 * underflow).
	 */
	assert_in_range(len, 0, 0x1000);

	/* Ensure the memory is in our valid range. */
	assert_in_range(ptr, valid_range_begin, valid_range_end);
	assert_in_range(ptr + len, valid_range_begin, valid_range_end);
}

/*
 * This function takes a pointer to volatile to allow it to be called from the
 * ct_memcmp() wrapper.
 */
static void assert_mem_outside_invalid_range(const volatile uint8_t *ptr,
					     const size_t len)
{
	const LargestIntegralType _valid_range_end
		= cast_ptr_to_largest_integral_type(valid_range_end);
	const LargestIntegralType _invalid_range_end
		= cast_ptr_to_largest_integral_type(invalid_range_end);
	const LargestIntegralType _ptr = cast_ptr_to_largest_integral_type(ptr);
	const LargestIntegralType _len = cast_to_largest_integral_type(len);

	/* Ensure we've set up the range pointers properly. */
	assert_non_null(valid_range_begin);
	assert_non_null(valid_range_end);
	assert_non_null(invalid_range_end);

	/*
	 * Ensure the length isn't excessively large (a symptom of integer
	 * underflow).
	 */
	assert_in_range(len, 0, 0x1000);

	/* Ensure the memory is outside the invalid range. */
	if (_ptr < _invalid_range_end && _ptr + _len > _valid_range_end) {
		fail();
	}
}

/*****************************************************************************
 * wrapped functions
 *****************************************************************************/

krb5_keyblock dummy_key;

krb5_error_code __wrap_krb5_auth_con_getlocalsubkey(krb5_context context,
						    krb5_auth_context auth_context,
						    krb5_keyblock **keyblock);
krb5_error_code __wrap_krb5_auth_con_getlocalsubkey(krb5_context context,
						    krb5_auth_context auth_context,
						    krb5_keyblock **keyblock)
{
	*keyblock = &dummy_key;
	return 0;
}

void __wrap_krb5_free_keyblock(krb5_context context,
			krb5_keyblock *keyblock);
void __wrap_krb5_free_keyblock(krb5_context context,
			krb5_keyblock *keyblock)
{
	assert_ptr_equal(&dummy_key, keyblock);
}

struct krb5_crypto_data dummy_crypto;

krb5_error_code __wrap_krb5_crypto_init(krb5_context context,
					const krb5_keyblock *key,
					krb5_enctype etype,
					krb5_crypto *crypto);
krb5_error_code __wrap_krb5_crypto_init(krb5_context context,
					const krb5_keyblock *key,
					krb5_enctype etype,
					krb5_crypto *crypto)
{
	static const LargestIntegralType etypes[] = {ETYPE_DES3_CBC_NONE, 0};

	assert_ptr_equal(&dummy_key, key);
	assert_in_set(etype, etypes, ARRAY_SIZE(etypes));

	*crypto = &dummy_crypto;

	return 0;
}

krb5_error_code __wrap_krb5_decrypt(krb5_context context,
				    krb5_crypto crypto,
				    unsigned usage,
				    void *data,
				    size_t len,
				    krb5_data *result);
krb5_error_code __wrap_krb5_decrypt(krb5_context context,
				    krb5_crypto crypto,
				    unsigned usage,
				    void *data,
				    size_t len,
				    krb5_data *result)
{
	assert_ptr_equal(&dummy_crypto, crypto);
	assert_int_equal(KRB5_KU_USAGE_SEAL, usage);

	assert_mem_in_valid_range(data, len);

	check_expected(len);
	check_expected_ptr(data);

	result->data = malloc(len);
	assert_non_null(result->data);
	result->length = len;

	memcpy(result->data, data, len);

	return 0;
}

krb5_error_code __wrap_krb5_decrypt_ivec(krb5_context context,
					 krb5_crypto crypto,
					 unsigned usage,
					 void *data,
					 size_t len,
					 krb5_data *result,
					 void *ivec);
krb5_error_code __wrap_krb5_decrypt_ivec(krb5_context context,
					 krb5_crypto crypto,
					 unsigned usage,
					 void *data,
					 size_t len,
					 krb5_data *result,
					 void *ivec)
{
	assert_ptr_equal(&dummy_crypto, crypto);
	assert_int_equal(KRB5_KU_USAGE_SEQ, usage);

	assert_mem_in_valid_range(data, len);

	assert_int_equal(8, len);
	check_expected_ptr(data);
	check_expected_ptr(ivec);

	result->data = malloc(len);
	assert_non_null(result->data);
	result->length = len;

	memcpy(result->data, data, len);

	return 0;
}

krb5_error_code __wrap_krb5_verify_checksum(krb5_context context,
					    krb5_crypto crypto,
					    krb5_key_usage usage,
					    void *data,
					    size_t len,
					    Checksum *cksum);
krb5_error_code __wrap_krb5_verify_checksum(krb5_context context,
					    krb5_crypto crypto,
					    krb5_key_usage usage,
					    void *data,
					    size_t len,
					    Checksum *cksum)
{
	assert_ptr_equal(&dummy_crypto, crypto);
	assert_int_equal(KRB5_KU_USAGE_SIGN, usage);

	assert_mem_in_valid_range(data, len);

	check_expected(len);
	check_expected_ptr(data);

	assert_non_null(cksum);
	assert_int_equal(CKSUMTYPE_HMAC_SHA1_DES3, cksum->cksumtype);
	assert_int_equal(20, cksum->checksum.length);
	check_expected_ptr(cksum->checksum.data);

	return 0;
}

krb5_error_code __wrap_krb5_crypto_destroy(krb5_context context,
					   krb5_crypto crypto);
krb5_error_code __wrap_krb5_crypto_destroy(krb5_context context,
					   krb5_crypto crypto)
{
	assert_ptr_equal(&dummy_crypto, crypto);

	return 0;
}


int __wrap_der_get_length(const unsigned char *p,
			  size_t len,
			  size_t *val,
			  size_t *size);
int __real_der_get_length(const unsigned char *p,
			  size_t len,
			  size_t *val,
			  size_t *size);
int __wrap_der_get_length(const unsigned char *p,
			  size_t len,
			  size_t *val,
			  size_t *size)
{
	assert_mem_in_valid_range(p, len);

	return __real_der_get_length(p, len, val, size);
}

int __wrap_ct_memcmp(const volatile void * volatile p1,
		     const volatile void * volatile p2,
		     size_t len);
int __real_ct_memcmp(const volatile void * volatile p1,
		     const volatile void * volatile p2,
		     size_t len);
int __wrap_ct_memcmp(const volatile void * volatile p1,
		     const volatile void * volatile p2,
		     size_t len)
{
	assert_mem_outside_invalid_range(p1, len);
	assert_mem_outside_invalid_range(p2, len);

	return __real_ct_memcmp(p1, p2, len);
}

void *__wrap_malloc(size_t size);
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size)
{
	/*
	 * Ensure the length isn't excessively large (a symptom of integer
	 * underflow).
	 */
	assert_in_range(size, 0, 0x10000);

	return __real_malloc(size);
}

/*****************************************************************************
 * Mock implementations
 *****************************************************************************/

/*
 * Set the globals used by the mocked functions to a known and consistent state
 *
 */
static void init_mock_results(TALLOC_CTX *mem_ctx)
{
	dummy_key.keytype = KRB5_ENCTYPE_DES3_CBC_MD5;
	dummy_key.keyvalue.data = NULL;
	dummy_key.keyvalue.length = 0;

	dummy_crypto = (struct krb5_crypto_data) {0};

	valid_range_begin = NULL;
	valid_range_end = NULL;
	invalid_range_end = NULL;
}

/*****************************************************************************
 * Unit test set up and tear down
 *****************************************************************************/

struct context {
	gss_ctx_id_t context_handle;
};

static int setup(void **state) {
	struct context *ctx = NULL;
	krb5_context context = NULL;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	krb5_error_code code;

	ctx = talloc_zero(NULL, struct context);
	assert_non_null(ctx);

	init_mock_results(ctx);

	code = _gsskrb5_init(&context);
	assert_int_equal(0, code);

	major_status = _gsskrb5_create_ctx(&minor_status,
					   &ctx->context_handle,
					   context,
					   GSS_C_NO_CHANNEL_BINDINGS,
					   ACCEPTOR_START);
	assert_int_equal(GSS_S_COMPLETE, major_status);

	*state = ctx;
	return 0;
}

static int teardown(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;

	major_status = _gsskrb5_delete_sec_context(&minor_status,
						   &ctx->context_handle,
						   GSS_C_NO_BUFFER);
	assert_int_equal(GSS_S_COMPLETE, major_status);

	TALLOC_FREE(ctx);
	return 0;
}

/*****************************************************************************
 * _gsskrb5_unwrap unit tests
 *****************************************************************************/

static void test_unwrap_dce_style_missing_payload(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gsskrb5_ctx gss_ctx;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x37, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0xff, 0xff, /* SEAL_ALG (none) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	};

	input = get_input_buffer(ctx, data, sizeof(data), 22);

	gss_ctx = (gsskrb5_ctx) ctx->context_handle;
	gss_ctx->flags |= GSS_C_DCE_STYLE;

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_BAD_MECH, major_status);
}

static void test_unwrap_dce_style_valid(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gsskrb5_ctx gss_ctx;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x37, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0xff, 0xff, /* SEAL_ALG (none) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		/* unused */
		0xb8, 0xb9, 0xba, 0xbb,
		0xbc, 0xbd, 0xbe,
		0x00, /* padding byte */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 57);

	gss_ctx = (gsskrb5_ctx) ctx->context_handle;
	gss_ctx->flags |= GSS_C_DCE_STYLE;

	expect_value(__wrap_krb5_decrypt_ivec, data, (uint8_t *)input.value + 21);
	expect_memory(__wrap_krb5_decrypt_ivec, ivec,
		      (uint8_t *)input.value + 29, DES_CBLOCK_LEN);

	expect_value(__wrap_krb5_verify_checksum, len, 16);
	expect_value(__wrap_krb5_verify_checksum, data, (uint8_t *)input.value + 41);
	expect_memory(__wrap_krb5_verify_checksum, cksum->checksum.data,
		      (uint8_t *)input.value + 29, 20);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_COMPLETE, major_status);

	assert_int_equal(0, conf_state);
	assert_int_equal(GSS_C_QOP_DEFAULT, qop_state);

	assert_int_equal(output.length, 0);

	major_status = gss_release_buffer(&minor_status, &output);
	assert_int_equal(GSS_S_COMPLETE, major_status);
}

static void test_unwrap_dce_style_with_seal_missing_payload(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gsskrb5_ctx gss_ctx;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x37, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0x02, 0x00, /* SEAL_ALG (DES3-KD) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	};

	input = get_input_buffer(ctx, data, sizeof(data), 22);

	gss_ctx = (gsskrb5_ctx) ctx->context_handle;
	gss_ctx->flags |= GSS_C_DCE_STYLE;

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_BAD_MECH, major_status);
}

static void test_unwrap_dce_style_with_seal_valid(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gsskrb5_ctx gss_ctx;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x37, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0x02, 0x00, /* SEAL_ALG (DES3-KD) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		/* unused */
		0xb8, 0xb9, 0xba, 0xbb,
		0xbc, 0xbd, 0xbe,
		0x00, /* padding byte */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 57);

	gss_ctx = (gsskrb5_ctx) ctx->context_handle;
	gss_ctx->flags |= GSS_C_DCE_STYLE;

	expect_value(__wrap_krb5_decrypt, len, 8);
	expect_value(__wrap_krb5_decrypt, data, (uint8_t *)input.value + 49);

	expect_value(__wrap_krb5_decrypt_ivec, data, (uint8_t *)input.value + 21);
	expect_memory(__wrap_krb5_decrypt_ivec, ivec,
		      (uint8_t *)input.value + 29, DES_CBLOCK_LEN);

	expect_value(__wrap_krb5_verify_checksum, len, 16);
	expect_value(__wrap_krb5_verify_checksum, data, (uint8_t *)input.value + 41);
	expect_memory(__wrap_krb5_verify_checksum, cksum->checksum.data,
		      (uint8_t *)input.value + 29, 20);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_COMPLETE, major_status);

	assert_int_equal(1, conf_state);
	assert_int_equal(GSS_C_QOP_DEFAULT, qop_state);

	assert_int_equal(output.length, 0);

	major_status = gss_release_buffer(&minor_status, &output);
	assert_int_equal(GSS_S_COMPLETE, major_status);
}

static void test_unwrap_missing_8_bytes(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x2f, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0xff, 0xff, /* SEAL_ALG (none) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0x00, /* padding byte */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 49);

	/*
	 * A fixed unwrap_des3() should fail before these wrappers are called,
	 * but we want the wrappers to have access to any required values in the
	 * event that they are called. Specifying WILL_RETURN_ONCE avoids a test
	 * failure if these values remain unused.
	 */
	expect_value_count(__wrap_krb5_decrypt_ivec, data,
			   (uint8_t *)input.value + 21,
			   WILL_RETURN_ONCE);
	expect_memory_count(__wrap_krb5_decrypt_ivec, ivec,
			    (uint8_t *)input.value + 29, DES_CBLOCK_LEN,
			    WILL_RETURN_ONCE);

	expect_value_count(__wrap_krb5_verify_checksum, len, 8, WILL_RETURN_ONCE);
	expect_value_count(__wrap_krb5_verify_checksum, data,
			   (uint8_t *)input.value + 41,
			   WILL_RETURN_ONCE);
	expect_memory_count(__wrap_krb5_verify_checksum, cksum->checksum.data,
			    (uint8_t *)input.value + 29, 20,
			    WILL_RETURN_ONCE);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_BAD_MECH, major_status);
}

static void test_unwrap_missing_payload(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x14, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0xff, 0xff, /* SEAL_ALG (none) */
		0xff, 0xff, /* Filler */
		0x00, 0xa1, 0xa2, 0xa3, /* padding byte / encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	};

	input = get_input_buffer(ctx, data, sizeof(data), 22);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_BAD_MECH, major_status);
}

static void test_unwrap_truncated_header_0(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x00, /* total length */
		0x06, /* OBJECT IDENTIFIER */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 2);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_DEFECTIVE_TOKEN, major_status);
}

static void test_unwrap_truncated_header_1(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x02, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, /* GSS KRB5 mech */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 4);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_BAD_MECH, major_status);
}

static void test_unwrap_valid(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x37, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0xff, 0xff, /* SEAL_ALG (none) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		/* unused */
		0xb8, 0xb9, 0xba, 0xbb,
		0xbc, 0xbd, 0xbe,
		0x00, /* padding byte */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 57);

	expect_value(__wrap_krb5_decrypt_ivec, data, (uint8_t *)input.value + 21);
	expect_memory(__wrap_krb5_decrypt_ivec, ivec,
		      (uint8_t *)input.value + 29, DES_CBLOCK_LEN);

	expect_value(__wrap_krb5_verify_checksum, len, 16);
	expect_value(__wrap_krb5_verify_checksum, data, (uint8_t *)input.value + 41);
	expect_memory(__wrap_krb5_verify_checksum, cksum->checksum.data,
		      (uint8_t *)input.value + 29, 20);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_COMPLETE, major_status);

	assert_int_equal(0, conf_state);
	assert_int_equal(GSS_C_QOP_DEFAULT, qop_state);

	assert_int_equal(output.length, 0);

	major_status = gss_release_buffer(&minor_status, &output);
	assert_int_equal(GSS_S_COMPLETE, major_status);
}

static void test_unwrap_with_padding_truncated_0(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x37, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0xff, 0xff, /* SEAL_ALG (none) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		/* unused */
		0xb8, 0xb9, 0xba, 0xbb,
		0x04, 0x04, 0x04, 0x04, /* padding bytes */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 57);

	/*
	 * A fixed unwrap_des3() should fail before these wrappers are called,
	 * but we want the wrappers to have access to any required values in the
	 * event that they are called. Specifying WILL_RETURN_ONCE avoids a test
	 * failure if these values remain unused.
	 */
	expect_value_count(__wrap_krb5_decrypt_ivec, data,
			   (uint8_t *)input.value + 21,
			   WILL_RETURN_ONCE);
	expect_memory_count(__wrap_krb5_decrypt_ivec, ivec,
			    (uint8_t *)input.value + 29, DES_CBLOCK_LEN,
			    WILL_RETURN_ONCE);

	expect_value_count(__wrap_krb5_verify_checksum, len, 16, WILL_RETURN_ONCE);
	expect_value_count(__wrap_krb5_verify_checksum, data,
			   (uint8_t *)input.value + 41,
			   WILL_RETURN_ONCE);
	expect_memory_count(__wrap_krb5_verify_checksum, cksum->checksum.data,
			    (uint8_t *)input.value + 29, 20,
			    WILL_RETURN_ONCE);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_BAD_MECH, major_status);
}

static void test_unwrap_with_padding_truncated_1(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x37, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0xff, 0xff, /* SEAL_ALG (none) */
		0xff, 0xff, /* Filler */
		0x00, 0xa1, 0xa2, 0xa3, /* padding byte / encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		/* padding bytes */
		0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	};

	input = get_input_buffer(ctx, data, sizeof(data), 57);

	/*
	 * A fixed unwrap_des3() should fail before these wrappers are called,
	 * but we want the wrappers to have access to any required values in the
	 * event that they are called. Specifying WILL_RETURN_ONCE avoids a test
	 * failure if these values remain unused.
	 */
	expect_value_count(__wrap_krb5_decrypt_ivec, data,
			   (uint8_t *)input.value + 21,
			   WILL_RETURN_ONCE);
	expect_memory_count(__wrap_krb5_decrypt_ivec, ivec,
			    (uint8_t *)input.value + 29, DES_CBLOCK_LEN,
			    WILL_RETURN_ONCE);

	expect_value_count(__wrap_krb5_verify_checksum, len, 16, WILL_RETURN_ONCE);
	expect_value_count(__wrap_krb5_verify_checksum, data,
			   (uint8_t *)input.value + 41,
			   WILL_RETURN_ONCE);
	expect_memory_count(__wrap_krb5_verify_checksum, cksum->checksum.data,
			    (uint8_t *)input.value + 29, 20,
			    WILL_RETURN_ONCE);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_BAD_MECH, major_status);
}

static void test_unwrap_with_padding_valid(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x3f, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0xff, 0xff, /* SEAL_ALG (none) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		/* unused */
		0xb8, 0xb9, 0xba, 0xbb,
		0xbc, 0xbd, 0xbe, 0xbf,
		/* padding bytes */
		0x08, 0x08, 0x08, 0x08,
		0x08, 0x08, 0x08, 0x08,
	};

	input = get_input_buffer(ctx, data, sizeof(data), 65);

	expect_value(__wrap_krb5_decrypt_ivec, data, (uint8_t *)input.value + 21);
	expect_memory(__wrap_krb5_decrypt_ivec, ivec,
		      (uint8_t *)input.value + 29, DES_CBLOCK_LEN);

	expect_value(__wrap_krb5_verify_checksum, len, 24);
	expect_value(__wrap_krb5_verify_checksum, data, (uint8_t *)input.value + 41);
	expect_memory(__wrap_krb5_verify_checksum, cksum->checksum.data,
		      (uint8_t *)input.value + 29, 20);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_COMPLETE, major_status);

	assert_int_equal(0, conf_state);
	assert_int_equal(GSS_C_QOP_DEFAULT, qop_state);

	assert_int_equal(output.length, 0);

	major_status = gss_release_buffer(&minor_status, &output);
	assert_int_equal(GSS_S_COMPLETE, major_status);
}

static void test_unwrap_with_seal_empty_token_valid(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x37, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0x02, 0x00, /* SEAL_ALG (DES3-KD) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		/* unused */
		0xb8, 0xb9, 0xba, 0xbb,
		0xbc, 0xbd, 0xbe,
		0x00, /* padding byte */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 57);

	expect_value(__wrap_krb5_decrypt, len, 8);
	expect_value(__wrap_krb5_decrypt, data, (uint8_t *)input.value + 49);

	expect_value(__wrap_krb5_decrypt_ivec, data, (uint8_t *)input.value + 21);
	expect_memory(__wrap_krb5_decrypt_ivec, ivec,
		      (uint8_t *)input.value + 29, DES_CBLOCK_LEN);

	expect_value(__wrap_krb5_verify_checksum, len, 16);
	expect_value(__wrap_krb5_verify_checksum, data, (uint8_t *)input.value + 41);
	expect_memory(__wrap_krb5_verify_checksum, cksum->checksum.data,
		      (uint8_t *)input.value + 29, 20);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_COMPLETE, major_status);

	assert_int_equal(1, conf_state);
	assert_int_equal(GSS_C_QOP_DEFAULT, qop_state);

	assert_int_equal(output.length, 0);

	major_status = gss_release_buffer(&minor_status, &output);
	assert_int_equal(GSS_S_COMPLETE, major_status);
}

static void test_unwrap_with_seal_missing_payload(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x14, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0x02, 0x00, /* SEAL_ALG (DES3-KD) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	};

	input = get_input_buffer(ctx, data, sizeof(data), 22);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_BAD_MECH, major_status);
}

static void test_unwrap_with_seal_valid(void **state) {
	struct context *ctx = *state;
	OM_uint32 major_status;
	OM_uint32 minor_status;
	gss_buffer_desc input = {0};
	gss_buffer_desc output = {0};
	int conf_state;
	gss_qop_t qop_state;

	/* See RFC 1964 for token format. */
	static const uint8_t data[] = {
		0x60, /* ASN.1 Application tag */
		0x3e, /* total length */
		0x06, /* OBJECT IDENTIFIER */
		0x09, /* mech length */
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, /* GSS KRB5 mech */
		0x02, 0x01, /* TOK_ID */
		0x04, 0x00, /* SGN_ALG (HMAC SHA1 DES3-KD) */
		0x02, 0x00, /* SEAL_ALG (DES3-KD) */
		0xff, 0xff, /* Filler */
		0xa0, 0xa1, 0xa2, 0xa3, /* encrypted sequence number */
		0x00, 0x00, 0x00, 0x00, /* sequence number direction (remote) */
		/* checksum */
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad,
		0xae, 0xaf, 0xb0, 0xb1, 0xb2,
		0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		/* unused */
		0xb8, 0xb9, 0xba, 0xbb,
		0xbc, 0xbd, 0xbe, 0xbf,
		0xc0, 0xc1, 0xc2, 0xc3,
		0xc4, 0xc5,
		0x00, /* padding byte */
	};

	input = get_input_buffer(ctx, data, sizeof(data), 64);

	expect_value(__wrap_krb5_decrypt, len, 15);
	expect_value(__wrap_krb5_decrypt, data, (uint8_t *)input.value + 49);

	expect_value(__wrap_krb5_decrypt_ivec, data, (uint8_t *)input.value + 21);
	expect_memory(__wrap_krb5_decrypt_ivec, ivec,
		      (uint8_t *)input.value + 29, DES_CBLOCK_LEN);

	expect_value(__wrap_krb5_verify_checksum, len, 23);
	expect_value(__wrap_krb5_verify_checksum, data, (uint8_t *)input.value + 41);
	expect_memory(__wrap_krb5_verify_checksum, cksum->checksum.data,
		      (uint8_t *)input.value + 29, 20);

	major_status = _gsskrb5_unwrap(&minor_status,
				       ctx->context_handle,
				       &input,
				       &output,
				       &conf_state,
				       &qop_state);
	assert_int_equal(GSS_S_COMPLETE, major_status);

	assert_int_equal(1, conf_state);
	assert_int_equal(GSS_C_QOP_DEFAULT, qop_state);

	assert_int_equal(output.length, 7);
	assert_memory_equal((uint8_t *)input.value + 57, output.value, output.length);

	major_status = gss_release_buffer(&minor_status, &output);
	assert_int_equal(GSS_S_COMPLETE, major_status);
}

int main(int argc, const char **argv)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_unwrap_dce_style_missing_payload, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_dce_style_valid, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_dce_style_with_seal_missing_payload, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_dce_style_with_seal_valid, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_missing_8_bytes, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_missing_payload, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_truncated_header_0, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_truncated_header_1, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_valid, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_with_padding_truncated_0, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_with_padding_truncated_1, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_with_padding_valid, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_with_seal_empty_token_valid, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_with_seal_missing_payload, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_unwrap_with_seal_valid, setup, teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
