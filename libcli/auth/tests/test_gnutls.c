/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2019 Guenther Deschner <gd@samba.org>
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

#include "includes.h"
#include "libcli/auth/libcli_auth.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#if defined(HAVE_GNUTLS_AES_CFB8) && GNUTLS_VERSION_NUMBER > 0x03060a
static void torture_gnutls_aes_128_cfb_flags(void **state,
					const DATA_BLOB session_key,
					const DATA_BLOB seq_num_initial,
					const DATA_BLOB confounder_initial,
					const DATA_BLOB confounder_expected,
					const DATA_BLOB clear_initial,
					const DATA_BLOB crypt_expected)
{
	uint8_t confounder[8];
	DATA_BLOB io;
	gnutls_cipher_hd_t cipher_hnd = NULL;
	uint8_t sess_kf0[16] = {0};
	gnutls_datum_t key = {
		.data = sess_kf0,
		.size = sizeof(sess_kf0),
	};
	uint32_t iv_size =
		gnutls_cipher_get_iv_size(GNUTLS_CIPHER_AES_128_CFB8);
	uint8_t _iv[iv_size];
	gnutls_datum_t iv = {
		.data = _iv,
		.size = iv_size,
	};
	uint32_t i;
	int rc;

	assert_int_equal(session_key.length, 16);
	assert_int_equal(seq_num_initial.length, 8);
	assert_int_equal(confounder_initial.length, 8);
	assert_int_equal(confounder_expected.length, 8);
	assert_int_equal(clear_initial.length, crypt_expected.length);

	DEBUG(0,("checking buffer size: %d\n", (int)clear_initial.length));

	io = data_blob_dup_talloc(NULL, clear_initial);
	assert_non_null(io.data);
	assert_int_equal(io.length, clear_initial.length);

	memcpy(confounder, confounder_initial.data, 8);

	DEBUG(0,("confounder before crypt:\n"));
	dump_data(0, confounder, 8);
	DEBUG(0,("initial seq num:\n"));
	dump_data(0, seq_num_initial.data, 8);
	DEBUG(0,("io data before crypt:\n"));
	dump_data(0, io.data, io.length);

	for (i = 0; i < key.size; i++) {
		key.data[i] = session_key.data[i] ^ 0xf0;
	}

	ZERO_ARRAY(_iv);

	memcpy(iv.data + 0, seq_num_initial.data, 8);
	memcpy(iv.data + 8, seq_num_initial.data, 8);

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_AES_128_CFB8,
				&key,
				&iv);
	assert_int_equal(rc, 0);

	rc = gnutls_cipher_encrypt(cipher_hnd,
				   confounder,
				   8);
	assert_int_equal(rc, 0);

	rc = gnutls_cipher_encrypt(cipher_hnd,
				   io.data,
				   io.length);
	assert_int_equal(rc, 0);

	DEBUG(0,("confounder after crypt:\n"));
	dump_data(0, confounder, 8);
	DEBUG(0,("initial seq num:\n"));
	dump_data(0, seq_num_initial.data, 8);
	DEBUG(0,("io data after crypt:\n"));
	dump_data(0, io.data, io.length);
	assert_memory_equal(io.data, crypt_expected.data, crypt_expected.length);
	assert_memory_equal(confounder, confounder_expected.data, confounder_expected.length);

	rc = gnutls_cipher_decrypt(cipher_hnd,
				   confounder,
				   8);
	assert_int_equal(rc, 0);

	rc = gnutls_cipher_decrypt(cipher_hnd,
				   io.data,
				   io.length);
	assert_int_equal(rc, 0);
	gnutls_cipher_deinit(cipher_hnd);

	DEBUG(0,("confounder after decrypt:\n"));
	dump_data(0, confounder, 8);
	DEBUG(0,("initial seq num:\n"));
	dump_data(0, seq_num_initial.data, 8);
	DEBUG(0,("io data after decrypt:\n"));
	dump_data(0, io.data, io.length);
	assert_memory_equal(io.data, clear_initial.data, clear_initial.length);
	assert_memory_equal(confounder, confounder_initial.data, confounder_initial.length);
}
#endif

static void torture_gnutls_aes_128_cfb(void **state)
{
#if defined(HAVE_GNUTLS_AES_CFB8) && GNUTLS_VERSION_NUMBER > 0x03060a
	const uint8_t _session_key[16] = {
		0x8E, 0xE8, 0x27, 0x85, 0x83, 0x41, 0x3C, 0x8D,
		0xC9, 0x54, 0x70, 0x75, 0x8E, 0xC9, 0x69, 0x91
	};
	const DATA_BLOB session_key = data_blob_const(_session_key, 16);
	const uint8_t _seq_num_initial[8] = {
		0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
	};
	const DATA_BLOB seq_num_initial =
		data_blob_const(_seq_num_initial, 8);
	const uint8_t _confounder_initial[8] = {
		0x6E, 0x09, 0x25, 0x94, 0x01, 0xA0, 0x09, 0x31
	};
	const DATA_BLOB confounder_initial =
		data_blob_const(_confounder_initial, 8);
	const uint8_t _confounder_expected[8] = {
		0xCA, 0xFB, 0xAC, 0xFB, 0xA8, 0x26, 0x75, 0x2A
	};
	const DATA_BLOB confounder_expected =
		data_blob_const(_confounder_expected, 8);
	const uint8_t _clear_initial[] = {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x8A, 0xE3, 0x13, 0x71, 0x02, 0xF4, 0x36, 0x71,
		0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x02, 0x40, 0x28, 0x00, 0x78, 0x57, 0x34, 0x12,
		0x34, 0x12, 0xCD, 0xAB, 0xEF, 0x00, 0x01, 0x23,
		0x45, 0x67, 0x89, 0xAB, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
		0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const DATA_BLOB clear_initial = data_blob_const(_clear_initial,
			sizeof(_clear_initial));
	const uint8_t crypt_buffer[] = {
		0xE2, 0xE5, 0xE3, 0x26, 0x45, 0xFB, 0xFC, 0xF3,
		0x9C, 0x14, 0xDD, 0xE1, 0x39, 0x23, 0xE0, 0x55,
		0xED, 0x8F, 0xF4, 0x92, 0xA1, 0xBD, 0xDC, 0x40,
		0x58, 0x6F, 0xD2, 0x5B, 0xF9, 0xC9, 0xA3, 0x87,
		0x46, 0x4B, 0x7F, 0xB2, 0x03, 0xD2, 0x35, 0x22,
		0x3E, 0x70, 0x9F, 0x1E, 0x3F, 0x1F, 0xDB, 0x7D,
		0x79, 0x88, 0x5A, 0x3D, 0xD3, 0x40, 0x1E, 0x69,
		0xD7, 0xE2, 0x1D, 0x5A, 0xE9, 0x3B, 0xE1, 0xE2,
		0x98, 0xFD, 0xCB, 0x3A, 0xF7, 0xB5, 0x1C, 0xF8,
		0xCA, 0x02, 0x00, 0x99, 0x9F, 0x0C, 0x01, 0xE6,
		0xD2, 0x00, 0xAF, 0xE0, 0x51, 0x88, 0x62, 0x50,
		0xB7, 0xE8, 0x6D, 0x63, 0x4B, 0x97, 0x05, 0xC1,
		0xD4, 0x83, 0x96, 0x29, 0x80, 0xAE, 0xD8, 0xA2,
		0xED, 0xC9, 0x5D, 0x0D, 0x29, 0xFF, 0x2C, 0x23,
		0x02, 0xFA, 0x3B, 0xEE, 0xE8, 0xBA, 0x06, 0x01,
		0x95, 0xDF, 0x80, 0x76, 0x0B, 0x17, 0x0E, 0xD8
	};
	const DATA_BLOB crypt_expected = data_blob_const(crypt_buffer,
							 sizeof(crypt_buffer));
	int buffer_sizes[] = {
		0, 1, 3, 7, 8, 9, 15, 16, 17
	};
	int i;

	torture_gnutls_aes_128_cfb_flags(state,
				    session_key,
				    seq_num_initial,
				    confounder_initial,
				    confounder_expected,
				    clear_initial,
				    crypt_expected);

	/* repeat the test for varying buffer sizes */

	for (i = 0; i < ARRAY_SIZE(buffer_sizes); i++) {
		DATA_BLOB clear_initial_trunc =
			data_blob_const(clear_initial.data, buffer_sizes[i]);
		DATA_BLOB crypt_expected_trunc =
			data_blob_const(crypt_expected.data, buffer_sizes[i]);
		torture_gnutls_aes_128_cfb_flags(state,
					    session_key,
					    seq_num_initial,
					    confounder_initial,
					    confounder_expected,
					    clear_initial_trunc,
					    crypt_expected_trunc);
	}
#endif
}

static void torture_gnutls_des_crypt56(void **state)
{
	static const uint8_t key[7] = {
		0x69, 0x88, 0x96, 0x8E, 0xB5, 0x3A, 0x24
	};
	static const uint8_t clear[8] = {
		0x3F, 0x49, 0x5B, 0x20, 0xA7, 0x84, 0xC2, 0x34
	};
	static const uint8_t crypt_expected[8] = {
		0x54, 0x86, 0xCF, 0x51, 0x49, 0x3A, 0x53, 0x5B
	};

	uint8_t crypt[8];
	uint8_t decrypt[8];
	int rc;

	rc = des_crypt56_gnutls(crypt, clear, key, SAMBA_GNUTLS_ENCRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt, crypt_expected, 8);

	rc = des_crypt56_gnutls(decrypt, crypt, key, SAMBA_GNUTLS_DECRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(decrypt, clear, 8);
}

static void torture_gnutls_E_P16(void **state)
{
	static const uint8_t key[14] = {
		0x98, 0xFD, 0xCB, 0x3A, 0xF7, 0xB5, 0x1C, 0xF8,
		0x69, 0x88, 0x96, 0x8E, 0xB5, 0x3A
	};
	uint8_t buffer[16] = {
		0x9C, 0x14, 0xDD, 0xE1, 0x39, 0x23, 0xE0, 0x55,
		0x3F, 0x49, 0x5B, 0x20, 0xA7, 0x84, 0xC2, 0x34
	};
	static const uint8_t crypt_expected[16] = {
		0x41, 0x4A, 0x7B, 0xEA, 0xAB, 0xBB, 0x95, 0xCE,
		0x1D, 0xEA, 0xD9, 0xFF, 0xB0, 0xA9, 0xA4, 0x05
	};

	int rc;

	rc = E_P16(key, buffer);
	assert_int_equal(rc, 0);
	assert_memory_equal(buffer, crypt_expected, 16);
}

static void torture_gnutls_E_P24(void **state)
{
	static const uint8_t key[21] = {
		0xFB, 0x67, 0x99, 0xA4, 0x83, 0xF3, 0xD4, 0xED,
		0x98, 0xFD, 0xCB, 0x3A, 0xF7, 0xB5, 0x1C, 0xF8,
		0x69, 0x88, 0x96, 0x8E, 0x3A
	};
	const uint8_t c8[8] = {
		0x44, 0xFB, 0xAC, 0xFB, 0x83, 0xB6, 0x75, 0x2A
	};
	static const uint8_t crypt_expected[24] = {
		0x1A, 0x5E, 0x11, 0xA1, 0x59, 0xA9, 0x6B, 0x4E,
		0x12, 0x5D, 0x81, 0x75, 0xA6, 0x62, 0x15, 0x6D,
		0x5D, 0x20, 0x25, 0xC1, 0xA3, 0x92, 0xB3, 0x28
	};

	uint8_t crypt[24];
	int rc;

	rc = E_P24(key, c8, crypt);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt, crypt_expected, 24);
}

static void torture_gnutls_SMBOWFencrypt(void **state)
{
	static const uint8_t password[16] = {
		'M', 'y', 'p', 'a', 's', 's', 'w', 'o',
		'r', 'd', 'i', 's', '1', '1', '1', '1'
	};
	const uint8_t c8[8] = {
		0x79, 0x88, 0x5A, 0x3D, 0xD3, 0x40, 0x1E, 0x69
	};
	static const uint8_t crypt_expected[24] = {
		0x3F, 0xE3, 0x53, 0x75, 0x81, 0xB4, 0xF0, 0xE7,
		0x0C, 0xDE, 0xCD, 0xAE, 0x39, 0x1F, 0x14, 0xB4,
		0xA4, 0x2B, 0x3E, 0x39, 0x16, 0xFD, 0x1D, 0x62
	};

	uint8_t crypt[24];
	int rc;

	rc = SMBOWFencrypt(password, c8, crypt);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt, crypt_expected, 24);
}

static void torture_gnutls_E_old_pw_hash(void **state)
{
	static uint8_t key[14] = {
		0x98, 0xFD, 0xCB, 0x3A, 0xF7, 0xB5, 0x1C, 0xF8,
		0x69, 0x88, 0x96, 0x8E, 0xB5, 0x3A
	};
	uint8_t clear[16] = {
		0x9C, 0x14, 0xDD, 0xE1, 0x39, 0x23, 0xE0, 0x55,
		0x3F, 0x49, 0x5B, 0x20, 0xA7, 0x84, 0xC2, 0x34
	};
	static const uint8_t crypt_expected[16] = {
		0x6A, 0xC7, 0x08, 0xCA, 0x2A, 0xC1, 0xAA, 0x64,
		0x37, 0xEF, 0xBE, 0x58, 0xC2, 0x59, 0x33, 0xEC
	};
	uint8_t crypt[16];
	int rc;

	rc = E_old_pw_hash(key, clear, crypt);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt, crypt_expected, 16);
}

static void torture_gnutls_des_crypt128(void **state)
{
	static uint8_t key[16] = {
		0x98, 0xFD, 0xCB, 0x3A, 0xF7, 0xB5, 0x1C, 0xF8,
		0xA9, 0x69, 0x88, 0x96, 0x8E, 0xB5, 0x3A, 0x24
	};
	static const uint8_t clear[8] = {
		0x3F, 0x49, 0x5B, 0x20, 0xA7, 0x84, 0xC2, 0x34
	};
	static const uint8_t crypt_expected[8] = {
		0x4C, 0xB4, 0x4B, 0xD3, 0xC8, 0xC1, 0xA5, 0x50
	};

	uint8_t crypt[8];
	int rc;

	rc = des_crypt128(crypt, clear, key);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt, crypt_expected, 8);
}

static void torture_gnutls_des_crypt112(void **state)
{
	static uint8_t key[14] = {
		0x98, 0xFD, 0xCB, 0x3A, 0xF7, 0xB5, 0x1C, 0xF8,
		0x88, 0x96, 0x8E, 0xB5, 0x3A, 0x24
	};
	static const uint8_t clear[8] = {
		0x2F, 0x49, 0x5B, 0x20, 0xD7, 0x84, 0xC2, 0x34
	};
	static const uint8_t crypt_expected[8] = {
		0x87, 0x35, 0xFA, 0xA4, 0x5D, 0x7A, 0xA5, 0x05
	};

	uint8_t crypt[8];
	uint8_t decrypt[8];
	int rc;

	rc = des_crypt112(crypt, clear, key, SAMBA_GNUTLS_ENCRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt, crypt_expected, 8);

	rc = des_crypt112(decrypt, crypt, key, SAMBA_GNUTLS_DECRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(decrypt, clear, 8);
}

static void torture_gnutls_des_crypt112_16(void **state)
{
	static uint8_t key[14] = {
		0x1E, 0x38, 0x27, 0x5B, 0x3B, 0xB8, 0x67, 0xEB,
		0x88, 0x96, 0x8E, 0xB5, 0x3A, 0x24
	};
	static const uint8_t clear[16] = {
		0x02, 0xFA, 0x3B, 0xEE, 0xE8, 0xBA, 0x06, 0x01,
		0xFB, 0x67, 0x99, 0xA4, 0x83, 0xF3, 0xD4, 0xED
	};
	static const uint8_t crypt_expected[16] = {
		0x3C, 0x10, 0x37, 0x67, 0x96, 0x95, 0xF7, 0x96,
		0xAA, 0x03, 0xB9, 0xEA, 0xD6, 0xB3, 0xC3, 0x2D
	};

	uint8_t crypt[16];
	uint8_t decrypt[16];
	int rc;

	rc = des_crypt112_16(crypt, clear, key, SAMBA_GNUTLS_ENCRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt, crypt_expected, 16);

	rc = des_crypt112_16(decrypt, crypt, key, SAMBA_GNUTLS_DECRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(decrypt, clear, 16);
}

static void torture_gnutls_sam_rid_crypt(void **state)
{
	static const uint8_t clear[16] = {
		0x02, 0xFA, 0x3B, 0xEE, 0xE8, 0xBA, 0x06, 0x01,
		0x3F, 0x49, 0x5B, 0x20, 0xA7, 0x84, 0xC2, 0x34
	};
	static const uint8_t crypt_expected[16] = {
		0x1E, 0x38, 0x27, 0x5B, 0x3B, 0xB8, 0x67, 0xEB,
		0xFB, 0x67, 0x99, 0xA4, 0x83, 0xF3, 0xD4, 0xED
	};

	uint8_t crypt[16];
	uint8_t decrypt[16];
	int rid = 500;
	int rc;

	rc = sam_rid_crypt(rid, clear, crypt, SAMBA_GNUTLS_ENCRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt, crypt_expected, 16);

	rc = sam_rid_crypt(rid, crypt, decrypt, SAMBA_GNUTLS_DECRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(decrypt, clear, 16);
}

static void torture_gnutls_SMBsesskeygen_lm_sess_key(void **state)
{
	static const uint8_t lm_hash[16] = {
		0xFB, 0x67, 0x99, 0xA4, 0x83, 0xF3, 0xD4, 0xED,
		0x9C, 0x14, 0xDD, 0xE1, 0x39, 0x23, 0xE0, 0x55
	};
	static const uint8_t lm_resp[24] = {
		0x02, 0xFA, 0x3B, 0xEE, 0xE8, 0xBA, 0x06, 0x01,
		0x02, 0xFA, 0x3B, 0xEE, 0xE8, 0xBA, 0x06, 0x01,
		0x1E, 0x38, 0x27, 0x5B, 0x3B, 0xB8, 0x67, 0xEB
	};
	static const uint8_t crypt_expected[16] = {
		0x52, 0x8D, 0xB2, 0xD3, 0x89, 0x83, 0xFB, 0x9C,
		0x96, 0x45, 0x15, 0x4B, 0xC3, 0xF5, 0xD5, 0x7F
	};

	uint8_t crypt_sess_key[16];
	NTSTATUS status;

	status = SMBsesskeygen_lm_sess_key(lm_hash, lm_resp, crypt_sess_key);
	assert_true(NT_STATUS_IS_OK(status));
	assert_memory_equal(crypt_sess_key, crypt_expected, 16);
}

static void torture_gnutls_sess_crypt_blob(void **state)
{
	static uint8_t _key[16] = {
		0x1E, 0x38, 0x27, 0x5B, 0x3B, 0xB8, 0x67, 0xEB,
		0xFA, 0xEE, 0xE8, 0xBA, 0x06, 0x01, 0x2D, 0x95
	};
	DATA_BLOB key = data_blob_const(_key, 16);
	static const uint8_t _clear[24] = {
		0x98, 0xFD, 0xCB, 0x3A, 0xF7, 0xB5, 0x1C, 0xF8,
		0x02, 0xFA, 0x3B, 0xEE, 0xE8, 0xBA, 0x06, 0x01,
		0x3F, 0x49, 0x5B, 0x20, 0xA7, 0x84, 0xC2, 0x34
	};
	DATA_BLOB clear = data_blob_const(_clear, 24);
	static const uint8_t crypt_expected[24] = {
		0x2B, 0xDD, 0x3B, 0xFA, 0x48, 0xC9, 0x63, 0x56,
		0xAE, 0x8B, 0x3E, 0xCF, 0xEF, 0xDF, 0x7A, 0x42,
		0xB3, 0x00, 0x71, 0x7F, 0x5D, 0x1D, 0xE4, 0x70
	};
	DATA_BLOB crypt = data_blob(NULL, 24);
	DATA_BLOB decrypt = data_blob(NULL, 24);
	int rc;

	rc = sess_crypt_blob(&crypt, &clear, &key, SAMBA_GNUTLS_ENCRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(crypt.data, crypt_expected, 24);

	rc = sess_crypt_blob(&decrypt, &crypt, &key, SAMBA_GNUTLS_DECRYPT);
	assert_int_equal(rc, 0);
	assert_memory_equal(decrypt.data, clear.data, 24);
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_gnutls_aes_128_cfb),
		cmocka_unit_test(torture_gnutls_des_crypt56),
		cmocka_unit_test(torture_gnutls_E_P16),
		cmocka_unit_test(torture_gnutls_E_P24),
		cmocka_unit_test(torture_gnutls_SMBOWFencrypt),
		cmocka_unit_test(torture_gnutls_E_old_pw_hash),
		cmocka_unit_test(torture_gnutls_des_crypt128),
		cmocka_unit_test(torture_gnutls_des_crypt112),
		cmocka_unit_test(torture_gnutls_des_crypt112_16),
		cmocka_unit_test(torture_gnutls_sam_rid_crypt),
		cmocka_unit_test(torture_gnutls_SMBsesskeygen_lm_sess_key),
		cmocka_unit_test(torture_gnutls_sess_crypt_blob),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}
