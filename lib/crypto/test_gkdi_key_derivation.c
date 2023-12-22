/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Catalyst.Net Ltd 2023
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "replace.h"
#include <talloc.h>
#include "libcli/util/ntstatus.h"
#include "lib/crypto/gkdi.h"

static const uint8_t gmsa_security_descriptor[] = {
	/* O:SYD:(A;;FRFW;;;S-1-5-9) */
	0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x9f, 0x01, 0x12, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x09, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00};

#define GKID(l0_idx_, l1_idx_, l2_idx_) \
	((struct Gkid){.l0_idx = l0_idx_, .l1_idx = l1_idx_, .l2_idx = l2_idx_})

#define GUID_LITERAL(                                                     \
	time_low_, time_mid_, time_hi_and_version_, clock_seq_, node_)    \
	((struct GUID){.time_low = (0x##time_low_),                       \
		       .time_mid = (0x##time_mid_),                       \
		       .time_hi_and_version = (0x##time_hi_and_version_), \
		       .clock_seq = {(uint32_t)(0x##clock_seq_) >> 8,     \
				     (uint8_t)(0x##clock_seq_)},          \
		       .node = {(uint64_t)(0x##node_) >> 40,              \
				(uint8_t)((uint64_t)(0x##node_) >> 32),   \
				(uint8_t)((uint64_t)(0x##node_) >> 24),   \
				(uint8_t)((uint64_t)(0x##node_) >> 16),   \
				(uint8_t)((uint64_t)(0x##node_) >> 8),    \
				(uint8_t)(0x##node_)}})

struct test_vector {
	const char *name; /* The name of the test scenario. */
	struct Gkid gkid; /* The GKID of the key to derive. */
	struct ProvRootKey root_key;
	NTSTATUS expected_status;
	uint8_t expected_key[GKDI_KEY_LEN]; /* The expected derived key. */
};

#define DATA_BLOB_CONST(data_, length_)                         \
	((DATA_BLOB){.data = (discard_const_p(uint8_t, data_)), \
		     .length = (length_)})

#define ARRAY(...) ((const uint8_t[]){__VA_ARGS__})
#define ROOT_KEY_DATA(...) \
	DATA_BLOB_CONST(ARRAY(__VA_ARGS__), sizeof(ARRAY(__VA_ARGS__)))
#define EXPECTED_KEY(...) {__VA_ARGS__}
#define ROOT_KEY_VERSION(version) (version)

#define ARBITRARY_ROOT_KEY_DATA                                              \
	ROOT_KEY_DATA(72,  159, 53,  49,  197, 55,  119, 77,  67,  45,	107, \
		      151, 227, 188, 31,  67,  210, 232, 198, 220, 23,	235, \
		      14,  79,	217, 160, 135, 13,  47,	 30,  191, 146, 226, \
		      73,  102, 104, 168, 181, 189, 17,	 174, 162, 211, 45,  \
		      10,  171, 113, 111, 72,  254, 86,	 159, 92,  155, 80,  \
		      255, 63,	155, 245, 222, 174, 165, 114, 251)

#define ARBITRARY_GUID GUID_LITERAL(4cdf4285, c46a, 62a3, 2f7d, 95f97342685b)

#define SUCCESS_VECTOR(                                                       \
	name_, root_key_id, algorithm, gkid_, root_key_data, expected_key_)   \
	{                                                                     \
		.name = (name_), .gkid = (gkid_),                               \
		.root_key = {.version = root_key_version_1,                   \
			     .id = (root_key_id),                             \
			     .data = (root_key_data),                         \
			     .kdf_algorithm =                                 \
				     {.id = KDF_ALGORITHM_SP800_108_CTR_HMAC, \
				      .param.sp800_108 = (algorithm)}},       \
		.expected_status = NT_STATUS_OK,                              \
		.expected_key = expected_key_,                                \
	}

#define FAILURE_VECTOR_VERSION(name_,                                         \
			       root_key_id,                                   \
			       algorithm,                                     \
			       gkid_,                                         \
			       root_key_version,                              \
			       root_key_data,                                 \
			       expected_status_)                              \
	{                                                                     \
		.name = (name_), .gkid = (gkid_),                               \
		.root_key = {.version = (root_key_version),                   \
			     .id = (root_key_id),                             \
			     .data = (root_key_data),                         \
			     .kdf_algorithm =                                 \
				     {.id = KDF_ALGORITHM_SP800_108_CTR_HMAC, \
				      .param.sp800_108 = (algorithm)}},       \
		.expected_status = (expected_status_), .expected_key = {},    \
	}

#define FAILURE_VECTOR(                                                        \
	name_, root_key_id, algorithm, gkid_, root_key_data, expected_status_) \
	FAILURE_VECTOR_VERSION(name_,                                          \
			       root_key_id,                                    \
			       algorithm,                                      \
			       gkid_,                                          \
			       root_key_version_1,                             \
			       root_key_data,                                  \
			       expected_status_)

/* Test vectors derived from samba.tests.krb5.gkdi_tests Python tests. */
static const struct test_vector gkdi_vectors[] = {
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_current_l0_idx_"
		"l1_seed_key",
		GUID_LITERAL(89f70521, 9d66, 441f, c314, 1b462f9b1052),
		KDF_PARAM_SHA512,
		GKID(255, 24, -1),
		ROOT_KEY_DATA(166, 239, 135, 219, 187, 248, 107, 107, 190, 85,
			      117, 11,	148, 31,  19,  202, 153, 239, 229, 24,
			      94,  46,	43,  222, 213, 184, 56,	 216, 160, 231,
			      118, 71,	5,   55,  230, 140, 174, 69,  167, 160,
			      244, 177, 214, 201, 191, 84,  148, 195, 248, 121,
			      225, 114, 227, 38,  85,  124, 219, 182, 165, 110,
			      135, 153, 167, 34),
		EXPECTED_KEY(189, 83,  138, 7,	 52,  144, 243, 207, 148, 81,
			     201, 51,  2,   93,	 233, 178, 44,	151, 234, 221,
			     175, 250, 148, 179, 121, 226, 185, 25,  164, 190,
			     209, 71,  91,  198, 127, 106, 145, 117, 177, 57,
			     198, 146, 4,   197, 125, 67,  0,	160, 20,  31,
			     254, 52,  209, 44,	 237, 132, 97,	69,  147, 177,
			     170, 19,  175, 28)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_current_l0_idx_"
		"l2_seed_key",
		GUID_LITERAL(1a3d6c30, aa81, cb7f, d3fe, 80775d135dfe),
		KDF_PARAM_SHA512,
		GKID(321, 0, 12),
		ROOT_KEY_DATA(223, 217, 91,  227, 21,  58,  8,	 5,   198, 86,
			      148, 231, 210, 132, 170, 206, 90,	 176, 170, 73,
			      51,  80,	2,   94,  184, 219, 198, 223, 11,  78,
			      146, 86,	251, 76,  191, 190, 98,	 55,  206, 55,
			      50,  105, 78,  38,  8,   118, 0,	 118, 182, 112,
			      130, 211, 154, 189, 60,  15,  237, 186, 27,  136,
			      115, 100, 80,  100),
		EXPECTED_KEY(187, 189, 147, 118, 205, 22,  194, 71, 237, 64,
			     245, 145, 45,  25,	 8,   33,  140, 8,  240, 145,
			     91,  174, 2,   254, 2,   203, 251, 55, 83,	 189,
			     228, 6,   249, 197, 83,  172, 217, 81, 67,	 207,
			     99,  144, 106, 4,	 64,  227, 207, 35, 125, 35,
			     53,  174, 78,  75,	 156, 210, 217, 70, 167, 19,
			     81,  235, 203, 123)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_current_l0_idx_"
		"both_seed_keys (next older L1)",
		GUID_LITERAL(09de0b38, c743, 7abf, 44ea, 7a3c3e404314),
		KDF_PARAM_SHA512,
		GKID(123, 20, -1),
		ROOT_KEY_DATA(213, 145, 45,  14,  179, 189, 96,	 225, 55,  27,
			      30,  82,	93,  216, 59,  231, 252, 91,  175, 119,
			      1,   139, 13,  186, 107, 217, 72,	 183, 169, 142,
			      190, 90,	243, 118, 116, 51,  37,	 6,   164, 108,
			      82,  193, 8,   166, 47,  42,  62,	 137, 37,  26,
			      209, 189, 230, 213, 57,  0,   70,	 121, 192, 101,
			      136, 83,	187, 104),
		EXPECTED_KEY(177, 247, 197, 137, 110, 125, 199, 145, 217, 192,
			     170, 248, 202, 125, 186, 184, 193, 114, 164, 248,
			     184, 115, 219, 72,	 138, 60,  76,	189, 15,  85,
			     155, 17,  82,  255, 186, 57,  212, 175, 242, 217,
			     232, 170, 218, 144, 178, 122, 60,	148, 165, 175,
			     153, 111, 75,  143, 88,  74,  79,	55,  204, 171,
			     77,  80,  93,  61)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_current_l0_idx_"
		"both_seed_keys (L2)",
		GUID_LITERAL(09de0b38, c743, 7abf, 44ea, 7a3c3e404314),
		KDF_PARAM_SHA512,
		GKID(123, 21, 0),
		ROOT_KEY_DATA(213, 145, 45,  14,  179, 189, 96,	 225, 55,  27,
			      30,  82,	93,  216, 59,  231, 252, 91,  175, 119,
			      1,   139, 13,  186, 107, 217, 72,	 183, 169, 142,
			      190, 90,	243, 118, 116, 51,  37,	 6,   164, 108,
			      82,  193, 8,   166, 47,  42,  62,	 137, 37,  26,
			      209, 189, 230, 213, 57,  0,   70,	 121, 192, 101,
			      136, 83,	187, 104),
		EXPECTED_KEY(19,  60,  155, 189, 32,  217, 34,	122, 235, 56,
			     223, 205, 59,  230, 188, 191, 197, 152, 59,  163,
			     114, 2,   8,   143, 245, 200, 167, 5,   17,  33,
			     69,  6,   166, 156, 25,  90,  136, 7,   205, 132,
			     75,  203, 149, 94,	 149, 105, 200, 228, 209, 151,
			     117, 159, 40,  87,	 124, 193, 38,	209, 95,  22,
			     167, 218, 78,  224)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_previous_l0_"
		"idx",
		GUID_LITERAL(27136e8f, e093, 6fe3, e57f, 1d915b102e1c),
		KDF_PARAM_SHA512,
		GKID(100, 31, -1),
		ROOT_KEY_DATA(180, 17,	24,  198, 10,  25,  202, 250, 94,  207,
			      133, 141, 26,  42,  34,  22,  82,	 123, 45,  174,
			      223, 56,	110, 157, 89,  158, 66,	 164, 106, 221,
			      108, 125, 201, 56,  104, 97,  151, 97,  200, 128,
			      255, 54,	116, 167, 124, 110, 95,	 191, 52,  52,
			      209, 48,	169, 114, 123, 178, 205, 42,  37,  87,
			      189, 207, 199, 82),
		EXPECTED_KEY(147, 92,  189, 192, 97,  152, 235, 40,  250, 68,
			     184, 216, 39,  143, 81,  7,   44,	70,  19,  153,
			     146, 54,  88,  80,	 65,  237, 232, 231, 45,  2,
			     254, 149, 227, 69,	 79,  4,   99,	130, 203, 192,
			     167, 0,   119, 155, 121, 71,  77,	215, 224, 128,
			     80,  157, 118, 48,	 45,  41,  55,	64,  126, 150,
			     227, 211, 208, 34)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha1 (next "
		"older L1)",
		GUID_LITERAL(970abad6, fe55, 073a, caf1, b801d3f26bd3),
		KDF_PARAM_SHA1,
		GKID(1, 1, -1),
		ROOT_KEY_DATA(59,  237, 3,   191, 15,  183, 212, 1,   49,  73,
			      21,  79,	36,  202, 45,  89,  185, 141, 182, 213,
			      136, 203, 31,  84,  236, 160, 131, 133, 94,  37,
			      235, 40,	211, 86,  42,  1,   173, 199, 140, 75,
			      112, 224, 183, 42,  89,  81,  88,	 99,  231, 115,
			      43,  133, 63,  186, 2,   221, 118, 70,  230, 49,
			      8,   68,	18,  17),
		EXPECTED_KEY(87,  108, 182, 143, 46,  82,  235, 115, 159, 129,
			     123, 72,  140, 53,	 144, 216, 111, 28,  44,  54,
			     95,  63,  201, 32,	 29,  156, 127, 238, 116, 148,
			     133, 61,  88,  116, 110, 225, 62,	72,  241, 138,
			     166, 250, 105, 247, 21,  125, 227, 208, 125, 227,
			     78,  19,  131, 103, 146, 183, 192, 136, 255, 182,
			     145, 74,  137, 194)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha1 (L2)",
		GUID_LITERAL(970abad6, fe55, 073a, caf1, b801d3f26bd3),
		KDF_PARAM_SHA1,
		GKID(1, 2, 3),
		ROOT_KEY_DATA(59,  237, 3,   191, 15,  183, 212, 1,   49,  73,
			      21,  79,	36,  202, 45,  89,  185, 141, 182, 213,
			      136, 203, 31,  84,  236, 160, 131, 133, 94,  37,
			      235, 40,	211, 86,  42,  1,   173, 199, 140, 75,
			      112, 224, 183, 42,  89,  81,  88,	 99,  231, 115,
			      43,  133, 63,  186, 2,   221, 118, 70,  230, 49,
			      8,   68,	18,  17),
		EXPECTED_KEY(63,  251, 130, 90,	 218, 241, 22,	182, 83,  50,
			     7,	  213, 104, 163, 14,  211, 211, 242, 28,  104,
			     132, 9,   65,  201, 69,  102, 132, 249, 175, 161,
			     27,  5,   110, 12,	 89,  57,  27,	77,  136, 196,
			     149, 217, 132, 195, 214, 128, 2,	156, 197, 197,
			     148, 99,  15,  52,	 23,  145, 25,	193, 197, 172,
			     170, 229, 233, 14)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha256 (next "
		"older L1)",
		GUID_LITERAL(45e26207, ed33, dcd5, 925a, 518a0deef69e),
		KDF_PARAM_SHA256,
		GKID(222, 21, -1),
		ROOT_KEY_DATA(40,  181, 182, 80,  61,  60,  29,	 36,  129, 77,
			      231, 129, 187, 123, 252, 227, 239, 105, 238, 209,
			      206, 72,	9,   55,  43,  238, 44,	 80,  98,  112,
			      197, 240, 181, 198, 223, 89,  116, 114, 98,  63,
			      37,  108, 134, 218, 160, 153, 30,	 138, 17,  161,
			      112, 95,	33,  178, 207, 220, 11,	 185, 219, 75,
			      162, 50,	70,  162),
		EXPECTED_KEY(87,  172, 237, 110, 117, 248, 63,	58,  244, 248,
			     121, 179, 139, 96,	 240, 144, 180, 46,  75,  250,
			     2,	  47,  174, 62,	 111, 217, 66,	128, 180, 105,
			     176, 236, 21,  216, 184, 83,  168, 112, 181, 251,
			     223, 40,  112, 140, 206, 25,  39,	59,  116, 165,
			     115, 172, 190, 13,	 237, 168, 239, 81,  93,  180,
			     105, 30,  45,  203)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha256 (L2)",
		GUID_LITERAL(45e26207, ed33, dcd5, 925a, 518a0deef69e),
		KDF_PARAM_SHA256,
		GKID(222, 22, 22),
		ROOT_KEY_DATA(40,  181, 182, 80,  61,  60,  29,	 36,  129, 77,
			      231, 129, 187, 123, 252, 227, 239, 105, 238, 209,
			      206, 72,	9,   55,  43,  238, 44,	 80,  98,  112,
			      197, 240, 181, 198, 223, 89,  116, 114, 98,  63,
			      37,  108, 134, 218, 160, 153, 30,	 138, 17,  161,
			      112, 95,	33,  178, 207, 220, 11,	 185, 219, 75,
			      162, 50,	70,  162),
		EXPECTED_KEY(117, 42,  8,   121, 174, 36,  36,	192, 80,  76,
			     116, 147, 89,  159, 19,  229, 136, 225, 187, 220,
			     37,  47,  131, 50,	 90,  213, 177, 251, 145, 194,
			     76,  137, 1,   212, 64,  243, 255, 159, 251, 165,
			     159, 205, 101, 187, 151, 87,  50,	217, 243, 131,
			     221, 80,  184, 152, 23,  75,  185, 57,  62,  56,
			     61,  37,  213, 64)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha384 (next "
		"older L1)",
		GUID_LITERAL(66e6d9f7, 4924, f3fc, fe34, 605634d42ebd),
		KDF_PARAM_SHA384,
		GKID(287, 27, -1),
		ROOT_KEY_DATA(35,  229, 186, 134, 203, 216, 143, 123, 67,  46,
			      230, 109, 187, 3,	  191, 78,  235, 244, 1,   203,
			      252, 61,	247, 53,  212, 215, 40,	 181, 3,   200,
			      127, 132, 50,  7,	  198, 246, 21,	 63,  25,  13,
			      254, 133, 168, 108, 184, 216, 183, 77,  241, 59,
			      37,  48,	89,  129, 190, 141, 126, 41,  201, 110,
			      229, 76,	150, 48),
		EXPECTED_KEY(250, 186, 221, 122, 154, 99,  223, 87,  214, 131,
			     45,  247, 167, 53,	 174, 187, 110, 24,  24,  136,
			     178, 234, 243, 1,	 162, 228, 255, 154, 112, 36,
			     109, 56,  171, 29,	 36,  22,  50,	91,  243, 235,
			     114, 106, 2,   103, 186, 180, 189, 149, 12,  114,
			     145, 240, 94,  165, 241, 113, 151, 236, 229, 105,
			     146, 175, 62,  184)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha384 (L2)",
		GUID_LITERAL(66e6d9f7, 4924, f3fc, fe34, 605634d42ebd),
		KDF_PARAM_SHA384,
		GKID(287, 28, 27),
		ROOT_KEY_DATA(35,  229, 186, 134, 203, 216, 143, 123, 67,  46,
			      230, 109, 187, 3,	  191, 78,  235, 244, 1,   203,
			      252, 61,	247, 53,  212, 215, 40,	 181, 3,   200,
			      127, 132, 50,  7,	  198, 246, 21,	 63,  25,  13,
			      254, 133, 168, 108, 184, 216, 183, 77,  241, 59,
			      37,  48,	89,  129, 190, 141, 126, 41,  201, 110,
			      229, 76,	150, 48),
		EXPECTED_KEY(236, 28,  101, 99,	 75,  86,  148, 129, 142, 29,
			     52,  29,  169, 153, 109, 184, 242, 161, 239, 106,
			     44,  119, 106, 113, 38,  167, 235, 209, 139, 55,
			     160, 115, 175, 218, 196, 76,  65,	177, 103, 177,
			     78,  75,  135, 45,	 72,  91,  187, 109, 123, 112,
			     150, 66,  21,  208, 232, 74,  47,	241, 66,  169,
			     217, 67,  242, 5)),
	SUCCESS_VECTOR(
		"samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_derive_key_"
		"exact",
		GUID_LITERAL(d95fb06f, 5a9c, 1829, e20d, 27f3f2ecfbeb),
		KDF_PARAM_SHA512,
		GKID(333, 22, 11),
		ROOT_KEY_DATA(72,  159, 53,  49,  197, 55,  119, 77,  67,  45,
			      107, 151, 227, 188, 31,  67,  210, 232, 198, 220,
			      23,  235, 14,  79,  217, 160, 135, 13,  47,  30,
			      191, 146, 226, 73,  102, 104, 168, 181, 189, 17,
			      174, 162, 211, 45,  10,  171, 113, 111, 72,  254,
			      86,  159, 92,  155, 80,  255, 63,	 155, 245, 222,
			      174, 165, 114, 251),
		EXPECTED_KEY(214, 171, 59,  20,	 244, 244, 200, 144, 138, 163,
			     70,  64,  17,  179, 159, 16,  168, 191, 173, 185,
			     151, 74,  249, 15,	 125, 154, 159, 237, 226, 253,
			     198, 229, 246, 138, 98,  142, 192, 15,  153, 148,
			     163, 171, 216, 165, 42,  233, 226, 219, 79,  104,
			     232, 54,  72,  49,	 30,  157, 119, 101, 242, 83,
			     85,  21,  181, 226)),
	FAILURE_VECTOR_VERSION("unsupported root key version (0)",
			       ARBITRARY_GUID,
			       KDF_PARAM_SHA512,
			       GKID(0, 0, 0),
			       ROOT_KEY_VERSION(0),
			       ARBITRARY_ROOT_KEY_DATA,
			       NT_STATUS_NOT_SUPPORTED),
	FAILURE_VECTOR_VERSION("unsupported root key version (2)",
			       ARBITRARY_GUID,
			       KDF_PARAM_SHA512,
			       GKID(0, 0, 0),
			       ROOT_KEY_VERSION(2),
			       ARBITRARY_ROOT_KEY_DATA,
			       NT_STATUS_NOT_SUPPORTED),
	FAILURE_VECTOR("unsupported algorithm (−1)",
		       ARBITRARY_GUID,
		       -1 /* an unsupported algorithm */,
		       GKID(0, 0, 0),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_NOT_SUPPORTED),
	FAILURE_VECTOR("wrong length (32 bytes short) for root key data",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(0, 0, 0),
		       ROOT_KEY_DATA(0,	 1,  2,	 3,  4,	 5,  6,	 7,  8,	 9,  10,
				     11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
				     22, 23, 24, 25, 26, 27, 28, 29, 30, 31),
		       NT_STATUS_NOT_SUPPORTED),
	FAILURE_VECTOR("default GKID (−1, −1, −1)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(-1, -1, -1),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
	FAILURE_VECTOR("invalid GKID (−2, −1, −1)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(-2, -1, -1),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
	FAILURE_VECTOR("invalid GKID (−1, 0, 0)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(-1, 0, 0),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
	FAILURE_VECTOR("invalid GKID (0, −1, 0)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(0, -1, 0),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
	FAILURE_VECTOR("invalid GKID (0, −2, −1)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(0, -2, -1),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
	FAILURE_VECTOR("invalid GKID (0, 0, −2)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(0, 0, -2),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
	FAILURE_VECTOR("invalid GKID (123, 0, 32)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(123, 0, 32),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
	FAILURE_VECTOR("invalid GKID (456, 32, 0)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(456, 32, 0),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
	FAILURE_VECTOR("try to derive L0 seed key (333, −1, −1)",
		       ARBITRARY_GUID,
		       KDF_PARAM_SHA512,
		       GKID(333, -1, -1),
		       ARBITRARY_ROOT_KEY_DATA,
		       NT_STATUS_INVALID_PARAMETER),
};

static void test_gkdi_key_derivation(void **state)
{
	TALLOC_CTX *mem_ctx = NULL;
	size_t n;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	for (n = 0; n < ARRAY_SIZE(gkdi_vectors); ++n) {
		const struct test_vector *test_vector = &gkdi_vectors[n];
		uint8_t out[GKDI_KEY_LEN] = {};
		NTSTATUS status;

		print_message("Running: %s\n", test_vector->name);

		status = compute_seed_key(
			mem_ctx,
			DATA_BLOB_CONST(gmsa_security_descriptor,
					sizeof gmsa_security_descriptor),
			&test_vector->root_key,
			test_vector->gkid,
			out);
		assert_int_equal(NT_STATUS_V(test_vector->expected_status),
				 NT_STATUS_V(status));
		assert_memory_equal(test_vector->expected_key,
				    out,
				    GKDI_KEY_LEN);
	}

	talloc_free(mem_ctx);
}

int main(int argc, char *argv[])
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_gkdi_key_derivation),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
