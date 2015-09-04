/*
   AES-GCM-128 tests

   Copyright (C) Stefan Metzmacher 2014

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
#include "replace.h"
#include "../lib/util/samba_util.h"
#include "../lib/crypto/crypto.h"
#include "../lib/crypto/aes_test.h"

#ifndef AES_GCM_128_ONLY_TESTVECTORS
struct torture_context;
bool torture_local_crypto_aes_gcm_128(struct torture_context *tctx);

/*
 This uses the test values from ...
*/
bool torture_local_crypto_aes_gcm_128(struct torture_context *tctx)
{
	bool ret = true;
	uint32_t i;
	struct aes_mode_testvector testarray[] = {
#endif /* AES_GCM_128_ONLY_TESTVECTORS */
#define AES_GCM_128_TESTVECTOR(_k, _n, _a, _p, _c, _t) \
	AES_MODE_TESTVECTOR(aes_gcm_128, _k, _n, _a, _p, _c, _t)

	AES_GCM_128_TESTVECTOR(
		/* K */
		"8BF9FBC2B8149484FF11AB1F3A544FF6",
		/* N */
		"010000000000000077F7A8FF",
		/* A */
		"010000000000000077F7A80000000000"
		"A8000000000001004100002C00980000",
		/* P */
		"FE534D4240000100000000000B00811F"
		"00000000000000000600000000000000"
		"00000000010000004100002C00980000"
		"00000000000000000000000000000000"
		"3900000094010600FFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFF7800000030000000"
		"000000007800000000000000FFFF0000"
		"0100000000000000"
		"03005C003100370032002E0033003100"
		"2E0039002E003100380033005C006E00"
		"650074006C006F0067006F006E000000",
		/* C */
		"863C07C1FBFA82D741A080C97DF52CFF"
		"432A63A37E5ACFA3865AE4E6E422D502"
		"FA7C6FBB9A7418F28C43F00A3869F687"
		"257CA665E25E62A0F458C42AA9E95DC4"
		"6CB351A0A497FABB7DCE58FEE5B20B08"
		"522E0E701B112FB93B36E7A0FB084D35"
		"62C0F3FDF0421079DD96BBCCA40949B3"
		"A7FC1AA635A72384"
		"2037DE3CA6385465D1884B29D7140790"
		"88AD3E770E2528D527B302536B7E5B1B"
		"430E048230AFE785DB89F4D87FC1F816",
		/* T */
		"BC9B5871EBFA89ADE21439ACDCD65D22"
	),
	AES_GCM_128_TESTVECTOR(
		/* K */
		"00000000000000000000000000000000",
		/* N */
		"000000000000000000000000",
		/* A */
		"",
		/* P */
		"",
		/* C */
		"",
		/* T */
		"58e2fccefa7e3061367f1d57a4e7455a"
	),
	AES_GCM_128_TESTVECTOR(
		/* K */
		"00000000000000000000000000000000",
		/* N */
		"000000000000000000000000",
		/* A */
		"",
		/* P */
		"00000000000000000000000000000000",
		/* C */
		"0388dace60b6a392f328c2b971b2fe78",
		/* T */
		"ab6e47d42cec13bdf53a67b21257bddf"
	),
	AES_GCM_128_TESTVECTOR(
		/* K */
		"feffe9928665731c6d6a8f9467308308",
		/* N */
		"cafebabefacedbaddecaf888",
		/* A */
		"",
		/* P */
		"d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b391aafd255",
		/* C */
		"42831ec2217774244b7221b784d0d49c"
		"e3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa05"
		"1ba30b396a0aac973d58e091473f5985",
		/* T */
		"4d5c2af327cd64a62cf35abd2ba6fab4"
	),
	AES_GCM_128_TESTVECTOR(
		/* K */
		"feffe9928665731c6d6a8f9467308308",
		/* N */
		"cafebabefacedbaddecaf888",
		/* A */
		"feedfacedeadbeeffeedfacedeadbeef"
		"abaddad2",
		/* P */
		"d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b39",
		/* C */
		"42831ec2217774244b7221b784d0d49c"
		"e3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa05"
		"1ba30b396a0aac973d58e091",
		/* T */
		"5bc94fbc3221a5db94fae95ae7121a47"
	),
#ifndef AES_GCM_128_ONLY_TESTVECTORS
	};

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		struct aes_gcm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB _T = data_blob_const(T, sizeof(T));
		DATA_BLOB C;
		int e;

		C = data_blob_dup_talloc(tctx, testarray[i].P);

		aes_gcm_128_init(&ctx, testarray[i].K.data, testarray[i].N.data);
		aes_gcm_128_updateA(&ctx,
				    testarray[i].A.data,
				    testarray[i].A.length);
		aes_gcm_128_crypt(&ctx, C.data, C.length);
		aes_gcm_128_updateC(&ctx, C.data, C.length);
		aes_gcm_128_digest(&ctx, T);

		e = memcmp(testarray[i].T.data, T, sizeof(T));
		if (e != 0) {
			aes_mode_testvector_debug(&testarray[i], NULL, &C, &_T);
			ret = false;
			goto fail;
		}

		e = memcmp(testarray[i].C.data, C.data, C.length);
		if (e != 0) {
			aes_mode_testvector_debug(&testarray[i], NULL, &C, &_T);
			ret = false;
			goto fail;
		}
	}

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		struct aes_gcm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB _T = data_blob_const(T, sizeof(T));
		DATA_BLOB C;
		int e;
		size_t j;

		C = data_blob_dup_talloc(tctx, testarray[i].P);

		aes_gcm_128_init(&ctx, testarray[i].K.data, testarray[i].N.data);
		for (j=0; j < testarray[i].A.length; j++) {
			aes_gcm_128_updateA(&ctx, NULL, 0);
			aes_gcm_128_updateA(&ctx, &testarray[i].A.data[j], 1);
			aes_gcm_128_updateA(&ctx, NULL, 0);
		}
		for (j=0; j < C.length; j++) {
			aes_gcm_128_crypt(&ctx, NULL, 0);
			aes_gcm_128_updateC(&ctx, NULL, 0);
			aes_gcm_128_crypt(&ctx, &C.data[j], 1);
			aes_gcm_128_updateC(&ctx, &C.data[j], 1);
			aes_gcm_128_crypt(&ctx, NULL, 0);
			aes_gcm_128_updateC(&ctx, NULL, 0);
		}
		aes_gcm_128_digest(&ctx, T);

		e = memcmp(testarray[i].T.data, T, sizeof(T));
		if (e != 0) {
			aes_mode_testvector_debug(&testarray[i], NULL, &C, &_T);
			ret = false;
			goto fail;
		}

		e = memcmp(testarray[i].C.data, C.data, C.length);
		if (e != 0) {
			aes_mode_testvector_debug(&testarray[i], NULL, &C, &_T);
			ret = false;
			goto fail;
		}
	}

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		struct aes_gcm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB _T = data_blob_const(T, sizeof(T));
		DATA_BLOB P;
		int e;
		size_t j;

		P = data_blob_dup_talloc(tctx, testarray[i].C);

		aes_gcm_128_init(&ctx, testarray[i].K.data, testarray[i].N.data);
		for (j=0; j < testarray[i].A.length; j++) {
			aes_gcm_128_updateA(&ctx, NULL, 0);
			aes_gcm_128_updateA(&ctx, &testarray[i].A.data[j], 1);
			aes_gcm_128_updateA(&ctx, NULL, 0);
		}
		for (j=0; j < P.length; j++) {
			aes_gcm_128_updateC(&ctx, NULL, 0);
			aes_gcm_128_crypt(&ctx, NULL, 0);
			aes_gcm_128_updateC(&ctx, &P.data[j], 1);
			aes_gcm_128_crypt(&ctx, &P.data[j], 1);
			aes_gcm_128_updateC(&ctx, NULL, 0);
			aes_gcm_128_crypt(&ctx, NULL, 0);
		}
		aes_gcm_128_digest(&ctx, T);

		e = memcmp(testarray[i].T.data, T, sizeof(T));
		if (e != 0) {
			aes_mode_testvector_debug(&testarray[i], &P, NULL, &_T);
			ret = false;
			goto fail;
		}

		e = memcmp(testarray[i].P.data, P.data, P.length);
		if (e != 0) {
			aes_mode_testvector_debug(&testarray[i], &P, NULL, &_T);
			ret = false;
			goto fail;
		}
	}

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		struct aes_gcm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB _T = data_blob_const(T, sizeof(T));
		DATA_BLOB P;
		int e;

		P = data_blob_dup_talloc(tctx, testarray[i].C);

		aes_gcm_128_init(&ctx, testarray[i].K.data, testarray[i].N.data);
		aes_gcm_128_updateA(&ctx, testarray[i].A.data, testarray[i].A.length);
		aes_gcm_128_updateC(&ctx, P.data, P.length);
		aes_gcm_128_crypt(&ctx, P.data, P.length);
		aes_gcm_128_digest(&ctx, T);

		e = memcmp(testarray[i].T.data, T, sizeof(T));
		if (e != 0) {
			aes_mode_testvector_debug(&testarray[i], &P, NULL, &_T);
			ret = false;
			goto fail;
		}

		e = memcmp(testarray[i].P.data, P.data, P.length);
		if (e != 0) {
			aes_mode_testvector_debug(&testarray[i], &P, NULL, &_T);
			ret = false;
			goto fail;
		}
	}

 fail:
	return ret;
}
#endif /* AES_GCM_128_ONLY_TESTVECTORS */
