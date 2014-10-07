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

struct torture_context;
bool torture_local_crypto_aes_gcm_128(struct torture_context *torture);

/*
 This uses the test values from ...
*/
bool torture_local_crypto_aes_gcm_128(struct torture_context *torture)
{
	bool ret = true;
	uint32_t i;
	struct {
		DATA_BLOB K;
		DATA_BLOB IV;
		DATA_BLOB A;
		DATA_BLOB P;
		DATA_BLOB C;
		DATA_BLOB T;
	} testarray[5];

	TALLOC_CTX *tctx = talloc_new(torture);
	if (!tctx) { return false; };

	ZERO_STRUCT(testarray);

	testarray[0].K = strhex_to_data_blob(tctx,
				"00000000000000000000000000000000");
	testarray[0].IV = strhex_to_data_blob(tctx,
				"000000000000000000000000");
	testarray[0].A = data_blob_null;
	testarray[0].P = data_blob_null;
	testarray[0].C = data_blob_null;
	testarray[0].T = strhex_to_data_blob(tctx,
				"58e2fccefa7e3061367f1d57a4e7455a");

	testarray[1].K = strhex_to_data_blob(tctx,
				"00000000000000000000000000000000");
	testarray[1].IV = strhex_to_data_blob(tctx,
				"000000000000000000000000");
	testarray[1].A = data_blob_null;
	testarray[1].P = strhex_to_data_blob(tctx,
				"00000000000000000000000000000000");
	testarray[1].C = strhex_to_data_blob(tctx,
				"0388dace60b6a392f328c2b971b2fe78");
	testarray[1].T = strhex_to_data_blob(tctx,
				"ab6e47d42cec13bdf53a67b21257bddf");

	testarray[2].K = strhex_to_data_blob(tctx,
				"feffe9928665731c6d6a8f9467308308");
	testarray[2].IV = strhex_to_data_blob(tctx,
				"cafebabefacedbaddecaf888");
	testarray[2].A = data_blob_null;
	testarray[2].P = strhex_to_data_blob(tctx,
				"d9313225f88406e5a55909c5aff5269a"
				"86a7a9531534f7da2e4c303d8a318a72"
				"1c3c0c95956809532fcf0e2449a6b525"
				"b16aedf5aa0de657ba637b391aafd255");
	testarray[2].C = strhex_to_data_blob(tctx,
				"42831ec2217774244b7221b784d0d49c"
				"e3aa212f2c02a4e035c17e2329aca12e"
				"21d514b25466931c7d8f6a5aac84aa05"
				"1ba30b396a0aac973d58e091473f5985");
	testarray[2].T = strhex_to_data_blob(tctx,
				"4d5c2af327cd64a62cf35abd2ba6fab4");

	testarray[3].K = strhex_to_data_blob(tctx,
				"feffe9928665731c6d6a8f9467308308");
	testarray[3].IV = strhex_to_data_blob(tctx,
				"cafebabefacedbaddecaf888");
	testarray[3].A = strhex_to_data_blob(tctx,
				"feedfacedeadbeeffeedfacedeadbeef"
				"abaddad2");
	testarray[3].P = strhex_to_data_blob(tctx,
				"d9313225f88406e5a55909c5aff5269a"
				"86a7a9531534f7da2e4c303d8a318a72"
				"1c3c0c95956809532fcf0e2449a6b525"
				"b16aedf5aa0de657ba637b39");
	testarray[3].C = strhex_to_data_blob(tctx,
				"42831ec2217774244b7221b784d0d49c"
				"e3aa212f2c02a4e035c17e2329aca12e"
				"21d514b25466931c7d8f6a5aac84aa05"
				"1ba30b396a0aac973d58e091");
	testarray[3].T = strhex_to_data_blob(tctx,
				"5bc94fbc3221a5db94fae95ae7121a47");

	for (i=1; testarray[i].T.length != 0; i++) {
		struct aes_gcm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB C;
		int e;

		C = data_blob_dup_talloc(tctx, testarray[i].P);

		aes_gcm_128_init(&ctx, testarray[i].K.data, testarray[i].IV.data);
		aes_gcm_128_updateA(&ctx,
				    testarray[i].A.data,
				    testarray[i].A.length);
		aes_gcm_128_crypt(&ctx, C.data, C.length);
		aes_gcm_128_updateC(&ctx, C.data, C.length);
		aes_gcm_128_digest(&ctx, T);

		e = memcmp(testarray[i].T.data, T, sizeof(T));
		if (e != 0) {
			printf("%s: aes_gcm_128 test[%u]: failed\n", __location__, i);
			printf("K\n");
			dump_data(0, testarray[i].K.data, testarray[i].K.length);
			printf("IV\n");
			dump_data(0, testarray[i].IV.data, testarray[i].IV.length);
			printf("A\n");
			dump_data(0, testarray[i].A.data, testarray[i].A.length);
			printf("P\n");
			dump_data(0, testarray[i].P.data, testarray[i].P.length);
			printf("C1\n");
			dump_data(0, testarray[i].C.data, testarray[i].C.length);
			printf("C2\n");
			dump_data(0, C.data, C.length);
			printf("T1\n");
			dump_data(0, testarray[i].T.data, testarray[i].T.length);
			printf("T2\n");
			dump_data(0, T, sizeof(T));
			ret = false;
			goto fail;
		}

		e = memcmp(testarray[i].C.data, C.data, C.length);
		if (e != 0) {
			printf("%s: aes_gcm_128 test[%u]: failed\n", __location__, i);
			printf("K\n");
			dump_data(0, testarray[i].K.data, testarray[i].K.length);
			printf("IV\n");
			dump_data(0, testarray[i].IV.data, testarray[i].IV.length);
			printf("A\n");
			dump_data(0, testarray[i].A.data, testarray[i].A.length);
			printf("P\n");
			dump_data(0, testarray[i].P.data, testarray[i].P.length);
			printf("C1\n");
			dump_data(0, testarray[i].C.data, testarray[i].C.length);
			printf("C2\n");
			dump_data(0, C.data, C.length);
			printf("T1\n");
			dump_data(0, testarray[i].T.data, testarray[i].T.length);
			printf("T2\n");
			dump_data(0, T, sizeof(T));
			ret = false;
			goto fail;
		}
	}

	for (i=1; testarray[i].T.length != 0; i++) {
		struct aes_gcm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB C;
		int e;
		size_t j;

		C = data_blob_dup_talloc(tctx, testarray[i].P);

		aes_gcm_128_init(&ctx, testarray[i].K.data, testarray[i].IV.data);
		for (j=0; j < testarray[i].A.length; j++) {
			aes_gcm_128_updateA(&ctx, &testarray[i].A.data[j], 1);
		}
		for (j=0; j < C.length; j++) {
			aes_gcm_128_crypt(&ctx, &C.data[j], 1);
			aes_gcm_128_updateC(&ctx, &C.data[j], 1);
		}
		aes_gcm_128_digest(&ctx, T);

		e = memcmp(testarray[i].T.data, T, sizeof(T));
		if (e != 0) {
			printf("%s: aes_gcm_128 test[%u]: failed\n", __location__, i);
			printf("K\n");
			dump_data(0, testarray[i].K.data, testarray[i].K.length);
			printf("IV\n");
			dump_data(0, testarray[i].IV.data, testarray[i].IV.length);
			printf("A\n");
			dump_data(0, testarray[i].A.data, testarray[i].A.length);
			printf("P\n");
			dump_data(0, testarray[i].P.data, testarray[i].P.length);
			printf("C1\n");
			dump_data(0, testarray[i].C.data, testarray[i].C.length);
			printf("C2\n");
			dump_data(0, C.data, C.length);
			printf("T1\n");
			dump_data(0, testarray[i].T.data, testarray[i].T.length);
			printf("T2\n");
			dump_data(0, T, sizeof(T));
			ret = false;
			goto fail;
		}

		e = memcmp(testarray[i].C.data, C.data, C.length);
		if (e != 0) {
			printf("%s: aes_gcm_128 test[%u]: failed\n", __location__, i);
			printf("K\n");
			dump_data(0, testarray[i].K.data, testarray[i].K.length);
			printf("IV\n");
			dump_data(0, testarray[i].IV.data, testarray[i].IV.length);
			printf("A\n");
			dump_data(0, testarray[i].A.data, testarray[i].A.length);
			printf("P\n");
			dump_data(0, testarray[i].P.data, testarray[i].P.length);
			printf("C1\n");
			dump_data(0, testarray[i].C.data, testarray[i].C.length);
			printf("C2\n");
			dump_data(0, C.data, C.length);
			printf("T1\n");
			dump_data(0, testarray[i].T.data, testarray[i].T.length);
			printf("T2\n");
			dump_data(0, T, sizeof(T));
			ret = false;
			goto fail;
		}
	}

	for (i=1; testarray[i].T.length != 0; i++) {
		struct aes_gcm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB P;
		int e;
		size_t j;

		P = data_blob_dup_talloc(tctx, testarray[i].C);

		aes_gcm_128_init(&ctx, testarray[i].K.data, testarray[i].IV.data);
		for (j=0; j < testarray[i].A.length; j++) {
			aes_gcm_128_updateA(&ctx, &testarray[i].A.data[j], 1);
		}
		for (j=0; j < P.length; j++) {
			aes_gcm_128_updateC(&ctx, &P.data[j], 1);
			aes_gcm_128_crypt(&ctx, &P.data[j], 1);
		}
		aes_gcm_128_digest(&ctx, T);

		e = memcmp(testarray[i].T.data, T, sizeof(T));
		if (e != 0) {
			printf("%s: aes_gcm_128 test[%u]: failed\n", __location__, i);
			printf("K\n");
			dump_data(0, testarray[i].K.data, testarray[i].K.length);
			printf("IV\n");
			dump_data(0, testarray[i].IV.data, testarray[i].IV.length);
			printf("A\n");
			dump_data(0, testarray[i].A.data, testarray[i].A.length);
			printf("P1\n");
			dump_data(0, testarray[i].P.data, testarray[i].P.length);
			printf("P2\n");
			dump_data(0, P.data, P.length);
			printf("C\n");
			dump_data(0, testarray[i].C.data, testarray[i].C.length);
			printf("T1\n");
			dump_data(0, testarray[i].T.data, testarray[i].T.length);
			printf("T2\n");
			dump_data(0, T, sizeof(T));
			ret = false;
			goto fail;
		}

		e = memcmp(testarray[i].P.data, P.data, P.length);
		if (e != 0) {
			printf("%s: aes_gcm_128 test[%u]: failed\n", __location__, i);
			printf("K\n");
			dump_data(0, testarray[i].K.data, testarray[i].K.length);
			printf("IV\n");
			dump_data(0, testarray[i].IV.data, testarray[i].IV.length);
			printf("A\n");
			dump_data(0, testarray[i].A.data, testarray[i].A.length);
			printf("P1\n");
			dump_data(0, testarray[i].P.data, testarray[i].P.length);
			printf("P2\n");
			dump_data(0, P.data, P.length);
			printf("C\n");
			dump_data(0, testarray[i].C.data, testarray[i].C.length);
			printf("T1\n");
			dump_data(0, testarray[i].T.data, testarray[i].T.length);
			printf("T2\n");
			dump_data(0, T, sizeof(T));
			ret = false;
			goto fail;
		}
	}

	for (i=1; testarray[i].T.length != 0; i++) {
		struct aes_gcm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB P;
		int e;

		P = data_blob_dup_talloc(tctx, testarray[i].C);

		aes_gcm_128_init(&ctx, testarray[i].K.data, testarray[i].IV.data);
		aes_gcm_128_updateA(&ctx, testarray[i].A.data, testarray[i].A.length);
		aes_gcm_128_updateC(&ctx, P.data, P.length);
		aes_gcm_128_crypt(&ctx, P.data, P.length);
		aes_gcm_128_digest(&ctx, T);

		e = memcmp(testarray[i].T.data, T, sizeof(T));
		if (e != 0) {
			printf("%s: aes_gcm_128 test[%u]: failed\n", __location__, i);
			printf("K\n");
			dump_data(0, testarray[i].K.data, testarray[i].K.length);
			printf("IV\n");
			dump_data(0, testarray[i].IV.data, testarray[i].IV.length);
			printf("A\n");
			dump_data(0, testarray[i].A.data, testarray[i].A.length);
			printf("P1\n");
			dump_data(0, testarray[i].P.data, testarray[i].P.length);
			printf("P2\n");
			dump_data(0, P.data, P.length);
			printf("C\n");
			dump_data(0, testarray[i].C.data, testarray[i].C.length);
			printf("T1\n");
			dump_data(0, testarray[i].T.data, testarray[i].T.length);
			printf("T2\n");
			dump_data(0, T, sizeof(T));
			ret = false;
			goto fail;
		}

		e = memcmp(testarray[i].P.data, P.data, P.length);
		if (e != 0) {
			printf("%s: aes_gcm_128 test[%u]: failed\n", __location__, i);
			printf("K\n");
			dump_data(0, testarray[i].K.data, testarray[i].K.length);
			printf("IV\n");
			dump_data(0, testarray[i].IV.data, testarray[i].IV.length);
			printf("A\n");
			dump_data(0, testarray[i].A.data, testarray[i].A.length);
			printf("P1\n");
			dump_data(0, testarray[i].P.data, testarray[i].P.length);
			printf("P2\n");
			dump_data(0, P.data, P.length);
			printf("C\n");
			dump_data(0, testarray[i].C.data, testarray[i].C.length);
			printf("T1\n");
			dump_data(0, testarray[i].T.data, testarray[i].T.length);
			printf("T2\n");
			dump_data(0, T, sizeof(T));
			ret = false;
			goto fail;
		}
	}

 fail:
	talloc_free(tctx);
	return ret;
}
