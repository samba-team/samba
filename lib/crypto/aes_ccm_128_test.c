/*
   AES-CCM-128 tests

   Copyright (C) Stefan Metzmacher 2015

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
#include "lib/crypto/aes.h"
#include "lib/crypto/aes_ccm_128.h"
#include "lib/crypto/aes_test.h"

#ifndef AES_CCM_128_ONLY_TESTVECTORS
struct torture_context;
bool torture_local_crypto_aes_ccm_128(struct torture_context *torture);

/*
 This uses our own test values as we rely on a 11 byte nonce
 and the values from rfc rfc3610 use 13 byte nonce.
*/
bool torture_local_crypto_aes_ccm_128(struct torture_context *tctx)
{
	bool ret = true;
	uint32_t i;
	struct aes_mode_testvector testarray[] = {
#endif /* AES_CCM_128_ONLY_TESTVECTORS */
#define AES_CCM_128_TESTVECTOR(_k, _n, _a, _p, _c, _t) \
	AES_MODE_TESTVECTOR(aes_ccm_128, _k, _n, _a, _p, _c, _t)

	AES_CCM_128_TESTVECTOR(
		/* K */
		"8BF9FBC2B8149484FF11AB1F3A544FF6",
		/* N */
		"010000000000000077F7A8",
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
		"25985364BF9AF90EB0B9C8FB55B7C446"
		"780F310F1EC4677726BFBF34E38E6408"
		"057EE228814F11CBAAB794A79F7A1F78"
		"2DE73B7477985360A02D35A7A347ABF7"
		"9F18DD8687767423BB08F18642B6EFEE"
		"8B1543D83091AF5952F58BB4BD89FF6B"
		"0206E7170481C7BC61F06653D0CF10F7"
		"C78380389382C276"
		"7B8BF34D687A5C3D4F783F926F7755C0"
		"2D44C30848C69CFDD8E54395F1881611"
		"E5502285870A7179068923105190C837",
		/* T */
		"3C11F652F8EA5600C8607D2E0FEAFD42"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"f9fdca4ac64fe7f014de0f43039c7571",
		/* N */
		"5a8aa485c316e947125478",
		/* A */
		"3796cf51b8726652a4204733b8fbb047"
		"cf00fb91a9837e22ec22b1a268f88e2c",
		/* P */
		"a265480ca88d5f536db0dc6abc40faf0"
		"d05be7a9669777682345647586786983",
		/* C */
		"65F8D8422006FB77FB7CCEFDFFF93729"
		"B3EFCB06A0FAF3A2ABAB485723373F53",
		/* T */
		"2C62BD82AD231887A7B326E1E045BC91"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"197afb02ffbd8f699dacae87094d5243",
		/* N */
		"5a8aa485c316e947125478",
		/* A */
		"",
		/* P */
		"3796cf51b8726652a4204733b8fbb047"
		"cf00fb91a9837e22",
		/* C */
		"CA53910394115C5DAB5D7250F04D6A27"
		"2BCFA4329528F3AC",
		/* T */
		"38E3A318F9BA88D4DD2FAF3521820001"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"90929a4b0ac65b350ad1591611fe4829",
		/* N */
		"5a8aa485c316e9403aff85",
		/* A */
		"",
		/* P */
		"a16a2e741f1cd9717285b6d882c1fc53"
		"655e9773761ad697",
		/* C */
		"ACA5E98D2784D131AE76E3C8BF9C3988"
		"35C0206C71893F26",
		/* T */
		"AE67C0EA38C5383BFDC7967F4E9D1678"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"f9fdca4ac64fe7f014de0f43039c7571",
		/* N */
		"5a8aa485c316e947125478",
		/* A */
		"3796cf51b8726652a4204733b8fbb047"
		"cf00fb91a9837e22ec22b1a268f88e2c",
		/* P */
		"a265480ca88d5f536db0dc6abc40faf0"
		"d05be7a966977768",
		/* C */
		"65F8D8422006FB77FB7CCEFDFFF93729"
		"B3EFCB06A0FAF3A2",
		/* T */
		"03C6E244586AFAB9B60D9F6DBDF7EB1A"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"26511fb51fcfa75cb4b44da75a6e5a0e",
		/* N */
		"5a8aa485c316e9403aff85",
		/* A */
		"a16a2e741f1cd9717285b6d882c1fc53"
		"655e9773761ad697a7ee6410184c7982",
		/* P */
		"8739b4bea1a099fe547499cbc6d1b13d"
		"849b8084c9b6acc5",
		/* C */
		"D31F9FC23674D5272125375E0A2F5365"
		"41B1FAF1DD68C819",
		/* T */
		"4F315233A76C4DD99972561C5158AB3B"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"f9fdca4ac64fe7f014de0f43039c7571",
		/* N */
		"5a8aa485c316e947125478",
		/* A */
		"3796cf51b8726652a4204733b8fbb047"
		"cf00fb91a9837e22ec22b1a268",
		/* P */
		"a265480ca88d5f536db0dc6abc40faf0"
		"d05be7a9669777682376345745",
		/* C */
		"65F8D8422006FB77FB7CCEFDFFF93729"
		"B3EFCB06A0FAF3A2AB981875E0",
		/* T */
		"EA93AAEDA607226E9E79D2EE5C4B62F8"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"26511fb51fcfa75cb4b44da75a6e5a0e",
		/* N */
		"5a8aa485c316e9403aff85",
		/* A */
		"a16a2e741f1cd9717285b6d882c1fc53"
		"65",
		/* P */
		"8739b4bea1a099fe547499cbc6d1b13d"
		"84",
		/* C */
		"D31F9FC23674D5272125375E0A2F5365"
		"41",
		/* T */
		"036F58DA2372B29BD0E01C58A0E7F9EE"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"00000000000000000000000000000000",
		/* N */
		"0000000000000000000000",
		/* A */
		"",
		/* P */
		"00",
		/* C */
		"2E",
		/* T */
		"61787D2C432A58293B73D01154E61B6B"
	),
	AES_CCM_128_TESTVECTOR(
		/* K */
		"00000000000000000000000000000000",
		/* N */
		"0000000000000000000000",
		/* A */
		"00",
		/* P */
		"00",
		/* C */
		"2E",
		/* T */
		"E4284A0E813F0FFA146CF59F9ADAFBD7"
	),
#ifndef AES_CCM_128_ONLY_TESTVECTORS
	};

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		struct aes_ccm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB _T = data_blob_const(T, sizeof(T));
		DATA_BLOB C;
		int e;

		C = data_blob_dup_talloc(tctx, testarray[i].P);

		aes_ccm_128_init(&ctx, testarray[i].K.data, testarray[i].N.data,
				 testarray[i].A.length, testarray[i].P.length);
		aes_ccm_128_update(&ctx,
				   testarray[i].A.data,
				   testarray[i].A.length);
		aes_ccm_128_update(&ctx, C.data, C.length);
		aes_ccm_128_crypt(&ctx, C.data, C.length);
		aes_ccm_128_digest(&ctx, T);

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
		struct aes_ccm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB _T = data_blob_const(T, sizeof(T));
		DATA_BLOB C;
		int e;
		size_t j;

		C = data_blob_dup_talloc(tctx, testarray[i].P);

		aes_ccm_128_init(&ctx, testarray[i].K.data, testarray[i].N.data,
				 testarray[i].A.length, testarray[i].P.length);
		for (j=0; j < testarray[i].A.length; j++) {
			aes_ccm_128_update(&ctx, NULL, 0);
			aes_ccm_128_update(&ctx, &testarray[i].A.data[j], 1);
			aes_ccm_128_update(&ctx, NULL, 0);
		}
		for (j=0; j < C.length; j++) {
			aes_ccm_128_crypt(&ctx, NULL, 0);
			aes_ccm_128_update(&ctx, NULL, 0);
			aes_ccm_128_update(&ctx, &C.data[j], 1);
			aes_ccm_128_crypt(&ctx, &C.data[j], 1);
			aes_ccm_128_crypt(&ctx, NULL, 0);
			aes_ccm_128_update(&ctx, NULL, 0);
		}
		aes_ccm_128_digest(&ctx, T);

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
		struct aes_ccm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB _T = data_blob_const(T, sizeof(T));
		DATA_BLOB P;
		int e;
		size_t j;

		P = data_blob_dup_talloc(tctx, testarray[i].C);

		aes_ccm_128_init(&ctx, testarray[i].K.data, testarray[i].N.data,
				 testarray[i].A.length, testarray[i].P.length);
		for (j=0; j < testarray[i].A.length; j++) {
			aes_ccm_128_update(&ctx, NULL, 0);
			aes_ccm_128_update(&ctx, &testarray[i].A.data[j], 1);
			aes_ccm_128_update(&ctx, NULL, 0);
		}
		for (j=0; j < P.length; j++) {
			aes_ccm_128_crypt(&ctx, NULL, 0);
			aes_ccm_128_update(&ctx, NULL, 0);
			aes_ccm_128_crypt(&ctx, &P.data[j], 1);
			aes_ccm_128_update(&ctx, &P.data[j], 1);
			aes_ccm_128_crypt(&ctx, NULL, 0);
			aes_ccm_128_update(&ctx, NULL, 0);
		}
		aes_ccm_128_digest(&ctx, T);

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
		struct aes_ccm_128_context ctx;
		uint8_t T[AES_BLOCK_SIZE];
		DATA_BLOB _T = data_blob_const(T, sizeof(T));
		DATA_BLOB P;
		int e;

		P = data_blob_dup_talloc(tctx, testarray[i].C);

		aes_ccm_128_init(&ctx, testarray[i].K.data, testarray[i].N.data,
				 testarray[i].A.length, testarray[i].P.length);
		aes_ccm_128_update(&ctx, testarray[i].A.data, testarray[i].A.length);
		aes_ccm_128_crypt(&ctx, P.data, P.length);
		aes_ccm_128_update(&ctx, P.data, P.length);
		aes_ccm_128_digest(&ctx, T);

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

#endif /* AES_CCM_128_ONLY_TESTVECTORS */
