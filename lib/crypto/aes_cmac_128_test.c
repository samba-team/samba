/*
   AES-CMAC-128 tests
   Copyright (C) Stefan Metzmacher 2012

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
bool torture_local_crypto_aes_cmac_128(struct torture_context *torture);

/*
 This uses the test values from rfc 4493
*/
bool torture_local_crypto_aes_cmac_128(struct torture_context *torture)
{
	bool ret = true;
	uint32_t i;
	DATA_BLOB key;
	struct {
		DATA_BLOB data;
		DATA_BLOB cmac;
	} testarray[5];

	TALLOC_CTX *tctx = talloc_new(torture);
	if (!tctx) { return false; };

	key = strhex_to_data_blob(tctx, "2b7e151628aed2a6abf7158809cf4f3c");

	testarray[0].data = data_blob_null;
	testarray[0].cmac = strhex_to_data_blob(tctx,
				"bb1d6929e95937287fa37d129b756746");

	testarray[1].data = strhex_to_data_blob(tctx,
				"6bc1bee22e409f96e93d7e117393172a");
	testarray[1].cmac = strhex_to_data_blob(tctx,
				"070a16b46b4d4144f79bdd9dd04a287c");

	testarray[2].data = strhex_to_data_blob(tctx,
				"6bc1bee22e409f96e93d7e117393172a"
				"ae2d8a571e03ac9c9eb76fac45af8e51"
				"30c81c46a35ce411");
	testarray[2].cmac = strhex_to_data_blob(tctx,
				"dfa66747de9ae63030ca32611497c827");

	testarray[3].data = strhex_to_data_blob(tctx,
				"6bc1bee22e409f96e93d7e117393172a"
				"ae2d8a571e03ac9c9eb76fac45af8e51"
				"30c81c46a35ce411e5fbc1191a0a52ef"
				"f69f2445df4f9b17ad2b417be66c3710");
	testarray[3].cmac = strhex_to_data_blob(tctx,
				"51f0bebf7e3b9d92fc49741779363cfe");

	ZERO_STRUCT(testarray[4]);

	for (i=0; testarray[i].cmac.length != 0; i++) {
		struct aes_cmac_128_context ctx;
		uint8_t cmac[AES_BLOCK_SIZE];
		int e;

		aes_cmac_128_init(&ctx, key.data);
		aes_cmac_128_update(&ctx,
				    testarray[i].data.data,
				    testarray[i].data.length);
		aes_cmac_128_final(&ctx, cmac);

		e = memcmp(testarray[i].cmac.data, cmac, sizeof(cmac));
		if (e != 0) {
			printf("aes_cmac_128 test[%u]: failed\n", i);
			dump_data(0, key.data, key.length);
			dump_data(0, testarray[i].data.data, testarray[i].data.length);
			dump_data(0, testarray[i].cmac.data, testarray[i].cmac.length);
			dump_data(0, cmac, sizeof(cmac));
			ret = false;
		}
	}
	talloc_free(tctx);
	return ret;
}
