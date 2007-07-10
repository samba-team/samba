/* 
   Unix SMB/CIFS implementation.
   HMAC SHA-1 tests
   Copyright (C) Stefan Metzmacher
   
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
#include "includes.h"
#include "lib/crypto/crypto.h"

struct torture_context;

static DATA_BLOB data_blob_repeat_byte(uint8_t byte, size_t length)
{
	DATA_BLOB b = data_blob(NULL, length);
	memset(b.data, byte, length);
	return b;
}

/*
 This uses the test values from rfc2202
*/
BOOL torture_local_crypto_hmacsha1(struct torture_context *torture) 
{
	BOOL ret = True;
	uint32_t i;
	struct {
		DATA_BLOB key;
		DATA_BLOB data;
		DATA_BLOB sha1;
	} testarray[7];

	testarray[0].key	= data_blob_repeat_byte(0x0b, 20);
	testarray[0].data	= data_blob_string_const("Hi There");
	testarray[0].sha1	= strhex_to_data_blob("b617318655057264e28bc0b6fb378c8ef146be00");

	testarray[1].key	= data_blob_string_const("Jefe");
	testarray[1].data	= data_blob_string_const("what do ya want for nothing?");
	testarray[1].sha1 = strhex_to_data_blob("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

	testarray[2].key	= data_blob_repeat_byte(0xaa, 20);
	testarray[2].data	= data_blob_repeat_byte(0xdd, 50);
	testarray[2].sha1	= strhex_to_data_blob("125d7342b9ac11cd91a39af48aa17b4f63f175d3");
	
	testarray[3].key	= strhex_to_data_blob("0102030405060708090a0b0c0d0e0f10111213141516171819");
	testarray[3].data	= data_blob_repeat_byte(0xcd, 50);
	testarray[3].sha1	= strhex_to_data_blob("4c9007f4026250c6bc8414f9bf50c86c2d7235da");

	testarray[4].key	= data_blob_repeat_byte(0x0c, 20);
	testarray[4].data	= data_blob_string_const("Test With Truncation");
	testarray[4].sha1	= strhex_to_data_blob("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04");
	/* sha1-96 =                 0x4c1a03424b55e07fe7f27be1 */

	testarray[5].key	= data_blob_repeat_byte(0xaa, 80);
	testarray[5].data	= data_blob_string_const("Test Using Larger Than Block-Size Key - Hash Key First");
	testarray[5].sha1	= strhex_to_data_blob("aa4ae5e15272d00e95705637ce8a3b55ed402112");

	testarray[6].key	= data_blob_repeat_byte(0xaa, 80);
	testarray[6].data	= data_blob_string_const("Test Using Larger Than Block-Size Key "
							 "and Larger Than One Block-Size Data");
	testarray[6].sha1	= strhex_to_data_blob("e8e99d0f45237d786d6bbaa7965c7808bbff1a91");

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		struct HMACSHA1Context ctx;
		uint8_t sha1[SHA1HashSize];
		int e;

		hmac_sha1_init(testarray[i].key.data, testarray[i].key.length, &ctx);
		hmac_sha1_update(testarray[i].data.data, testarray[i].data.length, &ctx);
		hmac_sha1_final(sha1, &ctx);

		e = memcmp(testarray[i].sha1.data,
			   sha1,
			   MIN(testarray[i].sha1.length, sizeof(sha1)));
		if (e != 0) {
			printf("hmacsha1 test[%u]: failed\n", i);
			dump_data(0, testarray[i].key.data, testarray[i].key.length);
			dump_data(0, testarray[i].data.data, testarray[i].data.length);
			dump_data(0, testarray[i].sha1.data, testarray[i].sha1.length);
			dump_data(0, sha1, sizeof(sha1));
			ret = False;
		}
	}

	return ret;
}
