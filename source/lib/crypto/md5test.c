/* 
   Unix SMB/CIFS implementation.
   MD5 tests
   Copyright (C) Stefan Metzmacher
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/crypto/crypto.h"

struct torture_context;

/*
 This uses the test values from rfc1321
*/
BOOL torture_local_crypto_md5(struct torture_context *torture) 
{
	BOOL ret = True;
	uint32_t i;
	struct {
		DATA_BLOB data;
		DATA_BLOB md5;
	} testarray[] = {
	{
		.data	= data_blob_string_const(""),
		.md5	= strhex_to_data_blob("d41d8cd98f00b204e9800998ecf8427e")
	},{
		.data	= data_blob_string_const("a"),
		.md5	= strhex_to_data_blob("0cc175b9c0f1b6a831c399e269772661")
	},{
		.data	= data_blob_string_const("abc"),
		.md5	= strhex_to_data_blob("900150983cd24fb0d6963f7d28e17f72")
	},{
		.data	= data_blob_string_const("message digest"),
		.md5	= strhex_to_data_blob("f96b697d7cb7938d525a2f31aaf161d0")
	},{
		.data	= data_blob_string_const("abcdefghijklmnopqrstuvwxyz"),
		.md5	= strhex_to_data_blob("c3fcd3d76192e4007dfb496cca67e13b")
	},{
		.data	= data_blob_string_const("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
						 "abcdefghijklmnopqrstuvwxyz"
						 "0123456789"),
		.md5	= strhex_to_data_blob("d174ab98d277d9f5a5611c2c9f419d9f")
	},{
		.data	= data_blob_string_const("123456789012345678901234567890"
						 "123456789012345678901234567890"
						 "12345678901234567890"),
		.md5	= strhex_to_data_blob("57edf4a22be3c955ac49da2e2107b67a")
	}
	};

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		struct MD5Context ctx;
		uint8_t md5[16];
		int e;

		MD5Init(&ctx);
		MD5Update(&ctx, testarray[i].data.data, testarray[i].data.length);
		MD5Final(md5, &ctx);

		e = memcmp(testarray[i].md5.data,
			   md5,
			   MIN(testarray[i].md5.length, sizeof(md5)));
		if (e != 0) {
			printf("hmacsha1 test[%u]: failed\n", i);
			dump_data(0, testarray[i].data.data, testarray[i].data.length);
			dump_data(0, testarray[i].md5.data, testarray[i].md5.length);
			dump_data(0, md5, sizeof(md5));
			ret = False;
		}
	}

	return ret;
}
