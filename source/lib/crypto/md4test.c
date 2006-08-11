/* 
   Unix SMB/CIFS implementation.
   MD4 tests
   Copyright (C) Stefan Metzmacher 2006
   
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
 This uses the test values from rfc1320
*/
BOOL torture_local_crypto_md4(struct torture_context *torture) 
{
	BOOL ret = True;
	uint32_t i;
	struct {
		DATA_BLOB data;
		DATA_BLOB md4;
	} testarray[] = {
	{
		.data	= data_blob_string_const(""),
		.md4	= strhex_to_data_blob("31d6cfe0d16ae931b73c59d7e0c089c0")
	},{
		.data	= data_blob_string_const("a"),
		.md4	= strhex_to_data_blob("bde52cb31de33e46245e05fbdbd6fb24")
	},{
		.data	= data_blob_string_const("abc"),
		.md4	= strhex_to_data_blob("a448017aaf21d8525fc10ae87aa6729d")
	},{
		.data	= data_blob_string_const("message digest"),
		.md4	= strhex_to_data_blob("d9130a8164549fe818874806e1c7014b")
	},{
		.data	= data_blob_string_const("abcdefghijklmnopqrstuvwxyz"),
		.md4	= strhex_to_data_blob("d79e1c308aa5bbcdeea8ed63df412da9")
	},{
		.data	= data_blob_string_const("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
						 "abcdefghijklmnopqrstuvwxyz"
						 "0123456789"),
		.md4	= strhex_to_data_blob("043f8582f241db351ce627e153e7f0e4")
	},{
		.data	= data_blob_string_const("123456789012345678901234567890"
						 "123456789012345678901234567890"
						 "12345678901234567890"),
		.md4	= strhex_to_data_blob("e33b4ddc9c38f2199c3e7b164fcc0536")
	}
	};

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		uint8_t md4[16];
		int e;

		mdfour(md4, testarray[i].data.data, testarray[i].data.length);

		e = memcmp(testarray[i].md4.data,
			   md4,
			   MIN(testarray[i].md4.length, sizeof(md4)));
		if (e != 0) {
			printf("md4 test[%u]: failed\n", i);
			dump_data(0, testarray[i].data.data, testarray[i].data.length);
			dump_data(0, testarray[i].md4.data, testarray[i].md4.length);
			dump_data(0, md4, sizeof(md4));
			ret = False;
		}
	}

	return ret;
}
