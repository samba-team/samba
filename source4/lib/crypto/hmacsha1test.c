#include "includes.h"

#include "lib/crypto/crypto.h"

struct torture_context;

BOOL torture_local_crypto_hmacsha1(struct torture_context *torture) 
{
	BOOL ret = True;
	uint32_t i;
	struct {
		DATA_BLOB key;
		DATA_BLOB data;
		DATA_BLOB digest;
	} testarray[] = {
	{
		.key	= strhex_to_data_blob("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
		.data	= data_blob_string_const("Hi There"),
		.digest	= strhex_to_data_blob("b617318655057264e28bc0b6fb378c8ef146be00")
	}
	};

	for (i=0; i < ARRAY_SIZE(testarray); i++) {
		struct HMACSHA1Context ctx;
		uint8_t digest[SHA1HashSize];
		int e;

		hmac_sha1_init(testarray[i].key.data, testarray[i].key.length, &ctx);
		hmac_sha1_update(testarray[i].data.data, testarray[i].data.length, &ctx);
		hmac_sha1_final(digest, &ctx);

		e = memcmp(testarray[i].digest.data,
			   digest,
			   MIN(testarray[i].digest.length, SHA1HashSize));
		if (e != 0) {
			printf("test[%u]: failed\n", i);
			dump_data(0, testarray[i].key.data, testarray[i].key.length);
			dump_data(0, testarray[i].data.data, testarray[i].data.length);
			dump_data(0, testarray[i].digest.data, testarray[i].digest.length);
			dump_data(0, digest, sizeof(digest));
			ret = False;
		}
	}

	return ret;
}
