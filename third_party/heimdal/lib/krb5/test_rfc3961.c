/*
 * Copyright (c) 2003-2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "krb5_locl.h"
#include <err.h>
#include <getarg.h>

static void
time_hmac(krb5_context context, size_t size, int iterations)
{
    struct timeval tv1, tv2;
    krb5_error_code ret;
    krb5_keyblock key;
    char sha1_data[20];
    Checksum result;
    char *buf;
    int i;

    ret = krb5_generate_random_keyblock(context,
					ETYPE_AES128_CTS_HMAC_SHA1_96,
					&key);
    if (ret)
	krb5_err(context, 1, ret, "krb5_generate_random_keyblock");

    buf = calloc(1, size);
    if (buf == NULL)
	krb5_errx(context, 1, "out of memory");

    gettimeofday(&tv1, NULL);

    result.checksum.data = &sha1_data;
    result.checksum.length = sizeof(sha1_data);
    for (i = 0; i < iterations; i++) {
	ret = krb5_hmac(context, CKSUMTYPE_SHA1, buf, size, 0, &key, &result);
	if (ret)
	    krb5_err(context, 1, ret, "hmac: %d", i);
    }

    gettimeofday(&tv2, NULL);

    timevalsub(&tv2, &tv1);

    printf("HMAC-SHA1 size: %7lu iterations: %d time: %3ld.%06ld\n",
	   (unsigned long)size, iterations,
	   (long)tv2.tv_sec, (long)tv2.tv_usec);

    free(buf);
    krb5_free_keyblock_contents(context, &key);
}

static void
time_hmac_evp(krb5_context context, size_t size, int iterations)
{
    struct timeval tv1, tv2;
    struct krb5_crypto_iov iov;
    struct _krb5_key_data kd;
    krb5_error_code ret;
    krb5_keyblock key;
    krb5_crypto crypto;
    char sha1_data[20];
    Checksum result;
    char *buf;
    int i;

    ret = krb5_generate_random_keyblock(context,
					ETYPE_AES128_CTS_HMAC_SHA1_96,
					&key);
    if (ret)
	krb5_err(context, 1, ret, "krb5_generate_random_keyblock");

    buf = calloc(1, size);
    if (buf == NULL)
	krb5_errx(context, 1, "out of memory");

    gettimeofday(&tv1, NULL);

    result.checksum.data = &sha1_data;
    result.checksum.length = sizeof(sha1_data);
    iov.data.data = buf;
    iov.data.length = size;
    iov.flags = KRB5_CRYPTO_TYPE_DATA;
    kd.key = &key;
    kd.schedule = NULL;

    ret = krb5_crypto_init(context, &key, ETYPE_AES128_CTS_HMAC_SHA1_96,
                           &crypto);
    if (ret)
	krb5_err(context, 1, ret, "krb5_crypto_init");

    for (i = 0; i < iterations; i++) {
        ret = _krb5_SP_HMAC_SHA1_checksum(context, crypto, &kd, 0,
                                          &iov, 1, &result);
	if (ret)
	    krb5_err(context, 1, ret, "hmac: %d", i);
    }

    gettimeofday(&tv2, NULL);

    timevalsub(&tv2, &tv1);

    printf("HMAC-SHA1 (evp) size: %7lu iterations: %d time: %3ld.%06ld\n",
	   (unsigned long)size, iterations,
	   (long)tv2.tv_sec, (long)tv2.tv_usec);

    free(buf);
    krb5_free_keyblock_contents(context, &key);
    krb5_crypto_destroy(context, crypto);
}

static void
time_encryption(krb5_context context, size_t size,
		krb5_enctype etype, int iterations)
{
    struct timeval tv1, tv2;
    krb5_error_code ret;
    krb5_keyblock key;
    krb5_crypto crypto;
    krb5_data data;
    char *etype_name;
    void *buf;
    int i;

    ret = krb5_generate_random_keyblock(context, etype, &key);
    if (ret)
	krb5_err(context, 1, ret, "krb5_generate_random_keyblock");

    ret = krb5_enctype_to_string(context, etype, &etype_name);
    if (ret)
	krb5_err(context, 1, ret, "krb5_enctype_to_string");

    buf = malloc(size);
    if (buf == NULL)
	krb5_errx(context, 1, "out of memory");
    memset(buf, 0, size);

    ret = krb5_crypto_init(context, &key, 0, &crypto);
    if (ret)
	krb5_err(context, 1, ret, "krb5_crypto_init");

    gettimeofday(&tv1, NULL);

    for (i = 0; i < iterations; i++) {
	ret = krb5_encrypt(context, crypto, 0, buf, size, &data);
	if (ret)
	    krb5_err(context, 1, ret, "encrypt: %d", i);
	krb5_data_free(&data);
    }

    gettimeofday(&tv2, NULL);

    timevalsub(&tv2, &tv1);

    printf("%s size: %7lu iterations: %d time: %3ld.%06ld\n",
	   etype_name, (unsigned long)size, iterations,
	   (long)tv2.tv_sec, (long)tv2.tv_usec);

    free(buf);
    free(etype_name);
    krb5_crypto_destroy(context, crypto);
    krb5_free_keyblock_contents(context, &key);
}

static void
time_s2k(krb5_context context,
	 krb5_enctype etype,
	 const char *password,
	 krb5_salt salt,
	 int iterations)
{
    struct timeval tv1, tv2;
    krb5_error_code ret;
    krb5_keyblock key;
    krb5_data opaque;
    char *etype_name;
    int i;

    ret = krb5_enctype_to_string(context, etype, &etype_name);
    if (ret)
	krb5_err(context, 1, ret, "krb5_enctype_to_string");

    opaque.data = NULL;
    opaque.length = 0;

    gettimeofday(&tv1, NULL);

    for (i = 0; i < iterations; i++) {
	ret = krb5_string_to_key_salt_opaque(context, etype, password, salt,
					 opaque, &key);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_string_to_key_data_salt_opaque");
	krb5_free_keyblock_contents(context, &key);
    }

    gettimeofday(&tv2, NULL);

    timevalsub(&tv2, &tv1);

    printf("%s string2key %d iterations time: %3ld.%06ld\n",
	   etype_name, iterations, (long)tv2.tv_sec, (long)tv2.tv_usec);
    free(etype_name);

}

static int version_flag = 0;
static int help_flag	= 0;

static struct getargs args[] = {
    {"version",	0,	arg_flag,	&version_flag,
     "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,
     NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args,
		    sizeof(args)/sizeof(*args),
		    NULL,
		    "");
    exit (ret);
}

/* SHA1 test vectors from RFC2202 */

struct rfc2202 {
    char key[80];
    int keylen;
    char data[80];
    int datalen;
    char digest[20];
    int digestlen;
};

static struct rfc2202 rfc2202_vectors[] =
{
    {
	{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	 0x0b, 0x0b, 0x0b, 0x0b},
	20,
	"Hi There",
	8,
	{0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
	 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
	 0xf1, 0x46, 0xbe, 0x00},
	20
    },
    {
	"Jefe",
	4,
	"what do ya want for nothing?",
	28,
	{0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
	 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
	 0x25, 0x9a, 0x7c, 0x79},
	20
    },
    {
	{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa},
	 20,
	{0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	 0xdd, 0xdd},
	50,
	{0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd,
	 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f,
	 0x63, 0xf1, 0x75, 0xd3},
	20
    },
    {
	{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19},
	25,
	{0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	 0xcd, 0xcd},
	50,
	{0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6,
	 0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50, 0xc8, 0x6c,
	 0x2d, 0x72, 0x35, 0xda},
	20
    },
    {
	{0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	 0x0c, 0x0c, 0x0c, 0x0c},
	20,
	"Test With Truncation",
	20,
	{0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f,
	 0xe7, 0xf2, 0x7b, 0xe1, 0xd5, 0x8b, 0xb9, 0x32,
	 0x4a, 0x9a, 0x5a, 0x04},
	20
    },
    {
	{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
	80,
	"Test Using Larger Than Block-Size Key - Hash Key First",
	54,
	{0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e,
	 0x95, 0x70, 0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55,
	 0xed, 0x40, 0x21, 0x12},
	20
    },
    {
	{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
	80,
	"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
	73,
	{0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78,
	 0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c, 0x78, 0x08,
	 0xbb, 0xff, 0x1a, 0x91},
	20
    }
};

/* RFC 2202 test vectors for HMAC-SHA1 */
static void
test_rfc2202(krb5_context context)
{
    int num_tests;
    int i;

    num_tests = sizeof(rfc2202_vectors) / sizeof(struct rfc2202);

    printf("Running %d RFC2202 HMAC-SHA1 tests\n", num_tests);
    for (i = 0; i < num_tests; i++) {
	krb5_keyblock keyblock;
	Checksum result;
	struct krb5_crypto_iov iov;
	struct _krb5_key_data kd;
	char sha1_data[20];
	int code;

	memset(&keyblock, 0, sizeof(keyblock));
	memset(&result, 0, sizeof(result));

	keyblock.keyvalue.length = rfc2202_vectors[i].keylen;
	keyblock.keyvalue.data = &rfc2202_vectors[i].key;

	result.checksum.data = &sha1_data;
	result.checksum.length = sizeof(sha1_data);

	code = krb5_hmac(context, CKSUMTYPE_SHA1,
			 &rfc2202_vectors[i].data, rfc2202_vectors[i].datalen,
			 0, &keyblock, &result);

	if (code != 0)
	    errx(1, "HMAC-SHA1 failed with %d on test %d", code, i + 1);

	if (memcmp(&sha1_data, rfc2202_vectors[i].digest, sizeof(sha1_data)) !=0)
	    errx(1, "Digests don't match on test %d", i);

	printf("Test %d okay\n", (i * 2) + 1);

	/* Now check the same using the internal HMAC function */

	iov.data.data = rfc2202_vectors[i].data;
	iov.data.length = rfc2202_vectors[i].datalen;
	iov.flags = KRB5_CRYPTO_TYPE_DATA;
	kd.key = &keyblock;
	kd.schedule = NULL;
	code = _krb5_SP_HMAC_SHA1_checksum(context, NULL, &kd, 0,
					   &iov, 1, &result);

	if (code != 0)
	    errx(1, "HMAC-SHA1 failed with %d on test %d", code, i + 1);

	if (memcmp(&sha1_data, rfc2202_vectors[i].digest, sizeof(sha1_data)) !=0)
	    errx(1, "Digests don't match on test %d", i);

	printf("Test %d okay\n", (i * 2) + 2);
    }
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    int i, enciter, s2kiter, hmaciter;
    int optidx = 0;
    krb5_salt salt;

    krb5_enctype enctypes[] = {
	ETYPE_DES_CBC_CRC,
	ETYPE_DES3_CBC_SHA1,
	ETYPE_ARCFOUR_HMAC_MD5,
	ETYPE_AES128_CTS_HMAC_SHA1_96,
	ETYPE_AES256_CTS_HMAC_SHA1_96,
	ETYPE_AES128_CTS_HMAC_SHA256_128,
	ETYPE_AES256_CTS_HMAC_SHA384_192
    };

    setprogname(argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);

    if (help_flag)
	usage (0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    salt.salttype = KRB5_PW_SALT;
    salt.saltvalue.data = NULL;
    salt.saltvalue.length = 0;

    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    test_rfc2202(context);

    enciter = 1000;
    hmaciter = 10000;
    s2kiter = 100;

    time_hmac(context, 16, hmaciter);
    time_hmac(context, 32, hmaciter);
    time_hmac(context, 512, hmaciter);
    time_hmac(context, 1024, hmaciter);
    time_hmac(context, 2048, hmaciter);
    time_hmac(context, 4096, hmaciter);
    time_hmac(context, 8192, hmaciter);
    time_hmac(context, 16384, hmaciter);
    time_hmac(context, 32768, hmaciter);

    time_hmac_evp(context, 16, hmaciter);
    time_hmac_evp(context, 32, hmaciter);
    time_hmac_evp(context, 512, hmaciter);
    time_hmac_evp(context, 1024, hmaciter);
    time_hmac_evp(context, 2048, hmaciter);
    time_hmac_evp(context, 4096, hmaciter);
    time_hmac_evp(context, 8192, hmaciter);
    time_hmac_evp(context, 16384, hmaciter);
    time_hmac_evp(context, 32768, hmaciter);

    for (i = 0; i < sizeof(enctypes)/sizeof(enctypes[0]); i++) {

	krb5_enctype_enable(context, enctypes[i]);

	time_encryption(context, 16, enctypes[i], enciter);
	time_encryption(context, 32, enctypes[i], enciter);
	time_encryption(context, 512, enctypes[i], enciter);
	time_encryption(context, 1024, enctypes[i], enciter);
	time_encryption(context, 2048, enctypes[i], enciter);
	time_encryption(context, 4096, enctypes[i], enciter);
	time_encryption(context, 8192, enctypes[i], enciter);
	time_encryption(context, 16384, enctypes[i], enciter);
	time_encryption(context, 32768, enctypes[i], enciter);

	time_s2k(context, enctypes[i], "mYsecreitPassword", salt, s2kiter);
    }

    krb5_free_context(context);

    return 0;
}
