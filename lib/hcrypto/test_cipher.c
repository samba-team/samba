/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef RCSID
RCSID("$Id$");
#endif

#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getarg.h>
#include <roken.h>

#include <evp.h>
#include <hex.h>
#include <err.h>

struct tests {
    const char *name;
    void *key;
    size_t keysize;
    void *iv;
    size_t datasize;
    void *indata;
    void *outdata;
    size_t outdatasize;
};

struct tests aes_tests[] = {
    { "aes-256",
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      32,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\xdc\x95\xc0\x78\xa2\x40\x89\x89\xad\x48\xa2\x14\x92\x84\x20\x87"
    }
};

struct tests rc2_40_tests[] = {
    { "rc2-40",
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\xc0\xb8\xff\xa5\xd6\xeb\xc9\x62\xcc\x52\x5f\xfe\x9a\x3c\x97\xe6"
    }
};

struct tests des_ede3_tests[] = {
    { "des-ede3",
      "1917ffe6bb772efc297643bc63567e9a002e4d431d5ffd58",
      24,
      "\xbf\x9a\x12\xb7\x26\x69\xfd\x05",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x9d\x50\xf4\xc6\x01\xdb\x45\x49\x11\x8f\x36\x06\x06\x08\x2e\xe5"
    }
};

struct tests camellia128_tests[] = {
    { "camellia128",
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x07\x92\x3A\x39\xEB\x0A\x81\x7D\x1C\x4D\x87\xBD\xB8\x2D\x1F\x1C"
    }
};


static int
test_cipher(const EVP_CIPHER *c, struct tests *t)
{
    EVP_CIPHER_CTX ectx;
    EVP_CIPHER_CTX dctx;
    void *d;

    EVP_CIPHER_CTX_init(&ectx);
    EVP_CIPHER_CTX_init(&dctx);

    if (!EVP_CipherInit_ex(&ectx, c, NULL, t->key, t->iv, 1))
	errx(1, "%s: EVP_CipherInit_ex encrypt", t->name);
    if (!EVP_CipherInit_ex(&dctx, c, NULL, t->key, t->iv, 0))
	errx(1, "%s: EVP_CipherInit_ex decrypt", t->name);

    d = emalloc(t->datasize);

    if (!EVP_Cipher(&ectx, d, t->indata, t->datasize))
	return 1;

    if (memcmp(d, t->outdata, t->datasize) != 0) {
	char *s;
	hex_encode(d, t->datasize, &s);
	errx(1, "%s: decrypt not the same: %s\n", t->name, s);
    }

    if (!EVP_Cipher(&dctx, d, d, t->datasize))
	return 1;

    if (memcmp(d, t->indata, t->datasize) != 0) {
	char *s;
	hex_encode(d, t->datasize, &s);
	errx(1, "%s: decrypt not the same: %s\n", t->name, s);
    }

    EVP_CIPHER_CTX_cleanup(&ectx);
    EVP_CIPHER_CTX_cleanup(&dctx);
    free(d);

    return 0;
}

static int version_flag;
static int help_flag;

static struct getargs args[] = {
    { "version",	0,	arg_flag,	&version_flag,
      "print version", NULL },
    { "help",		0,	arg_flag,	&help_flag,
      NULL, 	NULL }
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

int
main(int argc, char **argv)
{
    int ret = 0;
    int i, idx = 0;

    setprogname(argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &idx))
	usage(1);
    
    if (help_flag)
	usage(0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    argc -= idx;
    argv += idx;

    for (i = 0; i < sizeof(aes_tests)/sizeof(aes_tests[0]); i++)
	ret += test_cipher(EVP_aes_256_cbc(), &aes_tests[i]);
    for (i = 0; i < sizeof(rc2_40_tests)/sizeof(rc2_40_tests[0]); i++)
	ret += test_cipher(EVP_rc2_40_cbc(), &rc2_40_tests[i]);
    for (i = 0; i < sizeof(des_ede3_tests)/sizeof(des_ede3_tests[0]); i++)
	ret += test_cipher(EVP_des_ede3_cbc(), &des_ede3_tests[i]);
    for (i = 0; i < sizeof(camellia128_tests)/sizeof(camellia128_tests[0]); i++)
	ret += test_cipher(EVP_camellia_128_cbc(), &camellia128_tests[i]);

    return ret;
}
