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

#include <evp.h>

struct tests {
    void *key;
    size_t keysize;
    void *iv;
    size_t datasize;
    void *indata;
    void *outdata;
    size_t outdatasize;
};

struct tests aes_tests[] = {
    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      32,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\xdc\x95\xc0\x78\xa2\x40\x89\x89\xad\x48\xa2\x14\x92\x84\x20\x87"
    }
};

struct tests rc2_40_tests[] = {
    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\xc0\xb8\xff\xa5\xd6\xeb\xc9\x62\xcc\x52\x5f\xfe\x9a\x3c\x97\xe6"
    }
};

struct tests des_ede3_cbc_tests[] = {
    { "1917ffe6bb772efc297643bc63567e9a002e4d431d5ffd58",
      24,
      "\xbf\x9a\x12\xb7\x26\x69\xfd\x05",
      16,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x9d\x50\xf4\xc6\x01\xdb\x45\x49\x11\x8f\x36\x06\x06\x08\x2e\xe5"
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
	return 1;
    if (!EVP_CipherInit_ex(&dctx, c, NULL, t->key, t->iv, 0))
	return 1;

    d = malloc(t->datasize);

    if (!EVP_Cipher(&ectx, d, t->indata, t->datasize))
	return 1;

    if (memcmp(d, t->outdata, t->datasize) != 0) {
	printf("encrypt not the same\n");
	return 1;
    }

    if (!EVP_Cipher(&dctx, d, d, t->datasize))
	return 1;

    if (memcmp(d, t->indata, t->datasize) != 0) {
	printf("decrypt not the same\n");
	return 1;
    }

    EVP_CIPHER_CTX_cleanup(&ectx);
    EVP_CIPHER_CTX_cleanup(&dctx);

    return 0;
}

int
main(int argc, char **argv)
{
    int ret = 0;
    int i;

    for (i = 0; i < sizeof(aes_tests)/sizeof(aes_tests[0]); i++)
	ret += test_cipher(EVP_aes_256_cbc(), &aes_tests[i]);
    for (i = 0; i < sizeof(rc2_40_tests)/sizeof(rc2_40_tests[0]); i++)
	ret += test_cipher(EVP_rc2_40_cbc(), &rc2_40_tests[i]);
    for (i = 0; i < sizeof(rc2_40_tests)/sizeof(rc2_40_tests[0]); i++)
	ret += test_cipher(EVP_des_ede3_cbc(), &des_ede3_cbc_tests[i]);

    return ret;
}
