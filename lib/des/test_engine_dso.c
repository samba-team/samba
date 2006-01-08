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

#include <stdio.h>

#include <roken.h>
#include <getarg.h>

#include <engine.h>

static int version_flag;
static int help_flag;
static char *id_flag;
static char *rsa_flag;

static struct getargs args[] = {
    { "id",		0,	arg_string,	&id_flag,
      "id", 	NULL },
    { "rsa",		0,	arg_string,	&rsa_flag,
      "rsa-der-file", 	NULL },
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
		    "filename.so");
    exit (ret);
}

int
main(int argc, char **argv)
{
    ENGINE *engine;
    int idx = 0;
    int have_rsa;

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

    if (argc == 0)
	usage(1);

    engine = ENGINE_by_dso(argv[0], id_flag);
    if (engine == NULL)
	errx(1, "ENGINE_by_dso failed");

    printf("name: %s\n", ENGINE_get_name(engine));
    printf("id: %s\n", ENGINE_get_id(engine));
    have_rsa = ENGINE_get_RSA(engine) != NULL;
    printf("RSA: %s\n", have_rsa ? "yes" : "no");
    printf("DH: %s\n", ENGINE_get_DH(engine) ? "yes" : "no");

    if (rsa_flag && have_rsa) {
	unsigned char buf[1024 * 4];
	const unsigned char *p;
	size_t size;
	int keylen;
	RSA *rsa;
	FILE *f;
	
	f = fopen(rsa_flag, "r");
	if (f == NULL)
	    err(1, "could not open file %s", rsa_flag);
	
	size = fread(buf, 1, sizeof(buf), f);
	if (size == 0)
	    err(1, "failed to read file %s", rsa_flag);
	if (size == sizeof(buf))
	    err(1, "key too long in file %s!", rsa_flag);
	fclose(f);
	
	p = buf;
	rsa = d2i_RSAPrivateKey(NULL, &p, size);
	if (rsa == NULL)
	    err(1, "failed to parse key in file %s", rsa_flag);
	
	RSA_set_method(rsa, ENGINE_get_RSA(engine));

	/* 
	 * try rsa signing
	 */

	memcpy(buf, "hejsan", 7);
	keylen = RSA_private_encrypt(7, buf, buf, rsa, RSA_PKCS1_PADDING);
	if (keylen <= 0)
	    errx(1, "failed to private encrypt");

	keylen = RSA_public_decrypt(keylen, buf, buf, rsa, RSA_PKCS1_PADDING);
	if (keylen <= 0)
	    errx(1, "failed to public decrypt");

	if (keylen != 7)
	    errx(1, "output buffer not same length");

	if (memcmp(buf, "hejsan", 7) != 0)
	    errx(1, "string not the same after decryption");

	/* 
	 * try rsa encryption 
	 */

	memcpy(buf, "hejsan", 7);
	keylen = RSA_public_encrypt(7, buf, buf, rsa, RSA_PKCS1_PADDING);
	if (keylen <= 0)
	    errx(1, "failed to public encrypt");

	keylen = RSA_private_decrypt(keylen, buf, buf, rsa, RSA_PKCS1_PADDING);
	if (keylen <= 0)
	    errx(1, "failed to private decrypt");

	if (keylen != 7)
	    errx(1, "output buffer not same length");

	if (memcmp(buf, "hejsan", 7) != 0)
	    errx(1, "string not the same after decryption");

	RSA_free(rsa);

	printf("rsa test passed\n");

    }

    ENGINE_finish(engine);

    return 0;
}
