/*
 * Copyright (c) 2004 - 2005 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"
RCSID("$Id$");

#include <sl.h>

static int version_flag;
static int help_flag;

struct getargs args[] = {
    { "version", 0, arg_flag, &version_flag },
    { "help", 0, arg_flag, &help_flag }
};
int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int code)
{
    arg_printusage(args, num_args, NULL, "command");
    exit(code);
}

static int
cms_verify_sd(int argc, char **argv)
{
    int ret;
    hx509_verify_ctx ctx = NULL;
    heim_oid type;
    heim_octet_string c;
    hx509_certs signers = NULL;
    hx509_certs anchors = NULL;

    size_t sz;
    void *p;

    argc--;
    argv++;

    if (argc < 2)
	errx(1, "argc < 2");

    printf("cms verify signed data\n");

    ret = _hx509_map_file(argv[0], &p, &sz);
    if (ret)
	err(1, "map_file: %s: %d", argv[0], ret);

    ret = hx509_verify_init_ctx(&ctx);

    argc--;
    argv++;

    ret = hx509_certs_init("MEMORY:cms-anchors", 0, NULL, &anchors);

    while (argc > 0) {

	ret = hx509_certs_append(anchors, argv[0]);
	if (ret)
	    errx(1, "hx509_certs_append: %d", ret);

	argc--;
	argv++;
    }

    hx509_verify_attach_anchors(ctx, anchors);

    ret = hx509_cms_verify_signed(ctx, p, sz, &type, &c, &signers);
    if (ret)
	errx(1, "hx509_cms_verify_signed: %d", ret);

    printf("signers:\n");
    hx509_certs_iter(signers, hx509_ci_print_names, stdout);

    hx509_certs_free(&anchors);
    hx509_certs_free(&signers);

    _hx509_unmap_file(p, sz);

    return 0;
}

static int
cms_create_sd(int argc, char **argv)
{
    const heim_oid *contentType;
    heim_octet_string o;
    hx509_query q;
    hx509_lock lock;
    hx509_certs s;
    hx509_cert cert;
    size_t sz;
    void *p;
    int ret;

    contentType = oid_id_pkcs7_data();

    argc--;
    argv++;

    if (argc < 3)
	errx(1, "argc < 3");

    printf("cms create signed data\n");

    hx509_lock_init(&lock);
    hx509_lock_add_password(lock, "foobar");

    ret = _hx509_map_file(argv[1], &p, &sz);
    if (ret)
	err(1, "map_file: %s: %d", argv[0], ret);

    ret = hx509_certs_init(argv[2], 0, lock, &s);
    if (ret)
	errx(1, "hx509_certs_init: %d", ret);

    _hx509_query_clear(&q);
    q.match |= HX509_QUERY_PRIVATE_KEY;
    q.match |= HX509_QUERY_KU_DIGITALSIGNATURE;

    ret = _hx509_certs_find(s, &q, &cert);
    if (ret)
	errx(1, "hx509_certs_find: %d", ret);

    ret = hx509_cms_create_signed_1(contentType,
				    p,
				    sz, 
				    NULL,
				    cert,
				    &o);
    if (ret)
	errx(1, "hx509_cms_create_signed: %d", ret);

    _hx509_unmap_file(p, sz);
    hx509_lock_free(lock);

    ret = _hx509_write_file(argv[1], o.data, o.length);
    if (ret)
	errx(1, "hx509_write_file: %d", ret);

    return 0;
}

static int
cms_unenvelope(int argc, char **argv)
{
    heim_oid contentType = { 0, NULL };
    heim_octet_string o;
    hx509_certs certs;
    size_t sz;
    void *p;
    int ret;
    hx509_lock lock;

    argc--;
    argv++;

    if (argc != 3)
	errx(1, "argc != 3");

    printf("cms unenvelope data\n");

    hx509_lock_init(&lock);
    hx509_lock_add_password(lock, "foobar");

    ret = _hx509_map_file(argv[1], &p, &sz);
    if (ret)
	err(1, "map_file: %s: %d", argv[0], ret);

    ret = hx509_certs_init("MEMORY:cert-store", 0, NULL, &certs);

    ret = hx509_certs_init(argv[0], 0, lock, &certs);
    if (ret)
	errx(1, "hx509_certs_init: %d", ret);

    ret = hx509_cms_unenvelope(certs, p, sz, &contentType, &o);
    if (ret)
	errx(1, "hx509_cms_unenvelope: %d", ret);

    _hx509_unmap_file(p, sz);
    hx509_lock_free(lock);

    ret = _hx509_write_file(argv[2], o.data, o.length);
    if (ret)
	errx(1, "hx509_write_file: %d", ret);

    free_octet_string(&o);

    return 0;
}

static int
cms_create_enveloped(int argc, char **argv)
{
    heim_octet_string o;
    heim_oid contentType = { 0, NULL };
    hx509_query q;
    hx509_certs certs;
    hx509_cert cert;
    int ret;
    size_t sz;
    void *p;

    argc--;
    argv++;

    if (argc != 3)
	errx(1, "argc ! = 3");

    printf("cms create enveloped\n");

    ret = _hx509_map_file(argv[0], &p, &sz);
    if (ret)
	err(1, "map_file: %s: %d", argv[0], ret);

    ret = hx509_certs_init(argv[2], 0, NULL, &certs);
    if (ret)
	errx(1, "hx509_certs_init: %d", ret);

    _hx509_query_clear(&q);
    ret = _hx509_certs_find(certs, &q, &cert);
    if (ret)
	errx(1, "hx509_certs_find: %d", ret);

    ret = hx509_cms_envelope_1(cert, p, sz, NULL, &contentType, &o);
    if (ret)
	errx(1, "hx509_cms_unenvelope: %d", ret);

    _hx509_unmap_file(p, sz);

    ret = _hx509_write_file(argv[1], o.data, o.length);
    if (ret)
	errx(1, "hx509_write_file: %d", ret);

    free_octet_string(&o);

    return 0;
}

static int
validate_print_f(void *ctx, hx509_cert c)
{
    hx509_validate_cert(ctx, c);
    return 0;
}

static int
validate_print(int argc, char **argv, int flags)
{
    hx509_validate_ctx ctx;
    hx509_certs certs;
    hx509_lock lock;

    argc--;
    argv++;

    if (argc < 1)
	errx(1, "argc");

    hx509_lock_init(&lock);
    hx509_lock_add_password(lock, "foobar");

    hx509_validate_ctx_init(&ctx);
    hx509_validate_ctx_set_print(ctx, hx509_print_stdout, stdout);
    hx509_validate_ctx_add_flags(ctx, flags);

    while(argc--) {
	int ret;
	ret = hx509_certs_init(argv[0], 0, lock, &certs);
	if (ret)
	    errx(1, "hx509_certs_init");
	hx509_certs_iter(certs, validate_print_f, ctx);
	hx509_certs_free(&certs);
	argv++;
    }
    hx509_validate_ctx_free(ctx);

    hx509_lock_free(lock);

    return 0;
}

static int
pcert_print(int argc, char **argv)
{
    return validate_print(argc, argv, HX509_VALIDATE_F_VERBOSE);
}

static int
pcert_validate(int argc, char **argv)
{
    return validate_print(argc, argv, HX509_VALIDATE_F_VALIDATE);
}

struct verify {
    hx509_verify_ctx ctx;
    hx509_certs chain;
};

static int
verify_f(void *ctx, hx509_cert c)
{
    struct verify *v = ctx;
    int ret;

    ret = hx509_verify_path(v->ctx, c, v->chain);
    if (ret)
	printf("verify_path returned %d\n", ret);
    else
	printf("path ok\n");

    return 0;
}

static int
pcert_verify(int argc, char **argv)
{
    hx509_certs anchors, chain, certs;
    hx509_verify_ctx ctx;
    struct verify v;
    int ret;

    argc--;
    argv++;

    ret = hx509_verify_init_ctx(&ctx);
    ret = hx509_certs_init("MEMORY:anchors", 0, NULL, &anchors);
    ret = hx509_certs_init("MEMORY:chain", 0, NULL, &chain);
    ret = hx509_certs_init("MEMORY:certs", 0, NULL, &certs);

    if (argc < 1)
	errx(1, "argc");

    while(argc--) {
	char *s = *argv++;

	if (strncmp(s, "chain:", 6) == 0) {
	    s += 6;

	    ret = hx509_certs_append(chain, s);
	    if (ret)
		errx(1, "hx509_certs_append: chain: %d", ret);

	} else if (strncmp(s, "anchor:", 7) == 0) {
	    s += 7;

	    ret = hx509_certs_append(anchors, s);
	    if (ret)
		errx(1, "hx509_certs_append: anchor: %d", ret);

	} else if (strncmp(s, "cert:", 5) == 0) {
	    s += 5;

	    ret = hx509_certs_append(certs, s);
	    if (ret)
		errx(1, "hx509_certs_append: certs: %d", ret);

	} else {
	    errx(1, "unknown option to verify: `%s'\n", s);
	}
    }

    hx509_verify_attach_anchors(ctx, anchors);

    v.ctx = ctx;
    v.chain = chain;

    hx509_certs_iter(certs, verify_f, &v);

    hx509_certs_free(&anchors);
    hx509_certs_free(&certs);
    hx509_certs_free(&chain);

    return 0;
}

static int
pcert_pkcs11(int argc, char **argv)
{
    int ret;

    argc--;
    argv++;

    if (argc < 1)
	errx(1, "argc");

    ret = hx509_keyset_init(argv[0], NULL);
    if (ret) {
	printf("hx509_keyset_init: %d\n", ret);
	return 0;
    }

    return 0;
}

static int help(int, char **);

static SL_cmd cmds[] = {
    { "cms-create-sd",
      cms_create_sd,
      "in-file out-file cert ...",
      "create signed data"
    },
    { "cms-verify-sd",
      cms_verify_sd,
      "file cert ...",
      "verify signed data"
    },
    { "cms-unenvelope",
      cms_unenvelope,
      "cert key in-file out-file",
      "unenvelope data"
    },
    { "cms-create-envelope",
      cms_create_enveloped,
      "cert in-file out-file",
      "envelope data"
    },

    { "print",
      pcert_print,
      "cert ...",
      "print certificates"
    },
    { "validate",
      pcert_validate,
      "cert ...",
      "validate certificates"
    },
    { "verify",
      pcert_verify,
      "cert:foo chain:cert1 chain:cert2 anchor:anchor1 anchor:anchor2",
      "verify certificates"
    },
    { "pkcs11",
      pcert_pkcs11,
      "...",
      "deal with pkcs11 devices"
    },
    { "help", help, "help" },
    { "?" },
    { NULL }
};

int
help(int argc, char **argv)
{
    sl_help(cmds, argc, argv);
    return 0;
}

int
main(int argc, char **argv)
{
    int ret, optidx = 0;

    setprogname (argv[0]);

    if(getarg(args, num_args, argc, argv, &optidx))
	usage(1);
    if(help_flag)
	usage(0);
    if(version_flag) {
	print_version(NULL);
	exit(0);
    }
    argv += optidx;
    argc -= optidx;

    if (argc == 0)
	usage(1);

    ret = sl_command(cmds, argc, argv);
    if(ret == -1)
	warnx ("unrecognized command: %s", argv[0]);

    return 0;
}
