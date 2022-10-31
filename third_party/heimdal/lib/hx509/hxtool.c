/*
 * Copyright (c) 2004 - 2016 Kungliga Tekniska Högskolan
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

#include <hxtool-commands.h>
#include <sl.h>
#include <rtbl.h>
#include <parse_time.h>

static hx509_context context;

static char *stat_file_string;
static int version_flag;
static int help_flag;

struct getargs args[] = {
    { "statistic-file", 0, arg_string, &stat_file_string, NULL, NULL },
    { "version", 0, arg_flag, &version_flag, NULL, NULL },
    { "help", 0, arg_flag, &help_flag, NULL, NULL }
};
int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int code)
{
    arg_printusage(args, num_args, NULL, "command");
    printf("Use \"%s help\" to get more help\n", getprogname());
    exit(code);
}

/*
 *
 */

static void
lock_strings(hx509_lock lock, getarg_strings *pass)
{
    int i;
    for (i = 0; i < pass->num_strings; i++) {
	int ret = hx509_lock_command_string(lock, pass->strings[i]);
	if (ret)
	    errx(1, "hx509_lock_command_string: %s: %d",
		 pass->strings[i], ret);
    }
}

static char *
fix_store_name(hx509_context contextp, const char *sn, const char *def_type)
{
    const char *residue = strchr(sn, ':');
    char *s = NULL;

    if (residue) {
        s = estrdup(sn);
        s[residue - sn] = '\0';
        if (_hx509_ks_type(contextp, s)) {
            free(s);
            return estrdup(sn);
        }
        free(s);
        s = NULL;
    }
    if (asprintf(&s, "%s:%s", def_type, sn) == -1 || s == NULL)
        err(1, "Out of memory");
    return s;
}

static char *
fix_csr_name(const char *cn, const char *def_type)
{
    char *s = NULL;

    if (strncmp(cn, "PKCS10:", sizeof("PKCS10:") - 1) == 0 || strchr(cn, ':'))
        return estrdup(cn);
    if (asprintf(&s, "%s:%s", def_type, cn) == -1 || s == NULL)
        err(1, "Out of memory");
    return s;
}

/*
 *
 */

static void
certs_strings(hx509_context contextp, const char *type, hx509_certs certs,
	      hx509_lock lock, const getarg_strings *s)
{
    int i, ret;

    for (i = 0; i < s->num_strings; i++) {
        char *sn = fix_store_name(contextp, s->strings[i], "FILE");

	ret = hx509_certs_append(contextp, certs, lock, sn);
	if (ret)
	    hx509_err(contextp, 1, ret,
		      "hx509_certs_append: %s %s", type, sn);
        free(sn);
    }
}

/*
 *
 */

static void
parse_oid(const char *str, const heim_oid *def, heim_oid *oid)
{
    int ret;

    if (str) {
        const heim_oid *found = NULL;

        ret = der_find_heim_oid_by_name(str, &found);
        if (ret == 0)
            ret = der_copy_oid(found, oid);
        else
            ret = der_parse_heim_oid(str, " .", oid);
    } else {
	ret = der_copy_oid(def, oid);
    }
    if (ret)
	errx(1, "parse_oid failed for: %s", str ? str : "default oid");
}

/*
 *
 */

static void
peer_strings(hx509_context contextp,
	     hx509_peer_info *peer,
	     const getarg_strings *s)
{
    AlgorithmIdentifier *val;
    int ret, i;

    ret = hx509_peer_info_alloc(contextp, peer);
    if (ret)
	hx509_err(contextp, 1, ret, "hx509_peer_info_alloc");

    val = calloc(s->num_strings, sizeof(*val));
    if (val == NULL)
	err(1, "malloc");

    for (i = 0; i < s->num_strings; i++)
	parse_oid(s->strings[i], NULL, &val[i].algorithm);

    ret = hx509_peer_info_set_cms_algs(contextp, *peer, val, s->num_strings);
    if (ret)
	hx509_err(contextp, 1, ret, "hx509_peer_info_set_cms_algs");

    for (i = 0; i < s->num_strings; i++)
	free_AlgorithmIdentifier(&val[i]);
    free(val);
}

/*
 *
 */

struct pem_data {
    heim_octet_string *os;
    int detached_data;
};

static int
pem_reader(hx509_context contextp, const char *type,
	   const hx509_pem_header *headers,
	   const void *data , size_t length, void *ctx)
{
    struct pem_data *p = (struct pem_data *)ctx;
    const char *h;

    p->os->data = malloc(length);
    if (p->os->data == NULL)
	return ENOMEM;
    memcpy(p->os->data, data, length);
    p->os->length = length;

    h = hx509_pem_find_header(headers, "Content-disposition");
    if (h && strcasecmp(h, "detached") == 0)
	p->detached_data = 1;

    return 0;
}

/*
 *
 */

int
cms_verify_sd(struct cms_verify_sd_options *opt, int argc, char **argv)
{
    hx509_verify_ctx ctx = NULL;
    heim_oid type;
    heim_octet_string c, co, signeddata, *sd = NULL;
    hx509_certs store = NULL;
    hx509_certs signers = NULL;
    hx509_certs anchors = NULL;
    hx509_lock lock;
    int ret, flags = 0;

    size_t sz;
    void *p = NULL;

    if (opt->missing_revoke_flag)
	hx509_context_set_missing_revoke(context, 1);

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    ret = hx509_verify_init_ctx(context, &ctx);
    if (ret)
	hx509_err(context, 1, ret, "hx509_verify_init_ctx");

    ret = hx509_certs_init(context, "MEMORY:cms-anchors", 0, NULL, &anchors);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");
    ret = hx509_certs_init(context, "MEMORY:cert-store", 0, NULL, &store);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    certs_strings(context, "anchors", anchors, lock, &opt->anchors_strings);
    certs_strings(context, "store", store, lock, &opt->certificate_strings);

    if (opt->pem_flag) {
	struct pem_data pd;
	FILE *f;

	pd.os = &co;
	pd.detached_data = 0;

	f = fopen(argv[0], "r");
	if (f == NULL)
	    err(1, "Failed to open file %s", argv[0]);

	ret = hx509_pem_read(context, f, pem_reader, &pd);
	fclose(f);
	if (ret)
	    errx(1, "PEM reader failed: %d", ret);

	if (pd.detached_data && opt->signed_content_string == NULL) {
	    char *r = strrchr(argv[0], '.');
	    if (r && strcasecmp(r, ".pem") == 0) {
		char *s = strdup(argv[0]);
		if (s == NULL)
		    errx(1, "malloc: out of memory");
		s[r - argv[0]] = '\0';
		ret = _hx509_map_file_os(s, &signeddata);
		if (ret)
		    errx(1, "map_file: %s: %d", s, ret);
		free(s);
		sd = &signeddata;
	    }
	}

    } else {
	ret = rk_undumpdata(argv[0], &p, &sz);
	if (ret)
	    err(1, "map_file: %s: %d", argv[0], ret);

	co.data = p;
	co.length = sz;
    }

    if (opt->signed_content_string) {
	ret = _hx509_map_file_os(opt->signed_content_string, &signeddata);
	if (ret)
	    errx(1, "map_file: %s: %d", opt->signed_content_string, ret);
	sd = &signeddata;
    }

    if (opt->content_info_flag) {
	heim_octet_string uwco;
	heim_oid oid;

	ret = hx509_cms_unwrap_ContentInfo(&co, &oid, &uwco, NULL);
	if (ret)
	    errx(1, "hx509_cms_unwrap_ContentInfo: %d", ret);

	if (der_heim_oid_cmp(&oid, &asn1_oid_id_pkcs7_signedData) != 0)
	    errx(1, "Content is not SignedData");
	der_free_oid(&oid);

	if (p == NULL)
	    der_free_octet_string(&co);
	else {
	    rk_xfree(p);
	    p = NULL;
	}
	co = uwco;
    }

    hx509_verify_attach_anchors(ctx, anchors);

    if (!opt->signer_allowed_flag)
	flags |= HX509_CMS_VS_ALLOW_ZERO_SIGNER;
    if (opt->allow_wrong_oid_flag)
	flags |= HX509_CMS_VS_ALLOW_DATA_OID_MISMATCH;

    ret = hx509_cms_verify_signed(context, ctx, flags, co.data, co.length, sd,
				  store, &type, &c, &signers);
    if (p != co.data)
	der_free_octet_string(&co);
    else
	rk_xfree(p);
    if (ret)
	hx509_err(context, 1, ret, "hx509_cms_verify_signed");

    {
	char *str;
        if (opt->oid_sym_flag)
            der_print_heim_oid_sym(&type, '.', &str);
        else
            der_print_heim_oid(&type, '.', &str);
	printf("type: %s\n", str);
	free(str);
	der_free_oid(&type);
    }
    if (signers == NULL) {
	printf("unsigned\n");
    } else {
	printf("signers:\n");
	hx509_certs_iter_f(context, signers, hx509_ci_print_names, stdout);
    }

    hx509_verify_destroy_ctx(ctx);

    hx509_certs_free(&store);
    hx509_certs_free(&signers);
    hx509_certs_free(&anchors);

    hx509_lock_free(lock);

    if (argc > 1) {
	ret = _hx509_write_file(argv[1], c.data, c.length);
	if (ret)
	    errx(1, "hx509_write_file: %d", ret);
    }

    der_free_octet_string(&c);

    if (sd)
	_hx509_unmap_file_os(sd);

    return 0;
}

static int HX509_LIB_CALL
print_signer(hx509_context contextp, void *ctx, hx509_cert cert)
{
    hx509_pem_header **header = ctx;
    char *signer_name = NULL;
    hx509_name name;
    int ret;

    ret = hx509_cert_get_subject(cert, &name);
    if (ret)
	errx(1, "hx509_cert_get_subject");

    ret = hx509_name_to_string(name, &signer_name);
    hx509_name_free(&name);
    if (ret)
	errx(1, "hx509_name_to_string");

    hx509_pem_add_header(header, "Signer", signer_name);

    free(signer_name);
    return 0;
}

int
cms_create_sd(struct cms_create_sd_options *opt, int argc, char **argv)
{
    heim_oid contentType;
    hx509_peer_info peer = NULL;
    heim_octet_string o;
    hx509_query *q;
    hx509_lock lock;
    hx509_certs store, pool, anchors, signer = NULL;
    size_t sz;
    void *p;
    int ret, flags = 0;
    const char *outfile = NULL;
    char *infile, *freeme = NULL;

    memset(&contentType, 0, sizeof(contentType));

    infile = argv[0];

    if (argc < 2) {
	ret = asprintf(&freeme, "%s.%s", infile,
		       opt->pem_flag ? "pem" : "cms-signeddata");
	if (ret == -1 || freeme == NULL)
	    errx(1, "out of memory");
        outfile = freeme;
    } else
	outfile = argv[1];

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    ret = hx509_certs_init(context, "MEMORY:cert-store", 0, NULL, &store);
    if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");
    ret = hx509_certs_init(context, "MEMORY:cert-pool", 0, NULL, &pool);
    if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    certs_strings(context, "store", store, lock, &opt->certificate_strings);
    certs_strings(context, "pool", pool, lock, &opt->pool_strings);

    if (opt->anchors_strings.num_strings) {
	ret = hx509_certs_init(context, "MEMORY:cert-anchors",
			       0, NULL, &anchors);
	if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");
	certs_strings(context, "anchors", anchors, lock, &opt->anchors_strings);
    } else
	anchors = NULL;

    if (opt->detached_signature_flag)
	flags |= HX509_CMS_SIGNATURE_DETACHED;
    if (opt->id_by_name_flag)
	flags |= HX509_CMS_SIGNATURE_ID_NAME;
    if (!opt->signer_flag) {
	flags |= HX509_CMS_SIGNATURE_NO_SIGNER;

    }

    if (opt->signer_flag) {
	ret = hx509_query_alloc(context, &q);
	if (ret)
	    errx(1, "hx509_query_alloc: %d", ret);

	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
	hx509_query_match_option(q, HX509_QUERY_OPTION_KU_DIGITALSIGNATURE);

	if (opt->signer_string)
	    hx509_query_match_friendly_name(q, opt->signer_string);

	ret = hx509_certs_filter(context, store, q, &signer);
	hx509_query_free(context, q);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_find");
    }
    if (!opt->embedded_certs_flag)
	flags |= HX509_CMS_SIGNATURE_NO_CERTS;
    if (opt->embed_leaf_only_flag)
	flags |= HX509_CMS_SIGNATURE_LEAF_ONLY;

    ret = rk_undumpdata(infile, &p, &sz);
    if (ret)
	err(1, "map_file: %s: %d", infile, ret);

    if (opt->peer_alg_strings.num_strings)
	peer_strings(context, &peer, &opt->peer_alg_strings);

    parse_oid(opt->content_type_string, &asn1_oid_id_pkcs7_data, &contentType);

    ret = hx509_cms_create_signed(context,
				  flags,
				  &contentType,
				  p,
				  sz,
				  NULL,
				  signer,
				  peer,
				  anchors,
				  pool,
				  &o);
    if (ret)
	hx509_err(context, 1, ret, "hx509_cms_create_signed: %d", ret);

    hx509_certs_free(&anchors);
    hx509_certs_free(&pool);
    hx509_certs_free(&store);
    rk_xfree(p);
    hx509_lock_free(lock);
    hx509_peer_info_free(peer);
    der_free_oid(&contentType);

    if (opt->content_info_flag) {
	heim_octet_string wo;

	ret = hx509_cms_wrap_ContentInfo(&asn1_oid_id_pkcs7_signedData, &o, &wo);
	if (ret)
	    errx(1, "hx509_cms_wrap_ContentInfo: %d", ret);

	der_free_octet_string(&o);
	o = wo;
    }

    if (opt->pem_flag) {
	hx509_pem_header *header = NULL;
	FILE *f;

	hx509_pem_add_header(&header, "Content-disposition",
			     opt->detached_signature_flag ?
			     "detached" : "inline");
	if (signer) {
	    ret = hx509_certs_iter_f(context, signer, print_signer, header);
	    if (ret)
		hx509_err(context, 1, ret, "print signer");
	}

	f = fopen(outfile, "w");
	if (f == NULL)
	    err(1, "open %s", outfile);

	ret = hx509_pem_write(context, "CMS SIGNEDDATA", header, f,
			      o.data, o.length);
	fclose(f);
	hx509_pem_free_header(header);
	if (ret)
	    errx(1, "hx509_pem_write: %d", ret);

    } else {
	ret = _hx509_write_file(outfile, o.data, o.length);
	if (ret)
	    errx(1, "hx509_write_file: %d", ret);
    }

    hx509_certs_free(&signer);
    free(o.data);
    free(freeme);

    return 0;
}

int
cms_unenvelope(struct cms_unenvelope_options *opt, int argc, char **argv)
{
    heim_oid contentType = { 0, NULL };
    heim_octet_string o, co;
    hx509_certs certs;
    size_t sz;
    void *p;
    int ret;
    hx509_lock lock;
    int flags = 0;

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    ret = rk_undumpdata(argv[0], &p, &sz);
    if (ret)
	err(1, "map_file: %s: %d", argv[0], ret);

    co.data = p;
    co.length = sz;

    if (opt->content_info_flag) {
	heim_octet_string uwco;
	heim_oid oid;

	ret = hx509_cms_unwrap_ContentInfo(&co, &oid, &uwco, NULL);
	if (ret)
	    errx(1, "hx509_cms_unwrap_ContentInfo: %d", ret);

	if (der_heim_oid_cmp(&oid, &asn1_oid_id_pkcs7_envelopedData) != 0)
	    errx(1, "Content is not SignedData");
	der_free_oid(&oid);

	co = uwco;
    }

    ret = hx509_certs_init(context, "MEMORY:cert-store", 0, NULL, &certs);
    if (ret)
	errx(1, "hx509_certs_init: MEMORY: %d", ret);

    certs_strings(context, "store", certs, lock, &opt->certificate_strings);

    if (opt->allow_weak_crypto_flag)
	flags |= HX509_CMS_UE_ALLOW_WEAK;

    ret = hx509_cms_unenvelope(context, certs, flags, co.data, co.length,
			       NULL, 0, &contentType, &o);
    if (co.data != p)
	der_free_octet_string(&co);
    if (ret)
	hx509_err(context, 1, ret, "hx509_cms_unenvelope");

    rk_xfree(p);
    hx509_lock_free(lock);
    hx509_certs_free(&certs);
    der_free_oid(&contentType);

    ret = _hx509_write_file(argv[1], o.data, o.length);
    if (ret)
	errx(1, "hx509_write_file: %d", ret);

    der_free_octet_string(&o);

    return 0;
}

int
cms_create_enveloped(struct cms_envelope_options *opt, int argc, char **argv)
{
    heim_oid contentType;
    heim_octet_string o;
    const heim_oid *enctype = NULL;
    hx509_query *q;
    hx509_certs certs;
    hx509_cert cert;
    int ret;
    size_t sz;
    void *p;
    hx509_lock lock;
    int flags = 0;

    memset(&contentType, 0, sizeof(contentType));

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    ret = rk_undumpdata(argv[0], &p, &sz);
    if (ret)
	err(1, "map_file: %s: %d", argv[0], ret);

    ret = hx509_certs_init(context, "MEMORY:cert-store", 0, NULL, &certs);
    if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    certs_strings(context, "store", certs, lock, &opt->certificate_strings);

    if (opt->allow_weak_crypto_flag)
	flags |= HX509_CMS_EV_ALLOW_WEAK;

    if (opt->encryption_type_string) {
	enctype = hx509_crypto_enctype_by_name(opt->encryption_type_string);
	if (enctype == NULL)
	    errx(1, "encryption type: %s no found",
		 opt->encryption_type_string);
    }

    ret = hx509_query_alloc(context, &q);
    if (ret)
	errx(1, "hx509_query_alloc: %d", ret);

    hx509_query_match_option(q, HX509_QUERY_OPTION_KU_ENCIPHERMENT);

    ret = hx509_certs_find(context, certs, q, &cert);
    hx509_query_free(context, q);
    if (ret)
	errx(1, "hx509_certs_find: %d", ret);

    parse_oid(opt->content_type_string, &asn1_oid_id_pkcs7_data, &contentType);

    ret = hx509_cms_envelope_1(context, flags, cert, p, sz, enctype,
			       &contentType, &o);
    if (ret)
	errx(1, "hx509_cms_envelope_1: %d", ret);

    hx509_cert_free(cert);
    hx509_certs_free(&certs);
    rk_xfree(p);
    der_free_oid(&contentType);

    if (opt->content_info_flag) {
	heim_octet_string wo;

	ret = hx509_cms_wrap_ContentInfo(&asn1_oid_id_pkcs7_envelopedData, &o, &wo);
	if (ret)
	    errx(1, "hx509_cms_wrap_ContentInfo: %d", ret);

	der_free_octet_string(&o);
	o = wo;
    }

    hx509_lock_free(lock);

    ret = _hx509_write_file(argv[1], o.data, o.length);
    if (ret)
	errx(1, "hx509_write_file: %d", ret);

    der_free_octet_string(&o);

    return 0;
}

static void
print_certificate(hx509_context hxcontext, hx509_cert cert, int verbose)
{
    const char *fn;
    int ret;

    fn = hx509_cert_get_friendly_name(cert);
    if (fn)
	printf("    friendly name: %s\n", fn);
    printf("    private key: %s\n",
	   _hx509_cert_private_key(cert) ? "yes" : "no");

    ret = hx509_print_cert(hxcontext, cert, stdout);
    if (ret)
	errx(1, "failed to print cert");

    if (verbose) {
	hx509_validate_ctx vctx;

	hx509_validate_ctx_init(hxcontext, &vctx);
	hx509_validate_ctx_set_print(vctx, hx509_print_stdout, stdout);
	hx509_validate_ctx_add_flags(vctx, HX509_VALIDATE_F_VALIDATE);
	hx509_validate_ctx_add_flags(vctx, HX509_VALIDATE_F_VERBOSE);

	hx509_validate_cert(hxcontext, vctx, cert);

	hx509_validate_ctx_free(vctx);
    }
}


struct print_s {
    int counter;
    int verbose;
};

static int HX509_LIB_CALL
print_f(hx509_context hxcontext, void *ctx, hx509_cert cert)
{
    struct print_s *s = ctx;

    printf("cert: %d\n", s->counter++);
    print_certificate(context, cert, s->verbose);

    return 0;
}

static int HX509_LIB_CALL
print_fjson(hx509_context hxcontext, void *ctx, hx509_cert cert)
{
    const Certificate *c = NULL;
    char *json = NULL;

    c = _hx509_get_cert(cert);
    if (c)
        json = print_Certificate(c, ASN1_PRINT_INDENT);
    if (json)
        printf("%s\n", json);
    else
        hx509_err(context, 1, errno, "Could not format certificate as JSON");
    free(json);
    return 0;
}


int
pcert_print(struct print_options *opt, int argc, char **argv)
{
    hx509_certs certs;
    hx509_lock lock;
    struct print_s s;

    s.counter = 0;
    s.verbose = opt->content_flag;

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    while(argc--) {
        char *sn = fix_store_name(context, argv[0], "FILE");
	int ret;

	ret = hx509_certs_init(context, sn, 0, lock, &certs);
        free(sn);
	if (ret) {
	    if (opt->never_fail_flag) {
		printf("ignoreing failure: %d\n", ret);
		continue;
	    }
	    hx509_err(context, 1, ret, "hx509_certs_init");
	}
        if (opt->raw_json_flag) {
            hx509_certs_iter_f(context, certs, print_fjson, &s);
        } else {
            if (opt->info_flag)
                hx509_certs_info(context, certs, NULL, NULL);
            hx509_certs_iter_f(context, certs, print_f, &s);
        }
	hx509_certs_free(&certs);
	argv++;
    }

    hx509_lock_free(lock);

    return 0;
}


static int HX509_LIB_CALL
validate_f(hx509_context hxcontext, void *ctx, hx509_cert c)
{
    hx509_validate_cert(hxcontext, ctx, c);
    return 0;
}

int
pcert_validate(struct validate_options *opt, int argc, char **argv)
{
    hx509_validate_ctx ctx;
    hx509_certs certs;
    hx509_lock lock;

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    hx509_validate_ctx_init(context, &ctx);
    hx509_validate_ctx_set_print(ctx, hx509_print_stdout, stdout);
    hx509_validate_ctx_add_flags(ctx, HX509_VALIDATE_F_VALIDATE);

    while(argc--) {
        char *sn = fix_store_name(context, argv[0], "FILE");
	int ret;

	ret = hx509_certs_init(context, sn, 0, lock, &certs);
	if (ret)
	    errx(1, "hx509_certs_init: %d", ret);
	hx509_certs_iter_f(context, certs, validate_f, ctx);
	hx509_certs_free(&certs);
	argv++;
        free(sn);
    }
    hx509_validate_ctx_free(ctx);

    hx509_lock_free(lock);

    return 0;
}

int
certificate_copy(struct certificate_copy_options *opt, int argc, char **argv)
{
    hx509_certs certs;
    hx509_lock inlock, outlock = NULL;
    char *sn;
    int ret;

    hx509_lock_init(context, &inlock);
    lock_strings(inlock, &opt->in_pass_strings);

    if (opt->out_pass_string) {
	hx509_lock_init(context, &outlock);
	ret = hx509_lock_command_string(outlock, opt->out_pass_string);
	if (ret)
	    errx(1, "hx509_lock_command_string: %s: %d",
		 opt->out_pass_string, ret);
    }

    sn = fix_store_name(context, argv[argc - 1], "FILE");
    ret = hx509_certs_init(context, sn,
			   HX509_CERTS_CREATE, inlock, &certs);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_init %s", sn);
    free(sn);

    while(argc-- > 1) {
	int retx;

        sn = fix_store_name(context, argv[0], "FILE");
	retx = hx509_certs_append(context, certs, inlock, sn);
	if (retx)
	    hx509_err(context, 1, retx, "hx509_certs_append %s", sn);
        free(sn);
	argv++;
    }

    ret = hx509_certs_store(context, certs, 0, outlock);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_store");

    hx509_certs_free(&certs);
    hx509_lock_free(inlock);
    hx509_lock_free(outlock);

    return 0;
}

struct verify {
    hx509_verify_ctx ctx;
    hx509_certs chain;
    const char *hostname;
    int errors;
    int count;
};

static int HX509_LIB_CALL
verify_f(hx509_context hxcontext, void *ctx, hx509_cert c)
{
    struct verify *v = ctx;
    int ret;

    ret = hx509_verify_path(hxcontext, v->ctx, c, v->chain);
    if (ret) {
	char *s = hx509_get_error_string(hxcontext, ret);
	printf("verify_path: %s: %d\n", s, ret);
	hx509_free_error_string(s);
	v->errors++;
    } else {
	v->count++;
	printf("path ok\n");
    }

    if (v->hostname) {
	ret = hx509_verify_hostname(hxcontext, c, 0, HX509_HN_HOSTNAME,
				    v->hostname, NULL, 0);
	if (ret) {
	    printf("verify_hostname: %d\n", ret);
	    v->errors++;
	}
    }

    return 0;
}

int
pcert_verify(struct verify_options *opt, int argc, char **argv)
{
    hx509_certs anchors, chain, certs;
    hx509_revoke_ctx revoke_ctx;
    hx509_verify_ctx ctx;
    struct verify v;
    int ret;

    memset(&v, 0, sizeof(v));

    if (opt->missing_revoke_flag)
	hx509_context_set_missing_revoke(context, 1);

    ret = hx509_verify_init_ctx(context, &ctx);
    if (ret)
	hx509_err(context, 1, ret, "hx509_verify_init_ctx");
    ret = hx509_certs_init(context, "MEMORY:anchors", 0, NULL, &anchors);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");
    ret = hx509_certs_init(context, "MEMORY:chain", 0, NULL, &chain);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");
    ret = hx509_certs_init(context, "MEMORY:certs", 0, NULL, &certs);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    if (opt->allow_proxy_certificate_flag)
	hx509_verify_set_proxy_certificate(ctx, 1);

    if (opt->time_string) {
	const char *p;
	struct tm tm;
	time_t t;

	memset(&tm, 0, sizeof(tm));

	p = strptime (opt->time_string, "%Y-%m-%d", &tm);
	if (p == NULL)
	    errx(1, "Failed to parse time %s, need to be on format %%Y-%%m-%%d",
		 opt->time_string);

	t = tm2time (tm, 0);

	hx509_verify_set_time(ctx, t);
    }

    if (opt->hostname_string)
	v.hostname = opt->hostname_string;
    if (opt->max_depth_integer)
	hx509_verify_set_max_depth(ctx, opt->max_depth_integer);

    ret = hx509_revoke_init(context, &revoke_ctx);
    if (ret)
	errx(1, "hx509_revoke_init: %d", ret);

    while(argc--) {
	const char *s = *argv++;
        char *sn = NULL;

	if (strncmp(s, "chain:", 6) == 0) {
	    s += 6;

            sn = fix_store_name(context, s, "FILE");
	    ret = hx509_certs_append(context, chain, NULL, sn);
	    if (ret)
                hx509_err(context, 1, ret, "hx509_certs_append: chain: %s: %d",
                          sn, ret);

	} else if (strncmp(s, "anchor:", 7) == 0) {
	    s += 7;

            sn = fix_store_name(context, s, "FILE");
	    ret = hx509_certs_append(context, anchors, NULL, sn);
	    if (ret)
		hx509_err(context, 1, ret,
                          "hx509_certs_append: anchor: %s: %d", sn, ret);

	} else if (strncmp(s, "cert:", 5) == 0) {
	    s += 5;

            sn = fix_store_name(context, s, "FILE");
	    ret = hx509_certs_append(context, certs, NULL, sn);
	    if (ret)
		hx509_err(context, 1, ret, "hx509_certs_append: certs: %s: %d",
			  sn, ret);

	} else if (strncmp(s, "crl:", 4) == 0) {
	    s += 4;

	    ret = hx509_revoke_add_crl(context, revoke_ctx, s);
	    if (ret)
		errx(1, "hx509_revoke_add_crl: %s: %d", s, ret);

	} else if (strncmp(s, "ocsp:", 5) == 0) {
	    s += 5;

	    ret = hx509_revoke_add_ocsp(context, revoke_ctx, s);
	    if (ret)
		errx(1, "hx509_revoke_add_ocsp: %s: %d", s, ret);

	} else {
	    errx(1, "unknown option to verify: `%s'\n", s);
	}
        free(sn);
    }

    hx509_verify_attach_anchors(ctx, anchors);
    hx509_verify_attach_revoke(ctx, revoke_ctx);

    v.ctx = ctx;
    v.chain = chain;

    hx509_certs_iter_f(context, certs, verify_f, &v);

    hx509_verify_destroy_ctx(ctx);

    hx509_certs_free(&certs);
    hx509_certs_free(&chain);
    hx509_certs_free(&anchors);

    hx509_revoke_free(&revoke_ctx);


    if (v.count == 0) {
	printf("no certs verify at all\n");
	return 1;
    }

    if (v.errors) {
	printf("failed verifing %d checks\n", v.errors);
	return 1;
    }

    return 0;
}

int
query(struct query_options *opt, int argc, char **argv)
{
    hx509_lock lock;
    hx509_query *q;
    hx509_certs certs;
    hx509_cert c;
    int ret;

    ret = hx509_query_alloc(context, &q);
    if (ret)
	errx(1, "hx509_query_alloc: %d", ret);

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    ret = hx509_certs_init(context, "MEMORY:cert-store", 0, NULL, &certs);
    if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    while (argc > 0) {
        char *sn = fix_store_name(context, argv[0], "FILE");

	ret = hx509_certs_append(context, certs, lock, sn);
	if (ret)
	    errx(1, "hx509_certs_append: %s: %d", sn, ret);
        free(sn);

	argc--;
	argv++;
    }

    if (opt->friendlyname_string)
	hx509_query_match_friendly_name(q, opt->friendlyname_string);

    if (opt->eku_string) {
	heim_oid oid;

	parse_oid(opt->eku_string, NULL, &oid);

	ret = hx509_query_match_eku(q, &oid);
	if (ret)
	    errx(1, "hx509_query_match_eku: %d", ret);
	der_free_oid(&oid);
    }

    if (opt->private_key_flag)
	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);

    if (opt->keyEncipherment_flag)
	hx509_query_match_option(q, HX509_QUERY_OPTION_KU_ENCIPHERMENT);

    if (opt->digitalSignature_flag)
	hx509_query_match_option(q, HX509_QUERY_OPTION_KU_DIGITALSIGNATURE);

    if (opt->expr_string)
	hx509_query_match_expr(context, q, opt->expr_string);

    ret = hx509_certs_find(context, certs, q, &c);
    hx509_query_free(context, q);
    if (ret)
	printf("no match found (%d)\n", ret);
    else {
	printf("match found\n");
	if (opt->print_flag)
	    print_certificate(context, c, 0);
    }

    hx509_cert_free(c);
    hx509_certs_free(&certs);

    hx509_lock_free(lock);

    return ret;
}

int
ocsp_fetch(struct ocsp_fetch_options *opt, int argc, char **argv)
{
    hx509_certs reqcerts, pool;
    heim_octet_string req, nonce_data, *nonce = &nonce_data;
    hx509_lock lock;
    int i, ret;
    char *file;
    const char *url = "/";

    memset(&nonce, 0, sizeof(nonce));

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    /* no nonce */
    if (!opt->nonce_flag)
	nonce = NULL;

    if (opt->url_path_string)
	url = opt->url_path_string;

    ret = hx509_certs_init(context, "MEMORY:ocsp-pool", 0, NULL, &pool);
    if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    certs_strings(context, "ocsp-pool", pool, lock, &opt->pool_strings);

    file = argv[0];

    ret = hx509_certs_init(context, "MEMORY:ocsp-req", 0, NULL, &reqcerts);
    if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    for (i = 1; i < argc; i++) {
        char *sn = fix_store_name(context, argv[i], "FILE");

	ret = hx509_certs_append(context, reqcerts, lock, sn);
	if (ret)
	    errx(1, "hx509_certs_append: req: %s: %d", sn, ret);
        free(sn);
    }

    ret = hx509_ocsp_request(context, reqcerts, pool, NULL, NULL, &req, nonce);
    if (ret)
	errx(1, "hx509_ocsp_request: req: %d", ret);

    {
	FILE *f;

	f = fopen(file, "w");
	if (f == NULL)
	    abort();

	fprintf(f,
		"POST %s HTTP/1.0\r\n"
		"Content-Type: application/ocsp-request\r\n"
		"Content-Length: %ld\r\n"
		"\r\n",
		url,
		(unsigned long)req.length);
	fwrite(req.data, req.length, 1, f);
	fclose(f);
    }

    if (nonce)
	der_free_octet_string(nonce);

    hx509_certs_free(&reqcerts);
    hx509_certs_free(&pool);

    return 0;
}

int
ocsp_print(struct ocsp_print_options *opt, int argc, char **argv)
{
    hx509_revoke_ocsp_print(context, argv[0], stdout);
    return 0;
}

int
revoke_print(struct revoke_print_options *opt, int argc, char **argv)
{
    hx509_revoke_ctx revoke_ctx;
    int ret;

    ret = hx509_revoke_init(context, &revoke_ctx);
    if (ret)
	errx(1, "hx509_revoke_init: %d", ret);

    while(argc--) {
	char *s = *argv++;

	if (strncmp(s, "crl:", 4) == 0) {
	    s += 4;

	    ret = hx509_revoke_add_crl(context, revoke_ctx, s);
	    if (ret)
		errx(1, "hx509_revoke_add_crl: %s: %d", s, ret);

	} else if (strncmp(s, "ocsp:", 5) == 0) {
	    s += 5;

	    ret = hx509_revoke_add_ocsp(context, revoke_ctx, s);
	    if (ret)
		errx(1, "hx509_revoke_add_ocsp: %s: %d", s, ret);

	} else {
	    errx(1, "unknown option to verify: `%s'\n", s);
	}
    }

    ret = hx509_revoke_print(context, revoke_ctx, stdout);
    if (ret)
	warnx("hx509_revoke_print: %d", ret);

    hx509_revoke_free(&revoke_ctx);
    return ret;
}

/*
 *
 */

static int HX509_LIB_CALL
verify_o(hx509_context hxcontext, void *ctx, hx509_cert c)
{
    heim_octet_string *os = ctx;
    time_t expiration;
    int ret;

    ret = hx509_ocsp_verify(context, 0, c, 0,
			    os->data, os->length, &expiration);
    if (ret) {
	char *s = hx509_get_error_string(hxcontext, ret);
	printf("ocsp_verify: %s: %d\n", s, ret);
	hx509_free_error_string(s);
    } else
	printf("expire: %d\n", (int)expiration);

    return ret;
}


int
ocsp_verify(struct ocsp_verify_options *opt, int argc, char **argv)
{
    hx509_lock lock;
    hx509_certs certs;
    int ret, i;
    heim_octet_string os;

    hx509_lock_init(context, &lock);

    if (opt->ocsp_file_string == NULL)
	errx(1, "no ocsp file given");

    ret = _hx509_map_file_os(opt->ocsp_file_string, &os);
    if (ret)
	err(1, "map_file: %s: %d", argv[0], ret);

    ret = hx509_certs_init(context, "MEMORY:test-certs", 0, NULL, &certs);
    if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    for (i = 0; i < argc; i++) {
        char *sn = fix_store_name(context, argv[i], "FILE");

	ret = hx509_certs_append(context, certs, lock, sn);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_append: %s", sn);
        free(sn);
    }

    ret = hx509_certs_iter_f(context, certs, verify_o, &os);

    hx509_certs_free(&certs);
    _hx509_unmap_file_os(&os);
    hx509_lock_free(lock);

    return ret;
}

static int
read_private_key(const char *fn, hx509_private_key *key)
{
    hx509_private_key *keys;
    hx509_certs certs;
    char *sn = fix_store_name(context, fn, "FILE");
    int ret;

    *key = NULL;

    ret = hx509_certs_init(context, sn, 0, NULL, &certs);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_init: %s", sn);

    ret = _hx509_certs_keys_get(context, certs, &keys);
    hx509_certs_free(&certs);
    if (ret)
	hx509_err(context, 1, ret, "hx509_certs_keys_get");
    if (keys[0] == NULL)
	errx(1, "no keys in key store: %s", sn);
    free(sn);

    *key = _hx509_private_key_ref(keys[0]);
    _hx509_certs_keys_free(context, keys);

    return 0;
}

static void
get_key(const char *fn, const char *type, int optbits,
	hx509_private_key *signer)
{
    int ret = 0;

    if (type) {
        struct hx509_generate_private_context *gen_ctx = NULL;

	if (strcasecmp(type, "rsa") != 0)
	    errx(1, "can only handle rsa keys for now");

        ret = _hx509_generate_private_key_init(context,
                                               ASN1_OID_ID_PKCS1_RSAENCRYPTION,
                                               &gen_ctx);
        if (ret == 0)
            ret = _hx509_generate_private_key_bits(context, gen_ctx, optbits);
        if (ret == 0)
            ret = _hx509_generate_private_key(context, gen_ctx, signer);
        _hx509_generate_private_key_free(&gen_ctx);
        if (ret)
            hx509_err(context, 1, ret, "failed to generate private key of type %s", type);

        if (fn) {
            char *sn = fix_store_name(context, fn, "FILE");
            hx509_certs certs = NULL;
            hx509_cert cert = NULL;

            cert = hx509_cert_init_private_key(context, *signer, NULL);
            if (cert)
                ret = hx509_certs_init(context, sn,
                                       HX509_CERTS_CREATE |
                                       HX509_CERTS_UNPROTECT_ALL,
                                       NULL, &certs);
            if (ret == 0)
                ret = hx509_certs_add(context, certs, cert);
            if (ret == 0)
                ret = hx509_certs_store(context, certs, 0, NULL);
            if (ret)
                hx509_err(context, 1, ret, "failed to store generated private "
                          "key in %s", sn);

            if (certs)
                hx509_certs_free(&certs);
            if (cert)
                hx509_cert_free(cert);
            free(sn);
        }
    } else {
        if (fn == NULL)
            err(1, "no private key");
        ret = read_private_key(fn, signer);
        if (ret)
            hx509_err(context, 1, ret, "failed to read private key from %s",
                      fn);
    }
}

int
generate_key(struct generate_key_options *opt, int argc, char **argv)
{
    hx509_private_key signer;
    const char *type = opt->type_string ? opt->type_string : "rsa";
    int bits = opt->key_bits_integer ? opt->key_bits_integer : 2048;

    memset(&signer, 0, sizeof(signer));
    get_key(argv[0], type, bits, &signer);
    hx509_private_key_free(&signer);
    return 0;
}

int
request_create(struct request_create_options *opt, int argc, char **argv)
{
    heim_octet_string request;
    hx509_request req;
    int ret, i;
    hx509_private_key signer;
    SubjectPublicKeyInfo key;
    const char *outfile = argv[0];

    memset(&key, 0, sizeof(key));
    memset(&signer, 0, sizeof(signer));

    get_key(opt->key_string,
	    opt->generate_key_string,
	    opt->key_bits_integer,
	    &signer);

    hx509_request_init(context, &req);

    if (opt->subject_string) {
	hx509_name name = NULL;

	ret = hx509_parse_name(context, opt->subject_string, &name);
	if (ret)
	    errx(1, "hx509_parse_name: %d\n", ret);
	hx509_request_set_name(context, req, name);

	if (opt->verbose_flag) {
	    char *s;
	    hx509_name_to_string(name, &s);
	    printf("%s\n", s);
            free(s);
	}
	hx509_name_free(&name);
    }

    for (i = 0; i < opt->email_strings.num_strings; i++) {
        ret = hx509_request_add_email(context, req,
                                      opt->email_strings.strings[i]);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_request_add_email");
    }

    for (i = 0; i < opt->jid_strings.num_strings; i++) {
        ret = hx509_request_add_xmpp_name(context, req,
                                          opt->jid_strings.strings[i]);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_request_add_xmpp_name");
    }

    for (i = 0; i < opt->dnsname_strings.num_strings; i++) {
        ret = hx509_request_add_dns_name(context, req,
                                         opt->dnsname_strings.strings[i]);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_request_add_dns_name");
    }

    for (i = 0; i < opt->kerberos_strings.num_strings; i++) {
        ret = hx509_request_add_pkinit(context, req,
                                       opt->kerberos_strings.strings[i]);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_request_add_pkinit");
    }

    for (i = 0; i < opt->ms_kerberos_strings.num_strings; i++) {
        ret = hx509_request_add_ms_upn_name(context, req,
                                            opt->ms_kerberos_strings.strings[i]);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_request_add_ms_upn_name");
    }

    for (i = 0; i < opt->registered_strings.num_strings; i++) {
        heim_oid oid;

	parse_oid(opt->registered_strings.strings[i], NULL, &oid);
        ret = hx509_request_add_registered(context, req, &oid);
        der_free_oid(&oid);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_request_add_registered");
    }

    for (i = 0; i < opt->eku_strings.num_strings; i++) {
	heim_oid oid;

	parse_oid(opt->eku_strings.strings[i], NULL, &oid);
	ret = hx509_request_add_eku(context, req, &oid);
        der_free_oid(&oid);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_request_add_eku");
    }


    ret = hx509_private_key2SPKI(context, signer, &key);
    if (ret)
	errx(1, "hx509_private_key2SPKI: %d\n", ret);

    ret = hx509_request_set_SubjectPublicKeyInfo(context,
						  req,
						  &key);
    free_SubjectPublicKeyInfo(&key);
    if (ret)
	hx509_err(context, 1, ret, "hx509_request_set_SubjectPublicKeyInfo");

    ret = hx509_request_to_pkcs10(context,
                                  req,
                                  signer,
                                  &request);
    if (ret)
	hx509_err(context, 1, ret, "hx509_request_to_pkcs10");

    hx509_private_key_free(&signer);
    hx509_request_free(&req);

    if (ret == 0)
	rk_dumpdata(outfile, request.data, request.length);
    der_free_octet_string(&request);

    return 0;
}

int
request_print(struct request_print_options *opt, int argc, char **argv)
{
    int ret, i;

    printf("request print\n");

    for (i = 0; i < argc; i++) {
	hx509_request req;
        char *cn = fix_csr_name(argv[i], "PKCS10");

	ret = hx509_request_parse(context, cn, &req);
	if (ret)
	    hx509_err(context, 1, ret, "parse_request: %s", cn);

	ret = hx509_request_print(context, req, stdout);
	hx509_request_free(&req);
	if (ret)
	    hx509_err(context, 1, ret, "Failed to print file %s", cn);
        free(cn);
    }

    return 0;
}

int
info(void *opt, int argc, char **argv)
{

    ENGINE_add_conf_module();

    {
	const RSA_METHOD *m = RSA_get_default_method();
	if (m != NULL)
	    printf("rsa: %s\n", m->name);
    }
    {
	const DH_METHOD *m = DH_get_default_method();
	if (m != NULL)
	    printf("dh: %s\n", m->name);
    }
#ifdef HAVE_HCRYPTO_W_OPENSSL
    {
	printf("ecdsa: ECDSA_METHOD-not-export\n");
    }
#else
    {
	printf("ecdsa: hcrypto null\n");
    }
#endif
    {
	int ret = RAND_status();
	printf("rand: %s\n", ret == 1 ? "ok" : "not available");
    }

    return 0;
}

int
random_data(void *opt, int argc, char **argv)
{
    void *ptr;
    ssize_t len;
    int ret;

    len = parse_bytes(argv[0], "byte");
    if (len <= 0) {
	fprintf(stderr, "bad argument to random-data\n");
	return 1;
    }

    ptr = malloc(len);
    if (ptr == NULL) {
	fprintf(stderr, "out of memory\n");
	return 1;
    }

    ret = RAND_bytes(ptr, len);
    if (ret != 1) {
	free(ptr);
	fprintf(stderr, "did not get cryptographic strong random\n");
	return 1;
    }

    fwrite(ptr, len, 1, stdout);
    fflush(stdout);

    free(ptr);

    return 0;
}

int
crypto_available(struct crypto_available_options *opt, int argc, char **argv)
{
    AlgorithmIdentifier *val;
    unsigned int len, i;
    int ret, type = HX509_SELECT_ALL;

    if (opt->type_string) {
	if (strcmp(opt->type_string, "all") == 0)
	    type = HX509_SELECT_ALL;
	else if (strcmp(opt->type_string, "digest") == 0)
	    type = HX509_SELECT_DIGEST;
	else if (strcmp(opt->type_string, "public-sig") == 0)
	    type = HX509_SELECT_PUBLIC_SIG;
	else if (strcmp(opt->type_string, "secret") == 0)
	    type = HX509_SELECT_SECRET_ENC;
	else
	    errx(1, "unknown type: %s", opt->type_string);
    }

    ret = hx509_crypto_available(context, type, NULL, &val, &len);
    if (ret)
	errx(1, "hx509_crypto_available");

    for (i = 0; i < len; i++) {
	char *s;
        if (opt->oid_syms_flag)
            der_print_heim_oid_sym(&val[i].algorithm, '.', &s);
        else
            der_print_heim_oid(&val[i].algorithm, '.', &s);
	printf("%s\n", s);
	free(s);
    }

    hx509_crypto_free_algs(val, len);

    return 0;
}

int
crypto_select(struct crypto_select_options *opt, int argc, char **argv)
{
    hx509_peer_info peer = NULL;
    AlgorithmIdentifier selected;
    int ret, type = HX509_SELECT_DIGEST;
    char *s;

    if (opt->type_string) {
	if (strcmp(opt->type_string, "digest") == 0)
	    type = HX509_SELECT_DIGEST;
	else if (strcmp(opt->type_string, "public-sig") == 0)
	    type = HX509_SELECT_PUBLIC_SIG;
	else if (strcmp(opt->type_string, "secret") == 0)
	    type = HX509_SELECT_SECRET_ENC;
	else
	    errx(1, "unknown type: %s", opt->type_string);
    }

    if (opt->peer_cmstype_strings.num_strings)
	peer_strings(context, &peer, &opt->peer_cmstype_strings);

    ret = hx509_crypto_select(context, type, NULL, peer, &selected);
    if (ret)
	errx(1, "hx509_crypto_available");

    if (opt->oid_sym_flag)
        der_print_heim_oid_sym(&selected.algorithm, '.', &s);
    else
        der_print_heim_oid(&selected.algorithm, '.', &s);
    printf("%s\n", s);
    free(s);
    free_AlgorithmIdentifier(&selected);

    hx509_peer_info_free(peer);

    return 0;
}

int
hxtool_hex(struct hex_options *opt, int argc, char **argv)
{

    if (opt->decode_flag) {
	char buf[1024], buf2[1024], *p;
	ssize_t len;

	while(fgets(buf, sizeof(buf), stdin) != NULL) {
	    buf[strcspn(buf, "\r\n")] = '\0';
	    p = buf;
	    while(isspace(*(unsigned char *)p))
		p++;
	    len = hex_decode(p, buf2, strlen(p));
	    if (len < 0)
		errx(1, "hex_decode failed");
	    if (fwrite(buf2, 1, len, stdout) != (size_t)len)
		errx(1, "fwrite failed");
	}
    } else {
        char buf[28], *p;
	ssize_t len;

	while((len = fread(buf, 1, sizeof(buf), stdin)) != 0) {
	    len = hex_encode(buf, len, &p);
	    if (len < 0)
	        continue;
	    fprintf(stdout, "%s\n", p);
	    free(p);
	}
    }
    return 0;
}

struct cert_type_opt {
    int pkinit;
};


static int
https_server(hx509_context contextp, hx509_ca_tbs tbs, struct cert_type_opt *opt)
{
    return hx509_ca_tbs_add_eku(contextp, tbs, &asn1_oid_id_pkix_kp_serverAuth);
}

static int
https_negotiate_server(hx509_context contextp, hx509_ca_tbs tbs, struct cert_type_opt *opt)
{
    int ret = hx509_ca_tbs_add_eku(contextp, tbs, &asn1_oid_id_pkekuoid);
    if (ret == 0)
        ret = hx509_ca_tbs_add_eku(contextp, tbs, &asn1_oid_id_pkix_kp_serverAuth);
    opt->pkinit++;
    return ret;
}

static int
https_client(hx509_context contextp, hx509_ca_tbs tbs, struct cert_type_opt *opt)
{
    return hx509_ca_tbs_add_eku(contextp, tbs, &asn1_oid_id_pkix_kp_clientAuth);
}

static int
peap_server(hx509_context contextp, hx509_ca_tbs tbs, struct cert_type_opt *opt)
{
    return hx509_ca_tbs_add_eku(contextp, tbs, &asn1_oid_id_pkix_kp_serverAuth);
}

static int
pkinit_kdc(hx509_context contextp, hx509_ca_tbs tbs, struct cert_type_opt *opt)
{
    opt->pkinit++;
    return hx509_ca_tbs_add_eku(contextp, tbs, &asn1_oid_id_pkkdcekuoid);
}

static int
pkinit_client(hx509_context contextp, hx509_ca_tbs tbs, struct cert_type_opt *opt)
{
    int ret;

    opt->pkinit++;

    ret = hx509_ca_tbs_add_eku(contextp, tbs, &asn1_oid_id_pkekuoid);
    if (ret)
	return ret;

    ret = hx509_ca_tbs_add_eku(context, tbs, &asn1_oid_id_pkix_kp_clientAuth);
    if (ret)
	return ret;

    return hx509_ca_tbs_add_eku(context, tbs, &asn1_oid_id_pkinit_ms_eku);
}

static int
email_client(hx509_context contextp, hx509_ca_tbs tbs, struct cert_type_opt *opt)
{
    return hx509_ca_tbs_add_eku(contextp, tbs, &asn1_oid_id_pkix_kp_emailProtection);
}

struct {
    const char *type;
    const char *desc;
    int (*eval)(hx509_context, hx509_ca_tbs, struct cert_type_opt *);
} certtypes[] = {
    {
	"https-server",
	"Used for HTTPS server and many other TLS server certificate types",
	https_server
    },
    {
	"https-client",
	"Used for HTTPS client certificates",
	https_client
    },
    {
	"email-client",
	"Certificate will be use for email",
	email_client
    },
    {
	"pkinit-client",
	"Certificate used for Kerberos PK-INIT client certificates",
	pkinit_client
    },
    {
	"pkinit-kdc",
	"Certificates used for Kerberos PK-INIT KDC certificates",
	pkinit_kdc
    },
    {
	"https-negotiate-server",
	"Used for HTTPS server and many other TLS server certificate types",
	https_negotiate_server
    },
    {
	"peap-server",
	"Certificate used for Radius PEAP (Protected EAP)",
	peap_server
    }
};

static void
print_eval_types(FILE *out)
{
    rtbl_t table;
    unsigned i;

    table = rtbl_create();
    rtbl_add_column_by_id (table, 0, "Name", 0);
    rtbl_add_column_by_id (table, 1, "Description", 0);

    for (i = 0; i < sizeof(certtypes)/sizeof(certtypes[0]); i++) {
	rtbl_add_column_entry_by_id(table, 0, certtypes[i].type);
	rtbl_add_column_entry_by_id(table, 1, certtypes[i].desc);
    }

    rtbl_format (table, out);
    rtbl_destroy (table);
}

static int
eval_types(hx509_context contextp,
	   hx509_ca_tbs tbs,
	   const struct certificate_sign_options *opt)
{
    struct cert_type_opt ctopt;
    int i;
    size_t j;
    int ret;

    memset(&ctopt, 0, sizeof(ctopt));

    for (i = 0; i < opt->type_strings.num_strings; i++) {
	const char *type = opt->type_strings.strings[i];

	for (j = 0; j < sizeof(certtypes)/sizeof(certtypes[0]); j++) {
	    if (strcasecmp(type, certtypes[j].type) == 0) {
		ret = (*certtypes[j].eval)(contextp, tbs, &ctopt);
		if (ret)
		    hx509_err(contextp, 1, ret,
			      "Failed to evaluate cert type %s", type);
		break;
	    }
	}
	if (j >= sizeof(certtypes)/sizeof(certtypes[0])) {
	    fprintf(stderr, "Unknown certificate type %s\n\n", type);
	    fprintf(stderr, "Available types:\n");
	    print_eval_types(stderr);
	    exit(1);
	}
    }

    for (i = 0; i < opt->pk_init_principal_strings.num_strings; i++) {
	const char *pk_init_princ = opt->pk_init_principal_strings.strings[i];

	if (!ctopt.pkinit)
	    errx(1, "pk-init principal given but no pk-init oid");

	ret = hx509_ca_tbs_add_san_pkinit(contextp, tbs, pk_init_princ);
	if (ret)
	    hx509_err(contextp, 1, ret, "hx509_ca_tbs_add_san_pkinit");
    }

    if (opt->ms_upn_string) {
	if (!ctopt.pkinit)
	    errx(1, "MS upn given but no pk-init oid");

	ret = hx509_ca_tbs_add_san_ms_upn(contextp, tbs, opt->ms_upn_string);
	if (ret)
	    hx509_err(contextp, 1, ret, "hx509_ca_tbs_add_san_ms_upn");
    }


    for (i = 0; i < opt->hostname_strings.num_strings; i++) {
	const char *hostname = opt->hostname_strings.strings[i];

	ret = hx509_ca_tbs_add_san_hostname(contextp, tbs, hostname);
	if (ret)
	    hx509_err(contextp, 1, ret, "hx509_ca_tbs_add_san_hostname");
    }

    for (i = 0; i < opt->dnssrv_strings.num_strings; i++) {
	const char *dnssrv = opt->dnssrv_strings.strings[i];

	ret = hx509_ca_tbs_add_san_dnssrv(contextp, tbs, dnssrv);
	if (ret)
	    hx509_err(contextp, 1, ret, "hx509_ca_tbs_add_san_dnssrv");
    }

    for (i = 0; i < opt->email_strings.num_strings; i++) {
	const char *email = opt->email_strings.strings[i];

	ret = hx509_ca_tbs_add_san_rfc822name(contextp, tbs, email);
	if (ret)
	    hx509_err(contextp, 1, ret, "hx509_ca_tbs_add_san_hostname");

	ret = hx509_ca_tbs_add_eku(contextp, tbs,
				   &asn1_oid_id_pkix_kp_emailProtection);
	if (ret)
	    hx509_err(contextp, 1, ret, "hx509_ca_tbs_add_eku");
    }

    if (opt->jid_string) {
	ret = hx509_ca_tbs_add_san_jid(contextp, tbs, opt->jid_string);
	if (ret)
	    hx509_err(contextp, 1, ret, "hx509_ca_tbs_add_san_jid");
    }

    return 0;
}

int
hxtool_ca(struct certificate_sign_options *opt, int argc, char **argv)
{
    int ret;
    hx509_ca_tbs tbs;
    hx509_cert signer = NULL, cert = NULL;
    hx509_private_key private_key = NULL;
    hx509_private_key cert_key = NULL;
    hx509_name subject = NULL;
    SubjectPublicKeyInfo spki;
    heim_oid oid;
    size_t i;
    int delta = 0;

    memset(&oid, 0, sizeof(oid));
    memset(&spki, 0, sizeof(spki));

    if (opt->ca_certificate_string == NULL && !opt->self_signed_flag)
	errx(1, "--ca-certificate argument missing (not using --self-signed)");
    if (opt->ca_private_key_string == NULL && opt->generate_key_string == NULL && opt->self_signed_flag)
	errx(1, "--ca-private-key argument missing (using --self-signed)");
    if (opt->certificate_string == NULL)
	errx(1, "--certificate argument missing");

    if (opt->template_certificate_string && opt->template_fields_string == NULL)
        errx(1, "--template-certificate used but no --template-fields given");

    if (opt->lifetime_string) {
	delta = parse_time(opt->lifetime_string, "day");
	if (delta < 0)
	    errx(1, "Invalid lifetime: %s", opt->lifetime_string);
    }

    if (opt->ca_certificate_string) {
	hx509_certs cacerts = NULL;
	hx509_query *q;
        char *sn = fix_store_name(context, opt->ca_certificate_string, "FILE");

        ret = hx509_certs_init(context, sn, 0, NULL, &cacerts);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_init: %s", sn);

	ret = hx509_query_alloc(context, &q);
	if (ret)
	    errx(1, "hx509_query_alloc: %d", ret);

	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
	if (!opt->issue_proxy_flag)
	    hx509_query_match_option(q, HX509_QUERY_OPTION_KU_KEYCERTSIGN);

	ret = hx509_certs_find(context, cacerts, q, &signer);
	hx509_query_free(context, q);
	hx509_certs_free(&cacerts);
	if (ret)
	    hx509_err(context, 1, ret, "no CA certificate found");
        free(sn);
    } else if (opt->self_signed_flag) {
	if (opt->generate_key_string == NULL
	    && opt->ca_private_key_string == NULL)
	    errx(1, "no signing private key");

	if (opt->req_string)
	    errx(1, "can't be self-signing and have a request at the same time");
    } else
	errx(1, "missing ca key");

    if (opt->ca_private_key_string) {

	ret = read_private_key(opt->ca_private_key_string, &private_key);
	if (ret)
	    err(1, "read_private_key");

	ret = hx509_private_key2SPKI(context, private_key, &spki);
	if (ret)
	    errx(1, "hx509_private_key2SPKI: %d\n", ret);

	if (opt->self_signed_flag)
	    cert_key = private_key;
    }

    if (opt->req_string) {
	hx509_request req;
        char *cn = fix_csr_name(opt->req_string, "PKCS10");

        /*
         * Extract the CN and other attributes we want to preserve from the
         * requested subjectName and then set them in the hx509_env for the
         * template.
         */
	ret = hx509_request_parse(context, cn, &req);
	if (ret)
	    hx509_err(context, 1, ret, "parse_request: %s", cn);
	ret = hx509_request_get_name(context, req, &subject);
	if (ret)
	    hx509_err(context, 1, ret, "get name");
	ret = hx509_request_get_SubjectPublicKeyInfo(context, req, &spki);
	if (ret)
	    hx509_err(context, 1, ret, "get spki");
	hx509_request_free(&req);
        free(cn);
    }

    if (opt->generate_key_string) {
        /*
         * Note that we used to set isCA in the key gen context.  Now that we
         * use get_key() we no longer set isCA in the key gen context.  But
         * nothing uses that field of the key gen context.
         */
        get_key(opt->certificate_private_key_string,
                opt->generate_key_string,
                opt->key_bits_integer,
                &cert_key);

	ret = hx509_private_key2SPKI(context, cert_key, &spki);
	if (ret)
	    errx(1, "hx509_private_key2SPKI: %d\n", ret);

        if (opt->self_signed_flag)
            private_key = cert_key;
    } else if (opt->certificate_private_key_string) {
	ret = read_private_key(opt->certificate_private_key_string, &cert_key);
	if (ret)
	    err(1, "read_private_key for certificate");

	ret = hx509_private_key2SPKI(context, cert_key, &spki);
	if (ret)
	    errx(1, "hx509_private_key2SPKI: %d\n", ret);

        if (opt->self_signed_flag)
            private_key = cert_key;
    }

    if (opt->subject_string) {
	if (subject)
	    hx509_name_free(&subject);
	ret = hx509_parse_name(context, opt->subject_string, &subject);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_parse_name");
    }

    /*
     *
     */

    ret = hx509_ca_tbs_init(context, &tbs);
    if (ret)
	hx509_err(context, 1, ret, "hx509_ca_tbs_init");

    for (i = 0; i < opt->eku_strings.num_strings; i++) {
	parse_oid(opt->eku_strings.strings[i], NULL, &oid);
	ret = hx509_ca_tbs_add_eku(context, tbs, &oid);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_request_add_eku");
        der_free_oid(&oid);
    }
    if (opt->ku_strings.num_strings) {
        const struct units *kus = asn1_KeyUsage_units();
        const struct units *kup;
        uint64_t n = 0;

        for (i = 0; i < opt->ku_strings.num_strings; i++) {
            for (kup = kus; kup->name; kup++) {
                if (strcmp(kup->name, opt->ku_strings.strings[i]))
                    continue;
                n |= kup->mult;
                break;
            }
        }
        ret = hx509_ca_tbs_add_ku(context, tbs, int2KeyUsage(n));
        if (ret)
            hx509_err(context, 1, ret, "hx509_request_add_ku");
    }
    if (opt->signature_algorithm_string) {
	const AlgorithmIdentifier *sigalg;
	if (strcasecmp(opt->signature_algorithm_string, "rsa-with-sha1") == 0)
	    sigalg = hx509_signature_rsa_with_sha1();
	else if (strcasecmp(opt->signature_algorithm_string, "rsa-with-sha256") == 0)
	    sigalg = hx509_signature_rsa_with_sha256();
	else
	    errx(1, "unsupported sigature algorithm");
	hx509_ca_tbs_set_signature_algorithm(context, tbs, sigalg);
    }

    if (opt->template_certificate_string) {
	hx509_cert template;
	hx509_certs tcerts;
        char *sn = fix_store_name(context, opt->template_certificate_string,
                                  "FILE");
	int flags;

	ret = hx509_certs_init(context, sn, 0, NULL, &tcerts);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_init: %s", sn);

	ret = hx509_get_one_cert(context, tcerts, &template);

	hx509_certs_free(&tcerts);
	if (ret)
	    hx509_err(context, 1, ret, "no template certificate found");

	flags = parse_units(opt->template_fields_string,
			    hx509_ca_tbs_template_units(), "");

	ret = hx509_ca_tbs_set_template(context, tbs, flags, template);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_set_template");

	hx509_cert_free(template);
        free(sn);
    }

    if (opt->serial_number_string) {
	heim_integer serialNumber;

	ret = der_parse_hex_heim_integer(opt->serial_number_string,
					 &serialNumber);
	if (ret)
	    err(1, "der_parse_hex_heim_integer");
	ret = hx509_ca_tbs_set_serialnumber(context, tbs, &serialNumber);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_init");
	der_free_heim_integer(&serialNumber);
    }

    if (spki.subjectPublicKey.length) {
	ret = hx509_ca_tbs_set_spki(context, tbs, &spki);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_set_spki");
    }

    if (subject) {
	ret = hx509_ca_tbs_set_subject(context, tbs, subject);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_set_subject");
    }

    if (opt->crl_uri_string) {
	ret = hx509_ca_tbs_add_crl_dp_uri(context, tbs,
					  opt->crl_uri_string, NULL);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_add_crl_dp_uri");
    }

    eval_types(context, tbs, opt);

    if (opt->permanent_id_string) {
        ret = hx509_ca_tbs_add_san_permanentIdentifier_string(context, tbs,
                                                              opt->permanent_id_string);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_add_san_permanentIdentifier");
    }

    if (opt->hardware_module_name_string) {
        ret = hx509_ca_tbs_add_san_hardwareModuleName_string(context, tbs,
                                                             opt->hardware_module_name_string);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_add_san_hardwareModuleName_string");
    }

    for (i = 0; ret == 0 && i < opt->policy_strings.num_strings; i++) {
        char *oidstr, *uri, *dt;

        if ((oidstr = strdup(opt->policy_strings.strings[i])) == NULL)
            hx509_err(context, 1, ENOMEM, "out of memory");
        uri = strchr(oidstr, ':');
        if (uri)
            *(uri++) = '\0';
        dt = strchr(uri ? uri : "", ' ');
        if (dt)
            *(dt++) = '\0';

	parse_oid(oidstr, NULL, &oid);
        ret = hx509_ca_tbs_add_pol(context, tbs, &oid, uri, dt);
        der_free_oid(&oid);
        free(oidstr);
    }

    for (i = 0; ret == 0 && i < opt->policy_mapping_strings.num_strings; i++) {
        char *issuer_oidstr, *subject_oidstr;
        heim_oid issuer_oid, subject_oid;

        if ((issuer_oidstr =
             strdup(opt->policy_mapping_strings.strings[i])) == NULL)
            hx509_err(context, 1, ENOMEM, "out of memory");
        subject_oidstr = strchr(issuer_oidstr, ':');
        if (subject_oidstr == NULL)
            subject_oidstr = issuer_oidstr;
        else
            *(subject_oidstr++) = '\0';

	parse_oid(issuer_oidstr, NULL, &issuer_oid);
	parse_oid(subject_oidstr, NULL, &subject_oid);
        ret = hx509_ca_tbs_add_pol_mapping(context, tbs, &issuer_oid,
                                           &subject_oid);
        if (ret)
            hx509_err(context, 1, ret, "failed to add policy mapping");
        der_free_oid(&issuer_oid);
        der_free_oid(&subject_oid);
        free(issuer_oidstr);
    }

    if (opt->issue_ca_flag) {
	ret = hx509_ca_tbs_set_ca(context, tbs, opt->path_length_integer);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_set_ca");
    }
    if (opt->issue_proxy_flag) {
	ret = hx509_ca_tbs_set_proxy(context, tbs, opt->path_length_integer);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_set_proxy");
    }
    if (opt->domain_controller_flag) {
	hx509_ca_tbs_set_domaincontroller(context, tbs);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_set_domaincontroller");
    }

    if (delta) {
	ret = hx509_ca_tbs_set_notAfter_lifetime(context, tbs, delta);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_set_notAfter_lifetime");
    }
    if (opt->pkinit_max_life_string) {
        time_t t = parse_time(opt->pkinit_max_life_string, "s");

        ret = hx509_ca_tbs_set_pkinit_max_life(context, tbs, t);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_tbs_set_pkinit_max_life");
    }

    if (opt->self_signed_flag) {
	ret = hx509_ca_sign_self(context, tbs, private_key, &cert);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_sign_self");
    } else {
	ret = hx509_ca_sign(context, tbs, signer, &cert);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_ca_sign");
    }

    /* Copy the private key to the output store, maybe */
    if (cert_key && opt->generate_key_string &&
        !opt->certificate_private_key_string) {
        /*
         * Yes: because we're generating the key and --certificate-private-key
         * was not given.
         */
	ret = _hx509_cert_assign_key(cert, cert_key);
	if (ret)
	    hx509_err(context, 1, ret, "_hx509_cert_assign_key");
    } else if (opt->certificate_private_key_string && opt->certificate_string &&
               strcmp(opt->certificate_private_key_string,
                      opt->certificate_string) == 0) {
        /*
         * Yes: because we're re-writing the store whence the private key.  We
         * would lose the key otherwise.
         */
	ret = _hx509_cert_assign_key(cert, cert_key);
	if (ret)
	    hx509_err(context, 1, ret, "_hx509_cert_assign_key");
    } else if (opt->self_signed_flag && opt->ca_private_key_string &&
               opt->certificate_string &&
               strcmp(opt->ca_private_key_string,
                      opt->certificate_string) == 0) {
        /* Yes: same as preceding */
	ret = _hx509_cert_assign_key(cert, cert_key);
	if (ret)
	    hx509_err(context, 1, ret, "_hx509_cert_assign_key");
    }

    {
	hx509_certs certs;
        char *sn = fix_store_name(context, opt->certificate_string, "FILE");

        ret = hx509_certs_init(context, sn, HX509_CERTS_CREATE, NULL, &certs);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_init");

	ret = hx509_certs_add(context, certs, cert);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_add");

	ret = hx509_certs_store(context, certs, 0, NULL);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_store");

	hx509_certs_free(&certs);
        free(sn);
    }

    if (subject)
	hx509_name_free(&subject);
    if (signer)
	hx509_cert_free(signer);
    hx509_cert_free(cert);
    free_SubjectPublicKeyInfo(&spki);

    if (private_key != cert_key)
	hx509_private_key_free(&private_key);
    hx509_private_key_free(&cert_key);

    hx509_ca_tbs_free(&tbs);

    return 0;
}

static int HX509_LIB_CALL
test_one_cert(hx509_context hxcontext, void *ctx, hx509_cert cert)
{
    heim_octet_string sd, c;
    hx509_verify_ctx vctx = ctx;
    hx509_certs signer = NULL;
    heim_oid type;
    int ret;

    if (_hx509_cert_private_key(cert) == NULL)
	return 0;

    ret = hx509_cms_create_signed_1(context, 0, NULL, NULL, 0,
				    NULL, cert, NULL, NULL, NULL, &sd);
    if (ret)
	errx(1, "hx509_cms_create_signed_1");

    ret = hx509_cms_verify_signed(context, vctx, 0, sd.data, sd.length,
				  NULL, NULL, &type, &c, &signer);
    free(sd.data);
    if (ret)
	hx509_err(context, 1, ret, "hx509_cms_verify_signed");

    printf("create-signature verify-sigature done\n");

    free(c.data);

    return 0;
}

int
test_crypto(struct test_crypto_options *opt, int argc, char ** argv)
{
    hx509_verify_ctx vctx;
    hx509_certs certs;
    hx509_lock lock;
    int i, ret;

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    ret = hx509_certs_init(context, "MEMORY:test-crypto", 0, NULL, &certs);
    if (ret) hx509_err(context, 1, ret, "hx509_certs_init: MEMORY");

    for (i = 0; i < argc; i++) {
        char *sn = fix_store_name(context, argv[i], "FILE");
	ret = hx509_certs_append(context, certs, lock, sn);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_append %s", sn);
        free(sn);
    }

    ret = hx509_verify_init_ctx(context, &vctx);
    if (ret)
	hx509_err(context, 1, ret, "hx509_verify_init_ctx");

    hx509_verify_attach_anchors(vctx, certs);

    ret = hx509_certs_iter_f(context, certs, test_one_cert, vctx);
    if (ret)
	hx509_err(context, 1, ret, "hx509_cert_iter");

    hx509_certs_free(&certs);
    hx509_verify_destroy_ctx(vctx);

    return 0;
}

int
statistic_print(struct statistic_print_options*opt, int argc, char **argv)
{
    int type = 0;

    if (stat_file_string == NULL)
	errx(1, "no stat file");

    if (opt->type_integer)
	type = opt->type_integer;

    hx509_query_unparse_stats(context, type, stdout);
    return 0;
}

/*
 *
 */

int
crl_sign(struct crl_sign_options *opt, int argc, char **argv)
{
    hx509_crl crl;
    heim_octet_string os;
    hx509_cert signer = NULL;
    hx509_lock lock;
    int ret;

    hx509_lock_init(context, &lock);
    lock_strings(lock, &opt->pass_strings);

    ret = hx509_crl_alloc(context, &crl);
    if (ret)
	errx(1, "crl alloc");

    if (opt->signer_string == NULL)
	errx(1, "signer missing");

    {
	hx509_certs certs = NULL;
	hx509_query *q;
        char *sn = fix_store_name(context, opt->signer_string, "FILE");

        ret = hx509_certs_init(context, sn, 0, NULL, &certs);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_certs_init: %s", sn);

	ret = hx509_query_alloc(context, &q);
	if (ret)
	    hx509_err(context, 1, ret, "hx509_query_alloc: %d", ret);

	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);

	ret = hx509_certs_find(context, certs, q, &signer);
	hx509_query_free(context, q);
	hx509_certs_free(&certs);
	if (ret)
	    hx509_err(context, 1, ret, "no signer certificate found");
        free(sn);
    }

    if (opt->lifetime_string) {
	int delta;

	delta = parse_time(opt->lifetime_string, "day");
	if (delta < 0)
	    errx(1, "Invalid lifetime: %s", opt->lifetime_string);

	hx509_crl_lifetime(context, crl, delta);
    }

    {
	hx509_certs revoked = NULL;
	int i;

	ret = hx509_certs_init(context, "MEMORY:revoked-certs", 0,
			       NULL, &revoked);
	if (ret)
	    hx509_err(context, 1, ret,
		      "hx509_certs_init: MEMORY cert");

	for (i = 0; i < argc; i++) {
            char *sn = fix_store_name(context, argv[i], "FILE");

	    ret = hx509_certs_append(context, revoked, lock, sn);
	    if (ret)
		hx509_err(context, 1, ret, "hx509_certs_append: %s", sn);
            free(sn);
	}

	hx509_crl_add_revoked_certs(context, crl, revoked);
	hx509_certs_free(&revoked);
    }

    hx509_crl_sign(context, signer, crl, &os);

    if (opt->crl_file_string)
	rk_dumpdata(opt->crl_file_string, os.data, os.length);

    free(os.data);

    hx509_crl_free(context, &crl);
    hx509_cert_free(signer);
    hx509_lock_free(lock);

    return 0;
}

int
hxtool_list_oids(void *opt, int argc, char **argv)
{
    const heim_oid *oid;
    int cursor = -1;

    while (der_match_heim_oid_by_name("", &cursor, &oid) == 0) {
        char *s = NULL;

        if ((errno = der_print_heim_oid_sym(oid, '.', &s)) > 0)
            err(1, "der_print_heim_oid_sym");
        printf("%s\n", s);
        free(s);
    }
    return 0;
}

static int
acert1_sans_utf8_other(struct acert_options *opt,
                       struct getarg_strings *wanted,
                       const char *type,
                       heim_any *san,
                       size_t *count)
{
    size_t k, len;

    if (!wanted->num_strings)
        return 0;
    for (k = 0; k < wanted->num_strings; k++) {
        len = strlen(wanted->strings[k]);
        if (len == san->length &&
            strncmp(san->data, wanted->strings[k], len) == 0) {
            if (opt->verbose_flag)
                fprintf(stderr, "Matched OtherName SAN %s (%s)\n",
                        wanted->strings[k], type);
            (*count)++;
            return 0;
        }
    }
    if (opt->verbose_flag)
        fprintf(stderr, "Did not match OtherName SAN %s (%s)\n",
                wanted->strings[k], type);
    return -1;
}

static int
acert1_sans_other(struct acert_options *opt,
                  heim_oid *type_id,
                  heim_any *value,
                  size_t *count)
{
    heim_any pkinit;
    size_t k, match;
    const char *type_str = NULL;
    char *s = NULL;
    int ret;

    (void) der_print_heim_oid_sym(type_id, '.', &s);
    type_str = s ? s : "<unknown>";
    if (der_heim_oid_cmp(type_id, &asn1_oid_id_pkix_on_xmppAddr) == 0) {
        ret = acert1_sans_utf8_other(opt, &opt->has_xmpp_san_strings,
                                     s ? s : "xmpp", value, count);
        free(s);
        return ret;
    }
    if (der_heim_oid_cmp(type_id, &asn1_oid_id_pkinit_san) != 0) {
        if (opt->verbose_flag)
            fprintf(stderr, "Ignoring OtherName SAN of type %s\n", type_str);
        free(s);
        return -1;
    }

    free(s);
    type_str = s = NULL;

    if (opt->has_pkinit_san_strings.num_strings == 0)
        return 0;

    for (k = 0; k < opt->has_pkinit_san_strings.num_strings; k++) {
        const char *s2 = opt->has_pkinit_san_strings.strings[k];

        if ((ret = _hx509_make_pkinit_san(context, s2, &pkinit)))
            return ret;
        match = (pkinit.length == value->length &&
            memcmp(pkinit.data, value->data, pkinit.length) == 0);
        free(pkinit.data);
        if (match) {
            if (opt->verbose_flag)
                fprintf(stderr, "Matched PKINIT SAN %s\n", s2);
            (*count)++;
            return 0;
        }
    }
    if (opt->verbose_flag)
        fprintf(stderr, "Unexpected PKINIT SAN\n");
    return -1;
}

static int
acert1_sans(struct acert_options *opt,
            Extension *e,
            size_t *count,
            size_t *found)
{
    heim_printable_string hps;
    GeneralNames gns;
    size_t i, k, sz;
    size_t unwanted = 0;
    int ret = 0;

    memset(&gns, 0, sizeof(gns));
    decode_GeneralNames(e->extnValue.data, e->extnValue.length, &gns, &sz);
    for (i = 0; (ret == -1 || ret == 0) && i < gns.len; i++) {
        GeneralName *gn = &gns.val[i];
        const char *s;

        (*found)++;
        if (gn->element == choice_GeneralName_rfc822Name) {
            for (k = 0; k < opt->has_email_san_strings.num_strings; k++) {
                s = opt->has_email_san_strings.strings[k];
                hps.data = rk_UNCONST(s);
                hps.length = strlen(s);
                if (der_printable_string_cmp(&gn->u.rfc822Name, &hps) == 0) {
                    if (opt->verbose_flag)
                        fprintf(stderr, "Matched e-mail address SAN %s\n", s);
                    (*count)++;
                    break;
                }
            }
            if (k && k == opt->has_email_san_strings.num_strings) {
                if (opt->verbose_flag)
                    fprintf(stderr, "Unexpected e-mail address SAN %.*s\n",
                            (int)gn->u.rfc822Name.length,
                            (const char *)gn->u.rfc822Name.data);
                unwanted++;
            }
        } else if (gn->element == choice_GeneralName_dNSName) {
            for (k = 0; k < opt->has_dnsname_san_strings.num_strings; k++) {
                s = opt->has_dnsname_san_strings.strings[k];
                hps.data = rk_UNCONST(s);
                hps.length = strlen(s);
                if (der_printable_string_cmp(&gn->u.dNSName, &hps) == 0) {
                    if (opt->verbose_flag)
                        fprintf(stderr, "Matched dNSName SAN %s\n", s);
                    (*count)++;
                    break;
                }
            }
            if (k && k == opt->has_dnsname_san_strings.num_strings) {
                if (opt->verbose_flag)
                    fprintf(stderr, "Unexpected e-mail address SAN %.*s\n",
                            (int)gn->u.dNSName.length,
                            (const char *)gn->u.dNSName.data);
                unwanted++;
            }
        } else if (gn->element == choice_GeneralName_registeredID) {
            for (k = 0; k < opt->has_registeredID_san_strings.num_strings; k++) {
                heim_oid oid;

                s = opt->has_registeredID_san_strings.strings[k];
                memset(&oid, 0, sizeof(oid));
                parse_oid(s, NULL, &oid);
                if (der_heim_oid_cmp(&gn->u.registeredID, &oid) == 0) {
                    der_free_oid(&oid);
                    if (opt->verbose_flag)
                        fprintf(stderr, "Matched registeredID SAN %s\n", s);
                    (*count)++;
                    break;
                }
                der_free_oid(&oid);
            }
            if (k && k == opt->has_dnsname_san_strings.num_strings) {
                if (opt->verbose_flag)
                    fprintf(stderr, "Unexpected registeredID SAN\n");
                unwanted++;
            }
        } else if (gn->element == choice_GeneralName_otherName) {
            ret = acert1_sans_other(opt, &gn->u.otherName.type_id,
                                    &gn->u.otherName.value, count);
        } else if (opt->verbose_flag) {
            fprintf(stderr, "Unexpected unsupported SAN\n");
            unwanted++;
        }
    }
    free_GeneralNames(&gns);
    if (ret == 0 && unwanted && opt->exact_flag)
        return -1;
    return ret;
}

static int
acert1_ekus(struct acert_options *opt,
            Extension *e,
            size_t *count,
            size_t *found)
{
    ExtKeyUsage eku;
    size_t i, k, sz;
    size_t unwanted = 0;
    int ret = 0;

    memset(&eku, 0, sizeof(eku));
    decode_ExtKeyUsage(e->extnValue.data, e->extnValue.length, &eku, &sz);
    for (i = 0; (ret == -1 || ret == 0) && i < eku.len; i++) {
        (*found)++;
        for (k = 0; k < opt->has_eku_strings.num_strings; k++) {
            const char *s = opt->has_eku_strings.strings[k];
            heim_oid oid;

            memset(&oid, 0, sizeof(oid));
            parse_oid(s, NULL, &oid);
            if (der_heim_oid_cmp(&eku.val[i], &oid) == 0) {
                der_free_oid(&oid);
                if (opt->verbose_flag)
                    fprintf(stderr, "Matched EKU OID %s\n", s);
                (*count)++;
                break;
            }
            der_free_oid(&oid);
        }
        if (k && k == opt->has_eku_strings.num_strings) {
            char *oids = NULL;

            (void) der_print_heim_oid_sym(&eku.val[i], '.', &oids);
            if (opt->verbose_flag)
                fprintf(stderr, "Unexpected EKU OID %s\n",
                        oids ? oids : "<could-not-format-OID>");
            unwanted++;
        }
    }
    free_ExtKeyUsage(&eku);
    if (ret == 0 && unwanted && opt->exact_flag)
        return -1;
    return ret;
}

static int
acert1_kus(struct acert_options *opt,
           Extension *e,
           size_t *count,
           size_t *found)
{
    const struct units *u = asn1_KeyUsage_units();
    uint64_t ku_num;
    KeyUsage ku;
    size_t unwanted = 0;
    size_t wanted = opt->has_ku_strings.num_strings;
    size_t i, k, sz;
    int ret;

    memset(&ku, 0, sizeof(ku));
    ret = decode_KeyUsage(e->extnValue.data, e->extnValue.length, &ku, &sz);
    if (ret)
        return ret;
    ku_num = KeyUsage2int(ku);

    /* Validate requested key usage values */
    for (k = 0; k < wanted; k++) {
        const char *s = opt->has_ku_strings.strings[k];

        for (i = 0; u[i].name; i++)
            if (strcmp(s, u[i].name) == 0)
                break;

        if (u[i].name == NULL)
            warnx("Warning: requested key usage %s unknown", s);
    }

    for (i = 0; u[i].name; i++) {
        if ((u[i].mult & ku_num))
            (*found)++;
        for (k = 0; k < wanted; k++) {
            const char *s = opt->has_ku_strings.strings[k];

            if (!(u[i].mult & ku_num) || strcmp(s, u[i].name) != 0)
                continue;

            if (opt->verbose_flag)
                fprintf(stderr, "Matched key usage %s\n", s);
            (*count)++;
            break;
        }
        if ((u[i].mult & ku_num) && k == wanted) {
            if (opt->verbose_flag)
                fprintf(stderr, "Unexpected key usage %s\n", u[i].name);
            unwanted++;
        }
    }

    return (unwanted && opt->exact_flag) ? -1 : 0;
}

static time_t
ptime(const char *s)
{
    struct tm at_tm;
    char *rest;
    int at_s;

    if ((rest = strptime(s, "%Y-%m-%dT%H:%M:%S", &at_tm)) != NULL &&
        rest[0] == '\0')
        return mktime(&at_tm);
    if ((rest = strptime(s, "%Y%m%d%H%M%S", &at_tm)) != NULL && rest[0] == '\0')
        return mktime(&at_tm);
    if ((at_s = parse_time(s, "s")) != -1)
        return time(NULL) + at_s;
    errx(1, "Could not parse time spec %s", s);
}

static int
acert1_validity(struct acert_options *opt, hx509_cert cert)
{
    time_t not_before_eq = 0;
    time_t not_before_lt = 0;
    time_t not_before_gt = 0;
    time_t not_after_eq = 0;
    time_t not_after_lt = 0;
    time_t not_after_gt = 0;
    int ret = 0;

    if (opt->valid_now_flag) {
        time_t now = time(NULL);

        if (hx509_cert_get_notBefore(cert) > now) {
            if (opt->verbose_flag)
                fprintf(stderr, "Certificate not valid yet\n");
            ret = -1;
        }
        if (hx509_cert_get_notAfter(cert) < now) {
            if (opt->verbose_flag)
                fprintf(stderr, "Certificate currently expired\n");
            ret = -1;
        }
    }
    if (opt->valid_at_string) {
        time_t at = ptime(opt->valid_at_string);

        if (hx509_cert_get_notBefore(cert) > at) {
            if (opt->verbose_flag)
                fprintf(stderr, "Certificate not valid yet at %s\n",
                        opt->valid_at_string);
            ret = -1;
        }
        if (hx509_cert_get_notAfter(cert) < at) {
            if (opt->verbose_flag)
                fprintf(stderr, "Certificate expired before %s\n",
                        opt->valid_at_string);
            ret = -1;
        }
    }

    if (opt->not_before_eq_string)
        not_before_eq = ptime(opt->not_before_eq_string);
    if (opt->not_before_lt_string)
        not_before_lt = ptime(opt->not_before_lt_string);
    if (opt->not_before_gt_string)
        not_before_gt = ptime(opt->not_before_gt_string);
    if (opt->not_after_eq_string)
        not_after_eq = ptime(opt->not_after_eq_string);
    if (opt->not_after_lt_string)
        not_after_lt = ptime(opt->not_after_lt_string);
    if (opt->not_after_gt_string)
        not_after_gt = ptime(opt->not_after_gt_string);

    if ((not_before_eq && hx509_cert_get_notBefore(cert) != not_before_eq) ||
        (not_before_lt && hx509_cert_get_notBefore(cert) >= not_before_lt) ||
        (not_before_gt && hx509_cert_get_notBefore(cert) <= not_before_gt)) {
        if (opt->verbose_flag)
            fprintf(stderr, "Certificate notBefore not as requested\n");
        ret = -1;
    }
    if ((not_after_eq && hx509_cert_get_notAfter(cert) != not_after_eq) ||
        (not_after_lt && hx509_cert_get_notAfter(cert) >= not_after_lt) ||
        (not_after_gt && hx509_cert_get_notAfter(cert) <= not_after_gt)) {
        if (opt->verbose_flag)
            fprintf(stderr, "Certificate notAfter not as requested\n");
        ret = -1;
    }

    if (opt->has_private_key_flag && !hx509_cert_have_private_key(cert)) {
        if (opt->verbose_flag)
            fprintf(stderr, "Certificate does not have a private key\n");
        ret = -1;
    }

    if (opt->lacks_private_key_flag && hx509_cert_have_private_key(cert)) {
        if (opt->verbose_flag)
            fprintf(stderr, "Certificate does not have a private key\n");
        ret = -1;
    }

    return ret;
}

static int
acert1(struct acert_options *opt, size_t cert_num, hx509_cert cert, int *matched)
{
    const heim_oid *misc_exts [] = {
        &asn1_oid_id_x509_ce_authorityKeyIdentifier,
        &asn1_oid_id_x509_ce_subjectKeyIdentifier,
        &asn1_oid_id_x509_ce_basicConstraints,
        &asn1_oid_id_x509_ce_nameConstraints,
        &asn1_oid_id_x509_ce_certificatePolicies,
        &asn1_oid_id_x509_ce_policyMappings,
        &asn1_oid_id_x509_ce_issuerAltName,
        &asn1_oid_id_x509_ce_subjectDirectoryAttributes,
        &asn1_oid_id_x509_ce_policyConstraints,
        &asn1_oid_id_x509_ce_cRLDistributionPoints,
        &asn1_oid_id_x509_ce_deltaCRLIndicator,
        &asn1_oid_id_x509_ce_issuingDistributionPoint,
        &asn1_oid_id_x509_ce_inhibitAnyPolicy,
        &asn1_oid_id_x509_ce_cRLNumber,
        &asn1_oid_id_x509_ce_freshestCRL,
        NULL
    };
    const Certificate *c;
    const Extensions *e;
    KeyUsage ku;
    size_t matched_elements = 0;
    size_t wanted, sans_wanted, ekus_wanted, kus_wanted;
    size_t found, sans_found, ekus_found, kus_found;
    size_t i, k;
    int ret;

    if ((c = _hx509_get_cert(cert)) == NULL)
        errx(1, "Could not get Certificate");
    e = c->tbsCertificate.extensions;

    ret = _hx509_cert_get_keyusage(context, cert, &ku);
    if (ret && ret != HX509_KU_CERT_MISSING)
        hx509_err(context, 1, ret, "Could not get key usage of certificate");
    if (ret == HX509_KU_CERT_MISSING && opt->ca_flag)
        return 0; /* want CA cert; this isn't it */
    if (ret == 0 && opt->ca_flag && !ku.keyCertSign)
        return 0; /* want CA cert; this isn't it */
    if (ret == 0 && opt->end_entity_flag && ku.keyCertSign)
        return 0; /* want EE cert; this isn't it */

    if (opt->cert_num_integer != -1 && cert_num <= INT_MAX &&
        opt->cert_num_integer != (int)cert_num)
        return 0;
    if (opt->cert_num_integer == -1 || opt->cert_num_integer == (int)cert_num)
        *matched = 1;

    if (_hx509_cert_get_version(c) < 3) {
        warnx("Certificate with version %d < 3 ignored",
              _hx509_cert_get_version(c));
        return 0;
    }

    sans_wanted = opt->has_email_san_strings.num_strings
        + opt->has_xmpp_san_strings.num_strings
        + opt->has_ms_upn_san_strings.num_strings
        + opt->has_dnsname_san_strings.num_strings
        + opt->has_pkinit_san_strings.num_strings
        + opt->has_registeredID_san_strings.num_strings;
    ekus_wanted = opt->has_eku_strings.num_strings;
    kus_wanted = opt->has_ku_strings.num_strings;
    wanted = sans_wanted + ekus_wanted + kus_wanted;
    sans_found = ekus_found = kus_found = 0;

    if (e == NULL) {
        if (wanted)
            return -1;
        return acert1_validity(opt, cert);
    }

    for (i = 0; i < e->len; i++) {
        if (der_heim_oid_cmp(&e->val[i].extnID,
                             &asn1_oid_id_x509_ce_subjectAltName) == 0) {
            ret = acert1_sans(opt, &e->val[i], &matched_elements, &sans_found);
            if (ret == -1 && sans_wanted == 0 &&
                (!opt->exact_flag || sans_found == 0))
                ret = 0;
        } else if (der_heim_oid_cmp(&e->val[i].extnID,
                                  &asn1_oid_id_x509_ce_extKeyUsage) == 0) {
            ret = acert1_ekus(opt, &e->val[i], &matched_elements, &ekus_found);
            if (ret == -1 && ekus_wanted == 0 &&
                (!opt->exact_flag || ekus_found == 0))
                ret = 0;
        } else if (der_heim_oid_cmp(&e->val[i].extnID,
                                  &asn1_oid_id_x509_ce_keyUsage) == 0) {
            ret = acert1_kus(opt, &e->val[i], &matched_elements, &kus_found);
            if (ret == -1 && kus_wanted == 0 &&
                (!opt->exact_flag || kus_found == 0))
                ret = 0;
        } else {
            char *oids = NULL;

            for (k = 0; misc_exts[k]; k++) {
                if (der_heim_oid_cmp(&e->val[i].extnID, misc_exts[k]) == 0)
                    break;
            }
            if (misc_exts[k])
                continue;

            (void) der_print_heim_oid(&e->val[i].extnID, '.', &oids);
            warnx("Matching certificate has unexpected certificate "
                  "extension %s", oids ? oids : "<could not display OID>");
            free(oids);
            ret = -1;
        }
        if (ret && ret != -1)
            hx509_err(context, 1, ret, "Error checking matching certificate");
        if (ret == -1)
            break;
    }
    if (matched_elements != wanted)
        return -1;
    found = sans_found + ekus_found + kus_found;
    if (matched_elements != found && opt->exact_flag)
        return -1;
    if (ret)
        return ret;
    return acert1_validity(opt, cert);
}

int
acert(struct acert_options *opt, int argc, char **argv)
{
    hx509_cursor cursor = NULL;
    hx509_query *q = NULL;
    hx509_certs certs = NULL;
    hx509_cert cert = NULL;
    char *sn = fix_store_name(context, argv[0], "FILE");
    size_t n = 0;
    int matched = 0;
    int ret;

    if (opt->not_after_eq_string &&
        (opt->not_after_lt_string || opt->not_after_gt_string))
        errx(1, "--not-after-eq should not be given with --not-after-lt/gt");
    if (opt->not_before_eq_string &&
        (opt->not_before_lt_string || opt->not_before_gt_string))
        errx(1, "--not-before-eq should not be given with --not-before-lt/gt");

    if ((ret = hx509_certs_init(context, sn, 0, NULL, &certs)))
        hx509_err(context, 1, ret, "Could not load certificates from %s", sn);

    if (opt->expr_string) {
        if ((ret = hx509_query_alloc(context, &q)) ||
	    (ret = hx509_query_match_expr(context, q, opt->expr_string)))
            hx509_err(context, 1, ret, "Could not initialize query");
        if ((ret = hx509_certs_find(context, certs, q, &cert)) || !cert)
            hx509_err(context, 1, ret, "No matching certificate");
        ret = acert1(opt, -1, cert, &matched);
        matched = 1;
    } else {
        ret = hx509_certs_start_seq(context, certs, &cursor);
        while (ret == 0 &&
               (ret = hx509_certs_next_cert(context, certs,
                                            cursor, &cert)) == 0 &&
               cert) {
            ret = acert1(opt, n++, cert, &matched);
            if (matched)
                break;
            hx509_cert_free(cert);
            cert = NULL;
        }
        if (cursor)
            (void) hx509_certs_end_seq(context, certs, cursor);
    }
    if (!matched && ret)
        hx509_err(context, 1, ret, "Could not find certificate");
    if (!matched)
        errx(1, "Could not find certificate");
    if (ret == -1)
        errx(1, "Matching certificate did not meet requirements");
    if (ret)
        hx509_err(context, 1, ret, "Matching certificate did not meet "
                  "requirements");
    hx509_cert_free(cert);
    free(sn);
    return 0;
}

/*
 *
 */

int
help(void *opt, int argc, char **argv)
{
    sl_slc_help(commands, argc, argv);
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

    ret = hx509_context_init(&context);
    if (ret)
	errx(1, "hx509_context_init failed with %d", ret);

    if (stat_file_string)
	hx509_query_statistic_file(context, stat_file_string);

    ret = sl_command(commands, argc, argv);
    if(ret == -1)
	warnx ("unrecognized command: %s", argv[0]);

    hx509_context_free(&context);

    return ret;
}
