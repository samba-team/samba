/*
 * Copyright (c) 2003 - 2007 Kungliga Tekniska Högskolan
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

/*
 * If this test fails with
 *
 *      krb5_cc_gen_new: KEYRING: Key has been revoked
 *
 * then run
 *
 *      keyctl new_session
 */

#include "krb5_locl.h"
#include <getarg.h>
#include <err.h>

#ifdef HAVE_KEYUTILS_H
#include <keyutils.h>
#endif

static const char *unlink_this;
static const char *unlink_this2;
static char *tmpdir;
static int debug_flag	= 0;
static int version_flag = 0;
static int help_flag	= 0;

#define TEST_CC_TEMPLATE "%{TEMP}/krb5-cc-test-XXXXXX"

static void
cleanup(void)
{
    char *s = NULL;

    if (asprintf(&s, "%s/cc", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/scc", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/cccol/foobar+lha@H5L.SE", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/cccol/foobar+lha@SU.SE", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/cccol/foobar", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/cccol", tmpdir) > -1 && s != NULL)
        rmdir(s);
    free(s);

    if (asprintf(&s, "%s/dcc/tkt.lha@H5L.SE", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/dcc/tkt.lha@SU.SE", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/dcc/tkt", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/dcc/primary", tmpdir) > -1 && s != NULL)
        unlink(s);
    free(s);

    if (asprintf(&s, "%s/dcc", tmpdir) > -1 && s != NULL)
        rmdir(s);
    free(s);

    if (unlink_this)
        unlink(unlink_this);
    unlink_this = NULL;
    if (unlink_this2)
        unlink(unlink_this2);
    unlink_this2 = NULL;

    rmdir(tmpdir);
}

static void
make_dir(krb5_context context)
{
    krb5_error_code ret;
    char *template = NULL;
    char *dcc = NULL;

    ret = _krb5_expand_path_tokens(context, TEST_CC_TEMPLATE, 1, &template);
    if (ret)
        krb5_err(context, 1, ret, "_krb5_expand_path_tokens(%s) failed",
                 TEST_CC_TEMPLATE);
    if ((tmpdir = mkdtemp(template)) == NULL)
        krb5_err(context, 1, errno, "mkdtemp(%s) failed", template);
    if (asprintf(&dcc, "%s/dcc", tmpdir) == -1 || dcc == NULL)
        krb5_err(context, 1, errno, "asprintf failed");
    free(dcc);
    atexit(cleanup);
}

static void
test_default_name(krb5_context context)
{
    krb5_error_code ret;
    const char *p;
    char *test_cc_name = NULL;
    const char *p3;
    char *p1, *p2;
    char *exp_test_cc_name;

    if (asprintf(&test_cc_name, "%s/cc", tmpdir) == -1 || test_cc_name == NULL)
        krb5_err(context, 1, errno, "out of memory");

    /* Convert slashes to backslashes */
    ret = _krb5_expand_path_tokens(context, test_cc_name, 1,
                                   &exp_test_cc_name);
    if (ret)
        krb5_err(context, 1, ret, "_krb5_expand_path_tokens(%s) failed",
                 test_cc_name);
    free(test_cc_name);
    test_cc_name = NULL;

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 1 failed");
    p1 = estrdup(p);

    ret = krb5_cc_set_default_name(context, NULL);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_set_default_name(NULL) failed");

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 2 failed");
    p2 = estrdup(p);

    if (strcmp(p1, p2) != 0)
	krb5_errx (context, 1, "krb5_cc_default_name no longer same");

    ret = krb5_cc_set_default_name(context, exp_test_cc_name);
    if (ret)
        krb5_err(context, 1, ret, "krb5_cc_set_default_name(%s) failed",
                 exp_test_cc_name);

    p = krb5_cc_default_name(context);
    if (p == NULL)
	krb5_errx (context, 1, "krb5_cc_default_name 2 failed");

    if (strncmp(p, "FILE:", sizeof("FILE:") - 1) == 0)
        p3 = p + sizeof("FILE:") - 1;
    else
        p3 = p;

    if (strcmp(exp_test_cc_name, p3) != 0) {
#ifdef WIN32
	krb5_warnx(context, 1,
                   "krb5_cc_default_name() returned %s; expected %s",
                   p, exp_test_cc_name);
#else
	krb5_errx(context, 1,
                  "krb5_cc_default_name() returned %s; expected %s",
                  p, exp_test_cc_name);
#endif
    }

    free(exp_test_cc_name);
    free(p1);
    free(p2);
}

/*
 * Check that a closed cc still keeps it data and that it's no longer
 * there when it's destroyed.
 */

static void
test_mcache(krb5_context context)
{
    krb5_error_code ret;
    krb5_ccache id, id2;
    const char *nc, *tc;
    char *c;
    krb5_principal p, p2;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    nc = krb5_cc_get_name(context, id);
    if (nc == NULL)
	krb5_errx(context, 1, "krb5_cc_get_name");

    tc = krb5_cc_get_type(context, id);
    if (tc == NULL)
	krb5_errx(context, 1, "krb5_cc_get_name");

    if (asprintf(&c, "%s:%s", tc, nc) < 0 || c == NULL)
	errx(1, "malloc");

    krb5_cc_close(context, id);

    ret = krb5_cc_resolve(context, c, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    krb5_cc_destroy(context, id2);
    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    ret = krb5_cc_resolve(context, c, &id2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret == 0)
	krb5_errx(context, 1, "krb5_cc_get_principal");

    krb5_cc_destroy(context, id2);
    free(c);
}

/*
 * Test that init works on a destroyed cc.
 */

static void
test_init_vs_destroy(krb5_context context, const char *type)
{
    krb5_error_code ret;
    krb5_ccache id, id2;
    krb5_principal p, p2;
    char *n = NULL;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, type, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", type);

    if (asprintf(&n, "%s:%s",
		 krb5_cc_get_type(context, id),
		 krb5_cc_get_name(context, id)) < 0 || n == NULL)
	errx(1, "malloc");

    if (strcmp(krb5_cc_get_type(context, id), "FILE") == 0)
        unlink_this = krb5_cc_get_name(context, id);

    ret = krb5_cc_resolve(context, n, &id2);
    free(n);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_resolve");

    krb5_cc_destroy(context, id);

    ret = krb5_cc_initialize(context, id2, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    krb5_cc_destroy(context, id2);
    unlink_this = NULL;
    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);
}

static void
test_cache_remove(krb5_context context, const char *type)
{
    krb5_error_code ret;
    krb5_ccache id;
    krb5_principal p;
    krb5_creds cred, found;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, type, NULL, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_gen_new: %s", type);

    if (strcmp(krb5_cc_get_type(context, id), "FILE") == 0)
        unlink_this = krb5_cc_get_name(context, id);

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    /* */
    memset(&cred, 0, sizeof(cred));
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    cred.times.endtime = time(NULL) + 300;

    ret = krb5_cc_store_cred(context, id, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");

    ret = krb5_cc_remove_cred(context, id, 0, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_remove_cred");

    memset(&found, 0, sizeof(found));
    ret = krb5_cc_retrieve_cred(context, id, KRB5_TC_MATCH_TIMES,
                                &cred, &found);
    if (ret == 0)
	krb5_err(context, 1, ret, "krb5_cc_remove_cred didn't");

    ret = krb5_cc_destroy(context, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_destroy");
    unlink_this = NULL;

    krb5_free_principal(context, p);
    krb5_free_principal(context, cred.server);
    krb5_free_principal(context, cred.client);
}

static void
test_mcc_default(void)
{
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache id, id2;
    int i;

    for (i = 0; i < 10; i++) {

	ret = krb5_init_context(&context);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_init_context");

	ret = krb5_cc_set_default_name(context, "MEMORY:foo");
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_set_default_name");

	ret = krb5_cc_default(context, &id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_default");

	ret = krb5_cc_default(context, &id2);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_default");

	ret = krb5_cc_close(context, id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_close");

	ret = krb5_cc_close(context, id2);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_close");

	krb5_free_context(context);
    }
}

struct {
    char *str;
    int fail;
    char *res;
} cc_names[] = {
    { "foo", 0, "foo" },
    { "foo%}", 0, "foo%}" },
    { "%{uid}", 0, NULL },
    { "%{euid}", 0, NULL },
    { "%{username}", 0, NULL },
    { "foo%{null}", 0, "foo" },
    { "foo%{null}bar", 0, "foobar" },
    { "%{", 1, NULL },
    { "%{foo %{", 1, NULL },
    { "%{{", 1, NULL },
    { "%{{}", 1, NULL },
    { "%{nulll}", 1, NULL },
    { "%{does not exist}", 1, NULL },
    { "%{}", 1, NULL },
#ifdef WIN32
    { "%{APPDATA}", 0, NULL },
    { "%{COMMON_APPDATA}", 0, NULL},
    { "%{LOCAL_APPDATA}", 0, NULL},
    { "%{SYSTEM}", 0, NULL},
    { "%{WINDOWS}", 0, NULL},
    { "%{TEMP}", 0, NULL},
    { "%{USERID}", 0, NULL},
    { "%{uid}", 0, NULL},
    { "%{USERCONFIG}", 0, NULL},
    { "%{COMMONCONFIG}", 0, NULL},
    { "%{LIBDIR}", 0, NULL},
    { "%{BINDIR}", 0, NULL},
    { "%{LIBEXEC}", 0, NULL},
    { "%{SBINDIR}", 0, NULL},
#endif
};

static void
test_def_cc_name(krb5_context context)
{
    krb5_error_code ret;
    char *str;
    int i;

    for (i = 0; i < sizeof(cc_names)/sizeof(cc_names[0]); i++) {
	ret = _krb5_expand_default_cc_name(context, cc_names[i].str, &str);
	if (ret) {
	    if (cc_names[i].fail == 0)
		krb5_errx(context, 1, "test %d \"%s\" failed",
			  i, cc_names[i].str);
	} else {
	    if (cc_names[i].fail)
		krb5_errx(context, 1, "test %d \"%s\" was successful",
			  i, cc_names[i].str);
	    if (cc_names[i].res && strcmp(cc_names[i].res, str) != 0)
		krb5_errx(context, 1, "test %d %s != %s",
			  i, cc_names[i].res, str);
	    if (debug_flag)
		printf("%s => %s\n", cc_names[i].str, str);
	    free(str);
	}
    }
}

static void
test_cache_find(krb5_context context, const char *principal, int find)
{
    krb5_principal client;
    krb5_error_code ret;
    krb5_ccache id = NULL;

    ret = krb5_parse_name(context, principal, &client);
    if (ret)
	krb5_err(context, 1, ret, "parse_name for %s failed", principal);

    ret = krb5_cc_cache_match(context, client, &id);
    if (ret && find)
	krb5_err(context, 1, ret, "cc_cache_match for %s failed", principal);
    if (ret == 0 && !find)
	krb5_err(context, 1, ret, "cc_cache_match for %s found", principal);

    if (id)
	krb5_cc_close(context, id);
    krb5_free_principal(context, client);
}


static void
test_cache_iter(krb5_context context, const char *type, int destroy)
{
    krb5_cc_cache_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;

    ret = krb5_cc_cache_get_first (context, type, &cursor);
    if (ret == KRB5_CC_NOSUPP)
	return;
    else if (ret)
	krb5_err(context, 1, ret, "krb5_cc_cache_get_first(%s)", type);


    while ((ret = krb5_cc_cache_next (context, cursor, &id)) == 0) {
	krb5_principal principal;
	char *name;

	heim_assert(id != NULL, "credentials cache is non-NULL");
	if (debug_flag)
	    printf("name: %s\n", krb5_cc_get_name(context, id));
	ret = krb5_cc_get_principal(context, id, &principal);
	if (ret == 0) {
	    ret = krb5_unparse_name(context, principal, &name);
	    if (ret == 0) {
		if (debug_flag)
		    printf("\tprincipal: %s\n", name);
		free(name);
	    }
	    krb5_free_principal(context, principal);
	}
	if (destroy)
	    krb5_cc_destroy(context, id);
	else
	    krb5_cc_close(context, id);
    }

    krb5_cc_cache_end_seq_get(context, cursor);
}

static void
test_cache_iter_all(krb5_context context)
{
    krb5_cccol_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;

    ret = krb5_cccol_cursor_new (context, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cccol_cursor_new");


    while ((ret = krb5_cccol_cursor_next (context, cursor, &id)) == 0 && id != NULL) {
	krb5_principal principal;
	char *name;

	if (debug_flag)
	    printf("name: %s\n", krb5_cc_get_name(context, id));
	ret = krb5_cc_get_principal(context, id, &principal);
	if (ret == 0) {
	    ret = krb5_unparse_name(context, principal, &name);
	    if (ret == 0) {
		if (debug_flag)
		    printf("\tprincipal: %s\n", name);
		free(name);
	    }
	    krb5_free_principal(context, principal);
	}
	krb5_cc_close(context, id);
    }

    krb5_cccol_cursor_free(context, &cursor);
}


static void
test_copy(krb5_context context, const char *from, const char *to)
{
    krb5_ccache fromid, toid;
    krb5_error_code ret;
    krb5_principal p, p2;

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_new_unique(context, from, NULL, &fromid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", from);

    if (strcmp(krb5_cc_get_type(context, fromid), "FILE") == 0)
        unlink_this = krb5_cc_get_name(context, fromid);

    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_new_unique(context, to, NULL, &toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_gen_new: %s", to);

    if (strcmp(krb5_cc_get_type(context, toid), "FILE") == 0)
        unlink_this2 = krb5_cc_get_name(context, toid);

    ret = krb5_cc_copy_cache(context, fromid, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_copy_cache");

    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);

    krb5_cc_destroy(context, fromid);
    krb5_cc_destroy(context, toid);
    unlink_this = unlink_this2 = NULL;
}

static void
test_move(krb5_context context, const char *type)
{
    const krb5_cc_ops *ops;
    krb5_ccache fromid, toid;
    krb5_error_code ret;
    krb5_principal p, p2;
    krb5_creds cred, tocred;

    ops = krb5_cc_get_prefix_ops(context, type);
    if (ops == NULL)
	return;

    ret = krb5_cc_new_unique(context, type, NULL, &fromid);
    if (ret == KRB5_CC_NOSUPP)
	return;
    else if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique: %s", type);

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_initialize(context, fromid, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    memset(&cred, 0, sizeof(cred));
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred.server);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");
    ret = krb5_parse_name(context, "lha@SU.SE", &cred.client);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_store_cred(context, fromid, &cred);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_store_cred");


    ret = krb5_cc_new_unique(context, type, NULL, &toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_cc_move(context, fromid, toid);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_move");

    ret = krb5_cc_get_principal(context, toid, &p2);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_get_principal");

    if (krb5_principal_compare(context, p, p2) == FALSE)
	krb5_errx(context, 1, "p != p2");

    ret = krb5_cc_retrieve_cred(context, toid, 0, &cred, &tocred);
    if (ret)
	krb5_errx(context, 1, "move failed");
    krb5_free_cred_contents(context, &cred);
    krb5_free_cred_contents(context, &tocred);

    krb5_free_principal(context, p);
    krb5_free_principal(context, p2);
    krb5_cc_destroy(context, toid);
}


static void
test_prefix_ops(krb5_context context, const char *name, const krb5_cc_ops *ops)
{
    const krb5_cc_ops *o;

    o = krb5_cc_get_prefix_ops(context, name);
    if (o == NULL)
	krb5_errx(context, 1, "found no match for prefix '%s'", name);
    if (strcmp(o->prefix, ops->prefix) != 0)
	krb5_errx(context, 1, "ops for prefix '%s' is not "
		  "the expected %s != %s", name, o->prefix, ops->prefix);
}

static void
test_cc_config(krb5_context context, const char *cc_type,
	       const char *cc_name, size_t count)
{
    krb5_error_code ret;
    krb5_principal p;
    krb5_ccache id;
    unsigned int i;

    ret = krb5_cc_new_unique(context, cc_type, cc_name, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_new_unique");

    ret = krb5_parse_name(context, "lha@SU.SE", &p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_parse_name");

    ret = krb5_cc_initialize(context, id, p);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_initialize");

    for (i = 0; i < count; i++) {
	krb5_data data, data2;
	const char *name = "foo";
	krb5_principal p1 = NULL;

	if (i & 1)
	    p1 = p;

	data.data = rk_UNCONST(name);
	data.length = strlen(name);

	/*
	 * Because of how krb5_cc_set_config() this will also test
	 * krb5_cc_remove_cred().
	 */
	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", &data);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: add");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_get_config: first");

	if (data.length != data2.length ||
	    memcmp(data.data, data2.data, data.length) != 0)
	    krb5_errx(context, 1, "krb5_cc_get_config: did not fetch what was set");

	krb5_data_free(&data2);

	data.data = rk_UNCONST("bar");
	data.length = strlen("bar");

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", &data);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: add -second");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_get_config: second");

	if (data.length != data2.length ||
	    memcmp(data.data, data2.data, data.length) != 0)
	    krb5_errx(context, 1, "krb5_cc_get_config: replace failed");

	krb5_data_free(&data2);

	ret = krb5_cc_set_config(context, id, p1, "FriendlyName", NULL);
	if (ret)
	    krb5_errx(context, 1, "krb5_cc_set_config: delete");

	ret = krb5_cc_get_config(context, id, p1, "FriendlyName", &data2);
	if (ret == 0)
	    krb5_errx(context, 1, "krb5_cc_get_config: non-existant");

	if (data2.length)
	    krb5_errx(context, 1, "krb5_cc_get_config: delete failed");
    }

    krb5_cc_destroy(context, id);
    krb5_free_principal(context, p);
}

static krb5_error_code
test_cccol(krb5_context context, const char *def_cccol, const char **what)
{
    krb5_cc_cache_cursor cursor;
    krb5_error_code ret;
    krb5_principal p1, p2;
    krb5_ccache id, id1, id2;
    krb5_creds cred1, cred2;
    size_t match1 = 0;
    size_t match2 = 0;

    memset(&cred1, 0, sizeof(cred1));
    memset(&cred2, 0, sizeof(cred2));

    *what = "krb5_parse_name";
    ret = krb5_parse_name(context, "krbtgt/SU.SE@SU.SE", &cred1.server);
    if (ret) return ret;
    ret = krb5_parse_name(context, "lha@SU.SE", &cred1.client);
    if (ret) return ret;
    ret = krb5_parse_name(context, "krbtgt/H5L.SE@H5L.SE", &cred2.server);
    if (ret) return ret;
    ret = krb5_parse_name(context, "lha@H5L.SE", &cred2.client);
    if (ret) return ret;
    *what = "krb5_cc_set_default_name";
    ret = krb5_cc_set_default_name(context, def_cccol);
    if (ret) return ret;
    *what = "krb5_cc_default";
    ret = krb5_cc_default(context, &id1);
    if (ret) return ret;
    *what = "krb5_cc_initialize";
    ret = krb5_cc_initialize(context, id1, cred1.client);
    if (ret) return ret;
    *what = "krb5_cc_store_cred";
    ret = krb5_cc_store_cred(context, id1, &cred1);
    if (ret) return ret;
    *what = "krb5_cc_resolve";
    ret = krb5_cc_resolve_for(context, NULL, def_cccol, cred2.client, &id2);
    if (ret) return ret;
    *what = "krb5_cc_initialize";
    ret = krb5_cc_initialize(context, id2, cred2.client);
    if (ret) return ret;
    *what = "krb5_cc_store_cred";
    ret = krb5_cc_store_cred(context, id2, &cred2);
    if (ret) return ret;

    krb5_cc_close(context, id1);
    krb5_cc_close(context, id2);
    id1 = id2 = NULL;

    *what = "krb5_cc_default";
    ret = krb5_cc_default(context, &id1);
    if (ret) return ret;
    *what = "krb5_cc_resolve";
    ret = krb5_cc_resolve_for(context, NULL, def_cccol, cred2.client, &id2);
    if (ret) return ret;

    *what = "krb5_cc_get_principal";
    ret = krb5_cc_get_principal(context, id1, &p1);
    if (ret) return ret;
    ret = krb5_cc_get_principal(context, id2, &p2);
    if (ret) return ret;

    if (!krb5_principal_compare(context, p1, cred1.client)) {
        char *u1 = NULL;
        char *u2 = NULL;

        (void) krb5_unparse_name(context, p1, &u1);
        (void) krb5_unparse_name(context, cred1.client, &u2);
        warnx("Inconsistent principals for ccaches in %s: %s vs %s "
              "(expected lha@SU.SE)", def_cccol, u1, u2);
        return EINVAL;
    }
    if (!krb5_principal_compare(context, p2, cred2.client)) {
        char *u1 = NULL;
        char *u2 = NULL;

        (void) krb5_unparse_name(context, p2, &u1);
        (void) krb5_unparse_name(context, cred2.client, &u2);
        warnx("Inconsistent principals for ccaches in %s: %s and %s "
              "(expected lha@H5L.SE)", def_cccol, u1, u2);
        return EINVAL;
    }
    krb5_free_principal(context, p1);
    krb5_free_principal(context, p2);

    *what = "krb5_cc_cache_get_first";
    ret = krb5_cc_cache_get_first(context, NULL, &cursor);
    if (ret) return ret;
    *what = "krb5_cc_cache_next";
    while (krb5_cc_cache_next(context, cursor, &id) == 0) {
        krb5_principal p;

        *what = "krb5_cc_get_principal";
        ret = krb5_cc_get_principal(context, id, &p);
        if (ret) return ret;
        if (krb5_principal_compare(context, p, cred1.client))
            match1++;
        else if (krb5_principal_compare(context, p, cred2.client))
            match2++;
	krb5_free_principal(context, p);
        krb5_cc_close(context, id);
    }
    (void) krb5_cc_cache_end_seq_get(context, cursor);

    *what = "cccol iteration inconsistency";
    if (match1 != 1 || match2 != 1)
        return EINVAL;

    krb5_cc_close(context, id1);
    krb5_cc_close(context, id2);

    krb5_free_cred_contents(context, &cred1);
    krb5_free_cred_contents(context, &cred2);

    return 0;
}

static void
test_cccol_dcache(krb5_context context)
{
    krb5_error_code ret;
    char *dcc = NULL;
    const char *what;

    if (asprintf(&dcc, "DIR:%s/dcc", tmpdir) == -1 || dcc == NULL)
        krb5_err(context, 1, errno, "asprintf");

    ret = test_cccol(context, dcc, &what);
    free(dcc);
    if (ret)
        krb5_err(context, 1, ret, "%s", what);
}

static void
test_cccol_scache(krb5_context context)
{
    krb5_error_code ret;
    char *scache = NULL;
    const char *what;
    int fd;

    if (asprintf(&scache, "SCC:%s/scache", tmpdir) == -1 || scache == NULL)
        krb5_err(context, 1, errno, "asprintf");
    if ((fd = open(scache + sizeof("SCC:") - 1, O_CREAT | O_RDWR, 0600)) == -1)
        krb5_err(context, 1, errno, "open(%s)", scache + sizeof("SCC:") - 1);
    (void) close(fd);

    ret = test_cccol(context, scache, &what);
    (void) unlink(scache + sizeof("SCC:") - 1);
    free(scache);
    if (ret)
        krb5_err(context, 1, ret, "%s", what);
}


static struct getargs args[] = {
    {"debug",	'd',	arg_flag,	&debug_flag,
     "turn on debuggin", NULL },
    {"version",	0,	arg_flag,	&version_flag,
     "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,
     NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args), NULL, "hostname ...");
    exit (ret);
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    int optidx = 0;
    krb5_ccache id1, id2;

    setprogname(argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);

    if (help_flag)
	usage (0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    argc -= optidx;
    argv += optidx;

    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);

    make_dir(context);

    test_cache_remove(context, krb5_cc_type_file);
    test_cache_remove(context, krb5_cc_type_memory);
#ifdef USE_SQLITE
    test_cache_remove(context, krb5_cc_type_scc);
#endif
#ifdef HAVE_KEYUTILS_H
    keyctl_join_session_keyring(NULL);
    test_cache_remove(context, krb5_cc_type_keyring);
#endif

    test_default_name(context);
    test_mcache(context);
    /*
     * XXX Make sure to set default ccache names for each cc type!
     * Otherwise we clobber the user's ccaches.
     */
    test_init_vs_destroy(context, krb5_cc_type_memory);
    test_init_vs_destroy(context, krb5_cc_type_file);
#if 0
    test_init_vs_destroy(context, krb5_cc_type_api);
#endif
    /*
     * Cleanup so we can check that the permissions on the directory created by
     * scc are correct.
     */
    cleanup();
    test_init_vs_destroy(context, krb5_cc_type_scc);

#if defined(S_IRWXG) && defined(S_IRWXO)
    {
        struct stat st;

        if (stat(tmpdir, &st) == 0) {
            if ((st.st_mode & S_IRWXG) ||
                (st.st_mode & S_IRWXO))
                krb5_errx(context, 1,
                          "SQLite3 ccache dir perms wrong: %d", st.st_mode);
        }
    }
#endif
    test_init_vs_destroy(context, krb5_cc_type_dcc);
#ifdef HAVE_KEYUTILS_H
    test_init_vs_destroy(context, krb5_cc_type_keyring);
#endif
    test_mcc_default();
    test_def_cc_name(context);

    test_cache_iter_all(context);

    test_cache_iter(context, krb5_cc_type_memory, 0);
    {
	krb5_principal p;
	krb5_cc_new_unique(context, krb5_cc_type_memory, "bar", &id1);
	krb5_cc_new_unique(context, krb5_cc_type_memory, "baz", &id2);
	krb5_parse_name(context, "lha@SU.SE", &p);
	krb5_cc_initialize(context, id1, p);
	krb5_free_principal(context, p);
    }

    test_cache_find(context, "lha@SU.SE", 1);
    test_cache_find(context, "hulabundulahotentot@SU.SE", 0);

    /*
     * XXX We should compose and krb5_cc_set_default_name() a default ccache
     * for each cc type that we test with test_cache_iter(), and we should do
     * that inside test_cache_iter().
     *
     * Alternatively we should remove test_cache_iter() in favor of
     * test_cccol(), which is a much more complete test.
     */
    test_cache_iter(context, krb5_cc_type_memory, 0);
    test_cache_iter(context, krb5_cc_type_memory, 1);
    test_cache_iter(context, krb5_cc_type_memory, 0);
    test_cache_iter(context, krb5_cc_type_file, 0);
    test_cache_iter(context, krb5_cc_type_api, 0);
    test_cache_iter(context, krb5_cc_type_scc, 0);
    test_cache_iter(context, krb5_cc_type_scc, 1);
#if 0
    test_cache_iter(context, krb5_cc_type_dcc, 0);
    test_cache_iter(context, krb5_cc_type_dcc, 1);
#endif
#ifdef HAVE_KEYUTILS_H
    test_cache_iter(context, krb5_cc_type_keyring, 0);
    test_cache_iter(context, krb5_cc_type_keyring, 1);
#endif

    test_copy(context, krb5_cc_type_file, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_file, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_scc, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, krb5_cc_type_scc);
    test_copy(context, krb5_cc_type_scc, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, krb5_cc_type_scc);
#if 0
    test_copy(context, krb5_cc_type_dcc, krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_dcc, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_dcc, krb5_cc_type_scc);
#endif
#ifdef HAVE_KEYUTILS_H
    test_copy(context, krb5_cc_type_keyring, krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, krb5_cc_type_file);
    test_copy(context, "KEYRING:", "KEYRING:bar");
    test_copy(context, "KEYRING:bar", "KEYRING:baz");
# ifdef HAVE_KEYCTL_GET_PERSISTENT
    test_copy(context, krb5_cc_type_file, "KEYRING:persistent");
    test_copy(context, "KEYRING:persistent:", krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, "KEYRING:persistent:foo");
    test_copy(context, "KEYRING:persistent:foo", krb5_cc_type_file);
# endif
    test_copy(context, krb5_cc_type_memory, "KEYRING:process:");
    test_copy(context, "KEYRING:process:", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:process:foo");
    test_copy(context, "KEYRING:process:foo", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:thread:");
    test_copy(context, "KEYRING:thread:", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:thread:foo");
    test_copy(context, "KEYRING:thread:foo", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:session:");
    test_copy(context, "KEYRING:session:", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_memory, "KEYRING:session:foo");
    test_copy(context, "KEYRING:session:foo", krb5_cc_type_memory);
    test_copy(context, krb5_cc_type_file, "KEYRING:user:");
    test_copy(context, "KEYRING:user:", krb5_cc_type_file);
    test_copy(context, krb5_cc_type_file, "KEYRING:user:foo");
    test_copy(context, "KEYRING:user:foo", krb5_cc_type_memory);
#endif /* HAVE_KEYUTILS_H */

    test_move(context, krb5_cc_type_file);
    test_move(context, krb5_cc_type_memory);
    test_move(context, krb5_cc_type_scc);
#if 0
    test_move(context, krb5_cc_type_dcc);
#endif
#ifdef HAVE_KEYUTILS_H
    test_move(context, krb5_cc_type_keyring);
# ifdef HAVE_KEYCTL_GET_PERSISTENT
    test_move(context, "KEYRING:persistent:");
    test_move(context, "KEYRING:persistent:foo");
# endif
    test_move(context, "KEYRING:process:");
    test_move(context, "KEYRING:process:foo");
    test_move(context, "KEYRING:thread:");
    test_move(context, "KEYRING:thread:foo");
    test_move(context, "KEYRING:session:");
    test_move(context, "KEYRING:session:foo");
    test_move(context, "KEYRING:user:");
    test_move(context, "KEYRING:user:foo");
#endif /* HAVE_KEYUTILS_H */

    test_prefix_ops(context, "FILE:/tmp/foo", &krb5_fcc_ops);
    test_prefix_ops(context, "FILE", &krb5_fcc_ops);
    test_prefix_ops(context, "MEMORY", &krb5_mcc_ops);
    test_prefix_ops(context, "MEMORY:foo", &krb5_mcc_ops);
    test_prefix_ops(context, "/tmp/kaka", &krb5_fcc_ops);
#ifdef HAVE_SCC
    test_prefix_ops(context, "SCC:", &krb5_scc_ops);
    test_prefix_ops(context, "SCC:foo", &krb5_scc_ops);
#endif
#if 0
    test_prefix_ops(context, "DIR:", &krb5_dcc_ops);
    test_prefix_ops(context, "DIR:tkt1", &krb5_dcc_ops);
#endif
#ifdef HAVE_KEYUTILS_H
    test_prefix_ops(context, "KEYRING:", &krb5_krcc_ops);
    test_prefix_ops(context, "KEYRING:foo", &krb5_krcc_ops);
#endif /* HAVE_KEYUTILS_H */

    krb5_cc_destroy(context, id1);
    krb5_cc_destroy(context, id2);

    test_cc_config(context, "MEMORY", "bar", 1000);  /* 1000 because fast */
    test_cc_config(context, "FILE", "/tmp/foocc", 30); /* 30 because slower */

    test_cccol_dcache(context);
    test_cccol_scache(context);
#ifdef HAVE_KEYUTILS_H
    {
        const char *what;

        ret = test_cccol(context, "KEYRING:legacy:fooccol", &what);
        if (ret)
            krb5_err(context, 1, ret, "%s", what);

        ret = test_cccol(context, "MEMORY:fooccol", &what);
        if (ret)
            krb5_err(context, 1, ret, "%s", what);
    }
#endif /* HAVE_KEYUTILS_H */

    {
        const char *what;
        char *config = NULL;
        char *fname = NULL;
        char *d = NULL;

        if (asprintf(&d, "%s/cccol", tmpdir) == -1 || d == NULL)
            krb5_err(context, 1, errno, "asprintf");
        if (mkdir(d, 0700) == -1)
            krb5_err(context, 1, errno, "mkdir(%s)", d);
        if (asprintf(&fname, "%s/foobar", d) == -1 || fname == NULL ||
            asprintf(&config,
                     "[libdefaults]\n"
                     "\tdefault_file_cache_collections = FILE:%1$s/cccol/foobar\n"
                     "\tenable_file_cache_iteration = true\n",
                     tmpdir) == -1 || config == NULL)
            krb5_err(context, 1, errno, "asprintf");
        ret = krb5_set_config(context, config);
        if (ret)
            krb5_err(context, 1, ret,
                     "Could not configure context from string:\n%s\n", config);
        ret = test_cccol(context, fname, &what);
        if (ret)
            krb5_err(context, 1, ret, "%s", what);
        free(config);
        free(fname);
        free(d);
    }

    krb5_free_context(context);

#if 0
    sleep(60);
#endif

    return 0;
}
