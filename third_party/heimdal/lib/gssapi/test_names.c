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
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <roken.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <gssapi.h>
#include <gssapi_krb5.h>
#include <gssapi_spnego.h>
#include <krb5_asn1.h>
#include <err.h>
#include <getarg.h>

static void make_composite_name(CompositePrincipal *, gss_name_t *);
static void assert_attr(gss_name_t, const char *, OM_uint32, gss_buffer_t,
                        const char *, int, int, int);
static void assert_attr_unavail(gss_name_t, const char *);
static void assert_attr_set(gss_name_t, gss_buffer_set_t);

static void
gss_print_errors(OM_uint32 stat, gss_OID mech)
{
    OM_uint32 junk;
    OM_uint32 more = 0;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    OM_uint32 ret;

    if (mech) {
        junk = gss_oid_to_str(&junk, mech, &buf);
        if (junk == GSS_S_COMPLETE)
            fprintf(stderr, "mech = %.*s\n", (int)buf.length, (char *)buf.value);
        gss_release_buffer(&junk, &buf);
    }
    do {
	ret = gss_display_status(&junk,
				 stat,
				 mech ? GSS_C_MECH_CODE : GSS_C_GSS_CODE,
				 mech,
				 &more,
				 &buf);
	if (ret != GSS_S_COMPLETE)
            errx(1, "gss_display_status() failed");
        fprintf(stderr, "%.*s\n", (int)buf.length, (char *)buf.value);
        gss_release_buffer(&junk, &buf);
    } while (more);
}

static void
    __attribute__ ((__format__ (__printf__, 5, 6)))
gss_err(int exitval,
        OM_uint32 maj,
        OM_uint32 min,
        gss_OID mech,
        const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vwarnx(fmt, args);
    va_end(args);
    gss_print_errors(maj, GSS_C_NO_OID);
    if (mech)
        gss_print_errors(min, mech);
    exit(exitval);
}

#define MAKE_URN(tail)                                          \
    { sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN tail) - 1,        \
        GSS_KRB5_NAME_ATTRIBUTE_BASE_URN tail }

/*
 * Test RFC6680 name attributes for Kerberos.
 */
static void
check_name_attrs(void)
{
    CompositePrincipal p;
    EncTicketPart *t;
    gss_buffer_desc v = GSS_C_EMPTY_BUFFER;
    gss_name_t n;
    OM_uint32 maj, min;
    int32_t ret;
    gss_buffer_desc attrs[] = {
        MAKE_URN("realm"),
        MAKE_URN("name-ncomp"),
        MAKE_URN("name-ncomp#0"),
        MAKE_URN("peer-realm"),
        MAKE_URN("ticket-authz-data"),
        MAKE_URN("transit-path"),
        MAKE_URN("canonical-name"),
    }; /* Set of attributes we expect to see indicated */
    gss_buffer_set_desc attr_set;
    size_t i, sz;

    memset(&p, 0, sizeof(p));
    attr_set.elements = attrs;
    /*
     * attr_set.count is set in each of the following sections to ever more
     * items.
     */

    /*
     * Testing name attributes is pretty tricky.
     *
     * Our approach is to construct a composite name, construct an exported
     * composite name token for it, import it, then test the gss_inquire_name()
     * and gss_get_name_attribute() accessors, and then gss_display_name_ext().
     *
     * Ideally we'd test the accessors on names imported from query forms with
     * gss_import_name(), and on names from established contexts.  However,
     * that belongs in the test_context program.
     *
     * TODO: Implement and test gss_set_name_attribute() and
     *       gss_delete_name_attribute().
     */

    /* First construct and test an unauthenticated name */
    p.realm = estrdup("TEST.H5L.SE");
    p.name.name_type = KRB5_NT_PRINCIPAL;
    p.name.name_string.val = ecalloc(1, sizeof(p.name.name_string.val[0]));
    p.name.name_string.len = 1;
    p.name.name_string.val[0] = estrdup("someuser");
    p.nameattrs = NULL;
    make_composite_name(&p, &n);

    /* Test the attributes we expect it to have */
    v.length = sizeof("TEST.H5L.SE") - 1;
    v.value = "TEST.H5L.SE";
    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "realm", GSS_S_COMPLETE,
                &v, "TEST.H5L.SE", 0, 1, 0);

    i = 1;
    v.length = sizeof(size_t);
    v.value = &i;
    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "name-ncomp",
                GSS_S_COMPLETE, &v, "1", 0, 1, 0);

    v.length = sizeof("someuser") - 1;
    v.value = "someuser";
    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "name-ncomp#0",
                GSS_S_COMPLETE, &v, "someuser", 0, 1, 0);

    attr_set.count = 3;
    assert_attr_set(n, &attr_set);

    /* Check that it does not have prefixed attributes */
    assert_attr_unavail(n, "whatever " GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                        "realm");
    assert_attr_unavail(n, "whatever " GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                        "name-ncomp");
    assert_attr_unavail(n, "whatever " GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                        "name-ncomp#0");
    assert_attr_unavail(n, "what ever " GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                        "name-ncomp#0");

    /* Check that it does not have various other supported attributes */
    assert_attr_unavail(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "peer-realm");
    assert_attr_unavail(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "name-ncomp#1");
    assert_attr_unavail(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "canonical-name");
    assert_attr_unavail(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                        "ticket-authz-data#pac");
    assert_attr_unavail(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN
                        "ticket-authz-data");
    assert_attr_unavail(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "transit-path");

    /* Exercise URN parser */
    assert_attr_unavail(n, "urn:whatever");
    assert_attr_unavail(n, "urn:whatever#");
    assert_attr_unavail(n, "urn:what#ever");
    assert_attr_unavail(n, "#");
    assert_attr_unavail(n, "#whatever");
    assert_attr_unavail(n, "whatever");
    assert_attr_unavail(n, "what ever");
    assert_attr_unavail(n, "what ever#");

    /* Now test an authenticated name */
    gss_release_name(&min, &n);
    p.nameattrs = ecalloc(1, sizeof(p.nameattrs[0]));
    p.nameattrs->authenticated = 1;
    make_composite_name(&p, &n);

    v.length = sizeof("TEST.H5L.SE") - 1;
    v.value = "TEST.H5L.SE";
    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "realm", GSS_S_COMPLETE,
                &v, "TEST.H5L.SE", 1, 1, 0);

    i = 1;
    v.length = sizeof(size_t);
    v.value = &i;
    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "name-ncomp",
                GSS_S_COMPLETE, &v, "1", 1, 1, 0);

    v.length = sizeof("someuser") - 1;
    v.value = "someuser";
    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "name-ncomp#0",
                GSS_S_COMPLETE, &v, "someuser", 1, 1, 0);

    assert_attr_set(n, &attr_set);

    /* Now add a peer realm */
    gss_release_name(&min, &n);
    p.nameattrs->peer_realm = ecalloc(1, sizeof(p.nameattrs->peer_realm[0]));
    p.nameattrs->peer_realm[0] = estrdup("FOO.TEST.H5L.SE");
    make_composite_name(&p, &n);

    v.length = sizeof("FOO.TEST.H5L.SE") - 1;
    v.value = "FOO.TEST.H5L.SE";
    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "peer-realm",
                GSS_S_COMPLETE, &v, "FOO.TEST.H5L.SE", 1, 1, 0);
    attr_set.count = 4;
    assert_attr_set(n, &attr_set);

    /* Now add canonical name and an authz-data element */
    gss_release_name(&min, &n);
    p.nameattrs->source = ecalloc(1, sizeof(p.nameattrs->source[0]));
    p.nameattrs->source->element = choice_PrincipalNameAttrSrc_enc_ticket_part;

    t = &p.nameattrs->source->u.enc_ticket_part;
    t->cname.name_type = KRB5_NT_PRINCIPAL;
    t->cname.name_string.val = ecalloc(1, sizeof(t->cname.name_string.val[0]));
    t->crealm = estrdup("TEST.H5L.SE");
    t->cname.name_string.len = 1;
    t->cname.name_string.val[0] = estrdup("realusername");
    t->authorization_data = ecalloc(1, sizeof(t->authorization_data[0]));
    t->authorization_data->val =
        ecalloc(1, sizeof(t->authorization_data->val[0]));
    t->authorization_data->len = 1;
    t->authorization_data->val[0].ad_type =
        KRB5_AUTHDATA_ON_BEHALF_OF; /* whatever */
    t->authorization_data->val[0].ad_data.data =
        estrdup("foobar@TEST.H5L.SE");
    t->authorization_data->val[0].ad_data.length =
        sizeof("foobar@TEST.H5L.SE") - 1;
    make_composite_name(&p, &n);

    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "canonical-name",
                GSS_S_COMPLETE, GSS_C_NO_BUFFER, "realusername@TEST.H5L.SE", 1,
                1, 0);

    ASN1_MALLOC_ENCODE(AuthorizationData, v.value, v.length,
                       t->authorization_data, &sz, ret);
    if (ret)
        errx(1, "Failed to encode AuthorizationData");

    assert_attr(n, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "ticket-authz-data",
                GSS_S_COMPLETE, &v, NULL, 0, 1, 0);
    free(v.value);

    attr_set.count = 7;
    assert_attr_set(n, &attr_set);

    gss_release_name(&min, &n);
    free_CompositePrincipal(&p);

    /*
     * Test gss_display_name_ext() with a host-based service principal
     * "host/somehost.test.h5l.se@TEST.H5L.SE".
     *
     * Where gss_display_name() would display this as a Kerberos principal
     * name, gss_display_name_ext() with GSS_C_NT_HOSTBASED_SERVICE should
     * display it as "host@somehost.test.h5l.se".
     */
    p.realm = estrdup("TEST.H5L.SE");
    p.name.name_type = KRB5_NT_SRV_HST;
    p.name.name_string.val = ecalloc(2, sizeof(p.name.name_string.val[0]));
    p.name.name_string.len = 2;
    p.name.name_string.val[0] = estrdup("host");
    p.name.name_string.val[1] = estrdup("somehost.test.h5l.se");
    p.nameattrs = NULL;
    make_composite_name(&p, &n);

    maj = gss_display_name_ext(&min, n, GSS_C_NT_HOSTBASED_SERVICE, &v);
    if (maj)
	gss_err(1, maj, min, GSS_KRB5_MECHANISM, "display name ext");
    if (v.length != sizeof("host@somehost.test.h5l.se") - 1 ||
        strncmp(v.value, "host@somehost.test.h5l.se", v.length) != 0)
        errx(1, "display name ext");
    gss_release_buffer(&min, &v);
    gss_release_name(&min, &n);
    free_CompositePrincipal(&p);

    /*
     * TODO:
     *
     *  - test URN fragments for access to specific authorization data element
     *    types
     *  - test GSS_C_ATTR_LOCAL_LOGIN_USER support (requires configuration or
     *    that we register a plugin here)
     */
}

static int version_flag = 0;
static int help_flag	= 0;
static int anon_flag	= 0;

static struct getargs args[] = {
    {"version",	0,	arg_flag,	&version_flag, "print version", NULL },
    {"anonymous", 0,	arg_flag,	&anon_flag, "test anonymous names", NULL },
    {"help",	0,	arg_flag,	&help_flag,  NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args),
		    NULL, "service@host");
    exit (ret);
}


int
main(int argc, char **argv)
{
    gss_buffer_desc name_buffer;
    OM_uint32 maj_stat, min_stat;
    gss_name_t name, MNname, MNname2;
    int optidx = 0;
    char *str;
    int len, equal;
    gss_OID mech_oid;

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

    gsskrb5_set_default_realm("MIT.EDU");

    /*
     * test import/export
     */

    str = NULL;
    len = asprintf(&str, anon_flag ?
	"WELLKNOWN@ANONYMOUS" : "ftp@freeze-arrow.mit.edu");
    if (len < 0 || str == NULL)
	errx(1, "asprintf");

    name_buffer.value = str;
    name_buffer.length = len;

    maj_stat = gss_import_name(&min_stat, &name_buffer,
			       GSS_C_NT_HOSTBASED_SERVICE,
			       &name);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, GSS_C_NO_OID, "import name error");
    free(str);

    if (anon_flag)
	mech_oid = GSS_SANON_X25519_MECHANISM;
    else
	mech_oid = GSS_KRB5_MECHANISM;

    maj_stat = gss_canonicalize_name (&min_stat,
				      name,
				      mech_oid,
				      &MNname);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, mech_oid, "canonicalize name error");

    maj_stat = gss_export_name(&min_stat,
			       MNname,
			       &name_buffer);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, mech_oid, "export name error");

    /*
     * Import the exported name and compare
     */

    maj_stat = gss_import_name(&min_stat, &name_buffer,
			       GSS_C_NT_EXPORT_NAME,
			       &MNname2);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, mech_oid, "export name error");


    maj_stat = gss_compare_name(&min_stat, MNname, MNname2, &equal);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, mech_oid, "compare name error");
    if (equal && anon_flag)
	errx(1, "names %s equal", anon_flag ? "incorrectly" : "not");

    gss_release_name(&min_stat, &MNname2);
    gss_release_buffer(&min_stat, &name_buffer);
    gss_release_name(&min_stat, &MNname);
    gss_release_name(&min_stat, &name);

    /*
     * Import oid less name and compare to mech name.
     * Dovecot SASL lib does this.
     */

    str = NULL;
    len = asprintf(&str, "lha");
    if (len < 0 || str == NULL)
	errx(1, "asprintf");

    name_buffer.value = str;
    name_buffer.length = len;

    maj_stat = gss_import_name(&min_stat, &name_buffer,
			       GSS_C_NO_OID,
			       &name);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, NULL, "import (no oid) name error");

    maj_stat = gss_import_name(&min_stat, &name_buffer,
			       GSS_KRB5_NT_USER_NAME,
			       &MNname);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, NULL, "import (krb5 mn) name error");

    free(str);

    maj_stat = gss_compare_name(&min_stat, name, MNname, &equal);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_compare_name");
    if (!equal)
	errx(1, "names not equal");

    gss_release_name(&min_stat, &MNname);
    gss_release_name(&min_stat, &name);

#if 0
    maj_stat = gss_canonicalize_name (&min_stat,
				      name,
				      GSS_SPNEGO_MECHANISM,
				      &MNname);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, GSS_SPNEGO_MECHANISM,
                "canonicalize name error");


    maj_stat = gss_export_name(&maj_stat,
			       MNname,
			       &name_buffer);
    if (maj_stat != GSS_S_COMPLETE)
	gss_err(1, maj_stat, min_stat, GSS_SPNEGO_MECHANISM,
                "export name error (SPNEGO)");

    gss_release_name(&min_stat, &MNname);
    gss_release_buffer(&min_stat, &name_buffer);
#endif

    if (anon_flag) {
	/* check anonymous name canonicalizes to well known name */
	gss_OID name_type;

	name_buffer.length = 0;
	name_buffer.value = NULL;

	maj_stat = gss_import_name(&min_stat, &name_buffer,
				   GSS_C_NT_ANONYMOUS, &name);
	if (maj_stat != GSS_S_COMPLETE)
            gss_err(1, maj_stat, min_stat, GSS_C_NO_OID,
                    "import (anon) name error");

	maj_stat = gss_canonicalize_name(&min_stat, name,
					 GSS_SANON_X25519_MECHANISM,
					 &MNname);
	if (maj_stat != GSS_S_COMPLETE)
            gss_err(1, maj_stat, min_stat, GSS_SANON_X25519_MECHANISM,
                    "canonicalize (anon) name error");

	maj_stat = gss_display_name(&min_stat, MNname,
				    &name_buffer, &name_type);
	if (maj_stat != GSS_S_COMPLETE)
            gss_err(1, maj_stat, min_stat, GSS_SANON_X25519_MECHANISM,
                    "display_name (anon) name error");

	if (!gss_oid_equal(name_type, GSS_C_NT_ANONYMOUS))
	    errx(1, "display name type not anonymous");
	if (memcmp(name_buffer.value, "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS",
		   sizeof("WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS") - 1) != 0)
	    errx(1, "display name string not well known anonymous name");

	gss_release_name(&min_stat, &MNname);
	gss_release_name(&min_stat, &name);
	gss_release_buffer(&min_stat, &name_buffer);
    }

    check_name_attrs();
    return 0;
}

/* Copied from _gsskrb5_export_name_composite() */
static void
export_name_composite(CompositePrincipal *name, gss_buffer_t exported_name)
{
    gss_buffer_desc inner = GSS_C_EMPTY_BUFFER;
    unsigned char *buf;
    int32_t ret;
    size_t sz;

    ASN1_MALLOC_ENCODE(CompositePrincipal, inner.value, inner.length,
                       (void *)name, &sz, ret);
    if (ret)
        errx(1, "Failed to encode exported composite name token");

    exported_name->length = 10 + inner.length + GSS_KRB5_MECHANISM->length;
    exported_name->value  = malloc(exported_name->length);
    if (exported_name->value == NULL)
        errx(1, "Failed to allocate exported composite name token");

    /* TOK, MECH_OID_LEN, DER(MECH_OID), NAME_LEN, NAME */

    buf = exported_name->value;
    buf[0] = 0x04;
    buf[1] = 0x02;
    buf[2] = ((GSS_KRB5_MECHANISM->length + 2) >> 8) & 0xff;
    buf[3] = (GSS_KRB5_MECHANISM->length + 2) & 0xff;
    buf[4] = 0x06;
    buf[5] = (GSS_KRB5_MECHANISM->length) & 0xFF;

    memcpy(buf + 6, GSS_KRB5_MECHANISM->elements, GSS_KRB5_MECHANISM->length);
    buf += 6 + GSS_KRB5_MECHANISM->length;

    buf[0] = (inner.length >> 24) & 0xff;
    buf[1] = (inner.length >> 16) & 0xff;
    buf[2] = (inner.length >> 8) & 0xff;
    buf[3] = (inner.length) & 0xff;
    buf += 4;

    memcpy(buf, inner.value, inner.length);
    free(inner.value);
}

static void
make_composite_name(CompositePrincipal *princ, gss_name_t *n)
{
    gss_buffer_desc token, exported;
    OM_uint32 maj, min;

    export_name_composite(princ, &token);
    maj = gss_import_name(&min, &token, GSS_C_NT_COMPOSITE_EXPORT, n);
    if (maj)
	gss_err(1, maj, min, GSS_KRB5_MECHANISM, "import composite name");
    maj = gss_export_name_composite(&min, *n, &exported);
    if (maj)
	gss_err(1, maj, min, GSS_KRB5_MECHANISM, "export composite name");
    if (token.length != exported.length ||
        memcmp(token.value, exported.value, token.length) != 0)
        errx(1, "import/export composite token disagreement");
    gss_release_buffer(&min, &exported);
    free(token.value); /* Use free because we allocated this one */
}

static void
assert_attr(gss_name_t n,
            const char *aname,
            OM_uint32 exp_maj,
            gss_buffer_t exp_v,
            const char *exp_dv,
            int exp_authenticated,
            int exp_complete,
            int exp_multivalued)
{
    gss_buffer_desc dv = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc v = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc a;
    OM_uint32 maj, min;
    int authenticated, complete, more;

    a.value = (void*)(uintptr_t)aname;
    a.length = strlen(aname);
    more = 0;
    maj = gss_get_name_attribute(&min, n, &a, &authenticated, &complete, &v,
                                 &dv, &more);
    if (maj != GSS_S_COMPLETE && maj != exp_maj)
	gss_err(1, maj, min, GSS_KRB5_MECHANISM,
                "import composite name error");
    if (maj == GSS_S_COMPLETE && maj != exp_maj)
        errx(1, "unexpected name attribute %s", aname);
    if (maj == GSS_S_COMPLETE) {
        if (exp_v &&
            (v.length != exp_v->length ||
             memcmp(v.value, exp_v->value, exp_v->length) != 0))
            errx(1, "import composite name: wrong %s value", aname);
        if (exp_dv &&
            (dv.length != strlen(exp_dv) ||
             strncmp(dv.value, exp_dv, dv.length) != 0))
            errx(1, "import composite name: wrong %s display value "
                 "(wanted %s, got %.*s)", aname, exp_dv,
                 (int)dv.length, (char *)dv.value);
        if (authenticated != exp_authenticated)
            errx(1, "import composite name: %s incorrectly marked "
                 "%sauthenticated", aname, authenticated ? "" : "un");
        if (complete != exp_complete)
            errx(1, "import composite name: %s incorrectly marked "
                 "%scomplete", aname, complete ? "" : "in");
        if (more != exp_multivalued)
            errx(1, "import composite name: %s incorrectly marked "
                 "%s-valued", aname, more ? "multi" : "single");
    }
    gss_release_buffer(&min, &dv);
    gss_release_buffer(&min, &v);
}

static void
assert_attr_unavail(gss_name_t n, const char *aname)
{
    assert_attr(n, aname, GSS_S_UNAVAILABLE, GSS_C_NO_BUFFER, NULL, 0, 0, 0);
}

static void
assert_attr_set(gss_name_t n, gss_buffer_set_t exp_as)
{
    OM_uint32 maj, min;
    gss_buffer_set_t as = NULL;
    gss_OID MN_mech = GSS_C_NO_OID;
    size_t i;
    int name_is_MN = 0;

    maj = gss_inquire_name(&min, n, &name_is_MN, &MN_mech, &as);
    if (maj)
	gss_err(1, maj, min, MN_mech, "inquire name");
    for (i = 0; i < as->count && i < exp_as->count; i++) {
        if (as->elements[i].length != exp_as->elements[i].length ||
            memcmp(as->elements[i].value, exp_as->elements[i].value,
                   as->elements[i].length) != 0)
            errx(1, "attribute sets differ");
    }
    if (i < as->count)
            errx(1, "more attributes indicated than expected");
    if (i < exp_as->count)
            errx(1, "fewer attributes indicated than expected");
    gss_release_buffer_set(&min, &as);
}
