/*
 * Copyright (c) 2004 - 2006 Kungliga Tekniska Högskolan
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


struct hx509_validate_ctx_data {
    int flags;
    hx509_vprint_func vprint_func;
    void *ctx;
};

struct cert_status {
    unsigned int selfsigned:1;
    unsigned int isca:1;
    unsigned int isproxy:1;
    unsigned int haveSAN:1;
    unsigned int haveIAN:1;
    unsigned int haveSKI:1;
    unsigned int haveAKI:1;
};


/*
 *
 */

static int
Time2string(const Time *T, char **str)
{
    time_t t;
    char *s;
    struct tm *tm;

    *str = NULL;
    t = _hx509_Time2time_t(T);
    tm = gmtime (&t);
    s = malloc(30);
    if (s == NULL)
	return ENOMEM;
    strftime(s, 30, "%Y-%m-%d %H:%M:%S", tm);
    *str = s;
    return 0;
}

void
hx509_print_stdout(void *ctx, const char *fmt, va_list va)
{
    FILE *f = ctx;
    vfprintf(f, fmt, va);
}

void
hx509_print_func(hx509_vprint_func func, void *ctx, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    (*func)(ctx, fmt, va);
    va_end(va);
}

int
hx509_oid_sprint(const heim_oid *oid, char **str)
{
    return der_print_heim_oid(oid, '.', str);
}

void
hx509_oid_print(const heim_oid *oid, hx509_vprint_func func, void *ctx)
{
    char *str;
    hx509_oid_sprint(oid, &str);
    hx509_print_func(func, ctx, "%s", str);
    free(str);
}

void
hx509_bitstring_print(const heim_bit_string *b,
		      hx509_vprint_func func, void *ctx)
{
    int i;
    hx509_print_func(func, ctx, "\tlength: %d\n\t", b->length);
    for (i = 0; i < (b->length + 7) / 8; i++)
	hx509_print_func(func, ctx, "%02x%s%s",
			 ((unsigned char *)b->data)[i], 
			 i < (b->length - 7) / 8
			 && (i == 0 || (i % 16) != 15) ? ":" : "",
			 i != 0 && (i % 16) == 15 ?
			 (i <= ((b->length + 7) / 8 - 2) ? "\n\t" : "\n"):"");
}

int
hx509_cert_keyusage_print(hx509_context context, hx509_cert c, char **s)
{
    KeyUsage ku;
    char buf[256];
    int ret;

    *s = NULL;

    ret = _hx509_cert_get_keyusage(context, c, &ku);
    if (ret)
	return ret;
    unparse_flags(KeyUsage2int(ku), asn1_KeyUsage_units(), buf, sizeof(buf));
    *s = strdup(buf);
    if (*s == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }

    return 0;
}

/*
 *
 */

static void
validate_vprint(void *c, const char *fmt, va_list va)
{
    hx509_validate_ctx ctx = c;
    if (ctx->vprint_func == NULL)
	return;
    (ctx->vprint_func)(ctx->ctx, fmt, va);
}

static void
validate_print(hx509_validate_ctx ctx, int flags, const char *fmt, ...)
{
    va_list va;
    if ((ctx->flags & flags) == 0)
	return;
    va_start(va, fmt);
    validate_vprint(ctx, fmt, va);
    va_end(va);
}

/* 
 * Dont Care, SHOULD critical, SHOULD NOT critical, MUST critical,
 * MUST NOT critical
 */
enum critical_flag { D_C = 0, S_C, S_N_C, M_C, M_N_C };

static int
check_Null(hx509_validate_ctx ctx,
	   struct cert_status *status,
	   enum critical_flag cf, const Extension *e)
{
    switch(cf) {
    case D_C:
	break;
    case S_C:
	if (!e->critical)
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
			   "\tCritical not set on SHOULD\n");
	break;
    case S_N_C:
	if (e->critical)
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
			   "\tCritical set on SHOULD NOT\n");
	break;
    case M_C:
	if (!e->critical)
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
			   "\tCritical not set on MUST\n");
	break;
    case M_N_C:
	if (e->critical)
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
			   "\tCritical set on MUST NOT\n");
	break;
    default:
	_hx509_abort("internal check_Null state error");
    }
    return 0;
}

static int
check_subjectKeyIdentifier(hx509_validate_ctx ctx, 
			   struct cert_status *status,
			   enum critical_flag cf,
			   const Extension *e)
{
    SubjectKeyIdentifier si;
    size_t size;
    int ret;

    status->haveSKI = 1;
    check_Null(ctx, status, cf, e);

    ret = decode_SubjectKeyIdentifier(e->extnValue.data, 
				      e->extnValue.length,
				      &si, &size);
    if (ret) {
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "Decoding SubjectKeyIdentifier failed: %d", ret);
	return 1;
    }
    if (size != e->extnValue.length) {
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "Decoding SKI ahve extra bits on the end");
	return 1;
    }
    if (si.length == 0)
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "SKI is too short (0 bytes)");
    if (si.length > 20)
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "SKI is too long");
    free_SubjectKeyIdentifier(&si);

    return 0;
}

static int
check_authorityKeyIdentifier(hx509_validate_ctx ctx, 
			     struct cert_status *status,
			     enum critical_flag cf,
			     const Extension *e)
{
    status->haveAKI = 1;
    check_Null(ctx, status, cf, e);
    return 0;
}


static int
check_pkinit_san(hx509_validate_ctx ctx, heim_any *a)
{
    KRB5PrincipalName kn;
    unsigned i;
    size_t size;
    int ret;

    ret = decode_KRB5PrincipalName(a->data, a->length, &kn, &size);
    if (ret) {
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "Decoding kerberos name in SAN failed: %d", ret);
	return 1;
    }

    if (size != a->length) {
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "Decoding kerberos name have extra bits on the end");
	return 1;
    }

    /* print kerberos principal, add code to quote / within components */
    for (i = 0; i < kn.principalName.name_string.len; i++) {
	validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "%s", 
		       kn.principalName.name_string.val[i]);
	if (i + 1 < kn.principalName.name_string.len)
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "/");
    }
    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "@");
    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "%s", kn.realm);

    free_KRB5PrincipalName(&kn);
    return 0;
}

static int
check_xmpp_san(hx509_validate_ctx ctx, heim_any *a)
{
    PKIXXmppAddr jid;
    size_t size;
    int ret;

    ret = decode_PKIXXmppAddr(a->data, a->length, &jid, &size);
    if (ret) {
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "Decoding JID in SAN failed: %d", ret);
	return 1;
    }

    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "jid: %s", jid);
    free_PKIXXmppAddr(&jid);

    return 0;
}

static int
check_dnssrv_san(hx509_validate_ctx ctx, heim_any *a)
{
    return 0;
}

struct {
    const char *name;
    const heim_oid *(*oid)(void);
    int (*func)(hx509_validate_ctx, heim_any *);
} check_altname[] = {
    { "pk-init", oid_id_pkinit_san, check_pkinit_san },
    { "jabber", oid_id_pkix_on_xmppAddr, check_xmpp_san },
    { "dns-srv", oid_id_pkix_on_dnsSRV, check_dnssrv_san }
};

static int
check_altName(hx509_validate_ctx ctx,
	      struct cert_status *status,
	      const char *name,
	      enum critical_flag cf,
	      const Extension *e)
{
    GeneralNames gn;
    size_t size;
    int ret, i;

    check_Null(ctx, status, cf, e);

    if (e->extnValue.length == 0) {
	printf("%sAltName empty, not allowed", name);
	return 1;
    }
    ret = decode_GeneralNames(e->extnValue.data, e->extnValue.length,
			      &gn, &size);
    if (ret) {
	printf("\tret = %d while decoding %s GeneralNames\n", ret, name);
	return 1;
    }
    if (gn.len == 0) {
	printf("%sAltName generalName empty, not allowed", name);
	return 1;
    }

    for (i = 0; i < gn.len; i++) {
	switch (gn.val[i].element) {
	case choice_GeneralName_otherName: {
	    unsigned j;
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "%sAltName otherName ", name);

	    for (j = 0; j < sizeof(check_altname)/sizeof(check_altname[0]); j++) {
		if (der_heim_oid_cmp((*check_altname[j].oid)(), 
				     &gn.val[i].u.otherName.type_id) != 0)
		    continue;
		
		validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "%s: ", 
			       check_altname[j].name);
		(*check_altname[j].func)(ctx, &gn.val[i].u.otherName.value);
		break;
	    }
	    if (j == sizeof(check_altname)/sizeof(check_altname[0])) {
		hx509_oid_print(&gn.val[i].u.otherName.type_id,
				validate_vprint, ctx);
		validate_print(ctx, HX509_VALIDATE_F_VERBOSE, " unknown");
	    }
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "\n");
	    break;
	}
	case choice_GeneralName_rfc822Name:
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "rfc822Name: %s\n",
			   gn.val[i].u.rfc822Name);
	    break;
	case choice_GeneralName_dNSName:
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "dNSName: %s\n",
			   gn.val[i].u.dNSName);
	    break;
	case choice_GeneralName_directoryName: {
	    Name dir;
	    char *s;
	    dir.element = gn.val[i].u.directoryName.element;
	    dir.u.rdnSequence = gn.val[i].u.directoryName.u.rdnSequence;
	    ret = _hx509_unparse_Name(&dir, &s);
	    if (ret) {
		printf("unable to parse %sAltName directoryName\n", name);
		return 1;
	    }
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "directoryName: %s\n", s);
	    free(s);
	    break;
	}
	case choice_GeneralName_uniformResourceIdentifier:
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "uri: %s\n",
			   gn.val[i].u.uniformResourceIdentifier);
	    break;
	case choice_GeneralName_iPAddress:
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "ip address\n");
	    break;
	case choice_GeneralName_registeredID:
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "registered id: ");
		hx509_oid_print(&gn.val[i].u.registeredID,
				validate_vprint, ctx);
	    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "\n");
	    break;
	}
    }

    free_GeneralNames(&gn);

    return 0;
}

static int
check_subjectAltName(hx509_validate_ctx ctx,
		     struct cert_status *status,
		     enum critical_flag cf,
		     const Extension *e)
{
    status->haveSAN = 1;
    return check_altName(ctx, status, "subject", cf, e);
}

static int
check_issuerAltName(hx509_validate_ctx ctx,
		    struct cert_status *status,
		     enum critical_flag cf,
		     const Extension *e)
{
    status->haveIAN = 1;
    return check_altName(ctx, status, "issuer", cf, e);
}


static int
check_basicConstraints(hx509_validate_ctx ctx, 
		       struct cert_status *status,
		       enum critical_flag cf, 
		       const Extension *e)
{
    BasicConstraints b;
    size_t size;
    int ret;

    check_Null(ctx, status, cf, e);
    
    ret = decode_BasicConstraints(e->extnValue.data, e->extnValue.length,
				  &b, &size);
    if (ret) {
	printf("\tret = %d while decoding BasicConstraints\n", ret);
	return 0;
    }
    if (size != e->extnValue.length)
	printf("\tlength of der data isn't same as extension\n");

    validate_print(ctx, HX509_VALIDATE_F_VERBOSE,
		   "\tis %sa CA\n", b.cA && *b.cA ? "" : "NOT ");
    if (b.pathLenConstraint)
	validate_print(ctx, HX509_VALIDATE_F_VERBOSE,
		       "\tpathLenConstraint: %d\n", *b.pathLenConstraint);

    if (b.cA) {
	if (*b.cA) {
	    if (!e->critical)
		validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
			       "Is a CA and not BasicConstraints CRITICAL\n");
	    status->isca = 1;
	}
	else
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
			   "cA is FALSE, not allowed to be\n");
    }

    return 0;
}

static int
check_proxyCertInfo(hx509_validate_ctx ctx, 
		    struct cert_status *status,
		    enum critical_flag cf, 
		    const Extension *e)
{
    status->isproxy = 1;

    return 0;
}


struct {
    const char *name;
    const heim_oid *(*oid)(void);
    int (*func)(hx509_validate_ctx ctx, 
		struct cert_status *status,
		enum critical_flag cf, 
		const Extension *);
    enum critical_flag cf;
} check_extension[] = {
#define ext(name, checkname) #name, &oid_id_x509_ce_##name, check_##checkname 
    { ext(subjectDirectoryAttributes, Null), M_N_C },
    { ext(subjectKeyIdentifier, subjectKeyIdentifier), M_N_C },
    { ext(keyUsage, Null), S_C },
    { ext(subjectAltName, subjectAltName), M_N_C },
    { ext(issuerAltName, issuerAltName), S_N_C },
    { ext(basicConstraints, basicConstraints), D_C },
    { ext(cRLNumber, Null), M_N_C },
    { ext(cRLReason, Null), M_N_C },
    { ext(holdInstructionCode, Null), M_N_C },
    { ext(invalidityDate, Null), M_N_C },
    { ext(deltaCRLIndicator, Null), M_C },
    { ext(issuingDistributionPoint, Null), M_C },
    { ext(certificateIssuer, Null), M_C },
    { ext(nameConstraints, Null), M_C },
    { ext(cRLDistributionPoints, Null), S_N_C },
    { ext(certificatePolicies, Null) },
    { ext(policyMappings, Null), M_N_C },
    { ext(authorityKeyIdentifier, authorityKeyIdentifier), M_N_C },
    { ext(policyConstraints, Null), D_C },
    { ext(extKeyUsage, Null), D_C },
    { ext(freshestCRL, Null), M_N_C },
    { ext(inhibitAnyPolicy, Null), M_C },
    { "proxyCertInfo", &oid_id_pe_proxyCertInfo, check_proxyCertInfo, M_C },
    { NULL }
};

int
hx509_validate_ctx_init(hx509_context context, hx509_validate_ctx *ctx)
{
    *ctx = malloc(sizeof(**ctx));
    if (*ctx == NULL)
	return ENOMEM;
    memset(*ctx, 0, sizeof(**ctx));
    return 0;
}

void
hx509_validate_ctx_set_print(hx509_validate_ctx ctx, 
			     hx509_vprint_func func,
			     void *c)
{
    ctx->vprint_func = func;
    ctx->ctx = c;
}

void
hx509_validate_ctx_add_flags(hx509_validate_ctx ctx, int flags)
{
    ctx->flags |= flags;
}

void
hx509_validate_ctx_free(hx509_validate_ctx ctx)
{
    free(ctx);
}

int
hx509_validate_cert(hx509_context context,
		    hx509_validate_ctx ctx,
		    hx509_cert cert)
{
    Certificate *c = _hx509_get_cert(cert);
    TBSCertificate *t = &c->tbsCertificate;
    hx509_name issuer, subject;
    char *str;
    struct cert_status status;

    memset(&status, 0, sizeof(status));

    if (_hx509_cert_get_version(c) != 3)
	validate_print(ctx, HX509_VALIDATE_F_VERBOSE,
		       "Not version 3 certificate\n");
    
    if ((t->version == NULL || *t->version < 2) && t->extensions)
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "Not version 3 certificate with extensions\n");
	
    if (_hx509_cert_get_version(c) >= 3 && t->extensions == NULL)
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE,
		       "Version 3 certificate without extensions\n");

    _hx509_name_from_Name(&t->subject, &subject);
    hx509_name_to_string(subject, &str);
    validate_print(ctx, HX509_VALIDATE_F_VERBOSE,
		   "subject name: %s\n", str);
    free(str);

    _hx509_name_from_Name(&t->issuer, &issuer);
    hx509_name_to_string(issuer, &str);
    validate_print(ctx, HX509_VALIDATE_F_VERBOSE,
		   "issuer name: %s\n", str);
    free(str);

    if (hx509_name_cmp(subject, issuer) == 0)
	status.selfsigned = 1;

    validate_print(ctx, HX509_VALIDATE_F_VERBOSE,
		   "Validity:\n");

    Time2string(&t->validity.notBefore, &str);
    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "\tnotBefore %s\n", str);
    free(str);
    Time2string(&t->validity.notAfter, &str);
    validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "\tnotAfter  %s\n", str);
    free(str);

    if (t->extensions) {
	int i, j;

	if (t->extensions->len == 0) {
	    validate_print(ctx,
			   HX509_VALIDATE_F_VALIDATE|HX509_VALIDATE_F_VERBOSE,
			   "The empty extensions list is not "
			   "allowed by PKIX\n");
	}

	for (i = 0; i < t->extensions->len; i++) {

	    for (j = 0; check_extension[j].name; j++)
		if (der_heim_oid_cmp((*check_extension[j].oid)(),
				     &t->extensions->val[i].extnID) == 0)
		    break;
	    if (check_extension[j].name == NULL) {
		int flags = HX509_VALIDATE_F_VERBOSE;
		if (t->extensions->val[i].critical)
		    flags |= HX509_VALIDATE_F_VALIDATE;
		validate_print(ctx, flags, "don't know what ");
		if (t->extensions->val[i].critical)
		    validate_print(ctx, flags, "and is CRITICAL ");
		if (ctx->flags & flags)
		    hx509_oid_print(&t->extensions->val[i].extnID, 
				    validate_vprint, ctx);
		validate_print(ctx, flags, " is\n");
		continue;
	    }
	    validate_print(ctx,
			   HX509_VALIDATE_F_VALIDATE|HX509_VALIDATE_F_VERBOSE,
			   "checking extention: %s\n",
			   check_extension[j].name);
	    (*check_extension[j].func)(ctx,
				       &status,
				       check_extension[j].cf,
				       &t->extensions->val[i]);
	}
    } else
	validate_print(ctx, HX509_VALIDATE_F_VERBOSE, "no extentions\n");
	
    if (status.isca) {
	if (!status.haveSKI)
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE, 
			   "CA certificate have no SubjectKeyIdentifier\n");

    } else {
	if (!status.haveAKI)
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE, 
			   "Is not CA and doesn't have "
			   "AuthorityKeyIdentifier\n");
    }
	    

    if (!status.haveSKI)
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE, 
		       "Doesn't have SubjectKeyIdentifier\n");

    if (status.isproxy && status.isca)
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE, 
		       "Proxy and CA at the same time!\n");

    if (status.isproxy) {
	if (status.haveSAN)
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE, 
			   "Proxy and have SAN\n");
	if (status.haveIAN)
	    validate_print(ctx, HX509_VALIDATE_F_VALIDATE, 
			   "Proxy and have IAN\n");
    }

    if (hx509_name_is_null_p(subject) && !status.haveSAN)
	validate_print(ctx, HX509_VALIDATE_F_VALIDATE, 
		       "NULL subject DN and doesn't have a SAN\n");

    hx509_name_free(&subject);
    hx509_name_free(&issuer);

    return 0;
}
