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

#include "hx_locl.h"
#include <pkcs10_asn1.h>

typedef struct abitstring_s {
    unsigned char *feats;
    size_t feat_bytes;
} *abitstring;

struct hx509_request_data {
    hx509_context context;
    hx509_name name;
    SubjectPublicKeyInfo key;
    KeyUsage ku;
    ExtKeyUsage eku;
    GeneralNames san;
    struct abitstring_s authorized_EKUs;
    struct abitstring_s authorized_SANs;
    uint32_t nunsupported;  /* Count of unsupported features requested */
    uint32_t nauthorized;   /* Count of supported   features authorized */
    uint32_t ku_are_authorized:1;
};

/**
 * Allocate and initialize an hx509_request structure representing a PKCS#10
 * certificate signing request.
 *
 * @param context An hx509 context.
 * @param req Where to put the new hx509_request object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_init(hx509_context context, hx509_request *req)
{
    *req = calloc(1, sizeof(**req));
    if (*req == NULL)
	return ENOMEM;

    (*req)->context = context;
    return 0;
}

/**
 * Free a certificate signing request object.
 *
 * @param req A pointer to the hx509_request to free.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_request_free(hx509_request *reqp)
{
    hx509_request req = *reqp;

    *reqp = NULL;
    if (req == NULL)
        return;
    if (req->name)
	hx509_name_free(&req->name);
    free(req->authorized_EKUs.feats);
    free(req->authorized_SANs.feats);
    free_SubjectPublicKeyInfo(&req->key);
    free_ExtKeyUsage(&req->eku);
    free_GeneralNames(&req->san);
    memset(req, 0, sizeof(*req));
    free(req);
}

/**
 * Set the subjectName of the CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request to alter.
 * @param name The subjectName.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_set_name(hx509_context context,
			hx509_request req,
			hx509_name name)
{
    if (req->name)
	hx509_name_free(&req->name);
    if (name) {
	int ret = hx509_name_copy(context, name, &req->name);
	if (ret)
	    return ret;
    }
    return 0;
}

/**
 * Get the subject name requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param name Where to put the name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_name(hx509_context context,
			hx509_request req,
			hx509_name *name)
{
    if (req->name == NULL) {
	hx509_set_error_string(context, 0, EINVAL, "Request have no name");
	return EINVAL;
    }
    return hx509_name_copy(context, req->name, name);
}

/**
 * Set the subject public key requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param key The public key.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_set_SubjectPublicKeyInfo(hx509_context context,
					hx509_request req,
					const SubjectPublicKeyInfo *key)
{
    free_SubjectPublicKeyInfo(&req->key);
    return copy_SubjectPublicKeyInfo(key, &req->key);
}

/**
 * Get the subject public key requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param key Where to put the key.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_SubjectPublicKeyInfo(hx509_context context,
					hx509_request req,
					SubjectPublicKeyInfo *key)
{
    return copy_SubjectPublicKeyInfo(&req->key, key);
}

/**
 * Set the key usage requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param ku The key usage.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_set_ku(hx509_context context, hx509_request req, KeyUsage ku)
{
    uint64_t n = KeyUsage2int(ku);

    if ((KeyUsage2int(req->ku) & n) != n)
        req->ku_are_authorized = 0;
    req->ku = ku;
    return 0;
}

/**
 * Get the key usage requested by a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param ku Where to put the key usage.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_ku(hx509_context context, hx509_request req, KeyUsage *ku)
{
    *ku = req->ku;
    return 0;
}

/**
 * Add an extended key usage OID to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param oid The EKU OID.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_eku(hx509_context context,
                      hx509_request req,
                      const heim_oid *oid)
{
    void *val;
    int ret;

    val = realloc(req->eku.val, sizeof(req->eku.val[0]) * (req->eku.len + 1));
    if (val == NULL)
	return ENOMEM;
    req->eku.val = val;

    ret = der_copy_oid(oid, &req->eku.val[req->eku.len]);
    if (ret)
	return ret;

    req->eku.len += 1;

    return 0;
}

/**
 * Add a GeneralName (Jabber ID) subject alternative name to a CSR.
 *
 * XXX Make this take a heim_octet_string, not a GeneralName*.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param gn The GeneralName object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_GeneralName(hx509_context context,
                              hx509_request req,
                              const GeneralName *gn)
{
    return add_GeneralNames(&req->san, gn);
}

static int
add_utf8_other_san(hx509_context context,
                   GeneralNames *gns,
                   const heim_oid *oid,
                   const char *s)
{
    const PKIXXmppAddr us = (const PKIXXmppAddr)(uintptr_t)s;
    GeneralName gn;
    size_t size;
    int ret;

    gn.element = choice_GeneralName_otherName;
    gn.u.otherName.type_id.length = 0;
    gn.u.otherName.type_id.components = 0;
    gn.u.otherName.value.data = NULL;
    gn.u.otherName.value.length = 0;
    ret = der_copy_oid(oid, &gn.u.otherName.type_id);
    if (ret == 0)
        ASN1_MALLOC_ENCODE(PKIXXmppAddr, gn.u.otherName.value.data,
                           gn.u.otherName.value.length, &us, &size, ret);
    if (ret == 0 && size != gn.u.otherName.value.length)
        _hx509_abort("internal ASN.1 encoder error");
    if (ret == 0)
        ret = add_GeneralNames(gns, &gn);
    free_GeneralName(&gn);
    if (ret)
        hx509_set_error_string(context, 0, ret, "Out of memory");
    return ret;
}

/**
 * Add an xmppAddr (Jabber ID) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param jid The XMPP address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_xmpp_name(hx509_context context,
                            hx509_request req,
                            const char *jid)
{
    return add_utf8_other_san(context, &req->san,
                              &asn1_oid_id_pkix_on_xmppAddr, jid);
}

/**
 * Add a Microsoft UPN subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param hostname The XMPP address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_ms_upn_name(hx509_context context,
                              hx509_request req,
                              const char *upn)
{
    return add_utf8_other_san(context, &req->san, &asn1_oid_id_pkinit_ms_san,
                              upn);
}

/**
 * Add a dNSName (hostname) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param hostname The fully-qualified hostname.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_dns_name(hx509_context context,
                           hx509_request req,
                           const char *hostname)
{
    GeneralName name;

    memset(&name, 0, sizeof(name));
    name.element = choice_GeneralName_dNSName;
    name.u.dNSName.data = rk_UNCONST(hostname);
    name.u.dNSName.length = strlen(hostname);

    return add_GeneralNames(&req->san, &name);
}

/**
 * Add a dnsSRV (_service.hostname) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param dnssrv The DNS SRV name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_dns_srv(hx509_context context,
                          hx509_request req,
                          const char *dnssrv)
{
    GeneralName gn;
    SRVName n;
    size_t size;
    int ret;

    memset(&n, 0, sizeof(n));
    memset(&gn, 0, sizeof(gn));
    gn.element = choice_GeneralName_otherName;
    gn.u.otherName.type_id.length = 0;
    gn.u.otherName.type_id.components = 0;
    gn.u.otherName.value.data = NULL;
    gn.u.otherName.value.length = 0;
    n.length = strlen(dnssrv);
    n.data = (void *)(uintptr_t)dnssrv;
    ASN1_MALLOC_ENCODE(SRVName,
                       gn.u.otherName.value.data,
                       gn.u.otherName.value.length, &n, &size, ret);
    if (ret == 0)
        ret = der_copy_oid(&asn1_oid_id_pkix_on_dnsSRV, &gn.u.otherName.type_id);
    if (ret == 0)
        ret = add_GeneralNames(&req->san, &gn);
    free_GeneralName(&gn);
    return ret;
}

/**
 * Add an rfc822Name (e-mail address) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param email The e-mail address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_email(hx509_context context,
                        hx509_request req,
                        const char *email)
{
    GeneralName name;

    memset(&name, 0, sizeof(name));
    name.element = choice_GeneralName_rfc822Name;
    name.u.rfc822Name.data = rk_UNCONST(email);
    name.u.rfc822Name.length = strlen(email);

    return add_GeneralNames(&req->san, &name);
}

/**
 * Add a registeredID (OID) subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param oid The OID.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_registered(hx509_context context,
                             hx509_request req,
                             heim_oid *oid)
{
    GeneralName name;
    int ret;

    memset(&name, 0, sizeof(name));
    name.element = choice_GeneralName_registeredID;
    ret = der_copy_oid(oid, &name.u.registeredID);
    if (ret)
        return ret;
    ret = add_GeneralNames(&req->san, &name);
    free_GeneralName(&name);
    return ret;
}

/**
 * Add a Kerberos V5 principal subject alternative name to a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param princ The Kerberos principal name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_add_pkinit(hx509_context context,
                         hx509_request req,
                         const char *princ)
{
    KRB5PrincipalName kn;
    GeneralName gn;
    int ret;

    memset(&kn, 0, sizeof(kn));
    memset(&gn, 0, sizeof(gn));
    gn.element = choice_GeneralName_otherName;
    gn.u.otherName.type_id.length = 0;
    gn.u.otherName.type_id.components = 0;
    gn.u.otherName.value.data = NULL;
    gn.u.otherName.value.length = 0;
    ret = der_copy_oid(&asn1_oid_id_pkinit_san, &gn.u.otherName.type_id);
    if (ret == 0)
        ret = _hx509_make_pkinit_san(context, princ, &gn.u.otherName.value);
    if (ret == 0)
        ret = add_GeneralNames(&req->san, &gn);
    free_GeneralName(&gn);
    return ret;
}

/* XXX Add DNSSRV and other SANs */

static int
get_exts(hx509_context context,
         const hx509_request req,
         Extensions *exts)
{
    size_t size;
    int ret = 0;

    exts->val = NULL;
    exts->len = 0;

    if (KeyUsage2int(req->ku)) {
        Extension e;

        memset(&e, 0, sizeof(e));
        /* The critical field needs to be made DEFAULT FALSE... */
        e.critical = 1;
        if (ret == 0)
            ASN1_MALLOC_ENCODE(KeyUsage, e.extnValue.data, e.extnValue.length,
                               &req->ku, &size, ret);
        if (ret == 0)
            ret = der_copy_oid(&asn1_oid_id_x509_ce_keyUsage, &e.extnID);
        if (ret == 0)
            ret = add_Extensions(exts, &e);
        free_Extension(&e);
    }
    if (ret == 0 && req->eku.len) {
        Extension e;

        memset(&e, 0, sizeof(e));
        e.critical = 1;
        if (ret == 0)
            ASN1_MALLOC_ENCODE(ExtKeyUsage,
                               e.extnValue.data, e.extnValue.length,
                               &req->eku, &size, ret);
        if (ret == 0)
            ret = der_copy_oid(&asn1_oid_id_x509_ce_extKeyUsage, &e.extnID);
        if (ret == 0)
            ret = add_Extensions(exts, &e);
        free_Extension(&e);
    }
    if (ret == 0 && req->san.len) {
        Extension e;

        memset(&e, 0, sizeof(e));
        /*
         * SANs are critical when the subject Name is empty.
         *
         * The empty DN check could probably stand to be a function we export.
         */
        e.critical = FALSE;
        if (req->name &&
            req->name->der_name.element == choice_Name_rdnSequence &&
            req->name->der_name.u.rdnSequence.len == 0)
            e.critical = 1;
        if (ret == 0)
            ASN1_MALLOC_ENCODE(GeneralNames,
                               e.extnValue.data, e.extnValue.length,
                               &req->san,
                               &size, ret);
        if (ret == 0)
            ret = der_copy_oid(&asn1_oid_id_x509_ce_subjectAltName, &e.extnID);
        if (ret == 0)
            ret = add_Extensions(exts, &e);
        free_Extension(&e);
    }

    return ret;
}

/**
 * Get the KU/EKUs/SANs set on a request as a DER-encoding of Extensions.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param exts_der Where to put the DER-encoded Extensions.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_exts(hx509_context context,
                       const hx509_request req,
                       heim_octet_string *exts_der)
{
    Extensions exts;
    size_t size;
    int ret;

    exts_der->data = NULL;
    exts_der->length = 0;
    ret = get_exts(context, req, &exts);
    if (ret == 0 && exts.len /* Extensions has a min size constraint of 1 */)
        ASN1_MALLOC_ENCODE(Extensions, exts_der->data, exts_der->length,
                           &exts, &size, ret);
    free_Extensions(&exts);
    return ret;
}

/* XXX Add PEM */

/**
 * Encode a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param signer The private key corresponding to the CSR's subject public key.
 * @param request Where to put the DER-encoded CSR.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_to_pkcs10(hx509_context context,
                        const hx509_request req,
                        const hx509_private_key signer,
                        heim_octet_string *request)
{
    CertificationRequest r;
    Extensions exts;
    heim_octet_string data;
    size_t size;
    int ret;

    request->data = NULL;
    request->length = 0;

    data.length = 0;
    data.data = NULL;

    if (req->name == NULL) {
	hx509_set_error_string(context, 0, EINVAL,
			       "PKCS10 needs to have a subject");
	return EINVAL;
    }

    memset(&r, 0, sizeof(r));

    /* Setup CSR */
    r.certificationRequestInfo.version = pkcs10_v1;
    ret = copy_Name(&req->name->der_name,
		    &r.certificationRequestInfo.subject);
    if (ret == 0)
        ret = copy_SubjectPublicKeyInfo(&req->key,
                                        &r.certificationRequestInfo.subjectPKInfo);

    /* Encode extReq attribute with requested Certificate Extensions */

    if (ret == 0)
        ret = get_exts(context, req, &exts);
    if (ret == 0 && exts.len) {
        Attribute *a = NULL; /* Quiet VC */
        heim_any extns;

        extns.data = NULL;
        extns.length = 0;
        r.certificationRequestInfo.attributes =
            calloc(1, sizeof(r.certificationRequestInfo.attributes[0]));
        if (r.certificationRequestInfo.attributes == NULL)
            ret = ENOMEM;
        if (ret == 0) {
            r.certificationRequestInfo.attributes[0].len = 1;
            r.certificationRequestInfo.attributes[0].val =
                calloc(1, sizeof(r.certificationRequestInfo.attributes[0].val[0]));
            if (r.certificationRequestInfo.attributes[0].val == NULL)
                ret = ENOMEM;
            if (ret == 0)
                a = r.certificationRequestInfo.attributes[0].val;
        }
        if (ret == 0)
            ASN1_MALLOC_ENCODE(Extensions, extns.data, extns.length,
                               &exts, &size, ret);
        if (ret == 0 && a)
            ret = der_copy_oid(&asn1_oid_id_pkcs9_extReq, &a->type);
        if (ret == 0)
            ret = add_AttributeValues(&a->value, &extns);
        free_heim_any(&extns);
    }

    /* Encode CSR body for signing */
    if (ret == 0)
        ASN1_MALLOC_ENCODE(CertificationRequestInfo, data.data, data.length,
                           &r.certificationRequestInfo, &size, ret);
    if (ret == 0 && data.length != size)
	abort();

    /* Self-sign CSR body */
    if (ret == 0) {
        ret = _hx509_create_signature_bitstring(context, signer,
                                                _hx509_crypto_default_sig_alg,
                                                &data,
                                                &r.signatureAlgorithm,
                                                &r.signature);
    }
    free(data.data);

    /* Encode CSR */
    if (ret == 0)
        ASN1_MALLOC_ENCODE(CertificationRequest, request->data, request->length,
                           &r, &size, ret);
    if (ret == 0 && request->length != size)
	abort();

    free_CertificationRequest(&r);
    free_Extensions(&exts);
    return ret;
}

/**
 * Parse an encoded CSR and verify its self-signature.
 *
 * @param context An hx509 context.
 * @param der The DER-encoded CSR.
 * @param req Where to put request object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_parse_der(hx509_context context,
                        heim_octet_string *der,
                        hx509_request *req)
{
    CertificationRequestInfo *rinfo = NULL;
    CertificationRequest r;
    hx509_cert signer = NULL;
    Extensions exts;
    size_t i, size;
    int ret;

    memset(&exts, 0, sizeof(exts));

    /* Initial setup and decoding of CSR */
    ret = hx509_request_init(context, req);
    if (ret)
        return ret;
    ret = decode_CertificationRequest(der->data, der->length, &r, &size);
    if (ret) {
        hx509_set_error_string(context, 0, ret, "Failed to decode CSR");
        free(*req);
        *req = NULL;
        return ret;
    }
    rinfo = &r.certificationRequestInfo;

    /*
     * Setup a 'signer' for verifying the self-signature for proof of
     * possession.
     *
     * Sadly we need a "certificate" here because _hx509_verify_signature_*()
     * functions want one as a signer even though all the verification
     * functions that use the signer argument only ever use the spki of the
     * signer certificate.
     *
     * FIXME Change struct signature_alg's verify_signature's prototype to use
     *       an spki instead of an hx509_cert as the signer!  The we won't have
     *       to do this.
     */
    if (ret == 0) {
        Certificate c;
        memset(&c, 0, sizeof(c));
        c.tbsCertificate.subjectPublicKeyInfo = rinfo->subjectPKInfo;
        if ((signer = hx509_cert_init(context, &c, NULL)) == NULL)
            ret = ENOMEM;
    }

    /* Verify the signature */
    if (ret == 0)
        ret = _hx509_verify_signature_bitstring(context, signer,
                                                &r.signatureAlgorithm,
                                                &rinfo->_save,
                                                &r.signature);
    if (ret)
        hx509_set_error_string(context, 0, ret,
                               "CSR signature verification failed");
    hx509_cert_free(signer);

    /* Populate the hx509_request */
    if (ret == 0)
        ret = hx509_request_set_SubjectPublicKeyInfo(context, *req,
                                                     &rinfo->subjectPKInfo);
    if (ret == 0)
        ret = _hx509_name_from_Name(&rinfo->subject, &(*req)->name);

    /* Extract KUs, EKUs, and SANs from the CSR's attributes */
    if (ret || !rinfo->attributes || !rinfo->attributes[0].len)
        goto out;

    for (i = 0; ret == 0 && i < rinfo->attributes[0].len; i++) {
        Attribute *a = &rinfo->attributes[0].val[i];
        heim_any *av = NULL;

        /* We only support Extensions request attributes */
        if (der_heim_oid_cmp(&a->type, &asn1_oid_id_pkcs9_extReq) != 0) {
            char *oidstr = NULL;

            /*
             * We need an HX509_TRACE facility for this sort of warning.
             *
             * We'd put the warning in the context and then allow the caller to
             * extract and reset the warning.
             *
             * FIXME
             */
            der_print_heim_oid(&a->type, '.', &oidstr);
            warnx("Unknown or unsupported CSR attribute %s",
                  oidstr ? oidstr : "<error decoding OID>");
            free(oidstr);
            continue;
        }
        if (!a->value.val)
            continue;

        av = a->value.val;
        ret = decode_Extensions(av->data, av->length, &exts, NULL);
        if (ret) {
            hx509_set_error_string(context, 0, ret,
                                   "CSR signature verification failed "
                                   "due to invalid extReq attribute");
            goto out;
        }
    }
    for (i = 0; ret == 0 && i < exts.len; i++) {
        const char *what = "";
        Extension *e = &exts.val[i];

        if (der_heim_oid_cmp(&e->extnID,
                             &asn1_oid_id_x509_ce_keyUsage) == 0) {
            ret = decode_KeyUsage(e->extnValue.data, e->extnValue.length,
                                  &(*req)->ku, NULL);
            what = "keyUsage";
            /*
             * Count all KUs as one requested extension to be authorized,
             * though the caller will have to check the KU values individually.
             */
            if (KeyUsage2int((*req)->ku) & ~KeyUsage2int(int2KeyUsage(~0)))
                (*req)->nunsupported++;
        } else if (der_heim_oid_cmp(&e->extnID,
                                    &asn1_oid_id_x509_ce_extKeyUsage) == 0) {
            ret = decode_ExtKeyUsage(e->extnValue.data, e->extnValue.length,
                                     &(*req)->eku, NULL);
            what = "extKeyUsage";

            /*
             * Count each EKU as a separate requested extension to be
             * authorized.
             */
        } else if (der_heim_oid_cmp(&e->extnID,
                                    &asn1_oid_id_x509_ce_subjectAltName) == 0) {
            ret = decode_GeneralNames(e->extnValue.data, e->extnValue.length,
                                      &(*req)->san, NULL);
            what = "subjectAlternativeName";

            /*
             * Count each SAN as a separate requested extension to be
             * authorized.
             */
        } else {
            char *oidstr = NULL;

            (*req)->nunsupported++;

            /*
             * We need an HX509_TRACE facility for this sort of warning.
             *
             * We'd put the warning in the context and then allow the caller to
             * extract and reset the warning.
             *
             * FIXME
             */
            der_print_heim_oid(&e->extnID, '.', &oidstr);
            warnx("Unknown or unsupported CSR extension request %s",
                  oidstr ? oidstr : "<error decoding OID>");
            free(oidstr);
        }
        if (ret) {
            hx509_set_error_string(context, 0, ret,
                                   "CSR signature verification failed "
                                   "due to invalid %s extension", what);
            break;
        }
    }

out:
    free_CertificationRequest(&r);
    free_Extensions(&exts);
    if (ret)
        hx509_request_free(req);
    return ret;
}

/**
 * Parse an encoded CSR and verify its self-signature.
 *
 * @param context An hx509 context.
 * @param csr The name of a store containing the CSR ("PKCS10:/path/to/file")
 * @param req Where to put request object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_parse(hx509_context context,
                    const char *csr,
                    hx509_request *req)
{
    heim_octet_string d;
    int ret;

    /* XXX Add support for PEM */
    if (strncmp(csr, "PKCS10:", 7) != 0) {
	hx509_set_error_string(context, 0, HX509_UNSUPPORTED_OPERATION,
                               "CSR location does not start with \"PKCS10:\": %s",
                               csr);
	return HX509_UNSUPPORTED_OPERATION;
    }

    ret = rk_undumpdata(csr + 7, &d.data, &d.length);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Could not read %s", csr);
	return ret;
    }

    ret = hx509_request_parse_der(context, &d, req);
    free(d.data);
    if (ret)
        hx509_set_error_string(context, HX509_ERROR_APPEND, ret,
                               " (while parsing CSR from %s)", csr);
    return ret;
}

/**
 * Get some EKU from a CSR.  Usable as an iterator.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param idx The index of the EKU (0 for the first) to return
 * @param out A pointer to a char * variable where the OID will be placed
 *            (caller must free with free())
 *
 * @return Zero on success, HX509_NO_ITEM if no such item exists (denoting
 *         iteration end), or an error.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_get_eku(hx509_request req,
                      size_t idx,
                      char **out)
{
    *out = NULL;
    if (idx >= req->eku.len)
        return HX509_NO_ITEM;
    return der_print_heim_oid(&req->eku.val[idx], '.', out);
}

static int
abitstring_check(abitstring a, size_t n, int idx)
{
    size_t bytes;

    if (idx >= n)
        return HX509_NO_ITEM;

    bytes = (idx + 1) / CHAR_BIT + (((idx + 1) % CHAR_BIT) ? 1 : 0);
    if (a->feat_bytes < bytes)
        return 0;

    return !!(a->feats[idx / CHAR_BIT] & (1UL<<(idx % CHAR_BIT)));
}

/*
 * Sets and returns 0 if not already set, -1 if already set.  Positive return
 * values are system errors.
 */
static int
abitstring_set(abitstring a, size_t n, int idx)
{
    size_t bytes;

    if (idx >= n)
        return HX509_NO_ITEM;

    bytes = n / CHAR_BIT + ((n % CHAR_BIT) ? 1 : 0);
    if (a->feat_bytes < bytes) {
        unsigned char *tmp;

        if ((tmp = realloc(a->feats, bytes)) == NULL)
            return ENOMEM;
        memset(tmp + a->feat_bytes, 0, bytes - a->feat_bytes);
        a->feats = tmp;
        a->feat_bytes = bytes;
    }

    if (!(a->feats[idx / CHAR_BIT] & (1UL<<(idx % CHAR_BIT)))) {
        a->feats[idx / CHAR_BIT] |= 1UL<<(idx % CHAR_BIT);
        return 0;
    }
    return -1;
}

/*
 * Resets and returns 0 if not already reset, -1 if already reset.  Positive
 * return values are system errors.
 */
static int
abitstring_reset(abitstring a, size_t n, int idx)
{
    size_t bytes;

    if (idx >= n)
        return HX509_NO_ITEM;

    bytes = (idx + 1) / CHAR_BIT + (((idx + 1) % CHAR_BIT) ? 1 : 0);
    if (a->feat_bytes >= bytes &&
        (a->feats[idx / CHAR_BIT] & (1UL<<(idx % CHAR_BIT)))) {
        a->feats[idx / CHAR_BIT] &= ~(1UL<<(idx % CHAR_BIT));
        return 0;
    }
    return -1;
}

static int
authorize_feat(hx509_request req, abitstring a, size_t n, int idx)
{
    int ret;

    ret = abitstring_set(a, n, idx);
    switch (ret) {
    case 0:
        req->nauthorized++;
        HEIM_FALLTHROUGH;
    case -1:
        return 0;
    default:
        return ret;
    }
}

static int
reject_feat(hx509_request req, abitstring a, size_t n, int idx)
{
    int ret;

    ret = abitstring_reset(a, n, idx);
    switch (ret) {
    case 0:
        req->nauthorized--;
        HEIM_FALLTHROUGH;
    case -1:
        return 0;
    default:
        return ret;
    }
}

/**
 * Filter the requested KeyUsage and mark it authorized.
 *
 * @param req The hx509_request object.
 * @param ku Permitted KeyUsage
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_request_authorize_ku(hx509_request req, KeyUsage ku)
{
    (void) hx509_request_set_ku(NULL, req, ku);
    req->ku = int2KeyUsage(KeyUsage2int(req->ku) & KeyUsage2int(ku));
    if (KeyUsage2int(ku))
        req->ku_are_authorized = 1;
}

/**
 * Mark a requested EKU as authorized.
 *
 * @param req The hx509_request object.
 * @param idx The index of an EKU that can be fetched with
 *            hx509_request_get_eku()
 *
 * @return Zero on success, an error otherwise.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_authorize_eku(hx509_request req, size_t idx)
{
    return authorize_feat(req, &req->authorized_EKUs, req->eku.len, idx);
}

/**
 * Mark a requested EKU as not authorized.
 *
 * @param req The hx509_request object.
 * @param idx The index of an EKU that can be fetched with
 *            hx509_request_get_eku()
 *
 * @return Zero on success, an error otherwise.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_reject_eku(hx509_request req, size_t idx)
{
    return reject_feat(req, &req->authorized_EKUs, req->eku.len, idx);
}

/**
 * Check if an EKU has been marked authorized.
 *
 * @param req The hx509_request object.
 * @param idx The index of an EKU that can be fetched with
 *            hx509_request_get_eku()
 *
 * @return Non-zero if authorized, zero if not.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_eku_authorized_p(hx509_request req, size_t idx)
{
    return abitstring_check(&req->authorized_EKUs, req->eku.len, idx);
}

/**
 * Mark a requested SAN as authorized.
 *
 * @param req The hx509_request object.
 * @param idx The cursor as modified by a SAN iterator.
 *
 * @return Zero on success, an error otherwise.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_authorize_san(hx509_request req, size_t idx)
{
    return authorize_feat(req, &req->authorized_SANs, req->san.len, idx);
}

/**
 * Mark a requested SAN as not authorized.
 *
 * @param req The hx509_request object.
 * @param idx The cursor as modified by a SAN iterator.
 *
 * @return Zero on success, an error otherwise.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_reject_san(hx509_request req, size_t idx)
{
    return reject_feat(req, &req->authorized_SANs, req->san.len, idx);
}

/**
 * Check if a SAN has been marked authorized.
 *
 * @param req The hx509_request object.
 * @param idx The index of a SAN that can be fetched with
 *            hx509_request_get_san()
 *
 * @return Non-zero if authorized, zero if not.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_san_authorized_p(hx509_request req, size_t idx)
{
    return abitstring_check(&req->authorized_SANs, req->san.len, idx);
}

/**
 * Return the count of unsupported requested certificate extensions.
 *
 * @param req The hx509_request object.
 * @return The number of unsupported certificate extensions requested.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION size_t HX509_LIB_CALL
hx509_request_count_unsupported(hx509_request req)
{
    return req->nunsupported;
}

/**
 * Return the count of as-yet unauthorized certificate extensions requested.
 *
 * @param req The hx509_request object.
 * @return The number of as-yet unauthorized certificate extensions requested.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION size_t HX509_LIB_CALL
hx509_request_count_unauthorized(hx509_request req)
{
    size_t nrequested = req->eku.len + req->san.len +
        (KeyUsage2int(req->ku) ? 1 : 0) + req->nunsupported;

    return nrequested - (req->nauthorized + req->ku_are_authorized);
}

static hx509_san_type
san_map_type(GeneralName *san)
{
    static const struct {
        const heim_oid *oid;
        hx509_san_type type;
    } map[] = {
        { &asn1_oid_id_pkix_on_dnsSRV, HX509_SAN_TYPE_DNSSRV },
        { &asn1_oid_id_pkinit_san, HX509_SAN_TYPE_PKINIT },
        { &asn1_oid_id_pkix_on_xmppAddr, HX509_SAN_TYPE_XMPP },
        { &asn1_oid_id_pkinit_ms_san, HX509_SAN_TYPE_MS_UPN },
        { &asn1_oid_id_pkix_on_permanentIdentifier, HX509_SAN_TYPE_PERMANENT_ID },
        { &asn1_oid_id_on_hardwareModuleName, HX509_SAN_TYPE_HW_MODULE },
    };
    size_t i;

    switch (san->element) {
    case choice_GeneralName_rfc822Name:    return HX509_SAN_TYPE_EMAIL;
    case choice_GeneralName_dNSName:       return HX509_SAN_TYPE_DNSNAME;
    case choice_GeneralName_directoryName: return HX509_SAN_TYPE_DN;
    case choice_GeneralName_registeredID:  return HX509_SAN_TYPE_REGISTERED_ID;
    case choice_GeneralName_otherName: {
        for (i = 0; i < sizeof(map)/sizeof(map[0]); i++)
            if (der_heim_oid_cmp(&san->u.otherName.type_id, map[i].oid) == 0)
                return map[i].type;
    }
        HEIM_FALLTHROUGH;
    default:                               return HX509_SAN_TYPE_UNSUPPORTED;
    }
}

/**
 * Return the count of as-yet unauthorized certificate extensions requested.
 *
 * @param req The hx509_request object.
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION size_t HX509_LIB_CALL
hx509_request_get_san(hx509_request req,
                      size_t idx,
                      hx509_san_type *type,
                      char **out)
{
    struct rk_strpool *pool = NULL;
    GeneralName *san;

    *out = NULL;
    if (idx >= req->san.len)
        return HX509_NO_ITEM;

    san = &req->san.val[idx];
    switch ((*type = san_map_type(san))) {
    case HX509_SAN_TYPE_UNSUPPORTED: return 0;
    case HX509_SAN_TYPE_EMAIL:
        *out = strndup(san->u.rfc822Name.data,
                       san->u.rfc822Name.length);
        break;
    case HX509_SAN_TYPE_DNSNAME:
        *out = strndup(san->u.dNSName.data,
                       san->u.dNSName.length);
        break;
    case HX509_SAN_TYPE_DNSSRV: {
        SRVName name;
        size_t size;
        int ret;

        ret = decode_SRVName(san->u.otherName.value.data,
                             san->u.otherName.value.length, &name, &size);
        if (ret)
            return ret;
        *out = strndup(name.data, name.length);
        break;
    }
    case HX509_SAN_TYPE_PERMANENT_ID: {
        PermanentIdentifier pi;
        size_t size;
        char *s = NULL;
        int ret;

        ret = decode_PermanentIdentifier(san->u.otherName.value.data,
                                         san->u.otherName.value.length,
                                         &pi, &size);
        if (ret == 0 && pi.assigner) {
            ret = der_print_heim_oid(pi.assigner, '.', &s);
            if (ret == 0 &&
                (pool = rk_strpoolprintf(NULL, "%s", s)) == NULL)
                ret = ENOMEM;
        } else if (ret == 0) {
            pool = rk_strpoolprintf(NULL, "-");
        }
        if (ret == 0 &&
            (pool = rk_strpoolprintf(pool, "%s%s",
                                     *pi.identifierValue ? " " : "",
                                     *pi.identifierValue ? *pi.identifierValue : "")) == NULL)
            ret = ENOMEM;
        if (ret == 0 && (*out = rk_strpoolcollect(pool)) == NULL)
            ret = ENOMEM;
        free_PermanentIdentifier(&pi);
        free(s);
        return ret;
    }
    case HX509_SAN_TYPE_HW_MODULE: {
        HardwareModuleName hn;
        size_t size;
        char *s = NULL;
        int ret;

        ret = decode_HardwareModuleName(san->u.otherName.value.data,
                                        san->u.otherName.value.length,
                                        &hn, &size);
        if (ret == 0 && hn.hwSerialNum.length > 256)
            hn.hwSerialNum.length = 256;
        if (ret == 0)
            ret = der_print_heim_oid(&hn.hwType, '.', &s);
        if (ret == 0)
            pool = rk_strpoolprintf(NULL, "%s", s);
        if (ret == 0 && pool)
            pool = rk_strpoolprintf(pool, " %.*s",
                                    (int)hn.hwSerialNum.length,
                                    (char *)hn.hwSerialNum.data);
        if (ret == 0 &&
            (pool == NULL || (*out = rk_strpoolcollect(pool)) == NULL))
            ret = ENOMEM;
        free_HardwareModuleName(&hn);
        return ret;
    }
    case HX509_SAN_TYPE_DN: {
        Name name;

        if (san->u.directoryName.element == choice_Name_rdnSequence) {
            name.element = choice_Name_rdnSequence;
            name.u.rdnSequence = san->u.directoryName.u.rdnSequence;
            return _hx509_Name_to_string(&name, out);
        }
        *type = HX509_SAN_TYPE_UNSUPPORTED;
        return 0;
    }
    case HX509_SAN_TYPE_REGISTERED_ID:
        return der_print_heim_oid(&san->u.registeredID, '.', out);
    case HX509_SAN_TYPE_XMPP:
        HEIM_FALLTHROUGH;
    case HX509_SAN_TYPE_MS_UPN: {
        int ret;

        ret = _hx509_unparse_utf8_string_name(req->context, &pool,
                                              &san->u.otherName.value);
        if ((*out = rk_strpoolcollect(pool)) == NULL)
            return hx509_enomem(req->context);
        return ret;
    }
    case HX509_SAN_TYPE_PKINIT: {
        int ret;

        ret = _hx509_unparse_KRB5PrincipalName(req->context, &pool,
                                               &san->u.otherName.value);
        if ((*out = rk_strpoolcollect(pool)) == NULL)
            return hx509_enomem(req->context);
        return ret;
    }
    default:
        *type = HX509_SAN_TYPE_UNSUPPORTED;
        return 0;
    }
    if (*out == NULL)
        return ENOMEM;
    return 0;
}

/**
 * Display a CSR.
 *
 * @param context An hx509 context.
 * @param req The hx509_request object.
 * @param f A FILE * to print the CSR to.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_request
 */
HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_request_print(hx509_context context, hx509_request req, FILE *f)
{
    uint64_t ku_num;
    size_t i;
    char *s = NULL;
    int ret = 0;

    /*
     * It's really unformatunate that we can't reuse more of the
     * lib/hx509/print.c infrastructure here, as it's too focused on
     * Certificates.
     *
     * For that matter, it's really annoying that CSRs don't more resemble
     * Certificates.  Indeed, an ideal CSR would look like this:
     *
     *      CSRInfo ::= {
     *          desiredTbsCertificate TBSCertificate,
     *          attributes [1] SEQUENCE OF Attribute OPTIONAL,
     *      }
     *      CSR :: = {
     *          csrInfo CSRInfo,
     *          sigAlg AlgorithmIdentifier,
     *          signature BIT STRING
     *      }
     *
     * with everything related to the desired certificate in
     * desiredTbsCertificate and anything not related to the CSR's contents in
     * the 'attributes' field.
     *
     * That wouldn't allow one to have optional desired TBSCertificate
     * features, but hey.  One could express "gimme all or gimme nothing" as an
     * attribute, or "gimme what you can", then check what one got.
     */
    fprintf(f, "PKCS#10 CertificationRequest:\n");

    if (req->name) {
	char *subject;
	ret = hx509_name_to_string(req->name, &subject);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Failed to print name");
	    return ret;
	}
        fprintf(f, "  name: %s\n", subject);
	free(subject);
    }
    /* XXX Use hx509_request_get_ku() accessor */
    if ((ku_num = KeyUsage2int(req->ku))) {
        const struct units *u;
        const char *first = " ";

        fprintf(f, "  key usage:");
        for (u = asn1_KeyUsage_units(); u->name; ++u) {
            if ((ku_num & u->mult)) {
                fprintf(f, "%s%s", first, u->name);
                first = ", ";
                ku_num &= ~u->mult;
            }
        }
        if (ku_num)
            fprintf(f, "%s<unknown-KeyUsage-value(s)>", first);
        fprintf(f, "\n");
    }
    if (req->eku.len) {
        const char *first = " ";

        fprintf(f, "  eku:");
        for (i = 0; ret == 0; i++) {
            free(s); s = NULL;
            ret = hx509_request_get_eku(req, i, &s);
            if (ret)
                break;
            fprintf(f, "%s{%s}", first, s);
            first = ", ";
        }
        fprintf(f, "\n");
    }
    free(s); s = NULL;
    if (ret == HX509_NO_ITEM)
        ret = 0;
    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;

        free(s); s = NULL;
        ret = hx509_request_get_san(req, i, &san_type, &s);
        if (ret)
            break;
        switch (san_type) {
        case HX509_SAN_TYPE_EMAIL:
            fprintf(f, "  san: rfc822Name: %s\n", s);
            break;
        case HX509_SAN_TYPE_DNSNAME:
            fprintf(f, "  san: dNSName: %s\n", s);
            break;
        case HX509_SAN_TYPE_DN:
            fprintf(f, "  san: dn: %s\n", s);
            break;
        case HX509_SAN_TYPE_REGISTERED_ID:
            fprintf(f, "  san: registeredID: %s\n", s);
            break;
        case HX509_SAN_TYPE_XMPP:
            fprintf(f, "  san: xmpp: %s\n", s);
            break;
        case HX509_SAN_TYPE_PKINIT:
            fprintf(f, "  san: pkinit: %s\n", s);
            break;
        case HX509_SAN_TYPE_MS_UPN:
            fprintf(f, "  san: ms-upn: %s\n", s);
            break;
        default:
            fprintf(f, "  san: <SAN type not supported>\n");
            break;
        }
    }
    free(s); s = NULL;
    if (ret == HX509_NO_ITEM)
        ret = 0;
    return ret;
}
