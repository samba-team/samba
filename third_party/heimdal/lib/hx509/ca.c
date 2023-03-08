/*
 * Copyright (c) 2006 - 2010 Kungliga Tekniska Högskolan
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

/**
 * @page page_ca Hx509 CA functions
 *
 * See the library functions here: @ref hx509_ca
 */

struct hx509_ca_tbs {
    hx509_name subject;
    SubjectPublicKeyInfo spki;
    KeyUsage ku;
    ExtKeyUsage eku;
    GeneralNames san;
    CertificatePolicies cps;
    PolicyMappings pms;
    heim_integer serial;
    struct {
	unsigned int proxy:1;
	unsigned int ca:1;
	unsigned int key:1;
	unsigned int serial:1;
	unsigned int domaincontroller:1;
	unsigned int xUniqueID:1;
    } flags;
    time_t notBefore;
    time_t notAfter;
    HeimPkinitPrincMaxLifeSecs pkinitTicketMaxLife;
    int pathLenConstraint; /* both for CA and Proxy */
    CRLDistributionPoints crldp;
    heim_bit_string subjectUniqueID;
    heim_bit_string issuerUniqueID;
    AlgorithmIdentifier *sigalg;
};

/**
 * Allocate an to-be-signed certificate object that will be converted
 * into an certificate.
 *
 * @param context A hx509 context.
 * @param tbs returned to-be-signed certicate object, free with
 * hx509_ca_tbs_free().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_init(hx509_context context, hx509_ca_tbs *tbs)
{
    *tbs = calloc(1, sizeof(**tbs));
    if (*tbs == NULL)
	return ENOMEM;

    return 0;
}

/**
 * Free an To Be Signed object.
 *
 * @param tbs object to free.
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_ca_tbs_free(hx509_ca_tbs *tbs)
{
    if (tbs == NULL || *tbs == NULL)
	return;

    free_SubjectPublicKeyInfo(&(*tbs)->spki);
    free_CertificatePolicies(&(*tbs)->cps);
    free_PolicyMappings(&(*tbs)->pms);
    free_GeneralNames(&(*tbs)->san);
    free_ExtKeyUsage(&(*tbs)->eku);
    der_free_heim_integer(&(*tbs)->serial);
    free_CRLDistributionPoints(&(*tbs)->crldp);
    der_free_bit_string(&(*tbs)->subjectUniqueID);
    der_free_bit_string(&(*tbs)->issuerUniqueID);
    if ((*tbs)->subject)
        hx509_name_free(&(*tbs)->subject);
    if ((*tbs)->sigalg) {
	free_AlgorithmIdentifier((*tbs)->sigalg);
	free((*tbs)->sigalg);
    }

    memset(*tbs, 0, sizeof(**tbs));
    free(*tbs);
    *tbs = NULL;
}

/**
 * Set the absolute time when the certificate is valid from. If not
 * set the current time will be used.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param t time the certificated will start to be valid
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_notBefore(hx509_context context,
			   hx509_ca_tbs tbs,
			   time_t t)
{
    tbs->notBefore = t;
    return 0;
}

/**
 * Set the absolute time when the certificate is valid to.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param t time when the certificate will expire
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_notAfter(hx509_context context,
			   hx509_ca_tbs tbs,
			   time_t t)
{
    tbs->notAfter = t;
    return 0;
}

/**
 * Set the relative time when the certificiate is going to expire.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param delta seconds to the certificate is going to expire.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_notAfter_lifetime(hx509_context context,
				   hx509_ca_tbs tbs,
				   time_t delta)
{
    return hx509_ca_tbs_set_notAfter(context, tbs, time(NULL) + delta);
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_pkinit_max_life(hx509_context context,
                                 hx509_ca_tbs tbs,
                                 time_t max_life)
{
    tbs->pkinitTicketMaxLife = max_life;
    return 0;
}

static const struct units templatebits[] = {
    { "ExtendedKeyUsage", HX509_CA_TEMPLATE_EKU },
    { "KeyUsage", HX509_CA_TEMPLATE_KU },
    { "SPKI", HX509_CA_TEMPLATE_SPKI },
    { "notAfter", HX509_CA_TEMPLATE_NOTAFTER },
    { "notBefore", HX509_CA_TEMPLATE_NOTBEFORE },
    { "serial", HX509_CA_TEMPLATE_SERIAL },
    { "subject", HX509_CA_TEMPLATE_SUBJECT },
    { "pkinitMaxLife", HX509_CA_TEMPLATE_PKINIT_MAX_LIFE },
    { NULL, 0 }
};

/**
 * Make of template units, use to build flags argument to
 * hx509_ca_tbs_set_template() with parse_units().
 *
 * @return an units structure.
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION const struct units * HX509_LIB_CALL
hx509_ca_tbs_template_units(void)
{
    return templatebits;
}

/**
 * Initialize the to-be-signed certificate object from a template certificate.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param flags bit field selecting what to copy from the template
 * certificate.
 * @param cert template certificate.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_template(hx509_context context,
			  hx509_ca_tbs tbs,
			  int flags,
			  hx509_cert cert)
{
    int ret;

    if (flags & HX509_CA_TEMPLATE_SUBJECT) {
	if (tbs->subject)
	    hx509_name_free(&tbs->subject);
	ret = hx509_cert_get_subject(cert, &tbs->subject);
	if (ret) {
	    hx509_set_error_string(context, 0, ret,
				   "Failed to get subject from template");
	    return ret;
	}
    }
    if (flags & HX509_CA_TEMPLATE_SERIAL) {
	der_free_heim_integer(&tbs->serial);
	ret = hx509_cert_get_serialnumber(cert, &tbs->serial);
	tbs->flags.serial = !ret;
	if (ret) {
	    hx509_set_error_string(context, 0, ret,
				   "Failed to copy serial number");
	    return ret;
	}
    }
    if (flags & HX509_CA_TEMPLATE_NOTBEFORE)
	tbs->notBefore = hx509_cert_get_notBefore(cert);
    if (flags & HX509_CA_TEMPLATE_NOTAFTER)
	tbs->notAfter = hx509_cert_get_notAfter(cert);
    if (flags & HX509_CA_TEMPLATE_SPKI) {
	free_SubjectPublicKeyInfo(&tbs->spki);
	ret = hx509_cert_get_SPKI(context, cert, &tbs->spki);
	tbs->flags.key = !ret;
	if (ret)
	    return ret;
    }
    if (flags & HX509_CA_TEMPLATE_KU) {
	ret = _hx509_cert_get_keyusage(context, cert, &tbs->ku);
	if (ret)
	    return ret;
    }
    if (flags & HX509_CA_TEMPLATE_EKU) {
	ExtKeyUsage eku;
	size_t i;
	ret = _hx509_cert_get_eku(context, cert, &eku);
	if (ret)
	    return ret;
	for (i = 0; i < eku.len; i++) {
	    ret = hx509_ca_tbs_add_eku(context, tbs, &eku.val[i]);
	    if (ret) {
		free_ExtKeyUsage(&eku);
		return ret;
	    }
	}
	free_ExtKeyUsage(&eku);
    }
    if (flags & HX509_CA_TEMPLATE_PKINIT_MAX_LIFE) {
        time_t max_life;

        if ((max_life = hx509_cert_get_pkinit_max_life(context, cert, 0)) > 0)
            hx509_ca_tbs_set_pkinit_max_life(context, tbs, max_life);
    }
    return 0;
}

/**
 * Make the to-be-signed certificate object a CA certificate. If the
 * pathLenConstraint is negative path length constraint is used.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param pathLenConstraint path length constraint, negative, no
 * constraint.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_ca(hx509_context context,
		    hx509_ca_tbs tbs,
		    int pathLenConstraint)
{
    tbs->flags.ca = 1;
    tbs->pathLenConstraint = pathLenConstraint;
    return 0;
}

/**
 * Make the to-be-signed certificate object a proxy certificate. If the
 * pathLenConstraint is negative path length constraint is used.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param pathLenConstraint path length constraint, negative, no
 * constraint.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_proxy(hx509_context context,
		       hx509_ca_tbs tbs,
		       int pathLenConstraint)
{
    tbs->flags.proxy = 1;
    tbs->pathLenConstraint = pathLenConstraint;
    return 0;
}


/**
 * Make the to-be-signed certificate object a windows domain controller certificate.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_domaincontroller(hx509_context context,
				  hx509_ca_tbs tbs)
{
    tbs->flags.domaincontroller = 1;
    return 0;
}

/**
 * Set the subject public key info (SPKI) in the to-be-signed certificate
 * object. SPKI is the public key and key related parameters in the
 * certificate.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param spki subject public key info to use for the to-be-signed certificate object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_spki(hx509_context context,
		      hx509_ca_tbs tbs,
		      const SubjectPublicKeyInfo *spki)
{
    int ret;
    free_SubjectPublicKeyInfo(&tbs->spki);
    ret = copy_SubjectPublicKeyInfo(spki, &tbs->spki);
    tbs->flags.key = !ret;
    return ret;
}

/**
 * Set the serial number to use for to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param serialNumber serial number to use for the to-be-signed
 * certificate object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_serialnumber(hx509_context context,
			      hx509_ca_tbs tbs,
			      const heim_integer *serialNumber)
{
    int ret;
    der_free_heim_integer(&tbs->serial);
    ret = der_copy_heim_integer(serialNumber, &tbs->serial);
    tbs->flags.serial = !ret;
    return ret;
}

/**
 * Copy elements of a CSR into a TBS, but only if all of them are authorized.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param req CSR
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_from_csr(hx509_context context,
	                  hx509_ca_tbs tbs,
	                  hx509_request req)
{
    hx509_san_type san_type;
    heim_oid oid = { 0, 0 };
    KeyUsage ku;
    size_t i;
    char *s = NULL;
    int ret;

    if (hx509_request_count_unauthorized(req)) {
        hx509_set_error_string(context, 0, ENOMEM, "out of memory");
        return EACCES;
    }

    ret = hx509_request_get_ku(context, req, &ku);
    if (ret == 0 && KeyUsage2int(ku))
        ret = hx509_ca_tbs_add_ku(context, tbs, ku);

    for (i = 0; ret == 0; i++) {
        free(s); s = NULL;
        der_free_oid(&oid);
        ret = hx509_request_get_eku(req, i, &s);
        if (ret == 0)
            ret = der_parse_heim_oid(s, ".", &oid);
        if (ret == 0)
            ret = hx509_ca_tbs_add_eku(context, tbs, &oid);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    for (i = 0; ret == 0; i++) {
        free(s); s = NULL;
        ret = hx509_request_get_san(req, i, &san_type, &s);
        if (ret == 0)
            ret = hx509_ca_tbs_add_san(context, tbs, san_type, s);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    der_free_oid(&oid);
    free(s);
    return ret;
}

/**
 * An an extended key usage to the to-be-signed certificate object.
 * Duplicates will detected and not added.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param oid extended key usage to add.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_ku(hx509_context context,
		    hx509_ca_tbs tbs,
		    KeyUsage ku)
{
    tbs->ku = ku;
    return 0;
}

/**
 * An an extended key usage to the to-be-signed certificate object.
 * Duplicates will detected and not added.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param oid extended key usage to add.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_eku(hx509_context context,
		     hx509_ca_tbs tbs,
		     const heim_oid *oid)
{
    void *ptr;
    int ret;
    unsigned i;

    /* search for duplicates */
    for (i = 0; i < tbs->eku.len; i++) {
	if (der_heim_oid_cmp(oid, &tbs->eku.val[i]) == 0)
	    return 0;
    }

    ptr = realloc(tbs->eku.val, sizeof(tbs->eku.val[0]) * (tbs->eku.len + 1));
    if (ptr == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }
    tbs->eku.val = ptr;
    ret = der_copy_oid(oid, &tbs->eku.val[tbs->eku.len]);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "out of memory");
	return ret;
    }
    tbs->eku.len += 1;
    return 0;
}

/**
 * Add a certificate policy to the to-be-signed certificate object.  Duplicates
 * will detected and not added.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param oid policy OID.
 * @param cps_uri CPS URI to qualify policy with.
 * @param user_notice user notice display text to qualify policy with.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_pol(hx509_context context,
		     hx509_ca_tbs tbs,
		     const heim_oid *oid,
                     const char *cps_uri,
                     const char *user_notice)
{
    PolicyQualifierInfos pqis;
    PolicyQualifierInfo pqi;
    PolicyInformation pi;
    size_t i, size;
    int ret = 0;

    /* search for duplicates */
    for (i = 0; i < tbs->cps.len; i++) {
	if (der_heim_oid_cmp(oid, &tbs->cps.val[i].policyIdentifier) == 0)
	    return 0;
    }

    memset(&pi, 0, sizeof(pi));
    memset(&pqi, 0, sizeof(pqi));
    memset(&pqis, 0, sizeof(pqis));

    pi.policyIdentifier = *oid;
    if (cps_uri) {
        CPSuri uri;

        uri.length = strlen(cps_uri);
        uri.data = (void *)(uintptr_t)cps_uri;
        pqi.policyQualifierId = asn1_oid_id_pkix_qt_cps;

	ASN1_MALLOC_ENCODE(CPSuri,
			   pqi.qualifier.data,
			   pqi.qualifier.length,
			   &uri, &size, ret);
        if (ret == 0) {
            ret = add_PolicyQualifierInfos(&pqis, &pqi);
            free_heim_any(&pqi.qualifier);
        }
    }
    if (ret == 0 && user_notice) {
        DisplayText dt;
        UserNotice un;

        dt.element = choice_DisplayText_utf8String;
        dt.u.utf8String = (void *)(uintptr_t)user_notice;
        un.explicitText = &dt;
        un.noticeRef = 0;

        pqi.policyQualifierId = asn1_oid_id_pkix_qt_unotice;
	ASN1_MALLOC_ENCODE(UserNotice,
			   pqi.qualifier.data,
			   pqi.qualifier.length,
			   &un, &size, ret);
        if (ret == 0) {
            ret = add_PolicyQualifierInfos(&pqis, &pqi);
            free_heim_any(&pqi.qualifier);
        }
    }

    pi.policyQualifiers = pqis.len ? &pqis : 0;

    if (ret == 0)
        ret = add_CertificatePolicies(&tbs->cps, &pi);

    free_PolicyQualifierInfos(&pqis);
    return ret;
}

/**
 * Add a certificate policy mapping to the to-be-signed certificate object.
 * Duplicates will detected and not added.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param issuer issuerDomainPolicy policy OID.
 * @param subject subjectDomainPolicy policy OID.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_pol_mapping(hx509_context context,
                             hx509_ca_tbs tbs,
                             const heim_oid *issuer,
                             const heim_oid *subject)
{
    PolicyMapping pm;
    size_t i;

    /* search for duplicates */
    for (i = 0; i < tbs->pms.len; i++) {
        PolicyMapping *pmp = &tbs->pms.val[i];
	if (der_heim_oid_cmp(issuer, &pmp->issuerDomainPolicy) == 0 &&
            der_heim_oid_cmp(subject, &pmp->subjectDomainPolicy) == 0)
	    return 0;
    }

    memset(&pm, 0, sizeof(pm));
    pm.issuerDomainPolicy = *issuer;
    pm.subjectDomainPolicy = *subject;
    return add_PolicyMappings(&tbs->pms, &pm);
}

/**
 * Add CRL distribution point URI to the to-be-signed certificate
 * object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param uri uri to the CRL.
 * @param issuername name of the issuer.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_crl_dp_uri(hx509_context context,
			    hx509_ca_tbs tbs,
			    const char *uri,
			    hx509_name issuername)
{
    DistributionPointName dpn;
    DistributionPoint dp;
    GeneralNames crlissuer;
    GeneralName gn, ign;
    Name in;
    int ret;

    memset(&dp, 0, sizeof(dp));
    memset(&gn, 0, sizeof(gn));
    memset(&ign, 0, sizeof(ign));
    memset(&in, 0, sizeof(in));
    gn.element = choice_GeneralName_uniformResourceIdentifier;
    gn.u.uniformResourceIdentifier.data = rk_UNCONST(uri);
    gn.u.uniformResourceIdentifier.length = strlen(uri);
    dpn.element = choice_DistributionPointName_fullName;
    dpn.u.fullName.len = 1;
    dpn.u.fullName.val = &gn;
    dp.distributionPoint = &dpn;

    if (issuername) {
	ign.element = choice_GeneralName_directoryName;
	ret = hx509_name_to_Name(issuername, &ign.u.directoryName);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "out of memory");
	    return ret;
	}
        crlissuer.len = 1;
        crlissuer.val = &ign;
	dp.cRLIssuer = &crlissuer;
    }

    ret = add_CRLDistributionPoints(&tbs->crldp, &dp);
    if (issuername)
        free_Name(&ign.u.directoryName);

    if (ret)
	hx509_set_error_string(context, 0, ret, "out of memory");
    return ret;
}

/**
 * Add Subject Alternative Name otherName to the to-be-signed
 * certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param oid the oid of the OtherName.
 * @param os data in the other name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_otherName(hx509_context context,
			       hx509_ca_tbs tbs,
			       const heim_oid *oid,
			       const heim_octet_string *os)
{
    GeneralName gn;

    memset(&gn, 0, sizeof(gn));
    gn.element = choice_GeneralName_otherName;
    gn.u.otherName.type_id = *oid;
    gn.u.otherName.value = *os;

    return add_GeneralNames(&tbs->san, &gn);
}

static
int
dequote_strndup(hx509_context context, const char *in, size_t len, char **out)
{
    size_t i, k;
    char *s;

    *out = NULL;
    if ((s = malloc(len + 1)) == NULL) {
        hx509_set_error_string(context, 0, ENOMEM, "malloc: out of memory");
        return ENOMEM;
    }

    for (k = i = 0; i < len; i++) {
        if (in[i] == '\\') {
            switch (in[++i]) {
            case 't': s[k++] = '\t'; break;
            case 'b': s[k++] = '\b'; break;
            case 'n': s[k++] = '\n'; break;
            case '0':
                for (i++; i < len; i++) {
                    if (in[i] == '\0')
                        break;
                    if (in[i++] == '\\' && in[i] == '0')
                        continue;
                    hx509_set_error_string(context, 0,
                                           HX509_PARSING_NAME_FAILED,
                                           "embedded NULs not supported in "
                                           "PKINIT SANs");
                    free(s);
                    return HX509_PARSING_NAME_FAILED;
                }
                break;
            case '\0':
                hx509_set_error_string(context, 0,
                                       HX509_PARSING_NAME_FAILED,
                                       "trailing unquoted backslashes not "
                                       "allowed in PKINIT SANs");
                free(s);
                return HX509_PARSING_NAME_FAILED;
            default:  s[k++] = in[i]; break;
            }
        } else {
            s[k++] = in[i];
        }
    }
    s[k] = '\0';

    *out = s;
    return 0;
}

int
_hx509_make_pkinit_san(hx509_context context,
                       const char *principal,
                       heim_octet_string *os)
{
    KRB5PrincipalName p;
    size_t size;
    int ret;

    os->data = NULL;
    os->length = 0;
    memset(&p, 0, sizeof(p));

    /* Parse principal */
    {
	const char *str, *str_start;
        size_t n, i;

	/* Count number of components */
	n = 1;
	for (str = principal; *str != '\0' && *str != '@'; str++) {
	    if (*str == '\\') {
		if (str[1] == '\0') {
		    ret = HX509_PARSING_NAME_FAILED;
		    hx509_set_error_string(context, 0, ret,
					   "trailing \\ in principal name");
		    goto out;
		}
		str++;
	    } else if(*str == '/') {
		n++;
	    } else if(*str == '@') {
		break;
            }
	}
	if (*str != '@') {
            /* Note that we allow the realm to be empty */
	    ret = HX509_PARSING_NAME_FAILED;
	    hx509_set_error_string(context, 0, ret, "Missing @ in principal");
	    goto out;
	};

	p.principalName.name_string.val =
	    calloc(n, sizeof(*p.principalName.name_string.val));
	if (p.principalName.name_string.val == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "malloc: out of memory");
	    goto out;
	}
	p.principalName.name_string.len = n;
	p.principalName.name_type = KRB5_NT_PRINCIPAL;

	for (i = 0, str_start = str = principal; *str != '\0'; str++) {
	    if (*str=='\\') {
		str++;
	    } else if(*str == '/') {
                /* Note that we allow components to be empty */
                ret = dequote_strndup(context, str_start, str - str_start,
                                      &p.principalName.name_string.val[i++]);
                if (ret)
                    goto out;
                str_start = str + 1;
	    } else if(*str == '@') {
                ret = dequote_strndup(context, str_start, str - str_start,
                                      &p.principalName.name_string.val[i++]);
                if (ret == 0)
                    ret = dequote_strndup(context, str + 1, strlen(str + 1), &p.realm);
                if (ret)
                    goto out;
                break;
            }
	}
    }

    ASN1_MALLOC_ENCODE(KRB5PrincipalName, os->data, os->length, &p, &size, ret);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }
    if (size != os->length)
	_hx509_abort("internal ASN.1 encoder error");

out:
    free_KRB5PrincipalName(&p);
    return ret;
}

static int
add_ia5string_san(hx509_context context,
                  hx509_ca_tbs tbs,
                  const heim_oid *oid,
                  const char *string)
{
    SRVName ustring;
    heim_octet_string os;
    size_t size;
    int ret;

    ustring.data = (void *)(uintptr_t)string;
    ustring.length = strlen(string);

    os.length = 0;
    os.data = NULL;

    ASN1_MALLOC_ENCODE(SRVName, os.data, os.length, &ustring, &size, ret);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	return ret;
    }
    if (size != os.length)
	_hx509_abort("internal ASN.1 encoder error");

    ret = hx509_ca_tbs_add_san_otherName(context, tbs, oid, &os);
    free(os.data);
    return ret;
}

/**
 * Add DNSSRV Subject Alternative Name to the to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param dnssrv An ASCII string of the for _Service.Name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_dnssrv(hx509_context context,
			    hx509_ca_tbs tbs,
			    const char *dnssrv)
{
    size_t i, len;

    /* Minimal DNSSRV input validation */
    if (dnssrv == 0 || dnssrv[0] != '_') {
        hx509_set_error_string(context, 0, EINVAL, "Invalid DNSSRV name");
        return EINVAL;
    }
    for (i = 1, len = strlen(dnssrv); i < len; i++) {
        if (dnssrv[i] == '.' && dnssrv[i + 1] != '\0')
            break;
    }
    if (i == len) {
        hx509_set_error_string(context, 0, EINVAL, "Invalid DNSSRV name");
        return EINVAL;
    }

    return add_ia5string_san(context, tbs,
                             &asn1_oid_id_pkix_on_dnsSRV, dnssrv);
}

/**
 * Add Kerberos Subject Alternative Name to the to-be-signed
 * certificate object. The principal string is a UTF8 string.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param principal Kerberos principal to add to the certificate.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_pkinit(hx509_context context,
			    hx509_ca_tbs tbs,
			    const char *principal)
{
    heim_octet_string os;
    int ret;

    ret = _hx509_make_pkinit_san(context, principal, &os);
    if (ret == 0)
        ret = hx509_ca_tbs_add_san_otherName(context, tbs,
                                             &asn1_oid_id_pkinit_san, &os);
    free(os.data);
    return ret;
}

/*
 *
 */

static int
add_utf8_san(hx509_context context,
	     hx509_ca_tbs tbs,
	     const heim_oid *oid,
	     const char *string)
{
    const PKIXXmppAddr ustring = (const PKIXXmppAddr)(uintptr_t)string;
    heim_octet_string os;
    size_t size;
    int ret;

    os.length = 0;
    os.data = NULL;

    ASN1_MALLOC_ENCODE(PKIXXmppAddr, os.data, os.length, &ustring, &size, ret);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	return ret;
    }
    if (size != os.length)
	_hx509_abort("internal ASN.1 encoder error");

    ret = hx509_ca_tbs_add_san_otherName(context, tbs, oid, &os);
    free(os.data);
    return ret;
}

/**
 * Add Microsoft UPN Subject Alternative Name to the to-be-signed
 * certificate object. The principal string is a UTF8 string.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param principal Microsoft UPN string.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_ms_upn(hx509_context context,
			    hx509_ca_tbs tbs,
			    const char *principal)
{
    return add_utf8_san(context, tbs, &asn1_oid_id_pkinit_ms_san, principal);
}

/**
 * Add a Jabber/XMPP jid Subject Alternative Name to the to-be-signed
 * certificate object. The jid is an UTF8 string.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param jid string of an a jabber id in UTF8.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_jid(hx509_context context,
			 hx509_ca_tbs tbs,
			 const char *jid)
{
    return add_utf8_san(context, tbs, &asn1_oid_id_pkix_on_xmppAddr, jid);
}


/**
 * Add a Subject Alternative Name hostname to to-be-signed certificate
 * object. A domain match starts with ., an exact match does not.
 *
 * Example of a an domain match: .domain.se matches the hostname
 * host.domain.se.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param dnsname a hostame.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_hostname(hx509_context context,
			      hx509_ca_tbs tbs,
			      const char *dnsname)
{
    GeneralName gn;

    memset(&gn, 0, sizeof(gn));
    gn.element = choice_GeneralName_dNSName;
    gn.u.dNSName.data = rk_UNCONST(dnsname);
    gn.u.dNSName.length = strlen(dnsname);

    return add_GeneralNames(&tbs->san, &gn);
}

/**
 * Add a Subject Alternative Name rfc822 (email address) to
 * to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param rfc822Name a string to a email address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_rfc822name(hx509_context context,
				hx509_ca_tbs tbs,
				const char *rfc822Name)
{
    GeneralName gn;

    memset(&gn, 0, sizeof(gn));
    gn.element = choice_GeneralName_rfc822Name;
    gn.u.rfc822Name.data = rk_UNCONST(rfc822Name);
    gn.u.rfc822Name.length = strlen(rfc822Name);

    return add_GeneralNames(&tbs->san, &gn);
}

/*
 * PermanentIdentifier is one SAN for naming devices with TPMs after their
 * endorsement keys or EK certificates.  See TPM 2.0 Keys for Device Identity
 * and Attestation, Version 1.00, Revision 2, 9/17/2020 (DRAFT).
 *
 * The text on the form of permanent identifiers for TPM endorsement keys sans
 * certificates is clearly problematic, saying: "When the TPM does not have an
 * EK certificate, the identifierValue is a digest of a concatenation of the
 * UTF8 string “EkPubkey” (terminating NULL not included) with the binary EK
 * public key", but since arbitrary binary is not necessarily valid UTF-8...
 * and since NULs embedded in UTF-8 might be OK in some contexts but really
 * isn't in C (and Heimdal's ASN.1 compiler does not allow NULs in the
 * middle of strings)...  That just cannot be correct.  Since elsewhere the TCG
 * specs use the hex encoding of the SHA-256 digest of the DER encoding of
 * public keys, that's what we should support in Heimdal, and maybe send in a
 * comment.
 *
 * Also, even where one should use hex encoding of the SHA-256 digest of the
 * DER encoding of public keys, how should the public keys be represented?
 * Presumably as SPKIs, with all the required parameters and no more.
 */

/**
 * Add a Subject Alternative Name of PermanentIdentifier type to a to-be-signed
 * certificate object.  The permanent identifier form for TPM endorsement key
 * certificates is the hex encoding of the SHA-256 digest of the DER encoding
 * of the certificate.  The permanent identifier form for TPM endorsement keys
 * are of the form "EkPubkey<public-key>", where the form of <public-key> is
 * not well specified at this point.  It is the caller's responsibility to
 * format the identifierValue.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param str permanent identifier name in the form "[<assigner-oid>]:[<id>]".
 * @param assigner The OID of an assigner.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_permanentIdentifier_string(hx509_context context,
                                                hx509_ca_tbs tbs,
                                                const char *str)
{
    const heim_oid *found = NULL;
    heim_oid oid;
    const char *oidstr, *id;
    char *freeme, *p;
    int ret;

    memset(&oid, 0, sizeof(oid));
    if ((freeme = strdup(str)) == NULL)
        return hx509_enomem(context);

    oidstr = freeme;
    p = strchr(freeme, ':');
    if (!p) {
        hx509_set_error_string(context, 0, EINVAL,
                               "Invalid PermanentIdentifier string (should be \"[<oid>]:[<id>]\")",
                               oidstr);
        free(freeme);
        return EINVAL;
    }
    if (p) {
        *(p++) = '\0';
        id = p;
    }
    if (oidstr[0] != '\0') {
        ret = der_find_heim_oid_by_name(oidstr, &found);
        if (ret) {
            ret = der_parse_heim_oid(oidstr, " .", &oid);
            if (ret == 0)
                found = &oid;
        }
    }
    ret = hx509_ca_tbs_add_san_permanentIdentifier(context, tbs, id, found);
    if (found == &oid)
        der_free_oid(&oid);
    free(freeme);
    return ret;
}

/**
 * Add a Subject Alternative Name of PermanentIdentifier type to a to-be-signed
 * certificate object.  The permanent identifier form for TPM endorsement key
 * certificates is the hex encoding of the SHA-256 digest of the DER encoding
 * of the certificate.  The permanent identifier form for TPM endorsement keys
 * are of the form "EkPubkey<public-key>", where the form of <public-key> is
 * not well specified at this point.  It is the caller's responsibility to
 * format the identifierValue.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param identifierValue The permanent identifier name.
 * @param assigner The OID of an assigner.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_permanentIdentifier(hx509_context context,
                                         hx509_ca_tbs tbs,
                                         const char *identifierValue,
                                         const heim_oid *assigner)
{
    PermanentIdentifier pi;
    heim_utf8_string s = (void *)(uintptr_t)identifierValue;
    heim_octet_string os;
    size_t size;
    int ret;

    pi.identifierValue = &s;
    pi.assigner = (heim_oid*)(uintptr_t)assigner;
    os.length = 0;
    os.data = NULL;

    ASN1_MALLOC_ENCODE(PermanentIdentifier, os.data, os.length, &pi, &size,
                       ret);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	return ret;
    }
    if (size != os.length)
	_hx509_abort("internal ASN.1 encoder error");

    ret = hx509_ca_tbs_add_san_otherName(context, tbs,
                                         &asn1_oid_id_pkix_on_permanentIdentifier,
                                         &os);
    free(os.data);
    return ret;
}

/**
 * Add a Subject Alternative Name of HardwareModuleName type to a to-be-signed
 * certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param str a string of the form "<oid>:<serial>".
 * @param hwserial The serial number.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_hardwareModuleName_string(hx509_context context,
                                               hx509_ca_tbs tbs,
                                               const char *str)
{
    const heim_oid *found = NULL;
    heim_oid oid;
    const char *oidstr, *sno;
    char *freeme, *p;
    int ret;

    memset(&oid, 0, sizeof(oid));
    if ((freeme = strdup(str)) == NULL)
        return hx509_enomem(context);

    oidstr = freeme;
    p = strchr(freeme, ':');
    if (!p) {
        hx509_set_error_string(context, 0, EINVAL,
                               "Invalid HardwareModuleName string (should be "
                               "\"<oid>:<serial>\")",
                               oidstr);
        free(freeme);
        return EINVAL;
    }
    if (p) {
        *(p++) = '\0';
        sno = p;
    }
    if (oidstr[0] == '\0') {
        found = &asn1_oid_tcg_tpm20;
    } else {
        ret = der_find_heim_oid_by_name(oidstr, &found);
        if (ret) {
            ret = der_parse_heim_oid(oidstr, " .", &oid);
            if (ret == 0)
                found = &oid;
        }
    }
    if (!found) {
        hx509_set_error_string(context, 0, EINVAL,
                               "Could not resolve or parse OID \"%s\"",
                               oidstr);
        free(freeme);
        return EINVAL;
    }
    ret = hx509_ca_tbs_add_san_hardwareModuleName(context, tbs, found, sno);
    if (found == &oid)
        der_free_oid(&oid);
    free(freeme);
    return ret;
}

/**
 * Add a Subject Alternative Name of HardwareModuleName type to a to-be-signed
 * certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param hwtype The hardwar module type (e.g., `&asn1_oid_tcg_tpm20').
 * @param hwserial The serial number.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san_hardwareModuleName(hx509_context context,
                                        hx509_ca_tbs tbs,
                                        const heim_oid *hwtype,
                                        const char *hwserial)
{
    HardwareModuleName hm;
    heim_octet_string os;
    size_t size;
    int ret;

    hm.hwType = *hwtype;
    hm.hwSerialNum.data = (void *)(uintptr_t)hwserial;
    hm.hwSerialNum.length = strlen(hwserial);
    os.length = 0;
    os.data = NULL;

    ASN1_MALLOC_ENCODE(HardwareModuleName, os.data, os.length, &hm, &size,
                       ret);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	return ret;
    }
    if (size != os.length)
	_hx509_abort("internal ASN.1 encoder error");

    ret = hx509_ca_tbs_add_san_otherName(context, tbs,
                                         &asn1_oid_id_on_hardwareModuleName,
                                         &os);
    free(os.data);
    return ret;
}

/**
 * Add a Subject Alternative Name of the given type to the
 * to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param rfc822Name a string to a email address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_add_san(hx509_context context,
                     hx509_ca_tbs tbs,
                     hx509_san_type type,
                     const char *s)
{
    switch (type) {
    case HX509_SAN_TYPE_EMAIL:
        return hx509_ca_tbs_add_san_rfc822name(context, tbs, s);
    case HX509_SAN_TYPE_DNSNAME:
        return hx509_ca_tbs_add_san_hostname(context, tbs, s);
    case HX509_SAN_TYPE_DN:
        return ENOTSUP;
    case HX509_SAN_TYPE_REGISTERED_ID:
        return ENOTSUP;
    case HX509_SAN_TYPE_XMPP:
        return hx509_ca_tbs_add_san_jid(context, tbs, s);
    case HX509_SAN_TYPE_PKINIT:
        return hx509_ca_tbs_add_san_pkinit(context, tbs, s);
    case HX509_SAN_TYPE_MS_UPN:
        return hx509_ca_tbs_add_san_ms_upn(context, tbs, s);
    default:
        return ENOTSUP;
    }
}

/**
 * Set the subject name of a to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param subject the name to set a subject.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_subject(hx509_context context,
			 hx509_ca_tbs tbs,
			 hx509_name subject)
{
    if (tbs->subject)
	hx509_name_free(&tbs->subject);
    return hx509_name_copy(context, subject, &tbs->subject);
}

/**
 * Set the issuerUniqueID and subjectUniqueID
 *
 * These are only supposed to be used considered with version 2
 * certificates, replaced by the two extensions SubjectKeyIdentifier
 * and IssuerKeyIdentifier. This function is to allow application
 * using legacy protocol to issue them.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param issuerUniqueID to be set
 * @param subjectUniqueID to be set
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_unique(hx509_context context,
			hx509_ca_tbs tbs,
			const heim_bit_string *subjectUniqueID,
			const heim_bit_string *issuerUniqueID)
{
    int ret;

    der_free_bit_string(&tbs->subjectUniqueID);
    der_free_bit_string(&tbs->issuerUniqueID);

    if (subjectUniqueID) {
	ret = der_copy_bit_string(subjectUniqueID, &tbs->subjectUniqueID);
	if (ret)
	    return ret;
    }

    if (issuerUniqueID) {
	ret = der_copy_bit_string(issuerUniqueID, &tbs->issuerUniqueID);
	if (ret)
	    return ret;
    }

    return 0;
}

/**
 * Expand the the subject name in the to-be-signed certificate object
 * using hx509_name_expand().
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param env environment variable to expand variables in the subject
 * name, see hx509_env_init().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_subject_expand(hx509_context context,
			    hx509_ca_tbs tbs,
			    hx509_env env)
{
    return hx509_name_expand(context, tbs->subject, env);
}

/**
 * Get the name of a to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 *
 * @return An hx509 name.
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION hx509_name HX509_LIB_CALL
hx509_ca_tbs_get_name(hx509_ca_tbs tbs)
{
    return tbs->subject;
}

/**
 * Set signature algorithm on the to be signed certificate
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param sigalg signature algorithm to use
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_tbs_set_signature_algorithm(hx509_context context,
				     hx509_ca_tbs tbs,
				     const AlgorithmIdentifier *sigalg)
{
    int ret;

    tbs->sigalg = calloc(1, sizeof(*tbs->sigalg));
    if (tbs->sigalg == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "Out of memory");
	return ENOMEM;
    }
    ret = copy_AlgorithmIdentifier(sigalg, tbs->sigalg);
    if (ret) {
	free(tbs->sigalg);
	tbs->sigalg = NULL;
	return ret;
    }
    return 0;
}

/*
 *
 */

static int
add_extension(hx509_context context,
	      TBSCertificate *tbsc,
	      int critical_flag,
	      const heim_oid *oid,
	      const heim_octet_string *data)
{
    Extension ext;
    int ret;

    memset(&ext, 0, sizeof(ext));

    ext.critical = critical_flag;
    ret = der_copy_oid(oid, &ext.extnID);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }
    ret = der_copy_octet_string(data, &ext.extnValue);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }
    ret = add_Extensions(tbsc->extensions, &ext);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }
out:
    free_Extension(&ext);
    return ret;
}

static int
build_proxy_prefix(hx509_context context, const Name *issuer, Name *subject)
{
    char *tstr;
    time_t t;
    int ret;

    ret = copy_Name(issuer, subject);
    if (ret) {
	hx509_set_error_string(context, 0, ret,
			       "Failed to copy subject name");
	return ret;
    }

    t = time(NULL);
    ret = asprintf(&tstr, "ts-%lu", (unsigned long)t);
    if (ret == -1 || tstr == NULL) {
	hx509_set_error_string(context, 0, ENOMEM,
			       "Failed to copy subject name");
	return ENOMEM;
    }
    /* prefix with CN=<ts>,...*/
    ret = _hx509_name_modify(context, subject, 1, &asn1_oid_id_at_commonName, tstr);
    free(tstr);
    if (ret)
	free_Name(subject);
    return ret;
}

static int
ca_sign(hx509_context context,
	hx509_ca_tbs tbs,
	hx509_private_key signer,
	const AuthorityKeyIdentifier *ai,
	const Name *issuername,
	hx509_cert *certificate)
{
    heim_error_t error = NULL;
    heim_octet_string data;
    Certificate c;
    TBSCertificate *tbsc;
    size_t size;
    int ret;
    const AlgorithmIdentifier *sigalg;
    time_t notBefore;
    time_t notAfter;

    sigalg = tbs->sigalg;
    if (sigalg == NULL)
	sigalg = _hx509_crypto_default_sig_alg;

    memset(&c, 0, sizeof(c));

    /*
     * Default values are: Valid since 24h ago, valid one year into
     * the future, KeyUsage digitalSignature and keyEncipherment set,
     * and keyCertSign for CA certificates.
     */
    notBefore = tbs->notBefore;
    if (notBefore == 0)
	notBefore = time(NULL) - 3600 * 24;
    notAfter = tbs->notAfter;
    if (notAfter == 0)
	notAfter = time(NULL) + 3600 * 24 * 365;

    if (tbs->flags.ca) {
	tbs->ku.keyCertSign = 1;
	tbs->ku.cRLSign = 1;
    } else if (KeyUsage2int(tbs->ku) == 0) {
	tbs->ku.digitalSignature = 1;
	tbs->ku.keyEncipherment = 1;
    }

    /*
     *
     */

    tbsc = &c.tbsCertificate;

    /* Default subject Name to empty */
    if (tbs->subject == NULL &&
        (ret = hx509_empty_name(context, &tbs->subject)))
        return ret;

    /* Sanity checks */
    if (tbs->flags.key == 0) {
	ret = EINVAL;
	hx509_set_error_string(context, 0, ret, "No public key set");
	return ret;
    }
    /*
     * Don't put restrictions on proxy certificate's subject name, it
     * will be generated below.
     */
    if (!tbs->flags.proxy) {
	if (hx509_name_is_null_p(tbs->subject) && tbs->san.len == 0) {
	    hx509_set_error_string(context, 0, EINVAL,
				   "Empty subject and no SubjectAltNames");
	    return EINVAL;
	}
    }
    if (tbs->flags.ca && tbs->flags.proxy) {
	hx509_set_error_string(context, 0, EINVAL, "Can't be proxy and CA "
			       "at the same time");
	return EINVAL;
    }
    if (tbs->flags.proxy) {
	if (tbs->san.len > 0) {
	    hx509_set_error_string(context, 0, EINVAL,
				   "Proxy certificate is not allowed "
				   "to have SubjectAltNames");
	    return EINVAL;
	}
    }

    /* version         [0]  Version OPTIONAL, -- EXPLICIT nnn DEFAULT 1, */
    tbsc->version = calloc(1, sizeof(*tbsc->version));
    if (tbsc->version == NULL) {
	ret = ENOMEM;
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }
    *tbsc->version = rfc3280_version_3;
    /* serialNumber         CertificateSerialNumber, */
    if (tbs->flags.serial) {
	ret = der_copy_heim_integer(&tbs->serial, &tbsc->serialNumber);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
    } else {
	/*
	 * If no explicit serial number is specified, 20 random bytes should be
	 * sufficiently collision resistant.  Since the serial number must be a
	 * positive integer, ensure minimal ASN.1 DER form by forcing the high
	 * bit off and the next bit on (thus avoiding an all zero first octet).
	 */
	tbsc->serialNumber.length = 20;
	tbsc->serialNumber.data = malloc(tbsc->serialNumber.length);
	if (tbsc->serialNumber.data == NULL){
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	RAND_bytes(tbsc->serialNumber.data, tbsc->serialNumber.length);
	((unsigned char *)tbsc->serialNumber.data)[0] &= 0x7f;
	((unsigned char *)tbsc->serialNumber.data)[0] |= 0x40;
    }
    /* signature            AlgorithmIdentifier, */
    ret = copy_AlgorithmIdentifier(sigalg, &tbsc->signature);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Failed to copy signature alg");
	goto out;
    }
    /* issuer               Name, */
    if (issuername)
	ret = copy_Name(issuername, &tbsc->issuer);
    else
	ret = hx509_name_to_Name(tbs->subject, &tbsc->issuer);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Failed to copy issuer name");
	goto out;
    }
    /* validity             Validity, */
    {
        /*
         * From RFC 5280, section 4.1.2.5:
         *
         *    CAs conforming to this profile MUST always encode certificate
         *    validity dates through the year 2049 as UTCTime; certificate validity
         *    dates in 2050 or later MUST be encoded as GeneralizedTime.
         *    Conforming applications MUST be able to process validity dates that
         *    are encoded in either UTCTime or GeneralizedTime.
         *
         * 2524608000 is seconds since the epoch for 2050-01-01T00:00:00Z.
         *
         * Both, ...u.generalTime and ...u..utcTime are time_t.
         */
        if (notBefore < 1 || (int64_t)notBefore < 2524608000)
            tbsc->validity.notBefore.element = choice_Time_utcTime;
        else
            tbsc->validity.notBefore.element = choice_Time_generalTime;
        tbsc->validity.notBefore.u.generalTime = notBefore;

        if (notAfter < 1 || (int64_t)notAfter < 2524608000)
            tbsc->validity.notAfter.element = choice_Time_utcTime;
        else
            tbsc->validity.notAfter.element = choice_Time_generalTime;
        tbsc->validity.notAfter.u.generalTime = notAfter;
    }
    /* subject              Name, */
    if (tbs->flags.proxy) {
	ret = build_proxy_prefix(context, &tbsc->issuer, &tbsc->subject);
	if (ret)
	    goto out;
    } else {
	ret = hx509_name_to_Name(tbs->subject, &tbsc->subject);
	if (ret) {
	    hx509_set_error_string(context, 0, ret,
				   "Failed to copy subject name");
	    goto out;
	}
    }
    /* subjectPublicKeyInfo SubjectPublicKeyInfo, */
    ret = copy_SubjectPublicKeyInfo(&tbs->spki, &tbsc->subjectPublicKeyInfo);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Failed to copy spki");
	goto out;
    }
    /* issuerUniqueID  [1]  IMPLICIT BIT STRING OPTIONAL */
    if (tbs->issuerUniqueID.length) {
	tbsc->issuerUniqueID = calloc(1, sizeof(*tbsc->issuerUniqueID));
	if (tbsc->issuerUniqueID == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	ret = der_copy_bit_string(&tbs->issuerUniqueID, tbsc->issuerUniqueID);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
    }
    /* subjectUniqueID [2]  IMPLICIT BIT STRING OPTIONAL */
    if (tbs->subjectUniqueID.length) {
	tbsc->subjectUniqueID = calloc(1, sizeof(*tbsc->subjectUniqueID));
	if (tbsc->subjectUniqueID == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}

	ret = der_copy_bit_string(&tbs->subjectUniqueID, tbsc->subjectUniqueID);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
    }

    /* extensions      [3]  EXPLICIT Extensions OPTIONAL */
    tbsc->extensions = calloc(1, sizeof(*tbsc->extensions));
    if (tbsc->extensions == NULL) {
	ret = ENOMEM;
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }

    /* Add the text BMP string Domaincontroller to the cert */
    if (tbs->flags.domaincontroller) {
	data.data = rk_UNCONST("\x1e\x20\x00\x44\x00\x6f\x00\x6d"
			       "\x00\x61\x00\x69\x00\x6e\x00\x43"
			       "\x00\x6f\x00\x6e\x00\x74\x00\x72"
			       "\x00\x6f\x00\x6c\x00\x6c\x00\x65"
			       "\x00\x72");
	data.length = 34;

	ret = add_extension(context, tbsc, 0,
			    &asn1_oid_id_ms_cert_enroll_domaincontroller,
			    &data);
	if (ret)
	    goto out;
    }

    /* Add KeyUsage */
    if (KeyUsage2int(tbs->ku) > 0) {
        ASN1_MALLOC_ENCODE(KeyUsage, data.data, data.length,
                           &tbs->ku, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, 1,
			    &asn1_oid_id_x509_ce_keyUsage, &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add ExtendedKeyUsage */
    if (tbs->eku.len > 0) {
	ASN1_MALLOC_ENCODE(ExtKeyUsage, data.data, data.length,
			   &tbs->eku, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, 1,
			    &asn1_oid_id_x509_ce_extKeyUsage, &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add Subject Alternative Name */
    if (tbs->san.len > 0) {
	ASN1_MALLOC_ENCODE(GeneralNames, data.data, data.length,
			   &tbs->san, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");

        /* The SAN extension is critical if the subject Name is empty */
        ret = add_extension(context, tbsc, hx509_name_is_null_p(tbs->subject),
                            &asn1_oid_id_x509_ce_subjectAltName, &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add Authority Key Identifier */
    if (ai) {
	ASN1_MALLOC_ENCODE(AuthorityKeyIdentifier, data.data, data.length,
			   ai, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, 0,
			    &asn1_oid_id_x509_ce_authorityKeyIdentifier,
			    &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add Subject Key Identifier */
    {
	SubjectKeyIdentifier si;
	unsigned char hash[SHA_DIGEST_LENGTH];

	{
	    EVP_MD_CTX *ctx;

	    ctx = EVP_MD_CTX_create();
	    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
	    EVP_DigestUpdate(ctx, tbs->spki.subjectPublicKey.data,
			     tbs->spki.subjectPublicKey.length / 8);
	    EVP_DigestFinal_ex(ctx, hash, NULL);
	    EVP_MD_CTX_destroy(ctx);
	}

	si.data = hash;
	si.length = sizeof(hash);

	ASN1_MALLOC_ENCODE(SubjectKeyIdentifier, data.data, data.length,
			   &si, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, 0,
			    &asn1_oid_id_x509_ce_subjectKeyIdentifier,
			    &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add BasicConstraints */
    {
	BasicConstraints bc;
	unsigned int path;

	memset(&bc, 0, sizeof(bc));

	if (tbs->flags.ca) {
	    bc.cA = 1;
	    if (tbs->pathLenConstraint >= 0) {
		path = tbs->pathLenConstraint;
		bc.pathLenConstraint = &path;
	    }
	}

	ASN1_MALLOC_ENCODE(BasicConstraints, data.data, data.length,
			   &bc, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	/* Critical if this is a CA */
	ret = add_extension(context, tbsc, tbs->flags.ca,
			    &asn1_oid_id_x509_ce_basicConstraints,
			    &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add Proxy */
    if (tbs->flags.proxy) {
	ProxyCertInfo info;

	memset(&info, 0, sizeof(info));

	if (tbs->pathLenConstraint >= 0) {
	    info.pCPathLenConstraint =
		malloc(sizeof(*info.pCPathLenConstraint));
	    if (info.pCPathLenConstraint == NULL) {
		ret = ENOMEM;
		hx509_set_error_string(context, 0, ret, "Out of memory");
		goto out;
	    }
	    *info.pCPathLenConstraint = tbs->pathLenConstraint;
	}

	ret = der_copy_oid(&asn1_oid_id_pkix_ppl_inheritAll,
			   &info.proxyPolicy.policyLanguage);
	if (ret) {
	    free_ProxyCertInfo(&info);
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}

	ASN1_MALLOC_ENCODE(ProxyCertInfo, data.data, data.length,
			   &info, &size, ret);
	free_ProxyCertInfo(&info);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, 0,
			    &asn1_oid_id_pkix_pe_proxyCertInfo,
			    &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add CRL distribution point */
    if (tbs->crldp.len) {
	ASN1_MALLOC_ENCODE(CRLDistributionPoints, data.data, data.length,
			   &tbs->crldp, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, FALSE,
			    &asn1_oid_id_x509_ce_cRLDistributionPoints,
			    &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add CertificatePolicies */
    if (tbs->cps.len) {
	ASN1_MALLOC_ENCODE(CertificatePolicies, data.data, data.length,
			   &tbs->cps, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
        ret = add_extension(context, tbsc, FALSE,
                            &asn1_oid_id_x509_ce_certificatePolicies, &data);
        free(data.data);
	if (ret)
	    goto out;
    }

    /* Add PolicyMappings */
    if (tbs->cps.len) {
	ASN1_MALLOC_ENCODE(PolicyMappings, data.data, data.length,
			   &tbs->pms, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
        ret = add_extension(context, tbsc, FALSE,
                            &asn1_oid_id_x509_ce_policyMappings, &data);
        free(data.data);
	if (ret)
	    goto out;
    }

    /* Add Heimdal PKINIT ticket max life extension */
    if (tbs->pkinitTicketMaxLife > 0) {
        ASN1_MALLOC_ENCODE(HeimPkinitPrincMaxLifeSecs, data.data, data.length,
                           &tbs->pkinitTicketMaxLife, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
        ret = add_extension(context, tbsc, FALSE,
                            &asn1_oid_id_heim_ce_pkinit_princ_max_life, &data);
        free(data.data);
	if (ret)
	    goto out;
    }

    ASN1_MALLOC_ENCODE(TBSCertificate, data.data, data.length,tbsc, &size, ret);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "malloc out of memory");
	goto out;
    }
    if (data.length != size)
	_hx509_abort("internal ASN.1 encoder error");

    ret = _hx509_create_signature_bitstring(context,
					    signer,
					    sigalg,
					    &data,
					    &c.signatureAlgorithm,
					    &c.signatureValue);
    free(data.data);
    if (ret)
	goto out;

    *certificate = hx509_cert_init(context, &c, &error);
    if (*certificate == NULL) {
	ret = heim_error_get_code(error);
	heim_release(error);
	goto out;
    }

    free_Certificate(&c);

    return 0;

out:
    free_Certificate(&c);
    return ret;
}

static int
get_AuthorityKeyIdentifier(hx509_context context,
			   const Certificate *certificate,
			   AuthorityKeyIdentifier *ai)
{
    SubjectKeyIdentifier si;
    int ret;

    ret = _hx509_find_extension_subject_key_id(certificate, &si);
    if (ret == 0) {
	ai->keyIdentifier = calloc(1, sizeof(*ai->keyIdentifier));
	if (ai->keyIdentifier == NULL) {
	    free_SubjectKeyIdentifier(&si);
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	ret = der_copy_octet_string(&si, ai->keyIdentifier);
	free_SubjectKeyIdentifier(&si);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
    } else {
	GeneralNames gns;
	GeneralName gn;
	Name name;

	memset(&gn, 0, sizeof(gn));
	memset(&gns, 0, sizeof(gns));
	memset(&name, 0, sizeof(name));

	ai->authorityCertIssuer =
	    calloc(1, sizeof(*ai->authorityCertIssuer));
	if (ai->authorityCertIssuer == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	ai->authorityCertSerialNumber =
	    calloc(1, sizeof(*ai->authorityCertSerialNumber));
	if (ai->authorityCertSerialNumber == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}

	/*
	 * XXX unbreak when asn1 compiler handle IMPLICIT
	 *
	 * This is so horrible.
	 */

	ret = copy_Name(&certificate->tbsCertificate.subject, &name);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}

	memset(&gn, 0, sizeof(gn));
	gn.element = choice_GeneralName_directoryName;
	gn.u.directoryName.element = choice_Name_rdnSequence;
	gn.u.directoryName.u.rdnSequence = name.u.rdnSequence;

	ret = add_GeneralNames(&gns, &gn);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}

	ai->authorityCertIssuer->val = gns.val;
	ai->authorityCertIssuer->len = gns.len;

	ret = der_copy_heim_integer(&certificate->tbsCertificate.serialNumber,
				    ai->authorityCertSerialNumber);
	if (ai->authorityCertSerialNumber == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
    }
out:
    if (ret)
	free_AuthorityKeyIdentifier(ai);
    return ret;
}


/**
 * Sign a to-be-signed certificate object with a issuer certificate.
 *
 * The caller needs to at least have called the following functions on the
 * to-be-signed certificate object:
 * - hx509_ca_tbs_init()
 * - hx509_ca_tbs_set_subject()
 * - hx509_ca_tbs_set_spki()
 *
 * When done the to-be-signed certificate object should be freed with
 * hx509_ca_tbs_free().
 *
 * When creating self-signed certificate use hx509_ca_sign_self() instead.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param signer the CA certificate object to sign with (need private key).
 * @param certificate return cerificate, free with hx509_cert_free().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_sign(hx509_context context,
	      hx509_ca_tbs tbs,
	      hx509_cert signer,
	      hx509_cert *certificate)
{
    const Certificate *signer_cert;
    AuthorityKeyIdentifier ai;
    int ret;

    memset(&ai, 0, sizeof(ai));

    signer_cert = _hx509_get_cert(signer);

    ret = get_AuthorityKeyIdentifier(context, signer_cert, &ai);
    if (ret)
	goto out;

    ret = ca_sign(context,
		  tbs,
		  _hx509_cert_private_key(signer),
		  &ai,
		  &signer_cert->tbsCertificate.subject,
		  certificate);

out:
    free_AuthorityKeyIdentifier(&ai);

    return ret;
}

/**
 * Work just like hx509_ca_sign() but signs it-self.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param signer private key to sign with.
 * @param certificate return cerificate, free with hx509_cert_free().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_ca_sign_self(hx509_context context,
		   hx509_ca_tbs tbs,
		   hx509_private_key signer,
		   hx509_cert *certificate)
{
    return ca_sign(context,
		   tbs,
		   signer,
		   NULL,
		   NULL,
		   certificate);
}

/*
 * The following used to be `kdc_issue_certificate()', which was added for
 * kx509 support in the kdc, then adapted for bx509d.  It now has no
 * kdc-specific code and very little krb5-specific code, and is named
 * `hx509_ca_issue_certificate()'.
 */

/* From lib/krb5/principal.c */
#define princ_num_comp(P) ((P)->principalName.name_string.len)
#define princ_type(P) ((P)->principalName.name_type)
#define princ_comp(P) ((P)->principalName.name_string.val)
#define princ_ncomp(P, N) ((P)->principalName.name_string.val[(N)])
#define princ_realm(P) ((P)->realm)

static const char *
princ_get_comp_string(KRB5PrincipalName *principal, unsigned int component)
{
    if (component >= princ_num_comp(principal))
       return NULL;
    return princ_ncomp(principal, component);
}
/* XXX Add unparse_name() */

typedef enum {
    CERT_NOTSUP = 0,
    CERT_CLIENT = 1,
    CERT_SERVER = 2,
    CERT_MIXED  = 3
} cert_type;

static void
frees(char **s)
{
    free(*s);
    *s = NULL;
}

static heim_error_code
count_sans(hx509_request req, size_t *n)
{
    size_t i;
    char *s = NULL;
    int ret = 0;

    *n = 0;
    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;

        ret = hx509_request_get_san(req, i, &san_type, &s);
        if (ret)
            break;
        switch (san_type) {
        case HX509_SAN_TYPE_DNSNAME:
        case HX509_SAN_TYPE_EMAIL:
        case HX509_SAN_TYPE_XMPP:
        case HX509_SAN_TYPE_PKINIT:
        case HX509_SAN_TYPE_MS_UPN:
            (*n)++;
            break;
        default:
            ret = ENOTSUP;
        }
        frees(&s);
    }
    free(s);
    return ret == HX509_NO_ITEM ? 0 : ret;
}

static int
has_sans(hx509_request req)
{
    hx509_san_type san_type;
    char *s = NULL;
    int ret = hx509_request_get_san(req, 0, &san_type, &s);

    frees(&s);
    return ret == HX509_NO_ITEM ? 0 : 1;
}

static cert_type
characterize_cprinc(hx509_context context,
                    KRB5PrincipalName *cprinc)
{
    unsigned int ncomp = princ_num_comp(cprinc);
    const char *comp1 = princ_get_comp_string(cprinc, 1);

    switch (ncomp) {
    case 1:
        return CERT_CLIENT;
    case 2:
        if (strchr(comp1, '.') == NULL)
            return CERT_CLIENT;
        return CERT_SERVER;
    case 3:
        if (strchr(comp1, '.'))
            return CERT_SERVER;
        return CERT_NOTSUP;
    default:
        return CERT_NOTSUP;
    }
}

/* Characterize request as client or server cert req */
static cert_type
characterize(hx509_context context,
             KRB5PrincipalName *cprinc,
             hx509_request req)
{
    heim_error_code ret = 0;
    cert_type res = CERT_NOTSUP;
    size_t i;
    char *s = NULL;
    int want_ekus = 0;

    if (!has_sans(req))
        return characterize_cprinc(context, cprinc);

    for (i = 0; ret == 0; i++) {
        heim_oid oid;

        frees(&s);
        ret = hx509_request_get_eku(req, i, &s);
        if (ret)
            break;

        want_ekus = 1;
        ret = der_parse_heim_oid(s, ".", &oid);
        if (ret)
            break;
        /*
         * If the client wants only a server certificate, then we'll be
         * willing to issue one that may be longer-lived than the client's
         * ticket/token.
         *
         * There may be other server EKUs, but these are the ones we know
         * of.
         */
        if (der_heim_oid_cmp(&asn1_oid_id_pkix_kp_serverAuth, &oid) &&
            der_heim_oid_cmp(&asn1_oid_id_pkix_kp_OCSPSigning, &oid) &&
            der_heim_oid_cmp(&asn1_oid_id_pkix_kp_secureShellServer, &oid))
            res |= CERT_CLIENT;
        else
            res |= CERT_SERVER;
        der_free_oid(&oid);
    }
    frees(&s);
    if (ret == HX509_NO_ITEM)
        ret = 0;

    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;

        frees(&s);
        ret = hx509_request_get_san(req, i, &san_type, &s);
        if (ret)
            break;
        switch (san_type) {
        case HX509_SAN_TYPE_DNSNAME:
            if (!want_ekus)
                res |= CERT_SERVER;
            break;
        case HX509_SAN_TYPE_EMAIL:
        case HX509_SAN_TYPE_XMPP:
        case HX509_SAN_TYPE_PKINIT:
        case HX509_SAN_TYPE_MS_UPN:
            if (!want_ekus)
                res |= CERT_CLIENT;
            break;
        default:
            ret = ENOTSUP;
        }
        if (ret)
            break;
    }
    frees(&s);
    if (ret == HX509_NO_ITEM)
        ret = 0;
    return ret ? CERT_NOTSUP : res;
}

/*
 * Get a configuration sub-tree for kx509 based on what's being requested and
 * by whom.
 *
 * We have a number of cases:
 *
 *  - default certificate (no CSR used, or no certificate extensions requested)
 *     - for client principals
 *     - for service principals
 *  - client certificate requested (CSR used and client-y SANs/EKUs requested)
 *  - server certificate requested (CSR used and server-y SANs/EKUs requested)
 *  - mixed client/server certificate requested (...)
 */
static heim_error_code
get_cf(hx509_context context,
       const heim_config_binding *cf,
       heim_log_facility *logf,
       hx509_request req,
       KRB5PrincipalName *cprinc,
       const heim_config_binding **out)
{
    heim_error_code ret;
    unsigned int ncomp = princ_num_comp(cprinc);
    const char *realm = princ_realm(cprinc);
    const char *comp0 = princ_get_comp_string(cprinc, 0);
    const char *comp1 = princ_get_comp_string(cprinc, 1);
    const char *label = NULL;
    const char *svc = NULL;
    const char *def = NULL;
    cert_type certtype = CERT_NOTSUP;
    size_t nsans = 0;

    *out = NULL;
    if (ncomp == 0) {
        heim_log_msg(context->hcontext, logf, 5, NULL,
                     "Client principal has no components!");
        hx509_set_error_string(context, 0, ret = ENOTSUP,
                               "Client principal has no components!");
        return ret;
    }

    if ((ret = count_sans(req, &nsans)) ||
        (certtype = characterize(context, cprinc, req)) == CERT_NOTSUP) {
        heim_log_msg(context->hcontext, logf, 5, NULL,
                     "Could not characterize CSR");
        hx509_set_error_string(context, 0, ret, "Could not characterize CSR");
        return ret;
    }

    if (nsans) {
        def = "custom";
        /* Client requested some certificate extension, a SAN or EKU */
        switch (certtype) {
        case CERT_MIXED:    label = "mixed";  break;
        case CERT_CLIENT:   label = "client"; break;
        case CERT_SERVER:   label = "server"; break;
        default:
            hx509_set_error_string(context, 0, ret = ENOTSUP,
                                   "Requested SAN/EKU combination not "
                                   "supported");
            return ret;
        }
    } else {
        def = "default";
        /* Default certificate desired */
        if (ncomp == 1) {
            label = "user";
        } else if (ncomp == 2 && strcmp(comp1, "root") == 0) {
            label = "root_user";
        } else if (ncomp == 2 && strcmp(comp1, "admin") == 0) {
            label = "admin_user";
        } else if (strchr(comp1, '.')) {
            label = "hostbased_service";
            svc = comp0;
        } else {
            label = "other";
        }
    }

    *out = heim_config_get_list(context->hcontext, cf, label, svc, NULL);
    if (*out) {
        ret = 0;
    } else {
        heim_log_msg(context->hcontext, logf, 3, NULL,
                     "No configuration for %s %s certificate's realm "
                     "-> %s -> kx509 -> %s%s%s", def, label, realm, label,
                     svc ? " -> " : "", svc ? svc : "");
        hx509_set_error_string(context, 0, EACCES,
                "No configuration for %s %s certificate's realm "
                "-> %s -> kx509 -> %s%s%s", def, label, realm, label,
                svc ? " -> " : "", svc ? svc : "");
    }
    return ret;
}


/*
 * Find and set a certificate template using a configuration sub-tree
 * appropriate to the requesting principal.
 *
 * This allows for the specification of the following in configuration:
 *
 *  - certificates as templates, with ${var} tokens in subjectName attribute
 *    values that will be expanded later
 *  - a plain string with ${var} tokens to use as the subjectName
 *  - EKUs
 *  - whether to include a PKINIT SAN
 */
static heim_error_code
set_template(hx509_context context,
             heim_log_facility *logf,
             const heim_config_binding *cf,
             hx509_ca_tbs tbs)
{
    heim_error_code ret = 0;
    const char *cert_template = NULL;
    const char *subj_name = NULL;
    char **ekus = NULL;

    if (cf == NULL)
        return EACCES; /* Can't happen */

    cert_template = heim_config_get_string(context->hcontext, cf,
                                           "template_cert", NULL);
    subj_name = heim_config_get_string(context->hcontext, cf, "subject_name",
                                       NULL);

    if (cert_template) {
        hx509_certs certs;
        hx509_cert template;

        ret = hx509_certs_init(context, cert_template, 0, NULL, &certs);
        if (ret == 0)
            ret = hx509_get_one_cert(context, certs, &template);
        hx509_certs_free(&certs);
        if (ret) {
            heim_log_msg(context->hcontext, logf, 1, NULL,
                         "Failed to load certificate template from %s",
                         cert_template);
            hx509_set_error_string(context, 0, EACCES,
                                   "Failed to load certificate template from "
                                   "%s", cert_template);
            return ret;
        }

        /*
         * Only take the subjectName, the keyUsage, and EKUs from the template
         * certificate.
         */
        ret = hx509_ca_tbs_set_template(context, tbs,
                                        HX509_CA_TEMPLATE_SUBJECT |
                                        HX509_CA_TEMPLATE_KU |
                                        HX509_CA_TEMPLATE_EKU,
                                        template);
        hx509_cert_free(template);
        if (ret)
            return ret;
    }

    if (subj_name) {
        hx509_name dn = NULL;

        ret = hx509_parse_name(context, subj_name, &dn);
        if (ret == 0)
            ret = hx509_ca_tbs_set_subject(context, tbs, dn);
        hx509_name_free(&dn);
        if (ret)
            return ret;
    }

    if (cert_template == NULL && subj_name == NULL) {
        hx509_name dn = NULL;

        ret = hx509_empty_name(context, &dn);
        if (ret == 0)
            ret = hx509_ca_tbs_set_subject(context, tbs, dn);
        hx509_name_free(&dn);
        if (ret)
            return ret;
    }

    ekus = heim_config_get_strings(context->hcontext, cf, "ekus", NULL);
    if (ekus) {
        size_t i;

        for (i = 0; ret == 0 && ekus[i]; i++) {
            heim_oid oid = { 0, 0 };

            if ((ret = der_find_or_parse_heim_oid(ekus[i], ".", &oid)) == 0)
                ret = hx509_ca_tbs_add_eku(context, tbs, &oid);
            der_free_oid(&oid);
        }
        heim_config_free_strings(ekus);
    }

    /*
     * XXX A KeyUsage template would be nice, but it needs some smarts to
     * remove, e.g., encipherOnly, decipherOnly, keyEncipherment, if the SPKI
     * algorithm does not support encryption.  The same logic should be added
     * to hx509_ca_tbs_set_template()'s HX509_CA_TEMPLATE_KU functionality.
     */
    return ret;
}

/*
 * Find and set a certificate template, set "variables" in `env', and add add
 * default SANs/EKUs as appropriate.
 *
 * TODO:
 *  - lookup a template for the client principal in its HDB entry
 *  - lookup subjectName, SANs for a principal in its HDB entry
 *  - lookup a host-based client principal's HDB entry and add its canonical
 *    name / aliases as dNSName SANs
 *    (this would have to be if requested by the client, perhaps)
 */
static heim_error_code
set_tbs(hx509_context context,
        heim_log_facility *logf,
        const heim_config_binding *cf,
        hx509_request req,
        KRB5PrincipalName *cprinc,
        hx509_env *env,
        hx509_ca_tbs tbs)
{
    KRB5PrincipalName cprinc_no_realm = *cprinc;
    heim_error_code ret;
    unsigned int ncomp = princ_num_comp(cprinc);
    const char *realm = princ_realm(cprinc);
    const char *comp0 = princ_get_comp_string(cprinc, 0);
    const char *comp1 = princ_get_comp_string(cprinc, 1);
    const char *comp2 = princ_get_comp_string(cprinc, 2);
    struct rk_strpool *strpool;
    char *princ_no_realm = NULL;
    char *princ = NULL;

    strpool = _hx509_unparse_kerberos_name(NULL, cprinc);
    if (strpool)
        princ = rk_strpoolcollect(strpool);
    cprinc_no_realm.realm = NULL;
    strpool = _hx509_unparse_kerberos_name(NULL, &cprinc_no_realm);
    if (strpool)
        princ_no_realm = rk_strpoolcollect(strpool);
    if (princ == NULL || princ_no_realm == NULL) {
        free(princ);
        return hx509_enomem(context);
    }
    strpool = NULL;
    ret = hx509_env_add(context, env, "principal-name-without-realm",
                        princ_no_realm);
    if (ret == 0)
        ret = hx509_env_add(context, env, "principal-name", princ);
    if (ret == 0)
        ret = hx509_env_add(context, env, "principal-name-realm",
                            realm);

    /* Populate requested certificate extensions from CSR/CSRPlus if allowed */
    if (ret == 0)
        ret = hx509_ca_tbs_set_from_csr(context, tbs, req);
    if (ret == 0)
        ret = set_template(context, logf, cf, tbs);

    /*
     * Optionally add PKINIT SAN.
     *
     * Adding an id-pkinit-san means the client can use the certificate to
     * initiate PKINIT.  That might seem odd, but it enables a sort of PKIX
     * credential delegation by allowing forwarded Kerberos tickets to be
     * used to acquire PKIX credentials.  Thus this can work:
     *
     *      PKIX (w/ HW token) -> Kerberos ->
     *        PKIX (w/ softtoken) -> Kerberos ->
     *          PKIX (w/ softtoken) -> Kerberos ->
     *            ...
     *
     * Note that we may not have added the PKINIT EKU -- that depends on the
     * template, and host-based service templates might well not include it.
     */
    if (ret == 0 && !has_sans(req) &&
        heim_config_get_bool_default(context->hcontext, cf, FALSE,
                                     "include_pkinit_san", NULL)) {
        ret = hx509_ca_tbs_add_san_pkinit(context, tbs, princ);
    }

    if (ret)
        goto out;

    if (ncomp == 1) {
        const char *email_domain;

        ret = hx509_env_add(context, env, "principal-component0",
                            princ_no_realm);

        /*
         * If configured, include an rfc822Name that's just the client's
         * principal name sans realm @ configured email domain.
         */
        if (ret == 0 && !has_sans(req) &&
            (email_domain = heim_config_get_string(context->hcontext, cf,
                                                   "email_domain", NULL))) {
            char *email;

            if (asprintf(&email, "%s@%s", princ_no_realm, email_domain) == -1 ||
                email == NULL)
                goto enomem;
            ret = hx509_ca_tbs_add_san_rfc822name(context, tbs, email);
            free(email);
        }
    } else if (ncomp == 2 || ncomp == 3) {
        /*
         * 2- and 3-component principal name.
         *
         * We do not have a reliable name-type indicator.  If the second
         * component has a '.' in it then we'll assume that the name is a
         * host-based (2-component) or domain-based (3-component) service
         * principal name.  Else we'll assume it's a two-component admin-style
         * username.
         */

        ret = hx509_env_add(context, env, "principal-component0", comp0);
        if (ret == 0)
            ret = hx509_env_add(context, env, "principal-component1", comp1);
        if (ret == 0 && ncomp == 3)
            ret = hx509_env_add(context, env, "principal-component2", comp2);
        if (ret == 0 && strchr(comp1, '.')) {
            /* Looks like host-based or domain-based service */
            ret = hx509_env_add(context, env, "principal-service-name", comp0);
            if (ret == 0)
                ret = hx509_env_add(context, env, "principal-host-name",
                                    comp1);
            if (ret == 0 && ncomp == 3)
                ret = hx509_env_add(context, env, "principal-domain-name",
                                    comp2);
            if (ret == 0 && !has_sans(req) &&
                heim_config_get_bool_default(context->hcontext, cf, FALSE,
                                             "include_dnsname_san", NULL)) {
                ret = hx509_ca_tbs_add_san_hostname(context, tbs, comp1);
            }
        }
    } else {
        heim_log_msg(context->hcontext, logf, 5, NULL,
                     "kx509/bx509 client %s has too many components!", princ);
        hx509_set_error_string(context, 0, ret = EACCES,
                               "kx509/bx509 client %s has too many "
                               "components!", princ);
    }

out:
    if (ret == ENOMEM)
        goto enomem;
    free(princ_no_realm);
    free(princ);
    return ret;

enomem:
    heim_log_msg(context->hcontext, logf, 0, NULL,
                 "Could not set up TBSCertificate: Out of memory");
    ret = hx509_enomem(context);
    goto out;
}

/*
 * Set the notBefore/notAfter for the certificate to be issued.
 *
 * Here `starttime' is the supplicant's credentials' notBefore equivalent,
 * while `endtime' is the supplicant's credentials' notAfter equivalent.
 *
 * `req_life' is the lifetime requested by the supplicant.
 *
 * `endtime' must be larger than the current time.
 *
 * `starttime' can be zero or negative, in which case the notBefore will be the
 * current time minus five minutes.
 *
 * `endtime', `req_life' and configuration parameters will be used to compute
 * the actual notAfter.
 */
static heim_error_code
tbs_set_times(hx509_context context,
              const heim_config_binding *cf,
              heim_log_facility *logf,
              time_t starttime,
              time_t endtime,
              time_t req_life,
              hx509_ca_tbs tbs)
{
    time_t now = time(NULL);
    time_t force = heim_config_get_time_default(context->hcontext,
                                                cf, 5 * 24 * 3600,
                                                "force_cert_lifetime", NULL);
    time_t clamp = heim_config_get_time_default(context->hcontext, cf, 0,
                                                "max_cert_lifetime", NULL);
    int allow_more = heim_config_get_bool_default(context->hcontext, cf, FALSE,
                                                  "allow_extra_lifetime",
                                                  NULL);
    starttime = starttime > 0 ? starttime : now - 5 * 60;

    if (endtime < now) {
        heim_log_msg(context->hcontext, logf, 3, NULL,
                     "Endtime is in the past");
        hx509_set_error_string(context, 0, ERANGE, "Endtime is in the past");
        return ERANGE;
    }

    /* Apply requested lifetime if shorter or if allowed more */
    if (req_life > 0 && req_life <= endtime - now)
        endtime = now + req_life;
    else if (req_life > 0 && allow_more)
        endtime = now + req_life;

    /* Apply floor */
    if (force > 0 && force > endtime - now)
        endtime = now + force;

    /* Apply ceiling */
    if (clamp > 0 && clamp < endtime - now)
        endtime = now + clamp;

    hx509_ca_tbs_set_notAfter(context, tbs, endtime);
    hx509_ca_tbs_set_notBefore(context, tbs, starttime);
    return 0;
}

/*
 * Build a certifate for `principal' and its CSR.
 *
 * XXX Make `cprinc' a GeneralName!  That's why this is private for now.
 */
heim_error_code
_hx509_ca_issue_certificate(hx509_context context,
                            const heim_config_binding *cf,
                            heim_log_facility *logf,
                            hx509_request req,
                            KRB5PrincipalName *cprinc,
                            time_t starttime,
                            time_t endtime,
                            time_t req_life,
                            int send_chain,
                            hx509_certs *out)
{
    heim_error_code ret;
    const char *ca;
    hx509_ca_tbs tbs = NULL;
    hx509_certs chain = NULL;
    hx509_cert signer = NULL;
    hx509_cert cert = NULL;
    hx509_env env = NULL;
    KeyUsage ku;

    *out = NULL;
    /* Force KU */
    ku = int2KeyUsage(0);
    ku.digitalSignature = 1;
    hx509_request_authorize_ku(req, ku);

    ret = get_cf(context, cf, logf, req, cprinc, &cf);
    if (ret)
        return ret;

    if ((ca = heim_config_get_string(context->hcontext, cf,
                                     "ca", NULL)) == NULL) {
        heim_log_msg(context->hcontext, logf, 3, NULL,
                     "No kx509 CA issuer credential specified");
        hx509_set_error_string(context, 0, ret = EACCES,
                               "No kx509 CA issuer credential specified");
        return ret;
    }

    ret = hx509_ca_tbs_init(context, &tbs);
    if (ret) {
        heim_log_msg(context->hcontext, logf, 0, NULL,
                     "Failed to create certificate: Out of memory");
        return ret;
    }

    /* Lookup a template and set things in `env' and `tbs' as appropriate */
    if (ret == 0)
        ret = set_tbs(context, logf, cf, req, cprinc, &env, tbs);

    /* Populate generic template "env" variables */

    /*
     * The `tbs' and `env' are now complete as to naming and EKUs.
     *
     * We check that the `tbs' is not name-less, after which all remaining
     * failures here will not be policy failures.  So we also log the intent to
     * issue a certificate now.
     */
    if (ret == 0 && hx509_name_is_null_p(hx509_ca_tbs_get_name(tbs)) &&
        !has_sans(req)) {
        heim_log_msg(context->hcontext, logf, 3, NULL,
                     "Not issuing certificate because it would have no names");
        hx509_set_error_string(context, 0, ret = EACCES,
                               "Not issuing certificate because it "
                               "would have no names");
    }
    if (ret)
        goto out;

    /*
     * Still to be done below:
     *
     *  - set certificate spki
     *  - set certificate validity
     *  - expand variables in certificate subject name template
     *  - sign certificate
     *  - encode certificate and chain
     */

    /* Load the issuer certificate and private key */
    {
        hx509_certs certs;
        hx509_query *q;

        ret = hx509_certs_init(context, ca, 0, NULL, &certs);
        if (ret) {
            heim_log_msg(context->hcontext, logf, 1, NULL,
                         "Failed to load CA certificate and private key %s",
                         ca);
            hx509_set_error_string(context, 0, ret, "Failed to load "
                                   "CA certificate and private key %s", ca);
            goto out;
        }
        ret = hx509_query_alloc(context, &q);
        if (ret) {
            hx509_certs_free(&certs);
            goto out;
        }

        hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
        hx509_query_match_option(q, HX509_QUERY_OPTION_KU_KEYCERTSIGN);

        ret = hx509_certs_find(context, certs, q, &signer);
        hx509_query_free(context, q);
        hx509_certs_free(&certs);
        if (ret) {
            heim_log_msg(context->hcontext, logf, 1, NULL,
                         "Failed to find a CA certificate in %s", ca);
            hx509_set_error_string(context, 0, ret,
                                   "Failed to find a CA certificate in %s",
                                   ca);
            goto out;
        }
    }

    /* Populate the subject public key in the TBS context */
    {
        SubjectPublicKeyInfo spki;

        ret = hx509_request_get_SubjectPublicKeyInfo(context,
                                                     req, &spki);
        if (ret == 0)
            ret = hx509_ca_tbs_set_spki(context, tbs, &spki);
        free_SubjectPublicKeyInfo(&spki);
        if (ret)
            goto out;
    }

    /* Work out cert expiration */
    if (ret == 0)
        ret = tbs_set_times(context, cf, logf, starttime, endtime, req_life,
                            tbs);

    /* Expand the subjectName template in the TBS using the env */
    if (ret == 0)
        ret = hx509_ca_tbs_subject_expand(context, tbs, env);
    hx509_env_free(&env);

    /* All done with the TBS, sign/issue the certificate */
    if (ret == 0)
        ret = hx509_ca_sign(context, tbs, signer, &cert);

    /*
     * Gather the certificate and chain into a MEMORY store, being careful not
     * to include private keys in the chain.
     *
     * We could have specified a separate configuration parameter for an hx509
     * store meant to have only the chain and no private keys, but expecting
     * the full chain in the issuer credential store and copying only the certs
     * (but not the private keys) is safer and easier to configure.
     */
    if (ret == 0)
        ret = hx509_certs_init(context, "MEMORY:certs",
                               HX509_CERTS_NO_PRIVATE_KEYS, NULL, out);
    if (ret == 0)
        ret = hx509_certs_add(context, *out, cert);
    if (ret == 0 && send_chain) {
        ret = hx509_certs_init(context, ca,
                               HX509_CERTS_NO_PRIVATE_KEYS, NULL, &chain);
        if (ret == 0)
            ret = hx509_certs_merge(context, *out, chain);
    }

out:
    hx509_certs_free(&chain);
    if (env)
        hx509_env_free(&env);
    if (tbs)
        hx509_ca_tbs_free(&tbs);
    if (cert)
        hx509_cert_free(cert);
    if (signer)
        hx509_cert_free(signer);
    if (ret)
        hx509_certs_free(out);
    return ret;
}
