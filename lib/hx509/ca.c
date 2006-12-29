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
RCSID("$Id$");

struct hx509_ca_tbs {
    hx509_name subject;
    SubjectPublicKeyInfo spki;
    struct {
	ExtKeyUsage *val;
	size_t len;
    } eku;
    GeneralNames san;
    unsigned key_usage;
    struct {
	unsigned int proxy:1;
	unsigned int ca:1;
	unsigned int key:1;
    } flags;
    time_t notBefore;
    time_t notAfter;
    int pathLenConstraint; /* both for CA and Proxy */
};

int
hx509_ca_tbs_init(hx509_context context, hx509_ca_tbs *tbs)
{
    *tbs = calloc(1, sizeof(**tbs));
    if (*tbs == NULL)
	return ENOMEM;

    (*tbs)->subject = NULL;
    (*tbs)->san.len = 0;
    (*tbs)->san.val = NULL;
    (*tbs)->eku.len = 0;
    (*tbs)->eku.val = NULL;

    return 0;
}

void
hx509_ca_tbs_free(hx509_ca_tbs *tbs)
{
    size_t i;

    if (tbs == NULL || *tbs == NULL)
	return;

    free_SubjectPublicKeyInfo(&(*tbs)->spki);
    free_GeneralNames(&(*tbs)->san);
    for (i = 0; i < (*tbs)->eku.len; i++)
	free_ExtKeyUsage(&(*tbs)->eku.val[i]);
    free((*tbs)->eku.val);

    hx509_name_free(&(*tbs)->subject);

    memset(*tbs, 0, sizeof(**tbs));
    free(*tbs);
    *tbs = NULL;
}

int
hx509_ca_tbs_set_spki(hx509_context contex,
		      hx509_ca_tbs tbs,
		      const SubjectPublicKeyInfo *spki)
{
    int ret;
    free_SubjectPublicKeyInfo(&tbs->spki);
    ret = copy_SubjectPublicKeyInfo(spki, &tbs->spki);
    tbs->flags.key = !ret;
    return ret;
}

int
hx509_ca_tbs_set_subject(hx509_context context,
			 hx509_ca_tbs tbs,
			 hx509_name subject)
{
    if (tbs->subject)
	hx509_name_free(&tbs->subject);
    return hx509_name_copy(context, subject, &tbs->subject);
}

static int
ca_sign(hx509_context context,
	hx509_ca_tbs tbs,
	hx509_private_key signer,
	const Name *issuername,
	hx509_cert *certificate)
{
    heim_octet_string data;
    Certificate c;
    TBSCertificate *tbsc;
    size_t size;
    int ret;
    const AlgorithmIdentifier *sigalg;
    time_t notBefore;
    time_t notAfter;
    unsigned key_usage;

    sigalg = hx509_signature_rsa_with_sha1();

    memset(&c, 0, sizeof(c));

    /*
     * Default values are, valid since 24h ago, valid one year into
     * the future.
     */
    notBefore = tbs->notBefore;
    if (notBefore == 0)
	notBefore = time(NULL) - 3600 * 24;
    notAfter = tbs->notBefore;
    if (notAfter == 0)
	notAfter = time(NULL) + 3600 * 24 * 365;

    key_usage = tbs->key_usage;
    if (key_usage == 0) {
	KeyUsage ku;
	memset(&ku, 0, sizeof(ku));
	ku.digitalSignature = 1;
	ku.keyEncipherment = 1;
	key_usage = KeyUsage2int(ku);
    }

    /*
     *
     */

    tbsc = &c.tbsCertificate;

    if (tbs->flags.key == 0) {
	ret = EINVAL;
	hx509_set_error_string(context, 0, ret, "No public key set");
	return ret;
    }
    if (tbs->subject == NULL) {
	ret = EINVAL;
	hx509_set_error_string(context, 0, ret, "No subject name set");
	return ret;
    }
    if (tbs->flags.ca && tbs->flags.proxy) {
	ret = EINVAL;
	hx509_set_error_string(context, 0, ret, "Can't be proxy and CA "
			       "at the same time");
	return ret;
    }
    if (tbs->flags.ca || tbs->flags.proxy) {
	ret = EINVAL;
	hx509_set_error_string(context, 0, ret, 
			       "Can only handle EE certs for now");
	return ret;
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
    tbsc->serialNumber.length = 20;
    tbsc->serialNumber.data = malloc(tbsc->serialNumber.length);
    if (tbsc->serialNumber.data == NULL){
	ret = ENOMEM;
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }
    /* XXX diffrent */
    RAND_bytes(tbsc->serialNumber.data, tbsc->serialNumber.length);
    ((unsigned char *)tbsc->serialNumber.data)[0] &= 0x7f;
    /* signature            AlgorithmIdentifier, */
    ret = copy_AlgorithmIdentifier(sigalg, &tbsc->signature);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Failed to copy sigature alg");
	goto out;
    }
    /* issuer               Name, */
    if (issuername)
	ret = copy_Name(issuername, &tbsc->issuer);
    else
	ret = copy_Name(&tbsc->subject, &tbsc->issuer);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Failed to copy issuer name");
	goto out;
    }
    /* validity             Validity, */
    tbsc->validity.notBefore.element = choice_Time_generalTime;
    tbsc->validity.notBefore.u.generalTime = notBefore;
    tbsc->validity.notAfter.element = choice_Time_generalTime;
    tbsc->validity.notAfter.u.generalTime = notAfter;
    /* subject              Name, */
    ret = hx509_name_to_Name(tbs->subject, &tbsc->subject);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Failed to copy subject name");
	goto out;
    }
    /* subjectPublicKeyInfo SubjectPublicKeyInfo, */
    ret = copy_SubjectPublicKeyInfo(&tbs->spki, &tbsc->subjectPublicKeyInfo);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Failed to copy spki");
	goto out;
    }
    /* issuerUniqueID  [1]  IMPLICIT BIT STRING OPTIONAL */
    /* subjectUniqueID [2]  IMPLICIT BIT STRING OPTIONAL */
    /* extensions      [3]  EXPLICIT Extensions OPTIONAL */
    tbsc->extensions = calloc(1, sizeof(*tbsc->extensions));
    if (tbsc->extensions == NULL) {
	ret = ENOMEM;
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }
    
    /* add KeyUsage */
    {
	Extension ext;
	KeyUsage ku;
	memset(&ext, 0, sizeof(ext));

	ku = int2KeyUsage(key_usage);
	ret = der_copy_oid(oid_id_x509_ce_keyUsage(), &ext.extnID);
	if (ret) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	ASN1_MALLOC_ENCODE(KeyUsage, 
			   ext.extnValue.data,
			   ext.extnValue.length,
			   &ku, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	ret = add_Extensions(tbsc->extensions, &ext);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	free_Extension(&ext);
    }

    /* X509v3 Extended Key Usage: */
    /* X509v3 Subject Key Identifier:  */
    /* X509v3 Authority Key Identifier:  */

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

    ret = hx509_cert_init(context, &c, certificate);
    if (ret)
	goto out;

    free_Certificate(&c);

    return 0;

out:
    free_Certificate(&c);
    return ret;
}

int
hx509_ca_sign(hx509_context context,
	      hx509_ca_tbs tbs,
	      hx509_cert signer,
	      hx509_cert *certifiate)
{
    return ca_sign(context,
		   tbs, 
		   _hx509_cert_private_key(signer),
		   &_hx509_get_cert(signer)->tbsCertificate.subject,
		   certifiate);
}
