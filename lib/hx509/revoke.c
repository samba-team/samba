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

struct revoke_crl {
    char *path;
    CRLCertificateList crl;
    int verified;
};

struct hx509_revoke_ctx_data {
    struct {
	struct revoke_crl *val;
	size_t len;
    } crls;
};

int
hx509_revoke_init(hx509_context context, hx509_revoke_ctx *revoke)
{
    *revoke = calloc(1, sizeof(**revoke));
    if (*revoke == NULL)
	return ENOMEM;

    (*revoke)->crls.len = 0;
    (*revoke)->crls.val = NULL;

    return 0;
}

void
hx509_revoke_free(hx509_revoke_ctx *revoke)
{
    size_t i ;

    for (i = 0; i < (*revoke)->crls.len; i++) {
	free((*revoke)->crls.val[i].path);
	free_CRLCertificateList(&(*revoke)->crls.val[i].crl);
    }

    memset(*revoke, 0, sizeof(**revoke));
    free(*revoke);
    *revoke = NULL;
}

static int
verify_crl(hx509_context context,
	   CRLCertificateList *crl,
	   time_t time_now,
	   hx509_certs certs)
{
    heim_octet_string os;
    hx509_cert signer;
    hx509_query q;
    time_t t;
    int ret;
	
    t = _hx509_Time2time_t(&crl->tbsCertList.thisUpdate);
    if (t > time_now)
	return HX509_CRL_USED_BEFORE_TIME;

    if (crl->tbsCertList.nextUpdate == NULL)
	return HX509_CRL_INVALID_FORMAT;

    t = _hx509_Time2time_t(crl->tbsCertList.nextUpdate);
    if (t < time_now)
	return HX509_CRL_USED_AFTER_TIME;

    _hx509_query_clear(&q);
	
    q.match = HX509_QUERY_MATCH_SUBJECT_NAME;
    q.subject_name = &crl->tbsCertList.issuer;
	
    ret = _hx509_certs_find(context, certs, &q, &signer);
    if (ret)
	return ret;

    os.data = crl->signatureValue.data;
    os.length = crl->signatureValue.length / 8;

    ret = hx509_verify_signature(context,
				 signer, 
				 &crl->signatureAlgorithm,
				 &crl->tbsCertList._save,
				 &os);

    hx509_cert_free(signer);

    return ret;
}

int
hx509_revoke_add_crl(hx509_context context,
		     hx509_revoke_ctx revoke,
		     const char *path)
{
    size_t length, size;
    void *data;
    int ret, i;

    if (strncmp(path, "FILE:", 5) != 0)
	return EINVAL;
    
    path += 5;

    for (i = 0; i < revoke->crls.len; i++) {
	if (strcmp(revoke->crls.val[0].path, path) == 0)
	    return 0;
    }

    data = realloc(revoke->crls.val, 
		   (revoke->crls.len + 1) * sizeof(revoke->crls.val[0]));
    if (data == NULL)
	return ENOMEM;

    revoke->crls.val = data;

    memset(&revoke->crls.val[revoke->crls.len], 0, sizeof(revoke->crls.val[0]));

    revoke->crls.val[revoke->crls.len].path = strdup(path);
    if (revoke->crls.val[revoke->crls.len].path == NULL)
	return ENOMEM;

    ret = _hx509_map_file(path, &data, &length);
    if (ret) {
	free(revoke->crls.val[revoke->crls.len].path);
	return ret;
    }

    ret = decode_CRLCertificateList(data, length,
				    &revoke->crls.val[revoke->crls.len].crl,
				    &size);
    _hx509_unmap_file(data, length);
    if (ret) {
	free(revoke->crls.val[revoke->crls.len].path);
	return ret;
    }

    /* check signature is aligned */
    if (revoke->crls.val[revoke->crls.len].crl.signatureValue.length & 7) {
	free(revoke->crls.val[revoke->crls.len].path);
	free_CRLCertificateList(&revoke->crls.val[revoke->crls.len].crl);
	return EINVAL;
    }
    revoke->crls.len++;

    return ret;
}


int
hx509_revoke_verify(hx509_context context,
		    hx509_revoke_ctx revoke,
		    hx509_certs certs,
		    time_t now,
		    hx509_cert cert)
{
    const Certificate *c = _hx509_get_cert(cert);
    unsigned long i, j;
    int ret;

    for (i = 0; i < revoke->crls.len; i++) {
	struct revoke_crl *crl = &revoke->crls.val[i];

	/* check if cert.issuer == crls.val[i].crl.issuer */
	ret = _hx509_name_cmp(&c->tbsCertificate.issuer, 
			      &crl->crl.tbsCertList.issuer);
	if (ret)
	    continue;

	/* verify signature in crl if not already done */
	if (crl->verified == 0) {
	    ret = verify_crl(context, &crl->crl, now, certs);
	    if (ret)
		return ret;
	    crl->verified = 1;
	}
	
	if (crl->crl.tbsCertList.revokedCertificates == NULL)
	    return 0;

	/* check if cert is in crl */
	for (j = 0; j < crl->crl.tbsCertList.revokedCertificates->len; j++) {
	    time_t t;

	    ret = heim_integer_cmp(&crl->crl.tbsCertList.revokedCertificates->val[j].userCertificate,
		    &c->tbsCertificate.serialNumber);
	    if (ret != 0)
		continue;

	    t = _hx509_Time2time_t(&crl->crl.tbsCertList.revokedCertificates->val[j].revocationDate);
	    if (t > now)
		continue;

	    return HX509_CRL_CERT_REVOKED;
	}
	return 0;
    }

    if (context->flags & HX509_CTX_CRL_MISSING_OK)
	return 0;
    return HX509_CRL_MISSING;
}
