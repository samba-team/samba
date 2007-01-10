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
#include <pkinit_asn1.h>
RCSID("$Id: ca.c,v 1.12 2007/01/05 18:40:46 lha Exp $");

struct hx509_ca_tbs {
    hx509_name subject;
    SubjectPublicKeyInfo spki;
    ExtKeyUsage eku;
    GeneralNames san;
    unsigned key_usage;
    heim_integer serial;
    struct {
	unsigned int proxy:1;
	unsigned int ca:1;
	unsigned int key:1;
	unsigned int serial:1;
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
    (*tbs)->pathLenConstraint = 0;

    return 0;
}

void
hx509_ca_tbs_free(hx509_ca_tbs *tbs)
{
    if (tbs == NULL || *tbs == NULL)
	return;

    free_SubjectPublicKeyInfo(&(*tbs)->spki);
    free_GeneralNames(&(*tbs)->san);
    free_ExtKeyUsage(&(*tbs)->eku);
    der_free_heim_integer(&(*tbs)->serial);

    hx509_name_free(&(*tbs)->subject);

    memset(*tbs, 0, sizeof(**tbs));
    free(*tbs);
    *tbs = NULL;
}

int
hx509_ca_tbs_set_notBefore(hx509_context context,
			   hx509_ca_tbs tbs,
			   time_t t)
{
    tbs->notBefore = t;
    return 0;
}

int
hx509_ca_tbs_set_notAfter(hx509_context context,
			   hx509_ca_tbs tbs,
			   time_t t)
{
    tbs->notAfter = t;
    return 0;
}

int
hx509_ca_tbs_set_notAfter_lifetime(hx509_context context,
				   hx509_ca_tbs tbs,
				   time_t delta)
{
    return hx509_ca_tbs_set_notAfter(context, tbs, time(NULL) + delta);
}

int
hx509_ca_tbs_set_ca(hx509_context context,
		    hx509_ca_tbs tbs,
		    int pathLenConstraint)
{
    tbs->flags.ca = 1;
    tbs->pathLenConstraint = pathLenConstraint;
    return 0;
}

int
hx509_ca_tbs_set_proxy(hx509_context context,
		       hx509_ca_tbs tbs,
		       int pathLenConstraint)
{
    tbs->flags.proxy = 1;
    tbs->pathLenConstraint = pathLenConstraint;
    return 0;
}


int
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

int
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

int
hx509_ca_tbs_add_eku(hx509_context contex,
		     hx509_ca_tbs tbs,
		     const heim_oid *oid)
{
    void *ptr;
    int ret;

    ptr = realloc(tbs->eku.val, sizeof(tbs->eku.val[0]) * (tbs->eku.len + 1));
    if (ptr == NULL)
	return ENOMEM;
    tbs->eku.val = ptr;
    ret = der_copy_oid(oid, &tbs->eku.val[tbs->eku.len]);
    if (ret)
	return ret;
    tbs->eku.len += 1;
    return 0;
}

int
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


int
hx509_ca_tbs_add_san_pkinit(hx509_context context,
			    hx509_ca_tbs tbs,
			    const char *principal)
{
    heim_octet_string os;
    KRB5PrincipalName p;
    size_t size;
    int ret;
    char *s = NULL;

    memset(&p, 0, sizeof(p));

    /* parse principal */
    {
	const char *str;
	char *q;
	int n;
	
	/* count number of component */
	n = 1;
	for(str = principal; *str != '\0' && *str != '@'; str++){
	    if(*str=='\\'){
		if(str[1] == '\0' || str[1] == '@') {
		    ret = HX509_PARSING_NAME_FAILED;
		    hx509_set_error_string(context, 0, ret, 
					   "trailing \\ in principal name");
		    goto out;
		}
		str++;
	    } else if(*str == '/')
		n++;
	}
	p.principalName.name_string.val = 
	    calloc(n, sizeof(*p.principalName.name_string.val));
	if (p.principalName.name_string.val == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "malloc: out of memory");
	    goto out;
	}
	p.principalName.name_string.len = n;
	
	p.principalName.name_type = KRB5_NT_PRINCIPAL;
	q = s = strdup(principal);
	if (q == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "malloc: out of memory");
	    goto out;
	}
	p.realm = strrchr(q, '@');
	if (p.realm == NULL) {
	    ret = HX509_PARSING_NAME_FAILED;
	    hx509_set_error_string(context, 0, ret, "Missing @ in principal");
	    goto out;
	};
	*p.realm++ = '\0';

	n = 0;
	while (q) {
	    p.principalName.name_string.val[n++] = q;
	    q = strchr(q, '/');
	    if (q)
		*q++ = '\0';
	}
    }
    
    ASN1_MALLOC_ENCODE(KRB5PrincipalName, os.data, os.length, &p, &size, ret);
    if (ret) {
	hx509_set_error_string(context, 0, ret, "Out of memory");
	goto out;
    }
    if (size != os.length)
	_hx509_abort("internal ASN.1 encoder error");
    
    ret = hx509_ca_tbs_add_san_otherName(context,
					 tbs,
					 oid_id_pkinit_san(),
					 &os);
    free(os.data);
out:
    if (p.principalName.name_string.val)
	free (p.principalName.name_string.val);
    if (s)
	free(s);
    return ret;
}
    
int
hx509_ca_tbs_add_san_hostname(hx509_context context,
			      hx509_ca_tbs tbs,
			      const char *dnsname)
{
    GeneralName gn;

    memset(&gn, 0, sizeof(gn));
    gn.element = choice_GeneralName_dNSName;
    gn.u.dNSName = rk_UNCONST(dnsname);
    
    return add_GeneralNames(&tbs->san, &gn);
}

int
hx509_ca_tbs_add_san_rfc822name(hx509_context context,
				hx509_ca_tbs tbs,
				const char *rfc822Name)
{
    GeneralName gn;

    memset(&gn, 0, sizeof(gn));
    gn.element = choice_GeneralName_rfc822Name;
    gn.u.rfc822Name = rk_UNCONST(rfc822Name);
    
    return add_GeneralNames(&tbs->san, &gn);
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
add_extension(hx509_context context,
	      TBSCertificate *tbsc,
	      int critical_flag,
	      const heim_oid *oid,
	      const heim_octet_string *data)
{
    Extension ext;
    int ret;

    memset(&ext, 0, sizeof(ext));

    if (critical_flag) {
	ext.critical = malloc(sizeof(*ext.critical));
	if (ext.critical == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	*ext.critical = TRUE;
    }

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
    asprintf(&tstr, "ts-%lu", (unsigned long)t);
    if (tstr == NULL) {
	hx509_set_error_string(context, 0, ENOMEM,
			       "Failed to copy subject name");
	return ENOMEM;
    }
    /* prefix with CN=<ts>,...*/
    ret = _hx509_name_modify(context, subject, 1, oid_id_at_commonName(), tstr);
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

    key_usage = tbs->key_usage;
    if (key_usage == 0) {
	KeyUsage ku;
	memset(&ku, 0, sizeof(ku));
	ku.digitalSignature = 1;
	ku.keyEncipherment = 1;
	key_usage = KeyUsage2int(ku);
    }

    if (tbs->flags.ca) {
	KeyUsage ku;
	memset(&ku, 0, sizeof(ku));
	ku.keyCertSign = 1;
	key_usage |= KeyUsage2int(ku);
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
    if (tbs->subject == NULL && !tbs->flags.proxy) {
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
    }
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
	ret = hx509_name_to_Name(tbs->subject, &tbsc->issuer);
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
	KeyUsage ku;

	ku = int2KeyUsage(key_usage);
	ASN1_MALLOC_ENCODE(KeyUsage, data.data, data.length, &ku, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, 1, 
			    oid_id_x509_ce_keyUsage(), &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* add ExtendedKeyUsage */
    if (tbs->eku.len > 0) {
	ASN1_MALLOC_ENCODE(ExtKeyUsage, data.data, data.length, 
			   &tbs->eku, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, 0,
			    oid_id_x509_ce_extKeyUsage(), &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* add Subject Alternative Name */
    if (tbs->san.len > 0) {
	ASN1_MALLOC_ENCODE(GeneralNames, data.data, data.length, 
			   &tbs->san, &size, ret);
	if (ret) {
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	if (size != data.length)
	    _hx509_abort("internal ASN.1 encoder error");
	ret = add_extension(context, tbsc, 0,
			    oid_id_x509_ce_subjectAltName(),
			    &data);
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
			    oid_id_x509_ce_authorityKeyIdentifier(),
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
	    SHA_CTX m;
	    
	    SHA1_Init(&m);
	    SHA1_Update(&m, tbs->spki.subjectPublicKey.data,
			tbs->spki.subjectPublicKey.length / 8);
	    SHA1_Final (hash, &m);
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
			    oid_id_x509_ce_subjectKeyIdentifier(),
			    &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* Add BasicConstraints */ 
    {
	BasicConstraints bc;
	int aCA = 1;
	uint32_t path;

	memset(&bc, 0, sizeof(bc));

	if (tbs->flags.ca) {
	    bc.cA = &aCA;
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
	ret = add_extension(context, tbsc, 0,
			    oid_id_x509_ce_basicConstraints(),
			    &data);
	free(data.data);
	if (ret)
	    goto out;
    }

    /* add Proxy */
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

	ret = der_copy_oid(oid_id_pkix_ppl_inheritAll(),
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
			    oid_id_pe_proxyCertInfo(),
			    &data);
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

    ret = hx509_cert_init(context, &c, certificate);
    if (ret)
	goto out;

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
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}
	ret = der_copy_octet_string(&si, ai->keyIdentifier);
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
	if (ai->authorityCertSerialNumber == NULL) {
	    ret = ENOMEM;
	    hx509_set_error_string(context, 0, ret, "Out of memory");
	    goto out;
	}

	gn.element = choice_GeneralName_directoryName;
	gn.u.directoryName.element = 
	    choice_GeneralName_directoryName_rdnSequence;
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


int
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

int
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
