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

#define pkcs1(name, number) \
static unsigned name##_oid_data[] = { 1, 2, 840, 113549, 1, 1, number }; \
static heim_oid name##_oid = { 7, name##_oid_data }

pkcs1(rsaEncryption, 1);
pkcs1(md2WithRSAEncryption, 2);
pkcs1(md5WithRSAEncryption, 4);
pkcs1(sha1WithRSAEncryption, 5);

#undef pkcs1

#define x9_57(name, number) \
static unsigned name##_oid_data[] = { 1, 2, 840, 10040, 4, number }; \
static heim_oid name##_oid = { 6, name##_oid_data }

x9_57(id_dsa, 1);
x9_57(id_dsa_with_sha1, 3);

#undef x9_57

#define oiw_secsig_alg(name, number) \
static unsigned name##_oid_data[] = { 1, 3, 14, 3, 2, number }; \
static heim_oid name##_oid = { 6, name##_oid_data }

oiw_secsig_alg(id_sha1, 26);

#undef oiw_secsig_alg

#define rsadsi_digest(name, number) \
static unsigned name##_oid_data[] = { 1, 2, 840, 113549, 2, number }; \
static heim_oid name##_oid = { 6, name##_oid_data }

rsadsi_digest(id_md2, 2);
rsadsi_digest(id_md5, 5);

#undef rsadsi_digest

#define private_oid(name, number) \
static unsigned name##_oid_data[] = { 127, number }; \
static heim_oid name##_oid = { 2, name##_oid_data }

private_oid(private_rc2_40, 1);
/* private_oid(private_rc2_64, 2); */

#undef private_oid

struct hx509_crypto;

struct hx509_private_key {
    const heim_oid *signature_alg;
    struct {
	RSA *rsa;
    } private_key;
};

/*
 *
 */

struct signature_alg {
    char *name;
    heim_oid *sig_oid;
    heim_oid *key_oid;
    heim_oid *digest_oid;
    int flags;
#define PROVIDE_CONF 1
    int (*verify_signature)(const struct signature_alg *,
			    const Certificate *,
			    const AlgorithmIdentifier *,
			    const heim_octet_string *,
			    const heim_octet_string *);
    int (*create_signature)(const struct signature_alg *,
			    const hx509_private_key,
			    const AlgorithmIdentifier *,
			    const heim_octet_string *,
			    AlgorithmIdentifier *,
			    heim_octet_string *);
    int (*parse_private_key)(const struct signature_alg *,
			     const void *data,
			     size_t len,
			     hx509_private_key private_key);
};

/*
 *
 */

static BIGNUM *
heim_int2BN(const heim_integer *i)
{
    BIGNUM *bn;

    bn = BN_bin2bn(i->data, i->length, NULL);
    BN_set_negative(bn, i->negative);
    return bn;
}

static int
rsa_verify_signature(const struct signature_alg *sig_alg,
		     const Certificate *signer,
		     const AlgorithmIdentifier *alg,
		     const heim_octet_string *data,
		     const heim_octet_string *sig)
{
    const SubjectPublicKeyInfo *spi;
    DigestInfo di;
    unsigned char *to;
    int tosize;
    int ret;
    RSA *rsa;
    RSAPublicKey pk;
    size_t size;

    memset(&di, 0, sizeof(di));

    spi = &signer->tbsCertificate.subjectPublicKeyInfo;

    rsa = RSA_new();
    if (rsa == NULL)
	return ENOMEM;

    ret = decode_RSAPublicKey(spi->subjectPublicKey.data,
			      spi->subjectPublicKey.length / 8,
			      &pk, &size);
    if (ret)
	goto out;

    rsa->n = heim_int2BN(&pk.modulus);
    rsa->e = heim_int2BN(&pk.publicExponent);

    free_RSAPublicKey(&pk);

    if (rsa->n == NULL || rsa->e == NULL) {
	ret = ENOMEM;
	goto out;
    }

    tosize = RSA_size(rsa);
    to = malloc(tosize);
    if (to == NULL) {
	ret = ENOMEM;
	goto out;
    }

    ret = RSA_public_decrypt(sig->length, (unsigned char *)sig->data, 
			     to, rsa, RSA_PKCS1_PADDING);
    if (ret < 0) {
	ret = HX509_CRYPTO_SIG_INVALID_FORMAT;
	free(to);
	goto out;
    }
    if (ret > tosize)
	_hx509_abort("internal rsa decryption failure: ret > tosize");
    ret = decode_DigestInfo(to, ret, &di, &size);
    free(to);
    if (ret) {
	goto out;
    }

    if (sig_alg->digest_oid &&
	heim_oid_cmp(&di.digestAlgorithm.algorithm,
		     sig_alg->digest_oid) != 0) 
    {
	    ret = HX509_CRYPTO_OID_MISMATCH;
	    goto out;
    }

    ret = _hx509_verify_signature(NULL,
				  &di.digestAlgorithm,
				  data,
				  &di.digest);
 out:
    free_DigestInfo(&di);
    RSA_free(rsa);
    return ret;
}

static int
rsa_create_signature(const struct signature_alg *sig_alg,
		     const hx509_private_key signer,
		     const AlgorithmIdentifier *alg,
		     const heim_octet_string *data,
		     AlgorithmIdentifier *signatureAlgorithm,
		     heim_octet_string *sig)
{
    const AlgorithmIdentifier *digest_alg;
    heim_octet_string indata;
    const heim_oid *sig_oid;
    DigestInfo di;
    size_t size;
    int ret;
    
    if (alg)
	sig_oid = &alg->algorithm;
    else
	sig_oid = signer->signature_alg;

    if (heim_oid_cmp(sig_oid, oid_id_pkcs1_sha1WithRSAEncryption()) == 0) {
	digest_alg = hx509_signature_sha1();
    } else if (heim_oid_cmp(sig_oid, oid_id_pkcs1_md5WithRSAEncryption()) == 0) {
	digest_alg = hx509_signature_md5();
    } else if (heim_oid_cmp(sig_oid, oid_id_pkcs1_md5WithRSAEncryption()) == 0) {
	digest_alg = hx509_signature_md5();
    } else if (heim_oid_cmp(sig_oid, oid_id_dsa_with_sha1()) == 0) {
	digest_alg = hx509_signature_sha1();
    } else
	return HX509_ALG_NOT_SUPP;

    if (signatureAlgorithm) {
	ret = _hx509_set_digest_alg(signatureAlgorithm,
				    sig_oid, "\x05\x00", 2);
	if (ret)
	    return ret;
    }

    memset(&di, 0, sizeof(di));

    ret = _hx509_create_signature(NULL,
				  digest_alg,
				  data,
				  &di.digestAlgorithm,
				  &di.digest);
    ASN1_MALLOC_ENCODE(DigestInfo,
		       indata.data,
		       indata.length,
		       &di,
		       &size,
		       ret);
    free_DigestInfo(&di);
    if (ret)
	return ret;
    if (indata.length != size)
	_hx509_abort("internal ASN.1 encoder error");

    sig->length = RSA_size(signer->private_key.rsa);
    sig->data = malloc(sig->length);
    if (sig->data == NULL)
	return ENOMEM;

    ret = RSA_private_encrypt(indata.length, indata.data, 
			      sig->data, 
			      signer->private_key.rsa,
			      RSA_PKCS1_PADDING);
    free_octet_string(&indata);
    if (ret <= 0)
	return HX509_CMS_FAILED_CREATE_SIGATURE;
    if (ret < sig->length)
	_hx509_abort("RSA signature prelen shorter the output len");

    sig->length = ret;
    
    return 0;
}


#if 0
static int
create_signature(const struct signature_alg *sig_alg,
		 const hx509_private_key signer,
		 const AlgorithmIdentifier *alg,
		 const heim_octet_string *data,
		 AlgorithmIdentifier *signatureAlgorithm,
		 heim_octet_string *sig)
{
    const heim_oid *digest_oid, *sig_oid;
    const EVP_MD *mdtype;
    EVP_MD_CTX md;
    unsigned len;
    int ret;
    
    if (alg)
	sig_oid = &alg->algorithm;
    else
	sig_oid = signer->signature_alg;

    if (heim_oid_cmp(sig_oid, oid_id_dsa_with_sha1()) == 0) {
	mdtype = EVP_sha1();
	digest_oid = oid_id_secsig_sha_1();
    } else
	return HX509_ALG_NOT_SUPP;

    if (signatureAlgorithm) {
	ret = _hx509_set_digest_alg(signatureAlgorithm,
				    sig_oid, "\x05\x00", 2);
	if (ret)
	    return ret;
    }

    sig->data = malloc(EVP_PKEY_size(signer->private_key));
    if (sig->data == NULL)
	return ENOMEM;
	
    EVP_SignInit(&md, mdtype);
    EVP_SignUpdate(&md, data->data, data->length);
    ret = EVP_SignFinal(&md, sig->data, &len, signer->private_key);
    if (ret != 1) {
	free(sig->data);
	sig->data = NULL;
	return HX509_CMS_FAILED_CREATE_SIGATURE;
    }
    sig->length = len;

    return 0;
}
#endif

static int
rsa_parse_private_key(const struct signature_alg *sig_alg,
		      const void *data,
		      size_t len,
		      hx509_private_key private_key)
{
    const unsigned char *p = data;

    private_key->private_key.rsa = 
	d2i_RSAPrivateKey(NULL, &p, len);
    if (private_key->private_key.rsa == NULL)
	return EINVAL;
    private_key->signature_alg = oid_id_pkcs1_sha1WithRSAEncryption();

    return 0;
}


static int
dsa_verify_signature(const struct signature_alg *sig_alg,
		     const Certificate *signer,
		     const AlgorithmIdentifier *alg,
		     const heim_octet_string *data,
		     const heim_octet_string *sig)
{
    const SubjectPublicKeyInfo *spi;
    DSAPublicKey pk;
    DSAParams param;
    size_t size;
    DSA *dsa;
    int ret;

    spi = &signer->tbsCertificate.subjectPublicKeyInfo;

    dsa = DSA_new();
    if (dsa)
	return ENOMEM;

    ret = decode_DSAPublicKey(spi->subjectPublicKey.data,
			      spi->subjectPublicKey.length / 8,
			      &pk, &size);
    if (ret)
	goto out;

    dsa->pub_key = heim_int2BN(&pk);

    free_DSAPublicKey(&pk);

    if (dsa->pub_key == NULL) {
	ret = ENOMEM;
	goto out;
    }

    if (spi->algorithm.parameters == NULL) {
	ret = EINVAL;
	goto out;
    }

    ret = decode_DSAParams(spi->algorithm.parameters->data,
			   spi->algorithm.parameters->length,
			   &param,
			   &size);
    if (ret)
	goto out;

    dsa->p = heim_int2BN(&param.p);
    dsa->q = heim_int2BN(&param.q);
    dsa->g = heim_int2BN(&param.g);

    free_DSAParams(&param);

    if (dsa->p == NULL || dsa->q == NULL || dsa->g == NULL) {
	ret = ENOMEM;
	goto out;
    }

    ret = DSA_verify(-1, data->data, data->length,
		     (unsigned char*)sig->data, sig->length,
		     dsa);
    if (ret == 1)
	ret = 0;
    else if (ret == 0 || ret == -1)
	ret = HX509_CRYPTO_BAD_SIGNATURE;
    else
	ret = HX509_CRYPTO_SIG_INVALID_FORMAT;

 out:
    DSA_free(dsa);

    return ret;
}

static int
dsa_parse_private_key(const struct signature_alg *sig_alg,
		      const void *data,
		      size_t len,
		      hx509_private_key private_key)
{
#if 0
    unsigned char *p = rk_UNCONST(data);

    private_key->private_key = d2i_PrivateKey(EVP_PKEY_DSA, NULL, &p, len);
    if (private_key->private_key == NULL)
	return EINVAL;

    private_key->signature_alg = oid_id_dsa_with_sha1();

    return 0;
#else
    return EINVAL;
#endif
}


static int
sha1_verify_signature(const struct signature_alg *sig_alg,
		      const Certificate *signer,
		      const AlgorithmIdentifier *alg,
		      const heim_octet_string *data,
		      const heim_octet_string *sig)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA_CTX m;
    
    if (sig->length != SHA_DIGEST_LENGTH)
	return HX509_CRYPTO_SIG_INVALID_FORMAT;

    SHA1_Init(&m);
    SHA1_Update(&m, data->data, data->length);
    SHA1_Final (digest, &m);
	
    if (memcmp(digest, sig->data, SHA_DIGEST_LENGTH) != 0)
	return HX509_CRYPTO_BAD_SIGNATURE;

    return 0;
}

static int
sha1_create_signature(const struct signature_alg *sig_alg,
		      const hx509_private_key signer,
		      const AlgorithmIdentifier *alg,
		      const heim_octet_string *data,
		      AlgorithmIdentifier *signatureAlgorithm,
		      heim_octet_string *sig)
{
    SHA_CTX m;
    
    memset(sig, 0, sizeof(*sig));

    if (signatureAlgorithm) {
	int ret;
	ret = _hx509_set_digest_alg(signatureAlgorithm,
				    sig_alg->sig_oid, "\x05\x00", 2);
	if (ret)
	    return ret;
    }
	    

    sig->data = malloc(SHA_DIGEST_LENGTH);
    if (sig->data == NULL) {
	sig->length = 0;
	return ENOMEM;
    }
    sig->length = SHA_DIGEST_LENGTH;

    SHA1_Init(&m);
    SHA1_Update(&m, data->data, data->length);
    SHA1_Final (sig->data, &m);

    return 0;
}

static int
md5_verify_signature(const struct signature_alg *sig_alg,
		     const Certificate *signer,
		     const AlgorithmIdentifier *alg,
		     const heim_octet_string *data,
		     const heim_octet_string *sig)
{
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_CTX m;
    
    if (sig->length != MD5_DIGEST_LENGTH)
	return HX509_CRYPTO_SIG_INVALID_FORMAT;

    MD5_Init(&m);
    MD5_Update(&m, data->data, data->length);
    MD5_Final (digest, &m);
	
    if (memcmp(digest, sig->data, MD5_DIGEST_LENGTH) != 0)
	return HX509_CRYPTO_BAD_SIGNATURE;

    return 0;
}

static int
md2_verify_signature(const struct signature_alg *sig_alg,
		     const Certificate *signer,
		     const AlgorithmIdentifier *alg,
		     const heim_octet_string *data,
		     const heim_octet_string *sig)
{
    unsigned char digest[MD2_DIGEST_LENGTH];
    MD2_CTX m;
    
    if (sig->length != MD2_DIGEST_LENGTH)
	return HX509_CRYPTO_SIG_INVALID_FORMAT;

    MD2_Init(&m);
    MD2_Update(&m, data->data, data->length);
    MD2_Final (digest, &m);
	
    if (memcmp(digest, sig->data, MD2_DIGEST_LENGTH) != 0)
	return HX509_CRYPTO_BAD_SIGNATURE;

    return 0;
}

static struct signature_alg pkcs1_rsa_sha1_alg = {
    "rsa",
    &rsaEncryption_oid,
    &rsaEncryption_oid,
    NULL,
    PROVIDE_CONF,
    rsa_verify_signature,
    rsa_create_signature,
    rsa_parse_private_key
};

static struct signature_alg rsa_with_sha1_alg = {
    "rsa-with-sha1",
    &sha1WithRSAEncryption_oid,
    &rsaEncryption_oid,
    &id_sha1_oid,
    PROVIDE_CONF,
    rsa_verify_signature,
    rsa_create_signature,
    rsa_parse_private_key
};

static struct signature_alg rsa_with_md5_alg = {
    "rsa-with-md5",
    &md5WithRSAEncryption_oid,
    &rsaEncryption_oid,
    &id_md5_oid,
    PROVIDE_CONF,
    rsa_verify_signature,
    rsa_create_signature,
    rsa_parse_private_key
};

static struct signature_alg rsa_with_md2_alg = {
    "rsa-with-md2",
    &md2WithRSAEncryption_oid,
    &rsaEncryption_oid,
    &id_md2_oid,
    PROVIDE_CONF,
    rsa_verify_signature,
    rsa_create_signature,
    rsa_parse_private_key
};

static struct signature_alg dsa_sha1_alg = {
    "dsa-with-sha1",
    &id_dsa_with_sha1_oid,
    &id_dsa_oid, 
    &id_sha1_oid,
    PROVIDE_CONF,
    dsa_verify_signature,
    /* create_signature */ NULL,
    dsa_parse_private_key
};

static struct signature_alg sha1_alg = {
    "sha1",
    &id_sha1_oid,
    NULL,
    NULL,
    0,
    sha1_verify_signature,
    sha1_create_signature
};

static struct signature_alg md5_alg = {
    "rsa-md5",
    &id_md5_oid,
    NULL,
    NULL,
    0,
    md5_verify_signature
};

static struct signature_alg md2_alg = {
    "rsa-md2",
    &id_md2_oid,
    NULL,
    NULL,
    0,
    md2_verify_signature
};

static struct signature_alg *sig_algs[] = {
    &pkcs1_rsa_sha1_alg,
    &rsa_with_sha1_alg,
    &rsa_with_md5_alg,
    &rsa_with_md2_alg,
    &dsa_sha1_alg,
    &sha1_alg,
    &md5_alg,
    &md2_alg,
    0,
    NULL
};

static const struct signature_alg *
find_sig_alg(const heim_oid *oid)
{
    int i;
    for (i = 0; sig_algs[i]; i++)
	if (heim_oid_cmp(sig_algs[i]->sig_oid, oid) == 0)
	    return sig_algs[i];
    return NULL;
}

static const struct signature_alg *
find_key_alg(const heim_oid *oid)
{
    int i;
    for (i = 0; sig_algs[i]; i++)
	if (heim_oid_cmp(sig_algs[i]->key_oid, oid) == 0)
	    return sig_algs[i];
    return NULL;
}

int
_hx509_verify_signature(const Certificate *signer,
			const AlgorithmIdentifier *alg,
			const heim_octet_string *data,
			const heim_octet_string *sig)
{
    const struct signature_alg *md;

    md = find_sig_alg(&alg->algorithm);
    if (md == NULL) {
	return HX509_SIG_ALG_NO_SUPPORTED;
    }
    if (signer && (md->flags & PROVIDE_CONF) == 0)
	return HX509_CRYPTO_SIG_NO_CONF;
    if (md->key_oid) {
	const SubjectPublicKeyInfo *spi;
	spi = &signer->tbsCertificate.subjectPublicKeyInfo;

	if (heim_oid_cmp(&spi->algorithm.algorithm, md->key_oid) != 0)
	    return HX509_SIG_ALG_DONT_MATCH_KEY_ALG;
    }
    return (*md->verify_signature)(md, signer, alg, data, sig);
}

int
_hx509_create_signature(const hx509_private_key signer,
			const AlgorithmIdentifier *alg,
			const heim_octet_string *data,
			AlgorithmIdentifier *signatureAlgorithm,
			heim_octet_string *sig)
{
    const struct signature_alg *md;

    md = find_sig_alg(&alg->algorithm);
    if (md == NULL)
	return HX509_SIG_ALG_NO_SUPPORTED;

    if (signer && (md->flags & PROVIDE_CONF) == 0)
	return HX509_CRYPTO_SIG_NO_CONF;

    if (md->create_signature == NULL) /* XXX DSA */
	return HX509_CRYPTO_SIG_NO_CONF;

    return (*md->create_signature)(md, signer, alg, data, 
				   signatureAlgorithm, sig);
}

int
_hx509_public_encrypt(const heim_octet_string *cleartext,
		      const Certificate *cert,
		      heim_oid *encryption_oid,
		      heim_octet_string *ciphertext)
{
    const SubjectPublicKeyInfo *spi;
    unsigned char *to;
    int tosize;
    int ret;
    RSA *rsa;
    RSAPublicKey pk;
    size_t size;

    ciphertext->data = NULL;
    ciphertext->length = 0;

    spi = &cert->tbsCertificate.subjectPublicKeyInfo;

    rsa = RSA_new();
    if (rsa == NULL)
	return ENOMEM;

    ret = decode_RSAPublicKey(spi->subjectPublicKey.data,
			      spi->subjectPublicKey.length / 8,
			      &pk, &size);
    if (ret) {
	RSA_free(rsa);
	return ENOMEM;
    }
    rsa->n = heim_int2BN(&pk.modulus);
    rsa->e = heim_int2BN(&pk.publicExponent);

    free_RSAPublicKey(&pk);

    if (rsa->n == NULL || rsa->e == NULL) {
	RSA_free(rsa);
	return ENOMEM;
    }

    tosize = RSA_size(rsa);
    to = malloc(tosize);
    if (to == NULL) {
	RSA_free(rsa);
	return ENOMEM;
    }

    ret = RSA_public_encrypt(cleartext->length, 
			     (unsigned char *)cleartext->data, 
			     to, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret < 0) {
	free(to);
	return EINVAL;
    }
    if (ret > tosize)
	_hx509_abort("internal rsa decryption failure: ret > tosize");

    ciphertext->length = ret;
    ciphertext->data = to;

    ret = copy_oid(&rsaEncryption_oid, encryption_oid);
    if (ret) {
	free_octet_string(ciphertext);
	return ENOMEM;
    }

    return 0;
}

int
_hx509_private_key_private_decrypt(const heim_octet_string *ciphertext,
				   const heim_oid *encryption_oid,
				   hx509_private_key p,
				   heim_octet_string *cleartext)
{
    int ret;

    cleartext->data = NULL;
    cleartext->length = 0;

    if (p->private_key.rsa == NULL)
	return EINVAL;

    cleartext->length = RSA_size(p->private_key.rsa);
    cleartext->data = malloc(cleartext->length);
    if (cleartext->data == NULL) 
	return ENOMEM;

    ret = RSA_private_decrypt(ciphertext->length, ciphertext->data,
			      cleartext->data,
			      p->private_key.rsa,
			      RSA_PKCS1_PADDING);
    if (ret <= 0) {
	free_octet_string(cleartext);
	return ENOMEM;
    }
    if (cleartext->length < ret)
	_hx509_abort("internal rsa decryption failure: ret > tosize");

    cleartext->length = ret;

    return 0;
}


int
_hx509_parse_private_key(const heim_oid *key_oid,
			 const void *data,
			 size_t len,
			 hx509_private_key *private_key)
{
    const struct signature_alg *md;
    int ret;

    *private_key = NULL;

    md = find_key_alg(key_oid);
    if (md == NULL)
	return HX509_SIG_ALG_NO_SUPPORTED;

    ret = _hx509_new_private_key(private_key);
    if (ret)
	return ret;

    ret = (*md->parse_private_key)(md, data, len, *private_key);
    if (ret)
	_hx509_free_private_key(private_key);

    return ret;
}

/*
 *
 */

static const heim_octet_string null_entry_oid = { 2, "\x05\x00" };

static const unsigned sha1_oid_tree[] = { 1, 3, 14, 3, 2, 26 };
const AlgorithmIdentifier _hx509_signature_sha1_data = { 
    { 6, rk_UNCONST(sha1_oid_tree) }, rk_UNCONST(&null_entry_oid)
};

static const unsigned md5_oid_tree[] = { 1, 2, 840, 113549, 2, 5 };
const AlgorithmIdentifier _hx509_signature_md5_data = { 
    { 6, rk_UNCONST(md5_oid_tree) }, rk_UNCONST(&null_entry_oid)
};

static const unsigned md2_oid_tree[] = { 1, 2, 840, 113549, 2, 2 };
const AlgorithmIdentifier _hx509_signature_md2_data = { 
    { 6, rk_UNCONST(md2_oid_tree) }, rk_UNCONST(&null_entry_oid)
};

static const unsigned rsa_with_sha1_oid[] ={ 1, 2, 840, 113549, 1, 1, 5 };
const AlgorithmIdentifier _hx509_signature_rsa_with_sha1_data = { 
    { 7, rk_UNCONST(rsa_with_sha1_oid) }, NULL
};


const AlgorithmIdentifier *
hx509_signature_sha1(void)
{
    return &_hx509_signature_sha1_data;
}

const AlgorithmIdentifier *
hx509_signature_md5(void)
{
    return &_hx509_signature_md5_data;
}

const AlgorithmIdentifier *
hx509_signature_md2(void)
{
    return &_hx509_signature_md2_data;
}

const AlgorithmIdentifier *
hx509_signature_rsa_with_sha1(void)
{
    return &_hx509_signature_rsa_with_sha1_data;
}

int
_hx509_new_private_key(hx509_private_key *key)
{
    *key = calloc(1, sizeof(**key));
    if (*key == NULL)
	return ENOMEM;
    return 0;
}

int
_hx509_free_private_key(hx509_private_key *key)
{
    if ((*key)->private_key.rsa)
	RSA_free((*key)->private_key.rsa);
    (*key)->private_key.rsa = NULL;
    free(*key);
    *key = NULL;
    return 0;
}

int
_hx509_private_key_assign_key_file(hx509_private_key key,
				   hx509_lock lock,
				   const char *fn)
{
    const struct _hx509_password *pw;
    int i;

#ifdef HAVE_OPENSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif

    if (key->private_key.rsa) {
	RSA_free(key->private_key.rsa);
	key->private_key.rsa = NULL;
    }


    pw = _hx509_lock_get_passwords(lock);

    for (i = 0; i < pw->len; i++) {
#if HAVE_OPENSSL
	EVP_PKEY *private_key;
	FILE *f;

	f = fopen(fn, "r");
	if (f == NULL)
	    return ENOMEM;
	
	private_key = PEM_read_PrivateKey(f, NULL, NULL, pw->val[i]);
	fclose(f);
	if (private_key == NULL)
	    continue;

	key->private_key.rsa = EVP_PKEY_get1_RSA(private_key);
	EVP_PKEY_free(private_key);
	if (key->private_key.rsa == NULL)
	    return EINVAL;

	return 0;
#endif
    }

    return EINVAL;
}

void
_hx509_private_key_assign_rsa(hx509_private_key key, void *ptr)
{
    if (key->private_key.rsa)
	RSA_free(key->private_key.rsa);
    key->private_key.rsa = ptr;
}


struct hx509_crypto_data {
    char *name;
    const EVP_CIPHER *c;
    heim_octet_string key;
    heim_oid oid;
};

static const EVP_CIPHER *
find_cipher(const heim_oid *oid)
{
    if (heim_oid_cmp(oid, oid_id_pkcs3_rc2_cbc()) == 0) {
	return EVP_rc2_cbc();
    } else if (heim_oid_cmp(oid, oid_id_rsadsi_rc2_cbc()) == 0) {
	return EVP_rc2_cbc();
    } else if (heim_oid_cmp(oid, &private_rc2_40_oid) == 0) {
	return EVP_rc2_40_cbc();
    } else if (heim_oid_cmp(oid, oid_id_pkcs3_des_ede3_cbc()) == 0) {
	return EVP_des_ede3_cbc();
    } else if (heim_oid_cmp(oid, oid_id_rsadsi_des_ede3_cbc()) == 0) {
	return EVP_des_ede3_cbc();
    } else if (heim_oid_cmp(oid, oid_id_aes_128_cbc()) == 0) {
	return EVP_aes_128_cbc();
    } else if (heim_oid_cmp(oid, oid_id_aes_192_cbc()) == 0) {
	return EVP_aes_192_cbc();
    } else if (heim_oid_cmp(oid, oid_id_aes_256_cbc()) == 0) {
	return EVP_aes_256_cbc();
    }
    return NULL;
}

int
hx509_crypto_init(hx509_context context,
		  const char *provider,
		  const heim_oid *enctype,
		  hx509_crypto *crypto)
{
    const EVP_CIPHER *c;

    *crypto = NULL;

    c = find_cipher(enctype);
    if (c == NULL)
	return HX509_ALG_NOT_SUPP;

    *crypto = calloc(1, sizeof(**crypto));
    if (*crypto == NULL)
	return ENOMEM;

    (*crypto)->c = c;

    if (copy_oid(enctype, &(*crypto)->oid)) {
	hx509_crypto_destroy(*crypto);
	return ENOMEM;
    }

    return 0;
}

const char *
hx509_crypto_provider(hx509_crypto crypto)
{
    return "unknown";
}

void
hx509_crypto_destroy(hx509_crypto crypto)
{
    if (crypto->name)
	free(crypto->name);
    if (crypto->key.data)
	free(crypto->key.data);
    memset(crypto, 0, sizeof(*crypto));
    free(crypto);
}

int
hx509_crypto_set_key_name(hx509_crypto crypto, const char *name)
{
    return 0;
}

int
hx509_crypto_set_key_data(hx509_crypto crypto, const void *data, size_t length)
{
    if (EVP_CIPHER_key_length(crypto->c) > length)
	return HX509_CRYPTO_INTERNAL_ERROR;

    if (crypto->key.data) {
	free(crypto->key.data);
	crypto->key.length = 0;
    }
    crypto->key.data = malloc(length);
    if (crypto->key.data == NULL)
	return ENOMEM;
    memcpy(crypto->key.data, data, length);
    crypto->key.length = length;

    return 0;
}

int
hx509_crypto_set_random_key(hx509_crypto crypto, heim_octet_string *key)
{
    if (crypto->key.data) {
	free(crypto->key.data);
	crypto->key.length = 0;
    }

    crypto->key.length = EVP_CIPHER_key_length(crypto->c);
    crypto->key.data = malloc(crypto->key.length);
    if (crypto->key.data == NULL) {
	crypto->key.length = 0;
	return ENOMEM;
    }
    if (RAND_bytes(crypto->key.data, crypto->key.length) <= 0) {
	free(crypto->key.data);
	crypto->key.length = 0;
	return HX509_CRYPTO_INTERNAL_ERROR;
    }
    if (key)
	return copy_octet_string(&crypto->key, key);
    else
	return 0;
}

int
hx509_crypto_set_params(hx509_crypto crypto, 
			const heim_octet_string *param,
			heim_octet_string *ivec)
{
    if (ivec == NULL)
	return 0;
    return decode_CMSCBCParameter(param->data, param->length, ivec, NULL);
}

int
hx509_crypto_get_params(hx509_crypto crypto, 
			const heim_octet_string *ivec,
			heim_octet_string *param)
{
    int ret;
    size_t size;

    ASN1_MALLOC_ENCODE(CMSCBCParameter,
		       param->data,
		       param->length,
		       ivec,
		       &size,
		       ret);
    if (ret)
	return ret;
    if (param->length != size)
	_hx509_abort("internal ASN.1 encoder error");
    return 0;
}


int
hx509_crypto_encrypt(hx509_crypto crypto,
		     const void *data,
		     const size_t length,
		     heim_octet_string *ivec,
		     heim_octet_string **ciphertext)
{
    EVP_CIPHER_CTX evp;
    size_t padsize;
    int ret;

    *ciphertext = NULL;

    EVP_CIPHER_CTX_init(&evp);

    ivec->length = EVP_CIPHER_iv_length(crypto->c);
    ivec->data = malloc(ivec->length);
    if (ivec->data == NULL) {
	ret = ENOMEM;
	goto out;
    }

    if (RAND_bytes(ivec->data, ivec->length) <= 0) {
	ret = HX509_CRYPTO_INTERNAL_ERROR;
	goto out;
    }

    ret = EVP_CipherInit_ex(&evp, crypto->c, NULL,
			    crypto->key.data, ivec->data, 1);
    if (ret != 1) {
	EVP_CIPHER_CTX_cleanup(&evp);
	ret = HX509_CRYPTO_INTERNAL_ERROR;
	goto out;
    }

    *ciphertext = calloc(1, sizeof(**ciphertext));
    if (*ciphertext == NULL) {
	ret = ENOMEM;
	goto out;
    }
    
    if (EVP_CIPHER_block_size(crypto->c) == 1) {
	padsize = 0;
    } else {
	int bsize = EVP_CIPHER_block_size(crypto->c);
	padsize = bsize - (length % bsize);
    }
    (*ciphertext)->length = length + padsize;
    (*ciphertext)->data = malloc(length + padsize);
    if ((*ciphertext)->data == NULL) {
	ret = ENOMEM;
	goto out;
    }
	
    memcpy((*ciphertext)->data, data, length);
    if (padsize) {
	int i;
	unsigned char *p = (*ciphertext)->data;
	p += length;
	for (i = 0; i < padsize; i++)
	    *p++ = padsize;
    }

    ret = EVP_Cipher(&evp, (*ciphertext)->data,
		     (*ciphertext)->data,
		     length + padsize);
    if (ret != 1) {
	ret = HX509_CRYPTO_INTERNAL_ERROR;
	goto out;
    }
    ret = 0;

 out:
    if (ret) {
	if (ivec->data) {
	    free(ivec->data);
	    memset(ivec, 0, sizeof(*ivec));
	}
	if (ciphertext) {
	    if ((*ciphertext)->data) {
		free((*ciphertext)->data);
	    }
	    free(*ciphertext);
	    *ciphertext = NULL;
	}
    }
    EVP_CIPHER_CTX_cleanup(&evp);

    return ret;
}

int
hx509_crypto_decrypt(hx509_crypto crypto,
		     const void *data,
		     const size_t length,
		     heim_octet_string *ivec,
		     heim_octet_string *clear)
{
    EVP_CIPHER_CTX evp;
    void *idata = NULL;
    int ret;

    clear->data = NULL;
    clear->length = 0;

    if (ivec && EVP_CIPHER_iv_length(crypto->c) < ivec->length)
	return HX509_CRYPTO_INTERNAL_ERROR;

    if (crypto->key.data == NULL)
	return HX509_CRYPTO_INTERNAL_ERROR;

    if (ivec)
	idata = ivec->data;

    EVP_CIPHER_CTX_init(&evp);

    ret = EVP_CipherInit_ex(&evp, crypto->c, NULL,
			    crypto->key.data, idata, 0);
    if (ret != 1) {
	EVP_CIPHER_CTX_cleanup(&evp);
	return HX509_CRYPTO_INTERNAL_ERROR;
    }

    clear->length = length;
    clear->data = malloc(length);
    if (clear->data == NULL) {
	EVP_CIPHER_CTX_cleanup(&evp);
	clear->length = 0;
	return ENOMEM;
    }

    if (EVP_Cipher(&evp, clear->data, data, length) != 1) {
	return HX509_CRYPTO_INTERNAL_ERROR;
    }
    EVP_CIPHER_CTX_cleanup(&evp);

    if (EVP_CIPHER_block_size(crypto->c) > 1) {
	int padsize;
	unsigned char *p; 
	int j, bsize = EVP_CIPHER_block_size(crypto->c);

	if (clear->length < bsize) {
	    ret = HX509_CMS_PADDING_ERROR;
	    goto out;
	}

	p = clear->data;
	p += clear->length - 1;
	padsize = *p;
	if (padsize > bsize) {
	    ret = HX509_CMS_PADDING_ERROR;
	    goto out;
	}
	clear->length -= padsize;
	for (j = 0; j < padsize; j++) {
	    if (*p-- != padsize) {
		ret = HX509_CMS_PADDING_ERROR;
		goto out;
	    }
	}
    }

    return 0;

 out:
    if (clear->data)
	free(clear->data);
    clear->data = NULL;
    clear->length = 0;
    return ret;
}

typedef int (*PBE_string2key_func)(hx509_context,
				   const char *,
				   const heim_octet_string *,
				   hx509_crypto *, heim_octet_string *, 
				   heim_octet_string *,
				   const heim_oid *, const EVP_MD *);

static int
PBE_string2key(hx509_context context,
	       const char *password,
	       const heim_octet_string *parameters,
	       hx509_crypto *crypto, 
	       heim_octet_string *key, heim_octet_string *iv,
	       const heim_oid *enc_oid,
	       const EVP_MD *md)
{
    PKCS12_PBEParams p12params;
    int passwordlen = strlen(password);
    hx509_crypto c;
    int iter, saltlen, ret;
    unsigned char *salt;

    if (parameters == NULL)
 	return HX509_ALG_NOT_SUPP;

    ret = decode_PKCS12_PBEParams(parameters->data,
				  parameters->length,
				  &p12params, NULL);
    if (ret)
	goto out;

    if (p12params.iterations)
	iter = *p12params.iterations;
    else
	iter = 1;
    salt = p12params.salt.data;
    saltlen = p12params.salt.length;

    /* XXX It needs to be here, but why ?  */
    if (passwordlen == 0)
	password = NULL;

    if (!PKCS12_key_gen (password, passwordlen, salt, saltlen, 
			 PKCS12_KEY_ID, iter, key->length, key->data, md)) {
	ret = HX509_CRYPTO_INTERNAL_ERROR;
	goto out;
    }
    
    if (!PKCS12_key_gen (password, passwordlen, salt, saltlen, 
			 PKCS12_IV_ID, iter, iv->length, iv->data, md)) {
	ret = HX509_CRYPTO_INTERNAL_ERROR;
	goto out;
    }

    ret = hx509_crypto_init(context, NULL, enc_oid, &c);
    if (ret)
	goto out;

    ret = hx509_crypto_set_key_data(c, key->data, key->length);
    if (ret) {
	hx509_crypto_destroy(c);
	goto out;
    }

    *crypto = c;
out:
    free_PKCS12_PBEParams(&p12params);
    return ret;
}

static const heim_oid *
find_string2key(const heim_oid *oid, 
		const EVP_CIPHER **c, 
		const EVP_MD **md,
		PBE_string2key_func *s2k)
{
    if (heim_oid_cmp(oid, oid_id_pbewithSHAAnd40BitRC2_CBC()) == 0) {
	*c = EVP_rc2_40_cbc();
	*md = EVP_sha1();
	*s2k = PBE_string2key;
	return &private_rc2_40_oid;
    } else if (heim_oid_cmp(oid, oid_id_pbeWithSHAAnd128BitRC2_CBC()) == 0) {
	*c = EVP_rc2_cbc();
	*md = EVP_sha1();
	*s2k = PBE_string2key;
	return oid_id_pkcs3_rc2_cbc();
    } else if (heim_oid_cmp(oid, oid_id_pbeWithSHAAnd40BitRC4()) == 0) {
	*c = EVP_rc4_40();
	*md = EVP_sha1();
	*s2k = PBE_string2key;
	return NULL;
    } else if (heim_oid_cmp(oid, oid_id_pbeWithSHAAnd128BitRC4()) == 0) {
	*c = EVP_rc4();
	*md = EVP_sha1();
	*s2k = PBE_string2key;
	return oid_id_pkcs3_rc4();
    } else if (heim_oid_cmp(oid, oid_id_pbeWithSHAAnd3_KeyTripleDES_CBC()) == 0) {
	*c = EVP_des_ede3_cbc();
	*md = EVP_sha1();
	*s2k = PBE_string2key;
	return oid_id_pkcs3_des_ede3_cbc();
    }

    return NULL;
}


int
_hx509_pbe_decrypt(hx509_context context,
		   hx509_lock lock,
		   const AlgorithmIdentifier *ai,
		   const heim_octet_string *econtent,
		   heim_octet_string *content)
{
    const struct _hx509_password *pw;
    heim_octet_string key, iv;
    const heim_oid *enc_oid;
    const EVP_CIPHER *c;
    const EVP_MD *md;
    PBE_string2key_func s2k;
    int i, ret = 0;

    memset(&key, 0, sizeof(key));
    memset(&iv, 0, sizeof(iv));

    memset(content, 0, sizeof(*content));

    enc_oid = find_string2key(&ai->algorithm, &c, &md, &s2k);
    if (enc_oid == NULL) {
	ret = HX509_ALG_NOT_SUPP;
	goto out;
    }

    key.length = EVP_CIPHER_key_length(c);
    key.data = malloc(key.length);
    if (key.data == NULL)
	goto out;

    iv.length = EVP_CIPHER_iv_length(c);
    iv.data = malloc(iv.length);
    if (iv.data == NULL)
	goto out;

    pw = _hx509_lock_get_passwords(lock);

    ret = HX509_CRYPTO_INTERNAL_ERROR;
    for (i = 0; i < pw->len; i++) {
	hx509_crypto crypto;

	ret = (*s2k)(context, pw->val[i], ai->parameters, &crypto, 
		     &key, &iv, enc_oid, md);
	if (ret) {
	    goto out;
	}

	ret = hx509_crypto_decrypt(crypto,
				   econtent->data,
				   econtent->length,
				   &iv,
				   content);
	hx509_crypto_destroy(crypto);
	if (ret)
	    goto out;
				   
    }
out:
    if (key.data)
	free_octet_string(&key);
    if (iv.data)
	free_octet_string(&iv);
    return ret;
}

/*
 *
 */


int
_hx509_match_keys(hx509_cert c, hx509_private_key private_key)
{
    const Certificate *cert;
    const SubjectPublicKeyInfo *spi;
    RSAPublicKey pk;
    RSA *rsa;
    size_t size;
    int ret;

    if (private_key->private_key.rsa == NULL)
	return 0;

    rsa = private_key->private_key.rsa;
    if (rsa->d == NULL || rsa->p == NULL || rsa->q == NULL)
	return 0;

    cert = _hx509_get_cert(c);
    spi = &cert->tbsCertificate.subjectPublicKeyInfo;

    rsa = RSA_new();
    if (rsa == NULL)
	return 0;

    ret = decode_RSAPublicKey(spi->subjectPublicKey.data,
			      spi->subjectPublicKey.length / 8,
			      &pk, &size);
    if (ret) {
	RSA_free(rsa);
	return 0;
    }
    rsa->n = heim_int2BN(&pk.modulus);
    rsa->e = heim_int2BN(&pk.publicExponent);

    free_RSAPublicKey(&pk);

    rsa->d = BN_dup(private_key->private_key.rsa->d);
    rsa->p = BN_dup(private_key->private_key.rsa->p);
    rsa->q = BN_dup(private_key->private_key.rsa->q);

    if (rsa->n == NULL || rsa->e == NULL || 
	rsa->d == NULL || rsa->p == NULL|| rsa->q == NULL) {
	RSA_free(rsa);
	return 0;
    }

    ret = RSA_check_key(rsa);
    RSA_free(rsa);

    return ret == 1;
}
