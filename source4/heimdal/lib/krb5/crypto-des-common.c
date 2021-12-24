/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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

/* Functions which are used by both single and triple DES enctypes */

#include "krb5_locl.h"

/*
 * A = A xor B. A & B are 8 bytes.
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_xor8(unsigned char *a, const unsigned char *b)
{
    a[0] ^= b[0];
    a[1] ^= b[1];
    a[2] ^= b[2];
    a[3] ^= b[3];
    a[4] ^= b[4];
    a[5] ^= b[5];
    a[6] ^= b[6];
    a[7] ^= b[7];
}

#if defined(DES3_OLD_ENCTYPE) || defined(HEIM_WEAK_CRYPTO)
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_des_checksum(krb5_context context,
		   const EVP_MD *evp_md,
		   struct _krb5_key_data *key,
		   const struct krb5_crypto_iov *iov,
		   int niov,
		   Checksum *cksum)
{
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    EVP_MD_CTX *m;
    DES_cblock ivec;
    int i;
    unsigned char *p = cksum->checksum.data;

    krb5_generate_random_block(p, 8);

    m = EVP_MD_CTX_create();
    if (m == NULL)
	return krb5_enomem(context);

    EVP_DigestInit_ex(m, evp_md, NULL);
    EVP_DigestUpdate(m, p, 8);
    for (i = 0; i < niov; i++) {
	if (_krb5_crypto_iov_should_sign(&iov[i]))
	    EVP_DigestUpdate(m, iov[i].data.data, iov[i].data.length);
    }
    EVP_DigestFinal_ex (m, p + 8, NULL);
    EVP_MD_CTX_destroy(m);
    memset_s(&ivec, sizeof(ivec), 0, sizeof(ivec));
    EVP_CipherInit_ex(&ctx->ectx, NULL, NULL, NULL, (void *)&ivec, -1);
    EVP_Cipher(&ctx->ectx, p, p, 24);

    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_des_verify(krb5_context context,
		 const EVP_MD *evp_md,
		 struct _krb5_key_data *key,
		 const struct krb5_crypto_iov *iov,
		 int niov,
		 Checksum *C)
{
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    EVP_MD_CTX *m;
    unsigned char tmp[24];
    unsigned char res[16];
    DES_cblock ivec;
    krb5_error_code ret = 0;
    int i;

    m = EVP_MD_CTX_create();
    if (m == NULL)
	return krb5_enomem(context);

    memset_s(&ivec, sizeof(ivec), 0, sizeof(ivec));
    EVP_CipherInit_ex(&ctx->dctx, NULL, NULL, NULL, (void *)&ivec, -1);
    EVP_Cipher(&ctx->dctx, tmp, C->checksum.data, 24);

    EVP_DigestInit_ex(m, evp_md, NULL);
    EVP_DigestUpdate(m, tmp, 8); /* confounder */
    for (i = 0; i < niov; i++) {
	if (_krb5_crypto_iov_should_sign(&iov[i]))
	    EVP_DigestUpdate(m, iov[i].data.data, iov[i].data.length);
    }
    EVP_DigestFinal_ex (m, res, NULL);
    EVP_MD_CTX_destroy(m);
    if(ct_memcmp(res, tmp + 8, sizeof(res)) != 0) {
	krb5_clear_error_message (context);
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
    memset_s(res, sizeof(res), 0, sizeof(res));
    return ret;
}

#endif

static krb5_error_code
RSA_MD5_checksum(krb5_context context,
		 krb5_crypto crypto,
		 struct _krb5_key_data *key,
		 unsigned usage,
		 const struct krb5_crypto_iov *iov,
		 int niov,
		 Checksum *C)
{
    if (_krb5_evp_digest_iov(crypto, iov, niov, C->checksum.data,
			     NULL, EVP_md5(), NULL) != 1)
	krb5_abortx(context, "md5 checksum failed");

    return 0;
}

struct _krb5_checksum_type _krb5_checksum_rsa_md5 = {
    CKSUMTYPE_RSA_MD5,
    "rsa-md5",
    64,
    16,
    F_CPROOF,
    RSA_MD5_checksum,
    NULL
};
