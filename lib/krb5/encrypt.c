/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
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

#include <krb5_locl.h>
#include "crc.h"

RCSID("$Id$");

struct encryption_type {
    krb5_enctype type;
    size_t blocksize;
    size_t confoundersize;
    void (*encrypt)(void *, size_t, const krb5_keyblock *, int);
    krb5_keytype keytype;
    krb5_cksumtype cksumtype;
    const char *name;
};

static void
NULL_encrypt(void *p, size_t len, const krb5_keyblock *keyblock, int encrypt)
{
}

static void
DES_encrypt_null_ivec(void *p, size_t len, 
		      const krb5_keyblock *keyblock, int encrypt)
{
    des_cblock key;
    des_cblock ivec;
    des_key_schedule schedule;
    memcpy(&key, keyblock->keyvalue.data, sizeof(key));
    des_set_key(&key, schedule);
    memset (&ivec, 0, sizeof(ivec));
    des_cbc_encrypt(p, p, len, schedule, &ivec, encrypt);
}

static void
DES_encrypt_key_ivec(void *p, size_t len, 
		     const krb5_keyblock *keyblock, int encrypt)
{
    des_cblock key;
    des_key_schedule schedule;
    memcpy(&key, keyblock->keyvalue.data, sizeof(key));
    des_set_key(&key, schedule);
    des_cbc_encrypt(p, p, len, schedule, &key, encrypt);
    memset(&key, 0, sizeof(key));
    memset(&schedule, 0, sizeof(schedule));
}

static void
DES3_encrypt_null_ivec(void *p, size_t len, 
		       const krb5_keyblock *keyblock, int encrypt)
{
    des_cblock key;
    des_key_schedule schedule[3];
    int i;
    for(i = 0; i < 3; i++){
	memcpy(&key, (char*)keyblock->keyvalue.data + 8*i, 8);
	des_set_key(&key, schedule[i]);
    }
    memset(&key, 0, sizeof(key));
    des_ede3_cbc_encrypt(p, p, len, schedule[0], schedule[1], schedule[2],
			 &key, encrypt);
    memset(&schedule, 0, sizeof(schedule));
}

static struct encryption_type em [] = {
    { ETYPE_DES3_CBC_SHA1, 8, 8, DES3_encrypt_null_ivec, 
      KEYTYPE_DES3, CKSUMTYPE_SHA1, "des3-cbc-sha1" },
    { ETYPE_DES3_CBC_MD5, 8, 8, DES3_encrypt_null_ivec, 
      KEYTYPE_DES3, CKSUMTYPE_RSA_MD5, "des3-cbc-md5" },
    { ETYPE_DES_CBC_MD5, 8, 8, DES_encrypt_null_ivec,
      KEYTYPE_DES,  CKSUMTYPE_RSA_MD5, "des-cbc-md5" },
    { ETYPE_DES_CBC_MD4, 8, 8, DES_encrypt_null_ivec,
      KEYTYPE_DES,  CKSUMTYPE_RSA_MD4, "des-cbc-md4" },
    { ETYPE_DES_CBC_CRC, 8, 8, DES_encrypt_key_ivec,
      KEYTYPE_DES,  CKSUMTYPE_CRC32, "des-cbc-crc" },
    { ETYPE_NULL, 1, 0, NULL_encrypt, KEYTYPE_NULL, CKSUMTYPE_NONE, "null" },
};

static int num_etypes = sizeof(em) / sizeof(em[0]);

static struct encryption_type *
find_encryption_type(int etype)
{
    struct encryption_type *e;
    for(e = em; e < em + num_etypes; e++)
	if(etype == e->type)
	    return e;
    return NULL;
}

krb5_boolean
krb5_etype_valid(krb5_context context,
		 krb5_enctype etype)
{
    struct encryption_type *e;

    e = find_encryption_type(etype);
    return e != NULL && etype != ETYPE_NULL;
}

krb5_error_code
krb5_etype_to_string(krb5_context context,
		     krb5_enctype etype,
		     char **string)
{
    struct encryption_type *e;
    e = find_encryption_type(etype);
    if(e == NULL)
	return KRB5_PROG_ETYPE_NOSUPP;
    *string = strdup(e->name);
    return 0;
}

krb5_error_code
krb5_string_to_etype(krb5_context context,
		     const char *string,
		     krb5_enctype *etype)
{
    int i;
    for(i = 0; i < num_etypes; i++)
	if(strcasecmp(em[i].name, string) == 0){
	    *etype = em[i].type;
	    return 0;
	}
    return KRB5_PROG_ETYPE_NOSUPP;
}

krb5_error_code
krb5_keytype_to_etypes(krb5_context context,
		       krb5_keytype keytype,
		       krb5_enctype **etypes)
{
    krb5_enctype *tmp, *tmp2;
    struct encryption_type *e;
    int i;

    tmp = malloc((num_etypes + 1) * sizeof(*tmp));
    if (tmp == NULL)
	return ENOMEM;
    i = 0;
    for (e = em; e < em + num_etypes; ++e)
	if (e->keytype == keytype)
	    tmp[i++] = e->type;
    tmp[i++] = 0;
    tmp2 = realloc (tmp, i * sizeof(*tmp));
    if (tmp2 == NULL) {
	free (tmp);
	return ENOMEM;
    }
    *etypes = tmp2;
    return 0;
}

krb5_error_code
krb5_etype_to_keytype(krb5_context context,
		      krb5_enctype etype,
		      krb5_keytype *keytype)
{
    struct encryption_type *e;
    e = find_encryption_type(etype);
    if(e == NULL)
	return KRB5_PROG_ETYPE_NOSUPP;
    *keytype = e->keytype;
    return 0;
}

krb5_error_code
krb5_decode_keytype(krb5_context context,
		    krb5_keytype *keytype,
		    int decode)
{
    if(context->ktype_is_etype){
	krb5_error_code ret;
	if(decode) {
	    krb5_keytype kt;
	    ret = krb5_etype_to_keytype(context, 
					(krb5_enctype)*keytype, 
					&kt);
	    if(ret)
		return ret;
	    *keytype = kt;
	}else{
	    krb5_enctype et;
	    ret = krb5_keytype_to_etype(context, 
					*keytype, 
					&et);
	    if(ret)
		return ret;
	    *keytype = (krb5_keytype)et;
	}
    }
    return 0;
}

krb5_error_code
krb5_decode_keyblock(krb5_context context,
		     krb5_keyblock *key,
		     int decode)
{
    return krb5_decode_keytype(context, &key->keytype, decode);
}

void
krb5_generate_random_block(void *buf, size_t len)
{
    des_cblock tmp;
    unsigned char *p = buf;
    size_t l;
    while(len){
	des_new_random_key(&tmp);
	l = len > 8 ? 8 : len;
	memcpy(p, tmp, l);
	p += l;
	len -= l;
    }
}

static krb5_error_code
krb5_do_encrypt(krb5_context context,
		void *ptr, 
		size_t len,
		struct encryption_type *et,
		const krb5_keyblock *keyblock,
		krb5_data *result)
{
    size_t sz;
    size_t checksumsize;
    unsigned char *p;
    krb5_error_code ret;
    Checksum cksum;
    
    ret = krb5_cksumsize(context, et->cksumtype, &checksumsize);
    if(ret)
	return ret;
    sz = len + et->confoundersize + checksumsize;
    sz = (sz + et->blocksize - 1) & ~ (et->blocksize - 1);
    p = calloc(1, sz);
    if (p == NULL)
	return ENOMEM;
    krb5_generate_random_block(p, et->confoundersize); /* XXX */
    memcpy(p + et->confoundersize + checksumsize, ptr, len);

    krb5_create_checksum(context, et->cksumtype, p, sz, NULL, &cksum);
    memcpy(p + et->confoundersize, cksum.checksum.data, checksumsize);
    free_Checksum(&cksum);
    (*et->encrypt)(p, sz, keyblock, 1);
    result->data = p;
    result->length = sz;
    return 0;
}

static krb5_error_code
krb5_do_decrypt(krb5_context context,
		void *ptr,
		size_t len,
		struct encryption_type *et,
		const krb5_keyblock *keyblock,
		krb5_data *result)
{
    unsigned char *p = ptr;
    size_t outlen;
    Checksum cksum;
    krb5_error_code ret;

    cksum.cksumtype = et->cksumtype;
    ret = krb5_cksumsize(context, cksum.cksumtype, &cksum.checksum.length);
    if(ret)
	return ret;
    outlen = len - et->confoundersize - cksum.checksum.length;
    cksum.checksum.data = malloc(cksum.checksum.length);
    if(cksum.checksum.data == NULL)
	return ENOMEM;
    (*et->encrypt)(ptr, len, keyblock, 0);

    memcpy(cksum.checksum.data, p + et->confoundersize, cksum.checksum.length);
    memset(p + et->confoundersize, 0, cksum.checksum.length);
    
    ret = krb5_verify_checksum (context,
				ptr, 
				len,
				keyblock,
				&cksum);
    free_Checksum(&cksum);
    if(ret)
	return ret;
    
    result->data = malloc(outlen);
    if(result->data == NULL)
	return ENOMEM;
    result->length = outlen;
    memcpy(result->data, p + (len - outlen), outlen);
    return 0;
}

krb5_error_code
krb5_encrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      int etype,
	      const krb5_keyblock *keyblock,
	      krb5_data *result)
{
    struct encryption_type *e;
    if((e = find_encryption_type(etype)))
	return krb5_do_encrypt(context, ptr, len, e, keyblock, result);
    return KRB5_PROG_ETYPE_NOSUPP;
}

krb5_error_code
krb5_encrypt_EncryptedData(krb5_context context,
			   void *ptr,
			   size_t len,
			   int etype,
			   int kvno,
			   const krb5_keyblock *keyblock,
			   EncryptedData *result)
{
    result->etype = etype;
    if(kvno){
	result->kvno = malloc(sizeof(*result->kvno));
	*result->kvno = kvno;
    }else
	result->kvno = NULL;
    return krb5_encrypt(context, ptr, len, etype, keyblock, &result->cipher);
}

krb5_error_code
krb5_decrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      int etype,
	      const krb5_keyblock *keyblock,
	      krb5_data *result)
{
    struct encryption_type *e;
    if((e = find_encryption_type(etype)))
	return krb5_do_decrypt(context, ptr, len, e, keyblock, result);
    return KRB5_PROG_ETYPE_NOSUPP;
}

krb5_error_code
krb5_decrypt_EncryptedData (krb5_context context,
			    EncryptedData *e,
			    const krb5_keyblock *keyblock,
			    krb5_data *result)
{
    return krb5_decrypt(context, e->cipher.data, e->cipher.length, e->etype, 
			keyblock, result);
}

static krb5_error_code
DES_random_key(krb5_data *key)
{
    unsigned char *p;
    key->length = 8;
    p = malloc(key->length);
    if(p == NULL)
	return ENOMEM;
    des_new_random_key((void*)p);
    key->data = p;
    return 0;
}

static krb5_error_code
DES3_random_key(krb5_data *key)
{
    unsigned char *p;
    key->length = 24;
    p = malloc(key->length);
    if(p == NULL)
	return ENOMEM;
    des_new_random_key((void*)p);
    des_new_random_key((void*)(p + 8));
    des_new_random_key((void*)(p + 16));
    key->data = p;
    return 0;
}

static struct key_type {
    krb5_keytype ktype;
    krb5_error_code (*random_key)(krb5_data *);
    krb5_enctype best_etype;
    krb5_cksumtype best_cksumtype;
    const char *name;
} km [] = {
    { KEYTYPE_NULL,	NULL,			ETYPE_NULL,
      CKSUMTYPE_NONE,		"null" },
    { KEYTYPE_DES,	DES_random_key,		ETYPE_DES_CBC_MD5,
      CKSUMTYPE_RSA_MD5_DES,	"des" },
    { KEYTYPE_DES_AFS3,	DES_random_key,		ETYPE_DES_CBC_MD5,
      CKSUMTYPE_RSA_MD5_DES,	"des" },
    { KEYTYPE_DES3,	DES3_random_key,	ETYPE_DES3_CBC_SHA1,
      CKSUMTYPE_HMAC_SHA1_DES3, "des3" }
};

static struct key_type*
find_key_type(krb5_keytype ktype)
{
    int i;
    for(i = 0; i < sizeof(km) / sizeof(km[0]); i++)
	if(km[i].ktype == ktype)
	    return &km[i];
    return NULL;
}

krb5_error_code
krb5_generate_random_keyblock(krb5_context context,
			      krb5_keytype ktype,
			      krb5_keyblock *key)
{
    krb5_error_code ret;
    struct key_type *k = find_key_type(ktype);
    if(k == NULL)
	return KRB5_PROG_KEYTYPE_NOSUPP;
    ret = (*k->random_key)(&key->keyvalue);
    if(ret)
	return ret;
    key->keytype = ktype;
    return 0;
}


krb5_error_code
krb5_keytype_to_etype(krb5_context context, krb5_keytype ktype, 
		      krb5_enctype *etype)
{
    struct key_type *k = find_key_type(ktype);
    if(k == NULL)
	return KRB5_PROG_KEYTYPE_NOSUPP;
    *etype = k->best_etype;
    return 0;
}

krb5_error_code
krb5_keytype_to_cksumtype(krb5_context context,
			  krb5_keytype ktype,
			  krb5_cksumtype *ctype)
{
    struct key_type *k = find_key_type(ktype);
    if(k == NULL)
	return KRB5_PROG_KEYTYPE_NOSUPP;
    *ctype = k->best_cksumtype;
    return 0;
}

krb5_error_code
krb5_string_to_keytype(krb5_context context, const char *string,
		       krb5_keytype *ktype)
{
    int i;
    for(i = 0; i < sizeof(km) / sizeof(km[0]); i++)
	if(strcasecmp(km[i].name, string) == 0){
	    *ktype = km[i].ktype;
	    return 0;
	}
    return KRB5_PROG_KEYTYPE_NOSUPP;
}

krb5_error_code
krb5_keytype_to_string(krb5_context context, krb5_keytype ktype, char **string)
{
    struct key_type *k = find_key_type(ktype);
    if(k == NULL)
	return KRB5_PROG_KEYTYPE_NOSUPP;
    *string = strdup(k->name);
    if(*string == NULL)
	return ENOMEM;
    return 0;
}
