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
#include <crc.h>

RCSID("$Id$");

struct checksum_type {
    krb5_cksumtype type;
    size_t blocksize;
    size_t checksumsize;
    krb5_keytype keytype;
    void (*checksum)(void *, size_t, const krb5_keyblock *, void *);
    int (*verify)(void *, size_t, const krb5_keyblock *, void *);
    int flags;
    const char *name;
};

/* values for `flags' */
#define F_KEYED		1
#define F_CPROOF	2

static struct checksum_type* find_checksum_type(krb5_cksumtype);


static void
NULL_checksum(void *p, size_t len, const krb5_keyblock *k, void *result)
{
}

static void
MD4_checksum(void *p, size_t len, const krb5_keyblock *k, void *result)
{
    struct md4 m;
    md4_init(&m);
    md4_update(&m, p, len);
    md4_finito(&m, result);
}

static void
MD5_checksum(void *p, size_t len, const krb5_keyblock *k, void *result)
{
    struct md5 m;
    md5_init(&m);
    md5_update(&m, p, len);
    md5_finito(&m, result);
}

static void
SHA1_checksum(void *p, size_t len, const krb5_keyblock *k, void *result)
{
    struct sha m;
    sha_init(&m);
    sha_update(&m, p, len);
    sha_finito(&m, result);
}

static void
CRC_checksum(void *p, size_t len, const krb5_keyblock *k, void *result)
{
    u_int32_t crc;
    unsigned char *r = result;
    crc_init_table ();
    crc = crc_update (p, len, 0);
    r[0] = crc & 0xff;
    r[1] = (crc >> 8)  & 0xff;
    r[2] = (crc >> 16) & 0xff;
    r[3] = (crc >> 24) & 0xff;
}

static void
MD4_DES_checksum (void *p, size_t len, const krb5_keyblock *keyblock,
		  void *result)
{
    struct md4 md4;
    des_cblock ivec;
    des_cblock key;
    des_key_schedule schedule;
    int i;
    u_char *r = result;
    u_char *orig_key = (u_char *)keyblock->keyvalue.data;

    md4_init(&md4);
    krb5_generate_random_block(r, 8);
    md4_update(&md4, r, 8);
    md4_update(&md4, p, len);
    md4_finito(&md4, r + 8);
    for (i = 0; i < 8; ++i)
	key[i] = orig_key[i] ^ 0xF0;
    des_set_key(&key, schedule);
    memset (&ivec, 0, sizeof(ivec));
    des_cbc_encrypt(result, result, 24, schedule, &ivec, DES_ENCRYPT);
}

static int
MD4_DES_verify (void *p, size_t len, const krb5_keyblock *keyblock,
		void *other)
{
    des_cblock ivec;
    des_cblock key;
    des_key_schedule schedule;
    int i;
    u_char res[16];
    u_char *orig_key = (u_char *)keyblock->keyvalue.data;
    struct md4 md4;

    for (i = 0; i < 8; ++i)
	key[i] = orig_key[i] ^ 0xF0;
    des_set_key(&key, schedule);
    memset (&ivec, 0, sizeof(ivec));
    des_cbc_encrypt(other, other, 24, schedule, &ivec, DES_DECRYPT);

    md4_init(&md4);
    md4_update(&md4, other, 8);
    md4_update(&md4, p, len);
    md4_finito(&md4, res);

    return memcmp (res, (u_char *)other + 8, 16);
}


static void
MD5_DES_checksum (void *p, size_t len, const krb5_keyblock *keyblock,
		  void *result)
{
    struct md5 md5;
    des_cblock ivec;
    des_cblock key;
    des_key_schedule schedule;
    int i;
    u_char *r = result;
    u_char *orig_key = (u_char *)keyblock->keyvalue.data;

    md5_init(&md5);
    krb5_generate_random_block(r, 8);
    md5_update(&md5, r, 8);
    md5_update(&md5, p, len);
    md5_finito(&md5, r + 8);
    for (i = 0; i < 8; ++i)
	key[i] = orig_key[i] ^ 0xF0;
    des_set_key(&key, schedule);
    memset (&ivec, 0, sizeof(ivec));
    des_cbc_encrypt(result, result, 24, schedule, &ivec, DES_ENCRYPT);
}

static int
MD5_DES_verify (void *p, size_t len, const krb5_keyblock *keyblock,
		void *other)
{
    des_cblock ivec;
    des_cblock key;
    des_key_schedule schedule;
    int i;
    u_char res[16];
    u_char *orig_key = (u_char *)keyblock->keyvalue.data;
    struct md5 md5;

    for (i = 0; i < 8; ++i)
	key[i] = orig_key[i] ^ 0xF0;
    des_set_key(&key, schedule);
    memset (&ivec, 0, sizeof(ivec));
    des_cbc_encrypt(other, other, 24, schedule, &ivec, DES_DECRYPT);

    md5_init(&md5);
    md5_update(&md5, other, 8);
    md5_update(&md5, p, len);
    md5_finito(&md5, res);

    return memcmp (res, (u_char *)other + 8, 16);
}

static void
fix_des3_key(const krb5_keyblock *keyblock, des_key_schedule *sched)
{
    unsigned char *orig_key = keyblock->keyvalue.data;
    des_cblock key[3];
    int i;
    for (i = 0; i < 8; ++i){
	key[0][i] = orig_key[i] ^ 0xF0;
	key[1][i] = orig_key[i+8] ^ 0xF0;
	key[2][i] = orig_key[i+16] ^ 0xF0;
    }
    for(i = 0; i < 3; i++)
	des_set_key(&key[i], sched[i]);
    memset(key, 0, sizeof(key));
}

static void
MD5_DES3_checksum (void *p, size_t len, const krb5_keyblock *keyblock,
		   void *result)
{
    struct md5 md5;
    des_cblock ivec;
    des_key_schedule sched[3];
    unsigned char *r = result;

    md5_init(&md5);
    krb5_generate_random_block(r, 8);
    md5_update(&md5, r, 8);
    md5_update(&md5, p, len);
    md5_finito(&md5, r + 8);
    fix_des3_key(keyblock, sched);
    memset (&ivec, 0, sizeof(ivec));
    des_ede3_cbc_encrypt(result, result, 24, sched[0], sched[1], sched[2], 
			 &ivec, DES_ENCRYPT);
    memset(sched, 0, sizeof(sched));
}

static int
MD5_DES3_verify (void *p, size_t len, const krb5_keyblock *keyblock,
		 void *other)
{
    des_cblock ivec;
    des_key_schedule sched[3];
    unsigned char res[16];
    struct md5 md5;
    
    fix_des3_key(keyblock, sched);
    memset (&ivec, 0, sizeof(ivec));
    des_ede3_cbc_encrypt(other, other, 24, sched[0], sched[1], sched[2], 
			 &ivec, DES_DECRYPT);
    
    memset(sched, 0, sizeof(sched));
    md5_init(&md5);
    md5_update(&md5, other, 8);
    md5_update(&md5, p, len);
    md5_finito(&md5, res);
    
    return memcmp (res, (unsigned char*)other + 8, 16);
}


/* HMAC according to RFC2104 */
static void
hmac(struct checksum_type *cm, void *data, size_t len, 
     const krb5_keyblock *keyblock, void *result)
{
    unsigned char *ipad, *opad;
    unsigned char *key, *tmp_key = NULL;
    size_t key_len;
    int i;
    
    key = keyblock->keyvalue.data;
    key_len = keyblock->keyvalue.length;
    if(key_len > cm->blocksize){
	tmp_key = malloc(cm->checksumsize);
	(*cm->checksum)(key, key_len, keyblock, tmp_key);
	key = tmp_key;
	key_len = cm->checksumsize;
    }
    ipad = malloc(cm->blocksize + len);
    opad = malloc(cm->blocksize + cm->checksumsize);
    memset(ipad, 0x36, cm->blocksize);
    memset(opad, 0x5c, cm->blocksize);
    for(i = 0; i < key_len; i++){
	ipad[i] ^= key[i];
	opad[i] ^= key[i];
    }
    memcpy(ipad + cm->blocksize, data, len);
    (*cm->checksum)(ipad, cm->blocksize + len, keyblock, result);
    memcpy(opad + cm->blocksize, result, cm->checksumsize);
    (*cm->checksum)(opad, cm->blocksize + cm->checksumsize, keyblock, result);
    if(tmp_key)
	free(tmp_key);
    free(ipad);
    free(opad);
}

/* this is used for HMAC-SHA1-DES3, but we make no checks that it
   actually is a DES3 key that is passed */
static void
HMAC_SHA1_checksum(void *data, size_t len, const krb5_keyblock *key, 
		   void *result)
{
    struct checksum_type *c = find_checksum_type(CKSUMTYPE_SHA1);
    hmac(c, data, len, key, result);
}

static struct checksum_type cm[] = {
  { CKSUMTYPE_NONE,		 1,	0,	KEYTYPE_NULL,
    NULL_checksum,    NULL,				0, "none" },
  { CKSUMTYPE_CRC32,		 1,	4,	KEYTYPE_NULL,
    CRC_checksum,     NULL,				0, "crc32" },
  { CKSUMTYPE_RSA_MD4,		64,	16,	KEYTYPE_NULL,
    MD4_checksum,     NULL,				F_CPROOF, "md4" },
  { CKSUMTYPE_RSA_MD5,		64,	16,	KEYTYPE_NULL,
    MD5_checksum,     NULL,				F_CPROOF, "md5" },
  { CKSUMTYPE_RSA_MD4_DES,	64,	24,	KEYTYPE_DES,
    MD4_DES_checksum, MD4_DES_verify,			F_KEYED|F_CPROOF, "md4-des" },
  { CKSUMTYPE_RSA_MD5_DES,	64,	24,	KEYTYPE_DES,
    MD5_DES_checksum, MD5_DES_verify,			F_KEYED|F_CPROOF, "md5-des" },
  { CKSUMTYPE_RSA_MD5_DES3,	64,	24,	KEYTYPE_DES3,
    MD5_DES3_checksum, MD5_DES3_verify,			F_KEYED|F_CPROOF, "md5-des3" },
  { CKSUMTYPE_SHA1,		80,	20,	KEYTYPE_NULL,
    SHA1_checksum,	NULL,				F_CPROOF, "sha1" },
  { CKSUMTYPE_HMAC_SHA1_DES3,	80,	20,	KEYTYPE_DES3,
    HMAC_SHA1_checksum, NULL,				F_KEYED|F_CPROOF, "hmac-sha1-des3" }
};

static int num_ctypes = sizeof(cm) / sizeof(cm[0]);

static struct checksum_type *
find_checksum_type(krb5_cksumtype ctype)
{
    struct checksum_type *c;
    for(c = cm; c < cm + num_ctypes; c++)
	if(ctype == c->type)
	    return c;
    return NULL;
}

krb5_boolean
krb5_checksum_is_keyed(krb5_cksumtype ctype)
{
    struct checksum_type *c = find_checksum_type(ctype);
    if(c == NULL)
	return FALSE;
    return (c->flags & F_KEYED) != 0;
}

krb5_boolean
krb5_checksum_is_collision_proof(krb5_cksumtype ctype)
{
    struct checksum_type *c = find_checksum_type(ctype);
    if(c == NULL)
	return FALSE;
    return (c->flags & F_CPROOF) != 0;
}

krb5_error_code
krb5_checksum_to_string(krb5_context context, krb5_cksumtype ctype, 
			char **string)
{
    struct checksum_type *c = find_checksum_type(ctype);
    if(c == NULL)
	return KRB5_PROG_SUMTYPE_NOSUPP;
    *string = strdup(c->name);
    return 0;
}

krb5_error_code
krb5_string_to_checksum(krb5_context context, const char *string, 
			krb5_cksumtype *ctype)
{
    int i;
    for(i = 0; i < num_ctypes; i++)
	if(strcasecmp(cm[i].name, string) == 0){
	    *ctype = cm[i].type;
	    return 0;
	}
    return KRB5_PROG_SUMTYPE_NOSUPP;
}

krb5_error_code
krb5_cksumsize(krb5_context context,
	       krb5_cksumtype type,
	       size_t *size)
{
    struct checksum_type *c = find_checksum_type(type);
    if(c == NULL)
	return KRB5_PROG_SUMTYPE_NOSUPP;
    
    *size = c->checksumsize;
    return 0;
}

krb5_error_code
krb5_create_checksum (krb5_context context,
		      krb5_cksumtype type,
		      void *ptr,
		      size_t len,
		      const krb5_keyblock *keyblock,
		      Checksum *result)
{
    struct checksum_type *c;

    c = find_checksum_type (type);
    if (c == NULL)
	return KRB5_PROG_SUMTYPE_NOSUPP;
    if (c->keytype != KEYTYPE_NULL && c->keytype != keyblock->keytype)
	return KRB5_PROG_KEYTYPE_NOSUPP;
    result->cksumtype = type;
    result->checksum.length = c->checksumsize;
    result->checksum.data   = malloc(result->checksum.length);
    if(result->checksum.data == NULL)
	return ENOMEM;

    (*c->checksum)(ptr, len, keyblock, result->checksum.data);
    return 0;
}

krb5_error_code
krb5_verify_checksum (krb5_context context,
		      void *ptr,
		      size_t len,
		      const krb5_keyblock *keyblock,
		      Checksum *cksum)
{
    void *tmp;
    struct checksum_type *c;
    int ret;

    c = find_checksum_type (cksum->cksumtype);
    if (c == NULL)
	return KRB5_PROG_SUMTYPE_NOSUPP;
    if (c->keytype != KEYTYPE_NULL && c->keytype != keyblock->keytype)
	return KRB5_PROG_KEYTYPE_NOSUPP;
    if (cksum->checksum.length != c->checksumsize)
	return KRB5KRB_AP_ERR_MODIFIED;
    if (c->verify) {
	ret = (*c->verify)(ptr, len, keyblock, cksum->checksum.data);
    } else {
	tmp = malloc (c->checksumsize);
	if (tmp == NULL)
	    return ENOMEM;
	(*c->checksum)(ptr, len, keyblock, tmp);
	ret = memcmp (cksum->checksum.data, tmp, c->checksumsize);
	free (tmp);
    }
    if (ret == 0)
	return 0;
    else
	return KRB5KRB_AP_ERR_MODIFIED;
}
