#include <krb5_locl.h>
#include <crc.h>

RCSID("$Id$");

struct checksum_type {
    int type;
    size_t checksumsize;
    krb5_keytype keytype;
    void (*checksum)(void *, size_t, const krb5_keyblock *, void *);
    int (*verify)(void *, size_t, const krb5_keyblock *, void *);
};

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

static struct checksum_type cm[] = {
  { CKSUMTYPE_NONE,		 0,	KEYTYPE_NULL, NULL_checksum,    NULL},
  { CKSUMTYPE_CRC32,		 4,	KEYTYPE_NULL, CRC_checksum,     NULL},
  { CKSUMTYPE_RSA_MD4,		16,	KEYTYPE_NULL, MD4_checksum,     NULL},
  { CKSUMTYPE_RSA_MD5,		16,	KEYTYPE_NULL, MD5_checksum,     NULL},
  { CKSUMTYPE_RSA_MD4_DES,	24,	KEYTYPE_DES,  MD4_DES_checksum, MD4_DES_verify},
  { CKSUMTYPE_RSA_MD5_DES,	24,	KEYTYPE_DES,  MD5_DES_checksum, MD5_DES_verify}
};

static int num_ctypes = sizeof(cm) / sizeof(cm[0]);

static struct checksum_type *
find_checksum_type(int ctype)
{
    struct checksum_type *c;
    for(c = cm; c < cm + num_ctypes; c++)
	if(ctype == c->type)
	    return c;
    return NULL;
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
