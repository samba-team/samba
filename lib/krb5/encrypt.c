#include <krb5_locl.h>
#include "crc.h"

RCSID("$Id$");

struct encryption_type {
    int type;
    size_t blocksize;
    size_t confoundersize;
    size_t checksumsize;
    void (*encrypt)(void *, size_t, const krb5_keyblock *, int);
    void (*checksum)(void *, size_t, void *);
};

static void
NULL_checksum(void *p, size_t len, void *result)
{
}

static void
MD4_checksum(void *p, size_t len, void *result)
{
    struct md4 m;
    md4_init(&m);
    md4_update(&m, p, len);
    md4_finito(&m, result);
}

static void
MD5_checksum(void *p, size_t len, void *result)
{
    struct md5 m;
    md5_init(&m);
    md5_update(&m, p, len);
    md5_finito(&m, result);
}

static void
SHA1_checksum(void *p, size_t len, void *result)
{
    struct sha m;
    sha_init(&m);
    sha_update(&m, p, len);
    sha_finito(&m, result);
}

static void
CRC_checksum(void *p, size_t len, void *result)
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
NULL_encrypt(void *p, size_t len, const krb5_keyblock *keyblock, int encrypt)
{
}

static void
DES_encrypt(void *p, size_t len, 
		const krb5_keyblock *keyblock, int encrypt)
{
    des_cblock key;
    des_key_schedule schedule;
    memcpy(&key, keyblock->keyvalue.data, sizeof(key));
    des_set_key(&key, schedule);
    des_cbc_encrypt(p, p, len, schedule, &key, encrypt);
}

static void
DES3_encrypt(void *p, size_t len, const krb5_keyblock *keyblock, int encrypt)
{
    abort ();
}

static struct encryption_type em [] = {
    { ETYPE_DES_CBC_CRC, 8, 8, 4, DES_encrypt, CRC_checksum },
    { ETYPE_DES_CBC_MD4, 8, 8, 16, DES_encrypt, MD4_checksum },
    { ETYPE_DES_CBC_MD5, 8, 8, 16, DES_encrypt, MD5_checksum },
    { ETYPE_NULL, 1, 0, 0, NULL_encrypt, NULL_checksum },
};

static int num_etypes = sizeof(em) / sizeof(em[0]);

static krb5_error_code
krb5_do_encrypt(krb5_context context,
		 void *ptr, 
		 size_t len,
		 struct encryption_type *et,
		 krb5_keyblock *keyblock,
		 krb5_data *result)
{
    size_t sz;
    unsigned char *p;
    sz = len + et->confoundersize + et->checksumsize;
    sz = (sz + et->blocksize - 1) & ~ (et->blocksize - 1);
    p = calloc(1, sz);
    if (p == NULL)
	return ENOMEM;
    des_rand_data(p, et->confoundersize);
    memcpy(p + et->confoundersize + et->checksumsize, ptr, len);
    (*et->checksum)(p, sz, p + et->confoundersize);
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
    unsigned char *his_checksum;
    unsigned char *p = ptr;
    size_t outlen;

    (*et->encrypt)(ptr, len, keyblock, 0);
    his_checksum = malloc(et->checksumsize);
    memcpy(his_checksum, p + et->confoundersize, et->checksumsize);
    memset(p + et->confoundersize, 0, et->checksumsize);

    (*et->checksum)(p, len, p + et->confoundersize);
    if (memcmp(p + et->confoundersize, his_checksum, et->checksumsize))
	return KRB5KRB_AP_ERR_BAD_INTEGRITY;

    outlen = len - et->confoundersize - et->checksumsize;
    result->data = malloc(outlen);
    if(result->data == NULL)
	return ENOMEM;
    result->length = outlen;
    memcpy(result->data, p + et->confoundersize + et->checksumsize, outlen);
    return 0;
}

krb5_error_code
krb5_encrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      int etype,
	      krb5_keyblock *keyblock,
	      krb5_data *result)
{
    struct encryption_type *e;
    for(e = em; e < em + num_etypes; e++)
	if(etype == e->type)
	    return krb5_do_encrypt(context, ptr, len, e, keyblock, result);
    return KRB5_PROG_ETYPE_NOSUPP;
}
