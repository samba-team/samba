#include <krb5_locl.h>

RCSID("$Id$");

struct checksum_type {
    int type;
    size_t checksumsize;
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

static struct checksum_type cm[] = {
  { CKSUMTYPE_NONE,		 0,	NULL_checksum},
  { CKSUMTYPE_CRC32,		 4,	CRC_checksum},
  { CKSUMTYPE_RSA_MD4,		16,	MD4_checksum},
  { CKSUMTYPE_RSA_MD5,		16,	MD5_checksum}
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
		      Checksum *result)
{
    struct checksum_type *c;

    c = find_checksum_type (type);
    if (c == NULL)
	return KRB5_PROG_SUMTYPE_NOSUPP;
    result->cksumtype = type;
    result->checksum.length = c->checksumsize;
    result->checksum.data   = malloc(result->checksum.length);
    if(result->checksum.data == NULL)
	return ENOMEM;

    (*c->checksum)(ptr, len, result->checksum.data);
    return 0;
}

krb5_error_code
krb5_verify_checksum (krb5_context context,
		      void *ptr,
		      size_t len,
		      Checksum *cksum)
{
    void *tmp;
    struct checksum_type *c;
    int ret;

    c = find_checksum_type (cksum->cksumtype);
    if (c == NULL)
	return KRB5_PROG_SUMTYPE_NOSUPP;
    if (cksum->checksum.length != c->checksumsize)
	return KRB5KRB_AP_ERR_MODIFIED;
    tmp = malloc (c->checksumsize);
    if (tmp == NULL)
	return ENOMEM;
    (*c->checksum)(ptr, len, tmp);
    ret = memcmp (cksum->checksum.data, tmp, c->checksumsize);
    free (tmp);
    if (ret == 0)
	return 0;
    else
	return KRB5KRB_AP_ERR_MODIFIED;
}
