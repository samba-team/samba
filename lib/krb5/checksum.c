#include <krb5_locl.h>

RCSID("$Id$");

struct checksum_type {
    int type;
    size_t checksumsize;
    void (*checksum)(void *, size_t, void *);
};

static struct checksum_type cm[] = {
  { CKSUMTYPE_NONE,		 0,	krb5_NULL_checksum},
  { CKSUMTYPE_CRC32,		 4,	krb5_CRC_checksum},
  { CKSUMTYPE_RSA_MD4,		16,	krb5_MD4_checksum},
  { CKSUMTYPE_RSA_MD5,		16,	krb5_MD5_checksum}
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
