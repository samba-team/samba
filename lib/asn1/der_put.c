/* $Id$ */

#include "libasn1.h"

RCSID("$Id$");

/*
 * All encoding functions take a pointer `p' to first position in
 * which to write, from the right, `len' which means the maximum
 * number of characters we are able to write and return an int
 * indicating how many actually got written, or <0 in case of errors.
 */

int
der_put_int (unsigned char *p, size_t len, unsigned val, size_t *size)
{
    unsigned char *base = p;

    if (val) {
	while (len > 0 && val) {
	    *p-- = val % 256;
	    val /= 256;
	    --len;
	}
	if (val)
	    return ASN1_OVERFLOW;
	else {
	    *size = base - p;
	    return 0;
	}
    } else if (len < 1)
	return ASN1_OVERFLOW;
    else {
	*p = 0;
	*size = 1;
	return 0;
    }
}

int
der_put_length (unsigned char *p, size_t len, size_t val, size_t *size)
{
    if (val < 128) {
	if (len < 1)
	    return ASN1_OVERFLOW;
	else {
	    *p = val;
	    *size = 1;
	    return 0;
	}
    } else {
	size_t l;
	int e;

	e = der_put_int (p, len - 1, val, &l);
	if (e)
	    return e;
	p -= l;
	*p = 0x80 | l;
	*size = l + 1;
	return 0;
    }
}

int
der_put_general_string (unsigned char *p, size_t len, 
			general_string *str, size_t *size)
{
    size_t slen = strlen(*str);
    size_t l;
    int e;

    if (len < slen)
	return ASN1_OVERFLOW;
    p -= slen;
    len -= slen;
    memcpy (p+1, *str, slen);
    e = der_put_length (p, len, slen, &l);
    if(e)
	return e;
    *size = slen + l;
    return 0;
}

int
der_put_octet_string (unsigned char *p, size_t len, 
		      octet_string *data, size_t *size)
{
    size_t l;
    int e;

    if (len < data->length)
	return ASN1_OVERFLOW;
    p -= data->length;
    len -= data->length;
    memcpy (p+1, data->data, data->length);
    e = der_put_length (p, len, data->length, &l);
    if(e)
	return e;
    *size = l + data->length;
    return 0;
}

int
der_put_tag (unsigned char *p, size_t len, Der_class class, Der_type type,
	     int tag, size_t *size)
{
    if (len < 1)
	return ASN1_OVERFLOW;
    *p = (class << 6) | (type << 5) | tag; /* XXX */
    *size = 1;
    return 0;
}

int
der_put_length_and_tag (unsigned char *p, size_t len, size_t len_val,
			Der_class class, Der_type type, int tag, size_t *size)
{
    size_t ret = 0;
    size_t l;
    int e;

    e = der_put_length (p, len, len_val, &l);
    if(e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_tag (p, len, class, type, tag, &l);
    if(e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}

int
encode_integer (unsigned char *p, size_t len, unsigned *data, size_t *size)
{
    unsigned num = *data;
    size_t ret = 0;
    size_t l;
    int e;
    
    e = der_put_int (p, len, num, &l);
    if(e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_length (p, len, l, &l);
    if (e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_tag (p, len, UNIV, PRIM, UT_Integer, &l);
    if (e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}

int
encode_general_string (unsigned char *p, size_t len, 
		       general_string *data, size_t *size)
{
    size_t ret = 0;
    size_t l;
    int e;

    e = der_put_general_string (p, len, data, &l);
    if (e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_tag (p, len, UNIV, PRIM, UT_GeneralString, &l);
    if (e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}

int
encode_octet_string (unsigned char *p, size_t len, 
		     octet_string *k, size_t *size)
{
    size_t ret = 0;
    size_t l;
    int e;

    e = der_put_octet_string (p, len, k, &l);
    if (e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_tag (p, len, UNIV, PRIM, UT_OctetString, &l);
    if (e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}

void
time2generalizedtime (time_t t, octet_string *s)
{
     struct tm *tm;

     s->data = malloc(16);
     s->length = 15;
     tm = gmtime (&t);
     sprintf (s->data, "%04d%02d%02d%02d%02d%02dZ", tm->tm_year + 1900,
	      tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min,
	      tm->tm_sec);
}

int
encode_generalized_time (unsigned char *p, size_t len, time_t *t, size_t *size)
{
    size_t ret = 0;
    size_t l;
    octet_string k;
    int e;

    time2generalizedtime (*t, &k);
    e = der_put_octet_string (p, len, &k, &l);
    free (k.data);
    if (e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_tag (p, len, UNIV, PRIM, UT_GeneralizedTime, &l);
    if (e)
	return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}
