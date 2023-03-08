/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
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

#include "der_locl.h"

RCSID("$Id$");

/*
 * All encoding functions take a pointer `p' to first position in
 * which to write, from the right, `len' which means the maximum
 * number of characters we are able to write.  The function returns
 * the number of characters written in `size' (if non-NULL).
 * The return value is 0 or an error.
 */

int ASN1CALL
der_put_unsigned (unsigned char *p, size_t len, const unsigned *v, size_t *size)
{
    unsigned char *base = p;
    unsigned val = *v;

    *size = 0;

    if (val) {
	while (len > 0 && val) {
	    *p-- = val % 256;
	    val /= 256;
	    --len;
	}
	if (val != 0)
	    return ASN1_OVERFLOW;
	else {
	    if(p[1] >= 128) {
		if(len < 1)
		    return ASN1_OVERFLOW;
		*p-- = 0;
	    }
	    *size = base - p;
	    return 0;
	}
    } else if (len < 1)
	return ASN1_OVERFLOW;
    else {
	*p    = 0;
	*size = 1;
	return 0;
    }
}

int ASN1CALL
der_put_unsigned64 (unsigned char *p, size_t len, const uint64_t *v, size_t *size)
{
    unsigned char *base = p;
    uint64_t val = *v;

    *size = 0;

    if (val) {
       while (len > 0 && val) {
           *p-- = val % 256;
           val /= 256;
           --len;
       }
       if (val != 0)
           return ASN1_OVERFLOW;
       else {
           if(p[1] >= 128) {
               if(len < 1)
                   return ASN1_OVERFLOW;
               *p-- = 0;
           }
           *size = base - p;
           return 0;
       }
    } else if (len < 1)
       return ASN1_OVERFLOW;
    else {
       *p    = 0;
       *size = 1;
       return 0;
    }
}

int ASN1CALL
der_put_integer (unsigned char *p, size_t len, const int *v, size_t *size)
{
    unsigned char *base = p;
    int val = *v;

    *size = 0;

    if(val >= 0) {
	do {
	    if(len < 1)
		return ASN1_OVERFLOW;
	    *p-- = val % 256;
	    len--;
	    val /= 256;
	} while(val);
	if(p[1] >= 128) {
	    if(len < 1)
		return ASN1_OVERFLOW;
	    *p-- = 0;
	    len--;
	}
    } else {
	val = ~val;
	do {
	    if(len < 1)
		return ASN1_OVERFLOW;
	    *p-- = ~(val % 256);
	    len--;
	    val /= 256;
	} while(val);
	if(p[1] < 128) {
	    if(len < 1)
		return ASN1_OVERFLOW;
	    *p-- = 0xff;
	    len--;
	}
    }
    *size = base - p;
    return 0;
}

int ASN1CALL
der_put_integer64 (unsigned char *p, size_t len, const int64_t *v, size_t *size)
{
    unsigned char *base = p;
    int64_t val = *v;

    *size = 0;

    if(val >= 0) {
       do {
           if(len < 1)
               return ASN1_OVERFLOW;
           *p-- = val % 256;
           len--;
           val /= 256;
       } while(val);
       if(p[1] >= 128) {
           if(len < 1)
               return ASN1_OVERFLOW;
           *p-- = 0;
           len--;
       }
    } else {
       val = ~val;
       do {
           if(len < 1)
               return ASN1_OVERFLOW;
           *p-- = ~(val % 256);
           len--;
           val /= 256;
       } while(val);
       if(p[1] < 128) {
           if(len < 1)
               return ASN1_OVERFLOW;
           *p-- = 0xff;
           len--;
       }
    }
    *size = base - p;
    return 0;
}


int ASN1CALL
der_put_length (unsigned char *p, size_t len, size_t val, size_t *size)
{
    if (size)
	*size = 0;

    if (len < 1)
	return ASN1_OVERFLOW;

    if (val < 128) {
	*p = val;
	if (size)
	    *size = 1;
    } else {
	size_t l = 0;

	while(val > 0) {
	    if(len < 2)
		return ASN1_OVERFLOW;
	    *p-- = val % 256;
	    val /= 256;
	    len--;
	    l++;
	}
	*p = 0x80 | l;
	if(size)
	    *size = l + 1;
    }
    return 0;
}

int ASN1CALL
der_put_boolean(unsigned char *p, size_t len, const int *data, size_t *size)
{
    *size = 0;

    if(len < 1)
	return ASN1_OVERFLOW;
    if(*data != 0)
	*p = 0xff;
    else
	*p = 0;
    *size = 1;
    return 0;
}

int ASN1CALL
der_put_general_string (unsigned char *p, size_t len,
			const heim_general_string *str, size_t *size)
{
    size_t slen;

    assert(p != NULL && str != NULL && *str != NULL && size != NULL);
    *size = 0;
    slen = strlen(*str);
    if (len < slen)
	return ASN1_OVERFLOW;
    p -= slen;
    memcpy (p+1, *str, slen);
    *size = slen;
    return 0;
}

int ASN1CALL
der_put_utf8string (unsigned char *p, size_t len,
		    const heim_utf8_string *str, size_t *size)
{
    return der_put_general_string(p, len, str, size);
}

int ASN1CALL
der_put_printable_string (unsigned char *p, size_t len,
			  const heim_printable_string *str, size_t *size)
{
    return der_put_octet_string(p, len, str, size);
}

int ASN1CALL
der_put_ia5_string (unsigned char *p, size_t len,
		    const heim_ia5_string *str, size_t *size)
{
    return der_put_octet_string(p, len, str, size);
}

int ASN1CALL
der_put_bmp_string (unsigned char *p, size_t len,
		    const heim_bmp_string *data, size_t *size)
{
    size_t i;

    assert(p != NULL && data != NULL);

    if (size)
	*size = 0;

    if (len / 2 < data->length)
	return ASN1_OVERFLOW;
    p -= data->length * 2;
    for (i = 0; i < data->length; i++) {
	p[1] = (data->data[i] >> 8) & 0xff;
	p[2] = data->data[i] & 0xff;
	p += 2;
    }
    if (size) *size = data->length * 2;
    return 0;
}

int ASN1CALL
der_put_universal_string (unsigned char *p, size_t len,
			  const heim_universal_string *data, size_t *size)
{
    size_t i;

    if (size)
	*size = 0;

    if (len / 4 < data->length)
	return ASN1_OVERFLOW;
    p -= data->length * 4;
    for (i = 0; i < data->length; i++) {
	p[1] = (data->data[i] >> 24) & 0xff;
	p[2] = (data->data[i] >> 16) & 0xff;
	p[3] = (data->data[i] >> 8) & 0xff;
	p[4] = data->data[i] & 0xff;
	p += 4;
    }
    if (size) *size = data->length * 4;
    return 0;
}

int ASN1CALL
der_put_visible_string (unsigned char *p, size_t len,
			 const heim_visible_string *str, size_t *size)
{
    return der_put_general_string(p, len, str, size);
}

int ASN1CALL
der_put_octet_string (unsigned char *p, size_t len,
		      const heim_octet_string *data, size_t *size)
{
    assert(p != NULL && data != NULL && size != NULL);

    *size = 0;
    if (len < data->length)
	return ASN1_OVERFLOW;
    p -= data->length;
    if (data->length)
        memcpy(p+1, data->data, data->length);
    *size = data->length;
    return 0;
}

int ASN1CALL
der_put_heim_integer (unsigned char *p, size_t len,
		     const heim_integer *data, size_t *size)
{
    unsigned char *buf;
    int hibitset = 0;

    assert(p != NULL);

    if (size)
	*size = 0;

    if (data->length == 0) {
	if (len < 1)
	    return ASN1_OVERFLOW;
	*p-- = 0;
	if (size)
	    *size = 1;
	return 0;
    }
    if (len < data->length)
	return ASN1_OVERFLOW;

    assert(data->data != NULL);
    buf = data->data;
    len -= data->length;

    if (data->negative) {
	ssize_t i;
	int carry;

        /*
         * We represent the parsed integer as a positive value with a
         * negativity flag.  But we need to put it on the wire as the shortest
         * twos-complement byte sequence possible.  So we're going to negate
         * the number as go.
         */
        if (data->length == 1 && *(unsigned char *)data->data == 1) {
            *(p--) = 0xff;
        } else {
            for (i = data->length - 1, carry = 1; i >= 0; i--) {
                *p = buf[i] ^ 0xff;
                if (carry)
                    carry = !++*p;
                p--;
            }
            if (p[1] < 128) {
                if (len < 1)
                    return ASN1_OVERFLOW;
                *p-- = 0xff;
                len--;
                hibitset = 1;
            }
        }
    } else {
	p -= data->length;
	memcpy(p + 1, buf, data->length);

	if (p[1] >= 128) {
	    if (len < 1)
		return ASN1_OVERFLOW;
	    p[0] = 0;
	    len--;
	    hibitset = 1;
	}
    }
    if (size)
	*size = data->length + hibitset;
    return 0;
}

int ASN1CALL
der_put_generalized_time (unsigned char *p, size_t len,
			  const time_t *data, size_t *size)
{
    heim_octet_string k;
    size_t l;
    int e;

    e = _heim_time2generalizedtime (*data, &k, 1);
    if (e)
	return e;
    e = der_put_octet_string(p, len, &k, &l);
    free(k.data);
    if(e)
	return e;
    if(size)
	*size = l;
    return 0;
}

int ASN1CALL
der_put_utctime (unsigned char *p, size_t len,
		 const time_t *data, size_t *size)
{
    heim_octet_string k;
    size_t l;
    int e;

    e = _heim_time2generalizedtime (*data, &k, 0);
    if (e)
	return e;
    e = der_put_octet_string(p, len, &k, &l);
    free(k.data);
    if(e)
	return e;
    if(size)
	*size = l;
    return 0;
}

int ASN1CALL
der_put_oid (unsigned char *p, size_t len,
	     const heim_oid *data, size_t *size)
{
    unsigned char *base = p;
    size_t n;

    for (n = data->length - 1; n >= 2; --n) {
	unsigned u = data->components[n];

	if (len < 1)
	    return ASN1_OVERFLOW;
	*p-- = u % 128;
	u /= 128;
	--len;
	while (u > 0) {
	    if (len < 1)
		return ASN1_OVERFLOW;
	    *p-- = 128 + u % 128;
	    u /= 128;
	    --len;
	}
    }
    if (len < 1)
	return ASN1_OVERFLOW;
    *p-- = 40 * data->components[0] + data->components[1];
    *size = base - p;
    return 0;
}

/*
 * Output a copy of the DER TLV at `p' with a different outermost tag.
 *
 * This is used in the implementation of IMPLICIT tags in generated decoder
 * functions.
 */
int ASN1CALL
der_replace_tag(const unsigned char *p, size_t len,
                unsigned char **out, size_t *outlen,
                Der_class class, Der_type type,
                unsigned int tag)
{
    Der_class found_class;
    Der_type found_type;
    unsigned int found_tag;
    size_t payload_len, l, tag_len, len_len;
    int e;

    assert(p != NULL && out != NULL && outlen != NULL);

    e = der_get_tag(p, len, &found_class, &found_type, &found_tag, &l);
    if (e)
        return e;
    if (found_type != type)
        return ASN1_TYPE_MISMATCH;
    /* We don't care what found_class and found_tag are though */
    tag_len = der_length_tag(tag);
    p += l;
    len -= l;
    e = der_get_length(p, len, &payload_len, &len_len);
    if (e)
        return e;
    if (payload_len > len)
        return ASN1_OVERFLOW;
    /*
     * `p' now points at the payload; `*out' + the length of the tag points at
     * where we should copy the DER length and the payload.
     */
    if ((*out = malloc(*outlen = tag_len + len_len + payload_len)) == NULL)
        return ENOMEM;
    memcpy(*out + tag_len, p, len_len + payload_len);

    /* Put the new tag */
    e = der_put_tag(*out + tag_len - 1, tag_len, class, type, tag, &l);
    if (e)
        return e;
    if (l != tag_len)
        return ASN1_OVERFLOW;
    return 0;
}

#if 0
int ASN1CALL
der_encode_implicit(unsigned char *p, size_t len,
                    asn1_generic_encoder_f encoder,
                    void *obj, size_t *size,
                    Der_type type,
                    unsigned int ttag, Der_class iclass, unsigned int itag)
{
    size_t ttaglen = der_length_tag(ttag);
    size_t itaglen = der_length_tag(itag);
    size_t l;
    unsigned char *p2;
    int e;

    assert(p != NULL && size != NULL);

    /* Attempt to encode in place */
    e = encoder(p, len, obj, size);
    if (e == 0) {
        /* Fits!  Rewrite tag, adjust reported size. */
        e = der_put_tag(p + ttaglen - 1, itaglen, iclass, type, itag, &l);
        if (e == 0) {
            (*size) -= ttaglen;
            (*size) += itaglen;
        }
        return e;
    }
    if (e != ASN1_OVERFLOW || itaglen <= ttaglen)
        return e;

    /*
     * Did not fit because ttaglen > itaglen and this was the last / only thing
     * being encoded in a buffer of just the right size.
     */
    if ((p2 = malloc(len + ttaglen - itaglen)) == NULL)
        e = ENOMEM;
    if (e == 0)
        e = encoder(p2 + len + ttaglen - itaglen - 1, len + ttaglen - itaglen,
                    obj, size);
    if (e == 0)
        e = der_put_tag(p2 + ttaglen - 1, itaglen, iclass, type, itag, &l);
    if (e == 0) {
        (*size) -= ttaglen;
        (*size) += itaglen;
        memcpy(p - *size, p2 + ttaglen - itaglen, *size);
    }
    free(p2);
    return e;
}
#endif

int ASN1CALL
der_put_tag (unsigned char *p, size_t len, Der_class class, Der_type type,
	     unsigned int tag, size_t *size)
{
    if (tag <= 30) {
	if (len < 1)
	    return ASN1_OVERFLOW;
	*p = MAKE_TAG(class, type, tag);
	*size = 1;
    } else {
	size_t ret = 0;
	unsigned int continuation = 0;

	do {
	    if (len < 1)
		return ASN1_OVERFLOW;
	    *p-- = tag % 128 | continuation;
	    len--;
	    ret++;
	    tag /= 128;
	    continuation = 0x80;
	} while(tag > 0);
	if (len < 1)
	    return ASN1_OVERFLOW;
	*p-- = MAKE_TAG(class, type, 0x1f);
	ret++;
	*size = ret;
    }
    return 0;
}

int ASN1CALL
der_put_length_and_tag (unsigned char *p, size_t len, size_t len_val,
			Der_class class, Der_type type,
			unsigned int tag, size_t *size)
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

    ret += l;
    *size = ret;
    return 0;
}

int
_heim_time2generalizedtime (time_t t, heim_octet_string *s, int gtimep)
{
     struct tm tm;
     const size_t len = gtimep ? 15 : 13;
     int bytes;

     s->data = NULL;
     s->length = 0;
     if (_der_gmtime(t, &tm) == NULL)
	 return ASN1_BAD_TIMEFORMAT;
     s->data = malloc(len + 1);
     if (s->data == NULL)
	 return ENOMEM;
     s->length = len;
     if (gtimep)
	 bytes = snprintf(s->data, len + 1, "%04d%02d%02d%02d%02d%02dZ",
                          tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                          tm.tm_hour, tm.tm_min, tm.tm_sec);
     else
	 bytes = snprintf(s->data, len + 1, "%02d%02d%02d%02d%02d%02dZ",
                          tm.tm_year % 100, tm.tm_mon + 1, tm.tm_mday,
                          tm.tm_hour, tm.tm_min, tm.tm_sec);

     if (bytes > len)
         abort();

     return 0;
}

int ASN1CALL
der_put_bit_string (unsigned char *p, size_t len,
		    const heim_bit_string *data, size_t *size)
{
    size_t data_size;

    assert(p != NULL && data != NULL && size != NULL);

    *size = 0;
    data_size = (data->length + 7) / 8;
    if (len < data_size + 1)
	return ASN1_OVERFLOW;
    p -= data_size + 1;

    memcpy (p+2, data->data, data_size);
    if (data->length && (data->length % 8) != 0)
	p[1] = 8 - (data->length % 8);
    else
	p[1] = 0;
    *size = data_size + 1;
    return 0;
}

int
_heim_der_set_sort(const void *a1, const void *a2)
{
    const heim_octet_string *s1, *s2;
    int ret;

    assert(a1 != NULL && a2 != NULL);
    s1 = a1;
    s2 = a2;
    ret = memcmp(s1->data, s2->data,
		 s1->length < s2->length ? s1->length : s2->length);
    if (ret != 0)
	return ret;
    return (int)(s1->length - s2->length);
}
