/* $Id$ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "der.h"

/*
 * All encoding functions take a pointer `p' to first position in
 * which to write, from the right, `len' which means the maximum
 * number of characters we are able to write and return an int
 * indicating how many actually got written, or <0 in case of errors.
 */

int
der_put_int (unsigned char *p, int len, unsigned val)
{
  unsigned char *base = p;

  if (val) {
    while (len > 0 && val) {
      *p-- = val % 256;
      val /= 256;
      --len;
    }
    if (val)
      return -1;
    else
      return base - p;
  } else if (len < 1)
    return -1;
  else {
    *p = 0;
    return 1;
  }
}

int
der_put_length (unsigned char *p, int len, int val)
{
  if (val < 128) {
    if (len < 1)
      return -1;
    else {
      *p = val;
      return 1;
    }
  } else {
    int l;

    l = der_put_int (p, len - 1,val);
    if (l < 0)
      return l;
    p -= l;
    *p = 0x80 | l;
    return l + 1;
  }
}

int
der_put_general_string (unsigned char *p, int len, char *str)
{
  int slen = strlen(str);
  int l;

  if (len < slen)
    return -1;
  p -= slen;
  len -= slen;
  memcpy (p+1, str, slen);
  l = der_put_length (p, len, slen);
  if(l < 0)
    return l;
  return slen + l;
}

int
der_put_octet_string (unsigned char *p, int len, krb5_data *data)
{
  int l;

  if (len < data->len)
    return -1;
  p -= data->len;
  len -= data->len;
  memcpy (p+1, data->data, data->len);
  l = der_put_length (p, len, data->len);
  if (l < 0)
    return l;
  return l + data->len;
}

int
der_put_tag (unsigned char *p, int len, Der_class class, Der_type type,
	     int tag)
{
  if (len < 1)
    return -1;
  *p = (class << 6) | (type << 5) | tag; /* XXX */
  return 1;
}

int
encode_integer (unsigned char *p, int len, void *data)
{
  unsigned num = *((unsigned *)data);
  int ret = 0;
  int l;

  l = der_put_int (p, len, num);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  l = der_put_length (p, len, l);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  l = der_put_tag (p, len, UNIV, PRIM, UT_Integer);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  return ret;
}

int
encode_general_string (unsigned char *p, int len, void *data)
{
  char *str = *((char **)data);
  int ret = 0;
  int l;

  l = der_put_general_string (p, len, str);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  l = der_put_tag (p, len, UNIV, PRIM, UT_GeneralString);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  return ret;
}

int
encode_octet_string (unsigned char *p, int len, void *data)
{
  krb5_data *k = (krb5_data *)data;
  int ret = 0;
  int l;

  l = der_put_octet_string (p, len, k);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  l = der_put_tag (p, len, UNIV, PRIM, UT_OctetString);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  return ret;
}

static void
time2generalizedtime (time_t t, krb5_data *s)
{
     struct tm *tm;

     s->data = malloc(16);
     s->len = 15;
     tm = gmtime (&t);
     sprintf (s->data, "%04d%02d%02d%02d%02d%02dZ", tm->tm_year + 1900,
	      tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min,
	      tm->tm_sec);
}

int
encode_generalized_time (unsigned char *p, int len, void *data)
{
  time_t *t = (time_t *)data;
  krb5_data k;
  int l;
  int ret = 0;

  time2generalizedtime (*t, &k);
  l = der_put_octet_string (p, len, &k);
  free (k.data);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  l = der_put_tag (p, len, UNIV, PRIM, UT_GeneralizedTime);
  if (l < 0)
    return l;
  p -= l;
  len -= l;
  ret += l;
  return ret;
}
