/* $Id$ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "der.h"

/*
 * All decoding functions take a pointer `p' to first position in
 * which to read, from the left, `len' which means the maximum
 * number of characters we are able to read and return an int
 * indicating how many actually got read, or <0 in case of errors.
 */

int
der_get_int (unsigned char *p, int len, unsigned *ret)
{
  int val = 0;
  int oldlen = len;

  while (len--)
    val = val * 256 + *p++;
  *ret = val;
  return oldlen;
}

int
der_get_length (unsigned char *p, int len, int *ret)
{
  int val;

  if (--len < 0)
    return -1;
  val = *p++;
  if (val < 128) {
    *ret = val;
    return 1;
  } else {
    int l;
    unsigned tmp;

    val &= 0x7F;
    if (len < val)
      return -1;
    l = der_get_int (p, val, &tmp);
    *ret = tmp;
    if (l < 0)
      return l;
    else
      return l+1;
  }
}

int
der_get_general_string (unsigned char *p, int len, char **str)
{
  int l, slen;
  char *s;

  l = der_get_length (p, len, &slen);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  if (len < slen)
    return -1;
  s = malloc (slen + 1);
  if (s == NULL)
    return -1;
  memcpy (s, p, slen);
  s[slen] = '\0';
  *str = s;
  return slen + l;
}

int
der_get_octet_string (unsigned char *p, int len, krb5_data *data)
{
  int l, slen;

  l = der_get_length (p, len, &slen);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  if (len < slen)
    return -1;
  data->len = slen;
  data->data = malloc(slen);
  if (data->data == NULL && data->len != 0)
    return -1;
  memcpy (data->data, p, slen);
  return slen + l;
}

int
der_get_tag (unsigned char *p, int len, Der_class *class, Der_type *type,
	     int *tag)
{
  if (len < 1)
    return -1;
  *class = ((*p) >> 6) & 0x03;
  *type = ((*p) >> 5) & 0x01;
  *tag = (*p) & 0x1F;
  return 1;
}

int
der_match_tag (unsigned char *p, int len, Der_class class, Der_type type,
	       int tag)
{
  int l;
  Der_class thisclass;
  Der_type thistype;
  int thistag;

  l = der_get_tag (p, len, &thisclass, &thistype, &thistag);
  if (l < 0)
    return l;
  if (class == thisclass && type == thistype && tag == thistag)
    return l;
  else
    return -1;
}

int
der_match_tag_and_length (unsigned char *p, int len,
			  Der_class class, Der_type type, int tag,
			  int *length_ret)
{
  int ret = 0;
  int l;

  l = der_match_tag (p, len, class, type, tag);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  l = der_get_length (p, len, length_ret);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  return ret;
}

int
decode_integer (unsigned char *p, int len, unsigned *num)
{
  int ret = 0;
  int l, reallen;

  l = der_match_tag (p, len, UNIV, PRIM, UT_Integer);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  l = der_get_length (p, len, &reallen);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  l = der_get_int (p, reallen, num);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  return ret;
}

int
decode_general_string (unsigned char *p, int len, char **str)
{
  int ret = 0;
  int l;

  l = der_match_tag (p, len, UNIV, PRIM, UT_GeneralString);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  l = der_get_general_string (p, len, str);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  return ret;
}

int
decode_octet_string (unsigned char *p, int len, krb5_data *k)
{
  int ret = 0;
  int l;

  l = der_match_tag (p, len, UNIV, PRIM, UT_OctetString);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  l = der_get_octet_string (p, len, k);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  return ret;
}

static void
generalizedtime2time (char *s, time_t *t)
{
  struct tm tm;

  sscanf (s, "%04d%02d%02d%02d%02d%02dZ",
	  &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
	  &tm.tm_min, &tm.tm_sec);
  tm.tm_year -= 1900;
  tm.tm_mon -= 1;
  tm.tm_isdst = 0;

  *t = mktime(&tm);
#ifdef HAVE_STRUCT_TM_TM_GMTOFF
  *t += tm.tm_gmtoff;
#elif defined(HAVE_TIMEZONE)
  *t -= timezone;
#else
#error Cannot figure out where in timezoneworld we are
#endif
}

int
decode_generalized_time (unsigned char *p, int len, time_t *t)
{
  krb5_data k;
  char times[32]; /* XXX */
  int ret = 0;
  int l;

  l = der_match_tag (p, len, UNIV, PRIM, UT_GeneralizedTime);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  l = der_get_octet_string (p, len, &k);
  if (l < 0)
    return l;
  p += l;
  len -= l;
  ret += l;
  strncpy(times, (char*)k.data, k.len);
  times[k.len] = 0;
  generalizedtime2time (times, t);
  free (k.data);
  return ret;
}
