#include "der_locl.h"

RCSID("$Id$");

static size_t
length_int (unsigned val)
{
  size_t ret = 0;

  do {
    ++ret;
    val /= 256;
  } while (val);
  return ret;
}

size_t
length_len (size_t len)
{
  if (len < 128)
    return 1;
  else
    return length_int (len) + 1;
}

size_t
length_integer (unsigned *data)
{
  size_t len = length_int (*data);

  return 1 + length_len(len) + len;
}

size_t
length_general_string (general_string *data)
{
  char *str = *data;
  size_t len = strlen(str);
  return 1 + length_len(len) + len;
}

size_t
length_octet_string (octet_string *k)
{
  return 1 + length_len(k->length) + k->length;
}

size_t
length_generalized_time (time_t *t)
{
  octet_string k;
  size_t ret;

  time2generalizedtime (*t, &k);
  ret = 1 + length_len(k.length) + k.length;
  free (k.data);
  return ret;
}
