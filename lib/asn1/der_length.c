#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
RCSID("$Id$");
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "der.h"

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
length_len (int len)
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
length_general_string (char **data)
{
  char *str = *data;
  size_t len = strlen(str);
  return 1 + length_len(len) + len;
}

size_t
length_octet_string (krb5_data *k)
{
  return 1 + length_len(k->len) + k->len;
}

size_t
length_generalized_time (time_t *t)
{
  krb5_data k;
  size_t ret;

  time2generalizedtime (*t, &k);
  ret = 1 + length_len(k.len) + k.len;
  free (k.data);
  return ret;
}
