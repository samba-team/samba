/* $Id$ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "der.h"

void
free_integer (unsigned *num)
{
}

int
free_general_string (char **str)
{
    free(*str);
}

int
free_octet_string (krb5_data *k)
{
    free(k->data);
}

int
free_generalized_time (unsigned char *p, int len, time_t *t)
{
}
