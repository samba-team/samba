#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
RCSID("$Id$");
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "der.h"

void
free_integer (unsigned *num)
{
}

void
free_general_string (char **str)
{
    free(*str);
}

void
free_octet_string (krb5_data *k)
{
    free(k->data);
}

void
free_generalized_time (time_t *t)
{
}
