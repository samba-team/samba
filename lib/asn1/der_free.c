#include "der_locl.h"

RCSID("$Id$");

void
free_general_string (general_string *str)
{
    free(*str);
}

void
free_octet_string (octet_string *k)
{
    free(k->data);
}
