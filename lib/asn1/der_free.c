#include "asn1_locl.h"

RCSID("$Id$");

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
