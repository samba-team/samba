#include "asn1_locl.h"

RCSID("$Id$");

void
copy_general_string (char **from, char **to)
{
    *to = malloc(strlen(*from) + 1);
    strcpy(*to, *from);
}

void
copy_octet_string (krb5_data *from, krb5_data *to)
{
    to->len = from->len;
    to->data = malloc(to->len);
    memcpy(to->data, from->data, to->len);
}
