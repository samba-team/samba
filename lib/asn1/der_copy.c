#include "der_locl.h"

RCSID("$Id$");

void
copy_general_string (const general_string *from, general_string *to)
{
    *to = malloc(strlen(*from) + 1);
    strcpy(*to, *from);
}

void
copy_octet_string (const octet_string *from, octet_string *to)
{
    to->length = from->length;
    to->data = malloc(to->length);
    memcpy(to->data, from->data, to->length);
}
