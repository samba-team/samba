#include <stdlib.h>
#include <string.h>
#include <der.h>

/*
 * Type functions
 */

krb5_data
string_make_n (int n, char *s)
{
     krb5_data ret;

     ret.len = n;
     ret.data = s;
     return ret;
}

krb5_data
string_make (char *s)
{
     return string_make_n (strlen (s), s);
}

void
string_free (krb5_data s)
{
     free (s.data);
}
