#include "kdc_locl.h"

RCSID("$Id$");

int
maybe_version4(unsigned char *buf, int len)
{
    return len > 0 && *buf == 4;
}

krb5_error_code
do_version4()
{
    
}
