#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_write_message (krb5_context context,
		    krb5_pointer p_fd,
		    krb5_data *data)
{
    u_int32_t len;
    u_int8_t buf[4];
    int fd = *((int *)p_fd);

    len = data->length;
    buf[0] = (len >> 24) & 0xFF;
    buf[1] = (len >> 16) & 0xFF;
    buf[2] = (len >>  8) & 0xFF;
    buf[3] = (len >>  0) & 0xFF;
    if (krb5_net_write (context, fd, buf, 4) != 4
	|| krb5_net_write (context, fd, data->data, len) != len)
	return errno;
    return 0;
}
