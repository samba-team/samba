#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_read_message (krb5_context context,
		   krb5_pointer p_fd,
		   krb5_data *data)
{
    krb5_error_code ret;
    u_int32_t len;
    u_int8_t buf[4];
    int fd = *((int *)p_fd);

    if (krb5_net_read (context, fd, buf, 4) != 4)
	return errno;
    len = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    ret = krb5_data_alloc (data, len);
    if (ret)
	return ret;
    if (krb5_net_read (context, fd, data->data, len) != len) {
	krb5_data_free (data);
	return errno;
    }
    return 0;
}
