#include "test_locl.h"
#include <gssapi.h>
RCSID("$Id$");

void
write_token (int sock, gss_buffer_t buf)
{
    u_int32_t len, net_len;
    OM_uint32 min_stat;

    len = buf->length;

    net_len = htonl(len);

    if (write (sock, &net_len, 4) != 4)
	err (1, "write");
    if (write (sock, buf->value, len) != len)
	err (1, "write");

    gss_release_buffer (&min_stat, buf);
}

void
read_token (int sock, gss_buffer_t buf)
{
    u_int32_t len, net_len;

    if (read(sock, &net_len, 4) != 4)
	err (1, "read");
    len = ntohl(net_len);
    buf->length = len;
    buf->value  = malloc(len);
    if (read (sock, buf->value, len) != len)
	err (1, "read");
}

