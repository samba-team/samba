#include "krb5_locl.h"

RCSID("$Id$");

ssize_t
krb5_net_write (krb5_context context,
		int fd,
		const void *buf,
		size_t len)
{
  char *cbuf = (char *)buf;
  ssize_t count;
  size_t rem = len;

  while (rem > 0) {
    count = write (fd, cbuf, rem);
    if (count < 0)
      return count;
    cbuf += count;
    rem -= count;
  }
  return len;
}
