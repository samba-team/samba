#include "krb5_locl.h"


/*
 * Try to get all addresses, but return the one corresponding to
 * `hostname' if we fail.
 */

krb5_error_code
krb5_get_all_client_addrs (krb5_addresses *res)
{
     krb5_error_code err;
     char hostname[MAXHOSTNAMELEN];
     struct hostent *hostent;

     if (gethostname (hostname, sizeof(hostname)))
	  return errno;
     hostent = gethostbyname (hostname);
     if (hostent == NULL)
	  return errno;
     res->number = 1;
     res->addrs = malloc (sizeof(*res->addrs));
     res->addrs[0].type = hostent->h_addrtype;
     res->addrs[0].address.data = NULL;
     res->addrs[0].address.length = 0;
     err = krb5_data_alloc (&res->addrs[0].address, hostent->h_length);
     if (err)
	  return err;
     memcpy (res->addrs[0].address.data,
	     hostent->h_addr,
	     hostent->h_length);
     return 0;
}

/*
 * Same as above, but with the fall-back to INADDR_ANY.
 */

krb5_error_code
krb5_get_all_server_addrs ()
{
    return 0;
}
