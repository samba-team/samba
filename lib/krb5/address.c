#include "krb5_locl.h"

RCSID("$Id$");

#if 0
/* This is the supposedly MIT-api version */

krb5_boolean
krb5_address_search(krb5_context context,
		    const krb5_address *addr,
		    krb5_address *const *addrlist)
{
  krb5_address *a;

  while((a = *addrlist++))
    if (krb5_address_compare (context, addr, a))
      return TRUE;
  return FALSE;
}
#endif

krb5_boolean
krb5_address_search(krb5_context context,
		    const krb5_address *addr,
		    const krb5_addresses *addrlist)
{
    int i;

    for (i = 0; i < addrlist->len; ++i)
	if (krb5_address_compare (context, addr, addrlist->val[i]))
	    return TRUE;
    return FALSE;
}

krb5_boolean
krb5_address_compare(krb5_context context,
		     const krb5_address *addr1,
		     const krb5_address *addr2)
{
  return addr1->addr_type == addr2->addr_type
    && memcmp (addr1->address.data, addr2->address.data, addr1->address.length);
}

int
krb5_address_order(krb5_context context,
		   const krb5_address *addr1,
		   const krb5_address *addr2)
{
  abort ();
}

krb5_error_code
krb5_copy_addresses(krb5_context context,
		    const krb5_addresses *inaddr,
		    krb5_addresses *outaddr)
{
    copy_HostAddresses(inaddr, outaddr);
    return 0;
}

krb5_error_code
krb5_free_address(krb5_context context,
		  krb5_address *address)
{
  krb5_data_free (&address->address);
  return 0;
}

krb5_error_code
krb5_free_addresses(krb5_context context,
		    krb5_addresses *addresses)
{
    free_HostAddresses(addresses);
    return 0;
}
