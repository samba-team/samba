/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "krb5_locl.h"

RCSID("$Id$");

struct addr_operations {
    int af;
    krb5_address_type atype;
    size_t max_sockaddr_size;
    krb5_error_code (*sockaddr2addr)(const struct sockaddr *, krb5_address *);
    void (*addr2sockaddr)(const krb5_address *, struct sockaddr *,
			  int *sa_size, int port);
    void (*h_addr2sockaddr)(const char *, struct sockaddr *, int *, int);
    krb5_error_code (*h_addr2addr)(const char *, krb5_address *);
    krb5_boolean (*uninteresting)(const struct sockaddr *);
    void (*anyaddr)(struct sockaddr *, int *, int);
    int (*print_addr)(const krb5_address *, char *, size_t);
};

/*
 * AF_INET - aka IPv4 implementation
 */

static krb5_error_code
ipv4_sockaddr2addr (const struct sockaddr *sa, krb5_address *a)
{
    const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
    unsigned char buf[4];

    a->addr_type = KRB5_ADDRESS_INET;
    memcpy (buf, &sin->sin_addr, 4);
    return krb5_data_copy(&a->address, buf, 4);
}

static void
ipv4_addr2sockaddr (const krb5_address *a,
		    struct sockaddr *sa,
		    int *sa_size,
		    int port)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

    memset (sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    memcpy (&sin->sin_addr, a->address.data, 4);
    sin->sin_port = port;
    *sa_size = sizeof(*sin);
}

static void
ipv4_h_addr2sockaddr(const char *addr,
		     struct sockaddr *sa, int *sa_size, int port)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

    memset (sin, 0, sizeof(*sin));
    *sa_size = sizeof(*sin);
    sin->sin_family = AF_INET;
    sin->sin_port   = port;
    sin->sin_addr   = *((struct in_addr *)addr);
}

static krb5_error_code
ipv4_h_addr2addr (const char *addr,
		  krb5_address *a)
{
    unsigned char buf[4];

    a->addr_type = KRB5_ADDRESS_INET;
    memcpy(buf, addr, 4);
    return krb5_data_copy(&a->address, buf, 4);
}

/*
 * Are there any addresses that should be considered `uninteresting'?
 */

static krb5_boolean
ipv4_uninteresting (const struct sockaddr *sa)
{
    return FALSE;
}

static void
ipv4_anyaddr (struct sockaddr *sa, int *sa_size, int port)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

    memset (sin, 0, sizeof(*sin));
    *sa_size = sizeof(*sin);
    sin->sin_family = AF_INET;
    sin->sin_port   = port;
    sin->sin_addr.s_addr = INADDR_ANY;
}

static int
ipv4_print_addr (const krb5_address *addr, char *str, size_t len)
{
    struct in_addr ia;

    memcpy (&ia, addr->address.data, 4);

    return snprintf (str, len, "IPv4:%s", inet_ntoa(ia));
}

/*
 * AF_INET6 - aka IPv6 implementation
 */

#ifdef HAVE_IPV6

static krb5_error_code
ipv6_sockaddr2addr (const struct sockaddr *sa, krb5_address *a)
{
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;

    if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
	unsigned char buf[4];

	a->addr_type      = KRB5_ADDRESS_INET;
#ifndef IN6_ADDR_V6_TO_V4
#ifdef IN6_EXTRACT_V4ADDR
#define IN6_ADDR_V6_TO_V4(x) (&IN6_EXTRACT_V4ADDR(x))
#else
#define IN6_ADDR_V6_TO_V4(x) ((struct in_addr *)&(x)->s6_addr32[3])
#endif
#endif
	memcpy (buf, IN6_ADDR_V6_TO_V4(&sin6->sin6_addr), 4);
	return krb5_data_copy(&a->address, buf, 4);
    } else {
	a->addr_type = KRB5_ADDRESS_INET6;
	return krb5_data_copy(&a->address,
			      &sin6->sin6_addr,
			      sizeof(sin6->sin6_addr));
    }
}

static void
ipv6_addr2sockaddr (const krb5_address *a,
		    struct sockaddr *sa,
		    int *sa_size,
		    int port)
{
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

    memset (sin6, 0, sizeof(*sin6));
    sin6->sin6_family = AF_INET6;
    memcpy (&sin6->sin6_addr, a->address.data, sizeof(sin6->sin6_addr));
    sin6->sin6_port = port;
    *sa_size = sizeof(*sin6);
}

static void
ipv6_h_addr2sockaddr(const char *addr,
		     struct sockaddr *sa,
		     int *sa_size,
		     int port)
{
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

    memset (sin6, 0, sizeof(*sin6));
    *sa_size = sizeof(*sin6);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port   = port;
    sin6->sin6_addr   = *((struct in6_addr *)addr);
}

static krb5_error_code
ipv6_h_addr2addr (const char *addr,
		  krb5_address *a)
{
    a->addr_type = KRB5_ADDRESS_INET6;
    return krb5_data_copy(&a->address, addr, sizeof(struct in6_addr));
}

/*
 * 
 */

static krb5_boolean
ipv6_uninteresting (const struct sockaddr *sa)
{
#ifndef IN6_IS_ADDR_LOOPBACK
#define IN6_IS_ADDR_LOOPBACK(x) IN6_IS_LOOPBACK(*x)
#endif

    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
    const struct in6_addr *in6 = (const struct in6_addr *)&sin6->sin6_addr;
    
    return IN6_IS_ADDR_LOOPBACK(in6)
	|| IN6_IS_ADDR_LINKLOCAL(in6)
	|| IN6_IS_ADDR_V4COMPAT(in6);
}

static void
ipv6_anyaddr (struct sockaddr *sa, int *sa_size, int port)
{
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

    memset (sin6, 0, sizeof(*sin6));
    *sa_size = sizeof(*sin6);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port   = port;
    sin6->sin6_addr   = in6addr_any;
}

static int
ipv6_print_addr (const krb5_address *addr, char *str, size_t len)
{
    abort ();			/* XXX - not done yet */
}

#endif /* IPv6 */

/*
 * table
 */

static struct addr_operations at[] = {
    {AF_INET,	KRB5_ADDRESS_INET, sizeof(struct sockaddr_in),
     ipv4_sockaddr2addr, ipv4_addr2sockaddr,
     ipv4_h_addr2sockaddr, ipv4_h_addr2addr,
     ipv4_uninteresting, ipv4_anyaddr, ipv4_print_addr},
#ifdef HAVE_IPV6
    {AF_INET6,	KRB5_ADDRESS_INET6, sizeof(struct sockaddr_in6),
     ipv6_sockaddr2addr, ipv6_addr2sockaddr,
     ipv6_h_addr2sockaddr, ipv6_h_addr2addr,
     ipv6_uninteresting, ipv6_anyaddr, ipv6_print_addr}
#endif
};

static int num_addrs = sizeof(at) / sizeof(at[0]);

static size_t max_sockaddr_size = 0;

/*
 * generic functions
 */

static struct addr_operations *
find_af(int af)
{
    struct addr_operations *a;

    for (a = at; a < at + num_addrs; ++a)
	if (af == a->af)
	    return a;
    return NULL;
}

static struct addr_operations *
find_atype(int atype)
{
    struct addr_operations *a;

    for (a = at; a < at + num_addrs; ++a)
	if (atype == a->atype)
	    return a;
    return NULL;
}

krb5_error_code
krb5_sockaddr2address (const struct sockaddr *sa, krb5_address *addr)
{
    struct addr_operations *a = find_af(sa->sa_family);
    if (a == NULL)
	return KRB5_PROG_ATYPE_NOSUPP;
    return (*a->sockaddr2addr)(sa, addr);
}

krb5_error_code
krb5_addr2sockaddr (const krb5_address *addr,
		    struct sockaddr *sa,
		    int *sa_size,
		    int port)
{
    struct addr_operations *a = find_atype(addr->addr_type);

    if (a == NULL)
	return KRB5_PROG_ATYPE_NOSUPP;
    (*a->addr2sockaddr)(addr, sa, sa_size, port);
    return 0;
}

size_t
krb5_max_sockaddr_size (void)
{
    if (max_sockaddr_size == 0) {
	struct addr_operations *a;

	for(a = at; a < at + num_addrs; ++a)
	    max_sockaddr_size = max(max_sockaddr_size, a->max_sockaddr_size);
    }
    return max_sockaddr_size;
}

krb5_boolean
krb5_sockaddr_uninteresting(const struct sockaddr *sa)
{
    struct addr_operations *a = find_af(sa->sa_family);
    if (a == NULL)
	return TRUE;
    return (*a->uninteresting)(sa);
}

krb5_error_code
krb5_h_addr2sockaddr (int af,
		      const char *addr, struct sockaddr *sa, int *sa_size,
		      int port)
{
    struct addr_operations *a = find_af(af);
    if (a == NULL)
	return KRB5_PROG_ATYPE_NOSUPP;
    (*a->h_addr2sockaddr)(addr, sa, sa_size, port);
    return 0;
}

krb5_error_code
krb5_h_addr2addr (int af,
		  const char *haddr, krb5_address *addr)
{
    struct addr_operations *a = find_af(af);
    if (a == NULL)
	return KRB5_PROG_ATYPE_NOSUPP;
    return (*a->h_addr2addr)(haddr, addr);
}

krb5_error_code
krb5_anyaddr (int af,
	      struct sockaddr *sa,
	      int *sa_size,
	      int port)
{
    struct addr_operations *a = find_af (af);

    if (a == NULL)
	return KRB5_PROG_ATYPE_NOSUPP;

    (*a->anyaddr)(sa, sa_size, port);
    return 0;
}

krb5_error_code
krb5_print_address (const krb5_address *addr, char *str, int len, int *ret_len)
{
    struct addr_operations *a = find_atype(addr->addr_type);

    if (a == NULL)
	return KRB5_PROG_ATYPE_NOSUPP;
    *ret_len = (*a->print_addr)(addr, str, len);
    return 0;
}
