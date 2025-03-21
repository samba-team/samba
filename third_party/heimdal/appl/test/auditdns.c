/*-
 * Copyright (c) 2024 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "resolve.h"
#include "roken.h"

#if (__STDC_VERSION__ - 0) < 199901L
# define restrict /* empty */
#endif

struct rk_dns_reply *
rk_dns_lookup(const char *domain, const char *type_name)
{

    fprintf(stderr, "DNS leak: %s %s (%s)\n", __func__, domain, type_name);
    abort();
}

struct hostent *
gethostbyname(const char *name)
{

    fprintf(stderr, "DNS leak: %s %s\n", __func__, name);
    abort();
}

#ifdef HAVE_GETHOSTBYNAME2

struct hostent *
gethostbyname2(const char *name, int af)
{

    fprintf(stderr, "DNS leak: %s %s\n", __func__, name);
    abort();
}

#endif	/* HAVE_GETHOSTBYNAME2 */

struct hostent *
gethostbyaddr(const void *addr, socklen_t len, int af)
{
    const socklen_t maxlen[] = {
	[AF_INET] = sizeof(struct in_addr),
	[AF_INET6] = sizeof(struct in6_addr),
    };
    char n[INET6_ADDRSTRLEN + 1];

    if (af < 0 || af >= sizeof(maxlen)/sizeof(maxlen[0]) ||
	maxlen[af] == 0 || len < maxlen[af] ||
	inet_ntop(af, addr, n, sizeof n) == NULL)
	fprintf(stderr, "Reverse DNS leak: %s\n", __func__);
    else
	fprintf(stderr, "Reverse DNS leak: %s %s\n", __func__, n);
    abort();
}

#ifdef HAVE_GETADDRINFO

void
freeaddrinfo(struct addrinfo *ai)
{

    free(ai->ai_addr);
    free(ai);
}

int
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *restrict hints,
    struct addrinfo **restrict res)
{
    char *servend;
    unsigned long port;
    union {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
    } *addr = NULL;
    int af[2] = {AF_INET, AF_INET6};
    socklen_t addrlen[2] = {sizeof(addr->sin), sizeof(addr->sin6)};
    int socktype[2] = {SOCK_DGRAM, SOCK_STREAM};
    int proto[2] = {IPPROTO_UDP, IPPROTO_TCP};
    size_t i, j, naddr, nproto;
    struct addrinfo *ai = NULL;
    int error;

    /*
     * DNS audit: Abort unless the user specified hints with
     * AI_NUMERICHOST, AI_NUMERICSERV, and no AI_CANONNAME.
     */
    if (hints == NULL ||
	(hints->ai_flags & AI_NUMERICHOST) == 0 ||
	(hints->ai_flags & AI_NUMERICSERV) == 0 ||
	(hints->ai_flags & AI_CANONNAME) != 0) {
	fprintf(stderr, "DNS leak: %s %s:%s\n",
	    __func__, hostname, servname);
	abort();
    }

    /*
     * Check hints for address family.  If unspecified, use the default
     * set of address families: {AF_INET, AF_INET6}.
     */
    switch (hints->ai_family) {
    case AF_UNSPEC:
	naddr = 2;
	break;
    case AF_INET:
	naddr = 1;
	af[0] = AF_INET;
	addrlen[0] = sizeof(addr->sin);
	break;
    case AF_INET6:
	naddr = 1;
	af[0] = AF_INET6;
	addrlen[0] = sizeof(addr->sin6);
	break;
    default:
	error = EAI_FAMILY;
	goto out;
    }

    /*
     * Check hints for socket type and protocol.  If both are zero, we
     * use the default set of socktype/proto pairs.  If one is
     * specified but not the other, use the default.  If both are
     * specified, make sure they match.
     */
    switch (hints->ai_socktype) {
    case 0:
	if (hints->ai_protocol == 0)
	    nproto = sizeof(proto)/sizeof(proto[0]);
	else
	    nproto = 1;
	break;
    case SOCK_DGRAM:		/* datagram <-> UDP */
	if (hints->ai_protocol != 0 && hints->ai_protocol != IPPROTO_UDP) {
	    error = EAI_SOCKTYPE;
	    goto out;
	}
	socktype[0] = SOCK_DGRAM;
	proto[0] = IPPROTO_UDP;
	nproto = 1;
	break;
    case SOCK_STREAM:		/* stream <-> TCP */
	if (hints->ai_protocol != 0 && hints->ai_protocol != IPPROTO_TCP) {
	    error = EAI_SOCKTYPE;
	    goto out;
	}
	socktype[0] = SOCK_STREAM;
	proto[0] = IPPROTO_TCP;
	nproto = 1;
	break;
    default:
	error = EAI_SOCKTYPE;
	goto out;
    }

    /*
     * Check whether a service is specified at all.
     */
    if (servname == NULL) {
	/*
	 * No service specified.  Use the wildcard port 0.
	 */
	port = 0;
    } else {
	/*
	 * Service specified.  First verify it is at most 5 decimal
	 * digits; then parse it as a nonnegative integer in decimal,
	 * at most 65535.  (This avoids pathological inputs like
	 * -18446744073709551493 for which strtoul will succeed and
	 * return 123 on LP64 platforms.)
	 */
	if (strlen(servname) > strlen("65535") ||
	    strlen(servname) != strspn(servname, "0123456789")) {
	    error = EAI_NONAME;
	    goto out;
	}
	errno = 0;
	port = strtoul(servname, &servend, 10);
	if (servend == servname ||
	    *servend != '\0' ||
	    errno != 0 ||
	    port > 65535) {
	    error = EAI_NONAME;
	    goto out;
	}
    }

    /*
     * Check whether a hostname is specified at all.
     */
    if (hostname == NULL) {
	/*
	 * No hostname.  This only makes sense if we're going to bind
	 * to a socket and receive incoming packets or listen and
	 * accept incoming connections, i.e., only if AI_PASSIVE is
	 * set.  Otherwise, fail with EAI_NONAME.
	 */
	if ((hints->ai_flags & AI_PASSIVE) == 0) {
	    error = EAI_NONAME;
	    goto out;
	}

	/*
	 * Allocate an array of as many addresses as the hints allow.
	 */
	if ((addr = calloc(naddr, sizeof(*addr))) == NULL) {
	    error = EAI_MEMORY;
	    goto out;
	}

	/*
	 * Fill the addresses with the ANY wildcard address, IPv4
	 * 0.0.0.0 or IPv6 `::' (i.e., 0000:0000:....:0000).
	 */
	switch (hints->ai_family) {
	case AF_UNSPEC:
	    assert(naddr == 2);
	    addr[0].sin.sin_family = AF_INET;
	    addr[0].sin.sin_port = htons(port);
	    addr[0].sin.sin_addr.s_addr = htonl(INADDR_ANY);
	    addr[1].sin6.sin6_family = AF_INET6;
	    addr[1].sin6.sin6_port = htons(port);
	    addr[1].sin6.sin6_addr = in6addr_any;
	    break;
	case AF_INET:
	    assert(naddr == 1);
	    addr[0].sin.sin_family = AF_INET;
	    addr[0].sin.sin_port = htons(port);
	    addr[0].sin.sin_addr.s_addr = htonl(INADDR_ANY);
	    break;
	case AF_INET6:
	    assert(naddr == 1);
	    addr[0].sin6.sin6_family = AF_INET6;
	    addr[0].sin6.sin6_port = htons(port);
	    addr[0].sin6.sin6_addr = in6addr_any;
	    break;
	default:
	    error = EAI_FAIL;	/* XXX unreachable */
	    goto out;
	}
	goto have_addr;
    } else {
	/*
	 * Allocate a single socket address record.  Since we have
	 * AI_NUMERICHOST, the hostname can be parsed as only one
	 * address and won't be resolved to an array of possibly >1
	 * addresses.
	 */
	naddr = 1;
	if ((addr = calloc(naddr, sizeof(*addr))) == NULL) {
	    error = EAI_MEMORY;
	    goto out;
	}

	/*
	 * If the hints specify AF_INET, or don't specify anything, try
	 * to parse it as an IPv4 address.  If this fails, it will fall
	 * through.
	 */
	if (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET) {
	    switch (inet_pton(AF_INET, hostname, &addr->sin.sin_addr)) {
	    case -1:		/* system error */
		error = EAI_SYSTEM;
		goto out;
	    case 0:		/* failure */
		break;
	    case 1:		/* success */
		addr->sin.sin_family = AF_INET;
		addr->sin.sin_port = htons(port);
		af[0] = AF_INET;
		addrlen[0] = sizeof(addr->sin);
		goto have_addr;
	    }
	}

	/*
	 * If the hints specify AF_INET6, or don't specify anything,
	 * try to parse it as an IPv6 address.  If this fails, it will
	 * fall through.
	 */
	if (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET6) {
	    /* XXX scope id? */
	    switch (inet_pton(AF_INET6, hostname, &addr->sin6.sin6_addr)) {
	    case -1:		/* system error */
		error = EAI_SYSTEM;
		goto out;
	    case 0:		/* failure */
		break;
	    case 1:		/* success */
		addr->sin6.sin6_family = AF_INET6;
		addr->sin6.sin6_port = htons(port);
		af[0] = AF_INET6;
		addrlen[0] = sizeof(addr->sin6);
		goto have_addr;
	    }
	}

	/*
	 * Hostname can't be parsed.
	 */
	error = EAI_NONAME;
	goto out;
    }

have_addr:
    /*
     * We have an address, or multiple possible addresses.  Allocate an
     * array of addrinfo records to store the result.
     */
    if ((ai = calloc(naddr * nproto, sizeof(*ai))) == NULL) {
	error = EAI_MEMORY;
	goto out;
    }

    /*
     * Fill in the addrinfo records with the cartesian product of
     * matching address families and matching socktype/protocol pairs.
     *
     * XXX Consider randomizing the output for fun!
     */
    for (i = 0; i < naddr; i++) {
	for (j = 0; j < nproto; j++) {
	    ai[i*nproto + j] = (struct addrinfo) {
		.ai_flags = 0, /* input flags, unused on output */
		.ai_family = af[i],
		.ai_addrlen = addrlen[i],
		.ai_addr = &addr[i].sa,
		.ai_socktype = socktype[j],
		.ai_protocol = proto[j],
		.ai_canonname = NULL,
		.ai_next = &ai[i*nproto + j + 1],
	    };
	}
    }
    addr = NULL;		/* reference consumed by ai[...].ai_addr */

    /*
     * Null out the last addrinfo's next pointer.
     */
    ai[naddr*nproto - 1].ai_next = NULL;

    /*
     * Success!
     */
    error = 0;

out:
    /*
     * In the event of error, free whatever we've allocated so far.
     * Make sure to save and restore errno in case free touches it,
     * because EAI_SYSTEM requires errno to report the system error.
     */
    if (error) {
	int errno_save = errno;

	if (addr)
	    free(addr);
	addr = NULL;
	if (ai)
	    freeaddrinfo(ai);
	ai = NULL;

	errno = errno_save;
    }
    *res = ai;
    return error;
}

#endif	/* HAVE_GETADDRINFO */

#ifdef HAVE_GETNAMEINFO

int
getnameinfo(const struct sockaddr *restrict sa, socklen_t salen,
    char *restrict node, socklen_t nodelen,
    char *restrict service, socklen_t servicelen,
    int flags)
{
    char n[INET6_ADDRSTRLEN + 1] = "";
    char s[5 + 1] = "";		/* ceil(log_10(2^16)) + 1 */

    /*
     * Call inet_ntop to format the appropriate member of the
     * sockaddr_*.
     */
    switch (sa->sa_family) {
    case AF_INET: {
	struct sockaddr_in sin;

	/*
	 * Verify the socket address length is at least enough for
	 * sockaddr_in, and make a copy to avoid strict aliasing
	 * violation.
	 */
	if (salen < sizeof sin)
	    return EAI_FAIL;
	memcpy(&sin, sa, sizeof sin);

	/*
	 * Use inet_ntop to format sin_addr as x.y.z.w, and use
	 * snprintf to format the port number in decimal.
	 */
	if (inet_ntop(AF_INET, &sin.sin_addr, n, sizeof n) == NULL)
	    return EAI_FAIL;
	snprintf(s, sizeof s, "%d", (int)sin.sin_port);
	break;
    }
    case AF_INET6: {
	struct sockaddr_in6 sin6;

	/*
	 * Verify the socket address length is at least enough for
	 * sockaddr_in6, and make a copy to avoid strict aliasing
	 * violation.
	 */
	if (salen < sizeof sin6)
	    return EAI_FAIL;
	memcpy(&sin6, sa, sizeof sin6);

	/*
	 * Use inet_ntop to format sin6_addr as a:b:c:...:h, and use
	 * snprintf to format the port number in decimal.
	 */
	if (inet_ntop(AF_INET6, &sin6.sin6_addr, n, sizeof n) == NULL)
	    return EAI_FAIL;
	/* XXX scope id? */
	snprintf(s, sizeof s, "%d", (int)sin6.sin6_port);
	break;
    }
    default:
	return EAI_FAMILY;
    }

    /*
     * DNS audit: Abort unless the user specified flags with
     * NI_NUMERICHOST|NI_NUMERICSERV|NI_NUMERICSCOPE.  We format the
     * numeric syntax first so it can be included in the error message
     * to give a clue about what might have DNS leaks.
     *
     * The NI_NUMERICSCOPE test is written in a funny way so that on
     * platforms where it simply doesn't exist (like glibc and
     * Windows), it doesn't spuriously fail -- scope ids naming is
     * probably not a source of network leaks.
     */
    if ((flags & NI_NUMERICHOST) == 0 ||
	(flags & NI_NUMERICSERV) == 0 ||
	(flags & NI_NUMERICSCOPE) != NI_NUMERICSCOPE) {
	fprintf(stderr, "Reverse DNS leak: %s %s %s\n", __func__, n, s);
	abort();
    }

    /*
     * Verify the (numeric) `names' we determined fit in the buffers
     * provided, if any.
     */
    if ((node && nodelen > 0 && strlen(n) >= nodelen) ||
	(service && servicelen > 0 && strlen(s) >= servicelen))
	return EAI_OVERFLOW;

    /*
     * Copy out the answers that were requested.
     */
    if (node)
	strlcpy(node, n, nodelen);
    if (service)
	strlcpy(service, s, servicelen);

    return 0;
}

#endif	/* HAVE_GETNAMEINFO */
