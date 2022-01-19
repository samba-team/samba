/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of the Institute nor the names of its contributors
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

static krb5_error_code set_tgs_creds(krb5_context, krb5_ccache,
                                     krb5_const_principal,
                                     krb5_const_principal, krb5_creds *);
static krb5_error_code get_cred(krb5_context, krb5_ccache, krb5_creds *,
                                krb5_flags, const char *, krb5_creds **);
static krb5_error_code get_addresses(krb5_context, krb5_ccache, krb5_creds *,
                                     const char *, krb5_addresses *);

static krb5_error_code
add_addrs(krb5_context context,
	  krb5_addresses *addr,
	  struct addrinfo *ai)
{
    krb5_error_code ret;
    unsigned n, i;
    void *tmp;
    struct addrinfo *a;

    n = 0;
    for (a = ai; a != NULL; a = a->ai_next)
	++n;

    tmp = realloc(addr->val, (addr->len + n) * sizeof(*addr->val));
    if (tmp == NULL && (addr->len + n) != 0) {
	ret = krb5_enomem(context);
	goto fail;
    }
    addr->val = tmp;
    for (i = addr->len; i < (addr->len + n); ++i) {
	addr->val[i].addr_type = 0;
	krb5_data_zero(&addr->val[i].address);
    }
    i = addr->len;
    for (a = ai; a != NULL; a = a->ai_next) {
	krb5_address ad;

	ret = krb5_sockaddr2address (context, a->ai_addr, &ad);
	if (ret == 0) {
	    if (krb5_address_search(context, &ad, addr))
		krb5_free_address(context, &ad);
	    else
		addr->val[i++] = ad;
	}
	else if (ret == KRB5_PROG_ATYPE_NOSUPP)
	    krb5_clear_error_message (context);
	else
	    goto fail;
	addr->len = i;
    }
    return 0;
fail:
    krb5_free_addresses (context, addr);
    return ret;
}

/**
 * Forward credentials for client to host hostname, making them
 * forwardable if forwardable, and returning the blob of data to sent
 * in out_data.  If hostname == NULL, pick it from server.
 *
 * If the server's realm is configured for delegation of destination
 * TGTs, forward a TGT for the server realm, rather than the client
 * realm. This works better with destinations on the far side of a
 * firewall. We also forward the destination TGT when the client
 * TGT is not available (we may have just the destination TGT).
 *
 * @param context A kerberos 5 context.
 * @param auth_context the auth context with the key to encrypt the out_data.
 * @param hostname the host to forward the tickets too.
 * @param client the client to delegate from.
 * @param server the server to delegate the credential too.
 * @param ccache credential cache to use.
 * @param forwardable make the forwarded ticket forwabledable.
 * @param out_data the resulting credential.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_fwd_tgt_creds(krb5_context	context,
		   krb5_auth_context	auth_context,
		   const char		*hostname,
		   krb5_const_principal	client,
		   krb5_const_principal	server,
		   krb5_ccache		ccache,
		   int			forwardable,
		   krb5_data		*out_data)
{
    krb5_flags flags = 0;
    krb5_creds creds;
    krb5_error_code ret;

    flags |= KDC_OPT_FORWARDED;

    if (forwardable)
	flags |= KDC_OPT_FORWARDABLE;

    if (hostname == NULL &&
	krb5_principal_get_type(context, server) == KRB5_NT_SRV_HST) {
	const char *inst = krb5_principal_get_comp_string(context, server, 0);
	const char *host = krb5_principal_get_comp_string(context, server, 1);

	if (inst != NULL &&
	    strcmp(inst, "host") == 0 &&
	    host != NULL &&
	    krb5_principal_get_comp_string(context, server, 2) == NULL)
	    hostname = host;
    }

    /*
     * Fill-in the request creds, the server principal will be the TGS
     * of either the client's or the server's realm.
     */
    ret = set_tgs_creds(context, ccache, client, server, &creds);
    if (ret)
	return ret;

    ret = krb5_get_forwarded_creds (context,
				    auth_context,
				    ccache,
				    flags,
				    hostname,
				    &creds,
				    out_data);

    krb5_free_cred_contents(context, &creds);
    return ret;
}

/**
 * Gets tickets forwarded to hostname. If the tickets that are
 * forwarded are address-less, the forwarded tickets will also be
 * address-less.
 *
 * If the ticket have any address, hostname will be used for figure
 * out the address to forward the ticket too. This since this might
 * use DNS, its insecure and also doesn't represent configured all
 * addresses of the host. For example, the host might have two
 * adresses, one IPv4 and one IPv6 address where the later is not
 * published in DNS. This IPv6 address might be used communications
 * and thus the resulting ticket useless.
 *
 * @param context A kerberos 5 context.
 * @param auth_context the auth context with the key to encrypt the out_data.
 * @param ccache credential cache to use
 * @param flags the flags to control the resulting ticket flags
 * @param hostname the host to forward the tickets too.
 * @param in_creds the in client and server ticket names.  The client
 * and server components forwarded to the remote host.
 * @param out_data the resulting credential.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_forwarded_creds (krb5_context	    context,
			  krb5_auth_context auth_context,
			  krb5_ccache       ccache,
			  krb5_flags        flags,
			  const char        *hostname,
			  krb5_creds        *in_creds,
			  krb5_data         *out_data)
{
    krb5_error_code ret;
    krb5_creds *creds;

    /* Obtain the requested TGT */
    ret = get_cred(context, ccache, in_creds, flags, hostname, &creds);
    if (ret)
        return ret;

    /* Forward obtained creds */
    ret = _krb5_mk_1cred(context, auth_context, creds, out_data, NULL);
    krb5_free_creds(context, creds);
    return ret;
}

/*
 * Get a TGT for forwarding to hostname. If the client TGT is
 * addressless, the forwarded ticket will also be addressless.
 *
 * If the TGT has any addresses, hostname will be used to determine
 * the address to forward the ticket to. Thus, since this might use DNS,
 * it's insecure and also may not capture all the addresses of the host.
 * In general addressless tickets are more robust, be it at a small
 * security penalty.
 *
 * @param context A kerberos 5 context.
 * @param ccache The credential cache to use
 * @param creds Creds with client and server principals
 * @param flags The flags to control the resulting ticket flags
 * @param hostname The hostname of server
 * @param out_creds The resulting credential
 *
 * @return Return an error code or 0.
 */

static krb5_error_code
get_cred(krb5_context      context,
	 krb5_ccache       ccache,
	 krb5_creds	   *creds,
	 krb5_flags        flags,
	 const char        *hostname,
	 krb5_creds        **out_creds)
{
    krb5_error_code ret;
    krb5_kdc_flags kdc_flags;
    krb5_addresses addrs;

    addrs.len = 0;
    addrs.val = NULL;
    ret = get_addresses(context, ccache, creds, hostname, &addrs);
    if (ret)
	return ret;

    kdc_flags.b = int2KDCOptions(flags);
    ret = krb5_get_kdc_cred(context, ccache, kdc_flags, &addrs, NULL,
			    creds, out_creds);

    krb5_free_addresses(context, &addrs);
    return ret;
}

static krb5_error_code
set_tgs_creds(krb5_context		context,
	      krb5_ccache		ccache,
	      krb5_const_principal	client,
	      krb5_const_principal	server,
	      krb5_creds		*creds)
{
    krb5_error_code ret;
    krb5_const_realm client_realm;
    krb5_const_realm server_realm;
    krb5_boolean fwd_dest_tgt;
    krb5_creds *client_tgt;

    client_realm = krb5_principal_get_realm(context, client);
    server_realm = krb5_principal_get_realm(context, server);

    memset (creds, 0, sizeof(*creds));
    ret = krb5_copy_principal(context, client, &creds->client);
    if (ret)
	return ret;
    ret = krb5_make_principal(context, &creds->server, client_realm,
			      KRB5_TGS_NAME, client_realm, NULL);
    if (ret) {
	krb5_free_principal(context, creds->client);
	return ret;
    }

    /*
     * Optionally delegate a TGT for the server's realm, rather than
     * the client's. Do this also when we don't have a client realm TGT.
     *
     * XXX: Note, when we have a start-realm, and delegate-destination-tgt
     * is not set, we must use the start-realm.
     */
    krb5_appdefault_boolean(context, NULL, server_realm,
			    "delegate-destination-tgt", FALSE, &fwd_dest_tgt);

    if (!fwd_dest_tgt) {
	ret = krb5_get_credentials(context, KRB5_GC_CACHED, ccache, creds,
				   &client_tgt);
	if (ret == 0) {
	    krb5_free_creds(context, client_tgt);
	    return ret;
	}
    }

    /*
     * Client TGT inapplicable or unavailable
     */
    krb5_free_principal(context, creds->server);
    creds->server = 0;
    return krb5_make_principal(context, &creds->server, server_realm,
			       KRB5_TGS_NAME, server_realm, NULL);
}

/*
 * Obtain address list for hostname if server realm policy is not addressless.
 */
static krb5_error_code
get_addresses(krb5_context      context,
	      krb5_ccache       ccache,
	      krb5_creds        *creds,
	      const char        *hostname,
	      krb5_addresses    *addrs)
{
    krb5_error_code ret;
    krb5_creds *ticket;
    krb5_const_realm realm;
    krb5_boolean noaddr;
    struct addrinfo *ai;
    int eai;

    if (hostname == 0)
	return 0;

    ret = krb5_get_credentials(context, 0, ccache, creds, &ticket);
    if (ret == 0) {
        noaddr = (ticket->addresses.len == 0) ? TRUE : FALSE;
	krb5_free_creds(context, ticket);
    } else {
	realm = krb5_principal_get_realm(context, creds->server);
	krb5_appdefault_boolean(context, NULL, realm, "no-addresses",
				KRB5_ADDRESSLESS_DEFAULT, &noaddr);
    }

    if (noaddr)
	return 0;

    /* Need addresses, get the address of the remote host. */

    eai = getaddrinfo (hostname, NULL, NULL, &ai);
    if (eai) {
	ret = krb5_eai_to_heim_errno(eai, errno);
	krb5_set_error_message(context, ret,
			       N_("resolving host %s failed: %s",
				  "hostname, error"),
			       hostname, gai_strerror(eai));
	return ret;
    }

    ret = add_addrs(context, addrs, ai);
    freeaddrinfo(ai);

    return ret;
}
