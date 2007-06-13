/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"
RCSID("$Id: peer.c 20938 2007-06-06 20:51:34Z lha $");

int
hx509_peer_info_alloc(hx509_context context, hx509_peer_info *peer)
{
    *peer = calloc(1, sizeof(**peer));
    if (*peer == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }
    return 0;
}


static void
free_cms_alg(hx509_peer_info peer)
{
    if (peer->val) {
	size_t i;
	for (i = 0; i < peer->len; i++)
	    free_AlgorithmIdentifier(&peer->val[i]);
	free(peer->val);
	peer->val = NULL;
	peer->len = 0;
    }
}

void
hx509_peer_info_free(hx509_peer_info peer)
{
    if (peer == NULL)
	return;
    if (peer->cert)
	hx509_cert_free(peer->cert);
    free_cms_alg(peer);
    memset(peer, 0, sizeof(*peer));
    free(peer);
}

int
hx509_peer_info_set_cert(hx509_peer_info peer,
			 hx509_cert cert)
{
    if (peer->cert)
	hx509_cert_free(peer->cert);
    peer->cert = hx509_cert_ref(cert);
    return 0;
}

int
hx509_peer_info_set_cms_algs(hx509_context context,
			     hx509_peer_info peer,
			     const AlgorithmIdentifier *val,
			     size_t len)
{
    size_t i;

    free_cms_alg(peer);

    peer->val = calloc(len, sizeof(*peer->val));
    if (peer->val == NULL) {
	peer->len = 0;
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }
    peer->len = len;
    for (i = 0; i < len; i++) {
	int ret;
	ret = copy_AlgorithmIdentifier(&val[i], &peer->val[i]);
	if (ret) {
	    hx509_clear_error_string(context);
	    free_cms_alg(peer);
	    return ret;
	}
    }
    return 0;
}

#if 0

/*
 * S/MIME
 */

int
hx509_peer_info_parse_smime(hx509_peer_info peer,
			    const heim_octet_string *data)
{
    return 0;
}

int
hx509_peer_info_unparse_smime(hx509_peer_info peer,
			      heim_octet_string *data)
{
    return 0;
}

/*
 * For storing hx509_peer_info to be able to cache them.
 */

int
hx509_peer_info_parse(hx509_peer_info peer,
		      const heim_octet_string *data)
{
    return 0;
}

int
hx509_peer_info_unparse(hx509_peer_info peer,
		     heim_octet_string *data)
{
    return 0;
}
#endif
