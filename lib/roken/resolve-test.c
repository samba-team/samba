/*
 * Copyright (c) 1995 - 2004 Kungliga Tekniska Högskolan
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "roken.h"
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
#include "resolve.h"

RCSID("$Id$");

int 
main(int argc, char **argv)
{
    struct dns_reply *r;
    struct resource_record *rr;

    r = dns_lookup(argv[1], argv[2]);
    if(r == NULL){
	printf("No reply.\n");
	return 1;
    }
    if(r->q.type == rk_ns_t_srv)
	dns_srv_order(r);

    for(rr = r->head; rr;rr=rr->next){
	printf("%-30s %-5s %-6d ", rr->domain, dns_type_to_string(rr->type), rr->ttl);
	switch(rr->type){
	case rk_ns_t_ns:
	case rk_ns_t_cname:
	case rk_ns_t_ptr:
	    printf("%s\n", (char*)rr->u.data);
	    break;
	case rk_ns_t_a:
	    printf("%s\n", inet_ntoa(*rr->u.a));
	    break;
	case rk_ns_t_mx:
	case rk_ns_t_afsdb:{
	    printf("%d %s\n", rr->u.mx->preference, rr->u.mx->domain);
	    break;
	}
	case rk_ns_t_srv:{
	    struct srv_record *srv = rr->u.srv;
	    printf("%d %d %d %s\n", srv->priority, srv->weight, 
		   srv->port, srv->target);
	    break;
	}
	case rk_ns_t_txt: {
	    printf("%s\n", rr->u.txt);
	    break;
	}
	case rk_ns_t_sig : {
	    struct sig_record *sig = rr->u.sig;
	    const char *type_string = dns_type_to_string (sig->type);

	    printf ("type %u (%s), algorithm %u, labels %u, orig_ttl %u, sig_expiration %u, sig_inception %u, key_tag %u, signer %s\n",
		    sig->type, type_string ? type_string : "",
		    sig->algorithm, sig->labels, sig->orig_ttl,
		    sig->sig_expiration, sig->sig_inception, sig->key_tag,
		    sig->signer);
	    break;
	}
	case rk_ns_t_key : {
	    struct key_record *key = rr->u.key;

	    printf ("flags %u, protocol %u, algorithm %u\n",
		    key->flags, key->protocol, key->algorithm);
	    break;
	}
	case rk_ns_t_sshfp : {
	    struct sshfp_record *sshfp = rr->u.sshfp;
	    int i;

	    printf ("alg %u type %u length %u data ",
		    sshfp->algorithm, sshfp->type, sshfp->sshfp_len);
	    for (i = 0; i < sshfp->sshfp_len; i++)
		printf("%02X", sshfp->sshfp_data[i]);
	    printf("\n");

	    break;
	}
	default:
	    printf("\n");
	    break;
	}
    }
    
    return 0;
}
