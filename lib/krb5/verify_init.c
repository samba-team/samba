/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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

void
krb5_verify_init_creds_opt_init(krb5_init_creds_opt *options)
{
    memset (options, 0, sizeof(*options));
}

void
krb5_verify_init_creds_opt_set_ap_req_nofail(krb5_init_creds_opt *options,
					     int ap_req_nofail)
{
    options->flags |= KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL;
    options->ap_req_nofail = ap_req_nofail;
}

krb5_error_code
krb5_verify_init_creds(krb5_context context,
		       krb5_creds *creds,
		       krb5_principal ap_req_server,
		       krb5_keytab ap_req_keytab,
		       krb5_ccache *ccache,
		       krb5_verify_init_creds_opt *options)
{
    krb5_error_code ret;

    if (ap_req_server == NULL) {
	char local_hostname[MAXHOSTNAMELEN];
	chat *hostname;
	struct hostent *hostent;

	if (gethostname (local_hostname, sizeof(local_hostname)) < 0)
	    return errno;
	hostname = local_hostname;
	hostent = gethostbyname (hostname);
	if (hostent != NULL)
	    hostname = hostent->h_name;
	strlwr (hostname);	/* XXX */

	ret = krb5_sname_to_principal (context,
				       hostname,
				       "host",
				       KRB5_NT_SRV_INST,
				       &ap_req_server);
	if (ret)
	    return ret;
    }
    
}
