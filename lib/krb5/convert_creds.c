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
#ifdef KRB4
#include <krb.h>

RCSID("$Id$");

static krb5_error_code
check_ticket_flags(TicketFlags f)
{
    return 0; /* maybe add some more tests here? */
}

krb5_error_code
krb524_convert_creds_kdc(krb5_context context, 
			 krb5_creds *v5creds, 
			 struct credentials *v4creds)
{
    krb5_error_code ret;
    krb5_data reply;
    krb5_storage *sp;
    int32_t tmp;
    krb5_data ticket;
    char realm[REALM_SZ];

    ret = check_ticket_flags(v5creds->flags.b);
    if(ret) return ret;
    ret = krb5_sendto_kdc (context,
			   &v5creds->ticket,
			   krb5_princ_realm(context, v5creds->server),
			   &reply);
    sp = krb5_storage_from_mem(reply.data, reply.length);
    if(sp == NULL)
	return ENOMEM;
    krb5_ret_int32(sp, &tmp);
    ret = tmp;
    if(ret == 0){
	memset(v4creds, 0, sizeof(*v4creds));
	ret = krb5_ret_int32(sp, &tmp);
	if(ret) goto out;
	v4creds->kvno = tmp;
	ret = krb5_ret_data(sp, &ticket);
	if(ret) goto out;
	v4creds->ticket_st.length = ticket.length;
	memcpy(v4creds->ticket_st.dat, ticket.data, ticket.length);
	ret = krb5_524_conv_principal(context, 
				      v5creds->server, 
				      v4creds->service, 
				      v4creds->instance, 
				      v4creds->realm);
	if(ret) goto out;
	v4creds->issue_date = v5creds->times.authtime;
	v4creds->lifetime = krb_time_to_life(v4creds->issue_date,
					     v5creds->times.endtime);
	ret = krb5_524_conv_principal(context, v5creds->client, 
				      v4creds->pname, 
				      v4creds->pinst, 
				      realm);
	if(ret) goto out;
	memcpy(v4creds->session, v5creds->session.keyvalue.data, 8);
    }
out:
    krb5_storage_free(sp);
    return ret;
}
#endif
