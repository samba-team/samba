/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 *
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

#include "kdc_locl.h"

RCSID("$Id: process.c,v 1.5 2006/10/09 15:37:39 lha Exp $");

/*
 * handle the request in `buf, len', from `addr' (or `from' as a string),
 * sending a reply in `reply'.
 */

int
krb5_kdc_process_request(krb5_context context, 
			 krb5_kdc_configuration *config,
			 unsigned char *buf, 
			 size_t len, 
			 krb5_data *reply,
			 krb5_boolean *prependlength,
			 const char *from,
			 struct sockaddr *addr,
			 int datagram_reply)
{
    KDC_REQ req;
    Ticket ticket;
    DigestREQ digestreq;
    krb5_error_code ret;
    size_t i;

    gettimeofday(&_kdc_now, NULL);
    if(decode_AS_REQ(buf, len, &req, &i) == 0){
	krb5_data req_buffer;

	req_buffer.data = buf;
	req_buffer.length = len;

	ret = _kdc_as_rep(context, config, &req, &req_buffer, 
			  reply, from, addr, datagram_reply);
	free_AS_REQ(&req);
	return ret;
    }else if(decode_TGS_REQ(buf, len, &req, &i) == 0){
	ret = _kdc_tgs_rep(context, config, &req, reply, from, addr);
	free_TGS_REQ(&req);
	return ret;
    }else if(decode_Ticket(buf, len, &ticket, &i) == 0){
	ret = _kdc_do_524(context, config, &ticket, reply, from, addr);
	free_Ticket(&ticket);
	return ret;
    }else if(decode_DigestREQ(buf, len, &digestreq, &i) == 0){
	ret = _kdc_do_digest(context, config, &digestreq, reply, from, addr);
	free_DigestREQ(&digestreq);
	return ret;
    } else if(_kdc_maybe_version4(buf, len)){
	*prependlength = FALSE; /* elbitapmoc sdrawkcab XXX */
	_kdc_do_version4(context, config, buf, len, reply, from, 
			 (struct sockaddr_in*)addr);
	return 0;
    } else if (config->enable_kaserver) {
	ret = _kdc_do_kaserver(context, config, buf, len, reply, from,
			       (struct sockaddr_in*)addr);
	return ret;
    }
			  
    return -1;
}

/*
 * handle the request in `buf, len', from `addr' (or `from' as a string),
 * sending a reply in `reply'.
 *
 * This only processes krb5 requests
 */

int
krb5_kdc_process_krb5_request(krb5_context context, 
			      krb5_kdc_configuration *config,
			      unsigned char *buf, 
			      size_t len, 
			      krb5_data *reply,
			      const char *from,
			      struct sockaddr *addr,
			      int datagram_reply)
{
    KDC_REQ req;
    krb5_error_code ret;
    size_t i;

    gettimeofday(&_kdc_now, NULL);
    if(decode_AS_REQ(buf, len, &req, &i) == 0){
	krb5_data req_buffer;

	req_buffer.data = buf;
	req_buffer.length = len;

	ret = _kdc_as_rep(context, config, &req, &req_buffer,
			  reply, from, addr, datagram_reply);
	free_AS_REQ(&req);
	return ret;
    }else if(decode_TGS_REQ(buf, len, &req, &i) == 0){
	ret = _kdc_tgs_rep(context, config, &req, reply, from, addr);
	free_TGS_REQ(&req);
	return ret;
    }
    return -1;
}
