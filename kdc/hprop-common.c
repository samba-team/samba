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

#include "hprop.h"

RCSID("$Id$");

krb5_error_code 
send_priv(krb5_context context, krb5_auth_context ac,
	  krb5_data *data, int fd)
{
    krb5_data packet;
    krb5_error_code ret;
    unsigned char net_len[4];

    ret = krb5_mk_priv (context,
			ac,
			data,
			&packet,
			NULL);
    if (ret)
	return ret;
    
    net_len[0] = (packet.length >> 24) & 0xff;
    net_len[1] = (packet.length >> 16) & 0xff;
    net_len[2] = (packet.length >> 8) & 0xff;
    net_len[3] = packet.length & 0xff;
	
    if (krb5_net_write (context, &fd, net_len, 4) != 4)
	ret = errno;
    else if (krb5_net_write (context, &fd,
			     packet.data, packet.length) != packet.length)
	ret =  errno;
    krb5_data_free(&packet);
    return ret;
}

krb5_error_code
recv_priv(krb5_context context, krb5_auth_context ac, int fd, krb5_data *out)
{
    krb5_error_code ret;
    unsigned char tmp[4];
    unsigned char *buf;
    size_t len;
    krb5_data data;
    hdb_entry entry;
    if(krb5_net_read(context, &fd, tmp, 4) != 4)
	return errno;
    len = (tmp[0] << 24) | (tmp[1] << 16) | (tmp[2] << 8) | tmp[3];
    buf = malloc(len);
    if(krb5_net_read(context, &fd, buf, len) != len)
	return errno;
    data.data = buf;
    data.length = len;
    ret = krb5_rd_priv(context, ac, &data, out, NULL);
    if(ret) return ret;
    free(buf);
    return 0;
}

krb5_error_code
send_clear(krb5_context context, int fd, krb5_data data)
{
    unsigned char tmp[4];
    int len;
    
    tmp[0] = (data.length >> 24) & 0xff;
    tmp[1] = (data.length >> 16) & 0xff;
    tmp[2] = (data.length >> 8) & 0xff;
    tmp[3] = (data.length >> 0) & 0xff;
    len = write(fd, tmp, sizeof(tmp));
    if(len == sizeof(tmp))
	len = write(fd, data.data, data.length);
    if(len != data.length)
	return errno;
    return 0;
}

krb5_error_code
recv_clear(krb5_context context, int fd, krb5_data *out)
{
    unsigned char tmp[4];
    int len;
    len = read(fd, tmp, sizeof(tmp));
    if(len == 0){
	memset(out, 0, sizeof(*out));
	return 0;
    }
	
    if(len == sizeof(tmp)){
	len = (tmp[0] << 24) | (tmp[1] << 16) | (tmp[2] << 8) | tmp[3];
	krb5_data_alloc(out, len);
	len = read(fd, out->data, out->length);
    }
    if(len != out->length)
	return errno;
    return 0;
}
