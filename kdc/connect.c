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

#include "kdc_locl.h"

RCSID("$Id$");

struct descr {
    int s;
    int type;
    unsigned char *buf;
    size_t size;
    size_t len;
    time_t timeout;
};

static void 
init_socket(struct descr *d, int type, int port)
{
    struct sockaddr_in sin;
    memset(d, 0, sizeof(*d));
    d->s = socket(AF_INET, type, 0);
    if(d->s < 0){
	warn("socket(AF_INET, %d, 0)", type);
	d->s = -1;
	return;
    }
    d->type = type;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if(bind(d->s, (struct sockaddr*)&sin, sizeof(sin)) < 0){
	warn("bind(%d)", port);
	close(d->s);
	d->s = -1;
	return;
    }
    if(type == SOCK_STREAM && listen(d->s, 5) < 0){
	warn("listen");
	close(d->s);
	d->s = -1;
    }
}

static int
init_sockets(struct descr **d)
{
    *d = malloc(4 * sizeof(**d));
    init_socket(*d + 0, SOCK_DGRAM, 88);
    init_socket(*d + 1, SOCK_DGRAM, 750);
    init_socket(*d + 2, SOCK_STREAM, 88);
    init_socket(*d + 3, SOCK_STREAM, 750);
    return 4;
}

    
static int
process_request(krb5_context context, 
		unsigned char *buf, 
		size_t len, 
		krb5_data *reply,
		const char *from)
{
    KDC_REQ req;
    krb5_error_code err;
    size_t i;

    gettimeofday(&now, NULL);
    if(decode_AS_REQ(buf, len, &req, &i) == 0){
	err = as_rep(context, &req, reply, from);
	free_AS_REQ(&req);
	return err;
    }else if(decode_TGS_REQ(buf, len, &req, &i) == 0){
	err = tgs_rep(context, &req, reply, from);
	free_TGS_REQ(&req);
	return err;
    }
    return -1;
}

static void
do_request(krb5_context context, void *buf, size_t len, 
	   int socket, struct sockaddr *from, size_t from_len)
{
    krb5_error_code ret;
    krb5_data reply;
    
    char addr[128] = "<unknown address>";
    if(from->sa_family == AF_INET)
	strcpy(addr, inet_ntoa(((struct sockaddr_in*)from)->sin_addr));
    
    reply.length = 0;
    ret = process_request(context, buf, len, &reply, addr);
    if(reply.length){
	kdc_log(5, "sending %d bytes to %s", reply.length, addr);
	sendto(socket, reply.data, reply.length, 0, from, from_len);
	krb5_data_free(&reply);
    }
}

static void
handle_udp(krb5_context context, struct descr *d)
{
    unsigned char buf[1024];
    struct sockaddr_in from;
    int from_len = sizeof(from);
    size_t n;

    n = recvfrom(d->s, buf, sizeof(buf), 0, 
		 (struct sockaddr*)&from, &from_len);
    if(n < 0){
	warn("recvfrom");
	return;
    }
    if(n == 0){
	return;
    }
    do_request(context, buf, n, d->s, (struct sockaddr*)&from, from_len);
}

static void
clear_descr(struct descr *d)
{
    if(d->buf)
	memset(d->buf, 0, d->size);
    d->len = 0;
    if(d->s != -1)
	close(d->s);
    d->s = -1;
}

static void
handle_tcp(krb5_context context, struct descr *d, int index, int min_free)
{
    unsigned char buf[1024];
    struct sockaddr_in from;
    int from_len = sizeof(from);
    size_t n;

    if(d[index].timeout == 0){
	int s;
	from_len = sizeof(from);
	s = accept(d[index].s, (struct sockaddr*)&from, &from_len);
	if(s < 0){
	    warn("accept");
	    return;
	}
	if(min_free == -1){
	    close(s);
	    return;
	}
	    
	d[min_free].s = s;
	d[min_free].timeout = time(NULL) + 4;
	d[min_free].type = SOCK_STREAM;
	return;
    }
    n = recvfrom(d[index].s, buf, sizeof(buf), 0, 
		 (struct sockaddr*)&from, &from_len);
    if(n < 0){
	warn("recvfrom");
	return;
    }
    if(d[index].size - d[index].len < n){
	if(d[index].size == 0){
	    d[index].buf = malloc(1024);
	    if(d[index].buf == NULL){
		warnx("No memory");
		close(d[index].s);
		return;
	    }
	    d[index].size = 1024;
	    d[index].len = 0;
	}else{
	    unsigned char *tmp;
	    tmp = realloc(d[index].buf, 2 * d[index].size);
	    if(tmp == NULL){
		warnx("No memory");
		close(d[index].s);
		return;
	    }
	}
    }
    memcpy(d[index].buf + d[index].len, buf, n);
    d[index].len += n;
    if(d[index].len > 4 && d[index].buf[0] == 0){
	krb5_storage *sp;
	int32_t len;
	sp = krb5_storage_from_mem(d[index].buf, d[index].len);
	krb5_ret_int32(sp, &len);
	krb5_storage_free(sp);
	if(d[index].len - 4 >= len){
	    memcpy(d[index].buf, d[index].buf + 4, d[index].len - 4);
	    n = 0;
	}
    }
    if(n == 0){
	do_request(context, d[index].buf, d[index].len, 
		   d[index].s, (struct sockaddr*)&from, from_len);
	clear_descr(d + index);
    }
}



void
loop(krb5_context context)
{
    struct descr *d;
    int ndescr;
    ndescr = init_sockets(&d);
    while(exit_flag == 0){
	struct fd_set fds;
	int min_free = -1;
	int max_fd = 0;
	int i;
	FD_ZERO(&fds);
	for(i = 0; i < ndescr; i++){
	    if(d[i].s >= 0){
		if(d[i].type == SOCK_STREAM && 
		   d[i].timeout && d[i].timeout < time(NULL)){
		    clear_descr(&d[i]);
		    continue;
		}
		if(max_fd < d[i].s)
		    max_fd = d[i].s;
		FD_SET(d[i].s, &fds);
	    }else if(min_free < 0 || i < min_free)
		min_free = i;
	}
	if(min_free == -1){
	    struct descr *tmp;
	    tmp = realloc(d, (ndescr + 4) * sizeof(*d));
	    if(tmp == NULL)
		warnx("No memory");
	    else{
		d = tmp;
		memset(d + ndescr, 0, 4 * sizeof(*d));
		min_free = ndescr;
		ndescr += 4;
	    }
	}
    
	switch(select(max_fd + 1, &fds, 0, 0, 0)){
	case 0:
	    break;
	case -1:
	    warn("select");
	    break;
	default:
	    for(i = 0; i < ndescr; i++)
		if(d[i].s >= 0 && FD_ISSET(d[i].s, &fds))
		    if(d[i].type == SOCK_DGRAM)
			handle_udp(context, &d[i]);
		    else if(d[i].type == SOCK_STREAM)
			handle_tcp(context, d, i, min_free);
	}
    }
}
