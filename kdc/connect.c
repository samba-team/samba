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
    if(type == SOCK_STREAM && listen(d->s, SOMAXCONN) < 0){
	warn("listen");
	close(d->s);
	d->s = -1;
    }
}

static int
init_sockets(struct descr **d)
{
    int nsockets = 4;

#ifdef KASERVER
    nsockets++;
#endif

    *d = malloc(nsockets * sizeof(**d));
    init_socket(*d + 0, SOCK_DGRAM, 88);
    init_socket(*d + 1, SOCK_DGRAM, 750);
    init_socket(*d + 2, SOCK_STREAM, 88);
    init_socket(*d + 3, SOCK_STREAM, 750);
#ifdef KASERVER
    init_socket(*d + 4, SOCK_DGRAM, 7004);
#endif
    return nsockets;
}

    
static int
process_request(unsigned char *buf, 
		size_t len, 
		krb5_data *reply,
		const char *from,
		struct sockaddr *addr)
{
    KDC_REQ req;
#ifdef KRB4
    Ticket ticket;
#endif
    krb5_error_code ret;
    size_t i;

    gettimeofday(&now, NULL);
    if(decode_AS_REQ(buf, len, &req, &i) == 0){
	ret = as_rep(&req, reply, from);
	free_AS_REQ(&req);
	return ret;
    }else if(decode_TGS_REQ(buf, len, &req, &i) == 0){
	ret = tgs_rep(&req, reply, from);
	free_TGS_REQ(&req);
	return ret;
    }
#ifdef KRB4
    else if(maybe_version4(buf, len))
	do_version4(buf, len, reply, from, (struct sockaddr_in*)addr);
    else if(decode_Ticket(buf, len, &ticket, &i) == 0){
	ret = do_524(&ticket, reply, from);
	free_Ticket(&ticket);
	return ret;
    }
#endif
#ifdef KASERVER
    else {
	ret = do_kaserver (buf, len, reply, from, (struct sockaddr_in*)addr);
	return ret;
    }
#endif
			  
    return -1;
}

static void
do_request(void *buf, size_t len, 
	   int socket, struct sockaddr *from, size_t from_len)
{
    krb5_error_code ret;
    krb5_data reply;
    
    char addr[128] = "<unknown address>";
    if(from->sa_family == AF_INET)
	strcpy(addr, inet_ntoa(((struct sockaddr_in*)from)->sin_addr));
    
    reply.length = 0;
    ret = process_request(buf, len, &reply, addr, from);
    if(reply.length){
	kdc_log(5, "sending %d bytes to %s", reply.length, addr);
	sendto(socket, reply.data, reply.length, 0, from, from_len);
	krb5_data_free(&reply);
    }
}

static void
handle_udp(struct descr *d)
{
    unsigned char *buf;
    struct sockaddr_in from;
    int from_len = sizeof(from);
    size_t n;
    
    buf = malloc(max_request);
    if(buf == NULL){
	kdc_log(0, "Failed to allocate %u bytes", max_request);
	return;
    }

    n = recvfrom(d->s, buf, max_request, 0, 
		 (struct sockaddr*)&from, &from_len);
    if(n < 0){
	warn("recvfrom");
	goto out;
    }
    if(n == 0){
	goto out;
    }
    do_request(buf, n, d->s, (struct sockaddr*)&from, from_len);
out:
    free (buf);
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
handle_tcp(struct descr *d, int index, int min_free)
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
	unsigned char *tmp;
	d[index].size += 1024;
	if(d[index].size >= max_request){
	    kdc_log(0, "Request exceeds max request size (%u bytes).", d[index].size);
	    clear_descr(d + index);
	    return;
	}
	tmp = realloc(d[index].buf, d[index].size);
	if(tmp == NULL){
	    kdc_log(0, "Failed to re-allocate %u bytes.", d[index].size);
	    clear_descr(d + index);
	    return;
	}
	d[index].buf = tmp;
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
#ifdef HTTP
    else if(strncmp(d[index].buf, "GET ", 4) == 0 && 
	    strncmp(d[index].buf + d[index].len - 4, "\r\n\r\n", 4) == 0){
	char *s, *p, *t;
	void *data;
	int len;
	s = d[index].buf;
	p = strstr(s, "\r\n");
	*p = 0;
	p = NULL;
	kdc_log(5, "HTTP request");
	strtok_r(s, " \t", &p);
	t = strtok_r(NULL, " \t", &p);
	if(t == NULL){
	    
	}
	data = malloc(strlen(t));
	len = base64_decode(t, data);
	if(len < 0){
	    const char *msg = 
		"HTTP/1.1 404 Not found\r\n"
		"Server: Heimdal/" VERSION "\r\n"
		"Content-type: text/html\r\n"
		"Content-transfer-encoding: 8bit\r\n\r\n"
		"<TITLE>404 Not found</TITLE>\r\n"
		"<H1>404 Not found</H1>\r\n"
		"That page doesn't exist, maybe you are looking for "
		"<a href=\"http://www.pdc.kth.se/heimdal\">Heimdal</a>?\r\n";
	    write(d[index].s, msg, strlen(msg));
	    free(data);
	    clear_descr(d + index);
	    return;
	}
	{
	    const char *msg = 
		"HTTP/1.1 200 OK\r\n"
		"Server: Heimdal/" VERSION "\r\n"
		"Content-type: application/octet-stream\r\n"
		"Content-transfer-encoding: binary\r\n\r\n";
	    write(d[index].s, msg, strlen(msg));
	}
	memcpy(d[index].buf, data, len);
	d[index].len = len;
	n = 0;
	free(data);
    }
#endif
    if(n == 0){
	do_request(d[index].buf, d[index].len, 
		   d[index].s, (struct sockaddr*)&from, from_len);
	clear_descr(d + index);
    }
}



void
loop(void)
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
			handle_udp(&d[i]);
		    else if(d[i].type == SOCK_STREAM)
			handle_tcp(d, i, min_free);
	}
    }
    free (d);
}
