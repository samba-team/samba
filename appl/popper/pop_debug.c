/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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
 *      This product includes software developed by the Kungliga Tekniska
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

/* Tiny program to help debug popper */

#include "popper.h"
RCSID("$Id$");

void
loop(int s)
{
    char cmd[1024];
    char buf[1024];
    fd_set fds;
    while(1){
	FD_ZERO(&fds);
	FD_SET(0, &fds);
	FD_SET(s, &fds);
	if(select(s+1, &fds, 0, 0, 0) < 0)
	    err(1, "select");
	if(FD_ISSET(0, &fds)){
	    fgets(cmd, sizeof(cmd), stdin);
	    strcpy(cmd + strlen(cmd) - 1, "\r\n");
	    write(s, cmd, strlen(cmd));
	}
	if(FD_ISSET(s, &fds)){
	    int n = read(s, buf, sizeof(buf));
	    if(n == 0)
		exit(0);
	    fwrite(buf, n, 1, stdout);
	}
    }
}

void
usage()
{
    fprintf(stderr, "Usage: %s [-p port] hostname\n", __progname);
    exit(1);
}

int
main(int argc, char **argv)
{
    int c;
    int port;
    char *host;
    struct hostent *hp;
    int s;
    struct sockaddr_in sa;
    set_progname(argv[0]);
    port = k_getportbyname("kpop", "tcp", htons(1109));
    while ((c = getopt(argc,argv, "p:")) != EOF){
	switch(c){
	case 'p':
	    port = htons(atoi(optarg));
	    break;
	default:
	    usage();
	}
    }
    if(argc - optind != 1)
	usage();
    host = argv[optind];
    hp = gethostbyname(host);
    if(hp == NULL)
	err(1, "%s", host);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
	err(1, "socket");
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = port;
    memcpy(&sa.sin_addr, hp->h_addr, sizeof(sa.sin_addr));
    if(connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0)
	err(1, "connect");
    {
	KTEXT_ST ticket;
	MSG_DAT msg_data;
	CREDENTIALS cred;
	des_key_schedule sched;
	int ret;
	
	ret = krb_sendauth(0,
			   s,
			   &ticket, 
			   "pop",
			   host,
			   krb_realmofhost(host),
			   getpid(),
			   &msg_data,
			   &cred,
			   sched,
			   NULL,
			   NULL,
			   "KPOPV0.1");
	if(ret)
	    errx(1, "krb_sendauth: %s", krb_get_err_text(ret));
	loop(s);
    }
}
