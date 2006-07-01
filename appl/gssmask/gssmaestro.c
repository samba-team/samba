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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <common.h>
RCSID("$Id$");

/*
 *
 */

struct client {
    char *name;
    krb5_storage *sock;
};

#if 0
static struct client *clients;
static int num_clients;
#endif

static struct client *
connect_client(const char *name)
{
    struct client *c = ecalloc(1, sizeof(*c));
    struct addrinfo hints, *res0, *res;
    int ret, fd;

    c->name = estrdup(name);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(name, "4711", &hints, &res0);
    if (ret)
	errx(1, "error resolving %s", name);

    for (res = res0, fd = -1; res; res = res->ai_next) {
	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0)
	    continue;
	if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
	    close(fd);
	    fd = -1;
	    continue;
	}
	break;  /* okay we got one */
    }
    if (fd < 0)
	err(1, "connect to host: %s", name);
    freeaddrinfo(res);

    c->sock = krb5_storage_from_fd(fd);
    close(fd);
    if (c->sock == NULL)
	errx(1, "krb5_storage_from_fd");
    return c;
}

static int
init_sec_context(struct client *client, 
		 int32_t *hContext, int32_t *hCred,
		 int32_t flags, 
		 const char *targetname,
		 const krb5_data *itoken, krb5_data *otoken)
{
    int32_t val;
    krb5_data_zero(otoken);
    put32(client, eInitContext);
    put32(client, *hContext);
    put32(client, *hCred);
    put32(client, flags);
    putstring(client, targetname);
    putdata(client, *itoken);
    ret32(client, *hContext);
    ret32(client, val);
    retdata(client, *otoken);
    return val;
}

static int
accept_sec_context(struct client *client, 
		   int32_t *hContext,
		   const krb5_data *itoken,
		   krb5_data *otoken,
		   int32_t *hDelegCred)
{
    int32_t val;
    krb5_data_zero(otoken);
    put32(client, eAcceptContext);
    put32(client, *hContext);
    put32(client, 0);
    putdata(client, *itoken);
    ret32(client, *hContext);
    ret32(client, val);
    retdata(client, *otoken);
    ret32(client, *hDelegCred);
    return val;
}

static int
acquire_cred(struct client *client, 
	     const char *username,
	     const char *password,
	     int32_t flags,
	     int32_t *hCred)
{
    int32_t val;
    put32(client, eAcquireCreds);
    putstring(client, username);
    putstring(client, password);
    put32(client, flags);
    ret32(client, val);
    ret32(client, *hCred);
    return val;
}

static int
toast_resource(struct client *client, 
	       int32_t hCred)
{
    int32_t val;
    put32(client, eToastResource);
    put32(client, hCred);
    ret32(client, val);
    return val;
}

static int
goodbye(struct client *client)
{
    put32(client, eGoodBye);
    return GSMERR_OK;
}

static int version_flag;
static int help_flag;

struct getargs args[] = {
    { "version", 0,  arg_flag,		&version_flag,	"Print version",
      NULL },
    { "help",	 0,  arg_flag,		&help_flag,	NULL,
      NULL }
};

static void
usage(int ret)
{
    arg_printusage (args,
		    sizeof(args) / sizeof(args[0]),
		    NULL,
		    "");
    exit (ret);
}

int
main(int argc, char **argv)
{
    int optidx= 0;

    setprogname (argv[0]);

    if (getarg (args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage (1);

    if (help_flag)
	usage (0);

    if (version_flag) {
	print_version (NULL);
	return 0;
    }

    if (optidx != argc)
	usage (1);

    {
	struct client *c;
	int32_t hCred, delegCred;
	int32_t clientC, serverC;
	const char *user = "lha/test@SU.SE";
	const char *target = "host/nutcracker.it.su.se@SU.SE";
	krb5_data itoken, otoken;

	krb5_data_zero(&itoken);
	c = connect_client("localhost");
	acquire_cred(c, user, "nothere", 1, &hCred);
	init_sec_context(c, &clientC, &hCred, 
			 GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG, 
			 target, &itoken, &otoken);
	accept_sec_context(c, &serverC, &otoken, &itoken, &delegCred);
	init_sec_context(c, &clientC, &hCred, GSS_C_DELEG_FLAG,
			 target, &itoken, &otoken);

	toast_resource(c, clientC);
	toast_resource(c, serverC);
	toast_resource(c, hCred);
	if (delegCred)
	    toast_resource(c, delegCred);
	goodbye(c);

    }
    printf("done\n");

    return 0;
}
