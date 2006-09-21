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
    int32_t capabilities;
    char *target_name;
    char *moniker;
};

static struct client **clients;
static int num_clients;

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

static int
get_targetname(struct client *client, 
	       char **target)
{
    put32(client, eGetTargetName);
    retstring(client, *target);
    return GSMERR_OK;
}

static int32_t
wrap_token(struct client *client, int32_t hContext, int32_t flags,
	   krb5_data *in, krb5_data *out)
{
    int32_t val;
    put32(client, eWrap);
    put32(client, hContext);
    put32(client, flags);
    put32(client, 0);
    putdata(client, *in);
    ret32(client, val);
    retdata(client, *out);
    return val;
}

static int32_t
unwrap_token(struct client *client, int32_t hContext, int flags, 
	     krb5_data *in, krb5_data *out)
{
    int32_t val;
    put32(client, eUnwrap);
    put32(client, hContext);
    put32(client, flags);
    put32(client, 0);
    putdata(client, *in);
    ret32(client, val);
    retdata(client, *out);
    return val;
}

static int32_t
get_mic(struct client *client, int32_t hContext,
	krb5_data *in, krb5_data *mic)
{
    int32_t val;
    put32(client, eSign);
    put32(client, hContext);
    put32(client, 0);
    put32(client, 0);
    putdata(client, *in);
    ret32(client, val);
    retdata(client, *mic);
    return val;
}

static int32_t
verify_mic(struct client *client, int32_t hContext, 
	   krb5_data *in, krb5_data *mic)
{
    int32_t val;
    put32(client, eVerify);
    put32(client, hContext);
    put32(client, 0);
    put32(client, 0);
    putdata(client, *in);
    putdata(client, *mic);
    ret32(client, val);
    return val;
}


static int
get_version_capa(struct client *client, 
		 int32_t *version, int32_t *capa,
		 char **version_str)
{
    put32(client, eGetVersionAndCapabilities);
    ret32(client, *version);
    ret32(client, *capa);
    retstring(client, *version_str);
    return GSMERR_OK;
}

static int
get_moniker(struct client *client, 
	    char **moniker)
{
    put32(client, eGetMoniker);
    retstring(client, *moniker);
    return GSMERR_OK;
}


static int
build_context(struct client *ipeer, struct client *apeer,
	      int32_t flags, int32_t hCred,
	      int32_t *iContext, int32_t *aContext, int32_t *hDelegCred)
{
    int32_t val, ic = 0, ac = 0, deleg = 0;
    krb5_data itoken, otoken;
    int iDone = 0, aDone = 0;

    if (apeer->target_name == NULL)
	errx(1, "apeer %s have no target name", apeer->name);


    krb5_data_zero(&itoken);

    while (!iDone || !aDone) {
	
	if (iDone)
	    errx(1, "iPeer already done, aPeer want extra rtt");

	val = init_sec_context(ipeer, &ic, &hCred, flags, apeer->target_name,
			       &itoken, &otoken);
	switch(val) {
	case GSMERR_OK:
	    iDone = 1;
	    if (aDone)
		continue;
	    break;
	case GSMERR_CONTINUE_NEEDED:
	    break;
	default:
	    errx(1, "iPeer %s failed with %d", ipeer->name, (int)val);
	}

	if (aDone)
	    errx(1, "aPeer already done, iPeer want extra rtt");

	val = accept_sec_context(apeer, &ac, &otoken, &itoken, &deleg);
	switch(val) {
	case GSMERR_OK:
	    aDone = 1;
	    if (iDone)
		continue;
	    break;
	case GSMERR_CONTINUE_NEEDED:
	    break;
	default:
	    errx(1, "aPeer %s failed with %d", apeer->name, (int)val);
	}

	val = GSMERR_OK;
    }

    if (iContext == NULL || val != GSMERR_OK) {
	if (ic)
	    toast_resource(ipeer, ic);
	if (iContext)
	    *iContext = 0;
    } else
	*iContext = ic;

    if (aContext == NULL || val != GSMERR_OK) {
	if (ac)
	    toast_resource(apeer, ac);
	if (aContext)
	    *aContext = 0;
    } else
	*aContext = ac;

    if (hDelegCred == NULL || val != GSMERR_OK) {
	if (deleg)
	    toast_resource(apeer, deleg);
	if (hDelegCred)
	    *hDelegCred = 0;
    } else
	*hDelegCred = deleg;

    return val;
}
			 
static void
test_mic(struct client *c1, int32_t hc1, struct client *c2, int32_t hc2)
{
    krb5_data msg, mic;
    int32_t val;
    
    msg.data = "foo";
    msg.length = 3;

    krb5_data_zero(&mic);

    val = get_mic(c1, hc1, &msg, &mic);
    if (val)
	errx(1, "get_mic failed to host: %s", c1->moniker);
    val = verify_mic(c2, hc2, &msg, &mic);
    if (val)
	errx(1, "verify_mic failed to host: %s", c2->moniker);

    krb5_data_free(&mic);
}

static void
test_wrap(struct client *c1, int32_t hc1, struct client *c2, int32_t hc2, 
	  int conf)
{
    krb5_data msg, wrapped, out;
    int32_t val;
    
    msg.data = "foo";
    msg.length = 3;

    krb5_data_zero(&wrapped);
    krb5_data_zero(&out);

    val = wrap_token(c1, hc1, conf, &msg, &wrapped);
    if (val)
	errx(1, "wrap_token failed to host: %s", c1->moniker);
    val = unwrap_token(c2, hc2, conf, &wrapped, &out);
    if (val)
	errx(1, "unwrap_token failed to host: %s", c2->moniker);

    krb5_data_free(&wrapped);
    krb5_data_free(&out);
}

static void
test_token(struct client *c1, int32_t hc1, struct client *c2, int32_t hc2)
{
    test_mic(c1, hc1, c2, hc2);
    test_mic(c2, hc2, c1, hc1);
    test_wrap(c1, hc1, c2, hc2, 0);
    test_wrap(c2, hc2, c1, hc1, 0);
    test_wrap(c1, hc1, c2, hc2, 1);
    test_wrap(c2, hc2, c1, hc1, 1);
}

static void
connect_client(const char *slave)
{
    char *name, *port;
    struct client *c = ecalloc(1, sizeof(*c));
    struct addrinfo hints, *res0, *res;
    int ret, fd;

    name = estrdup(slave);
    port = strchr(name, ':');
    if (port == NULL)
	errx(1, "port missing from %s", name);
    *port++ = 0;

    c->name = estrdup(slave);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(name, port, &hints, &res0);
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

    {
	int32_t version;
	char *str = NULL;
	get_version_capa(c, &version, &c->capabilities, &str);
	if (str) {
	    free(str);
	}
	if (c->capabilities & HAS_MONIKER)
	    get_moniker(c, &c->moniker);
	else
	    c->moniker = c->name;
	if (c->capabilities & ISSERVER)
	    get_targetname(c, &c->target_name);
    }

    clients = erealloc(clients, (num_clients + 1) * sizeof(*clients));
    
    clients[num_clients] = c;
    num_clients++;

    free(name);
}

static struct client *
get_client(const char *slave)
{
    size_t i;
    for (i = 0; i < num_clients; i++)
	if (strcmp(slave, clients[i]->name) == 0)
	    return clients[i];
    errx(1, "failed to find client %s", slave);
}

/*
 *
 */

static int version_flag;
static int help_flag;
static getarg_strings principals;
static getarg_strings slaves;

struct getargs args[] = {
    { "principals", 0,  arg_strings,	&principals,	"Test principal",
      NULL },
    { "slaves", 0,  arg_strings,	&slaves,	"Slaves",
      NULL },
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
    char *user;
    char *password;
    char ***list, **p;
    size_t num_list, i, j, k;

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

    if (principals.num_strings == 0)
	errx(1, "no principals");

    user = estrdup(principals.strings[0]);
    password = strchr(user, ':');
    if (password == NULL)
	errx(1, "password missing from %s", user);
    *password++ = 0;
	
    if (slaves.num_strings == 0)
	errx(1, "no principals");

    list = permutate_all(&slaves, &num_list);

    /*
     * Set up connection to all clients
     */

    for (i = 0; i < slaves.num_strings; i++)
	connect_client(slaves.strings[i]);

    /* 
     * First test if all slaves can build context to them-self.
     */

    for (i = 0; i < num_clients; i++) {
	int32_t hCred, val, delegCred;
	int32_t clientC, serverC;
	struct client *c = clients[i];
	
	if (c->target_name == NULL)
	    continue;

	printf("%s connects to self using %s\n",
	       c->moniker, c->target_name);

	val = acquire_cred(c, user, password, 1, &hCred);
	if (val != GSMERR_OK)
	    errx(1, "failed to acquire_cred: %d", (int)val);
    
	val = build_context(c, c, GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG,
			    hCred, &clientC, &serverC, &delegCred);
	if (val == GSMERR_OK) {
	    test_token(c, clientC, c, serverC);
	    toast_resource(c, clientC);
	    toast_resource(c, serverC);
	    if (delegCred)
		toast_resource(c, delegCred);
	} else {
	    warnx("build_context failed: %d", (int)val);
	}

	/*
	 *
	 */

	val = build_context(c, c, 0,
			    hCred, &clientC, &serverC, &delegCred);
	if (val == GSMERR_OK) {
	    test_token(c, clientC, c, serverC);
	    toast_resource(c, clientC);
	    toast_resource(c, serverC);
	    if (delegCred)
		toast_resource(c, delegCred);
	} else {
	    warnx("build_context failed: %d", (int)val);
	}

	toast_resource(c, hCred);
    }

    /*
     * Build contexts though all entries in each lists, including the
     * step from the last entry to the first, ie treat the list as a
     * circle.
     *
     * Only follow the delegated credential, but test "all"
     * flags. (XXX only do deleg|mutual right now.
     */

    for (i = 0; i < num_list; i++) {
	int32_t hCred, val, delegCred;
	int32_t clientC, serverC;
	struct client *client, *server;

	p = list[i];
	
	client = get_client(p[0]);

	val = acquire_cred(client, user, password, 1, &hCred);
	if (val != GSMERR_OK)
	    errx(1, "failed to acquire_cred: %d", (int)val);

	for (j = 1; j < num_clients + 1; j++) {
	    server = get_client(p[j % num_clients]);
	    
	    if (server->target_name == NULL) {
		warnx("no target on %s", server->moniker);
		break;
	    }

	    for (k = 1; k < j; k++)
		printf("\t");
	    printf("%s -> %s\n", client->moniker, server->moniker);

	    val = build_context(client, server,
				GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG,
				hCred, &clientC, &serverC, &delegCred);
	    if (val != GSMERR_OK) {
		warnx("build_context failed: %d", (int)val);
		break;
	    }

	    test_token(client, clientC, server, serverC);

	    toast_resource(client, clientC);
	    toast_resource(server, serverC);
	    if (!delegCred) {
		warnx("no delegated cred on %s", server->moniker);
		break;
	    }
	    toast_resource(client, hCred);
	    hCred = delegCred;
	    client = server;
	}
	if (hCred)
	    toast_resource(client, hCred);
    }



    /*
     * Close all connections to clients
     */

    for (i = 0; i < num_clients; i++)
	goodbye(clients[i]);

    printf("done\n");

    return 0;
}
