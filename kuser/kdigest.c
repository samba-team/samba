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

#include "kuser_locl.h"
RCSID("$Id$");
#include <kdigest-commands.h>
#include <hex.h>
#include "crypto-headers.h"

static int version_flag = 0;
static int help_flag	= 0;

static struct getargs args[] = {
    {"version",	0,	arg_flag,	&version_flag, "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,  NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args),
		    NULL, "");
    exit (ret);
}

const static char *secret = "secret";
static char server_nonce[16];
static char server_identifier;

int
server_init(struct server_init_options *opt, int argc, char ** argv)
{
    char *s;

    if (strcasecmp(opt->type_string, "CHAP") != 0)
	errx(1, "type not CHAP");

    RAND_pseudo_bytes(&server_identifier, sizeof(server_identifier));
    RAND_pseudo_bytes(&server_nonce, sizeof(server_nonce));

    printf("type=%s\n", opt->type_string);
    hex_encode(server_nonce, sizeof(server_nonce), &s);
    printf("server-nonce=%s\n", s);
    free(s);
    printf("identifier=%02X\n", (server_identifier & 0xff));
    printf("opaque=bar\n");

    return 0;
}

int
server_request(struct server_request_options *opt, int argc, char **argv)
{
    MD5_CTX ctx;
    char md[16], *h;

    if (opt->server_nonce_string == NULL)
	errx(1, "server nonce missing");
    if (opt->server_identifier_string == NULL)
	errx(1, "server identifier missing");

    if (opt->opaque_string == NULL)
	errx(1, "opaque missing");
    if (strcmp(opt->opaque_string, "bar") != 0)
	errx(1, "opaque wrong string");

    if (hex_decode(opt->server_nonce_string, server_nonce, 16) != 16)
	errx(1, "server nonce wrong length");
    if (hex_decode(opt->server_identifier_string, &server_identifier, 1) != 1)
	errx(1, "server identifier wrong length");

    MD5_Init(&ctx);
    MD5_Update(&ctx, &server_identifier, 1);
    MD5_Update(&ctx, secret, strlen(secret));
    MD5_Update(&ctx, server_nonce, 16);
    MD5_Final(md, &ctx);

    hex_encode(md, 16, &h);

    printf("responseData=%s\n", h);
    printf("tickets=no\n");

    /*
    printf("rsp=bar\n");
    printf("cb-type=type\n");
    printf("cb-binding=binding\n");
    printf("hash-a1=bar\n");
    printf("message=message here\n");
    */
    return 0;
}

/*
 *
 */

int
help(void *opt, int argc, char **argv)
{
    if(argc == 0) {
	sl_help(commands, 1, argv - 1 /* XXX */);
    } else {
	SL_cmd *c = sl_match (commands, argv[0], 0);
 	if(c == NULL) {
	    fprintf (stderr, "No such command: %s. "
		     "Try \"help\" for a list of commands\n",
		     argv[0]);
	} else {
	    if(c->func) {
		char *fake[] = { NULL, "--help", NULL };
		fake[0] = argv[0];
		(*c->func)(2, fake);
		fprintf(stderr, "\n");
	    }
	    if(c->help && *c->help)
		fprintf (stderr, "%s\n", c->help);
	    if((++c)->name && c->func == NULL) {
		int f = 0;
		fprintf (stderr, "Synonyms:");
		while (c->name && c->func == NULL) {
		    fprintf (stderr, "%s%s", f ? ", " : " ", (c++)->name);
		    f = 1;
		}
		fprintf (stderr, "\n");
	    }
	}
    }
    return 0;
}

int
main(int argc, char **argv)
{
    int optidx = 0;

    setprogname(argv[0]);
    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);
    
    if (help_flag)
	usage (0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    argc -= optidx;
    argv += optidx;

    if (argc == 0) {
	help(NULL, argc, argv);
	return 1;
    }

    return sl_command (commands, argc, argv);
}
