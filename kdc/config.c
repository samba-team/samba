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
#include <getarg.h>

RCSID("$Id$");

static char *config_file;
char *logfile;
int loglevel = -2;
int require_preauth = 1;
char *keyfile;

static int help;

static struct getargs args[] = {
    { 
	"config-file",	'c',	arg_string,	&config_file, 
	"location of config file",	"file" 
    },
    { 
	"log-file", 	'l', 	arg_string, 	&logfile,
	"location of log file",		"file"
    },
    { 
	"log-level",	0,	arg_integer,	&loglevel, 
	"level of logging"
    },
    { 
	"require-preauth",	'p',	arg_negative_flag, &require_preauth, 
	"don't require pa-data in as-reqs"
    },
    { 
	"key-file",	'k',	arg_string, &keyfile, 
	"location of master key file", "file"
    },
    { "help", 'h', arg_flag, &help },
};

static int num_args = sizeof(args) / sizeof(args[0]);

extern const char *krb5_config_get_string(krb5_config_section*, ...);

void
configure(int argc, char **argv)
{
    krb5_config_section *cf;
    int optind = 0;
    int e;
    const char *p;
    
    while((e = getarg(args, num_args, argc, argv, &optind)))
	warnx("error at argument `%s'", argv[optind]);

    if(help){
	arg_printusage (args, num_args, "");
	exit(0);
    }
    
    if(config_file == NULL)
	config_file = "kdc.conf";
    
    if(krb5_config_parse_file(config_file, &cf))
	goto end;
    
    if(logfile == NULL){
	p = krb5_config_get_string (cf, 
				    "kdc",
				    "log-file",
				    NULL);
	if(p)
	    logfile = strdup(p);
    }
	
    if(loglevel == -2){
	p = krb5_config_get_string (cf, 
				    "kdc",
				    "log-level",
				    NULL);
	if(p)
	    loglevel = atoi(p);
    }

    if(keyfile == NULL){
	p = krb5_config_get_string (cf, 
				    "kdc",
				    "key-file",
				    NULL);
	if(p)
	    keyfile = strdup(p);
    }
    
    if(require_preauth == -1){
	p = krb5_config_get_string (cf, 
				    "kdc",
				    "require-preauth",
				    NULL);
    
	if(p){
	    if(strcasecmp(p, "true") == 0 || strcasecmp(p, "yes") == 0)
		require_preauth = 1;
	    else if(strcasecmp(p, "false") == 0 || strcasecmp(p, "no") == 0)
		require_preauth = 0;
	}
    }
    krb5_config_file_free (cf);
end:
    if(logfile == NULL)
	logfile = "kdc.log";
    if(loglevel == -2)
	loglevel = 0;
    if(require_preauth == -1)
	require_preauth = 1;
}
