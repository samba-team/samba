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

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <stdio.h>
#include <roken.h>
#include "getarg.h"

static void
print_arg (struct getargs *arg)
{
    switch (arg->type) {
    case arg_integer:
	fprintf (stderr, " n]");
	break;
    case arg_string:
	fprintf (stderr, " s]");
	break;
    case arg_flag:
    case arg_negative_flag:
	fprintf (stderr, "]");
	break;
    default:
	abort ();
    }
}

void
arg_printusage (struct getargs *args,
		size_t num_args,
		const char *extra_string)
{
    int i;
    size_t max_len = 0;

    fprintf (stderr, "Usage: %s", __progname);
    for (i = 0; i < num_args; ++i) {
	size_t len = 0;

	if (args[i].long_name) {
	    len += 2 + strlen(args[i].long_name);
	    fprintf (stderr, " [--%s", args[i].long_name);
	    print_arg (&args[i]);
	}
	if (args[i].short_name) {
	    len += 2;
	    fprintf (stderr, " [-%c", args[i].short_name);
	    print_arg (&args[i]);
	}
	if (args[i].long_name && args[i].short_name)
	    len += 4;
	max_len = max(max_len, len);
    }
    if (extra_string)
	fprintf (stderr, " %s\n", extra_string);
    else
	fprintf (stderr, "\n");
    for (i = 0; i < num_args; ++i) {
	if (args[i].help) {
	    size_t count = 0;

	    if (args[i].short_name) {
		fprintf (stderr, "-%c", args[i].short_name);
		count += 2;
	    }
	    if (args[i].short_name && args[i].long_name) {
		fprintf (stderr, " or ");
		count += 4;
	    }
	    if (args[i].long_name) {
		fprintf (stderr, "--%s", args[i].long_name);
		count += 2 + strlen(args[i].long_name);
	    }
	    while(count++ <= max_len)
		putc (' ', stderr);
	    fprintf (stderr, "%s\n", args[i].help);
	}
    }
}

static int
arg_match_long(struct getargs *args, size_t num_args,
	       char *argv)
{
    int i;
    char *optarg;
    int negate;
    int partial_match = 0;
    struct getargs *partial = NULL;
    struct getargs *current = NULL;
    int argv_len;
    char *p;

    argv_len = strlen(argv);
    p = strchr (argv, '=');
    if (p != NULL)
	argv_len = p - argv;

    for (i = 0; i < num_args; ++i) {
	if(args[i].long_name) {
	    int len = strlen(args[i].long_name);
	    char *p = argv;
	    int p_len = argv_len;
	    negate = 0;

	    for (;;) {
		if (strncmp (args[i].long_name, p, len) == 0) {
		    current = &args[i];
		    optarg  = p + len;
		} else if (strncmp (args[i].long_name,
				    p,
				    p_len) == 0) {
		    ++partial_match;
		    partial = &args[i];
		    optarg  = p + p_len;
		} else if (args[i].type == arg_flag
			   && strncmp (argv, "no-", 3) == 0) {
		    negate = !negate;
		    p += 3;
		    p_len -= 3;
		    continue;
		}
		break;
	    }
	    if (current)
		break;
	}
    }
    if (current == NULL)
	if (partial_match == 1)
	    current = partial;
	else
	    return ARG_ERR_NO_MATCH;
    
    if(*optarg != '=' && (current->type != arg_flag && *optarg == 0))
	return ARG_ERR_NO_MATCH;
    switch(current->type){
    case arg_integer:
    {
	int tmp;
	if(sscanf(optarg + 1, "%d", &tmp) != 1)
	    return ARG_ERR_BAD_ARG;
	*(int*)current->value = tmp;
	return 0;
    }
    case arg_string:
    {
	*(char**)current->value = optarg + 1;
	return 0;
    }
    case arg_flag:
    {
	int *flag = current->value;
	if(*optarg == 0 ||
	   strcmp(optarg + 1, "yes") == 0 || 
	   strcmp(optarg + 1, "true") == 0){
	    *flag = !negate;
	    return 0;
	} else {
	    *flag = negate;
	    return 0;
	}
	return ARG_ERR_BAD_ARG;
    }
    default:
	abort ();
    }
}

int
getarg(struct getargs *args, size_t num_args, 
       int argc, char **argv, int *optind)
{
    int i, j, k;
    int ret = 0;
    (*optind)++;
    for(i = *optind; i < argc; i++) {
	if(argv[i][0] != '-')
	    break;
	if(argv[i][1] == '-'){
	    if(argv[i][2] == 0){
		i++;
		break;
	    }
	    ret = arg_match_long (args, num_args, argv[i] + 2);
	    if(ret)
		return ret;
	}else{
	    for(j = 1; argv[i][j]; j++) {
		for(k = 0; k < num_args; k++) {
		    char *optarg;
		    if(args[k].short_name == 0)
			continue;
		    if(argv[i][j] == args[k].short_name){
			if(args[k].type == arg_flag){
			    *(int*)args[k].value = 1;
			    break;
			}
			if(args[k].type == arg_negative_flag){
			    *(int*)args[k].value = 0;
			    break;
			}
			if(argv[i][j + 1])
			    optarg = &argv[i][j + 1];
			else{
			    i++;
			    optarg = argv[i];
			}
			if(optarg == NULL)
			    return ARG_ERR_NO_ARG;
			if(args[k].type == arg_integer){
			    int tmp;
			    if(sscanf(optarg, "%d", &tmp) != 1)
				return ARG_ERR_BAD_ARG;
			    *(int*)args[k].value = tmp;
			    break;
			}else if(args[k].type == arg_string){
			    *(char**)args[k].value = optarg;
			    break;
			}
			return ARG_ERR_BAD_ARG;
		    }
			
		}
		if (k == num_args)
		    return ARG_ERR_NO_MATCH;
	    }
	}
    }
    *optind = i;
    return 0;
}

#if TEST
int foo_flag = 2;
int flag1 = 0;
int flag2 = 0;
int bar_int;
char *baz_string;

struct getargs args[] = {
    { NULL, '1', arg_flag, &flag1, NULL },
    { NULL, '2', arg_flag, &flag2, NULL },
    { "foo", 'f', arg_flag, &foo_flag, NULL },
    { "bar", 'b', arg_integer, &bar_int, NULL },
    { "baz", 'x', arg_string, &baz_string, NULL },
};

int main(int argc, char **argv)
{
    int optind = 0;
    while(getarg(args, 5, argc, argv, &optind))
	printf("Bad arg: %s\n", argv[optind]);
    printf("flag1 = %d\n", flag1);  
    printf("flag2 = %d\n", flag2);  
    printf("foo_flag = %d\n", foo_flag);  
    printf("bar_int = %d\n", bar_int);
    printf("baz_flag = %s\n", baz_string);
}
#endif
