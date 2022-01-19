/*
 * Copyright (c) 2011, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <roken.h>
#include <heimbase.h>
#include <getarg.h>
#include <vers.h>

int help_flag;
int version_flag;
int verbose_flag;
int print_keys_flag;
int no_values_flag;
int block_size_int;
int max_size_int;

struct getargs args[] = {
    { "print-keys",     'K',  arg_flag, &print_keys_flag,
	"print keys", NULL },
    { "no-values",      'V',  arg_flag, &no_values_flag,
	"don't print values", NULL },
    { "verbose",        'v',  arg_flag, &verbose_flag,
	"print statistics and informative messages", NULL },
    { "help",           'h',  arg_flag, &help_flag,
	"print usage message", NULL },
    { "block-size",     'b',  arg_integer, &block_size_int,
	"block size", "integer" },
    { "max-cache-size", 'm',  arg_integer, &max_size_int,
	"maximum cache size", "integer" },
    { "version",        '\0', arg_flag, &version_flag, NULL, NULL }
};

static int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int status)
{
    arg_printusage(args, num_args, NULL, "file [key ...]");
    exit(status);
}

#define MAX_BLOCK_SIZE (1024 * 1024)
#define DEFAULT_MAX_FILE_SIZE (1024 * 1024)

int
main(int argc, char **argv)
{
    char keybuf[1024];
    char *fname;
    char *key = keybuf;
    char *value;
    char *p;
    bsearch_file_handle bfh = NULL;
    size_t num;
    size_t loc;           /* index where record is located or to be inserted */
    size_t loops;         /* number of loops/comparisons needed for lookup */
    size_t reads = 0;	  /* number of reads needed for a lookup */
    size_t failures = 0;  /* number of lookup failures -- for exit status */
    size_t block_size = 0;
    size_t max_size = 0;
    int optidx = 0;
    int blockwise;
    int ret = 0;

    setprogname(argv[0]);
    if (getarg(args, num_args, argc, argv, &optidx))
	usage(1);

    if (version_flag) {
	print_version(NULL);
	return 0;
    }

    if (help_flag)
	usage(0);

    if (block_size_int != 0 && block_size_int < 512) {
	fprintf(stderr, "Invalid block size: too small\n");
	return 1;
    }
    if (block_size_int > 0) {
	/* Check that block_size is a power of 2 */
	num = block_size_int;
	while (num) {
	    if ((num % 2) && (num >> 1)) {
		fprintf(stderr, "Invalid block size: must be power "
			"of two\n");
		return 1;
	    }
	    num >>= 1;
	}
	if (block_size_int > MAX_BLOCK_SIZE)
	    fprintf(stderr, "Invalid block size: too large\n");
	block_size = block_size_int;
    }
    if (max_size_int < 0)
	usage(1);
    max_size = max_size_int;

    argc -= optind;
    argv += optind;

    if (argc == 0)
	usage(1);

    fname = argv[0];
    argc--;
    argv++;

    ret = _bsearch_file_open(fname, max_size, block_size, &bfh, &reads);
    if (ret != 0) {
	perror("bsearch_file_open");
	return 1;
    }

    _bsearch_file_info(bfh, &block_size, &max_size, &blockwise);
    if (verbose_flag && blockwise) {
	fprintf(stderr, "Using block-wise method with block size %lu and "
		"cache size %lu\n",
		(long unsigned)block_size, (long unsigned)max_size);
    } else if (verbose_flag) {
	fprintf(stderr, "Using whole-file method\n");
    }

    for (;;) {
	loops = 0; /* reset stats */
	/* Eww */
	if (argc) {
	    key = *(argv++);
	    if (!key)
		break;
	} else {
	    if (!fgets(keybuf, sizeof (keybuf), stdin))
		break;
	    p = strchr(key, '\n');
	    if (!p)
		break;
	    *p = '\0';
	    if (!*key)
		continue;
	}
	ret = _bsearch_file(bfh, key, &value, &loc, &loops, &reads);
	if (ret != 0) {
	    if (ret > 0) {
		fprintf(stderr, "Error: %s\n", strerror(ret));
		_bsearch_file_close(&bfh);
		return 1;
	    }
	    if (verbose_flag)
		fprintf(stderr, "Key %s not found in %lu loops and %lu reads; "
			"insert at %lu\n", key, (long unsigned)loops,
			(long unsigned)reads, (long unsigned)loc);
	    failures++;
	    continue;
	}
	if (verbose_flag)
	    fprintf(stderr, "Key %s found at offset %lu in %lu loops and "
		    "%lu reads\n", key, (long unsigned)loc,
		    (long unsigned)loops, (long unsigned)reads);
	if (print_keys_flag && !no_values_flag && value)
	    printf("%s %s\n", key, value);
	else if (print_keys_flag)
	    printf("%s\n", key);
	else if (no_values_flag && value)
	    printf("%s\n", value);
	free(value);
    }
    if (failures)
	return 2;
    _bsearch_file_close(&bfh);
    return 0;
}
