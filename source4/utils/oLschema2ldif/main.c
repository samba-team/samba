/*
   ldb database library

   Copyright (C) Simo Sorce 2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: oLschema2ldif
 *
 *  Description: utility to convert an OpenLDAP schema into AD LDIF
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "./lib.h"
#include "lib/cmdline/popt_common.h"

static struct options {
	const char *basedn;
	const char *input;
	const char *output;
} options;

static struct poptOption popt_options[] = {
	POPT_AUTOHELP
	{ "basedn",    'b', POPT_ARG_STRING, &options.basedn, 0, "base DN", "DN" },
	{ "input", 'I', POPT_ARG_STRING, &options.input, 0,
	  "inputfile of OpenLDAP style schema otherwise STDIN", "inputfile"},
	{ "output", 'O', POPT_ARG_STRING, &options.output, 0,
	  "outputfile otherwise STDOUT", "outputfile"},
	POPT_COMMON_VERSION
	{0}
};


static void usage(void)
{
	poptContext pc;
	printf("Usage: oLschema2ldif <options>\n");
	printf("\nConvert OpenLDAP schema to AD-like LDIF format\n\n");
	printf("Converts records from an openLdap formatted schema to an ldif schema\n\n");
	pc = poptGetContext("oLschema2ldif", 0, NULL, popt_options,
			    POPT_CONTEXT_KEEP_FIRST);
	poptPrintHelp(pc, stdout, 0);
	exit(1);
}


 int main(int argc, const char **argv)
{
	TALLOC_CTX *ctx;
	struct schema_conv ret;
	poptContext pc;
	struct conv_options copt;
	int opt;

	ctx = talloc_new(NULL);

	setenv("LDB_URL", "NONE", 1);

	pc = poptGetContext(argv[0], argc, argv, popt_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		fprintf(stderr, "Invalid option %s: %s\n",
			poptBadOption(pc, 0), poptStrerror(opt));
		usage();
	}

	if (options.basedn == NULL) {
		printf("Base DN not specified\n");
		usage();
		exit(1);
	}

	copt.in = stdin;
	copt.out = stdout;
	copt.ldb_ctx = ldb_init(ctx, NULL);

	copt.basedn = ldb_dn_new(ctx, copt.ldb_ctx, options.basedn);
	if (!ldb_dn_validate(copt.basedn)) {
		printf("Malformed Base DN\n");
		usage();
		exit(1);
	}

	if (options.input) {
		copt.in = fopen(options.input, "r");
		if (!copt.in) {
			perror(options.input);
			usage();
			exit(1);
		}
	}
	if (options.output) {
		copt.out = fopen(options.output, "w");
		if (!copt.out) {
			perror(options.output);
			usage();
			exit(1);
		}
	}

	ret = process_file(ctx, &copt);

	fclose(copt.in);
	fclose(copt.out);

	printf("Converted %d records with %d failures\n", ret.count, ret.failures);

	poptFreeContext(pc);

	return 0;
}
