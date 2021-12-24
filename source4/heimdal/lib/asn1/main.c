/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
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

#include "gen_locl.h"
#include <getarg.h>
#include "lex.h"

extern FILE *yyin;

static getarg_strings preserve;
static getarg_strings seq;
static getarg_strings decorate;

int
preserve_type(const char *p)
{
    int i;
    for (i = 0; i < preserve.num_strings; i++)
	if (strcmp(preserve.strings[i], p) == 0)
	    return 1;
    return 0;
}

int
seq_type(const char *p)
{
    size_t i;

    for (i = 0; i < seq.num_strings; i++)
	if (strcmp(seq.strings[i], p) == 0)
	    return 1;
    return 0;
}

int
decorate_type(const char *p, char **field_type, char **field_name, int *opt)
{
    size_t plen = strlen(p);
    size_t i;

    *field_type = NULL;
    *field_name = NULL;
    *opt = 0;

    for (i = 0; i < decorate.num_strings; i++) {
        const char *r;
        char *q;

	if (strncmp(decorate.strings[i], p, plen) != 0)
            continue;
	if (decorate.strings[i][plen] != ':')
            errx(1, "--decorate argument missing field type");

        p = &decorate.strings[i][plen + 1];
        if ((r = strchr(p, ':')) == NULL)
            errx(1, "--decorate argument missing field name");
        r++;
        *field_type = estrdup(p);
        *(strchr(*field_type, ':')) = '\0';
        *field_name = estrdup(r);
        if ((q = strchr(*field_name, '?'))) {
            *q = '\0';
            *opt = 1;
        }
        return 1;
    }
    return 0;
}

static const char *
my_basename(const char *fn)
{
    const char *base, *p;

    for (p = base = fn; *p; p++) {
#ifdef WIN32
        if (*p == '/' || *p == '\\')
            base = p + 1;
#else
        if (*p == '/')
            base = p + 1;
#endif
    }
    return base;
}

const char *fuzzer_string = "";
const char *enum_prefix;
const char *name;
int prefix_enum;
int fuzzer_flag;
int support_ber;
int template_flag;
int rfc1510_bitstring;
int one_code_file;
char *option_file;
int parse_units_flag = 1;
char *type_file_string = "krb5-types.h";
int original_order;
int version_flag;
int help_flag;
struct getargs args[] = {
    { "fuzzer", 0, arg_flag, &fuzzer_flag, NULL, NULL },
    { "template", 0, arg_flag, &template_flag, NULL, NULL },
    { "prefix-enum", 0, arg_flag, &prefix_enum,
        "prefix C enum labels for ENUMERATED types and INTEGER types with the "
            "type's name", NULL },
    { "enum-prefix", 0, arg_string, &enum_prefix,
        "prefix for C enum labels for ENUMERATED types and INTEGER types with "
            "enumerated values", "PREFIX" },
    { "encode-rfc1510-bit-string", 0, arg_flag, &rfc1510_bitstring,
        "Use RFC1510 incorrect BIT STRING handling for all BIT STRING types "
            "in the module", NULL },
    { "decode-dce-ber", 0, arg_flag, &support_ber,
        "Allow DCE-style BER on decode", NULL },
    { "support-ber", 0, arg_flag, &support_ber, "Allow BER on decode", NULL },
    { "preserve-binary", 0, arg_strings, &preserve,
        "Names of types for which to generate _save fields, saving original "
            "encoding, in containing structures (useful for signature "
            "verification)", "TYPE-NAME" },
    { "sequence", 0, arg_strings, &seq,
        "Generate add/remove functions for SEQUENCE OF types", "TYPE-NAME" },
    { "decorate", 0, arg_strings, &decorate,
        "Generate private field for SEQUENCE/SET type", "TYPE-NAME:FIELD_TYPE:field_name[?]" },
    { "one-code-file", 0, arg_flag, &one_code_file, NULL, NULL },
    { "gen-name", 0, arg_string, &name,
        "Name of generated module", "NAME" },
    { "option-file", 0, arg_string, &option_file,
        "File with additional compiler CLI options", "FILE" },
    { "original-order", 0, arg_flag, &original_order,
        "Define C types and functions in the order in which they appear in "
            "the ASN.1 module instead of topologically sorting types.  This "
            "is useful for comparing output to earlier compiler versions.",
        NULL },
    { "parse-units", 0, arg_negative_flag, &parse_units_flag,
        "Do not generate roken-style units", NULL },
    { "type-file", 0, arg_string, &type_file_string,
        "Name of a C header file to generate includes of for base types",
        "C-HEADER-FILE" },
    { "version", 0, arg_flag, &version_flag, NULL, NULL },
    { "help", 0, arg_flag, &help_flag, NULL, NULL }
};
int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int code)
{
    arg_printusage(args, num_args, NULL, "[asn1-file [name]]");
    exit(code);
}

int error_flag;

int
main(int argc, char **argv)
{
    int ret;
    const char *file;
    FILE *opt = NULL;
    int optidx = 0;
    char **arg = NULL;
    size_t len = 0;
    size_t sz = 0;
    int i;

    setprogname(argv[0]);
    if (getarg(args, num_args, argc, argv, &optidx))
	usage(1);
    if (help_flag)
	usage(0);
    if (version_flag) {
	print_version(NULL);
	exit(0);
    }
    if (argc == optidx) {
        /* Compile the module on stdin */
	file = "stdin";
	name = "stdin";
	yyin = stdin;
    } else {
        /* Compile a named module */
	file = argv[optidx];

        /*
         * If the .asn1 stem is not given, then assume it, and also assume
         * --option-file was given if the .opt file exists
         */
        if (strchr(file, '.') == NULL) {
            char *s = NULL;

            if (asprintf(&s, "%s.opt", file) == -1 || s == NULL)
                err(1, "Out of memory");
            if ((opt = fopen(s, "r")))
                option_file = s;
            else
                free(s);
            if (asprintf(&s, "%s.asn1", file) == -1 || s == NULL)
                err(1, "Out of memory");
            file = s;
        }
	yyin = fopen (file, "r");
	if (yyin == NULL)
	    err (1, "open %s", file);
	if (argc == optidx + 1) {
	    char *p;

            /* C module name substring not given; derive from file name */
            name = my_basename(estrdup(file));
	    p = strrchr(name, '.');
	    if (p)
		*p = '\0';
	} else
	    name = argv[optidx + 1];
    }

    /*
     * Parse extra options file
     */
    if (option_file) {
	char buf[1024];

        if (opt == NULL &&
            (opt = fopen(option_file, "r")) == NULL)
	    err(1, "Could not open given option file %s", option_file);

	arg = calloc(2, sizeof(arg[0]));
	if (arg == NULL) {
	    perror("calloc");
	    exit(1);
	}
	arg[0] = option_file;
	arg[1] = NULL;
	len = 1;
        sz = 2;

	while (fgets(buf, sizeof(buf), opt) != NULL) {
	    buf[strcspn(buf, "\n\r")] = '\0';

            if (len + 1 >= sz) {
                arg = realloc(arg, (sz + (sz>>1) + 2) * sizeof(arg[0]));
                if (arg == NULL) {
                    perror("malloc");
                    exit(1);
                }
                sz += (sz>>1) + 2;
            }
	    arg[len] = strdup(buf);
	    if (arg[len] == NULL) {
		perror("strdup");
		exit(1);
	    }
	    arg[len + 1] = NULL;
	    len++;
	}
	fclose(opt);

	optidx = 0;
	if(getarg(args, num_args, len, arg, &optidx))
	    usage(1);

	if (len != optidx) {
	    fprintf(stderr, "extra args");
	    exit(1);
	}
    }

    if (fuzzer_flag) {
	if (!template_flag) {
	    printf("can't do fuzzer w/o --template");
	    exit(1);
	}
#ifdef ASN1_FUZZER
	fuzzer_string = "_fuzzer";
#endif
    }


    init_generate(file, name);

    if (one_code_file)
	generate_header_of_codefile(name);

    initsym ();
    ret = yyparse ();
    if(ret != 0 || error_flag != 0)
	exit(1);
    if (!original_order)
        generate_types();
    close_generate ();
    if (argc != optidx)
	fclose(yyin);

    if (one_code_file)
	close_codefile();

    if (arg) {
	for (i = 1; i < len; i++)
	    free(arg[i]);
	free(arg);
    }

    return 0;
}
