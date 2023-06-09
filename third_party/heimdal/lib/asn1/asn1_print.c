/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include "der_locl.h"
#include <com_err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <getarg.h>
#include <err.h>
#include <der.h>
#include "cms_asn1.h"
#include "digest_asn1.h"
#include "krb5_asn1.h"
#include "kx509_asn1.h"
#include "ocsp_asn1.h"
#include "pkcs10_asn1.h"
#include "pkcs12_asn1.h"
#include "pkcs8_asn1.h"
#include "pkcs9_asn1.h"
#include "pkinit_asn1.h"
#include "rfc2459_asn1.h"
#include "rfc4108_asn1.h"
#ifdef ASN1_PRINT_SUPPORTED
#include "x690sample_template_asn1.h"
#else
#include "x690sample_asn1.h"
#endif

static int quiet_flag = 0;
static int print_flag = 1;
static int test_copy_flag;
static int test_encode_flag;
static int sequence_flag;
static int try_all_flag;
static int indent_flag = 1;
static int inner_flag;

static unsigned long indefinite_form_loop;
static unsigned long indefinite_form_loop_max = 10000;

typedef size_t (*lengther)(void *);
typedef int (*copyer)(const void *, void *);
typedef int (*encoder)(unsigned char *, size_t, void *, size_t *);
typedef int (*decoder)(const unsigned char *, size_t, void *, size_t *);
typedef char *(*printer)(const void *, int);
typedef void (*releaser)(void *);
const struct types {
    const char *name;
    size_t sz;
    copyer cpy;
    lengther len;
    decoder decode;
    encoder encode;
    printer print;
    releaser release;
} types[] = {
#define ASN1_SYM_INTVAL(n, gn, gns, i)
#define ASN1_SYM_OID(n, gn, gns)
#ifdef ASN1_PRINT_SUPPORTED
#define ASN1_SYM_TYPE(n, gn, gns)       \
    {                                   \
        n,                              \
        sizeof(gns),                    \
        (copyer)copy_ ## gns,           \
        (lengther)length_ ## gns,       \
        (decoder)decode_ ## gns,        \
        (encoder)encode_ ## gns,        \
        (printer)print_ ## gns,         \
        (releaser)free_ ## gns,         \
    },
#else
#define ASN1_SYM_TYPE(n, gn, gns)       \
    {                                   \
        n,                              \
        sizeof(gns),                    \
        (copyer)copy_ ## gns,           \
        (lengther)length_ ## gns,       \
        (decoder)decode_ ## gns,        \
        (encoder)encode_ ## gns,        \
        0,                              \
        (releaser)free_ ## gns,         \
    },
#endif
#include "cms_asn1_syms.c"
#include "digest_asn1_syms.c"
#include "krb5_asn1_syms.c"
#include "kx509_asn1_syms.c"
#include "ocsp_asn1_syms.c"
#include "pkcs10_asn1_syms.c"
#include "pkcs12_asn1_syms.c"
#include "pkcs8_asn1_syms.c"
#include "pkcs9_asn1_syms.c"
#include "pkinit_asn1_syms.c"
#include "rfc2459_asn1_syms.c"
#include "rfc4108_asn1_syms.c"
#ifdef ASN1_PRINT_SUPPORTED
#include "x690sample_template_asn1_syms.c"
#else
#include "x690sample_asn1_syms.c"
#endif
};

struct types sorted_types[sizeof(types)/sizeof(types[0])];

static size_t
loop (unsigned char *buf, size_t len, int indent)
{
    unsigned char *start_buf = buf;

    while (len > 0) {
	int ret;
	Der_class class;
	Der_type type;
	unsigned int tag;
	size_t sz;
	size_t length;
	size_t loop_length = 0;
	int end_tag = 0;
	const char *tagname;

	ret = der_get_tag (buf, len, &class, &type, &tag, &sz);
	if (ret)
	    errx (1, "der_get_tag: %s", error_message (ret));
	if (sz > len)
	    errx (1, "unreasonable length (%u) > %u",
		  (unsigned)sz, (unsigned)len);
	buf += sz;
	len -= sz;
	if (indent_flag) {
	    int i;
	    for (i = 0; i < indent; ++i)
		printf (" ");
	}
	printf ("%s %s ", der_get_class_name(class), der_get_type_name(type));
	tagname = der_get_tag_name(tag);
	if (class == ASN1_C_UNIV && tagname != NULL)
	    printf ("%s = ", tagname);
	else
	    printf ("tag %d = ", tag);
	ret = der_get_length (buf, len, &length, &sz);
	if (ret)
	    errx (1, "der_get_tag: %s", error_message (ret));
	if (sz > len)
	    errx (1, "unreasonable tag length (%u) > %u",
		  (unsigned)sz, (unsigned)len);
	buf += sz;
	len -= sz;
	if (length == ASN1_INDEFINITE) {
	    if ((class == ASN1_C_UNIV && type == PRIM && tag == UT_OctetString) ||
		(class == ASN1_C_CONTEXT && type == CONS) ||
		(class == ASN1_C_UNIV && type == CONS && tag == UT_Sequence) ||
		(class == ASN1_C_UNIV && type == CONS && tag == UT_Set)) {
		printf("*INDEFINITE FORM*");
	    } else {
		fflush(stdout);
		errx(1, "indef form used on unsupported object");
	    }
	    end_tag = 1;
	    if (indefinite_form_loop > indefinite_form_loop_max)
		errx(1, "indefinite form used recursively more then %lu "
		     "times, aborting", indefinite_form_loop_max);
	    indefinite_form_loop++;
	    length = len;
	} else if (length > len) {
	    printf("\n");
	    fflush(stdout);
	    errx (1, "unreasonable inner length (%u) > %u",
		  (unsigned)length, (unsigned)len);
	}
	if (class == ASN1_C_CONTEXT || class == ASN1_C_APPL) {
	    printf ("%lu bytes [%u]", (unsigned long)length, tag);
	    if (type == CONS) {
		printf("\n");
		loop_length = loop (buf, length, indent + 2);
	    } else {
		printf(" IMPLICIT content\n");
	    }
	} else if (class == ASN1_C_UNIV) {
	    switch (tag) {
	    case UT_EndOfContent:
		printf (" INDEFINITE length was %lu\n",
			(unsigned long)(buf - start_buf));
		break;
	    case UT_Set :
	    case UT_Sequence :
		printf ("%lu bytes {\n", (unsigned long)length);
		loop_length = loop (buf, length, indent + 2);
		if (indent_flag) {
		    int i;
		    for (i = 0; i < indent; ++i)
			printf (" ");
		    printf ("}\n");
		} else
		    printf ("} indent = %d\n", indent / 2);
		break;
	    case UT_Integer : {
		int val;

		if (length <= sizeof(val)) {
		    ret = der_get_integer (buf, length, &val, NULL);
		    if (ret)
			errx (1, "der_get_integer: %s", error_message (ret));
		    printf ("integer %d\n", val);
		} else {
		    heim_integer vali;
		    char *p;

		    ret = der_get_heim_integer(buf, length, &vali, NULL);
		    if (ret)
			errx (1, "der_get_heim_integer: %s",
			      error_message (ret));
		    ret = der_print_hex_heim_integer(&vali, &p);
		    if (ret)
			errx (1, "der_print_hex_heim_integer: %s",
			      error_message (ret));
		    printf ("BIG NUM integer: length %lu %s\n",
			    (unsigned long)length, p);
		    free(p);
		}
		break;
	    }
	    case UT_OctetString : {
		heim_octet_string str;
		size_t i;

		ret = der_get_octet_string (buf, length, &str, NULL);
		if (ret)
		    errx (1, "der_get_octet_string: %s", error_message (ret));
		printf ("(length %lu), ", (unsigned long)length);

		if (inner_flag) {
		    Der_class class2;
		    Der_type type2;
		    unsigned int tag2;

		    ret = der_get_tag(str.data, str.length,
				      &class2, &type2, &tag2, &sz);
		    if (ret || sz > str.length ||
			type2 != CONS || tag2 != UT_Sequence)
			goto just_an_octet_string;

		    printf("{\n");
		    loop (str.data, str.length, indent + 2);
		    for (i = 0; i < indent; ++i)
			printf (" ");
		    printf ("}\n");

		} else {
		    unsigned char *uc;

		just_an_octet_string:
		    uc = (unsigned char *)str.data;
		    for (i = 0; i < min(16,length); ++i)
			printf ("%02x", uc[i]);
		    printf ("\n");
		}
		free (str.data);
		break;
	    }
	    case UT_IA5String :
	    case UT_PrintableString : {
		heim_printable_string str;
		unsigned char *s;
		size_t n;

		memset(&str, 0, sizeof(str));

		ret = der_get_printable_string (buf, length, &str, NULL);
		if (ret)
		    errx (1, "der_get_general_string: %s",
			  error_message (ret));
		s = str.data;
		printf("\"");
		for (n = 0; n < str.length; n++) {
		    if (isprint(s[n]))
			printf ("%c", s[n]);
		    else
			printf ("#%02x", s[n]);
		}
		printf("\"\n");
		der_free_printable_string(&str);
		break;
	    }
	    case UT_GeneralizedTime :
	    case UT_GeneralString :
	    case UT_VisibleString :
	    case UT_UTF8String : {
		heim_general_string str;

		ret = der_get_general_string (buf, length, &str, NULL);
		if (ret)
		    errx (1, "der_get_general_string: %s",
			  error_message (ret));
		printf ("\"%s\"\n", str);
		free (str);
		break;
	    }
	    case UT_OID: {
		heim_oid o;
		char *p;

		ret = der_get_oid(buf, length, &o, NULL);
		if (ret)
		    errx (1, "der_get_oid: %s", error_message (ret));
		ret = der_print_heim_oid_sym(&o, '.', &p);
		der_free_oid(&o);
		if (ret)
		    errx (1, "der_print_heim_oid_sym: %s", error_message (ret));
		printf("%s\n", p);
		free(p);

		break;
	    }
	    case UT_Enumerated: {
		int num;

		ret = der_get_integer (buf, length, &num, NULL);
		if (ret)
		    errx (1, "der_get_enum: %s", error_message (ret));

		printf("%u\n", num);
		break;
	    }
	    default :
		printf ("%lu bytes\n", (unsigned long)length);
		break;
	    }
	}
	if (end_tag) {
	    if (loop_length == 0)
		errx(1, "zero length INDEFINITE data ? indent = %d\n",
		     indent / 2);
	    if (loop_length < length)
		length = loop_length;
	    if (indefinite_form_loop == 0)
		errx(1, "internal error in indefinite form loop detection");
	    indefinite_form_loop--;
	} else if (loop_length)
	    errx(1, "internal error for INDEFINITE form");
	buf += length;
	len -= length;
    }
    return 0;
}

static int
type_cmp(const void *va, const void *vb)
{
    const struct types *ta = (const struct types *)va;
    const struct types *tb = (const struct types *)vb;

    return strcmp(ta->name, tb->name);
}

static int
dotype(unsigned char *buf, size_t len, char **argv, size_t *size)
{
    const char *typename = "";
    size_t matches = 0;
    size_t sz;
    size_t tried = 0;
    size_t i = 0;
    void *v;
    int ret = 0;

    *size = len;

    memcpy(sorted_types, types, sizeof(types));
    qsort(sorted_types,
          sizeof(types)/sizeof(types[0]),
          sizeof(types[0]),
          type_cmp);

    while ((try_all_flag && i < sizeof(types)/sizeof(types[0])) ||
           (typename = (argv++)[0])) {

        if (try_all_flag) {
            typename = sorted_types[i].name;
        } else {
            size_t right = sizeof(types)/sizeof(types[0]) - 1;
            size_t left = 0;
            size_t mid = (left + right) >> 1;
            int c = -1;

            while (left <= right) {
                mid = (left + right) >> 1;
                c = strcmp(sorted_types[mid].name, typename);
                if (c < 0)
                    left = mid + 1;
                else if (c > 0)
                    right = mid - 1;
                else
                    break;
            }
            if (c != 0)
                errx(1, "Type %s not found", typename);
            i = mid;
        }
        v = ecalloc(1, sorted_types[i].sz);
        ret = sorted_types[i].decode(buf, len, v, &sz);
        if (ret == 0) {
            matches++;
            if (!quiet_flag && sz == len) {
                fprintf(stderr, "Match: %s\n", typename);
            } else if (sequence_flag) {
                *size = sz;
            } else if (!quiet_flag) {
                fprintf(stderr, "Prefix match: %s\n", typename);
            }
            if (print_flag) {
                static int warned = 0;

                if (!sorted_types[i].print) {
                    if (!warned)
                        warnx("Missing print support; try enabling / not "
                              "disabling ASN.1 templating in build "
                              "configuration");
                    warned = 1;
                } else {
                    char *s;

                    s = sorted_types[i].print(v, indent_flag ? ASN1_PRINT_INDENT : 0);
                    if (!s)
                        err(1, "Could not print %s\n", typename);
                    if (!quiet_flag)
                        printf("%s\n", s);
                    free(s);
                }
            }
            if (test_encode_flag) {
                unsigned char *der = emalloc(sz);
                size_t wants = sorted_types[i].len(v);

                if (wants != sz)
                    errx(1, "Encoding will not round trip");
                ret = sorted_types[i].encode(der + (sz - 1), sz, v, &sz);
                if (ret != 0)
                    errx(1, "Encoding failed");
                if (memcmp(buf, der, sz) != 0)
                    errx(1, "Encoding did not round trip");
                free(der);
            }
            if (test_copy_flag) {
                void *vcpy = ecalloc(1, sorted_types[i].sz);

                ret = sorted_types[i].cpy(v, vcpy);
                if (ret != 0)
                    errx(1, "Copy function failed");
                if (test_encode_flag) {
                    unsigned char *der = emalloc(sz);
                    size_t wants = sorted_types[i].len(vcpy);

                    if (wants != sz)
                        errx(1, "Encoding of copy will not round trip");
                    ret = sorted_types[i].encode(der + (sz - 1), sz, vcpy, &sz);
                    if (ret != 0)
                        errx(1, "Encoding of copy failed");
                    if (memcmp(buf, der, sz) != 0)
                        errx(1, "Encoding of copy did not round trip");
                    free(der);
                }
                sorted_types[i].release(vcpy);
                free(vcpy);
            }
        }
        sorted_types[i].release(v);
        free(v);
        tried++;
        i++;

        if (ret == 0 && !try_all_flag && !argv[0])
            return 0;

        if (!try_all_flag && argv[0])
            continue;

        if (try_all_flag) {
            if (i < sizeof(types)/sizeof(types[0]))
                continue;
            if (matches)
                break;
        }
        if (tried > 1)
            errx(1, "No type matched the input value");

        /* XXX Use com_err */
        switch (ret) {
        case ASN1_BAD_TIMEFORMAT:
            errx(1, "Could not decode and print data as type %s: "
                 "Bad time format", typename);
        case ASN1_MISSING_FIELD:
            errx(1, "Could not decode and print data as type %s: "
                 "Missing required field", typename);
        case ASN1_MISPLACED_FIELD:
            errx(1, "Could not decode and print data as type %s: "
                 "Fields out of order", typename);
        case ASN1_TYPE_MISMATCH:
            errx(1, "Could not decode and print data as type %s: "
                 "Type mismatch", typename);
        case ASN1_OVERFLOW:
            errx(1, "Could not decode and print data as type %s: "
                 "DER value too large", typename);
        case ASN1_OVERRUN:
            errx(1, "Could not decode and print data as type %s: "
                 "DER value too short", typename);
        case ASN1_BAD_ID:
            errx(1, "Could not decode and print data as type %s: "
                 "DER tag is unexpected", typename);
        case ASN1_BAD_LENGTH:
            errx(1, "Could not decode and print data as type %s: "
                 "DER length does not match value", typename);
        case ASN1_BAD_FORMAT:
        case ASN1_PARSE_ERROR:
            errx(1, "Could not decode and print data as type %s: "
                 "DER badly formatted", typename);
        case ASN1_EXTRA_DATA:
            errx(1, "Could not decode and print data as type %s: "
                 "Extra data past end of end structure", typename);
        case ASN1_BAD_CHARACTER:
            errx(1, "Could not decode and print data as type %s: "
                 "Invalid character encoding in string", typename);
        case ASN1_MIN_CONSTRAINT:
            errx(1, "Could not decode and print data as type %s: "
                 "Too few elements", typename);
        case ASN1_MAX_CONSTRAINT:
            errx(1, "Could not decode and print data as type %s: "
                 "Too many elements", typename);
        case ASN1_EXACT_CONSTRAINT:
            errx(1, "Could not decode and print data as type %s: "
                 "Wrong count of elements", typename);
        case ASN1_INDEF_OVERRUN:
            errx(1, "Could not decode and print data as type %s: "
                 "BER indefinte encoding overun", typename);
        case ASN1_INDEF_UNDERRUN:
            errx(1, "Could not decode and print data as type %s: "
                 "BER indefinte encoding underun", typename);
        case ASN1_GOT_BER:
            errx(1, "Could not decode and print data as type %s: "
                 "BER encoding when DER expected", typename);
        case ASN1_INDEF_EXTRA_DATA:
            errx(1, "Could not decode and print data as type %s: "
                 "End-of-contents tag contains data", typename);
        default:
            errx(1, "Could not decode and print data as type %s", typename);
        }
    }
    return 0;
}

static int
doit(char **argv)
{
    int fd = open(argv[0], O_RDONLY);
    struct stat sb;
    unsigned char *buf;
    size_t len;
    int ret;

    if(fd < 0)
	err(1, "opening %s for read", argv[0]);
    if (fstat (fd, &sb) < 0)
	err(1, "stat %s", argv[0]);
    len = sb.st_size;
    buf = emalloc(len);
    if (read(fd, buf, len) != len)
	errx(1, "read failed");
    close(fd);

    argv++;
    if (argv[0] || try_all_flag) {
        size_t off = 0;
        size_t sz = 0;

        do {
            ret = dotype(buf + off, len - off, argv, &sz);
            off += sz;
        } while (ret == 0 && sequence_flag && off < len);
    } else {
        ret = loop(buf, len, 0);
    }
    free(buf);
    return ret;
}


static int list_types_flag;
static int version_flag;
static int help_flag;
struct getargs args[] = {
    { "indent", 'i', arg_negative_flag, &indent_flag,
        "\tdo not indent dump", NULL },
    { "inner", 'I', arg_flag, &inner_flag,
        "\ttry to parse inner structures of OCTET STRING", NULL },
    { "list-types", 'l', arg_flag, &list_types_flag,
        "\tlist ASN.1 types known to this program", NULL },
    { "try-all-types", 'A', arg_flag, &try_all_flag,
        "\ttry all known types", NULL },
    { "raw-sequence", 'S', arg_flag, &sequence_flag,
        "\ttry parsing leftover data", NULL },
    { "test-encode", 0, arg_flag, &test_encode_flag,
        "\ttest encode round trip (for memory debugging and fuzzing)", NULL },
    { "test-copy", 0, arg_flag, &test_copy_flag,
        "\ttest copy operation (for memory debugging and fuzzing)", NULL },
    { "print", 'n', arg_negative_flag, &print_flag,
        "\ttest copy operation (for memory debugging and fuzzing)", NULL },
    { "quiet", 'q', arg_flag, &quiet_flag,
        "\tOutput nothing (exit status 0 means type matched)", NULL },
    { "version", 'v', arg_flag, &version_flag, NULL, NULL },
    { "help", 'h', arg_flag, &help_flag, NULL, NULL }
};
int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int code)
{
    arg_printusage(args, num_args, NULL, "dump-file [TypeName [TypeName ...]]");
    exit(code);
}

int
main(int argc, char **argv)
{
    int optidx = 0;

    setprogname(argv[0]);
    initialize_asn1_error_table();
    if (getarg(args, num_args, argc, argv, &optidx))
	usage(1);
    if (help_flag)
	usage(0);
    if (version_flag) {
	print_version(NULL);
	exit(0);
    }
    argv += optidx;
    argc -= optidx;

    if (sequence_flag && try_all_flag)
        errx(1, "--raw-sequence and --try-all-types are mutually exclusive");
    if (quiet_flag && !try_all_flag && argc < 2)
        errx(1, "--quiet requires --try-all-types or that a TypeName be given");
    if (!print_flag && !try_all_flag && argc < 2)
        errx(1, "--no-print requires --try-all-types or that a TypeName be given");

    if (list_types_flag) {
        size_t i;

        if (argc)
            errx(1, "--list-types is exclusive of other options or arguments");

        for (i = 0; i < sizeof(types)/sizeof(types[0]); i++)
            printf("%s\n", types[i].name);
        exit(0);
    }

    if (argc < 1)
	usage(1);
    return doit(argv);
}
