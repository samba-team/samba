/*
 * Copyright (c) 1999 - 2005 Kungliga Tekniska Högskolan
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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <roken.h>

#include <asn1-common.h>
#include <asn1_err.h>
#include <der.h>
#include <krb5_asn1.h>
#include <heim_asn1.h>
#include <rfc2459_asn1.h>
#include <x690sample_asn1.h>
#include <test_asn1.h>
#include <cms_asn1.h>

#include "check-common.h"

static int my_copy_vers_called;
static int my_free_vers_called;

int
my_copy_vers(const my_vers *from, my_vers *to)
{
    my_copy_vers_called++;
    *to = *from;
    return 0;
}

void
my_free_vers(my_vers *v)
{
    my_free_vers_called++;
    v->v = -1;
}

static char *lha_principal[] = { "lha" };
static char *lharoot_princ[] = { "lha", "root" };
static char *datan_princ[] = { "host", "nutcracker.e.kth.se" };
static char *nada_tgt_principal[] = { "krbtgt", "NADA.KTH.SE" };

static int
cmp_principal (void *a, void *b)
{
    Principal *pa = a;
    Principal *pb = b;
    int i;

    COMPARE_STRING(pa,pb,realm);
    COMPARE_INTEGER(pa,pb,name.name_type);
    COMPARE_INTEGER(pa,pb,name.name_string.len);

    for (i = 0; i < pa->name.name_string.len; i++)
	COMPARE_STRING(pa,pb,name.name_string.val[i]);

    return 0;
}

static int
test_principal (void)
{

    struct test_case tests[] = {
	{ NULL, 29,
	  "\x30\x1b\xa0\x10\x30\x0e\xa0\x03\x02\x01\x01\xa1\x07\x30\x05\x1b"
	  "\x03\x6c\x68\x61\xa1\x07\x1b\x05\x53\x55\x2e\x53\x45",
	  NULL
	},
	{ NULL, 35,
	  "\x30\x21\xa0\x16\x30\x14\xa0\x03\x02\x01\x01\xa1\x0d\x30\x0b\x1b"
	  "\x03\x6c\x68\x61\x1b\x04\x72\x6f\x6f\x74\xa1\x07\x1b\x05\x53\x55"
	  "\x2e\x53\x45",
	  NULL
	},
	{ NULL, 54,
	  "\x30\x34\xa0\x26\x30\x24\xa0\x03\x02\x01\x03\xa1\x1d\x30\x1b\x1b"
	  "\x04\x68\x6f\x73\x74\x1b\x13\x6e\x75\x74\x63\x72\x61\x63\x6b\x65"
	  "\x72\x2e\x65\x2e\x6b\x74\x68\x2e\x73\x65\xa1\x0a\x1b\x08\x45\x2e"
	  "\x4b\x54\x48\x2e\x53\x45",
	  NULL
	}
    };


    Principal values[] = {
	{ { KRB5_NT_PRINCIPAL, { 1, lha_principal } },  "SU.SE", NULL },
	{ { KRB5_NT_PRINCIPAL, { 2, lharoot_princ } },  "SU.SE", NULL },
	{ { KRB5_NT_SRV_HST, { 2, datan_princ } },  "E.KTH.SE", NULL }
    };
    int i, ret;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	if (asprintf (&tests[i].name, "Principal %d", i) < 0)
	    errx(1, "malloc");
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    ret = generic_test (tests, ntests, sizeof(Principal),
			(generic_encode)encode_Principal,
			(generic_length)length_Principal,
			(generic_decode)decode_Principal,
			(generic_free)free_Principal,
			cmp_principal,
			NULL);
    for (i = 0; i < ntests; ++i)
	free (tests[i].name);

    return ret;
}

static int
cmp_authenticator (void *a, void *b)
{
    Authenticator *aa = a;
    Authenticator *ab = b;
    int i;

    COMPARE_INTEGER(aa,ab,authenticator_vno);
    COMPARE_STRING(aa,ab,crealm);

    COMPARE_INTEGER(aa,ab,cname.name_type);
    COMPARE_INTEGER(aa,ab,cname.name_string.len);

    for (i = 0; i < aa->cname.name_string.len; i++)
	COMPARE_STRING(aa,ab,cname.name_string.val[i]);

    return 0;
}

static int
test_authenticator (void)
{
    struct test_case tests[] = {
	{ NULL, 63,
	  "\x62\x3d\x30\x3b\xa0\x03\x02\x01\x05\xa1\x0a\x1b\x08"
	  "\x45\x2e\x4b\x54\x48\x2e\x53\x45\xa2\x10\x30\x0e\xa0"
	  "\x03\x02\x01\x01\xa1\x07\x30\x05\x1b\x03\x6c\x68\x61"
	  "\xa4\x03\x02\x01\x0a\xa5\x11\x18\x0f\x31\x39\x37\x30"
	  "\x30\x31\x30\x31\x30\x30\x30\x31\x33\x39\x5a",
	  NULL
	},
	{ NULL, 67,
	  "\x62\x41\x30\x3f\xa0\x03\x02\x01\x05\xa1\x07\x1b\x05"
	  "\x53\x55\x2e\x53\x45\xa2\x16\x30\x14\xa0\x03\x02\x01"
	  "\x01\xa1\x0d\x30\x0b\x1b\x03\x6c\x68\x61\x1b\x04\x72"
	  "\x6f\x6f\x74\xa4\x04\x02\x02\x01\x24\xa5\x11\x18\x0f"
	  "\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x31\x36\x33"
	  "\x39\x5a",
	  NULL
	}
    };

    Authenticator values[] = {
	{ 5, "E.KTH.SE", { KRB5_NT_PRINCIPAL, { 1, lha_principal } },
	  NULL, 10, 99, NULL, NULL, NULL },
	{ 5, "SU.SE", { KRB5_NT_PRINCIPAL, { 2, lharoot_princ } },
	  NULL, 292, 999, NULL, NULL, NULL }
    };
    int i, ret;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	if (asprintf (&tests[i].name, "Authenticator %d", i) < 0)
	    errx(1, "malloc");
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    ret = generic_test (tests, ntests, sizeof(Authenticator),
			(generic_encode)encode_Authenticator,
			(generic_length)length_Authenticator,
			(generic_decode)decode_Authenticator,
			(generic_free)free_Authenticator,
			cmp_authenticator,
			(generic_copy)copy_Authenticator);
    for (i = 0; i < ntests; ++i)
	free(tests[i].name);

    return ret;
}

static int
cmp_KRB_ERROR (void *a, void *b)
{
    KRB_ERROR *aa = a;
    KRB_ERROR *ab = b;
    int i;

    COMPARE_INTEGER(aa,ab,pvno);
    COMPARE_INTEGER(aa,ab,msg_type);

    IF_OPT_COMPARE(aa,ab,ctime) {
	COMPARE_INTEGER(aa,ab,ctime);
    }
    IF_OPT_COMPARE(aa,ab,cusec) {
	COMPARE_INTEGER(aa,ab,cusec);
    }
    COMPARE_INTEGER(aa,ab,stime);
    COMPARE_INTEGER(aa,ab,susec);
    COMPARE_INTEGER(aa,ab,error_code);

    IF_OPT_COMPARE(aa,ab,crealm) {
	COMPARE_OPT_STRING(aa,ab,crealm);
    }
#if 0
    IF_OPT_COMPARE(aa,ab,cname) {
	COMPARE_OPT_STRING(aa,ab,cname);
    }
#endif
    COMPARE_STRING(aa,ab,realm);

    COMPARE_INTEGER(aa,ab,sname.name_string.len);
    for (i = 0; i < aa->sname.name_string.len; i++)
	COMPARE_STRING(aa,ab,sname.name_string.val[i]);

    IF_OPT_COMPARE(aa,ab,e_text) {
	COMPARE_OPT_STRING(aa,ab,e_text);
    }
    IF_OPT_COMPARE(aa,ab,e_data) {
	/* COMPARE_OPT_OCTET_STRING(aa,ab,e_data); */
    }

    return 0;
}

static int
test_krb_error (void)
{
    struct test_case tests[] = {
	{ NULL, 127,
	  "\x7e\x7d\x30\x7b\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11"
	  "\x18\x0f\x32\x30\x30\x33\x31\x31\x32\x34\x30\x30\x31\x31\x31\x39"
	  "\x5a\xa5\x05\x02\x03\x04\xed\xa5\xa6\x03\x02\x01\x1f\xa7\x0d\x1b"
	  "\x0b\x4e\x41\x44\x41\x2e\x4b\x54\x48\x2e\x53\x45\xa8\x10\x30\x0e"
	  "\xa0\x03\x02\x01\x01\xa1\x07\x30\x05\x1b\x03\x6c\x68\x61\xa9\x0d"
	  "\x1b\x0b\x4e\x41\x44\x41\x2e\x4b\x54\x48\x2e\x53\x45\xaa\x20\x30"
	  "\x1e\xa0\x03\x02\x01\x01\xa1\x17\x30\x15\x1b\x06\x6b\x72\x62\x74"
	  "\x67\x74\x1b\x0b\x4e\x41\x44\x41\x2e\x4b\x54\x48\x2e\x53\x45",
	  "KRB-ERROR Test 1"
	}
    };
    int ntests = sizeof(tests) / sizeof(*tests);
    KRB_ERROR e1;
    PrincipalName lhaprincipalname = { 1, { 1, lha_principal } };
    PrincipalName tgtprincipalname = { 1, { 2, nada_tgt_principal } };
    char *realm = "NADA.KTH.SE";

    e1.pvno = 5;
    e1.msg_type = 30;
    e1.ctime = NULL;
    e1.cusec = NULL;
    e1.stime = 1069632679;
    e1.susec = 322981;
    e1.error_code = 31;
    e1.crealm = &realm;
    e1.cname = &lhaprincipalname;
    e1.realm = "NADA.KTH.SE";
    e1.sname = tgtprincipalname;
    e1.e_text = NULL;
    e1.e_data = NULL;

    tests[0].val = &e1;

    return generic_test (tests, ntests, sizeof(KRB_ERROR),
			 (generic_encode)encode_KRB_ERROR,
			 (generic_length)length_KRB_ERROR,
			 (generic_decode)decode_KRB_ERROR,
			 (generic_free)free_KRB_ERROR,
			 cmp_KRB_ERROR,
			 (generic_copy)copy_KRB_ERROR);
}

static int
cmp_Name (void *a, void *b)
{
    Name *aa = a;
    Name *ab = b;

    COMPARE_INTEGER(aa,ab,element);

    return 0;
}

static int
test_Name (void)
{
    struct test_case tests[] = {
	{ NULL, 35,
	  "\x30\x21\x31\x1f\x30\x0b\x06\x03\x55\x04\x03\x13\x04\x4c\x6f\x76"
	  "\x65\x30\x10\x06\x03\x55\x04\x07\x13\x09\x53\x54\x4f\x43\x4b\x48"
	  "\x4f\x4c\x4d",
	  "Name CN=Love+L=STOCKHOLM"
	},
	{ NULL, 35,
	  "\x30\x21\x31\x1f\x30\x0b\x06\x03\x55\x04\x03\x13\x04\x4c\x6f\x76"
	  "\x65\x30\x10\x06\x03\x55\x04\x07\x13\x09\x53\x54\x4f\x43\x4b\x48"
	  "\x4f\x4c\x4d",
	  "Name L=STOCKHOLM+CN=Love"
	}
    };

    int ntests = sizeof(tests) / sizeof(*tests);
    Name n1, n2;
    RelativeDistinguishedName rdn1[1];
    RelativeDistinguishedName rdn2[1];
    AttributeTypeAndValue atv1[2];
    AttributeTypeAndValue atv2[2];
    unsigned cmp_CN[] = { 2, 5, 4, 3 };
    unsigned cmp_L[] = { 2, 5, 4, 7 };

    /* n1 */
    n1.element = choice_Name_rdnSequence;
    n1.u.rdnSequence.val = rdn1;
    n1.u.rdnSequence.len = sizeof(rdn1)/sizeof(rdn1[0]);
    rdn1[0].val = atv1;
    rdn1[0].len = sizeof(atv1)/sizeof(atv1[0]);

    atv1[0].type.length = sizeof(cmp_CN)/sizeof(cmp_CN[0]);
    atv1[0].type.components = cmp_CN;
    atv1[0].value.element = choice_DirectoryString_printableString;
    atv1[0].value.u.printableString.data = "Love";
    atv1[0].value.u.printableString.length = 4;

    atv1[1].type.length = sizeof(cmp_L)/sizeof(cmp_L[0]);
    atv1[1].type.components = cmp_L;
    atv1[1].value.element = choice_DirectoryString_printableString;
    atv1[1].value.u.printableString.data = "STOCKHOLM";
    atv1[1].value.u.printableString.length = 9;

    /* n2 */
    n2.element = choice_Name_rdnSequence;
    n2.u.rdnSequence.val = rdn2;
    n2.u.rdnSequence.len = sizeof(rdn2)/sizeof(rdn2[0]);
    rdn2[0].val = atv2;
    rdn2[0].len = sizeof(atv2)/sizeof(atv2[0]);

    atv2[0].type.length = sizeof(cmp_L)/sizeof(cmp_L[0]);
    atv2[0].type.components = cmp_L;
    atv2[0].value.element = choice_DirectoryString_printableString;
    atv2[0].value.u.printableString.data = "STOCKHOLM";
    atv2[0].value.u.printableString.length = 9;

    atv2[1].type.length = sizeof(cmp_CN)/sizeof(cmp_CN[0]);
    atv2[1].type.components = cmp_CN;
    atv2[1].value.element = choice_DirectoryString_printableString;
    atv2[1].value.u.printableString.data = "Love";
    atv2[1].value.u.printableString.length = 4;

    /* */
    tests[0].val = &n1;
    tests[1].val = &n2;

    return generic_test (tests, ntests, sizeof(Name),
			 (generic_encode)encode_Name,
			 (generic_length)length_Name,
			 (generic_decode)decode_Name,
			 (generic_free)free_Name,
			 cmp_Name,
			 (generic_copy)copy_Name);
}

static int
cmp_KeyUsage (void *a, void *b)
{
    KeyUsage *aa = a;
    KeyUsage *ab = b;

    return KeyUsage2int(*aa) != KeyUsage2int(*ab);
}

static int
test_bit_string (void)
{
    struct test_case tests[] = {
	{ NULL, 4,
	  "\x03\x02\x07\x80",
	  "bitstring 1"
	},
	{ NULL, 4,
	  "\x03\x02\x05\xa0",
	  "bitstring 2"
	},
	{ NULL, 5,
	  "\x03\x03\x07\x00\x80",
	  "bitstring 3"
	},
	{ NULL, 3,
	  "\x03\x01\x00",
	  "bitstring 4"
	}
    };

    int ntests = sizeof(tests) / sizeof(*tests);
    KeyUsage ku1, ku2, ku3, ku4;

    memset(&ku1, 0, sizeof(ku1));
    ku1.digitalSignature = 1;
    tests[0].val = &ku1;

    memset(&ku2, 0, sizeof(ku2));
    ku2.digitalSignature = 1;
    ku2.keyEncipherment = 1;
    tests[1].val = &ku2;

    memset(&ku3, 0, sizeof(ku3));
    ku3.decipherOnly = 1;
    tests[2].val = &ku3;

    memset(&ku4, 0, sizeof(ku4));
    tests[3].val = &ku4;


    return generic_test (tests, ntests, sizeof(KeyUsage),
			 (generic_encode)encode_KeyUsage,
			 (generic_length)length_KeyUsage,
			 (generic_decode)decode_KeyUsage,
			 (generic_free)free_KeyUsage,
			 cmp_KeyUsage,
			 (generic_copy)copy_KeyUsage);
}

static int
cmp_TicketFlags (void *a, void *b)
{
    TicketFlags *aa = a;
    TicketFlags *ab = b;

    return TicketFlags2int(*aa) != TicketFlags2int(*ab);
}

static int
test_bit_string_rfc1510 (void)
{
    struct test_case tests[] = {
	{ NULL, 7,
	  "\x03\x05\x00\x80\x00\x00\x00",
	  "TF bitstring 1"
	},
	{ NULL, 7,
	  "\x03\x05\x00\x40\x20\x00\x00",
	  "TF bitstring 2"
	},
	{ NULL, 7,
	  "\x03\x05\x00\x00\x20\x00\x00",
	  "TF bitstring 3"
	},
	{ NULL, 7,
	  "\x03\x05\x00\x00\x00\x00\x00",
	  "TF bitstring 4"
	}
    };

    int ntests = sizeof(tests) / sizeof(*tests);
    TicketFlags tf1, tf2, tf3, tf4;

    memset(&tf1, 0, sizeof(tf1));
    tf1.reserved = 1;
    tests[0].val = &tf1;

    memset(&tf2, 0, sizeof(tf2));
    tf2.forwardable = 1;
    tf2.pre_authent = 1;
    tests[1].val = &tf2;

    memset(&tf3, 0, sizeof(tf3));
    tf3.pre_authent = 1;
    tests[2].val = &tf3;

    memset(&tf4, 0, sizeof(tf4));
    tests[3].val = &tf4;


    return generic_test (tests, ntests, sizeof(TicketFlags),
			 (generic_encode)encode_TicketFlags,
			 (generic_length)length_TicketFlags,
			 (generic_decode)decode_TicketFlags,
			 (generic_free)free_TicketFlags,
			 cmp_TicketFlags,
			 (generic_copy)copy_TicketFlags);
}

static int
cmp_KerberosTime (void *a, void *b)
{
    KerberosTime *aa = a;
    KerberosTime *ab = b;

    return *aa != *ab;
}

static int
test_time (void)
{
    struct test_case tests[] = {
	{ NULL,  17,
	  "\x18\x0f\x31\x39\x37\x30\x30\x31\x30\x31\x30\x31\x31\x38\x33\x31"
	  "\x5a",
	  "time 1" },
	{ NULL,  17,
	  "\x18\x0f\x32\x30\x30\x39\x30\x35\x32\x34\x30\x32\x30\x32\x34\x30"
	  "\x5a",
	  "time 2" }
    };

    int ntests = sizeof(tests) / sizeof(*tests);
    KerberosTime times[] = {
	4711,
	1243130560
    };

    tests[0].val = &times[0];
    tests[1].val = &times[1];

    return generic_test (tests, ntests, sizeof(KerberosTime),
			 (generic_encode)encode_KerberosTime,
			 (generic_length)length_KerberosTime,
			 (generic_decode)decode_KerberosTime,
			 (generic_free)free_KerberosTime,
			 cmp_KerberosTime,
			 (generic_copy)copy_KerberosTime);
}

struct {
    const char *cert;
    size_t len;
} certs[] = {
    {
	"\x30\x82\x02\x6c\x30\x82\x01\xd5\xa0\x03\x02\x01\x02\x02\x09\x00"
	"\x99\x32\xde\x61\x0e\x40\x19\x8a\x30\x0d\x06\x09\x2a\x86\x48\x86"
	"\xf7\x0d\x01\x01\x05\x05\x00\x30\x2a\x31\x1b\x30\x19\x06\x03\x55"
	"\x04\x03\x0c\x12\x68\x78\x35\x30\x39\x20\x54\x65\x73\x74\x20\x52"
	"\x6f\x6f\x74\x20\x43\x41\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
	"\x02\x53\x45\x30\x1e\x17\x0d\x30\x39\x30\x34\x32\x36\x32\x30\x32"
	"\x39\x34\x30\x5a\x17\x0d\x31\x39\x30\x34\x32\x34\x32\x30\x32\x39"
	"\x34\x30\x5a\x30\x2a\x31\x1b\x30\x19\x06\x03\x55\x04\x03\x0c\x12"
	"\x68\x78\x35\x30\x39\x20\x54\x65\x73\x74\x20\x52\x6f\x6f\x74\x20"
	"\x43\x41\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x53\x45\x30"
	"\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05"
	"\x00\x03\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xb9\xd3\x1b\x67"
	"\x1c\xf7\x5e\x26\x81\x3b\x82\xff\x03\xa4\x43\xb5\xb2\x63\x0b\x89"
	"\x58\x43\xfe\x3d\xe0\x38\x7d\x93\x74\xbb\xad\x21\xa4\x29\xd9\x34"
	"\x79\xf3\x1c\x8c\x5a\xd6\xb0\xd7\x19\xea\xcc\xaf\xe0\xa8\x40\x02"
	"\x1d\x91\xf1\xac\x36\xb0\xfb\x08\xbd\xcc\x9a\xe1\xb7\x6e\xee\x0a"
	"\x69\xbf\x6d\x2b\xee\x20\x82\x61\x06\xf2\x18\xcc\x89\x11\x64\x7e"
	"\xb2\xff\x47\xd1\x3b\x52\x73\xeb\x5a\xc0\x03\xa6\x4b\xc7\x40\x7e"
	"\xbc\xe1\x0e\x65\x44\x3f\x40\x8b\x02\x82\x54\x04\xd9\xcc\x2c\x67"
	"\x01\xb6\x16\x82\xd8\x33\x53\x17\xd7\xde\x8d\x5d\x02\x03\x01\x00"
	"\x01\xa3\x81\x99\x30\x81\x96\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16"
	"\x04\x14\x6e\x48\x13\xdc\xbf\x8b\x95\x4c\x13\xf3\x1f\x97\x30\xdd"
	"\x27\x96\x59\x9b\x0e\x68\x30\x5a\x06\x03\x55\x1d\x23\x04\x53\x30"
	"\x51\x80\x14\x6e\x48\x13\xdc\xbf\x8b\x95\x4c\x13\xf3\x1f\x97\x30"
	"\xdd\x27\x96\x59\x9b\x0e\x68\xa1\x2e\xa4\x2c\x30\x2a\x31\x1b\x30"
	"\x19\x06\x03\x55\x04\x03\x0c\x12\x68\x78\x35\x30\x39\x20\x54\x65"
	"\x73\x74\x20\x52\x6f\x6f\x74\x20\x43\x41\x31\x0b\x30\x09\x06\x03"
	"\x55\x04\x06\x13\x02\x53\x45\x82\x09\x00\x99\x32\xde\x61\x0e\x40"
	"\x19\x8a\x30\x0c\x06\x03\x55\x1d\x13\x04\x05\x30\x03\x01\x01\xff"
	"\x30\x0b\x06\x03\x55\x1d\x0f\x04\x04\x03\x02\x01\xe6\x30\x0d\x06"
	"\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05\x05\x00\x03\x81\x81\x00"
	"\x52\x9b\xe4\x0e\xee\xc2\x5d\xb7\xf1\xba\x47\xe3\xfe\xaf\x3d\x51"
	"\x10\xfd\xe8\x0d\x14\x58\x05\x36\xa7\xeb\xd8\x05\xe5\x27\x6f\x51"
	"\xb8\xec\x90\xd9\x03\xe1\xbc\x9c\x93\x38\x21\x5c\xaf\x4e\x6c\x7b"
	"\x6c\x65\xa9\x92\xcd\x94\xef\xa8\xae\x90\x12\x14\x78\x2d\xa3\x15"
	"\xaa\x42\xf1\xd9\x44\x64\x2c\x3c\xc0\xbd\x3a\x48\xd8\x80\x45\x8b"
	"\xd1\x79\x82\xe0\x0f\xdf\x08\x3c\x60\x21\x6f\x31\x47\x98\xae\x2f"
	"\xcb\xb1\xa1\xb9\xc1\xa3\x71\x5e\x4a\xc2\x67\xdf\x66\x0a\x51\xb5"
	"\xad\x60\x05\xdb\x02\xd4\x1a\xd2\xb9\x4e\x01\x08\x2b\xc3\x57\xaf",
	624 },
    {
	"\x30\x82\x02\x54\x30\x82\x01\xbd\xa0\x03\x02\x01\x02\x02\x01\x08"
	"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05\x05\x00\x30"
	"\x2a\x31\x1b\x30\x19\x06\x03\x55\x04\x03\x0c\x12\x68\x78\x35\x30"
	"\x39\x20\x54\x65\x73\x74\x20\x52\x6f\x6f\x74\x20\x43\x41\x31\x0b"
	"\x30\x09\x06\x03\x55\x04\x06\x13\x02\x53\x45\x30\x1e\x17\x0d\x30"
	"\x39\x30\x34\x32\x36\x32\x30\x32\x39\x34\x30\x5a\x17\x0d\x31\x39"
	"\x30\x34\x32\x34\x32\x30\x32\x39\x34\x30\x5a\x30\x1b\x31\x0b\x30"
	"\x09\x06\x03\x55\x04\x06\x13\x02\x53\x45\x31\x0c\x30\x0a\x06\x03"
	"\x55\x04\x03\x0c\x03\x6b\x64\x63\x30\x81\x9f\x30\x0d\x06\x09\x2a"
	"\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30\x81"
	"\x89\x02\x81\x81\x00\xd2\x41\x7a\xf8\x4b\x55\xb2\xaf\x11\xf9\x43"
	"\x9b\x43\x81\x09\x3b\x9a\x94\xcf\x00\xf4\x85\x75\x92\xd7\x2a\xa5"
	"\x11\xf1\xa8\x50\x6e\xc6\x84\x74\x24\x17\xda\x84\xc8\x03\x37\xb2"
	"\x20\xf3\xba\xb5\x59\x36\x21\x4d\xab\x70\xe2\xc3\x09\x93\x68\x14"
	"\x12\x79\xc5\xbb\x9e\x1b\x4a\xf0\xc6\x24\x59\x25\xc3\x1c\xa8\x70"
	"\x66\x5b\x3e\x41\x8e\xe3\x25\x71\x9a\x94\xa0\x5b\x46\x91\x6f\xdd"
	"\x58\x14\xec\x89\xe5\x8c\x96\xc5\x38\x60\xe4\xab\xf2\x75\xee\x6e"
	"\x62\xfc\xe1\xbd\x03\x47\xff\xc4\xbe\x0f\xca\x70\x73\xe3\x74\x58"
	"\x3a\x2f\x04\x2d\x39\x02\x03\x01\x00\x01\xa3\x81\x98\x30\x81\x95"
	"\x30\x09\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x0b\x06\x03\x55"
	"\x1d\x0f\x04\x04\x03\x02\x05\xe0\x30\x12\x06\x03\x55\x1d\x25\x04"
	"\x0b\x30\x09\x06\x07\x2b\x06\x01\x05\x02\x03\x05\x30\x1d\x06\x03"
	"\x55\x1d\x0e\x04\x16\x04\x14\x3a\xd3\x73\xff\xab\xdb\x7d\x8d\xc6"
	"\x3a\xa2\x26\x3e\xae\x78\x95\x80\xc9\xe6\x31\x30\x48\x06\x03\x55"
	"\x1d\x11\x04\x41\x30\x3f\xa0\x3d\x06\x06\x2b\x06\x01\x05\x02\x02"
	"\xa0\x33\x30\x31\xa0\x0d\x1b\x0b\x54\x45\x53\x54\x2e\x48\x35\x4c"
	"\x2e\x53\x45\xa1\x20\x30\x1e\xa0\x03\x02\x01\x01\xa1\x17\x30\x15"
	"\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x0b\x54\x45\x53\x54\x2e\x48"
	"\x35\x4c\x2e\x53\x45\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01"
	"\x01\x05\x05\x00\x03\x81\x81\x00\x83\xf4\x14\xa7\x6e\x59\xff\x80"
	"\x64\xe7\xfa\xcf\x13\x80\x86\xe1\xed\x02\x38\xad\x96\x72\x25\xe5"
	"\x06\x7a\x9a\xbc\x24\x74\xa9\x75\x55\xb2\x49\x80\x69\x45\x95\x4a"
	"\x4c\x76\xa9\xe3\x4e\x49\xd3\xc2\x69\x5a\x95\x03\xeb\xba\x72\x23"
	"\x9c\xfd\x3d\x8b\xc6\x07\x82\x3b\xf4\xf3\xef\x6c\x2e\x9e\x0b\xac"
	"\x9e\x6c\xbb\x37\x4a\xa1\x9e\x73\xd1\xdc\x97\x61\xba\xfc\xd3\x49"
	"\xa6\xc2\x4c\x55\x2e\x06\x37\x76\xb5\xef\x57\xe7\x57\x58\x8a\x71"
	"\x63\xf3\xeb\xe7\x55\x68\x0d\xf6\x46\x4c\xfb\xf9\x43\xbb\x0c\x92"
	"\x4f\x4e\x22\x7b\x63\xe8\x4f\x9c",
	600
    }
};

static int
test_cert(void)
{
    Certificate c, c2;
    size_t size;
    size_t i;
    int ret;

    memset(&c, 0, sizeof(c));
    ret = copy_Certificate(&c, &c2);
    if (ret)
        return ret;
    free_Certificate(&c2);

    for (i = 0; i < sizeof(certs)/sizeof(certs[0]); i++) {

	ret = decode_Certificate((unsigned char *)certs[i].cert,
				 certs[i].len, &c, &size);
	if (ret)
	    return ret;

	ret = copy_Certificate(&c, &c2);
	free_Certificate(&c);
	if (ret)
	    return ret;

	free_Certificate(&c2);
    }

    return 0;
}

struct {
    const char *sd;
    size_t len;
} signeddata[] = {
    {
	"\x30\x80\x02\x01\x03\x31\x0b\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a"
	"\x05\x00\x30\x80\x06\x07\x2b\x06\x01\x05\x02\x03\x03\xa0\x80\x24"
	"\x80\x04\x50\x30\x4e\xa0\x2b\x30\x29\xa0\x03\x02\x01\x12\xa1\x22"
	"\x04\x20\x78\xf4\x86\x31\xc6\xc2\xc9\xcb\xef\x0c\xd7\x3a\x2a\xcd"
	"\x8c\x13\x34\x83\xb1\x5c\xa8\xbe\xbf\x2f\xea\xd2\xbb\xd8\x8c\x18"
	"\x47\x01\xa1\x1f\x30\x1d\xa0\x03\x02\x01\x0c\xa1\x16\x04\x14\xa6"
	"\x2c\x52\xb2\x80\x98\x30\x40\xbc\x5f\xb0\x77\x2d\x8a\xd7\xa1\xda"
	"\x3c\xc5\x62\x00\x00\x00\x00\x00\x00\xa0\x82\x02\x09\x30\x82\x02"
	"\x05\x30\x82\x01\x6e\xa0\x03\x02\x01\x02\x02\x04\x49\x75\x57\xbf"
	"\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05\x30\x3b\x31"
	"\x1f\x30\x1d\x06\x03\x55\x04\x03\x0c\x16\x63\x6f\x6d\x2e\x61\x70"
	"\x70\x6c\x65\x2e\x6b\x65\x72\x62\x65\x72\x6f\x73\x2e\x6b\x64\x63"
	"\x31\x18\x30\x16\x06\x03\x55\x04\x0a\x0c\x0f\x53\x79\x73\x74\x65"
	"\x6d\x20\x49\x64\x65\x6e\x74\x69\x74\x79\x30\x1e\x17\x0d\x30\x39"
	"\x31\x32\x30\x34\x30\x30\x32\x30\x32\x34\x5a\x17\x0d\x32\x39\x31"
	"\x31\x32\x39\x30\x30\x32\x30\x32\x34\x5a\x30\x3b\x31\x1f\x30\x1d"
	"\x06\x03\x55\x04\x03\x0c\x16\x63\x6f\x6d\x2e\x61\x70\x70\x6c\x65"
	"\x2e\x6b\x65\x72\x62\x65\x72\x6f\x73\x2e\x6b\x64\x63\x31\x18\x30"
	"\x16\x06\x03\x55\x04\x0a\x0c\x0f\x53\x79\x73\x74\x65\x6d\x20\x49"
	"\x64\x65\x6e\x74\x69\x74\x79\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86"
	"\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30\x81\x89"
	"\x02\x81\x81\x00\xb2\xc5\x4b\x34\xe3\x93\x99\xbb\xaa\xd1\x70\x62"
	"\x6c\x9c\xcc\xa6\xbc\x47\xc3\x23\xff\x15\xb9\x11\x27\x0a\xf8\x55"
	"\x4c\xb2\x43\x34\x75\xad\x55\xbb\xb9\x8a\xd0\x25\x64\xa4\x8c\x82"
	"\x74\x5d\x89\x52\xe2\x76\x75\x08\x67\xb5\x9c\x9c\x69\x86\x0c\x6d"
	"\x79\xf7\xa0\xbe\x42\x8f\x90\x46\x0c\x18\xf4\x7a\x56\x17\xa4\x65"
	"\x00\x3a\x5e\x3e\xbf\xbc\xf5\xe2\x2c\x26\x03\x52\xdd\xd4\x85\x3f"
	"\x03\xd7\x0c\x45\x7f\xff\xdd\x1e\x70\x6c\x9f\xb0\x8c\xd0\x33\xad"
	"\x92\x54\x17\x9d\x88\x89\x1a\xee\xef\xf7\x96\x3e\x68\xc3\xd1\x60"
	"\x47\x86\x80\x5d\x02\x03\x01\x00\x01\xa3\x18\x30\x16\x30\x14\x06"
	"\x03\x55\x1d\x25\x04\x0d\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x63"
	"\x64\x04\x04\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05"
	"\x05\x00\x03\x81\x81\x00\x9b\xbb\xaa\x63\x66\xd8\x70\x84\x3e\xf6"
	"\xa1\x3b\xf3\xe6\xd7\x3d\xfc\x4f\xc9\x45\xaa\x31\x43\x8d\xb5\x72"
	"\xe4\x34\x95\x7b\x6e\x5f\xe5\xc8\x5e\xaf\x12\x08\x6d\xd7\x25\x76"
	"\x40\xd5\xdc\x83\x7f\x2f\x74\xd1\x63\xc0\x7c\x26\x4d\x53\x10\xe7"
	"\xfa\xcc\xf2\x60\x41\x63\xdf\x56\xd6\xd9\xc0\xb4\xd0\x73\x99\x54"
	"\x40\xad\x90\x79\x2d\xd2\x5e\xcb\x13\x22\x2b\xd0\x76\xef\x8a\x48"
	"\xfd\xb2\x6e\xca\x04\x4e\x91\x3f\xb4\x63\xad\x22\x3a\xf7\x20\x9c"
	"\x4c\x0e\x47\x78\xe5\x2a\x85\x0e\x90\x7a\xce\x46\xe6\x15\x02\xb0"
	"\x83\xe7\xac\xfa\x92\xf8\x31\x81\xe8\x30\x81\xe5\x02\x01\x01\x30"
	"\x43\x30\x3b\x31\x1f\x30\x1d\x06\x03\x55\x04\x03\x0c\x16\x63\x6f"
	"\x6d\x2e\x61\x70\x70\x6c\x65\x2e\x6b\x65\x72\x62\x65\x72\x6f\x73"
	"\x2e\x6b\x64\x63\x31\x18\x30\x16\x06\x03\x55\x04\x0a\x0c\x0f\x53"
	"\x79\x73\x74\x65\x6d\x20\x49\x64\x65\x6e\x74\x69\x74\x79\x02\x04"
	"\x49\x75\x57\xbf\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x30"
	"\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x81"
	"\x80\x50\x2c\x69\xe1\xd2\xc4\xd1\xcc\xdc\xe0\xe9\x8a\x6b\x6a\x97"
	"\x1b\xb4\xe0\xa8\x20\xbe\x09\x6d\xe1\x55\x5f\x07\x70\x94\x2e\x14"
	"\xed\x4e\xb1\x69\x75\x40\xbb\x99\x87\xed\x23\x50\x27\x5f\xaa\xc4"
	"\x84\x60\x06\xfe\x45\xfd\x7e\x1b\x18\xe0\x0b\x77\x35\x2a\xb2\xf2"
	"\xe0\x88\x31\xad\x82\x31\x4a\xbc\x6d\x71\x62\xe6\x4d\x33\xb4\x09"
	"\x6e\x3f\x14\x12\xf2\x89\x29\x31\x84\x60\x2b\xa8\x2d\xe6\xca\x2f"
	"\x03\x3d\xd4\x69\x89\xb3\x98\xfd\xac\x63\x14\xaf\x6a\x52\x2a\xac"
	"\xe3\x8e\xfa\x21\x41\x8f\xcc\x04\x2d\x52\xee\x49\x54\x0d\x58\x51"
	"\x77\x00\x00",
	883
    }
};

static int
test_SignedData(void)
{
    SignedData sd;
    size_t size, i;
    int ret;

    for (i = 0; i < sizeof(signeddata) / sizeof(signeddata[0]); i++) {

	ret = decode_SignedData((unsigned char *)signeddata[i].sd,
				signeddata[i].len, &sd, &size);
	if (ret)
	    return ret;

	free_SignedData(&sd);
    }

    return 0;
}


static int
cmp_TESTLargeTag (void *a, void *b)
{
    TESTLargeTag *aa = a;
    TESTLargeTag *ab = b;

    COMPARE_INTEGER(aa,ab,foo);
    COMPARE_INTEGER(aa,ab,bar);
    return 0;
}

static int
test_large_tag (void)
{
    struct test_case tests[] = {
	{ NULL,  15,  "\x30\x0d\xbf\x7f\x03\x02\x01\x01\xbf\x81\x00\x03\x02\x01\x02", "large tag 1" }
    };

    int ntests = sizeof(tests) / sizeof(*tests);
    TESTLargeTag lt1;

    memset(&lt1, 0, sizeof(lt1));
    lt1.foo = 1;
    lt1.bar = 2;

    tests[0].val = &lt1;

    return generic_test (tests, ntests, sizeof(TESTLargeTag),
			 (generic_encode)encode_TESTLargeTag,
			 (generic_length)length_TESTLargeTag,
			 (generic_decode)decode_TESTLargeTag,
			 (generic_free)free_TESTLargeTag,
			 cmp_TESTLargeTag,
			 (generic_copy)copy_TESTLargeTag);
}

struct test_data {
    int ok;
    size_t len;
    size_t expected_len;
    void *data;
};

static int
check_tag_length(void)
{
    struct test_data td[] = {
	{ 1, 3, 3, "\x02\x01\x00"},
	{ 1, 3, 3, "\x02\x01\x7f"},
	{ 1, 4, 4, "\x02\x02\x00\x80"},
	{ 1, 4, 4, "\x02\x02\x01\x00"},
	{ 1, 4, 4, "\x02\x02\x02\x00"},
	{ 0, 3, 0, "\x02\x02\x00"},
	{ 0, 3, 0, "\x02\x7f\x7f"},
	{ 0, 4, 0, "\x02\x03\x00\x80"},
	{ 0, 4, 0, "\x02\x7f\x01\x00"},
	{ 0, 5, 0, "\x02\xff\x7f\x02\x00"}
    };
    size_t sz;
    TESTuint32 values[] = {0, 127, 128, 256, 512,
			 0, 127, 128, 256, 512 };
    TESTuint32 u;
    int i, ret, failed = 0;
    void *buf;

    for (i = 0; i < sizeof(td)/sizeof(td[0]); i++) {
	struct map_page *page;

	buf = map_alloc(OVERRUN, td[i].data, td[i].len, &page);

	ret = decode_TESTuint32(buf, td[i].len, &u, &sz);
	if (ret) {
	    if (td[i].ok) {
		printf("failed with tag len test %d\n", i);
		failed = 1;
	    }
	} else {
	    if (td[i].ok == 0) {
		printf("failed with success for tag len test %d\n", i);
		failed = 1;
	    }
	    if (td[i].expected_len != sz) {
		printf("wrong expected size for tag test %d\n", i);
		failed = 1;
	    }
	    if (values[i] != u) {
		printf("wrong value for tag test %d\n", i);
		failed = 1;
	    }
	}
	map_free(page, "test", "decode");
    }
    return failed;
}

static int
check_tag_length64(void)
{
    struct test_data td[] = {
	{ 1, 3, 3, "\x02\x01\x00"},
	{ 1, 7, 7, "\x02\x05\x01\xff\xff\xff\xff"},
	{ 1, 7, 7, "\x02\x05\x02\x00\x00\x00\x00"},
	{ 1, 9, 9, "\x02\x07\x7f\xff\xff\xff\xff\xff\xff"},
	{ 1, 10, 10, "\x02\x08\x00\x80\x00\x00\x00\x00\x00\x00"},
	{ 1, 10, 10, "\x02\x08\x7f\xff\xff\xff\xff\xff\xff\xff"},
	{ 1, 11, 11, "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff"},
	{ 0, 3, 0, "\x02\x02\x00"},
	{ 0, 3, 0, "\x02\x7f\x7f"},
	{ 0, 4, 0, "\x02\x03\x00\x80"},
	{ 0, 4, 0, "\x02\x7f\x01\x00"},
	{ 0, 5, 0, "\x02\xff\x7f\x02\x00"}
    };
    size_t sz;
    TESTuint64 values[] = {0, 8589934591LL, 8589934592LL,
			   36028797018963967LL, 36028797018963968LL,
			   9223372036854775807LL, 18446744073709551615ULL,
			   0, 127, 128, 256, 512 };
    TESTuint64 u;
    int i, ret, failed = 0;
    void *buf;

    if (sizeof(TESTuint64) != sizeof(uint64_t)) {
	ret += 1;
	printf("sizeof(TESTuint64) %d != sizeof(uint64_t) %d\n",
	       (int)sizeof(TESTuint64), (int)sizeof(uint64_t));
    }

    for (i = 0; i < sizeof(td)/sizeof(td[0]); i++) {
	struct map_page *page;

	buf = map_alloc(OVERRUN, td[i].data, td[i].len, &page);

	ret = decode_TESTuint64(buf, td[i].len, &u, &sz);
	if (ret) {
	    if (td[i].ok) {
		printf("failed with tag len test %d\n", i);
		printf("ret = %d\n", ret);
		failed = 1;
	    }
	} else {
	    if (td[i].ok == 0) {
		printf("failed with success for tag len test %d\n", i);
		failed = 1;
	    }
	    if (td[i].expected_len != sz) {
		printf("wrong expected size for tag test %d\n", i);
		printf("sz = %lu\n", (unsigned long)sz);
		failed = 1;
	    }
	    if (values[i] != u) {
		printf("wrong value for tag test %d\n", i);
		printf("Expected value: %llu\nActual value: %llu\n",
		       (unsigned long long)values[i], (unsigned long long)u);
		failed = 1;
	    }
	}
	map_free(page, "test", "decode");
    }
    return failed;
}

static int
check_tag_length64s(void)
{
    struct test_data td[] = {
	{ 1, 3, 3, "\x02\x01\x00"},
	{ 1, 7, 7, "\x02\x05\xfe\x00\x00\x00\x01"},
	{ 1, 7, 7, "\x02\x05\xfe\x00\x00\x00\x00"},
	{ 1, 9, 9, "\x02\x07\x80\x00\x00\x00\x00\x00\x01"},
	{ 1, 9, 9, "\x02\x07\x80\x00\x00\x00\x00\x00\x00"},
	{ 1, 10, 10, "\x02\x08\x80\x00\x00\x00\x00\x00\x00\x01"},
	{ 1, 9, 9, "\x02\x07\x80\x00\x00\x00\x00\x00\x01"},
	{ 0, 3, 0, "\x02\x02\x00"},
	{ 0, 3, 0, "\x02\x7f\x7f"},
	{ 0, 4, 0, "\x02\x03\x00\x80"},
	{ 0, 4, 0, "\x02\x7f\x01\x00"},
	{ 0, 5, 0, "\x02\xff\x7f\x02\x00"}
    };
    size_t sz;
    TESTint64 values[] = {0, -8589934591LL, -8589934592LL,
			   -36028797018963967LL, -36028797018963968LL,
			   -9223372036854775807LL, -36028797018963967LL,
			   0, 127, 128, 256, 512 };
    TESTint64 u;
    int i, ret, failed = 0;
    void *buf;

    for (i = 0; i < sizeof(td)/sizeof(td[0]); i++) {
	struct map_page *page;

	buf = map_alloc(OVERRUN, td[i].data, td[i].len, &page);

	ret = decode_TESTint64(buf, td[i].len, &u, &sz);
	if (ret) {
	    if (td[i].ok) {
		printf("failed with tag len test %d\n", i);
		printf("ret = %d\n", ret);
		failed = 1;
	    }
	} else {
	    if (td[i].ok == 0) {
		printf("failed with success for tag len test %d\n", i);
		failed = 1;
	    }
	    if (td[i].expected_len != sz) {
		printf("wrong expected size for tag test %d\n", i);
		printf("sz = %lu\n", (unsigned long)sz);
		failed = 1;
	    }
	    if (values[i] != u) {
		printf("wrong value for tag test %d\n", i);
		printf("Expected value: %lld\nActual value: %lld\n",
		       (long long)values[i], (long long)u);
		failed = 1;
	    }
	}
	map_free(page, "test", "decode");
    }
    return failed;
}

static int
cmp_TESTChoice (void *a, void *b)
{
    return 0;
}

static int
test_choice (void)
{
    struct test_case tests[] = {
	{ NULL,  5,  "\xa1\x03\x02\x01\x01", "large choice 1" },
	{ NULL,  5,  "\xa2\x03\x02\x01\x02", "large choice 2" }
    };

    int ret = 0, ntests = sizeof(tests) / sizeof(*tests);
    TESTChoice1 c1;
    TESTChoice1 c2_1;
    TESTChoice2 c2_2;

    memset(&c1, 0, sizeof(c1));
    c1.element = choice_TESTChoice1_i1;
    c1.u.i1 = 1;
    tests[0].val = &c1;

    memset(&c2_1, 0, sizeof(c2_1));
    c2_1.element = choice_TESTChoice1_i2;
    c2_1.u.i2 = 2;
    tests[1].val = &c2_1;

    ret += generic_test (tests, ntests, sizeof(TESTChoice1),
			 (generic_encode)encode_TESTChoice1,
			 (generic_length)length_TESTChoice1,
			 (generic_decode)decode_TESTChoice1,
			 (generic_free)free_TESTChoice1,
			 cmp_TESTChoice,
			 (generic_copy)copy_TESTChoice1);

    memset(&c2_2, 0, sizeof(c2_2));
    c2_2.element = choice_TESTChoice2_asn1_ellipsis;
    c2_2.u.asn1_ellipsis.data = "\xa2\x03\x02\x01\x02";
    c2_2.u.asn1_ellipsis.length = 5;
    tests[1].val = &c2_2;

    ret += generic_test (tests, ntests, sizeof(TESTChoice2),
			 (generic_encode)encode_TESTChoice2,
			 (generic_length)length_TESTChoice2,
			 (generic_decode)decode_TESTChoice2,
			 (generic_free)free_TESTChoice2,
			 cmp_TESTChoice,
			 (generic_copy)copy_TESTChoice2);

    return ret;
}

/* Test --decorate=TYPE:FIELD-TYPE:field-name[?] */
static int
test_decorated(void)
{
    TESTNotDecorated tnd;
    TESTDecorated td, td_copy;
    size_t len, size;
    void *ptr;
    int ret;

    memset(&td, 0, sizeof(td));
    memset(&tnd, 0, sizeof(tnd));

    my_copy_vers_called = 0;
    my_free_vers_called = 0;

    td.version = 3;
    td.version3.v = 5;
    td.privthing = &td;
    if ((td.version2 = malloc(sizeof(*td.version2))) == NULL)
        errx(1, "out of memory");
    *td.version2 = 5;
    ASN1_MALLOC_ENCODE(TESTDecorated, ptr, len, &td, &size, ret);
    if (ret) {
        warnx("could not encode a TESTDecorated struct");
        return 1;
    }
    ret = decode_TESTNotDecorated(ptr, len, &tnd, &size);
    if (ret) {
        warnx("could not decode a TESTDecorated struct as TESTNotDecorated");
        return 1;
    }
    free(ptr);
    if (size != len) {
        warnx("TESTDecorated encoded size mismatch");
        return 1;
    }
    if (td.version != tnd.version) {
        warnx("TESTDecorated did not decode as a TESTNotDecorated correctly");
        return 1;
    }
    if (copy_TESTDecorated(&td, &td_copy)) {
        warnx("copy_TESTDecorated() failed");
        return 1;
    }
    if (td.version != td_copy.version) {
        warnx("copy_TESTDecorated() did not work correctly (1)");
        return 1;
    }
    if (td_copy.version2 == NULL || *td.version2 != *td_copy.version2) {
        warnx("copy_TESTDecorated() did not work correctly (2)");
        return 1;
    }
    if (td.version3.v != td_copy.version3.v ||
        my_copy_vers_called != 1) {
        warnx("copy_TESTDecorated() did not work correctly (3)");
        return 1;
    }
    if (td_copy.privthing != 0) {
        warnx("copy_TESTDecorated() did not work correctly (4)");
        return 1;
    }

    free_TESTDecorated(&td_copy);
    free_TESTDecorated(&td);
    if (td.version2) {
        warnx("free_TESTDecorated() did not work correctly (1)");
        return 1;
    }
    if (td.version3.v != 0 || my_free_vers_called != 2) {
        warnx("free_TESTDecorated() did not work correctly (2)");
        return 1;
    }
    if (td.privthing != 0) {
        warnx("free_TESTDecorated() did not work correctly (3)");
        return 1;
    }
    return 0;
}

static int
test_extensible_choice(void)
{
    PA_FX_FAST_REQUEST r, r2;
    size_t len, size;
    void *ptr;
    int ret;

    memset(&r, 0, sizeof(r));

    ret = copy_PA_FX_FAST_REQUEST(&r, &r2);
    if (ret)
        return ret;
    free_PA_FX_FAST_REQUEST(&r2);

    r.element = 0;
    r.u.asn1_ellipsis.data = "hello";
    r.u.asn1_ellipsis.length = sizeof("hello") - 1;
    ret = copy_PA_FX_FAST_REQUEST(&r, &r2);
    if (ret)
        errx(1, "Out of memory");
    if (r2.element != 0)
        errx(1, "Extensible CHOICE copy failure to set discriminant to 0");
    if (r2.u.asn1_ellipsis.length != r.u.asn1_ellipsis.length)
        errx(1, "Extensible CHOICE copy failure to copy extension");
    if (memcmp(r.u.asn1_ellipsis.data, r2.u.asn1_ellipsis.data,
               r.u.asn1_ellipsis.length) != 0)
        errx(1, "Extensible CHOICE copy failure to copy extension (2)");
    free_PA_FX_FAST_REQUEST(&r2);

    ASN1_MALLOC_ENCODE(PA_FX_FAST_REQUEST, ptr, len, &r, &size, ret);
    if (ret || len != size)
        errx(1, "Extensible CHOICE encoding failure");

    ret = decode_PA_FX_FAST_REQUEST(ptr, len, &r2, &size);
    if (ret || len != size)
        errx(1, "Extensible CHOICE decoding failure");

    if (r2.element != 0)
        errx(1, "Extensible CHOICE decode failure to set discriminant to 0");
    if (r2.u.asn1_ellipsis.length != r.u.asn1_ellipsis.length)
        errx(1, "Extensible CHOICE decode failure to copy extension");
    if (memcmp(r.u.asn1_ellipsis.data, r2.u.asn1_ellipsis.data,
               r.u.asn1_ellipsis.length) != 0)
        errx(1, "Extensible CHOICE decode failure to copy extension (2)");

    free_PA_FX_FAST_REQUEST(&r2);
    free(ptr);
    return 0;
}

static int
test_decorated_choice(void)
{
    TESTNotDecoratedChoice tndc;
    TESTDecoratedChoice tdc, tdc_copy;
    size_t len, size;
    void *ptr;
    int ret;

    memset(&tdc, 0, sizeof(tdc));
    memset(&tndc, 0, sizeof(tndc));

    my_copy_vers_called = 0;
    my_free_vers_called = 0;

    tdc.element = choice_TESTDecoratedChoice_version;
    tdc.u.version = 3;
    tdc.version3.v = 5;
    tdc.privthing = &tdc;
    if ((tdc.version2 = malloc(sizeof(*tdc.version2))) == NULL)
        errx(1, "out of memory");
    *tdc.version2 = 5;
    ASN1_MALLOC_ENCODE(TESTDecoratedChoice, ptr, len, &tdc, &size, ret);
    if (ret) {
        warnx("could not encode a TESTDecoratedChoice struct");
        return 1;
    }
    ret = decode_TESTNotDecoratedChoice(ptr, len, &tndc, &size);
    if (ret) {
        warnx("could not decode a TESTDecoratedChoice struct as TESTNotDecoratedChoice");
        return 1;
    }
    free(ptr);
    if (size != len) {
        warnx("TESTDecoratedChoice encoded size mismatch");
        return 1;
    }
    if ((int)tdc.element != (int)tndc.element ||
        tdc.u.version != tndc.u.version) {
        warnx("TESTDecoratedChoice did not decode as a TESTNotDecoratedChoice correctly");
        return 1;
    }
    if (copy_TESTDecoratedChoice(&tdc, &tdc_copy)) {
        warnx("copy_TESTDecoratedChoice() failed");
        return 1;
    }
    if ((int)tdc.element != (int)tdc_copy.element ||
        tdc.u.version != tdc_copy.u.version) {
        warnx("copy_TESTDecoratedChoice() did not work correctly (1)");
        return 1;
    }
    if (tdc_copy.version2 == NULL || *tdc.version2 != *tdc_copy.version2) {
        warnx("copy_TESTDecoratedChoice() did not work correctly (2)");
        return 1;
    }
    if (tdc.version3.v != tdc_copy.version3.v ||
        my_copy_vers_called != 1) {
        warnx("copy_TESTDecoratedChoice() did not work correctly (3)");
        return 1;
    }
    if (tdc_copy.privthing != 0) {
        warnx("copy_TESTDecoratedChoice() did not work correctly (4)");
        return 1;
    }

    free_TESTDecoratedChoice(&tdc_copy);
    free_TESTDecoratedChoice(&tdc);
    if (tdc.version2) {
        warnx("free_TESTDecoratedChoice() did not work correctly (1)");
        return 1;
    }
    if (tdc.version3.v != 0 || my_free_vers_called != 2) {
        warnx("free_TESTDecoratedChoice() did not work correctly (2)");
        return 1;
    }
    if (tdc.privthing != 0) {
        warnx("free_TESTDecoratedChoice() did not work correctly (3)");
        return 1;
    }
    return 0;
}


static int
cmp_TESTImplicit (void *a, void *b)
{
    TESTImplicit *aa = a;
    TESTImplicit *ab = b;

    COMPARE_INTEGER(aa,ab,ti1);
    COMPARE_INTEGER(aa,ab,ti2.foo);
    COMPARE_INTEGER(aa,ab,ti3);
    return 0;
}

static int
cmp_TESTImplicit2 (void *a, void *b)
{
    TESTImplicit2 *aa = a;
    TESTImplicit2 *ab = b;

    COMPARE_INTEGER(aa,ab,ti1);
    COMPARE_INTEGER(aa,ab,ti3);
    IF_OPT_COMPARE(aa,ab,ti4) {
	COMPARE_INTEGER(aa,ab,ti4[0]);
    }
    return 0;
}

static int
cmp_TESTImplicit3 (void *a, void *b)
{
    TESTImplicit3 *aa = a;
    TESTImplicit3 *ab = b;

    COMPARE_INTEGER(aa,ab,element);
    if (aa->element == choice_TESTImplicit3_ti1) {
        COMPARE_INTEGER(aa,ab,u.ti1);
    } else {
        COMPARE_INTEGER(aa,ab,u.ti2.element);
        COMPARE_INTEGER(aa,ab,u.ti2.u.i1);
    }
    return 0;
}

static int
cmp_TESTImplicit4 (void *a, void *b)
{
    TESTImplicit4 *aa = a;
    TESTImplicit4 *ab = b;

    COMPARE_INTEGER(aa,ab,element);
    if (aa->element == choice_TESTImplicit4_ti1) {
        COMPARE_INTEGER(aa,ab,u.ti1);
    } else {
        COMPARE_INTEGER(aa,ab,u.ti2.element);
        COMPARE_INTEGER(aa,ab,u.ti2.u.i1);
    }
    return 0;
}

static int
test_implicit (void)
{
    int ret = 0;
    /*
     * UNIV CONS Sequence = 14 bytes {
     *   CONTEXT PRIM tag 0 = 1 bytes [0] IMPLICIT content
     *   CONTEXT CONS tag 1 = 6 bytes [1]
     *     CONTEXT CONS tag 127 = 3 bytes [127]
     *       UNIV PRIM Integer = integer 2
     *   CONTEXT PRIM tag 2 = 1 bytes [2] IMPLICIT content
     * }
     */
    struct test_case tests[] = {
	{ NULL,  16,
          "\x30\x0e\x80\x01\x00\xa1\x06\xbf\x7f\x03\x02\x01\x02\x82\x01\x03",
	  "implicit 1" }
    };
    /*
     * UNIV CONS Sequence = 10 bytes {
     *   CONTEXT PRIM tag 0 = 1 bytes [0] IMPLICIT content
     *   CONTEXT PRIM tag 2 = 1 bytes [2] IMPLICIT content
     *   CONTEXT PRIM tag 51 = 1 bytes [51] IMPLICIT content
     * }
     */
    struct test_case tests2[] = {
	{ NULL,  12,
          "\x30\x0a\x80\x01\x01\x82\x01\x03\x9f\x33\x01\x04",
	  "implicit 2" }
    };
    /*
     * CONTEXT CONS tag 5 = 5 bytes [5]
     *   CONTEXT CONS tag 1 = 3 bytes [1]
     *     UNIV PRIM Integer = integer 5
     */
    struct test_case tests3[] = {
	{ NULL,  7,
          "\xa5\x05\xa1\x03\x02\x01\x05",
	  "implicit 3" }
    };
    /*
     * Notice: same as tests3[].bytes.
     *
     * CONTEXT CONS tag 5 = 5 bytes [5]
     *   CONTEXT CONS tag 1 = 3 bytes [1]
     *     UNIV PRIM Integer = integer 5
     */
    struct test_case tests4[] = {
	{ NULL,  7,
          "\xa5\x05\xa1\x03\x02\x01\x05",
	  "implicit 4" }
    };

    TESTImplicit c0;
    TESTImplicit2 c1;
    TESTImplicit3 c2;
    TESTImplicit4 c3;
    int ti4 = 4;

    memset(&c0, 0, sizeof(c0));
    c0.ti1 = 0;
    c0.ti2.foo = 2;
    c0.ti3 = 3;
    tests[0].val = &c0;

    memset(&c1, 0, sizeof(c1));
    c1.ti1 = 1;
    c1.ti3 = 3;
    c1.ti4 = &ti4;
    tests2[0].val = &c1;

    memset(&c2, 0, sizeof(c2));
    c2.element = choice_TESTImplicit3_ti2;
    c2.u.ti2.element = choice_TESTImplicit3_ti2_i1;
    c2.u.ti2.u.i1 = 5;
    tests3[0].val = &c2;

    memset(&c3, 0, sizeof(c3));
    c3.element = choice_TESTImplicit4_ti2;
    c3.u.ti2.element = choice_TESTChoice2_i1;
    c3.u.ti2.u.i1 = 5;
    tests4[0].val = &c3;

    ret += generic_test(tests,
                        sizeof(tests) / sizeof(*tests),
                        sizeof(TESTImplicit),
                        (generic_encode)encode_TESTImplicit,
                        (generic_length)length_TESTImplicit,
                        (generic_decode)decode_TESTImplicit,
                        (generic_free)free_TESTImplicit,
                        cmp_TESTImplicit,
                        (generic_copy)copy_TESTImplicit);

    ret += generic_test(tests2,
                        sizeof(tests2) / sizeof(*tests2),
                        sizeof(TESTImplicit2),
                        (generic_encode)encode_TESTImplicit2,
                        (generic_length)length_TESTImplicit2,
                        (generic_decode)decode_TESTImplicit2,
                        (generic_free)free_TESTImplicit2,
                        cmp_TESTImplicit2,
                        NULL);

    ret += generic_test(tests3,
                        sizeof(tests3) / sizeof(*tests3),
                        sizeof(TESTImplicit3),
                        (generic_encode)encode_TESTImplicit3,
                        (generic_length)length_TESTImplicit3,
                        (generic_decode)decode_TESTImplicit3,
                        (generic_free)free_TESTImplicit3,
                        cmp_TESTImplicit3,
                        NULL);

    ret += generic_test(tests4,
                        sizeof(tests4) / sizeof(*tests4),
                        sizeof(TESTImplicit4),
                        (generic_encode)encode_TESTImplicit4,
                        (generic_length)length_TESTImplicit4,
                        (generic_decode)decode_TESTImplicit4,
                        (generic_free)free_TESTImplicit4,
                        cmp_TESTImplicit4,
                        NULL);

    return ret;
}

static int
cmp_TESTAlloc (void *a, void *b)
{
    TESTAlloc *aa = a;
    TESTAlloc *ab = b;

    IF_OPT_COMPARE(aa,ab,tagless) {
	COMPARE_INTEGER(aa,ab,tagless->ai);
    }

    COMPARE_INTEGER(aa,ab,three);

    IF_OPT_COMPARE(aa,ab,tagless2) {
	COMPARE_OPT_OCTET_STRING(aa, ab, tagless2);
    }

    return 0;
}

/*
UNIV CONS Sequence 12
  UNIV CONS Sequence 5
    CONTEXT CONS 0 3
      UNIV PRIM Integer 1 01
  CONTEXT CONS 1 3
    UNIV PRIM Integer 1 03

UNIV CONS Sequence 5
  CONTEXT CONS 1 3
    UNIV PRIM Integer 1 03

UNIV CONS Sequence 8
  CONTEXT CONS 1 3
    UNIV PRIM Integer 1 04
  UNIV PRIM Integer 1 05

*/

static int
test_taglessalloc (void)
{
    struct test_case tests[] = {
	{ NULL,  14,
	  "\x30\x0c\x30\x05\xa0\x03\x02\x01\x01\xa1\x03\x02\x01\x03",
	  "alloc 1" },
	{ NULL,  7,
	  "\x30\x05\xa1\x03\x02\x01\x03",
	  "alloc 2" },
	{ NULL,  10,
	  "\x30\x08\xa1\x03\x02\x01\x04\x02\x01\x05",
	  "alloc 3" }
    };

    int ret = 0, ntests = sizeof(tests) / sizeof(*tests);
    TESTAlloc c1, c2, c3;
    heim_any any3;

    memset(&c1, 0, sizeof(c1));
    c1.tagless = ecalloc(1, sizeof(*c1.tagless));
    c1.tagless->ai = 1;
    c1.three = 3;
    tests[0].val = &c1;

    memset(&c2, 0, sizeof(c2));
    c2.tagless = NULL;
    c2.three = 3;
    tests[1].val = &c2;

    memset(&c3, 0, sizeof(c3));
    c3.tagless = NULL;
    c3.three = 4;
    c3.tagless2 = &any3;
    any3.data = "\x02\x01\x05";
    any3.length = 3;
    tests[2].val = &c3;

    ret += generic_test (tests, ntests, sizeof(TESTAlloc),
			 (generic_encode)encode_TESTAlloc,
			 (generic_length)length_TESTAlloc,
			 (generic_decode)decode_TESTAlloc,
			 (generic_free)free_TESTAlloc,
			 cmp_TESTAlloc,
			 (generic_copy)copy_TESTAlloc);

    free(c1.tagless);

    return ret;
}

static int
cmp_TESTOptional (void *a, void *b)
{
    TESTOptional *aa = a;
    TESTOptional *ab = b;

    IF_OPT_COMPARE(aa,ab,zero) {
	COMPARE_OPT_INTEGER(aa,ab,zero);
    }
    IF_OPT_COMPARE(aa,ab,one) {
	COMPARE_OPT_INTEGER(aa,ab,one);
    }
    return 0;
}

/*
UNIV CONS Sequence 5
  CONTEXT CONS 0 3
    UNIV PRIM Integer 1 00

UNIV CONS Sequence 5
  CONTEXT CONS 1 3
    UNIV PRIM Integer 1 03

UNIV CONS Sequence 10
  CONTEXT CONS 0 3
    UNIV PRIM Integer 1 00
  CONTEXT CONS 1 3
    UNIV PRIM Integer 1 01

*/

static int
test_optional (void)
{
    struct test_case tests[] = {
	{ NULL,  2,
	  "\x30\x00",
	  "optional 0" },
	{ NULL,  7,
	  "\x30\x05\xa0\x03\x02\x01\x00",
	  "optional 1" },
	{ NULL,  7,
	  "\x30\x05\xa1\x03\x02\x01\x01",
	  "optional 2" },
	{ NULL,  12,
	  "\x30\x0a\xa0\x03\x02\x01\x00\xa1\x03\x02\x01\x01",
	  "optional 3" }
    };

    int ret = 0, ntests = sizeof(tests) / sizeof(*tests);
    TESTOptional c0, c1, c2, c3;
    int zero = 0;
    int one = 1;

    c0.zero = NULL;
    c0.one = NULL;
    tests[0].val = &c0;

    c1.zero = &zero;
    c1.one = NULL;
    tests[1].val = &c1;

    c2.zero = NULL;
    c2.one = &one;
    tests[2].val = &c2;

    c3.zero = &zero;
    c3.one = &one;
    tests[3].val = &c3;

    ret += generic_test (tests, ntests, sizeof(TESTOptional),
			 (generic_encode)encode_TESTOptional,
			 (generic_length)length_TESTOptional,
			 (generic_decode)decode_TESTOptional,
			 (generic_free)free_TESTOptional,
			 cmp_TESTOptional,
			 (generic_copy)copy_TESTOptional);

    return ret;
}

static int
check_fail_largetag(void)
{
    struct test_case tests[] = {
	{NULL, 14, "\x30\x0c\xbf\x87\xff\xff\xff\xff\xff\x7f\x03\x02\x01\x01",
	 "tag overflow"},
	{NULL, 0, "", "empty buffer"},
	{NULL, 7, "\x30\x05\xa1\x03\x02\x02\x01",
	 "one too short" },
	{NULL, 7, "\x30\x04\xa1\x03\x02\x02\x01",
	 "two too short" },
	{NULL, 7, "\x30\x03\xa1\x03\x02\x02\x01",
	 "three too short" },
	{NULL, 7, "\x30\x02\xa1\x03\x02\x02\x01",
	 "four too short" },
	{NULL, 7, "\x30\x01\xa1\x03\x02\x02\x01",
	 "five too short" },
	{NULL, 7, "\x30\x00\xa1\x03\x02\x02\x01",
	 "six too short" },
	{NULL, 7, "\x30\x05\xa1\x04\x02\x02\x01",
	 "inner one too long" },
	{NULL, 7, "\x30\x00\xa1\x02\x02\x02\x01",
	 "inner one too short" },
	{NULL, 8, "\x30\x05\xbf\x7f\x03\x02\x02\x01",
	 "inner one too short"},
	{NULL, 8, "\x30\x06\xbf\x64\x03\x02\x01\x01",
	 "wrong tag"},
	{NULL, 10, "\x30\x08\xbf\x9a\x9b\x38\x03\x02\x01\x01",
	 "still wrong tag"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(TESTLargeTag),
			       (generic_decode)decode_TESTLargeTag);
}


static int
check_fail_sequence(void)
{
    struct test_case tests[] = {
	{NULL, 0, "", "empty buffer"},
	{NULL, 24,
	 "\x30\x16\xa0\x03\x02\x01\x01\xa1\x08\x30\x06\xbf\x7f\x03\x02\x01\x01"
	 "\x02\x01\x01\xa2\x03\x02\x01\x01",
	 "missing one byte from the end, internal length ok"},
	{NULL, 25,
	 "\x30\x18\xa0\x03\x02\x01\x01\xa1\x08\x30\x06\xbf\x7f\x03\x02\x01\x01"
	 "\x02\x01\x01\xa2\x03\x02\x01\x01",
	 "inner length one byte too long"},
	{NULL, 24,
	 "\x30\x17\xa0\x03\x02\x01\x01\xa1\x08\x30\x06\xbf\x7f\x03\x02\x01"
	 "\x01\x02\x01\x01\xa2\x03\x02\x01\x01",
	 "correct buffer but missing one too short"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(TESTSeq),
			       (generic_decode)decode_TESTSeq);
}

static int
check_fail_choice(void)
{
    struct test_case tests[] = {
	{NULL, 6,
	 "\xa1\x02\x02\x01\x01",
	 "choice one too short"},
	{NULL, 6,
	 "\xa1\x03\x02\x02\x01",
	 "choice one too short inner"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(TESTChoice1),
			       (generic_decode)decode_TESTChoice1);
}

static int
check_fail_Ticket(void)
{
    char buf[100];
    size_t i;
    int ret;
    struct test_case test;
    Ticket ticket;

    for (i = 0; i < sizeof(buf); i++) {
	memset(buf, 0, sizeof(buf));
	memset(&ticket, 0, sizeof(ticket));
	test.val = &ticket;
	test.byte_len = i;
	test.bytes = buf;
	test.name = "zero life";
	ret = generic_decode_fail(&test, 1, sizeof(Ticket),
				  (generic_decode)decode_Ticket);
	if (ret)
	    return ret;
    }
    return 0;
}

static int
check_seq(void)
{
    TESTSeqOf seq;
    TESTInteger i = 0;
    int ret;

    seq.val = NULL;
    seq.len = 0;

    ret = add_TESTSeqOf(&seq, &i);
    if (ret) { printf("failed adding\n"); goto out; }
    ret = add_TESTSeqOf(&seq, &i);
    if (ret) { printf("failed adding\n"); goto out; }
    ret = add_TESTSeqOf(&seq, &i);
    if (ret) { printf("failed adding\n"); goto out; }
    ret = add_TESTSeqOf(&seq, &i);
    if (ret) { printf("failed adding\n"); goto out; }

    ret = remove_TESTSeqOf(&seq, seq.len - 1);
    if (ret) { printf("failed removing\n"); goto out; }
    ret = remove_TESTSeqOf(&seq, 2);
    if (ret) { printf("failed removing\n"); goto out; }
    ret = remove_TESTSeqOf(&seq, 0);
    if (ret) { printf("failed removing\n"); goto out; }
    ret = remove_TESTSeqOf(&seq, 0);
    if (ret) { printf("failed removing\n"); goto out; }
    ret = remove_TESTSeqOf(&seq, 0);
    if (ret == 0) {
	printf("can remove from empty list");
	return 1;
    }

    if (seq.len != 0) {
	printf("seq not empty!");
	return 1;
    }
    free_TESTSeqOf(&seq);
    ret = 0;

out:

    return ret;
}

#define test_seq_of(type, ok, ptr)					\
{									\
    heim_octet_string os;						\
    size_t size;							\
    type decode;							\
    ASN1_MALLOC_ENCODE(type, os.data, os.length, ptr, &size, ret);	\
    if (ret)								\
	return ret;							\
    if (os.length != size)						\
	abort();							\
    ret = decode_##type(os.data, os.length, &decode, &size);		\
    free(os.data);							\
    if (ret) {								\
	if (ok)								\
	    return 1;							\
    } else {								\
	free_##type(&decode);						\
	if (!ok)							\
	    return 1;							\
	if (size != 0)							\
            return 1;							\
    }									\
    return 0;								\
}

static int
check_seq_of_size(void)
{
#if 0 /* template */
    TESTInteger integers[4] = { 1, 2, 3, 4 };
    int ret;

    {
	TESTSeqSizeOf1 ssof1f1 = { 1, integers };
	TESTSeqSizeOf1 ssof1ok1 = { 2, integers };
	TESTSeqSizeOf1 ssof1f2 = { 3, integers };

	test_seq_of(TESTSeqSizeOf1, 0, &ssof1f1);
	test_seq_of(TESTSeqSizeOf1, 1, &ssof1ok1);
	test_seq_of(TESTSeqSizeOf1, 0, &ssof1f2);
    }
    {
	TESTSeqSizeOf2 ssof2f1 = { 0, NULL };
	TESTSeqSizeOf2 ssof2ok1 = { 1, integers };
	TESTSeqSizeOf2 ssof2ok2 = { 2, integers };
	TESTSeqSizeOf2 ssof2f2 = { 3, integers };

	test_seq_of(TESTSeqSizeOf2, 0, &ssof2f1);
	test_seq_of(TESTSeqSizeOf2, 1, &ssof2ok1);
	test_seq_of(TESTSeqSizeOf2, 1, &ssof2ok2);
	test_seq_of(TESTSeqSizeOf2, 0, &ssof2f2);
    }
    {
	TESTSeqSizeOf3 ssof3f1 = { 0, NULL };
	TESTSeqSizeOf3 ssof3ok1 = { 1, integers };
	TESTSeqSizeOf3 ssof3ok2 = { 2, integers };

	test_seq_of(TESTSeqSizeOf3, 0, &ssof3f1);
	test_seq_of(TESTSeqSizeOf3, 1, &ssof3ok1);
	test_seq_of(TESTSeqSizeOf3, 1, &ssof3ok2);
    }
    {
	TESTSeqSizeOf4 ssof4ok1 = { 0, NULL };
	TESTSeqSizeOf4 ssof4ok2 = { 1, integers };
	TESTSeqSizeOf4 ssof4ok3 = { 2, integers };
	TESTSeqSizeOf4 ssof4f1  = { 3, integers };

	test_seq_of(TESTSeqSizeOf4, 1, &ssof4ok1);
	test_seq_of(TESTSeqSizeOf4, 1, &ssof4ok2);
	test_seq_of(TESTSeqSizeOf4, 1, &ssof4ok3);
	test_seq_of(TESTSeqSizeOf4, 0, &ssof4f1);
   }
#endif
    return 0;
}

static int
check_TESTMechTypeList(void)
{
    TESTMechTypeList tl;
    unsigned oid1[] =  { 1, 2, 840, 48018, 1, 2, 2};
    unsigned oid2[] =  { 1, 2, 840, 113554, 1, 2, 2};
    unsigned oid3[] =   { 1, 3, 6, 1, 4, 1, 311, 2, 2, 30};
    unsigned oid4[] =   { 1, 3, 6, 1, 4, 1, 311, 2, 2, 10};
    TESTMechType array[] = {{ 7, oid1 },
                            { 7, oid2 },
                            { 10, oid3 },
                            { 10, oid4 }};
    size_t size, len;
    void *ptr;
    int ret;

    tl.len = 4;
    tl.val = array;

    ASN1_MALLOC_ENCODE(TESTMechTypeList, ptr, len, &tl, &size, ret);
    if (ret)
	errx(1, "TESTMechTypeList: %d", ret);
    if (len != size)
	abort();
    free(ptr);
    return 0;
}

static int
cmp_TESTSeqOf4(void *a, void *b)
{
    TESTSeqOf4 *aa = a;
    TESTSeqOf4 *ab = b;
    int i;

    IF_OPT_COMPARE(aa, ab, b1) {
	COMPARE_INTEGER(aa->b1, ab->b1, len);
	for (i = 0; i < aa->b1->len; ++i) {
	    COMPARE_INTEGER(aa->b1->val+i, ab->b1->val+i, u1);
	    COMPARE_INTEGER(aa->b1->val+i, ab->b1->val+i, u2);
	    COMPARE_OCTET_STRING(aa->b1->val+i, ab->b1->val+i, s1);
	    COMPARE_OCTET_STRING(aa->b1->val+i, ab->b1->val+i, s2);
	}
    }
    IF_OPT_COMPARE(aa, ab, b2) {
	COMPARE_INTEGER(aa->b2, ab->b2, len);
	for (i = 0; i < aa->b2->len; ++i) {
	    COMPARE_INTEGER(aa->b2->val+i, ab->b2->val+i, u1);
	    COMPARE_INTEGER(aa->b2->val+i, ab->b2->val+i, u2);
	    COMPARE_INTEGER(aa->b2->val+i, ab->b2->val+i, u3);
	    COMPARE_OCTET_STRING(aa->b2->val+i, ab->b2->val+i, s1);
	    COMPARE_OCTET_STRING(aa->b2->val+i, ab->b2->val+i, s2);
	    COMPARE_OCTET_STRING(aa->b2->val+i, ab->b2->val+i, s3);
	}
    }
    IF_OPT_COMPARE(aa, ab, b3) {
	COMPARE_INTEGER(aa->b3, ab->b3, len);
	for (i = 0; i < aa->b3->len; ++i) {
	    COMPARE_INTEGER(aa->b3->val+i, ab->b3->val+i, u1);
	    COMPARE_INTEGER(aa->b3->val+i, ab->b3->val+i, u2);
	    COMPARE_INTEGER(aa->b3->val+i, ab->b3->val+i, u3);
	    COMPARE_INTEGER(aa->b3->val+i, ab->b3->val+i, u4);
	    COMPARE_OCTET_STRING(aa->b3->val+i, ab->b3->val+i, s1);
	    COMPARE_OCTET_STRING(aa->b3->val+i, ab->b3->val+i, s2);
	    COMPARE_OCTET_STRING(aa->b3->val+i, ab->b3->val+i, s3);
	    COMPARE_OCTET_STRING(aa->b3->val+i, ab->b3->val+i, s4);
	}
    }
    return 0;
}

static int
test_seq4 (void)
{
    int ret = 0;
    struct test_case tests[] = {
	{ NULL,  2,
	  "\x30\x00",
	  "seq4 0" },
	{ NULL,  4,
	  "\x30\x02" "\xa1\x00",
	  "seq4 1" },
	{ NULL,  8,
	  "\x30\x06" "\xa0\x02\x30\x00" "\xa1\x00",
	  "seq4 2" },
	{ NULL,  2 + (2 + 0x18) + (2 + 0x27) + (2 + 0x31),
	  "\x30\x76"					/* 2 SEQ */
	   "\xa0\x18\x30\x16"				/* 4 [0] SEQ */
	    "\x30\x14"					/* 2 SEQ */
	     "\x04\x00"					/* 2 OCTET-STRING */
             "\x04\x02\x01\x02"				/* 4 OCTET-STRING */
	     "\x02\x01\x01"				/* 3 INT */
	     "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff"
							/* 11 INT */
	   "\xa1\x27"					/* 2 [1] IMPL SEQ */
	    "\x30\x25"					/* 2 SEQ */
	     "\x02\x01\x01"				/* 3 INT */
	     "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff"
							/* 11 INT */
	     "\x02\x09\x00\x80\x00\x00\x00\x00\x00\x00\x00"
							/* 11 INT */
	     "\x04\x00"					/* 2 OCTET-STRING */
             "\x04\x02\x01\x02"				/* 4 OCTET-STRING */
             "\x04\x04\x00\x01\x02\x03"			/* 6 OCTET-STRING */
	   "\xa2\x31"					/* 2 [2] IMPL SEQ */
	    "\x30\x2f"					/* 2 SEQ */
	     "\x04\x00"					/* 2 OCTET-STRING */
	     "\x02\x01\x01"				/* 3 INT */
             "\x04\x02\x01\x02"				/* 4 OCTET-STRING */
	     "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff"
							/* 11 INT */
             "\x04\x04\x00\x01\x02\x03"			/* 6 OCTET-STRING */
	     "\x02\x09\x00\x80\x00\x00\x00\x00\x00\x00\x00"
							/* 11 INT */
	     "\x04\x01\x00"				/* 3 OCTET-STRING */
	     "\x02\x05\x01\x00\x00\x00\x00",		/* 7 INT */
	  "seq4 3" },
    };

    int ntests = sizeof(tests) / sizeof(*tests);
    TESTSeqOf4 c[4];
    struct TESTSeqOf4_b1 b1[4];
    struct TESTSeqOf4_b2 b2[4];
    struct TESTSeqOf4_b3 b3[4];
    struct TESTSeqOf4_b1_val b1val[4];
    struct TESTSeqOf4_b2_val b2val[4];
    struct TESTSeqOf4_b3_val b3val[4];

    c[0].b1 = NULL;
    c[0].b2 = NULL;
    c[0].b3 = NULL;
    tests[0].val = &c[0];

    b2[1].len = 0;
    b2[1].val = NULL;
    c[1].b1 = NULL;
    c[1].b2 = &b2[1];
    c[1].b3 = NULL;
    tests[1].val = &c[1];

    b1[2].len = 0;
    b1[2].val = NULL;
    b2[2].len = 0;
    b2[2].val = NULL;
    c[2].b1 = &b1[2];
    c[2].b2 = &b2[2];
    c[2].b3 = NULL;
    tests[2].val = &c[2];

    b1val[3].s1.data = "";
    b1val[3].s1.length = 0;
    b1val[3].u1 = 1LL;
    b1val[3].s2.data = "\x01\x02";
    b1val[3].s2.length = 2;
    b1val[3].u2 = -1LL;

    b2val[3].s1.data = "";
    b2val[3].s1.length = 0;
    b2val[3].u1 = 1LL;
    b2val[3].s2.data = "\x01\x02";
    b2val[3].s2.length = 2;
    b2val[3].u2 = -1LL;
    b2val[3].s3.data = "\x00\x01\x02\x03";
    b2val[3].s3.length = 4;
    b2val[3].u3 = 1LL<<63;

    b3val[3].s1.data = "";
    b3val[3].s1.length = 0;
    b3val[3].u1 = 1LL;
    b3val[3].s2.data = "\x01\x02";
    b3val[3].s2.length = 2;
    b3val[3].u2 = -1LL;
    b3val[3].s3.data = "\x00\x01\x02\x03";
    b3val[3].s3.length = 4;
    b3val[3].u3 = 1LL<<63;
    b3val[3].s4.data = "\x00";
    b3val[3].s4.length = 1;
    b3val[3].u4 = 1LL<<32;

    b1[3].len = 1;
    b1[3].val = &b1val[3];
    b2[3].len = 1;
    b2[3].val = &b2val[3];
    b3[3].len = 1;
    b3[3].val = &b3val[3];
    c[3].b1 = &b1[3];
    c[3].b2 = &b2[3];
    c[3].b3 = &b3[3];
    tests[3].val = &c[3];

    ret += generic_test (tests, ntests, sizeof(TESTSeqOf4),
			 (generic_encode)encode_TESTSeqOf4,
			 (generic_length)length_TESTSeqOf4,
			 (generic_decode)decode_TESTSeqOf4,
			 (generic_free)free_TESTSeqOf4,
			 cmp_TESTSeqOf4,
			 (generic_copy)copy_TESTSeqOf4);
    return ret;
}

static int
cmp_test_seqof5 (void *a, void *b)
{
    TESTSeqOf5 *aval = a;
    TESTSeqOf5 *bval = b;

    IF_OPT_COMPARE(aval, bval, outer) {
            COMPARE_INTEGER(&aval->outer->inner, &bval->outer->inner, u0);
            COMPARE_OCTET_STRING(&aval->outer->inner, &bval->outer->inner, s0);
            COMPARE_INTEGER(&aval->outer->inner, &bval->outer->inner, u1);
            COMPARE_OCTET_STRING(&aval->outer->inner, &bval->outer->inner, s1);
            COMPARE_INTEGER(&aval->outer->inner, &bval->outer->inner, u2);
            COMPARE_OCTET_STRING(&aval->outer->inner, &bval->outer->inner, s2);
            COMPARE_INTEGER(&aval->outer->inner, &bval->outer->inner, u3);
            COMPARE_OCTET_STRING(&aval->outer->inner, &bval->outer->inner, s3);
            COMPARE_INTEGER(&aval->outer->inner, &bval->outer->inner, u4);
            COMPARE_OCTET_STRING(&aval->outer->inner, &bval->outer->inner, s4);
            COMPARE_INTEGER(&aval->outer->inner, &bval->outer->inner, u5);
            COMPARE_OCTET_STRING(&aval->outer->inner, &bval->outer->inner, s5);
            COMPARE_INTEGER(&aval->outer->inner, &bval->outer->inner, u6);
            COMPARE_OCTET_STRING(&aval->outer->inner, &bval->outer->inner, s6);
            COMPARE_INTEGER(&aval->outer->inner, &bval->outer->inner, u7);
            COMPARE_OCTET_STRING(&aval->outer->inner, &bval->outer->inner, s7);
    }
    return 0;
}

static int
test_seqof5(void)
{
    struct test_case tests[] = {
	{ NULL,  2, "\x30\x00", "seq5 0" },
	{ NULL,  126,
          "\x30\x7c"                                            /* SEQ */
            "\x30\x7a"                                          /* SEQ */
              "\x30\x78"                                        /* SEQ */
                "\x02\x01\x01"                                  /* INT 1 */
                "\x04\x06\x01\x01\x01\x01\x01\x01"              /* "\0x1"x6 */
                "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xfe"  /* INT ~1 */
                "\x04\x06\x02\x02\x02\x02\x02\x02"              /* "\x02"x6 */
                "\x02\x01\x02"                                  /* INT 2 */
                "\x04\x06\x03\x03\x03\x03\x03\x03"              /* "\x03"x6 */
                "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xfd"  /* INT ~2 */
                "\x04\x06\x04\x04\x04\x04\x04\x04"              /* ... */
                "\x02\x01\x03"
                "\x04\x06\x05\x05\x05\x05\x05\x05"
                "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xfc"
                "\x04\x06\x06\x06\x06\x06\x06\x06"
                "\x02\x01\x04"
                "\x04\x06\x07\x07\x07\x07\x07\x07"
                "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xfb"
                "\x04\x06\x08\x08\x08\x08\x08\x08",
          "seq5 1" },
    };

    int ret = 0, ntests = sizeof(tests) / sizeof(*tests);
    TESTSeqOf5 c[2];
    struct TESTSeqOf5_outer outer;
    struct TESTSeqOf5_outer_inner inner;
    TESTuint64 u[8];
    heim_octet_string s[8];
    int i;

    c[0].outer = NULL;
    tests[0].val = &c[0];

    for (i = 0; i < 8; ++i) {
        u[i] = (i&1) == 0 ? i/2+1 : ~(i/2+1);
        s[i].data = memset(malloc(s[i].length = 6), i+1, 6);
    }

    inner.u0 = u[0]; inner.u1 = u[1]; inner.u2 = u[2]; inner.u3 = u[3];
    inner.u4 = u[4]; inner.u5 = u[5]; inner.u6 = u[6]; inner.u7 = u[7];
    inner.s0 = s[0]; inner.s1 = s[1]; inner.s2 = s[2]; inner.s3 = s[3];
    inner.s4 = s[4]; inner.s5 = s[5]; inner.s6 = s[6]; inner.s7 = s[7];

    outer.inner = inner;
    c[1].outer = &outer;
    tests[1].val = &c[1];

    ret += generic_test (tests, ntests, sizeof(TESTSeqOf5),
			 (generic_encode)encode_TESTSeqOf5,
			 (generic_length)length_TESTSeqOf5,
			 (generic_decode)decode_TESTSeqOf5,
			 (generic_free)free_TESTSeqOf5,
			 cmp_test_seqof5,
			 NULL);

    for (i = 0; i < 8; ++i)
        free(s[i].data);

    return ret;
}

static int
cmp_default(void *a, void *b)
{
    TESTDefault *aa = a;
    TESTDefault *ab = b;

    COMPARE_STRING(aa,ab,name);
    COMPARE_INTEGER(aa,ab,version);
    COMPARE_INTEGER(aa,ab,maxint);
    COMPARE_INTEGER(aa,ab,works);
    return 0;
}

static int
test_default(void)
{
    struct test_case tests[] = {
	{ NULL, 2, "\x30\x00", NULL },
	{ NULL, 25,
          "\x30\x17\x0c\x07\x68\x65\x69\x6d\x64\x61"
          "\x6c\xa0\x03\x02\x01\x07\x02\x04\x7f\xff"
          "\xff\xff\x01\x01\x00",
	  NULL
	},
	{ NULL, 10,
          "\x30\x08\xa0\x03\x02\x01\x07\x01\x01\x00",
	  NULL
	},
	{ NULL, 17,
          "\x30\x0f\x0c\x07\x68\x65\x69\x6d\x64\x61\x6c\x02\x04"
          "\x7f\xff\xff\xff",
	  NULL
	}
    };

    TESTDefault values[] = {
	{ "Heimdal", 8, 9223372036854775807, 1 },
	{ "heimdal", 7, 2147483647, 0 },
	{ "Heimdal", 7, 9223372036854775807, 0 },
	{ "heimdal", 8, 2147483647, 1 },
    };
    int i, ret;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	if (asprintf (&tests[i].name, "TESTDefault %d", i) < 0)
	    errx(1, "malloc");
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    ret = generic_test (tests, ntests, sizeof(TESTDefault),
			(generic_encode)encode_TESTDefault,
			(generic_length)length_TESTDefault,
			(generic_decode)decode_TESTDefault,
			(generic_free)free_TESTDefault,
			cmp_default,
			(generic_copy)copy_TESTDefault);
    for (i = 0; i < ntests; ++i)
	free(tests[i].name);

    return ret;
}

static int
test_x690sample(void)
{
    /*
     * Taken from X.690, Appendix A, though sadly it's not specified whether
     * it's in BER, DER, or CER, but it is clearly BER and neither DER nor CER
     * because the tags of the members of the X690SamplePersonnelRecord type
     * are not canonically sorted in the given sample.
     *
     * Our compiler does NOT canonically sort the members of SET { ... } types
     * so it produces the same encoding after decoding this test vector.  That
     * is clearly a bug given that we aim to output DER.
     *
     * The template compiler doesn't even decode SET { ... } values properly
     * when their members are not in the same order as defined (but the regular
     * compiler does).
     */
    X690SamplePersonnelRecord r;
    heim_octet_string os;
    unsigned char encoded_sample[] = {
      0x60, 0x81, 0x85, 0x61, 0x10, 0x1a, 0x04, 0x4a, 0x6f, 0x68, 0x6e, 0x1a,
      0x01, 0x50, 0x1a, 0x05, 0x53, 0x6d, 0x69, 0x74, 0x68, 0xa0, 0x0a, 0x1a,
      0x08, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x42, 0x01, 0x33,
      0xa1, 0x0a, 0x43, 0x08, 0x31, 0x39, 0x37, 0x31, 0x30, 0x39, 0x31, 0x37,
      0xa2, 0x12, 0x61, 0x10, 0x1a, 0x04, 0x4d, 0x61, 0x72, 0x79, 0x1a, 0x01,
      0x54, 0x1a, 0x05, 0x53, 0x6d, 0x69, 0x74, 0x68, 0xa3, 0x42, 0x31, 0x1f,
      0x61, 0x11, 0x1a, 0x05, 0x52, 0x61, 0x6c, 0x70, 0x68, 0x1a, 0x01, 0x54,
      0x1a, 0x05, 0x53, 0x6d, 0x69, 0x74, 0x68, 0xa0, 0x0a, 0x43, 0x08, 0x31,
      0x39, 0x35, 0x37, 0x31, 0x31, 0x31, 0x31, 0x31, 0x1f, 0x61, 0x11, 0x1a,
      0x05, 0x53, 0x75, 0x73, 0x61, 0x6e, 0x1a, 0x01, 0x42, 0x1a, 0x05, 0x53,
      0x6d, 0x69, 0x74, 0x68, 0xa0, 0x0a, 0x43, 0x08, 0x31, 0x39, 0x35, 0x39,
      0x30, 0x37, 0x31, 0x37
    };
    size_t sz = 0;
    int ret;

    memset(&r, 0, sizeof(r));
    if (decode_X690SamplePersonnelRecord(encoded_sample, sizeof(encoded_sample), &r, &sz))
        return 1;
    if (sz != sizeof(encoded_sample))
        return 1;
    free_X690SamplePersonnelRecord(&r);
    memset(&r, 0, sizeof(r));

    /* We re-construct the record manually to double-check the spec */
    r.name.givenName = strdup("John");
    r.name.initial = strdup("P");
    r.name.familyName = strdup("Smith");
    r.title = strdup("Director");
    r.dateOfHire = strdup("19710917");
    r.number = 51;
    r.nameOfSpouse.givenName = strdup("Mary");
    r.nameOfSpouse.initial = strdup("T");
    r.nameOfSpouse.familyName = strdup("Smith");
    r.children.val = calloc(2, sizeof(r.children.val[0]));
    r.children.len = 2;
    r.children.val[0].name.givenName = strdup("Ralph");
    r.children.val[0].name.initial = strdup("T");
    r.children.val[0].name.familyName = strdup("Smith");
    r.children.val[0].dateOfBirth = strdup("19571111");
    r.children.val[1].name.givenName = strdup("Susan");
    r.children.val[1].name.initial = strdup("B");
    r.children.val[1].name.familyName = strdup("Smith");
    r.children.val[1].dateOfBirth = strdup("19590717");
    os.length = 0;
    os.data = 0;
    ASN1_MALLOC_ENCODE(X690SamplePersonnelRecord, os.data, os.length, &r, &sz,
                       ret);
    if (ret || sz != sizeof(encoded_sample) || sz != os.length ||
        memcmp(encoded_sample, os.data, sz) != 0)
        return 1;
    free_X690SamplePersonnelRecord(&r);
    free(os.data);
    return 0;
}

#if ASN1_IOS_SUPPORTED
static int
test_ios(void)
{
    unsigned char encoded_sample[] = {
      0x30, 0x82, 0x04, 0x8e, 0x30, 0x82, 0x03, 0x76,
      0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x6a,
      0x05, 0x97, 0xba, 0x71, 0xd7, 0xe6, 0xd3, 0xac,
      0x0e, 0xdc, 0x9e, 0xdc, 0x95, 0xa1, 0x5b, 0x99,
      0x8d, 0xe4, 0x0a, 0x30, 0x0d, 0x06, 0x09, 0x2a,
      0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
      0x05, 0x00, 0x30, 0x55, 0x31, 0x0b, 0x30, 0x09,
      0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
      0x48, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55,
      0x04, 0x0a, 0x13, 0x15, 0x53, 0x54, 0x4d, 0x69,
      0x63, 0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74,
      0x72, 0x6f, 0x6e, 0x69, 0x63, 0x73, 0x20, 0x4e,
      0x56, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55,
      0x04, 0x03, 0x13, 0x1d, 0x53, 0x54, 0x4d, 0x20,
      0x54, 0x50, 0x4d, 0x20, 0x45, 0x4b, 0x20, 0x49,
      0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69,
      0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x20, 0x30,
      0x35, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31,
      0x32, 0x31, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x5a, 0x17, 0x0d, 0x32, 0x38, 0x31, 0x32,
      0x31, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x5a, 0x30, 0x00, 0x30, 0x82, 0x01, 0x22, 0x30,
      0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82,
      0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
      0x82, 0x01, 0x01, 0x00, 0xcc, 0x14, 0xeb, 0x27,
      0xa7, 0x8c, 0xeb, 0x0e, 0xa4, 0x86, 0xfa, 0x2d,
      0xf7, 0x83, 0x5f, 0x5f, 0xa8, 0xe9, 0x05, 0xb0,
      0x97, 0x01, 0x2b, 0x5b, 0xde, 0x50, 0x38, 0x0c,
      0x35, 0x5b, 0x1a, 0x2a, 0x72, 0x1b, 0xbc, 0x3d,
      0x08, 0xdd, 0x21, 0x79, 0x6c, 0xdb, 0x23, 0x9f,
      0xa9, 0x53, 0x10, 0x65, 0x1b, 0x1b, 0x56, 0xfd,
      0x2c, 0xfe, 0x53, 0xc8, 0x73, 0x52, 0xeb, 0xd9,
      0x96, 0xe3, 0x32, 0x56, 0x16, 0x04, 0x04, 0xce,
      0x93, 0x02, 0xa0, 0x80, 0x66, 0x80, 0x1e, 0x78,
      0x6a, 0x2f, 0x86, 0xe1, 0x81, 0xf9, 0x49, 0x96,
      0x6f, 0x49, 0x2a, 0x85, 0xb5, 0x8e, 0xaa, 0x4a,
      0x6a, 0x8c, 0xb3, 0x69, 0x75, 0x51, 0xbb, 0x23,
      0x6e, 0x87, 0xcc, 0x7b, 0xf8, 0xec, 0x13, 0x47,
      0x87, 0x1c, 0x91, 0xe1, 0x54, 0x37, 0xe8, 0xf2,
      0x66, 0xbf, 0x1e, 0xa5, 0xeb, 0x27, 0x1f, 0xdc,
      0xf3, 0x74, 0xd8, 0xb4, 0x7d, 0xf8, 0xbc, 0xe8,
      0x9e, 0x1f, 0xad, 0x61, 0xc2, 0xa0, 0x88, 0xcb,
      0x40, 0x36, 0xb3, 0x59, 0xcb, 0x72, 0xa2, 0x94,
      0x97, 0x3f, 0xed, 0xcc, 0xf0, 0xc3, 0x40, 0xaf,
      0xfd, 0x14, 0xb6, 0x4f, 0x04, 0x11, 0x65, 0x58,
      0x1a, 0xca, 0x34, 0x14, 0x7c, 0x1c, 0x75, 0x61,
      0x70, 0x47, 0x05, 0x8f, 0x7e, 0xd7, 0xd6, 0x03,
      0xe0, 0x32, 0x50, 0x80, 0x94, 0xfa, 0x73, 0xe8,
      0xb9, 0x15, 0x3d, 0xa3, 0xbf, 0x25, 0x5d, 0x2c,
      0xbb, 0xc5, 0xdf, 0x30, 0x1b, 0xa8, 0xf7, 0x4d,
      0x19, 0x8b, 0xeb, 0xce, 0x86, 0x04, 0x0f, 0xc1,
      0xd2, 0x92, 0x7c, 0x76, 0x57, 0x41, 0x44, 0x90,
      0xd8, 0x02, 0xf4, 0x82, 0xf3, 0xeb, 0xf2, 0xde,
      0x35, 0xee, 0x14, 0x9a, 0x1a, 0x6d, 0xe8, 0xd1,
      0x68, 0x91, 0xfb, 0xfb, 0xa0, 0x2a, 0x18, 0xaf,
      0xe5, 0x9f, 0x9d, 0x6f, 0x14, 0x97, 0x44, 0xe5,
      0xf0, 0xd5, 0x59, 0xb1, 0x02, 0x03, 0x01, 0x00,
      0x01, 0xa3, 0x82, 0x01, 0xa9, 0x30, 0x82, 0x01,
      0xa5, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
      0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x1a, 0xdb,
      0x99, 0x4a, 0xb5, 0x8b, 0xe5, 0x7a, 0x0c, 0xc9,
      0xb9, 0x00, 0xe7, 0x85, 0x1e, 0x1a, 0x43, 0xc0,
      0x86, 0x60, 0x30, 0x42, 0x06, 0x03, 0x55, 0x1d,
      0x20, 0x04, 0x3b, 0x30, 0x39, 0x30, 0x37, 0x06,
      0x04, 0x55, 0x1d, 0x20, 0x00, 0x30, 0x2f, 0x30,
      0x2d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
      0x07, 0x02, 0x01, 0x16, 0x21, 0x68, 0x74, 0x74,
      0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e,
      0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x54,
      0x50, 0x4d, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73,
      0x69, 0x74, 0x6f, 0x72, 0x79, 0x2f, 0x30, 0x59,
      0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff,
      0x04, 0x4f, 0x30, 0x4d, 0xa4, 0x4b, 0x30, 0x49,
      0x31, 0x16, 0x30, 0x14, 0x06, 0x05, 0x67, 0x81,
      0x05, 0x02, 0x01, 0x0c, 0x0b, 0x69, 0x64, 0x3a,
      0x35, 0x33, 0x35, 0x34, 0x34, 0x44, 0x32, 0x30,
      0x31, 0x17, 0x30, 0x15, 0x06, 0x05, 0x67, 0x81,
      0x05, 0x02, 0x02, 0x0c, 0x0c, 0x53, 0x54, 0x33,
      0x33, 0x48, 0x54, 0x50, 0x48, 0x41, 0x48, 0x43,
      0x30, 0x31, 0x16, 0x30, 0x14, 0x06, 0x05, 0x67,
      0x81, 0x05, 0x02, 0x03, 0x0c, 0x0b, 0x69, 0x64,
      0x3a, 0x30, 0x30, 0x34, 0x39, 0x30, 0x30, 0x30,
      0x38, 0x30, 0x67, 0x06, 0x03, 0x55, 0x1d, 0x09,
      0x04, 0x60, 0x30, 0x5e, 0x30, 0x17, 0x06, 0x05,
      0x67, 0x81, 0x05, 0x02, 0x10, 0x31, 0x0e, 0x30,
      0x0c, 0x0c, 0x03, 0x32, 0x2e, 0x30, 0x02, 0x01,
      0x00, 0x02, 0x02, 0x00, 0x8a, 0x30, 0x43, 0x06,
      0x05, 0x67, 0x81, 0x05, 0x02, 0x12, 0x31, 0x3a,
      0x30, 0x38, 0x02, 0x01, 0x00, 0x01, 0x01, 0xff,
      0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa1, 0x03, 0x0a,
      0x01, 0x00, 0xa2, 0x03, 0x0a, 0x01, 0x00, 0xa3,
      0x10, 0x30, 0x0e, 0x16, 0x03, 0x33, 0x2e, 0x31,
      0x0a, 0x01, 0x04, 0x0a, 0x01, 0x02, 0x01, 0x01,
      0xff, 0xa4, 0x0f, 0x30, 0x0d, 0x16, 0x05, 0x31,
      0x34, 0x30, 0x2d, 0x32, 0x0a, 0x01, 0x02, 0x01,
      0x01, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
      0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
      0x05, 0x20, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d,
      0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
      0x30, 0x10, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04,
      0x09, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x05,
      0x08, 0x01, 0x30, 0x4a, 0x06, 0x08, 0x2b, 0x06,
      0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x3e,
      0x30, 0x3c, 0x30, 0x3a, 0x06, 0x08, 0x2b, 0x06,
      0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x2e,
      0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x73,
      0x65, 0x63, 0x75, 0x72, 0x65, 0x2e, 0x67, 0x6c,
      0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e,
      0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x74, 0x6d,
      0x74, 0x70, 0x6d, 0x65, 0x6b, 0x69, 0x6e, 0x74,
      0x30, 0x35, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x0d,
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
      0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01,
      0x01, 0x00, 0x3d, 0x4c, 0x38, 0x1e, 0x5b, 0x4f,
      0x1b, 0xcb, 0xe0, 0x9c, 0x63, 0xd5, 0x2f, 0x1f,
      0x04, 0x57, 0x0c, 0xae, 0xa1, 0x42, 0xfd, 0x9c,
      0xd9, 0x42, 0x04, 0x3b, 0x11, 0xf8, 0xe3, 0xbd,
      0xcf, 0x50, 0x00, 0x7a, 0xe1, 0x6c, 0xf8, 0x86,
      0x90, 0x13, 0x04, 0x1e, 0x92, 0xcd, 0xd3, 0x28,
      0x0b, 0xa4, 0xb5, 0x1f, 0xbb, 0xd4, 0x05, 0x82,
      0xed, 0x75, 0x02, 0x19, 0xe2, 0x61, 0xa6, 0x95,
      0x09, 0x56, 0x74, 0x85, 0x5a, 0xac, 0xeb, 0x52,
      0x0a, 0xda, 0xff, 0x9e, 0x7e, 0x90, 0x84, 0x80,
      0xa3, 0x9c, 0xdc, 0xf9, 0x00, 0x46, 0x2d, 0x91,
      0x71, 0x96, 0x0f, 0xfe, 0x55, 0xd3, 0xac, 0x49,
      0xe8, 0xc9, 0x81, 0x34, 0x1b, 0xbd, 0x2e, 0xfb,
      0xcc, 0x25, 0x2a, 0x4c, 0x18, 0xa4, 0xf3, 0xb7,
      0xc8, 0x4c, 0xce, 0x42, 0xce, 0x70, 0xa2, 0x08,
      0xc8, 0x4d, 0x26, 0x30, 0xa7, 0xab, 0xfb, 0xe7,
      0x2d, 0x62, 0x71, 0xe7, 0x5b, 0x9f, 0xf1, 0xc9,
      0x71, 0xd2, 0x0e, 0xb3, 0xdb, 0xd7, 0x63, 0xf1,
      0xe0, 0x4d, 0x83, 0x4e, 0xaa, 0x69, 0x2d, 0x2e,
      0x40, 0x01, 0xbb, 0xf4, 0x73, 0x0a, 0x3e, 0x3f,
      0xda, 0x97, 0x11, 0xae, 0x38, 0x65, 0x24, 0xd9,
      0x1c, 0x63, 0xbe, 0x0e, 0x51, 0x6d, 0x00, 0xd5,
      0xc6, 0x14, 0x1f, 0xcc, 0xf6, 0xc5, 0x39, 0xf3,
      0x51, 0x8e, 0x18, 0x00, 0x49, 0x86, 0x5b, 0xe1,
      0x6b, 0x69, 0xca, 0xe1, 0xf8, 0xcb, 0x7f, 0xdc,
      0x47, 0x4b, 0x38, 0xf7, 0xee, 0x56, 0xcb, 0xe7,
      0xd8, 0xa8, 0x9d, 0x9b, 0xa9, 0x9b, 0x65, 0xd5,
      0x26, 0x5a, 0xef, 0x32, 0xaa, 0x62, 0x42, 0x6b,
      0x10, 0xe6, 0xd7, 0x5b, 0xb8, 0x67, 0x7e, 0xc4,
      0x4f, 0x75, 0x5b, 0xbc, 0x28, 0x06, 0xfd, 0x2b,
      0x4e, 0x04, 0xbd, 0xf5, 0xd4, 0x42, 0x59, 0xdb,
      0xea, 0xa4, 0x2b, 0x6f, 0x56, 0x3d, 0xf7, 0xaa,
      0x75, 0x06,
    };
    char cert_json[] = {
	"{\"_type\":\"Certificate\",\"tbsCertificate\":{\"_type\":\"TBSCertificate"
	"\",\"_save\":\"30820376A00302010202146A0597BA71D7E6D3AC0EDC9EDC95A15"
	"B998DE40A300D06092A864886F70D01010B05003055310B30090603550406130"
	"24348311E301C060355040A131553544D6963726F656C656374726F6E6963732"
	"04E56312630240603550403131D53544D2054504D20454B20496E7465726D656"
	"469617465204341203035301E170D3138313231343030303030305A170D32383"
	"13231343030303030305A300030820122300D06092A864886F70D01010105000"
	"382010F003082010A0282010100CC14EB27A78CEB0EA486FA2DF7835F5FA8E90"
	"5B097012B5BDE50380C355B1A2A721BBC3D08DD21796CDB239FA95310651B1B5"
	"6FD2CFE53C87352EBD996E33256160404CE9302A08066801E786A2F86E181F94"
	"9966F492A85B58EAA4A6A8CB3697551BB236E87CC7BF8EC1347871C91E15437E"
	"8F266BF1EA5EB271FDCF374D8B47DF8BCE89E1FAD61C2A088CB4036B359CB72A"
	"294973FEDCCF0C340AFFD14B64F041165581ACA34147C1C75617047058F7ED7D"
	"603E032508094FA73E8B9153DA3BF255D2CBBC5DF301BA8F74D198BEBCE86040"
	"FC1D2927C7657414490D802F482F3EBF2DE35EE149A1A6DE8D16891FBFBA02A1"
	"8AFE59F9D6F149744E5F0D559B10203010001A38201A9308201A5301F0603551"
	"D230418301680141ADB994AB58BE57A0CC9B900E7851E1A43C08660304206035"
	"51D20043B303930370604551D2000302F302D06082B060105050702011621687"
	"474703A2F2F7777772E73742E636F6D2F54504D2F7265706F7369746F72792F3"
	"0590603551D110101FF044F304DA44B304931163014060567810502010C0B696"
	"43A353335343444323031173015060567810502020C0C5354333348545048414"
	"8433031163014060567810502030C0B69643A303034393030303830670603551"
	"D090460305E301706056781050210310E300C0C03322E300201000202008A304"
	"306056781050212313A30380201000101FFA0030A0101A1030A0100A2030A010"
	"0A310300E1603332E310A01040A01020101FFA40F300D16053134302D320A010"
	"2010100300E0603551D0F0101FF040403020520300C0603551D130101FF04023"
	"00030100603551D250409300706056781050801304A06082B060105050701010"
	"43E303C303A06082B06010505073002862E687474703A2F2F7365637572652E6"
	"76C6F62616C7369676E2E636F6D2F73746D74706D656B696E7430352E637274\""
	",\"version\":\"rfc3280_version_3\",\"serialNumber\":\"6A0597BA71D7E6D3A"
	"C0EDC9EDC95A15B998DE40A\",\"signature\":{\"_type\":\"AlgorithmIdentifi"
	"er\",\"algorithm\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"1.2.840.1135"
	"49.1.1.11\",\"components\":[1,2,840,113549,1,1,11],\"name\":\"id-pkcs1"
	"-sha256WithRSAEncryption\"},\"parameters\":\"0500\"},\"issuer\":{\"_choi"
	"ce\":\"rdnSequence\",\"value\":[[{\"_type\":\"AttributeTypeAndValue\",\"ty"
	"pe\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2.5.4.6\",\"components\":[2"
	",5,4,6],\"name\":\"id-at-countryName\"},\"value\":{\"_choice\":\"printabl"
	"eString\",\"value\":\"CH\"}}],[{\"_type\":\"AttributeTypeAndValue\",\"type"
	"\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2.5.4.10\",\"components\":[2,"
	"5,4,10],\"name\":\"id-at-organizationName\"},\"value\":{\"_choice\":\"pri"
	"ntableString\",\"value\":\"STMicroelectronics NV\"}}],[{\"_type\":\"Attr"
	"ibuteTypeAndValue\",\"type\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2."
	"5.4.3\",\"components\":[2,5,4,3],\"name\":\"id-at-commonName\"},\"value\""
	":{\"_choice\":\"printableString\",\"value\":\"STM TPM EK Intermediate C"
	"A 05\"}}]]},\"validity\":{\"_type\":\"Validity\",\"notBefore\":{\"_choice\""
	":\"utcTime\",\"value\":\"2018-12-14T00:00:00Z\"},\"notAfter\":{\"_choice\""
	":\"utcTime\",\"value\":\"2028-12-14T00:00:00Z\"}},\"subject\":{\"_choice\""
	":\"rdnSequence\",\"value\":[]},\"subjectPublicKeyInfo\":{\"_type\":\"Subj"
	"ectPublicKeyInfo\",\"algorithm\":{\"_type\":\"AlgorithmIdentifier\",\"al"
	"gorithm\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"1.2.840.113549.1.1."
	"1\",\"components\":[1,2,840,113549,1,1,1],\"name\":\"id-pkcs1-rsaEncry"
	"ption\"},\"parameters\":\"0500\"},\"subjectPublicKey\":\"2160:3082010A02"
	"82010100CC14EB27A78CEB0EA486FA2DF7835F5FA8E905B097012B5BDE50380C"
	"355B1A2A721BBC3D08DD21796CDB239FA95310651B1B56FD2CFE53C87352EBD9"
	"96E33256160404CE9302A08066801E786A2F86E181F949966F492A85B58EAA4A"
	"6A8CB3697551BB236E87CC7BF8EC1347871C91E15437E8F266BF1EA5EB271FDC"
	"F374D8B47DF8BCE89E1FAD61C2A088CB4036B359CB72A294973FEDCCF0C340AF"
	"FD14B64F041165581ACA34147C1C75617047058F7ED7D603E032508094FA73E8"
	"B9153DA3BF255D2CBBC5DF301BA8F74D198BEBCE86040FC1D2927C7657414490"
	"D802F482F3EBF2DE35EE149A1A6DE8D16891FBFBA02A18AFE59F9D6F149744E5"
	"F0D559B10203010001\"},\"issuerUniqueID\":null,\"subjectUniqueID\":nul"
	"l,\"extensions\":[{\"_type\":\"Extension\",\"extnID\":{\"_type\":\"OBJECT I"
	"DENTIFIER\",\"oid\":\"2.5.29.35\",\"components\":[2,5,29,35],\"name\":\"id"
	"-x509-ce-authorityKeyIdentifier\"},\"critical\":false,\"extnValue\":\""
	"301680141ADB994AB58BE57A0CC9B900E7851E1A43C08660\",\"_extnValue_ch"
	"oice\":\"ext-AuthorityKeyIdentifier\",\"_extnValue\":{\"_type\":\"Author"
	"ityKeyIdentifier\",\"keyIdentifier\":\"1ADB994AB58BE57A0CC9B900E7851"
	"E1A43C08660\",\"authorityCertIssuer\":null,\"authorityCertSerialNumb"
	"er\":null}},{\"_type\":\"Extension\",\"extnID\":{\"_type\":\"OBJECT IDENTI"
	"FIER\",\"oid\":\"2.5.29.32\",\"components\":[2,5,29,32],\"name\":\"id-x509"
	"-ce-certificatePolicies\"},\"critical\":false,\"extnValue\":\"30393037"
	"0604551D2000302F302D06082B060105050702011621687474703A2F2F777777"
	"2E73742E636F6D2F54504D2F7265706F7369746F72792F\",\"_extnValue_choi"
	"ce\":\"ext-CertificatePolicies\",\"_extnValue\":[{\"_type\":\"PolicyInfo"
	"rmation\",\"policyIdentifier\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\""
	"2.5.29.32.0\",\"components\":[2,5,29,32,0],\"name\":\"id-x509-ce-certi"
	"ficatePolicies-anyPolicy\"},\"policyQualifiers\":[{\"_type\":\"PolicyQ"
	"ualifierInfo\",\"policyQualifierId\":{\"_type\":\"OBJECT IDENTIFIER\",\""
	"oid\":\"1.3.6.1.5.5.7.2.1\",\"components\":[1,3,6,1,5,5,7,2,1],\"name\""
	":\"id-pkix-qt-cps\"},\"qualifier\":\"1621687474703A2F2F7777772E73742E"
	"636F6D2F54504D2F7265706F7369746F72792F\",\"_qualifier_choice\":\"pq-"
	"CPS\"}]}]},{\"_type\":\"Extension\",\"extnID\":{\"_type\":\"OBJECT IDENTIF"
	"IER\",\"oid\":\"2.5.29.17\",\"components\":[2,5,29,17],\"name\":\"id-x509-"
	"ce-subjectAltName\"},\"critical\":true,\"extnValue\":\"304DA44B3049311"
	"63014060567810502010C0B69643A35333534344432303117301506056781050"
	"2020C0C53543333485450484148433031163014060567810502030C0B69643A3"
	"030343930303038\",\"_extnValue_choice\":\"ext-SubjectAltName\",\"_extn"
	"Value\":[{\"_choice\":\"directoryName\",\"value\":{\"_choice\":\"rdnSequen"
	"ce\",\"value\":[[{\"_type\":\"AttributeTypeAndValue\",\"type\":{\"_type\":\""
	"OBJECT IDENTIFIER\",\"oid\":\"2.23.133.2.1\",\"components\":[2,23,133,2"
	",1],\"name\":\"tcg-at-tpmManufacturer\"},\"value\":{\"_choice\":\"utf8Str"
	"ing\",\"value\":\"id:53544D20\"}}],[{\"_type\":\"AttributeTypeAndValue\","
	"\"type\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2.23.133.2.2\",\"compon"
	"ents\":[2,23,133,2,2],\"name\":\"tcg-at-tpmModel\"},\"value\":{\"_choice"
	"\":\"utf8String\",\"value\":\"ST33HTPHAHC0\"}}],[{\"_type\":\"AttributeTyp"
	"eAndValue\",\"type\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2.23.133.2"
	".3\",\"components\":[2,23,133,2,3],\"name\":\"tcg-at-tpmVersion\"},\"val"
	"ue\":{\"_choice\":\"utf8String\",\"value\":\"id:00490008\"}}]]}}]},{\"_typ"
	"e\":\"Extension\",\"extnID\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2.5."
	"29.9\",\"components\":[2,5,29,9],\"name\":\"id-x509-ce-subjectDirector"
	"yAttributes\"},\"critical\":false,\"extnValue\":\"305E3017060567810502"
	"10310E300C0C03322E300201000202008A304306056781050212313A30380201"
	"000101FFA0030A0101A1030A0100A2030A0100A310300E1603332E310A01040A"
	"01020101FFA40F300D16053134302D320A0102010100\",\"_extnValue_choice"
	"\":\"ext-SubjectDirectoryAttributes\",\"_extnValue\":[{\"_type\":\"Attri"
	"buteSet\",\"type\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2.23.133.2.1"
	"6\",\"components\":[2,23,133,2,16],\"name\":\"tcg-at-tpmSpecification\""
	"},\"values\":[\"300C0C03322E300201000202008A\"],\"_values_choice\":\"at"
	"-TPMSpecification\",\"_values\":[{\"_type\":\"TPMSpecification\",\"famil"
	"y\":\"2.0\",\"level\":0,\"revision\":138}]},{\"_type\":\"AttributeSet\",\"ty"
	"pe\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2.23.133.2.18\",\"componen"
	"ts\":[2,23,133,2,18],\"name\":\"tcg-at-tpmSecurityAssertions\"},\"valu"
	"es\":[\"30380201000101FFA0030A0101A1030A0100A2030A0100A310300E1603"
	"332E310A01040A01020101FFA40F300D16053134302D320A0102010100\"],\"_v"
	"alues_choice\":\"at-TPMSecurityAssertions\",\"_values\":[{\"_type\":\"TP"
	"MSecurityAssertions\",\"version\":0,\"fieldUpgradable\":true,\"ekGener"
	"ationType\":\"ekgt-injected\",\"ekGenerationLocation\":\"tpmManufactur"
	"er\",\"ekCertificateGenerationLocation\":\"tpmManufacturer\",\"ccInfo\""
	":{\"_type\":\"CommonCriteriaMeasures\",\"version\":\"3.1\",\"assurancelev"
	"el\":\"ealevel4\",\"evaluationStatus\":\"evaluationCompleted\",\"plus\":t"
	"rue,\"strengthOfFunction\":null,\"profileOid\":null,\"profileUri\":nul"
	"l,\"targetOid\":null,\"targetUri\":null},\"fipsLevel\":{\"_type\":\"FIPSL"
	"evel\",\"version\":\"140-2\",\"level\":\"sllevel2\",\"plus\":false},\"iso900"
	"0Certified\":false,\"iso9000Uri\":null}]}]},{\"_type\":\"Extension\",\"e"
	"xtnID\":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"2.5.29.15\",\"component"
	"s\":[2,5,29,15],\"name\":\"id-x509-ce-keyUsage\"},\"critical\":true,\"ex"
	"tnValue\":\"03020520\",\"_extnValue_choice\":\"ext-KeyUsage\",\"_extnVal"
	"ue\":[\"keyEncipherment\"]},{\"_type\":\"Extension\",\"extnID\":{\"_type\":"
	"\"OBJECT IDENTIFIER\",\"oid\":\"2.5.29.19\",\"components\":[2,5,29,19],\""
	"name\":\"id-x509-ce-basicConstraints\"},\"critical\":true,\"extnValue\""
	":\"3000\",\"_extnValue_choice\":\"ext-BasicConstraints\",\"_extnValue\":"
	"{\"_type\":\"BasicConstraints\",\"cA\":false,\"pathLenConstraint\":null}"
	"},{\"_type\":\"Extension\",\"extnID\":{\"_type\":\"OBJECT IDENTIFIER\",\"oi"
	"d\":\"2.5.29.37\",\"components\":[2,5,29,37],\"name\":\"id-x509-ce-extKe"
	"yUsage\"},\"critical\":false,\"extnValue\":\"300706056781050801\",\"_ext"
	"nValue_choice\":\"ext-ExtKeyUsage\",\"_extnValue\":[{\"_type\":\"OBJECT "
	"IDENTIFIER\",\"oid\":\"2.23.133.8.1\",\"components\":[2,23,133,8,1],\"na"
	"me\":\"tcg-kp-EKCertificate\"}]},{\"_type\":\"Extension\",\"extnID\":{\"_t"
	"ype\":\"OBJECT IDENTIFIER\",\"oid\":\"1.3.6.1.5.5.7.1.1\",\"components\":"
	"[1,3,6,1,5,5,7,1,1],\"name\":\"id-pkix-pe-authorityInfoAccess\"},\"cr"
	"itical\":false,\"extnValue\":\"303C303A06082B06010505073002862E68747"
	"4703A2F2F7365637572652E676C6F62616C7369676E2E636F6D2F73746D74706"
	"D656B696E7430352E637274\",\"_extnValue_choice\":\"ext-AuthorityInfoA"
	"ccess\",\"_extnValue\":[{\"_type\":\"AccessDescription\",\"accessMethod\""
	":{\"_type\":\"OBJECT IDENTIFIER\",\"oid\":\"1.3.6.1.5.5.7.48.2\",\"compon"
	"ents\":[1,3,6,1,5,5,7,48,2],\"name\":\"id-pkix-ad-caIssuers\"},\"acces"
	"sLocation\":{\"_choice\":\"uniformResourceIdentifier\",\"value\":\"http:"
	"//secure.globalsign.com/stmtpmekint05.crt\"}}]}]},\"signatureAlgor"
	"ithm\":{\"_type\":\"AlgorithmIdentifier\",\"algorithm\":{\"_type\":\"OBJEC"
	"T IDENTIFIER\",\"oid\":\"1.2.840.113549.1.1.11\",\"components\":[1,2,84"
	"0,113549,1,1,11],\"name\":\"id-pkcs1-sha256WithRSAEncryption\"},\"par"
	"ameters\":\"0500\"},\"signatureValue\":\"2048:3D4C381E5B4F1BCBE09C63D5"
	"2F1F04570CAEA142FD9CD942043B11F8E3BDCF50007AE16CF8869013041E92CD"
	"D3280BA4B51FBBD40582ED750219E261A695095674855AACEB520ADAFF9E7E90"
	"8480A39CDCF900462D9171960FFE55D3AC49E8C981341BBD2EFBCC252A4C18A4"
	"F3B7C84CCE42CE70A208C84D2630A7ABFBE72D6271E75B9FF1C971D20EB3DBD7"
	"63F1E04D834EAA692D2E4001BBF4730A3E3FDA9711AE386524D91C63BE0E516D"
	"00D5C6141FCCF6C539F3518E180049865BE16B69CAE1F8CB7FDC474B38F7EE56"
	"CBE7D8A89D9BA99B65D5265AEF32AA62426B10E6D75BB8677EC44F755BBC2806"
	"FD2B4E04BDF5D44259DBEAA42B6F563DF7AA7506\""
	"}"
            };
    heim_octet_string os;
    Certificate c0, c1;
    size_t i, nknown, size;
    char *s;
    int ret;

    /*
     * Test automatic decoding of open types.
     *
     * Decode a value that has plenty of open types with values of known
     * alternatives in them, then check that we got what we wanted.
     */
    ret = decode_Certificate(encoded_sample, sizeof(encoded_sample),
                             &c0, &size);
    if (ret)
        return 1;
    if (size != sizeof(encoded_sample))
        return 1;

    s = print_Certificate(&c0, 0);
    if (!s)
        return 1;
    if (strcmp(s, cert_json) != 0)
        return 1;
    free(s);

    ret = copy_Certificate(&c0, &c1);
    if (ret)
        return 1;

    if (!c0.tbsCertificate.extensions || !c1.tbsCertificate.extensions)
        return 1;
    if (!c0.tbsCertificate.extensions->len ||
        c0.tbsCertificate.extensions->len != c1.tbsCertificate.extensions->len)
        return 1;
    for (i = nknown = 0; i < c0.tbsCertificate.extensions->len; i++) {
        if (c0.tbsCertificate.extensions->val[i]._ioschoice_extnValue.element !=
            c1.tbsCertificate.extensions->val[i]._ioschoice_extnValue.element)
            return 1;
        if (c0.tbsCertificate.extensions->val[i]._ioschoice_extnValue.element) {
#if 0
            fprintf(stderr, "extension %llu known %u\n",
                    (unsigned long long)i,
                    c0.tbsCertificate.extensions->val[i]._ioschoice_extnValue._element);
#endif
            nknown++;
        }
    }
    if (!nknown)
        return 1;


    /*
     * Check that this round trips.  But note that this attempt to encode will
     * ignore the automatically decoded open type values from above because
     * their encodings are still present.
     */
    ASN1_MALLOC_ENCODE(Certificate, os.data, os.length, &c1, &size, ret);
    if (ret)
        return 1;
    if (os.length != size || size != sizeof(encoded_sample))
        return 1;
    if (memcmp(os.data, encoded_sample, os.length) != 0)
        return 1;
    der_free_octet_string(&os);

    /*
     * Test automatic encoding of open types by clearing the encoding of one
     * such open type value, forcing the encoder to encode the value from
     * before.
     */
    der_free_octet_string(&c0.tbsCertificate.extensions->val[0].extnValue);
    der_free_oid(&c0.tbsCertificate.extensions->val[0].extnID);

    ASN1_MALLOC_ENCODE(Certificate, os.data, os.length, &c0, &size, ret);
    if (ret)
        return 1;
    if (os.length != size || size != sizeof(encoded_sample))
        return 1;
    if (memcmp(os.data, encoded_sample, os.length) != 0)
        return 1;
    der_free_octet_string(&os);

    /*
     * Repeat, but with the copy, as this will test that copying data
     * structures with decoded open types in them also copies those.
     */
    der_free_octet_string(&c1.tbsCertificate.extensions->val[0].extnValue);
    der_free_oid(&c1.tbsCertificate.extensions->val[0].extnID);

    ASN1_MALLOC_ENCODE(Certificate, os.data, os.length, &c1, &size, ret);
    if (ret)
        return 1;
    if (os.length != size || size != sizeof(encoded_sample))
        return 1;
    if (memcmp(os.data, encoded_sample, os.length) != 0)
        return 1;
    der_free_octet_string(&os);

    free_Certificate(&c0);
    free_Certificate(&c1);
    return 0;
}
#endif

int
main(int argc, char **argv)
{
    int ret = 0;

#define DO_ONE(t) if (t()) { fprintf(stderr, "%s() failed!\n", #t); ret++; }
    DO_ONE(test_principal);
    DO_ONE(test_authenticator);
    DO_ONE(test_krb_error);
    DO_ONE(test_Name);
    DO_ONE(test_bit_string);
    DO_ONE(test_bit_string_rfc1510);
    DO_ONE(test_time);
    DO_ONE(test_cert);

    DO_ONE(check_tag_length);
    DO_ONE(check_tag_length64);
    DO_ONE(check_tag_length64s);
    DO_ONE(test_large_tag);
    DO_ONE(test_choice);

    DO_ONE(test_implicit);

    DO_ONE(test_taglessalloc);
    DO_ONE(test_optional);

    DO_ONE(check_fail_largetag);
    DO_ONE(check_fail_sequence);
    DO_ONE(check_fail_choice);
    DO_ONE(check_fail_Ticket);

    DO_ONE(check_seq);
    DO_ONE(check_seq_of_size);
    DO_ONE(test_SignedData);

    DO_ONE(check_TESTMechTypeList);
    DO_ONE(test_seq4);
    DO_ONE(test_seqof5);

    DO_ONE(test_x690sample);

    DO_ONE(test_default);

    DO_ONE(test_extensible_choice);

    DO_ONE(test_decorated_choice);
    DO_ONE(test_decorated);

#if ASN1_IOS_SUPPORTED
    DO_ONE(test_ios);
#endif

    return ret;
}
