/*
 * Copyright (c) 1999 - 2006 Kungliga Tekniska Högskolan
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

#include "der_locl.h"
#include <err.h>
#include <roken.h>

#include <asn1-common.h>
#include <asn1_err.h>
#include <der.h>

#include "check-common.h"

RCSID("$Id$");

static int
cmp_integer (void *a, void *b)
{
    int *ia = (int *)a;
    int *ib = (int *)b;

    return *ib - *ia;
}

static int
test_integer (void)
{
    struct test_case tests[] = {
	{NULL, 1, "\x00"},
	{NULL, 1, "\x7f"},
	{NULL, 2, "\x00\x80"},
	{NULL, 2, "\x01\x00"},
	{NULL, 1, "\x80"},
	{NULL, 2, "\xff\x7f"},
	{NULL, 1, "\xff"},
	{NULL, 2, "\xff\x01"},
	{NULL, 2, "\x00\xff"},
	{NULL, 4, "\x80\x00\x00\x00"},
	{NULL, 4, "\x7f\xff\xff\xff"}
    };

    int values[] = {0, 127, 128, 256, -128, -129, -1, -255, 255,
		    0x80000000, 0x7fffffff};
    int i;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	asprintf (&tests[i].name, "integer %d", values[i]);
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    return generic_test (tests, ntests, sizeof(int),
			 (generic_encode)der_put_integer,
			 (generic_length) der_length_integer,
			 (generic_decode)der_get_integer,
			 (generic_free)NULL,
			 cmp_integer);
}

static int
test_one_int(int val)
{
    int ret, dval;
    unsigned char *buf;
    size_t len_len, len;

    len = _heim_len_int(val);

    buf = emalloc(len + 2);

    buf[0] = '\xff';
    buf[len + 1] = '\xff';
    memset(buf + 1, 0, len);

    ret = der_put_integer(buf + 1 + len - 1, len, &val, &len_len);
    if (ret) {
	printf("integer %d encode failed %d\n", val, ret);
	return 1;
    }
    if (len != len_len) {
	printf("integer %d encode fail with %d len %lu, result len %lu\n",
	       val, ret, (unsigned long)len, (unsigned long)len_len);
	return 1;
    }

    ret = der_get_integer(buf + 1, len, &dval, &len_len);
    if (ret) {
	printf("integer %d decode failed %d\n", val, ret);
	return 1;
    }
    if (len != len_len) {
	printf("integer %d decoded diffrent len %lu != %lu",
	       val, (unsigned long)len, (unsigned long)len_len);
	return 1;
    }
    if (val != dval) {
	printf("decode decoded to diffrent value %d != %d",
	       val, dval);
	return 1;
    }

    if (buf[0] != (unsigned char)'\xff') {
	printf("precanary dead %d\n", val);
	return 1;
    }
    if (buf[len + 1] != (unsigned char)'\xff') {
	printf("postecanary dead %d\n", val);
	return 1;
    }
    free(buf);
    return 0;
}

static int
test_integer_more (void)
{
    int i, n1, n2, n3, n4, n5, n6;

    n2 = 0;
    for (i = 0; i < (sizeof(int) * 8); i++) {
	n1 = 0x01 << i;
	n2 = n2 | n1;
	n3 = ~n1;
	n4 = ~n2;
	n5 = (-1) & ~(0x3f << i);
	n6 = (-1) & ~(0x7f << i);

	test_one_int(n1);
	test_one_int(n2);
	test_one_int(n3);
	test_one_int(n4);
	test_one_int(n5);
	test_one_int(n6);
    }
    return 0;
}

static int
cmp_unsigned (void *a, void *b)
{
    return *(unsigned int*)b - *(unsigned int*)a;
}

static int
test_unsigned (void)
{
    struct test_case tests[] = {
	{NULL, 1, "\x00"},
	{NULL, 1, "\x7f"},
	{NULL, 2, "\x00\x80"},
	{NULL, 2, "\x01\x00"},
	{NULL, 2, "\x02\x00"},
	{NULL, 3, "\x00\x80\x00"},
	{NULL, 5, "\x00\x80\x00\x00\x00"},
	{NULL, 4, "\x7f\xff\xff\xff"}
    };

    unsigned int values[] = {0, 127, 128, 256, 512, 32768, 
			     0x80000000, 0x7fffffff};
    int i;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	asprintf (&tests[i].name, "unsigned %u", values[i]);
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    return generic_test (tests, ntests, sizeof(int),
			 (generic_encode)der_put_unsigned,
			 (generic_length)der_length_unsigned,
			 (generic_decode)der_get_unsigned,
			 (generic_free)NULL,
			 cmp_unsigned);
}

static int
cmp_octet_string (void *a, void *b)
{
    heim_octet_string *oa = (heim_octet_string *)a;
    heim_octet_string *ob = (heim_octet_string *)b;

    if (oa->length != ob->length)
	return ob->length - oa->length;

    return (memcmp (oa->data, ob->data, oa->length));
}

static int
test_octet_string (void)
{
    heim_octet_string s1 = {8, "\x01\x23\x45\x67\x89\xab\xcd\xef"};

    struct test_case tests[] = {
	{NULL, 8, "\x01\x23\x45\x67\x89\xab\xcd\xef"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    tests[0].val = &s1;
    asprintf (&tests[0].name, "a octet string");
    if (tests[0].name == NULL)
	errx(1, "malloc");

    return generic_test (tests, ntests, sizeof(heim_octet_string),
			 (generic_encode)der_put_octet_string,
			 (generic_length)der_length_octet_string,
			 (generic_decode)der_get_octet_string,
			 (generic_free)der_free_octet_string,
			 cmp_octet_string);
}

static int
cmp_bmp_string (void *a, void *b)
{
    heim_bmp_string *oa = (heim_bmp_string *)a;
    heim_bmp_string *ob = (heim_bmp_string *)b;

    return der_heim_bmp_string_cmp(oa, ob);
}

static uint16_t bmp_d1[] = { 32 };
static uint16_t bmp_d2[] = { 32, 32 };

static int
test_bmp_string (void)
{
    heim_bmp_string s1 = { 1, bmp_d1 };
    heim_bmp_string s2 = { 2, bmp_d2 };

    struct test_case tests[] = {
	{NULL, 2, "\x00\x20"},
	{NULL, 4, "\x00\x20\x00\x20"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    tests[0].val = &s1;
    asprintf (&tests[0].name, "a bmp string");
    if (tests[0].name == NULL)
	errx(1, "malloc");
    tests[1].val = &s2;
    asprintf (&tests[1].name, "second bmp string");
    if (tests[1].name == NULL)
	errx(1, "malloc");

    return generic_test (tests, ntests, sizeof(heim_bmp_string),
			 (generic_encode)der_put_bmp_string,
			 (generic_length)der_length_bmp_string,
			 (generic_decode)der_get_bmp_string,
			 (generic_free)der_free_bmp_string,
			 cmp_bmp_string);
}

static int
cmp_general_string (void *a, void *b)
{
    char **sa = (char **)a;
    char **sb = (char **)b;

    return strcmp (*sa, *sb);
}

static int
test_general_string (void)
{
    char *s1 = "Test User 1";

    struct test_case tests[] = {
	{NULL, 11, "\x54\x65\x73\x74\x20\x55\x73\x65\x72\x20\x31"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    tests[0].val = &s1;
    asprintf (&tests[0].name, "the string \"%s\"", s1);
    if (tests[0].name == NULL)
	errx(1, "malloc");

    return generic_test (tests, ntests, sizeof(unsigned char *),
			 (generic_encode)der_put_general_string,
			 (generic_length)der_length_general_string,
			 (generic_decode)der_get_general_string,
			 (generic_free)der_free_general_string,
			 cmp_general_string);
}

static int
cmp_generalized_time (void *a, void *b)
{
    time_t *ta = (time_t *)a;
    time_t *tb = (time_t *)b;

    return *tb - *ta;
}

static int
test_generalized_time (void)
{
    struct test_case tests[] = {
	{NULL, 15, "19700101000000Z"},
	{NULL, 15, "19851106210627Z"}
    };
    time_t values[] = {0, 500159187};
    int i;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	asprintf (&tests[i].name, "time %d", (int)values[i]);
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    return generic_test (tests, ntests, sizeof(time_t),
			 (generic_encode)der_put_generalized_time,
			 (generic_length)der_length_generalized_time,
			 (generic_decode)der_get_generalized_time,
			 (generic_free)NULL,
			 cmp_generalized_time);
}

static int
test_cmp_oid (void *a, void *b)
{
    return der_heim_oid_cmp((heim_oid *)a, (heim_oid *)b);
}

static unsigned oid_comp1[] = { 1, 1, 1 };
static unsigned oid_comp2[] = { 1, 1 };
static unsigned oid_comp3[] = { 6, 15, 1 };
static unsigned oid_comp4[] = { 6, 15 };

static int
test_oid (void)
{
    struct test_case tests[] = {
	{NULL, 2, "\x29\x01"},
	{NULL, 1, "\x29"},
	{NULL, 2, "\xff\x01"},
	{NULL, 1, "\xff"}
    };
    heim_oid values[] = {
	{ 3, oid_comp1 },
	{ 2, oid_comp2 },
	{ 3, oid_comp3 },
	{ 2, oid_comp4 }
    };
    int i;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	asprintf (&tests[i].name, "oid %d", i);
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    return generic_test (tests, ntests, sizeof(heim_oid),
			 (generic_encode)der_put_oid,
			 (generic_length)der_length_oid,
			 (generic_decode)der_get_oid,
			 (generic_free)der_free_oid,
			 test_cmp_oid);
}

static int
test_cmp_bit_string (void *a, void *b)
{
    return der_heim_bit_string_cmp((heim_bit_string *)a, (heim_bit_string *)b);
}

static int
test_bit_string (void)
{
    struct test_case tests[] = {
	{NULL, 1, "\x00"}
    };
    heim_bit_string values[] = {
	{ 0, "" }
    };
    int i;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	asprintf (&tests[i].name, "bit_string %d", i);
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    return generic_test (tests, ntests, sizeof(heim_bit_string),
			 (generic_encode)der_put_bit_string,
			 (generic_length)der_length_bit_string,
			 (generic_decode)der_get_bit_string,
			 (generic_free)der_free_bit_string,
			 test_cmp_bit_string);
}

static int
test_cmp_heim_integer (void *a, void *b)
{
    return der_heim_integer_cmp((heim_integer *)a, (heim_integer *)b);
}

static int
test_heim_integer (void)
{
    struct test_case tests[] = {
	{NULL, 2, "\xfe\x01"},
	{NULL, 2, "\xef\x01"},
	{NULL, 3, "\xff\x00\xff"},
	{NULL, 3, "\xff\x01\x00"},
	{NULL, 1, "\x00"},
	{NULL, 1, "\x01"},
	{NULL, 2, "\x00\x80"}
    };

    heim_integer values[] = {
	{ 2, "\x01\xff", 1 },
	{ 2, "\x10\xff", 1 },
	{ 2, "\xff\x01", 1 },
	{ 2, "\xff\x00", 1 },
	{ 0, "", 0 },
	{ 1, "\x01", 0 },
	{ 1, "\x80", 0 }
    };
    int i;
    int ntests = sizeof(tests) / sizeof(tests[0]);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	asprintf (&tests[i].name, "heim_integer %d", i);
	if (tests[i].name == NULL)
	    errx(1, "malloc");
    }

    return generic_test (tests, ntests, sizeof(heim_integer),
			 (generic_encode)der_put_heim_integer,
			 (generic_length)der_length_heim_integer,
			 (generic_decode)der_get_heim_integer,
			 (generic_free)der_free_heim_integer,
			 test_cmp_heim_integer);
}

static int
check_fail_unsigned(void)
{
    struct test_case tests[] = {
	{NULL, sizeof(unsigned) + 1,
	 "\x01\x01\x01\x01\x01\x01\x01\x01\x01", "data overrun" }
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(unsigned),
			       (generic_decode)der_get_unsigned);
}

static int
check_fail_integer(void)
{
    struct test_case tests[] = {
	{NULL, sizeof(int) + 1,
	 "\x01\x01\x01\x01\x01\x01\x01\x01\x01", "data overrun" }
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(int),
			       (generic_decode)der_get_integer);
}

static int
check_fail_length(void)
{
    struct test_case tests[] = {
	{NULL, 0, "", "empty input data"},
	{NULL, 1, "\x82", "internal length overrun" }
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(size_t),
			       (generic_decode)der_get_length);
}

static int
check_fail_boolean(void)
{
    struct test_case tests[] = {
	{NULL, 0, "", "empty input data"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(int),
			       (generic_decode)der_get_boolean);
}

static int
check_fail_general_string(void)
{
#if 0
    struct test_case tests[] = {
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(heim_general_string),
			       (generic_decode)der_get_general_string);
#else
    return 0;
#endif
}

static int
check_fail_bmp_string(void)
{
    struct test_case tests[] = {
	{NULL, 1, "\x00", "odd length bmpstring"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(heim_bmp_string),
			       (generic_decode)der_get_bmp_string);
}

static int
check_fail_universal_string(void)
{
    struct test_case tests[] = {
	{NULL, 1, "\x00", "x & 3 == 1 universal string"},
	{NULL, 2, "\x00\x00", "x & 3 == 2 universal string"},
	{NULL, 3, "\x00\x00\x00", "x & 3 == 3 universal string"},
	{NULL, 5, "\x00\x00\x00\x00\x00", "x & 3 == 1 universal string"},
	{NULL, 6, "\x00\x00\x00\x00\x00\x00", "x & 3 == 2 universal string"},
	{NULL, 7, "\x00\x00\x00\x00\x00\x00\x00", "x & 3 == 3 universal string"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(heim_universal_string),
			       (generic_decode)der_get_universal_string);
}

static int
check_fail_heim_integer(void)
{
#if 0
    struct test_case tests[] = {
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(heim_integer),
			       (generic_decode)der_get_heim_integer);
#else
    return 0;
#endif
}

static int
check_fail_generalized_time(void)
{
    struct test_case tests[] = {
	{NULL, 1, "\x00", "no time"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(time_t),
			       (generic_decode)der_get_generalized_time);
}

static int
check_fail_oid(void)
{
    struct test_case tests[] = {
	{NULL, 0, "", "empty input data"},
	{NULL, 2, "\x00\x80", "last byte continuation" },
	{NULL, 11, "\x00\x81\x80\x80\x80\x80\x80\x80\x80\x80\x00", 
	"oid element overflow" }
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(heim_oid),
			       (generic_decode)der_get_oid);
}

static int
check_fail_bitstring(void)
{
    struct test_case tests[] = {
	{NULL, 0, "", "empty input data"},
	{NULL, 1, "\x08", "larger then 8 bits trailer"},
	{NULL, 1, "\x01", "to few bytes for bits"},
	{NULL, -2, "\x00", "length overrun"},
	{NULL, -1, "", "length to short"}
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    return generic_decode_fail(tests, ntests, sizeof(heim_bit_string),
			       (generic_decode)der_get_bit_string);
}

static int
check_heim_integer_same(const char *p, const char *norm_p, heim_integer *i)
{
    heim_integer i2;
    char *str;
    int ret;

    ret = der_print_hex_heim_integer(i, &str);
    if (ret)
	errx(1, "der_print_hex_heim_integer: %d", ret);

    if (strcmp(str, norm_p) != 0)
	errx(1, "der_print_hex_heim_integer: %s != %s", str, p);

    ret = der_parse_hex_heim_integer(str, &i2);
    if (ret)
	errx(1, "der_parse_hex_heim_integer: %d", ret);

    if (der_heim_integer_cmp(i, &i2) != 0)
	errx(1, "der_heim_integer_cmp: p %s", p);

    der_free_heim_integer(&i2);
    free(str);

    ret = der_parse_hex_heim_integer(p, &i2);
    if (ret)
	errx(1, "der_parse_hex_heim_integer: %d", ret);

    if (der_heim_integer_cmp(i, &i2) != 0)
	errx(1, "der_heim_integer_cmp: norm");

    return 0;
}

static int
test_heim_int_format(void)
{
    heim_integer i = { 1, "\x10", 0 };
    heim_integer i2 = { 1, "\x10", 1 };
    heim_integer i3 = { 1, "\01", 0 };
    char *p =
	"FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	"29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	"EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	"E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	"EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	"FFFFFFFF" "FFFFFFFF";
    heim_integer bni = {
	128, 
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2"
	"\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1"
	"\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6"
	"\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD"
	"\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D"
	"\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45"
	"\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9"
	"\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED"
	"\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11"
	"\x7C\x4B\x1F\xE6\x49\x28\x66\x51\xEC\xE6\x53\x81"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
	0
    };
    int ret = 0;

    ret += check_heim_integer_same(p, p, &bni);
    ret += check_heim_integer_same("10", "10", &i);
    ret += check_heim_integer_same("00000010", "10", &i);
    ret += check_heim_integer_same("-10", "-10", &i2);
    ret += check_heim_integer_same("-00000010", "-10", &i2);
    ret += check_heim_integer_same("01", "01", &i3);
    ret += check_heim_integer_same("1", "01", &i3);

    return ret;
}

static int
test_heim_oid_format_same(const char *str, const heim_oid *oid)
{
    int ret;
    char *p;
    heim_oid o2;

    ret = der_print_heim_oid(oid, ' ', &p);
    if (ret) {
	printf("fail to print oid: %s\n", str);
	return 1;
    }
    ret = strcmp(p, str);
    if (ret) {
	printf("oid %s != formated oid %s\n", str, p);
	free(p);
	return ret;
    }

    ret = der_parse_heim_oid(p, " ", &o2);
    if (ret) {
	printf("failed to parse %s\n", p);
	free(p);
	return ret;
    }
    ret = der_heim_oid_cmp(&o2, oid);
    der_free_oid(&o2);

    return ret;
}

static int
test_heim_oid_format(void)
{
    unsigned sha1_oid_tree[] = { 1, 3, 14, 3, 2, 26 };
    heim_oid sha1 = { 6, sha1_oid_tree };
    int ret = 0;

    ret += test_heim_oid_format_same("1 3 14 3 2 26", &sha1);

    return ret;
}

int
main(int argc, char **argv)
{
    int ret = 0;

    ret += test_integer ();
    ret += test_integer_more();
    ret += test_unsigned ();
    ret += test_octet_string ();
    ret += test_bmp_string ();
    ret += test_general_string ();
    ret += test_generalized_time ();
    ret += test_oid ();
    ret += test_bit_string();
    ret += test_heim_integer();

    ret += check_fail_unsigned();
    ret += check_fail_integer();
    ret += check_fail_length();
    ret += check_fail_boolean();
    ret += check_fail_general_string();
    ret += check_fail_bmp_string();
    ret += check_fail_universal_string();
    ret += check_fail_heim_integer();
    ret += check_fail_generalized_time();
    ret += check_fail_oid();
    ret += check_fail_bitstring();
    ret += test_heim_int_format();
    ret += test_heim_oid_format();

    return ret;
}
