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

#include "hx_locl.h"
RCSID("$Id$");

static int
test_name(const char *name)
{
    hx509_name n;
    char *s;
    int ret;

    ret = hx509_parse_name(name, &n);
    if (ret)
	return 1;

    ret = hx509_name_to_string(n, &s);
    if (ret)
	return 1;

    if (strcmp(s, name) != 0)
	return 1;

    hx509_name_free(&n);
    free(s);

    return 0;
}

static int
test_name_fail(const char *name)
{
    hx509_name n;

    if (hx509_parse_name(name, &n) == HX509_NAME_MALFORMED)
	return 0;
    hx509_name_free(&n);
    return 1;
}

int
main(int argc, char **argv)
{
    int ret = 0;

    ret += test_name("CN=foo,C=SE");
    ret += test_name("CN=foo,CN=kaka,CN=FOO,DC=ad1,C=SE");
    ret += test_name_fail("=");
    ret += test_name_fail("CN=foo,=foo");
    ret += test_name_fail("CN=foo,really-unknown-type=foo");

    return ret;
}
