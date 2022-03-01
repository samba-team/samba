/*
 * Copyright (c) 1999 - 2001 Kungliga Tekniska Högskolan
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

#include <config.h>

#include "roken.h"
#include <base32.h>

int
main(int argc, char **argv)
{
    int numerr = 0;
    int numtest = 1;
    struct test {
        int preserve_order;
	void *data;
	size_t len;
	const char *result;
    } *t, tests[] = {
	{ 0, "", 0 , "" },
	{ 0, "f", 1, "MY======" },
	{ 0, "fo", 2, "MZXQ====" },
	{ 0, "foo", 3, "MZXW6===" },
	{ 0, "foob", 4, "MZXW6YQ=" },
	{ 0, "fooba", 5, "MZXW6YTB" },
	{ 0, "foobar", 6, "MZXW6YTBOI======" },
	{ 1, "", 0 , "" },
	{ 1, "f", 1, "CO======" },
	{ 1, "fo", 2, "CPNG====" },
	{ 1, "foo", 3, "CPNMU===" },
	{ 1, "foob", 4, "CPNMUOG=" },
	{ 1, "fooba", 5, "CPNMUOJ1" },
	{ 1, "foobar", 6, "CPNMUOJ1E8======" },
	{ 0, NULL, 0, NULL }
    };
    for(t = tests; t->data; t++) {
	char *str;
	int len;

	(void) rk_base32_encode(t->data, t->len, &str, t->preserve_order);
	if (strcmp(str, t->result) != 0) {
	    fprintf(stderr, "failed test %d: %s != %s\n", numtest,
		    str, t->result);
	    numerr++;
	}
	free(str);
	str = strdup(t->result);
	len = rk_base32_decode(t->result, str, t->preserve_order);
	if (len != t->len) {
	    fprintf(stderr, "failed test %d: len %lu != %lu\n", numtest,
		    (unsigned long)len, (unsigned long)t->len);
	    numerr++;
	} else if(memcmp(str, t->data, t->len) != 0) {
	    fprintf(stderr, "failed test %d: data\n", numtest);
	    numerr++;
	}
	free(str);
	numtest++;
    }

    {
	char str[32];

	if (rk_base32_decode("M=M=", str, 1) != -1) {
	    fprintf(stderr, "failed test %d: successful decode of `M=M='\n",
		    numtest++);
	    numerr++;
	}
	if (rk_base32_decode("MQ===", str, 1) != -1) {
	    fprintf(stderr, "failed test %d: successful decode of `MQ==='\n",
		    numtest++);
	    numerr++;
	}
    }
    return numerr;
}
