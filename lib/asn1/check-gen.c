/*
 * Copyright (c) 1999 - 2003 Kungliga Tekniska Högskolan
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <roken.h>

#include <asn1-common.h>
#include <asn1_err.h>
#include <der.h>
#include <krb5_asn1.h>

#include "check-common.h"

RCSID("$Id$");

#define COMPARE_STRING(ac,bc,e) \
	do { if (strcmp((ac)->e, (bc)->e) != 0) return 1; } while(0)
#define COMPARE_INTEGER(ac,bc,e) \
	do { if ((ac)->e != (bc)->e) return 1; } while(0)
#define COMPARE_MEM(ac,bc,e,len) \
	do { if (memcmp((ac)->e, (bc)->e,len) != 0) return 1; } while(0)

static int
cmp_Principal (void *a, void *b)
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
	  "0\e \0200\016 \003\002\001\001¡\a0\005\e\003"
	  "lha¡\a\e\005SU.SE" 
	},
	{ NULL, 35,
	  "0! \0260\024 \003\002\001\001¡\r0\013\e\003"
	  "lha\e\004root¡\a\e\005SU.SE"
	},
	{ NULL, 54, 
	  "04 &0$ \003\002\001\003¡\0350\e\e\004"
	  "host\e\023nutcracker.e.kth.se¡\n\e\bE.KTH.SE"
	},
    };


    char *lha[] = { "lha" };
    char *lharoot[] = { "lha", "root" };
    char *datan[] = { "host", "nutcracker.e.kth.se" };

    Principal values[] = { 
	{ { KRB5_NT_PRINCIPAL, { 1, lha } },  "SU.SE" },
	{ { KRB5_NT_PRINCIPAL, { 2, lharoot } },  "SU.SE" },
	{ { KRB5_NT_SRV_HST, { 2, datan } },  "E.KTH.SE" }
    };
    int i;
    int ntests = sizeof(tests) / sizeof(*tests);

    for (i = 0; i < ntests; ++i) {
	tests[i].val = &values[i];
	asprintf (&tests[i].name, "Principal %d", i);
    }

    return generic_test (tests, ntests, sizeof(int),
			 (generic_encode)encode_Principal,
			 (generic_length)length_Principal,
			 (generic_decode)decode_Principal,
			 cmp_Principal);
}

int
main(int argc, char **argv)
{
    int ret = 0;

    ret += test_principal ();

    return ret;
}
