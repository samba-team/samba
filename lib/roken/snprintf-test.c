/*
 * Copyright (c) 2000 - 2001 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "roken.h"

RCSID("$Id$");

static int
try (const char *format, ...)
{
    int ret;
    va_list ap;
    char buf1[256], buf2[256];

    va_start (ap, format);
    ret = vsnprintf (buf1, sizeof(buf1), format, ap);
    if (ret >= sizeof(buf1))
	errx (1, "increase buf and try again");
    vsprintf (buf2, format, ap);
    ret = strcmp (buf1, buf2);
    if (ret)
	printf ("failed: format = \"%s\", \"%s\" != \"%s\"\n",
		format, buf1, buf2);
    va_end (ap);
    return ret;
}

static int
cmp_with_sprintf_int (void)
{
    int tot = 0;
    int int_values[] = {INT_MIN, -17, -1, 0, 1, 17, 4711, 65535, INT_MAX};
    int i;

    for (i = 0; i < sizeof(int_values) / sizeof(int_values[0]); ++i) {
	tot += try ("%d", int_values[i]);
	tot += try ("%x", int_values[i]);
	tot += try ("%o", int_values[i]);
	tot += try ("%#x", int_values[i]);
	tot += try ("%#X", int_values[i]);
	tot += try ("%#o", int_values[i]);
	tot += try ("%10d", int_values[i]);
	tot += try ("%10x", int_values[i]);
	tot += try ("%10o", int_values[i]);
	tot += try ("%#10x", int_values[i]);
	tot += try ("%#10X", int_values[i]);
	tot += try ("%#10o", int_values[i]);
	tot += try ("%-10d", int_values[i]);
	tot += try ("%-10x", int_values[i]);
	tot += try ("%-10o", int_values[i]);
	tot += try ("%-#10x", int_values[i]);
	tot += try ("%-#10X", int_values[i]);
	tot += try ("%-#10o", int_values[i]);
    }
    return tot;
}

#if 0
static int
cmp_with_sprintf_float (void)
{
    int tot = 0;
    double double_values[] = {-99999, -999, -17.4, -4.3, -3.0, -1.5, -1,
			      0, 0.1, 0.2342374852, 0.2340007,
			      3.1415926, 14.7845, 34.24758, 9999, 9999999};
    int i;

    for (i = 0; i < sizeof(double_values) / sizeof(double_values[0]); ++i) {
	tot += try ("%f", double_values[i]);
	tot += try ("%10f", double_values[i]);
	tot += try ("%.2f", double_values[i]);
	tot += try ("%7.0f", double_values[i]);
	tot += try ("%5.2f", double_values[i]);
	tot += try ("%0f", double_values[i]);
	tot += try ("%#f", double_values[i]);
	tot += try ("%e", double_values[i]);
	tot += try ("%10e", double_values[i]);
	tot += try ("%.2e", double_values[i]);
	tot += try ("%7.0e", double_values[i]);
	tot += try ("%5.2e", double_values[i]);
	tot += try ("%0e", double_values[i]);
	tot += try ("%#e", double_values[i]);
	tot += try ("%E", double_values[i]);
	tot += try ("%10E", double_values[i]);
	tot += try ("%.2E", double_values[i]);
	tot += try ("%7.0E", double_values[i]);
	tot += try ("%5.2E", double_values[i]);
	tot += try ("%0E", double_values[i]);
	tot += try ("%#E", double_values[i]);
	tot += try ("%g", double_values[i]);
	tot += try ("%10g", double_values[i]);
	tot += try ("%.2g", double_values[i]);
	tot += try ("%7.0g", double_values[i]);
	tot += try ("%5.2g", double_values[i]);
	tot += try ("%0g", double_values[i]);
	tot += try ("%#g", double_values[i]);
	tot += try ("%G", double_values[i]);
	tot += try ("%10G", double_values[i]);
	tot += try ("%.2G", double_values[i]);
	tot += try ("%7.0G", double_values[i]);
	tot += try ("%5.2G", double_values[i]);
	tot += try ("%0G", double_values[i]);
	tot += try ("%#G", double_values[i]);
    }
    return tot;
}
#endif

static int
test_null (void)
{
    return snprintf (NULL, 0, "foo") != 3;
}

int
main (int argc, char **argv)
{
    int ret = 0;

    ret += cmp_with_sprintf_int ();
    ret += test_null ();
    return ret;
}
