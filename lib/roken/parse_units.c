/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
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
RCSID("$Id$");
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <roken.h>
#include "parse_units.h"

/*
 * Parse string in `s' according to `units' and return value.
 * def_unit defines the default unit.
 */

int
parse_units (const char *s, const struct units *units,
	     const char *def_unit)
{
    const char *p;
    int res = 0;
    int val;
    unsigned def_mult = 1;

    if (def_unit != NULL) {
	const struct units *u;

	for (u = units; u->name; ++u) {
	    if (strcasecmp (u->name, def_unit) == 0) {
		def_mult = u->mult;
		break;
	    }
	}
	if (u->name == NULL)
	    return -1;
    }

    p = s;
    while (*p) {
	double val;
	char *next;
	const struct units *u, *partial_unit;
	size_t u_len;
	unsigned partial;

	val = strtod (p, &next); /* strtol(p, &next, 0); */
	if (val == 0 && p == next)
	    return -1;
	p = next;
	while (isspace(*p))
	    ++p;
	if (*p == '\0') {
	    res += val * def_mult;
	    break;
	}
	u_len = strcspn (p, "0123456789 \t");
	partial = NULL;
	partial = 0;
	if (u_len > 1 && p[u_len - 1] == 's')
	    --u_len;
	for (u = units; u->name; ++u) {
	    if (strncasecmp (p, u->name, u_len) == 0) {
		if (u_len == strlen (u->name)) {
		    p += u_len;
		    res += val * u->mult;
		    break;
		} else {
		    ++partial;
		    partial_unit = u;
		}
	    }
	}
	if (u->name == NULL)
	    if (partial == 1) {
		p += u_len;
		res += val * partial_unit->mult;
	    } else {
		return -1;
	    }
	if (*p == 's')
	    ++p;
    }
    return res;
}

/*
 * Return a string representation according to `units' of `num' in `s'
 * with maximum length `len'.
 */

size_t
unparse_units (int num, const struct units *units, char *s, size_t len)
{
    const struct units *u;
    size_t ret = 0, tmp;

    if (num == 0)
	return snprintf (s, len, "%u", 0);

    for (u = units; num > 0 && u->name; ++u) {
	int div;

	div = num / u->mult;
	if (div) {
	    num %= u->mult;
	    tmp = snprintf (s, len, "%u %s%s%s", div, u->name,
			    div == 1 ? "" : "s",
			    num > 0 ? " " : "");
	    len -= tmp;
	    s += tmp;
	    ret += tmp;
	}
    }
    return ret;
}
