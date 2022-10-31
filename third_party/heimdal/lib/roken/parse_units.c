/*
 * Copyright (c) 1997 - 2001 Kungliga Tekniska Högskolan
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "roken.h"
#include "parse_units.h"

/*
 * Parse string in `s' according to `units' and return value.
 * def_unit defines the default unit.
 */

static int64_t
parse_something_signed(const char *s, const struct units *units,
                       const char *def_unit,
                       int64_t (*func)(int64_t res, int64_t val, uint64_t mult),
                       int64_t init,
                       int accept_no_val_p)
{
    const char *p;
    int64_t res = init;
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
	int64_t val;
	char *next;
	const struct units *u, *partial_unit;
	size_t u_len;
	unsigned partial;
	int no_val_p = 0;

	while (isspace((unsigned char)*p) || *p == ',')
	    ++p;

	val = strtoll(p, &next, 0);
	if (p == next) {
	    val = 0;
	    if(!accept_no_val_p)
		return -1;
	    no_val_p = 1;
	}
	p = next;
	while (isspace((unsigned char)*p))
	    ++p;
	if (*p == '\0') {
	    res = (*func)(res, val, def_mult);
	    if (res < 0)
		return res;
	    break;
	} else if (*p == '+') {
	    ++p;
	    val = 1;
	} else if (*p == '-') {
	    ++p;
	    val = -1;
	}
	if (no_val_p && val == 0)
	    val = 1;
	u_len = strcspn (p, ", \t");
	partial = 0;
	partial_unit = NULL;
	if (u_len > 1 && p[u_len - 1] == 's')
	    --u_len;
	for (u = units; u->name; ++u) {
	    if (strncasecmp (p, u->name, u_len) == 0) {
		if (u_len == strlen (u->name)) {
		    p += u_len;
		    res = (*func)(res, val, u->mult);
		    if (res < 0)
			return res;
		    break;
		} else {
		    ++partial;
		    partial_unit = u;
		}
	    }
	}
	if (u->name == NULL) {
	    if (partial == 1) {
		p += u_len;
		res = (*func)(res, val, partial_unit->mult);
		if (res < 0)
		    return res;
	    } else {
		return -1;
	    }
	}
	if (*p == 's')
	    ++p;
	while (isspace((unsigned char)*p))
	    ++p;
    }
    return res;
}

static uint64_t
parse_something_unsigned(const char *s, const struct units *units,
                         const char *def_unit,
                         uint64_t (*func)(uint64_t res, int64_t val, uint64_t mult),
                         uint64_t init,
                         int accept_no_val_p)
{
    const char *p;
    int64_t res = init;
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
	int64_t val;
	char *next;
	const struct units *u, *partial_unit;
	size_t u_len;
	unsigned partial;
	int no_val_p = 0;

	while (isspace((unsigned char)*p) || *p == ',')
	    ++p;

	val = strtoll(p, &next, 0);
	if (p == next) {
	    val = 0;
	    if(!accept_no_val_p)
		return -1;
	    no_val_p = 1;
	}
	p = next;
	while (isspace((unsigned char)*p))
	    ++p;
	if (*p == '\0') {
	    res = (*func)(res, val, def_mult);
	    if (res < 0)
		return res;
	    break;
	} else if (*p == '+') {
	    ++p;
	    val = 1;
	} else if (*p == '-') {
	    ++p;
	    val = -1;
	}
	if (no_val_p && val == 0)
	    val = 1;
	u_len = strcspn (p, ", \t");
	partial = 0;
	partial_unit = NULL;
	if (u_len > 1 && p[u_len - 1] == 's')
	    --u_len;
	for (u = units; u->name; ++u) {
	    if (strncasecmp (p, u->name, u_len) == 0) {
		if (u_len == strlen (u->name)) {
		    p += u_len;
		    res = (*func)(res, val, u->mult);
		    if (res < 0)
			return res;
		    break;
		} else {
		    ++partial;
		    partial_unit = u;
		}
	    }
	}
	if (u->name == NULL) {
	    if (partial == 1) {
		p += u_len;
		res = (*func)(res, val, partial_unit->mult);
		if (res < 0)
		    return res;
	    } else {
		return -1;
	    }
	}
	if (*p == 's')
	    ++p;
	while (isspace((unsigned char)*p))
	    ++p;
    }
    return res;
}

/*
 * The string consists of a sequence of `n unit'
 */

static int64_t
acc_units(int64_t res, int64_t val, uint64_t mult)
{
    return res + val * mult;
}

ROKEN_LIB_FUNCTION int64_t ROKEN_LIB_CALL
parse_units (const char *s, const struct units *units,
	     const char *def_unit)
{
    return parse_something_signed(s, units, def_unit, acc_units, 0, 0);
}

/*
 * The string consists of a sequence of `[+-]flag'.  `orig' consists
 * the original set of flags, those are then modified and returned as
 * the function value.
 */

static uint64_t
acc_flags(uint64_t res, int64_t val, uint64_t mult)
{
    if(val == 1)
	return res | mult;
    else if(val == -1)
	return res & ~mult;
    else if (val == 0)
	return mult;
    else
	return -1;
}

ROKEN_LIB_FUNCTION uint64_t ROKEN_LIB_CALL
parse_flags(const char *s, const struct units *units, uint64_t orig)
{
    return parse_something_unsigned (s, units, NULL, acc_flags, orig, 1);
}

/*
 * Return a string representation according to `units' of `num' in `s'
 * with maximum length `len'.  The actual length is the function value.
 */

static int
unparse_something_signed(int64_t num, const struct units *units, char *s,
                         size_t len,
                         int64_t (*get_divisor)(int64_t, uint64_t),
                         int (*print)(char *, size_t, int64_t, const char *, int64_t),
                         int64_t (*update)(int64_t, uint64_t),
                         const char *zero_string)
{
    const struct units *u;
    int ret = 0, tmp;

    if (num == 0)
	return snprintf (s, len, "%s", zero_string);
    if (len)
        s[0] = '\0';
    if (num < 0)
        return -1;

    for (u = units; num > 0 && u->name; ++u) {
	long long divisor = get_divisor(num, u->mult);

	if (divisor) {
	    num = (*update)(num, u->mult);
	    tmp = (*print)(s, len, divisor, u->name, num);
	    if (tmp < 0)
		return tmp;
	    if ((size_t)tmp > len) {
		len = 0;
		s = NULL;
	    } else {
		len -= tmp;
		s += tmp;
	    }
	    ret += tmp;
	}
    }
    return ret;
}

static int
unparse_something_unsigned(uint64_t num, const struct units *units, char *s,
                           size_t len,
                           uint64_t (*get_divisor)(uint64_t, uint64_t),
                           int (*print)(char *, size_t, uint64_t, const char *, uint64_t),
                           uint64_t (*update)(uint64_t, uint64_t),
                           const char *zero_string)
{
    const struct units *u;
    int64_t tmp;
    int ret = 0;

    if (num == 0)
	return snprintf (s, len, "%s", zero_string);
    if (len)
        s[0] = '\0';

    for (u = units; num > 0 && u->name; ++u) {
	long long divisor = get_divisor(num, u->mult);

	if (divisor) {
	    num = (*update) (num, u->mult);
	    tmp = (*print) (s, len, divisor, u->name, num);
	    if (tmp < 0)
		return tmp;
	    if ((size_t)tmp > len) {
		len = 0;
		s = NULL;
	    } else {
		len -= tmp;
		s += tmp;
	    }
	    ret += tmp;
	}
    }
    return ret;
}

static int
print_unit(char *s, size_t len, int64_t divisor, const char *name, int64_t rem)
{
    return snprintf(s, len, "%lld %s%s%s", (long long)divisor, name,
		    divisor == 1 ? "" : "s", rem > 0 ? " " : "");
}

static int64_t
get_divisor_unit(int64_t in, uint64_t mult)
{
    return in / mult;
}

static int64_t
update_unit(int64_t in, uint64_t mult)
{
    return in % mult;
}

static int64_t
update_unit_approx(int64_t in, uint64_t mult)
{
    if (in / mult > 0)
	return 0;
    else
	return update_unit (in, mult);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unparse_units(int64_t num, const struct units *units, char *s, size_t len)
{
    return unparse_something_signed(num, units, s, len,
                                    get_divisor_unit, print_unit, update_unit,
                                    "0");
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unparse_units_approx(int64_t num, const struct units *units, char *s, size_t len)
{
    return unparse_something_signed(num, units, s, len, get_divisor_unit,
                                    print_unit, update_unit_approx, "0");
}

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
print_units_table (const struct units *units, FILE *f)
{
    const struct units *u, *u2;
    size_t max_sz = 0;

    for (u = units; u->name; ++u) {
	max_sz = max(max_sz, strlen(u->name));
    }

    for (u = units; u->name;) {
	char buf[1024];
	const struct units *next;

	for (next = u + 1; next->name && next->mult == u->mult; ++next)
	    ;

	if (next->name) {
	    for (u2 = next;
		 u2->name && u->mult % u2->mult != 0;
		 ++u2)
		;
	    if (u2->name == NULL)
		--u2;
	    unparse_units (u->mult, u2, buf, sizeof(buf));
	    fprintf (f, "1 %*s = %s\n", (int)max_sz, u->name, buf);
	} else {
	    fprintf (f, "1 %s\n", u->name);
	}
	u = next;
    }
}

static uint64_t
get_divisor_flag(uint64_t in, uint64_t mult)
{
    return in & mult;
}

static int
print_flag(char *s, size_t len, uint64_t divisor, const char *name, uint64_t rem)
{
    return snprintf (s, len, "%s%s", name, rem > 0 ? ", " : "");
}

static uint64_t
update_flag(uint64_t in, uint64_t mult)
{
    return in & ~mult;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unparse_flags (uint64_t num, const struct units *units, char *s, size_t len)
{
    return unparse_something_unsigned(num, units, s, len, get_divisor_flag,
                                      print_flag, update_flag, "");
}

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
print_flags_table (const struct units *units, FILE *f)
{
    const struct units *u;

    for(u = units; u->name; ++u)
	fprintf(f, "%s%s", u->name, (u+1)->name ? ", " : "\n");
}

#undef parse_units
#undef unparse_units
#undef unparse_units_approx
#undef print_units_table
#undef parse_flags
#undef unparse_flags
#undef print_flags_table

ROKEN_LIB_FUNCTION int64_t ROKEN_LIB_CALL
parse_units(const char *s, const struct units *units,
	     const char *def_unit)
{
    return rk_parse_units(s, units, def_unit);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unparse_units(int64_t num, const struct units *units, char *s, size_t len)
{
    return rk_unparse_units(num, units, s, len);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unparse_units_approx(int64_t num, const struct units *units, char *s, size_t len)
{
    return rk_unparse_units_approx(num, units, s, len);
}

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
print_units_table(const struct units *units, FILE *f)
{
    rk_print_units_table(units, f);
}

ROKEN_LIB_FUNCTION uint64_t ROKEN_LIB_CALL
parse_flags(const char *s, const struct units *units, int orig)
{
    return rk_parse_flags(s, units, orig);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unparse_flags(uint64_t num, const struct units *units, char *s, size_t len)
{
    return rk_unparse_flags(num, units, s, len);
}

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
print_flags_table (const struct units *units, FILE *f)
{
    rk_print_flags_table(units, f);
}
