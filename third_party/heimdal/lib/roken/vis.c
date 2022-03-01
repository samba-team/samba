/*	$NetBSD: vis.c,v 1.37 2008/07/25 22:29:23 dsl Exp $	*/

/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*-
 * Copyright (c) 1999, 2005 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define _DEFAULT_SOURCE
#include <config.h>
#include "roken.h"
#ifdef TEST
#include "getarg.h"
#endif
#ifndef _DIAGASSERT
#define _DIAGASSERT(X)
#endif

#include <sys/types.h>
#include <assert.h>
#include <ctype.h>
#ifdef TEST
#include <err.h>
#endif
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vis.h>

#if !HAVE_VIS || !HAVE_SVIS
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#endif

#if !HAVE_VIS || !HAVE_SVIS || TEST
/*
 * We use makextralist() in main(), so we need it even if we have all the VIS
 * routines in the host's C libraries.
 */

/* 5 is for VIS_SP, VIS_TAB, VIS_NL, VIS_DQ, and VIS_NOSLASH */
#define MAXEXTRAS	(sizeof(char_glob) - 1 + sizeof(char_shell) - 1 + 5)

#ifndef VIS_SHELL
#define VIS_SHELL       0x2000
#endif
#ifndef VIS_GLOB
#define VIS_GLOB        0x0100
#endif

#ifndef VIS_SP
#define VIS_SP          0x0004  /* also encode space */
#endif
#ifndef VIS_TAB
#define VIS_TAB         0x0008  /* also encode tab */
#endif
#ifndef VIS_NL
#define VIS_NL          0x0010  /* also encode newline */
#endif
#ifndef VIS_WHITE
#define VIS_WHITE       (VIS_SP | VIS_TAB | VIS_NL)
#endif
#ifndef VIS_SAFE
#define VIS_SAFE        0x0020  /* only encode "unsafe" characters */
#endif
#ifndef VIS_DQ
#define VIS_DQ          0x8000  /* also encode double quotes */
#endif


/*
 * Expand list of extra characters to not visually encode.
 */
static char *
makeextralist(int flags, const char *src)
{
    static const char char_glob[] = "*?[#";
    static const char char_shell[] = "'`\";&<>()|{}]\\$!^~";
    char *dst, *d;
    size_t len;

    len = strlen(src);
    if ((dst = d = calloc(1, len + MAXEXTRAS + 1)) == NULL)
        return NULL;

    memcpy(dst, src, len);
    d += len;

    if (flags & VIS_GLOB) {
        memcpy(d, char_glob, sizeof(char_glob) - 1);
        d += sizeof(char_glob) - 1;
    }
    if (flags & VIS_SHELL) {
        memcpy(d, char_shell, sizeof(char_shell) - 1);
        d += sizeof(char_shell) - 1;
    }

    if (flags & VIS_SP) *d++ = ' ';
    if (flags & VIS_TAB) *d++ = '\t';
    if (flags & VIS_NL) *d++ = '\n';
    if (flags & VIS_DQ) *d++ = '"';
    if ((flags & VIS_NOSLASH) == 0) *d++ = '\\';

    return dst;
}
#endif

#if !HAVE_VIS || !HAVE_SVIS
static char *do_svis(char *, int, int, int, const char *);

#undef BELL
#if defined(__STDC__)
#define BELL '\a'
#else
#define BELL '\007'
#endif

ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
	rk_vis (char *, int, int, int);
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
	rk_svis (char *, int, int, int, const char *);
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
	rk_strvis (char *, const char *, int);
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
	rk_strsvis (char *, const char *, int, const char *);
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
	rk_strvisx (char *, const char *, size_t, int);
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
	rk_strsvisx (char *, const char *, size_t, int, const char *);

#define isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#define iswhite(c)	(c == ' ' || c == '\t' || c == '\n')
#define issafe(c)	(c == '\b' || c == BELL || c == '\r')
#define xtoa(c)		"0123456789abcdef"[c]

/*
 * This is do_hvis, for HTTP style (RFC 1808)
 */
static char *
do_hvis(char *dst, int c, int flag, int nextc, const char *extra)
{
	if (!isascii(c) || !isalnum(c) || strchr("$-_.+!*'(),", c) != NULL ||
            strchr(extra, c)) {
		*dst++ = '%';
		*dst++ = xtoa(((unsigned int)c >> 4) & 0xf);
		*dst++ = xtoa((unsigned int)c & 0xf);
	} else {
		dst = do_svis(dst, c, flag, nextc, extra);
	}
	return dst;
}

/*
 * This is do_vis, the central code of vis.
 * dst:	      Pointer to the destination buffer
 * c:	      Character to encode
 * flag:      Flag word
 * nextc:     The character following 'c'
 * extra:     Pointer to the list of extra characters to be
 *	      backslash-protected.
 */
static char *
do_svis(char *dst, int c, int flag, int nextc, const char *extra)
{
	int isextra;
	isextra = strchr(extra, c) != NULL;
	if (!isextra && isascii(c) && (isgraph(c) || iswhite(c) ||
	    ((flag & VIS_SAFE) && issafe(c)))) {
		*dst++ = c;
		return dst;
	}
	if (flag & VIS_CSTYLE) {
		switch (c) {
		case '\n':
			*dst++ = '\\'; *dst++ = 'n';
			return dst;
		case '\r':
			*dst++ = '\\'; *dst++ = 'r';
			return dst;
		case '\b':
			*dst++ = '\\'; *dst++ = 'b';
			return dst;
		case BELL:
			*dst++ = '\\'; *dst++ = 'a';
			return dst;
		case '\v':
			*dst++ = '\\'; *dst++ = 'v';
			return dst;
		case '\t':
			*dst++ = '\\'; *dst++ = 't';
			return dst;
		case '\f':
			*dst++ = '\\'; *dst++ = 'f';
			return dst;
		case ' ':
			*dst++ = '\\'; *dst++ = 's';
			return dst;
		case '\0':
			*dst++ = '\\'; *dst++ = '0';
			if (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			return dst;
		default:
			if (isgraph(c)) {
				*dst++ = '\\'; *dst++ = c;
				return dst;
			}
		}
	}
	if (isextra || ((c & 0177) == ' ') || (flag & VIS_OCTAL)) {
		*dst++ = '\\';
		*dst++ = (u_char)(((unsigned int)(u_char)c >> 6) & 03) + '0';
		*dst++ = (u_char)(((unsigned int)(u_char)c >> 3) & 07) + '0';
		*dst++ = (u_char)(			 c       & 07) + '0';
	} else {
		if ((flag & VIS_NOSLASH) == 0) *dst++ = '\\';
		if (c & 0200) {
			c &= 0177; *dst++ = 'M';
		}
		if (iscntrl(c)) {
			*dst++ = '^';
			if (c == 0177)
				*dst++ = '?';
			else
				*dst++ = c + '@';
		} else {
			*dst++ = '-'; *dst++ = c;
		}
	}
	return dst;
}


/*
 * svis - visually encode characters, also encoding the characters
 *	  pointed to by `extra'
 */
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
rk_svis(char *dst, int c, int flag, int nextc, const char *extra)
{
	char *nextra = NULL;

	_DIAGASSERT(dst != NULL);
	_DIAGASSERT(extra != NULL);
	nextra = makeextralist(flag, extra);
	if (!nextra) {
		*dst = '\0';		/* can't create nextra, return "" */
		return dst;
	}
	if (flag & VIS_HTTPSTYLE)
		dst = do_hvis(dst, c, flag, nextc, nextra);
	else
		dst = do_svis(dst, c, flag, nextc, nextra);
	free(nextra);
	*dst = '\0';
	return dst;
}


/*
 * strsvis, strsvisx - visually encode characters from src into dst
 *
 *	Extra is a pointer to a \0-terminated list of characters to
 *	be encoded, too. These functions are useful e. g. to
 *	encode strings in such a way so that they are not interpreted
 *	by a shell.
 *
 *	Dst must be 4 times the size of src to account for possible
 *	expansion.  The length of dst, not including the trailing NULL,
 *	is returned.
 *
 *	Strsvisx encodes exactly len bytes from src into dst.
 *	This is useful for encoding a block of data.
 */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_strsvis(char *dst, const char *csrc, int flag, const char *extra)
{
	int c;
	char *start;
	char *nextra = NULL;
	const unsigned char *src = (const unsigned char *)csrc;

	_DIAGASSERT(dst != NULL);
	_DIAGASSERT(src != NULL);
	_DIAGASSERT(extra != NULL);
	nextra = makeextralist(flag, extra);
	if (!nextra) {
		*dst = '\0';		/* can't create nextra, return "" */
		return 0;
	}
	if (flag & VIS_HTTPSTYLE) {
		for (start = dst; (c = *src++) != '\0'; /* empty */)
			dst = do_hvis(dst, c, flag, *src, nextra);
	} else {
		for (start = dst; (c = *src++) != '\0'; /* empty */)
			dst = do_svis(dst, c, flag, *src, nextra);
	}
	free(nextra);
	*dst = '\0';
	return (dst - start);
}


ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_strsvisx(char *dst, const char *csrc, size_t len, int flag, const char *extra)
{
	unsigned char c;
	char *start;
	char *nextra = NULL;
	const unsigned char *src = (const unsigned char *)csrc;

	_DIAGASSERT(dst != NULL);
	_DIAGASSERT(src != NULL);
	_DIAGASSERT(extra != NULL);
	nextra = makeextralist(flag, extra);
	if (! nextra) {
		*dst = '\0';		/* can't create nextra, return "" */
		return 0;
	}

	if (flag & VIS_HTTPSTYLE) {
		for (start = dst; len > 0; len--) {
			c = *src++;
			dst = do_hvis(dst, c, flag, *src, nextra);
		}
	} else {
		for (start = dst; len > 0; len--) {
			c = *src++;
			dst = do_svis(dst, c, flag, *src, nextra);
		}
	}
	free(nextra);
	*dst = '\0';
	return (dst - start);
}
#endif

/*
 * Heimdal innovations: functions that allocate or reallocate a destination
 * buffer as needed.  Based on OpenBSD's stravis().
 */

#include <vis-extras.h>

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_strasvis(char **out, const char *csrc, int flag, const char *extra)
{
	return rk_strasvisx(out, csrc, strlen(csrc), flag, extra);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_strrasvis(char **out, size_t *outsz, const char *csrc, int flag, const char *extra)
{
	return rk_strrasvisx(out, outsz, csrc, strlen(csrc), flag, extra);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_strasvisx(char **out, const char *csrc, size_t len, int flag, const char *extra)
{
	size_t sz = 0;

	*out = NULL;
	return rk_strrasvisx(out, &sz, csrc, strlen(csrc), flag, extra);
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_strrasvisx(char **out,
	      size_t *outsz,
	      const char *csrc,
	      size_t len,
	      int flag,
	      const char *extra)
{
	size_t want = 4 * len + 4;
	size_t have = *outsz;
	char *s = *out;
	int r;

	_DIAGASSERT(dst != NULL);
	_DIAGASSERT(src != NULL);
	_DIAGASSERT(extra != NULL);
	if (want < len || want > INT_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	if (have < want) {
		if ((s = realloc(s, want)) == NULL)
			return -1;
		*outsz = want;
		*out = s;
	}
        if (*out == NULL) {
            errno = EINVAL;
            return -1;
        }
	**out = '\0'; /* Makes source debugging nicer, that's all */
	r = strsvisx(*out, csrc, len, flag, extra);
        return r;
}

#if !HAVE_VIS
/*
 * vis - visually encode characters
 */
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
rk_vis(char *dst, int c, int flag, int nextc)
{
	char *extra = NULL;
	unsigned char uc = (unsigned char)c;

	_DIAGASSERT(dst != NULL);

	extra = makeextralist(flag, "");
	if (! extra) {
		*dst = '\0';		/* can't create extra, return "" */
		return dst;
	}
	if (flag & VIS_HTTPSTYLE)
		dst = do_hvis(dst, uc, flag, nextc, extra);
	else
		dst = do_svis(dst, uc, flag, nextc, extra);
	free(extra);
	*dst = '\0';
	return dst;
}


/*
 * strvis, strvisx - visually encode characters from src into dst
 *
 *	Dst must be 4 times the size of src to account for possible
 *	expansion.  The length of dst, not including the trailing NULL,
 *	is returned.
 *
 *	Strvisx encodes exactly len bytes from src into dst.
 *	This is useful for encoding a block of data.
 */
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_strvis(char *dst, const char *src, int flag)
{
	char *extra = NULL;
	int rv;

	extra = makeextralist(flag, "");
	if (!extra) {
		*dst = '\0';		/* can't create extra, return "" */
		return 0;
	}
	rv = strsvis(dst, src, flag, extra);
	free(extra);
	return rv;
}


ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_strvisx(char *dst, const char *src, size_t len, int flag)
{
	char *extra = NULL;
	int rv;

	extra = makeextralist(flag, "");
	if (!extra) {
		*dst = '\0';		/* can't create extra, return "" */
		return 0;
	}
	rv = strsvisx(dst, src, len, flag, extra);
	free(extra);
	return rv;
}
#endif

#ifdef TEST
static const char *extra_arg = "";
static int cstyle_flag;
static int glob_flag;
static int help_flag;
static int http_flag;
static int httponly_flag;
static int line_flag;
static int octal_flag;
static int safe_flag;
static int shell_flag;
static int stdin_flag;
static int tab_flag;
static int whitespace_flag;

/*
 * The short options are compatible with a subset of the FreeBSD contrib
 * vis(1).  Heimdal additions have long option names only.
 */
static struct getargs args[] = {
    { "c", 'C', arg_flag, &cstyle_flag, "C style", "C style" },
    { "extra", 'e', arg_string, &extra_arg, "also encode extra", "also encode extra"},
    { "glob", 'g', arg_flag, &glob_flag, "escape glob specials", "escape glob specials" },
    { "help", 0, arg_flag, &help_flag, "help", "help"},
    { "line", 0, arg_flag, &line_flag, "read and escape stdin without escaping newlines", NULL },
    { "octal", 'o', arg_flag, &octal_flag, "octal escape", "octal escape" },
    { "safe", 's', arg_flag, &safe_flag, "only encode \"unsafe\" characters", "only encode \"unsafe\" characters" },
    { "shell", 'S', arg_flag, &shell_flag, "encode shell meta-characters", "encode shell meta-characters" },
    { "stdin", 0, arg_flag, &stdin_flag, "read and escape stdin", NULL },
    { "tab", 't', arg_flag, &tab_flag, "encode tabs", "encode tabs" },
    { "url", 'h', arg_flag, &http_flag, "url escape", "url escape" },
    { "url-only", 0, arg_flag, &httponly_flag, "url escape", "url escape" },
    { "whitespace", 'w', arg_flag, &whitespace_flag, "encode whitespace", "encode whitespace" },
    { 0, 0, 0, 0, 0, 0}
};
static size_t num_args = sizeof(args)/sizeof(args[0]);

int
main(int argc, char **argv)
{
    size_t sz = 0;
    char *nextra = NULL;
    char *s = NULL;
    int goptind = 0;
    int flags = 0;

    setprogname("vis");
    if (getarg(args, num_args, argc, argv, &goptind) || help_flag) {
        arg_printusage(args, num_args, NULL, "strings...");
        return help_flag ? 0 : 1;
    }

    argc -= goptind;
    argv += goptind;

    if (argc == 0 && !stdin_flag && !line_flag) {
        arg_printusage(args, num_args, NULL, "strings...");
        return 1;
    }

    if (http_flag && cstyle_flag)
        errx(1, "--http and --cstyle are mutually exclusive");

    flags |= cstyle_flag ? VIS_CSTYLE : 0;
    flags |= http_flag ? VIS_HTTPSTYLE : 0;
    flags |= httponly_flag ? VIS_HTTPSTYLE | VIS_NOESCAPE : 0;
    flags |= octal_flag ? VIS_OCTAL : 0;
    flags |= safe_flag ? VIS_SAFE : 0;
    flags |= tab_flag ? VIS_TAB : 0;
    flags |= whitespace_flag ? VIS_WHITE : 0;

    if ((nextra = makeextralist(flags, extra_arg)) == NULL)
        err(1, "Out of memory");

    while (argc) {
	if (rk_strrasvis(&s, &sz, argv[0], flags, nextra) < 0)
		err(2, "Out of memory");
        printf("%s\n", s);
        argc--;
    }
    if (line_flag) {
        ssize_t nbytes;
        size_t linesz = 0;
        char *line = NULL;

        while (!feof(stdin) &&
               (nbytes = getline(&line, &linesz, stdin)) > 0) {
            const char *nl = "";

            if (line[nbytes - 1] == '\n') {
                line[--nbytes] = '\0';
                nl = "\n";
            }

	    if (rk_strrasvisx(&s, &sz, line, nbytes, flags, nextra) < 0)
		err(2, "Out of memory");
            printf("%s%s", s, nl);
        }
        fflush(stdout);
        if (ferror(stdin))
            errx(2, "I/O error");
    } else if (stdin_flag) {
        size_t nbytes;
        char buf[2048 + 1];
        char vbuf[4 * (sizeof(buf) - 1) + 1];

        while (!feof(stdin) &&
               (nbytes = fread(buf, 1, sizeof(buf) - 1, stdin))) {
            buf[nbytes] = '\0';
            strsvis(vbuf, buf, flags, nextra);
            printf("%s", vbuf);
        }
        fflush(stdout);
        if (ferror(stdin))
            errx(2, "I/O error");
    }

    free(nextra);
    free(s);
    return 0;
}
#endif
