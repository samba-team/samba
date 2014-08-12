/*
 * Trivial smb.conf parsing code
 *
 * Copyright Volker Lendecke <vl@samba.org> 2014
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License Version 3 or later, in which case the
 * provisions of the GPL are required INSTEAD OF the above restrictions.
 * (This clause is necessary due to a potential bad interaction between the
 * GPL and the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include "tini.h"

static int next_content(FILE *f)
{
	int c;

	for (c = fgetc(f); c != EOF; c = fgetc(f)) {
		if (!isspace(c)) {
			break;
		}
		if (c == '\n') {
			break;
		}
	}

	return c;
}

static int next_end_of_line(FILE *f)
{
	int c;

	for (c = fgetc(f); c != EOF; c = fgetc(f)) {
		if (c == '\n') {
			break;
		}
	}
	return c;
}

static bool make_space(char **buf, size_t *buflen, size_t position)
{
	char *tmp;

	if (position < *buflen) {
		return true;
	}
	tmp = realloc(*buf, (*buflen) * 2);
	if (tmp == NULL) {
		return false;
	}
	*buf = tmp;
	*buflen *= 2;
	return true;
}

/*
 * Get a conf line into *pbuf (which must be a malloc'ed buffer already).
 *
 * Ignores leading spaces
 * Ignores comment lines
 * Ignores empty lines
 * Takes care of continuation lines
 * Zaps multiple spaces into one
 */

static int get_line(FILE *f, char **pbuf, size_t *pbuflen)
{
	int c;
	char *buf;
	size_t buflen, pos;

	buf = *pbuf;
	buflen = *pbuflen;
	pos = 0;

next_line:

	c = next_content(f);
	if (c == EOF) {
		return ENOENT;
	}

	if ((c == '#') || (c == ';')) {
		/*
		 * Line starting with a comment, skip
		 */
		c = next_end_of_line(f);
		if (c == EOF) {
			return ENOENT;
		}
		goto next_line;
	}

	if (c == '\n') {
		/*
		 * Blank line, skip
		 */
		goto next_line;
	}

	for ( ; c != EOF ; c = fgetc(f)) {

		if (c == '\n') {

			if ((pos > 0) && (buf[pos-1] == '\\')) {
				/*
				 * Line ends in "\". Continuation.
				 */
				pos -= 1;
				continue;
			}

			if ((pos > 1) && (buf[pos-2] == '\\') &&
			    isspace(buf[pos-1])) {
				/*
				 * Line ends in "\ ". Mind that we zap
				 * multiple spaces into one. Continuation.
				 */
				pos -= 2;
				continue;
			}

			/*
			 * No continuation, done with the line
			 */
			break;
		}

		if ((pos > 0) && isspace(buf[pos-1]) && isspace(c)) {
			/*
			 * Zap multiple spaces to one
			 */
			continue;
		}

		if (!make_space(&buf, &buflen, pos)) {
			return ENOMEM;
		}
		buf[pos++] = c;
	}

	if (!make_space(&buf, &buflen, pos)) {
		return ENOMEM;
	}
	buf[pos++] = '\0';

	*pbuf = buf;
	return 0;
}

static bool parse_section(
	char *buf, bool (*sfunc)(const char *section, void *private_data),
	void *private_data)
{
	char *p, *q;

	p = buf+1; 		/* skip [ */

	q = strchr(p, ']');
	if (q == NULL) {
		return false;
	}
	*q = '\0';

	return sfunc(p, private_data);
}

static char *trim_one_space(char *buf)
{
	size_t len;

	if (isspace(buf[0])) {
		buf += 1;
	}
	len = strlen(buf);
	if (len == 0) {
		return buf;
	}
	if (isspace(buf[len-1])) {
		buf[len-1] = '\0';
	}

	return buf;
}

static bool parse_param(char *buf,
			bool (*pfunc)(const char *name, const char *value,
				      void *private_data),
			void *private_data)
{
	char *equals;
	char *name, *value;
	size_t len;

	equals = strchr(buf, '=');
	if (equals == NULL) {
		return true;
	}
	*equals = '\0';

	name = trim_one_space(buf);
	len = strlen(buf);
	if (len == 0) {
		return false;
	}

	value = trim_one_space(equals+1);

	return pfunc(name, value, private_data);
}

bool tini_parse(FILE *f,
		bool (*sfunc)(const char *section, void *private_data),
		bool (*pfunc)(const char *name, const char *value,
			      void *private_data),
		void *private_data)
{
	char *buf;
	size_t buflen;

	buflen = 256;

	buf = malloc(buflen);
	if (buf == NULL) {
		return false;
	}

	while (true) {
		int ret;
		bool ok;

		ret = get_line(f, &buf, &buflen);

		if (ret == ENOENT) {
			/* No lines anymore */
			break;
		}

		if (ret != 0) {
			/* Real error */
			free(buf);
			return false;
		}

		switch(buf[0]) {
		case 0:
			continue;
			break;
		case '[':
			ok = parse_section(buf, sfunc, private_data);
			break;
		default:
			ok = parse_param(buf, pfunc, private_data);
			break;
		}

		if (!ok) {
			free(buf);
			return false;
		}
	}
	free(buf);
	return true;
}
