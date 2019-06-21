/*
 * talloc_report into a string
 *
 * Copyright Volker Lendecke <vl@samba.org> 2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "talloc_report.h"

/*
 * talloc_vasprintf into a buffer that doubles its size. The real string
 * length is maintained in "pstr_len".
 */

static char *talloc_vasprintf_append_largebuf(char *buf, ssize_t *pstr_len,
					      const char *fmt, va_list ap)
					      PRINTF_ATTRIBUTE(3,0);

static char *talloc_vasprintf_append_largebuf(char *buf, ssize_t *pstr_len,
					      const char *fmt, va_list ap)
{
	ssize_t str_len = *pstr_len;
	size_t buflen, needed, space = 0;
	char *start = NULL, *tmpbuf = NULL;
	va_list ap2;
	int printlen;

	if (str_len == -1) {
		return NULL;
	}
	if (buf == NULL) {
		return NULL;
	}
	if (fmt == NULL) {
		return NULL;
	}
	buflen = talloc_get_size(buf);

	if (buflen > (size_t)str_len) {
		start = buf + str_len;
		space = buflen - str_len;
	} else {
		return NULL;
	}

	va_copy(ap2, ap);
	printlen = vsnprintf(start, space, fmt, ap2);
	va_end(ap2);

	if (printlen < 0) {
		goto fail;
	}

	needed = str_len + printlen + 1;

	if (needed > buflen) {
		buflen = MAX(128, buflen);

		while (buflen < needed) {
			buflen *= 2;
		}

		tmpbuf = talloc_realloc(NULL, buf, char, buflen);
		if (tmpbuf == NULL) {
			goto fail;
		}
		buf = tmpbuf;

		va_copy(ap2, ap);
		vsnprintf(buf + str_len, buflen - str_len, fmt, ap2);
		va_end(ap2);
	}
	*pstr_len = (needed - 1);
	return buf;
fail:
	*pstr_len = -1;
	return buf;
}

static char *talloc_asprintf_append_largebuf(char *buf, ssize_t *pstr_len,
					     const char *fmt, ...)
					     PRINTF_ATTRIBUTE(3,4);

static char *talloc_asprintf_append_largebuf(char *buf, ssize_t *pstr_len,
					     const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	buf = talloc_vasprintf_append_largebuf(buf, pstr_len, fmt, ap);
	va_end(ap);
	return buf;
}

struct talloc_report_str_state {
	ssize_t str_len;
	char *s;
};

static void talloc_report_str_helper(const void *ptr, int depth, int max_depth,
				     int is_ref, void *private_data)
{
	struct talloc_report_str_state *state = private_data;
	const char *name = talloc_get_name(ptr);

	if (ptr == state->s) {
		return;
	}

	if (is_ref) {
		state->s = talloc_asprintf_append_largebuf(
			state->s, &state->str_len,
			"%*sreference to: %s\n", depth*4, "", name);
		return;
	}

	if (depth == 0) {
		state->s = talloc_asprintf_append_largebuf(
			state->s, &state->str_len,
			"%stalloc report on '%s' "
			"(total %6lu bytes in %3lu blocks)\n",
			(max_depth < 0 ? "full " :""), name,
			(unsigned long)talloc_total_size(ptr),
			(unsigned long)talloc_total_blocks(ptr));
		return;
	}

	if (strcmp(name, "char") == 0) {
		/*
		 * Print out the first 50 bytes of the string
		 */
		state->s = talloc_asprintf_append_largebuf(
			state->s, &state->str_len,
			"%*s%-30s contains %6lu bytes in %3lu blocks "
			"(ref %zu): %*s\n", depth*4, "", name,
			(unsigned long)talloc_total_size(ptr),
			(unsigned long)talloc_total_blocks(ptr),
			talloc_reference_count(ptr),
			(int)MIN(50, talloc_get_size(ptr)),
			(const char *)ptr);
		return;
	}

	state->s = talloc_asprintf_append_largebuf(
		state->s, &state->str_len,
		"%*s%-30s contains %6lu bytes in %3lu blocks (ref %zu) %p\n",
		depth*4, "", name,
		(unsigned long)talloc_total_size(ptr),
		(unsigned long)talloc_total_blocks(ptr),
		talloc_reference_count(ptr), ptr);
}

char *talloc_report_str(TALLOC_CTX *mem_ctx, TALLOC_CTX *root)
{
	struct talloc_report_str_state state;

	state.s = talloc_strdup(mem_ctx, "");
	if (state.s == NULL) {
		return NULL;
	}
	state.str_len = 0;

	talloc_report_depth_cb(root, 0, -1, talloc_report_str_helper, &state);

	if (state.str_len == -1) {
		talloc_free(state.s);
		return NULL;
	}

	return talloc_realloc(mem_ctx, state.s, char, state.str_len+1);
}
