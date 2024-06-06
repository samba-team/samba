/*
 *  Unix SMB/CIFS implementation.
 *
 *  elasticsearch common routines
 *
 *  Copyright (c) Ralph Boehme
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <includes.h>
#include "elastic_util.h"
/*
 * Escaping of special characters in Lucene query syntax across HTTP and JSON
 * ==========================================================================
 *
 * These characters in Lucene queries need escaping [1]:
 *
 *   + - & | ! ( ) { } [ ] ^ " ~ * ? : \ /
 *
 * Additionally JSON requires escaping of:
 *
 *   " \
 *
 * Characters already escaped by the mdssvc client:
 *
 *   * " \
 *
 * The following table contains the resulting escaped strings, beginning with the
 * search term, the corresponding Spotlight query and the final string that gets
 * sent to the target Elasticsearch server.
 *
 * string | mdfind | http
 * -------+--------+------
 * x!x     x!x      x\\!x
 * x&x     x&x      x\\&x
 * x+x     x+x      x\\+x
 * x-x     x-x      x\\-x
 * x.x     x.x      x\\.x
 * x<x     x<x      x\\<x
 * x>x     x>x      x\\>x
 * x=x     x=x      x\\=x
 * x?x     x?x      x\\?x
 * x[x     x[x      x\\[x
 * x]x     x]x      x\\]x
 * x^x     x^x      x\\^x
 * x{x     x{x      x\\{x
 * x}x     x}x      x\\}x
 * x|x     x|x      x\\|x
 * x x     x x      x\\ x
 * x*x     x\*x     x\\*x
 * x\x     x\\x     x\\\\x
 * x"x     x\"x     x\\\"x
 *
 * Special cases:
 * x y    It's not possible to search for terms including spaces, Spotlight
 *        will search for x OR y.
 * x(x    Search for terms including ( and ) does not work with Spotlight.
 *
 * [1] <http://lucene.apache.org/core/8_2_0/queryparser/org/apache/lucene/queryparser/classic/package-summary.html#Escaping_Special_Characters>
 */

static char *escape_str(TALLOC_CTX *mem_ctx,
			const char *in,
			const char *escape_list,
			const char *escape_exceptions)
{
	char *out = NULL;
	size_t in_len;
	size_t new_len;
	size_t in_pos;
	size_t out_pos = 0;

	if (in == NULL) {
		return NULL;
	}
	in_len = strlen(in);

	if (escape_list == NULL) {
		escape_list = "";
	}
	if (escape_exceptions == NULL) {
		escape_exceptions = "";
	}

	/*
	 * Allocate enough space for the worst case: every char needs to be
	 * escaped and requires an additional char.
	 */
	new_len = (in_len * 2) + 1;
	if (new_len <= in_len) {
		return NULL;
	}

	out = talloc_zero_array(mem_ctx, char, new_len);
	if (out == NULL) {
		return NULL;
	}

	for (in_pos = 0, out_pos = 0; in_pos < in_len; in_pos++, out_pos++) {
		if (strchr(escape_list, in[in_pos]) != NULL &&
		    strchr(escape_exceptions, in[in_pos]) == NULL)
		{
			out[out_pos++] = '\\';
		}
		out[out_pos] = in[in_pos];
	}

	return out;
}

char *es_escape_str(TALLOC_CTX *mem_ctx,
		    const char *in,
		    const char *json_escape_list,
		    const char *exceptions)
{
	const char *lucene_escape_list = "+-&|!(){}[]^\"~*?:\\/ ";
	char *lucene_escaped = NULL;
	char *full_escaped = NULL;

	lucene_escaped = escape_str(mem_ctx,
				    in,
				    lucene_escape_list,
				    exceptions);

	if (lucene_escaped == NULL) {
		return NULL;
	}

	full_escaped = escape_str(mem_ctx,
				  lucene_escaped,
				  json_escape_list,
				  NULL);
	TALLOC_FREE(lucene_escaped);
	return full_escaped;
}
