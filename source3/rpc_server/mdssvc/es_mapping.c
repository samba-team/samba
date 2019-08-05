/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines / Elasticsearch backend

   Copyright (C) Ralph Boehme			2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "es_mapping.h"

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
 * x(x    Search for terms including ( and ) doesn not work with Spotlight.
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
		    const char *exceptions)
{
	const char *lucene_escape_list = "+-&|!(){}[]^\"~*?:\\/ ";
	const char *json_escape_list = "\\\"";
	char *lucene_escaped = NULL;
	char *full_escaped = NULL;

	lucene_escaped =  escape_str(mem_ctx,
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

struct es_attr_map *es_map_sl_attr(TALLOC_CTX *mem_ctx,
				   json_t *kmd_map,
				   const char *sl_attr)
{
	struct es_attr_map *es_map = NULL;
	const char *typestr = NULL;
	enum ssm_type type;
	char *es_attr = NULL;
	size_t i;
	int cmp;
	int ret;

	static struct {
		const char *typestr;
		enum ssm_type typeval;
	} ssmt_type_map[] = {
		{"bool", ssmt_bool},
		{"num", ssmt_num},
		{"str", ssmt_str},
		{"fts", ssmt_fts},
		{"date", ssmt_date},
		{"type", ssmt_type},
	};

	if (sl_attr == NULL) {
		return NULL;
	}

	ret = json_unpack(kmd_map,
			  "{s: {s: s}}",
			  sl_attr,
			  "type",
			  &typestr);
	if (ret != 0) {
		DBG_ERR("No JSON type mapping for [%s]\n", sl_attr);
		return NULL;
	}

	ret = json_unpack(kmd_map,
			  "{s: {s: s}}",
			  sl_attr,
			  "attribute",
			  &es_attr);
	if (ret != 0) {
		DBG_ERR("No JSON attribute mapping for [%s]\n", sl_attr);
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(ssmt_type_map); i++) {
		cmp = strcmp(typestr, ssmt_type_map[i].typestr);
		if (cmp == 0) {
			type = ssmt_type_map[i].typeval;
			break;
		}
	}
	if (i == ARRAY_SIZE(ssmt_type_map)) {
		return NULL;
	}

	es_map = talloc_zero(mem_ctx, struct es_attr_map);
	if (es_map == NULL) {
		return NULL;
	}
	es_map->type = type;

	es_map->name = es_escape_str(es_map, es_attr, NULL);
	if (es_map->name == NULL) {
		TALLOC_FREE(es_map);
		return false;
	}

	return es_map;
}

const char *es_map_sl_type(json_t *mime_map,
			   const char *sl_type)
{
	const char *mime_type = NULL;
	int ret;

	if (sl_type == NULL) {
		return NULL;
	}

	ret = json_unpack(mime_map,
			  "{s: s}",
			  sl_type,
			  &mime_type);
	if (ret != 0) {
		return NULL;
	}

	return mime_type;
}
