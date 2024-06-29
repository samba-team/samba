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
#include "lib/elastic_util.h"

struct es_attr_map *es_map_sl_attr(TALLOC_CTX *mem_ctx,
				   json_t *kmd_map,
				   const char *sl_attr)
{
	struct es_attr_map *es_map = NULL;
	const char *typestr = NULL;
	enum ssm_type type = ssmt_bool;
	char *es_attr = NULL;
	const char *json_escape_list = "\\\"";

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
		DBG_DEBUG("No JSON type mapping for [%s]\n", sl_attr);
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

	es_map->name = es_escape_str(es_map, es_attr, json_escape_list, NULL);
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
