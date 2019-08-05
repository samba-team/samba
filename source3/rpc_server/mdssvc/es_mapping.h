/*
  Unix SMB/CIFS implementation.
  Main metadata server / Spotlight routines / Elasticsearch backend

  Copyright (c) Ralph Boehme			2019

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ES_MAPPING_H_
#define _ES_MAPPING_H_

#include <jansson.h>

enum ssm_type {
	ssmt_bool,   /* a boolean value */
	ssmt_num,    /* a numeric value */
	ssmt_str,    /* a string value */
	ssmt_fts,    /* a string value */
	ssmt_date,   /* date values */
	ssmt_type    /* kMDItemContentType, requires special mapping */
};

struct es_attr_map {
	enum ssm_type type;
	const char *name;
};

char *es_escape_str(TALLOC_CTX *mem_ctx,
		    const char *in,
		    const char *exceptions);
struct es_attr_map *es_map_sl_attr(TALLOC_CTX *mem_ctx,
				   json_t *kmd_map,
				   const char *sl_attr);
const char *es_map_sl_type(json_t *mime_map,
			   const char *sl_type);

#endif
