/*
  Copyright (c) 2012 Ralph Boehme

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
*/

#ifndef SPOTLIGHT_SPARQL_MAP_H
#define SPOTLIGHT_SPARQL_MAP_H

enum ssm_type {
	ssmt_bool,   /* a boolean value that doesn't requires a SPARQL FILTER */
	ssmt_num,    /* a numeric value that requires a SPARQL FILTER */
	ssmt_str,    /* a string value that requieres a SPARQL FILTER */
	ssmt_fts,    /* a string value that will be queried with SPARQL 'fts:match' */
	ssmt_date,   /* date values are handled in a special map function map_daterange() */
	ssmt_type    /* kMDItemContentType, requires special mapping */
};

struct sl_attr_map {
	const char *spotlight_attr;
	enum ssm_type type;
	const char *sparql_attr;
};

enum kMDTypeMap {
	kMDTypeMapNotSup, /* not supported */
	kMDTypeMapRDF,    /* query with rdf:type */
	kMDTypeMapMime    /* query with nie:mimeType */
};

struct sl_type_map {
	/*
	 * MD query value of attributes '_kMDItemGroupId' and
	 * 'kMDItemContentTypeTree
	 */
	const char *spotlight_type;

	/*
	 * Whether SPARQL query must search attribute rdf:type or
	 * nie:mime_Type
	 */
	enum kMDTypeMap type;

	/* the SPARQL query match string */
	const char *sparql_type;
};

const struct sl_attr_map *sl_attr_map_by_spotlight(const char *sl_attr);
const struct sl_type_map *sl_type_map_by_spotlight(const char *sl_type);
#endif
