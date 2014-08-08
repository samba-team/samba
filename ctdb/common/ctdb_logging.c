/* 
   ctdb logging code

   Copyright (C) Ronnie Sahlberg 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <ctype.h>
#include "replace.h"
#include "ctdb_logging.h"

const char *debug_extra = "";

struct debug_levels {
	int32_t	level;
	const char *description;
};

static struct debug_levels debug_levels[] = {
	{DEBUG_ERR,	"ERR"},
	{DEBUG_WARNING,	"WARNING"},
	{DEBUG_NOTICE,	"NOTICE"},
	{DEBUG_INFO,	"INFO"},
	{DEBUG_DEBUG,	"DEBUG"},
	{0, NULL}
};

const char *get_debug_by_level(int32_t level)
{
	int i;

	for (i=0; debug_levels[i].description != NULL; i++) {
		if (debug_levels[i].level == level) {
			return debug_levels[i].description;
		}
	}
	return NULL;
}

static bool get_debug_by_desc(const char *desc, int32_t *level)
{
	int i;

	for (i=0; debug_levels[i].description != NULL; i++) {
		if (!strcasecmp(debug_levels[i].description, desc)) {
			*level = debug_levels[i].level;
			return true;
		}
	}

	return false;
}

bool parse_debug(const char *str, int32_t *level)
{
	if (isalpha(str[0])) {
		return get_debug_by_desc(str, level);
	} else {
		*level = strtol(str, NULL, 0);
		return get_debug_by_level(*level) != NULL;
	}
}

void print_debug_levels(FILE *stream)
{
	int i;

	for (i=0; debug_levels[i].description != NULL; i++) {
		fprintf(stream,
			"%s (%d)\n",
			debug_levels[i].description, debug_levels[i].level);
	}
}
