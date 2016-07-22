/*
   Logging utilities

   Copyright (C) Amitay Isaacs  2015

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

#include <replace.h>
#include <system/locale.h>

#include "common/logging.h"

struct {
	enum debug_level log_level;
	const char *log_string;
} log_string_map[] = {
	{ DEBUG_ERR,     "ERROR" },
	{ DEBUG_WARNING, "WARNING" },
	{ DEBUG_NOTICE,  "NOTICE" },
	{ DEBUG_INFO,    "INFO" },
	{ DEBUG_DEBUG,   "DEBUG" },
};

bool debug_level_parse(const char *log_string, enum debug_level *log_level)
{
	int i;

	if (log_string == NULL) {
		return false;
	}

	if (isdigit(log_string[0])) {
		int level = atoi(log_string);

		if (level >= 0 && level < ARRAY_SIZE(log_string_map)) {
			*log_level = debug_level_from_int(level);
			return true;
		}
		return false;
	}

	for (i=0; i<ARRAY_SIZE(log_string_map); i++) {
		if (strncasecmp(log_string_map[i].log_string,
				log_string, strlen(log_string)) == 0) {
			*log_level = log_string_map[i].log_level;
			return true;
		}
	}

	return false;
}

const char *debug_level_to_string(enum debug_level log_level)
{
	int i;

	for (i=0; ARRAY_SIZE(log_string_map); i++) {
		if (log_string_map[i].log_level == log_level) {
			return log_string_map[i].log_string;
		}
	}
	return "UNKNOWN";
}

enum debug_level debug_level_from_string(const char *log_string)
{
	bool found;
	enum debug_level log_level;

	found = debug_level_parse(log_string, &log_level);
	if (found) {
		return log_level;
	}

	/* Default debug level */
	return DEBUG_ERR;
}

int debug_level_to_int(enum debug_level log_level)
{
	return (int)log_level;
}

enum debug_level debug_level_from_int(int level)
{
	enum debug_level log_level;

	if (level >= 0 && level < ARRAY_SIZE(log_string_map)) {
		log_level = log_string_map[level].log_level;
	} else {
		log_level = DEBUG_ERR;
	}

	return log_level;
}
