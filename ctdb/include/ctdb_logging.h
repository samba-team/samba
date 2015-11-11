/*
   ctdb logging code

   Copyright (C) Andrew Tridgell  2008

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

#ifndef _CTDB_LOGGING_H_
#define _CTDB_LOGGING_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <talloc.h>

#include "common/logging.h"

const char *get_debug_by_level(int32_t level);
bool parse_debug(const char *str, int32_t *level);
void print_debug_levels(FILE *stream);

#endif /* _CTDB_LOGGING_H_ */
