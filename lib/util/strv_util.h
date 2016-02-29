/*
 * strv-based utilities
 *
 * Copyright Martin Schwenke <martin@meltin.net> 2016
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

#ifndef _STRV_UTIL_H_
#define _STRV_UTIL_H_

#include <talloc.h>

/* Split string at characters in sep, adding non-separator words to
 * *strv.  On failure *strv is undefined. */
int strv_split(TALLOC_CTX *mem_ctx, char **strv,
	       const char *string, const char *sep);

#endif
