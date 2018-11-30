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

#include "replace.h"

#include <string.h>
#include <talloc.h>

#include "strv.h"

#include "strv_util.h"

int strv_split(TALLOC_CTX *mem_ctx, char **strv,
	       const char *src, const char *sep)
{
	const char *s;

	if (src == NULL) {
		return 0;
	}

	s = src;
	while (*s != '\0') {
		size_t len;

		/* Skip separators */
		len = strspn(s, sep);
		if (len != 0) {
			s += len;
		}

		/* Find non-separator substring */
		len = strcspn(s, sep);
		if (len != 0) {
			int ret = strv_addn(mem_ctx, strv, s, len);
			if (ret != 0) {
				TALLOC_FREE(*strv);
				return ret;
			}
			s += len;
		}
	}

	return 0;
}
