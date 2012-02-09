/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   Copyright (C) James Peach	 2005
   
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
#include "system/locale.h"
#undef strncasecmp
#undef strcasemp

/**
 * @file
 * @brief String utilities.
 **/

/**
 * Parse a string containing a boolean value.
 *
 * val will be set to the read value.
 *
 * @retval true if a boolean value was parsed, false otherwise.
 */
_PUBLIC_ bool conv_str_bool(const char * str, bool * val)
{
	char *	end = NULL;
	long	lval;

	if (str == NULL || *str == '\0') {
		return false;
	}

	lval = strtol(str, &end, 10 /* base */);
	if (end == NULL || *end != '\0' || end == str) {
		return set_boolean(str, val);
	}

	*val = (lval) ? true : false;
	return true;
}

/**
 * Convert a size specification like 16K into an integral number of bytes. 
 **/
_PUBLIC_ bool conv_str_size_error(const char * str, uint64_t * val)
{
	char *		    end = NULL;
	unsigned long long  lval;

	if (str == NULL || *str == '\0') {
		return false;
	}

	lval = strtoull(str, &end, 10 /* base */);
	if (end == NULL || end == str) {
		return false;
	}

	if (*end) {
		if (strwicmp(end, "K") == 0) {
			lval *= 1024ULL;
		} else if (strwicmp(end, "M") == 0) {
			lval *= (1024ULL * 1024ULL);
		} else if (strwicmp(end, "G") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL);
		} else if (strwicmp(end, "T") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL * 1024ULL);
		} else if (strwicmp(end, "P") == 0) {
			lval *= (1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL);
		} else {
			return false;
		}
	}

	*val = (uint64_t)lval;
	return true;
}

/**
 * Parse a uint64_t value from a string
 *
 * val will be set to the value read.
 *
 * @retval true if parsing was successful, false otherwise
 */
_PUBLIC_ bool conv_str_u64(const char * str, uint64_t * val)
{
	char *		    end = NULL;
	unsigned long long  lval;

	if (str == NULL || *str == '\0') {
		return false;
	}

	lval = strtoull(str, &end, 10 /* base */);
	if (end == NULL || *end != '\0' || end == str) {
		return false;
	}

	*val = (uint64_t)lval;
	return true;
}

/**
 * Compare 2 strings.
 *
 * @note The comparison is case-insensitive.
 **/
_PUBLIC_ bool strequal(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
  
	return strcasecmp_m(s1,s2) == 0;
}

