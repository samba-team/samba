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
 Safe string copy into a known length string. maxlength does not
 include the terminating zero.
**/
_PUBLIC_ char *safe_strcpy(char *dest,const char *src, size_t maxlength)
{
	size_t len;

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in safe_strcpy\n"));
		return NULL;
	}

#ifdef DEVELOPER
	/* We intentionally write out at the extremity of the destination
	 * string.  If the destination is too short (e.g. pstrcpy into mallocd
	 * or fstring) then this should cause an error under a memory
	 * checker. */
	dest[maxlength] = '\0';
	if (PTR_DIFF(&len, dest) > 0) {  /* check if destination is on the stack, ok if so */
		log_suspicious_usage("safe_strcpy", src);
	}
#endif

	if (!src) {
		*dest = 0;
		return dest;
	}  

	len = strlen(src);

	if (len > maxlength) {
		DEBUG(0,("ERROR: string overflow by %u (%u - %u) in safe_strcpy [%.50s]\n",
			 (unsigned int)(len-maxlength), (unsigned)len, (unsigned)maxlength, src));
		len = maxlength;
	}
      
	memmove(dest, src, len);
	dest[len] = 0;
	return dest;
}  

/**
 Safe string cat into a string. maxlength does not
 include the terminating zero.
**/
_PUBLIC_ char *safe_strcat(char *dest, const char *src, size_t maxlength)
{
	size_t src_len, dest_len;

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in safe_strcat\n"));
		return NULL;
	}

	if (!src)
		return dest;
	
#ifdef DEVELOPER
	if (PTR_DIFF(&src_len, dest) > 0) {  /* check if destination is on the stack, ok if so */
		log_suspicious_usage("safe_strcat", src);
	}
#endif
	src_len = strlen(src);
	dest_len = strlen(dest);

	if (src_len + dest_len > maxlength) {
		DEBUG(0,("ERROR: string overflow by %d in safe_strcat [%.50s]\n",
			 (int)(src_len + dest_len - maxlength), src));
		if (maxlength > dest_len) {
			memcpy(&dest[dest_len], src, maxlength - dest_len);
		}
		dest[maxlength] = 0;
		return NULL;
	}
	
	memcpy(&dest[dest_len], src, src_len);
	dest[dest_len + src_len] = 0;
	return dest;
}

/**
  format a string into length-prefixed dotted domain format, as used in NBT
  and in some ADS structures
**/
_PUBLIC_ const char *str_format_nbt_domain(TALLOC_CTX *mem_ctx, const char *s)
{
	char *ret;
	int i;
	if (!s || !*s) {
		return talloc_strdup(mem_ctx, "");
	}
	ret = talloc_array(mem_ctx, char, strlen(s)+2);
	if (!ret) {
		return ret;
	}
	
	memcpy(ret+1, s, strlen(s)+1);
	ret[0] = '.';

	for (i=0;ret[i];i++) {
		if (ret[i] == '.') {
			char *p = strchr(ret+i+1, '.');
			if (p) {
				ret[i] = p-(ret+i+1);
			} else {
				ret[i] = strlen(ret+i+1);
			}
		}
	}

	talloc_set_name_const(ret, ret);

	return ret;
}

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
_PUBLIC_ bool conv_str_size(const char * str, uint64_t * val)
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
  
	return strcasecmp(s1,s2) == 0;
}

/**
 String replace.
**/
_PUBLIC_ void string_replace(char *s, char oldc, char newc)
{
	while (*s) {
		if (*s == oldc) *s = newc;
		s++;
	}
}
