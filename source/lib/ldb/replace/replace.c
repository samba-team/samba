/* 
   Unix SMB/CIFS implementation.

   replacement routines for broken systems

   Copyright (C) Andrew Tridgell 1992-2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "ldb/include/includes.h"

#ifndef HAVE_STRNLEN
/**
 Some platforms don't have strnlen
**/
 size_t strnlen(const char *s, size_t n)
{
	int i;
	for (i=0; s[i] && i<n; i++)
		/* noop */ ;
	return i;
}
#endif

#ifndef HAVE_STRTOLL
 long long int strtoll(const char *str, char **endptr, int base)
{
#ifdef HAVE_STRTOQ
	return strtoq(str, endptr, base);
#elif defined(HAVE___STRTOLL) 
	return __strtoll(str, endptr, base);
#elif SIZEOF_LONG == SIZEOF_LONG_LONG
	return (long long int) strtol(str, endptr, base);
#else
# error "You need a strtoll function"
#endif
}
#endif


#ifndef HAVE_STRTOULL
 unsigned long long int strtoull(const char *str, char **endptr, int base)
{
#ifdef HAVE_STRTOUQ
	return strtouq(str, endptr, base);
#elif defined(HAVE___STRTOULL) 
	return __strtoull(str, endptr, base);
#elif SIZEOF_LONG == SIZEOF_LONG_LONG
	return (unsigned long long int) strtoul(str, endptr, base);
#else
# error "You need a strtoull function"
#endif
}
#endif

#ifndef HAVE_SETENV
 int setenv(const char *name, const char *value, int overwrite) 
{
	char *p;
	size_t l1, l2;
	int ret;

	if (!overwrite && getenv(name)) {
		return 0;
	}

	l1 = strlen(name);
	l2 = strlen(value);

	p = malloc(l1+l2+2);
	if (p == NULL) {
		return -1;
	}
	memcpy(p, name, l1);
	p[l1] = '=';
	memcpy(p+l1+1, value, l2);
	p[l1+l2+1] = 0;

	ret = putenv(p);
	if (ret != 0) {
		free(p);
	}

	return ret;
}
#endif
