/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2007
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) James Peach 2006

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

#if defined(PARANOID_MALLOC_CHECKER)

/****************************************************************************
 Internal malloc wrapper. Externally visible.
****************************************************************************/

void *malloc_(size_t size)
{
	if (size == 0) {
		return NULL;
	}
#undef malloc
	return malloc(size);
#define malloc(s) __ERROR_DONT_USE_MALLOC_DIRECTLY
}

/****************************************************************************
 Internal realloc wrapper. Not externally visible.
****************************************************************************/

static void *realloc_(void *ptr, size_t size)
{
#undef realloc
	return realloc(ptr, size);
#define realloc(p,s) __ERROR_DONT_USE_RELLOC_DIRECTLY
}

#endif /* PARANOID_MALLOC_CHECKER */

/****************************************************************************
 Expand a pointer to be a particular size.
 Note that this version of Realloc has an extra parameter that decides
 whether to free the passed in storage on allocation failure or if the
 new size is zero.

 This is designed for use in the typical idiom of :

 p = SMB_REALLOC(p, size)
 if (!p) {
    return error;
 }

 and not to have to keep track of the old 'p' contents to free later, nor
 to worry if the size parameter was zero. In the case where NULL is returned
 we guarentee that p has been freed.

 If free later semantics are desired, then pass 'free_old_on_error' as False which
 guarentees that the old contents are not freed on error, even if size == 0. To use
 this idiom use :

 tmp = SMB_REALLOC_KEEP_OLD_ON_ERROR(p, size);
 if (!tmp) {
    SAFE_FREE(p);
    return error;
 } else {
    p = tmp;
 }

 Changes were instigated by Coverity error checking. JRA.
****************************************************************************/

void *Realloc(void *p, size_t size, bool free_old_on_error)
{
	void *ret=NULL;

	if (size == 0) {
		if (free_old_on_error) {
			SAFE_FREE(p);
		}
		DEBUG(2,("Realloc asked for 0 bytes\n"));
		return NULL;
	}

#if defined(PARANOID_MALLOC_CHECKER)
	if (!p) {
		ret = (void *)malloc_(size);
	} else {
		ret = (void *)realloc_(p,size);
	}
#else
	if (!p) {
		ret = (void *)malloc(size);
	} else {
		ret = (void *)realloc(p,size);
	}
#endif

	if (!ret) {
		if (free_old_on_error && p) {
			SAFE_FREE(p);
		}
		DEBUG(0,("Memory allocation error: failed to expand to %d bytes\n",(int)size));
	}

	return(ret);
}

