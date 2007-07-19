/*
 *	@file 	miniMpr.cpp
 *	@brief 	Mini Mbedthis Portable Runtime (MPR)
 *	@copy	default
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2005. All Rights Reserved.
 *	
 *	This software is distributed under commercial and open source licenses.
 *	You may use the GPL open source license described below or you may acquire 
 *	a commercial license from Mbedthis Software. You agree to be fully bound 
 *	by the terms of either license. Consult the LICENSE.TXT distributed with 
 *	this software for full details.
 *	
 *	This software is open source; you can redistribute it and/or modify it 
 *	under the terms of the GNU General Public License as published by the 
 *	Free Software Foundation; either version 2 of the License, or (at your 
 *	option) any later version. See the GNU General Public License for more 
 *	details at: http://www.mbedthis.com/downloads/gplLicense.html
 *	
 *	This program is distributed WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	
 *	This GPL license does NOT permit incorporating this software into 
 *	proprietary programs. If you are unable to comply with the GPL, you must
 *	acquire a commercial license to use this software. Commercial licenses 
 *	for this software and support services are available from Mbedthis 
 *	Software at http://www.mbedthis.com 
 *	
 *	@end
 */

#include	"miniMpr.h"

/************************************ Code ************************************/
#if !BLD_APPWEB
#if !BLD_GOAHEAD_WEBSERVER

static void *mpr_ctx;

/* set the memory context to be used for all ejs variables */
void mprSetCtx(TALLOC_CTX *ctx)
{
	mpr_ctx = ctx;
}

/* return the memory context being used for all ejs variables */
void *mprMemCtx(void)
{
	return mpr_ctx;
}

void mprFree(void *ptr)
{
	talloc_free(ptr);
}

void *mprMalloc(uint size)
{
	return talloc_size(mpr_ctx, size);
}

/******************************************************************************/

void *mprRealloc(void *ptr, uint size)
{
	return talloc_realloc_size(mpr_ctx, ptr, size);
}

/******************************************************************************/

char *mprStrdup(const char *str)
{
	if (str == 0) {
		str = "";
	}
	return talloc_strdup(mpr_ctx, str);
}

/*****************************************************************************/

int mprAllocSprintf(char **msgbuf, int maxSize, const char *fmt, ...)
{
	va_list	args;
	char	*buf;
	int		count;

	va_start(args, fmt);
	buf = mprMalloc(maxSize + 1);
	count = mtVsprintf(buf, maxSize, fmt, args);
	*msgbuf = buf;
	va_end(args);
	return count;
}

/*****************************************************************************/

int mprAllocVsprintf(char **msgbuf, int maxSize, const char *fmt, va_list args)
{
	char	*buf;
	int		count;

	buf = mprMalloc(maxSize + 1);
	count = mtVsprintf(buf, maxSize, fmt, args);
	*msgbuf = buf;
	return count;
}


/*****************************************************************************/
/*
 *	Format a number as a string. FUTURE -- reverse args to be standard.
 *		ie. mprItoa(char *userBuf, int bufsize, int value);
 */

char *mprItoa(int value, char *buf, int width)
{
	char	numBuf[16];
	char	*cp, *dp, *endp;
	int		negative;

	cp = &numBuf[sizeof(numBuf)];
	*--cp = '\0';

	if (value < 0) {
		negative = 1;
		value = -value;
		width--;
	} else {
		negative = 0;
	}

	do {
		*--cp = '0' + (value % 10);
		value /= 10;
	} while (value > 0);

	if (negative) {
		*--cp = '-';
	}

	dp = buf;
	endp = &buf[width];
	while (dp < endp && *cp) {
		*dp++ = *cp++;
	}
	*dp++ = '\0';
	return buf;
}

/*****************************************************************************/

void mprLog(int level, const char *fmt, ...)
{
	va_list	args;
	char	*buf;

	if (DEBUGLVL(level)) {
		va_start(args, fmt);
		mprAllocVsprintf(&buf, MPR_MAX_STRING, fmt, args);
		va_end(args);
		DEBUG(level, ("mprLog: %s", buf));
		mprFree(buf);
	}
}

/*****************************************************************************/

void mprBreakpoint(const char *file, int line, const char *cond)
{
	char *buf;
	mprAllocSprintf(&buf, MPR_MAX_STRING, "esp exception - ASSERT at %s:%d, %s\n", 
					file, line, cond);
	ejs_exception(buf);
}

#endif /* !BLD_GOAHEAD_WEBSERVER */
/*****************************************************************************/
/*
 *	Create a general growable array structure
 */

MprArray *mprCreateArray()
{
	MprArray	*array;
	int			size;

	array = (MprArray*) mprMalloc(sizeof(MprArray));
	if (array == 0) {
		return 0;
	}
	memset(array, 0, sizeof(MprArray));

	size = MPR_ARRAY_INCR * sizeof(void*);
	array->handles = (void**) mprMalloc(size);
	if (array->handles == 0) {
		mprFree(array);
		return 0;
	}
	memset(array->handles, 0, size);
	array->max = MPR_ARRAY_INCR;
	array->used = 0;
	return array;
}

/*****************************************************************************/
/*
 *	Dispose of the array. Callers responsibility to dispose of handle entries.
 */

void mprDestroyArray(MprArray *array)
{
	mprAssert(array);
	mprAssert(array->max >= 0);
	mprAssert(array->used >= 0);

	mprFree(array->handles);
	mprFree(array);
}

/*****************************************************************************/
/*
 *	Add an item to the array
 */

int mprAddToArray(MprArray *array, void *item)
{
	int		memsize, idx, len;

	mprAssert(array);
	mprAssert(array->max >= 0);
	mprAssert(array->used >= 0);

	if (array->used < array->max) {
		idx = array->used++;
		mprAssert(idx >= 0 && idx < array->max);
		mprAssert(array->handles[idx] == 0);
		array->handles[idx] = item;
		return idx;
	}

	for (idx = array->used; idx < array->max; idx++) {
		if (array->handles[idx] == 0) {
			array->used++;
			mprAssert(array->handles[idx] == 0);
			array->handles[idx] = item;
			return idx;
		}
	}

	len = array->max + MPR_ARRAY_INCR;
	memsize = len * sizeof(void*);
	array->handles = (void**) mprRealloc((void*) array->handles, memsize);
	if (array->handles == NULL) {
		return -1;
	}
	memset(&array->handles[array->max], 0, sizeof(void*) * MPR_ARRAY_INCR);
	array->max = len;
	array->used++;

	mprAssert(idx >= 0 && idx < array->max);
	mprAssert(array->handles[idx] == 0);

	array->handles[idx] = item;
	return idx;
}

/*****************************************************************************/
/*
 *	Remove from the array
 */

int mprRemoveFromArray(MprArray *array, int idx)
{
	mprAssert(array);
	mprAssert(array->max > 0);
	mprAssert(idx >= 0 && idx < array->max);
	mprAssert(array->handles[idx] != 0);
	mprAssert(array->used > 0);

	array->handles[idx] = 0;
	return --array->used;
}

/*****************************************************************************/
/*
 *	Thread-safe wrapping of strtok. Note "str" is modifed as per strtok()
 */

char *mprStrTok(char *str, const char *delim, char **tok)
{
	char	*start, *end;
	int		i;

	start = str ? str : *tok;

	if (start == 0) {
		return 0;
	}
	
	i = strspn(start, delim);
	start += i;
	if (*start == '\0') {
		*tok = 0;
		return 0;
	}
	end = strpbrk(start, delim);
	if (end) {
		*end++ = '\0';
		i = strspn(end, delim);
		end += i;
	}
	*tok = end;
	return start;
}

/*****************************************************************************/

static int mprCoreStrcat(int alloc, char **destp, int destMax, int existingLen, 
	const char *delim, const char *src, va_list args)
{
	va_list		ap;
	char		*dest, *dp;
	const char *str;
	int			sepLen, addBytes, required;

	mprAssert(destp);
	mprAssert(destMax > 0);
	mprAssert(src);

	dest = *destp;
	sepLen = (delim) ? strlen(delim) : 0;

	va_copy(ap, args);
	addBytes = 0;
	str = src;
	while (str) {
		addBytes += strlen(str) + sepLen;
		str = va_arg(ap, const char*);
	}
	va_end(ap);

	if (existingLen > 0) {
		addBytes += sepLen;
	}
	required = existingLen + addBytes + 1;
	if (required >= destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}

	if (alloc) {
		if (dest == 0) {
			dest = (char*) mprMalloc(required);
		} else {
			dest = (char*) mprRealloc(dest, required);
		}
	} else {
		dest = (char*) *destp;
	}

	dp = &dest[existingLen];
	if (delim) {
		strcpy(dp, delim);
		dp += sepLen;
	}

	if (addBytes > 0) {
		va_copy(ap, args);
		str = src;
		while (str) {
			strcpy(dp, str);
			dp += strlen(str);
			str = va_arg(ap, char*);
			if (delim && str) {
				strcpy(dp, delim);
				dp += sepLen;
			}
		}
		va_end(ap);
	} else if (dest == 0) {
		dest = (char*) mprMalloc(1);
	} 
	*dp = '\0';

	*destp = dest;
	mprAssert(dp < &dest[required]);
	return required - 1;
}

/*****************************************************************************
  Note that this VARARGS function must be NULL (not 0, this must be a
  pointer) terminated
*/

int mprReallocStrcat(char **destp, int destMax, int existingLen, 
	const char *delim, const char *src,...)
{
	va_list		ap;
	int			rc;

	va_start(ap, src);
	rc = mprCoreStrcat(1, destp, destMax, existingLen, delim, src, ap);
	va_end(ap);
	return rc;
}

/*****************************************************************************/
/*
 *	Return the directory portion of a pathname into the users buffer.
 */

int mprGetDirName(char *buf, int bufsize, char *path)
{
	char	*cp;
	int		dlen;

	mprAssert(path);
	mprAssert(buf);
	mprAssert(bufsize > 0);

	cp = strrchr(path, '/');
	if (cp == 0) {
#if WIN
		cp = strrchr(path, '\\');
		if (cp == 0)
#endif
		{
			buf[0] = '\0';
			return 0;
		}
	}

	if (cp == path && cp[1] == '\0') {
		strcpy(buf, ".");
		return 0;
	}

	dlen = cp - path;
	if (dlen < bufsize) {
		if (dlen == 0) {
			dlen++;
		}
		mprMemcpy(buf, bufsize, path, dlen);
		buf[dlen] = '\0';
		return 0;
	}
	return MPR_ERR_WONT_FIT;
}

/*****************************************************************************/

int mprStrcpy(char *dest, int destMax, const char *src)
{
	int		len;

	mprAssert(dest);
	mprAssert(destMax > 0);
	mprAssert(src);

	len = strlen(src);
	if (len >= destMax && len > 0) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	if (len > 0) {
		memcpy(dest, src, len);
		dest[len] = '\0';
	} else {
		*dest = '\0';
		len = 0;
	} 
	return len;
}

/*****************************************************************************/

int mprMemcpy(char *dest, int destMax, const char *src, int nbytes)
{
	mprAssert(dest);
	mprAssert(destMax > nbytes);
	mprAssert(src);
	mprAssert(nbytes > 0);

	if (nbytes > destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	if (nbytes > 0) {
		memcpy(dest, src, nbytes);
		return nbytes;
	} else {
		return 0;
	}
}

/*****************************************************************************/
#else
void miniMprDummy() {}
#endif // !BLD_APPWEB && !BLD_GOAHEAD_WEBSERVER

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
