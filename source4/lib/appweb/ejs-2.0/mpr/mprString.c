/**
 *	@file 	mprString.c
 *	@brief	String routines safe for embedded programming
 *	@overview This module provides safe replacements for the standard 
 *		string library.
 *	@remarks Most routines in this file are not thread-safe. It is the callers 
 *		responsibility to perform all thread synchronization.
 */

/*
 *	@copy	default
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
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

#include	"mpr.h"

/********************************** Includes **********************************/
/*
 *	We need to use the underlying str(cpy) routines to implement our safe
 *	alternatives
 */
#if !DOXYGEN
#define 	UNSAFE_FUNCTIONS_OK 1
#endif

/******************************************************************************/
/**************************** Safe String Handling ****************************/
/******************************************************************************/

int mprStrcpy(char *dest, int destMax, const char *src)
{
	int		len;

	mprAssert(dest);
	mprAssert(destMax >= 0);
	mprAssert(src);

	len = strlen(src);
	if (destMax > 0 && len >= destMax && len > 0) {
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

/******************************************************************************/

int mprAllocStrcpy(MPR_LOC_DEC(ctx, loc), char **dest, int destMax, 
	const char *src)
{
	int		len;

	mprAssert(dest);
	mprAssert(destMax >= 0);
	mprAssert(src);

	len = strlen(src);
	if (destMax > 0 && len >= destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	if (len > 0) {
		*dest = (char*) mprAllocBlock(MPR_LOC_PASS(ctx, loc), len);
		memcpy(*dest, src, len);
		(*dest)[len] = '\0';
	} else {
		*dest = (char*) mprAlloc(ctx, 1);
		*dest = '\0';
		len = 0;
	} 
	return len;
}

/******************************************************************************/

int mprMemcpy(char *dest, int destMax, const char *src, int nbytes)
{
	mprAssert(dest);
	mprAssert(destMax <= 0 || destMax >= nbytes);
	mprAssert(src);
	mprAssert(nbytes >= 0);

	if (destMax > 0 && nbytes > destMax) {
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

/******************************************************************************/

int mprAllocMemcpy(MPR_LOC_DEC(ctx, loc), char **dest, int destMax, 
	const void *src, int nbytes)
{
	mprAssert(dest);
	mprAssert(src);
	mprAssert(nbytes > 0);
	mprAssert(destMax <= 0 || destMax >= nbytes);

	if (destMax > 0 && nbytes > destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	if (nbytes > 0) {
		*dest = (char*) mprAllocBlock(MPR_LOC_PASS(ctx,loc), nbytes);
		if (*dest == 0) {
			return MPR_ERR_MEMORY;
		}
		memcpy(*dest, src, nbytes);
	} else {
		*dest = (char*) mprAlloc(ctx, 1);
	}
	return nbytes;
}

/******************************************************************************/

static int mprCoreStrcat(MPR_LOC_DEC(ctx, loc), char **destp, int destMax, 
	int existingLen, const char *delim, const char *src, va_list args)
{
	va_list		ap;
	char		*dest, *str, *dp;
	int			sepLen, addBytes, required;

	mprAssert(destp);
	mprAssert(destMax >= 0);
	mprAssert(src);

	dest = *destp;
	sepLen = (delim) ? strlen(delim) : 0;

#ifdef __va_copy
	__va_copy(ap, args);
#else
	ap = args;
#endif
	addBytes = 0;
	if (existingLen > 0) {
		addBytes += sepLen;
	}
	str = (char*) src;

	while (str) {
		addBytes += strlen(str);
		str = va_arg(ap, char*);
		if (str) {
			addBytes += sepLen;
		}
	}

	required = existingLen + addBytes + 1;
	if (destMax > 0 && required >= destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}

	if (ctx != 0) {
		if (dest == 0) {
			dest = (char*) mprAllocBlock(MPR_LOC_PASS(ctx, loc), required);
		} else {
			dest = (char*) mprReallocBlock(MPR_LOC_PASS(ctx, loc), dest, 
				required);
		}
	} else {
		dest = (char*) *destp;
	}

	dp = &dest[existingLen];
	if (delim && existingLen > 0) {
		strcpy(dp, delim);
		dp += sepLen;
	}

	if (addBytes > 0) {
#ifdef __va_copy
		__va_copy(ap, args);
#else
		ap = args;
#endif
		str = (char*) src;
		while (str) {
			strcpy(dp, str);
			dp += strlen(str);
			str = va_arg(ap, char*);
			if (delim && str) {
				strcpy(dp, delim);
				dp += sepLen;
			}
		}
	} else if (dest == 0) {
		dest = (char*) mprAlloc(ctx, 1);
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
int mprStrcat(char *dest, int destMax, const char *delim, const char *src, ...)
{
	va_list		ap;
	int			rc;

	mprAssert(dest);
	mprAssert(src);

	va_start(ap, src);
	rc = mprCoreStrcat(MPR_LOC_ARGS(0), &dest, destMax, strlen(dest), 
		delim, src, ap);
	va_end(ap);
	return rc;
}

/*****************************************************************************
  Note that this VARARGS function must be NULL (not 0, this must be a
  pointer) terminated
*/
int mprAllocStrcat(MPR_LOC_DEC(ctx, loc), char **destp, int destMax, 
	const char *delim, const char *src, ...)
{
	va_list		ap;
	int			rc;

	mprAssert(destp);
	mprAssert(src);

	*destp = 0;
	va_start(ap, src);
	rc = mprCoreStrcat(MPR_LOC_PASS(ctx, loc), destp, destMax, 0, delim, 
		src, ap);
	va_end(ap);
	return rc;
}

/*****************************************************************************
  Note that this VARARGS function must be NULL (not 0, this must be a
  pointer) terminated
*/
int mprReallocStrcat(MPR_LOC_DEC(ctx, loc), char **destp, int destMax, 
	int existingLen, const char *delim, const char *src,...)
{
	va_list		ap;
	int			rc;

	va_start(ap, src);
	rc = mprCoreStrcat(MPR_LOC_PASS(ctx, loc), destp, destMax, existingLen, 
		delim, src, ap);
	va_end(ap);
	return rc;
}

/******************************************************************************/

int mprStrlen(const char *src, int max)
{
	int		len;

	len = strlen(src);
	if (len >= max) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	return len;
}

/******************************************************************************/

char *mprStrTrim(char *str, const char *set)
{
	int		len, i;

	if (str == 0 || set == 0) {
		return str;
	}

	i = strspn(str, set);
	str += i;

	len = strlen(str);
	while (strspn(&str[len - 1], set) > 0) {
		str[len - 1] = '\0';
		len--;
	}
	return str;
}

/******************************************************************************/
/*	
 *	Map a string to lower case (overwrites original string)
 */

char *mprStrLower(char *str)
{
	char	*cp;

	mprAssert(str);

	if (str == 0) {
		return 0;
	}

	for (cp = str; *cp; cp++) {
		if (isupper(*cp)) {
			*cp = (char) tolower(*cp);
		}
	}
	return str;
}

/******************************************************************************/
/*	
 *	Map a string to upper case (overwrites buffer)
 */

char *mprStrUpper(char *str)
{
	char	*cp;

	mprAssert(str);
	if (str == 0) {
		return 0;
	}

	for (cp = str; *cp; cp++) {
		if (islower(*cp)) {
			*cp = (char) toupper(*cp);
		}
	}
	return str;
}

/******************************************************************************/
/*
 *	Case insensitive string comparison. Stop at the end of str1.
 */

int mprStrcmpAnyCase(const char *str1, const char *str2)
{
	int		rc;

	if (str1 == 0 || str2 == 0) {
		return -1;
	}
	if (str1 == str2) {
		return 0;
	}

	for (rc = 0; *str1 && rc == 0; str1++, str2++) {
		rc = tolower(*str1) - tolower(*str2);
	}
	if (*str2) {
		return -1;
	}
	return rc;
}

/******************************************************************************/
/*
 *	Case insensitive string comparison. Limited by length
 */

int mprStrcmpAnyCaseCount(const char *str1, const char *str2, int len)
{
	int		rc;

	if (str1 == 0 || str2 == 0) {
		return -1;
	}
	if (str1 == str2) {
		return 0;
	}

	for (rc = 0; len-- > 0 && *str1 && rc == 0; str1++, str2++) {
		rc = tolower(*str1) - tolower(*str2);
	}
	return rc;
}

/******************************************************************************/
/*
 *	Return the last portion of a pathname
 */

const char *mprGetBaseName(const char *name)
{
	char *cp;

	cp = strrchr(name, '/');

	if (cp == 0) {
		cp = strrchr(name, '\\');
		if (cp == 0) {
			return name;
		}
	} 
	if (cp == name) {
		if (cp[1] == '\0') {
			return name;
		}
	} else {
		if (cp[1] == '\0') {
			return "";
		}
	}
	return &cp[1];
}

/******************************************************************************/
/*
 *	Return the directory portion of a pathname into the users buffer.
 */

char *mprGetDirName(char *buf, int bufsize, const char *path)
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
			return buf;
		}
	}

	if (cp == path && cp[1] == '\0') {
		strcpy(buf, ".");
		return buf;
	}

	dlen = cp - path;
	if (dlen < bufsize) {
		if (dlen == 0) {
			dlen++;
		}
		mprMemcpy(buf, bufsize, path, dlen);
		buf[dlen] = '\0';
		return buf;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Thread-safe wrapping of strtok. Note "str" is modifed as per strtok()
 */

char *mprStrTok(char *str, const char *delim, char **last)
{
	char	*start, *end;
	int		i;

	start = str ? str : *last;

	if (start == 0) {
		return 0;
	}
	
	i = strspn(start, delim);
	start += i;
	if (*start == '\0') {
		*last = 0;
		return 0;
	}
	end = strpbrk(start, delim);
	if (end) {
		*end++ = '\0';
		i = strspn(end, delim);
		end += i;
	}
	*last = end;
	return start;
}

/******************************************************************************/
/*
 *	Split the buffer into word tokens
 */

char *mprGetWordTok(char *buf, int bufsize, const char *str, const char *delim, 
	const char **tok)
{
	const char	*start, *end;
	int			i, len;

	start = str ? str : *tok;

	if (start == 0) {
		return 0;
	}
	
	i = strspn(start, delim);
	start += i;
	if (*start =='\0') {
		*tok = 0;
		return 0;
	}
	end = strpbrk(start, delim);
	if (end) {
		len = min(end - start, bufsize - 1);
		mprMemcpy(buf, bufsize, start, len);
		buf[len] = '\0';
	} else {
		if (mprStrcpy(buf, bufsize, start) < 0) {
			buf[bufsize - 1] = '\0';
			return 0;
		}
		buf[bufsize - 1] = '\0';
	}
	*tok = end;
	return buf;
}

/******************************************************************************/
/*
 *	Format a number as a string. 
 */

char *mprItoa(char *buf, int size, int value)
{
	char	numBuf[16];
	char	*cp, *dp, *endp;
	int		negative;

	cp = &numBuf[sizeof(numBuf)];
	*--cp = '\0';

	if (value < 0) {
		negative = 1;
		value = -value;
		size--;
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
	endp = &buf[size];
	while (dp < endp && *cp) {
		*dp++ = *cp++;
	}
	*dp++ = '\0';
	return buf;
}

/******************************************************************************/
/*
 *	Parse an ascii number. Supports radix 10 or 16.
 */

int mprAtoi(const char *str, int radix)
{
	int		c, val, negative;

	mprAssert(radix == 10 || radix == 16);

	if (str == 0) {
		return 0;
	}

	val = 0;
	if (radix == 10 && *str == '-') {
		negative = 1;
		str++;
	} else {
		negative = 0;
	}

	if (radix == 10) {
		while (*str && isdigit(*str)) {
			val = (val * radix) + *str - '0';
			str++;
		}
	} else if (radix == 16) {
		if (*str == '0' && tolower(str[1]) == 'x') {
			str += 2;
		}
		while (*str) {
			c = tolower(*str);
			if (isdigit(c)) {
				val = (val * radix) + c - '0';
			} else if (c >= 'a' && c <= 'f') {
				val = (val * radix) + c - 'a' + 10;
			} else {
				break;
			}
			str++;
		}
	}

	return (negative) ? -val: val;
}

/******************************************************************************/
/*
 *	Make an argv array. Caller must free by calling mprFree(argv) to free
 *	everything.
 */

int mprMakeArgv(MprCtx ctx, const char *program, const char *cmd, 
	char ***argvp, int *argcp)
{
	char		*cp, **argv, *buf, *args;
	int			size, argc;

	/*
	 *	Allocate one buffer for argv and the actual args themselves
	 */
	size = strlen(cmd) + 1;

	buf = (char*) mprAlloc(ctx, (MPR_MAX_ARGC * sizeof(char*)) + size);
	if (buf == 0) {
		return MPR_ERR_MEMORY;
	}

	args = &buf[MPR_MAX_ARGC * sizeof(char*)];
	strcpy(args, cmd);
	argv = (char**) buf;

	argc = 0;
	if (program) {
		argv[argc++] = (char*) mprStrdup(ctx, program);
	}

	for (cp = args; cp && *cp != '\0'; argc++) {
		if (argc >= MPR_MAX_ARGC) {
			mprAssert(argc < MPR_MAX_ARGC);
			mprFree(buf);
			*argvp = 0;
			if (argcp) {
				*argcp = 0;
			}
			return MPR_ERR_TOO_MANY;
		}
		while (isspace(*cp)) {
			cp++;
		}
		if (*cp == '\0')  {
			break;
		}
		if (*cp == '"') {
			cp++;
			argv[argc] = cp;
			while ((*cp != '\0') && (*cp != '"')) {
				cp++;
			}
		} else {
			argv[argc] = cp;
			while (*cp != '\0' && !isspace(*cp)) {
				cp++;
			}
		}
		if (*cp != '\0') {
			*cp++ = '\0';
		}
	}
	argv[argc] = 0;

	if (argcp) {
		*argcp = argc;
	}
	*argvp = argv;

	return argc;
}

/******************************************************************************/

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
