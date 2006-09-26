/**
 *	@file 	mprPlatform.c
 *	@brief	Cross platform routines 
 *	@overview This module provides low level cross platform routines.
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

/********************************** Includes **********************************/
/*
 *	We need to use the underlying str(cpy) routines to implement our safe
 *	alternatives
 */
#if !DOXYGEN
#define 	UNSAFE_FUNCTIONS_OK 1
#endif

#include	"mpr.h"

/************************************ Code ************************************/

char *mprInetToStr(char *buffer, int bufsize, const struct in_addr in)
{
#if HAVE_NTOA_R
	inet_ntoa_r(in, buffer, bufsize);
#else
	uchar	*cp;
	/*	FUTURE -- this is not portable */
	cp = (uchar*) &in;
	mprSprintf(buffer, bufsize, "%d.%d.%d.%d", cp[0], cp[1], cp[2], cp[3]);
#endif
	return buffer;
}

/******************************************************************************/

void mprSetShell(MprCtx ctx, void *shell)
{
}

/******************************************************************************/

void *mprGetShell(MprCtx ctx)
{
	return 0;
}

/******************************************************************************/
/*
 *	Sleep. Period given in milliseconds.
 */

void mprSleep(MprCtx ctx, int milliseconds)
{
	struct timeval 	timeout;
	int				rc;

	timeout.tv_sec = milliseconds / 1000;
	timeout.tv_usec = (milliseconds % 1000) * 1000;
	do {
		rc = select(1, 0, 0, 0, &timeout);
	} while (rc < 0 && errno == EINTR);
}

/******************************************************************************/
/*
 *	Make intervening directories
 */

int mprMakeDirPath(MprCtx ctx, const char *path)
{
	char	dir[MPR_MAX_PATH], buf[MPR_MAX_PATH];
	char	*dirSep;
	char	*next, *tok;

	dir[0] = '\0';
	dirSep = "/\\";

	if (path == 0 || *path == '\0') {
		return MPR_ERR_BAD_ARGS;
	}

	mprStrcpy(buf, sizeof(buf), path);
	next = mprStrTok(buf, dirSep, &tok);
	if (*buf == '/') {
		dir[0] = '/';
	}
	while (next != NULL) {
		if (strcmp(next, ".") == 0 ) {
			next = mprStrTok(NULL, dirSep, &tok);
			continue;
		}
		strcat(dir, next);
		if (access(dir, R_OK) != 0) {
			if (mkdir(dir) < 0) {
				return MPR_ERR_CANT_CREATE;
			}
		}
		strcat(dir, "/");
		next = mprStrTok(NULL, dirSep, &tok);
	}
	return 0;
}

/******************************************************************************/
/*
 *	Get a fully qualified file name for the given path. Return with forward
 *	slashes always
 */

char *mprGetFullPathName(char *buf, int buflen, const char *path)
{
	if (mprStrcpy(buf, buflen, path) < 0) {
		mprAssert(0);
		return 0;
	}
	return buf;
}

/******************************************************************************/
/*
 *	Replacement for gethostbyname that is multi-thread safe
 */

struct hostent *mprGetHostByName(MprCtx ctx, const char *name)
{
	struct hostent	*hp;

	hp = (struct hostent*) mprAlloc(ctx, sizeof(struct hostent));
	memset(hp, 0, sizeof(struct hostent));

	struct in_addr inaddr;
	inaddr.s_addr = (ulong) hostGetByName(name);
	if (inaddr.s_addr < 0) {
		mprAssert(0);
		return 0;
	}
	hp->h_addrtype = AF_INET;
	hp->h_length = sizeof(int);
	hp->h_name = mprStrdup(name);
	hp->h_addr_list = 0;
	hp->h_aliases = 0;

	hp->h_addr_list = new char*[2];
	hp->h_addr_list[0] = (char *) mprAlloc(hp, sizeof(struct in_addr));
	memcpy(&hp->h_addr_list[0], &inaddr, hp->h_length);
	hp->h_addr_list[1] = 0;

	return hp;
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
