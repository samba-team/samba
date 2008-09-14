/**
 *	@file mprTime.c  
 *	@brief Time handling for Windows
 *	@overview 
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

/********************************* Includes ***********************************/

#include	"mpr.h"

#ifdef __cplusplus
extern "C" {
#endif

/************************************ Code ************************************/
/*
 *	Returns time in seconds and milliseconds. This is NOT time-of-day.
 */

MprTime *mprGetTime(MprCtx ctx, MprTime *tp)
{
	FILETIME	fileTime;
	int64		now, base;

	GetSystemTimeAsFileTime(&fileTime);

	now = ((((int64) fileTime.dwHighDateTime) << BITS(uint)) +
			((int64) fileTime.dwLowDateTime));

	/*
	 *	Convert from 100-nanosec units to milliseconds
	 */
	now = (now / 10000);

	/*
	 *	Adjust to be seconds since Jan 1 1970. Do this to be consistent with 
	 *	UNIX but not really required by the API definition.
 	 */
	base = ((UINT64(365) * 86400 * (1970 - 1601)) * 1000);
	now -= base;
	tp->sec = (uint) (now / 1000);
	tp->msec = (uint) (now % 1000);

#if UNUSED
{
	static int64 start;

	if (start == 0) {
		start = now;
	}
	if (now < start) {
		mprLog(ctx, 0, "TIME WENT BACKWARDS");
		mprLog(ctx, 0, "start %Ld", start);
		mprLog(ctx, 0, "now   %Ld", now);
	}
	mprLog(ctx, 0, "getTime %Ld", now);
	start = now;
}
#endif

	return tp;
}

/******************************************************************************/
/*
 *	Thread-safe wrapping of localtime 
 */

struct tm *mprLocaltime(MprCtx ctx, struct tm *timep, time_t *now)
{
	struct tm *tbuf;
	mprGlobalLock(ctx);
	tbuf = localtime(now);
	*timep = *tbuf;
	mprGlobalUnlock(ctx);

	return timep;
}

/******************************************************************************/
/*
 *	Thread-safe wrapping of gmtime 
 */

struct tm *mprGmtime(MprCtx ctx, time_t *now, struct tm *timep)
{
	struct tm *tbuf;
	tbuf = gmtime(now);
	*timep = *tbuf;

	return timep;
}

/******************************************************************************/
/*
 *	Thread-safe wrapping of ctime
 */

int mprCtime(MprCtx ctx, char *buf, int bufsize, const time_t *timer)
{
	char	*cp;
	int		len;
		
	mprAssert(buf);

	mprGlobalLock(ctx);

	cp = ctime(timer);
	if ((int) strlen(cp) >= bufsize) {
		mprStrcpy(buf, bufsize, "WONT FIT");
		mprAssert(0);
		mprGlobalUnlock(ctx);
		return MPR_ERR_WONT_FIT;
	}

	len = mprStrcpy(buf, bufsize, cp);
	if (buf[len - 1] == '\n') {
		buf[len - 1] = '\0';
	}

	mprGlobalUnlock(ctx);

	return 0;
}

/******************************************************************************/
/*
 *	Thread-safe wrapping of asctime
 */

int mprAsctime(MprCtx ctx, char *buf, int bufsize, const struct tm *timeptr)
{
	char	*cp;

	mprAssert(buf);
	mprGlobalLock(ctx);
	cp = asctime(timeptr);
	if ((int) strlen(cp) >= bufsize) {
		mprAssert(0);
		mprGlobalUnlock(ctx);
		return MPR_ERR_WONT_FIT;
	}
	mprStrcpy(buf, bufsize, cp);
	mprGlobalUnlock(ctx);

	return strlen(buf);
}

/******************************************************************************/

#ifdef __cplusplus
}
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
