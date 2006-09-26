/**
 *	@file mprTime.c 
 *	@brief Time handling for VxWorks
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

#undef localtime
#undef localtime_r
#undef gmtime
#undef gmtime_r
#undef ctime
#undef ctime_r
#undef asctime
#undef asctime_r

/******************************************************************************/
/*
 *	Returns time in seconds and milliseconds. This is NOT time-of-day.
 */

MprTime *mprGetTime(MprCtx ctx, MprTime *tp)
{
	struct timeval	tv;

	if (gettimeofday(&tv, 0) < 0) {
		mprAssert(0);
		tp->sec = 0;
		tp->msec = 0;
		return tp;
	}
	tp->sec = tv.tv_sec;
	tp->msec = tv.tv_usec / 1000;
	return tp;
}

/******************************************************************************/
/*
 *	Thread-safe wrapping of localtime 
 */

struct tm *mprLocaltime(MprCtx ctx, struct tm *timep, time_t *now)
{
	localtime_r(now, timep);

	return timep;
}

/******************************************************************************/
/*
 *	Thread-safe wrapping of gmtime 
 */

struct tm *mprGmtime(MprCtx ctx, time_t *now, struct tm *timep)
{
	gmtime_r(now, timep);

	return timep;
}

/******************************************************************************/
/*
 *	Thread-safe wrapping of ctime
 */

int mprCtime(MprCtx ctx, char *buf, int bufsize, const time_t *timer)
{
	char	localBuf[80];
	char	*cp;
	int		len;
		
	mprAssert(buf);

	mprGlobalLock(ctx);

	cp = ctime_r(timer, localBuf);
	if ((int) strlen(cp) >= bufsize) {
		mprStrcpy(buf, bufsize, "WONT FIT");
		mprAssert(0);
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
	char	localBuf[80];

	cp = asctime_r(timeptr, localBuf);
	if ((int) strlen(cp) >= bufsize) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	mprStrcpy(buf, bufsize, cp);

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
