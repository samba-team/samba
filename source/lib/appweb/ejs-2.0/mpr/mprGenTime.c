/**
 *	@file mprGenTime.c 
 *	@brief Generic Time handling
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

/******************************************************************************/
/*
 *	Return the number of milliseconds until the given timeout has expired.
 */

int mprGetTimeRemaining(MprCtx ctx, MprTime mark, uint timeout)
{
	MprTime		now;
	uint		diff;

	mprGetTime(ctx, &now);
	diff = ((now.sec - mark.sec) * 1000) + (now.msec - mark.msec);

	if (diff < 0) {
		/*
		 *	Detect time going backwards
		 */
		mprAssert(diff >= 0);
		diff = 0;
	}	
	return (int) (timeout - diff);
}
 
/******************************************************************************/
/*
 *	Return the number of milliseconds until the given timeout has expired.
 */

int mprGetElapsedTime(MprCtx ctx, MprTime mark)
{
	MprTime		now;

	mprGetTime(ctx, &now);
	return ((now.sec - mark.sec) * 1000) + (now.msec - mark.msec);
}
 
/******************************************************************************/

void mprAddElapsedToTime(MprTime *time, uint elapsed)
{
	time->sec += elapsed / 1000;
	time->msec += elapsed % 1000;
	if (time->msec > 1000) {
		time->msec -= 1000;
		time->sec++;
	}
}

/******************************************************************************/

int mprCompareTime(MprTime *t1, MprTime *t2)
{
	if (t1->sec < t2->sec) {
		return -1;
	} else if (t1->sec == t2->sec) {
		if (t1->msec < t2->msec) {
			return -1;
		} else if (t1->msec == t2->msec) {
			return 0;
		}
	}
	return 1;
}

/******************************************************************************/

uint mprSubtractTime(MprTime *t1, MprTime *t2)
{
	return ((t1->sec - t2->sec) * 1000) + (t1->msec - t2->msec);
}

/******************************************************************************/
#if !BREW
/*
 * 	Thread-safe RFC822 dates (Eg: "Fri, 07 Jan 2003 12:12:21 GMT")
 */

int mprRfcTime(MprCtx ctx, char *buf, int bufsize, const struct tm *timep)
{
	char months[12][4] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", 
		"Oct", "Nov", "Dec"
	};

	char days[7][4] = {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
	};

    char	*dayp, *monthp;
    int		year;

	if (bufsize < 30) {
		return MPR_ERR_WONT_FIT;
	}
    dayp = &days[timep->tm_wday][0];
    *buf++ = *dayp++;
    *buf++ = *dayp++;
    *buf++ = *dayp++;
    *buf++ = ',';
    *buf++ = ' ';

    *buf++ = timep->tm_mday / 10 + '0';
    *buf++ = timep->tm_mday % 10 + '0';
    *buf++ = ' ';

    monthp = &months[timep->tm_mon][0];
    *buf++ = *monthp++;
    *buf++ = *monthp++;
    *buf++ = *monthp++;
    *buf++ = ' ';

    year = 1900 + timep->tm_year;
    /* This routine isn't y10k ready. */
    *buf++ = year / 1000 + '0';
    *buf++ = year % 1000 / 100 + '0';
    *buf++ = year % 100 / 10 + '0';
    *buf++ = year % 10 + '0';
    *buf++ = ' ';

    *buf++ = timep->tm_hour / 10 + '0';
    *buf++ = timep->tm_hour % 10 + '0';
    *buf++ = ':';
    *buf++ = timep->tm_min / 10 + '0';
    *buf++ = timep->tm_min % 10 + '0';
    *buf++ = ':';
    *buf++ = timep->tm_sec / 10 + '0';
    *buf++ = timep->tm_sec % 10 + '0';
    *buf++ = ' ';

    *buf++ = 'G';
    *buf++ = 'M';
    *buf++ = 'T';
    *buf++ = 0;
    return 0;
}

#endif
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
