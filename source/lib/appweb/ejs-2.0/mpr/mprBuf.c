/**
 *	@file 	mprBuf.c
 *	@brief	Dynamic buffer module
 *	@overview 
 *	@remarks 
 */

/******************************************************************************/
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

#include	"mpr.h"

/**************************** Forward Declarations ****************************/

static int grow(MprBuf *bp);

/*********************************** Code *************************************/
/*
 *	Create a new buffer. "maxsize" is the limit to which the buffer can 
 *	ever grow. -1 means no limit. The buffer can ever only fix maxsize-1 bytes.
 *	"initialSize" is used to define the amount to increase the size of the 
 *	buffer each time if it becomes full. (Note: grow() will exponentially 
 *	increase this number for performance.)
 */

MprBuf *mprCreateBuf(MprCtx ctx, int initialSize, int maxSize)
{
	MprBuf		*bp;
	
	if (initialSize <= 0) {
		initialSize = MPR_DEFAULT_ALLOC;
	}
	bp = mprAllocTypeZeroed(ctx, MprBuf);
	bp->growBy = MPR_BUFSIZE;
	bp->maxsize = 0;
	mprSetBufSize(bp, initialSize, maxSize);
	return bp;
}

/******************************************************************************/
/*
 *	Set the initial buffer parameters and create the first buffer
 */

void mprSetBufSize(MprBuf *bp, int initialSize, int max)
{
	mprAssert(initialSize > 0);

	if (max > 0 && initialSize > max) {
		initialSize = max;
	}

	if (bp->buf && bp->growBy > 0) {
		mprFree(bp->buf);
	}

	bp->buf = (uchar*) mprAlloc(bp, initialSize);
	bp->growBy = initialSize;
	bp->maxsize = max;
	bp->buflen = initialSize;
	bp->endbuf = &bp->buf[bp->buflen];
	bp->start = bp->buf;
	bp->end = bp->buf;
	*bp->start = '\0';
}

/******************************************************************************/

char *mprStealBuf(MprCtx ctx, MprBuf *bp)
{
	char	*str;

	str = (char*) bp->start;

	mprStealAllocBlock(MPR_LOC_ARGS(ctx), bp->start);

	bp->start = bp->end = bp->buf = bp->endbuf = 0;
	bp->buflen = 0;

	return str;
}

/******************************************************************************/

void mprAddNullToBuf(MprBuf *bp)
{
	*((char*) bp->end) = (char) '\0';
}

/******************************************************************************/

void mprAdjustBufEnd(MprBuf *bp, int size)
{
	mprAssert(bp->buflen == (bp->endbuf - bp->buf));
	mprAssert(size < bp->buflen);

	bp->end += size;
	if (bp->end >= bp->endbuf) {
		bp->end -= bp->buflen;
	}
	if (bp->end < bp->buf) {
		bp->end += bp->buflen;
	}

	if (bp->end >= bp->endbuf) {
		mprAssert(bp->end < bp->endbuf);
		mprFlushBuf(bp);
	}
}

/******************************************************************************/
/*
 *	Adjust the start pointer after a user copy
 */

void mprAdjustBufStart(MprBuf *bp, int size)
{
	mprAssert(bp->buflen == (bp->endbuf - bp->buf));
	mprAssert(size < bp->buflen);

	bp->start += size;
	while (bp->start >= bp->endbuf) {
		bp->start -= bp->buflen;
	}
	while (bp->start < bp->buf) {
		bp->start += bp->buflen;
	}

	/*
	 *	Flush the buffer if the start pointer is corrupted via a bad size 
	 */
	if (bp->start >= bp->endbuf) {
		mprAssert(bp->start < bp->endbuf);
		mprFlushBuf(bp);
	}
}


/******************************************************************************/

void mprFlushBuf(MprBuf *bp)
{
	bp->start = bp->buf;
	bp->end = bp->buf;
}

/******************************************************************************/

int mprGetCharFromBuf(MprBuf *bp)
{
	int		c;

	if (bp->start == bp->end) {
		return -1;
	}
	c = (uchar) *bp->start++;
	if (bp->start >= bp->endbuf) {
		bp->start = bp->buf;
	}
	return c;
}

/******************************************************************************/

int mprGetBlockFromBuf(MprBuf *bp, uchar *buf, int size)
{
	int		thisLen, bytesRead;

	mprAssert(buf);
	mprAssert(size > 0);
	mprAssert(bp->buflen == (bp->endbuf - bp->buf));

	/*
	 *	Get the max bytes in a straight copy
	 */
	bytesRead = 0;
	while (size > 0) {
		thisLen = mprGetBufLinearData(bp);
		thisLen = min(thisLen, size);
		if (thisLen <= 0) {
			break;
		}

		memcpy(buf, bp->start, thisLen);
		buf += thisLen;
		bp->start += thisLen;
		size -= thisLen;
		bytesRead += thisLen;

		if (bp->start >= bp->endbuf) {
			bp->start = bp->buf;
		}
	}
	return bytesRead;
}

/******************************************************************************/

int mprGetBufLength(MprBuf *bp)
{
	if (bp->start > bp->end) {
		return (bp->buflen + (bp->end - bp->start));
	} else {
		return (bp->end - bp->start);
	}
}

/******************************************************************************/

int mprGetBufLinearData(MprBuf *bp)
{
	return min(mprGetBufLength(bp), (bp->endbuf - bp->start));
}

/******************************************************************************/

int mprGetBufLinearSpace(MprBuf *bp)
{
	int len = mprGetBufLength(bp);
	int space = bp->buflen - len - 1;
	return min((bp->endbuf - bp->end), space);
}

/******************************************************************************/

int mprGetBufSize(MprBuf *bp)
{
	return bp->buflen;
}

/******************************************************************************/

int mprGetBufSpace(MprBuf *bp)
{
	return bp->buflen - mprGetBufLength(bp) - 1;
}

/******************************************************************************/

char *mprGetBufOrigin(MprBuf *bp)
{
	return (char*) bp->buf;
}

/******************************************************************************/

char *mprGetBufStart(MprBuf *bp)
{
	return (char*) bp->start;
}

/******************************************************************************/

char *mprGetBufEnd(MprBuf *bp)
{
	return (char*) bp->end;
}

/******************************************************************************/

int mprInsertCharToBuf(MprBuf *bp, int c)
{
	char	*cp;
	int		space;

	mprAssert(bp->buflen == (bp->endbuf - bp->buf));

	space = bp->buflen - mprGetBufLength(bp) - 1;
	if (space < (int) sizeof(char)) {
		if (!grow(bp)) {
			return -1;
		}
	}
	if (bp->start <= bp->buf) {
		bp->start = bp->endbuf;
	}
	cp = (char*) bp->start;
	*--cp = (char) c;
	bp->start = (uchar *) cp;
	return 0;
}

/******************************************************************************/

int mprLookAtNextCharInBuf(MprBuf *bp)
{
	if (bp->start == bp->end) {
		return -1;
	}
	return *bp->start;
}

/******************************************************************************/

int mprLookAtLastCharInBuf(MprBuf *bp)
{
	if (bp->start == bp->end) {
		return -1;
	}
	return (bp->end == bp->buf) ? bp->endbuf[-1] : bp->end[-1];
}

/******************************************************************************/

int mprPutCharToBuf(MprBuf *bp, int c)
{
	char	*cp;
	int		space;

	mprAssert(bp->buflen == (bp->endbuf - bp->buf));

	space = bp->buflen - mprGetBufLength(bp) - 1;
	if (space < (int) sizeof(char)) {
		if (! grow(bp)) {
			return -1;
		}
	}

	cp = (char*) bp->end;
	*cp++ = (char) c;
	bp->end = (uchar *) cp;
	if (bp->end >= bp->endbuf) {
		bp->end = bp->buf;
	}
	*((char*) bp->end) = (char) '\0';
	return 0;
}

/******************************************************************************/

int mprPutBlockToBuf(MprBuf *bp, const char *str, int size)
{
	int		thisLen, bytes, space;

	mprAssert(str);
	mprAssert(size >= 0);
	mprAssert(bp->buflen == (bp->endbuf - bp->buf));

	/*
	 *	Add the max we can in one copy
	 */
	bytes = 0;
	while (size > 0) {
		space = mprGetBufLinearSpace(bp);
		thisLen = min(space, size);
		if (thisLen <= 0) {
			if (! grow(bp)) {
				break;
			}
			space = mprGetBufLinearSpace(bp);
			thisLen = min(space, size);
		}

		memcpy(bp->end, str, thisLen);
		str += thisLen;
		bp->end += thisLen;
		size -= thisLen;
		bytes += thisLen;

		if (bp->end >= bp->endbuf) {
			bp->end = bp->buf;
		}
	}
	*((char*) bp->end) = (char) '\0';
	return bytes;
}

/******************************************************************************/

int mprPutStringToBuf(MprBuf *bp, const char *str)
{
	return mprPutBlockToBuf(bp, str, strlen(str));
}

/******************************************************************************/

int mprPutFmtStringToBuf(MprBuf *bp, const char *fmt, ...)
{
	va_list		ap;
	char		*buf;
	int			rc, len, space;

	va_start(ap, fmt);
	space = mprGetBufLinearSpace(bp);

	/*
	 *	Add max that the buffer can grow 
	 */
	space += (bp->maxsize - bp->buflen - 1);

	len = mprAllocVsprintf(MPR_LOC_ARGS(bp), &buf, space, fmt, ap);
	rc = mprPutBlockToBuf(bp, buf, len);

	mprFree(buf);
	va_end(ap);
	return rc;
}

/******************************************************************************/
/*
 *	Grow the buffer to fit new data. Return 1 if the buffer can grow. 
 *	Grow using the growBy size specified when creating the buffer. 
 */

static int grow(MprBuf *bp)
{
	uchar	*newbuf;

	if (bp->maxsize > 0 && bp->buflen >= bp->maxsize) {
		return 0;
	}

	newbuf = (uchar*) mprAlloc(bp, bp->buflen + bp->growBy);
	if (bp->buf) {
		memcpy(newbuf, bp->buf, bp->buflen);
		mprFree(bp->buf);
	}

	bp->buflen += bp->growBy;
	bp->end = newbuf + (bp->end - bp->buf);
	bp->start = newbuf + (bp->start - bp->buf);
	bp->buf = newbuf;
	bp->endbuf = &bp->buf[bp->buflen];

	/*
	 *	Increase growBy to reduce overhead
	 */
	bp->growBy *= 2;
	if (bp->maxsize > 0 && (bp->buflen + bp->growBy) > bp->maxsize) {
		bp->growBy = bp->maxsize - bp->buflen;
	}
	return 1;
}

/******************************************************************************/
/*
 *	Add a number to the buffer (always null terminated).
 */

int mprPutIntToBuf(MprBuf *bp, int i)
{
	char	numBuf[16];
	int		rc;

	mprItoa(numBuf, sizeof(numBuf), i);
	rc = mprPutStringToBuf(bp, numBuf);
	*((char*) bp->end) = (char) '\0';

	return rc;
}

/******************************************************************************/

void mprCopyBufDown(MprBuf *bp)
{
	if (mprGetBufLength(bp) == 0) {
		mprFlushBuf(bp);
		return;
	}
	memmove(bp->buf, bp->start, (bp->end - bp->start));
	bp->end -= (bp->start - bp->buf);
	bp->start = bp->buf;
}

/******************************************************************************/

MprBufProc mprGetBufRefillProc(MprBuf *bp) 
{
	return bp->refillProc;
}

/******************************************************************************/

void mprSetBufRefillProc(MprBuf *bp, MprBufProc fn, void *arg)
{ 
	bp->refillProc = fn; 
	bp->refillArg = arg; 
}

/******************************************************************************/

int	mprRefillBuf(MprBuf *bp) 
{ 
	return (bp->refillProc) ? (bp->refillProc)(bp, bp->refillArg) : 0; 
}

/******************************************************************************/

void mprResetBufIfEmpty(MprBuf *bp)
{
	if (mprGetBufLength(bp) == 0) {
		mprFlushBuf(bp);
	}
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
