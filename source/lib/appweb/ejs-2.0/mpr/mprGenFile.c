/**
 *	@file 	mprGenFile.c
 *	@brief	Generic File services
 *	@overview 
 *	@remarks 
 *		See OS/mprFile.c for the per O/S portions
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

/****************************** Forward Declarations **************************/
#if !BREW

static int closeDestructor(void *data);

/************************************ Code ************************************/

int mprStartFileServices(MprCtx ctx)
{
	MprApp		*app;

	app = mprGetApp(ctx);
	app->console = mprAllocTypeZeroed(ctx, MprFile);
	app->error = mprAllocTypeZeroed(ctx, MprFile);

	/*
	 *	We assume that STDOUT is 1 and STDERR is 2
 	 */
	app->console->fd = 1;
	app->error->fd = 2;

	return 0;
}

/******************************************************************************/

void mprStopFileServices(MprCtx ctx)
{
	MprApp		*app;

	app = mprGetApp(ctx);

	mprFree(app->console);
	app->console = 0;
	mprFree(app->error);
	app->error = 0;
}

/******************************************************************************/

MprFile *mprOpen(MprCtx ctx, const char *path, int omode, int perms)
{
	MprFile		*file;
	
	mprAssert(path && *path);

	file = mprAllocTypeZeroed(ctx, MprFile);
	
	file->fd = open(path, omode, perms);
	if (file->fd < 0) {
		mprFree(file);
		return 0;
	}

	mprSetDestructor(file, closeDestructor);
	return file;
}

/******************************************************************************/

static int closeDestructor(void *data)
{
	MprFile	*file = (MprFile*) data;

	mprAssert(file);
	
	mprClose(file);
	return 0;
}

/******************************************************************************/

void mprClose(MprFile *file)
{
	mprAssert(file);

	if (file < 0) {
		return;
	}

	mprAssert(file->fd >= 0);
	close(file->fd);

	mprSetDestructor(file, 0);
	mprFree(file);
}
 
/******************************************************************************/

int mprRead(MprFile *file, void *buf, uint size)
{
	mprAssert(file);

	if (file == 0) {
		return MPR_ERR_BAD_HANDLE;
	}

	return read(file->fd, buf, size);
}

/******************************************************************************/

int mprWrite(MprFile *file, const void *buf, uint count)
{
	mprAssert(file);

	if (file == 0) {
		return MPR_ERR_BAD_HANDLE;
	}

	return write(file->fd, buf, count);
}

/******************************************************************************/

int mprSeek(MprFile *file, int seekType, long distance)
{
	mprAssert(file);

	if (file == 0) {
		return MPR_ERR_BAD_HANDLE;
	}

	return lseek(file->fd, seekType, distance);
}

/******************************************************************************/

int mprDelete(MprCtx ctx, const char *path)
{
	return unlink(path);
}

/******************************************************************************/

int mprDeleteDir(MprCtx ctx, const char *path)
{
	return rmdir(path);
}
 
#endif /* !BREW */
/******************************************************************************/

char *mprGets(MprFile *file, char *buf, uint size)
{
	MprBuf	*bp;
	int		count, len, c;

	mprAssert(file);

	if (file == 0) {
		return 0;
	}

	if (file->buf == 0) {
		file->buf = mprCreateBuf(file, MPR_DEFAULT_ALLOC, MPR_MAX_STRING);
	}
	bp = file->buf;

	/*
	 *	Must leave room for null
	 */
	count = 0;
	while (--size > 0) {
		if (mprGetBufLength(bp) == 0) {
			mprFlushBuf(bp);
			len = mprRead(file, mprGetBufEnd(bp), 
				mprGetBufLinearSpace(bp));
			if (len <= 0) {
				return 0;
			}
			mprAdjustBufEnd(bp, len);
			mprAddNullToBuf(bp);
		}
		if ((c = mprGetCharFromBuf(bp)) == '\n') {
			buf[count] = '\0';
			return buf;
		}
		buf[count++] = c;
	}
	buf[count] = '\0';
	return buf;
}

/******************************************************************************/

int mprPuts(MprFile *file, const char *writeBuf, uint count)
{
	MprBuf	*bp;
	char	*buf;
	int		total, bytes, len;

	mprAssert(file);

	/*
	 *	Buffer output and flush when full.
	 */
	if (file->buf == 0) {
		file->buf = mprCreateBuf(file, MPR_BUFSIZE, 0);
		if (file->buf == 0) {
			return MPR_ERR_CANT_ALLOCATE;
		}
	}
	bp = file->buf;

	if (mprGetBufLength(bp) > 0 && mprGetBufSpace(bp) < (int) count) {
		len = mprGetBufLength(bp);
		if (mprWrite(file, mprGetBufStart(bp), len) != len) {
			return MPR_ERR_CANT_WRITE;
		}
		mprFlushBuf(bp);
	}

	total = 0;
	buf = (char*) writeBuf;

	while (count > 0) {
		bytes = mprPutBlockToBuf(bp, buf, count);
		if (bytes <= 0) {
			return MPR_ERR_CANT_ALLOCATE;
		}
		count -= bytes;
		buf += bytes;
		total += bytes;
		mprAddNullToBuf(bp);

		if (count > 0) {
			len = mprGetBufLength(bp);
			if (mprWrite(file, mprGetBufStart(bp), len) != len) {
				return MPR_ERR_CANT_WRITE;
			}
			mprFlushBuf(bp);
		}
	}
	return total;
}

/******************************************************************************/

int mprMakeTempFileName(MprCtx ctx, char *buf, int bufsize, const char *tempDir)
{
	MprFile		*file;
	MprTime		now;
	char		*dir;
	int 		seed, i;

	if (tempDir == 0) {
#if WIN
		char	*cp;
		dir = mprStrdup(ctx, getenv("TEMP"));
		for (cp = dir; *cp; cp++) {
			if (*cp == '\\') {
				*cp = '/';
			}
		}
#else
		dir = mprStrdup(ctx, "/tmp");
#endif
	} else {
		dir = mprStrdup(ctx, tempDir);
	}

	mprGetTime(ctx, &now);
	seed = now.msec % 64000;
	file = 0;

	for (i = 0; i < 128; i++) {
		mprSprintf(buf, bufsize, "%s/MPR_%d_%d.tmp", dir, getpid(), seed++);
		file = mprOpen(ctx, buf, O_CREAT | O_EXCL | O_BINARY, 0664);
		if (file) {
			break;
		}
	}

	if (file == 0) {
		return MPR_ERR_CANT_CREATE;
	}

	mprClose(file);
	mprFree(dir);

	return 0;
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
