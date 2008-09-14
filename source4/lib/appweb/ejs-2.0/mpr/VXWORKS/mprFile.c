/**
 *	@file 	mprUnixFile.c
 *	@brief	File services for Unix
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

/************************************ Code ************************************/

int mprGetFileInfo(MprCtx ctx, const char *path, MprFileInfo *info)
{
	struct stat	s;

	mprAssert(path);
	mprAssert(info);

	if (stat(path, &s) < 0) {
		return -1;
	}

	info->size = s.st_size;
	info->ctime = s.st_ctime;
	info->mtime = s.st_mtime;
	info->inode = s.st_ino;
	info->isDir = (s.st_mode & S_IFDIR) != 0;
	info->isReg = (s.st_mode & S_IFREG) != 0;

	if (strcmp(path, "/dev/null") == 0) {
		info->isReg = 0;
	}

	return 0;
}
 
/******************************************************************************/

int mprMakeDir(MprCtx ctx, const char *path, int perms)
{
	return mkdir(path, perms);
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
