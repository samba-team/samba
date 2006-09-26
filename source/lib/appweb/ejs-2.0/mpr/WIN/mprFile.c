/**
 *	@file 	mprWinFile.c
 *	@brief	File services for Windows
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
	/*
	 *	MOB -- these are time64_t. Loss of precision
	 */
	info->ctime = (uint) s.st_ctime;
	info->mtime = (uint) s.st_mtime;
	info->inode = s.st_ino;
	info->isDir = (s.st_mode & S_IFDIR) != 0;
	info->isReg = (s.st_mode & S_IFREG) != 0;

	/*
	 *  Work hard on windows to determine if the file is a regular file.
	 *	FUTURE -- OPT. Eliminate this CreateFile.
	 */
	if (info->isReg) {
		long	fileType, att;

		if ((att = GetFileAttributes(path)) == -1) {
			return -1;
		}
		if (att & (FILE_ATTRIBUTE_REPARSE_POINT |
				FILE_ATTRIBUTE_DIRECTORY |
				FILE_ATTRIBUTE_ENCRYPTED |
				FILE_ATTRIBUTE_SYSTEM |
				FILE_ATTRIBUTE_OFFLINE)) {
			/*
			 *	Catch accesses to devices like CON, AUX, NUL, LPT etc
			 *	att will be set to ENCRYPTED on Win9X and NT.
			 */
			info->isReg = 0;
		}
		if (info->isReg) {
			HANDLE handle;
			handle = CreateFile(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
				0, OPEN_EXISTING, 0, 0);
			if (handle == INVALID_HANDLE_VALUE) {
				info->isReg = 0;
			} else {
				fileType = GetFileType(handle);
				if (fileType == FILE_TYPE_CHAR || fileType == FILE_TYPE_PIPE) {
					info->isReg = 0;
				}
				CloseHandle(handle);
			}
		}
	}
	if (strcmp(path, "nul") == 0) {
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
