/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "MacExtensions.h"

extern int DEBUGLEVEL;

/*
** Given a path to file/directory build a path to the stream in question.
** If it is not a directory they place the .streams folder after the last
** slash then add the filename with the stream cat on. If it is a directory
** then just cat the .streams folder and the stream on it. If mode is true
** then force the .streams directory to be created.
**
** Some examples.
**   input::
**		fname = folder1/folder2/filea
** 		stream = :AFP_Resource:$DATA the resource fork
**		isDir = False
**   output::		
**		streampath = folder1/folder2/.streams/filea:AFP_Resource:$DATA
**
**   input::
**		fname = folder1/folder2
** 		stream = :AFP_AfpInfo:$DATA the Finder Info
**		isDir = True
**   output::		
**		streampath = folder1/folder2/.streams/:AFP_Resource:$DATA		
** 
*/ 
void makestreampath(char *fname, char *stream, char *streampath, int mode, int isDir, int dirOnly)
{
	char *cptr;

	pstrcpy(streampath, fname);
	if (!isDir)
	{
		cptr = strrchr(streampath, '/');
		if (cptr) *(cptr+1) = 0;
		else streampath[0] = 0;
	}
	else
	if (streampath[0] == 0)		/* Start at the current position */
		pstrcat(streampath, "./");
	else  pstrcat(streampath, "/");

	pstrcat(streampath, STREAM_FOLDER_SLASH);
	if (mode)
		(void)mkdir(streampath, 0777);
	if (! dirOnly)
	{
		cptr = strrchr(fname, '/');
		if (!isDir)
		{
			cptr = strrchr(fname, '/');
			if (cptr) pstrcat(streampath, cptr+1);
			else pstrcat(streampath, fname);
		}
		pstrcat(streampath, stream);
	}
	DEBUG(4,("MACEXTENSION-makestreampath: streampath = %s\n", streampath));
}

/*
** Given a path to file/directory open the stream in question.
*/ 
int openstream(char *fname, char *stream, int oflag, int mode, int isDir)
{
	pstring streampath;
	char *cptr;

	makestreampath(fname, stream, streampath, mode, isDir, False);
	return(open(streampath, oflag, mode));
}

/*
** Fill in the AFP structure with the default values and
** then write it out.
*/ 
void writedefaultafp(int fd, SambaAfpInfo *safp, int writeit)
{
	safp->afp.afpi_Signature = AFP_Signature;   		/* Must be *(PDWORD)"AFP" */
	safp->afp.afpi_Version = AFP_Version;     			/* Must be 0x00010000 */
	safp->afp.afpi_Reserved1 = 0;
	safp->afp.afpi_BackupTime = AFP_BackupTime;  		/* Backup time for the file/dir */
	memset(safp->afp.afpi_FinderInfo, 0,  AFP_FinderSize);	/* Finder Info (32 bytes) */
	memset(safp->afp.afpi_ProDosInfo, 0,  6);	/* ProDos Info (6 bytes) # */
	memset(safp->afp.afpi_Reserved2, 0,  6);
	safp->createtime = time(NULL);
	if (writeit) (void)write(fd, safp, sizeof(*safp));
}

/*
** Check to see if the fname has a stream component. 
** If it does then check to see if it is the data fork
** stream. If so then just remove the stream since we
** treat them the same otherwise build a path to the 
** streams folder.
** Return true if it is a stream
** Return false no stream and the name has not been touched.
*/ 
int CheckForStream(char *fname)
{
	pstring streampath;
	char *cptr;

	cptr = strrchr(fname, ':');
    	/* Must be a streams file */
	if (cptr && strequal(cptr, DefaultStreamTest))
    {
    	cptr = strstr(fname, AFPDATA_STREAM);
    	if (cptr) *cptr = 0;/* The datafork just remove the stream name */
    	else				/* Build the streams path */
    	{
 			makestreampath(fname, "", streampath, 1, False, False);
			pstrcpy(fname, streampath);
    	}
    	return(True);
    }
    return(False);
}
