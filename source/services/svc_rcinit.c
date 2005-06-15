
/* 
 *  Unix SMB/CIFS implementation.
 *  Service Control API Implementation
 *  Copyright (C) Gerald Carter                   2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

/* Implementation for LSB compliant init scripts */

/*******************************************************************************
 Get the services information  by reading and parsing the shell scripts. These 
 are symbolically linked into the  SVCCTL_SCRIPT_DIR  directory.

 Get the names of the services/scripts to read from the smb.conf file.
*******************************************************************************/

BOOL get_LSB_data(char *fname,Service_info *si )
{
	pstring initdfile;
	char mybuffer[256];
	const char *tokenptr;
	char **qlines;
	int fd = -1;
	int nlines, *numlines,i,in_section,in_description;
	
	pstrcpy(si->servicename,"");
	pstrcpy(si->servicetype,"EXTERNAL");
	pstrcpy(si->filename,fname);
	pstrcpy(si->provides,"");
	pstrcpy(si->dependencies,"");
	pstrcpy(si->shouldstart,"");
	pstrcpy(si->shouldstop,"");
	pstrcpy(si->requiredstart,"");
	pstrcpy(si->requiredstop,"");
	pstrcpy(si->description,"");
	pstrcpy(si->shortdescription,"");

	numlines = &nlines;
	in_section = 0;
	in_description = 0;

   
	if( !fname || !*fname ) {
		DEBUG(0, ("Must define an \"LSB-style init file\" to read.\n"));
		return False;
	}
	pstrcpy(initdfile,dyn_LIBDIR);
	pstrcat(initdfile,SVCCTL_SCRIPT_DIR);
	pstrcat(initdfile,fname);

	/* TODO  - should check to see if the file that we're trying to open is 
	   actually a script. If it's NOT, we should do something like warn, 
	   and not continue to try to find info we're looking for */

	DEBUG(10, ("Opening [%s]\n", initdfile));
	fd = -1;
	fd = open(initdfile,O_RDONLY);
	*numlines = 0;

	if (fd == -1) {
		DEBUG(10, ("Couldn't open [%s]\n", initdfile));
		return False;
	}

	qlines = fd_lines_load(fd, numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", *numlines));
	close(fd);
    

	if (*numlines) {
	
		for(i = 0; i < *numlines; i++) {

			DEBUGADD(10, ("Line[%d] = %s\n", i, qlines[i]));
			if (!in_section && (0==strwicmp("### BEGIN INIT INFO", qlines[i]))) {
				/* we now can look for params */
				DEBUGADD(10, ("Configuration information starts on line = [%d]\n", i));
				in_section = 1;

			} else if (in_section && (0==strwicmp("### END INIT INFO", qlines[i]))) {
				DEBUGADD(10, ("Configuration information ends on line = [%d]\n", i));
				DEBUGADD(10, ("Description is [%s]\n", si->description));
				in_description = 0;
				in_section = 0;
				break;
			} else if (in_section) {
				tokenptr = qlines[i];
				if (in_description) {
					DEBUGADD(10, ("Processing DESCRIPTION [%d]\n", *tokenptr));
					if (tokenptr && (*tokenptr=='#') && (*(tokenptr+1)=='\t')) {
						DEBUGADD(10, ("Adding to DESCRIPTION [%d]\n", *tokenptr));
						pstrcat(si->description," ");
						pstrcat(si->description,tokenptr+2);
						continue;
					}
					in_description = 0;
					DEBUGADD(10, ("Not a description!\n"));
				}
				if (!next_token(&tokenptr,mybuffer," \t",sizeof(mybuffer))) {
					DEBUGADD(10, ("Invalid line [%d]\n", i));
					break; /* bad line? */
				}
				if (0 != strncmp(mybuffer,"#",1)) {
					DEBUGADD(10, ("Invalid line [%d], is %s\n", i,mybuffer));
					break;
				}
				if (!next_token(&tokenptr,mybuffer," \t",sizeof(mybuffer))) {
					DEBUGADD(10, ("Invalid token on line [%d]\n", i));
					break; /* bad line? */
				}	      
				DEBUGADD(10, ("Keyword is  [%s]\n", mybuffer));
				if (0==strwicmp(mybuffer,"Description:")) {
					while (tokenptr && *tokenptr && (strchr(" \t",*tokenptr))) { 
						tokenptr++; 
					}
					pstrcpy(si->description,tokenptr);
					DEBUGADD(10, ("FOUND DESCRIPTION! Data is [%s]\n", tokenptr));
					in_description = 1;
				} else {
					while (tokenptr && *tokenptr && (strchr(" \t",*tokenptr))) { 
						tokenptr++; 
					}
					DEBUGADD(10, ("Data is [%s]\n", tokenptr));
					in_description = 0;

					/* save certain keywords, don't save others */
					if (0==strwicmp(mybuffer, "Provides:")) {
						pstrcpy(si->provides,tokenptr);
						pstrcpy(si->servicename,tokenptr);
					}

					if (0==strwicmp(mybuffer, "Short-Description:")) {
						pstrcpy(si->shortdescription,tokenptr);
					}

					if (0==strwicmp(mybuffer, "Required-start:")) {
						pstrcpy(si->requiredstart,tokenptr);
						pstrcpy(si->dependencies,tokenptr);
					}

					if (0==strwicmp(mybuffer, "Should-start:")) {
						pstrcpy(si->shouldstart,tokenptr);
					}
				}
			}
		}

		file_lines_free(qlines);
			return True;
	}

	return False;
}

/*********************************************************************
*********************************************************************/

static WERROR rcinit_stop( void )
{
	return WERR_OK;
}

/*********************************************************************
*********************************************************************/

static WERROR rcinit_start( void )
{
	return WERR_OK;
}

/*********************************************************************
*********************************************************************/

static WERROR rcinit_status( SERVICE_STATUS *service_status )
{
	return WERR_OK;
}

/*********************************************************************
*********************************************************************/

/* struct for svcctl control to manipulate rcinit service */

SERVICE_CONTROL_OPS rcinit_svc_ops = {
	rcinit_stop,
	rcinit_start,
	rcinit_status
};
