/* 
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Jeremy Allison                 2003
   Copyright (C) Gerald (Jerry) Carter          2004
   
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


/**********************************************************************
 logging function used by smbd to detect and remove corrupted tdb's
**********************************************************************/

void smbd_tdb_log(TDB_CONTEXT *tdb, int level, const char *format, ...)
{
	va_list ap;
	char *ptr = NULL;
	BOOL decrement_smbd_count;

	va_start(ap, format);
	vasprintf(&ptr, format, ap);
	va_end(ap);
	
	if (!ptr || !*ptr)
		return;

	DEBUG(level, ("tdb(%s): %s", tdb->name ? tdb->name : "unnamed", ptr));
	
	if (tdb->ecode == TDB_ERR_CORRUPT) {
		int ret;

		DEBUG(0,("tdb_log: TDB %s is corrupt. Removing file and stopping this process.\n",
			tdb->name ));

		become_root();
		ret = unlink(tdb->name);
		if ( ret ) {
			DEBUG(0,("ERROR: %s\n", strerror(errno)));
		}
		unbecome_root();

		
		/* if its not connections.tdb, then make sure we decrement the 
		   smbd count.  If connections.tdb is bad, there's nothing we 
		   can do and everything will eventually shut down or clean 
		   up anyways */
		
		if ( strcmp(tdb->name, lock_path("connections.tdb")) == 0 )
			decrement_smbd_count = False;
		else
			decrement_smbd_count = True;
		
		/* now die */
		
		smb_panic2("corrupt tdb\n", decrement_smbd_count );
	}

	if (tdb->ecode == TDB_ERR_IO) 
	{
		if ( strcmp(tdb->name, lock_path("connections.tdb")) == 0 )
			decrement_smbd_count = False;
		else
			decrement_smbd_count = True;
			
		smb_panic2( "i/o error on tdb.\n", decrement_smbd_count );
	}
	
	SAFE_FREE(ptr);
}

