/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba connection status utility functions
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Michael Glauche 1999
   
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

extern int DEBUGLEVEL;

/*******************************************************************
parse the STATUS..LCK file.  caller is responsible for freeing *crec.
********************************************************************/
BOOL get_connection_status(struct connect_record **crec,
				uint32 *connection_count)
{
  int fd;
  pstring fname;
  int conn;
  int num_recs;
  struct connect_record *c;
  int i;

  if (crec == NULL || connection_count == NULL)
  {
    return False;
  }

  pstrcpy(fname,lp_lockdir());
  standard_sub_basic(fname);
  trim_string(fname,"","/");
  pstrcat(fname,"/STATUS..LCK");
  
fd = sys_open(fname,O_RDONLY, 0);

  if (fd == -1)
  {
    DEBUG(0,("Couldn't open status file %s\n",fname));
    return False;
  }
 
  (*crec) = NULL;
 
   num_recs = file_size(fname) / sizeof(*c);

  DEBUG(5,("Opened status file %s, record count %d\n",fname, num_recs));

   for (i = 0, conn = 0; i < num_recs; i++)
   {
        (*crec) = Realloc((*crec), (conn+1) * sizeof((*crec)[conn]));
        if ((*crec) == NULL)
        {
           DEBUG(0,("Realloc failed in get_connection_status\n"));
           return False;
        }
	c = &((*crec)[conn]);
	if (sys_lseek(fd,i*sizeof(*c),SEEK_SET) != i*sizeof(*c) ||
	    read(fd,c,sizeof(*c)) != sizeof(*c))
        {
          DEBUG(0,("unable to read a crec in get_connection_status\n"));
	  break;
        }
	DEBUG(10,("cnum:%u.  pid: %d magic: %x\n",
	           c->cnum, c->pid, c->magic));
	if ( c->magic == 0x280267 && process_exists(c->pid) )
	  {
		conn++;
	  }
      }

    close(fd);
    (*connection_count)=conn;

    return True;
}
