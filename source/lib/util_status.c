/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba connection status utility functions
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Michael Glauche 1999-2000
   
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

   Revision History:

   2. may 2000: mg@glauche.de 
   added TDB status lookup
*/

#include "includes.h"

extern int DEBUGLEVEL;
static int status_locks_count;
static int status_locks_pid;

/*******************************************************************
parse the STATUS..LCK file.  caller is responsible for freeing *crec.
********************************************************************/
BOOL get_connection_status(struct connect_record **crec,
				uint32 *connection_count)
{
  int fd;
  pstring fname;
  TDB_CONTEXT *tdb;
  TDB_DATA key,nextkey,d;
  int conn;
  int num_recs;
  struct connect_record *c;
  struct connections_data cdata;  
  int i;

  if (crec == NULL || connection_count == NULL)
  {
    return False;
  }
  conn = 0;
  
  tdb = tdb_open(lock_path("connections.tdb"), 0, 0, O_RDONLY, 0);
  if (!tdb) {
    DEBUG(0,("connections.tdb not initialised\n"));
    if (!lp_status(-1))
       DEBUG(0,("You need to have status=yes in your smb config file\n"));
      
    return False;
  }  else {
       DEBUG(5,("Opened TDB status file\n"));
  }

  (*crec) = NULL;
  conn = 0;

  key = tdb_firstkey(tdb);
  while (key.dptr) {
    d = tdb_fetch(tdb, key);

    memcpy(&cdata, d.dptr, sizeof(cdata));

    DEBUG(5,("TDB status cnum = %d\n",cdata.cnum));
    DEBUG(5,("TDB status pid = %u\n",cdata.pid));

    if ((cdata.cnum != -1) && (process_exists(cdata.pid))) {
        (*crec) = Realloc((*crec), (conn+1) * sizeof((*crec)[conn]));
        if ((*crec) == NULL)
            {
              DEBUG(0,("Realloc failed in get_connection_status\n"));
              return False;
            }

	c = &((*crec)[conn]);
        c->uid = cdata.uid;
	c->pid = cdata.pid;
	c->cnum = cdata.cnum;
	pstrcpy(c->name,cdata.name);
	pstrcpy(c->addr,cdata.addr);
	pstrcpy(c->machine,cdata.machine);
	c->start = cdata.start;

        DEBUG(5,("TDB status name = %s\n",c->name));
        conn++;
    }

    nextkey = tdb_nextkey(tdb, key);
    free(key.dptr);
    free(d.dptr);
    key = nextkey;
  } 
  
  (*connection_count)=conn;
  return True;
}

/*******************************************************************
Get the number of open Sessions. Not optimal yet. Has at least O(n*log(n)).
 ********************************************************************/
BOOL get_session_count(struct connect_record **srec,uint32 *session_count)
{
  struct 	connect_record *crec = NULL;
  struct connect_record *c;
  
  uint32 	connection_count;
  uint32 	conn;	
  int		*pid;
  int 		i;
  int		MaxPid;
  BOOL		found;

  (*srec) = NULL;
  pid = NULL;   
  if (get_connection_status(&crec, &connection_count))
   {
     MaxPid = 0;
     for (conn = 0; conn < connection_count; conn++)
       {
         DEBUG(3,("Connection nr : %u\n",conn));
         found=False;
         for (i = 0; i < MaxPid; i++) 
	 {
           if (crec[conn].pid == pid[i]) 
	   { 
             DEBUG(3,("Session count - found PID : %u\n",pid[i]));

             found = True;
             i=MaxPid;
           }
         }
         if (!found) {
            DEBUG(3,("Session count - did not found PID : %u\n",crec[conn].pid));
           (*srec) = Realloc((*srec), (MaxPid+1) * sizeof((*srec)[MaxPid]));
           if ((*srec) == NULL)
            {
              DEBUG(0,("Realloc failed in get_connection_status\n"));
              return False;
            }
           pid = Realloc(pid, (MaxPid+1) * sizeof(int));
           if (pid == NULL)
           {
              DEBUG(0,("Realloc failed in get_session_count\n"));
   	      free(crec);
              return False;
           }
           c = &((*srec)[MaxPid]);
           pid[MaxPid]=crec[conn].pid;
	   pstrcpy(c->machine,crec[conn].machine);
	   c->uid = crec[conn].uid;
	   c->pid = crec[conn].pid;
	   c->cnum = crec[conn].cnum;
	   c->start = crec[conn].start;
	   pstrcpy(c->name,crec[conn].name);
	   
           MaxPid++;
         }
       }                                                             
   } else {
/* crec is not valid, so no need to free it here */
     return False;
   }
   free(crec);
   (*session_count) = MaxPid;
   return True;
}

/*******************************************************************
Get the number of open Locks. uses global variables *yuck* any 
other way to get the share modes without a traverse function ????
 ********************************************************************/


void status_traverse_share_mode(share_mode_entry *e, char *fname)
{
   if ((int)e->pid == status_locks_pid) {
   	status_locks_count ++;
   }
}

BOOL get_locks_count(int pid, uint32 *locks_count)
{
  int ret;

  if (pid < 1)
  {
    return False;
  }
  status_locks_count = 0;
  status_locks_pid = pid;  
  
  if (!locking_init(1)) {
       DEBUG(0,("Can't initialise shared memory - exiting\n"));
       return False;
  }
  ret = share_mode_forall(status_traverse_share_mode);
  locking_end();
  DEBUG(3,("Locks found for PID %u : %u\n",pid,status_locks_count));
  (*locks_count) = status_locks_count;

  return ret;
}
