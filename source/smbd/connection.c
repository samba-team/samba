/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   connection claim routines
   Copyright (C) Andrew Tridgell 1998
   
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


extern fstring remote_machine;

extern int DEBUGLEVEL;

/****************************************************************************
simple routines to do connection counting
****************************************************************************/
BOOL yield_connection(connection_struct *conn,char *name,int max_connections)
{
	struct connect_record crec;
	pstring fname;
	int fd;
	pid_t mypid = getpid();
	int i;

	DEBUG(3,("Yielding connection to %s\n",name));

	if (max_connections <= 0)
		return(True);

	memset((char *)&crec,'\0',sizeof(crec));

	pstrcpy(fname,lp_lockdir());
	trim_string(fname,"","/");

	pstrcat(fname,"/");
	pstrcat(fname,name);
	pstrcat(fname,".LCK");

	fd = sys_open(fname,O_RDWR,0);
	if (fd == -1) {
		DEBUG(2,("Couldn't open lock file %s (%s)\n",fname,strerror(errno)));
		return(False);
	}

	if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_WRLCK)==False) {
		DEBUG(0,("ERROR: can't get lock on %s\n", fname));
		return False;
	}

	/* find the right spot */
	for (i=0;i<max_connections;i++) {
		if (read(fd, &crec,sizeof(crec)) != sizeof(crec)) {
			DEBUG(2,("Entry not found in lock file %s\n",fname));
			if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_UNLCK)==False) {
				DEBUG(0,("ERROR: can't release lock on %s\n", fname));
			}
			close(fd);
			return(False);
		}
		if (crec.pid == mypid && crec.cnum == conn->cnum)
			break;
	}

	if (crec.pid != mypid || crec.cnum != conn->cnum) {
		if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_UNLCK)==False) {
			DEBUG(0,("ERROR: can't release lock on %s\n", fname));
		}
		close(fd);
		DEBUG(2,("Entry not found in lock file %s\n",fname));
		return(False);
	}

	memset((void *)&crec,'\0',sizeof(crec));
  
	/* remove our mark */
	if (sys_lseek(fd,i*sizeof(crec),SEEK_SET) != i*sizeof(crec) ||
	    write(fd, &crec,sizeof(crec)) != sizeof(crec)) {
		DEBUG(2,("Couldn't update lock file %s (%s)\n",fname,strerror(errno)));
		if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_UNLCK)==False) {
			DEBUG(0,("ERROR: can't release lock on %s\n", fname));
		}
		close(fd);
		return(False);
	}

	if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_UNLCK)==False) {
		DEBUG(0,("ERROR: can't release lock on %s\n", fname));
	}

	DEBUG(3,("Yield successful\n"));

	close(fd);
	return(True);
}


/****************************************************************************
simple routines to do connection counting
****************************************************************************/
BOOL claim_connection(connection_struct *conn,char *name,int max_connections,BOOL Clear)
{
	extern int Client;
	struct connect_record crec;
	pstring fname;
	int fd=-1;
	int i,foundi= -1;
	int total_recs;
	
	if (max_connections <= 0)
		return(True);
	
	DEBUG(5,("trying claim %s %s %d\n",lp_lockdir(),name,max_connections));
	
	pstrcpy(fname,lp_lockdir());
	trim_string(fname,"","/");
	
	if (!directory_exist(fname,NULL))
		mkdir(fname,0755);
	
	pstrcat(fname,"/");
	pstrcat(fname,name);
	pstrcat(fname,".LCK");
	
	if (!file_exist(fname,NULL)) {
		fd = sys_open(fname,O_RDWR|O_CREAT|O_EXCL, 0644);
	}

	if (fd == -1) {
		fd = sys_open(fname,O_RDWR,0);
	}
	
	if (fd == -1) {
		DEBUG(1,("couldn't open lock file %s\n",fname));
		return(False);
	}

	if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_WRLCK)==False) {
		DEBUG(0,("ERROR: can't get lock on %s\n", fname));
		return False;
	}

	total_recs = get_file_size(fname) / sizeof(crec);
			
	/* find a free spot */
	for (i=0;i<max_connections;i++) {
		if (i>=total_recs || 
		    sys_lseek(fd,i*sizeof(crec),SEEK_SET) != i*sizeof(crec) ||
		    read(fd,&crec,sizeof(crec)) != sizeof(crec)) {
			if (foundi < 0) foundi = i;
			break;
		}
		
		if (Clear && crec.pid && !process_exists(crec.pid)) {
			if(sys_lseek(fd,i*sizeof(crec),SEEK_SET) != i*sizeof(crec)) {
              DEBUG(0,("claim_connection: ERROR: sys_lseek failed to seek \
to %d\n", (int)(i*sizeof(crec)) ));
              continue;
            }
			memset((void *)&crec,'\0',sizeof(crec));
			write(fd, &crec,sizeof(crec));
			if (foundi < 0) foundi = i;
			continue;
		}
		if (foundi < 0 && (!crec.pid || !process_exists(crec.pid))) {
			foundi=i;
			if (!Clear) break;
		}
	}  
	
	if (foundi < 0) {
		DEBUG(3,("no free locks in %s\n",fname));
		if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_UNLCK)==False) {
			DEBUG(0,("ERROR: can't release lock on %s\n", fname));
		}
		close(fd);
		return(False);
	}      
	
	/* fill in the crec */
	memset((void *)&crec,'\0',sizeof(crec));
	crec.magic = 0x280267;
	crec.pid = getpid();
	if (conn) {
		crec.cnum = conn->cnum;
		crec.uid = conn->uid;
		crec.gid = conn->gid;
		StrnCpy(crec.name,
			lp_servicename(SNUM(conn)),sizeof(crec.name)-1);
	} else {
		crec.cnum = -1;
	}
	crec.start = time(NULL);
	
	StrnCpy(crec.machine,remote_machine,sizeof(crec.machine)-1);
	StrnCpy(crec.addr,client_addr(Client),sizeof(crec.addr)-1);
	
	/* make our mark */
	if (sys_lseek(fd,foundi*sizeof(crec),SEEK_SET) != foundi*sizeof(crec) ||
	    write(fd, &crec,sizeof(crec)) != sizeof(crec)) {
		if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_UNLCK)==False) {
			DEBUG(0,("ERROR: can't release lock on %s\n", fname));
		}
		close(fd);
		return(False);
	}

	if (fcntl_lock(fd,SMB_F_SETLKW,0,1,F_UNLCK)==False) {
		DEBUG(0,("ERROR: can't release lock on %s\n", fname));
	}
	
	close(fd);
	return(True);
}
