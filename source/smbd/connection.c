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

#ifdef WITH_UTMP
static void utmp_yield(pid_t pid, const connection_struct *conn, int i);
static void utmp_claim(const struct connect_record *crec, const connection_struct *conn, int i);
#endif

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

#ifdef WITH_UTMP
	utmp_yield(mypid, conn, i);
#endif

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

#ifdef WITH_UTMP
	utmp_claim(&crec, conn, foundi);
#endif

	return(True);
}

#ifdef WITH_UTMP

/****************************************************************************
Reflect connection status in utmp/wtmp files.
	T.D.Lee@durham.ac.uk  September 1999

Hints for porting:
	o Always attempt to use programmatic interface (pututline() etc.)
	o The "x" (utmpx/wtmpx; HAVE_UTMPX_H) seems preferable.

OS status:
	Solaris 2.x:  Tested on 2.6 and 2.7; should be OK on other flavours.
		T.D.Lee@durham.ac.uk
	HPUX 9.x:  Not tested.  Appears not to have "x".
	IRIX 6.5:  Not tested.  Appears to have "x".

Notes:
	The 4 byte 'ut_id' component is vital to distinguish connections,
	of which there could be several hundered or even thousand.
	Entries seem to be printable characters, with optional NULL pads.

	We need to be distinct from other entries in utmp/wtmp.

	Observed things: therefore avoid them.  Add to this list please.
	From Solaris 2.x (because that's what I have):
		'sN'	: run-levels; N: [0-9]
		'co'	: console
		'CC'	: arbitrary things;  C: [a-z]
		'rXNN'	: rlogin;  N: [0-9]; X: [0-9a-z]
		'tXNN'	: rlogin;  N: [0-9]; X: [0-9a-z]
		'/NNN'	: Solaris CDE
		'ftpZ'	: ftp (Z is the number 255, aka 0377, aka 0xff)
	Mostly a record uses the same 'ut_id' in both "utmp" and "wtmp",
	but differences have been seen.

	Arbitrarily I have chosen to use a distinctive 'SM' for the
	first two bytes.

	The remaining two encode the connection number used in samba locking
	functions "claim_connection() and "yield_connection()".  This seems
	to be a "nicely behaved" number: starting from 0 then working up
	looking for an available slot.

****************************************************************************/

#include <utmp.h>

#ifdef HAVE_UTMPX_H
#include <utmpx.h>
#endif

static const char *ut_id_encstr =
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static
int
ut_id_encode(int i, char *fourbyte)
{
	int nbase;

	fourbyte[0] = 'S';
	fourbyte[1] = 'M';

/*
 * Encode remaining 2 bytes from 'i'.
 * 'ut_id_encstr' is the character set on which modulo arithmetic is done.
 * Example: digits would produce the base-10 numbers from '001'.
 */
	nbase = strlen(ut_id_encstr);

	fourbyte[3] = ut_id_encstr[i % nbase];
	i /= nbase;
	fourbyte[2] = ut_id_encstr[i % nbase];
	i /= nbase;

	return(i);	/* 0: good; else overflow */
}

static int utmp_fill(struct utmp *u, const connection_struct *conn, pid_t pid, int i)
{
	struct timeval timeval;
	int rc;

	pstrcpy(u->ut_user, conn->user);
	rc = ut_id_encode(i, u->ut_id);
	slprintf(u->ut_line, 12, "smb/%d", i);

	u->ut_pid = pid;

	gettimeofday(&timeval, NULL);
	u->ut_time = timeval.tv_sec;

	return(rc);
}

static void utmp_update(const pstring dirname, const struct utmp *u, const char *host)
{
	pstring fname;

#ifdef HAVE_UTMPX_H
	struct utmpx ux, *uxrc;

	getutmpx(u, &ux);
	if (host) {
#if defined(HAVE_UX_UT_SYSLEN)
		ux.ut_syslen = strlen(host);
#endif /* defined(HAVE_UX_UT_SYSLEN) */
		pstrcpy(ux.ut_host, host);
	}

	pstrcpy(fname, dirname);
	pstrcat(fname, "utmpx");
	utmpxname(fname);
	uxrc = pututxline(&ux);
	if (uxrc == NULL) {
		DEBUG(2,("utmp_update: pututxline() failed\n"));
		return;
	}

	pstrcpy(fname, dirname);
	pstrcat(fname, "wtmpx");
	updwtmpx(fname, &ux);
#else
	pstrcpy(fname, dirname);
	pstrcat(fname, "utmp");

	utmpname(fname);
	pututline(u);

	pstrcpy(fname, dirname);
	pstrcat(fname, "wtmp");

	/* *** OK.  Appending wtmp (as distinct from overwriting utmp) has
	me baffled.  How is it to be done? *** */
#endif
}

static void utmp_yield(pid_t pid, const connection_struct *conn, int i)
{
	struct utmp u;
	pstring dirname;

	if (! lp_utmp(SNUM(conn))) {
		DEBUG(2,("utmp_yield: lp_utmp() NULL\n"));
		return;
	}

	pstrcpy(dirname,lp_utmpdir());
	trim_string(dirname,"","/");
	pstrcat(dirname,"/");

	DEBUG(2,("utmp_yield: dir:%s conn: user:%s cnum:%d i:%d\n",
	  dirname, conn->user, conn->cnum, i));

	memset((char *)&u, '\0', sizeof(struct utmp));
	u.ut_type = DEAD_PROCESS;
	u.ut_exit.e_termination = 0;
	u.ut_exit.e_exit = 0;
	if (utmp_fill(&u, conn, pid, i) == 0) {
		utmp_update(dirname, &u, NULL);
	}
}

static void utmp_claim(const struct connect_record *crec, const connection_struct *conn, int i)
{
	extern int Client;
	struct utmp u;
	pstring dirname;

	if (conn == NULL) {
		DEBUG(2,("utmp_claim: conn NULL\n"));
		return;
	}

	if (! lp_utmp(SNUM(conn))) {
		DEBUG(2,("utmp_claim: lp_utmp() NULL\n"));
		return;
	}

	pstrcpy(dirname,lp_utmpdir());
	trim_string(dirname,"","/");
	pstrcat(dirname,"/");

	DEBUG(2,("utmp_claim: dir:%s conn: user:%s cnum:%d i:%d\n",
	  dirname, conn->user, conn->cnum, i));
	DEBUG(2,("utmp_claim: crec: pid:%d, cnum:%d name:%s addr:%s mach:%s DNS:%s\n",
	  crec->pid, crec->cnum, crec->name, crec->addr, crec->machine, client_name(Client)));


	memset((char *)&u, '\0', sizeof(struct utmp));
	u.ut_type = USER_PROCESS;
	if (utmp_fill(&u, conn, crec->pid, i) == 0) {
		utmp_update(dirname, &u, crec->machine);
	}
}

#endif
