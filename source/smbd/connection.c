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
static TDB_CONTEXT *tdb;

extern int DEBUGLEVEL;

#ifdef WITH_UTMP
static void utmp_yield(pid_t pid, const connection_struct *conn);
static void utmp_claim(const struct connections_data *crec, const connection_struct *conn);
#endif

/****************************************************************************
delete a connection record
****************************************************************************/
BOOL yield_connection(connection_struct *conn,char *name,int max_connections)
{
	struct connections_key key;
	TDB_DATA kbuf;

	if (!tdb) return False;

	DEBUG(3,("Yielding connection to %s\n",name));

	ZERO_STRUCT(key);
	key.pid = sys_getpid();
	if (conn) key.cnum = conn->cnum;
	fstrcpy(key.name, name);

	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	tdb_delete(tdb, kbuf);

#ifdef WITH_UTMP
	if(conn)
		utmp_yield(key.pid, conn);
#endif

	return(True);
}


/****************************************************************************
claim an entry in the connections database
****************************************************************************/
BOOL claim_connection(connection_struct *conn,char *name,int max_connections,BOOL Clear)
{
	struct connections_key key;
	struct connections_data crec;
	TDB_DATA kbuf, dbuf;

	if (max_connections <= 0)
		return(True);

	if (!tdb) {
		tdb = tdb_open(lock_path("connections.tdb"), 0, TDB_CLEAR_IF_FIRST, 
			       O_RDWR | O_CREAT, 0644);
	}
	if (!tdb) return False;

	DEBUG(5,("claiming %s %d\n",name,max_connections));

	ZERO_STRUCT(key);
	key.pid = sys_getpid();
	key.cnum = conn?conn->cnum:-1;
	fstrcpy(key.name, name);

	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	/* fill in the crec */
	ZERO_STRUCT(crec);
	crec.magic = 0x280267;
	crec.pid = sys_getpid();
	crec.cnum = conn?conn->cnum:-1;
	if (conn) {
		crec.uid = conn->uid;
		crec.gid = conn->gid;
		StrnCpy(crec.name,
			lp_servicename(SNUM(conn)),sizeof(crec.name)-1);
	}
	crec.start = time(NULL);
	
	StrnCpy(crec.machine,remote_machine,sizeof(crec.machine)-1);
	StrnCpy(crec.addr,conn?conn->client_address:client_addr(),sizeof(crec.addr)-1);

	dbuf.dptr = (char *)&crec;
	dbuf.dsize = sizeof(crec);

	if (tdb_store(tdb, kbuf, dbuf, TDB_REPLACE) != 0) return False;

#ifdef WITH_UTMP
	if (conn)
	    utmp_claim(&crec, conn);
#endif

	return True;
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

/* Default path (if possible) */
#ifdef	HAVE_UTMPX_H

# ifdef UTMPX_FILE
static char *ut_pathname = UTMPX_FILE;
# else
static char *ut_pathname = "";
# endif
# ifdef WTMPX_FILE
static char *wt_pathname = WTMPX_FILE;
# else
static char *wt_pathname = "";
# endif

#else	/* HAVE_UTMPX_H */

# ifdef UTMP_FILE
static char *ut_pathname = UTMP_FILE;
# else
static char *ut_pathname = "";
# endif
# ifdef WTMP_FILE
static char *wt_pathname = WTMP_FILE;
# else
static char *wt_pathname = "";
# endif

#endif	/* HAVE_UTMPX_H */

static void uw_pathname(pstring fname, const char *uw_name)
{
	pstring dirname;

	pstrcpy(dirname,lp_utmpdir());
	trim_string(dirname,"","/");

	/* Given directory: use it */
	if (dirname != 0 && strlen(dirname) != 0) {
		pstrcpy(fname, dirname);
		pstrcat(fname, "/");
		pstrcat(fname, uw_name);
		return;
	}

	/* No given directory: attempt to use default paths */
	if (uw_name[0] == 'u') {
		pstrcpy(fname, ut_pathname);
		return;
	}

	if (uw_name[0] == 'w') {
		pstrcpy(fname, wt_pathname);
		return;
	}

	pstrcpy(fname, "");
}

static void utmp_update(const struct utmp *u, const char *host)
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

	uw_pathname(fname, "utmpx");
	DEBUG(2,("utmp_update: fname:%s\n", fname));
	if (strlen(fname) != 0) {
		utmpxname(fname);
	}
	uxrc = pututxline(&ux);
	if (uxrc == NULL) {
		DEBUG(2,("utmp_update: pututxline() failed\n"));
		return;
	}

	uw_pathname(fname, "wtmpx");
	DEBUG(2,("utmp_update: fname:%s\n", fname));
	if (strlen(fname) != 0) {
		updwtmpx(fname, &ux);
	}
#else
	uw_pathname(fname, "utmp");
	DEBUG(2,("utmp_update: fname:%s\n", fname));
	if (strlen(fname) != 0) {
		utmpname(fname);
	}
	pututline(u);

	uw_pathname(fname, "wtmp");

	/* *** Hmmm.  Appending wtmp (as distinct from overwriting utmp) has
	me baffled.  How is it to be done? *** */
#endif
}

static void utmp_yield(pid_t pid, const connection_struct *conn)
{
	struct utmp u;

	if (! lp_utmp(SNUM(conn))) {
		DEBUG(2,("utmp_yield: lp_utmp() NULL\n"));
		return;
	}

	DEBUG(2,("utmp_yield: conn: user:%s cnum:%d\n",
		 conn->user, conn->cnum));

	memset((char *)&u, '\0', sizeof(struct utmp));
	u.ut_type = DEAD_PROCESS;
	u.ut_exit.e_termination = 0;
	u.ut_exit.e_exit = 0;
	if (utmp_fill(&u, conn, pid, conn->cnum) == 0) {
		utmp_update(&u, NULL);
	}
}

static void utmp_claim(const struct connections_data *crec, const connection_struct *conn)
{
	struct utmp u;

	if (conn == NULL) {
		DEBUG(2,("utmp_claim: conn NULL\n"));
		return;
	}

	if (! lp_utmp(SNUM(conn))) {
		DEBUG(2,("utmp_claim: lp_utmp() NULL\n"));
		return;
	}

	DEBUG(2,("utmp_claim: conn: user:%s cnum:%d\n",
	  conn->user, conn->cnum));
	DEBUG(2,("utmp_claim: crec: pid:%d, cnum:%d name:%s addr:%s mach:%s DNS:%s\n",
	  crec->pid, crec->cnum, crec->name, crec->addr, crec->machine, client_name()));


	memset((char *)&u, '\0', sizeof(struct utmp));
	u.ut_type = USER_PROCESS;
	if (utmp_fill(&u, conn, crec->pid, conn->cnum) == 0) {
		utmp_update(&u, crec->machine);
	}
}

#endif
