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

	With grateful thanks since then to many who have helped port it to
	different operating systems.  The variety of OS quirks thereby
	uncovered is amazing...

Hints for porting:
	o  Always attempt to use programmatic interface (pututline() etc.)
	   Indeed, at present only programmatic use is supported.
	o  The only currently supported programmatic interface to "wtmp{,x}"
	   is through "updwtmp*()" routines.
	o  The "x" (utmpx/wtmpx; HAVE_UTMPX_H) seems preferable.
	o  The HAVE_* items should identify supported features.
	o  If at all possible, avoid "if defined(MY-OS)" constructions.

OS observations and status:
	Almost every OS seems to have its own quirks.

	Solaris 2.x:
		Tested on 2.6 and 2.7; should be OK on other flavours.
	AIX:
		Apparently has utmpx.h but doesn't implement.
	OSF:
		Has utmpx.h, but (e.g.) no "getutmpx()".  (Is this like AIX ?)
	Redhat 6:
		utmpx.h seems not to set default filenames.  non-x better.
	IRIX 6.5:
		Not tested.  Appears to have "x".
	HP-UX 9.x:
		Not tested.  Appears to lack "x".
	HP-UX 10.x:
		Not tested.
		"updwtmp*()" routines seem absent, so no current wtmp* support.
		Has "ut_addr": probably trivial to implement (although remember
		that IPv6 is coming...).

	FreeBSD:
		No "putut*()" type of interface.
		No "ut_type" and associated defines. 
		Write files directly.  Alternatively use its login(3)/logout(3).
	SunOS 4:
		Not tested.  Resembles FreeBSD, but no login()/logout().

lastlog:
	Should "lastlog" files, if any, be updated?
	BSD systems (SunOS 4, FreeBSD):
		o  Prominent mention on man pages.
	System-V (e.g. Solaris 2):
		o  No mention on man pages, even under "man -k".
		o  Has a "/var/adm/lastlog" file, but pututxline() etc. seem
		   not to touch it.
		o  Despite downplaying (above), nevertheless has <lastlog.h>.
	So perhaps UN*X "lastlog" facility is intended for tty/terminal only?

Notes:
	Each connection requires a small number (starting at 0, working up)
	to represent the line (unum).  This must be unique within and across
	all smbd processes.

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

	The remaining two encode the "unum" (see above).

	For "utmp consolidate" the suggestion was made to encode the pid into
	those remaining two bytes (16 bits).  But recent UNIX (e.g Solaris 8)
	is migrating to pids > 16 bits, so we ought not to do this.

****************************************************************************/

#include <utmp.h>

#ifdef HAVE_UTMPX_H
#include <utmpx.h>
#endif

/* BSD systems: some may need lastlog.h (SunOS 4), some may not (FreeBSD) */
/* Some System-V systems (e.g. Solaris 2) declare this too. */
#ifdef HAVE_LASTLOG_H
#include <lastlog.h>
#endif

/****************************************************************************
obtain/release a small number (0 upwards) unique within and across smbds
****************************************************************************/
/*
 * Need a "small" number to represent this connection, unique within this
 * smbd and across all smbds.
 *
 * claim:
 *	Start at 0, hunt up for free, unique number "unum" by attempting to
 *	store it as a key in a tdb database:
 *		key: unum		data: pid+conn  
 *	Also store its inverse, ready for yield function:
 *		key: pid+conn		data: unum
 *
 * yield:
 *	Find key: pid+conn; data is unum;  delete record
 *	Find key: unum ; delete record.
 *
 * Comment:
 *	The claim algorithm (a "for" loop attempting to store numbers in a tdb
 *	database) will be increasingly inefficient with larger numbers of
 *	connections.  Is it possible to write a suitable primitive within tdb?
 *
 *	However, by also storing the inverse key/data pair, we at least make
 *	the yield algorithm efficient.
 */

static TDB_CONTEXT *tdb_utmp;

struct utmp_tdb_data {
	pid_t pid;
	int cnum;
};

static int utmp_claim_tdb(const connection_struct *conn)
{
	struct utmp_tdb_data udata;
	int i, slotnum;
	TDB_DATA kbuf, dbuf;

	if (!tdb_utmp) {
		tdb_utmp = tdb_open(lock_path("utmp.tdb"), 0,
				TDB_CLEAR_IF_FIRST, O_RDWR | O_CREAT, 0644);
	}
	if (!tdb_utmp) return(-1);

	DEBUG(2,("utmp_claim_tdb: entered\n"));

	ZERO_STRUCT(udata);
	udata.pid = sys_getpid();
	udata.cnum = conn ? conn->cnum : -1;

	dbuf.dptr = (char *) &udata;
	dbuf.dsize = sizeof(udata);

	/* The key is simply a number as close as possible to zero: find it */
	slotnum = -1;
	/* stop loop when overflow +ve integers (a huge, busy machine!) */
	for (i = 0; i >= 0 ; i++) {
		kbuf.dptr = (char *) &i;
		kbuf.dsize = sizeof(i);

		if (tdb_store(tdb_utmp, kbuf, dbuf, TDB_INSERT) == 0) {
			/* have successfully grabbed a free slot */
			slotnum = i;

			/* store the inverse for faster utmp_yield_tdb() */
			tdb_store(tdb_utmp, dbuf, kbuf, TDB_INSERT);

			break;	/* Got it; escape */
		}
	}
	if (slotnum < 0) {	/* more connections than positive integers! */
		DEBUG(2,("utmp_claim_tdb: failed\n"));
		return(-1);
	}

	DEBUG(2,("utmp_claim_tdb: leaving with %d\n", slotnum));

	return(slotnum);
}

static int utmp_yield_tdb(const connection_struct *conn)
{
	struct utmp_tdb_data revkey;
	int i, slotnum;
	TDB_DATA kbuf, dbuf;

	if (!tdb_utmp) {
		return(-1);
	}

	DEBUG(2,("utmp_yield_tdb: entered\n"));

	ZERO_STRUCT(revkey);
	revkey.pid = sys_getpid();
	revkey.cnum = conn ? conn->cnum : -1;

	kbuf.dptr = (char *) &revkey;
	kbuf.dsize = sizeof(revkey);

	dbuf = tdb_fetch(tdb_utmp, kbuf);
	if (dbuf.dptr == NULL) {
		DEBUG(2,("utmp_yield_tdb: failed\n"));
		return(-1);		/* shouldn't happen */
	}

	/* Save our result */
	slotnum = (int) dbuf.dptr;

	/* Tidy up */
	tdb_delete(tdb_utmp, kbuf);
	tdb_delete(tdb_utmp, dbuf);

	free(dbuf.dptr);
	DEBUG(2,("utmp_yield_tdb: leaving with %d\n", slotnum));

	return(slotnum);
}

#if defined(HAVE_UT_UT_ID)
/****************************************************************************
encode the unique connection number into "ut_id"
****************************************************************************/
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
#endif /* defined(HAVE_UT_UT_ID) */

/*
 * ut_line:
 *	size small, e.g. Solaris: 12;  FreeBSD: 8
 *	pattern conventions differ across systems.
 * So take care in tweaking the template below.
 * Arguably, this could be yet another smb.conf parameter.
 */
static const char *ut_line_template =
#if defined(__FreeBSD__)
	"smb%d" ;
#else
	"smb/%d" ;
#endif

/****************************************************************************
Fill in a utmp (not utmpx) template
****************************************************************************/
static int utmp_fill(struct utmp *u, const connection_struct *conn, pid_t pid,
  int i, pstring host)
{
#if defined(HAVE_UT_UT_TIME)
	struct timeval timeval;
#endif /* defined(HAVE_UT_UT_TIME) */
	char line_tmp[1024];	/* plenty big enough for slprintf() */
	int line_len;
	int rc = 0;

/*
 * ut_name, ut_user:
 *	Several (all?) systems seems to define one as the other.
 *	It is easier and clearer simply to let the following take its course,
 *	rather than to try to detect and optimise.
 */
#if defined(HAVE_UT_UT_USER)
	pstrcpy(u->ut_user, conn->user);
#endif /* defined(HAVE_UT_UT_USER) */

#if defined(HAVE_UT_UT_NAME)
	pstrcpy(u->ut_name, conn->user);
#endif /* defined(HAVE_UT_UT_NAME) */

/*
 * ut_line:
 *	If size limit proves troublesome, then perhaps use "ut_id_encode()".
 *
 * Temporary variable "line_tmp" avoids trouble:
 * o  with unwanted trailing NULL if ut_line full;
 * o  with overflow if ut_line would be more than full.
 */
	memset(line_tmp, '\0', sizeof(line_tmp));
	slprintf(line_tmp, sizeof(line_tmp), (char *) ut_line_template, i);
	line_len = strlen(line_tmp);
	if (line_len <= sizeof(u->ut_line)) {
		memcpy(u->ut_line, line_tmp, sizeof(u->ut_line));
	}
	else {
		DEBUG(1,("utmp_fill: ut_line exceeds field length(%d > %d)\n",
		  line_len, sizeof(u->ut_line)));
		return(1);
	}

#if defined(HAVE_UT_UT_PID)
	u->ut_pid = pid;
#endif /* defined(HAVE_UT_UT_PID) */

/*
 * ut_time, ut_tv: 
 *	Some have one, some the other.  Many have both, but defined (aliased).
 *	It is easier and clearer simply to let the following take its course.
 *	But note that we do the more precise ut_tv as the final assignment.
 */
#if defined(HAVE_UT_UT_TIME)
	gettimeofday(&timeval, NULL);
	u->ut_time = timeval.tv_sec;
#endif /* defined(HAVE_UT_UT_TIME) */

#if defined(HAVE_UT_UT_TV)
	gettimeofday(&timeval, NULL);
	u->ut_tv = timeval;
#endif /* defined(HAVE_UT_UT_TV) */

#if defined(HAVE_UT_UT_HOST)
	if (host) {
		pstrcpy(u->ut_host, host);
	}
#endif /* defined(HAVE_UT_UT_HOST) */

#if defined(HAVE_UT_UT_ADDR)
	/*
	 * "(unsigned long) ut_addr" apparently exists on at least HP-UX 10.20.
	 * Volunteer to implement, please ...
	 */
#endif /* defined(HAVE_UT_UT_ADDR) */

#if defined(HAVE_UT_UT_ID)
	rc = ut_id_encode(i, u->ut_id);
#endif /* defined(HAVE_UT_UT_ID) */

	return(rc);
}

/****************************************************************************
Default paths to various {u,w}tmp{,x} files
****************************************************************************/
#ifdef	HAVE_UTMPX_H

static const char *ux_pathname =
# if defined (UTMPX_FILE)
	UTMPX_FILE ;
# elif defined (_UTMPX_FILE)
	_UTMPX_FILE ;
# elif defined (_PATH_UTMPX)
	_PATH_UTMPX ;
# else
	"" ;
# endif

static const char *wx_pathname =
# if defined (WTMPX_FILE)
	WTMPX_FILE ;
# elif defined (_WTMPX_FILE)
	_WTMPX_FILE ;
# elif defined (_PATH_WTMPX)
	_PATH_WTMPX ;
# else
	"" ;
# endif

#endif	/* HAVE_UTMPX_H */

static const char *ut_pathname =
# if defined (UTMP_FILE)
	UTMP_FILE ;
# elif defined (_UTMP_FILE)
	_UTMP_FILE ;
# elif defined (_PATH_UTMP)
	_PATH_UTMP ;
# else
	"" ;
# endif

static const char *wt_pathname =
# if defined (WTMP_FILE)
	WTMP_FILE ;
# elif defined (_WTMP_FILE)
	_WTMP_FILE ;
# elif defined (_PATH_WTMP)
	_PATH_WTMP ;
# else
	"" ;
# endif

/* BSD-like systems might want "lastlog" support. */
/* *** Not yet implemented */
#ifndef HAVE_PUTUTLINE		/* see "pututline_my()" */
static const char *ll_pathname =
# if defined (_PATH_LASTLOG)	/* what other names (if any?) */
	_PATH_LASTLOG ;
# else
	"" ;
# endif	/* _PATH_LASTLOG */
#endif	/* HAVE_PUTUTLINE */

/*
 * Get name of {u,w}tmp{,x} file.
 *	return: fname contains filename
 *		Possibly empty if this code not yet ported to this system.
 *
 * utmp{,x}:  try "utmp dir", then default (a define)
 * wtmp{,x}:  try "wtmp dir", then "utmp dir", then default (a define)
 */
static void uw_pathname(pstring fname, const char *uw_name, const char *uw_default)
{
	pstring dirname;

	pstrcpy(dirname, "");

	/* For w-files, first look for explicit "wtmp dir" */
	if (uw_name[0] == 'w') {
		pstrcpy(dirname,lp_wtmpdir());
		trim_string(dirname,"","/");
	}

	/* For u-files and non-explicit w-dir, look for "utmp dir" */
	if (dirname == 0 || strlen(dirname) == 0) {
		pstrcpy(dirname,lp_utmpdir());
		trim_string(dirname,"","/");
	}

	/* If explicit directory above, use it */
	if (dirname != 0 && strlen(dirname) != 0) {
		pstrcpy(fname, dirname);
		pstrcat(fname, "/");
		pstrcat(fname, uw_name);
		return;
	}

	/* No explicit directory: attempt to use default paths */
	if (strlen(uw_default) == 0) {
		/* No explicit setting, no known default.
		 * Has it yet been ported to this OS?
		 */
		DEBUG(2,("uw_pathname: unable to determine pathname\n"));
	}
	pstrcpy(fname, uw_default);
}

#ifndef HAVE_PUTUTLINE
/****************************************************************************
Update utmp file directly.  No subroutine interface: probably a BSD system.
****************************************************************************/
static void pututline_my(pstring uname, struct utmp *u, BOOL claim)
{
	DEBUG(1,("pututline_my: not yet implemented\n"));
	/* BSD implementor: may want to consider (or not) adjusting "lastlog" */
}
#endif /* HAVE_PUTUTLINE */

#ifndef HAVE_UPDWTMP
/****************************************************************************
Update wtmp file directly.  No subroutine interface: probably a BSD system.
Credit: Michail Vidiassov <master@iaas.msu.ru>
****************************************************************************/
static void updwtmp_my(pstring wname, struct utmp *u, BOOL claim)
{
	int fd;
	struct stat buf;

	if (! claim) {
		/*
	 	 * BSD-like systems:
		 *	may use empty ut_name to distinguish a logout record.
		 *
		 * May need "if defined(SUNOS4)" etc. around some of these,
		 * but try to avoid if possible.
		 *
		 * SunOS 4:
		 *	man page indicates ut_name and ut_host both NULL
		 * FreeBSD 4.0:
		 *	man page appears not to specify (hints non-NULL)
		 *	A correspondent suggest at least ut_name should be NULL
		 */
		memset((char *)&(u->ut_name), '\0', sizeof(u->ut_name));
		memset((char *)&(u->ut_host), '\0', sizeof(u->ut_host));
	}
	/* Stolen from logwtmp function in libutil.
	 * May be more locking/blocking is needed?
	 */
	if ((fd = open(wname, O_WRONLY|O_APPEND, 0)) < 0)
		return;
	if (fstat(fd, &buf) == 0) {
		if (write(fd, (char *)u, sizeof(struct utmp)) != sizeof(struct utmp))
		(void) ftruncate(fd, buf.st_size);
	}
	(void) close(fd);
}
#endif /* HAVE_UPDWTMP */

/****************************************************************************
Update via utmp/wtmp (not utmpx/wtmpx)
****************************************************************************/
static void utmp_nox_update(struct utmp *u, pstring host, BOOL claim)
{
	pstring uname, wname;
#if defined(PUTUTLINE_RETURNS_UTMP)
	struct utmp *urc;
#endif /* PUTUTLINE_RETURNS_UTMP */

	uw_pathname(uname, "utmp", ut_pathname);
	DEBUG(2,("utmp_nox_update: uname:%s\n", uname));

#ifdef HAVE_PUTUTLINE
	if (strlen(uname) != 0) {
		utmpname(uname);
	}

# if defined(PUTUTLINE_RETURNS_UTMP)
	setutent();
	urc = pututline(u);
	endutent();
	if (urc == NULL) {
		DEBUG(2,("utmp_nox_update: pututline() failed\n"));
		return;
	}
# else	/* PUTUTLINE_RETURNS_UTMP */
	setutent();
	pututline(u);
	endutent();
# endif	/* PUTUTLINE_RETURNS_UTMP */

#else	/* HAVE_PUTUTLINE */
	if (strlen(uname) != 0) {
		pututline_my(uname, u, claim);
	}
#endif /* HAVE_PUTUTLINE */

	uw_pathname(wname, "wtmp", wt_pathname);
	DEBUG(2,("utmp_nox_update: wname:%s\n", wname));
	if (strlen(wname) != 0) {
#ifdef HAVE_UPDWTMP
		updwtmp(wname, u);
		/*
		 * updwtmp() and the newer updwtmpx() may be unsymmetrical.
		 * At least one OS, Solaris 2.x declares the former in the
		 * "utmpx" (latter) file and context.
		 * In the Solaris case this is irrelevant: it has both and
		 * we always prefer the "x" case, so doesn't come here.
		 * But are there other systems, with no "x", which lack
		 * updwtmp() perhaps?
		 */
#else
		updwtmp_my(wname, u, claim);
#endif /* HAVE_UPDWTMP */
	}
}

/****************************************************************************
Update via utmpx/wtmpx (preferred) or via utmp/wtmp
****************************************************************************/
static void utmp_update(struct utmp *u, pstring host, BOOL claim)
{
#if !defined(HAVE_UTMPX_H)
	/* No utmpx stuff.  Drop to non-x stuff */
	utmp_nox_update(u, host, claim);
#elif !defined(HAVE_PUTUTXLINE)
	/* Odd.  Have utmpx.h but no "pututxline()".  Drop to non-x stuff */
	DEBUG(1,("utmp_update: have utmpx.h but no pututxline() function\n"));
	utmp_nox_update(u, host, claim);
#elif !defined(HAVE_GETUTMPX)
	/* Odd.  Have utmpx.h but no "getutmpx()".  Drop to non-x stuff */
	DEBUG(1,("utmp_update: have utmpx.h but no getutmpx() function\n"));
	utmp_nox_update(u, host, claim);
#else
	pstring uname, wname;
	struct utmpx ux, *uxrc;

	getutmpx(u, &ux);
	if (host) {
#if defined(HAVE_UX_UT_SYSLEN)
		ux.ut_syslen = strlen(host) + 1;	/* include end NULL */
#endif /* defined(HAVE_UX_UT_SYSLEN) */
		pstrcpy(ux.ut_host, host);
	}

	uw_pathname(uname, "utmpx", ux_pathname);
	uw_pathname(wname, "wtmpx", wx_pathname);
	DEBUG(2,("utmp_update: uname:%s wname:%s\n", uname, wname));
	/*
	 * Check for either uname or wname being empty.
	 * Some systems, such as Redhat 6, have a "utmpx.h" which doesn't
	 * define default filenames.
	 * Also, our local installation has not provided an override.
	 * Drop to non-x method.  (E.g. RH6 has good defaults in "utmp.h".)
	 */
	if ((strlen(uname) == 0) || (strlen(wname) == 0)) {
		utmp_nox_update(u, host, claim);
	}
	else {
		utmpxname(uname);
		setutxent();
		uxrc = pututxline(&ux);
		endutxent();
		if (uxrc == NULL) {
			DEBUG(2,("utmp_update: pututxline() failed\n"));
			return;
		}
#ifdef HAVE_UPDWTMPX
		updwtmpx(wname, &ux);
#else
		/* Have utmpx.h but no "updwtmpx()". */
		DEBUG(1,("utmp_update: no updwtmpx() function\n"));
#endif /* HAVE_UPDWTMPX */
	}
#endif /* HAVE_UTMPX_H */
}

/*
 * "utmp consolidate": some background:
 *	False (default):
 *		In "utmp" files note every connection via this process.
 *		Argument "i" is simply a tty-like number we can use as-is.
 *	True:
 *		In "utmp" files, only note first open and final close.  Keep:
 *		o  count of open processes;
 *		o  record value of first "i", to use as "i" in final close.
 */
static int utmp_count = 0;
static int utmp_consolidate_conn_num;

/****************************************************************************
close a connection
****************************************************************************/
static void utmp_yield(pid_t pid, const connection_struct *conn)
{
	struct utmp u;
	int conn_num, i;

	if (! lp_utmp(SNUM(conn))) {
		DEBUG(2,("utmp_yield: lp_utmp() NULL\n"));
		return;
	}

	i = utmp_yield_tdb(conn);
	if (i < 0) {
		DEBUG(2,("utmp_yield: utmp_yield_tdb() failed\n"));
		return;
	}
	conn_num = i;
	DEBUG(2,("utmp_yield: conn: user:%s cnum:%d i:%d (utmp_count:%d)\n",
	  conn->user, conn->cnum, i, utmp_count));

	utmp_count -= 1;
	if (lp_utmp_consolidate()) {
		if (utmp_count > 0) {
			DEBUG(2,("utmp_yield: utmp consolidate: %d entries still open\n", utmp_count));
			return;
		}
		else {
			/* consolidate; final close: override conn_num  */
			conn_num = utmp_consolidate_conn_num;
		}
	}

	memset((char *)&u, '\0', sizeof(struct utmp));

#if defined(HAVE_UT_UT_EXIT)
	u.ut_exit.e_termination = 0;
	u.ut_exit.e_exit = 0;
#endif	/* defined(HAVE_UT_UT_EXIT) */

#if defined(HAVE_UT_UT_TYPE)
	u.ut_type = DEAD_PROCESS;
#endif	/* defined(HAVE_UT_UT_TYPE) */

	if (utmp_fill(&u, conn, pid, conn_num, NULL) == 0) {
		utmp_update(&u, NULL, False);
	}
}

/****************************************************************************
open a connection
****************************************************************************/
static void utmp_claim(const struct connections_data *crec, const connection_struct *conn)
{
	struct utmp u;
	pstring host;
	int i;

	if (conn == NULL) {
		DEBUG(2,("utmp_claim: conn NULL\n"));
		return;
	}

	if (! lp_utmp(SNUM(conn))) {
		DEBUG(2,("utmp_claim: lp_utmp() NULL\n"));
		return;
	}

	i = utmp_claim_tdb(conn);
	if (i < 0) {
		DEBUG(2,("utmp_claim: utmp_claim_tdb() failed\n"));
		return;
	}

	pstrcpy(host, lp_utmp_hostname());
	if (host == 0 || strlen(host) == 0) {
		pstrcpy(host, crec->machine);
	}
	else {
		/* explicit "utmp host": expand for any "%" variables */
		standard_sub_basic(host);
	}

	DEBUG(2,("utmp_claim: conn: user:%s cnum:%d i:%d (utmp_count:%d)\n",
	  conn->user, conn->cnum, i, utmp_count));
	DEBUG(2,("utmp_claim: crec: pid:%d, cnum:%d name:%s addr:%s mach:%s DNS:%s host:%s\n",
	  crec->pid, crec->cnum, crec->name, crec->addr, crec->machine, client_name(), host));

	utmp_count += 1;
	if (lp_utmp_consolidate()) {
		if (utmp_count > 1) {
			DEBUG(2,("utmp_claim: utmp consolidate: %d entries already open\n", (utmp_count-1)));
			return;
		}
		else {
			/* consolidate; first open: keep record of "i" */
			utmp_consolidate_conn_num = i;
		}
	}

	memset((char *)&u, '\0', sizeof(struct utmp));

#if defined(HAVE_UT_UT_TYPE)
	u.ut_type = USER_PROCESS;
#endif	/* defined(HAVE_UT_UT_TYPE) */

	if (utmp_fill(&u, conn, crec->pid, i, host) == 0) {
		utmp_update(&u, host, True);
	}
}

#endif	/* WITH_UTMP */
