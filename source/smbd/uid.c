/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   uid/user handling
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

extern int DEBUGLEVEL;

static int initial_uid;
static int initial_gid;

/* what user is current? */
struct current_user current_user;

pstring OriginalDir;

/****************************************************************************
initialise the uid routines
****************************************************************************/
void init_uid(void)
{
  initial_uid = current_user.uid = geteuid();
  initial_gid = current_user.gid = getegid();

  if (initial_gid != 0 && initial_uid == 0)
    {
#ifdef HPUX
      setresgid(0,0,0);
#else
      setgid(0);
      setegid(0);
#endif
    }

  initial_uid = geteuid();
  initial_gid = getegid();

  current_user.cnum = -1;
  current_user.vuid = UID_FIELD_INVALID;

  ChDir(OriginalDir);
}


/****************************************************************************
  become the specified uid 
****************************************************************************/
static BOOL become_uid(int uid)
{
  if (initial_uid != 0)
    return(True);

  if (uid == -1 || uid == 65535) {
    DEBUG(1,("WARNING: using uid %d is a security risk\n",uid));    
  }

#ifdef AIX
  {
    /* AIX 3 stuff - inspired by a code fragment in wu-ftpd */
    /* MWW: This is all undocumented, of course.  There's a patch to WU-ftpd
       in the AIX FAQ which does the setpriv, then sets the gid stuff, then
       sets uid.  Since Samba separates setting the gid and setting the uid,
       I've duplicated the setpriv code in become_gid.  I've also made the
       requisite changes to become_gid to match the WU-ftpd patch.

       I believe we'll still get errors in the Samba logs.  This setpriv
       call is supposed to disable "trapdooring" on AIX - ie. normally
       once a seteuid / setegid is done, the effective ID can't be set back
       to what it was before.  See the comments in become_root / unbecome_root.
       I *think* that we may have to do something additional here to prevent
       the "Can't set uid (AIX3)" messages, though - possibly change the
       values of priv.pv_priv to keep the SET_PROC_DAC privilege, and
       possibly SET_OBJ_DAC and SET_OBJ_STAT as well.

       The pv_priv array is two longwords, and the constants in sys/priv.h
       have values between 1 and 64, according to the comments in priv.h.
       This strongly suggests a bit vector - but does BYPASS_DAC_WRITE
       (#define'd to 1) mean 1<<0 or 1<<1?  Unfortunately, nothing's
       defined to 0 or 64, which would be a dead giveaway.  Also, what's the
       fullword-boundary endianness?  That is, is pv_priv[0] the high or
       the low 32 bits?  Fortunately, the values used by "su" (see below)
       don't make much sense if pv_priv[0] is the high bits.  Also, based
       on analysis of the values used by su, I concluded that, for example,
       BYPASS_DAC_READ (defined to 2) is bit "2" counting from 1 - ie.
       if (pv_priv[0] & (1 << (BYPASS_DAC_READ - 1))) then BYPASS_DAC_READ
       is on.  That's a bit odd, but it makes more sense than if the
       privilege constants are meant to be taken as exponents of 2.

       For analysis, I ran "su" as root under dbx, and stopped in setpriv.
       The first argument to setpriv can be examined using

          print $r3   (eg. "0x30009" = PRIV_SET|PRIV_MAXIMUM|PRIV_EFFECTIV)

       the contents of the pv_priv array can be examined using

          ($r4)/2X

       Here's what su does:

          setpriv(PRIV_SET | PRIV_INHERITED | PRIV_BEQUEATH, {0,0})
          setpriv(PRIV_SET | PRIV_EFFECTIVE | PRIV_MAXIMUM,
                  {0x02800006, 0x00040000})
             0x02800006 = SET_PROC_AUDIT | SET_PROC_ENV |
                          BYPASS_DAC_EXEC | BYPASS_DAC_READ
             0x00040000 = TPATH_CONFIG
          setpriv(PRIV_SET | PRIV_EFFECTIVE, {0, 0})

       Analysis:

          Reduce inherited privileges to none, so the child doesn't inherit
             anything special.
          Change su's privileges so it can execute the shell even if someone
             has goofed up the permissions to it or to directories on the
             search path; so it can set the process auditing characteristics
             and privileged environment (stuff in /etc/security/environ with
             the sysenv attribute); and so that it can set the trusted path
             characteristics for this login.
          Zap those privileges back off when we don't need them any more.

       I'm guessing we want to keep SET_PROC_DAC in the current priv set,
       but not in the inherited one.  That is, set PRIV_INHERITED and
       PRIV_BEQUEATH to 0.  We also probably want to set PRIV_MAXIMUM and
       PRIV_EFFECTIVE to only the privs we need, which at this point would
       appear to be just SET_PROC_DAC.  *Note*: setting PRIV_MAXIMUM
       with any of the privilege sets higher than what you're trying to
       set the maximum to will produce an EINVAL.  For example, if we
       try to set PRIV_MAXIMUM to SET_PROC_DAC *before* we reduce
       PRIV_INHERITED and PRIV_BEQUEATH, it won't work.  Zero out the
       inherited privileges first.

       Some experimentation with simple programs confirms that if we're
       running with an EUID of 0 we can switch our UID/EUID back and
       forth with setuidx - *unless* we call setpriv({0,0}, ...) first.
       In other words, by default root has SET_PROC_DAT set, but we can
       remove it from our privilege set.  This is what we want to do for
       child processes, I believe.

       Also, calling setpriv(PRIV_SUB|PRIV_EFFECTIVE,...) with pv_priv[0]
       set to SET_PROC_DAC (1 << (SET_PROC_DAC - 1)) will prevent an
       EUID-root process from switching its EUID back with setuidx.

       In other words, setuidx on AIX is *not* trapdoor.  setuid is
       trapdoor.  We need a non-trapdoor setuid function, but we don't
       want processes we fork to have access to it.  Thus we use setuidx
       but first we disable it for our children.

       Note, however, that we can only increase our privileges (as we
       do in the first call to setpriv) if we're EUID-root.  If we
       started out as root, and then switched to a non-root user ID,
       that's OK; we've already set them.  Just don't try to set them
       again.

       Also, I suspect that after using setpriv / setuidx / etc. here in
       the AIX-specific code we DON'T want to fall through to the code that
       calls setuid, etc.  However, I haven't noticed any more problems with
       the code the way it is here.
       */

    priv_t priv;

    priv.pv_priv[0] = 0;
    priv.pv_priv[1] = 0;
    if (setpriv(PRIV_SET|PRIV_INHERITED|PRIV_BEQUEATH,
		&priv, sizeof(priv_t)) < 0) {
       DEBUG(1, ("Can't set child privileges (AIX3): %s\n", strerror(errno)));
    }

    priv.pv_priv[0] = (1 << (SET_PROC_DAC - 1));
    if (setpriv(PRIV_SET|PRIV_EFFECTIVE|PRIV_MAXIMUM,
		&priv, sizeof(priv_t)) < 0) {
       DEBUG(1, ("Can't set own privileges (AIX3): %s\n", strerror(errno)));
    }

    if (setuidx(ID_REAL|ID_EFFECTIVE, (uid_t)uid) < 0 ||
	seteuid((uid_t)uid) < 0) {
      DEBUG(1,("Can't set uid (AIX3)\n"));
    }
  }
#endif

#ifdef USE_SETRES
  if (setresuid(-1,uid,-1) != 0)
#elif defined(USE_SETFS)
    if (setfsuid(uid) != 0)
#else
    if ((seteuid(uid) != 0) && 
	(setuid(uid) != 0))
#endif
      {
	DEBUG(0,("Couldn't set uid %d currently set to (%d,%d)\n",
		 uid,getuid(), geteuid()));
	if (uid > 32000)
	  DEBUG(0,("Looks like your OS doesn't like high uid values - try using a different account\n"));
	return(False);
      }

  if (((uid == -1) || (uid == 65535)) && geteuid() != uid) {
    DEBUG(0,("Invalid uid -1. perhaps you have a account with uid 65535?\n"));
    return(False);
  }

  current_user.uid = uid;

  return(True);
}


/****************************************************************************
  become the specified gid
****************************************************************************/
static BOOL become_gid(int gid)
{
  if (initial_uid != 0)
    return(True);

  if (gid == -1 || gid == 65535) {
    DEBUG(1,("WARNING: using gid %d is a security risk\n",gid));    
  }
  
#ifdef AIX
  {
    /* MWW: See comment above in become_uid. */
    priv_t priv;

    priv.pv_priv[0] = 0;
    priv.pv_priv[1] = 0;
    if (setpriv(PRIV_SET|PRIV_INHERITED|PRIV_EFFECTIVE|PRIV_BEQUEATH,
		&priv, sizeof(priv_t)) < 0) {
       DEBUG(1, ("Can't set privilege (AIX3)\n"));
       }
    if (setgidx(ID_REAL|ID_EFFECTIVE, (gid_t)gid) < 0 ||
	setegid((gid_t)gid) < 0) {
      DEBUG(1,("Can't set gid (AIX3)\n"));
    }
  }
#endif

#ifdef USE_SETRES 
  if (setresgid(-1,gid,-1) != 0)
#elif defined(USE_SETFS)
  if (setfsgid(gid) != 0)
#else
  if (setgid(gid) != 0)
#endif
      {
	DEBUG(0,("Couldn't set gid %d currently set to (%d,%d)\n",
		 gid,getgid(),getegid()));
	if (gid > 32000)
	  DEBUG(0,("Looks like your OS doesn't like high gid values - try using a different account\n"));
	return(False);
      }

  current_user.gid = gid;

  return(True);
}


/****************************************************************************
  become the specified uid and gid
****************************************************************************/
static BOOL become_id(int uid,int gid)
{
  return(become_gid(gid) && become_uid(uid));
}

/****************************************************************************
become the guest user
****************************************************************************/
BOOL become_guest(void)
{
  BOOL ret;
  static struct passwd *pass=NULL;

  if (initial_uid != 0) 
    return(True);

  if (!pass)
    pass = Get_Pwnam(lp_guestaccount(-1),True);
  if (!pass) return(False);

#ifdef AIX
  /* MWW: From AIX FAQ patch to WU-ftpd: call initgroups before setting IDs */
  initgroups(pass->pw_name, (gid_t)pass->pw_gid);
#endif
  ret = become_id(pass->pw_uid,pass->pw_gid);

  if (!ret)
    DEBUG(1,("Failed to become guest. Invalid guest account?\n"));

  current_user.cnum = -2;
  current_user.vuid = UID_FIELD_INVALID;

  return(ret);
}

/*******************************************************************
check if a username is OK
********************************************************************/
static BOOL check_user_ok(connection_struct *conn, user_struct *vuser,int snum)
{
  int i;
  for (i=0;i<conn->uid_cache.entries;i++)
    if (conn->uid_cache.list[i] == vuser->uid) return(True);

  if (!user_ok(vuser->name,snum)) return(False);

  i = conn->uid_cache.entries % UID_CACHE_SIZE;
  conn->uid_cache.list[i] = vuser->uid;

  if (conn->uid_cache.entries < UID_CACHE_SIZE)
    conn->uid_cache.entries++;

  return(True);
}


/****************************************************************************
  become the user of a connection number
****************************************************************************/
BOOL become_user(connection_struct *conn, int cnum, uint16 vuid)
{
  user_struct *vuser = get_valid_user_struct(vuid);
  int snum,gid;
  int uid;

  if ((current_user.cnum == cnum) && (vuser != 0) && (current_user.vuid == vuid) && 
      (current_user.uid == vuser->uid)) {
    DEBUG(4,("Skipping become_user - already user\n"));
    return(True);
  }

  unbecome_user();

  if (!(VALID_CNUM(cnum) && conn->open)) {
    DEBUG(2,("Connection %d not open\n",cnum));
    return(False);
  }

  snum = conn->service;

  if((vuser != NULL) && !check_user_ok(conn, vuser, snum))
    return False;

  if (conn->force_user || 
      lp_security() == SEC_SHARE ||
      !(vuser) || (vuser->guest)
     )
  {
    uid = conn->uid;
    gid = conn->gid;
    current_user.groups = conn->groups;
    current_user.igroups = conn->igroups;
    current_user.ngroups = conn->ngroups;
    current_user.attrs   = conn->attrs;
  }
  else
  {
    if (!vuser) {
      DEBUG(2,("Invalid vuid used %d\n",vuid));
      return(False);
    }
    uid = vuser->uid;
    if(!*lp_force_group(snum))
      gid = vuser->gid;
    else
      gid = conn->gid;
    current_user.ngroups = vuser->n_groups;
    current_user.groups  = vuser->groups;
    current_user.igroups = vuser->igroups;
    current_user.attrs   = vuser->attrs;
  }

  if (initial_uid == 0)
    {
      if (!become_gid(gid)) return(False);

#ifndef NO_SETGROUPS      
      if (!(VALID_CNUM(cnum) && conn->ipc)) {
	/* groups stuff added by ih/wreu */
	if (current_user.ngroups > 0)
	  if (setgroups(current_user.ngroups,current_user.groups)<0)
	    DEBUG(0,("setgroups call failed!\n"));
      }
#endif

      if (!conn->admin_user && !become_uid(uid))
	return(False);
    }

  current_user.cnum = cnum;
  current_user.vuid = vuid;

  DEBUG(5,("become_user uid=(%d,%d) gid=(%d,%d)\n",
	   getuid(),geteuid(),getgid(),getegid()));
  
  return(True);
}

/****************************************************************************
  unbecome the user of a connection number
****************************************************************************/
BOOL unbecome_user(void )
{
  if (current_user.cnum == -1)
    return(False);

  ChDir(OriginalDir);

  if (initial_uid == 0)
    {
#ifdef USE_SETRES
      setresuid(-1,getuid(),-1);
      setresgid(-1,getgid(),-1);
#elif defined(USE_SETFS)
      setfsuid(initial_uid);
      setfsgid(initial_gid);
#else
      if (seteuid(initial_uid) != 0) 
	setuid(initial_uid);
      setgid(initial_gid);
#endif
    }
#ifdef NO_EID
  if (initial_uid == 0)
    DEBUG(2,("Running with no EID\n"));
  initial_uid = getuid();
  initial_gid = getgid();
#else
  if (geteuid() != initial_uid)
    {
      DEBUG(0,("Warning: You appear to have a trapdoor uid system\n"));
      initial_uid = geteuid();
    }
  if (getegid() != initial_gid)
    {
      DEBUG(0,("Warning: You appear to have a trapdoor gid system\n"));
      initial_gid = getegid();
    }
#endif

  current_user.uid = initial_uid;
  current_user.gid = initial_gid;
  
  if (ChDir(OriginalDir) != 0)
    DEBUG(0,("%s chdir(%s) failed in unbecome_user\n",
	     timestring(),OriginalDir));

  DEBUG(5,("unbecome_user now uid=(%d,%d) gid=(%d,%d)\n",
	getuid(),geteuid(),getgid(),getegid()));

  current_user.cnum = -1;
  current_user.vuid = UID_FIELD_INVALID;

  return(True);
}


/****************************************************************************
This is a utility function of smbrun(). It must be called only from
the child as it may leave the caller in a privilaged state.
****************************************************************************/
static BOOL setup_stdout_file(char *outfile,BOOL shared)
{  
  int fd;
  struct stat st;
  mode_t mode = S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH;
  int flags = O_RDWR|O_CREAT|O_TRUNC|O_EXCL;

  close(1);

  if (shared) {
    /* become root - unprivilaged users can't delete these files */
#ifdef USE_SETRES
    setresgid(0,0,0);
    setresuid(0,0,0);
#else      
    setuid(0);
    seteuid(0);
#endif
  }

  if(stat(outfile, &st) == 0) {
    /* Check we're not deleting a device file. */ 
    if(st.st_mode & S_IFREG)
      unlink(outfile);
    else
      flags = O_RDWR;
  }
  /* now create the file */
  fd = open(outfile,flags,mode);

  if (fd == -1) return False;

  if (fd != 1) {
    if (dup2(fd,1) != 0) {
      DEBUG(2,("Failed to create stdout file descriptor\n"));
      close(fd);
      return False;
    }
    close(fd);
  }
  return True;
}


/****************************************************************************
run a command being careful about uid/gid handling and putting the output in
outfile (or discard it if outfile is NULL).

if shared is True then ensure the file will be writeable by all users
but created such that its owned by root. This overcomes a security hole.

if shared is not set then open the file with O_EXCL set
****************************************************************************/
int smbrun(char *cmd,char *outfile,BOOL shared)
{
  int fd,pid;
  int uid = current_user.uid;
  int gid = current_user.gid;

#if USE_SYSTEM
  int ret;
  pstring syscmd;  
  char *path = lp_smbrun();

  /* in the old method we use system() to execute smbrun which then
     executes the command (using system() again!). This involves lots
     of shell launches and is very slow. It also suffers from a
     potential security hole */
  if (!file_exist(path,NULL))
    {
      DEBUG(0,("SMBRUN ERROR: Can't find %s. Installation problem?\n",path));
      return(1);
    }

  slprintf(syscmd,sizeof(syscmd)-1,"%s %d %d \"(%s 2>&1) > %s\"",
	  path,uid,gid,cmd,
	  outfile?outfile:"/dev/null");

  DEBUG(5,("smbrun - running %s ",syscmd));
  ret = system(syscmd);
  DEBUG(5,("gave %d\n",ret));
  return(ret);
#else
  /* in this newer method we will exec /bin/sh with the correct
     arguments, after first setting stdout to point at the file */

  if ((pid=fork())) {
    int status=0;
    /* the parent just waits for the child to exit */
    if (sys_waitpid(pid,&status,0) != pid) {
      DEBUG(2,("waitpid(%d) : %s\n",pid,strerror(errno)));
      return -1;
    }
    return status;
  }


  /* we are in the child. we exec /bin/sh to do the work for us. we
     don't directly exec the command we want because it may be a
     pipeline or anything else the config file specifies */

  /* point our stdout at the file we want output to go into */
  if (outfile && !setup_stdout_file(outfile,shared)) {
    exit(80);
  }

  /* now completely lose our privilages. This is a fairly paranoid
     way of doing it, but it does work on all systems that I know of */
#ifdef USE_SETRES
  setresgid(0,0,0);
  setresuid(0,0,0);
  setresgid(gid,gid,gid);
  setresuid(uid,uid,uid);      
#else      
  setuid(0);
  seteuid(0);
  setgid(gid);
  setegid(gid);
  setuid(uid);
  seteuid(uid);
#endif

  if (getuid() != uid || geteuid() != uid ||
      getgid() != gid || getegid() != gid) {
    /* we failed to lose our privilages - do not execute the command */
    exit(81); /* we can't print stuff at this stage, instead use exit codes
		 for debugging */
  }

  /* close all other file descriptors, leaving only 0, 1 and 2. 0 and
     2 point to /dev/null from the startup code */
  for (fd=3;fd<256;fd++) close(fd);

  execl("/bin/sh","sh","-c",cmd,NULL);  

  /* not reached */
  exit(82);
#endif
  return 1;
}

static struct current_user current_user_saved;
static int become_root_depth;
static pstring become_root_dir;

/****************************************************************************
This is used when we need to do a privilaged operation (such as mucking
with share mode files) and temporarily need root access to do it. This
call should always be paired with an unbecome_root() call immediately
after the operation

Set save_dir if you also need to save/restore the CWD 
****************************************************************************/
void become_root(BOOL save_dir) 
{
	if (become_root_depth) {
		DEBUG(0,("ERROR: become root depth is non zero\n"));
	}
	if (save_dir)
		GetWd(become_root_dir);

	current_user_saved = current_user;
	become_root_depth = 1;

	become_uid(0);
	become_gid(0);
}

/****************************************************************************
When the privilaged operation is over call this

Set save_dir if you also need to save/restore the CWD 
****************************************************************************/
void unbecome_root(BOOL restore_dir)
{
	if (become_root_depth != 1) {
		DEBUG(0,("ERROR: unbecome root depth is %d\n",
			 become_root_depth));
	}

	/* we might have done a become_user() while running as root,
	   if we have then become root again in order to become 
	   non root! */
	if (current_user.uid != 0) {
		become_uid(0);
	}

	/* restore our gid first */
	if (!become_gid(current_user_saved.gid)) {
		DEBUG(0,("ERROR: Failed to restore gid\n"));
		exit_server("Failed to restore gid");
	}

#ifndef NO_SETGROUPS      
	if (current_user_saved.ngroups > 0) {
		if (setgroups(current_user_saved.ngroups,
			      current_user_saved.groups)<0)
			DEBUG(0,("ERROR: setgroups call failed!\n"));
	}
#endif

	/* now restore our uid */
	if (!become_uid(current_user_saved.uid)) {
		DEBUG(0,("ERROR: Failed to restore uid\n"));
		exit_server("Failed to restore uid");
	}

	if (restore_dir)
		ChDir(become_root_dir);

	current_user = current_user_saved;

	become_root_depth = 0;
}
