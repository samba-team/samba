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

/* fork a child process to exec passwd and write to its
* tty to change a users password. This is running as the
* user who is attempting to change the password.
*/

/* 
 * This code was copied/borrowed and stolen from various sources.
 * The primary source was the poppasswd.c from the authors of POPMail. This software
 * was included as a client to change passwords using the 'passwd' program
 * on the remote machine.
 *
 * This routine is called by set_user_password() in password.c only if ALLOW_PASSWORD_CHANGE
 * is defined in the compiler directives located in the Makefile.
 *
 * This code has been hacked by Bob Nance (nance@niehs.nih.gov) and Evan Patterson
 * (patters2@niehs.nih.gov) at the National Institute of Environmental Health Sciences
 * and rights to modify, distribute or incorporate this change to the CAP suite or
 * using it for any other reason are granted, so long as this disclaimer is left intact.
 */

/*
   This code was hacked considerably for inclusion in Samba, primarily
   by Andrew.Tridgell@anu.edu.au. The biggest change was the addition
   of the "password chat" option, which allows the easy runtime
   specification of the expected sequence of events to change a
   password.
   */

#include "includes.h"

extern int DEBUGLEVEL;

#if ALLOW_CHANGE_PASSWORD
#define MINPASSWDLENGTH 5
#define BUFSIZE 512

static int findpty(char **slave)
{
  int master;
#ifndef HAVE_GRANTPT
  static fstring line;
  DIR *dirp;
  struct dirent *dentry;
  char *dpname;
#endif /* !HAVE_GRANTPT */
  
#if defined(HAVE_GRANTPT)
  if ((master = sys_open("/dev/ptmx", O_RDWR, 0)) >= 1) {
    grantpt(master);
    unlockpt(master);
    *slave = ptsname(master);
    if (*slave == NULL) {
      DEBUG(0,("findpty: Unable to create master/slave pty pair.\n"));
      /* Stop fd leak on error. */
      close(master);
      return -1;
    } else {
      DEBUG(10, ("findpty: Allocated slave pty %s\n", *slave));
      return (master);
    }
  }
#else /* HAVE_GRANTPT */
  fstrcpy( line, "/dev/ptyXX" );

  dirp = opendir("/dev");
  if (!dirp)
    return(-1);
  while ((dentry = readdir(dirp)) != NULL) {
    dpname = dentry->d_name;
    if (strncmp(dpname, "pty", 3) == 0 && strlen(dpname) == 5) {
      DEBUG(3,("pty: try to open %s, line was %s\n", dpname, line ) );
      line[8] = dpname[3];
      line[9] = dpname[4];
      if ((master = sys_open(line, O_RDWR, 0)) >= 0) {
        DEBUG(3,("pty: opened %s\n", line ) );
        line[5] = 't';
        *slave = line;
        closedir(dirp);
        return (master);
      }
    }
  }
  closedir(dirp);
#endif /* HAVE_GRANTPT */
  return (-1);
}

static int dochild(int master,char *slavedev, char *name, char *passwordprogram, BOOL as_root)
{
  int slave;
  struct termios stermios;
  const struct passwd *pass = Get_Pwnam(name,True);
  int gid;
  int uid;

  if (pass == NULL) {
    DEBUG(0,("dochild: user name %s doesn't exist in the UNIX password database.\n",
              name));
    return False;
  }

  gid = pass->pw_gid;
  uid = pass->pw_uid;
#ifdef HAVE_SETRESUID
  setresuid(0,0,0);
#else 
  setuid(0);
#endif

  /* Start new session - gets rid of controlling terminal. */
  if (setsid() < 0) {
    DEBUG(3,("Weirdness, couldn't let go of controlling terminal\n"));
    return(False);
  }

  /* Open slave pty and acquire as new controlling terminal. */
  if ((slave = sys_open(slavedev, O_RDWR, 0)) < 0) {
    DEBUG(3,("More weirdness, could not open %s\n", 
	     slavedev));
    return(False);
  }
#ifdef I_PUSH
  ioctl(slave, I_PUSH, "ptem");
  ioctl(slave, I_PUSH, "ldterm");
#elif defined(TIOCSCTTY)
  if (ioctl(slave,TIOCSCTTY,0) <0) {
     DEBUG(3,("Error in ioctl call for slave pty\n"));
     /* return(False); */
  }
#endif 

  /* Close master. */
  close(master);

  /* Make slave stdin/out/err of child. */

  if (dup2(slave, STDIN_FILENO) != STDIN_FILENO) {
    DEBUG(3,("Could not re-direct stdin\n"));
    return(False);
  }
  if (dup2(slave, STDOUT_FILENO) != STDOUT_FILENO) {
    DEBUG(3,("Could not re-direct stdout\n"));
    return(False);
  }
  if (dup2(slave, STDERR_FILENO) != STDERR_FILENO) {
    DEBUG(3,("Could not re-direct stderr\n"));
    return(False);
  }
  if (slave > 2) close(slave);

  /* Set proper terminal attributes - no echo, canonical input processing,
     no map NL to CR/NL on output. */

  if (tcgetattr(0, &stermios) < 0) {
    DEBUG(3,("could not read default terminal attributes on pty\n"));
    return(False);
  }
  stermios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  stermios.c_lflag |= ICANON;
  stermios.c_oflag &= ~(ONLCR);
  if (tcsetattr(0, TCSANOW, &stermios) < 0) {
    DEBUG(3,("could not set attributes of pty\n"));
    return(False);
  }

  /* make us completely into the right uid */
  if (!as_root) {
#ifdef HAVE_SETRESUID
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
  }

  DEBUG(10, ("Invoking '%s' as password change program.\n", passwordprogram));

  /* execl() password-change application */
  if (execl("/bin/sh","sh","-c",passwordprogram,NULL) < 0) {
    DEBUG(3,("Bad status returned from %s\n",passwordprogram));
    return(False);
  }
  return(True);
}

static int expect(int master,char *expected,char *buf)
{
  int n, m;
 
  n = 0;
  buf[0] = 0;
  while (1) {
    if (n >= BUFSIZE-1) {
      return False;
    }

    /* allow 4 seconds for some output to appear */
    m = read_with_timeout(master, buf+n, 1, BUFSIZE-1-n, 4000);
    if (m < 0) 
      return False;

    n += m;
    buf[n] = 0;

    {
      pstring s1,s2;
      pstrcpy(s1,buf);
      pstrcpy(s2,expected);
      if (do_match(s1, s2, False))
	return(True);
    }
  }
}

static void pwd_sub(char *buf)
{
  string_sub(buf,"\\n","\n");
  string_sub(buf,"\\r","\r");
  string_sub(buf,"\\s"," ");
  string_sub(buf,"\\t","\t");
}

static void writestring(int fd,char *s)
{
  int l;
  
  l = strlen (s);
  write (fd, s, l);
}


static int talktochild(int master, char *chatsequence)
{
  char buf[BUFSIZE];
  int count=0;
  char *ptr=chatsequence;
  fstring chatbuf;

  *buf = 0;
  sleep(1);

  while (next_token(&ptr,chatbuf,NULL,sizeof(chatbuf))) {
    BOOL ok=True;
    count++;
    pwd_sub(chatbuf);
    if (!strequal(chatbuf,"."))
      ok = expect(master,chatbuf,buf);

    if (lp_passwd_chat_debug())
      DEBUG(100,("talktochild: chatbuf=[%s] responsebuf=[%s]\n",chatbuf,buf));

    if (!ok) {
      DEBUG(3,("response %d incorrect\n",count));
      return(False);
    }

    if (!next_token(&ptr,chatbuf,NULL,sizeof(chatbuf))) break;
    pwd_sub(chatbuf);
    if (!strequal(chatbuf,"."))
      writestring(master,chatbuf);

    if (lp_passwd_chat_debug())
      DEBUG(100,("talktochild: sendbuf=[%s]\n",chatbuf));
  }

  if (count<1) return(False);

  return (True);
}


static BOOL chat_with_program(char *passwordprogram,char *name,char *chatsequence, BOOL as_root)
{
  char *slavedev;
  int master;
  pid_t pid, wpid;
  int wstat;
  BOOL chstat = False;    

  /* allocate a pseudo-terminal device */
  if ((master = findpty (&slavedev)) < 0) {
    DEBUG(3,("Cannot Allocate pty for password change: %s\n",name));
    return(False);
  }

  if ((pid = fork()) < 0) {
    DEBUG(3,("Cannot fork() child for password change: %s\n",name));
    close(master);
    return(False);
  }

  /* we now have a pty */
  if (pid > 0){			/* This is the parent process */
    if ((chstat = talktochild(master, chatsequence)) == False) {
      DEBUG(3,("Child failed to change password: %s\n",name));
      kill(pid, SIGKILL); /* be sure to end this process */
    }

    if ((wpid = sys_waitpid(pid, &wstat, 0)) < 0) {
      DEBUG(3,("The process is no longer waiting!\n\n"));
      close(master);
      return(False);
    }

    close(master);

    if (pid != wpid) {
      DEBUG(3,("We were waiting for the wrong process ID\n"));	
      return(False);
    }
    if (WIFEXITED(wstat) == 0) {
      DEBUG(3,("The process exited while we were waiting\n"));
      return(False);
    }
    if (WEXITSTATUS(wstat) != 0) {
      DEBUG(3,("The status of the process exiting was %d\n", wstat));
      return(False);
    }
    
  } else {
    /* CHILD */

    /*
     * Lose any oplock capabilities.
     */
    set_process_capability(KERNEL_OPLOCK_CAPABILITY, False);
    set_inherited_process_capability(KERNEL_OPLOCK_CAPABILITY, False);

    /* make sure it doesn't freeze */
    alarm(20);

    if (as_root)
      become_root(False);
    DEBUG(3,("Dochild for user %s (uid=%d,gid=%d)\n",name,(int)getuid(),(int)getgid()));
    chstat = dochild(master, slavedev, name, passwordprogram, as_root);

    if (as_root)
      unbecome_root(False);
  }

  if (chstat)
    DEBUG(3,("Password change %ssuccessful for user %s\n", (chstat?"":"un"), name));
  return (chstat);
}


BOOL chgpasswd(char *name,char *oldpass,char *newpass, BOOL as_root)
{
  pstring passwordprogram;
  pstring chatsequence;
  int i;
  int len;

  strlower(name); 
  DEBUG(3,("Password change for user: %s\n",name));

#if DEBUG_PASSWORD
  DEBUG(100,("Passwords: old=%s new=%s\n",oldpass,newpass)); 
#endif

  /* Take the passed information and test it for minimum criteria */
  /* Minimum password length */
  if (strlen(newpass) < MINPASSWDLENGTH) /* too short, must be at least MINPASSWDLENGTH */ 
    {
      DEBUG(2,("Password Change: %s, New password is shorter than MINPASSWDLENGTH\n",name));
      return (False);		/* inform the user */
    }
  
  /* Password is same as old password */
  if (strcmp(oldpass,newpass) == 0) /* don't allow same password */
    {
      DEBUG(2,("Password Change: %s, New password is same as old\n",name)); /* log the attempt */
      return (False);		/* inform the user */
    }

  pstrcpy(passwordprogram,lp_passwd_program());
  pstrcpy(chatsequence,lp_passwd_chat());

  if (!*chatsequence) {
    DEBUG(2,("Null chat sequence - no password changing\n"));
    return(False);
  }

  if (!*passwordprogram) {
    DEBUG(2,("Null password program - no password changing\n"));
    return(False);
  }

  /* 
   * Check the old and new passwords don't contain any control
   * characters.
   */

  len = strlen(oldpass); 
  for(i = 0; i < len; i++) {
    if (iscntrl((int)oldpass[i])) {
      DEBUG(0,("chat_with_program: oldpass contains control characters (disallowed).\n"));
      return False;
    }
  }

  len = strlen(newpass);
  for(i = 0; i < len; i++) {
    if (iscntrl((int)newpass[i])) {
      DEBUG(0,("chat_with_program: newpass contains control characters (disallowed).\n"));
      return False;
    }
  }

  string_sub(passwordprogram,"%u",name);
  all_string_sub(passwordprogram,"%o",oldpass);
  all_string_sub(passwordprogram,"%n",newpass);

  string_sub(chatsequence,"%u",name);
  all_string_sub(chatsequence,"%o",oldpass);
  all_string_sub(chatsequence,"%n",newpass);
  return(chat_with_program(passwordprogram,name,chatsequence, as_root));
}

#else /* ALLOW_CHANGE_PASSWORD */
BOOL chgpasswd(char *name,char *oldpass,char *newpass, BOOL as_root)
{
  DEBUG(0,("Password changing not compiled in (user=%s)\n",name));
  return(False);
}
#endif /* ALLOW_CHANGE_PASSWORD */

/***********************************************************
 Code to check the lanman hashed password.
************************************************************/

BOOL check_lanman_password(char *user, uchar *pass1, 
                           uchar *pass2, struct smb_passwd **psmbpw)
{
  static uchar null_pw[16];
  uchar unenc_new_pw[16];
  uchar unenc_old_pw[16];
  struct smb_passwd *smbpw;

  *psmbpw = NULL;

  become_root(0);
  smbpw = getsmbpwnam(user);
  unbecome_root(0);

  if (smbpw == NULL)
  {
    DEBUG(0,("check_lanman_password: getsmbpwnam returned NULL\n"));
    return False;
  }

  if (smbpw->acct_ctrl & ACB_DISABLED)
  {
    DEBUG(0,("check_lanman_password: account %s disabled.\n", user));
    return False;
  }

  if ((smbpw->smb_passwd == NULL) && (smbpw->acct_ctrl & ACB_PWNOTREQ))
  {
    uchar no_pw[14];
    memset(no_pw, '\0', 14);
    E_P16(no_pw, null_pw);
    smbpw->smb_passwd = null_pw;
  } else if (smbpw->smb_passwd == NULL) {
    DEBUG(0,("check_lanman_password: no lanman password !\n"));
    return False;
  }

  /* Get the new lanman hash. */
  D_P16(smbpw->smb_passwd, pass2, unenc_new_pw);

  /* Use this to get the old lanman hash. */
  D_P16(unenc_new_pw, pass1, unenc_old_pw);

  /* Check that the two old passwords match. */
  if (memcmp(smbpw->smb_passwd, unenc_old_pw, 16))
  {
    DEBUG(0,("check_lanman_password: old password doesn't match.\n"));
    return False;
  }

  *psmbpw = smbpw;
  return True;
}

/***********************************************************
 Code to change the lanman hashed password.
 It nulls out the NT hashed password as it will
 no longer be valid.
************************************************************/

BOOL change_lanman_password(struct smb_passwd *smbpw, uchar *pass1, uchar *pass2)
{
  static uchar null_pw[16];
  uchar unenc_new_pw[16];
  BOOL ret;

  if (smbpw == NULL)
  { 
    DEBUG(0,("change_lanman_password: no smb password entry.\n"));
    return False;
  }

  if (smbpw->acct_ctrl & ACB_DISABLED)
  {
    DEBUG(0,("change_lanman_password: account %s disabled.\n", smbpw->unix_name));
    return False;
  }

  if ((smbpw->smb_passwd == NULL) && (smbpw->acct_ctrl & ACB_PWNOTREQ))
  {
    uchar no_pw[14];
    memset(no_pw, '\0', 14);
    E_P16(no_pw, null_pw);
    smbpw->smb_passwd = null_pw;
  } else if (smbpw->smb_passwd == NULL) {
    DEBUG(0,("change_lanman_password: no lanman password !\n"));
    return False;
  }

  /* Get the new lanman hash. */
  D_P16(smbpw->smb_passwd, pass2, unenc_new_pw);

  smbpw->smb_passwd = unenc_new_pw;
  smbpw->smb_nt_passwd = NULL; /* We lose the NT hash. Sorry. */

  /* Now write it into the file. */
  become_root(0);
  ret = mod_smbpwd_entry(smbpw,False);
  unbecome_root(0);
    
  return ret;
}

/***********************************************************
 Code to check and change the OEM hashed password.
************************************************************/
BOOL pass_oem_change(char *user,
			uchar *lmdata, uchar *lmhash,
			uchar *ntdata, uchar *nthash)
{
	UNISTR2 new_passwd;
	struct smb_passwd *sampw;
	BOOL ret = check_oem_password( user, lmdata, lmhash, ntdata, nthash,
	                               &sampw, 
	                               &new_passwd);

	/* now we check to see if we are actually allowed to change the
	   password. */
	   
	if (ret && (sampw->acct_ctrl & ACB_PWLOCK))
	{
		ret = False;
	}
	
	/* 
	 * At this point we have the new case-sensitive plaintext
	 * password in the fstring new_passwd. If we wanted to synchronise
	 * with UNIX passwords we would call a UNIX password changing 
	 * function here. However it would have to be done as root
	 * as the plaintext of the old users password is not 
	 * available. JRA.
	 */

	if ( ret && lp_unix_password_sync())
	{
		ret = chgpasswd(user,"", (char*)new_passwd.buffer, True);
	}

	if (ret)
	{
		ret = change_oem_password( sampw, &new_passwd, False );
	}

	ZERO_STRUCT(new_passwd);

	return ret;
}

/***********************************************************
 Code to check the OEM hashed password.

 this function ignores the 516 byte nt OEM hashed password
 but does use the lm OEM password to check the nt hashed-hash.

************************************************************/
BOOL check_oem_password(char *user,
			uchar *lmdata, uchar *lmhash,
			uchar *ntdata, uchar *nthash,
                        struct smb_passwd **psmbpw, UNISTR2 *new_passwd)
{
	static uchar null_pw[16];
	static uchar null_ntpw[16];
	struct smb_passwd *smbpw = NULL;
	uchar new_ntp16[16];
	uchar unenc_old_ntpw[16];
	uchar new_p16[16];
	uchar unenc_old_pw[16];
	char no_pw[2];
	uint32 len;

	BOOL nt_pass_set = (ntdata != NULL && nthash != NULL);

	become_root(False);
	*psmbpw = smbpw = getsmbpwnam(user);
	unbecome_root(False);

	if (smbpw == NULL)
	{
		DEBUG(0,("check_oem_password: getsmbpwnam returned NULL\n"));
		return False;
	}

	if (smbpw->acct_ctrl & ACB_DISABLED)
	{
		DEBUG(0,("check_lanman_password: account %s disabled.\n", user));
		return False;
	}

	/* construct a null password (in case one is needed */
	no_pw[0] = 0;
	no_pw[1] = 0;
	nt_lm_owf_gen(no_pw, null_ntpw, null_pw);

	/* check for null passwords */
	if (smbpw->smb_passwd == NULL)
	{
		if (smbpw->acct_ctrl & ACB_PWNOTREQ)
		{
			smbpw->smb_passwd = null_pw;
		}
		else 
		{
			DEBUG(0,("check_oem_password: no lanman password !\n"));
			return False;
		}
	}

	if (smbpw->smb_nt_passwd == NULL && nt_pass_set)
	{
		if (smbpw->acct_ctrl & ACB_PWNOTREQ)
		{
			smbpw->smb_nt_passwd = null_pw;
		}
		else 
		{
			DEBUG(0,("check_oem_password: no ntlm password !\n"));
			return False;
		}
	}

	/* 
	 * Call the hash function to get the new password.
	 */
	SamOEMhash( (uchar *)lmdata, (uchar *)smbpw->smb_passwd, True);

	if (!decode_pw_buffer(lmdata, (char*)new_passwd->buffer, 256, &len))
	{
		return False;
	}

	/*
	 * To ensure we got the correct new password, hash it and
	 * use it as a key to test the passed old password.
	 */

	if (!nt_pass_set)
	{
		DEBUG(10,("check_oem_password: non-unicode\n"));
		nt_lm_owf_gen((char*)new_passwd->buffer, new_ntp16, new_p16);

		/*
		 * Now use new_p16 as the key to see if the old
		 * password matches.
		 */
		D_P16(new_p16  , lmhash, unenc_old_pw);

		if (memcmp(smbpw->smb_passwd, unenc_old_pw, 16))
		{
			DEBUG(0,("check_oem_password: old lm password doesn't match.\n"));
			return False;
		}

#ifdef DEBUG_PASSWORD
		DEBUG(100,("check_oem_password: password %s ok\n",
		            (char*)new_passwd->buffer));
#endif
		return True;
	}
	else
	{
		new_passwd->uni_max_len = len / 2;
		new_passwd->uni_str_len = len / 2;
		nt_lm_owf_genW(new_passwd, new_ntp16, new_p16);
	}

	/*
	 * Now use new_p16 as the key to see if the old
	 * password matches.
	 */
	D_P16(new_ntp16, lmhash, unenc_old_pw);
	D_P16(new_ntp16, nthash, unenc_old_ntpw);

#ifdef DEBUG_PASSWORD
	dump_data(100, lmhash, 16);
	dump_data(100, unenc_old_pw, 16);
	dump_data(100, new_ntp16, 16);
	dump_data(100, smbpw->smb_passwd, 16);
#endif
	if (memcmp(smbpw->smb_passwd, unenc_old_pw, 16))
	{
		DEBUG(0,("check_oem_password: old lm password doesn't match.\n"));
		return False;
	}

	if (memcmp(smbpw->smb_nt_passwd, unenc_old_ntpw, 16))
	{
		DEBUG(0,("check_oem_password: old nt password doesn't match.\n"));
		return False;
	}
#ifdef DEBUG_PASSWORD
	DEBUG(100,("check_oem_password: password ok\n"));
#endif
	return True;
}

/***********************************************************
 Code to change the oem password. Changes both the lanman
 and NT hashes.
 override = False, normal
 override = True, override XXXXXXXXXX'd password
************************************************************/

BOOL change_oem_password(struct smb_passwd *smbpw, UNISTR2 *new_passwd, BOOL override)
{
  int ret;
  uchar new_nt_p16[16];
  uchar new_p16[16];

  nt_lm_owf_genW(new_passwd, new_nt_p16, new_p16);

  smbpw->smb_passwd = new_p16;
  smbpw->smb_nt_passwd = new_nt_p16;
  
  /* Now write it into the file. */
  become_root(0);
  ret = mod_smbpwd_entry(smbpw,override);
  unbecome_root(0);

 	ZERO_STRUCTP(new_passwd);

  return ret;
}

/****************************************************************************
update the encrypted smbpasswd file from the plaintext username and password
*****************************************************************************/
BOOL update_smbpassword_file(char *user, char *password)
{
	struct smb_passwd *smbpw;
	UNISTR2 newpw;
	BOOL ret;
	
	become_root(0);
	smbpw = getsmbpwnam(user);
	unbecome_root(0);

	if(smbpw == NULL)
	{
		DEBUG(0,("getsmbpwnam returned NULL\n"));
		return False;
	}
 
	make_unistr2(&newpw, password, password != NULL ? strlen(password) : 0);

	/* Here, the flag is one, because we want to ignore the
           XXXXXXX'd out password */
	ret = change_oem_password( smbpw, &newpw, True);
	if (!ret)
	{
		DEBUG(3,("change_oem_password returned False\n"));
	}

	ZERO_STRUCT(newpw);

	return ret;
}
