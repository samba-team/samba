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

#ifdef ALLOW_CHANGE_PASSWORD

#define MINPASSWDLENGTH 5
#define BUFSIZE 512

static int findpty(char **slave)
{
  int master;
#ifdef SVR4
  extern char *ptsname();
#else
  static char line[12] = "/dev/ptyXX";
  void *dirp;
  char *dpname;
#endif
  
#ifdef SVR4
  if ((master = open("/dev/ptmx", O_RDWR)) >= 1) {
    grantpt(master);
    unlockpt(master);
    *slave = ptsname(master);
    return (master);
  }
#else
  dirp = OpenDir("/dev");
  if (!dirp) return(-1);
  while ((dpname = ReadDirName(dirp)) != NULL) {
    if (strncmp(dpname, "pty", 3) == 0 && strlen(dpname) == 5) {
      line[8] = dpname[3];
      line[9] = dpname[4];
      if ((master = open(line, O_RDWR)) >= 0) {
	line[5] = 't';
	*slave = line;
	CloseDir(dirp);
	return (master);
      }
    }
  }
  CloseDir(dirp);
#endif
  return (-1);
}

static int dochild(int master,char *slavedev, char *name, char *passwordprogram)
{
  int slave;
  struct termios stermios;
  struct passwd *pass = Get_Pwnam(name,True);
  int gid = pass->pw_gid;
  int uid = pass->pw_uid;

#ifdef USE_SETRES
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
  if ((slave = open(slavedev, O_RDWR)) < 0) {
    DEBUG(3,("More weirdness, could not open %s\n", 
	     slavedev));
    return(False);
  }
#ifdef SVR4
  ioctl(slave, I_PUSH, "ptem");
  ioctl(slave, I_PUSH, "ldterm");
#else
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
      strcpy(s1,buf);
      strcpy(s2,expected);
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

  while (next_token(&ptr,chatbuf,NULL)) {
    BOOL ok=True;
    count++;
    pwd_sub(chatbuf);
    if (!strequal(chatbuf,"."))
      ok = expect(master,chatbuf,buf);

#if DEBUG_PASSWORD
      DEBUG(100,("chatbuf=[%s] responsebuf=[%s]\n",chatbuf,buf));
#endif      

    if (!ok) {
      DEBUG(3,("response %d incorrect\n",count));
      return(False);
    }

    if (!next_token(&ptr,chatbuf,NULL)) break;
    pwd_sub(chatbuf);
    if (!strequal(chatbuf,"."))
      writestring(master,chatbuf);

#if DEBUG_PASSWORD
    DEBUG(100,("sendbuf=[%s]\n",chatbuf));
#endif      
  }

  if (count<1) return(False);

  return (True);
}


BOOL chat_with_program(char *passwordprogram,char *name,char *chatsequence)
{
  char *slavedev;
  int master;
  pid_t pid, wpid;
  int wstat;
  BOOL chstat;    

  /* allocate a pseudo-terminal device */
  if ((master = findpty (&slavedev)) < 0) {
    DEBUG(3,("Cannot Allocate pty for password change: %s",name));
    return(False);
  }

  if ((pid = fork()) < 0) {
    DEBUG(3,("Cannot fork() child for password change: %s",name));
    return(False);
  }

  /* we now have a pty */
  if (pid > 0){			/* This is the parent process */
    if ((chstat = talktochild(master, chatsequence)) == False) {
      DEBUG(3,("Child failed to change password: %s\n",name));
      kill(pid, SIGKILL); /* be sure to end this process */
      return(False);
    }
    if ((wpid = waitpid(pid, &wstat, 0)) < 0) {
      DEBUG(3,("The process is no longer waiting!\n\n"));
      return(False);
    }
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

    /* make sure it doesn't freeze */
    alarm(20);

    DEBUG(3,("Dochild for user %s (uid=%d,gid=%d)\n",name,getuid(),getgid()));
    chstat = dochild(master, slavedev, name, passwordprogram);
  }
  DEBUG(3,("Password change %ssuccessful for user %s\n", (chstat?"":"un"), name));
  return (chstat);
}


BOOL chgpasswd(char *name,char *oldpass,char *newpass)
{
  pstring passwordprogram;
  pstring chatsequence;

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

#if (defined(PASSWD_PROGRAM) && defined(PASSWD_CHAT))
  strcpy(passwordprogram,PASSWD_PROGRAM);
  strcpy(chatsequence,PASSWD_CHAT);
#else
  strcpy(passwordprogram,lp_passwd_program());
  strcpy(chatsequence,lp_passwd_chat());
#endif

  if (!*chatsequence) {
    DEBUG(2,("Null chat sequence - no password changing\n"));
    return(False);
  }

  if (!*passwordprogram) {
    DEBUG(2,("Null password program - no password changing\n"));
    return(False);
  }

  string_sub(passwordprogram,"%u",name);
  string_sub(passwordprogram,"%o",oldpass);
  string_sub(passwordprogram,"%n",newpass);

  string_sub(chatsequence,"%u",name);
  string_sub(chatsequence,"%o",oldpass);
  string_sub(chatsequence,"%n",newpass);
  return(chat_with_program(passwordprogram,name,chatsequence));
}

#else
BOOL chgpasswd(char *name,char *oldpass,char *newpass)
{
  DEBUG(0,("Password changing not compiled in (user=%s)\n",name));
  return(False);
}
#endif
