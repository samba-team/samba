/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

extern int DEBUGLEVEL;

static int gotalarm;
static char s_readbuf[16 * 1024];

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/

static void gotalarm_sig()
{
  gotalarm = 1;
}

/***************************************************************
 Lock or unlock a fd for a known lock type. Abandon after waitsecs 
 seconds.
****************************************************************/

static int do_pw_lock(int fd, int waitsecs, int type)
{
  struct flock    lock;
  int             ret;

  gotalarm = 0;
  signal(SIGALRM, SIGNAL_CAST gotalarm_sig);

  lock.l_type = type;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 1;
  lock.l_pid = 0;

  alarm(5);
  ret = fcntl(fd, F_SETLKW, &lock);
  alarm(0);
  signal(SIGALRM, SIGNAL_CAST SIG_DFL);

  if (gotalarm) {
    DEBUG(0, ("do_pw_lock: failed to %s SMB passwd file.\n",
                type == F_UNLCK ? "unlock" : "lock"));
    return -1;
  }
  return ret;
}

/***************************************************************
 Lock an fd. Abandon after waitsecs seconds.
****************************************************************/

int pw_file_lock(int fd, int type, int secs)
{
  if (fd < 0)
    return (-1);
  if (do_pw_lock(fd, secs, type)) {
    return -1;
  }
  return fd;
}

/***************************************************************
 Unlock an fd. Abandon after waitsecs seconds.
****************************************************************/

int pw_file_unlock(int fd)
{
 return do_pw_lock(fd, 5, F_UNLCK);
}

/***************************************************************
 Open the smbpasswd file - get ready to enumerate it.
****************************************************************/

FILE *startsmbpwent(BOOL update)
{
  FILE *fp = NULL;
  char *pfile = lp_smb_passwd_file();

  if (!*pfile) {
    DEBUG(0, ("startsmbpwent: No SMB password file set\n"));
    return (NULL);
  }
  DEBUG(10, ("startsmbpwent: opening file %s\n", pfile));

  fp = fopen(pfile, update ? "r+b" : "rb");

  if (fp == NULL) {
    DEBUG(0, ("startsmbpwent: unable to open file %s\n", pfile));
    return NULL;
  }

  /* Set a 16k buffer to do more efficient reads */
  setvbuf(fp, s_readbuf, _IOFBF, sizeof(s_readbuf));

  if ((pw_file_lock(fileno(fp), F_RDLCK | (update ? F_WRLCK : 0), 5)) < 0) {
    DEBUG(0, ("startsmbpwent: unable to lock file %s\n", pfile));
    fclose(fp);
    return NULL;
  }

  /* Make sure it is only rw by the owner */
  chmod(pfile, 0600);

  /* We have a lock on the file. */
  return fp;
}

/***************************************************************
 Close the smbpasswd file - end enumeration.
****************************************************************/

void endsmbpwent(FILE *fp)
{
  pw_file_unlock(fileno(fp));
  fclose(fp);
  DEBUG(7, ("endsmbpwent: closed password file.\n"));
}

/*************************************************************
 Routine to get the next 32 hex characters and turn them
 into a 16 byte array.
**************************************************************/

static int gethexpwd(char *p, char *pwd)
{
  int i;
  unsigned char   lonybble, hinybble;
  char           *hexchars = "0123456789ABCDEF";
  char           *p1, *p2;

  for (i = 0; i < 32; i += 2) {
    hinybble = toupper(p[i]);
    lonybble = toupper(p[i + 1]);
 
    p1 = strchr(hexchars, hinybble);
    p2 = strchr(hexchars, lonybble);
    if (!p1 || !p2)
      return (False);
    hinybble = PTR_DIFF(p1, hexchars);
    lonybble = PTR_DIFF(p2, hexchars);
 
    pwd[i / 2] = (hinybble << 4) | lonybble;
  }
  return (True);
}

/*************************************************************************
 Routine to return the next entry in the smbpasswd file.
 *************************************************************************/

struct smb_passwd *getsmbpwent(FILE *fp)
{
  /* Static buffers we will return. */
  static struct smb_passwd pw_buf;
  static pstring  user_name;
  static unsigned char smbpwd[16];
  static unsigned char smbntpwd[16];
  char            linebuf[256];
  unsigned char   c;
  unsigned char  *p;
  long            uidval;
  long            linebuf_len;

  if(fp == NULL) {
    DEBUG(0,("getsmbpwent: Bad password file pointer.\n"));
    return NULL;
  }

  pw_buf.acct_ctrl = ACB_NORMAL;  

  /*
   * Scan the file, a line at a time and check if the name matches.
   */
  while (!feof(fp)) {
    linebuf[0] = '\0';

    fgets(linebuf, 256, fp);
    if (ferror(fp)) {
      return NULL;
    }

    /*
     * Check if the string is terminated with a newline - if not
     * then we must keep reading and discard until we get one.
     */
    linebuf_len = strlen(linebuf);
    if (linebuf[linebuf_len - 1] != '\n') {
      c = '\0';
      while (!ferror(fp) && !feof(fp)) {
        c = fgetc(fp);
        if (c == '\n')
          break;
      }
    } else
      linebuf[linebuf_len - 1] = '\0';

#ifdef DEBUG_PASSWORD
    DEBUG(100, ("getsmbpwent: got line |%s|\n", linebuf));
#endif
    if ((linebuf[0] == 0) && feof(fp)) {
      DEBUG(4, ("getsmbpwent: end of file reached\n"));
      break;
    }
    /*
     * The line we have should be of the form :-
     * 
     * username:uid:[32hex bytes]:....other flags presently
     * ignored....
     * 
     * or,
     *
     * username:uid:[32hex bytes]:[32hex bytes]:....ignored....
     *
     * if Windows NT compatible passwords are also present.
     */

    if (linebuf[0] == '#' || linebuf[0] == '\0') {
      DEBUG(6, ("getsmbpwent: skipping comment or blank line\n"));
      continue;
    }
    p = (unsigned char *) strchr(linebuf, ':');
    if (p == NULL) {
      DEBUG(0, ("getsmbpwent: malformed password entry (no :)\n"));
      continue;
    }
    /*
     * As 256 is shorter than a pstring we don't need to check
     * length here - if this ever changes....
     */
    strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
    user_name[PTR_DIFF(p, linebuf)] = '\0';

    /* Get smb uid. */

    p++;		/* Go past ':' */
    if (!isdigit(*p)) {
      DEBUG(0, ("getsmbpwent: malformed password entry (uid not number)\n"));
      continue;
    }

    uidval = atoi((char *) p);

    while (*p && isdigit(*p))
      p++;

    if (*p != ':') {
      DEBUG(0, ("getsmbpwent: malformed password entry (no : after uid)\n"));
      continue;
    }

    pw_buf.smb_name = user_name;
    pw_buf.smb_userid = uidval;

    /*
     * Now get the password value - this should be 32 hex digits
     * which are the ascii representations of a 16 byte string.
     * Get two at a time and put them into the password.
     */

    /* Skip the ':' */
    p++;

    if (*p == '*' || *p == 'X') {
      /* Password deliberately invalid - end here. */
      DEBUG(10, ("getsmbpwent: entry invalidated for user %s\n", user_name));
      pw_buf.smb_nt_passwd = NULL;
      pw_buf.smb_passwd = NULL;
      pw_buf.acct_ctrl |= ACB_DISABLED;
      return &pw_buf;
    }

    if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
      DEBUG(0, ("getsmbpwent: malformed password entry (passwd too short)\n"));
      continue;
    }

    if (p[32] != ':') {
      DEBUG(0, ("getsmbpwent: malformed password entry (no terminating :)\n"));
      continue;
    }

    if (!strncasecmp((char *) p, "NO PASSWORD", 11)) {
      pw_buf.smb_passwd = NULL;
      pw_buf.acct_ctrl |= ACB_PWNOTREQ;
    } else {
      if (!gethexpwd((char *)p, (char *)smbpwd)) {
        DEBUG(0, ("getsmbpwent: Malformed Lanman password entry (non hex chars)\n"));
        continue;
      }
      pw_buf.smb_passwd = smbpwd;
    }

    /* 
     * Now check if the NT compatible password is
     * available.
     */
    pw_buf.smb_nt_passwd = NULL;

    p += 33; /* Move to the first character of the line after
                the lanman password. */
    if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':')) {
      if (*p != '*' && *p != 'X') {
        if(gethexpwd((char *)p,(char *)smbntpwd))
          pw_buf.smb_nt_passwd = smbntpwd;
      }
      p += 33; /* Move to the first character of the line after
                  the NT password. */
    }

    DEBUG(5, ("getsmbpwent: returning passwd entry for user %s, uid %d\n",
			  user_name, uidval));

    /*
     * Check if the account type bits have been encoded after the
     * NT password (in the form [NDHTUWSLXI]).
     */

    if (*p == '[') {
      BOOL finished = False;

      pw_buf.acct_ctrl = 0;

      for(p++;*p && !finished; p++) {
        switch (*p) {
          case 'N':
            /* 'N'o password. */
            pw_buf.acct_ctrl |= ACB_PWNOTREQ;
            break;
          case 'D':
            /* 'D'isabled. */
            pw_buf.acct_ctrl |= ACB_DISABLED;
            break;
          case 'H':
            /* 'H'omedir required. */
            pw_buf.acct_ctrl |= ACB_HOMDIRREQ;
            break;
          case 'T':
            /* 'T'emp account. */
            pw_buf.acct_ctrl |= ACB_TEMPDUP;
            break;
          case 'U':
            /* 'U'ser account (normal). */
            pw_buf.acct_ctrl |= ACB_NORMAL;
            break;
          case 'M':
            /* 'M'NS logon user account. What is this ? */
            pw_buf.acct_ctrl |= ACB_MNS;
            break;
          case 'W':
            /* 'W'orkstation account. */
            pw_buf.acct_ctrl |= ACB_WSTRUST;
            break;
          case 'S':
            /* 'S'erver account. */
            pw_buf.acct_ctrl |= ACB_SVRTRUST;
            break;
          case 'L':
            /* 'L'ocked account. */
            pw_buf.acct_ctrl |= ACB_AUTOLOCK;
            break;
          case 'X':
            /* No 'X'piry. */
            pw_buf.acct_ctrl |= ACB_PWNOEXP;
            break;
          case 'I':
            /* 'I'nterdomain trust account. */
            pw_buf.acct_ctrl |= ACB_DOMTRUST;
            break;

          case ':':
          case '\n':
          case '\0': 
          case ']':
          default:
            finished = True;
        }
      }

      /* Must have some account type set. */
      if(pw_buf.acct_ctrl == 0)
        pw_buf.acct_ctrl = ACB_NORMAL;

    } else {
      /* 'Old' style file. Fake up based on user name. */
      /*
       * Currently machine accounts are kept in the same
       * password file as 'normal accounts'. If this changes
       * we will have to fix this code. JRA.
       */
      if(pw_buf.smb_name[strlen(pw_buf.smb_name) - 1] == '$') {
        pw_buf.acct_ctrl &= ~ACB_NORMAL;
        pw_buf.acct_ctrl |= ACB_WSTRUST;
      }
    }

    return &pw_buf;
  }

  DEBUG(5,("getsmbpwent: end of file reached.\n"));
  return NULL;
}

/*************************************************************************
 Routine to search the smbpasswd file for an entry matching the username
 or user id.  if the name is NULL, then the smb_uid is used instead.
 *************************************************************************/

struct smb_passwd *get_smbpwd_entry(char *name, int smb_userid)
{
  struct smb_passwd *pwd = NULL;
  FILE *fp = NULL;

  if (name != NULL) {
    DEBUG(10, ("get_smbpwd_entry: search by name: %s\n", name));
  } else {
    DEBUG(10, ("get_smbpwd_entry: search by smb_userid: %x\n", smb_userid));
  }

  /* Open the smbpassword file - not for update. */
  fp = startsmbpwent(False);

  if (fp == NULL) {
    DEBUG(0, ("get_smbpwd_entry: unable to open password file.\n"));
    return NULL;
  }

  /*
   * Scan the file, a line at a time and check if the name 
   * or uid matches.
   */

  while ((pwd = getsmbpwent(fp)) != NULL) {
    if (name != NULL) {
      /* Search is by user name */
      if (!strequal(pwd->smb_name, name))
        continue;
      DEBUG(10, ("get_smbpwd_entry: found by name: %s\n", name));
      break;
    } else {
      /* Search is by user id */
      if (pwd->smb_userid != smb_userid)
        continue;
      DEBUG(10, ("get_smbpwd_entry: found by smb_userid: %x\n", smb_userid));
      break;
    }
  }

  endsmbpwent(fp);
  return pwd;
}

/************************************************************************
 Routine to add an entry to the smbpasswd file.
*************************************************************************/

BOOL add_smbpwd_entry(struct smb_passwd *newpwd)
{
  char *pfile = lp_smb_passwd_file();
  struct smb_passwd *pwd = NULL;
  FILE *fp = NULL;

  int i;
  int wr_len;

  int fd;
  int new_entry_length;
  char *new_entry;
  long offpos;
  unsigned char *p;

  /* Open the smbpassword file - for update. */
  fp = startsmbpwent(True);

  if (fp == NULL) {
    DEBUG(0, ("add_smbpwd_entry: unable to open file.\n"));
    return False;
  }

  /*
   * Scan the file, a line at a time and check if the name matches.
   */

  while ((pwd = getsmbpwent(fp)) != NULL) {
    if (strequal(newpwd->smb_name, pwd->smb_name)) {
      DEBUG(0, ("add_smbpwd_entry: entry with name %s already exists\n", pwd->smb_name));
      endsmbpwent(fp);
      return False;
    }
  }

  /* Ok - entry doesn't exist. We can add it */

  /* Create a new smb passwd entry and set it to the given password. */
  /* 
   * The add user write needs to be atomic - so get the fd from 
   * the fp and do a raw write() call.
   */
  fd = fileno(fp);

  if((offpos = lseek(fd, 0, SEEK_END)) == -1) {
    DEBUG(0, ("add_smbpwd_entry(lseek): Failed to add entry for user %s to file %s. \
Error was %s\n", pwd->smb_name, pfile, strerror(errno)));
    endsmbpwent(fp);
    return False;
  }

  new_entry_length = strlen(pwd->smb_name) + 1 + 15 + 1 + 32 + 1 + 32 + 1 + 2;

  if((new_entry = (char *)malloc( new_entry_length )) == NULL) {
    DEBUG(0, ("add_smbpwd_entry(malloc): Failed to add entry for user %s to file %s. \
Error was %s\n", pwd->smb_name, pfile, strerror(errno)));
    endsmbpwent(fp);
    return False;
  }

  sprintf(new_entry, "%s:%u:", pwd->smb_name, (unsigned)pwd->smb_userid);
  p = (unsigned char *)&new_entry[strlen(new_entry)];

  for( i = 0; i < 16; i++) {
    sprintf((char *)&p[i*2], "%02X", pwd->smb_passwd[i]);
  }

  p += 32;

  *p++ = ':';

  for( i = 0; i < 16; i++) {
    sprintf((char *)&p[i*2], "%02X", pwd->smb_nt_passwd[i]);
  }
  p += 32;

  *p++ = ':';
  sprintf((char *)p,"\n");

#ifdef DEBUG_PASSWORD
  DEBUG(100, ("add_smbpwd_entry(%d): new_entry_len %d entry_len %d made line |%s|\n", 
		             fd, new_entry_length, strlen(new_entry), new_entry));
#endif

  if ((wr_len = write(fd, new_entry, strlen(new_entry))) != strlen(new_entry)) {
    DEBUG(0, ("add_smbpwd_entry(write): %d Failed to add entry for user %s to file %s. \
Error was %s\n", wr_len, pwd->smb_name, pfile, strerror(errno)));

    /* Remove the entry we just wrote. */
    if(ftruncate(fd, offpos) == -1) {
      DEBUG(0, ("add_smbpwd_entry: ERROR failed to ftruncate file %s. \
Error was %s. Password file may be corrupt ! Please examine by hand !\n", 
             pwd->smb_name, strerror(errno)));
    }

    endsmbpwent(fp);
    return False;
  }

  endsmbpwent(fp);
  return True;
}

/************************************************************************
 Routine to search the smbpasswd file for an entry matching the username.
 and then modify its password entry. We can't use the startsmbpwent()/
 getsmbpwent()/endsmbpwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
************************************************************************/

BOOL mod_smbpwd_entry(struct smb_passwd* pwd)
{
  /* Static buffers we will return. */
  static pstring  user_name;

  char            linebuf[256];
  char            readbuf[16 * 1024];
  unsigned char   c;
  char            ascii_p16[66];
  unsigned char  *p = NULL;
  long            linebuf_len = 0;
  FILE           *fp;
  int             lockfd;
  char           *pfile = lp_smb_passwd_file();
  BOOL found_entry = False;

  long pwd_seekpos = 0;

  int i;
  int wr_len;
  int fd;

  if (!*pfile) {
    DEBUG(0, ("No SMB password file set\n"));
    return False;
  }
  DEBUG(10, ("mod_smbpwd_entry: opening file %s\n", pfile));

  fp = fopen(pfile, "r+");

  if (fp == NULL) {
    DEBUG(0, ("mod_smbpwd_entry: unable to open file %s\n", pfile));
    return False;
  }
  /* Set a 16k buffer to do more efficient reads */
  setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));

  if ((lockfd = pw_file_lock(fileno(fp), F_RDLCK | F_WRLCK, 5)) < 0) {
    DEBUG(0, ("mod_smbpwd_entry: unable to lock file %s\n", pfile));
    fclose(fp);
    return False;
  }

  /* Make sure it is only rw by the owner */
  chmod(pfile, 0600);

  /* We have a write lock on the file. */
  /*
   * Scan the file, a line at a time and check if the name matches.
   */
  while (!feof(fp)) {
    pwd_seekpos = ftell(fp);

    linebuf[0] = '\0';

    fgets(linebuf, 256, fp);
    if (ferror(fp)) {
      fclose(fp);
      pw_file_unlock(lockfd);
      return False;
    }

    /*
     * Check if the string is terminated with a newline - if not
     * then we must keep reading and discard until we get one.
     */
    linebuf_len = strlen(linebuf);
    if (linebuf[linebuf_len - 1] != '\n') {
      c = '\0';
      while (!ferror(fp) && !feof(fp)) {
        c = fgetc(fp);
        if (c == '\n') {
          break;
        }
      }
    } else {
      linebuf[linebuf_len - 1] = '\0';
    }

#ifdef DEBUG_PASSWORD
    DEBUG(100, ("mod_smbpwd_entry: got line |%s|\n", linebuf));
#endif

    if ((linebuf[0] == 0) && feof(fp)) {
      DEBUG(4, ("mod_smbpwd_entry: end of file reached\n"));
      break;
    }

    /*
     * The line we have should be of the form :-
     * 
     * username:uid:[32hex bytes]:....other flags presently
     * ignored....
     * 
     * or,
     *
     * username:uid:[32hex bytes]:[32hex bytes]:....ignored....
     *
     * if Windows NT compatible passwords are also present.
     */

    if (linebuf[0] == '#' || linebuf[0] == '\0') {
      DEBUG(6, ("mod_smbpwd_entry: skipping comment or blank line\n"));
      continue;
    }

    p = (unsigned char *) strchr(linebuf, ':');

    if (p == NULL) {
      DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no :)\n"));
      continue;
    }

    /*
     * As 256 is shorter than a pstring we don't need to check
     * length here - if this ever changes....
     */
    strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
    user_name[PTR_DIFF(p, linebuf)] = '\0';
    if (strequal(user_name, pwd->smb_name)) {
      found_entry = True;
      break;
    }
  }

  if (!found_entry) return False;

  DEBUG(6, ("mod_smbpwd_entry: entry exists\n"));

  /* User name matches - get uid and password */
  p++;		/* Go past ':' */

  if (!isdigit(*p)) {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (uid not number)\n"));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  while (*p && isdigit(*p))
    p++;
  if (*p != ':') {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no : after uid)\n"));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  /*
   * Now get the password value - this should be 32 hex digits
   * which are the ascii representations of a 16 byte string.
   * Get two at a time and put them into the password.
   */
  p++;

  /* Record exact password position */
  pwd_seekpos += PTR_DIFF(p, linebuf);

  if (*p == '*' || *p == 'X') {
    /* Password deliberately invalid - end here. */
    DEBUG(10, ("get_smbpwd_entry: entry invalidated for user %s\n", user_name));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (passwd too short)\n"));
    fclose(fp);
    pw_file_unlock(lockfd);
    return (False);
  }

  if (p[32] != ':') {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no terminating :)\n"));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  if (*p == '*' || *p == 'X') {
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  /* Now check if the NT compatible password is
     available. */
  p += 33; /* Move to the first character of the line after
              the lanman password. */
  if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (passwd too short)\n"));
    fclose(fp);
    pw_file_unlock(lockfd);
    return (False);
  }

  if (p[32] != ':') {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no terminating :)\n"));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  /* Entry is correctly formed. */

  /*
   * Do an atomic write into the file at the position defined by
   * seekpos.
   */

  /* The mod user write needs to be atomic - so get the fd from 
     the fp and do a raw write() call.
   */

  fd = fileno(fp);

  if (lseek(fd, pwd_seekpos - 1, SEEK_SET) != pwd_seekpos - 1) {
    DEBUG(0, ("mod_smbpwd_entry: seek fail on file %s.\n", pfile));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  /* Sanity check - ensure the character is a ':' */
  if (read(fd, &c, 1) != 1) {
    DEBUG(0, ("mod_smbpwd_entry: read fail on file %s.\n", pfile));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  if (c != ':')	{
    DEBUG(0, ("mod_smbpwd_entry: check on passwd file %s failed.\n", pfile));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }
 
  /* Create the 32 byte representation of the new p16 */
  for (i = 0; i < 16; i++) {
    sprintf(&ascii_p16[i*2], "%02X", (uchar) pwd->smb_passwd[i]);
  }

  /* Add on the NT md4 hash */
  ascii_p16[32] = ':';
  wr_len = 65;
  if (pwd->smb_nt_passwd != NULL) {
    for (i = 0; i < 16; i++) {
      sprintf(&ascii_p16[(i*2)+33], "%02X", (uchar) pwd->smb_nt_passwd[i]);
    }
  } else {
    /* No NT hash - write out an 'invalid' string. */
    strcpy(&ascii_p16[33], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  }

#ifdef DEBUG_PASSWORD
  DEBUG(100,("mod_smbpwd_entry: "));
  dump_data(100, ascii_p16, wr_len);
#endif

  if (write(fd, ascii_p16, wr_len) != wr_len) {
    DEBUG(0, ("mod_smbpwd_entry: write failed in passwd file %s\n", pfile));
    fclose(fp);
    pw_file_unlock(lockfd);
    return False;
  }

  fclose(fp);
  pw_file_unlock(lockfd);
  return True;
}
