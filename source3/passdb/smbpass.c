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

static void gotalarm_sig(void)
{
  gotalarm = 1;
}

/***************************************************************
 Lock or unlock a fd for a known lock type. Abandon after waitsecs 
 seconds.
****************************************************************/

static BOOL do_pw_lock(int fd, int waitsecs, int type)
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
    return False;
  }

  return (ret == 0);
}

static int pw_file_lock_depth;

/***************************************************************
 Lock an fd. Abandon after waitsecs seconds.
****************************************************************/

static BOOL pw_file_lock(int fd, int type, int secs, int *plock_depth)
{
  if (fd < 0)
    return False;

  (*plock_depth)++;

  if(pw_file_lock_depth == 0) {
    if (!do_pw_lock(fd, secs, type)) {
      DEBUG(10,("pw_file_lock: locking file failed, error = %s.\n",
                 strerror(errno)));
      return False;
    }
  }

  return True;
}

/***************************************************************
 Unlock an fd. Abandon after waitsecs seconds.
****************************************************************/

static BOOL pw_file_unlock(int fd, int *plock_depth)
{
  BOOL ret;

  if(*plock_depth == 1)
    ret = do_pw_lock(fd, 5, F_UNLCK);

  (*plock_depth)--;

  if(!ret)
    DEBUG(10,("pw_file_unlock: unlocking file failed, error = %s.\n",
                 strerror(errno)));
  return ret;
}

/***************************************************************
 Start to enumerate the smbpasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

void *startsmbpwent(BOOL update)
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

  if (!pw_file_lock(fileno(fp), (update ? F_WRLCK : F_RDLCK), 5, &pw_file_lock_depth))
  {
    DEBUG(0, ("startsmbpwent: unable to lock file %s\n", pfile));
    fclose(fp);
    return NULL;
  }

  /* Make sure it is only rw by the owner */
  chmod(pfile, 0600);

  /* We have a lock on the file. */
  return (void *)fp;
}

/***************************************************************
 End enumeration of the smbpasswd list.
****************************************************************/

void endsmbpwent(void *vp)
{
  FILE *fp = (FILE *)vp;

  pw_file_unlock(fileno(fp), &pw_file_lock_depth);
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
 Routine to return the next entry in the smbpasswd list.
 *************************************************************************/

struct smb_passwd *getsmbpwent(void *vp)
{
  /* Static buffers we will return. */
  static struct smb_passwd pw_buf;
  static pstring  user_name;
  static unsigned char smbpwd[16];
  static unsigned char smbntpwd[16];
  FILE *fp = (FILE *)vp;
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
  pw_buf.last_change_time = (time_t)-1;

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
     * username:uid:32hex bytes:[Account type]:LCT-12345678....other flags presently
     * ignored....
     * 
     * or,
     *
     * username:uid:32hex bytes:32hex bytes:[Account type]:LCT-12345678....ignored....
     *
     * if Windows NT compatible passwords are also present.
     * [Account type] is an ascii encoding of the type of account.
     * LCT-(8 hex digits) is the time_t value of the last change time.
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
#if 0
   /*
    * Hmmm. Don't allow these to be set/read independently
    * of the actual password fields. We don't want a mismatch.
    * JRA.
    */
          case 'N':
            /* 'N'o password. */
            pw_buf.acct_ctrl |= ACB_PWNOTREQ;
            break;
          case 'D':
            /* 'D'isabled. */
            pw_buf.acct_ctrl |= ACB_DISABLED;
            break;
#endif 
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

      /* Now try and get the last change time. */
      if(*p == ']')
        p++;
      if(*p == ':') {
        p++;
        if(*p && StrnCaseCmp( p, "LCT-", 4)) {
          int i;
          p += 4;
          for(i = 0; i < 8; i++) {
            if(p[i] == '\0' || !isxdigit(p[i]))
              break;
          }
          if(i == 8) {
            /*
             * p points at 8 characters of hex digits - 
             * read into a time_t as the seconds since
             * 1970 that the password was last changed.
             */
            pw_buf.last_change_time = (time_t)strtol(p, NULL, 16);
          }
        }
      }
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
 Return the current position in the smbpasswd list as an unsigned long.
 This must be treated as an opaque token.
*************************************************************************/

unsigned long getsmbpwpos(void *vp)
{
  return (unsigned long)ftell((FILE *)vp);
}

/*************************************************************************
 Set the current position in the smbpasswd list from unsigned long.
 This must be treated as an opaque token.
*************************************************************************/

BOOL setsmbpwpos(void *vp, unsigned long tok)
{
  return !fseek((FILE *)vp, tok, SEEK_SET);
}

/*************************************************************************
 Routine to search the smbpasswd file for an entry matching the username
 or user id.  if the name is NULL, then the smb_uid is used instead.
 *************************************************************************/

static struct smb_passwd *get_smbpwd_entry(char *name, int smb_userid)
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
 Routine to search smbpasswd by name.
*************************************************************************/

struct smb_passwd *getsmbpwnam(char *name)
{
  return get_smbpwd_entry(name, 0);
}

/************************************************************************
 Routine to search smbpasswd by uid.
*************************************************************************/

struct smb_passwd *getsmbpwuid(unsigned int uid)
{
  return get_smbpwd_entry(NULL, uid);
}

/**********************************************************
 Encode the account control bits into a string.
**********************************************************/
        
char *encode_acct_ctrl(uint16 acct_ctrl)
{
  static fstring acct_str;
  char *p = acct_str;
 
  *p++ = '[';

  if(acct_ctrl & ACB_HOMDIRREQ)
    *p++ = 'H';
  if(acct_ctrl & ACB_TEMPDUP)
    *p++ = 'T'; 
  if(acct_ctrl & ACB_NORMAL)
    *p++ = 'U';
  if(acct_ctrl & ACB_MNS)
    *p++ = 'M';
  if(acct_ctrl & ACB_WSTRUST)
    *p++ = 'W';
  if(acct_ctrl & ACB_SVRTRUST) 
    *p++ = 'S';
  if(acct_ctrl & ACB_AUTOLOCK)
    *p++ = 'L';
  if(acct_ctrl & ACB_PWNOEXP)
    *p++ = 'X';
  if(acct_ctrl & ACB_DOMTRUST)
    *p++ = 'I';
      
  *p++ = ']';
  *p = '\0';
  return acct_str;
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
Error was %s\n", newpwd->smb_name, pfile, strerror(errno)));
    endsmbpwent(fp);
    return False;
  }

  new_entry_length = strlen(newpwd->smb_name) + 1 + 15 + 1 + 32 + 1 + 32 + 1 + 5 + 1 + 13 + 2;

  if((new_entry = (char *)malloc( new_entry_length )) == NULL) {
    DEBUG(0, ("add_smbpwd_entry(malloc): Failed to add entry for user %s to file %s. \
Error was %s\n", newpwd->smb_name, pfile, strerror(errno)));
    endsmbpwent(fp);
    return False;
  }

  sprintf(new_entry, "%s:%u:", newpwd->smb_name, (unsigned)newpwd->smb_userid);
  p = (unsigned char *)&new_entry[strlen(new_entry)];

  if(newpwd->smb_passwd != NULL) {
    for( i = 0; i < 16; i++) {
      sprintf((char *)&p[i*2], "%02X", newpwd->smb_passwd[i]);
    }
  } else {
    if(newpwd->acct_ctrl & ACB_PWNOTREQ)
      sprintf((char *)&p[i*2], "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX");
    else
      sprintf((char *)&p[i*2], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  }
  
  p += 32;

  *p++ = ':';

  if(newpwd->smb_nt_passwd != NULL) {
    for( i = 0; i < 16; i++) {
      sprintf((char *)&p[i*2], "%02X", newpwd->smb_nt_passwd[i]);
    }
  } else {
    if(newpwd->acct_ctrl & ACB_PWNOTREQ)
      sprintf(p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX");
    else
      sprintf(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  }

  p += 32;

  *p++ = ':';

  /* Add the account encoding and the last change time. */
  sprintf((char *)p, "%s:LCT-%08X:\n", encode_acct_ctrl(newpwd->acct_ctrl),
                     (uint32)time(NULL));

#ifdef DEBUG_PASSWORD
  DEBUG(100, ("add_smbpwd_entry(%d): new_entry_len %d entry_len %d made line |%s|", 
		             fd, new_entry_length, strlen(new_entry), new_entry));
#endif

  if ((wr_len = write(fd, new_entry, strlen(new_entry))) != strlen(new_entry)) {
    DEBUG(0, ("add_smbpwd_entry(write): %d Failed to add entry for user %s to file %s. \
Error was %s\n", wr_len, newpwd->smb_name, pfile, strerror(errno)));

    /* Remove the entry we just wrote. */
    if(ftruncate(fd, offpos) == -1) {
      DEBUG(0, ("add_smbpwd_entry: ERROR failed to ftruncate file %s. \
Error was %s. Password file may be corrupt ! Please examine by hand !\n", 
             newpwd->smb_name, strerror(errno)));
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
  fstring         ascii_p16;
  fstring         encode_bits;
  unsigned char  *p = NULL;
  long            linebuf_len = 0;
  FILE           *fp;
  int             lockfd;
  char           *pfile = lp_smb_passwd_file();
  BOOL found_entry = False;
  BOOL got_last_change_time = False;

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

  lockfd = fileno(fp);

  if (!pw_file_lock(lockfd, F_WRLCK, 5, &pw_file_lock_depth)) {
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

    fgets(linebuf, sizeof(linebuf), fp);
    if (ferror(fp)) {
      pw_file_unlock(lockfd, &pw_file_lock_depth);
      fclose(fp);
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
    pw_file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  while (*p && isdigit(*p))
    p++;
  if (*p != ':') {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no : after uid)\n"));
    pw_file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
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
    pw_file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (passwd too short)\n"));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return (False);
  }

  if (p[32] != ':') {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no terminating :)\n"));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (*p == '*' || *p == 'X') {
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  /* Now check if the NT compatible password is
     available. */
  p += 33; /* Move to the first character of the line after
              the lanman password. */
  if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (passwd too short)\n"));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return (False);
  }

  if (p[32] != ':') {
    DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no terminating :)\n"));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  /* 
   * Now check if the account info and the password last
   * change time is available.
   */
  p += 33; /* Move to the first character of the line after
              the NT password. */

  if (*p == '[') {

    i = 0;
    p++;
    while((linebuf_len > PTR_DIFF(p, linebuf)) && (*p != ']'))
      encode_bits[i++] = *p++;

    encode_bits[i] = '\0';

    /* Go past the ']' */
    if(linebuf_len > PTR_DIFF(p, linebuf))
      p++;

    if((linebuf_len > PTR_DIFF(p, linebuf)) && (*p == ':')) {
      p++;

      /* We should be pointing at the TLC entry. */
      if((linebuf_len > (PTR_DIFF(p, linebuf) + 13)) && StrnCaseCmp( p, "LCT-", 4)) {

        p += 4;
        for(i = 0; i < 8; i++) {
          if(p[i] == '\0' || !isxdigit(p[i]))
            break;
        }
        if(i == 8) {
          /*
           * p points at 8 characters of hex digits -
           * read into a time_t as the seconds since
           * 1970 that the password was last changed.
           */
          got_last_change_time = True;
        } /* i == 8 */
      } /* *p && StrnCaseCmp() */
    } /* p == ':' */
  } /* p == '[' */

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
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  /* Sanity check - ensure the character is a ':' */
  if (read(fd, &c, 1) != 1) {
    DEBUG(0, ("mod_smbpwd_entry: read fail on file %s.\n", pfile));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (c != ':')	{
    DEBUG(0, ("mod_smbpwd_entry: check on passwd file %s failed.\n", pfile));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }
 
  /* Create the 32 byte representation of the new p16 */
  if(pwd->smb_passwd != NULL) {
    for (i = 0; i < 16; i++) {
      sprintf(&ascii_p16[i*2], "%02X", (uchar) pwd->smb_passwd[i]);
    }
  } else {
    if(pwd->acct_ctrl & ACB_PWNOTREQ)
      sprintf(ascii_p16, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX");
    else
      sprintf(ascii_p16, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  }

  /* Add on the NT md4 hash */
  ascii_p16[32] = ':';
  wr_len = 65;
  if (pwd->smb_nt_passwd != NULL) {
    for (i = 0; i < 16; i++) {
      sprintf(&ascii_p16[(i*2)+33], "%02X", (uchar) pwd->smb_nt_passwd[i]);
    }
  } else {
    if(pwd->acct_ctrl & ACB_PWNOTREQ)
      sprintf(&ascii_p16[33], "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX");
    else
      sprintf(&ascii_p16[33], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  }

  /* Add on the account info bits and the time of last
     password change. */

  pwd->last_change_time = time(NULL);

  if(got_last_change_time) {
    sprintf(&ascii_p16[strlen(ascii_p16)], ":[%s]:TLC-%08X:", 
                     encode_bits, (uint32)pwd->last_change_time );
    wr_len = strlen(ascii_p16);
  }

#ifdef DEBUG_PASSWORD
  DEBUG(100,("mod_smbpwd_entry: "));
  dump_data(100, ascii_p16, wr_len);
#endif

  if (write(fd, ascii_p16, wr_len) != wr_len) {
    DEBUG(0, ("mod_smbpwd_entry: write failed in passwd file %s\n", pfile));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  pw_file_unlock(lockfd,&pw_file_lock_depth);
  fclose(fp);
  return True;
}

static int mach_passwd_lock_depth;

/************************************************************************
 Routine to get the name for a machine account file.
************************************************************************/

static void get_machine_account_file_name( char *domain, char *name, char *mac_file)
{
  unsigned int mac_file_len;
  char *p;

  pstrcpy(mac_file, lp_smb_passwd_file());
  p = strrchr(mac_file, '/');
  if(p != NULL)
    *++p = '\0';

  mac_file_len = strlen(mac_file);

  if (sizeof(pstring) - mac_file_len - strlen(domain) - strlen(name) - 6 < 0)
  {
    DEBUG(0,("machine_password_lock: path %s too long to add machine details.\n",
              mac_file));
    return;
  }

  strcat(mac_file, domain);
  strcat(mac_file, ".");
  strcat(mac_file, name);
  strcat(mac_file, ".mac");
}
 
/************************************************************************
 Routine to lock the machine account password file for a domain.
************************************************************************/

void *machine_password_lock( char *domain, char *name, BOOL update)
{
  FILE *fp;
  pstring mac_file;

  if(mach_passwd_lock_depth == 0) {

    get_machine_account_file_name( domain, name, mac_file);

    if((fp = fopen(mac_file, "r+b")) == NULL) {
      if(errno == ENOENT && update) {
        fp = fopen(mac_file, "w+b");
      }

      if(fp == NULL) {
        DEBUG(0,("machine_password_lock: cannot open file %s - Error was %s.\n",
              mac_file, strerror(errno) ));
        return NULL;
      }
    }

    chmod(mac_file, 0600);
  }

  if(!pw_file_lock(fileno(fp), (update ? F_WRLCK : F_RDLCK), 
                                      60, &mach_passwd_lock_depth))
  {
    DEBUG(0,("machine_password_lock: cannot lock file %s\n", mac_file));
    fclose(fp);
    return NULL;
  }

  return (void *)fp;
}

/************************************************************************
 Routine to unlock the machine account password file for a domain.
************************************************************************/

BOOL machine_password_unlock( void *token )
{
  FILE *fp = (FILE *)token;
  BOOL ret = pw_file_unlock(fileno(fp), &mach_passwd_lock_depth);
  if(mach_passwd_lock_depth == 0)
    fclose(fp);
  return ret;
}

/************************************************************************
 Routine to delete the machine account password file for a domain.
************************************************************************/

BOOL machine_password_delete( char *domain, char *name )
{
  pstring mac_file;

  get_machine_account_file_name( domain, name, mac_file);
  return (unlink( mac_file ) == 0);
}

/************************************************************************
 Routine to get the machine account password for a domain.
 The user of this function must have locked the machine password file.
************************************************************************/

BOOL get_machine_account_password( void *mach_tok, unsigned char *ret_pwd,
                                   time_t *last_change_time)
{
  FILE *fp = (FILE *)mach_tok;
  char linebuf[256];
  char *p;
  int i;

  linebuf[0] = '\0';

  *last_change_time = (time_t)0;
  memset(ret_pwd, '\0', 16);

  if(fseek( fp, 0L, SEEK_SET) == -1) {
    DEBUG(0,("get_machine_account_password: Failed to seek to start of file. Error was %s.\n",
              strerror(errno) ));
    return False;
  } 

  fgets(linebuf, sizeof(linebuf), fp);
  if(ferror(fp)) {
    DEBUG(0,("get_machine_account_password: Failed to read password. Error was %s.\n",
              strerror(errno) ));
    return False;
  }

  /*
   * The length of the line read
   * must be 45 bytes ( <---XXXX 32 bytes-->:TLC-12345678
   */

  if(strlen(linebuf) != 45) {
    DEBUG(0,("get_machine_account_password: Malformed machine password file (wrong length).\n"));
#ifdef DEBUG_PASSWORD
    DEBUG(100,("get_machine_account_password: line = |%s|\n", linebuf));
#endif
    return False;
  }

  /*
   * Get the hex password.
   */

  if (!gethexpwd((char *)linebuf, (char *)ret_pwd) || linebuf[32] != ':' || 
         strncmp(&linebuf[33], "TLC-", 4)) {
    DEBUG(0,("get_machine_account_password: Malformed machine password file (incorrect format).\n"));
#ifdef DEBUG_PASSWORD
    DEBUG(100,("get_machine_account_password: line = |%s|\n", linebuf));
#endif
    return False;
  }

  /*
   * Get the last changed time.
   */
  p = &linebuf[37];

  for(i = 0; i < 8; i++) {
    if(p[i] == '\0' || !isxdigit(p[i])) {
      DEBUG(0,("get_machine_account_password: Malformed machine password file (no timestamp).\n"));
#ifdef DEBUG_PASSWORD
      DEBUG(100,("get_machine_account_password: line = |%s|\n", linebuf));
#endif
      return False;
    }
  }

  /*
   * p points at 8 characters of hex digits -
   * read into a time_t as the seconds since
   * 1970 that the password was last changed.
   */

  *last_change_time = (time_t)strtol(p, NULL, 16);

  return True;
}

/************************************************************************
 Routine to get the machine account password for a domain.
 The user of this function must have locked the machine password file.
************************************************************************/

BOOL set_machine_account_password( void *mach_tok, unsigned char *md4_new_pwd)
{
  char linebuf[64];
  int i;
  FILE *fp = (FILE *)mach_tok;

  if(fseek( fp, 0L, SEEK_SET) == -1) {
    DEBUG(0,("set_machine_account_password: Failed to seek to start of file. Error was %s.\n",
              strerror(errno) ));
    return False;
  } 

  for (i = 0; i < 16; i++)
    sprintf(&linebuf[(i*2)], "%02X", md4_new_pwd[i]);

  sprintf(&linebuf[32], ":TLC-%08X\n", (unsigned)time(NULL));

  if(fwrite( linebuf, 1, 45, fp)!= 45) {
    DEBUG(0,("set_machine_account_password: Failed to write file. Warning - the machine \
machine account is now invalid. Please recreate. Error was %s.\n", strerror(errno) ));
    return False;
  }

  fflush(fp);
  return True;
}
