/*
 * Unix SMB/Netbios implementation. 
 * Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 
 * Modified by Jeremy Allison 1995.
 * Modified by Gerald (Jerry) Carter 2000-2001
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

#ifdef WITH_SMBPASSWD_SAM


/* 
   smb_passwd is analogous to sam_passwd used everywhere
   else.  However, smb_passwd is limited to the information
   stored by an smbpasswd entry 
 */
 
struct smb_passwd
{
        uid_t smb_userid;     /* this is actually the unix uid_t */
        char *smb_name;     /* username string */

        unsigned char *smb_passwd; /* Null if no password */
        unsigned char *smb_nt_passwd; /* Null if no password */

        uint16 acct_ctrl; /* account info (ACB_xxxx bit-mask) */
        time_t pass_last_set_time;    /* password last set time */
};


extern pstring samlogon_user;
extern BOOL sam_logon_in_ssb;
extern struct passdb_ops pdb_ops;


/* used for maintain locks on the smbpasswd file */
static int 	pw_file_lock_depth;
static void 	*global_vp;


enum pwf_access_type { PWF_READ, PWF_UPDATE, PWF_CREATE };

/***************************************************************
 Lock an fd. Abandon after waitsecs seconds.
****************************************************************/

static BOOL pw_file_lock(int fd, int type, int secs, int *plock_depth)
{
  if (fd < 0)
    return False;

  if(*plock_depth == 0) {
    if (!do_file_lock(fd, secs, type)) {
      DEBUG(10,("pw_file_lock: locking file failed, error = %s.\n",
                 strerror(errno)));
      return False;
    }
  }

  (*plock_depth)++;

  return True;
}

/***************************************************************
 Unlock an fd. Abandon after waitsecs seconds.
****************************************************************/

static BOOL pw_file_unlock(int fd, int *plock_depth)
{
  BOOL ret=True;

  if(*plock_depth == 1)
    ret = do_file_lock(fd, 5, F_UNLCK);

  if (*plock_depth > 0)
    (*plock_depth)--;

  if(!ret)
    DEBUG(10,("pw_file_unlock: unlocking file failed, error = %s.\n",
                 strerror(errno)));
  return ret;
}


/**************************************************************
 Intialize a smb_passwd struct
 *************************************************************/

static void pdb_init_smb(struct smb_passwd *user)
{
	if (user == NULL) 
		return;
	ZERO_STRUCTP (user);
	
	user->pass_last_set_time = (time_t)0;
}

/***************************************************************
 Internal fn to enumerate the smbpasswd list. Returns a void pointer
 to ensure no modification outside this module. Checks for atomic
 rename of smbpasswd file on update or create once the lock has
 been granted to prevent race conditions. JRA.
****************************************************************/

static void *startsmbfilepwent(const char *pfile, enum pwf_access_type type, int *lock_depth)
{
  FILE *fp = NULL;
  const char *open_mode = NULL;
  int race_loop = 0;
  int lock_type = F_RDLCK;

  if (!*pfile) {
    DEBUG(0, ("startsmbfilepwent: No SMB password file set\n"));
    return (NULL);
  }

  switch(type) {
  case PWF_READ:
    open_mode = "rb";
    lock_type = F_RDLCK;
    break;
  case PWF_UPDATE:
    open_mode = "r+b";
    lock_type = F_WRLCK;
    break;
  case PWF_CREATE:
    /*
     * Ensure atomic file creation.
     */
    {
      int i, fd = -1;

      for(i = 0; i < 5; i++) {
        if((fd = sys_open(pfile, O_CREAT|O_TRUNC|O_EXCL|O_RDWR, 0600))!=-1)
          break;
        sys_usleep(200); /* Spin, spin... */
      }
      if(fd == -1) {
        DEBUG(0,("startsmbfilepwent_internal: too many race conditions creating file %s\n", pfile));
        return NULL;
      }
      close(fd);
      open_mode = "r+b";
      lock_type = F_WRLCK;
      break;
    }
  }
		       
  for(race_loop = 0; race_loop < 5; race_loop++) {
    DEBUG(10, ("startsmbfilepwent_internal: opening file %s\n", pfile));

    if((fp = sys_fopen(pfile, open_mode)) == NULL) {
      DEBUG(2, ("startsmbfilepwent_internal: unable to open file %s. Error was %s\n", pfile, strerror(errno) ));
      return NULL;
    }

    if (!pw_file_lock(fileno(fp), lock_type, 5, lock_depth)) {
      DEBUG(0, ("startsmbfilepwent_internal: unable to lock file %s. Error was %s\n", pfile, strerror(errno) ));
      fclose(fp);
      return NULL;
    }

    /*
     * Only check for replacement races on update or create.
     * For read we don't mind if the data is one record out of date.
     */

    if(type == PWF_READ) {
      break;
    } else {
      SMB_STRUCT_STAT sbuf1, sbuf2;

      /*
       * Avoid the potential race condition between the open and the lock
       * by doing a stat on the filename and an fstat on the fd. If the
       * two inodes differ then someone did a rename between the open and
       * the lock. Back off and try the open again. Only do this 5 times to
       * prevent infinate loops. JRA.
       */

      if (sys_stat(pfile,&sbuf1) != 0) {
        DEBUG(0, ("startsmbfilepwent_internal: unable to stat file %s. Error was %s\n", pfile, strerror(errno)));
        pw_file_unlock(fileno(fp), lock_depth);
        fclose(fp);
        return NULL;
      }

      if (sys_fstat(fileno(fp),&sbuf2) != 0) {
        DEBUG(0, ("startsmbfilepwent_internal: unable to fstat file %s. Error was %s\n", pfile, strerror(errno)));
        pw_file_unlock(fileno(fp), lock_depth);
        fclose(fp);
        return NULL;
      }

      if( sbuf1.st_ino == sbuf2.st_ino) {
        /* No race. */
        break;
      }

      /*
       * Race occurred - back off and try again...
       */

      pw_file_unlock(fileno(fp), lock_depth);
      fclose(fp);
    }
  }

  if(race_loop == 5) {
    DEBUG(0, ("startsmbfilepwent_internal: too many race conditions opening file %s\n", pfile));
    return NULL;
  }

  /* Set a buffer to do more efficient reads */
  setvbuf(fp, (char *)NULL, _IOFBF, 1024);

  /* Make sure it is only rw by the owner */
  if(fchmod(fileno(fp), S_IRUSR|S_IWUSR) == -1) {
    DEBUG(0, ("startsmbfilepwent_internal: failed to set 0600 permissions on password file %s. \
Error was %s\n.", pfile, strerror(errno) ));
    pw_file_unlock(fileno(fp), lock_depth);
    fclose(fp);
    return NULL;
  }

  /* We have a lock on the file. */
  return (void *)fp;
}

/***************************************************************
 End enumeration of the smbpasswd list.
****************************************************************/
static void endsmbfilepwent(void *vp, int *lock_depth)
{
  FILE *fp = (FILE *)vp;

  if (!fp)
	return;
  pw_file_unlock(fileno(fp), lock_depth);
  fclose(fp);
  DEBUG(7, ("endsmbfilepwent_internal: closed password file.\n"));
}

/*************************************************************************
 Routine to return the next entry in the smbpasswd list.
 *************************************************************************/

static struct smb_passwd *getsmbfilepwent(void *vp)
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
  size_t            linebuf_len;

  if(fp == NULL) {
    DEBUG(0,("getsmbfilepwent: Bad password file pointer.\n"));
    return NULL;
  }

  pdb_init_smb(&pw_buf);

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
    if ((linebuf_len = strlen(linebuf)) == 0)
		continue;

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
    DEBUG(100, ("getsmbfilepwent: got line |%s|\n", linebuf));
#endif
    if ((linebuf[0] == 0) && feof(fp)) {
      DEBUG(4, ("getsmbfilepwent: end of file reached\n"));
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
      DEBUG(6, ("getsmbfilepwent: skipping comment or blank line\n"));
      continue;
    }
    p = (unsigned char *) strchr(linebuf, ':');
    if (p == NULL) {
      DEBUG(0, ("getsmbfilepwent: malformed password entry (no :)\n"));
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

    if(*p == '-') {
      DEBUG(0, ("getsmbfilepwent: uids in the smbpasswd file must not be negative.\n"));
      continue;
    }

    if (!isdigit(*p)) {
      DEBUG(0, ("getsmbfilepwent: malformed password entry (uid not number)\n"));
      continue;
    }

    uidval = atoi((char *) p);

    while (*p && isdigit(*p))
      p++;

    if (*p != ':') {
      DEBUG(0, ("getsmbfilepwent: malformed password entry (no : after uid)\n"));
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
      DEBUG(10, ("getsmbfilepwent: entry invalidated for user %s\n", user_name));
      pw_buf.smb_nt_passwd = NULL;
      pw_buf.smb_passwd = NULL;
      pw_buf.acct_ctrl |= ACB_DISABLED;
      return &pw_buf;
    }

    if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
      DEBUG(0, ("getsmbfilepwent: malformed password entry (passwd too short)\n"));
      continue;
    }

    if (p[32] != ':') {
      DEBUG(0, ("getsmbfilepwent: malformed password entry (no terminating :)\n"));
      continue;
    }

    if (!strncasecmp((char *) p, "NO PASSWORD", 11)) {
      pw_buf.smb_passwd = NULL;
      pw_buf.acct_ctrl |= ACB_PWNOTREQ;
    } else {
      if (!pdb_gethexpwd((char *)p, smbpwd)) {
        DEBUG(0, ("getsmbfilepwent: Malformed Lanman password entry (non hex chars)\n"));
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
        if(pdb_gethexpwd((char *)p,smbntpwd))
          pw_buf.smb_nt_passwd = smbntpwd;
      }
      p += 33; /* Move to the first character of the line after
                  the NT password. */
    }

    DEBUG(5,("getsmbfilepwent: returning passwd entry for user %s, uid %ld\n",
	     user_name, uidval));

    if (*p == '[')
	{
      unsigned char *end_p = (unsigned char *)strchr((char *)p, ']');
      pw_buf.acct_ctrl = pdb_decode_acct_ctrl((char*)p);

      /* Must have some account type set. */
      if(pw_buf.acct_ctrl == 0)
        pw_buf.acct_ctrl = ACB_NORMAL;

      /* Now try and get the last change time. */
      if(end_p)
        p = end_p + 1;
      if(*p == ':') {
        p++;
        if(*p && (StrnCaseCmp((char *)p, "LCT-", 4)==0)) {
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
            pw_buf.pass_last_set_time = (time_t)strtol((char *)p, NULL, 16);
          }
        }
      }
    } else {
      /* 'Old' style file. Fake up based on user name. */
      /*
       * Currently trust accounts are kept in the same
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

  DEBUG(5,("getsmbfilepwent: end of file reached.\n"));
  return NULL;
}

/************************************************************************
 Create a new smbpasswd entry - malloced space returned.
*************************************************************************/

static char *format_new_smbpasswd_entry(struct smb_passwd *newpwd)
{
  int new_entry_length;
  char *new_entry;
  char *p;
  int i;

  new_entry_length = strlen(newpwd->smb_name) + 1 + 15 + 1 + 32 + 1 + 32 + 1 + NEW_PW_FORMAT_SPACE_PADDED_LEN + 1 + 13 + 2;

  if((new_entry = (char *)malloc( new_entry_length )) == NULL) {
    DEBUG(0, ("format_new_smbpasswd_entry: Malloc failed adding entry for user %s.\n", newpwd->smb_name ));
    return NULL;
  }

  slprintf(new_entry, new_entry_length - 1, "%s:%u:", newpwd->smb_name, (unsigned)newpwd->smb_userid);
  p = &new_entry[strlen(new_entry)];

  if(newpwd->smb_passwd != NULL) {
    for( i = 0; i < 16; i++) {
      slprintf((char *)&p[i*2], new_entry_length - (p - new_entry) - 1, "%02X", newpwd->smb_passwd[i]);
    }
  } else {
    i=0;
    if(newpwd->acct_ctrl & ACB_PWNOTREQ)
      safe_strcpy((char *)p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", new_entry_length - 1 - (p - new_entry));
    else
      safe_strcpy((char *)p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", new_entry_length - 1 - (p - new_entry));
  }
  
  p += 32;

  *p++ = ':';

  if(newpwd->smb_nt_passwd != NULL) {
    for( i = 0; i < 16; i++) {
      slprintf((char *)&p[i*2], new_entry_length - 1 - (p - new_entry), "%02X", newpwd->smb_nt_passwd[i]);
    }
  } else {
    if(newpwd->acct_ctrl & ACB_PWNOTREQ)
      safe_strcpy((char *)p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", new_entry_length - 1 - (p - new_entry));
    else
      safe_strcpy((char *)p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", new_entry_length - 1 - (p - new_entry));
  }

  p += 32;

  *p++ = ':';

  /* Add the account encoding and the last change time. */
  slprintf((char *)p, new_entry_length - 1 - (p - new_entry),  "%s:LCT-%08X:\n",
           pdb_encode_acct_ctrl(newpwd->acct_ctrl, NEW_PW_FORMAT_SPACE_PADDED_LEN),
           (uint32)newpwd->pass_last_set_time);

  return new_entry;
}

/************************************************************************
 Routine to add an entry to the smbpasswd file.
*************************************************************************/

static BOOL add_smbfilepwd_entry(struct smb_passwd *newpwd)
{
  char *pfile = lp_smb_passwd_file();
  struct smb_passwd *pwd = NULL;
  FILE *fp = NULL;
  int wr_len;
  int fd;
  size_t new_entry_length;
  char *new_entry;
  SMB_OFF_T offpos;

  /* Open the smbpassword file - for update. */
  fp = startsmbfilepwent(pfile, PWF_UPDATE, &pw_file_lock_depth);

  if (fp == NULL && errno == ENOENT) {
	/* Try again - create. */
	fp = startsmbfilepwent(pfile, PWF_CREATE, &pw_file_lock_depth);
  }

  if (fp == NULL) {
    DEBUG(0, ("add_smbfilepwd_entry: unable to open file.\n"));
    return False;
  }

  /*
   * Scan the file, a line at a time and check if the name matches.
   */

  while ((pwd = getsmbfilepwent(fp)) != NULL) 
  {
    if (strequal(newpwd->smb_name, pwd->smb_name)) 
    {
      	DEBUG(0, ("add_smbfilepwd_entry: entry with name %s already exists\n", pwd->smb_name));
      	endsmbfilepwent(fp, &pw_file_lock_depth);
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

  if((offpos = sys_lseek(fd, 0, SEEK_END)) == -1) 
  {
    	DEBUG(0, ("add_smbfilepwd_entry(sys_lseek): Failed to add entry for user %s to file %s. \
Error was %s\n", newpwd->smb_name, pfile, strerror(errno)));
    	endsmbfilepwent(fp, &pw_file_lock_depth);
    	return False;
  }

  if((new_entry = format_new_smbpasswd_entry(newpwd)) == NULL) 
  {
    	DEBUG(0, ("add_smbfilepwd_entry(malloc): Failed to add entry for user %s to file %s. \
Error was %s\n", newpwd->smb_name, pfile, strerror(errno)));
	endsmbfilepwent(fp, &pw_file_lock_depth);
    	return False;
  }

  new_entry_length = strlen(new_entry);

#ifdef DEBUG_PASSWORD
  DEBUG(100, ("add_smbfilepwd_entry(%d): new_entry_len %d made line |%s|", 
		             fd, new_entry_length, new_entry));
#endif

  if ((wr_len = write(fd, new_entry, new_entry_length)) != new_entry_length) 
  {
  	DEBUG(0, ("add_smbfilepwd_entry(write): %d Failed to add entry for user %s to file %s. \
Error was %s\n", wr_len, newpwd->smb_name, pfile, strerror(errno)));

    	/* Remove the entry we just wrote. */
    	if(sys_ftruncate(fd, offpos) == -1) 
	{
      		DEBUG(0, ("add_smbfilepwd_entry: ERROR failed to ftruncate file %s. \
Error was %s. Password file may be corrupt ! Please examine by hand !\n", 
		newpwd->smb_name, strerror(errno)));
    	}

	endsmbfilepwent(fp, &pw_file_lock_depth);
	free(new_entry);
	return False;
  }

  free(new_entry);
  endsmbfilepwent(fp, &pw_file_lock_depth);
  return True;
}

/************************************************************************
 Routine to search the smbpasswd file for an entry matching the username.
 and then modify its password entry. We can't use the startsmbpwent()/
 getsmbpwent()/endsmbpwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out password or NO PASS
************************************************************************/

static BOOL mod_smbfilepwd_entry(struct smb_passwd* pwd, BOOL override)
{
  /* Static buffers we will return. */
  static pstring  user_name;

  char            linebuf[256];
  char            readbuf[1024];
  unsigned char   c;
  fstring         ascii_p16;
  fstring         encode_bits;
  unsigned char  *p = NULL;
  size_t            linebuf_len = 0;
  FILE           *fp;
  int             lockfd;
  char           *pfile = lp_smb_passwd_file();
  BOOL found_entry = False;
  BOOL got_pass_last_set_time = False;

  SMB_OFF_T pwd_seekpos = 0;

  int i;
  int wr_len;
  int fd;

  if (!*pfile) {
    DEBUG(0, ("No SMB password file set\n"));
    return False;
  }
  DEBUG(10, ("mod_smbfilepwd_entry: opening file %s\n", pfile));

  fp = sys_fopen(pfile, "r+");

  if (fp == NULL) {
    DEBUG(0, ("mod_smbfilepwd_entry: unable to open file %s\n", pfile));
    return False;
  }
  /* Set a buffer to do more efficient reads */
  setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));

  lockfd = fileno(fp);

  if (!pw_file_lock(lockfd, F_WRLCK, 5, &pw_file_lock_depth)) {
    DEBUG(0, ("mod_smbfilepwd_entry: unable to lock file %s\n", pfile));
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
    pwd_seekpos = sys_ftell(fp);

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
    DEBUG(100, ("mod_smbfilepwd_entry: got line |%s|\n", linebuf));
#endif

    if ((linebuf[0] == 0) && feof(fp)) {
      DEBUG(4, ("mod_smbfilepwd_entry: end of file reached\n"));
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
     * username:uid:[32hex bytes]:[32hex bytes]:[attributes]:LCT-XXXXXXXX:...ignored.
     *
     * if Windows NT compatible passwords are also present.
     */

    if (linebuf[0] == '#' || linebuf[0] == '\0') {
      DEBUG(6, ("mod_smbfilepwd_entry: skipping comment or blank line\n"));
      continue;
    }

    p = (unsigned char *) strchr(linebuf, ':');

    if (p == NULL) {
      DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (no :)\n"));
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

  if (!found_entry) {
    pw_file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  DEBUG(6, ("mod_smbfilepwd_entry: entry exists\n"));

  /* User name matches - get uid and password */
  p++;		/* Go past ':' */

  if (!isdigit(*p)) {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (uid not number)\n"));
    pw_file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  while (*p && isdigit(*p))
    p++;
  if (*p != ':') {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (no : after uid)\n"));
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

  if (!override && (*p == '*' || *p == 'X')) {
    /* Password deliberately invalid - end here. */
    DEBUG(10, ("mod_smbfilepwd_entry: entry invalidated for user %s\n", user_name));
    pw_file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (passwd too short)\n"));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return (False);
  }

  if (p[32] != ':') {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (no terminating :)\n"));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (!override && (*p == '*' || *p == 'X')) {
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  /* Now check if the NT compatible password is
     available. */
  p += 33; /* Move to the first character of the line after
              the lanman password. */
  if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (passwd too short)\n"));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return (False);
  }

  if (p[32] != ':') {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (no terminating :)\n"));
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

  /*
   * If both NT and lanman passwords are provided - reset password
   * not required flag.
   */

  if(pwd->smb_passwd != NULL || pwd->smb_nt_passwd != NULL) {
    /* Reqiure password in the future (should ACB_DISABLED also be reset?) */
    pwd->acct_ctrl &= ~(ACB_PWNOTREQ);
  }

  if (*p == '[') {

    i = 0;
    encode_bits[i++] = *p++;
    while((linebuf_len > PTR_DIFF(p, linebuf)) && (*p != ']'))
      encode_bits[i++] = *p++;

    encode_bits[i++] = ']';
    encode_bits[i++] = '\0';

    if(i == NEW_PW_FORMAT_SPACE_PADDED_LEN) {
      /*
       * We are using a new format, space padded
       * acct ctrl field. Encode the given acct ctrl
       * bits into it.
       */
      fstrcpy(encode_bits, pdb_encode_acct_ctrl(pwd->acct_ctrl, NEW_PW_FORMAT_SPACE_PADDED_LEN));
    } else {
      /*
       * If using the old format and the ACB_DISABLED or
       * ACB_PWNOTREQ are set then set the lanman and NT passwords to NULL
       * here as we have no space to encode the change.
       */
      if(pwd->acct_ctrl & (ACB_DISABLED|ACB_PWNOTREQ)) {
        pwd->smb_passwd = NULL;
        pwd->smb_nt_passwd = NULL;
      }
    }

    /* Go past the ']' */
    if(linebuf_len > PTR_DIFF(p, linebuf))
      p++;

    if((linebuf_len > PTR_DIFF(p, linebuf)) && (*p == ':')) {
      p++;

      /* We should be pointing at the LCT entry. */
      if((linebuf_len > (PTR_DIFF(p, linebuf) + 13)) && (StrnCaseCmp((char *)p, "LCT-", 4) == 0)) {

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
          got_pass_last_set_time = True;
        } /* i == 8 */
      } /* *p && StrnCaseCmp() */
    } /* p == ':' */
  } /* p == '[' */

  /* Entry is correctly formed. */

  /* Create the 32 byte representation of the new p16 */
  if(pwd->smb_passwd != NULL) {
    for (i = 0; i < 16; i++) {
      slprintf(&ascii_p16[i*2], sizeof(fstring) - 1, "%02X", (uchar) pwd->smb_passwd[i]);
    }
  } else {
    if(pwd->acct_ctrl & ACB_PWNOTREQ)
      fstrcpy(ascii_p16, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX");
    else
      fstrcpy(ascii_p16, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  }

  /* Add on the NT md4 hash */
  ascii_p16[32] = ':';
  wr_len = 66;
  if (pwd->smb_nt_passwd != NULL) {
    for (i = 0; i < 16; i++) {
      slprintf(&ascii_p16[(i*2)+33], sizeof(fstring) - 1, "%02X", (uchar) pwd->smb_nt_passwd[i]);
    }
  } else {
    if(pwd->acct_ctrl & ACB_PWNOTREQ)
      fstrcpy(&ascii_p16[33], "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX");
    else
      fstrcpy(&ascii_p16[33], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  }
  ascii_p16[65] = ':';
  ascii_p16[66] = '\0'; /* null-terminate the string so that strlen works */

  /* Add on the account info bits and the time of last
     password change. */

  pwd->pass_last_set_time = time(NULL);

  if(got_pass_last_set_time) {
    slprintf(&ascii_p16[strlen(ascii_p16)], 
	     sizeof(ascii_p16)-(strlen(ascii_p16)+1),
	     "%s:LCT-%08X:", 
                     encode_bits, (uint32)pwd->pass_last_set_time );
    wr_len = strlen(ascii_p16);
  }

#ifdef DEBUG_PASSWORD
  DEBUG(100,("mod_smbfilepwd_entry: "));
  dump_data(100, ascii_p16, wr_len);
#endif

  if(wr_len > sizeof(linebuf)) {
    DEBUG(0, ("mod_smbfilepwd_entry: line to write (%d) is too long.\n", wr_len+1));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return (False);
  }

  /*
   * Do an atomic write into the file at the position defined by
   * seekpos.
   */

  /* The mod user write needs to be atomic - so get the fd from 
     the fp and do a raw write() call.
   */

  fd = fileno(fp);

  if (sys_lseek(fd, pwd_seekpos - 1, SEEK_SET) != pwd_seekpos - 1) {
    DEBUG(0, ("mod_smbfilepwd_entry: seek fail on file %s.\n", pfile));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  /* Sanity check - ensure the areas we are writing are framed by ':' */
  if (read(fd, linebuf, wr_len+1) != wr_len+1) {
    DEBUG(0, ("mod_smbfilepwd_entry: read fail on file %s.\n", pfile));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if ((linebuf[0] != ':') || (linebuf[wr_len] != ':'))	{
    DEBUG(0, ("mod_smbfilepwd_entry: check on passwd file %s failed.\n", pfile));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }
 
  if (sys_lseek(fd, pwd_seekpos, SEEK_SET) != pwd_seekpos) {
    DEBUG(0, ("mod_smbfilepwd_entry: seek fail on file %s.\n", pfile));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (write(fd, ascii_p16, wr_len) != wr_len) {
    DEBUG(0, ("mod_smbfilepwd_entry: write failed in passwd file %s\n", pfile));
    pw_file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  pw_file_unlock(lockfd,&pw_file_lock_depth);
  fclose(fp);
  return True;
}

/************************************************************************
 Routine to delete an entry in the smbpasswd file by name.
*************************************************************************/

static BOOL del_smbfilepwd_entry(const char *name)
{
  char *pfile = lp_smb_passwd_file();
  pstring pfile2;
  struct smb_passwd *pwd = NULL;
  FILE *fp = NULL;
  FILE *fp_write = NULL;
  int pfile2_lockdepth = 0;

  slprintf(pfile2, sizeof(pfile2)-1, "%s.%u", pfile, (unsigned)sys_getpid() );

  /*
   * Open the smbpassword file - for update. It needs to be update
   * as we need any other processes to wait until we have replaced
   * it.
   */

  if((fp = startsmbfilepwent(pfile, PWF_UPDATE, &pw_file_lock_depth)) == NULL) {
    DEBUG(0, ("del_smbfilepwd_entry: unable to open file %s.\n", pfile));
    return False;
  }

  /*
   * Create the replacement password file.
   */
  if((fp_write = startsmbfilepwent(pfile2, PWF_CREATE, &pfile2_lockdepth)) == NULL) {
    DEBUG(0, ("del_smbfilepwd_entry: unable to open file %s.\n", pfile));
    endsmbfilepwent(fp, &pw_file_lock_depth);
    return False;
  }

  /*
   * Scan the file, a line at a time and check if the name matches.
   */

  while ((pwd = getsmbfilepwent(fp)) != NULL) {
    char *new_entry;
    size_t new_entry_length;

    if (strequal(name, pwd->smb_name)) {
      DEBUG(10, ("del_smbfilepwd_entry: found entry with name %s - deleting it.\n", name));
      continue;
    }

    /*
     * We need to copy the entry out into the second file.
     */

    if((new_entry = format_new_smbpasswd_entry(pwd)) == NULL) 
    {
    	DEBUG(0, ("del_smbfilepwd_entry(malloc): Failed to copy entry for user %s to file %s. \
Error was %s\n", pwd->smb_name, pfile2, strerror(errno)));
	unlink(pfile2);
	endsmbfilepwent(fp, &pw_file_lock_depth);
	endsmbfilepwent(fp_write, &pfile2_lockdepth);
	return False;
    }

    new_entry_length = strlen(new_entry);

    if(fwrite(new_entry, 1, new_entry_length, fp_write) != new_entry_length) 
    {
    	DEBUG(0, ("del_smbfilepwd_entry(write): Failed to copy entry for user %s to file %s. \
Error was %s\n", pwd->smb_name, pfile2, strerror(errno)));
      	unlink(pfile2);
	endsmbfilepwent(fp, &pw_file_lock_depth);
	endsmbfilepwent(fp_write, &pfile2_lockdepth);
	free(new_entry);
	return False;
    }

    free(new_entry);
  }

  /*
   * Ensure pfile2 is flushed before rename.
   */

  if(fflush(fp_write) != 0) 
  {
  	DEBUG(0, ("del_smbfilepwd_entry: Failed to flush file %s. Error was %s\n", pfile2, strerror(errno)));
	endsmbfilepwent(fp, &pw_file_lock_depth);
	endsmbfilepwent(fp_write,&pfile2_lockdepth);
	return False;
  }

  /*
   * Do an atomic rename - then release the locks.
   */

  if(rename(pfile2,pfile) != 0) {
    unlink(pfile2);
  }
  
  endsmbfilepwent(fp, &pw_file_lock_depth);
  endsmbfilepwent(fp_write,&pfile2_lockdepth);
  return True;
}

/*********************************************************************
 Create a smb_passwd struct from a SAM_ACCOUNT.
 We will not allocate any new memory.  The smb_passwd struct
 should only stay around as long as the SAM_ACCOUNT does.
 ********************************************************************/
static BOOL build_smb_pass (struct smb_passwd *smb_pw, SAM_ACCOUNT *sampass)
{
	if (sampass == NULL) 
		return False;

	ZERO_STRUCTP(smb_pw);

	smb_pw->smb_userid=pdb_get_uid(sampass);
	smb_pw->smb_name=pdb_get_username(sampass);

	smb_pw->smb_passwd=pdb_get_lanman_passwd(sampass);
	smb_pw->smb_nt_passwd=pdb_get_nt_passwd(sampass);

	smb_pw->acct_ctrl=pdb_get_acct_ctrl(sampass);
	smb_pw->pass_last_set_time=pdb_get_pass_last_set_time(sampass);

	return True;
}	

/*********************************************************************
 Create a SAM_ACCOUNT from a smb_passwd struct
 ********************************************************************/
static BOOL build_sam_account(SAM_ACCOUNT *sam_pass, struct smb_passwd *pw_buf)
{
	struct passwd *pwfile;
	
	if (sam_pass==NULL) {
		DEBUG(5,("build_sam_account: SAM_ACCOUNT is NULL\n"));
		return False;
	}
		
	/* Verify in system password file...
	   FIXME!!!  This is where we should look up an internal
	   mapping of allocated uid for machine accounts as well 
	   --jerry */ 
	pwfile = sys_getpwnam(pw_buf->smb_name);
	if (pwfile == NULL) {
		DEBUG(0,("build_sam_account: smbpasswd database is corrupt!  username %s not in unix passwd database!\n", pw_buf->smb_name));
		return False;
	}

	/* FIXME!!  This doesn't belong here.  Should be set in net_sam_logon() 
	   --jerry */
	pstrcpy(samlogon_user, pw_buf->smb_name);
	
	pdb_set_uid (sam_pass, pwfile->pw_uid);
	pdb_set_gid (sam_pass, pwfile->pw_gid);
	pdb_set_fullname(sam_pass, pwfile->pw_gecos);		
	
	pdb_set_user_rid(sam_pass, pdb_uid_to_user_rid (pwfile->pw_uid));

	/* should check the group mapping here instead of static mappig. JFM */
	pdb_set_group_rid(sam_pass, pdb_gid_to_group_rid(pwfile->pw_gid)); 
	
	pdb_set_username (sam_pass, pw_buf->smb_name);
	if (!pdb_set_nt_passwd (sam_pass, pw_buf->smb_nt_passwd)) {
		if (pw_buf->smb_nt_passwd)
			return False;
	}
	if (!pdb_set_lanman_passwd (sam_pass, pw_buf->smb_passwd)) {
		if (pw_buf->smb_passwd)
			return False;
	}
	pdb_set_acct_ctrl (sam_pass, pw_buf->acct_ctrl);
	pdb_set_pass_last_set_time (sam_pass, pw_buf->pass_last_set_time);
	pdb_set_pass_can_change_time (sam_pass, pw_buf->pass_last_set_time);
	pdb_set_domain (sam_pass, lp_workgroup());
	
	pdb_set_dir_drive     (sam_pass, lp_logon_drive(), False);

	/* FIXME!!  What should this be set to?  New smb.conf parameter maybe?
	   max password age?   For now, we'll use the current time + 21 days. 
	   --jerry */
	pdb_set_pass_must_change_time (sam_pass, time(NULL)+1814400);

	/* check if this is a user account or a machine account */
	if (samlogon_user[strlen(samlogon_user)-1] != '$')
	{
		pstring 	str;
		gid_t 		gid = getegid();
		
	        sam_logon_in_ssb = True;

	        pstrcpy(str, lp_logon_script());
       		standard_sub_advanced(-1, pw_buf->smb_name, "", gid, str,sizeof(str));
		pdb_set_logon_script(sam_pass, str, False);

	        pstrcpy(str, lp_logon_path());
       		standard_sub_advanced(-1, pw_buf->smb_name, "", gid, str,sizeof(str));
		pdb_set_profile_path(sam_pass, str, False);

	        pstrcpy(str, lp_logon_home());
        	standard_sub_advanced(-1, pw_buf->smb_name, "", gid, str,sizeof(str));
		pdb_set_homedir(sam_pass, str, False);
 		
		sam_logon_in_ssb = False;
	} else {
		/* lkclXXXX this is OBSERVED behaviour by NT PDCs, enforced here. */
		pdb_set_group_rid (sam_pass, DOMAIN_GROUP_RID_USERS); 
	}
	
	return True;
}
/*****************************************************************
 Functions to be implemented by the new passdb API 
 ****************************************************************/
BOOL pdb_setsampwent (BOOL update)
{
	global_vp = startsmbfilepwent(lp_smb_passwd_file(), 
	                        update ? PWF_UPDATE : PWF_READ, 
			        &pw_file_lock_depth);
				   
	/* did we fail?  Should we try to create it? */
	if (!global_vp && update && errno == ENOENT) 
	{
		FILE *fp;
		/* slprintf(msg_str,msg_str_len-1,
			"smbpasswd file did not exist - attempting to create it.\n"); */
		DEBUG(0,("smbpasswd file did not exist - attempting to create it.\n"));
		fp = sys_fopen(lp_smb_passwd_file(), "w");
		if (fp) 
		{
			fprintf(fp, "# Samba SMB password file\n");
			fclose(fp);
		}
		
		global_vp = startsmbfilepwent(lp_smb_passwd_file(), 
		                        update ? PWF_UPDATE : PWF_READ, 
			                &pw_file_lock_depth);
	}
	
	return (global_vp != NULL);		   
}

void pdb_endsampwent (void)
{
	endsmbfilepwent(global_vp, &pw_file_lock_depth);
}
 
/*****************************************************************
 ****************************************************************/
BOOL pdb_getsampwent(SAM_ACCOUNT *user)
{
	struct smb_passwd *pw_buf=NULL;
	BOOL done = False;
	DEBUG(5,("pdb_getsampwent\n"));

	if (user==NULL) {
		DEBUG(5,("pdb_getsampwent: user is NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_getsampwent\n");
#endif
		return False;
	}

	while (!done)
	{
		/* do we have an entry? */
		pw_buf = getsmbfilepwent(global_vp);
		if (pw_buf == NULL) 
			return False;

		/* build the SAM_ACCOUNT entry from the smb_passwd struct. 
		   We loop in case the user in the pdb does not exist in 
		   the local system password file */
		if (build_sam_account(user, pw_buf))
			done = True;
	}

	DEBUG(5,("pdb_getsampwent:done\n"));

	/* success */
	return True;
}


/****************************************************************
 Search smbpasswd file by iterating over the entries.  Do not
 call getpwnam() for unix account information until we have found
 the correct entry
 ***************************************************************/
BOOL pdb_getsampwnam(SAM_ACCOUNT *sam_acct, const char *username)
{
	struct smb_passwd *smb_pw;
	void *fp = NULL;
	char *domain = NULL;
	char *user = NULL;
	fstring name;

	DEBUG(10, ("pdb_getsampwnam: search by name: %s\n", username));

	
	/* break the username from the domain if we have 
	   been given a string in the form 'DOMAIN\user' */
	fstrcpy (name, username);
	if ((user=strchr(name, '\\')) != NULL) {
		domain = name;
		*user = '\0';
		user++;
	}
	
	/* if a domain was specified and it wasn't ours
	   then there is no chance of matching */
	if ( domain && !StrCaseCmp(domain, lp_workgroup()) )
		return False;

	/* startsmbfilepwent() is used here as we don't want to lookup
	   the UNIX account in the local system password file until
	   we have a match.  */
	fp = startsmbfilepwent(lp_smb_passwd_file(), PWF_READ, &pw_file_lock_depth);

	if (fp == NULL) {
		DEBUG(0, ("unable to open passdb database.\n"));
		return False;
	}

	/* if we have a domain name, then we should map it to a UNIX 
	   username first */
	if ( domain )
		map_username(user);

	while ( ((smb_pw=getsmbfilepwent(fp)) != NULL)&& (!strequal(smb_pw->smb_name, username)) )
		/* do nothing....another loop */ ;
	
	endsmbfilepwent(fp, &pw_file_lock_depth);


	/* did we locate the username in smbpasswd  */
	if (smb_pw == NULL)
		return False;
	
	DEBUG(10, ("pdb_getsampwnam: found by name: %s\n", smb_pw->smb_name));

	if (!sam_acct) {
		DEBUG(10,("pdb_getsampwnam:SAM_ACCOUNT is NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_getsampwnam\n");
#endif
		return False;
	}
		
	/* now build the SAM_ACCOUNT */
	if (!build_sam_account(sam_acct, smb_pw))
		return False;

	/* success */
	return True;
}


BOOL pdb_getsampwrid(SAM_ACCOUNT *sam_acct,uint32 rid)
{
	struct smb_passwd *smb_pw;
	void *fp = NULL;

	DEBUG(10, ("pdb_getsampwrid: search by rid: %d\n", rid));

	/* Open the sam password file - not for update. */
	fp = startsmbfilepwent(lp_smb_passwd_file(), PWF_READ, &pw_file_lock_depth);

	if (fp == NULL) {
		DEBUG(0, ("unable to open passdb database.\n"));
		return False;
	}

	while ( ((smb_pw=getsmbfilepwent(fp)) != NULL) && (pdb_uid_to_user_rid(smb_pw->smb_userid) != rid) )
      		/* do nothing */ ;

	endsmbfilepwent(fp, &pw_file_lock_depth);


	/* did we locate the username in smbpasswd  */
	if (smb_pw == NULL)
		return False;
	
	DEBUG(10, ("pdb_getsampwrid: found by name: %s\n", smb_pw->smb_name));
		
	if (!sam_acct) {
		DEBUG(10,("pdb_getsampwrid:SAM_ACCOUNT is NULL\n"));
#if 0
		smb_panic("NULL pointer passed to pdb_getsampwrid\n");
#endif
		return False;
	}

	/* now build the SAM_ACCOUNT */
	if (!build_sam_account (sam_acct, smb_pw))
		return False;

	/* success */
	return True;
}

BOOL pdb_add_sam_account(SAM_ACCOUNT *sampass)
{
	struct smb_passwd smb_pw;
	
	/* convert the SAM_ACCOUNT */
	build_smb_pass(&smb_pw, sampass);
	
	/* add the entry */
	if(!add_smbfilepwd_entry(&smb_pw))
		return False;
	
	return True;
}

BOOL pdb_update_sam_account(SAM_ACCOUNT *sampass, BOOL override)
{
	struct smb_passwd smb_pw;
	
	/* convert the SAM_ACCOUNT */
	build_smb_pass(&smb_pw, sampass);
	
	/* update the entry */
	if(!mod_smbfilepwd_entry(&smb_pw, override))
		return False;
		
	return True;
}

BOOL pdb_delete_sam_account (const char* username)
{
	return del_smbfilepwd_entry(username);
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void smbpass_dummy_function(void) { } /* stop some compilers complaining */
#endif /* WTH_SMBPASSWD_SAM*/
