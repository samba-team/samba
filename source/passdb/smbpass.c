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

#ifdef USE_SMBPASS_DB

static int pw_file_lock_depth = 0;
extern int DEBUGLEVEL;

static char s_readbuf[1024];

/***************************************************************
 Start to enumerate the smbpasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startsmbfilepwent(BOOL update)
{
	return startfileent(lp_smb_passwd_file(), s_readbuf, sizeof(s_readbuf),
	                      &pw_file_lock_depth, update);
}

/***************************************************************
 End enumeration of the smbpasswd list.
****************************************************************/

static void endsmbfilepwent(void *vp)
{
	endfileent(vp, &pw_file_lock_depth);
}

/*************************************************************************
 Return the current position in the smbpasswd list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/

static SMB_BIG_UINT getsmbfilepwpos(void *vp)
{
	return getfilepwpos(vp);
}

/*************************************************************************
 Set the current position in the smbpasswd list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/

static BOOL setsmbfilepwpos(void *vp, SMB_BIG_UINT tok)
{
	return setfilepwpos(vp, tok);
}

/*************************************************************************
 Routine to return the next entry in the smbpasswd list.

 this function is non-static as it is called (exclusively and only)
 from getsamfile21pwent().
 *************************************************************************/
struct smb_passwd *getsmbfilepwent(void *vp)
{
	/* Static buffers we will return. */
	static struct smb_passwd pw_buf;
	static pstring  unix_name;
	static unsigned char smbpwd[16];
	static unsigned char smbntpwd[16];
	char            linebuf[256];
	char  *p;
	int            uidval;
	size_t            linebuf_len;

	if (vp == NULL)
	{
		DEBUG(0,("getsmbfilepwent: Bad password file pointer.\n"));
		return NULL;
	}

	pwdb_init_smb(&pw_buf);

	pw_buf.acct_ctrl = ACB_NORMAL;  

	/*
	 * Scan the file, a line at a time.
	 */
	while ((linebuf_len = getfileline(vp, linebuf, sizeof(linebuf))) > 0)
	{
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

		/*
		 * As 256 is shorter than a pstring we don't need to check
		 * length here - if this ever changes....
		 */
		p = strncpyn(unix_name, linebuf, sizeof(unix_name), ':');

		if (p == NULL)
		{
			DEBUG(0,("getsmbfilepwent: no ':' separator found\n"));
			continue;
		}

		/* Go past ':' */
		p++;

		/* Get smb uid. */

		p = Atoic( p, &uidval, ":");

		pw_buf.unix_name = unix_name;
		pw_buf.unix_uid = uidval;

		/*
		 * Now get the password value - this should be 32 hex digits
		 * which are the ascii representations of a 16 byte string.
		 * Get two at a time and put them into the password.
		 */

		/* Skip the ':' */
		p++;

		if (linebuf_len < (PTR_DIFF(p, linebuf) + 33))
		{
			DEBUG(0, ("getsmbfilepwent: malformed password entry (passwd too short)\n"));
			continue;
		}

		if (p[32] != ':')
		{
			DEBUG(0, ("getsmbfilepwent: malformed password entry (no terminating :)\n"));
			continue;
		}

		if (!strncasecmp( p, "NO PASSWORD", 11))
		{
			pw_buf.smb_passwd = NULL;
			pw_buf.acct_ctrl |= ACB_PWNOTREQ;
		}
		else
		{
			if (!pwdb_gethexpwd(p, (char *)smbpwd, NULL))
			{
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

		/* Move to the first character of the line after the lanman password. */
		p += 33;
		if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':'))
		{
			if (*p != '*' && *p != 'X')
			{
				if(pwdb_gethexpwd(p,(char *)smbntpwd, NULL))
				{
					pw_buf.smb_nt_passwd = smbntpwd;
				}
			}
			/* Move to the first character of the line after the NT password. */
			p += 33;
		}

		DEBUG(5,("getsmbfilepwent: returning passwd entry for unix user %s, unix uid %d\n",
		          unix_name, uidval));

		if (*p == '[')
		{
			pw_buf.acct_ctrl = pwdb_decode_acct_ctrl((char*)p);

			/* Must have some account type set. */
			if (pw_buf.acct_ctrl == 0)
			{
				pw_buf.acct_ctrl = ACB_NORMAL;
			}

			/* Now try and get the last change time. */
                        while (*p != ']' && *p != ':') 
                        {
                                p++;
                        }
			if (*p == ']')
			{
				p++;
			}
			if (*p == ':')
			{
				p++;
				pw_buf.pass_last_set_time = pwdb_get_last_set_time(p);
			}
		}
		else
		{
			/* 'Old' style file. Fake up based on user name. */
			/*
			 * Currently trust accounts are kept in the same
			 * password file as 'normal accounts'. If this changes
			 * we will have to fix this code. JRA.
			 */
			if (pw_buf.unix_name[strlen(pw_buf.unix_name) - 1] == '$')	
			{
				pw_buf.acct_ctrl &= ~ACB_NORMAL;
				pw_buf.acct_ctrl |= ACB_WSTRUST;
			}
		}

		if (*p == '*' || *p == 'X')
		{
			/* Password deliberately invalid - end here. */
			DEBUG(10, ("getsmbfilepwent: entry invalidated for unix user %s\n", unix_name));
			pw_buf.smb_nt_passwd = NULL;
			pw_buf.smb_passwd = NULL;
			pw_buf.acct_ctrl |= ACB_DISABLED;
		}

		DEBUG(6,("unixuser:%s uid:%d acb:%x\n",
		          pw_buf.unix_name, pw_buf.unix_uid, pw_buf.acct_ctrl));

		return &pw_buf;
	}

	DEBUG(5,("getsmbfilepwent: end of file reached.\n"));
	return NULL;
}

/************************************************************************
 Create a new smbpasswd entry - malloced space returned.
*************************************************************************/

char *format_new_smbpasswd_entry(struct smb_passwd *newpwd)
{
  int new_entry_length;
  char *new_entry;
  char *p;
  int i;

  new_entry_length = strlen(newpwd->unix_name) + 1 + 15 + 1 + 32 + 1 + 32 + 1 + NEW_PW_FORMAT_SPACE_PADDED_LEN + 1 + 13 + 2;

  if((new_entry = (char *)malloc( new_entry_length )) == NULL) {
    DEBUG(0, ("format_new_smbpasswd_entry: Malloc failed adding entry for user %s.\n", newpwd->unix_name ));
    return NULL;
  }

  slprintf(new_entry, new_entry_length - 1, "%s:%u:", newpwd->unix_name, (unsigned)newpwd->unix_uid);
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
           pwdb_encode_acct_ctrl(newpwd->acct_ctrl, NEW_PW_FORMAT_SPACE_PADDED_LEN),
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
  fp = startsmbfilepwent(True);

  if (fp == NULL) {
    DEBUG(0, ("add_smbfilepwd_entry: unable to open file.\n"));
    return False;
  }

  /*
   * Scan the file, a line at a time and check if the name matches.
   */

  while ((pwd = getsmbfilepwent(fp)) != NULL) {
    if (strequal(newpwd->unix_name, pwd->unix_name)) {
      DEBUG(0, ("add_smbfilepwd_entry: entry with name %s already exists\n", pwd->unix_name));
      endsmbfilepwent(fp);
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

  if((offpos = sys_lseek(fd, 0, SEEK_END)) == -1) {
    DEBUG(0, ("add_smbfilepwd_entry(sys_lseek): Failed to add entry for user %s to file %s. \
Error was %s\n", newpwd->unix_name, pfile, strerror(errno)));
    endsmbfilepwent(fp);
    return False;
  }

  if((new_entry = format_new_smbpasswd_entry(newpwd)) == NULL) {
    DEBUG(0, ("add_smbfilepwd_entry(malloc): Failed to add entry for user %s to file %s. \
Error was %s\n", newpwd->unix_name, pfile, strerror(errno)));
    endsmbfilepwent(fp);
    return False;
  }

  new_entry_length = strlen(new_entry);

#ifdef DEBUG_PASSWORD
  DEBUG(100, ("add_smbfilepwd_entry(%d): new_entry_len %d made line |%s|",
                             fd, new_entry_length, new_entry));
#endif

  if ((wr_len = write(fd, new_entry, new_entry_length)) != new_entry_length) {
    DEBUG(0, ("add_smbfilepwd_entry(write): %d Failed to add entry for user %s to file %s. \
Error was %s\n", wr_len, newpwd->unix_name, pfile, strerror(errno)));

    /* Remove the entry we just wrote. */
    if(sys_ftruncate(fd, offpos) == -1) {
      DEBUG(0, ("add_smbfilepwd_entry: ERROR failed to ftruncate file %s. \
Error was %s. Password file may be corrupt ! Please examine by hand !\n",
             newpwd->unix_name, strerror(errno)));
    }

    endsmbfilepwent(fp);
    free(new_entry);
    return False;
  }

  free(new_entry);
  endsmbfilepwent(fp);
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
  static pstring  unix_name;

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

#ifdef DEBUG_PASSWORD
	DEBUG(100,("mod_smbfilepwd_entry: password entries\n"));
	if (pwd->smb_passwd != NULL)
	{
		dump_data(100, pwd->smb_passwd, 16);
	}
	if (pwd->smb_nt_passwd != NULL)
	{
		dump_data(100, pwd->smb_nt_passwd, 16);
	}
#endif
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

  if (!file_lock(lockfd, F_WRLCK, 5, &pw_file_lock_depth)) {
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
      file_unlock(lockfd, &pw_file_lock_depth);
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
    strncpy(unix_name, linebuf, PTR_DIFF(p, linebuf));
    unix_name[PTR_DIFF(p, linebuf)] = '\0';
    if (strequal(unix_name, pwd->unix_name)) {
      found_entry = True;
      break;
    }
  }

  if (!found_entry) {
    file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  DEBUG(6, ("mod_smbfilepwd_entry: entry exists\n"));

  /* User name matches - get uid and password */
  p++;		/* Go past ':' */

  if (!isdigit(*p)) {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (uid not number)\n"));
    file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  while (*p && isdigit(*p))
    p++;
  if (*p != ':') {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (no : after uid)\n"));
    file_unlock(lockfd, &pw_file_lock_depth);
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
    DEBUG(10, ("mod_smbfilepwd_entry: entry invalidated for unix user %s\n", unix_name));
    file_unlock(lockfd, &pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (passwd too short)\n"));
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return (False);
  }

  if (p[32] != ':') {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (no terminating :)\n"));
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (!override && (*p == '*' || *p == 'X')) {
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  /* Now check if the NT compatible password is
     available. */
  p += 33; /* Move to the first character of the line after
              the lanman password. */
  if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (passwd too short)\n"));
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return (False);
  }

  if (p[32] != ':') {
    DEBUG(0, ("mod_smbfilepwd_entry: malformed password entry (no terminating :)\n"));
    file_unlock(lockfd,&pw_file_lock_depth);
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
      fstrcpy(encode_bits, pwdb_encode_acct_ctrl(pwd->acct_ctrl, NEW_PW_FORMAT_SPACE_PADDED_LEN));
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
    file_unlock(lockfd,&pw_file_lock_depth);
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
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  /* Sanity check - ensure the areas we are writing are framed by ':' */
  if (read(fd, linebuf, wr_len+1) != wr_len+1) {
    DEBUG(0, ("mod_smbfilepwd_entry: read fail on file %s.\n", pfile));
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if ((linebuf[0] != ':') || (linebuf[wr_len] != ':'))	{
    DEBUG(0, ("mod_smbfilepwd_entry: check on passwd file %s failed.\n", pfile));
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }
 
  if (sys_lseek(fd, pwd_seekpos, SEEK_SET) != pwd_seekpos) {
    DEBUG(0, ("mod_smbfilepwd_entry: seek fail on file %s.\n", pfile));
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  if (write(fd, ascii_p16, wr_len) != wr_len) {
    DEBUG(0, ("mod_smbfilepwd_entry: write failed in passwd file %s\n", pfile));
    file_unlock(lockfd,&pw_file_lock_depth);
    fclose(fp);
    return False;
  }

  file_unlock(lockfd,&pw_file_lock_depth);
  fclose(fp);
  return True;
}

/************************************************************************
 Routine to delete an entry in the smbpasswd file by rid.
*************************************************************************/

static BOOL del_smbfilepwd_entry(uint32 user_rid)
{
  char *pfile = lp_smb_passwd_file();
  pstring pfile2;
  struct smb_passwd *pwd = NULL;
  FILE *fp = NULL;
  FILE *fp_write = NULL;
  int pfile2_lockdepth = 0;
  struct sam_passwd *sam_pass;
  fstring name;

  DEBUG(0, ("del_smbfilepwd_entry\n"));

  become_root(True);
  sam_pass = getsam21pwrid(user_rid);
  unbecome_root(True);

  if (sam_pass == NULL)
  {
          DEBUG(0, ("User 0x%x not found\n", user_rid));
          return False;
  }

  DEBUG(0, ("del_smbfilepwd_entry: User:[%s]\n", sam_pass->nt_name));

/*  unistr2_to_ascii(name, sam_pass->nt_name, sizeof(name) - 1); */
  fstrcpy(name, sam_pass->nt_name);

  DEBUG(0, ("del_smbfilepwd_entry: user: %s\n", name));

  slprintf(pfile2, sizeof(pfile2)-1, "%s.%u", pfile, (unsigned)sys_getpid() );

  /*
   * Open the smbpassword file - for update. It needs to be update
   * as we need any other processes to wait until we have replaced
   * it.
   */

  if((fp = startsmbfilepwent(True)) == NULL) {
    DEBUG(0, ("del_smbfilepwd_entry: unable to open file %s.\n", pfile));
    return False;
  }

  /*
   * Create the replacement password file.
   */
  if((fp_write = startfilepw_race_condition_avoid(pfile2, PWF_CREATE, &pfile2_lockdepth)) == NULL) {
    DEBUG(0, ("del_smbfilepwd_entry: unable to open file %s.\n", pfile));
    endsmbfilepwent(fp);
    return False;
  }

  /*
   * Scan the file, a line at a time and check if the name matches.
   */

  while ((pwd = getsmbfilepwent(fp)) != NULL) {
    char *new_entry;
    size_t new_entry_length;

    if (strequal(name, pwd->unix_name)) {
      DEBUG(10, ("add_smbfilepwd_entry: found entry with name %s - deleting it.\n", name));
      continue;
    }

    /*
     * We need to copy the entry out into the second file.
     */

    if((new_entry = format_new_smbpasswd_entry(pwd)) == NULL) {
      DEBUG(0, ("del_smbfilepwd_entry(malloc): Failed to copy entry for user %s to file %s. \
Error was %s\n", pwd->unix_name, pfile2, strerror(errno)));
      unlink(pfile2);
      endsmbfilepwent(fp);
      endfilepw_race_condition_avoid(fp_write,&pfile2_lockdepth);
      return False;
    }

    new_entry_length = strlen(new_entry);

    if(fwrite(new_entry, 1, new_entry_length, fp_write) != new_entry_length) {
      DEBUG(0, ("del_smbfilepwd_entry(write): Failed to copy entry for user %s to file %s. \
Error was %s\n", pwd->unix_name, pfile2, strerror(errno)));
      unlink(pfile2);
      endsmbfilepwent(fp);
      endfilepw_race_condition_avoid(fp_write,&pfile2_lockdepth);
      free(new_entry);
      return False;
    }

    free(new_entry);
  }

  /*
   * Ensure pfile2 is flushed before rename.
   */

  if(fflush(fp_write) != 0) {
    DEBUG(0, ("del_smbfilepwd_entry: Failed to flush file %s. Error was %s\n", pfile2, strerror(errno)));
    endsmbfilepwent(fp);
    endfilepw_race_condition_avoid(fp_write,&pfile2_lockdepth);
    return False;
  }

  /*
   * Do an atomic rename - then release the locks.
   */

  if(rename(pfile2,pfile) != 0) {
    unlink(pfile2);
  }
  endsmbfilepwent(fp);
  endfilepw_race_condition_avoid(fp_write,&pfile2_lockdepth);
  return True;
}


static struct smb_passdb_ops file_ops = {
  startsmbfilepwent,
  endsmbfilepwent,
  getsmbfilepwpos,
  setsmbfilepwpos,
  iterate_getsmbpwnam,          /* In passdb.c */
  iterate_getsmbpwuid,          /* In passdb.c */
  getsmbfilepwent,
  add_smbfilepwd_entry,
  mod_smbfilepwd_entry,
  del_smbfilepwd_entry
};

struct smb_passdb_ops *file_initialise_password_db(void)
{    
  return &file_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void smbpass_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
