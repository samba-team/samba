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

/*
 * This file also contains migration code to move from an old
 * trust account password file stored in the file :
 * ${SAMBA_HOME}/private/{domain}.{netbiosname}.mac
 * into a record stored in the tdb ${SAMBA_HOME}/private/secrets.tdb
 * database. JRA.
 */

#include "includes.h"

extern pstring global_myname;


static int mach_passwd_lock_depth;
static FILE *mach_passwd_fp;

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

/************************************************************************
 Routine to get the name for an old trust account file.
************************************************************************/

static void get_trust_account_file_name( char *domain, char *name, char *mac_file)
{
  unsigned int mac_file_len;

  /* strip the filename to the last '/' */
  get_private_directory(mac_file);
  pstrcat(mac_file, "/");

  mac_file_len = strlen(mac_file);

  if ((int)(sizeof(pstring) - mac_file_len - strlen(domain) - strlen(name) - 6) < 0) {
    DEBUG(0,("trust_password_lock: path %s too long to add trust details.\n",
              mac_file));
    return;
  }

  pstrcat(mac_file, domain);
  pstrcat(mac_file, ".");
  pstrcat(mac_file, name);
  pstrcat(mac_file, ".mac");
}
 
/************************************************************************
 Routine to lock the old trust account password file for a domain.
 As this is a function to migrate to the new secrets.tdb, we never
 create the file here, only open it.
************************************************************************/

static BOOL trust_password_file_lock(char *domain, char *name)
{
  pstring mac_file;

  if(mach_passwd_lock_depth == 0) {
    int fd;

    get_trust_account_file_name( domain, name, mac_file);

    if ((fd = sys_open(mac_file, O_RDWR, 0)) == -1)
      return False;

    if((mach_passwd_fp = fdopen(fd, "w+b")) == NULL) {
        DEBUG(0,("trust_password_lock: cannot open file %s - Error was %s.\n",
              mac_file, strerror(errno) ));
        return False;
    }

    if(!pw_file_lock(fileno(mach_passwd_fp), F_WRLCK, 60, &mach_passwd_lock_depth)) {
      DEBUG(0,("trust_password_lock: cannot lock file %s\n", mac_file));
      fclose(mach_passwd_fp);
      return False;
    }

  }

  return True;
}

/************************************************************************
 Routine to unlock the old trust account password file for a domain.
************************************************************************/

static BOOL trust_password_file_unlock(void)
{
  BOOL ret = pw_file_unlock(fileno(mach_passwd_fp), &mach_passwd_lock_depth);
  if(mach_passwd_lock_depth == 0)
    fclose(mach_passwd_fp);
  return ret;
}

/************************************************************************
 Routine to delete the old trust account password file for a domain.
 Note that this file must be locked as it is truncated before the
 delete. This is to ensure it only gets deleted by one smbd.
************************************************************************/

static BOOL trust_password_file_delete( char *domain, char *name )
{
  pstring mac_file;
  int ret;

  get_trust_account_file_name( domain, name, mac_file);
  if(sys_ftruncate(fileno(mach_passwd_fp),(SMB_OFF_T)0) == -1) {
    DEBUG(0,("trust_password_file_delete: Failed to truncate file %s (%s)\n",
        mac_file, strerror(errno) ));
  }
  ret = unlink( mac_file );
  return (ret != -1);
}

/************************************************************************
 Routine to get the old trust account password for a domain - to convert
 to the new secrets.tdb entry.
 The user of this function must have locked the trust password file.
************************************************************************/

static BOOL get_trust_account_password_from_file( unsigned char *ret_pwd, time_t *pass_last_set_time)
{
  char linebuf[256];
  char *p;
  int i;
  SMB_STRUCT_STAT st;
  linebuf[0] = '\0';

  *pass_last_set_time = (time_t)0;
  memset(ret_pwd, '\0', 16);

  if(sys_fstat(fileno(mach_passwd_fp), &st) == -1) {
    DEBUG(0,("get_trust_account_password: Failed to stat file. Error was %s.\n",
              strerror(errno) )); 
    return False;
  }

  /*
   * If size is zero, another smbd has migrated this file
   * to the secrets.tdb file, and we are in a race condition.
   * Just ignore the file.
   */

  if (st.st_size == 0)
    return False;

  if(sys_fseek( mach_passwd_fp, (SMB_OFF_T)0, SEEK_SET) == -1) {
    DEBUG(0,("get_trust_account_password: Failed to seek to start of file. Error was %s.\n",
              strerror(errno) ));
    return False;
  } 

  fgets(linebuf, sizeof(linebuf), mach_passwd_fp);
  if(ferror(mach_passwd_fp)) {
    DEBUG(0,("get_trust_account_password: Failed to read password. Error was %s.\n",
              strerror(errno) ));
    return False;
  }

  if(linebuf[strlen(linebuf)-1] == '\n')
    linebuf[strlen(linebuf)-1] = '\0';

  /*
   * The length of the line read
   * must be 45 bytes ( <---XXXX 32 bytes-->:TLC-12345678
   */

  if(strlen(linebuf) != 45) {
    DEBUG(0,("get_trust_account_password: Malformed trust password file (wrong length \
- was %d, should be 45).\n", (int)strlen(linebuf)));
#ifdef DEBUG_PASSWORD
    DEBUG(100,("get_trust_account_password: line = |%s|\n", linebuf));
#endif
    return False;
  }

  /*
   * Get the hex password.
   */

  if (!pdb_gethexpwd((char *)linebuf, ret_pwd) || linebuf[32] != ':' || 
         strncmp(&linebuf[33], "TLC-", 4)) {
    DEBUG(0,("get_trust_account_password: Malformed trust password file (incorrect format).\n"));
#ifdef DEBUG_PASSWORD
    DEBUG(100,("get_trust_account_password: line = |%s|\n", linebuf));
#endif
    return False;
  }

  /*
   * Get the last changed time.
   */
  p = &linebuf[37];

  for(i = 0; i < 8; i++) {
    if(p[i] == '\0' || !isxdigit((int)p[i])) {
      DEBUG(0,("get_trust_account_password: Malformed trust password file (no timestamp).\n"));
#ifdef DEBUG_PASSWORD
      DEBUG(100,("get_trust_account_password: line = |%s|\n", linebuf));
#endif
      return False;
    }
  }

  /*
   * p points at 8 characters of hex digits -
   * read into a time_t as the seconds since
   * 1970 that the password was last changed.
   */

  *pass_last_set_time = (time_t)strtol(p, NULL, 16);

  return True;
}

/************************************************************************
 Migrate an old DOMAIN.MACINE.mac password file to the tdb secrets db.
************************************************************************/

BOOL migrate_from_old_password_file(char *domain)
{
	struct machine_acct_pass pass;

	if (!trust_password_file_lock(domain, global_myname))
		return True;

	if (!get_trust_account_password_from_file( pass.hash, &pass.mod_time)) {
		trust_password_file_unlock();
		return False;
	}

	if (!secrets_store(trust_keystr(domain), (void *)&pass, sizeof(pass)))
		return False;

	trust_password_file_delete(domain, global_myname);
	trust_password_file_unlock();

	return True;
}
