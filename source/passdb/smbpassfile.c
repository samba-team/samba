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

BOOL global_machine_password_needs_changing = False;

/***************************************************************
 Lock an fd. Abandon after waitsecs seconds.
****************************************************************/
BOOL pw_file_lock(int fd, int type, int secs, int *plock_depth)
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
BOOL pw_file_unlock(int fd, int *plock_depth)
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
form a key for fetching a domain trust password
************************************************************************/
static char *trust_keystr(char *domain)
{
	static fstring keystr;
	slprintf(keystr,sizeof(keystr),"%s/%s", SECRETS_MACHINE_ACCT_PASS, domain);
	return keystr;
}


/************************************************************************
 Routine to delete the trust account password file for a domain.
************************************************************************/
BOOL trust_password_delete(char *domain)
{
	return secrets_delete(trust_keystr(domain));
}

/************************************************************************
 Routine to get the trust account password for a domain.
 The user of this function must have locked the trust password file.
************************************************************************/
BOOL get_trust_account_password(char *domain, unsigned char *ret_pwd, time_t *pass_last_set_time)
{
	struct machine_acct_pass *pass;
	size_t size;

	if (!(pass = secrets_fetch(trust_keystr(domain), &size)) ||
	    size != sizeof(*pass)) return False;

	if (pass_last_set_time) *pass_last_set_time = pass->mod_time;
	memcpy(ret_pwd, pass->hash, 16);
	free(pass);
	return True;
}


/************************************************************************
 Routine to get the trust account password for a domain.
 The user of this function must have locked the trust password file.
************************************************************************/
BOOL set_trust_account_password(char *domain, unsigned char *md4_new_pwd)
{
	struct machine_acct_pass pass;

	pass.mod_time = time(NULL);
	memcpy(pass.hash, md4_new_pwd, 16);

	return secrets_store(trust_keystr(domain), (void *)&pass, sizeof(pass));
}
