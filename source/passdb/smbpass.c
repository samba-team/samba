/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1997 Modified by Jeremy Allison 1995.
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

extern int      DEBUGLEVEL;

int             gotalarm;

void 
gotalarm_sig()
{
	gotalarm = 1;
}

int 
do_pw_lock(int fd, int waitsecs, int type)
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

int pw_file_lock(char *name, int type, int secs)
{
	int fd = open(name, O_RDWR | O_CREAT, 0600);
	if (fd < 0)
		return (-1);
	if (do_pw_lock(fd, secs, type)) {
		close(fd);
		return -1;
	}
	return fd;
}

int pw_file_unlock(int fd)
{
	do_pw_lock(fd, 5, F_UNLCK);
	return close(fd);
}

/*
 * Routine to get the next hex characters and turn them
 * into a byte array.
 */

static int gethexpwd(char *p, char *pwd)
{
	int i;
	unsigned char   lonybble, hinybble;
	char           *hexchars = "0123456789ABCDEF";
	char           *p1, *p2;

	for (i = 0; i < 32; i += 2)
	{
		hinybble = toupper(p[i  ]);
		lonybble = toupper(p[i+1]);
 
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
 Routine to search the smbpasswd file for an entry matching the username
 or user id.  if the name is NULL, then the smb_uid is used instead.
 *************************************************************************/
BOOL get_smbpwd_entries(struct smb_passwd *pw_buf,
				int *total_entries, int *num_entries,
				int max_num_entries,
				uint16 acb_mask)
{
	/* Static buffers we will return. */
	static pstring  user_name;
	static unsigned char smbpwd[16];
	static unsigned char smbntpwd[16];
	char            linebuf[256];
	char            readbuf[16 * 1024];
	unsigned char   c;
	unsigned char  *p;
	long            uidval;
	long            linebuf_len;
	FILE           *fp;
	int             lockfd;
	char           *pfile = lp_smb_passwd_file();
	unsigned long   acct_ctrl;

	(*num_entries) = 0;
	(*total_entries) = 0;

	if (pw_buf == NULL) return False;

	if (!*pfile)
	{
		DEBUG(0, ("No SMB password file set\n"));
		return False;
	}

	DEBUG(10, ("get_smbpwd_entries: opening file %s\n", pfile));

	fp = fopen(pfile, "r");

	if (fp == NULL) {
		DEBUG(0, ("get_smbpwd_entries: unable to open file %s\n", pfile));
		return False;
	}
	/* Set a 16k buffer to do more efficient reads */
	setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));

	if ((lockfd = pw_file_lock(pfile, F_RDLCK, 5)) < 0) {
		DEBUG(0, ("get_smbpwd_entries: unable to lock file %s\n", pfile));
		fclose(fp);
		return False;
	}
	/* make sure it is only rw by the owner */
	chmod(pfile, 0600);

	/* We have a read lock on the file. */
	/*
	 * Scan the file, a line at a time and check if the name matches.
	 */
	while (!feof(fp) && (*num_entries) < max_num_entries)
	{
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
				if (c == '\n')
					break;
			}
		} else
			linebuf[linebuf_len - 1] = '\0';

#ifdef DEBUG_PASSWORD
		DEBUG(100, ("get_smbpwd_entries: got line |%s|\n", linebuf));
#endif
		if ((linebuf[0] == 0) && feof(fp)) {
			DEBUG(4, ("get_smbpwd_entries: end of file reached\n"));
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
			DEBUG(6, ("get_smbpwd_entries: skipping comment or blank line\n"));
			continue;
		}
		p = (unsigned char *) strchr(linebuf, ':');
		if (p == NULL) {
			DEBUG(0, ("get_smbpwd_entries: malformed password entry (no :)\n"));
			continue;
		}
		/*
		 * As 256 is shorter than a pstring we don't need to check
		 * length here - if this ever changes....
		 */
		strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
		user_name[PTR_DIFF(p, linebuf)] = '\0';

		/* get smb uid */

		p++;		/* Go past ':' */
		if (!isdigit(*p))
		{
			DEBUG(0, ("get_smbpwd_entries: malformed password entry (uid not number)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return False;
		}

		uidval = atoi((char *) p);

		while (*p && isdigit(*p))
		{
			p++;
		}

		if (*p != ':')
		{
			DEBUG(0, ("get_smbpwd_entries: malformed password entry (no : after uid)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return False;
		}

		/* if we're here, the entry has been found (either by name or uid) */

		/*
		 * Now get the password value - this should be 32 hex digits
		 * which are the ascii representations of a 16 byte string.
		 * Get two at a time and put them into the password.
		 */

		/* skip the ':' */
		p++;

		if (*p == '*' || *p == 'X')
		{
			/* Password deliberately invalid - end here. */
			DEBUG(10, ("get_smbpwd_entries: entry invalidated for user %s\n", user_name));
			fclose(fp);
			pw_file_unlock(lockfd);
			return False;
		}

		if (linebuf_len < (PTR_DIFF(p, linebuf) + 33))
		{
			DEBUG(0, ("get_smbpwd_entries: malformed password entry (passwd too short)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return (False);
		}

		if (p[32] != ':')
		{
			DEBUG(0, ("get_smbpwd_entries: malformed password entry (no terminating :)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return False;
		}

		if (!strncasecmp((char *) p, "NO PASSWORD", 11))
		{
			pw_buf[(*num_entries)].smb_passwd = NULL;
		}
		else
		{
			if (!gethexpwd((char *)p, (char *)smbpwd))
			{
				DEBUG(0, ("Malformed Lanman password entry (non hex chars)\n"));
				fclose(fp);
				pw_file_unlock(lockfd);
				return False;
			}
			pw_buf[(*num_entries)].smb_passwd = smbpwd;
		}

		fstrcpy(pw_buf[(*num_entries)].smb_name, user_name);
		pw_buf[(*num_entries)].smb_userid    = uidval;
		pw_buf[(*num_entries)].smb_nt_passwd = NULL;

		/* Now check if the NT compatible password is available. */
		p += 33; /* Move to the first character of the line after
					the lanman password. */
		if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':'))
		{
			if (*p != '*' && *p != 'X')
			{
				if(gethexpwd((char *)p,(char *)smbntpwd))
					pw_buf[(*num_entries)].smb_nt_passwd = smbntpwd;
			}
		}

		/* Now check if the Account Control Bits are available */
		p += 33; 
		if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 5)) && (p[4] == ':'))
		{
			acct_ctrl = strtoul( p, (char**)NULL, 16);
		}
		else
		{
			int len = strlen(user_name);
			if (len != 0 && user_name[len-1] == '$')
			{
				/* oops - have to assume that it's a workstation trust account */
				acct_ctrl = ACB_WSTRUST;
			}
			else
			{
				acct_ctrl = ACB_NORMAL;
			}
		}
		
		pw_buf[(*num_entries)].acct_ctrl = (uint16)acct_ctrl;

		DEBUG(5, ("get_smbpwd_entries: idx: %d user %s, uid %d, acb %x",
			  (*num_entries), user_name, uidval, acct_ctrl));

		if (acb_mask == 0 || IS_BITS_SET_SOME(acct_ctrl, acb_mask))
		{
			DEBUG(5,(" acb_mask %x accepts\n", acb_mask));
			(*num_entries)++;
		}
		else
		{
			DEBUG(5,(" acb_mask %x rejects\n", acb_mask));
		}

		(*total_entries)++;
	}

	fclose(fp);
	pw_file_unlock(lockfd);

	return (*num_entries) > 0;
}

/*************************************************************************
 Routine to search the smbpasswd file for an entry matching the username
 or user id.  if the name is NULL, then the smb_uid is used instead.
 *************************************************************************/
struct smb_passwd *get_smbpwd_entry(char *name, int smb_userid)
{
	/* Static buffers we will return. */
	static struct smb_passwd pw_buf;
	static pstring  user_name;
	static unsigned char smbpwd[16];
	static unsigned char smbntpwd[16];
	char            linebuf[256];
	char            readbuf[16 * 1024];
	unsigned char   c;
	unsigned char  *p;
	long            uidval;
	long            linebuf_len;
	FILE           *fp;
	int             lockfd;
	char           *pfile = lp_smb_passwd_file();
	unsigned long   acct_ctrl;
	int len_user_name;

	if (!*pfile) {
		DEBUG(0, ("No SMB password file set\n"));
		return (NULL);
	}
	DEBUG(10, ("get_smbpwd_entry: opening file %s\n", pfile));

	if (name != NULL)
	{
		DEBUG(10, ("get_smbpwd_entry: search by name: %s\n", name));
	}
	else
	{
		DEBUG(10, ("get_smbpwd_entry: search by smb_userid: %x\n", smb_userid));
	}

	fp = fopen(pfile, "r");

	if (fp == NULL) {
		DEBUG(0, ("get_smbpwd_entry: unable to open file %s\n", pfile));
		return NULL;
	}
	/* Set a 16k buffer to do more efficient reads */
	setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));

	if ((lockfd = pw_file_lock(pfile, F_RDLCK, 5)) < 0) {
		DEBUG(0, ("get_smbpwd_entry: unable to lock file %s\n", pfile));
		fclose(fp);
		return NULL;
	}
	/* make sure it is only rw by the owner */
	chmod(pfile, 0600);

	/* We have a read lock on the file. */
	/*
	 * Scan the file, a line at a time and check if the name matches.
	 */
	while (!feof(fp)) {
		linebuf[0] = '\0';

		fgets(linebuf, 256, fp);
		if (ferror(fp)) {
			fclose(fp);
			pw_file_unlock(lockfd);
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
		DEBUG(100, ("get_smbpwd_entry: got line |%s|\n", linebuf));
#endif
		if ((linebuf[0] == 0) && feof(fp)) {
			DEBUG(4, ("get_smbpwd_entry: end of file reached\n"));
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
			DEBUG(6, ("get_smbpwd_entry: skipping comment or blank line\n"));
			continue;
		}
		p = (unsigned char *) strchr(linebuf, ':');
		if (p == NULL) {
			DEBUG(0, ("get_smbpwd_entry: malformed password entry (no :)\n"));
			continue;
		}
		/*
		 * As 256 is shorter than a pstring we don't need to check
		 * length here - if this ever changes....
		 */
		strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
		user_name[PTR_DIFF(p, linebuf)] = '\0';

		/* get smb uid */

		p++;		/* Go past ':' */
		if (!isdigit(*p))
		{
			DEBUG(0, ("get_smbpwd_entry: malformed password entry (uid not number)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return NULL;
		}

		uidval = atoi((char *) p);

		while (*p && isdigit(*p))
		{
			p++;
		}

		if (*p != ':')
		{
			DEBUG(0, ("get_smbpwd_entry: malformed password entry (no : after uid)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return NULL;
		}

		if (name != NULL)
		{
			/* search is by user name */
			if (!strequal(user_name, name)) continue;
			DEBUG(10, ("get_smbpwd_entry: found by name: %s\n", user_name));
		}
		else
		{
			/* search is by user id */
			if (uidval != smb_userid) continue;
			DEBUG(10, ("get_smbpwd_entry: found by smb_userid: %x\n", uidval));
		}

		/* if we're here, the entry has been found (either by name or uid) */

		/*
		 * Now get the password value - this should be 32 hex digits
		 * which are the ascii representations of a 16 byte string.
		 * Get two at a time and put them into the password.
		 */

		/* skip the ':' */
		p++;

		if (*p == '*' || *p == 'X')
		{
			/* Password deliberately invalid - end here. */
			DEBUG(10, ("get_smbpwd_entry: entry invalidated for user %s\n", user_name));
			fclose(fp);
			pw_file_unlock(lockfd);
			return NULL;
		}

		if (linebuf_len < (PTR_DIFF(p, linebuf) + 33))
		{
			DEBUG(0, ("get_smbpwd_entry: malformed password entry (passwd too short)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return (False);
		}

		if (p[32] != ':')
		{
			DEBUG(0, ("get_smbpwd_entry: malformed password entry (no terminating :)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return NULL;
		}

		if (!strncasecmp((char *) p, "NO PASSWORD", 11))
		{
			pw_buf.smb_passwd = NULL;
		}
		else
		{
			if (!gethexpwd((char *)p, (char *)smbpwd))
			{
				DEBUG(0, ("Malformed Lanman password entry (non hex chars)\n"));
				fclose(fp);
				pw_file_unlock(lockfd);
				return NULL;
			}
			pw_buf.smb_passwd = smbpwd;
		}

		fstrcpy(pw_buf.smb_name, user_name);
		pw_buf.smb_userid    = uidval;
		pw_buf.smb_nt_passwd = NULL;
		len_user_name = strlen(user_name);
		if (len_user_name != 0 && user_name[len_user_name-1] == '$')
		{
			/* oops - have to assume that it's a workstation trust account */
			pw_buf.acct_ctrl = ACB_WSTRUST;
		}
		else
		{
			pw_buf.acct_ctrl = ACB_NORMAL;
		}

		/* Now check if the NT compatible password is available. */
		p += 33; /* Move to the first character of the line after
					the lanman password. */
		if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':'))
		{
			if (*p != '*' && *p != 'X')
			{
				if(gethexpwd((char *)p,(char *)smbntpwd))
					pw_buf.smb_nt_passwd = smbntpwd;
			}
		}

		/* Now check if the Account Control Bits are available */
		p += 33; 
		if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 5)) && (p[4] == ':'))
		{
			acct_ctrl = strtoul( p, (char**)NULL, 16);
			pw_buf.acct_ctrl = (uint16)acct_ctrl;
		}
		
		fclose(fp);
		pw_file_unlock(lockfd);
		DEBUG(5, ("get_smbpwd_entry: returning passwd entry for user %s, uid %d, acb %x\n",
			  user_name, uidval, acct_ctrl));
		return &pw_buf;
	}

	fclose(fp);
	pw_file_unlock(lockfd);
	return NULL;
}

/*
 * Routine to search the smbpasswd file for an entry matching the username.
 */
BOOL add_smbpwd_entry(struct smb_passwd* pwd)
{
	/* Static buffers we will return. */
	static pstring  user_name;

	char  linebuf[256];
	char  readbuf[16 * 1024];
	uchar c;
	char  *p;
	long  linebuf_len;
	FILE  *fp;
	int   lockfd;
	char  *pfile = lp_smb_passwd_file();

	int i;
	int wr_len;

	int fd;
	int new_entry_length;
	int smb_name_len = 0;
	char *new_entry;
	long offpos;

	if (!*pfile)
	{
		DEBUG(0, ("No SMB password file set\n"));
		return False;
	}
	DEBUG(10, ("add_smbpwd_entry: opening file %s\n", pfile));

	fp = fopen(pfile, "r+");

	if (fp == NULL)
	{
		DEBUG(0, ("add_smbpwd_entry: unable to open file %s\n", pfile));
		return False;
	}
	/* Set a 16k buffer to do more efficient reads */
	setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));

	if ((lockfd = pw_file_lock(pfile, F_RDLCK | F_WRLCK, 5)) < 0)
	{
		DEBUG(0, ("add_smbpwd_entry: unable to lock file %s\n", pfile));
		fclose(fp);
		return False;
	}
	/* make sure it is only rw by the owner */
	chmod(pfile, 0600);

	/* We have a write lock on the file. */
	/*
	* Scan the file, a line at a time and check if the name matches.
	*/
	while (!feof(fp))
	{
		linebuf[0] = '\0';

		fgets(linebuf, 256, fp);
		if (ferror(fp))
		{
			fclose(fp);
			pw_file_unlock(lockfd);
			return False;
		}

		/*
		 * Check if the string is terminated with a newline - if not
		 * then we must keep reading and discard until we get one.
		 */
		linebuf_len = strlen(linebuf);
		if (linebuf[linebuf_len - 1] != '\n')
		{
			c = '\0';
			while (!ferror(fp) && !feof(fp))
			{
				c = fgetc(fp);
				if (c == '\n')
				{
					break;
				}
			}
		}
		else
		{
			linebuf[linebuf_len - 1] = '\0';
		}

#ifdef DEBUG_PASSWORD
		DEBUG(100, ("add_smbpwd_entry: got line |%s|\n", linebuf));
#endif

		if ((linebuf[0] == 0) && feof(fp))
		{
			DEBUG(4, ("add_smbpwd_entry: end of file reached\n"));
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
		* username:uid:[32hex bytes]:[32hex bytes]:[4hex bytes]:....ignored....
		*
		* if Windows NT compatible passwords are also present.
		*/

		if (linebuf[0] == '#' || linebuf[0] == '\0')
		{
			DEBUG(6, ("add_smbpwd_entry: skipping comment or blank line\n"));
			continue;
		}

		p = (unsigned char *) strchr(linebuf, ':');

		if (p == NULL)
		{
			DEBUG(0, ("add_smbpwd_entry: malformed password entry (no :)\n"));
			continue;
		}

		/*
		 * As 256 is shorter than a pstring we don't need to check
		 * length here - if this ever changes....
		 */
		strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
		user_name[PTR_DIFF(p, linebuf)] = '\0';
		if (strequal(user_name, pwd->smb_name))
		{
			DEBUG(6, ("add_smbpwd_entry: entry already exists\n"));
			return False;
		}
	}

	/* ok - entry doesn't exist.  we can add it */

	/* Create a new smb passwd entry and set it to the given password. */
	/* The add user write needs to be atomic - so get the fd from 
	   the fp and do a raw write() call.
	 */
	fd = fileno(fp);

	if((offpos = lseek(fd, 0, SEEK_END)) == -1)
	{
		DEBUG(0, ("add_smbpwd_entry(lseek): Failed to add entry for user %s to file %s. \
Error was %s\n", pwd->smb_name, pfile, strerror(errno)));

		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	smb_name_len = strlen(pwd->smb_name);

	new_entry_length = smb_name_len + 1 + 15 + 1 + 32 + 1 + 32 + 1 + 2 + 5;

	if((new_entry = (char *)malloc( new_entry_length )) == 0)
	{
		DEBUG(0, ("add_smbpwd_entry(malloc): Failed to add entry for user %s to file %s. \
Error was %s\n", 
		pwd->smb_name, pfile, strerror(errno)));

		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	sprintf(new_entry, "%s:%u:", pwd->smb_name, (unsigned)pwd->smb_userid);
	p = (unsigned char*)(&new_entry[strlen(new_entry)]);

	for( i = 0; i < 16; i++)
	{
		sprintf(&p[i*2], "%02X", pwd->smb_passwd[i]);
	}
	p += 32;

	*p++ = ':';

	for( i = 0; i < 16; i++)
	{
		sprintf(&p[i*2], "%02X", pwd->smb_nt_passwd[i]);
	}
	p += 32;

	sprintf(p, ":%4x:\n", pwd->acct_ctrl);

#ifdef DEBUG_PASSWORD
		DEBUG(100, ("add_smbpwd_entry(%d): new_entry_len %d entry_len %d made line |%s|\n", 
		             fd, new_entry_length, strlen(new_entry), new_entry));
#endif

	if ((wr_len = write(fd, new_entry, strlen(new_entry))) != strlen(new_entry))
	{
		DEBUG(0, ("add_smbpwd_entry(write): %d Failed to add entry for user %s to file %s. \
Error was %s\n", wr_len, pwd->smb_name, pfile, strerror(errno)));

		/* Remove the entry we just wrote. */
		if(ftruncate(fd, offpos) == -1)
		{
			DEBUG(0, ("add_smbpwd_entry: ERROR failed to ftruncate file %s. \
Error was %s. Password file may be corrupt ! Please examine by hand !\n", 
			pwd->smb_name, strerror(errno)));
		}

		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	fclose(fp);
	pw_file_unlock(lockfd);
	return True;
}
/*
 * Routine to search the smbpasswd file for an entry matching the username.
 * and then modify its password entry
 */
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
	BOOL mod_acb_acct = False;

	long pwd_seekpos = 0;

	int i;
	int wr_len;
	int fd;

	if (!*pfile)
	{
		DEBUG(0, ("No SMB password file set\n"));
		return False;
	}
	DEBUG(10, ("mod_smbpwd_entry: opening file %s\n", pfile));

	fp = fopen(pfile, "r+");

	if (fp == NULL)
	{
		DEBUG(0, ("mod_smbpwd_entry: unable to open file %s\n", pfile));
		return False;
	}
	/* Set a 16k buffer to do more efficient reads */
	setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));

	if ((lockfd = pw_file_lock(pfile, F_RDLCK | F_WRLCK, 5)) < 0)
	{
		DEBUG(0, ("mod_smbpwd_entry: unable to lock file %s\n", pfile));
		fclose(fp);
		return False;
	}
	/* make sure it is only rw by the owner */
	chmod(pfile, 0600);

	/* We have a write lock on the file. */
	/*
	* Scan the file, a line at a time and check if the name matches.
	*/
	while (!feof(fp))
	{
		pwd_seekpos = ftell(fp);

		linebuf[0] = '\0';

		fgets(linebuf, 256, fp);
		if (ferror(fp))
		{
			fclose(fp);
			pw_file_unlock(lockfd);
			return False;
		}

		/*
		 * Check if the string is terminated with a newline - if not
		 * then we must keep reading and discard until we get one.
		 */
		linebuf_len = strlen(linebuf);
		if (linebuf[linebuf_len - 1] != '\n')
		{
			c = '\0';
			while (!ferror(fp) && !feof(fp))
			{
				c = fgetc(fp);
				if (c == '\n')
				{
					break;
				}
			}
		}
		else
		{
			linebuf[linebuf_len - 1] = '\0';
		}

#ifdef DEBUG_PASSWORD
		DEBUG(100, ("mod_smbpwd_entry: got line |%s|\n", linebuf));
#endif

		if ((linebuf[0] == 0) && feof(fp))
		{
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

		if (linebuf[0] == '#' || linebuf[0] == '\0')
		{
			DEBUG(6, ("mod_smbpwd_entry: skipping comment or blank line\n"));
			continue;
		}

		p = (unsigned char *) strchr(linebuf, ':');

		if (p == NULL)
		{
			DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no :)\n"));
			continue;
		}

		/*
		 * As 256 is shorter than a pstring we don't need to check
		 * length here - if this ever changes....
		 */
		strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
		user_name[PTR_DIFF(p, linebuf)] = '\0';
		if (strequal(user_name, pwd->smb_name))
		{
			found_entry = True;
			break;
		}
	}

	if (!found_entry) return False;

	DEBUG(6, ("mod_smbpwd_entry: entry exists\n"));

	/* User name matches - get uid and password */
	p++;		/* Go past ':' */

	if (!isdigit(*p))
	{
		DEBUG(0, ("mod_smbpwd_entry: malformed password entry (uid not number)\n"));
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	while (*p && isdigit(*p))
		p++;
	if (*p != ':')
	{
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

	/* record exact password position */
	pwd_seekpos += PTR_DIFF(p, linebuf);

	if (*p == '*' || *p == 'X')
	{
		/* Password deliberately invalid - end here. */
		DEBUG(10, ("get_smbpwd_entry: entry invalidated for user %s\n", user_name));
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	if (linebuf_len < (PTR_DIFF(p, linebuf) + 33))
	{
		DEBUG(0, ("mod_smbpwd_entry: malformed password entry (passwd too short)\n"));
		fclose(fp);
		pw_file_unlock(lockfd);
		return (False);
	}

	if (p[32] != ':')
	{
		DEBUG(0, ("mod_smbpwd_entry: malformed password entry (no terminating :)\n"));
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	if (*p == '*' || *p == 'X')
	{
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}
	if (!strncasecmp((char *) p, "NO PASSWORD", 11))
	{
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	/* Now check if the NT compatible password is available. */
	p += 33; /* Move to the first character of the line after the lanman password. */
	if (linebuf_len < (PTR_DIFF(p, linebuf) + 33))
	{
		DEBUG(0, ("mod_smbpwd_entry: malformed password entry (passwd too short)\n"));
		fclose(fp);
		pw_file_unlock(lockfd);
		return (False);
	}

	if (*p == '*' || *p == 'X')
	{
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	if (p[32] != ':')
	{
		DEBUG(0, ("mod_smbpwd_entry: malformed password entry (nt passwd too short)"));
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	p += 33;

	/* optional account ACB details */
	mod_acb_acct = (linebuf_len >= (PTR_DIFF(p + 5, linebuf)));

	if (mod_acb_acct) p += 4;

	if (*p != ':')
	{
		DEBUG(0, ("mod_smbpwd_entry: malformed ACB entry (no terminating :)\n"));
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	/* whew.  entry is correctly formed. */

	/*
	 * Do an atomic write into the file at the position defined by
	 * seekpos.
	 */

	/* The mod user write needs to be atomic - so get the fd from 
	   the fp and do a raw write() call.
	 */

	fd = fileno(fp);

	if (lseek(fd, pwd_seekpos - 1, SEEK_SET) != pwd_seekpos - 1)
	{
		DEBUG(1, ("mod_smbpwd_entry: seek fail on file %s.\n", pfile));
			fclose(fp);
			pw_file_unlock(lockfd);
			return False;
	}

	/* Sanity check - ensure the character is a ':' */
	if (read(fd, &c, 1) != 1)
	{
		DEBUG(1, ("mod_smbpwd_entry: read fail on file %s.\n", pfile));
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	if (c != ':')
	{
		DEBUG(1, ("mod_smbpwd_entry: check on passwd file %s failed.\n", pfile));
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}
 
	/* Create the 32 byte representation of the new p16 */
	for (i = 0; i < 16; i++)
	{
		sprintf(&ascii_p16[i*2], "%02X", (uchar) pwd->smb_passwd[i]);
	}
	if (pwd->smb_nt_passwd != NULL)
	{
		/* Add on the NT md4 hash */
		ascii_p16[32] = ':';
		for (i = 0; i < 16; i++)
		{
			sprintf(&ascii_p16[(i*2)+33], "%02X", (uchar) pwd->smb_nt_passwd[i]);
		}
		wr_len = 65;
	}
	else	
	{
		wr_len = 32;
	}

	if (mod_acb_acct)
	{
		sprintf(&(ascii_p16[wr_len]), ":%04x", pwd->acct_ctrl);
		wr_len += 5;
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100,("mod_smbpwd_entry: "));
	dump_data(100, ascii_p16, wr_len);
#endif

	if (write(fd, ascii_p16, wr_len) != wr_len)
	{
		DEBUG(1, ("mod_smbpwd_entry: write failed in passwd file %s\n", pfile));
		fclose(fp);
		pw_file_unlock(lockfd);
		return False;
	}

	fclose(fp);
	pw_file_unlock(lockfd);
	return True;
}
