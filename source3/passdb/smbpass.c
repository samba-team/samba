#ifdef SMB_PASSWD
/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1995 Modified by Jeremy Allison 1995.
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
	int             fd = open(name, O_RDWR | O_CREAT, 0666);
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
 * Routine to get the next 32 hex characters and turn them
 * into a 16 byte array.
 */

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

/*
 * Routine to search the smbpasswd file for an entry matching the username.
 */
struct smb_passwd *get_smbpwnam(char *name)
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

	if (!*pfile) {
		DEBUG(0, ("No SMB password file set\n"));
		return (NULL);
	}
	DEBUG(10, ("get_smbpwnam: opening file %s\n", pfile));

	fp = fopen(pfile, "r");

	if (fp == NULL) {
		DEBUG(0, ("get_smbpwnam: unable to open file %s\n", pfile));
		return NULL;
	}
	/* Set a 16k buffer to do more efficient reads */
	setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));

	if ((lockfd = pw_file_lock(pfile, F_RDLCK, 5)) < 0) {
		DEBUG(0, ("get_smbpwnam: unable to lock file %s\n", pfile));
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
		DEBUG(100, ("get_smbpwnam: got line |%s|\n", linebuf));
#endif
		if ((linebuf[0] == 0) && feof(fp)) {
			DEBUG(4, ("get_smbpwnam: end of file reached\n"));
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
			DEBUG(6, ("get_smbpwnam: skipping comment or blank line\n"));
			continue;
		}
		p = (unsigned char *) strchr(linebuf, ':');
		if (p == NULL) {
			DEBUG(0, ("get_smbpwnam: malformed password entry (no :)\n"));
			continue;
		}
		/*
		 * As 256 is shorter than a pstring we don't need to check
		 * length here - if this ever changes....
		 */
		strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
		user_name[PTR_DIFF(p, linebuf)] = '\0';
		if (!strequal(user_name, name))
			continue;

		/* User name matches - get uid and password */
		p++;		/* Go past ':' */
		if (!isdigit(*p)) {
			DEBUG(0, ("get_smbpwnam: malformed password entry (uid not number)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return NULL;
		}
		uidval = atoi((char *) p);
		while (*p && isdigit(*p))
			p++;
		if (*p != ':') {
			DEBUG(0, ("get_smbpwnam: malformed password entry (no : after uid)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return NULL;
		}
		/*
		 * Now get the password value - this should be 32 hex digits
		 * which are the ascii representations of a 16 byte string.
		 * Get two at a time and put them into the password.
		 */
		p++;
		if (*p == '*' || *p == 'X') {
			/* Password deliberately invalid - end here. */
			DEBUG(10, ("get_smbpwnam: entry invalidated for user %s\n", user_name));
			fclose(fp);
			pw_file_unlock(lockfd);
			return NULL;
		}
		if (linebuf_len < (PTR_DIFF(p, linebuf) + 33)) {
			DEBUG(0, ("get_smbpwnam: malformed password entry (passwd too short)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return (False);
		}
		if (p[32] != ':') {
			DEBUG(0, ("get_smbpwnam: malformed password entry (no terminating :)\n"));
			fclose(fp);
			pw_file_unlock(lockfd);
			return NULL;
		}
		if (!strncasecmp((char *) p, "NO PASSWORD", 11)) {
			pw_buf.smb_passwd = NULL;
		} else {
			if(!gethexpwd((char *)p,(char *)smbpwd)) {
				DEBUG(0, ("Malformed Lanman password entry (non hex chars)\n"));
				fclose(fp);
				pw_file_unlock(lockfd);
				return NULL;
			}
			pw_buf.smb_passwd = smbpwd;
		}
		pw_buf.smb_name = user_name;
		pw_buf.smb_userid = uidval;
		pw_buf.smb_nt_passwd = NULL;

		/* Now check if the NT compatible password is
			available. */
		p += 33; /* Move to the first character of the line after
					the lanman password. */
		if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':')) {
			if (*p != '*' && *p != 'X') {
				if(gethexpwd((char *)p,(char *)smbntpwd))
					pw_buf.smb_nt_passwd = smbntpwd;
			}
		}

		fclose(fp);
		pw_file_unlock(lockfd);
		DEBUG(5, ("get_smbpwname: returning passwd entry for user %s, uid %d\n",
			  user_name, uidval));
		return &pw_buf;
	}

	fclose(fp);
	pw_file_unlock(lockfd);
	return NULL;
}
#else
 void smbpass_dummy(void)
{
}				/* To avoid compiler complaints */
#endif
