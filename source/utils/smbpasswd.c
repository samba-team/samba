/*
 * Unix SMB/Netbios implementation. Version 1.9. smbpasswd module. Copyright
 * (C) Jeremy Allison 1995-1998
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

/* 
 * Password changing error codes.
 */

struct
{
  int err;
  char *message;
} pw_change_errmap[] =
{
  {5,    "User has insufficient privilege" },
  {86,   "The specified password is invalid" },
  {2226, "Operation only permitted on a Primary Domain Controller"  },
  {2242, "The password of this user has expired." },
  {2243, "The password of this user cannot change." },
  {2244, "This password cannot be used now (password history conflict)." },
  {2245, "The password is shorter than required." },
  {2246, "The password of this user is too recent to change."},
  {0, NULL}
};

/******************************************************
 Return an error message for a remote password change.
*******************************************************/

char *get_error_message(struct cli_state *cli)
{
  static fstring error_message;
  int errclass;
  int errnum;
  int i;

  /*
   * Errors are of two kinds - smb errors,
   * dealt with by cli_errstr, and rap
   * errors, whose error code is in cli.error.
   */

  cli_error(cli, &errclass, &errnum);
  if(errclass != 0)
    return cli_errstr(cli);

  sprintf(error_message, "code %d", cli->error);

  for(i = 0; pw_change_errmap[i].message != NULL; i++) {
    if (pw_change_errmap[i].err == cli->error) {
      fstrcpy( error_message, pw_change_errmap[i].message);
      break;
    }
  }

  return error_message;
}

/******************************************************
 Convert a hex password.
*******************************************************/

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

/******************************************************
 Find a password entry by name.
*******************************************************/

static struct smb_passwd *
_my_get_smbpwnam(FILE * fp, char *name, BOOL * valid_old_pwd, 
		BOOL *got_valid_nt_entry, BOOL *got_valid_last_change_time, long *pwd_seekpos)
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

        pw_buf.acct_ctrl = ACB_NORMAL;
        *got_valid_last_change_time = False;
        *got_valid_nt_entry = False;
        *valid_old_pwd = False;

	/*
	 * Scan the file, a line at a time and check if the name matches.
	 */
	while (!feof(fp)) {
		linebuf[0] = '\0';
		*pwd_seekpos = ftell(fp);

		fgets(linebuf, 256, fp);
		if (ferror(fp))
			return NULL;

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

		if ((linebuf[0] == 0) && feof(fp))
			break;
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
			continue;
		p = (unsigned char *) strchr(linebuf, ':');
		if (p == NULL)
			continue;
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
		if (!isdigit(*p))
			return (False);

		uidval = atoi((char *) p);
		while (*p && isdigit(*p))
			p++;

		if (*p != ':')
			return (False);

		/*
		 * Now get the password value - this should be 32 hex digits
		 * which are the ascii representations of a 16 byte string.
		 * Get two at a time and put them into the password.
		 */
		p++;
		*pwd_seekpos += PTR_DIFF(p, linebuf);	/* Save exact position
							 * of passwd in file -
							 * this is used by
							 * smbpasswd.c */
		if (*p == '*' || *p == 'X') {
			/* Password deliberately invalid - end here. */
			*valid_old_pwd = False;
			*got_valid_nt_entry = False;
			pw_buf.smb_nt_passwd = NULL;	/* No NT password (yet)*/

                        pw_buf.acct_ctrl |= ACB_DISABLED;

			/* Now check if the NT compatible password is
			   available. */
			p += 33; /* Move to the first character of the line after 
						the lanman password. */
			if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':')) {
				/* NT Entry was valid - even if 'X' or '*', can be overwritten */
				*got_valid_nt_entry = True;
				if (*p != '*' && *p != 'X') {
				  if (gethexpwd((char *)p,(char *)smbntpwd))
				    pw_buf.smb_nt_passwd = smbntpwd;
				}
			}
			pw_buf.smb_name = user_name;
			pw_buf.smb_userid = uidval;
			pw_buf.smb_passwd = NULL;	/* No password */
			return (&pw_buf);
		}
		if (linebuf_len < (PTR_DIFF(p, linebuf) + 33))
			return (False);

		if (p[32] != ':')
			return (False);

		if (!strncasecmp((char *)p, "NO PASSWORD", 11)) {
		  pw_buf.smb_passwd = NULL;	/* No password */
                  pw_buf.acct_ctrl |= ACB_PWNOTREQ;
		} else {
		  if(!gethexpwd((char *)p,(char *)smbpwd))
		    return False;
		  pw_buf.smb_passwd = smbpwd;
		}

		pw_buf.smb_name = user_name;
		pw_buf.smb_userid = uidval;
		pw_buf.smb_nt_passwd = NULL;
		*got_valid_nt_entry = False;
		*valid_old_pwd = True;

		/* Now check if the NT compatible password is
		   available. */
		p += 33; /* Move to the first character of the line after 
					the lanman password. */
		if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':')) {
			/* NT Entry was valid - even if 'X' or '*', can be overwritten */
			*got_valid_nt_entry = True;
			if (*p != '*' && *p != 'X') {
			  if (gethexpwd((char *)p,(char *)smbntpwd))
			    pw_buf.smb_nt_passwd = smbntpwd;
			}

                        p += 33; /* Move to the first character of the line after
                                    the NT password. */
		}

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
                        *got_valid_last_change_time = True;
                      } /* i == 8 */
                    } /* *p && StrnCaseCmp() */
                  } /* *p == ':' */
 
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
	return NULL;
}

/**********************************************************
 Allocate an unused uid in the smbpasswd file to a new
 machine account.
***********************************************************/

int get_new_machine_uid(void)
{
  int next_uid_start;
  void *vp;
  struct smb_passwd *smbpw;

  if(sizeof(uid_t) == 2)
    next_uid_start = 65533;

  if(sizeof(uid_t) == 4)
    next_uid_start = 0x7fffffff;

  vp = startsmbpwent(False);
  while((smbpw = getsmbpwent(vp)) != NULL) {
    if((smbpw->acct_ctrl & (ACB_SVRTRUST|ACB_WSTRUST)))
      next_uid_start = MIN(next_uid_start, (smbpw->smb_userid-1));
  }
  endsmbpwent(vp);
  return next_uid_start;
}

/*********************************************************
 Print command usage on stderr and die.
**********************************************************/

static void usage(char *name, BOOL is_root)
{
	if(is_root)
		fprintf(stderr, "Usage is : %s [-D DEBUGLEVEL] [-a] [-d] [-m] [-n] [username] [password]\n\
%s: [-R <name resolve order>] [-D DEBUGLEVEL] [-r machine] [username] [password]\n%s: [-h]\n", name, name, name);
	else
		fprintf(stderr, "Usage is : %s [-h] [-D DEBUGLEVEL] [-r machine] [password]\n", name);
	exit(1);
}

/*********************************************************
 Start here.
**********************************************************/

int main(int argc, char **argv)
{
  extern char *optarg;
  extern int optind;
  extern int DEBUGLEVEL;
  char *prog_name;
  int             real_uid;
  struct passwd  *pwd;
  struct passwd   machine_account_pwd;
  fstring         old_passwd;
  fstring         new_passwd;
  uchar           new_p16[16];
  uchar           new_nt_p16[16];
  char           *p;
  struct smb_passwd *smb_pwent;
  FILE           *fp;
  BOOL            valid_old_pwd = False;
  BOOL		 got_valid_nt_entry = False;
  long            seekpos;
  int             pwfd;
  pstring         ascii_p16;
  char            c;
  int             ch;
  int             ret, i, err, writelen;
  int             lockfd = -1;
  char           *pfile = SMB_PASSWD_FILE;
  char            readbuf[16 * 1024];
  BOOL is_root = False;
  pstring  user_name;
  pstring  machine_dir_name;
  char *remote_machine = NULL;
  BOOL		 add_user = False;
  BOOL		 got_new_pass = False;
  BOOL		 got_valid_last_change_time = False;
  BOOL		 machine_account = False;
  BOOL		 disable_user = False;
  BOOL		 set_no_password = False;
  pstring servicesf = CONFIGFILE;

  new_passwd[0] = '\0';
  user_name[0] = '\0';

  memset(old_passwd, '\0', sizeof(old_passwd));
  memset(new_passwd, '\0', sizeof(new_passwd));

  prog_name = argv[0];

  TimeInit();

  setup_logging(prog_name,True);
  
  charset_initialise();

  if (!lp_load(servicesf,True,False,False)) {
    fprintf(stderr, "%s: Can't load %s - run testparm to debug it\n", prog_name, servicesf);
  }
    
  codepage_initialise(lp_client_code_page());

  /* Get the real uid */
  real_uid = getuid();
  
  /* Check the effective uid */
  if ((geteuid() == 0) && (real_uid != 0)) {
    fprintf(stderr, "%s: Must *NOT* be setuid root.\n", prog_name);
    exit(1);
  }

  is_root = (real_uid == 0);

  while ((ch = getopt(argc, argv, "adhmnr:R:D:")) != EOF) {
    switch(ch) {
    case 'a':
      if(is_root)
        add_user = True;
      else
        usage(prog_name, is_root);
      break;
    case 'd':
      if(is_root) {
        disable_user = True;
        got_new_pass = True;
        strcpy(new_passwd, "XXXXXX");
      } else
        usage(prog_name, is_root);
      break;
    case 'D':
      DEBUGLEVEL = atoi(optarg);
      break;
    case 'n':
      if(is_root) {
        set_no_password = True;
        got_new_pass = True;
        strcpy(new_passwd, "NO PASSWORD");
      } else
        usage(prog_name, is_root);
    case 'r':
      remote_machine = optarg;
      break;
    case 'R':
      if(is_root) {
        lp_set_name_resolve_order(optarg);
        break;
      } else
        usage(prog_name, is_root);
    case 'm':
      if(is_root) {
        machine_account = True;
      } else
        usage(prog_name, is_root);
      break;
    case 'h':
    default:
      usage(prog_name, is_root);
    }
  }

  argc -= optind;
  argv += optind;

  /*
   * Ensure add_user and remote machine are
   * not both set.
   */
  if(add_user && (remote_machine != NULL))
    usage(prog_name, True);

  if( is_root ) {

    /*
     * Deal with root - can add a user, but only locally.
     */

    switch(argc) {
      case 0:
        break;
      case 1:
        /* If we are root we can change another's password. */
        pstrcpy(user_name, argv[0]);
        break;
      case 2:
        pstrcpy(user_name, argv[0]);
        fstrcpy(new_passwd, argv[1]);
        got_new_pass = True;
        break;
      default:
        usage(prog_name, True);
    }

    if(*user_name) {
      if((pwd = getpwnam(user_name)) == NULL) {
        fprintf(stderr, "%s: User \"%s\" was not found in system password file.\n", 
                    prog_name, user_name);
        exit(1);
      }
    } else {
      if((pwd = getpwuid(real_uid)) != NULL)
        pstrcpy( user_name, pwd->pw_name);
    }

  } else {

    if(add_user) {
      fprintf(stderr, "%s: Only root can set anothers password.\n", prog_name);
      usage(prog_name, False);
    }

    if(argc > 1)
      usage(prog_name, False);

    if(argc == 1) {
      fstrcpy(new_passwd, argv[0]);
      got_new_pass = True;
    }

    if((pwd = getpwuid(real_uid)) != NULL)
      pstrcpy( user_name, pwd->pw_name);

    /*
     * A non-root user is always setting a password
     * via a remote machine (even if that machine is
     * localhost).
     */

    if(remote_machine == NULL)
      remote_machine = "127.0.0.1";
  }    
    
  if (*user_name == '\0') {
    fprintf(stderr, "%s: Unable to get a user name for password change.\n", prog_name);
    exit(1);
  }

  /*
   * If we are adding a machine account then pretend
   * we already have the new password, we will be using
   * the machinename as the password.
   */

  if(add_user && machine_account) {
    got_new_pass = True;
    strncpy(new_passwd, user_name, sizeof(fstring));
    new_passwd[sizeof(fstring)-1] = '\0';
    strlower(new_passwd);
  }

  /* 
   * If we are root we don't ask for the old password (unless it's on a
   * remote machine.
   */

  if (remote_machine != NULL) {
    p = getpass("Old SMB password:");
    fstrcpy(old_passwd, p);
  }

  if (!got_new_pass) {
    new_passwd[0] = '\0';

    p = getpass("New SMB password:");

    strncpy(new_passwd, p, sizeof(fstring));
    new_passwd[sizeof(fstring)-1] = '\0';

    p = getpass("Retype new SMB password:");

    if (strncmp(p, new_passwd, sizeof(fstring)-1))
    {
      fprintf(stderr, "%s: Mismatch - password unchanged.\n", prog_name);
      exit(1);
    }
  }
  
  if (new_passwd[0] == '\0') {
    printf("Password not set\n");
    exit(0);
  }
 
  /* 
   * Now do things differently depending on if we're changing the
   * password on a remote machine. Remember - a normal user is
   * always using this code, looping back to the local smbd.
   */

  if(remote_machine != NULL) {
    struct cli_state cli;
    struct in_addr ip;
    fstring myname;

    if(get_myname(myname,NULL) == False) {
      fprintf(stderr, "%s: unable to get my hostname.\n", prog_name );
      exit(1);
    }

    if(!resolve_name( remote_machine, &ip)) {
      fprintf(stderr, "%s: unable to find an IP address for machine %s.\n",
              prog_name, remote_machine );
      exit(1);
    }
 
    memset(&cli, '\0', sizeof(struct cli_state));
 
    if (!cli_initialise(&cli) || !cli_connect(&cli, remote_machine, &ip)) {
      fprintf(stderr, "%s: unable to connect to SMB server on machine %s. Error was : %s.\n",
              prog_name, remote_machine, get_error_message(&cli) );
      exit(1);
    }
  
    if (!cli_session_request(&cli, remote_machine, 0x20, myname)) {
      fprintf(stderr, "%s: machine %s rejected the session setup. Error was : %s.\n",
              prog_name, remote_machine, get_error_message(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }
  
    cli.protocol = PROTOCOL_NT1;

    if (!cli_negprot(&cli)) {
      fprintf(stderr, "%s: machine %s rejected the negotiate protocol. Error was : %s.\n",        
              prog_name, remote_machine, get_error_message(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }
  
    if (!cli_session_setup(&cli, user_name, old_passwd, strlen(old_passwd),
                           "", 0, "")) {
      fprintf(stderr, "%s: machine %s rejected the session setup. Error was : %s.\n",        
              prog_name, remote_machine, get_error_message(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }               

    if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1)) {
      fprintf(stderr, "%s: machine %s rejected the tconX on the IPC$ share. Error was : %s.\n",
              prog_name, remote_machine, get_error_message(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }

    if(!cli_oem_change_password(&cli, user_name, new_passwd, old_passwd)) {
      fprintf(stderr, "%s: machine %s rejected the password change: Error was : %s.\n",
              prog_name, remote_machine, get_error_message(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }

    cli_shutdown(&cli);
    exit(0);
  }

  /*
   * Check for a machine account flag - make sure the username ends in
   * a '$' etc....
   */

  if(machine_account) {
    int username_len = strlen(user_name);
    if(username_len >= sizeof(pstring) - 1) {
      fprintf(stderr, "%s: machine account name too long.\n", user_name);
      exit(1);
    }

    if(user_name[username_len] != '$') {
      user_name[username_len] = '$';
      user_name[username_len+1] = '\0';
    }

    /*
     * Setup the pwd struct to point to known
     * values for a machine account (it doesn't
     * exist in /etc/passwd).
     */

    pwd = &machine_account_pwd;
    pwd->pw_name = user_name;
    sprintf(machine_dir_name, "Workstation machine account for %s", user_name);
    pwd->pw_gecos = "";
    pwd->pw_dir = machine_dir_name;
    pwd->pw_shell = "";
    pwd->pw_uid = get_new_machine_uid();
      
  }

  /* Calculate the MD4 hash (NT compatible) of the new password. */
  
  memset(new_nt_p16, '\0', 16);
  E_md4hash((uchar *) new_passwd, new_nt_p16);
  
  /* Mangle the password into Lanman format */
  new_passwd[14] = '\0';
  strupper(new_passwd);
  
  /*
   * Calculate the SMB (lanman) hash functions of the new password.
   */
  
  memset(new_p16, '\0', 16);
  E_P16((uchar *) new_passwd, new_p16);
  
  /*
   * Open the smbpaswd file XXXX - we need to parse smb.conf to get the
   * filename
   */
  fp = fopen(pfile, "r+");
  if (!fp && errno == ENOENT) {
	  fp = fopen(pfile, "w");
	  if (fp) {
		  fprintf(fp, "# Samba SMB password file\n");
		  fclose(fp);
		  fp = fopen(pfile, "r+");
	  }
  }
  if (!fp) {
	  err = errno;
	  fprintf(stderr, "%s: Failed to open password file %s.\n",
		  prog_name, pfile);
	  errno = err;
	  perror(prog_name);
	  exit(err);
  }
  
  /* Set read buffer to 16k for effiecient reads */
  setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));
  
  /* make sure it is only rw by the owner */
  chmod(pfile, 0600);

  /* Lock the smbpasswd file for write. */
  if ((lockfd = pw_file_lock(fileno(fp), F_WRLCK, 5)) < 0) {
    err = errno;
    fprintf(stderr, "%s: Failed to lock password file %s.\n",
	    prog_name, pfile);
    fclose(fp);
    errno = err;
    perror(prog_name);
    exit(err);
  }

  /* Get the smb passwd entry for this user */
  smb_pwent = _my_get_smbpwnam(fp, user_name, &valid_old_pwd, 
                    &got_valid_nt_entry, &got_valid_last_change_time, &seekpos);
  if (smb_pwent == NULL) {
    if(add_user == False) {
      fprintf(stderr, "%s: Failed to find entry for user %s in file %s.\n",
  	      prog_name, pwd->pw_name, pfile);
      fclose(fp);
      pw_file_unlock(lockfd);
      exit(1);
    }

    /* Create a new smb passwd entry and set it to the given password. */
    {
      int fd;
      int new_entry_length;
      char *new_entry;
      long offpos;
      uint16 acct_ctrl = (machine_account ? ACB_WSTRUST : ACB_NORMAL);

      /* The add user write needs to be atomic - so get the fd from 
         the fp and do a raw write() call.
       */
      fd = fileno(fp);

      if((offpos = lseek(fd, 0, SEEK_END)) == -1) {
        fprintf(stderr, "%s: Failed to add entry for user %s to file %s. \
Error was %s\n", prog_name, user_name, pfile, strerror(errno));
        fclose(fp);
        pw_file_unlock(lockfd);
        exit(1);
      }

      new_entry_length = strlen(user_name) + 1 + 15 + 1 + 
                         32 + 1 + 32 + 1 + sizeof(fstring) + 
                         1 + 13 + 
                         1 + strlen(pwd->pw_dir) + 1 + 
                         strlen(pwd->pw_shell) + 1;
      if((new_entry = (char *)malloc( new_entry_length )) == 0) {
        fprintf(stderr, "%s: Failed to add entry for user %s to file %s. \
Error was %s\n", prog_name, pwd->pw_name, pfile, strerror(errno));
        pw_file_unlock(lockfd);
        fclose(fp);
        exit(1);
      }

      sprintf(new_entry, "%s:%u:", pwd->pw_name, (unsigned)pwd->pw_uid);
      p = &new_entry[strlen(new_entry)];
      if(disable_user) {
        memcpy(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32);
        p += 32;
        *p++ = ':';
        memcpy(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32);
      } else if (set_no_password) {
        memcpy(p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", 32);
        p += 32;
        *p++ = ':';
        memcpy(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32);
      } else {
        for( i = 0; i < 16; i++)
          sprintf(&p[i*2], "%02X", new_p16[i]);
        p += 32;
        *p++ = ':';
        for( i = 0; i < 16; i++)
          sprintf(&p[i*2], "%02X", new_nt_p16[i]);
      }
      p += 32;
      *p++ = ':';
      sprintf(p, "%s:TLC-%08X:%s:%s\n", encode_acct_ctrl(acct_ctrl),
              (uint32)time(NULL), pwd->pw_dir, pwd->pw_shell);
      if(write(fd, new_entry, strlen(new_entry)) != strlen(new_entry)) {
        fprintf(stderr, "%s: Failed to add entry for user %s to file %s. \
Error was %s\n", prog_name, pwd->pw_name, pfile, strerror(errno));
        /* Remove the entry we just wrote. */
        if(ftruncate(fd, offpos) == -1) {
          fprintf(stderr, "%s: ERROR failed to ftruncate file %s. \
Error was %s. Password file may be corrupt ! Please examine by hand !\n", 
                   prog_name, pwd->pw_name, strerror(errno));
        }
        pw_file_unlock(lockfd);
        fclose(fp);
        exit(1);
      }
      
      pw_file_unlock(lockfd);  
      fclose(fp);  
      exit(0);
    }
  } else {
	  /* the entry already existed */
	  add_user = False;
  }

  /*
   * We are root - just write the new password
   * and the valid last change time.
   */

  /* Create the 32 byte representation of the new p16 */
  if(disable_user) {
    memcpy(ascii_p16, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32);
  } else if (set_no_password) {
    memcpy(ascii_p16, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", 32);
  } else {
    for (i = 0; i < 16; i++) {
      sprintf(&ascii_p16[i * 2], "%02X", (uchar) new_p16[i]);
    }
  }
  if(got_valid_nt_entry) {
    /* Add on the NT md4 hash */
    ascii_p16[32] = ':';
    if(disable_user) {
      memcpy(&ascii_p16[33], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32);
    } else if (set_no_password) {
      memcpy(&ascii_p16[33], "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32);
    } else {
      for (i = 0; i < 16; i++) {
        sprintf(&ascii_p16[(i * 2)+33], "%02X", (uchar) new_nt_p16[i]);
      }
    }
  }
  ascii_p16[65] = ':';
  ascii_p16[66] = '\0';
  if(got_valid_last_change_time) {
    strcpy(&ascii_p16[66], encode_acct_ctrl(smb_pwent->acct_ctrl));
    sprintf(&ascii_p16[strlen(ascii_p16)], ":TLC-%08X", (uint32)time(NULL));
  }

  /*
   * Do an atomic write into the file at the position defined by
   * seekpos.
   */
  pwfd = fileno(fp);
  ret = lseek(pwfd, seekpos - 1, SEEK_SET);
  if (ret != seekpos - 1) {
    err = errno;
    fprintf(stderr, "%s: seek fail on file %s.\n",
	    prog_name, pfile);
    errno = err;
    perror(prog_name);
    pw_file_unlock(lockfd);
    fclose(fp);
    exit(1);
  }
  /* Sanity check - ensure the character is a ':' */
  if (read(pwfd, &c, 1) != 1) {
    err = errno;
    fprintf(stderr, "%s: read fail on file %s.\n",
	    prog_name, pfile);
    errno = err;
    perror(prog_name);
    pw_file_unlock(lockfd);
    fclose(fp);
    exit(1);
  }
  if (c != ':') {
    fprintf(stderr, "%s: sanity check on passwd file %s failed.\n",
	    prog_name, pfile);
    pw_file_unlock(lockfd);
    fclose(fp);
    exit(1);
  }
  writelen = (got_valid_nt_entry) ? 
              ( got_valid_last_change_time ? strlen(ascii_p16) : 65) : 32;
  if (write(pwfd, ascii_p16, writelen) != writelen) {
    err = errno;
    fprintf(stderr, "%s: write fail in file %s.\n",
	    prog_name, pfile);
    errno = err;
    perror(prog_name);
    pw_file_unlock(lockfd);
    fclose(fp);
    exit(err);
  }
  pw_file_unlock(lockfd);
  fclose(fp);
  if(disable_user)
    printf("User %s disabled.\n", user_name);
  else if (set_no_password)
    printf("User %s - set to no password.\n", user_name);
  else
    printf("Password changed for user %s.\n", user_name);
  return 0;
}
