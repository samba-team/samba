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
  fstring         old_passwd;
  fstring         new_passwd;
  uchar           new_p16[16];
  uchar           new_nt_p16[16];
  char           *p;
  struct smb_passwd *smb_pwent;
  FILE           *fp;
  int             ch;
  int             err;
  BOOL is_root = False;
  pstring  user_name;
  char *remote_machine = NULL;
  BOOL		 add_user = False;
  BOOL		 got_new_pass = False;
  BOOL		 machine_account = False;
  BOOL		 disable_user = False;
  BOOL		 set_no_password = False;
  pstring servicesf = CONFIGFILE;
  void           *vp;

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

      if(machine_account) {
        int username_len = strlen(user_name);
        if(username_len >= sizeof(pstring) - 1) {
          fprintf(stderr, "%s: machine account name too long.\n", user_name);
          exit(1);
        }

        if(user_name[username_len-1] != '$') {
          user_name[username_len] = '$';
          user_name[username_len+1] = '\0';
        }
      }

    /*
     * Setup the pwd struct to point to known
     * values for a machine account (it doesn't
     * exist in /etc/passwd).
     */
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
    if(new_passwd[strlen(new_passwd)-1] == '$')
      new_passwd[strlen(new_passwd)-1] = '\0';
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
              prog_name, remote_machine, cli_errstr(&cli) );
      exit(1);
    }
  
    if (!cli_session_request(&cli, remote_machine, 0x20, myname)) {
      fprintf(stderr, "%s: machine %s rejected the session setup. Error was : %s.\n",
              prog_name, remote_machine, cli_errstr(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }
  
    cli.protocol = PROTOCOL_NT1;

    if (!cli_negprot(&cli)) {
      fprintf(stderr, "%s: machine %s rejected the negotiate protocol. Error was : %s.\n",        
              prog_name, remote_machine, cli_errstr(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }
  
    if (!cli_session_setup(&cli, user_name, old_passwd, strlen(old_passwd),
                           "", 0, "")) {
      fprintf(stderr, "%s: machine %s rejected the session setup. Error was : %s.\n",        
              prog_name, remote_machine, cli_errstr(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }               

    if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1)) {
      fprintf(stderr, "%s: machine %s rejected the tconX on the IPC$ share. Error was : %s.\n",
              prog_name, remote_machine, cli_errstr(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }

    if(!cli_oem_change_password(&cli, user_name, new_passwd, old_passwd)) {
      fprintf(stderr, "%s: machine %s rejected the password change: Error was : %s.\n",
              prog_name, remote_machine, cli_errstr(&cli) );
      cli_shutdown(&cli);
      exit(1);
    }

    cli_shutdown(&cli);
    exit(0);
  }

  /*
   * Check for a machine account.
   */

  if(machine_account && !pwd) {
    fprintf(stderr, "%s: User %s does not exist in system password file \
(usually /etc/passwd). Cannot add machine account without a valid system user.\n",
           prog_name, user_name);
    exit(1);
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
   * Open the smbpaswd file.
   */
  vp = startsmbpwent(True);
  if (!vp && errno == ENOENT) {
	  fp = fopen(lp_smb_passwd_file(), "w");
	  if (fp) {
		  fprintf(fp, "# Samba SMB password file\n");
		  fclose(fp);
		  vp = startsmbpwent(True);
	  }
  }
  if (!fp) {
	  err = errno;
	  fprintf(stderr, "%s: Failed to open password file %s.\n",
		  prog_name, lp_smb_passwd_file());
	  errno = err;
	  perror(prog_name);
	  exit(err);
  }
  
  /* Get the smb passwd entry for this user */
  smb_pwent = getsmbpwnam(user_name);
  if (smb_pwent == NULL) {
    if(add_user == False) {
      fprintf(stderr, "%s: Failed to find entry for user %s.\n",
  	      prog_name, pwd->pw_name);
      endsmbpwent(vp);
      exit(1);
    }

    /* Create a new smb passwd entry and set it to the given password. */
    {
      struct smb_passwd new_smb_pwent;

      new_smb_pwent.smb_userid = pwd->pw_uid;
      new_smb_pwent.smb_name = pwd->pw_name; 
      new_smb_pwent.smb_passwd = NULL;
      new_smb_pwent.smb_nt_passwd = NULL;
      new_smb_pwent.acct_ctrl = (machine_account ? ACB_WSTRUST : ACB_NORMAL);

      if(disable_user) {
        new_smb_pwent.acct_ctrl |= ACB_DISABLED;
      } else if (set_no_password) {
        new_smb_pwent.acct_ctrl |= ACB_PWNOTREQ;
      } else {
        new_smb_pwent.smb_passwd = new_p16;
        new_smb_pwent.smb_nt_passwd = new_nt_p16;
      }

      if(add_smbpwd_entry(&new_smb_pwent) == False) {
        fprintf(stderr, "%s: Failed to add entry for user %s.\n", 
                prog_name, pwd->pw_name);
        endsmbpwent(vp);
        exit(1);
      }
      
      endsmbpwent(vp);
      printf("%s: Added user %s.\n", prog_name, user_name);
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

  if(disable_user) {
    /*
     * This currently won't work as it means changing
     * the length of the record. JRA.
     */
    smb_pwent->acct_ctrl |= ACB_DISABLED;
    smb_pwent->smb_passwd = NULL;
    smb_pwent->smb_nt_passwd = NULL;
  } else if (set_no_password) {
    /*
     * This currently won't work as it means changing
     * the length of the record. JRA.
     */
    smb_pwent->acct_ctrl |= ACB_PWNOTREQ;
    smb_pwent->smb_passwd = NULL;
    smb_pwent->smb_nt_passwd = NULL; 
  } else {
    smb_pwent->smb_passwd = new_p16;
    smb_pwent->smb_nt_passwd = new_nt_p16;
  }

  if(mod_smbpwd_entry(smb_pwent) == False) {
    fprintf(stderr, "%s: Failed to modify entry for user %s.\n",
            prog_name, pwd->pw_name);
    endsmbpwent(vp);
    exit(1);
  }

  endsmbpwent(vp);
  if(disable_user)
    printf("User %s disabled.\n", user_name);
  else if (set_no_password)
    printf("User %s - set to no password.\n", user_name);
  else
    printf("Password changed for user %s.\n", user_name);
  return 0;
}
