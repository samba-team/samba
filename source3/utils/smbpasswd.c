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

extern pstring scope;
extern pstring myhostname;
extern pstring global_myname;
extern fstring global_myworkgroup;

static char *prog_name;

/*********************************************************
 Print command usage on stderr and die.
**********************************************************/

static void usage(char *name, BOOL is_root)
{
	if(is_root)
		fprintf(stderr, "Usage is : %s [-D DEBUGLEVEL] [-a] [-d] [-e] [-m] [-n] [username] [password]\n\
%s: [-R <name resolve order>] [-D DEBUGLEVEL] [-j DOMAINNAME] [-r machine] [-U remote_username] [username] [password]\n%s: [-h]\n", name, name, name);
	else
		fprintf(stderr, "Usage is : %s [-h] [-D DEBUGLEVEL] [-r machine] [-U remote_username] [password]\n", name);
	exit(1);
}

/*********************************************************
Join a domain.
**********************************************************/

static int join_domain( char *domain, char *remote)
{
  pstring remote_machine;
  fstring trust_passwd;
  unsigned char orig_trust_passwd_hash[16];
  BOOL ret;

  pstrcpy(remote_machine, remote ? remote : "");
  fstrcpy(trust_passwd, global_myname);
  strlower(trust_passwd);
  E_md4hash( (uchar *)trust_passwd, orig_trust_passwd_hash);

  /* Ensure that we are not trying to join a
     domain if we are locally set up as a domain
     controller. */

  if(lp_domain_controller() && strequal(lp_workgroup(), domain)) {
    fprintf(stderr, "%s: Cannot join domain %s as we already configured as \
domain controller for that domain.\n", prog_name, domain);
    return 1;
  }

  /*
   * Create the machine account password file.
   */
  if(!trust_password_lock( domain, global_myname, True)) {
    fprintf(stderr, "%s: unable to open the machine account password file for \
machine %s in domain %s.\n", prog_name, global_myname, domain); 
    return 1;
  }

  /*
   * Write the old machine account password.
   */

  if(!set_trust_account_password( orig_trust_passwd_hash)) {              
    fprintf(stderr, "%s: unable to write the machine account password for \
machine %s in domain %s.\n", prog_name, global_myname, domain);
    trust_password_unlock();
    return 1;
  }

  /*
   * If we are given a remote machine assume this is the PDC.
   */

  if(remote == NULL)
    pstrcpy(remote_machine, lp_passwordserver());

  if(!*remote_machine) {
    fprintf(stderr, "%s: No password server list given in smb.conf - \
unable to join domain.\n", prog_name);
    trust_password_unlock();
    return 1;
  }

  ret = change_trust_account_password( domain, remote_machine);
  trust_password_unlock();

  if(!ret) {
    trust_password_delete( domain, global_myname);
    fprintf(stderr,"%s: Unable to join domain %s.\n", prog_name, domain);
  } else {
    printf("%s: Joined domain %s.\n", prog_name, domain);
  }

  return (int)ret;
}

/*************************************************************
 Utility function to prompt for new password.
*************************************************************/

static void prompt_for_new_password(char *new_passwd)
{
  char *p;

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

  if (new_passwd[0] == '\0') {
    printf("Password not set\n");
    exit(0);
  }
}

/*********************************************************
 Start here.
**********************************************************/

int main(int argc, char **argv)
{
  extern char *optarg;
  extern int optind;
  extern int DEBUGLEVEL;
  int             real_uid;
  struct passwd  *pwd = NULL;
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
  BOOL remote_user_name = False;
  char *remote_machine = NULL;
  BOOL add_user = False;
  BOOL got_new_pass = False;
  BOOL trust_account = False;
  BOOL disable_user = False;
  BOOL enable_user = False;
  BOOL set_no_password = False;
  BOOL joining_domain = False;
  char *new_domain = NULL;
  pstring servicesf = CONFIGFILE;
  void           *vp;
	struct nmb_name calling, called;
  

  new_passwd[0] = '\0';
  user_name[0] = '\0';

  memset(old_passwd, '\0', sizeof(old_passwd));
  memset(new_passwd, '\0', sizeof(new_passwd));

  prog_name = argv[0];

  TimeInit();

  setup_logging(prog_name,True);
  
  charset_initialise();

  if(!initialize_password_db()) {
    fprintf(stderr, "%s: Can't setup password database vectors.\n", prog_name);
    exit(1);
  }

  if (!lp_load(servicesf,True,False,False)) {
    fprintf(stderr, "%s: Can't load %s - run testparm to debug it\n", prog_name, servicesf);
    exit(1);
  }

  if(!get_myname(myhostname,NULL)) {
    fprintf(stderr, "%s: unable to get my hostname.\n", prog_name );
    exit(1);
  }

  /*
   * Set the machine NETBIOS name if not already
   * set from the config file. 
   */ 
    
  if (!*global_myname)
  {   
    fstrcpy( global_myname, myhostname );
    p = strchr( global_myname, '.' );
    if (p) 
      *p = 0;
  }           
  strupper( global_myname );

  codepage_initialise(lp_client_code_page());

  /* Get the real uid */
  real_uid = getuid();
  
  /* Check the effective uid */
  if ((geteuid() == 0) && (real_uid != 0)) {
    fprintf(stderr, "%s: Must *NOT* be setuid root.\n", prog_name);
    exit(1);
  }

  is_root = (real_uid == 0);

  while ((ch = getopt(argc, argv, "adehmnj:r:R:D:U:")) != EOF) {
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
        fstrcpy(new_passwd, "XXXXXX");
      } else
        usage(prog_name, is_root);
      break;
    case 'e':
      if(is_root) {
        enable_user = True;
        got_new_pass = True;
        fstrcpy(new_passwd, "XXXXXX");
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
        fstrcpy(new_passwd, "NO PASSWORD");
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
        trust_account = True;
      } else
        usage(prog_name, is_root);
      break;
    case 'j':
      if(is_root) {
        new_domain = optarg;
        strupper(new_domain);
        joining_domain = True;
      } else
        usage(prog_name, is_root);  
      break;
    case 'U':
      remote_user_name = True;
      pstrcpy(user_name, optarg);
      break;
    case 'h':
    default:
      usage(prog_name, is_root);
    }
  }

  argc -= optind;
  argv += optind;

  if (!is_root && remote_user_name && !remote_machine) {
    fprintf(stderr, "%s: You can only use -U with -r.\n", prog_name);
    usage(prog_name, False);
  }

  /*
   * Ensure add_user and either remote machine or join domain are
   * not both set.
   */

  if(add_user && ((remote_machine != NULL) || joining_domain))
    usage(prog_name, True);

  /*
   * Deal with joining a domain.
   */
  if(joining_domain && argc != 0)
    usage(prog_name, True);

  if(joining_domain) {
    return join_domain( new_domain, remote_machine);
  }

  if(is_root) {

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

      if(trust_account) {
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

      if(!remote_machine && ((pwd = Get_Pwnam(user_name, True)) == NULL)) {
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
      fprintf(stderr, "%s: Only root can add a user.\n", prog_name);
      usage(prog_name, False);
    }

    if(disable_user) {
      fprintf(stderr, "%s: Only root can disable a user.\n", prog_name);
      usage(prog_name, False);
    }

    if(enable_user) {
      fprintf(stderr, "%s: Only root can enable a user.\n", prog_name);
      usage(prog_name, False);
    }

    if(argc > 1)
      usage(prog_name, False);

    if(argc == 1) {
      fstrcpy(new_passwd, argv[0]);
      got_new_pass = True;
    }

    if(!remote_user_name && ((pwd = getpwuid(real_uid)) != NULL))
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

  if(add_user && trust_account) {
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

  if (!got_new_pass)
    prompt_for_new_password(new_passwd);
  
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

    if(!resolve_name( remote_machine, &ip, 0x20)) {
      fprintf(stderr, "%s: unable to find an IP address for machine %s.\n",
              prog_name, remote_machine );
      exit(1);
    }
 
    ZERO_STRUCT(cli);
 
    if (!cli_initialise(&cli) || !cli_connect(&cli, remote_machine, &ip)) {
      fprintf(stderr, "%s: unable to connect to SMB server on machine %s. Error was : %s.\n",
              prog_name, remote_machine, cli_errstr(&cli) );
      exit(1);
    }
  
	make_nmb_name(&calling, global_myname , 0x0 , scope);
	make_nmb_name(&called , remote_machine, 0x20, scope);

	if (!cli_session_request(&cli, &calling, &called))
	{
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
  
    /*
     * We should connect as the anonymous user here, in case
     * the server has "must change password" checked...
     * Thanks to <Nicholas.S.Jenkins@cdc.com> for this fix.
     */

    if (!cli_session_setup(&cli, "", "", 0, "", 0, "")) {
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

  if(trust_account && !pwd) {
    fprintf(stderr, "%s: User %s does not exist in system password file \
(usually /etc/passwd). Cannot add machine account without a valid system user.\n",
           prog_name, user_name);
    exit(1);
  }

  /* Calculate the MD4 hash (NT compatible) of the new password. */
  
  nt_lm_owf_gen( new_passwd, new_nt_p16, new_p16);

  /*
   * Open the smbpaswd file.
   */
  vp = startsmbpwent(True);
  if (!vp && errno == ENOENT) {
      fprintf(stderr,"%s: smbpasswd file did not exist - attempting to create it.\n", prog_name);
	  fp = fopen(lp_smb_passwd_file(), "w");
	  if (fp) {
		  fprintf(fp, "# Samba SMB password file\n");
		  fclose(fp);
		  vp = startsmbpwent(True);
	  }
  }
  if (!vp) {
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
      new_smb_pwent.acct_ctrl = (trust_account ? ACB_WSTRUST : ACB_NORMAL);

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

  if(disable_user)
    smb_pwent->acct_ctrl |= ACB_DISABLED;
  else if (enable_user) {
    if(smb_pwent->smb_passwd == NULL) {
      prompt_for_new_password(new_passwd);
      nt_lm_owf_gen( new_passwd, new_nt_p16, new_p16);
      smb_pwent->smb_passwd = new_p16;
      smb_pwent->smb_nt_passwd = new_nt_p16;
    }
    smb_pwent->acct_ctrl &= ~ACB_DISABLED;
  } else if (set_no_password) {
    smb_pwent->acct_ctrl |= ACB_PWNOTREQ;
    /* This is needed to preserve ACB_PWNOTREQ in mod_smbfilepwd_entry */
    smb_pwent->smb_passwd = NULL;
    smb_pwent->smb_nt_passwd = NULL;
  } else {
    smb_pwent->acct_ctrl &= ~ACB_PWNOTREQ;
    smb_pwent->smb_passwd = new_p16;
    smb_pwent->smb_nt_passwd = new_nt_p16;
  }

  if(mod_smbpwd_entry(smb_pwent,True) == False) {
    fprintf(stderr, "%s: Failed to modify entry for user %s.\n",
            prog_name, pwd->pw_name);
    endsmbpwent(vp);
    exit(1);
  }

  endsmbpwent(vp);
  if(disable_user)
    printf("User %s disabled.\n", user_name);
  else if(enable_user)
    printf("User %s enabled.\n", user_name);
  else if (set_no_password)
    printf("User %s - set to no password.\n", user_name);
  else
    printf("Password changed for user %s.\n", user_name);
  return 0;
}
