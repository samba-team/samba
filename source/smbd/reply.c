/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
/*
   This file handles most of the reply_ calls that the server
   makes to handle specific protocols
*/


#include "includes.h"

/* look in server.c for some explanation of these variables */
extern int Protocol;
extern int max_send;
extern int max_recv;
extern char magic_char;
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL short_case_preserve;
extern userdom_struct current_user_info;
extern pstring global_myname;
extern fstring global_myworkgroup;
extern int global_oplock_break;
uint32 global_client_caps = 0;
unsigned int smb_echo_count = 0;

/****************************************************************************
 Report a possible attack via the password buffer overflow bug.
****************************************************************************/

static void overflow_attack(int len)
{
	if( DEBUGLVL( 0 ) ) {
		dbgtext( "ERROR: Invalid password length %d.\n", len );
		dbgtext( "Your machine may be under attack by someone " );
		dbgtext( "attempting to exploit an old bug.\n" );
		dbgtext( "Attack was from IP = %s.\n", client_addr() );
	}
}


/****************************************************************************
 Reply to an special message.
****************************************************************************/

int reply_special(char *inbuf,char *outbuf)
{
	int outsize = 4;
	int msg_type = CVAL(inbuf,0);
	int msg_flags = CVAL(inbuf,1);
	pstring name1,name2;
	extern fstring remote_machine;
	extern fstring local_machine;
	int len;
	char name_type = 0;
	
	*name1 = *name2 = 0;
	
	memset(outbuf,'\0',smb_size);

	smb_setlen(outbuf,0);
	
	switch (msg_type) {
	case 0x81: /* session request */
		SCVAL(outbuf,0,0x82);
		SCVAL(outbuf,3,0);
		if (name_len(inbuf+4) > 50 || 
		    name_len(inbuf+4 + name_len(inbuf + 4)) > 50) {
			DEBUG(0,("Invalid name length in session request\n"));
			return(0);
		}
		name_extract(inbuf,4,name1);
		name_extract(inbuf,4 + name_len(inbuf + 4),name2);
		DEBUG(2,("netbios connect: name1=%s name2=%s\n",
			 name1,name2));      

		fstrcpy(remote_machine,name2);
		remote_machine[15] = 0;
		trim_string(remote_machine," "," ");
		strlower(remote_machine);
		alpha_strcpy(remote_machine,remote_machine,SAFE_NETBIOS_CHARS,sizeof(remote_machine)-1);

		fstrcpy(local_machine,name1);
		len = strlen(local_machine);
		if (len == 16) {
			name_type = local_machine[15];
			local_machine[15] = 0;
		}
		trim_string(local_machine," "," ");
		strlower(local_machine);
		alpha_strcpy(local_machine,local_machine,SAFE_NETBIOS_CHARS,sizeof(local_machine)-1);

		DEBUG(2,("netbios connect: local=%s remote=%s\n",
			local_machine, remote_machine ));

		if (name_type == 'R') {
			/* We are being asked for a pathworks session --- 
			   no thanks! */
			SCVAL(outbuf, 0, 0x83);
			break;
		}

		/* add it as a possible user name if we 
		   are in share mode security */
		if (lp_security() == SEC_SHARE) {
			add_session_user(remote_machine);
		}

		reload_services(True);
		reopen_logs();

		if (lp_status(-1))
			claim_connection(NULL,"",0,True);

		break;
		
	case 0x89: /* session keepalive request 
		      (some old clients produce this?) */
		SCVAL(outbuf,0,0x85);
		SCVAL(outbuf,3,0);
		break;
		
	case 0x82: /* positive session response */
	case 0x83: /* negative session response */
	case 0x84: /* retarget session response */
		DEBUG(0,("Unexpected session response\n"));
		break;
		
	case 0x85: /* session keepalive */
	default:
		return(0);
	}
	
	DEBUG(5,("init msg_type=0x%x msg_flags=0x%x\n",
		    msg_type, msg_flags));
	
	return(outsize);
}

/*******************************************************************
 Work out what error to give to a failed connection.
********************************************************************/

static int connection_error(char *outbuf, int ecode)
{
	if (ecode == ERRnoipc || ecode == ERRnosuchshare)
		return(ERROR_DOS(ERRDOS,ecode));
 
	return(ERROR_DOS(ERRSRV,ecode));
}

/****************************************************************************
 Parse a share descriptor string.
****************************************************************************/

static void parse_connect(char *p,char *service,char *user,
			  char *password,int *pwlen,char *dev)
{
  char *p2;

  DEBUG(4,("parsing connect string %s\n",p));
    
  p2 = strrchr(p,'\\');
  if (p2 == NULL)
    fstrcpy(service,p);
  else
    fstrcpy(service,p2+1);
  
  p += strlen(p) + 2;
  
  fstrcpy(password,p);
  *pwlen = strlen(password);

  p += strlen(p) + 2;

  fstrcpy(dev,p);
  
  *user = 0;
  p = strchr(service,'%');
  if (p != NULL)
    {
      *p = 0;
      fstrcpy(user,p+1);
    }
}

/****************************************************************************
 Reply to a tcon.
****************************************************************************/

int reply_tcon(connection_struct *conn,
	       char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	BOOL doencrypt = SMBENCRYPT();
	pstring service;
	pstring user;
	pstring password;
	pstring dev;
	int outsize = 0;
	uint16 vuid = SVAL(inbuf,smb_uid);
	int pwlen=0;
	int ecode = -1;
	START_PROFILE(SMBtcon);

	*service = *user = *password = *dev = 0;

	parse_connect(smb_buf(inbuf)+1,service,user,password,&pwlen,dev);

	/*
	 * If the vuid is valid, we should be using that....
	 */

	if (*user == '\0' && (lp_security() != SEC_SHARE) && validated_username(vuid)) {
		pstrcpy(user,validated_username(vuid));
	}

	/*
	 * Ensure the user and password names are in UNIX codepage format.
	 */

	pstrcpy(user,dos_to_unix_static(user));
	if (!doencrypt)
    	pstrcpy(password,dos_to_unix_static(password));

	/*
	 * Pass the user through the NT -> unix user mapping
	 * function.
	 */
   
	(void)map_username(user);

	/*
	 * Do any UNIX username case mangling.
	 */
	(void)Get_Pwnam( user, True);

	conn = make_connection(service,user,password,pwlen,dev,vuid,&ecode);
  
	if (!conn) {
		END_PROFILE(SMBtcon);
		return(connection_error(outbuf,ecode));
	}
  
	outsize = set_message(outbuf,2,0,True);
	SSVAL(outbuf,smb_vwv0,max_recv);
	SSVAL(outbuf,smb_vwv1,conn->cnum);
	SSVAL(outbuf,smb_tid,conn->cnum);
  
	DEBUG(3,("tcon service=%s user=%s cnum=%d\n", 
		 service, user, conn->cnum));
  
	END_PROFILE(SMBtcon);
	return(outsize);
}

/****************************************************************************
 Reply to a tcon and X.
****************************************************************************/

int reply_tcon_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	fstring service;
	pstring user;
	pstring password;
	pstring devicename;
	BOOL doencrypt = SMBENCRYPT();
	int ecode = -1;
	uint16 vuid = SVAL(inbuf,smb_uid);
	int passlen = SVAL(inbuf,smb_vwv3);
	char *path;
	char *p;
	START_PROFILE(SMBtconX);
	
	*service = *user = *password = *devicename = 0;

	/* we might have to close an old one */
	if ((SVAL(inbuf,smb_vwv2) & 0x1) && conn) {
		close_cnum(conn,vuid);
	}

	if (passlen > MAX_PASS_LEN) {
		overflow_attack(passlen);
		return(ERROR_DOS(ERRDOS,ERRbuftoosmall));
	}
 
	memcpy(password,smb_buf(inbuf),passlen);
	password[passlen]=0;    
	path = smb_buf(inbuf) + passlen;

	if (passlen != 24) {
		if (strequal(password," "))
			*password = 0;
		passlen = strlen(password);
	}

	/*
	 * the service name can be either: \\server\share
	 * or share directly like on the DELL PowerVault 705
	 */
	if (*path=='\\') {	
		p = strchr(path+2,'\\');
		if (!p) {
			END_PROFILE(SMBtconX);
			return(ERROR_DOS(ERRDOS,ERRnosuchshare));
		}
		fstrcpy(service,p+1);
	}
	else
		fstrcpy(service,path);
		
	p = strchr(service,'%');
	if (p) {
		*p++ = 0;
		fstrcpy(user,p);
	}
	StrnCpy(devicename,path + strlen(path) + 1,6);
	DEBUG(4,("Got device type %s\n",devicename));

	/*
	 * If the vuid is valid, we should be using that....
	 */

	if (*user == '\0' && (lp_security() != SEC_SHARE) && validated_username(vuid)) {
		pstrcpy(user,validated_username(vuid));
	}

	/*
	 * Ensure the user and password names are in UNIX codepage format.
	 */

	pstrcpy(user,dos_to_unix_static(user));
	if (!doencrypt)
		pstrcpy(password,dos_to_unix_static(password));

	/*
	 * Pass the user through the NT -> unix user mapping
	 * function.
	 */
	
	(void)map_username(user);
	
	/*
	 * Do any UNIX username case mangling.
	 */
	(void)Get_Pwnam(user, True);
	
	conn = make_connection(service,user,password,passlen,devicename,vuid,&ecode);
	
	if (!conn) {
		END_PROFILE(SMBtconX);
		return(connection_error(outbuf,ecode));
	}

	if (Protocol < PROTOCOL_NT1) {
		set_message(outbuf,2,strlen(devicename)+1,True);
		pstrcpy(smb_buf(outbuf),devicename);
	} else {
		char *fsname = lp_fstype(SNUM(conn));

		set_message(outbuf,3,3,True);

		p = smb_buf(outbuf);
		pstrcpy(p,devicename); p = skip_string(p,1); /* device name */
		pstrcpy(p,fsname); p = skip_string(p,1); /* filesystem type e.g NTFS */
		
		set_message(outbuf,3,PTR_DIFF(p,smb_buf(outbuf)),False);
		
		/* what does setting this bit do? It is set by NT4 and
		   may affect the ability to autorun mounted cdroms */
		SSVAL(outbuf, smb_vwv2, SMB_SUPPORT_SEARCH_BITS|
				(lp_csc_policy(SNUM(conn)) << 2));
		
		init_dfsroot(conn, inbuf, outbuf);
	}

  
	DEBUG(3,("tconX service=%s user=%s\n",
		 service, user));
  
	/* set the incoming and outgoing tid to the just created one */
	SSVAL(inbuf,smb_tid,conn->cnum);
	SSVAL(outbuf,smb_tid,conn->cnum);

	END_PROFILE(SMBtconX);
	return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to an unknown type.
****************************************************************************/

int reply_unknown(char *inbuf,char *outbuf)
{
	int type;
	type = CVAL(inbuf,smb_com);
  
	DEBUG(0,("unknown command type (%s): type=%d (0x%X)\n",
		 smb_fn_name(type), type, type));
  
	return(ERROR_DOS(ERRSRV,ERRunknownsmb));
}

/****************************************************************************
 Reply to an ioctl.
****************************************************************************/

int reply_ioctl(connection_struct *conn,
		char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	uint16 device     = SVAL(inbuf,smb_vwv1);
	uint16 function   = SVAL(inbuf,smb_vwv2);
	uint32 ioctl_code = (device << 16) + function;
	int replysize, outsize;
	char *p;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBioctl);

	DEBUG(4, ("Received IOCTL (code 0x%x)\n", ioctl_code));

	switch (ioctl_code)
	{
	    case IOCTL_QUERY_JOB_INFO:
		replysize = 32;
		break;
	    default:
		END_PROFILE(SMBioctl);
		return(ERROR_DOS(ERRSRV,ERRnosupport));
	}

	outsize = set_message(outbuf,8,replysize+1,True);
	SSVAL(outbuf,smb_vwv1,replysize); /* Total data bytes returned */
	SSVAL(outbuf,smb_vwv5,replysize); /* Data bytes this buffer */
	SSVAL(outbuf,smb_vwv6,52);        /* Offset to data */
	p = smb_buf(outbuf) + 1;          /* Allow for alignment */

	switch (ioctl_code)
	{
	    case IOCTL_QUERY_JOB_INFO:		    
		SSVAL(p,0,fsp->print_jobid);             /* Job number */
		StrnCpy(p+2, global_myname, 15);         /* Our NetBIOS name */
		StrnCpy(p+18, lp_servicename(SNUM(conn)), 13); /* Service name */
		break;
	}

	END_PROFILE(SMBioctl);
	return outsize;
}

/****************************************************************************
 Always return an error: it's just a matter of which one...
 ****************************************************************************/

static int session_trust_account(connection_struct *conn, char *inbuf, char *outbuf, char *user,
                                char *smb_passwd, int smb_passlen,
                                char *smb_nt_passwd, int smb_nt_passlen)
{
	SAM_ACCOUNT *sam_trust_acct = NULL; /* check if trust account exists */
	uint16        acct_ctrl;  

	if (lp_security() == SEC_USER) {
		pdb_init_sam(&sam_trust_acct);
		pdb_getsampwnam(sam_trust_acct, user);
	} else {
		DEBUG(0,("session_trust_account: Trust account %s only supported with security = user\n", user));
		return(ERROR_BOTH(NT_STATUS_LOGON_FAILURE,ERRSRV,ERRbadpw));
	}

	if (sam_trust_acct == NULL) {
		/* lkclXXXX: workstation entry doesn't exist */
		DEBUG(0,("session_trust_account: Trust account %s user doesn't exist\n",user));
		return(ERROR_BOTH(NT_STATUS_NO_SUCH_USER,ERRDOS,1317));
	} else {
		if ((smb_passlen != 24) || (smb_nt_passlen != 24)) {
			DEBUG(0,("session_trust_account: Trust account %s - password length wrong.\n", user));
			pdb_free_sam(sam_trust_acct);
			return(ERROR_BOTH(NT_STATUS_LOGON_FAILURE,ERRSRV,ERRbadpw));
		}

		if (!smb_password_ok(sam_trust_acct, NULL, (unsigned char *)smb_passwd, (unsigned char *)smb_nt_passwd)) {
			DEBUG(0,("session_trust_account: Trust Account %s - password failed\n", user));
			pdb_free_sam(sam_trust_acct);
			return(ERROR_BOTH(NT_STATUS_LOGON_FAILURE,ERRSRV,ERRbadpw));
		}

		acct_ctrl = pdb_get_acct_ctrl(sam_trust_acct);
		if (acct_ctrl & ACB_DOMTRUST) {
			DEBUG(0,("session_trust_account: Domain trust account %s denied by server\n",user));
			pdb_free_sam(sam_trust_acct);
			return(ERROR_BOTH(NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT,ERRDOS,1807));
		}

		if (acct_ctrl & ACB_SVRTRUST) {
			DEBUG(0,("session_trust_account: Server trust account %s denied by server\n",user));
			pdb_free_sam(sam_trust_acct);
			return(ERROR_BOTH(NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT,ERRDOS,1809));
		}

		if (acct_ctrl & ACB_WSTRUST) {
			DEBUG(4,("session_trust_account: Wksta trust account %s denied by server\n", user));
			pdb_free_sam(sam_trust_acct);
			return(ERROR_BOTH(NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT,ERRDOS,1808));
		}
	}

	/* don't know what to do: indicate logon failure */
	pdb_free_sam(sam_trust_acct);
	return(ERROR_BOTH(NT_STATUS_LOGON_FAILURE,ERRDOS,1326));
}

/****************************************************************************
 Create a UNIX user on demand.
****************************************************************************/

int smb_create_user(char *unix_user, char *homedir)
{
	pstring add_script;
	int ret;

	pstrcpy(add_script, lp_adduser_script());
	if (! *add_script)
		return -1;
	all_string_sub(add_script, "%u", unix_user, sizeof(pstring));
	if (homedir)
		all_string_sub(add_script, "%H", homedir, sizeof(pstring));
	ret = smbrun(add_script,NULL);
	DEBUG(3,("smb_create_user: Running the command `%s' gave %d\n",add_script,ret));
	return ret;
}

/****************************************************************************
 Delete a UNIX user on demand.
****************************************************************************/

static int smb_delete_user(char *unix_user)
{
	pstring del_script;
	int ret;

	/*
	 * Sanity check -- do not delete 'root' account
	 */

	if (StrCaseCmp("root", unix_user) == 0) {
		DEBUG(0,("smb_delete_user: Will not delete the [%s] user account!\n", unix_user));
		return -1;
	}

	pstrcpy(del_script, lp_deluser_script());
	if (! *del_script)
		return -1;
	all_string_sub(del_script, "%u", unix_user, sizeof(pstring));
	ret = smbrun(del_script,NULL);
	DEBUG(3,("smb_delete_user: Running the command `%s' gave %d\n",del_script,ret));
	return ret;
}

/****************************************************************************
 Check user is in correct domain if required
****************************************************************************/

static BOOL check_domain_match(char *user, char *domain) 
{
  /*
   * If we aren't serving to trusted domains, we must make sure that
   * the validation request comes from an account in the same domain
   * as the Samba server
   */

  if (!lp_allow_trusted_domains() &&
      !strequal(lp_workgroup(), domain) ) {
      DEBUG(1, ("check_domain_match: Attempt to connect as user %s from domain %s denied.\n", user, domain));
      return False;
  } else {
      return True;
  }
}

/****************************************************************************
 Check for a valid username and password in security=server mode.
****************************************************************************/

static BOOL check_server_security(char *orig_user, char *domain, char *unix_user,
                                  char *smb_apasswd, int smb_apasslen,
                                  char *smb_ntpasswd, int smb_ntpasslen)
{
	BOOL ret = False;

	if(lp_security() != SEC_SERVER)
		return False;

	if (!check_domain_match(orig_user, domain))
		return False;

	ret = server_validate(orig_user, domain, 
					smb_apasswd, smb_apasslen, 
					smb_ntpasswd, smb_ntpasslen);

	if(ret) {
		/*
		 * User validated ok against Domain controller.
		 * If the admin wants us to try and create a UNIX
		 * user on the fly, do so.
		 * Note that we can never delete users when in server
		 * level security as we never know if it was a failure
		 * due to a bad password, or the user really doesn't exist.
		 */

		if(lp_adduser_script() && !smb_getpwnam(unix_user,True))
			smb_create_user(unix_user, NULL);
	}

	return ret;
}

/****************************************************************************
 Check for a valid username and password in security=domain mode.
****************************************************************************/

static BOOL check_domain_security(char *orig_user, char *domain, char *unix_user, 
                                  char *smb_apasswd, int smb_apasslen,
                                  char *smb_ntpasswd, int smb_ntpasslen, NT_USER_TOKEN **pptoken)
{
  BOOL ret = False;
  BOOL user_exists = True;
  struct passwd *pwd = NULL;

  if(lp_security() != SEC_DOMAIN)
    return False;

  if (!check_domain_match(orig_user, domain))
     return False;

  ret = domain_client_validate(orig_user, domain,
                                smb_apasswd, smb_apasslen,
                                smb_ntpasswd, smb_ntpasslen,
                                &user_exists, pptoken);

  if(ret) {
    /*
     * User validated ok against Domain controller.
     * If the admin wants us to try and create a UNIX
     * user on the fly, do so.
     */
    if(user_exists && lp_adduser_script() && !(pwd = smb_getpwnam(unix_user,True))) {
      smb_create_user(unix_user, NULL);
    }

    if(lp_adduser_script() && pwd) {
      SMB_STRUCT_STAT st;

      /*
       * Also call smb_create_user if the users home directory
       * doesn't exist. Used with winbindd to allow the script to
       * create the home directory for a user mapped with winbindd.
       */

      if (pwd->pw_dir && (sys_stat(pwd->pw_dir, &st) == -1) && (errno == ENOENT))
        smb_create_user(unix_user, pwd->pw_dir);
    }

  } else {
    /*
     * User failed to validate ok against Domain controller.
     * If the failure was "user doesn't exist" and admin 
     * wants us to try and delete that UNIX user on the fly,
     * do so.
     */
    if(!user_exists && lp_deluser_script() && smb_getpwnam(unix_user,True)) {
      smb_delete_user(unix_user);
    }
  }

  return ret;
}

/****************************************************************************
 Reply to a session setup command.
****************************************************************************/

int reply_sesssetup_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
  int sess_vuid;
  gid_t gid;
  uid_t uid;
  int   smb_bufsize;    
  int   smb_apasslen = 0;   
  pstring smb_apasswd;
  int   smb_ntpasslen = 0;   
  pstring smb_ntpasswd;
  BOOL valid_nt_password = False;
  BOOL valid_lm_password = False;
  fstring user;
  fstring orig_user;
  BOOL guest=False;
  static BOOL done_sesssetup = False;
  BOOL doencrypt = SMBENCRYPT();
  fstring domain;
  NT_USER_TOKEN *ptok = NULL;

  START_PROFILE(SMBsesssetupX);

  *smb_apasswd = 0;
  *smb_ntpasswd = 0;
  *domain = 0;

  smb_bufsize = SVAL(inbuf,smb_vwv2);

  if (Protocol < PROTOCOL_NT1) {
    smb_apasslen = SVAL(inbuf,smb_vwv7);
    if (smb_apasslen > MAX_PASS_LEN) {
      overflow_attack(smb_apasslen);
      return(ERROR_DOS(ERRDOS,ERRbuftoosmall));
    }
      
    memcpy(smb_apasswd,smb_buf(inbuf),smb_apasslen);
    smb_apasswd[smb_apasslen] = 0;
    fstrcpy(user,smb_buf(inbuf)+smb_apasslen);
    /*
     * Incoming user is in DOS codepage format. Convert
     * to UNIX.
     */
    fstrcpy(user,dos_to_unix_static(user));
  
    if (!doencrypt && (lp_security() != SEC_SERVER)) {
      smb_apasslen = strlen(smb_apasswd);
    }
  } else {
    uint16 passlen1 = SVAL(inbuf,smb_vwv7);
    uint16 passlen2 = SVAL(inbuf,smb_vwv8);
    enum remote_arch_types ra_type = get_remote_arch();
    char *p = smb_buf(inbuf);    
    char *username_str;
    fstring native_lanman;
    

    if(global_client_caps == 0)
      global_client_caps = IVAL(inbuf,smb_vwv11);

    /* client_caps is used as final determination if client is NT or Win95. 
       This is needed to return the correct error codes in some
       circumstances.
     */
    
    if(ra_type == RA_WINNT || ra_type == RA_WIN2K || ra_type == RA_WIN95) {
      if(!(global_client_caps & (CAP_NT_SMBS | CAP_STATUS32))) {
        set_remote_arch( RA_WIN95);
      }
    }

    username_str = smb_buf(inbuf)+smb_apasslen;
    fstrcpy( native_lanman, skip_string(username_str, 3));
    
    /* 
     * we distinguish between 2K and XP by the "Native Lan Manager" 
     * string.  
     *   .NET RC2 => "Windows .NET 5.2"
     *   WinXP    => "Windows 2002 5.1"
     *   Win2k    => "Windows 2000 5.0"
     *   NT4      => (off by one bug) "Windows NT 4.0" 
     *   Win9x    => "Windows 4.0"
     */
    if ( ra_type == RA_WIN2K ) {
    	if ( 0 == strcmp( native_lanman, "Windows 2002 5.1" ) )
	    set_remote_arch( RA_WINXP );
        else if ( 0 == strcmp( native_lanman, "Windows .NET 5.2" ) )
            set_remote_arch( RA_WIN2K3 );
    }

    if (passlen1 != 24 && passlen2 != 24)
      doencrypt = False;

    if (passlen1 > MAX_PASS_LEN) {
      overflow_attack(passlen1);
      return(ERROR_DOS(ERRDOS,ERRbuftoosmall));
    }

    passlen1 = MIN(passlen1, MAX_PASS_LEN);
    passlen2 = MIN(passlen2, MAX_PASS_LEN);

    if(!doencrypt) {
       /* both Win95 and WinNT stuff up the password lengths for
          non-encrypting systems. Uggh. 
      
          if passlen1==24 its a win95 system, and its setting the
          password length incorrectly. Luckily it still works with the
          default code because Win95 will null terminate the password
          anyway 

          if passlen1>0 and passlen2>0 then maybe its a NT box and its
          setting passlen2 to some random value which really stuffs
          things up. we need to fix that one.  */

      if (passlen1 > 0 && passlen2 > 0 && passlen2 != 24 && passlen2 != 1)
        passlen2 = 0;
    }

    if (lp_restrict_anonymous()) {
      /* there seems to be no reason behind the differences in MS clients formatting
       * various info like the domain, NativeOS, and NativeLanMan fields. Win95
       * in particular seems to have an extra null byte between the username and the
       * domain, or the password length calculation is wrong, which throws off the
       * string extraction routines below.  This makes the value of domain be the
       * empty string, which fails the restrict anonymous check further down.
       * This compensates for that, and allows browsing to work in mixed NT and
       * win95 environments even when restrict anonymous is true. AAB
       */
      dump_data(100, p, 0x70);
      DEBUG(9, ("passlen1=%d, passlen2=%d\n", passlen1, passlen2));
      if (ra_type == RA_WIN95 && !passlen1 && !passlen2 && p[0] == 0 && p[1] == 0) {
        DEBUG(0, ("restrict anonymous parameter used in a win95 environment!\n"));
        DEBUG(0, ("client is win95 and broken passlen1 offset -- attempting fix\n"));
        DEBUG(0, ("if win95 cilents are having difficulty browsing, you will be unable to use restrict anonymous\n"));
        passlen1 = 1;
      }
    }

    if(doencrypt || ((lp_security() == SEC_SERVER) || (lp_security() == SEC_DOMAIN))) {
      /* Save the lanman2 password and the NT md4 password. */
      smb_apasslen = passlen1;
      memcpy(smb_apasswd,p,smb_apasslen);
      smb_apasswd[smb_apasslen] = 0;
      smb_ntpasslen = passlen2;
      memcpy(smb_ntpasswd,p+passlen1,smb_ntpasslen);
      smb_ntpasswd[smb_ntpasslen] = 0;

      /*
       * Ensure the plaintext passwords are in UNIX format.
       */
      if(!doencrypt) {
        pstrcpy(smb_apasswd,dos_to_unix_static(smb_apasswd));
        pstrcpy(smb_ntpasswd,dos_to_unix_static(smb_ntpasswd));
      }

    } else {
      /* we use the first password that they gave */
      smb_apasslen = passlen1;
      StrnCpy(smb_apasswd,p,smb_apasslen);      
      /*
       * Ensure the plaintext password is in UNIX format.
       */
      pstrcpy(smb_apasswd,dos_to_unix_static(smb_apasswd));
      
      /* trim the password */
      smb_apasslen = strlen(smb_apasswd);

      /* wfwg sometimes uses a space instead of a null */
      if (strequal(smb_apasswd," ")) {
        smb_apasslen = 0;
        *smb_apasswd = 0;
      }
    }
    
    p += passlen1 + passlen2;
    fstrcpy(user,p);
    p = skip_string(p,1);
    /*
     * Incoming user and domain are in DOS codepage format. Convert
     * to UNIX.
     */
    fstrcpy(user,dos_to_unix_static(user));
    fstrcpy(domain, dos_to_unix_static(p));
    DEBUG(3,("Domain=[%s]  NativeOS=[%s] NativeLanMan=[%s]\n",
	     domain,skip_string(p,1),skip_string(p,2)));
  }

  /* don't allow strange characters in usernames or domains */
  alpha_strcpy(user, user, ". _-$", sizeof(user));
  alpha_strcpy(domain, domain, ". _-@", sizeof(domain));
  if (strstr(user, "..") || strstr(domain,"..")) {
	  return ERROR_BOTH(NT_STATUS_LOGON_FAILURE,ERRSRV,ERRbadpw);
  }

  DEBUG(3,("sesssetupX:name=[%s]\n",user));

  /* If name ends in $ then I think it's asking about whether a */
  /* computer with that name (minus the $) has access. For now */
  /* say yes to everything ending in $. */

  if (*user && (user[strlen(user) - 1] == '$') && (smb_apasslen == 24) && (smb_ntpasslen == 24)) {
    END_PROFILE(SMBsesssetupX);
    return session_trust_account(conn, inbuf, outbuf, user, 
                                 smb_apasswd, smb_apasslen,
                                 smb_ntpasswd, smb_ntpasslen);
  }

  if (done_sesssetup && lp_restrict_anonymous()) {
    /* tests show that even if browsing is done over already validated connections
     * without a username and password the domain is still provided, which it
     * wouldn't be if it was a purely anonymous connection.  So, in order to
     * restrict anonymous, we only deny connections that have no session
     * information.  If a domain has been provided, then it's not a purely
     * anonymous connection. AAB
     */
    if (!*user && !*smb_apasswd && !*domain) {
      DEBUG(0, ("restrict anonymous is True and anonymous connection attempted. Denying access.\n"));
      END_PROFILE(SMBsesssetupX);
      return(ERROR_DOS(ERRDOS,ERRnoaccess));
    }
  }

  /* setup %U substitution */
  sub_set_smb_name(user);

  /* If no username is sent use the guest account */
  if (!*user) {
    fstrcpy(user,lp_guestaccount(-1));
    guest = True;
  }

  fstrcpy(current_user_info.smb_name,user);
  
  reload_services(True);

  /*
   * Save the username before mapping. We will use
   * the original username sent to us for security=server
   * and security=domain checking.
   */

  fstrcpy( orig_user, user);

  /*
   * Always try the "DOMAIN\user" lookup first, as this is the most
   * specific case. If this fails then try the simple "user" lookup.
   */

  {
    fstring dom_user;

    /* Work out who's who */

    slprintf(dom_user, sizeof(dom_user) - 1,"%s%s%s",
               domain, lp_winbind_separator(), user);

    if (sys_getpwnam(dom_user) != NULL) {
      fstrcpy(user, dom_user);
      DEBUG(3,("Using unix username %s\n", dom_user));
    }
  }

  /*
   * Pass the user through the NT -> unix user mapping
   * function.
   */
   
  (void)map_username(user);

  /*
   * Do any UNIX username case mangling.
   */
  smb_getpwnam(user, True);

  add_session_user(user);

  /* 
   * Check with orig_user for security=server and
   * security=domain.
   */

  if (!guest && !check_server_security(orig_user, domain, user, 
         smb_apasswd, smb_apasslen, smb_ntpasswd, smb_ntpasslen) &&
      !check_domain_security(orig_user, domain, user, smb_apasswd,
         smb_apasslen, smb_ntpasswd, smb_ntpasslen, &ptok) &&
      !check_hosts_equiv(user))
  {

    /* 
     * If we get here then the user wasn't guest and the remote
     * authentication methods failed. Check the authentication
     * methods on this local server.
     *
     * If an NT password was supplied try and validate with that
     * first. This is superior as the passwords are mixed case 
     * 128 length unicode.
      */

    if(smb_ntpasslen)
    {
      if(!password_ok(user, smb_ntpasswd,smb_ntpasslen,NULL))
        DEBUG(2,("NT Password did not match for user '%s'!\n", user));
      else
        valid_nt_password = True;
    } 
    
    
    /* check the LanMan password only if necessary and if allowed 
       by lp_lanman_auth() */
    if (!valid_nt_password && lp_lanman_auth())
    {
      DEBUG(2,("Defaulting to Lanman password for %s\n", user));
      valid_lm_password = password_ok(user, smb_apasswd,smb_apasslen,NULL);
    }
      

    /* The true branch will be executed if 
       (1) the NT password failed (or was not tried), and 
       (2) LanMan authentication failed (or was disabled) 
     */
    if (!valid_nt_password && !valid_lm_password)
    {
      if (lp_security() >= SEC_USER) 
      {
        if (lp_map_to_guest() == NEVER_MAP_TO_GUEST)
        {
          delete_nt_token(&ptok);
          DEBUG(1,("Rejecting user '%s': authentication failed\n", user));
		  END_PROFILE(SMBsesssetupX);
          return ERROR_BOTH(NT_STATUS_LOGON_FAILURE,ERRSRV,ERRbadpw);
        }

        if (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_USER)
        {
	  SAM_ACCOUNT *sampass = NULL;
	  
	  pdb_init_sam(&sampass);
	  
          /*
           * This is really bad form.  We know that password_ok() failed,
           * but the return value can't distinguish between a non-existent user
           * and a bad password.  So we try to look the user up again here
           * to see if he or she exists.  We must look up the user in the
           * "smb passwd file" and not /etc/passwd so that we don't
           * get confused when the two don't have a one-to-one correspondence.
           * e.g. a standard UNIX account such as "operator"  --jerry
           */	  
	  
          if (pdb_getsampwnam(sampass, user))
          {
            delete_nt_token(&ptok);
            DEBUG(1,("Rejecting user '%s': bad password\n", user));
            END_PROFILE(SMBsesssetupX);
	    pdb_free_sam(sampass);
            return ERROR_BOTH(NT_STATUS_LOGON_FAILURE,ERRSRV,ERRbadpw);
          }
	  
	  pdb_free_sam(sampass);
        }

        /*
         * ..else if lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_PASSWORD
         * Then always map to guest account - as done below.
         */
      }

      if (*smb_apasswd || !smb_getpwnam(user,True))
         fstrcpy(user,lp_guestaccount(-1));
      DEBUG(3,("Registered username %s for guest access\n",user));
      guest = True;
    }
  }

  if (!smb_getpwnam(user,True)) {
    DEBUG(3,("No such user %s [%s] - using guest account\n",user, domain));
    fstrcpy(user,lp_guestaccount(-1));
    guest = True;
  }

  if (!strequal(user,lp_guestaccount(-1)) &&
      lp_servicenumber(user) < 0)      
  {
	add_home_service(user,get_user_service_home_dir(user));
  }


  /* it's ok - setup a reply */
  if (Protocol < PROTOCOL_NT1) {
    set_message(outbuf,3,0,True);
  } else {
    char *p;
    set_message(outbuf,3,3,True);
    p = smb_buf(outbuf);
    pstrcpy(p,"Unix"); p = skip_string(p,1);
    pstrcpy(p,"Samba "); pstrcat(p,VERSION); p = skip_string(p,1);
    pstrcpy(p,global_myworkgroup); unix_to_dos(p); p = skip_string(p,1);
    set_message(outbuf,3,PTR_DIFF(p,smb_buf(outbuf)),False);
    /* perhaps grab OS version here?? */
  }

  /* Set the correct uid in the outgoing and incoming packets
     We will use this on future requests to determine which
     user we should become.
     */
  {
    const struct passwd *pw = smb_getpwnam(user,False);
    if (!pw) {
      delete_nt_token(&ptok);
      DEBUG(1,("Username %s is invalid on this system\n",user));
      END_PROFILE(SMBsesssetupX);
      return ERROR_BOTH(NT_STATUS_LOGON_FAILURE,ERRSRV,ERRbadpw);
    }
    gid = pw->pw_gid;
    uid = pw->pw_uid;
  }

  if (guest)
    SSVAL(outbuf,smb_vwv2,1);

  /* register the name and uid as being validated, so further connections
     to a uid can get through without a password, on the same VC */

  sess_vuid = register_vuid(uid,gid,user,current_user_info.smb_name,domain,guest,&ptok);

  delete_nt_token(&ptok);
  
  if (sess_vuid == -1) {
  	  END_PROFILE(SMBsesssetupX);
	  return(ERROR_DOS(ERRDOS,ERRnoaccess));
  }

  SSVAL(outbuf,smb_uid,sess_vuid);
  SSVAL(inbuf,smb_uid,sess_vuid);

  if (!done_sesssetup)
    max_send = MIN(max_send,smb_bufsize);

  DEBUG(6,("Client requested max send size of %d\n", max_send));

  done_sesssetup = True;

  END_PROFILE(SMBsesssetupX);
  return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to a chkpth.
****************************************************************************/

int reply_chkpth(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int outsize = 0;
  int mode;
  pstring name;
  BOOL ok = False;
  BOOL bad_path = False;
  SMB_STRUCT_STAT sbuf;
  START_PROFILE(SMBchkpth);
 
  pstrcpy(name,smb_buf(inbuf) + 1);

  RESOLVE_DFSPATH(name, conn, inbuf, outbuf);

  unix_convert(name,conn,0,&bad_path,&sbuf);

  mode = SVAL(inbuf,smb_vwv0);

  if (check_name(name,conn)) {
    if (VALID_STAT(sbuf) || vfs_stat(conn,name,&sbuf) == 0)
      ok = S_ISDIR(sbuf.st_mode);
  }

  if (!ok) {
    /* We special case this - as when a Windows machine
       is parsing a path is steps through the components
       one at a time - if a component fails it expects
       ERRbadpath, not ERRbadfile.
     */
    if(errno == ENOENT) {
	    return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
    }

    return(UNIXERROR(ERRDOS,ERRbadpath));
  }

  outsize = set_message(outbuf,0,0,True);

  DEBUG(3,("chkpth %s mode=%d\n", name, mode));

  END_PROFILE(SMBchkpth);
  return(outsize);
}

/****************************************************************************
 Reply to a getatr.
****************************************************************************/

int reply_getatr(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring fname;
  int outsize = 0;
  SMB_STRUCT_STAT sbuf;
  BOOL ok = False;
  int mode=0;
  SMB_OFF_T size=0;
  time_t mtime=0;
  BOOL bad_path = False;
  START_PROFILE(SMBgetatr);
 
  pstrcpy(fname,smb_buf(inbuf) + 1);

  RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);
  
  /* dos smetimes asks for a stat of "" - it returns a "hidden directory"
     under WfWg - weird! */
  if (! (*fname))
  {
    mode = aHIDDEN | aDIR;
    if (!CAN_WRITE(conn)) mode |= aRONLY;
    size = 0;
    mtime = 0;
    ok = True;
  }
  else
  {
    unix_convert(fname,conn,0,&bad_path,&sbuf);
    if (check_name(fname,conn))
    {
      if (VALID_STAT(sbuf) || vfs_stat(conn,fname,&sbuf) == 0)
      {
        mode = dos_mode(conn,fname,&sbuf);
        size = sbuf.st_size;
        mtime = sbuf.st_mtime;
        if (mode & aDIR)
          size = 0;
        ok = True;
      }
      else
        DEBUG(3,("stat of %s failed (%s)\n",fname,strerror(errno)));
    }
  }
  
  if (!ok)
  {
    set_bad_path_error(errno, bad_path);
    END_PROFILE(SMBgetatr);
    return(UNIXERROR(ERRDOS,ERRbadfile));
  }
 
  outsize = set_message(outbuf,10,0,True);

  SSVAL(outbuf,smb_vwv0,mode);
  if(lp_dos_filetime_resolution(SNUM(conn)) )
    put_dos_date3(outbuf,smb_vwv1,mtime & ~1);
  else
    put_dos_date3(outbuf,smb_vwv1,mtime);
  SIVAL(outbuf,smb_vwv3,(uint32)size);

  if (Protocol >= PROTOCOL_NT1)
	  SSVAL(outbuf,smb_flg2,SVAL(outbuf, smb_flg2) | FLAGS2_IS_LONG_NAME);
  
  DEBUG( 3, ( "getatr name=%s mode=%d size=%d\n", fname, mode, (uint32)size ) );
  
  END_PROFILE(SMBgetatr);
  return(outsize);
}

/****************************************************************************
 Reply to a setatr.
****************************************************************************/

int reply_setatr(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring fname;
  int outsize = 0;
  BOOL ok=False;
  int mode;
  time_t mtime;
  SMB_STRUCT_STAT sbuf;
  BOOL bad_path = False;
  START_PROFILE(SMBsetatr);
 
  pstrcpy(fname,smb_buf(inbuf) + 1);
  unix_convert(fname,conn,0,&bad_path,&sbuf);

  mode = SVAL(inbuf,smb_vwv0);
  mtime = make_unix_date3(inbuf+smb_vwv1);
  
  if (VALID_STAT_OF_DIR(sbuf))
    mode |= aDIR;
  else
    mode &= ~aDIR;

  if (check_name(fname,conn))
    ok =  (file_chmod(conn,fname,mode,NULL) == 0);
  if (ok)
    ok = set_filetime(conn,fname,mtime);
  
  if (!ok)
  {
    set_bad_path_error(errno, bad_path);
    END_PROFILE(SMBsetatr);
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG( 3, ( "setatr name=%s mode=%d\n", fname, mode ) );
  
  END_PROFILE(SMBsetatr);
  return(outsize);
}

/****************************************************************************
 Reply to a dskattr.
****************************************************************************/

int reply_dskattr(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	SMB_BIG_UINT dfree,dsize,bsize;
	START_PROFILE(SMBdskattr);

	conn->vfs_ops.disk_free(conn,".",True,&bsize,&dfree,&dsize);
  
	outsize = set_message(outbuf,5,0,True);
	
	if (Protocol <= PROTOCOL_LANMAN2) {
		double total_space, free_space;
		/* we need to scale this to a number that DOS6 can handle. We
		   use floating point so we can handle large drives on systems
		   that don't have 64 bit integers 

		   we end up displaying a maximum of 2G to DOS systems
		*/
		total_space = dsize * (double)bsize;
		free_space = dfree * (double)bsize;

		dsize = (total_space+63*512) / (64*512);
		dfree = (free_space+63*512) / (64*512);
		
		if (dsize > 0xFFFF) dsize = 0xFFFF;
		if (dfree > 0xFFFF) dfree = 0xFFFF;

		SSVAL(outbuf,smb_vwv0,dsize);
		SSVAL(outbuf,smb_vwv1,64); /* this must be 64 for dos systems */
		SSVAL(outbuf,smb_vwv2,512); /* and this must be 512 */
		SSVAL(outbuf,smb_vwv3,dfree);
	} else {
		SSVAL(outbuf,smb_vwv0,dsize);
		SSVAL(outbuf,smb_vwv1,bsize/512);
		SSVAL(outbuf,smb_vwv2,512);
		SSVAL(outbuf,smb_vwv3,dfree);
	}

	DEBUG(3,("dskattr dfree=%d\n", (unsigned int)dfree));

	END_PROFILE(SMBdskattr);
	return(outsize);
}

/****************************************************************************
 Reply to a search.
 Can be called from SMBsearch, SMBffirst or SMBfunique.
****************************************************************************/

int reply_search(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring mask;
  pstring directory;
  pstring fname;
  SMB_OFF_T size;
  int mode;
  time_t date;
  int dirtype;
  int outsize = 0;
  int numentries = 0;
  BOOL finished = False;
  int maxentries;
  int i;
  char *p;
  BOOL ok = False;
  int status_len;
  char *path;
  char status[21];
  int dptr_num= -1;
  BOOL check_descend = False;
  BOOL expect_close = False;
  BOOL can_open = True;
  BOOL bad_path = False;
  START_PROFILE(SMBsearch);

  *mask = *directory = *fname = 0;

  /* If we were called as SMBffirst then we must expect close. */
  if(CVAL(inbuf,smb_com) == SMBffirst)
    expect_close = True;
  
  outsize = set_message(outbuf,1,3,True);
  maxentries = SVAL(inbuf,smb_vwv0); 
  dirtype = SVAL(inbuf,smb_vwv1);
  path = smb_buf(inbuf) + 1;
  status_len = SVAL(smb_buf(inbuf),3 + strlen(path));

  RESOLVE_DFSPATH(path, conn, inbuf, outbuf);
  /* dirtype &= ~aDIR; */

  if (status_len == 0)
  {
    SMB_STRUCT_STAT sbuf;
    pstring dir2;

    pstrcpy(directory,smb_buf(inbuf)+1);
    pstrcpy(dir2,smb_buf(inbuf)+1);
    unix_convert(directory,conn,0,&bad_path,&sbuf);
    unix_format(dir2);

    if (!check_name(directory,conn))
      can_open = False;

    p = strrchr(dir2,'/');
    if (p == NULL) 
    {
      pstrcpy(mask,dir2);
      *dir2 = 0;
    }
    else
    {
      *p = 0;
      pstrcpy(mask,p+1);
    }

    p = strrchr(directory,'/');
    if (!p) 
      *directory = 0;
    else
      *p = 0;

    if (strlen(directory) == 0)
      pstrcpy(directory,"./");
    memset((char *)status,'\0',21);
    SCVAL(status,0,(dirtype & 0x1F));
  }
  else
  {
    int status_dirtype;
    memcpy(status,smb_buf(inbuf) + 1 + strlen(path) + 4,21);
    status_dirtype = CVAL(status,0) & 0x1F;
    if (status_dirtype != (dirtype & 0x1F))
    	dirtype = status_dirtype;
    conn->dirptr = dptr_fetch(status+12,&dptr_num);      
    if (!conn->dirptr)
      goto SearchEmpty;
    string_set(&conn->dirpath,dptr_path(dptr_num));
    fstrcpy(mask, dptr_wcard(dptr_num));
  }

  if (can_open)
  {
    p = smb_buf(outbuf) + 3;
      
    ok = True;
     
    if (status_len == 0)
    {
      dptr_num = dptr_create(conn,directory,True,expect_close,SVAL(inbuf,smb_pid));
      if (dptr_num < 0)
      {
        if(dptr_num == -2)
        {
          set_bad_path_error(errno, bad_path);
          END_PROFILE(SMBsearch);
          return (UNIXERROR(ERRDOS,ERRnofids));
        }
		END_PROFILE(SMBsearch);
        return ERROR_DOS(ERRDOS,ERRnofids);
      }
      dptr_set_wcard(dptr_num, strdup(mask));
      dptr_set_attr(dptr_num, dirtype);
    } else {
      dirtype = dptr_attr(dptr_num);
    }

    DEBUG(4,("dptr_num is %d\n",dptr_num));

    if (ok)
    {
      if ((dirtype&0x1F) == aVOLID)
      {	  
        memcpy(p,status,21);
        make_dir_struct(p,"???????????",volume_label(SNUM(conn)),0,aVOLID,0);
        dptr_fill(p+12,dptr_num);
        if (dptr_zero(p+12) && (status_len==0))
          numentries = 1;
        else
          numentries = 0;
        p += DIR_STRUCT_SIZE;
      }
      else 
      {
        DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
              conn->dirpath,lp_dontdescend(SNUM(conn))));
        if (in_list(conn->dirpath, lp_dontdescend(SNUM(conn)),True))
          check_descend = True;

        for (i=numentries;(i<maxentries) && !finished;i++)
        {
	  /* check to make sure we have room in the buffer */
	  if ( ((PTR_DIFF(p, outbuf))+DIR_STRUCT_SIZE) > BUFFER_SIZE )
	  	break;
          finished = 
            !get_dir_entry(conn,mask,dirtype,fname,&size,&mode,&date,check_descend);
          if (!finished)
          {
            memcpy(p,status,21);
            make_dir_struct(p,mask,fname,size,mode,date);
            dptr_fill(p+12,dptr_num);
            numentries++;
	  }
	  p += DIR_STRUCT_SIZE;
        }
      }
	} /* if (ok ) */
  }


  SearchEmpty:

  if ( (numentries == 0) || !ok)
  {
	  SCVAL(outbuf,smb_rcls,ERRDOS);
	  SSVAL(outbuf,smb_err,ERRnofiles);
	  dptr_close(&dptr_num);
  }

  /* If we were called as SMBffirst with smb_search_id == NULL
     and no entries were found then return error and close dirptr 
     (X/Open spec) */

  if(ok && expect_close && numentries == 0 && status_len == 0)
  {
    SCVAL(outbuf,smb_rcls,ERRDOS);
    SSVAL(outbuf,smb_err,ERRnofiles);
    /* Also close the dptr - we know it's gone */
    dptr_close(&dptr_num);
  }

  /* If we were called as SMBfunique, then we can close the dirptr now ! */
  if(dptr_num >= 0 && CVAL(inbuf,smb_com) == SMBfunique)
    dptr_close(&dptr_num);

  SSVAL(outbuf,smb_vwv0,numentries);
  SSVAL(outbuf,smb_vwv1,3 + numentries * DIR_STRUCT_SIZE);
  SCVAL(smb_buf(outbuf),0,5);
  SSVAL(smb_buf(outbuf),1,numentries*DIR_STRUCT_SIZE);

  if (Protocol >= PROTOCOL_NT1)
    SSVAL(outbuf,smb_flg2,SVAL(outbuf, smb_flg2) | FLAGS2_IS_LONG_NAME);

  outsize += DIR_STRUCT_SIZE*numentries;
  smb_setlen(outbuf,outsize - 4);
  
  if ((! *directory) && dptr_path(dptr_num))
    slprintf(directory, sizeof(directory)-1, "(%s)",dptr_path(dptr_num));

  DEBUG( 4, ( "%s mask=%s path=%s dtype=%d nument=%d of %d\n",
        smb_fn_name(CVAL(inbuf,smb_com)), 
        mask, directory, dirtype, numentries, maxentries ) );

  END_PROFILE(SMBsearch);
  return(outsize);
}

/****************************************************************************
 Reply to a fclose (stop directory search).
****************************************************************************/

int reply_fclose(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int outsize = 0;
  int status_len;
  char *path;
  char status[21];
  int dptr_num= -2;
  START_PROFILE(SMBfclose);

  outsize = set_message(outbuf,1,0,True);
  path = smb_buf(inbuf) + 1;
  status_len = SVAL(smb_buf(inbuf),3 + strlen(path));

  
  if (status_len == 0) {
    END_PROFILE(SMBfclose);
    return ERROR_DOS(ERRSRV,ERRsrverror);
  }

  memcpy(status,smb_buf(inbuf) + 1 + strlen(path) + 4,21);

  if(dptr_fetch(status+12,&dptr_num)) {
    /*  Close the dptr - we know it's gone */
    dptr_close(&dptr_num);
  }

  SSVAL(outbuf,smb_vwv0,0);

  DEBUG(3,("search close\n"));

  END_PROFILE(SMBfclose);
  return(outsize);
}

/****************************************************************************
 Reply to an open.
****************************************************************************/

int reply_open(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring fname;
  int outsize = 0;
  int fmode=0;
  int share_mode;
  SMB_OFF_T size = 0;
  time_t mtime=0;
  mode_t unixmode;
  int rmode=0;
  SMB_STRUCT_STAT sbuf;
  BOOL bad_path = False;
  files_struct *fsp;
  int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
  START_PROFILE(SMBopen);
 
  share_mode = SVAL(inbuf,smb_vwv0);

  pstrcpy(fname,smb_buf(inbuf)+1);

  RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

  unix_convert(fname,conn,0,&bad_path,&sbuf);
    
  unixmode = unix_mode(conn,aARCH,fname);
      
  fsp = open_file_shared(conn,fname,&sbuf,share_mode,(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
                   unixmode, oplock_request,&rmode,NULL);

  if (!fsp)
  {
    set_bad_path_error(errno, bad_path);
    END_PROFILE(SMBopen);
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  size = sbuf.st_size;
  fmode = dos_mode(conn,fname,&sbuf);
  mtime = sbuf.st_mtime;

  if (fmode & aDIR) {
    DEBUG(3,("attempt to open a directory %s\n",fname));
    close_file(fsp,False);
    END_PROFILE(SMBopen);
    return ERROR_DOS(ERRDOS,ERRnoaccess);
  }
  
  outsize = set_message(outbuf,7,0,True);
  SSVAL(outbuf,smb_vwv0,fsp->fnum);
  SSVAL(outbuf,smb_vwv1,fmode);
  if(lp_dos_filetime_resolution(SNUM(conn)) )
    put_dos_date3(outbuf,smb_vwv2,mtime & ~1);
  else
    put_dos_date3(outbuf,smb_vwv2,mtime);
  SIVAL(outbuf,smb_vwv4,(uint32)size);
  SSVAL(outbuf,smb_vwv6,rmode);

  if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
    SCVAL(outbuf,smb_flg, CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }
    
  if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
    SCVAL(outbuf,smb_flg, CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  END_PROFILE(SMBopen);
  return(outsize);
}

/****************************************************************************
 Reply to an open and X.
****************************************************************************/

int reply_open_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname;
  int smb_mode = SVAL(inbuf,smb_vwv3);
  int smb_attr = SVAL(inbuf,smb_vwv5);
  /* Breakout the oplock request bits so we can set the
     reply bits separately. */
  BOOL ex_oplock_request = EXTENDED_OPLOCK_REQUEST(inbuf);
  BOOL core_oplock_request = CORE_OPLOCK_REQUEST(inbuf);
  BOOL oplock_request = ex_oplock_request | core_oplock_request;
#if 0
  int open_flags = SVAL(inbuf,smb_vwv2);
  int smb_sattr = SVAL(inbuf,smb_vwv4); 
  uint32 smb_time = make_unix_date3(inbuf+smb_vwv6);
#endif
  int smb_ofun = SVAL(inbuf,smb_vwv8);
  mode_t unixmode;
  SMB_OFF_T size=0;
  int fmode=0,mtime=0,rmode=0;
  SMB_STRUCT_STAT sbuf;
  int smb_action = 0;
  BOOL bad_path = False;
  files_struct *fsp;
  START_PROFILE(SMBopenX);

  /* If it's an IPC, pass off the pipe handler. */
  if (IS_IPC(conn)) {
    if (lp_nt_pipe_support()) {
	    END_PROFILE(SMBopenX);
	    return reply_open_pipe_and_X(conn, inbuf,outbuf,length,bufsize);
    } else {
		END_PROFILE(SMBopenX);
        return ERROR_DOS(ERRSRV,ERRaccess);
    }
  }

  /* XXXX we need to handle passed times, sattr and flags */

  pstrcpy(fname,smb_buf(inbuf));

  RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

  unix_convert(fname,conn,0,&bad_path,&sbuf);
    
  unixmode = unix_mode(conn,smb_attr | aARCH, fname);
      
  fsp = open_file_shared(conn,fname,&sbuf,smb_mode,smb_ofun,unixmode,
	               oplock_request, &rmode,&smb_action);
      
  if (!fsp)
  {
    set_bad_path_error(errno, bad_path);
    END_PROFILE(SMBopenX);
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  size = sbuf.st_size;
  fmode = dos_mode(conn,fname,&sbuf);
  mtime = sbuf.st_mtime;
  if (fmode & aDIR) {
    close_file(fsp,False);
    END_PROFILE(SMBopenX);
    return ERROR_DOS(ERRDOS,ERRnoaccess);
  }

  /* If the caller set the extended oplock request bit
     and we granted one (by whatever means) - set the
     correct bit for extended oplock reply.
   */

  if (ex_oplock_request && lp_fake_oplocks(SNUM(conn))) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  }

  if(ex_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  }

  /* If the caller set the core oplock request bit
     and we granted one (by whatever means) - set the
     correct bit for core oplock reply.
   */

  if (core_oplock_request && lp_fake_oplocks(SNUM(conn))) {
    SCVAL(outbuf,smb_flg, CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }

  if(core_oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
    SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }

  set_message(outbuf,15,0,True);
  SSVAL(outbuf,smb_vwv2,fsp->fnum);
  SSVAL(outbuf,smb_vwv3,fmode);
  if(lp_dos_filetime_resolution(SNUM(conn)) )
    put_dos_date3(outbuf,smb_vwv4,mtime & ~1);
  else
    put_dos_date3(outbuf,smb_vwv4,mtime);
  SIVAL(outbuf,smb_vwv6,(uint32)size);
  SSVAL(outbuf,smb_vwv8,rmode);
  SSVAL(outbuf,smb_vwv11,smb_action);

  END_PROFILE(SMBopenX);
  return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to a SMBulogoffX.
****************************************************************************/

int reply_ulogoffX(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
  uint16 vuid = SVAL(inbuf,smb_uid);
  user_struct *vuser = get_valid_user_struct(vuid);
  START_PROFILE(SMBulogoffX);

  if(vuser == 0) {
    DEBUG(3,("ulogoff, vuser id %d does not map to user.\n", vuid));
  }

  /* in user level security we are supposed to close any files
     open by this user */
  if ((vuser != 0) && (lp_security() != SEC_SHARE)) {
	  file_close_user(vuid);
  }

  invalidate_vuid(vuid);

  set_message(outbuf,2,0,True);

  DEBUG( 3, ( "ulogoffX vuid=%d\n", vuid ) );

  END_PROFILE(SMBulogoffX);
  return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to a mknew or a create.
****************************************************************************/

int reply_mknew(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring fname;
  int com;
  int outsize = 0;
  int createmode;
  mode_t unixmode;
  int ofun = 0;
  BOOL bad_path = False;
  files_struct *fsp;
  int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
  SMB_STRUCT_STAT sbuf;
  START_PROFILE(SMBcreate);
 
  com = SVAL(inbuf,smb_com);

  createmode = SVAL(inbuf,smb_vwv0);
  pstrcpy(fname,smb_buf(inbuf)+1);

  RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

  unix_convert(fname,conn,0,&bad_path,&sbuf);

  if (createmode & aVOLID) {
      DEBUG(0,("Attempt to create file (%s) with volid set - please report this\n",fname));
  }
  
  unixmode = unix_mode(conn,createmode,fname);
  
  if(com == SMBmknew)
  {
    /* We should fail if file exists. */
    ofun = FILE_CREATE_IF_NOT_EXIST;
  }
  else
  {
    /* SMBcreate - Create if file doesn't exist, truncate if it does. */
    ofun = FILE_CREATE_IF_NOT_EXIST|FILE_EXISTS_TRUNCATE;
  }

  /* Open file in dos compatibility share mode. */
  fsp = open_file_shared(conn,fname,&sbuf,SET_DENY_MODE(DENY_FCB)|SET_OPEN_MODE(DOS_OPEN_FCB), 
                   ofun, unixmode, oplock_request, NULL, NULL);
  
  if (!fsp)
  {
    set_bad_path_error(errno, bad_path);
    END_PROFILE(SMBcreate);
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }
 
  outsize = set_message(outbuf,1,0,True);
  SSVAL(outbuf,smb_vwv0,fsp->fnum);

  if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
    SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }
 
  if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
    SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
 
  DEBUG( 2, ( "new file %s\n", fname ) );
  DEBUG( 3, ( "mknew %s fd=%d dmode=%d umode=%o\n",
        fname, fsp->fd, createmode, (int)unixmode ) );

  END_PROFILE(SMBcreate);
  return(outsize);
}

/****************************************************************************
 Reply to a create temporary file.
****************************************************************************/

int reply_ctemp(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int outsize = 0;
	int createmode;
	mode_t unixmode;
	BOOL bad_path = False;
	files_struct *fsp;
	int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
	int tmpfd;
	SMB_STRUCT_STAT sbuf;
	char *p, *s;

	START_PROFILE(SMBctemp);

	createmode = SVAL(inbuf,smb_vwv0);
	pstrcpy(fname,smb_buf(inbuf)+1);
	pstrcat(fname,"\\TMXXXXXX");

	RESOLVE_DFSPATH(fname, conn, inbuf, outbuf);

	unix_convert(fname,conn,0,&bad_path,&sbuf);

	unixmode = unix_mode(conn,createmode,fname); 

	tmpfd = smb_mkstemp(fname);
	if (tmpfd == -1) {
		END_PROFILE(SMBctemp);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	vfs_stat(conn,fname,&sbuf);

	/* Open file in dos compatibility share mode. */
	/* We should fail if file does not exist. */
	fsp = open_file_shared(conn,fname,&sbuf,
			 SET_DENY_MODE(DENY_FCB)|SET_OPEN_MODE(DOS_OPEN_FCB), 
			 FILE_EXISTS_OPEN|FILE_FAIL_IF_NOT_EXIST, 
			 unixmode, oplock_request, NULL, NULL);
	/* close fd from smb_mkstemp() */
	close(tmpfd);

	if (!fsp) {
		set_bad_path_error(errno, bad_path);
		END_PROFILE(SMBctemp);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	/* the returned filename is relative to the directory */
	s = strrchr(fname, '/');
	if (!s)
		s = fname;
	else
		s++;

	outsize = set_message(outbuf,1,4+ strlen(fname),True);
	SSVAL(outbuf,smb_vwv0,fsp->fnum);

	p = smb_buf(outbuf);
	SSVALS(p, 0, -1); /* what is this? not in spec */
	SSVAL(p, 2, strlen(s));
	p += 4;
	pstrcpy(p,s);

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
	}
  
	if(EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))
		SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);

	DEBUG( 2, ( "created temp file %s\n", fname ) );
	DEBUG( 3, ( "ctemp %s fd=%d dmode=%d umode=%o\n",
		fname, fsp->fd, createmode, (int)unixmode ) );

	END_PROFILE(SMBctemp);
	return(outsize);
}

/*******************************************************************
 Check if a user is allowed to rename a file.
********************************************************************/

static NTSTATUS can_rename(char *fname,connection_struct *conn, SMB_STRUCT_STAT *pst)
{
	int smb_action;
	int access_mode;
	files_struct *fsp;

	if (!CAN_WRITE(conn))
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	
	if (S_ISDIR(pst->st_mode))
		return NT_STATUS_OK;

	/* We need a better way to return NT status codes from open... */
	unix_ERR_class = 0;
	unix_ERR_code = 0;

	fsp = open_file_shared1(conn, fname, pst, DELETE_ACCESS, SET_DENY_MODE(DENY_ALL),
		(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), 0, 0, &access_mode, &smb_action);

	if (!fsp) {
		NTSTATUS ret = NT_STATUS_ACCESS_DENIED;
		if (!NT_STATUS_IS_OK(unix_ERR_ntstatus))
			ret = unix_ERR_ntstatus;
		else if (unix_ERR_class == ERRDOS && unix_ERR_code == ERRbadshare)
			ret = NT_STATUS_SHARING_VIOLATION;
		unix_ERR_class = 0;
		unix_ERR_code = 0;
		unix_ERR_ntstatus = NT_STATUS_OK;
		return ret;
	}
	close_file(fsp,False);
	return NT_STATUS_OK;
}

/*******************************************************************
 Check if a user is allowed to delete a file.
********************************************************************/

static NTSTATUS can_delete(char *fname,connection_struct *conn, int dirtype)
{
	SMB_STRUCT_STAT sbuf;
	int fmode;
	int smb_action;
	int access_mode;
	files_struct *fsp;

	if (!CAN_WRITE(conn))
		return NT_STATUS_MEDIA_WRITE_PROTECTED;

	if (conn->vfs_ops.lstat(conn,dos_to_unix_static(fname),&sbuf) != 0)
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	fmode = dos_mode(conn,fname,&sbuf);
	if (fmode & aDIR)
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	if (!lp_delete_readonly(SNUM(conn))) {
		if (fmode & aRONLY)
			return NT_STATUS_CANNOT_DELETE;
	}

	if ((fmode & ~dirtype) & (aHIDDEN | aSYSTEM))
		return NT_STATUS_CANNOT_DELETE;

	/* We need a better way to return NT status codes from open... */
	unix_ERR_class = 0;
	unix_ERR_code = 0;

	fsp = open_file_shared1(conn, fname, &sbuf, DELETE_ACCESS, SET_DENY_MODE(DENY_ALL),
		(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), 0, 0, &access_mode, &smb_action);

	if (!fsp) {
		NTSTATUS ret = NT_STATUS_ACCESS_DENIED;
		if (unix_ERR_class == ERRDOS && unix_ERR_code == ERRbadshare)
			ret = NT_STATUS_SHARING_VIOLATION;
		unix_ERR_class = 0;
		unix_ERR_code = 0;
		return ret;
	}
	close_file(fsp,False);
	return NT_STATUS_OK;
}

/****************************************************************************
 The guts of the unlink command, split out so it may be called by the NT SMB
 code.
****************************************************************************/

NTSTATUS unlink_internals(connection_struct *conn, int dirtype, char *name)
{
	pstring directory;
	pstring mask;
	char *p;
	int count=0;
	NTSTATUS error = NT_STATUS_OK;
	BOOL has_wild;
	BOOL bad_path = False;
	BOOL rc = True;
	SMB_STRUCT_STAT sbuf;

	*directory = *mask = 0;

	rc = unix_convert(name,conn,0,&bad_path,&sbuf);

	p = strrchr(name,'/');
	if (!p) {
		pstrcpy(directory,".");
		pstrcpy(mask,name);
	} else {
		*p = 0;
		pstrcpy(directory,name);
		pstrcpy(mask,p+1);
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!rc && mangle_is_mangled(mask))
		mangle_check_cache( mask, sizeof(pstring)-1 );

	has_wild = ms_has_wild(mask);

	if (!has_wild) {
		pstrcat(directory,"/");
		pstrcat(directory,mask);
		error = can_delete(directory,conn,dirtype);
		if (!NT_STATUS_IS_OK(error))
			return error;

		if (vfs_unlink(conn,directory) == 0)
			count++;
	} else {
		void *dirptr = NULL;
		char *dname;
    		if (check_name(directory,conn))
		dirptr = OpenDir(conn, directory, True);

		/* XXXX the CIFS spec says that if bit0 of the flags2 field is set then
			the pattern matches against the long name, otherwise the short name 
			We don't implement this yet XXXX
		*/

		if (dirptr) {
			error = NT_STATUS_OBJECT_NAME_NOT_FOUND;

			if (strequal(mask,"????????.???"))
				pstrcpy(mask,"*");

			while ((dname = ReadDirName(dirptr))) {
				pstring fname;
				pstrcpy(fname,dname);
	    
				if(!mask_match(fname, mask, case_sensitive))
					continue;

				slprintf(fname,sizeof(fname)-1, "%s/%s",directory,dname);
				error = can_delete(fname,conn,dirtype);
				if (!NT_STATUS_IS_OK(error))
					continue;
				if (vfs_unlink(conn,fname) == 0)
					count++;
				DEBUG(3,("unlink_internals: succesful unlink [%s]\n",fname));
			}
			CloseDir(dirptr);
		}
	}
  
	if (count == 0 && NT_STATUS_IS_OK(error))
		error = map_nt_error_from_unix(errno);
  
	return error;
}

/****************************************************************************
 Reply to a unlink
****************************************************************************/

int reply_unlink(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	pstring name;
	int dirtype;
	NTSTATUS status;

	START_PROFILE(SMBunlink);

	dirtype = SVAL(inbuf,smb_vwv0);

	pstrcpy(name,smb_buf(inbuf) + 1);

	RESOLVE_DFSPATH(name, conn, inbuf, outbuf);

	DEBUG(3,("reply_unlink : %s\n",name));

	status = unlink_internals(conn, dirtype, name);
	if (!NT_STATUS_IS_OK(status))
		return ERROR_NT(status);

	/*
	 * Win2k needs a changenotify request response before it will
	 * update after a rename..
	 */

	process_pending_change_notify_queue((time_t)0);

	outsize = set_message(outbuf,0,0,True);
  
	END_PROFILE(SMBunlink);
	return outsize;
}

/****************************************************************************
 Fail for readbraw.
****************************************************************************/

void fail_readraw(void)
{
	pstring errstr;
	slprintf(errstr, sizeof(errstr)-1, "FAIL ! reply_readbraw: socket write fail (%s)",
		strerror(errno) );
	exit_server(errstr);
}

/****************************************************************************
 Use sendfile in readbraw.
****************************************************************************/

void send_file_readbraw(connection_struct *conn, files_struct *fsp, SMB_OFF_T startpos, size_t nread,
		ssize_t mincount, char *outbuf)
{
	ssize_t ret=0;

#if defined(WITH_SENDFILE)
	/*
	 * We can only use sendfile on a non-chained packet and on a file
	 * that is exclusively oplocked. reply_readbraw has already checked the length.
	 */

	if ((nread > 0) && (lp_write_cache_size(SNUM(conn)) == 0) &&
			EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type) && lp_use_sendfile(SNUM(conn)) ) {
		DATA_BLOB header;

		_smb_setlen(outbuf,nread);
		header.data = outbuf;
		header.length = 4;
		header.free = NULL;

		if ( conn->vfs_ops.sendfile( smbd_server_fd(), fsp, fsp->fd, &header, startpos, nread) == -1) {
			/*
			 * Special hack for broken Linux with no 64 bit clean sendfile. If we
			 * return ENOSYS then pretend we just got a normal read.
			 */
			if (errno == ENOSYS)
				goto normal_read;

			DEBUG(0,("send_file_readbraw: sendfile failed for file %s (%s). Terminating\n",
				fsp->fsp_name, strerror(errno) ));
			exit_server("send_file_readbraw sendfile failed");
		}

	}

  normal_read:
#endif

	if (nread > 0) {
		ret = read_file(fsp,outbuf+4,startpos,nread);
		if (ret < mincount)
			ret = 0;
	}

	_smb_setlen(outbuf,ret);
	if (write_data(smbd_server_fd(),outbuf,4+ret) != 4+ret)
		fail_readraw();
}

/****************************************************************************
 Reply to a readbraw (core+ protocol).
****************************************************************************/

int reply_readbraw(connection_struct *conn, char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	ssize_t maxcount,mincount;
	size_t nread = 0;
	SMB_OFF_T startpos;
	char *header = outbuf;
	files_struct *fsp;
	START_PROFILE(SMBreadbraw);

	/*
	 * Special check if an oplock break has been issued
	 * and the readraw request croses on the wire, we must
	 * return a zero length response here.
	 */

	if(global_oplock_break) {
		_smb_setlen(header,0);
		if (write_data(smbd_server_fd(),header,4) != 4)
			fail_readraw();
		DEBUG(5,("readbraw - oplock break finished\n"));
		END_PROFILE(SMBreadbraw);
		return -1;
	}

	fsp = file_fsp(inbuf,smb_vwv0);

	if (!FNUM_OK(fsp,conn) || !fsp->can_read) {
		/*
		 * fsp could be NULL here so use the value from the packet. JRA.
		 */
		DEBUG(3,("fnum %d not open in readbraw - cache prime?\n",(int)SVAL(inbuf,smb_vwv0)));
		_smb_setlen(header,0);
		if (write_data(smbd_server_fd(),header,4) != 4)
			fail_readraw();
		END_PROFILE(SMBreadbraw);
		return(-1);
	}

	CHECK_FSP(fsp,conn);

	flush_write_cache(fsp, READRAW_FLUSH);

	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv1);
	if(CVAL(inbuf,smb_wct) == 10) {
		/*
		 * This is a large offset (64 bit) read.
		 */
#ifdef LARGE_SMB_OFF_T

		startpos |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv8)) << 32);

#else /* !LARGE_SMB_OFF_T */

		/*
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(inbuf,smb_vwv8) != 0) {
			DEBUG(0,("readbraw - large offset (%x << 32) used and we don't support \
64 bit offsets.\n", (unsigned int)IVAL(inbuf,smb_vwv8) ));
			_smb_setlen(header,0);
			if (write_data(smbd_server_fd(),header,4) != 4)
				fail_readraw();
			END_PROFILE(SMBreadbraw);
			return(-1);
		}

#endif /* LARGE_SMB_OFF_T */

		if(startpos < 0) {
			DEBUG(0,("readbraw - negative 64 bit readraw offset (%.0f) !\n", (double)startpos ));
			_smb_setlen(header,0);
			if (write_data(smbd_server_fd(),header,4) != 4)
				fail_readraw();
			END_PROFILE(SMBreadbraw);
			return(-1);
		}      
	}
	maxcount = (SVAL(inbuf,smb_vwv3) & 0xFFFF);
	mincount = (SVAL(inbuf,smb_vwv4) & 0xFFFF);

	/* ensure we don't overrun the packet size */
	maxcount = MIN(65535,maxcount);
	maxcount = MAX(mincount,maxcount);

	if (!is_locked(fsp,conn,(SMB_BIG_UINT)maxcount,(SMB_BIG_UINT)startpos, READ_LOCK,False)) {
		SMB_OFF_T size = fsp->size;
		SMB_OFF_T sizeneeded = startpos + maxcount;
  
		if (size < sizeneeded) {
			SMB_STRUCT_STAT st;
			if (vfs_fstat(fsp,fsp->fd,&st) == 0)
				fsp->size = size = st.st_size;
		}

		if (startpos >= size)
			nread = 0;
		else
			nread = MIN(maxcount,(size - startpos));	  
	}

	if (nread < mincount)
		nread = 0;
  
	DEBUG( 3, ( "readbraw fnum=%d start=%.0f max=%d min=%d nread=%d\n", fsp->fnum, (double)startpos,
				(int)maxcount, (int)mincount, (int)nread ) );
  
	send_file_readbraw(conn, fsp, startpos, nread, mincount, outbuf);

	DEBUG(5,("readbraw finished\n"));
	END_PROFILE(SMBreadbraw);
	return -1;
}

/****************************************************************************
 Reply to a lockread (core+ protocol).
****************************************************************************/

int reply_lockread(connection_struct *conn, char *inbuf,char *outbuf, int length, int dum_buffsiz)
{
	ssize_t nread = -1;
	char *data;
	int outsize = 0;
	SMB_OFF_T startpos;
	size_t numtoread;
	NTSTATUS status;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBlockread);

	CHECK_FSP(fsp,conn);
	CHECK_READ(fsp);

	release_level_2_oplocks_on_change(fsp);

	numtoread = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  
	outsize = set_message(outbuf,5,3,True);
	numtoread = MIN(BUFFER_SIZE-outsize,numtoread);
	data = smb_buf(outbuf) + 3;
 
	/*
	 * NB. Discovered by Menny Hamburger at Mainsoft. This is a core+
	 * protocol request that predates the read/write lock concept. 
	 * Thus instead of asking for a read lock here we need to ask
	 * for a write lock. JRA.
	 */

	status = do_lock_spin(fsp, conn, SVAL(inbuf,smb_pid), 
			 (SMB_BIG_UINT)numtoread, (SMB_BIG_UINT)startpos, WRITE_LOCK);

	if (NT_STATUS_V(status)) {
		if (lp_blocking_locks(SNUM(conn)) && ERROR_WAS_LOCK_DENIED(status)) {
			/*
			 * A blocking lock was requested. Package up
			 * this smb into a queued request and push it
			 * onto the blocking lock queue.
			 */
			if(push_blocking_lock_request(inbuf, length, -1, 0, SVAL(inbuf,smb_pid), (SMB_BIG_UINT)startpos,
								(SMB_BIG_UINT)numtoread)) {
				END_PROFILE(SMBlockread);
				return -1;
			}
		}
		END_PROFILE(SMBlockread);
		return ERROR_NT(status);
	}

	nread = read_file(fsp,data,startpos,numtoread);

	if (nread < 0) {
		END_PROFILE(SMBlockread);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	outsize += nread;
	SSVAL(outbuf,smb_vwv0,nread);
	SSVAL(outbuf,smb_vwv5,nread+3);
	SSVAL(smb_buf(outbuf),1,nread);

	DEBUG( 3, ( "lockread fnum=%d num=%d nread=%d\n",
		fsp->fnum, (int)numtoread, (int)nread ) );

	END_PROFILE(SMBlockread);
	return(outsize);
}

/****************************************************************************
 Reply to a read.
****************************************************************************/

int reply_read(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	size_t numtoread;
	ssize_t nread = 0;
	char *data;
	SMB_OFF_T startpos;
	int outsize = 0;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBread);

	CHECK_FSP(fsp,conn);
	CHECK_READ(fsp);

	numtoread = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  
	outsize = set_message(outbuf,5,3,True);
	numtoread = MIN(BUFFER_SIZE-outsize,numtoread);
	data = smb_buf(outbuf) + 3;
  
	if (is_locked(fsp,conn,(SMB_BIG_UINT)numtoread,(SMB_BIG_UINT)startpos, READ_LOCK,False)) {
		END_PROFILE(SMBread);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	if (numtoread > 0)
		nread = read_file(fsp,data,startpos,numtoread);
  
	if (nread < 0) {
		END_PROFILE(SMBread);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}
  
	outsize += nread;
	SSVAL(outbuf,smb_vwv0,nread);
	SSVAL(outbuf,smb_vwv5,nread+3);
	SCVAL(smb_buf(outbuf),0,1);
	SSVAL(smb_buf(outbuf),1,nread);
  
	DEBUG( 3, ( "read fnum=%d num=%d nread=%d\n",
		fsp->fnum, (int)numtoread, (int)nread ) );

	END_PROFILE(SMBread);
	return(outsize);
}

/****************************************************************************
 Reply to a read and X - possibly using sendfile.
****************************************************************************/

int send_file_readX(connection_struct *conn, char *inbuf,char *outbuf,int length, 
		files_struct *fsp, SMB_OFF_T startpos, size_t smb_maxcnt)
{
	ssize_t nread = -1;
	char *data = smb_buf(outbuf);

#if defined(WITH_SENDFILE)
	/*
	 * We can only use sendfile on a non-chained packet and on a file
	 * that is exclusively oplocked.
	 */

	if ((CVAL(inbuf,smb_vwv0) == 0xFF) && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type) &&
			lp_use_sendfile(SNUM(conn)) && (lp_write_cache_size(SNUM(conn)) == 0) ) {
		SMB_STRUCT_STAT sbuf;
		DATA_BLOB header;

		if(vfs_fstat(fsp,fsp->fd, &sbuf) == -1)
			return(UNIXERROR(ERRDOS,ERRnoaccess));

		if (startpos > sbuf.st_size)
			goto normal_read;

		if (smb_maxcnt > (sbuf.st_size - startpos))
			smb_maxcnt = (sbuf.st_size - startpos);

		if (smb_maxcnt == 0)
			goto normal_read;

		/* 
		 * Set up the packet header before send. We
		 * assume here the sendfile will work (get the
		 * correct amount of data).
		 */

		SSVAL(outbuf,smb_vwv5,smb_maxcnt);
		SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
		SSVAL(smb_buf(outbuf),-2,smb_maxcnt);
		SCVAL(outbuf,smb_vwv0,0xFF);
		set_message(outbuf,12,smb_maxcnt,False);
		header.data = outbuf;
		header.length = data - outbuf;
		header.free = NULL;

		if ( conn->vfs_ops.sendfile( smbd_server_fd(), fsp, fsp->fd, &header, startpos, smb_maxcnt) == -1) {
			/*
			 * Special hack for broken Linux with no 64 bit clean sendfile. If we
			 * return ENOSYS then pretend we just got a normal read.
			 */
			if (errno == ENOSYS)
				goto normal_read;

			DEBUG(0,("send_file_readX: sendfile failed for file %s (%s). Terminating\n",
				fsp->fsp_name, strerror(errno) ));
			exit_server("send_file_readX sendfile failed");
		}

		DEBUG( 3, ( "send_file_readX: sendfile fnum=%d max=%d nread=%d\n",
			fsp->fnum, (int)smb_maxcnt, (int)nread ) );
		return -1;
	}

  normal_read:

#endif

	nread = read_file(fsp,data,startpos,smb_maxcnt);
  
	if (nread < 0) {
		END_PROFILE(SMBreadX);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	SSVAL(outbuf,smb_vwv5,nread);
	SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
	SSVAL(smb_buf(outbuf),-2,nread);
  
	DEBUG( 3, ( "send_file_readX fnum=%d max=%d nread=%d\n",
		fsp->fnum, (int)smb_maxcnt, (int)nread ) );

	return nread;
}

/****************************************************************************
 Reply to a read and X.
****************************************************************************/

int reply_read_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	files_struct *fsp = file_fsp(inbuf,smb_vwv2);
	SMB_OFF_T startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
	size_t smb_maxcnt = SVAL(inbuf,smb_vwv5);
#if 0
	size_t smb_mincnt = SVAL(inbuf,smb_vwv6);
#endif
	ssize_t nread = -1;
	char *data;
	START_PROFILE(SMBreadX);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		END_PROFILE(SMBreadX);
		return reply_pipe_read_and_X(inbuf,outbuf,length,bufsize);
	}

	CHECK_FSP(fsp,conn);
	CHECK_READ(fsp);

	set_message(outbuf,12,0,True);
	data = smb_buf(outbuf);

	if(CVAL(inbuf,smb_wct) == 12) {
#ifdef LARGE_SMB_OFF_T
		/*
		 * This is a large offset (64 bit) read.
		 */
		startpos |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv10)) << 32);

#else /* !LARGE_SMB_OFF_T */

		/*
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(inbuf,smb_vwv10) != 0) {
			DEBUG(0,("reply_read_and_X - large offset (%x << 32) used and we don't support \
64 bit offsets.\n", (unsigned int)IVAL(inbuf,smb_vwv10) ));
			END_PROFILE(SMBreadX);
			return ERROR_DOS(ERRDOS,ERRbadaccess);
		}

#endif /* LARGE_SMB_OFF_T */

	}

	if (is_locked(fsp,conn,(SMB_BIG_UINT)smb_maxcnt,(SMB_BIG_UINT)startpos, READ_LOCK,False)) {
		END_PROFILE(SMBreadX);
		return ERROR_DOS(ERRDOS,ERRlock);
	}
	nread = send_file_readX(conn, inbuf, outbuf, length, fsp, startpos, smb_maxcnt);
	if (nread != -1)
		nread = chain_reply(inbuf,outbuf,length,bufsize);

	END_PROFILE(SMBreadX);
	return nread;
}

/****************************************************************************
 Reply to a writebraw (core+ or LANMAN1.0 protocol).
****************************************************************************/

int reply_writebraw(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	ssize_t nwritten=0;
	ssize_t total_written=0;
	size_t numtowrite=0;
	size_t tcount;
	SMB_OFF_T startpos;
	char *data=NULL;
	BOOL write_through;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	int outsize = 0;
	START_PROFILE(SMBwritebraw);

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);
  
	tcount = IVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
	write_through = BITSETW(inbuf+smb_vwv7,0);

	/* We have to deal with slightly different formats depending
		on whether we are using the core+ or lanman1.0 protocol */

	if(Protocol <= PROTOCOL_COREPLUS) {
		numtowrite = SVAL(smb_buf(inbuf),-2);
		data = smb_buf(inbuf);
	} else {
		numtowrite = SVAL(inbuf,smb_vwv10);
		data = smb_base(inbuf) + SVAL(inbuf, smb_vwv11);
	}

	/* force the error type */
	SCVAL(inbuf,smb_com,SMBwritec);
	SCVAL(outbuf,smb_com,SMBwritec);

	if (is_locked(fsp,conn,(SMB_BIG_UINT)tcount,(SMB_BIG_UINT)startpos, WRITE_LOCK,False)) {
		END_PROFILE(SMBwritebraw);
		return(ERROR_DOS(ERRDOS,ERRlock));
	}

	if (numtowrite>0)
		nwritten = write_file(fsp,data,startpos,numtowrite);
  
	DEBUG(3,("writebraw1 fnum=%d start=%.0f num=%d wrote=%d sync=%d\n",
		fsp->fnum, (double)startpos, (int)numtowrite, (int)nwritten, (int)write_through));

	if (nwritten < (ssize_t)numtowrite)  {
		END_PROFILE(SMBwritebraw);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	total_written = nwritten;

	/* Return a message to the redirector to tell it to send more bytes */
	SCVAL(outbuf,smb_com,SMBwritebraw);
	SSVALS(outbuf,smb_vwv0,-1);
	outsize = set_message(outbuf,Protocol>PROTOCOL_COREPLUS?1:0,0,True);
	if (!send_smb(smbd_server_fd(),outbuf))
		exit_server("reply_writebraw: send_smb failed.");
  
	/* Now read the raw data into the buffer and write it */
	if (read_smb_length(smbd_server_fd(),inbuf,SMB_SECONDARY_WAIT) == -1) {
		exit_server("secondary writebraw failed");
	}
  
	/* Even though this is not an smb message, smb_len returns the generic length of an smb message */
	numtowrite = smb_len(inbuf);

	/* Set up outbuf to return the correct return */
	outsize = set_message(outbuf,1,0,True);
	SCVAL(outbuf,smb_com,SMBwritec);
	SSVAL(outbuf,smb_vwv0,total_written);

	if (numtowrite != 0) {

		if (numtowrite > BUFFER_SIZE) {
			DEBUG(0,("reply_writebraw: Oversize secondary write raw requested (%u). Terminating\n",
				(unsigned int)numtowrite ));
			exit_server("secondary writebraw failed");
		}

		if (tcount > nwritten+numtowrite) {
			DEBUG(3,("Client overestimated the write %d %d %d\n",
				(int)tcount,(int)nwritten,(int)numtowrite));
		}

		if (read_data( smbd_server_fd(), inbuf+4, numtowrite) != numtowrite ) {
			DEBUG(0,("reply_writebraw: Oversize secondary write raw read failed (%s). Terminating\n",
				strerror(errno) ));
			exit_server("secondary writebraw failed");
		}

		nwritten = write_file(fsp,inbuf+4,startpos+nwritten,numtowrite);

		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(outbuf,smb_rcls,ERRHRD);
			SSVAL(outbuf,smb_err,ERRdiskfull);      
		}

		if (nwritten > 0)
			total_written += nwritten;
 	}
 
	if ((lp_syncalways(SNUM(conn)) || write_through) && lp_strict_sync(SNUM(conn)))
		sync_file(conn,fsp);

	DEBUG(3,("writebraw2 fnum=%d start=%.0f num=%d wrote=%d\n",
		fsp->fnum, (double)startpos, (int)numtowrite,(int)total_written));

	/* we won't return a status if write through is not selected - this follows what WfWg does */
	END_PROFILE(SMBwritebraw);
	if (!write_through && total_written==tcount) {
		/*
		 * Fix for "rabbit pellet" mode, trigger an early TCP ack by
		 * sending a SMBkeepalive. Thanks to DaveCB at Sun for this. JRA.
		 */
		if (!send_keepalive(smbd_server_fd()))
			exit_server("reply_writebraw: send of keepalive failed");
		return(-1);
	}

	return(outsize);
}

/****************************************************************************
 Reply to a writeunlock (core+).
****************************************************************************/

int reply_writeunlock(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
  ssize_t nwritten = -1;
  size_t numtowrite;
  SMB_OFF_T startpos;
  char *data;
	NTSTATUS status;
  files_struct *fsp = file_fsp(inbuf,smb_vwv0);
  int outsize = 0;
  START_PROFILE(SMBwriteunlock);

  CHECK_FSP(fsp,conn);
  CHECK_WRITE(fsp);

  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  data = smb_buf(inbuf) + 3;
  
	if (is_locked(fsp,conn,(SMB_BIG_UINT)numtowrite,(SMB_BIG_UINT)startpos, 
		      WRITE_LOCK,False)) {
    END_PROFILE(SMBwriteunlock);
		return ERROR_DOS(ERRDOS,ERRlock);
  }

  /* The special X/Open SMB protocol handling of
     zero length writes is *NOT* done for
     this call */
  if(numtowrite == 0)
    nwritten = 0;
  else
    nwritten = write_file(fsp,data,startpos,numtowrite);
  
  if (lp_syncalways(SNUM(conn)))
      sync_file(conn,fsp);

  if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
    END_PROFILE(SMBwriteunlock);
    return(UNIXERROR(ERRHRD,ERRdiskfull));
  }

	status = do_unlock(fsp, conn, SVAL(inbuf,smb_pid), (SMB_BIG_UINT)numtowrite, 
			   (SMB_BIG_UINT)startpos);
	if (NT_STATUS_V(status)) {
    END_PROFILE(SMBwriteunlock);
		return ERROR_NT(status);
  }

  outsize = set_message(outbuf,1,0,True);
  
  SSVAL(outbuf,smb_vwv0,nwritten);
  
  DEBUG( 3, ( "writeunlock fnum=%d num=%d wrote=%d\n",
	      fsp->fnum, (int)numtowrite, (int)nwritten ) );

  END_PROFILE(SMBwriteunlock);
  return(outsize);
}

/****************************************************************************
 Reply to a write.
****************************************************************************/

int reply_write(connection_struct *conn, char *inbuf,char *outbuf,int size,int dum_buffsize)
{
	size_t numtowrite;
	ssize_t nwritten = -1;
	SMB_OFF_T startpos;
	char *data;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	int outsize = 0;
	START_PROFILE(SMBwrite);

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(conn)) {
		END_PROFILE(SMBwrite);
		return reply_pipe_write(inbuf,outbuf,size,dum_buffsize);
	}

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	numtowrite = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
	data = smb_buf(inbuf) + 3;
  
	if (is_locked(fsp,conn,(SMB_BIG_UINT)numtowrite,(SMB_BIG_UINT)startpos, WRITE_LOCK,False)) {
		END_PROFILE(SMBwrite);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	/*
	 * X/Open SMB protocol says that if smb_vwv1 is
	 * zero then the file size should be extended or
	 * truncated to the size given in smb_vwv[2-3].
	 */

	if(numtowrite == 0) {
		/*
		 * This is actually an allocate call, and set EOF. JRA.
		 */
		nwritten = vfs_allocate_file_space(fsp, (SMB_OFF_T)startpos);
		if (nwritten < 0) {
			END_PROFILE(SMBwrite);
			return ERROR_NT(NT_STATUS_DISK_FULL);
		}
		nwritten = vfs_set_filelen(fsp, (SMB_OFF_T)startpos);
		if (nwritten < 0) {
			END_PROFILE(SMBwrite);
			return ERROR_NT(NT_STATUS_DISK_FULL);
		}
	} else
		nwritten = write_file(fsp,data,startpos,numtowrite);
  
	if (lp_syncalways(SNUM(conn)))
		sync_file(conn,fsp);

	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		END_PROFILE(SMBwrite);
    		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	outsize = set_message(outbuf,1,0,True);
  
	SSVAL(outbuf,smb_vwv0,nwritten);

	if (nwritten < (ssize_t)numtowrite) {
		SCVAL(outbuf,smb_rcls,ERRHRD);
		SSVAL(outbuf,smb_err,ERRdiskfull);      
	}
  
	DEBUG(3,("write fnum=%d num=%d wrote=%d\n", fsp->fnum, (int)numtowrite, (int)nwritten));

	END_PROFILE(SMBwrite);
	return(outsize);
}

/****************************************************************************
 Reply to a write and X.
****************************************************************************/

int reply_write_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
  files_struct *fsp = file_fsp(inbuf,smb_vwv2);
  SMB_OFF_T startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
  size_t numtowrite = SVAL(inbuf,smb_vwv10);
  BOOL write_through = BITSETW(inbuf+smb_vwv7,0);
  ssize_t nwritten = -1;
  unsigned int smb_doff = SVAL(inbuf,smb_vwv11);
  unsigned int smblen = smb_len(inbuf);
  char *data;
  BOOL large_writeX = ((CVAL(inbuf,smb_wct) == 14) && (smblen > 0xFFFF));
  START_PROFILE(SMBwriteX);

  /* If it's an IPC, pass off the pipe handler. */
  if (IS_IPC(conn)) {
    END_PROFILE(SMBwriteX);
    return reply_pipe_write_and_X(inbuf,outbuf,length,bufsize);
  }

  CHECK_FSP(fsp,conn);
  CHECK_WRITE(fsp);

  /* Deal with possible LARGE_WRITEX */
  if (large_writeX)
    numtowrite |= ((((size_t)SVAL(inbuf,smb_vwv9)) & 1 )<<16);

  if(smb_doff > smblen || (smb_doff + numtowrite > smblen)) {
    END_PROFILE(SMBwriteX);
    return ERROR_DOS(ERRDOS,ERRbadmem);
  }

  data = smb_base(inbuf) + smb_doff;

  if(CVAL(inbuf,smb_wct) == 14) {
#ifdef LARGE_SMB_OFF_T
    /*
     * This is a large offset (64 bit) write.
     */
    startpos |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv12)) << 32);

#else /* !LARGE_SMB_OFF_T */

    /*
     * Ensure we haven't been sent a >32 bit offset.
     */

    if(IVAL(inbuf,smb_vwv12) != 0) {
      DEBUG(0,("reply_write_and_X - large offset (%x << 32) used and we don't support \
64 bit offsets.\n", (unsigned int)IVAL(inbuf,smb_vwv12) ));
      END_PROFILE(SMBwriteX);
      return ERROR_DOS(ERRDOS,ERRbadaccess);
    }

#endif /* LARGE_SMB_OFF_T */
  }

  if (is_locked(fsp,conn,(SMB_BIG_UINT)numtowrite,(SMB_BIG_UINT)startpos, WRITE_LOCK,False)) {
    END_PROFILE(SMBwriteX);
    return ERROR_DOS(ERRDOS,ERRlock);
  }

  /* X/Open SMB protocol says that, unlike SMBwrite
     if the length is zero then NO truncation is
     done, just a write of zero. To truncate a file,
     use SMBwrite. */
  if(numtowrite == 0)
    nwritten = 0;
  else
    nwritten = write_file(fsp,data,startpos,numtowrite);
  
  if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
    END_PROFILE(SMBwriteX);
    return(UNIXERROR(ERRHRD,ERRdiskfull));
  }

  set_message(outbuf,6,0,True);
  
  SSVAL(outbuf,smb_vwv2,nwritten);
  if (large_writeX)
    SSVAL(outbuf,smb_vwv4,(nwritten>>16)&1);

  if (nwritten < (ssize_t)numtowrite) {
    SCVAL(outbuf,smb_rcls,ERRHRD);
    SSVAL(outbuf,smb_err,ERRdiskfull);      
  }

  DEBUG(3,("writeX fnum=%d num=%d wrote=%d\n",
	   fsp->fnum, (int)numtowrite, (int)nwritten));

  if (lp_syncalways(SNUM(conn)) || write_through)
    sync_file(conn,fsp);

  END_PROFILE(SMBwriteX);
  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
 Reply to a lseek.
****************************************************************************/

int reply_lseek(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
  SMB_OFF_T startpos;
  SMB_OFF_T res= -1;
  int mode,umode;
  int outsize = 0;
  files_struct *fsp = file_fsp(inbuf,smb_vwv0);
  START_PROFILE(SMBlseek);

  CHECK_FSP(fsp,conn);

  flush_write_cache(fsp, SEEK_FLUSH);

  mode = SVAL(inbuf,smb_vwv1) & 3;
  /* NB. This doesn't use IVAL_TO_SMB_OFF_T as startpos can be signed in this case. */
  startpos = (SMB_OFF_T)IVALS(inbuf,smb_vwv2);

  switch (mode) {
    case 0: umode = SEEK_SET; break;
    case 1: umode = SEEK_CUR; break;
    case 2: umode = SEEK_END; break;
    default:
      umode = SEEK_SET; break;
  }

  if((res = conn->vfs_ops.lseek(fsp,fsp->fd,startpos,umode)) == -1) {
    /*
     * Check for the special case where a seek before the start
     * of the file sets the offset to zero. Added in the CIFS spec,
     * section 4.2.7.
     */

    if(errno == EINVAL) {
      SMB_OFF_T current_pos = startpos;

      if(umode == SEEK_CUR) {

        if((current_pos = conn->vfs_ops.lseek(fsp,fsp->fd,0,SEEK_CUR)) == -1) {
	  		END_PROFILE(SMBlseek);
          return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

        current_pos += startpos;

      } else if (umode == SEEK_END) {

        SMB_STRUCT_STAT sbuf;

        if(vfs_fstat(fsp,fsp->fd, &sbuf) == -1) {
		  END_PROFILE(SMBlseek);
          return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

        current_pos += sbuf.st_size;
      }
 
      if(current_pos < 0)
        res = conn->vfs_ops.lseek(fsp,fsp->fd,0,SEEK_SET);
    }

    if(res == -1) {
      END_PROFILE(SMBlseek);
      return(UNIXERROR(ERRDOS,ERRnoaccess));
    }
  }

  fsp->pos = res;
  
  outsize = set_message(outbuf,2,0,True);
  SIVAL(outbuf,smb_vwv0,res);
  
  DEBUG(3,("lseek fnum=%d ofs=%.0f newpos = %.0f mode=%d\n",
	   fsp->fnum, (double)startpos, (double)res, mode));

  END_PROFILE(SMBlseek);
  return(outsize);
}

/****************************************************************************
 Reply to a flush.
****************************************************************************/

int reply_flush(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBflush);

	CHECK_FSP(fsp,conn);

	if (!fsp) {
		file_sync_all(conn);
	} else {
		sync_file(conn,fsp);
	}

	DEBUG(3,("flush\n"));
	END_PROFILE(SMBflush);
	return(outsize);
}

/****************************************************************************
 Reply to a exit.
****************************************************************************/

int reply_exit(connection_struct *conn, 
	       char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize;
	START_PROFILE(SMBexit);
	outsize = set_message(outbuf,0,0,True);

	DEBUG(3,("exit\n"));

	END_PROFILE(SMBexit);
	return(outsize);
}


/****************************************************************************
 Reply to a close - has to deal with closing a directory opened by NT SMB's.
****************************************************************************/

int reply_close(connection_struct *conn, char *inbuf,char *outbuf, int size,
                int dum_buffsize)
{
	int outsize = 0;
	time_t mtime;
	files_struct *fsp = NULL;
	START_PROFILE(SMBclose);

	outsize = set_message(outbuf,0,0,True);

	/* If it's an IPC, pass off to the pipe handler. */
	if (IS_IPC(conn)) {
		END_PROFILE(SMBclose);
		return reply_pipe_close(conn, inbuf,outbuf);
	}

	fsp = file_fsp(inbuf,smb_vwv0);

	/*
	 * We can only use CHECK_FSP if we know it's not a directory.
	 */

	if(!fsp || (fsp->conn != conn)) {
		END_PROFILE(SMBclose);
		return ERROR_DOS(ERRDOS,ERRbadfid);
	}

	if(fsp->is_directory) {
		/*
		 * Special case - close NT SMB directory handle.
		 */
		DEBUG(3,("close %s fnum=%d\n", fsp->is_directory ? "directory" : "stat file open", fsp->fnum));
		close_file(fsp,True);
	} else {
		/*
		 * Close ordinary file.
		 */
		int close_err;
		pstring file_name;

		/* Save the name for time set in close. */
		pstrcpy( file_name, fsp->fsp_name);

		DEBUG(3,("close fd=%d fnum=%d (numopen=%d)\n",
			 fsp->fd, fsp->fnum,
			 conn->num_files_open));
 
		/*
		 * close_file() returns the unix errno if an error
		 * was detected on close - normally this is due to
		 * a disk full error. If not then it was probably an I/O error.
		 */
 
		if((close_err = close_file(fsp,True)) != 0) {
			errno = close_err;
			END_PROFILE(SMBclose);
			return (UNIXERROR(ERRHRD,ERRgeneral));
		}

		/*
		 * Now take care of any time sent in the close.
		 */

		mtime = make_unix_date3(inbuf+smb_vwv1);
		
		/* try and set the date */
		set_filetime(conn, file_name, mtime);

	}  

	END_PROFILE(SMBclose);
	return(outsize);
}

/****************************************************************************
 Reply to a writeclose (Core+ protocol)
****************************************************************************/

int reply_writeclose(connection_struct *conn,
		     char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	size_t numtowrite;
	ssize_t nwritten = -1;
	int outsize = 0;
	int close_err = 0;
	SMB_OFF_T startpos;
	char *data;
	time_t mtime;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBwriteclose);

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	numtowrite = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
	mtime = make_unix_date3(inbuf+smb_vwv4);
	data = smb_buf(inbuf) + 1;
  
	if (is_locked(fsp,conn,(SMB_BIG_UINT)numtowrite,(SMB_BIG_UINT)startpos, WRITE_LOCK,False)) {
		END_PROFILE(SMBwriteclose);
		return ERROR_DOS(ERRDOS,ERRlock);
	}
  
	nwritten = write_file(fsp,data,startpos,numtowrite);

	set_filetime(conn, fsp->fsp_name,mtime);
  
	close_err = close_file(fsp,True);

	DEBUG(3,("writeclose fnum=%d num=%d wrote=%d (numopen=%d)\n",
		 fsp->fnum, (int)numtowrite, (int)nwritten,
		 conn->num_files_open));
  
	if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)) {
		END_PROFILE(SMBwriteclose);
    		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}
 
	if(close_err != 0) {
		errno = close_err;
		END_PROFILE(SMBwriteclose);
		return(UNIXERROR(ERRHRD,ERRgeneral));
	}
 
	outsize = set_message(outbuf,1,0,True);
  
	SSVAL(outbuf,smb_vwv0,nwritten);
	END_PROFILE(SMBwriteclose);
	return(outsize);
}

/****************************************************************************
 Reply to a lock.
****************************************************************************/

int reply_lock(connection_struct *conn,
	       char *inbuf,char *outbuf, int length, int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	SMB_BIG_UINT count,offset;
	NTSTATUS status;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBlock);

	CHECK_FSP(fsp,conn);

	release_level_2_oplocks_on_change(fsp);

	count = (SMB_BIG_UINT)IVAL(inbuf,smb_vwv1);
	offset = (SMB_BIG_UINT)IVAL(inbuf,smb_vwv3);

	DEBUG(3,("lock fd=%d fnum=%d offset=%.0f count=%.0f\n",
		 fsp->fd, fsp->fnum, (double)offset, (double)count));

	status = do_lock_spin(fsp, conn, SVAL(inbuf,smb_pid), count, offset, WRITE_LOCK);
	if (NT_STATUS_V(status)) {
		if (lp_blocking_locks(SNUM(conn)) && ERROR_WAS_LOCK_DENIED(status)) {
			/*
			 * A blocking lock was requested. Package up
			 * this smb into a queued request and push it
			 * onto the blocking lock queue.
			 */
			if(push_blocking_lock_request(inbuf, length, -1, 0, SVAL(inbuf,smb_pid), offset, count)) {
				END_PROFILE(SMBlock);
				return -1;
			}
		}
		END_PROFILE(SMBlock);
		return ERROR_NT(status);
	}

	END_PROFILE(SMBlock);
	return(outsize);
}

/****************************************************************************
 Reply to a unlock.
****************************************************************************/

int reply_unlock(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
  int outsize = set_message(outbuf,0,0,True);
  SMB_BIG_UINT count,offset;
	NTSTATUS status;
  files_struct *fsp = file_fsp(inbuf,smb_vwv0);
  START_PROFILE(SMBunlock);

  CHECK_FSP(fsp,conn);

  count = (SMB_BIG_UINT)IVAL(inbuf,smb_vwv1);
  offset = (SMB_BIG_UINT)IVAL(inbuf,smb_vwv3);

	status = do_unlock(fsp, conn, SVAL(inbuf,smb_pid), count, offset);
	if (NT_STATUS_V(status)) {
    END_PROFILE(SMBunlock);
		return ERROR_NT(status);
  }

  DEBUG( 3, ( "unlock fd=%d fnum=%d offset=%.0f count=%.0f\n",
        fsp->fd, fsp->fnum, (double)offset, (double)count ) );
  
  END_PROFILE(SMBunlock);
  return(outsize);
}

/****************************************************************************
 Reply to a tdis.
****************************************************************************/

int reply_tdis(connection_struct *conn, 
	       char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	uint16 vuid;
	START_PROFILE(SMBtdis);

	vuid = SVAL(inbuf,smb_uid);

	if (!conn) {
		DEBUG(4,("Invalid connection in tdis\n"));
		END_PROFILE(SMBtdis);
		return ERROR_DOS(ERRSRV,ERRinvnid);
	}

	conn->used = False;

	close_cnum(conn,vuid);
  
	END_PROFILE(SMBtdis);
	return outsize;
}

/****************************************************************************
 Reply to a echo.
****************************************************************************/

int reply_echo(connection_struct *conn,
	       char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int smb_reverb = SVAL(inbuf,smb_vwv0);
	int seq_num;
	unsigned int data_len = smb_buflen(inbuf);
	int outsize = set_message(outbuf,1,data_len,True);
	START_PROFILE(SMBecho);

	data_len = MIN(data_len, (sizeof(inbuf)-(smb_buf(inbuf)-inbuf)));

	/* copy any incoming data back out */
	if (data_len > 0)
		memcpy(smb_buf(outbuf),smb_buf(inbuf),data_len);

	if (smb_reverb > 100) {
		DEBUG(0,("large reverb (%d)?? Setting to 100\n",smb_reverb));
		smb_reverb = 100;
	}

	for (seq_num =1 ; seq_num <= smb_reverb ; seq_num++) {
		SSVAL(outbuf,smb_vwv0,seq_num);

		smb_setlen(outbuf,outsize - 4);

		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_echo: send_smb failed.");
	}

	DEBUG(3,("echo %d times\n", smb_reverb));

	smb_echo_count++;

	END_PROFILE(SMBecho);
	return -1;
}

/****************************************************************************
 Reply to a printopen.
****************************************************************************/

int reply_printopen(connection_struct *conn, 
		    char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	files_struct *fsp;
	START_PROFILE(SMBsplopen);
	
	if (!CAN_PRINT(conn)) {
		END_PROFILE(SMBsplopen);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	/* Open for exclusive use, write only. */
	fsp = print_fsp_open(conn, NULL);

	if (!fsp) {
		END_PROFILE(SMBsplopen);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}

	outsize = set_message(outbuf,1,0,True);
	SSVAL(outbuf,smb_vwv0,fsp->fnum);
  
	DEBUG(3,("openprint fd=%d fnum=%d\n",
		 fsp->fd, fsp->fnum));

	END_PROFILE(SMBsplopen);
	return(outsize);
}

/****************************************************************************
 Reply to a printclose.
****************************************************************************/

int reply_printclose(connection_struct *conn,
		     char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = set_message(outbuf,0,0,True);
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	int close_err = 0;
	START_PROFILE(SMBsplclose);

	CHECK_FSP(fsp,conn);

	if (!CAN_PRINT(conn)) {
		END_PROFILE(SMBsplclose);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}
  
	DEBUG(3,("printclose fd=%d fnum=%d\n",
		 fsp->fd,fsp->fnum));
  
	close_err = close_file(fsp,True);

	if(close_err != 0) {
		errno = close_err;
		END_PROFILE(SMBsplclose);
		return(UNIXERROR(ERRHRD,ERRgeneral));
	}

	END_PROFILE(SMBsplclose);
	return(outsize);
}

/****************************************************************************
 Reply to a printqueue.
****************************************************************************/

int reply_printqueue(connection_struct *conn,
		     char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = set_message(outbuf,2,3,True);
	int max_count = SVAL(inbuf,smb_vwv0);
	int start_index = SVAL(inbuf,smb_vwv1);
	START_PROFILE(SMBsplretq);

	/* we used to allow the client to get the cnum wrong, but that
	   is really quite gross and only worked when there was only
	   one printer - I think we should now only accept it if they
	   get it right (tridge) */
	if (!CAN_PRINT(conn)) {
		END_PROFILE(SMBsplretq);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}

	SSVAL(outbuf,smb_vwv0,0);
	SSVAL(outbuf,smb_vwv1,0);
	SCVAL(smb_buf(outbuf),0,1);
	SSVAL(smb_buf(outbuf),1,0);
  
	DEBUG(3,("printqueue start_index=%d max_count=%d\n",
		 start_index, max_count));

	{
		print_queue_struct *queue = NULL;
		print_status_struct status;
		char *p = smb_buf(outbuf) + 3;
		int count = print_queue_status(SNUM(conn), &queue, &status);
		int num_to_get = ABS(max_count);
		int first = (max_count>0?start_index:start_index+max_count+1);
		int i;

		if (first >= count)
			num_to_get = 0;
		else
			num_to_get = MIN(num_to_get,count-first);
    

		for (i=first;i<first+num_to_get;i++) {
			/* check to make sure we have room in the buffer */
			if ( (PTR_DIFF(p, outbuf)+28) > BUFFER_SIZE )
				break;
			put_dos_date2(p,0,queue[i].time);
			SCVAL(p,4,(queue[i].status==LPQ_PRINTING?2:3));
			SSVAL(p,5, queue[i].job);
			SIVAL(p,7,queue[i].size);
			SCVAL(p,11,0);
			StrnCpy(p+12,queue[i].fs_user,16);
			p += 28;
		}

		if (count > 0) {
			outsize = set_message(outbuf,2,28*count+3,False); 
			SSVAL(outbuf,smb_vwv0,count);
			SSVAL(outbuf,smb_vwv1,(max_count>0?first+count:first-1));
			SCVAL(smb_buf(outbuf),0,1);
			SSVAL(smb_buf(outbuf),1,28*count);
		}

		SAFE_FREE(queue);
	  
		DEBUG(3,("%d entries returned in queue\n",count));
	}
  
	END_PROFILE(SMBsplretq);
	return(outsize);
}

/****************************************************************************
 Reply to a printwrite.
****************************************************************************/

int reply_printwrite(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int numtowrite;
  int outsize = set_message(outbuf,0,0,True);
  char *data;
  files_struct *fsp = file_fsp(inbuf,smb_vwv0);
  START_PROFILE(SMBsplwr);
  
  if (!CAN_PRINT(conn)) {
    END_PROFILE(SMBsplwr);
    return ERROR_DOS(ERRDOS,ERRnoaccess);
  }

  CHECK_FSP(fsp,conn);
  CHECK_WRITE(fsp);

  numtowrite = SVAL(smb_buf(inbuf),1);
  data = smb_buf(inbuf) + 3;
  
  if (write_file(fsp,data,-1,numtowrite) != numtowrite) {
    END_PROFILE(SMBsplwr);
    return(UNIXERROR(ERRHRD,ERRdiskfull));
  }

  DEBUG( 3, ( "printwrite fnum=%d num=%d\n", fsp->fnum, numtowrite ) );
  
  END_PROFILE(SMBsplwr);
  return(outsize);
}

/****************************************************************************
 The guts of the mkdir command, split out so it may be called by the NT SMB
 code. 
****************************************************************************/

NTSTATUS mkdir_internal(connection_struct *conn, pstring directory)
{
	BOOL bad_path = False;
	SMB_STRUCT_STAT sbuf;
	int ret= -1;
  
	unix_convert(directory,conn,0,&bad_path,&sbuf);
  
	if (check_name(directory, conn))
		ret = vfs_mkdir(conn,directory,unix_mode(conn,aDIR,directory));
  
	if (ret == -1) {
		NTSTATUS nterr = set_bad_path_error(errno, bad_path);
		if (!NT_STATUS_IS_OK(nterr))
			return nterr;
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a mkdir.
****************************************************************************/

int reply_mkdir(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	pstring directory;
	int outsize;
	NTSTATUS status;
	START_PROFILE(SMBmkdir);
 
	pstrcpy(directory,smb_buf(inbuf) + 1);

	RESOLVE_DFSPATH(directory, conn, inbuf, outbuf);

	status = mkdir_internal(conn, directory);
	if (!NT_STATUS_IS_OK(status))
		return ERROR_NT(status);

	outsize = set_message(outbuf,0,0,True);

	DEBUG( 3, ( "mkdir %s ret=%d\n", directory, outsize ) );

	END_PROFILE(SMBmkdir);
	return(outsize);
}

/****************************************************************************
 Static function used by reply_rmdir to delete an entire directory
 tree recursively. Return False on ok, True on fail.
****************************************************************************/

static BOOL recursive_rmdir(connection_struct *conn, char *directory)
{
	char *dname = NULL;
	BOOL ret = False;
	void *dirptr = OpenDir(conn, directory, False);

	if(dirptr == NULL)
		return True;

	while((dname = ReadDirName(dirptr))) {
		pstring fullname;
		SMB_STRUCT_STAT st;

		if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
			continue;

		/* Construct the full name. */
		if(strlen(directory) + strlen(dname) + 1 >= sizeof(fullname)) {
			errno = ENOMEM;
			ret = True;
			break;
		}

		pstrcpy(fullname, directory);
		pstrcat(fullname, "/");
		pstrcat(fullname, dname);

		if(conn->vfs_ops.lstat(conn,dos_to_unix_static(fullname), &st) != 0) {
			ret = True;
			break;
		}

		if(st.st_mode & S_IFDIR) {
			if(recursive_rmdir(conn, fullname)!=0) {
				ret = True;
				break;
			}
			if(vfs_rmdir(conn,fullname) != 0) {
				ret = True;
				break;
			}
		} else if(vfs_unlink(conn,fullname) != 0) {
			ret = True;
			break;
		}
	}

	CloseDir(dirptr);
	return ret;
}

/****************************************************************************
 The internals of the rmdir code - called elsewhere.
****************************************************************************/

BOOL rmdir_internals(connection_struct *conn, char *directory)
{
	BOOL ok;

	ok = (vfs_rmdir(conn,directory) == 0);
	if(!ok && ((errno == ENOTEMPTY)||(errno == EEXIST)) && lp_veto_files(SNUM(conn))) {
		/* 
		 * Check to see if the only thing in this directory are
		 * vetoed files/directories. If so then delete them and
		 * retry. If we fail to delete any of them (and we *don't*
		 * do a recursive delete) then fail the rmdir.
		 */
		BOOL all_veto_files = True;
		char *dname;
		void *dirptr = OpenDir(conn, directory, False);

		if(dirptr != NULL) {
			int dirpos = TellDir(dirptr);
			while ((dname = ReadDirName(dirptr))) {
				if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
					continue;
				if(!IS_VETO_PATH(conn, dname)) {
					all_veto_files = False;
					break;
				}
			}
			if(all_veto_files) {
				SeekDir(dirptr,dirpos);
				while ((dname = ReadDirName(dirptr))) {
					pstring fullname;
					SMB_STRUCT_STAT st;

					if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
						continue;

					/* Construct the full name. */
					if(strlen(directory) + strlen(dname) + 1 >= sizeof(fullname)) {
						errno = ENOMEM;
						break;
					}
					pstrcpy(fullname, directory);
					pstrcat(fullname, "/");
					pstrcat(fullname, dname);
                     
					if(conn->vfs_ops.lstat(conn,dos_to_unix_static(fullname), &st) != 0)
						break;
					if(st.st_mode & S_IFDIR) {
						if(lp_recursive_veto_delete(SNUM(conn))) {
							if(recursive_rmdir(conn, fullname) != 0)
								break;
						}
						if(vfs_rmdir(conn,fullname) != 0)
							break;
					} else if(vfs_unlink(conn,fullname) != 0)
						break;
				}
				CloseDir(dirptr);
				/* Retry the rmdir */
				ok = (vfs_rmdir(conn,directory) == 0);
			} else {
				CloseDir(dirptr);
			}
		} else {
			errno = ENOTEMPTY;
		}
	}
          
	if (!ok)
		DEBUG(3,("rmdir_internals: couldn't remove directory %s : %s\n", directory,strerror(errno)));

	return ok;
}

/****************************************************************************
 Reply to a rmdir.
****************************************************************************/

int reply_rmdir(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring directory;
  int outsize = 0;
  BOOL ok = False;
  BOOL bad_path = False;
  SMB_STRUCT_STAT sbuf;
  START_PROFILE(SMBrmdir);

  pstrcpy(directory,smb_buf(inbuf) + 1);

  RESOLVE_DFSPATH(directory, conn, inbuf, outbuf)

  unix_convert(directory,conn, NULL,&bad_path,&sbuf);
  
  if (check_name(directory,conn))
  {
    dptr_closepath(directory,SVAL(inbuf,smb_pid));
    ok = rmdir_internals(conn, directory);
  }
  
  if (!ok)
  {
    set_bad_path_error(errno, bad_path);
    END_PROFILE(SMBrmdir);
    return(UNIXERROR(ERRDOS,ERRbadpath));
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG( 3, ( "rmdir %s\n", directory ) );
  
  END_PROFILE(SMBrmdir);
  return(outsize);
}

/*******************************************************************
 Resolve wildcards in a filename rename.
********************************************************************/

static BOOL resolve_wildcards(char *name1,char *name2)
{
  fstring root1,root2;
  fstring ext1,ext2;
  char *p,*p2;

  name1 = strrchr(name1,'/');
  name2 = strrchr(name2,'/');

  if (!name1 || !name2) return(False);
  
  fstrcpy(root1,name1);
  fstrcpy(root2,name2);
  p = strrchr(root1,'.');
  if (p) {
    *p = 0;
    fstrcpy(ext1,p+1);
  } else {
    fstrcpy(ext1,"");    
  }
  p = strrchr(root2,'.');
  if (p) {
    *p = 0;
    fstrcpy(ext2,p+1);
  } else {
    fstrcpy(ext2,"");    
  }

  p = root1;
  p2 = root2;
  while (*p2) {
    if (*p2 == '?') {
      *p2 = *p;
      p2++;
    } else {
      p2++;
    }
    if (*p) p++;
  }

  p = ext1;
  p2 = ext2;
  while (*p2) {
    if (*p2 == '?') {
      *p2 = *p;
      p2++;
    } else {
      p2++;
    }
    if (*p) p++;
  }

  pstrcpy(name2,root2);
  if (ext2[0]) {
    pstrcat(name2,".");
    pstrcat(name2,ext2);
  }

  return(True);
}

/****************************************************************************
 The guts of the rename command, split out so it may be called by the NT SMB
 code. 
****************************************************************************/

NTSTATUS rename_internals(connection_struct *conn, char *name, char *newname, BOOL replace_if_exists)
{
	pstring directory;
	pstring mask;
	pstring newname_last_component;
	char *p;
	BOOL has_wild;
	BOOL bad_path1 = False;
	BOOL bad_path2 = False;
	int count=0;
	NTSTATUS error = NT_STATUS_OK;
	BOOL rc = True;
	SMB_STRUCT_STAT sbuf1, sbuf2;

	*directory = *mask = 0;

	rc = unix_convert(name,conn,0,&bad_path1,&sbuf1);
	unix_convert(newname,conn,newname_last_component,&bad_path2,&sbuf2);

	/*
	 * Split the old name into directory and last component
	 * strings. Note that unix_convert may have stripped off a 
	 * leading ./ from both name and newname if the rename is 
	 * at the root of the share. We need to make sure either both
	 * name and newname contain a / character or neither of them do
	 * as this is checked in resolve_wildcards().
	 */
	
	p = strrchr(name,'/');
	if (!p) {
		pstrcpy(directory,".");
		pstrcpy(mask,name);
	} else {
		*p = 0;
		pstrcpy(directory,name);
		pstrcpy(mask,p+1);
		*p = '/'; /* Replace needed for exceptional test below. */
	}

	/*
	 * We should only check the mangled cache
	 * here if unix_convert failed. This means
	 * that the path in 'mask' doesn't exist
	 * on the file system and so we need to look
	 * for a possible mangle. This patch from
	 * Tine Smukavec <valentin.smukavec@hermes.si>.
	 */

	if (!rc && mangle_is_mangled(mask))
		mangle_check_cache( mask, sizeof(pstring)-1 );

	has_wild = ms_has_wild(mask);

	if (!has_wild) {
		pstring zdirectory;
		pstring znewname;

		/*
		 * No wildcards - just process the one file.
		 */
		BOOL is_short_name = mangle_is_8_3(name, True);

		/* Add a terminating '/' to the directory name. */
		pstrcat(directory,"/");
		pstrcat(directory,mask);
		
		/* Ensure newname contains a '/' also */
		if(strrchr(newname,'/') == 0) {
			pstring tmpstr;
			
			pstrcpy(tmpstr, "./");
			pstrcat(tmpstr, newname);
			pstrcpy(newname, tmpstr);
		}
		
		DEBUG(3,("rename_internals: case_sensitive = %d, case_preserve = %d, short case preserve = %d, \
directory = %s, newname = %s, newname_last_component = %s, mangle_is_8_3 = %d\n", 
			 case_sensitive, case_preserve, short_case_preserve, directory, 
			 newname, newname_last_component, is_short_name));

		/*
		 * Check for special case with case preserving and not
		 * case sensitive, if directory and newname are identical,
		 * and the old last component differs from the original
		 * last component only by case, then we should allow
		 * the rename (user is trying to change the case of the
		 * filename).
		 */
		if((case_sensitive == False) && 
		   (((case_preserve == True) && 
		     (is_short_name == False)) || 
		    ((short_case_preserve == True) && 
		     (is_short_name == True))) &&
		   strcsequal(directory, newname)) {
			pstring newname_modified_last_component;

			/*
			 * Get the last component of the modified name.
			 * Note that we guarantee that newname contains a '/'
			 * character above.
			 */
			p = strrchr(newname,'/');
			pstrcpy(newname_modified_last_component,p+1);
			
			if(strcsequal(newname_modified_last_component, 
				      newname_last_component) == False) {
				/*
				 * Replace the modified last component with
				 * the original.
				 */
				pstrcpy(p+1, newname_last_component);
			}
		}
		

		resolve_wildcards(directory,newname);

		/*
		 * The source object must exist.
		 */

		if (!vfs_object_exist(conn, directory, &sbuf1)) {
			DEBUG(3,("rename_internals: source doesn't exist doing rename %s -> %s\n",
				directory,newname));

			if (errno == ENOTDIR || errno == EISDIR || errno == ENOENT) {
				/*
				 * Must return different errors depending on whether the parent
				 * directory existed or not.
				 */

				p = strrchr(directory, '/');
				if (!p)
					return NT_STATUS_OBJECT_NAME_NOT_FOUND;
				*p = '\0';
				if (vfs_object_exist(conn, directory, NULL))
					return NT_STATUS_OBJECT_NAME_NOT_FOUND;
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}
			error = map_nt_error_from_unix(errno);
			DEBUG(3,("rename_internals: Error %s rename %s -> %s\n",
				get_nt_error_msg(error), directory,newname));

			return error;
		}

		error = can_rename(directory,conn,&sbuf1);

		if (!NT_STATUS_IS_OK(error)) {
			DEBUG(3,("rename_internals: Error %s rename %s -> %s\n",
				get_nt_error_msg(error), directory,newname));
			return error;
		}

               	pstrcpy(zdirectory, dos_to_unix_static(directory));
		pstrcpy(znewname, dos_to_unix_static(newname));

		/*
		 * If the src and dest names are identical - including case,
		 * don't do the rename, just return success.
		 */

		if (strcsequal(zdirectory, znewname)) {
			DEBUG(3,("rename_internals: identical names in rename %s - returning success\n", directory));
			return NT_STATUS_OK;
		}

		if(!replace_if_exists && vfs_object_exist(conn,newname,NULL)) {
			DEBUG(3,("rename_internals: dest exists doing rename %s -> %s\n",
				directory,newname));
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}

		if(conn->vfs_ops.rename(conn,zdirectory, znewname) == 0) {
			DEBUG(3,("rename_internals: succeeded doing rename on %s -> %s\n",
				directory,newname));
			return NT_STATUS_OK;	
		}

		if (errno == ENOTDIR || errno == EISDIR)
			error = NT_STATUS_OBJECT_NAME_COLLISION;
		else
			error = map_nt_error_from_unix(errno);
		
		DEBUG(3,("rename_internals: Error %s rename %s -> %s\n",
			get_nt_error_msg(error), directory,newname));

		return error;
	} else {

		/*
		 * Wildcards - process each file that matches.
		 */
		void *dirptr = NULL;
		char *dname;
		pstring destname;
		
		if (check_name(directory,conn))
			dirptr = OpenDir(conn, directory, True);
		
		if (dirptr) {
			error = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			
			if (strequal(mask,"????????.???"))
				pstrcpy(mask,"*");
			
			while ((dname = ReadDirName(dirptr))) {
				pstring fname;

				pstrcpy(fname,dname);
				
				if(!mask_match(fname, mask, case_sensitive))
					continue;
				
				error = NT_STATUS_ACCESS_DENIED;
				slprintf(fname,sizeof(fname)-1,"%s/%s",directory,dname);
				if (!vfs_object_exist(conn, fname, &sbuf1)) {
					error = NT_STATUS_OBJECT_NAME_NOT_FOUND;
					DEBUG(6,("rename %s failed. Error %s\n", fname, get_nt_error_msg(error)));
					continue;
				}
				error = can_rename(fname,conn,&sbuf1);
				if (!NT_STATUS_IS_OK(error)) {
					DEBUG(6,("rename %s failed. Error %s\n", fname, get_nt_error_msg(error)));
					continue;
				}
				pstrcpy(destname,newname);
				
				if (!resolve_wildcards(fname,destname)) {
					DEBUG(6,("resolve_wildcards %s %s failed\n", 
                                                 fname, destname));
					continue;
				}
				
				if (!replace_if_exists && 
                                    vfs_object_exist(conn,destname, NULL)) {
					DEBUG(6,("file_exist %s\n", destname));
					error = NT_STATUS_OBJECT_NAME_COLLISION;
					continue;
				}
				
				if (!conn->vfs_ops.rename(conn,dos_to_unix_static(fname),
                                                          dos_to_unix_static(destname)))
					count++;
				DEBUG(3,("rename_internals: doing rename on %s -> %s\n",fname,destname));
			}
			CloseDir(dirptr);
		}
	}

	if (count == 0 && NT_STATUS_IS_OK(error)) {
		error = map_nt_error_from_unix(errno);
	}
	
	return error;
}

/****************************************************************************
 Reply to a mv.
****************************************************************************/

int reply_mv(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	pstring name;
	pstring newname;
	NTSTATUS status;
	START_PROFILE(SMBmv);

	pstrcpy(name,smb_buf(inbuf) + 1);
	pstrcpy(newname,smb_buf(inbuf) + 3 + strlen(name));

	RESOLVE_DFSPATH(name, conn, inbuf, outbuf);
	RESOLVE_DFSPATH(newname, conn, inbuf, outbuf);

	DEBUG(3,("reply_mv : %s -> %s\n",name,newname));

	status = rename_internals(conn, name, newname, False);
	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}

	/*
	 * Win2k needs a changenotify request response before it will
	 * update after a rename..
	 */
	process_pending_change_notify_queue((time_t)0);
	outsize = set_message(outbuf,0,0,True);
  
	END_PROFILE(SMBmv);
	return(outsize);
}

/*******************************************************************
 Copy a file as part of a reply_copy.
******************************************************************/

static BOOL copy_file(char *src,char *dest1,connection_struct *conn, int ofun,
		      int count,BOOL target_is_directory, int *err_ret)
{
	int Access,action;
	SMB_STRUCT_STAT src_sbuf, sbuf2;
	SMB_OFF_T ret=-1;
	files_struct *fsp1,*fsp2;
	pstring dest;
  
	*err_ret = 0;

	pstrcpy(dest,dest1);
	if (target_is_directory) {
		char *p = strrchr(src,'/');
		if (p) 
			p++;
		else
			p = src;
		pstrcat(dest,"/");
		pstrcat(dest,p);
	}

	if (!vfs_file_exist(conn,src,&src_sbuf))
		return(False);

	fsp1 = open_file_shared(conn,src,&src_sbuf,SET_DENY_MODE(DENY_NONE)|SET_OPEN_MODE(DOS_OPEN_RDONLY),
					(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),0,0,&Access,&action);

	if (!fsp1)
		return(False);

	if (!target_is_directory && count)
		ofun = FILE_EXISTS_OPEN;

	if (vfs_stat(conn,dest,&sbuf2) == -1)
		ZERO_STRUCTP(&sbuf2);

	fsp2 = open_file_shared(conn,dest,&sbuf2,SET_DENY_MODE(DENY_NONE)|SET_OPEN_MODE(DOS_OPEN_WRONLY),
			ofun,src_sbuf.st_mode,0,&Access,&action);

	if (!fsp2) {
		close_file(fsp1,False);
		return(False);
	}

	if ((ofun&3) == 1) {
		if(conn->vfs_ops.lseek(fsp2,fsp2->fd,0,SEEK_END) == -1) {
			DEBUG(0,("copy_file: error - vfs lseek returned error %s\n", strerror(errno) ));
			/*
			 * Stop the copy from occurring.
			 */
			ret = -1;
			src_sbuf.st_size = 0;
		}
	}
  
	if (src_sbuf.st_size)
		ret = vfs_transfer_file(fsp1, fsp2, src_sbuf.st_size);

	close_file(fsp1,False);

	/* Ensure the modtime is set correctly on the destination file. */
	fsp2->pending_modtime = src_sbuf.st_mtime;

	/*
	 * As we are opening fsp1 read-only we only expect
	 * an error on close on fsp2 if we are out of space.
	 * Thus we don't look at the error return from the
	 * close of fsp1.
	 */
	*err_ret = close_file(fsp2,False);

	return(ret == (SMB_OFF_T)src_sbuf.st_size);
}

/****************************************************************************
 Reply to a file copy.
****************************************************************************/

int reply_copy(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int outsize = 0;
  pstring name;
  pstring directory;
  pstring mask,newname;
  char *p;
  int count=0;
  int error = ERRnoaccess;
  int err = 0;
  BOOL has_wild;
  BOOL exists=False;
  int tid2 = SVAL(inbuf,smb_vwv0);
  int ofun = SVAL(inbuf,smb_vwv1);
  int flags = SVAL(inbuf,smb_vwv2);
  BOOL target_is_directory=False;
  BOOL bad_path1 = False;
  BOOL bad_path2 = False;
  BOOL rc = True;
  SMB_STRUCT_STAT sbuf1, sbuf2;
  START_PROFILE(SMBcopy);

  *directory = *mask = 0;

  pstrcpy(name,smb_buf(inbuf));
  pstrcpy(newname,smb_buf(inbuf) + 1 + strlen(name));
   
  DEBUG(3,("reply_copy : %s -> %s\n",name,newname));
   
  if (tid2 != conn->cnum) {
    /* can't currently handle inter share copies XXXX */
    DEBUG(3,("Rejecting inter-share copy\n"));
    END_PROFILE(SMBcopy);
    return ERROR_DOS(ERRSRV,ERRinvdevice);
  }

  RESOLVE_DFSPATH(name, conn, inbuf, outbuf);
  RESOLVE_DFSPATH(newname, conn, inbuf, outbuf);

  rc = unix_convert(name,conn,0,&bad_path1,&sbuf1);
  unix_convert(newname,conn,0,&bad_path2,&sbuf2);

  target_is_directory = VALID_STAT_OF_DIR(sbuf2);

  if ((flags&1) && target_is_directory) {
    END_PROFILE(SMBcopy);
    return ERROR_DOS(ERRDOS,ERRbadfile);
  }

  if ((flags&2) && !target_is_directory) {
    END_PROFILE(SMBcopy);
    return ERROR_DOS(ERRDOS,ERRbadpath);
  }

  if ((flags&(1<<5)) && VALID_STAT_OF_DIR(sbuf1)) {
    /* wants a tree copy! XXXX */
    DEBUG(3,("Rejecting tree copy\n"));
    END_PROFILE(SMBcopy);
    return ERROR_DOS(ERRSRV,ERRerror);
  }

  p = strrchr(name,'/');
  if (!p) {
    pstrcpy(directory,"./");
    pstrcpy(mask,name);
  } else {
    *p = 0;
    pstrcpy(directory,name);
    pstrcpy(mask,p+1);
  }

  /*
   * We should only check the mangled cache
   * here if unix_convert failed. This means
   * that the path in 'mask' doesn't exist
   * on the file system and so we need to look
   * for a possible mangle. This patch from
   * Tine Smukavec <valentin.smukavec@hermes.si>.
   */

  if (!rc && mangle_is_mangled(mask))
    mangle_check_cache( mask, sizeof(pstring)-1 );

  has_wild = ms_has_wild(mask);

  if (!has_wild) {
    pstrcat(directory,"/");
    pstrcat(directory,mask);
    if (resolve_wildcards(directory,newname) && 
	copy_file(directory,newname,conn,ofun,
		  count,target_is_directory,&err)) count++;
    if(!count && err) {
		errno = err;
		END_PROFILE(SMBcopy);
		return(UNIXERROR(ERRHRD,ERRgeneral));
	}
    if (!count) exists = vfs_file_exist(conn,directory,NULL);
  } else {
    void *dirptr = NULL;
    char *dname;
    pstring destname;

    if (check_name(directory,conn))
      dirptr = OpenDir(conn, directory, True);

    if (dirptr) {
	error = ERRbadfile;

	if (strequal(mask,"????????.???"))
	  pstrcpy(mask,"*");

	while ((dname = ReadDirName(dirptr))) {
	    pstring fname;
	    pstrcpy(fname,dname);
	    
	    if(!mask_match(fname, mask, case_sensitive))
			continue;

	    error = ERRnoaccess;
	    slprintf(fname,sizeof(fname)-1, "%s/%s",directory,dname);
	    pstrcpy(destname,newname);
	    if (resolve_wildcards(fname,destname) && 
		copy_file(fname,destname,conn,ofun,
			  count,target_is_directory,&err)) count++;
	    DEBUG(3,("reply_copy : doing copy on %s -> %s\n",fname,destname));
	  }
	CloseDir(dirptr);
    }
  }
  
  if (count == 0) {
    if(err) {
      /* Error on close... */
      errno = err;
      END_PROFILE(SMBcopy);
      return(UNIXERROR(ERRHRD,ERRgeneral));
    }

    if (exists) {
      END_PROFILE(SMBcopy);
      return ERROR_DOS(ERRDOS,error);
    } else
    {
      if((errno == ENOENT) && (bad_path1 || bad_path2))
      {
        unix_ERR_class = ERRDOS;
        unix_ERR_code = ERRbadpath;
      }
      END_PROFILE(SMBcopy);
      return(UNIXERROR(ERRDOS,error));
    }
  }
  
  outsize = set_message(outbuf,1,0,True);
  SSVAL(outbuf,smb_vwv0,count);

  END_PROFILE(SMBcopy);
  return(outsize);
}

/****************************************************************************
 Reply to a setdir.
****************************************************************************/

int reply_setdir(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int snum;
  int outsize = 0;
  BOOL ok = False;
  pstring newdir;
  START_PROFILE(pathworks_setdir);
  
  snum = SNUM(conn);
  if (!CAN_SETDIR(snum)) {
    END_PROFILE(pathworks_setdir);
    return ERROR_DOS(ERRDOS,ERRnoaccess);
  }
  
  pstrcpy(newdir,smb_buf(inbuf) + 1);
  strlower(newdir);
  
  if (strlen(newdir) == 0) {
	  ok = True;
  } else {
	  ok = vfs_directory_exist(conn,newdir,NULL);
	  if (ok) {
		  string_set(&conn->connectpath,newdir);
	  }
  }
  
  if (!ok) {
	  END_PROFILE(pathworks_setdir);
	  return ERROR_DOS(ERRDOS,ERRbadpath);
  }
  
  outsize = set_message(outbuf,0,0,True);
  SCVAL(outbuf,smb_reh,CVAL(inbuf,smb_reh));
  
  DEBUG(3,("setdir %s\n", newdir));

  END_PROFILE(pathworks_setdir);
  return(outsize);
}

/****************************************************************************
 Get a lock pid, dealing with large count requests.
****************************************************************************/

uint16 get_lock_pid( char *data, int data_offset, BOOL large_file_format)
{
	if(!large_file_format)
		return SVAL(data,SMB_LPID_OFFSET(data_offset));
	else
		return SVAL(data,SMB_LARGE_LPID_OFFSET(data_offset));
}

/****************************************************************************
 Get a lock count, dealing with large count requests.
****************************************************************************/

SMB_BIG_UINT get_lock_count( char *data, int data_offset, BOOL large_file_format)
{
  SMB_BIG_UINT count = 0;

  if(!large_file_format) {
    count = (SMB_BIG_UINT)IVAL(data,SMB_LKLEN_OFFSET(data_offset));
  } else {

#if defined(HAVE_LONGLONG)
    count = (((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset))) << 32) |
            ((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset)));
#else /* HAVE_LONGLONG */

    /*
     * NT4.x seems to be broken in that it sends large file (64 bit)
     * lockingX calls even if the CAP_LARGE_FILES was *not*
     * negotiated. For boxes without large unsigned ints truncate the
     * lock count by dropping the top 32 bits.
     */

    if(IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset)) != 0) {
      DEBUG(3,("get_lock_count: truncating lock count (high)0x%x (low)0x%x to just low count.\n",
            (unsigned int)IVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset)),
            (unsigned int)IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset)) ));
      SIVAL(data,SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset),0);
    }

    count = (SMB_BIG_UINT)IVAL(data,SMB_LARGE_LKLEN_OFFSET_LOW(data_offset));
#endif /* HAVE_LONGLONG */
  }

  return count;
}

#if !defined(HAVE_LONGLONG)
/****************************************************************************
 Pathetically try and map a 64 bit lock offset into 31 bits. I hate Windows :-).
****************************************************************************/

static uint32 map_lock_offset(uint32 high, uint32 low)
{
	unsigned int i;
	uint32 mask = 0;
	uint32 highcopy = high;
 
	/*
	 * Try and find out how many significant bits there are in high.
	 */
 
	for(i = 0; highcopy; i++)
		highcopy >>= 1;
 
	/*
	 * We use 31 bits not 32 here as POSIX
	 * lock offsets may not be negative.
	 */
 
	mask = (~0) << (31 - i);
 
	if(low & mask)
		return 0; /* Fail. */
 
	high <<= (31 - i);
 
	return (high|low);
}
#endif /* !defined(HAVE_LONGLONG) */

/****************************************************************************
 Get a lock offset, dealing with large offset requests.
****************************************************************************/

SMB_BIG_UINT get_lock_offset( char *data, int data_offset, BOOL large_file_format, BOOL *err)
{
  SMB_BIG_UINT offset = 0;

  *err = False;

  if(!large_file_format) {
    offset = (SMB_BIG_UINT)IVAL(data,SMB_LKOFF_OFFSET(data_offset));
  } else {

#if defined(HAVE_LONGLONG)
    offset = (((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset))) << 32) |
            ((SMB_BIG_UINT) IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset)));
#else /* HAVE_LONGLONG */

    /*
     * NT4.x seems to be broken in that it sends large file (64 bit)
     * lockingX calls even if the CAP_LARGE_FILES was *not*
     * negotiated. For boxes without large unsigned ints mangle the
     * lock offset by mapping the top 32 bits onto the lower 32.
     */
      
    if(IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset)) != 0) {
      uint32 low = IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset));
      uint32 high = IVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset));
      uint32 new_low = 0;

      if((new_low = map_lock_offset(high, low)) == 0) {
        *err = True;
        return (SMB_BIG_UINT)-1;
      }

      DEBUG(3,("get_lock_offset: truncating lock offset (high)0x%x (low)0x%x to offset 0x%x.\n",
            (unsigned int)high, (unsigned int)low, (unsigned int)new_low ));
      SIVAL(data,SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset),0);
      SIVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset),new_low);
    }

    offset = (SMB_BIG_UINT)IVAL(data,SMB_LARGE_LKOFF_OFFSET_LOW(data_offset));
#endif /* HAVE_LONGLONG */
  }

  return offset;
}

/****************************************************************************
 Reply to a lockingX request.
****************************************************************************/

int reply_lockingX(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	files_struct *fsp = file_fsp(inbuf,smb_vwv2);
	unsigned char locktype = CVAL(inbuf,smb_vwv3);
	unsigned char oplocklevel = CVAL(inbuf,smb_vwv3+1);
	uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
	uint16 num_locks = SVAL(inbuf,smb_vwv7);
	SMB_BIG_UINT count = 0, offset = 0;
	uint16 lock_pid;
	int32 lock_timeout = IVAL(inbuf,smb_vwv4);
	int i;
	char *data;
	BOOL large_file_format = (locktype & LOCKING_ANDX_LARGE_FILES)?True:False;
	BOOL err;
	NTSTATUS status;

	START_PROFILE(SMBlockingX);

	CHECK_FSP(fsp,conn);

	data = smb_buf(inbuf);

	if (locktype & (LOCKING_ANDX_CANCEL_LOCK | LOCKING_ANDX_CHANGE_LOCKTYPE)) {
		/* we don't support these - and CANCEL_LOCK makes w2k
		   and XP reboot so I don't really want to be
		   compatible! (tridge) */
		return ERROR_NT(NT_STATUS_NOT_SUPPORTED);
	}

	/* Check if this is an oplock break on a file
		we have granted an oplock on.
	*/
	if ((locktype & LOCKING_ANDX_OPLOCK_RELEASE)) {
		/* Client can insist on breaking to none. */
		BOOL break_to_none = (oplocklevel == 0);

		DEBUG(5,("reply_lockingX: oplock break reply (%u) from client for fnum = %d\n",
			(unsigned int)oplocklevel, fsp->fnum ));

		/*
		 * Make sure we have granted an exclusive or batch oplock on this file.
		 */

		if(!EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
			DEBUG(0,("reply_lockingX: Error : oplock break from client for fnum = %d and \
no oplock granted on this file (%s).\n", fsp->fnum, fsp->fsp_name));

			/* if this is a pure oplock break request then don't send a reply */
			if (num_locks == 0 && num_ulocks == 0) {
				END_PROFILE(SMBlockingX);
				return -1;
			} else {
				END_PROFILE(SMBlockingX);
				return ERROR_DOS(ERRDOS,ERRlock);
			}
		}

		if (remove_oplock(fsp, break_to_none) == False) {
			DEBUG(0,("reply_lockingX: error in removing oplock on file %s\n",
				fsp->fsp_name ));
		}

		/* if this is a pure oplock break request then don't send a reply */
		if (num_locks == 0 && num_ulocks == 0) {
			/* Sanity check - ensure a pure oplock break is not a
				chained request. */
			if(CVAL(inbuf,smb_vwv0) != 0xff)
				DEBUG(0,("reply_lockingX: Error : pure oplock break is a chained %d request !\n",
					(unsigned int)CVAL(inbuf,smb_vwv0) ));
			END_PROFILE(SMBlockingX);
			return -1;
		}
	}

	/*
	 * We do this check *after* we have checked this is not a oplock break
	 * response message. JRA.
	 */

	release_level_2_oplocks_on_change(fsp);

	/* Data now points at the beginning of the list
		of smb_unlkrng structs */
	for(i = 0; i < (int)num_ulocks; i++) {
		lock_pid = get_lock_pid( data, i, large_file_format);
		count = get_lock_count( data, i, large_file_format);
		offset = get_lock_offset( data, i, large_file_format, &err);

		/*
		 * There is no error code marked "stupid client bug".... :-).
		 */
		if(err) {
			END_PROFILE(SMBlockingX);
			return ERROR_DOS(ERRDOS,ERRnoaccess);
		}

		DEBUG(10,("reply_lockingX: unlock start=%.0f, len=%.0f for pid %u, file %s\n",
			(double)offset, (double)count, (unsigned int)lock_pid, fsp->fsp_name ));

		status = do_unlock(fsp,conn,lock_pid,count,offset);
		if (NT_STATUS_V(status)) {
			END_PROFILE(SMBlockingX);
			return ERROR_NT(status);
		}
	}

	/* Setup the timeout in seconds. */

	lock_timeout = ((lock_timeout == -1) ? -1 : (lock_timeout+999)/1000);

	/* Now do any requested locks */
	data += ((large_file_format ? 20 : 10)*num_ulocks);

	/* Data now points at the beginning of the list
		of smb_lkrng structs */

	for(i = 0; i < (int)num_locks; i++) {
		lock_pid = get_lock_pid( data, i, large_file_format);
		count = get_lock_count( data, i, large_file_format);
		offset = get_lock_offset( data, i, large_file_format, &err);

		/*
		 * There is no error code marked "stupid client bug".... :-).
		 */
		if(err) {
			END_PROFILE(SMBlockingX);
			return ERROR_DOS(ERRDOS,ERRnoaccess);
		}
 
		DEBUG(10,("reply_lockingX: lock start=%.0f, len=%.0f for pid %u, file %s timeout = %d\n",
			(double)offset, (double)count, (unsigned int)lock_pid, fsp->fsp_name, 
			(int)lock_timeout ));

		status = do_lock_spin(fsp,conn,lock_pid, count,offset, 
				((locktype & 1) ? READ_LOCK : WRITE_LOCK));

		if (NT_STATUS_V(status)) {
			if ((lock_timeout != 0) && lp_blocking_locks(SNUM(conn)) && ERROR_WAS_LOCK_DENIED(status)) {
				/*
				 * A blocking lock was requested. Package up
				 * this smb into a queued request and push it
				 * onto the blocking lock queue.
				 */
				if(push_blocking_lock_request(inbuf, length, lock_timeout, i, lock_pid, offset, count)) {
					END_PROFILE(SMBlockingX);
					return -1;
				}
			}
			break;
		}
	}

	/* If any of the above locks failed, then we must unlock
		all of the previous locks (X/Open spec). */
	if(i != num_locks && num_locks != 0) {
		/*
		 * Ensure we don't do a remove on the lock that just failed,
		 * as under POSIX rules, if we have a lock already there, we
		 * will delete it (and we shouldn't) .....
		 */
		for(i--; i >= 0; i--) {
			lock_pid = get_lock_pid( data, i, large_file_format);
			count = get_lock_count( data, i, large_file_format);
			offset = get_lock_offset( data, i, large_file_format, &err);

			/*
			 * There is no error code marked "stupid client bug".... :-).
			 */
			if(err) {
				END_PROFILE(SMBlockingX);
				return ERROR_DOS(ERRDOS,ERRnoaccess);
			}
 
			do_unlock(fsp,conn,lock_pid,count,offset);
		}
		END_PROFILE(SMBlockingX);
		return ERROR_NT(status);
	}

	set_message(outbuf,2,0,True);
  
	DEBUG( 3, ( "lockingX fnum=%d type=%d num_locks=%d num_ulocks=%d\n",
		fsp->fnum, (unsigned int)locktype, num_locks, num_ulocks ) );

	END_PROFILE(SMBlockingX);
	return chain_reply(inbuf,outbuf,length,bufsize);
}

/* Back from the dead for OS/2..... JRA. */

/****************************************************************************
 Reply to a SMBreadbmpx (read block multiplex) request
****************************************************************************/

int reply_readbmpx(connection_struct *conn, char *inbuf,char *outbuf,int length,int bufsize)
{
	ssize_t nread = -1;
	ssize_t total_read;
	char *data;
	SMB_OFF_T startpos;
	int outsize;
	size_t maxcount;
	int max_per_packet;
	size_t tcount;
	int pad;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBreadBmpx);

	/* this function doesn't seem to work - disable by default */
	if (!lp_readbmpx()) {
		END_PROFILE(SMBreadBmpx);
		return ERROR_DOS(ERRSRV,ERRuseSTD);
	}

	outsize = set_message(outbuf,8,0,True);

	CHECK_FSP(fsp,conn);
	CHECK_READ(fsp);
	CHECK_ERROR(fsp);

	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv1);
	maxcount = SVAL(inbuf,smb_vwv3);

	data = smb_buf(outbuf);
	pad = ((long)data)%4;
	if (pad)
		pad = 4 - pad;
	data += pad;

	max_per_packet = bufsize-(outsize+pad);
	tcount = maxcount;
	total_read = 0;

	if (is_locked(fsp,conn,(SMB_BIG_UINT)maxcount,(SMB_BIG_UINT)startpos, READ_LOCK, False)) {
		END_PROFILE(SMBreadBmpx);
		return ERROR_DOS(ERRDOS,ERRlock);
	}

	do {
		size_t N = MIN(max_per_packet,tcount-total_read);

		nread = read_file(fsp,data,startpos,N);

		if (nread <= 0)
			nread = 0;

		if (nread < (ssize_t)N)
			tcount = total_read + nread;

		set_message(outbuf,8,nread,False);
		SIVAL(outbuf,smb_vwv0,startpos);
		SSVAL(outbuf,smb_vwv2,tcount);
		SSVAL(outbuf,smb_vwv6,nread);
		SSVAL(outbuf,smb_vwv7,smb_offset(data,outbuf));

		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_readbmpx: send_smb failed.");

		total_read += nread;
		startpos += nread;
	} while (total_read < (ssize_t)tcount);

	END_PROFILE(SMBreadBmpx);
	return(-1);
}

/****************************************************************************
 Reply to a SMBsetattrE.
****************************************************************************/

int reply_setattrE(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	struct utimbuf unix_times;
	int outsize = 0;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBsetattrE);

	outsize = set_message(outbuf,0,0,True);

	if(!fsp || (fsp->conn != conn)) {
		END_PROFILE(SMBsetattrE);
		return ERROR_DOS(ERRDOS,ERRbadfid);
	}

	/*
	 * Convert the DOS times into unix times. Ignore create
	 * time as UNIX can't set this.
	 */
	unix_times.actime = make_unix_date2(inbuf+smb_vwv3);
	unix_times.modtime = make_unix_date2(inbuf+smb_vwv5);
  
	/* 
	 * Patch from Ray Frush <frush@engr.colostate.edu>
	 * Sometimes times are sent as zero - ignore them.
	 */

	if ((unix_times.actime == 0) && (unix_times.modtime == 0)) {
		/* Ignore request */
		if( DEBUGLVL( 3 ) ) {
			dbgtext( "reply_setattrE fnum=%d ", fsp->fnum);
			dbgtext( "ignoring zero request - not setting timestamps of 0\n" );
		}
		END_PROFILE(SMBsetattrE);
		return(outsize);
	} else if ((unix_times.actime != 0) && (unix_times.modtime == 0)) {
		/* set modify time = to access time if modify time was 0 */
		unix_times.modtime = unix_times.actime;
	}

	/* Set the date on this file */
	if(file_utime(conn, fsp->fsp_name, &unix_times)) {
		END_PROFILE(SMBsetattrE);
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	}
  
	DEBUG( 3, ( "reply_setattrE fnum=%d actime=%d modtime=%d\n",
		fsp->fnum, (int)unix_times.actime, (int)unix_times.modtime ) );

	END_PROFILE(SMBsetattrE);
	return(outsize);
}


/* Back from the dead for OS/2..... JRA. */

/****************************************************************************
 Reply to a SMBwritebmpx (write block multiplex primary) request.
****************************************************************************/

int reply_writebmpx(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	size_t numtowrite;
	ssize_t nwritten = -1;
	int outsize = 0;
	SMB_OFF_T startpos;
	size_t tcount;
	BOOL write_through;
	int smb_doff;
	char *data;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBwriteBmpx);

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);
	CHECK_ERROR(fsp);

	tcount = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
	write_through = BITSETW(inbuf+smb_vwv7,0);
	numtowrite = SVAL(inbuf,smb_vwv10);
	smb_doff = SVAL(inbuf,smb_vwv11);

	data = smb_base(inbuf) + smb_doff;

	/* If this fails we need to send an SMBwriteC response,
		not an SMBwritebmpx - set this up now so we don't forget */
	SCVAL(outbuf,smb_com,SMBwritec);

	if (is_locked(fsp,conn,(SMB_BIG_UINT)tcount,(SMB_BIG_UINT)startpos,WRITE_LOCK,False)) {
		END_PROFILE(SMBwriteBmpx);
		return(ERROR_DOS(ERRDOS,ERRlock));
	}

	nwritten = write_file(fsp,data,startpos,numtowrite);

	if(lp_syncalways(SNUM(conn)) || write_through)
		sync_file(conn,fsp);
  
	if(nwritten < (ssize_t)numtowrite) {
		END_PROFILE(SMBwriteBmpx);
		return(UNIXERROR(ERRHRD,ERRdiskfull));
	}

	/* If the maximum to be written to this file
		is greater than what we just wrote then set
		up a secondary struct to be attached to this
		fd, we will use this to cache error messages etc. */

	if((ssize_t)tcount > nwritten) {
		write_bmpx_struct *wbms;
		if(fsp->wbmpx_ptr != NULL)
			wbms = fsp->wbmpx_ptr; /* Use an existing struct */
		else
			wbms = (write_bmpx_struct *)malloc(sizeof(write_bmpx_struct));

		if(!wbms) {
			DEBUG(0,("Out of memory in reply_readmpx\n"));
			END_PROFILE(SMBwriteBmpx);
			return(ERROR_DOS(ERRSRV,ERRnoresource));
		}
		wbms->wr_mode = write_through;
		wbms->wr_discard = False; /* No errors yet */
		wbms->wr_total_written = nwritten;
		wbms->wr_errclass = 0;
		wbms->wr_error = 0;
		fsp->wbmpx_ptr = wbms;
	}

	/* We are returning successfully, set the message type back to
		SMBwritebmpx */
	SCVAL(outbuf,smb_com,SMBwriteBmpx);
  
	outsize = set_message(outbuf,1,0,True);

	SSVALS(outbuf,smb_vwv0,-1); /* We don't support smb_remaining */
  
	DEBUG( 3, ( "writebmpx fnum=%d num=%d wrote=%d\n",
		fsp->fnum, (int)numtowrite, (int)nwritten ) );

	if (write_through && tcount==nwritten) {
		/* We need to send both a primary and a secondary response */
		smb_setlen(outbuf,outsize - 4);
		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_writebmpx: send_smb failed.");

		/* Now the secondary */
		outsize = set_message(outbuf,1,0,True);
		SCVAL(outbuf,smb_com,SMBwritec);
		SSVAL(outbuf,smb_vwv0,nwritten);
	}

	END_PROFILE(SMBwriteBmpx);
	return(outsize);
}

/****************************************************************************
 Reply to a SMBwritebs (write block multiplex secondary) request.
****************************************************************************/

int reply_writebs(connection_struct *conn, char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
	size_t numtowrite;
	ssize_t nwritten = -1;
	int outsize = 0;
	SMB_OFF_T startpos;
	size_t tcount;
	BOOL write_through;
	int smb_doff;
	char *data;
	write_bmpx_struct *wbms;
	BOOL send_response = False; 
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBwriteBs);

	CHECK_FSP(fsp,conn);
	CHECK_WRITE(fsp);

	tcount = SVAL(inbuf,smb_vwv1);
	startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
	numtowrite = SVAL(inbuf,smb_vwv6);
	smb_doff = SVAL(inbuf,smb_vwv7);

	data = smb_base(inbuf) + smb_doff;

	/* We need to send an SMBwriteC response, not an SMBwritebs */
	SCVAL(outbuf,smb_com,SMBwritec);

	/* This fd should have an auxiliary struct attached,
		check that it does */
	wbms = fsp->wbmpx_ptr;
	if(!wbms) {
		END_PROFILE(SMBwriteBs);
		return(-1);
	}

	/* If write through is set we can return errors, else we must cache them */
	write_through = wbms->wr_mode;

	/* Check for an earlier error */
	if(wbms->wr_discard) {
		END_PROFILE(SMBwriteBs);
		return -1; /* Just discard the packet */
	}

	nwritten = write_file(fsp,data,startpos,numtowrite);

	if(lp_syncalways(SNUM(conn)) || write_through)
		sync_file(conn,fsp);
  
	if (nwritten < (ssize_t)numtowrite) {
		if(write_through) {
			/* We are returning an error - we can delete the aux struct */
			SAFE_FREE(wbms);
			fsp->wbmpx_ptr = NULL;
			END_PROFILE(SMBwriteBs);
			return(ERROR_DOS(ERRHRD,ERRdiskfull));
		}
		END_PROFILE(SMBwriteBs);
		return(CACHE_ERROR(wbms,ERRHRD,ERRdiskfull));
	}

	/* Increment the total written, if this matches tcount
		we can discard the auxiliary struct (hurrah !) and return a writeC */
	wbms->wr_total_written += nwritten;
	if(wbms->wr_total_written >= tcount) {
		if (write_through) {
			outsize = set_message(outbuf,1,0,True);
			SSVAL(outbuf,smb_vwv0,wbms->wr_total_written);    
			send_response = True;
		}

		SAFE_FREE(wbms);
		fsp->wbmpx_ptr = NULL;
	}

	if(send_response) {
		END_PROFILE(SMBwriteBs);
		return(outsize);
	}

	END_PROFILE(SMBwriteBs);
	return(-1);
}

/****************************************************************************
 Reply to a SMBgetattrE.
****************************************************************************/

int reply_getattrE(connection_struct *conn, char *inbuf,char *outbuf, int size, int dum_buffsize)
{
	SMB_STRUCT_STAT sbuf;
	int outsize = 0;
	int mode;
	files_struct *fsp = file_fsp(inbuf,smb_vwv0);
	START_PROFILE(SMBgetattrE);

	outsize = set_message(outbuf,11,0,True);

	if(!fsp || (fsp->conn != conn)) {
		END_PROFILE(SMBgetattrE);
		return ERROR_DOS(ERRDOS,ERRbadfid);
	}

	/* Do an stat on this file */

	if(fsp_stat(fsp, &sbuf)) {
		END_PROFILE(SMBgetattrE);
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	}
  
	mode = dos_mode(conn,fsp->fsp_name,&sbuf);
  
	/* Convert the times into dos times. Set create
	 * date to be last modify date as UNIX doesn't save
	 * this.
	 */

	put_dos_date2(outbuf,smb_vwv0,get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(conn))));
	put_dos_date2(outbuf,smb_vwv2,sbuf.st_atime);
	put_dos_date2(outbuf,smb_vwv4,sbuf.st_mtime);
	if (mode & aDIR) {
		SIVAL(outbuf,smb_vwv6,0);
		SIVAL(outbuf,smb_vwv8,0);
	} else {
		SIVAL(outbuf,smb_vwv6,(uint32)sbuf.st_size);
		SIVAL(outbuf,smb_vwv8,SMB_ROUNDUP(sbuf.st_size,1024));
	}
	SSVAL(outbuf,smb_vwv10, mode);
  
	DEBUG( 3, ( "reply_getattrE fnum=%d\n", fsp->fnum));
  
	END_PROFILE(SMBgetattrE);
	return(outsize);
}
