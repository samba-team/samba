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
#include "trans2.h"
#include "nterr.h"

/* look in server.c for some explanation of these variables */
extern int Protocol;
extern int DEBUGLEVEL;
extern int max_send;
extern int max_recv;
extern int chain_fnum;
extern char magic_char;
extern connection_struct Connections[];
extern files_struct Files[];
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL short_case_preserve;
extern pstring sesssetup_user;
extern fstring myworkgroup;
extern int Client;
extern int global_oplock_break;

/* this macro should always be used to extract an fnum (smb_fid) from
a packet to ensure chaining works correctly */
#define GETFNUM(buf,where) (chain_fnum!= -1?chain_fnum:SVAL(buf,where))


/****************************************************************************
report a possible attack via the password buffer overflow bug
****************************************************************************/
static void overflow_attack(int len)
{
	DEBUG(0,("%s: ERROR: Invalid password length %d\n", timestring(), len));
	DEBUG(0,("your machine may be under attack by a user exploiting an old bug\n"));
	DEBUG(0,("Attack was from IP=%s\n", client_addr()));
	exit_server("possible attack");
}


/****************************************************************************
  reply to an special message 
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
	
	smb_setlen(outbuf,0);
	
	switch (msg_type) {
	case 0x81: /* session request */
		CVAL(outbuf,0) = 0x82;
		CVAL(outbuf,3) = 0;
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

		fstrcpy(local_machine,name1);
		len = strlen(local_machine);
		if (len == 16) {
			name_type = local_machine[15];
			local_machine[15] = 0;
		}
		trim_string(local_machine," "," ");
		strlower(local_machine);

		if (name_type == 'R') {
			/* We are being asked for a pathworks session --- 
			   no thanks! */
			CVAL(outbuf, 0) = 0x83;
			break;
		}

		add_session_user(remote_machine);

		reload_services(True);
		reopen_logs();

		break;
		
	case 0x89: /* session keepalive request 
		      (some old clients produce this?) */
		CVAL(outbuf,0) = 0x85;
		CVAL(outbuf,3) = 0;
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
	
	DEBUG(5,("%s init msg_type=0x%x msg_flags=0x%x\n",
		 timestring(),msg_type,msg_flags));
	
	return(outsize);
}


/*******************************************************************
work out what error to give to a failed connection
********************************************************************/
static int connection_error(char *inbuf,char *outbuf,int connection_num)
{
  switch (connection_num)
    {
    case -8:
      return(ERROR(ERRSRV,ERRnoresource));
    case -7:
      return(ERROR(ERRSRV,ERRbaduid));
    case -6:
      return(ERROR(ERRSRV,ERRinvdevice));
    case -5:
      return(ERROR(ERRSRV,ERRinvnetname));
    case -4:
      return(ERROR(ERRSRV,ERRaccess));
    case -3:
      return(ERROR(ERRDOS,ERRnoipc));
    case -2:
      return(ERROR(ERRSRV,ERRinvnetname));
    }
  return(ERROR(ERRSRV,ERRbadpw));
}



/****************************************************************************
  parse a share descriptor string
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
  reply to a tcon
****************************************************************************/
int reply_tcon(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring service;
  pstring user;
  pstring password;
  pstring dev;
  int connection_num;
  int outsize = 0;
  uint16 vuid = SVAL(inbuf,smb_uid);
  int pwlen=0;

  *service = *user = *password = *dev = 0;

  parse_connect(smb_buf(inbuf)+1,service,user,password,&pwlen,dev);

  /*
   * Pass the user through the NT -> unix user mapping
   * function.
   */
  
  (void)map_username(user);
   
  /*
   * Do any UNIX username case mangling.
   */
  (void)Get_Pwnam( user, True);

  connection_num = make_connection(service,user,password,pwlen,dev,vuid);
  
  if (connection_num < 0)
    return(connection_error(inbuf,outbuf,connection_num));
  
  outsize = set_message(outbuf,2,0,True);
  SSVAL(outbuf,smb_vwv0,max_recv);
  SSVAL(outbuf,smb_vwv1,connection_num);
  SSVAL(outbuf,smb_tid,connection_num);
  
  DEBUG(3,("%s tcon service=%s user=%s cnum=%d\n",timestring(),service,user,connection_num));
  
  return(outsize);
}


/****************************************************************************
  reply to a tcon and X
****************************************************************************/
int reply_tcon_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring service;
  pstring user;
  pstring password;
  pstring devicename;
  int connection_num;
  uint16 vuid = SVAL(inbuf,smb_uid);
  int passlen = SVAL(inbuf,smb_vwv3);

  *service = *user = *password = *devicename = 0;

  /* we might have to close an old one */
  if ((SVAL(inbuf,smb_vwv2) & 0x1) != 0)
    close_cnum(SVAL(inbuf,smb_tid),vuid);

  if (passlen > MAX_PASS_LEN) {
	  overflow_attack(passlen);
  }
  
  {
    char *path;
    char *p;
    memcpy(password,smb_buf(inbuf),passlen);
    password[passlen]=0;    
    path = smb_buf(inbuf) + passlen;

    if (passlen != 24) {
      if (strequal(password," "))
	*password = 0;
      passlen = strlen(password);
    }
    
    fstrcpy(service,path+2);
    p = strchr(service,'\\');
    if (!p)
      return(ERROR(ERRSRV,ERRinvnetname));
    *p = 0;
    fstrcpy(service,p+1);
    p = strchr(service,'%');
    if (p)
      {
	*p++ = 0;
	fstrcpy(user,p);
      }
    StrnCpy(devicename,path + strlen(path) + 1,6);
    DEBUG(4,("Got device type %s\n",devicename));
  }

  /*
   * Pass the user through the NT -> unix user mapping
   * function.
   */
  
  (void)map_username(user);
   
  /*
   * Do any UNIX username case mangling.
   */
  (void)Get_Pwnam( user, True);

  connection_num = make_connection(service,user,password,passlen,devicename,vuid);
  
  if (connection_num < 0)
    return(connection_error(inbuf,outbuf,connection_num));

  if (Protocol < PROTOCOL_NT1)
  {
    set_message(outbuf,2,strlen(devicename)+1,True);
    pstrcpy(smb_buf(outbuf),devicename);
  }
  else
  {
    char *fsname = "SAMBA";
    char *p;

    set_message(outbuf,3,3,True);

    p = smb_buf(outbuf);
    pstrcpy(p,devicename); p = skip_string(p,1); /* device name */
    pstrcpy(p,fsname); p = skip_string(p,1); /* filesystem type e.g NTFS */

    set_message(outbuf,3,PTR_DIFF(p,smb_buf(outbuf)),False);

    SSVAL(outbuf, smb_vwv2, 0x0); /* optional support */
  }
  
  DEBUG(3,("%s tconX service=%s user=%s cnum=%d\n",timestring(),service,user,connection_num));
  
  /* set the incoming and outgoing tid to the just created one */
  SSVAL(inbuf,smb_tid,connection_num);
  SSVAL(outbuf,smb_tid,connection_num);

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to an unknown type
****************************************************************************/
int reply_unknown(char *inbuf,char *outbuf)
{
  int cnum;
  int type;
  cnum = SVAL(inbuf,smb_tid);
  type = CVAL(inbuf,smb_com);
  
  DEBUG(0,("%s unknown command type (%s): cnum=%d type=%d (0x%X)\n",
	timestring(),
	smb_fn_name(type),
	cnum,type,type));
  
  return(ERROR(ERRSRV,ERRunknownsmb));
}


/****************************************************************************
  reply to an ioctl
****************************************************************************/
int reply_ioctl(char *inbuf,char *outbuf, int size, int bufsize)
{
  DEBUG(3,("ignoring ioctl\n"));
#if 0
  /* we just say it succeeds and hope its all OK. 
     some day it would be nice to interpret them individually */
  return set_message(outbuf,1,0,True); 
#else
  return(ERROR(ERRSRV,ERRnosupport));
#endif
}


/****************************************************************************
reply to a session setup command
****************************************************************************/
int reply_sesssetup_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  uint16 sess_vuid;
  int gid;
  int uid;
  int   smb_bufsize;    
  int   smb_mpxmax;     
  int   smb_vc_num;     
  uint32   smb_sesskey;    
  int   smb_apasslen = 0;   
  pstring smb_apasswd;
  int   smb_ntpasslen = 0;   
  pstring smb_ntpasswd;
  BOOL valid_nt_password = False;
  pstring user;
  BOOL guest=False;
  BOOL computer_id=False;
  static BOOL done_sesssetup = False;
  BOOL doencrypt = SMBENCRYPT();
  char *domain = "";

  *smb_apasswd = 0;
  *smb_ntpasswd = 0;
  
  smb_bufsize = SVAL(inbuf,smb_vwv2);
  smb_mpxmax = SVAL(inbuf,smb_vwv3);
  smb_vc_num = SVAL(inbuf,smb_vwv4);
  smb_sesskey = IVAL(inbuf,smb_vwv5);

  if (Protocol < PROTOCOL_NT1) {
    smb_apasslen = SVAL(inbuf,smb_vwv7);
    if (smb_apasslen > MAX_PASS_LEN)
    {
	    overflow_attack(smb_apasslen);
    }

    memcpy(smb_apasswd,smb_buf(inbuf),smb_apasslen);
    smb_apasswd[smb_apasslen] = 0;
    pstrcpy(user,smb_buf(inbuf)+smb_apasslen);

    if (!doencrypt && (lp_security() != SEC_SERVER)) {
	    smb_apasslen = strlen(smb_apasswd);
    }
  } else {
    uint16 passlen1 = SVAL(inbuf,smb_vwv7);
    uint16 passlen2 = SVAL(inbuf,smb_vwv8);
    uint32 client_caps = IVAL(inbuf,smb_vwv11);
    enum remote_arch_types ra_type = get_remote_arch();

    char *p = smb_buf(inbuf);    

    /* client_caps is used as final determination if client is NT or Win95. 
       This is needed to return the correct error codes in some
       circumstances.
     */
    
    if(ra_type == RA_WINNT || ra_type == RA_WIN95)
    {
      if(client_caps & (CAP_NT_SMBS | CAP_STATUS32))
        set_remote_arch( RA_WINNT);
      else
        set_remote_arch( RA_WIN95);
    }

    if (passlen1 != 24 && passlen2 != 24)
      doencrypt = False;

    if (passlen1 > MAX_PASS_LEN) {
	    overflow_attack(passlen1);
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

    if(doencrypt || (lp_security() == SEC_SERVER)) {
      /* Save the lanman2 password and the NT md4 password. */
      smb_apasslen = passlen1;
      memcpy(smb_apasswd,p,smb_apasslen);
      smb_apasswd[smb_apasslen] = 0;
      smb_ntpasslen = passlen2;
      memcpy(smb_ntpasswd,p+passlen1,smb_ntpasslen);
      smb_ntpasswd[smb_ntpasslen] = 0;
    } else {
      /* we use the first password that they gave */
      smb_apasslen = passlen1;
      StrnCpy(smb_apasswd,p,smb_apasslen);      
      
      /* trim the password */
      smb_apasslen = strlen(smb_apasswd);

      /* wfwg sometimes uses a space instead of a null */
      if (strequal(smb_apasswd," ")) {
	smb_apasslen = 0;
	*smb_apasswd = 0;
      }
    }
    
    p += passlen1 + passlen2;
    fstrcpy(user,p); p = skip_string(p,1);
    domain = p;

    DEBUG(3,("Domain=[%s]  NativeOS=[%s] NativeLanMan=[%s]\n",
	     domain,skip_string(p,1),skip_string(p,2)));
  }


  DEBUG(3,("sesssetupX:name=[%s]\n",user));

  /* If name ends in $ then I think it's asking about whether a */
  /* computer with that name (minus the $) has access. For now */
  /* say yes to everything ending in $. */
  if (user[strlen(user) - 1] == '$')
  {
#ifdef NTDOMAIN
    struct smb_passwd *smb_pass; /* To check if machine account exists */
/* 
   PAXX: Ack. We don't want to do this. The workstation trust account
   with a $ on the end should exist in the local password database
   or be mapped to something generic, but not modified. For NT
   domain support we must reject this used in certain circumstances
   with a code to indicate to the client that it is an invalid use
   of a workstation trust account. NTWKS needs this error to join
   a domain. This may be the source of future bugs if we cannot
   be sure whether to reject this or not.
*/
   /* non-null user name indicates search by username not by smb userid */
   smb_pass = get_smbpwd_entry(user, 0);

   if (!smb_pass)
   {
     /* lkclXXXX: if workstation entry doesn't exist, indicate logon failure */
     DEBUG(4,("Workstation trust account %s doesn't exist.",user));
     SSVAL(outbuf, smb_flg2, 0xc003); /* PAXX: Someone please unhack this */
     CVAL(outbuf, smb_reh) = 1; /* PAXX: Someone please unhack this */
     return(ERROR(NT_STATUS_LOGON_FAILURE, 0xc000)); /* decimal 109 NT error, 0xc000 */
   }
   else
   {
     /* PAXX: This is the NO LOGON workstation trust account stuff */
     /* lkclXXXX: if the workstation *does* exist, indicate failure differently! */
     DEBUG(4,("No Workstation trust account %s",user));
     SSVAL(outbuf, smb_flg2, 0xc003); /* PAXX: Someone please unhack this */
     CVAL(outbuf, smb_reh) = 1; /* PAXX: Someone please unhack this */
     return(ERROR(NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT, 0xc000)); /* decimal 409 NT error, 0xc000 */
   }

   computer_id = True;
#else /* not NTDOMAIN, leave this in. PAXX: Someone get rid of this */
    user[strlen(user) - 1] = '\0';
#endif
  }


  /* If no username is sent use the guest account */
  if (!*user)
    {
      pstrcpy(user,lp_guestaccount(-1));
      /* If no user and no password then set guest flag. */
      if( *smb_apasswd == 0)
        guest = True;
    }

  strlower(user);

  /* 
   * In share level security, only overwrite sesssetup_use if
   * it's a non null-session share. Helps keep %U and %G
   * working.
   */

  if((lp_security() != SEC_SHARE) || *user)
    pstrcpy(sesssetup_user,user);

  reload_services(True);

  /*
   * Pass the user through the NT -> unix user mapping
   * function.
   */
  
  (void)map_username(user);
   
  /*
   * Do any UNIX username case mangling.
   */
  (void)Get_Pwnam( user, True);

  add_session_user(user);

  /* Check if the given username was the guest user with no password.
     We need to do this check after add_session_user() as that
     call can potentially change the username (via map_user).
   */

  if(!guest && strequal(user,lp_guestaccount(-1)) && (*smb_apasswd == 0))
    guest = True;

  if (!guest && !(lp_security() == SEC_SERVER && 
		  server_validate(user, domain, 
				  smb_apasswd, smb_apasslen, 
				  smb_ntpasswd, smb_ntpasslen)) &&
      !check_hosts_equiv(user))
    {

      /* now check if it's a valid username/password */
      /* If an NT password was supplied try and validate with that
	 first. This is superior as the passwords are mixed case 
         128 length unicode */
      if(smb_ntpasslen)
	{
	  if(!password_ok(user,smb_ntpasswd,smb_ntpasslen,NULL))
	    DEBUG(0,("NT Password did not match ! Defaulting to Lanman\n"));
	  else
	    valid_nt_password = True;
	} 
      if (!valid_nt_password && !password_ok(user,smb_apasswd,smb_apasslen,NULL))
	{
	  if (!computer_id && lp_security() >= SEC_USER) {
#if (GUEST_SESSSETUP == 0)
	    return(ERROR(ERRSRV,ERRbadpw));
#endif
#if (GUEST_SESSSETUP == 1)
	    if (Get_Pwnam(user,True))
	      return(ERROR(ERRSRV,ERRbadpw));
#endif
	  }
 	  if (*smb_apasswd || !Get_Pwnam(user,True))
	    pstrcpy(user,lp_guestaccount(-1));
	  DEBUG(3,("Registered username %s for guest access\n",user));
	  guest = True;
	}
    }

  if (!Get_Pwnam(user,True)) {
    DEBUG(3,("No such user %s - using guest account\n",user));
    pstrcpy(user,lp_guestaccount(-1));
    guest = True;
  }

  if (!strequal(user,lp_guestaccount(-1)) &&
      lp_servicenumber(user) < 0)      
    {
      int homes = lp_servicenumber(HOMES_NAME);
      char *home = get_home_dir(user);
      if (homes >= 0 && home)
	lp_add_home(user,homes,home);
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
    pstrcpy(p,myworkgroup); p = skip_string(p,1);
    set_message(outbuf,3,PTR_DIFF(p,smb_buf(outbuf)),False);
    /* perhaps grab OS version here?? */
  }

  /* Set the correct uid in the outgoing and incoming packets
     We will use this on future requests to determine which
     user we should become.
     */
  {
    struct passwd *pw = Get_Pwnam(user,False);
    if (!pw) {
      DEBUG(1,("Username %s is invalid on this system\n",user));
      return(ERROR(ERRSRV,ERRbadpw));
    }
    gid = pw->pw_gid;
    uid = pw->pw_uid;
  }

  if (guest && !computer_id)
    SSVAL(outbuf,smb_vwv2,1);

  /* register the name and uid as being validated, so further connections
     to a uid can get through without a password, on the same VC */
  sess_vuid = register_vuid(uid,gid,user,sesssetup_user,guest);
 
  SSVAL(outbuf,smb_uid,sess_vuid);
  SSVAL(inbuf,smb_uid,sess_vuid);

  if (!done_sesssetup)
    max_send = MIN(max_send,smb_bufsize);

  DEBUG(6,("Client requested max send size of %d\n", max_send));

  done_sesssetup = True;

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a chkpth
****************************************************************************/
int reply_chkpth(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int outsize = 0;
  int cnum,mode;
  pstring name;
  BOOL ok = False;
  BOOL bad_path = False;
 
  cnum = SVAL(inbuf,smb_tid);
  
  pstrcpy(name,smb_buf(inbuf) + 1);
  unix_convert(name,cnum,0,&bad_path);

  mode = SVAL(inbuf,smb_vwv0);

  if (check_name(name,cnum))
    ok = directory_exist(name,NULL);

  if (!ok)
  {
    /* We special case this - as when a Windows machine
       is parsing a path is steps through the components
       one at a time - if a component fails it expects
       ERRbadpath, not ERRbadfile.
     */
    if(errno == ENOENT)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }

#if 0
    /* Ugly - NT specific hack - maybe not needed ? (JRA) */
    if((errno == ENOTDIR) && (Protocol >= PROTOCOL_NT1) &&
       (get_remote_arch() == RA_WINNT))
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbaddirectory;
    }
#endif

    return(UNIXERROR(ERRDOS,ERRbadpath));
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG(3,("%s chkpth %s cnum=%d mode=%d\n",timestring(),name,cnum,mode));
  
  return(outsize);
}


/****************************************************************************
  reply to a getatr
****************************************************************************/
int reply_getatr(char *inbuf,char *outbuf, int in_size, int buffsize)
{
  pstring fname;
  int cnum;
  int outsize = 0;
  struct stat sbuf;
  BOOL ok = False;
  int mode=0;
  uint32 size=0;
  time_t mtime=0;
  BOOL bad_path = False;
 
  cnum = SVAL(inbuf,smb_tid);

  pstrcpy(fname,smb_buf(inbuf) + 1);
  unix_convert(fname,cnum,0,&bad_path);

  /* dos smetimes asks for a stat of "" - it returns a "hidden directory"
     under WfWg - weird! */
  if (! (*fname))
    {
      mode = aHIDDEN | aDIR;
      if (!CAN_WRITE(cnum)) mode |= aRONLY;
      size = 0;
      mtime = 0;
      ok = True;
    }
  else
    if (check_name(fname,cnum))
    {
      if (sys_stat(fname,&sbuf) == 0)
      {
        mode = dos_mode(cnum,fname,&sbuf);
        size = sbuf.st_size;
        mtime = sbuf.st_mtime;
        if (mode & aDIR)
          size = 0;
        ok = True;
      }
      else
        DEBUG(3,("stat of %s failed (%s)\n",fname,strerror(errno)));
    }
  
  if (!ok)
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }

    return(UNIXERROR(ERRDOS,ERRbadfile));
  }
 
  outsize = set_message(outbuf,10,0,True);

  SSVAL(outbuf,smb_vwv0,mode);
  if(lp_dos_filetime_resolution(SNUM(cnum)) )
    put_dos_date3(outbuf,smb_vwv1,mtime & ~1);
  else
    put_dos_date3(outbuf,smb_vwv1,mtime);
  SIVAL(outbuf,smb_vwv3,size);

  if (Protocol >= PROTOCOL_NT1) {
    char *p = strrchr(fname,'/');
    uint16 flg2 = SVAL(outbuf,smb_flg2);
    if (!p) p = fname;
    if (!is_8_3(fname, True))
      SSVAL(outbuf,smb_flg2,flg2 | 0x40); /* IS_LONG_NAME */
  }
  
  DEBUG(3,("%s getatr name=%s mode=%d size=%d\n",timestring(),fname,mode,size));
  
  return(outsize);
}


/****************************************************************************
  reply to a setatr
****************************************************************************/
int reply_setatr(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring fname;
  int cnum;
  int outsize = 0;
  BOOL ok=False;
  int mode;
  time_t mtime;
  BOOL bad_path = False;
 
  cnum = SVAL(inbuf,smb_tid);
  
  pstrcpy(fname,smb_buf(inbuf) + 1);
  unix_convert(fname,cnum,0,&bad_path);

  mode = SVAL(inbuf,smb_vwv0);
  mtime = make_unix_date3(inbuf+smb_vwv1);
  
  if (directory_exist(fname,NULL))
    mode |= aDIR;
  if (check_name(fname,cnum))
    ok =  (dos_chmod(cnum,fname,mode,NULL) == 0);
  if (ok)
    ok = set_filetime(cnum,fname,mtime);
  
  if (!ok)
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }

    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG(3,("%s setatr name=%s mode=%d\n",timestring(),fname,mode));
  
  return(outsize);
}


/****************************************************************************
  reply to a dskattr
****************************************************************************/
int reply_dskattr(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int cnum;
  int outsize = 0;
  int dfree,dsize,bsize;
  
  cnum = SVAL(inbuf,smb_tid);
  
  sys_disk_free(".",&bsize,&dfree,&dsize);
  
  outsize = set_message(outbuf,5,0,True);
  
  SSVAL(outbuf,smb_vwv0,dsize);
  SSVAL(outbuf,smb_vwv1,bsize/512);
  SSVAL(outbuf,smb_vwv2,512);
  SSVAL(outbuf,smb_vwv3,dfree);
  
  DEBUG(3,("%s dskattr cnum=%d dfree=%d\n",timestring(),cnum,dfree));
  
  return(outsize);
}


/****************************************************************************
  reply to a search
  Can be called from SMBsearch, SMBffirst or SMBfunique.
****************************************************************************/
int reply_search(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring mask;
  pstring directory;
  pstring fname;
  int size,mode;
  time_t date;
  int dirtype;
  int cnum;
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

  *mask = *directory = *fname = 0;

  /* If we were called as SMBffirst then we must expect close. */
  if(CVAL(inbuf,smb_com) == SMBffirst)
    expect_close = True;
  
  cnum = SVAL(inbuf,smb_tid);

  outsize = set_message(outbuf,1,3,True);
  maxentries = SVAL(inbuf,smb_vwv0); 
  dirtype = SVAL(inbuf,smb_vwv1);
  path = smb_buf(inbuf) + 1;
  status_len = SVAL(smb_buf(inbuf),3 + strlen(path));

  
  /* dirtype &= ~aDIR; */
  
  DEBUG(5,("path=%s status_len=%d\n",path,status_len));

  
  if (status_len == 0)
    {
      pstring dir2;

      pstrcpy(directory,smb_buf(inbuf)+1);
      pstrcpy(dir2,smb_buf(inbuf)+1);
      unix_convert(directory,cnum,0,&bad_path);
      unix_format(dir2);

      if (!check_name(directory,cnum))
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
      bzero(status,21);
      CVAL(status,0) = dirtype;
    }
  else
    {
      memcpy(status,smb_buf(inbuf) + 1 + strlen(path) + 4,21);
      memcpy(mask,status+1,11);
      mask[11] = 0;
      dirtype = CVAL(status,0) & 0x1F;
      Connections[cnum].dirptr = dptr_fetch(status+12,&dptr_num);      
      if (!Connections[cnum].dirptr)
	goto SearchEmpty;
      string_set(&Connections[cnum].dirpath,dptr_path(dptr_num));
      if (!case_sensitive)
	strnorm(mask);
    }

  /* turn strings of spaces into a . */  
  {
    trim_string(mask,NULL," ");
    if ((p = strrchr(mask,' ')))
      {
	fstring ext;
	fstrcpy(ext,p+1);
	*p = 0;
	trim_string(mask,NULL," ");
	pstrcat(mask,".");
	pstrcat(mask,ext);
      }
  }

  {
    for (p=mask; *p; p++)
      {
	if (*p != '?' && *p != '*' && !isdoschar(*p))
	  {
	    DEBUG(5,("Invalid char [%c] in search mask?\n",*p));
	    *p = '?';
	  }
      }
  }

  if (!strchr(mask,'.') && strlen(mask)>8)
    {
      fstring tmp;
      fstrcpy(tmp,&mask[8]);
      mask[8] = '.';
      mask[9] = 0;
      pstrcat(mask,tmp);
    }

  DEBUG(5,("mask=%s directory=%s\n",mask,directory));
  
  if (can_open)
    {
      p = smb_buf(outbuf) + 3;
      
      ok = True;
      
      if (status_len == 0)
	{
	  dptr_num = dptr_create(cnum,directory,expect_close,SVAL(inbuf,smb_pid));
	  if (dptr_num < 0)
        {
          if(dptr_num == -2)
          {
            if((errno == ENOENT) && bad_path)
            {
              unix_ERR_class = ERRDOS;
              unix_ERR_code = ERRbadpath;
            }
            return (UNIXERROR(ERRDOS,ERRnofids));
          }
          return(ERROR(ERRDOS,ERRnofids));
        }
	}

      DEBUG(4,("dptr_num is %d\n",dptr_num));

      if (ok)
	{
	  if ((dirtype&0x1F) == aVOLID)
	    {	  
	      memcpy(p,status,21);
	      make_dir_struct(p,"???????????",volume_label(SNUM(cnum)),0,aVOLID,0);
	      dptr_fill(p+12,dptr_num);
	      if (dptr_zero(p+12) && (status_len==0))
		numentries = 1;
	      else
		numentries = 0;
	      p += DIR_STRUCT_SIZE;
	    }
	  else 
	    {
	      DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",Connections[cnum].dirpath,lp_dontdescend(SNUM(cnum))));
	      if (in_list(Connections[cnum].dirpath,
			  lp_dontdescend(SNUM(cnum)),True))
		check_descend = True;

	      for (i=numentries;(i<maxentries) && !finished;i++)
		{
		  finished = 
		    !get_dir_entry(cnum,mask,dirtype,fname,&size,&mode,&date,check_descend);
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
	}
    }


 SearchEmpty:

  if (numentries == 0 || !ok)
    {
      CVAL(outbuf,smb_rcls) = ERRDOS;
      SSVAL(outbuf,smb_err,ERRnofiles);
    }

  /* If we were called as SMBffirst with smb_search_id == NULL
     and no entries were found then return error and close dirptr 
     (X/Open spec) */

  if(ok && expect_close && numentries == 0 && status_len == 0)
    {
      CVAL(outbuf,smb_rcls) = ERRDOS;
      SSVAL(outbuf,smb_err,ERRnofiles);
      /* Also close the dptr - we know it's gone */
      dptr_close(dptr_num);
    }

  /* If we were called as SMBfunique, then we can close the dirptr now ! */
  if(dptr_num >= 0 && CVAL(inbuf,smb_com) == SMBfunique)
    dptr_close(dptr_num);

  SSVAL(outbuf,smb_vwv0,numentries);
  SSVAL(outbuf,smb_vwv1,3 + numentries * DIR_STRUCT_SIZE);
  CVAL(smb_buf(outbuf),0) = 5;
  SSVAL(smb_buf(outbuf),1,numentries*DIR_STRUCT_SIZE);

  if (Protocol >= PROTOCOL_NT1) {
    uint16 flg2 = SVAL(outbuf,smb_flg2);
    SSVAL(outbuf,smb_flg2,flg2 | 0x40); /* IS_LONG_NAME */
  }
  
  outsize += DIR_STRUCT_SIZE*numentries;
  smb_setlen(outbuf,outsize - 4);
  
  if ((! *directory) && dptr_path(dptr_num))
    slprintf(directory, sizeof(directory)-1, "(%s)",dptr_path(dptr_num));

  DEBUG(4,("%s %s mask=%s path=%s cnum=%d dtype=%d nument=%d of %d\n",
	timestring(),
	smb_fn_name(CVAL(inbuf,smb_com)), 
	mask,directory,cnum,dirtype,numentries,maxentries));

  return(outsize);
}


/****************************************************************************
  reply to a fclose (stop directory search)
****************************************************************************/
int reply_fclose(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int cnum;
  int outsize = 0;
  int status_len;
  char *path;
  char status[21];
  int dptr_num= -1;

  cnum = SVAL(inbuf,smb_tid);

  outsize = set_message(outbuf,1,0,True);
  path = smb_buf(inbuf) + 1;
  status_len = SVAL(smb_buf(inbuf),3 + strlen(path));

  
  if (status_len == 0)
    return(ERROR(ERRSRV,ERRsrverror));

  memcpy(status,smb_buf(inbuf) + 1 + strlen(path) + 4,21);

  if(dptr_fetch(status+12,&dptr_num)) {
    /*  Close the dptr - we know it's gone */
    dptr_close(dptr_num);
  }

  SSVAL(outbuf,smb_vwv0,0);

  DEBUG(3,("%s search close cnum=%d\n",timestring(),cnum));

  return(outsize);
}


/****************************************************************************
  reply to an open
****************************************************************************/
int reply_open(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring fname;
  int cnum;
  int fnum = -1;
  int outsize = 0;
  int fmode=0;
  int share_mode;
  int size = 0;
  time_t mtime=0;
  int unixmode;
  int rmode=0;
  struct stat sbuf;
  BOOL bad_path = False;
  files_struct *fsp;
  int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
 
  cnum = SVAL(inbuf,smb_tid);

  share_mode = SVAL(inbuf,smb_vwv0);

  pstrcpy(fname,smb_buf(inbuf)+1);
  unix_convert(fname,cnum,0,&bad_path);
    
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }
 
  unixmode = unix_mode(cnum,aARCH);
      
  open_file_shared(fnum,cnum,fname,share_mode,3,unixmode,
                   oplock_request,&rmode,NULL);

  fsp = &Files[fnum];

  if (!fsp->open)
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  if (fstat(fsp->fd_ptr->fd,&sbuf) != 0) {
    close_file(fnum,False);
    return(ERROR(ERRDOS,ERRnoaccess));
  }
    
  size = sbuf.st_size;
  fmode = dos_mode(cnum,fname,&sbuf);
  mtime = sbuf.st_mtime;

  if (fmode & aDIR) {
    DEBUG(3,("attempt to open a directory %s\n",fname));
    close_file(fnum,False);
    return(ERROR(ERRDOS,ERRnoaccess));
  }
  
  outsize = set_message(outbuf,7,0,True);
  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,fmode);
  if(lp_dos_filetime_resolution(SNUM(cnum)) )
    put_dos_date3(outbuf,smb_vwv2,mtime & ~1);
  else
    put_dos_date3(outbuf,smb_vwv2,mtime);
  SIVAL(outbuf,smb_vwv4,size);
  SSVAL(outbuf,smb_vwv6,rmode);

  if (oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
  }
    
  if(fsp->granted_oplock)
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
  return(outsize);
}


/****************************************************************************
  reply to an open and X
****************************************************************************/
int reply_open_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname;
  int cnum = SVAL(inbuf,smb_tid);
  int fnum = -1;
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
  int unixmode;
  int size=0,fmode=0,mtime=0,rmode=0;
  struct stat sbuf;
  int smb_action = 0;
  BOOL bad_path = False;
  files_struct *fsp;

  /* If it's an IPC, pass off the pipe handler. */
  if (IS_IPC(cnum))
    return reply_open_pipe_and_X(inbuf,outbuf,length,bufsize);

  /* XXXX we need to handle passed times, sattr and flags */

  pstrcpy(fname,smb_buf(inbuf));
  unix_convert(fname,cnum,0,&bad_path);
    
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  unixmode = unix_mode(cnum,smb_attr | aARCH);
      
  open_file_shared(fnum,cnum,fname,smb_mode,smb_ofun,unixmode,
		   oplock_request, &rmode,&smb_action);
      
  fsp = &Files[fnum];

  if (!fsp->open)
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  if (fstat(fsp->fd_ptr->fd,&sbuf) != 0) {
    close_file(fnum,False);
    return(ERROR(ERRDOS,ERRnoaccess));
  }

  size = sbuf.st_size;
  fmode = dos_mode(cnum,fname,&sbuf);
  mtime = sbuf.st_mtime;
  if (fmode & aDIR) {
    close_file(fnum,False);
    return(ERROR(ERRDOS,ERRnoaccess));
  }

  /* If the caller set the extended oplock request bit
     and we granted one (by whatever means) - set the
     correct bit for extended oplock reply.
   */

  if (ex_oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  }

  if(ex_oplock_request && fsp->granted_oplock) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  }

  /* If the caller set the core oplock request bit
     and we granted one (by whatever means) - set the
     correct bit for core oplock reply.
   */

  if (core_oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
  }

  if(core_oplock_request && fsp->granted_oplock) {
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
  }

  set_message(outbuf,15,0,True);
  SSVAL(outbuf,smb_vwv2,fnum);
  SSVAL(outbuf,smb_vwv3,fmode);
  if(lp_dos_filetime_resolution(SNUM(cnum)) )
    put_dos_date3(outbuf,smb_vwv4,mtime & ~1);
  else
    put_dos_date3(outbuf,smb_vwv4,mtime);
  SIVAL(outbuf,smb_vwv6,size);
  SSVAL(outbuf,smb_vwv8,rmode);
  SSVAL(outbuf,smb_vwv11,smb_action);

  chain_fnum = fnum;

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a SMBulogoffX
****************************************************************************/
int reply_ulogoffX(char *inbuf,char *outbuf,int length,int bufsize)
{
  uint16 vuid = SVAL(inbuf,smb_uid);
  user_struct *vuser = get_valid_user_struct(vuid);

  if(vuser == 0) {
    DEBUG(3,("ulogoff, vuser id %d does not map to user.\n", vuid));
  }

  /* in user level security we are supposed to close any files
     open by this user */
  if ((vuser != 0) && (lp_security() != SEC_SHARE)) {
    int i;
    for (i=0;i<MAX_OPEN_FILES;i++)
      if ((Files[i].vuid == vuid) && Files[i].open) {
	close_file(i,False);
      }
  }

  invalidate_vuid(vuid);

  set_message(outbuf,2,0,True);

  DEBUG(3,("%s ulogoffX vuid=%d\n",timestring(),vuid));

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a mknew or a create
****************************************************************************/
int reply_mknew(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring fname;
  int cnum,com;
  int fnum = -1;
  int outsize = 0;
  int createmode;
  mode_t unixmode;
  int ofun = 0;
  BOOL bad_path = False;
  files_struct *fsp;
  int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
 
  com = SVAL(inbuf,smb_com);
  cnum = SVAL(inbuf,smb_tid);

  createmode = SVAL(inbuf,smb_vwv0);
  pstrcpy(fname,smb_buf(inbuf)+1);
  unix_convert(fname,cnum,0,&bad_path);

  if (createmode & aVOLID)
    {
      DEBUG(0,("Attempt to create file (%s) with volid set - please report this\n",fname));
    }
  
  unixmode = unix_mode(cnum,createmode);
  
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  if(com == SMBmknew)
  {
    /* We should fail if file exists. */
    ofun = 0x10;
  }
  else
  {
    /* SMBcreate - Create if file doesn't exist, truncate if it does. */
    ofun = 0x12;
  }

  /* Open file in dos compatibility share mode. */
  open_file_shared(fnum,cnum,fname,(DENY_FCB<<4)|0xF, ofun, unixmode, 
                   oplock_request, NULL, NULL);
  
  fsp = &Files[fnum];

  if (!fsp->open)
  {
    if((errno == ENOENT) && bad_path) 
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }
 
  outsize = set_message(outbuf,1,0,True);
  SSVAL(outbuf,smb_vwv0,fnum);

  if (oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
  }
 
  if(fsp->granted_oplock)
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
 
  DEBUG(2,("new file %s\n",fname));
  DEBUG(3,("%s mknew %s fd=%d fnum=%d cnum=%d dmode=%d umode=%o\n",timestring(),fname,Files[fnum].fd_ptr->fd,fnum,cnum,createmode,unixmode));
  
  return(outsize);
}


/****************************************************************************
  reply to a create temporary file
****************************************************************************/
int reply_ctemp(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  pstring fname;
  pstring fname2;
  int cnum;
  int fnum = -1;
  int outsize = 0;
  int createmode;
  mode_t unixmode;
  BOOL bad_path = False;
  files_struct *fsp;
  int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
 
  cnum = SVAL(inbuf,smb_tid);
  createmode = SVAL(inbuf,smb_vwv0);
  pstrcpy(fname,smb_buf(inbuf)+1);
  pstrcat(fname,"/TMXXXXXX");
  unix_convert(fname,cnum,0,&bad_path);
  
  unixmode = unix_mode(cnum,createmode);
  
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  pstrcpy(fname2,(char *)mktemp(fname));

  /* Open file in dos compatibility share mode. */
  /* We should fail if file exists. */
  open_file_shared(fnum,cnum,fname2,(DENY_FCB<<4)|0xF, 0x10, unixmode, 
                   oplock_request, NULL, NULL);

  fsp = &Files[fnum];

  if (!fsp->open)
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  outsize = set_message(outbuf,1,2 + strlen(fname2),True);
  SSVAL(outbuf,smb_vwv0,fnum);
  CVAL(smb_buf(outbuf),0) = 4;
  pstrcpy(smb_buf(outbuf) + 1,fname2);

  if (oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
  }
  
  if(fsp->granted_oplock)
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;

  DEBUG(2,("created temp file %s\n",fname2));
  DEBUG(3,("%s ctemp %s fd=%d fnum=%d cnum=%d dmode=%d umode=%o\n",timestring(),fname2,Files[fnum].fd_ptr->fd,fnum,cnum,createmode,unixmode));
  
  return(outsize);
}


/*******************************************************************
check if a user is allowed to delete a file
********************************************************************/
static BOOL can_delete(char *fname,int cnum,int dirtype)
{
  struct stat sbuf;
  int fmode;

  if (!CAN_WRITE(cnum)) return(False);

  if (sys_lstat(fname,&sbuf) != 0) return(False);
  fmode = dos_mode(cnum,fname,&sbuf);
  if (fmode & aDIR) return(False);
  if (!lp_delete_readonly(SNUM(cnum))) {
    if (fmode & aRONLY) return(False);
  }
  if ((fmode & ~dirtype) & (aHIDDEN | aSYSTEM))
    return(False);
  if (!check_file_sharing(cnum,fname,False)) return(False);
  return(True);
}

/****************************************************************************
  reply to a unlink
****************************************************************************/
int reply_unlink(char *inbuf,char *outbuf, int dum_size, int dum_bufsize)
{
  int outsize = 0;
  pstring name;
  int cnum;
  int dirtype;
  pstring directory;
  pstring mask;
  char *p;
  int count=0;
  int error = ERRnoaccess;
  BOOL has_wild;
  BOOL exists=False;
  BOOL bad_path = False;

  *directory = *mask = 0;

  cnum = SVAL(inbuf,smb_tid);
  dirtype = SVAL(inbuf,smb_vwv0);
  
  pstrcpy(name,smb_buf(inbuf) + 1);
   
  DEBUG(3,("reply_unlink : %s\n",name));
   
  unix_convert(name,cnum,0,&bad_path);

  p = strrchr(name,'/');
  if (!p) {
    pstrcpy(directory,"./");
    pstrcpy(mask,name);
  } else {
    *p = 0;
    pstrcpy(directory,name);
    pstrcpy(mask,p+1);
  }

  if (is_mangled(mask))
    check_mangled_stack(mask);

  has_wild = strchr(mask,'*') || strchr(mask,'?');

  if (!has_wild) {
    pstrcat(directory,"/");
    pstrcat(directory,mask);
    if (can_delete(directory,cnum,dirtype) && !sys_unlink(directory)) count++;
    if (!count) exists = file_exist(directory,NULL);    
  } else {
    void *dirptr = NULL;
    char *dname;

    if (check_name(directory,cnum))
      dirptr = OpenDir(cnum, directory, True);

    /* XXXX the CIFS spec says that if bit0 of the flags2 field is set then
       the pattern matches against the long name, otherwise the short name 
       We don't implement this yet XXXX
       */

    if (dirptr)
      {
	error = ERRbadfile;

	if (strequal(mask,"????????.???"))
	  pstrcpy(mask,"*");

	while ((dname = ReadDirName(dirptr)))
	  {
	    pstring fname;
	    pstrcpy(fname,dname);
	    
	    if(!mask_match(fname, mask, case_sensitive, False)) continue;

	    error = ERRnoaccess;
	    slprintf(fname,sizeof(fname)-1, "%s/%s",directory,dname);
	    if (!can_delete(fname,cnum,dirtype)) continue;
	    if (!sys_unlink(fname)) count++;
	    DEBUG(3,("reply_unlink : doing unlink on %s\n",fname));
	  }
	CloseDir(dirptr);
      }
  }
  
  if (count == 0) {
    if (exists)
      return(ERROR(ERRDOS,error));
    else
    {
      if((errno == ENOENT) && bad_path)
      {
        unix_ERR_class = ERRDOS;
        unix_ERR_code = ERRbadpath;
      }
      return(UNIXERROR(ERRDOS,error));
    }
  }
  
  outsize = set_message(outbuf,0,0,True);
  
  return(outsize);
}


/****************************************************************************
   reply to a readbraw (core+ protocol)
****************************************************************************/
int reply_readbraw(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
  int cnum,maxcount,mincount,fnum;
  int nread = 0;
  uint32 startpos;
  char *header = outbuf;
  int ret=0;
  int fd;
  char *fname;

  /*
   * Special check if an oplock break has been issued
   * and the readraw request croses on the wire, we must
   * return a zero length response here.
   */

  if(global_oplock_break)
  {
    _smb_setlen(header,0);
    transfer_file(0,Client,0,header,4,0);
    DEBUG(5,("readbraw - oplock break finished\n"));
    return -1;
  }

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  startpos = IVAL(inbuf,smb_vwv1);
  maxcount = SVAL(inbuf,smb_vwv3);
  mincount = SVAL(inbuf,smb_vwv4);

  /* ensure we don't overrun the packet size */
  maxcount = MIN(65535,maxcount);
  maxcount = MAX(mincount,maxcount);

  if (!FNUM_OK(fnum,cnum) || !Files[fnum].can_read)
    {
      DEBUG(3,("fnum %d not open in readbraw - cache prime?\n",fnum));
      _smb_setlen(header,0);
      transfer_file(0,Client,0,header,4,0);
      return(-1);
    }
  else
    {
      fd = Files[fnum].fd_ptr->fd;
      fname = Files[fnum].name;
    }


  if (!is_locked(fnum,cnum,maxcount,startpos))
    {
      int size = Files[fnum].size;
      int sizeneeded = startpos + maxcount;
	    
      if (size < sizeneeded) {
	struct stat st;
	if (fstat(Files[fnum].fd_ptr->fd,&st) == 0)
	  size = st.st_size;
	if (!Files[fnum].can_write) 
	  Files[fnum].size = size;
      }

      nread = MIN(maxcount,(int)(size - startpos));	  
    }

  if (nread < mincount)
    nread = 0;
  
  DEBUG(3,("%s readbraw fnum=%d cnum=%d start=%d max=%d min=%d nread=%d\n",
	   timestring(),
	   fnum,cnum,startpos,
	   maxcount,mincount,nread));
  
#if UNSAFE_READRAW
  {
    int predict=0;
    _smb_setlen(header,nread);

#if USE_READ_PREDICTION
    if (!Files[fnum].can_write)
      predict = read_predict(fd,startpos,header+4,NULL,nread);
#endif

    if ((nread-predict) > 0)
      seek_file(fnum,startpos + predict);
    
    ret = transfer_file(fd,Client,nread-predict,header,4+predict,
			startpos+predict);
  }

  if (ret != nread+4)
    DEBUG(0,("ERROR: file read failure on %s at %d for %d bytes (%d)\n",
	     fname,startpos,nread,ret));

#else
  ret = read_file(fnum,header+4,startpos,nread);
  if (ret < mincount) ret = 0;

  _smb_setlen(header,ret);
  transfer_file(0,Client,0,header,4+ret,0);
#endif

  DEBUG(5,("readbraw finished\n"));
  return -1;
}


/****************************************************************************
  reply to a lockread (core+ protocol)
****************************************************************************/
int reply_lockread(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int cnum,fnum;
  int nread = -1;
  char *data;
  int outsize = 0;
  uint32 startpos, numtoread;
  int eclass;
  uint32 ecode;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);

  numtoread = SVAL(inbuf,smb_vwv1);
  startpos = IVAL(inbuf,smb_vwv2);
  
  outsize = set_message(outbuf,5,3,True);
  numtoread = MIN(BUFFER_SIZE-outsize,numtoread);
  data = smb_buf(outbuf) + 3;
  
  if(!do_lock( fnum, cnum, numtoread, startpos, &eclass, &ecode))
    return (ERROR(eclass,ecode));

  nread = read_file(fnum,data,startpos,numtoread);
  
  if (nread < 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  outsize += nread;
  SSVAL(outbuf,smb_vwv0,nread);
  SSVAL(outbuf,smb_vwv5,nread+3);
  SSVAL(smb_buf(outbuf),1,nread);
  
  DEBUG(3,("%s lockread fnum=%d cnum=%d num=%d nread=%d\n",timestring(),fnum,cnum,numtoread,nread));
  
  return(outsize);
}


/****************************************************************************
  reply to a read
****************************************************************************/
int reply_read(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int cnum,numtoread,fnum;
  int nread = 0;
  char *data;
  uint32 startpos;
  int outsize = 0;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);

  numtoread = SVAL(inbuf,smb_vwv1);
  startpos = IVAL(inbuf,smb_vwv2);
  
  outsize = set_message(outbuf,5,3,True);
  numtoread = MIN(BUFFER_SIZE-outsize,numtoread);
  data = smb_buf(outbuf) + 3;
  
  if (is_locked(fnum,cnum,numtoread,startpos))
    return(ERROR(ERRDOS,ERRlock));	

  if (numtoread > 0)
    nread = read_file(fnum,data,startpos,numtoread);
  
  if (nread < 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  outsize += nread;
  SSVAL(outbuf,smb_vwv0,nread);
  SSVAL(outbuf,smb_vwv5,nread+3);
  CVAL(smb_buf(outbuf),0) = 1;
  SSVAL(smb_buf(outbuf),1,nread);
  
  DEBUG(3,("%s read fnum=%d cnum=%d num=%d nread=%d\n",timestring(),fnum,cnum,numtoread,nread));
  
  return(outsize);
}


/****************************************************************************
  reply to a read and X
****************************************************************************/
int reply_read_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum = GETFNUM(inbuf,smb_vwv2);
  uint32 smb_offs = IVAL(inbuf,smb_vwv3);
  int smb_maxcnt = SVAL(inbuf,smb_vwv5);
  int smb_mincnt = SVAL(inbuf,smb_vwv6);
  int cnum;
  int nread = -1;
  char *data;
  BOOL ok = False;

  cnum = SVAL(inbuf,smb_tid);

  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);

  set_message(outbuf,12,0,True);
  data = smb_buf(outbuf);

  if (is_locked(fnum,cnum,smb_maxcnt,smb_offs))
    return(ERROR(ERRDOS,ERRlock));
  nread = read_file(fnum,data,smb_offs,smb_maxcnt);
  ok = True;
  
  if (nread < 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  SSVAL(outbuf,smb_vwv5,nread);
  SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
  SSVAL(smb_buf(outbuf),-2,nread);
  
  DEBUG(3,("%s readX fnum=%d cnum=%d min=%d max=%d nread=%d\n",
	timestring(),fnum,cnum,
	smb_mincnt,smb_maxcnt,nread));

  chain_fnum = fnum;

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a writebraw (core+ or LANMAN1.0 protocol)
****************************************************************************/
int reply_writebraw(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int nwritten=0;
  int total_written=0;
  int numtowrite=0;
  int cnum,fnum;
  int outsize = 0;
  long startpos;
  char *data=NULL;
  BOOL write_through;
  int tcount;

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);
  
  tcount = IVAL(inbuf,smb_vwv1);
  startpos = IVAL(inbuf,smb_vwv3);
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
  CVAL(inbuf,smb_com) = SMBwritec;
  CVAL(outbuf,smb_com) = SMBwritec;

  if (is_locked(fnum,cnum,tcount,startpos))
    return(ERROR(ERRDOS,ERRlock));

  if (seek_file(fnum,startpos) != startpos)
    DEBUG(0,("couldn't seek to %d in writebraw\n",startpos));

  if (numtowrite>0)
    nwritten = write_file(fnum,data,numtowrite);
  
  DEBUG(3,("%s writebraw1 fnum=%d cnum=%d start=%d num=%d wrote=%d sync=%d\n",
	   timestring(),fnum,cnum,startpos,numtowrite,nwritten,write_through));

  if (nwritten < numtowrite) 
    return(UNIXERROR(ERRHRD,ERRdiskfull));

  total_written = nwritten;

  /* Return a message to the redirector to tell it
     to send more bytes */
  CVAL(outbuf,smb_com) = SMBwritebraw;
  SSVALS(outbuf,smb_vwv0,-1);
  outsize = set_message(outbuf,Protocol>PROTOCOL_COREPLUS?1:0,0,True);
  send_smb(Client,outbuf);
  
  /* Now read the raw data into the buffer and write it */
  if (read_smb_length(Client,inbuf,SMB_SECONDARY_WAIT) == -1) {
    exit_server("secondary writebraw failed");
  }
  
  /* Even though this is not an smb message, smb_len
     returns the generic length of an smb message */
  numtowrite = smb_len(inbuf);

  if (tcount > nwritten+numtowrite) {
    DEBUG(3,("Client overestimated the write %d %d %d\n",
	     tcount,nwritten,numtowrite));
  }

  nwritten = transfer_file(Client,Files[fnum].fd_ptr->fd,numtowrite,NULL,0,
			   startpos+nwritten);
  total_written += nwritten;
  
  /* Set up outbuf to return the correct return */
  outsize = set_message(outbuf,1,0,True);
  CVAL(outbuf,smb_com) = SMBwritec;
  SSVAL(outbuf,smb_vwv0,total_written);

  if (nwritten < numtowrite) {
    CVAL(outbuf,smb_rcls) = ERRHRD;
    SSVAL(outbuf,smb_err,ERRdiskfull);      
  }

  if (lp_syncalways(SNUM(cnum)) || write_through)
    sync_file(fnum);

  DEBUG(3,("%s writebraw2 fnum=%d cnum=%d start=%d num=%d wrote=%d\n",
	   timestring(),fnum,cnum,startpos,numtowrite,total_written));

  /* we won't return a status if write through is not selected - this 
     follows what WfWg does */
  if (!write_through && total_written==tcount)
    return(-1);

  return(outsize);
}


/****************************************************************************
  reply to a writeunlock (core+)
****************************************************************************/
int reply_writeunlock(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum,fnum;
  int nwritten = -1;
  int outsize = 0;
  char *data;
  uint32 numtowrite,startpos;
  int eclass;
  uint32 ecode;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = IVAL(inbuf,smb_vwv2);
  data = smb_buf(inbuf) + 3;
  
  if (is_locked(fnum,cnum,numtowrite,startpos))
    return(ERROR(ERRDOS,ERRlock));

  seek_file(fnum,startpos);

  /* The special X/Open SMB protocol handling of
     zero length writes is *NOT* done for
     this call */
  if(numtowrite == 0)
    nwritten = 0;
  else
    nwritten = write_file(fnum,data,numtowrite);
  
  if (lp_syncalways(SNUM(cnum)))
    sync_file(fnum);

  if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0))
    return(UNIXERROR(ERRDOS,ERRnoaccess));

  if(!do_unlock(fnum, cnum, numtowrite, startpos, &eclass, &ecode))
    return(ERROR(eclass,ecode));

  outsize = set_message(outbuf,1,0,True);
  
  SSVAL(outbuf,smb_vwv0,nwritten);
  
  DEBUG(3,("%s writeunlock fnum=%d cnum=%d num=%d wrote=%d\n",
	   timestring(),fnum,cnum,numtowrite,nwritten));
  
  return(outsize);
}


/****************************************************************************
  reply to a write
****************************************************************************/
int reply_write(char *inbuf,char *outbuf,int dum1,int dum2)
{
  int cnum,numtowrite,fnum;
  int nwritten = -1;
  int outsize = 0;
  int startpos;
  char *data;

  dum1 = dum2 = 0;

  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = IVAL(inbuf,smb_vwv2);
  data = smb_buf(inbuf) + 3;
  
  if (is_locked(fnum,cnum,numtowrite,startpos))
    return(ERROR(ERRDOS,ERRlock));

  seek_file(fnum,startpos);

  /* X/Open SMB protocol says that if smb_vwv1 is
     zero then the file size should be extended or
     truncated to the size given in smb_vwv[2-3] */
  if(numtowrite == 0)
    nwritten = set_filelen(Files[fnum].fd_ptr->fd, startpos);
  else
    nwritten = write_file(fnum,data,numtowrite);
  
  if (lp_syncalways(SNUM(cnum)))
    sync_file(fnum);

  if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0))
    return(UNIXERROR(ERRDOS,ERRnoaccess));

  outsize = set_message(outbuf,1,0,True);
  
  SSVAL(outbuf,smb_vwv0,nwritten);

  if (nwritten < numtowrite) {
    CVAL(outbuf,smb_rcls) = ERRHRD;
    SSVAL(outbuf,smb_err,ERRdiskfull);      
  }
  
  DEBUG(3,("%s write fnum=%d cnum=%d num=%d wrote=%d\n",timestring(),fnum,cnum,numtowrite,nwritten));
  
  return(outsize);
}


/****************************************************************************
  reply to a write and X
****************************************************************************/
int reply_write_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum = GETFNUM(inbuf,smb_vwv2);
  uint32 smb_offs = IVAL(inbuf,smb_vwv3);
  int smb_dsize = SVAL(inbuf,smb_vwv10);
  int smb_doff = SVAL(inbuf,smb_vwv11);
  BOOL write_through = BITSETW(inbuf+smb_vwv7,0);
  int cnum;
  int nwritten = -1;
  char *data;

  cnum = SVAL(inbuf,smb_tid);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  data = smb_base(inbuf) + smb_doff;

  if (is_locked(fnum,cnum,smb_dsize,smb_offs))
    return(ERROR(ERRDOS,ERRlock));

  seek_file(fnum,smb_offs);
  
  /* X/Open SMB protocol says that, unlike SMBwrite
     if the length is zero then NO truncation is
     done, just a write of zero. To truncate a file,
     use SMBwrite. */
  if(smb_dsize == 0)
    nwritten = 0;
  else
    nwritten = write_file(fnum,data,smb_dsize);
  
  if(((nwritten == 0) && (smb_dsize != 0))||(nwritten < 0))
    return(UNIXERROR(ERRDOS,ERRnoaccess));

  set_message(outbuf,6,0,True);
  
  SSVAL(outbuf,smb_vwv2,nwritten);
  
  if (nwritten < smb_dsize) {
    CVAL(outbuf,smb_rcls) = ERRHRD;
    SSVAL(outbuf,smb_err,ERRdiskfull);      
  }

  DEBUG(3,("%s writeX fnum=%d cnum=%d num=%d wrote=%d\n",timestring(),fnum,cnum,smb_dsize,nwritten));

  chain_fnum = fnum;

  if (lp_syncalways(SNUM(cnum)) || write_through)
    sync_file(fnum);

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a lseek
****************************************************************************/
int reply_lseek(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum,fnum;
  uint32 startpos;
  int32 res= -1;
  int mode,umode;
  int outsize = 0;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  mode = SVAL(inbuf,smb_vwv1) & 3;
  startpos = IVAL(inbuf,smb_vwv2);

  switch (mode & 3) 
    {
    case 0: umode = SEEK_SET; break;
    case 1: umode = SEEK_CUR; break;
    case 2: umode = SEEK_END; break;
    default:
      umode = SEEK_SET; break;
    }
  
  res = lseek(Files[fnum].fd_ptr->fd,startpos,umode);
  Files[fnum].pos = res;
  
  outsize = set_message(outbuf,2,0,True);
  SIVALS(outbuf,smb_vwv0,res);
  
  DEBUG(3,("%s lseek fnum=%d cnum=%d ofs=%d mode=%d\n",timestring(),fnum,cnum,startpos,mode));
  
  return(outsize);
}


/****************************************************************************
  reply to a flush
****************************************************************************/
int reply_flush(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum, fnum;
  int outsize = set_message(outbuf,0,0,True);

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  if (fnum != 0xFFFF) {
    CHECK_FNUM(fnum,cnum);
    CHECK_ERROR(fnum);
  }

  if (fnum == 0xFFFF)
    {
      int i;
      for (i=0;i<MAX_OPEN_FILES;i++)
	if (OPEN_FNUM(i))
	  sync_file(i);
    }
  else
    sync_file(fnum);

  DEBUG(3,("%s flush fnum=%d\n",timestring(),fnum));
  return(outsize);
}


/****************************************************************************
  reply to a exit
****************************************************************************/
int reply_exit(char *inbuf,char *outbuf, int size, int bufsize)
{
  int outsize = set_message(outbuf,0,0,True);
  DEBUG(3,("%s exit\n",timestring()));
  
  return(outsize);
}


/****************************************************************************
  reply to a close
****************************************************************************/
int reply_close(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int fnum,cnum;
  int outsize = 0;
  time_t mtime;
  int32 eclass = 0, err = 0;

  outsize = set_message(outbuf,0,0,True);

  cnum = SVAL(inbuf,smb_tid);

  /* If it's an IPC, pass off to the pipe handler. */
  if (IS_IPC(cnum))
    return reply_pipe_close(inbuf,outbuf);

  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);

  if(HAS_CACHED_ERROR(fnum)) {
    eclass = Files[fnum].wbmpx_ptr->wr_errclass;
    err = Files[fnum].wbmpx_ptr->wr_error;
  }

  mtime = make_unix_date3(inbuf+smb_vwv1);

  /* try and set the date */
  set_filetime(cnum, Files[fnum].name,mtime);

  DEBUG(3,("%s close fd=%d fnum=%d cnum=%d (numopen=%d)\n",
	   timestring(),Files[fnum].fd_ptr->fd,fnum,cnum,
	   Connections[cnum].num_files_open));
  
  close_file(fnum,True);

  /* We have a cached error */
  if(eclass || err)
    return(ERROR(eclass,err));

  return(outsize);
}


/****************************************************************************
  reply to a writeclose (Core+ protocol)
****************************************************************************/
int reply_writeclose(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum,numtowrite,fnum;
  int nwritten = -1;
  int outsize = 0;
  int startpos;
  char *data;
  time_t mtime;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = IVAL(inbuf,smb_vwv2);
  mtime = make_unix_date3(inbuf+smb_vwv4);
  data = smb_buf(inbuf) + 1;
  
  if (is_locked(fnum,cnum,numtowrite,startpos))
    return(ERROR(ERRDOS,ERRlock));
      
  seek_file(fnum,startpos);
      
  nwritten = write_file(fnum,data,numtowrite);

  set_filetime(cnum, Files[fnum].name,mtime);
  
  DEBUG(3,("%s writeclose fnum=%d cnum=%d num=%d wrote=%d (numopen=%d)\n",
	   timestring(),fnum,cnum,numtowrite,nwritten,
	   Connections[cnum].num_files_open));
  
  close_file(fnum,True);

  if (nwritten <= 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  outsize = set_message(outbuf,1,0,True);
  
  SSVAL(outbuf,smb_vwv0,nwritten);
  return(outsize);
}


/****************************************************************************
  reply to a lock
****************************************************************************/
int reply_lock(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int fnum,cnum;
  int outsize = set_message(outbuf,0,0,True);
  uint32 count,offset;
  int eclass;
  uint32 ecode;

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  count = IVAL(inbuf,smb_vwv1);
  offset = IVAL(inbuf,smb_vwv3);

  DEBUG(3,("%s lock fd=%d fnum=%d cnum=%d ofs=%d cnt=%d\n",timestring(),Files[fnum].fd_ptr->fd,fnum,cnum,offset,count));

  if(!do_lock( fnum, cnum, count, offset, &eclass, &ecode))
    return (ERROR(eclass,ecode));
  
  return(outsize);
}


/****************************************************************************
  reply to a unlock
****************************************************************************/
int reply_unlock(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int fnum,cnum;
  int outsize = set_message(outbuf,0,0,True);
  uint32 count,offset;
  int eclass;
  uint32 ecode;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  count = IVAL(inbuf,smb_vwv1);
  offset = IVAL(inbuf,smb_vwv3);

  if(!do_unlock(fnum, cnum, count, offset, &eclass, &ecode))
    return (ERROR(eclass,ecode));

  DEBUG(3,("%s unlock fd=%d fnum=%d cnum=%d ofs=%d cnt=%d\n",timestring(),Files[fnum].fd_ptr->fd,fnum,cnum,offset,count));
  
  return(outsize);
}


/****************************************************************************
  reply to a tdis
****************************************************************************/
int reply_tdis(char *inbuf,char *outbuf, int size, int bufsize)
{
  int cnum;
  int outsize = set_message(outbuf,0,0,True);
  uint16 vuid;

  cnum = SVAL(inbuf,smb_tid);
  vuid = SVAL(inbuf,smb_uid);

  if (!OPEN_CNUM(cnum)) {
    DEBUG(4,("Invalid cnum in tdis (%d)\n",cnum));
    return(ERROR(ERRSRV,ERRinvnid));
  }

  Connections[cnum].used = False;

  close_cnum(cnum,vuid);
  
  DEBUG(3,("%s tdis cnum=%d\n",timestring(),cnum));

  return outsize;
}



/****************************************************************************
  reply to a echo
****************************************************************************/
int reply_echo(char *inbuf,char *outbuf, int size, int bufsize)
{
  int cnum;
  int smb_reverb = SVAL(inbuf,smb_vwv0);
  int seq_num;
  int data_len = smb_buflen(inbuf);
  int outsize = set_message(outbuf,1,data_len,True);

  cnum = SVAL(inbuf,smb_tid);

  /* According to the latest CIFS spec we shouldn't
     care what the TID is.
   */

#if 0
  if (cnum != 0xFFFF && !OPEN_CNUM(cnum))
    {
      DEBUG(4,("Invalid cnum in echo (%d)\n",cnum));
      return(ERROR(ERRSRV,ERRinvnid));
    }
#endif

  /* copy any incoming data back out */
  if (data_len > 0)
    memcpy(smb_buf(outbuf),smb_buf(inbuf),data_len);

  if (smb_reverb > 100)
    {
      DEBUG(0,("large reverb (%d)?? Setting to 100\n",smb_reverb));
      smb_reverb = 100;
    }

  for (seq_num =1 ; seq_num <= smb_reverb ; seq_num++)
    {
      SSVAL(outbuf,smb_vwv0,seq_num);

      smb_setlen(outbuf,outsize - 4);

      send_smb(Client,outbuf);
    }

  DEBUG(3,("%s echo %d times cnum=%d\n",timestring(),smb_reverb,cnum));

  return -1;
}


/****************************************************************************
  reply to a printopen
****************************************************************************/
int reply_printopen(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  pstring fname;
  pstring fname2;
  int cnum;
  int fnum = -1;
  int outsize = 0;

  *fname = *fname2 = 0;

  cnum = SVAL(inbuf,smb_tid);

  if (!CAN_PRINT(cnum))
    return(ERROR(ERRDOS,ERRnoaccess));

  {
    pstring s;
    char *p;
    pstrcpy(s,smb_buf(inbuf)+1);
    p = s;
    while (*p)
      {
	if (!(isalnum(*p) || strchr("._-",*p)))
	  *p = 'X';
	p++;
      }

    if (strlen(s) > 10) s[10] = 0;

    slprintf(fname,sizeof(fname)-1, "%s.XXXXXX",s);  
  }

  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR(ERRSRV,ERRnofids));

  pstrcpy(fname2,(char *)mktemp(fname));

  if (!check_name(fname2,cnum)) {
	  Files[fnum].reserved = False;
	  return(ERROR(ERRDOS,ERRnoaccess));
  }

  /* Open for exclusive use, write only. */
  open_file_shared(fnum,cnum,fname2,(DENY_ALL<<4)|1, 0x12, unix_mode(cnum,0), 
                   0, NULL, NULL);

  if (!Files[fnum].open) {
	  Files[fnum].reserved = False;
	  return(UNIXERROR(ERRDOS,ERRnoaccess));
  }

  /* force it to be a print file */
  Files[fnum].print_file = True;
  
  outsize = set_message(outbuf,1,0,True);
  SSVAL(outbuf,smb_vwv0,fnum);
  
  DEBUG(3,("%s openprint %s fd=%d fnum=%d cnum=%d\n",timestring(),fname2,Files[fnum].fd_ptr->fd,fnum,cnum));
  
  return(outsize);
}


/****************************************************************************
  reply to a printclose
****************************************************************************/
int reply_printclose(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int fnum,cnum;
  int outsize = set_message(outbuf,0,0,True);
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  if (!CAN_PRINT(cnum))
    return(ERROR(ERRDOS,ERRnoaccess));
  
  DEBUG(3,("%s printclose fd=%d fnum=%d cnum=%d\n",timestring(),Files[fnum].fd_ptr->fd,fnum,cnum));
  
  close_file(fnum,True);
  
  return(outsize);
}


/****************************************************************************
  reply to a printqueue
****************************************************************************/
int reply_printqueue(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum;
  int outsize = set_message(outbuf,2,3,True);
  int max_count = SVAL(inbuf,smb_vwv0);
  int start_index = SVAL(inbuf,smb_vwv1);
  uint16 vuid;

  cnum = SVAL(inbuf,smb_tid);
  vuid = SVAL(inbuf,smb_uid);

/* allow checking the queue for anyone */
#if 0
  if (!CAN_PRINT(cnum))
    return(ERROR(ERRDOS,ERRnoaccess));
#endif

  SSVAL(outbuf,smb_vwv0,0);
  SSVAL(outbuf,smb_vwv1,0);
  CVAL(smb_buf(outbuf),0) = 1;
  SSVAL(smb_buf(outbuf),1,0);
  
  DEBUG(3,("%s printqueue cnum=%d start_index=%d max_count=%d\n",
	timestring(),cnum,start_index,max_count));

  if (!OPEN_CNUM(cnum) || !Connections[cnum].printer)
    {
      int i;
      cnum = -1;

      for (i=0;i<MAX_CONNECTIONS;i++)
	if (CAN_PRINT(i) && Connections[i].printer)
	  cnum = i;

      if (cnum == -1)
	for (i=0;i<MAX_CONNECTIONS;i++)
	  if (OPEN_CNUM(i))
	    cnum = i;

      if (!OPEN_CNUM(cnum))
	return(ERROR(ERRSRV,ERRinvnid));

      DEBUG(5,("connection not open or not a printer, using cnum %d\n",cnum));
    }

  if (!become_user(&Connections[cnum], cnum, vuid))
    return(ERROR(ERRSRV,ERRinvnid));

  {
    print_queue_struct *queue = NULL;
    char *p = smb_buf(outbuf) + 3;
    int count = get_printqueue(SNUM(cnum),cnum,&queue,NULL);
    int num_to_get = ABS(max_count);
    int first = (max_count>0?start_index:start_index+max_count+1);
    int i;

    if (first >= count)
      num_to_get = 0;
    else
      num_to_get = MIN(num_to_get,count-first);
    

    for (i=first;i<first+num_to_get;i++)
      {
	put_dos_date2(p,0,queue[i].time);
	CVAL(p,4) = (queue[i].status==LPQ_PRINTING?2:3);
	SSVAL(p,5,printjob_encode(SNUM(cnum), queue[i].job));
	SIVAL(p,7,queue[i].size);
	CVAL(p,11) = 0;
	StrnCpy(p+12,queue[i].user,16);
	p += 28;
      }

    if (count > 0)
      {
	outsize = set_message(outbuf,2,28*count+3,False);	  
	SSVAL(outbuf,smb_vwv0,count);
	SSVAL(outbuf,smb_vwv1,(max_count>0?first+count:first-1));
	CVAL(smb_buf(outbuf),0) = 1;
	SSVAL(smb_buf(outbuf),1,28*count);
      }

    if (queue) free(queue);
	  
    DEBUG(3,("%d entries returned in queue\n",count));
  }
  
  return(outsize);
}


/****************************************************************************
  reply to a printwrite
****************************************************************************/
int reply_printwrite(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum,numtowrite,fnum;
  int outsize = set_message(outbuf,0,0,True);
  char *data;
  
  cnum = SVAL(inbuf,smb_tid);

  if (!CAN_PRINT(cnum))
    return(ERROR(ERRDOS,ERRnoaccess));

  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  numtowrite = SVAL(smb_buf(inbuf),1);
  data = smb_buf(inbuf) + 3;
  
  if (write_file(fnum,data,numtowrite) != numtowrite)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  DEBUG(3,("%s printwrite fnum=%d cnum=%d num=%d\n",timestring(),fnum,cnum,numtowrite));
  
  return(outsize);
}


/****************************************************************************
  reply to a mkdir
****************************************************************************/
int reply_mkdir(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  pstring directory;
  int cnum;
  int outsize,ret= -1;
  BOOL bad_path = False;
 
  pstrcpy(directory,smb_buf(inbuf) + 1);
  cnum = SVAL(inbuf,smb_tid);
  unix_convert(directory,cnum,0,&bad_path);
  
  if (check_name(directory,cnum))
    ret = sys_mkdir(directory,unix_mode(cnum,aDIR));
  
  if (ret < 0)
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG(3,("%s mkdir %s cnum=%d ret=%d\n",timestring(),directory,cnum,ret));
  
  return(outsize);
}

/****************************************************************************
Static function used by reply_rmdir to delete an entire directory
tree recursively.
****************************************************************************/
static BOOL recursive_rmdir(char *directory)
{
  char *dname = NULL;
  BOOL ret = False;
  void *dirptr = OpenDir(-1, directory, False);

  if(dirptr == NULL)
    return True;

  while((dname = ReadDirName(dirptr)))
  {
    pstring fullname;
    struct stat st;

    if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
      continue;

    /* Construct the full name. */
    if(strlen(directory) + strlen(dname) + 1 >= sizeof(fullname))
    {
      errno = ENOMEM;
      ret = True;
      break;
    }
    pstrcpy(fullname, directory);
    pstrcat(fullname, "/");
    pstrcat(fullname, dname);

    if(sys_lstat(fullname, &st) != 0)
    {
      ret = True;
      break;
    }

    if(st.st_mode & S_IFDIR)
    {
      if(recursive_rmdir(fullname)!=0)
      {
        ret = True;
        break;
      }
      if(sys_rmdir(fullname) != 0)
      {
        ret = True;
        break;
      }
    }
    else if(sys_unlink(fullname) != 0)
    {
      ret = True;
      break;
    }
  }
  CloseDir(dirptr);
  return ret;
}

/****************************************************************************
  reply to a rmdir
****************************************************************************/
int reply_rmdir(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  pstring directory;
  int cnum;
  int outsize = 0;
  BOOL ok = False;
  BOOL bad_path = False;

  cnum = SVAL(inbuf,smb_tid);
  pstrcpy(directory,smb_buf(inbuf) + 1);
  unix_convert(directory,cnum,0,&bad_path);
  
  if (check_name(directory,cnum))
    {

      dptr_closepath(directory,SVAL(inbuf,smb_pid));
      ok = (sys_rmdir(directory) == 0);
      if(!ok && (errno == ENOTEMPTY) && lp_veto_files(SNUM(cnum)))
        {
          /* Check to see if the only thing in this directory are
             vetoed files/directories. If so then delete them and
             retry. If we fail to delete any of them (and we *don't*
             do a recursive delete) then fail the rmdir. */
          BOOL all_veto_files = True;
          char *dname;
          void *dirptr = OpenDir(cnum, directory, False);

          if(dirptr != NULL)
            {
              int dirpos = TellDir(dirptr);
	          while ((dname = ReadDirName(dirptr)))
	            {
                  if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
                    continue;
                  if(!IS_VETO_PATH(cnum, dname))
                    {
                      all_veto_files = False;
                      break;
                    }
                }
              if(all_veto_files)
                {
                  SeekDir(dirptr,dirpos);
                  while ((dname = ReadDirName(dirptr)))
                    {
                      pstring fullname;
                      struct stat st;

                      if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
                        continue;

                      /* Construct the full name. */
                      if(strlen(directory) + strlen(dname) + 1 >= sizeof(fullname))
                        {
                          errno = ENOMEM;
                          break;
                        }
                      pstrcpy(fullname, directory);
                      pstrcat(fullname, "/");
                      pstrcat(fullname, dname);
                      
                      if(sys_lstat(fullname, &st) != 0)
                        break;
                      if(st.st_mode & S_IFDIR)
                      {
                        if(lp_recursive_veto_delete(SNUM(cnum)))
                        {
                          if(recursive_rmdir(fullname) != 0)
                            break;
                        }
                        if(sys_rmdir(fullname) != 0)
                          break;
                      }
                      else if(sys_unlink(fullname) != 0)
                        break;
                    }
                  CloseDir(dirptr);
                  /* Retry the rmdir */
                  ok = (sys_rmdir(directory) == 0);
                }
              else
                CloseDir(dirptr);
            }
          else
            errno = ENOTEMPTY;
         }
          
      if (!ok)
        DEBUG(3,("couldn't remove directory %s : %s\n",
		 directory,strerror(errno)));
    }
  
  if (!ok)
  {
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    return(UNIXERROR(ERRDOS,ERRbadpath));
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG(3,("%s rmdir %s\n",timestring(),directory));
  
  return(outsize);
}


/*******************************************************************
resolve wildcards in a filename rename
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

  fstrcpy(name2,root2);
  if (ext2[0]) {
    fstrcat(name2,".");
    fstrcat(name2,ext2);
  }

  return(True);
}

/*******************************************************************
check if a user is allowed to rename a file
********************************************************************/
static BOOL can_rename(char *fname,int cnum)
{
  struct stat sbuf;

  if (!CAN_WRITE(cnum)) return(False);

  if (sys_lstat(fname,&sbuf) != 0) return(False);
  if (!check_file_sharing(cnum,fname,True)) return(False);

  return(True);
}

/****************************************************************************
  reply to a mv
****************************************************************************/
int reply_mv(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int outsize = 0;
  pstring name;
  int cnum;
  pstring directory;
  pstring mask,newname;
  pstring newname_last_component;
  char *p;
  int count=0;
  int error = ERRnoaccess;
  BOOL has_wild;
  BOOL exists=False;
  BOOL bad_path1 = False;
  BOOL bad_path2 = False;

  *directory = *mask = 0;

  cnum = SVAL(inbuf,smb_tid);
  
  pstrcpy(name,smb_buf(inbuf) + 1);
  pstrcpy(newname,smb_buf(inbuf) + 3 + strlen(name));
   
  DEBUG(3,("reply_mv : %s -> %s\n",name,newname));
   
  unix_convert(name,cnum,0,&bad_path1);
  unix_convert(newname,cnum,newname_last_component,&bad_path2);

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

  if (is_mangled(mask))
    check_mangled_stack(mask);

  has_wild = strchr(mask,'*') || strchr(mask,'?');

  if (!has_wild) {
    BOOL is_short_name = is_8_3(name, True);

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
  
    DEBUG(3,("reply_mv : case_sensitive = %d, case_preserve = %d, short case preserve = %d, directory = %s, newname = %s, newname_last_component = %s, is_8_3 = %d\n", 
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
    if((case_sensitive == False) && ( ((case_preserve == True) && (is_short_name == False)) || 
            ((short_case_preserve == True) && (is_short_name == True))) &&
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

    if (resolve_wildcards(directory,newname) && 
	can_rename(directory,cnum) && 
	!file_exist(newname,NULL) &&
	!sys_rename(directory,newname)) count++;

    DEBUG(3,("reply_mv : %s doing rename on %s -> %s\n",(count != 0) ? "succeeded" : "failed",
                         directory,newname));

    if (!count) exists = file_exist(directory,NULL);
    if (!count && exists && file_exist(newname,NULL)) {
      exists = True;
      error = 183;
    }
  } else {
    void *dirptr = NULL;
    char *dname;
    pstring destname;

    if (check_name(directory,cnum))
      dirptr = OpenDir(cnum, directory, True);

    if (dirptr)
      {
	error = ERRbadfile;

	if (strequal(mask,"????????.???"))
	  pstrcpy(mask,"*");

	while ((dname = ReadDirName(dirptr)))
	  {
	    pstring fname;
	    pstrcpy(fname,dname);
	    
	    if(!mask_match(fname, mask, case_sensitive, False)) continue;

	    error = ERRnoaccess;
	    slprintf(fname,sizeof(fname)-1,"%s/%s",directory,dname);
	    if (!can_rename(fname,cnum)) {
		    DEBUG(6,("rename %s refused\n", fname));
		    continue;
	    }
	    pstrcpy(destname,newname);

	    if (!resolve_wildcards(fname,destname)) {
		    DEBUG(6,("resolve_wildcards %s %s failed\n", 
			     fname, destname));
		    continue;
	    }

	    if (file_exist(destname,NULL)) {
		    DEBUG(6,("file_exist %s\n", 
			     destname));
		    error = 183;
		    continue;
	    }
	    if (!sys_rename(fname,destname)) count++;
	    DEBUG(3,("reply_mv : doing rename on %s -> %s\n",fname,destname));
	  }
	CloseDir(dirptr);
      }
  }
  
  if (count == 0) {
    if (exists)
      return(ERROR(ERRDOS,error));
    else
    {
      if((errno == ENOENT) && (bad_path1 || bad_path2))
      {
        unix_ERR_class = ERRDOS;
        unix_ERR_code = ERRbadpath;
      }
      return(UNIXERROR(ERRDOS,error));
    }
  }
  
  outsize = set_message(outbuf,0,0,True);
  
  return(outsize);
}

/*******************************************************************
  copy a file as part of a reply_copy
  ******************************************************************/
static BOOL copy_file(char *src,char *dest1,int cnum,int ofun,
		      int count,BOOL target_is_directory)
{
  int Access,action;
  struct stat st;
  int ret=0;
  int fnum1,fnum2;
  pstring dest;
  
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

  if (!file_exist(src,&st)) return(False);

  fnum1 = find_free_file();
  if (fnum1<0) return(False);
  open_file_shared(fnum1,cnum,src,(DENY_NONE<<4),
		   1,0,0,&Access,&action);

  if (!Files[fnum1].open) {
	  Files[fnum1].reserved = False;
	  return(False);
  }

  if (!target_is_directory && count)
    ofun = 1;

  fnum2 = find_free_file();
  if (fnum2<0) {
    close_file(fnum1,False);
    return(False);
  }
  open_file_shared(fnum2,cnum,dest,(DENY_NONE<<4)|1,
		   ofun,st.st_mode,0,&Access,&action);

  if (!Files[fnum2].open) {
    close_file(fnum1,False);
    Files[fnum2].reserved = False;
    return(False);
  }

  if ((ofun&3) == 1) {
    lseek(Files[fnum2].fd_ptr->fd,0,SEEK_END);
  }
  
  if (st.st_size)
    ret = transfer_file(Files[fnum1].fd_ptr->fd,Files[fnum2].fd_ptr->fd,st.st_size,NULL,0,0);

  close_file(fnum1,False);
  close_file(fnum2,False);

  return(ret == st.st_size);
}



/****************************************************************************
  reply to a file copy.
  ****************************************************************************/
int reply_copy(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int outsize = 0;
  pstring name;
  int cnum;
  pstring directory;
  pstring mask,newname;
  char *p;
  int count=0;
  int error = ERRnoaccess;
  BOOL has_wild;
  BOOL exists=False;
  int tid2 = SVAL(inbuf,smb_vwv0);
  int ofun = SVAL(inbuf,smb_vwv1);
  int flags = SVAL(inbuf,smb_vwv2);
  BOOL target_is_directory=False;
  BOOL bad_path1 = False;
  BOOL bad_path2 = False;

  *directory = *mask = 0;

  cnum = SVAL(inbuf,smb_tid);
  
  pstrcpy(name,smb_buf(inbuf));
  pstrcpy(newname,smb_buf(inbuf) + 1 + strlen(name));
   
  DEBUG(3,("reply_copy : %s -> %s\n",name,newname));
   
  if (tid2 != cnum) {
    /* can't currently handle inter share copies XXXX */
    DEBUG(3,("Rejecting inter-share copy\n"));
    return(ERROR(ERRSRV,ERRinvdevice));
  }

  unix_convert(name,cnum,0,&bad_path1);
  unix_convert(newname,cnum,0,&bad_path2);

  target_is_directory = directory_exist(newname,NULL);

  if ((flags&1) && target_is_directory) {
    return(ERROR(ERRDOS,ERRbadfile));
  }

  if ((flags&2) && !target_is_directory) {
    return(ERROR(ERRDOS,ERRbadpath));
  }

  if ((flags&(1<<5)) && directory_exist(name,NULL)) {
    /* wants a tree copy! XXXX */
    DEBUG(3,("Rejecting tree copy\n"));
    return(ERROR(ERRSRV,ERRerror));    
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

  if (is_mangled(mask))
    check_mangled_stack(mask);

  has_wild = strchr(mask,'*') || strchr(mask,'?');

  if (!has_wild) {
    pstrcat(directory,"/");
    pstrcat(directory,mask);
    if (resolve_wildcards(directory,newname) && 
	copy_file(directory,newname,cnum,ofun,
		  count,target_is_directory)) count++;
    if (!count) exists = file_exist(directory,NULL);
  } else {
    void *dirptr = NULL;
    char *dname;
    pstring destname;

    if (check_name(directory,cnum))
      dirptr = OpenDir(cnum, directory, True);

    if (dirptr)
      {
	error = ERRbadfile;

	if (strequal(mask,"????????.???"))
	  pstrcpy(mask,"*");

	while ((dname = ReadDirName(dirptr)))
	  {
	    pstring fname;
	    pstrcpy(fname,dname);
	    
	    if(!mask_match(fname, mask, case_sensitive, False)) continue;

	    error = ERRnoaccess;
	    slprintf(fname,sizeof(fname)-1, "%s/%s",directory,dname);
	    pstrcpy(destname,newname);
	    if (resolve_wildcards(fname,destname) && 
		copy_file(directory,newname,cnum,ofun,
			  count,target_is_directory)) count++;
	    DEBUG(3,("reply_copy : doing copy on %s -> %s\n",fname,destname));
	  }
	CloseDir(dirptr);
      }
  }
  
  if (count == 0) {
    if (exists)
      return(ERROR(ERRDOS,error));
    else
    {
      if((errno == ENOENT) && (bad_path1 || bad_path2))
      {
        unix_ERR_class = ERRDOS;
        unix_ERR_code = ERRbadpath;
      }
      return(UNIXERROR(ERRDOS,error));
    }
  }
  
  outsize = set_message(outbuf,1,0,True);
  SSVAL(outbuf,smb_vwv0,count);

  return(outsize);
}



/****************************************************************************
  reply to a setdir
****************************************************************************/
int reply_setdir(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum,snum;
  int outsize = 0;
  BOOL ok = False;
  pstring newdir;
  
  cnum = SVAL(inbuf,smb_tid);
  
  snum = Connections[cnum].service;
  if (!CAN_SETDIR(snum))
    return(ERROR(ERRDOS,ERRnoaccess));
  
  pstrcpy(newdir,smb_buf(inbuf) + 1);
  strlower(newdir);
  
  if (strlen(newdir) == 0)
    ok = True;
  else
    {
      ok = directory_exist(newdir,NULL);
      if (ok)
	string_set(&Connections[cnum].connectpath,newdir);
    }
  
  if (!ok)
    return(ERROR(ERRDOS,ERRbadpath));
  
  outsize = set_message(outbuf,0,0,True);
  CVAL(outbuf,smb_reh) = CVAL(inbuf,smb_reh);
  
  DEBUG(3,("%s setdir %s cnum=%d\n",timestring(),newdir,cnum));
  
  return(outsize);
}


/****************************************************************************
  reply to a lockingX request
****************************************************************************/
int reply_lockingX(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum = GETFNUM(inbuf,smb_vwv2);
  unsigned char locktype = CVAL(inbuf,smb_vwv3);
#if 0
  unsigned char oplocklevel = CVAL(inbuf,smb_vwv3+1);
#endif
  uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
  uint16 num_locks = SVAL(inbuf,smb_vwv7);
  uint32 count, offset;

  int cnum;
  int i;
  char *data;
  uint32 ecode=0, dummy2;
  int eclass=0, dummy1;

  cnum = SVAL(inbuf,smb_tid);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  data = smb_buf(inbuf);

  /* Check if this is an oplock break on a file
     we have granted an oplock on.
   */
  if ((locktype & LOCKING_ANDX_OPLOCK_RELEASE))
  {
    int token;
    files_struct *fsp = &Files[fnum];
    uint32 dev = fsp->fd_ptr->dev;
    uint32 inode = fsp->fd_ptr->inode;

    DEBUG(5,("reply_lockingX: oplock break reply from client for fnum = %d\n",
              fnum));
    /*
     * Make sure we have granted an oplock on this file.
     */
    if(!fsp->granted_oplock)
    {
      DEBUG(0,("reply_lockingX: Error : oplock break from client for fnum = %d and \
no oplock granted on this file.\n", fnum));
      return ERROR(ERRDOS,ERRlock);
    }

    /* Remove the oplock flag from the sharemode. */
    lock_share_entry(fsp->cnum, dev, inode, &token);
    if(remove_share_oplock( fnum, token)==False) {
	    DEBUG(0,("reply_lockingX: failed to remove share oplock for fnum %d, \
dev = %x, inode = %x\n", 
		     fnum, dev, inode));
	    unlock_share_entry(fsp->cnum, dev, inode, token);
    } else {
	    unlock_share_entry(fsp->cnum, dev, inode, token);

	    /* Clear the granted flag and return. */
	    fsp->granted_oplock = False;
    }

    /* if this is a pure oplock break request then don't send a reply */
    if (num_locks == 0 && num_ulocks == 0)
    {
      /* Sanity check - ensure a pure oplock break is not a
         chained request. */
      if(CVAL(inbuf,smb_vwv0) != 0xff)
        DEBUG(0,("reply_lockingX: Error : pure oplock break is a chained %d request !\n",
                 (unsigned int)CVAL(inbuf,smb_vwv0) ));
      return -1;
    }
  }

  /* Data now points at the beginning of the list
     of smb_unlkrng structs */
  for(i = 0; i < (int)num_ulocks; i++) {
    count = IVAL(data,SMB_LKLEN_OFFSET(i));
    offset = IVAL(data,SMB_LKOFF_OFFSET(i));
    if(!do_unlock(fnum,cnum,count,offset,&eclass, &ecode))
      return ERROR(eclass,ecode);
  }

  /* Now do any requested locks */
  data += 10*num_ulocks;
  /* Data now points at the beginning of the list
     of smb_lkrng structs */
  for(i = 0; i < (int)num_locks; i++) {
    count = IVAL(data,SMB_LKLEN_OFFSET(i)); 
    offset = IVAL(data,SMB_LKOFF_OFFSET(i)); 
    if(!do_lock(fnum,cnum,count,offset, &eclass, &ecode))
      break;
  }

  /* If any of the above locks failed, then we must unlock
     all of the previous locks (X/Open spec). */
  if(i != num_locks && num_locks != 0) {
    for(; i >= 0; i--) {
      count = IVAL(data,SMB_LKLEN_OFFSET(i));  
      offset = IVAL(data,SMB_LKOFF_OFFSET(i)); 
      do_unlock(fnum,cnum,count,offset,&dummy1,&dummy2);
    }
    return ERROR(eclass,ecode);
  }

  set_message(outbuf,2,0,True);
  
  DEBUG(3,("%s lockingX fnum=%d cnum=%d type=%d num_locks=%d num_ulocks=%d\n",
	timestring(),fnum,cnum,(unsigned int)locktype,num_locks,num_ulocks));

  chain_fnum = fnum;

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a SMBreadbmpx (read block multiplex) request
****************************************************************************/
int reply_readbmpx(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum,fnum;
  int nread = -1;
  int total_read;
  char *data;
  uint32 startpos;
  int outsize, mincount, maxcount;
  int max_per_packet;
  int tcount;
  int pad;

  /* this function doesn't seem to work - disable by default */
  if (!lp_readbmpx())
    return(ERROR(ERRSRV,ERRuseSTD));

  outsize = set_message(outbuf,8,0,True);

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);

  startpos = IVAL(inbuf,smb_vwv1);
  maxcount = SVAL(inbuf,smb_vwv3);
  mincount = SVAL(inbuf,smb_vwv4);

  data = smb_buf(outbuf);
  pad = ((long)data)%4;
  if (pad) pad = 4 - pad;
  data += pad;

  max_per_packet = bufsize-(outsize+pad);
  tcount = maxcount;
  total_read = 0;

  if (is_locked(fnum,cnum,maxcount,startpos))
    return(ERROR(ERRDOS,ERRlock));
	
  do
    {
      int N = MIN(max_per_packet,tcount-total_read);
  
      nread = read_file(fnum,data,startpos,N);

      if (nread <= 0) nread = 0;

      if (nread < N)
	tcount = total_read + nread;

      set_message(outbuf,8,nread,False);
      SIVAL(outbuf,smb_vwv0,startpos);
      SSVAL(outbuf,smb_vwv2,tcount);
      SSVAL(outbuf,smb_vwv6,nread);
      SSVAL(outbuf,smb_vwv7,smb_offset(data,outbuf));

      send_smb(Client,outbuf);

      total_read += nread;
      startpos += nread;
    }
  while (total_read < tcount);

  return(-1);
}


/****************************************************************************
  reply to a SMBwritebmpx (write block multiplex primary) request
****************************************************************************/
int reply_writebmpx(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum,numtowrite,fnum;
  int nwritten = -1;
  int outsize = 0;
  uint32 startpos;
  int tcount, write_through, smb_doff;
  char *data;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  tcount = SVAL(inbuf,smb_vwv1);
  startpos = IVAL(inbuf,smb_vwv3);
  write_through = BITSETW(inbuf+smb_vwv7,0);
  numtowrite = SVAL(inbuf,smb_vwv10);
  smb_doff = SVAL(inbuf,smb_vwv11);

  data = smb_base(inbuf) + smb_doff;

  /* If this fails we need to send an SMBwriteC response,
     not an SMBwritebmpx - set this up now so we don't forget */
  CVAL(outbuf,smb_com) = SMBwritec;

  if (is_locked(fnum,cnum,tcount,startpos))
    return(ERROR(ERRDOS,ERRlock));

  seek_file(fnum,startpos);
  nwritten = write_file(fnum,data,numtowrite);

  if(lp_syncalways(SNUM(cnum)) || write_through)
    sync_file(fnum);
  
  if(nwritten < numtowrite)
    return(UNIXERROR(ERRHRD,ERRdiskfull));

  /* If the maximum to be written to this file
     is greater than what we just wrote then set
     up a secondary struct to be attached to this
     fd, we will use this to cache error messages etc. */
  if(tcount > nwritten) 
    {
      write_bmpx_struct *wbms;
      if(Files[fnum].wbmpx_ptr != NULL)
	wbms = Files[fnum].wbmpx_ptr; /* Use an existing struct */
      else
	wbms = (write_bmpx_struct *)malloc(sizeof(write_bmpx_struct));
      if(!wbms)
	{
	  DEBUG(0,("Out of memory in reply_readmpx\n"));
	  return(ERROR(ERRSRV,ERRnoresource));
	}
      wbms->wr_mode = write_through;
      wbms->wr_discard = False; /* No errors yet */
      wbms->wr_total_written = nwritten;
      wbms->wr_errclass = 0;
      wbms->wr_error = 0;
      Files[fnum].wbmpx_ptr = wbms;
    }

  /* We are returning successfully, set the message type back to
     SMBwritebmpx */
  CVAL(outbuf,smb_com) = SMBwriteBmpx;
  
  outsize = set_message(outbuf,1,0,True);
  
  SSVALS(outbuf,smb_vwv0,-1); /* We don't support smb_remaining */
  
  DEBUG(3,("%s writebmpx fnum=%d cnum=%d num=%d wrote=%d\n",
	timestring(),fnum,cnum,numtowrite,nwritten));
  
  if (write_through && tcount==nwritten) {
    /* we need to send both a primary and a secondary response */
    smb_setlen(outbuf,outsize - 4);
    send_smb(Client,outbuf);

    /* now the secondary */
    outsize = set_message(outbuf,1,0,True);
    CVAL(outbuf,smb_com) = SMBwritec;
    SSVAL(outbuf,smb_vwv0,nwritten);
  }

  return(outsize);
}


/****************************************************************************
  reply to a SMBwritebs (write block multiplex secondary) request
****************************************************************************/
int reply_writebs(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum,numtowrite,fnum;
  int nwritten = -1;
  int outsize = 0;
  int32 startpos;
  int tcount, write_through, smb_doff;
  char *data;
  write_bmpx_struct *wbms;
  BOOL send_response = False;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);
  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);

  tcount = SVAL(inbuf,smb_vwv1);
  startpos = IVAL(inbuf,smb_vwv2);
  numtowrite = SVAL(inbuf,smb_vwv6);
  smb_doff = SVAL(inbuf,smb_vwv7);

  data = smb_base(inbuf) + smb_doff;

  /* We need to send an SMBwriteC response, not an SMBwritebs */
  CVAL(outbuf,smb_com) = SMBwritec;

  /* This fd should have an auxiliary struct attached,
     check that it does */
  wbms = Files[fnum].wbmpx_ptr;
  if(!wbms) return(-1);

  /* If write through is set we can return errors, else we must
     cache them */
  write_through = wbms->wr_mode;

  /* Check for an earlier error */
  if(wbms->wr_discard)
    return -1; /* Just discard the packet */

  seek_file(fnum,startpos);
  nwritten = write_file(fnum,data,numtowrite);

  if(lp_syncalways(SNUM(cnum)) || write_through)
    sync_file(fnum);
  
  if (nwritten < numtowrite)
    {
      if(write_through)	{
	/* We are returning an error - we can delete the aux struct */
	if (wbms) free((char *)wbms);
	Files[fnum].wbmpx_ptr = NULL;
	return(ERROR(ERRHRD,ERRdiskfull));
      }
      return(CACHE_ERROR(wbms,ERRHRD,ERRdiskfull));
    }

  /* Increment the total written, if this matches tcount
     we can discard the auxiliary struct (hurrah !) and return a writeC */
  wbms->wr_total_written += nwritten;
  if(wbms->wr_total_written >= tcount)
    {
      if (write_through) {
	outsize = set_message(outbuf,1,0,True);
	SSVAL(outbuf,smb_vwv0,wbms->wr_total_written);    
	send_response = True;
      }

      free((char *)wbms);
      Files[fnum].wbmpx_ptr = NULL;
    }

  if(send_response)
    return(outsize);

  return(-1);
}


/****************************************************************************
  reply to a SMBsetattrE
****************************************************************************/
int reply_setattrE(char *inbuf,char *outbuf,int dum_size, int dum_buffsize)
{
  int cnum,fnum;
  struct utimbuf unix_times;
  int outsize = 0;

  outsize = set_message(outbuf,0,0,True);

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  /* Convert the DOS times into unix times. Ignore create
     time as UNIX can't set this.
     */
  unix_times.actime = make_unix_date2(inbuf+smb_vwv3);
  unix_times.modtime = make_unix_date2(inbuf+smb_vwv5);
  
  /* 
   * Patch from Ray Frush <frush@engr.colostate.edu>
   * Sometimes times are sent as zero - ignore them.
   */

  if ((unix_times.actime == 0) && (unix_times.modtime == 0)) 
  {
    /* Ignore request */
    DEBUG(3,("%s reply_setattrE fnum=%d cnum=%d ignoring zero request - \
not setting timestamps of 0\n",
          timestring(), fnum,cnum,unix_times.actime,unix_times.modtime));
    return(outsize);
  }
  else if ((unix_times.actime != 0) && (unix_times.modtime == 0)) 
  {
    /* set modify time = to access time if modify time was 0 */
    unix_times.modtime = unix_times.actime;
  }

  /* Set the date on this file */
  if(file_utime(cnum, Files[fnum].name, &unix_times))
    return(ERROR(ERRDOS,ERRnoaccess));
  
  DEBUG(3,("%s reply_setattrE fnum=%d cnum=%d actime=%d modtime=%d\n",
    timestring(), fnum,cnum,unix_times.actime,unix_times.modtime));

  return(outsize);
}


/****************************************************************************
  reply to a SMBgetattrE
****************************************************************************/
int reply_getattrE(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int cnum,fnum;
  struct stat sbuf;
  int outsize = 0;
  int mode;

  outsize = set_message(outbuf,11,0,True);

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  /* Do an fstat on this file */
  if(fstat(Files[fnum].fd_ptr->fd, &sbuf))
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  mode = dos_mode(cnum,Files[fnum].name,&sbuf);
  
  /* Convert the times into dos times. Set create
     date to be last modify date as UNIX doesn't save
     this */
  put_dos_date2(outbuf,smb_vwv0,get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(cnum))));
  put_dos_date2(outbuf,smb_vwv2,sbuf.st_atime);
  put_dos_date2(outbuf,smb_vwv4,sbuf.st_mtime);
  if (mode & aDIR)
    {
      SIVAL(outbuf,smb_vwv6,0);
      SIVAL(outbuf,smb_vwv8,0);
    }
  else
    {
      SIVAL(outbuf,smb_vwv6,sbuf.st_size);
      SIVAL(outbuf,smb_vwv8,ROUNDUP(sbuf.st_size,1024));
    }
  SSVAL(outbuf,smb_vwv10, mode);
  
  DEBUG(3,("%s reply_getattrE fnum=%d cnum=%d\n",timestring(),fnum,cnum));
  
  return(outsize);
}
