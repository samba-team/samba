/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
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

#include "includes.h"

#if (defined(NETGROUP) && defined (AUTOMOUNT))
#include "rpcsvc/ypclnt.h"
#endif

extern int DEBUGLEVEL;
extern int Protocol;

/* users from session setup */
static pstring session_users="";

/* these are kept here to keep the string_combinations function simple */
static char this_user[100]="";
static char this_salt[100]="";
static char this_crypted[100]="";

/* Data to do lanman1/2 password challenge. */
static unsigned char saved_challenge[8];
static BOOL challenge_sent=False;

/*******************************************************************
Get the next challenge value - no repeats.
********************************************************************/
void generate_next_challenge(char *challenge)
{
	unsigned char buf[16];
	static int counter = 0;
	struct timeval tval;
	int v1,v2;

	/* get a sort-of random number */
	GetTimeOfDay(&tval);
	v1 = (counter++) + getpid() + tval.tv_sec;
	v2 = (counter++) * getpid() + tval.tv_usec;
	SIVAL(challenge,0,v1);
	SIVAL(challenge,4,v2);

	/* mash it up with md4 */
	mdfour(buf, (unsigned char *)challenge, 8);

	memcpy(saved_challenge, buf, 8);
	memcpy(challenge,buf,8);
	challenge_sent = True;
}

/*******************************************************************
set the last challenge sent, usually from a password server
********************************************************************/
BOOL set_challenge(char *challenge)
{
  memcpy(saved_challenge,challenge,8);
  challenge_sent = True;
  return(True);
}

/*******************************************************************
get the last challenge sent
********************************************************************/
BOOL last_challenge(char *challenge)
{
  if (!challenge_sent) return(False);
  memcpy(challenge,saved_challenge,8);
  return(True);
}

/* this holds info on user ids that are already validated for this VC */
static user_struct *validated_users = NULL;
static int num_validated_users = 0;

/****************************************************************************
check if a uid has been validated, and return an pointer to the user_struct
if it has. NULL if not. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
user_struct *get_valid_user_struct(uint16 vuid)
{
  if (vuid == UID_FIELD_INVALID)
    return NULL;
  vuid -= VUID_OFFSET;
  if ((vuid >= (uint16)num_validated_users) || 
     (validated_users[vuid].uid == -1) || (validated_users[vuid].gid == -1))
    return NULL;
  return &validated_users[vuid];
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void invalidate_vuid(uint16 vuid)
{
  user_struct *vuser = get_valid_user_struct(vuid);

  if (vuser == NULL) return;

  vuser->uid = -1;
  vuser->gid = -1;

  vuser->n_sids = 0;

  /* same number of igroups as groups as attrs */
  vuser->n_groups = 0;

  if (vuser->groups && (vuser->groups != (gid_t *)vuser->igroups))
       free(vuser->groups);

  if (vuser->igroups) free(vuser->igroups);
  if (vuser->attrs  ) free(vuser->attrs);
  if (vuser->sids   ) free(vuser->sids);

  vuser->attrs   = NULL;
  vuser->sids    = NULL;
  vuser->igroups = NULL;
  vuser->groups  = NULL;
}


/****************************************************************************
return a validated username
****************************************************************************/
char *validated_username(uint16 vuid)
{
  user_struct *vuser = get_valid_user_struct(vuid);
  if (vuser == NULL)
    return 0;
  return(vuser->name);
}

/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
uint16 register_vuid(int uid,int gid, char *unix_name, char *requested_name, BOOL guest)
{
  user_struct *vuser;
  struct passwd *pwfile; /* for getting real name from passwd file */

  /* Ensure no vuid gets registered in share level security. */
  if(lp_security() == SEC_SHARE)
    return UID_FIELD_INVALID;

#if 0
  /*
   * After observing MS-Exchange services writing to a Samba share
   * I belive this code is incorrect. Each service does its own
   * sessionsetup_and_X for the same user, and as each service shuts
   * down, it does a user_logoff_and_X. As we are consolidating multiple
   * sessionsetup_and_X's onto the same vuid here, when the first service
   * shuts down, it invalidates all the open files for the other services.
   * Hence I am removing this code and forcing each sessionsetup_and_X
   * to get a new vuid.
   * Jeremy Allison. (jallison@whistle.com).
   */

  int i;
  for(i = 0; i < num_validated_users; i++) {
    vuser = &validated_users[i];
    if ( vuser->uid == uid )
      return (uint16)(i + VUID_OFFSET); /* User already validated */
  }
#endif

  validated_users = (user_struct *)Realloc(validated_users,
			   sizeof(user_struct)*
			   (num_validated_users+1));
  
  if (!validated_users)
    {
      DEBUG(0,("Failed to realloc users struct!\n"));
      num_validated_users = 0;
      return UID_FIELD_INVALID;
    }

  vuser = &validated_users[num_validated_users];
  num_validated_users++;

  vuser->uid = uid;
  vuser->gid = gid;
  vuser->guest = guest;
  fstrcpy(vuser->name,unix_name);
  fstrcpy(vuser->requested_name,requested_name);

  vuser->n_sids = 0;
  vuser->sids   = NULL;

  vuser->n_groups = 0;
  vuser->groups  = NULL;
  vuser->igroups = NULL;
  vuser->attrs    = NULL;

  /* Find all the groups this uid is in and store them. 
     Used by become_user() */
  setup_groups(unix_name,uid,gid,
	       &vuser->n_groups,
	       &vuser->igroups,
	       &vuser->groups,
	       &vuser->attrs);

  DEBUG(3,("uid %d registered to name %s\n",uid,unix_name));

  DEBUG(3, ("Clearing default real name\n"));
  fstrcpy(vuser->real_name, "<Full Name>\0");
  if (lp_unix_realname()) {
    if ((pwfile=getpwnam(vuser->name))!= NULL)
      {
      DEBUG(3, ("User name: %s\tReal name: %s\n",vuser->name,pwfile->pw_gecos));
      fstrcpy(vuser->real_name, pwfile->pw_gecos);
      }
  }

  return (uint16)((num_validated_users - 1) + VUID_OFFSET);
}


/****************************************************************************
add a name to the session users list
****************************************************************************/
void add_session_user(char *user)
{
  fstring suser;
  StrnCpy(suser,user,sizeof(suser)-1);

  if (!Get_Pwnam(suser,True)) return;

  if (suser && *suser && !in_list(suser,session_users,False))
    {
      if (strlen(suser) + strlen(session_users) + 2 >= sizeof(pstring))
	DEBUG(1,("Too many session users??\n"));
      else
	{
	  pstrcat(session_users," ");
	  pstrcat(session_users,suser);
	}
    }
}


#ifdef NO_GETSPNAM
/* a fake shadow password routine which just fills a fake spwd struct
 * with the sp_pwdp field. (sreiz@aie.nl)
 */
static struct spwd *getspnam(char *username) /* fake shadow password routine */
{
       FILE *f;
       char line[1024];
       static char pw[20];
       static struct spwd static_spwd;

       static_spwd.sp_pwdp=0;
       if (!(f=fopen("/etc/master.passwd", "r")))
               return 0;
       while (fgets(line, 1024, f)) {
               if (!strncmp(line, username, strlen(username)) &&
                line[strlen(username)]==':') { /* found entry */
                       char *p, *q;

                       p=line+strlen(username)+1;
                       if ((q=strchr(p, ':'))) {
                               *q=0;
                               if (q-p+1>20)
                                       break;
                               safe_strcpy(pw, p, sizeof(pw)-1);
                               static_spwd.sp_pwdp=pw;
                       }
                       break;
               }
       }
       fclose(f);
       if (static_spwd.sp_pwdp)
               return &static_spwd;
       return 0;
}
#endif


#ifdef OSF1_ENH_SEC
/****************************************************************************
an enhanced crypt for OSF1
****************************************************************************/
static char *osf1_bigcrypt(char *password,char *salt1)
{
  static char result[AUTH_MAX_PASSWD_LENGTH] = "";
  char *p1;
  char *p2=password;
  char salt[3];
  int i;
  int parts = strlen(password) / AUTH_CLEARTEXT_SEG_CHARS;
  if (strlen(password)%AUTH_CLEARTEXT_SEG_CHARS)
    parts++;

  StrnCpy(salt,salt1,2);
  StrnCpy(result,salt1,2);

  for (i=0; i<parts;i++)
    {
      p1 = crypt(p2,salt);
      safe_strcat(result,p1+2,sizeof(result)-1);
      StrnCpy(salt,&result[2+i*AUTH_CIPHERTEXT_SEG_CHARS],2);
      p2 += AUTH_CLEARTEXT_SEG_CHARS;
    }

  return(result);
}
#endif

/****************************************************************************
update the encrypted smbpasswd file from the plaintext username and password
*****************************************************************************/
BOOL update_smbpassword_file( struct passwd *pass, fstring password)
{
  struct smb_passwd smbpw;
  BOOL ret;

  /* Fake up an smb_passwd. */
  smbpw.smb_userid = pass->pw_uid;
  smbpw.smb_name = pass->pw_name;
  smbpw.smb_passwd = NULL;
  smbpw.smb_nt_passwd = NULL;
  smbpw.acct_ctrl = ACB_NORMAL;

  /* Here, the flag is one, because we want to ignore the XXXXXXX'd out password */
  ret = change_oem_password( &smbpw, password, 1);
  if (ret == False)
    DEBUG(3,("update_smbpasswd_entry: change_oem_password returned False\n"));
 
  return ret;
}

/****************************************************************************
update the enhanced security database. Only relevant for OSF1 at the moment.
****************************************************************************/
static void update_protected_database( char *user, BOOL result)
{
#ifdef OSF1_ENH_SEC
  struct pr_passwd *mypasswd;
  time_t starttime;

  mypasswd = getprpwnam (user);
  starttime = time (NULL);

  if (result)
    {
      mypasswd->ufld.fd_slogin = starttime;
      mypasswd->ufld.fd_nlogins = 0;
      
      putprpwnam(user,mypasswd);
      
      DEBUG(3,("Update protected database for Account %s after succesful connection\n",user));
    }
  else
    {
      mypasswd->ufld.fd_ulogin = starttime;
      mypasswd->ufld.fd_nlogins = mypasswd->ufld.fd_nlogins + 1;
      if ( mypasswd->ufld.fd_max_tries != 0 && mypasswd->ufld.fd_nlogins > mypasswd->ufld.fd_max_tries )
	{
	  mypasswd->uflg.fg_lock = 0;
	  DEBUG(3,("Account is disabled -- see Account Administrator.\n"));
	}
      putprpwnam ( user , mypasswd );
      DEBUG(3,("Update protected database for Account %s after refusing connection\n",user));
    }
#else
  DEBUG(6,("Updated database with %s %s\n",user,BOOLSTR(result)));
#endif
}


#ifdef USE_PAM
/*******************************************************************
check on PAM authentication
********************************************************************/

/* We first need some helper functions */
#include <security/pam_appl.h>
/* Static variables used to communicate between the conversation function
 * and the server_login function
 */
static char *PAM_username;
static char *PAM_password;

/* PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */
static int PAM_conv (int num_msg,
                     const struct pam_message **msg,
                     struct pam_response **resp,
                     void *appdata_ptr) {
  int replies = 0;
  struct pam_response *reply = NULL;

  #define COPY_STRING(s) (s) ? strdup(s) : NULL

  reply = malloc(sizeof(struct pam_response) * num_msg);
  if (!reply) return PAM_CONV_ERR;

  for (replies = 0; replies < num_msg; replies++) {
    switch (msg[replies]->msg_style) {
      case PAM_PROMPT_ECHO_ON:
        reply[replies].resp_retcode = PAM_SUCCESS;
        reply[replies].resp = COPY_STRING(PAM_username);
          /* PAM frees resp */
        break;
      case PAM_PROMPT_ECHO_OFF:
        reply[replies].resp_retcode = PAM_SUCCESS;
        reply[replies].resp = COPY_STRING(PAM_password);
          /* PAM frees resp */
        break;
      case PAM_TEXT_INFO:
	/* fall through */
      case PAM_ERROR_MSG:
        /* ignore it... */
        reply[replies].resp_retcode = PAM_SUCCESS;
        reply[replies].resp = NULL;
        break;
      default:
        /* Must be an error of some sort... */
        free (reply);
        return PAM_CONV_ERR;
    }
  }
  if (reply) *resp = reply;
  return PAM_SUCCESS;
}
static struct pam_conv PAM_conversation = {
    &PAM_conv,
    NULL
};


static BOOL pam_auth(char *this_user,char *password)
{
  pam_handle_t *pamh;
  int pam_error;

  /* Now use PAM to do authentication.  For now, we won't worry about
   * session logging, only authentication.  Bail out if there are any
   * errors.  Since this is a limited protocol, and an even more limited
   * function within a server speaking this protocol, we can't be as
   * verbose as would otherwise make sense.
   * Query: should we be using PAM_SILENT to shut PAM up?
   */
  #define PAM_BAIL if (pam_error != PAM_SUCCESS) { \
     pam_end(pamh, 0); return False; \
   }
  PAM_password = password;
  PAM_username = this_user;
  pam_error = pam_start("samba", this_user, &PAM_conversation, &pamh);
  PAM_BAIL;
/* Setting PAM_SILENT stops generation of error messages to syslog
 * to enable debugging on Red Hat Linux set:
 * /etc/pam.d/samba:
 *	auth required /lib/security/pam_pwdb.so nullok shadow audit
 * _OR_ change PAM_SILENT to 0 to force detailed reporting (logging)
 */
  pam_error = pam_authenticate(pamh, PAM_SILENT);
  PAM_BAIL;
  /* It is not clear to me that account management is the right thing
   * to do, but it is not clear that it isn't, either.  This can be
   * removed if no account management should be done.  Alternately,
   * put a pam_allow.so entry in /etc/pam.conf for account handling. */
  pam_error = pam_acct_mgmt(pamh, PAM_SILENT);
  PAM_BAIL;
  pam_end(pamh, PAM_SUCCESS);
  /* If this point is reached, the user has been authenticated. */
  return(True);
}
#endif


#ifdef AFS_AUTH
/*******************************************************************
check on AFS authentication
********************************************************************/
static BOOL afs_auth(char *this_user,char *password)
{
  long password_expires = 0;
  char *reason;
    
  /* For versions of AFS prior to 3.3, this routine has few arguments, */
  /* but since I can't find the old documentation... :-)               */
  setpag();
  if (ka_UserAuthenticateGeneral(KA_USERAUTH_VERSION+KA_USERAUTH_DOSETPAG,
				 this_user,
				 (char *) 0, /* instance */
				 (char *) 0, /* cell */
				 password,
				 0,          /* lifetime, default */
				 &password_expires, /*days 'til it expires */
				 0,          /* spare 2 */
				 &reason) == 0)
    return(True);
  return(False);
}
#endif


#ifdef DFS_AUTH

sec_login_handle_t my_dce_sec_context;
int dcelogin_atmost_once = 0;

/*******************************************************************
check on a DCE/DFS authentication
********************************************************************/
static BOOL dfs_auth(char *this_user,char *password)
{
  error_status_t err;
  int err2;
  int prterr;
  boolean32 password_reset;
  sec_passwd_rec_t my_dce_password;
  sec_login_auth_src_t auth_src = sec_login_auth_src_network;
  unsigned char dce_errstr[dce_c_error_string_len];

  /*
   * We only go for a DCE login context if the given password
   * matches that stored in the local password file.. 
   * Assumes local passwd file is kept in sync w/ DCE RGY!
   */

  /* Fix for original (broken) code from Brett Wooldridge <brettw@austin.ibm.com> */
  if (dcelogin_atmost_once)
    return (False);
  /* This can be ifdefed as the DCE check below is stricter... */
#ifndef NO_CRYPT
  if ( strcmp((char *)crypt(password,this_salt),this_crypted) )
    return (False);
#endif

  if (sec_login_setup_identity(
			       (unsigned char *)this_user,
			       sec_login_no_flags,
			       &my_dce_sec_context,
			       &err) == 0)
    {
      dce_error_inq_text(err, dce_errstr, &err2);
      DEBUG(0,("DCE Setup Identity for %s failed: %s\n",
	       this_user,dce_errstr));
      return(False);
    }

  my_dce_password.version_number = sec_passwd_c_version_none;
  my_dce_password.pepper = NULL; 
  my_dce_password.key.key_type = sec_passwd_plain;
  my_dce_password.key.tagged_union.plain  = (idl_char *)password;
  
  if (sec_login_valid_and_cert_ident(my_dce_sec_context,
				     &my_dce_password,
				     &password_reset,
				     &auth_src,
				     &err) == 0 )
    { 
      dce_error_inq_text(err, dce_errstr, &err2);
      DEBUG(0,("DCE Identity Validation failed for principal %s: %s\n",
	       this_user,dce_errstr));
	  
      return(False);
    }

  sec_login_set_context(my_dce_sec_context, &err);
  if (err != error_status_ok )
    {  
      dce_error_inq_text(err, dce_errstr, &err2);
      DEBUG(0,("DCE login failed for principal %s, cant set context: %s\n",
	       this_user,dce_errstr));
      sec_login_purge_context(my_dce_sec_context, &err);
      return(False);
    }
  else
    {
      DEBUG(0,("DCE login succeeded for principal %s on pid %d\n",
	       this_user, getpid()));
    }

  dcelogin_atmost_once = 1;
  return (True);
}

void dfs_unlogin(void)
{
  error_status_t err;
  int err2;
  unsigned char dce_errstr[dce_c_error_string_len];

  sec_login_purge_context(my_dce_sec_context, &err);
  if (err != error_status_ok )
    {  
      dce_error_inq_text(err, dce_errstr, &err2);
      DEBUG(0,("DCE purge login context failed for server instance %d: %s\n",
	       getpid(), dce_errstr));
    }
}

#endif

#ifdef KRB5_AUTH
/*******************************************************************
check on Kerberos authentication
********************************************************************/
static BOOL krb5_auth(char *this_user,char *password)
{
	krb5_data tgtname = {
		0,
		KRB5_TGS_NAME_SIZE,
	 	KRB5_TGS_NAME
 	};
	krb5_context kcontext;
	krb5_principal kprinc;
	krb5_principal server;
	krb5_creds kcreds;
	int options = 0;
	krb5_address **addrs = (krb5_address **)0;
	krb5_preauthtype *preauth = NULL;
	krb5_keytab keytab = NULL;
	krb5_timestamp now;
	krb5_ccache ccache = NULL;
	int retval;
	char *name;

	if ( retval=krb5_init_context(&kcontext))
	{
		return(False);
	}

	if ( retval = krb5_timeofday(kcontext, &now) )
	{
		return(False);
	}

	if ( retval = krb5_cc_default(kcontext, &ccache) )
	{
		return(False);
	}
	
	if ( retval = krb5_parse_name(kcontext, this_user, &kprinc) )
	{
		return(False);
	}

	memset((char *)&kcreds, 0, sizeof(kcreds));

	kcreds.client = kprinc;
	
	if ((retval = krb5_build_principal_ext(kcontext, &server,
		krb5_princ_realm(kcontext, kprinc)->length,
		krb5_princ_realm(kcontext, kprinc)->data,
		tgtname.length,
		tgtname.data,
		krb5_princ_realm(kcontext, kprinc)->length,
		krb5_princ_realm(kcontext, kprinc)->data,
		0)))
	{
 		return(False);
	}

	kcreds.server = server;

	retval = krb5_get_in_tkt_with_password(kcontext,
		options,
		addrs,
		NULL,
		preauth,
		password,
		0,
		&kcreds,
		0);

	if ( retval )
	{
		return(False);
	}

	return(True);
}
#endif /* KRB5_AUTH */

#ifdef KRB4_AUTH
/*******************************************************************
check on Kerberos authentication
********************************************************************/
static BOOL krb4_auth(char *this_user,char *password)
{
  char realm[REALM_SZ];
  char tkfile[MAXPATHLEN];
  
  if (krb_get_lrealm(realm, 1) != KSUCCESS)
    (void) strncpy(realm, KRB_REALM, sizeof (realm));
  
  (void) slprintf(tkfile, sizeof(tkfile)-1, "/tmp/samba_tkt_%d", getpid());
  
  krb_set_tkt_string(tkfile);
  if (krb_verify_user(this_user, "", realm,
                     password, 0,
                     "rmcd") == KSUCCESS) {
    unlink(tkfile);
    return 1;
  }
  unlink(tkfile);
  return 0;
}
#endif /* KRB4_AUTH */

#ifdef LINUX_BIGCRYPT
/****************************************************************************
an enhanced crypt for Linux to handle password longer than 8 characters
****************************************************************************/
static int linux_bigcrypt(char *password,char *salt1, char *crypted)
{
#define LINUX_PASSWORD_SEG_CHARS 8
  char salt[3];
  int i;
  
  StrnCpy(salt,salt1,2);
  crypted +=2;
  
  for ( i=strlen(password); i > 0; i -= LINUX_PASSWORD_SEG_CHARS) {
    char * p = crypt(password,salt) + 2;
    if (strncmp(p, crypted, LINUX_PASSWORD_SEG_CHARS) != 0)
      return(0);
    password += LINUX_PASSWORD_SEG_CHARS;
    crypted  += strlen(p);
  }
  
  return(1);
}
#endif


/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static BOOL string_combinations2(char *s,int offset,BOOL (*fn)(char *),int N)
{
  int len = strlen(s);
  int i;

#ifdef PASSWORD_LENGTH
  len = MIN(len,PASSWORD_LENGTH);
#endif

  if (N <= 0 || offset >= len)
    return(fn(s));

  for (i=offset;i<(len-(N-1));i++)
    {      
      char c = s[i];
      if (!islower(c)) continue;
      s[i] = toupper(c);
      if (string_combinations2(s,i+1,fn,N-1))
	return(True);
      s[i] = c;
    }
  return(False);
}

/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with up to N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static BOOL string_combinations(char *s,BOOL (*fn)(char *),int N)
{
  int n;
  for (n=1;n<=N;n++)
    if (string_combinations2(s,0,fn,n)) return(True);
  return(False);
}



/****************************************************************************
core of password checking routine
****************************************************************************/
BOOL password_check(char *password)
{

#ifdef USE_PAM
/* This falls through if the password check fails
	- if NO_CRYPT is defined this causes an error msg
		saying Warning - no crypt available
	- if NO_CRYPT is NOT defined this is a potential security hole
		as it may authenticate via the crypt call when PAM
		settings say it should fail.
  if (pam_auth(this_user,password)) return(True);
Hence we make a direct return to avoid a second chance!!!
*/
  return (pam_auth(this_user,password));
#endif

#ifdef AFS_AUTH
  if (afs_auth(this_user,password)) return(True);
#endif

#ifdef DFS_AUTH
  if (dfs_auth(this_user,password)) return(True);
#endif 

#ifdef KRB5_AUTH
  if (krb5_auth(this_user,password)) return(True);
#endif

#ifdef KRB4_AUTH
  if (krb4_auth(this_user,password)) return(True);
#endif

#ifdef PWDAUTH
  if (pwdauth(this_user,password) == 0)
    return(True);
#endif

#ifdef OSF1_ENH_SEC
  {
    BOOL ret = (strcmp(osf1_bigcrypt(password,this_salt),this_crypted) == 0);
    if(!ret) {
      DEBUG(2,("password_check: OSF1_ENH_SEC failed. Trying normal crypt.\n"));
      ret = (strcmp((char *)crypt(password,this_salt),this_crypted) == 0);
    }
    return ret;
  }
#endif

#ifdef ULTRIX_AUTH
  return (strcmp((char *)crypt16(password, this_salt ),this_crypted) == 0);
#endif

#ifdef LINUX_BIGCRYPT
  return(linux_bigcrypt(password,this_salt,this_crypted));
#endif

#ifdef HPUX_10_TRUSTED
  return(strcmp(bigcrypt(password,this_salt),this_crypted) == 0);
#endif

#ifdef NO_CRYPT
  DEBUG(1,("Warning - no crypt available\n"));
  return(False);
#else
  return(strcmp((char *)crypt(password,this_salt),this_crypted) == 0);
#endif
}

/****************************************************************************
core of smb password checking routine.
****************************************************************************/
BOOL smb_password_check(char *password, unsigned char *part_passwd, unsigned char *c8)
{
  /* Finish the encryption of part_passwd. */
  unsigned char p21[21];
  unsigned char p24[24];

  if (part_passwd == NULL)
    DEBUG(10,("No password set - allowing access\n"));
  /* No password set - always true ! */
  if (part_passwd == NULL)
    return 1;

  memset(p21,'\0',21);
  memcpy(p21,part_passwd,16);
  E_P24(p21, c8, p24);
#if DEBUG_PASSWORD
  {
    int i;
    DEBUG(100,("Part password (P16) was |"));
    for(i = 0; i < 16; i++)
      DEBUG(100,("%X ", (unsigned char)part_passwd[i]));
    DEBUG(100,("|\n"));
    DEBUG(100,("Password from client was |"));
    for(i = 0; i < 24; i++)
      DEBUG(100,("%X ", (unsigned char)password[i]));
    DEBUG(100,("|\n"));
    DEBUG(100,("Given challenge was |"));
    for(i = 0; i < 8; i++)
      DEBUG(100,("%X ", (unsigned char)c8[i]));
    DEBUG(100,("|\n"));
    DEBUG(100,("Value from encryption was |"));
    for(i = 0; i < 24; i++)
      DEBUG(100,("%X ", (unsigned char)p24[i]));
    DEBUG(100,("|\n"));
  }
#endif
  return (memcmp(p24, password, 24) == 0);
}

/****************************************************************************
check if a username/password is OK
****************************************************************************/
BOOL password_ok(char *user,char *password, int pwlen, struct passwd *pwd)
{
  pstring pass2;
  int level = lp_passwordlevel();
  struct passwd *pass;
  char challenge[8];
  BOOL update_encrypted = lp_update_encrypted();
  struct smb_passwd *smb_pass;
  BOOL challenge_done = False;

  if (password) password[pwlen] = 0;

  if (pwlen == 24)
    challenge_done = last_challenge(challenge);

#if DEBUG_PASSWORD
  if (challenge_done)
    {
      int i;      
      DEBUG(100,("checking user=[%s] pass=[",user));
      for( i = 0; i < 24; i++)
	DEBUG(100,("%0x ", (unsigned char)password[i]));
      DEBUG(100,("]\n"));
    } else {
	    DEBUG(100,("checking user=[%s] pass=[%s]\n",user,password));
    }
#endif

  if (!password)
    return(False);

  if (((!*password) || (!pwlen)) && !lp_null_passwords())
    return(False);

  if (pwd && !user) 
    {
      pass = (struct passwd *) pwd;
      user = pass->pw_name;
    } 
  else 
    pass = Get_Pwnam(user,True);

  DEBUG(4,("SMB Password - pwlen = %d, challenge_done = %d\n", pwlen, challenge_done));

  if ((pwlen == 24) && challenge_done)
  {
    DEBUG(4,("Checking SMB password for user %s (l=24)\n",user));

    if (!pass) 
    {
      DEBUG(3,("Couldn't find user %s\n",user));
      return(False);
    }

    /* non-null username indicates search by username not smb userid */
    smb_pass = get_smbpwd_entry(user, 0);
    if (!smb_pass)
    {
      DEBUG(3,("Couldn't find user %s in smb_passwd file.\n", user));
      return(False);
    }

    if(smb_pass->acct_ctrl & ACB_DISABLED)
    {
      DEBUG(3,("password_ok: account for user %s was disabled.\n", user));
          return(False);
    }

      /* Ensure the uid's match */
    if (smb_pass->smb_userid != pass->pw_uid)
    {
      DEBUG(3,("Error : UNIX and SMB uids in password files do not match !\n"));
      return(False);
    }

    if (Protocol >= PROTOCOL_NT1)
    {
      /* We have the NT MD4 hash challenge available - see if we can
         use it (ie. does it exist in the smbpasswd file).
       */
      if (smb_pass->smb_nt_passwd != NULL)
      {
        DEBUG(4,("Checking NT MD4 password\n"));
        if (smb_password_check(password, 
                               smb_pass->smb_nt_passwd, 
                               (unsigned char *)challenge))
        {
          update_protected_database(user,True);
          return(True);
        }
        DEBUG(4,("NT MD4 password check failed\n"));
      }
    }

    /* Try against the lanman password */
    if((smb_pass->smb_passwd == NULL) && (smb_pass->acct_ctrl & ACB_PWNOTREQ ))
    {
      /* No password. */
      DEBUG(1,("password_ok: User %s has NO PASSWORD !\n", user));
      update_protected_database(user,True);
      return(True);
    }

    if ((smb_pass->smb_passwd != NULL) && 
        smb_password_check(password, smb_pass->smb_passwd,
                           (unsigned char *)challenge))
    {
      update_protected_database(user,True);
      return(True);
    }

    DEBUG(3,("Error smb_password_check failed\n"));
  }

  DEBUG(4,("Checking password for user %s (l=%d)\n",user,pwlen));

  if (!pass) 
    {
      DEBUG(3,("Couldn't find user %s\n",user));
      return(False);
    }

#ifdef SHADOW_PWD
  {
    struct spwd *spass;

    /* many shadow systems require you to be root to get the password,
       in most cases this should already be the case when this
       function is called, except perhaps for IPC password changing
       requests */

    spass = getspnam(pass->pw_name);
    if (spass && spass->sp_pwdp)
      pass->pw_passwd = spass->sp_pwdp;
  }
#elif defined(IA_UINFO)
  {
      /* Need to get password with SVR4.2's ia_ functions instead of
         get{sp,pw}ent functions. Required by UnixWare 2.x, tested on 
         version 2.1. (tangent@cyberport.com) */
      uinfo_t uinfo;
      if (ia_openinfo(pass->pw_name, &uinfo) != -1)
        ia_get_logpwd(uinfo, &(pass->pw_passwd));
  }
#endif

#ifdef SecureWare
  {
    struct pr_passwd *pr_pw = getprpwnam(pass->pw_name);
    if (pr_pw && pr_pw->ufld.fd_encrypt)
      pass->pw_passwd = pr_pw->ufld.fd_encrypt;
  }
#endif

#ifdef HPUX_10_TRUSTED
  {
    struct pr_passwd *pr_pw = getprpwnam(pass->pw_name);
    if (pr_pw && pr_pw->ufld.fd_encrypt)
      pass->pw_passwd = pr_pw->ufld.fd_encrypt;
  }
#endif

#ifdef OSF1_ENH_SEC
  {
    struct pr_passwd *mypasswd;
    DEBUG(5,("Checking password for user %s in OSF1_ENH_SEC\n",user));
    mypasswd = getprpwnam (user);
    if ( mypasswd )
      { 
  	pstrcpy(pass->pw_name,mypasswd->ufld.fd_name);
  	pstrcpy(pass->pw_passwd,mypasswd->ufld.fd_encrypt);
      }
    else
      {
	DEBUG(5,("No entry for user %s in protected database !\n",user));
	return(False);
      }
  }
#endif

#ifdef ULTRIX_AUTH
  {
    AUTHORIZATION *ap = getauthuid( pass->pw_uid );
    if (ap)
      {
	pstrcpy( pass->pw_passwd, ap->a_password );
	endauthent();
      }
  }
#endif

  /* extract relevant info */
  fstrcpy(this_user,pass->pw_name);  
  fstrcpy(this_salt,pass->pw_passwd);
#ifdef HPUX
  /* The crypt on HPUX won't work with more than 2 salt characters. */
  this_salt[2] = 0;
#endif /* HPUX */
  fstrcpy(this_crypted,pass->pw_passwd);
 
  if (!*this_crypted) {
    if (!lp_null_passwords()) {
      DEBUG(2,("Disallowing access to %s due to null password\n",this_user));
      return(False);
    }
#ifndef PWDAUTH
    if (!*password) {
      DEBUG(3,("Allowing access to %s with null password\n",this_user));
      return(True);
    }
#endif    
  }

  /* try it as it came to us */
  if (password_check(password))
    {
      update_protected_database(user,True);
      if (pass && update_encrypted)
        update_smbpassword_file(pass,password);
      return(True);
    }

  /* if the password was given to us with mixed case then we don't
     need to proceed as we know it hasn't been case modified by the
     client */
  if (strhasupper(password) && strhaslower(password))
    return(False);

  /* make a copy of it */
  StrnCpy(pass2,password,sizeof(pstring)-1);
  
  /* try all lowercase */
  strlower(password);
  if (password_check(password))
    {
      update_protected_database(user,True);
      if (pass && update_encrypted)
        update_smbpassword_file(pass,password);
      return(True);
    }

  /* give up? */
  if (level < 1)
    {
      update_protected_database(user,False);

      /* restore it */
      pstrcpy(password,pass2);

      return(False);
    }

  /* last chance - all combinations of up to level chars upper! */
  strlower(password);

  if (string_combinations(password,password_check,level))
    {
      update_protected_database(user,True);
      if (pass && update_encrypted)
        update_smbpassword_file(pass,password);
      return(True);
    }

  update_protected_database(user,False);
  
  /* restore it */
  pstrcpy(password,pass2);
  
  return(False);
}



/****************************************************************************
check if a username is valid
****************************************************************************/
BOOL user_ok(char *user,int snum)
{
  pstring valid, invalid;
  BOOL ret;

  StrnCpy(valid, lp_valid_users(snum), sizeof(pstring));
  StrnCpy(invalid, lp_invalid_users(snum), sizeof(pstring));

  string_sub(valid,"%S",lp_servicename(snum));
  string_sub(invalid,"%S",lp_servicename(snum));

  ret = !user_in_list(user,invalid);

  if (ret && valid && *valid)
    ret = user_in_list(user,valid);

  if (ret && lp_onlyuser(snum)) {
    char *user_list = lp_username(snum);
    string_sub(user_list,"%S",lp_servicename(snum));
    ret = user_in_list(user,user_list);
  }

  return(ret);
}




/****************************************************************************
validate a group username entry. Return the username or NULL
****************************************************************************/
static char *validate_group(char *group,char *password,int pwlen,int snum)
{
#ifdef NETGROUP
  {
    char *host, *user, *domain;
    setnetgrent(group);
    while (getnetgrent(&host, &user, &domain)) {
      if (user) {
	if (user_ok(user, snum) && 
	    password_ok(user,password,pwlen,NULL)) {
	  endnetgrent();
	  return(user);
	}
      }
    }
    endnetgrent();
  }
#endif
  
#if HAVE_GETGRNAM 
  {
    struct group *gptr = (struct group *)getgrnam(group);
    char **member;
    if (gptr)
      {
	member = gptr->gr_mem;
	while (member && *member)
	  {
	    static fstring name;
	    fstrcpy(name,*member);
	    if (user_ok(name,snum) &&
		password_ok(name,password,pwlen,NULL))
	      return(&name[0]);
	    member++;
	  }
#ifdef GROUP_CHECK_PWENT
	{
	  struct passwd *pwd;
	  static fstring tm;
	  
	  setpwent ();
	  while (pwd = getpwent ()) {
	    if (*(pwd->pw_passwd) && pwd->pw_gid == gptr->gr_gid) {
	      /* This Entry have PASSWORD and same GID then check pwd */
	      if (password_ok(NULL, password, pwlen, pwd)) {
		fstrcpy(tm, pwd->pw_name);
		endpwent ();
		return tm;
	      }
	    }
	  }
	  endpwent ();
	}
#endif /* GROUP_CHECK_PWENT */
      }
  }      
#endif
  return(NULL);
}



/****************************************************************************
check for authority to login to a service with a given username/password
****************************************************************************/
BOOL authorise_login(int snum,char *user,char *password, int pwlen, 
		     BOOL *guest,BOOL *force,uint16 vuid)
{
  BOOL ok = False;
  
  *guest = False;
  
#if DEBUG_PASSWORD
  DEBUG(100,("checking authorisation on user=%s pass=%s\n",user,password));
#endif

  /* there are several possibilities:
     1) login as the given user with given password
     2) login as a previously registered username with the given password
     3) login as a session list username with the given password
     4) login as a previously validated user/password pair
     5) login as the "user =" user with given password
     6) login as the "user =" user with no password (guest connection)
     7) login as guest user with no password

     if the service is guest_only then steps 1 to 5 are skipped
  */

  if (GUEST_ONLY(snum)) *force = True;

  if (!(GUEST_ONLY(snum) && GUEST_OK(snum)))
    {

      user_struct *vuser = get_valid_user_struct(vuid);

      /* check the given username and password */
      if (!ok && (*user) && user_ok(user,snum)) {
	ok = password_ok(user,password, pwlen, NULL);
	if (ok) DEBUG(3,("ACCEPTED: given username password ok\n"));
      }

      /* check for a previously registered guest username */
      if (!ok && (vuser != 0) && vuser->guest) {	  
	if (user_ok(vuser->name,snum) &&
	    password_ok(vuser->name, password, pwlen, NULL)) {
	  pstrcpy(user, vuser->name);
	  vuser->guest = False;
	  DEBUG(3,("ACCEPTED: given password with registered user %s\n", user));
	  ok = True;
	}
      }


      /* now check the list of session users */
      if (!ok)
	{
	  char *auser;
	  char *user_list = strdup(session_users);
	  if (!user_list) return(False);

	  for (auser=strtok(user_list,LIST_SEP); 
	       !ok && auser; 
	       auser = strtok(NULL,LIST_SEP))
	    {
	      fstring user2;
	      fstrcpy(user2,auser);
	      if (!user_ok(user2,snum)) continue;
		  
	      if (password_ok(user2,password, pwlen, NULL)) {
		ok = True;
		pstrcpy(user,user2);
		DEBUG(3,("ACCEPTED: session list username and given password ok\n"));
	      }
	    }
	  free(user_list);
	}

      /* check for a previously validated username/password pair */
      if (!ok && (!lp_revalidate(snum) || lp_security() > SEC_SHARE) &&
	  (vuser != 0) && !vuser->guest &&
	  user_ok(vuser->name,snum)) {
	pstrcpy(user,vuser->name);
	*guest = False;
	DEBUG(3,("ACCEPTED: validated uid ok as non-guest\n"));
	ok = True;
      }

      /* check for a rhosts entry */
      if (!ok && user_ok(user,snum) && check_hosts_equiv(user)) {
	ok = True;
	DEBUG(3,("ACCEPTED: hosts equiv or rhosts entry\n"));
      }

      /* check the user= fields and the given password */
      if (!ok && lp_username(snum)) {
	char *auser;
	pstring user_list;
	StrnCpy(user_list,lp_username(snum),sizeof(pstring));

	string_sub(user_list,"%S",lp_servicename(snum));
	  
	for (auser=strtok(user_list,LIST_SEP);
	     auser && !ok;
	     auser = strtok(NULL,LIST_SEP))
	  {
	    if (*auser == '@')
	      {
		auser = validate_group(auser+1,password,pwlen,snum);
		if (auser)
		  {
		    ok = True;
		    pstrcpy(user,auser);
		    DEBUG(3,("ACCEPTED: group username and given password ok\n"));
		  }
	      }
	    else
	      {
		fstring user2;
		fstrcpy(user2,auser);
		if (user_ok(user2,snum) && 
		    password_ok(user2,password,pwlen,NULL))
		  {
		    ok = True;
		    pstrcpy(user,user2);
		    DEBUG(3,("ACCEPTED: user list username and given password ok\n"));
		  }
	      }
	  }
      }      
    } /* not guest only */

  /* check for a normal guest connection */
  if (!ok && GUEST_OK(snum))
    {
      fstring guestname;
      StrnCpy(guestname,lp_guestaccount(snum),sizeof(guestname)-1);
      if (Get_Pwnam(guestname,True))
	{
	  pstrcpy(user,guestname);
	  ok = True;
	  DEBUG(3,("ACCEPTED: guest account and guest ok\n"));
	}
      else
	DEBUG(0,("Invalid guest account %s??\n",guestname));
      *guest = True;
      *force = True;
    }

  if (ok && !user_ok(user,snum))
    {
      DEBUG(0,("rejected invalid user %s\n",user));
      ok = False;
    }

  return(ok);
}


/****************************************************************************
read the a hosts.equiv or .rhosts file and check if it
allows this user from this machine
****************************************************************************/
static BOOL check_user_equiv(char *user, char *remote, char *equiv_file)
{
  pstring buf;
  int plus_allowed = 1;
  char *file_host;
  char *file_user;
  FILE *fp = fopen(equiv_file, "r");
  DEBUG(5, ("check_user_equiv %s %s %s\n", user, remote, equiv_file));
  if (! fp) return False;
  while(fgets(buf, sizeof(buf), fp)) 
  {
    trim_string(buf," "," ");

    if (buf[0] != '#' && buf[0] != '\n') 
    {
      BOOL is_group = False;
      int plus = 1;
      char *bp = buf;
      if (strcmp(buf, "NO_PLUS\n") == 0)
      {
	DEBUG(6, ("check_user_equiv NO_PLUS\n"));
	plus_allowed = 0;
      }
      else {
	if (buf[0] == '+') 
	{
	  bp++;
	  if (*bp == '\n' && plus_allowed) 
	  {
	    /* a bare plus means everbody allowed */
	    DEBUG(6, ("check_user_equiv everybody allowed\n"));
	    fclose(fp);
	    return True;
	  }
	}
	else if (buf[0] == '-')
	{
	  bp++;
	  plus = 0;
	}
	if (*bp == '@') 
	{
	  is_group = True;
	  bp++;
	}
	file_host = strtok(bp, " \t\n");
	file_user = strtok(NULL, " \t\n");
	DEBUG(7, ("check_user_equiv %s %s\n", file_host ? file_host : "(null)", 
                 file_user ? file_user : "(null)" ));
	if (file_host && *file_host) 
	{
	  BOOL host_ok = False;

#ifdef NETGROUP	  
	  if (is_group)
	    {
	      static char *mydomain = NULL;
	      if (!mydomain)
		yp_get_default_domain(&mydomain);
	      if (mydomain && innetgr(file_host,remote,user,mydomain))
		host_ok = True;
	    }
#else
	  if (is_group)
	    {
	      DEBUG(1,("Netgroups not configured - add -DNETGROUP and recompile\n"));
	      continue;
	    }
#endif

	  /* is it this host */
	  /* the fact that remote has come from a call of gethostbyaddr
	   * means that it may have the fully qualified domain name
	   * so we could look up the file version to get it into
	   * a canonical form, but I would rather just type it
	   * in full in the equiv file
	   */
	  if (!host_ok && !is_group && strequal(remote, file_host))
	    host_ok = True;

	  if (!host_ok)
	    continue;

	  /* is it this user */
	  if (file_user == 0 || strequal(user, file_user)) 
	    {
	      fclose(fp);
	      DEBUG(5, ("check_user_equiv matched %s%s %s\n",
			(plus ? "+" : "-"), file_host,
			(file_user ? file_user : "")));
	      return (plus ? True : False);
	    }
	}
      }
    }
  }
  fclose(fp);
  return False;
}


/****************************************************************************
check for a possible hosts equiv or rhosts entry for the user
****************************************************************************/
BOOL check_hosts_equiv(char *user)
{
  char *fname = NULL;
  pstring rhostsfile;
  struct passwd *pass = Get_Pwnam(user,True);

  if (!pass) 
    return(False);

  fname = lp_hosts_equiv();

  /* note: don't allow hosts.equiv on root */
  if (fname && *fname && (pass->pw_uid != 0))
    {
      if (check_user_equiv(user,client_name(),fname))
	return(True);
    }
  
  if (lp_use_rhosts())
    {
      char *home = get_home_dir(user);
      if (home)
	{
	  slprintf(rhostsfile, sizeof(rhostsfile)-1, "%s/.rhosts", home);
	  if (check_user_equiv(user,client_name(),rhostsfile))
	    return(True);
	}
    }

  return(False);
}


static struct cli_state cli;

/****************************************************************************
return the client state structure
****************************************************************************/
struct cli_state *server_client(void)
{
	return &cli;
}

/****************************************************************************
support for server level security 
****************************************************************************/
struct cli_state *server_cryptkey(void)
{
	fstring desthost;
	struct in_addr dest_ip;
	extern fstring local_machine;
	char *p;

	if (!cli_initialise(&cli))
		return NULL;
	    
	for (p=strtok(lp_passwordserver(),LIST_SEP); p ; p = strtok(NULL,LIST_SEP)) {
		fstrcpy(desthost,p);
		standard_sub_basic(desthost);
		strupper(desthost);

                if(!resolve_name( desthost, &dest_ip)) {
			DEBUG(1,("server_cryptkey: Can't resolve address for %s\n",p));
			continue;
		}

		if (ismyip(dest_ip)) {
			DEBUG(1,("Password server loop - disabling password server %s\n",p));
			continue;
		}

		if (cli_connect(&cli, desthost, &dest_ip)) {
			DEBUG(3,("connected to password server %s\n",p));
			break;
		}
	}

	if (!p) {
		DEBUG(1,("password server not available\n"));
		cli_shutdown(&cli);
		return NULL;
	}

	if (!cli_session_request(&cli, desthost, 0x20, local_machine)) {
		DEBUG(1,("%s rejected the session\n",desthost));
		cli_shutdown(&cli);
		return NULL;
	}

	DEBUG(3,("got session\n"));

	if (!cli_negprot(&cli)) {
		DEBUG(1,("%s rejected the negprot\n",desthost));
		cli_shutdown(&cli);
		return NULL;
	}

	if (cli.protocol < PROTOCOL_LANMAN2 ||
	    !(cli.sec_mode & 1)) {
		DEBUG(1,("%s isn't in user level security mode\n",desthost));
		cli_shutdown(&cli);
		return NULL;
	}

	DEBUG(3,("password server OK\n"));

	return &cli;
}

/****************************************************************************
validate a password with the password server
****************************************************************************/
BOOL server_validate(char *user, char *domain, 
		     char *pass, int passlen,
		     char *ntpass, int ntpasslen)
{
	extern fstring local_machine;
        static unsigned char badpass[24];

	if (!cli.initialised) {
		DEBUG(1,("password server %s is not connected\n", cli.desthost));
		return(False);
	}  

        if(badpass[0] == 0) {
          memset(badpass, 0x1f, sizeof(badpass));
        }

        if((passlen == sizeof(badpass)) && !memcmp(badpass, pass, passlen)) {
          /* Very unlikely, our random bad password is the same as the users
             password. */
          memset(badpass, badpass[0]+1, sizeof(badpass));
        }

        /*
         * Attempt a session setup with a totally incorrect password.
         * If this succeeds with the guest bit *NOT* set then the password
         * server is broken and is not correctly setting the guest bit. We
         * need to detect this as some versions of NT4.x are broken. JRA.
         */

        if (cli_session_setup(&cli, user, (char *)badpass, sizeof(badpass), 
                              (char *)badpass, sizeof(badpass), domain)) {
          if ((SVAL(cli.inbuf,smb_vwv2) & 1) == 0) {
            DEBUG(0,("server_validate: password server %s allows users as non-guest \
with a bad password.\n", cli.desthost));
            DEBUG(0,("server_validate: This is broken (and insecure) behaviour. Please do not \
use this machine as the password server.\n"));
            cli_ulogoff(&cli);
            return False;
          }
          cli_ulogoff(&cli);
        }

        /*
         * Now we know the password server will correctly set the guest bit, or is
         * not guest enabled, we can try with the real password.
         */

	if (!cli_session_setup(&cli, user, pass, passlen, ntpass, ntpasslen, domain)) {
		DEBUG(1,("password server %s rejected the password\n", cli.desthost));
		return False;
	}

	/* if logged in as guest then reject */
	if ((SVAL(cli.inbuf,smb_vwv2) & 1) != 0) {
		DEBUG(0,("password server %s gave us guest only\n", cli.desthost));
		return(False);
	}


        /*
         * This patch from Rob Nielsen <ran@adc.com> makes doing
         * the NetWksaUserLogon a dynamic, rather than compile-time
         * parameter, defaulting to on. This is somewhat dangerous
         * as it allows people to turn off this neccessary check,
         * but so many people have had problems with this that I
         * think it is a neccessary change. JRA.
         */

	if (lp_net_wksta_user_logon()) {
		DEBUG(3,("trying NetWkstaUserLogon with password server %s\n", cli.desthost));
	        if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1)) {
                        DEBUG(0,("password server %s refused IPC$ connect\n", cli.desthost));
                        return False;
                }

		if (!cli_NetWkstaUserLogon(&cli,user,local_machine)) {
			DEBUG(0,("password server %s failed NetWkstaUserLogon\n", cli.desthost));
			cli_tdis(&cli);
			return False;
		}

		if (cli.privilages == 0) {
			DEBUG(0,("password server %s gave guest privilages\n", cli.desthost));
			cli_tdis(&cli);
			return False;
		}

		if (!strequal(cli.eff_name, user)) {
			DEBUG(0,("password server %s gave different username %s\n", 
			 	cli.desthost,
			 	cli.eff_name));
			cli_tdis(&cli);
			return False;
		}
	        cli_tdis(&cli);
	}
        else {
		DEBUG(3,("skipping NetWkstaUserLogon with password server %s\n", cli.desthost));
        }

	DEBUG(3,("password server %s accepted the password\n", cli.desthost));

        cli_ulogoff(&cli);

	return(True);
}


