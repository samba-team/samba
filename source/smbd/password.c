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

extern int Protocol;

/* users from session setup */
static pstring session_users="";

extern pstring global_myname;
extern fstring global_myworkgroup;

/* 
 * track the machine trust account password timeout when
 * in domain mode security
 */  
BOOL global_machine_password_needs_changing = False;

/* Data to do lanman1/2 password challenge. */
static unsigned char saved_challenge[8];
static BOOL challenge_sent=False;

/*******************************************************************
Get the next challenge value - no repeats.
********************************************************************/

void generate_next_challenge(char *challenge)
{
	unsigned char buf[8];

	generate_random_buffer(buf,8,False);

	memcpy(saved_challenge, buf, 8);
	memcpy(challenge,buf,8);
	challenge_sent = True;
}

/*******************************************************************
 Set the last challenge sent, usually from a password server.
********************************************************************/

BOOL set_challenge(unsigned char *challenge)
{
	memcpy(saved_challenge,challenge,8);
	challenge_sent = True;
	return(True);
}

/*******************************************************************
 Get the last challenge sent.
********************************************************************/

static BOOL last_challenge(unsigned char *challenge)
{
	if (!challenge_sent)
		return(False);
	memcpy(challenge,saved_challenge,8);
	return(True);
}

/* this holds info on user ids that are already validated for this VC */
static user_struct *validated_users;
static int next_vuid = VUID_OFFSET;
static int num_validated_vuids;

/****************************************************************************
 Check if a uid has been validated, and return an pointer to the user_struct
 if it has. NULL if not. vuid is biased by an offset. This allows us to
 tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/

user_struct *get_valid_user_struct(uint16 vuid)
{
	user_struct *usp;
	int count=0;

	if (vuid == UID_FIELD_INVALID)
		return NULL;

	for (usp=validated_users;usp;usp=usp->next,count++) {
		if (vuid == usp->vuid) {
			if (count > 10) {
				DLIST_PROMOTE(validated_users, usp);
			}
			return usp;
		}
	}

	return NULL;
}

/****************************************************************************
 Invalidate a uid.
****************************************************************************/

void invalidate_vuid(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);

	if (vuser == NULL)
		return;

	session_yield(vuid);

	DLIST_REMOVE(validated_users, vuser);

	SAFE_FREE(vuser->groups);
	delete_nt_token(&vuser->nt_user_token);
	safe_free(vuser);
	num_validated_vuids--;
}

/****************************************************************************
 Invalidate all vuid entries for this process.
****************************************************************************/

void invalidate_all_vuids(void)
{
	user_struct *usp, *next=NULL;

	for (usp=validated_users;usp;usp=next) {
		next = usp->next;
		
		invalidate_vuid(usp->vuid);
	}
}

/****************************************************************************
 Return a validated username.
****************************************************************************/

char *validated_username(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	if (vuser == NULL)
		return 0;
	return(vuser->user.unix_name);
}

/****************************************************************************
 Return a validated domain.
****************************************************************************/

char *validated_domain(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	if (vuser == NULL)
		return 0;
	return(vuser->user.domain);
}

/****************************************************************************
 Create the SID list for this user.
****************************************************************************/

NT_USER_TOKEN *create_nt_token(uid_t uid, gid_t gid, int ngroups, gid_t *groups, BOOL is_guest, NT_USER_TOKEN *sup_tok)
{
	extern DOM_SID global_sid_World;
	extern DOM_SID global_sid_Network;
	extern DOM_SID global_sid_Builtin_Guests;
	extern DOM_SID global_sid_Authenticated_Users;
	NT_USER_TOKEN *token;
	DOM_SID *psids;
	int i, psid_ndx = 0;
	size_t num_sids = 0;
	fstring sid_str;

	if ((token = (NT_USER_TOKEN *)malloc( sizeof(NT_USER_TOKEN) ) ) == NULL)
		return NULL;

	ZERO_STRUCTP(token);

	/* We always have uid/gid plus World and Network and Authenticated Users or Guest SIDs. */
	num_sids = 5 + ngroups;

	if (sup_tok && sup_tok->num_sids)
		num_sids += sup_tok->num_sids;

	if ((token->user_sids = (DOM_SID *)malloc( num_sids*sizeof(DOM_SID))) == NULL) {
		SAFE_FREE(token);
		return NULL;
	}

	psids = token->user_sids;

	/*
	 * Note - user SID *MUST* be first in token !
	 * se_access_check depends on this.
	 */

	uid_to_sid( &psids[PRIMARY_USER_SID_INDEX], uid);
	psid_ndx++;

	/*
	 * Primary group SID is second in token. Convention.
	 */

	gid_to_sid( &psids[PRIMARY_GROUP_SID_INDEX], gid);
	psid_ndx++;

	/* Now add the group SIDs. */

	for (i = 0; i < ngroups; i++) {
		if (groups[i] != gid) {
			gid_to_sid( &psids[psid_ndx++], groups[i]);
		}
	}

	/* Now add the additional SIDs from the supplimentary token. */
	if (sup_tok) {
		for (i = 0; i < sup_tok->num_sids; i++)
			sid_copy( &psids[psid_ndx++], &sup_tok->user_sids[i] );
	}

	/*
	 * Finally add the "standard" SIDs.
	 * The only difference between guest and "anonymous" (which we
	 * don't really support) is the addition of Authenticated_Users.
	 */

	sid_copy( &psids[psid_ndx++], &global_sid_World);
	sid_copy( &psids[psid_ndx++], &global_sid_Network);

	if (is_guest)
		sid_copy( &psids[psid_ndx++], &global_sid_Builtin_Guests);
	else
		sid_copy( &psids[psid_ndx++], &global_sid_Authenticated_Users);

	token->num_sids = psid_ndx;

	/* Dump list of sids in token */

	for (i = 0; i < token->num_sids; i++) {
		DEBUG(5, ("user token sid %s\n", 
			  sid_to_string(sid_str, &token->user_sids[i])));
	}

	return token;
}

/****************************************************************************
 Register a uid/name pair as being valid and that a valid password
 has been given. vuid is biased by an offset. This allows us to
 tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/

int register_vuid(uid_t uid,gid_t gid, char *unix_name, char *requested_name, 
		  char *domain,BOOL guest, NT_USER_TOKEN **pptok)
{
	user_struct *vuser = NULL;
	struct passwd *pwfile; /* for getting real name from passwd file */

	/* Ensure no vuid gets registered in share level security. */
	if(lp_security() == SEC_SHARE)
		return UID_FIELD_INVALID;

	/* Limit allowed vuids to 16bits - VUID_OFFSET. */
	if (num_validated_vuids >= 0xFFFF-VUID_OFFSET)
		return UID_FIELD_INVALID;

	if((vuser = (user_struct *)malloc( sizeof(user_struct) )) == NULL) {
		DEBUG(0,("Failed to malloc users struct!\n"));
		return UID_FIELD_INVALID;
	}

	ZERO_STRUCTP(vuser);

	DEBUG(10,("register_vuid: (%u,%u) %s %s %s guest=%d\n", (unsigned int)uid, (unsigned int)gid,
				unix_name, requested_name, domain, guest ));

	/* Allocate a free vuid. Yes this is a linear search... :-) */
	while( get_valid_user_struct(next_vuid) != NULL ) {
		next_vuid++;
		/* Check for vuid wrap. */
		if (next_vuid == UID_FIELD_INVALID)
			next_vuid = VUID_OFFSET;
	}

	DEBUG(10,("register_vuid: allocated vuid = %u\n", (unsigned int)next_vuid ));

	vuser->vuid = next_vuid;
	vuser->uid = uid;
	vuser->gid = gid;
	vuser->guest = guest;
	fstrcpy(vuser->user.unix_name,unix_name);
	fstrcpy(vuser->user.smb_name,requested_name);
	fstrcpy(vuser->user.domain,domain);

	vuser->n_groups = 0;
	vuser->groups  = NULL;

	/* Find all the groups this uid is in and store them. 
		Used by change_to_user() */
	initialise_groups(unix_name, uid, gid);
	get_current_groups( vuser->gid, &vuser->n_groups, &vuser->groups);

#ifdef HAVE_GETGROUPS_TOO_MANY_EGIDS
	/*
	 * Under OSes to which this applies, we get GID 0 as the first
	 * element of vuser->groups, so we put GID back in there.
	 * It is ignored by setgroups
	 */
	if (vuser->n_groups) vuser->groups[0] = gid;
#endif /* HAVE_GETGROUPS_TOO_MANY_EGIDS */

	if (*pptok)
		add_supplementary_nt_login_groups(&vuser->n_groups, &vuser->groups, pptok);

	/* Create an NT_USER_TOKEN struct for this user. */
	vuser->nt_user_token = create_nt_token(uid,gid, vuser->n_groups, vuser->groups, guest, *pptok);

	next_vuid++;
	num_validated_vuids++;

	DLIST_ADD(validated_users, vuser);

	DEBUG(3,("uid %d registered to name %s\n",(int)uid,unix_name));

	DEBUG(3, ("Clearing default real name\n"));
	if ((pwfile=sys_getpwnam(vuser->user.unix_name))!= NULL) {
		DEBUG(3, ("User name: %s\tReal name: %s\n",vuser->user.unix_name,pwfile->pw_gecos));
		fstrcpy(vuser->user.full_name, pwfile->pw_gecos);
	}

	if (!session_claim(vuser->vuid)) {
		DEBUG(1,("Failed to claim session for vuid=%d\n", vuser->vuid));
		invalidate_vuid(vuser->vuid);
		return -1;
	}

	return vuser->vuid;
}

/****************************************************************************
 Add a name to the session users list.
****************************************************************************/

void add_session_user(char *user)
{
	fstring suser;
	StrnCpy(suser,user,sizeof(suser)-1);

	if (!Get_Pwnam(suser,True))
		return;

	if (suser && *suser && !in_list(suser,session_users,False)) {
		if (strlen(suser) + strlen(session_users) + 2 >= sizeof(pstring))
			DEBUG(1,("Too many session users??\n"));
		else {
			pstrcat(session_users," ");
			pstrcat(session_users,suser);
		}
	}
}

/****************************************************************************
 Update the encrypted smbpasswd file from the plaintext username and password.
*****************************************************************************/

static BOOL update_smbpassword_file(char *user, char *password)
{
	SAM_ACCOUNT 	*sampass = NULL;
	BOOL 		ret;

	pdb_init_sam(&sampass);
		
	become_root();
	ret = pdb_getsampwnam(sampass, user);
	unbecome_root();

	if(!ret) {
		DEBUG(0,("update_smbpassword_file: pdb_getsampwnam failed to locate %s\n", user));
		return False;
	}

	/*
	 * Remove the account disabled flag - we are updating the
	 * users password from a login.
	 */
	pdb_set_acct_ctrl(sampass, pdb_get_acct_ctrl(sampass) & ~ACB_DISABLED);

	/* Here, the flag is one, because we want to ignore the
           XXXXXXX'd out password */
	ret = change_oem_password( sampass, password, True);
	if (ret == False) {
		DEBUG(3,("change_oem_password returned False\n"));
	}
	
	if (sampass) 
		pdb_free_sam(sampass);
		
	return ret;
}

/****************************************************************************
 Core of smb password checking routine.
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
		return True;

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
 Do a specific test for an smb password being correct, given a smb_password and
 the lanman and NT responses.
****************************************************************************/

BOOL smb_password_ok(SAM_ACCOUNT *sampass, uchar chal[8],
                     uchar lm_pass[24], uchar nt_pass[24])
{
	uchar challenge[8];
	char* user_name;
	uint8 *nt_pw, *lm_pw;

	if (!lm_pass || !sampass) 
		return(False);

	user_name = pdb_get_username(sampass);
	
	DEBUG(4,("smb_password_ok: Checking SMB password for user %s\n",user_name));

	if(pdb_get_acct_ctrl(sampass) & ACB_DISABLED) {
		DEBUG(1,("smb_password_ok: account for user %s was disabled.\n", user_name));
		return(False);
	}

	if (chal == NULL) {
		DEBUG(5,("smb_password_ok: use last SMBnegprot challenge\n"));
		if (!last_challenge(challenge)) {
			DEBUG(1,("smb_password_ok: no challenge done - password failed\n"));
			return False;
		}
	} else {
		DEBUG(5,("smb_password_ok: challenge received\n"));
		memcpy(challenge, chal, 8);
	}

	nt_pw = pdb_get_nt_passwd(sampass);
	
	if ((Protocol >= PROTOCOL_NT1) && (nt_pw != NULL)) {
		/* We have the NT MD4 hash challenge available - see if we can
		   use it (ie. does it exist in the smbpasswd file).
		*/
		DEBUG(4,("smb_password_ok: Checking NT MD4 password\n"));
		if (smb_password_check((char *)nt_pass, (uchar *)nt_pw, challenge)) {
			DEBUG(4,("smb_password_ok: NT MD4 password check succeeded\n"));
			return(True);
		}
		DEBUG(4,("smb_password_ok: NT MD4 password check failed\n"));
	}

	/* Try against the lanman password. pdb_get_lanman_passwd(sampass) == NULL 
	   means no password, allow access. */

	lm_pw = pdb_get_lanman_passwd(sampass);
	
	if((lm_pw == NULL) && (pdb_get_acct_ctrl(sampass) & ACB_PWNOTREQ)) {
		DEBUG(4,("smb_password_ok: no password required for user %s\n",user_name));
		return True;
	}

	if(lp_lanman_auth() && (lm_pw != NULL)) {
		DEBUG(4,("smb_password_ok: Checking LM password\n"));
		if(smb_password_check((char *)lm_pass,(uchar *)lm_pw, challenge)) {
			DEBUG(4,("smb_password_ok: LM password check succeeded\n"));
			return(True);
		}
		DEBUG(4,("smb_password_ok: LM password check failed\n"));
	}

	return False;
}

/****************************************************************************
 Check if a username/password is OK assuming the password is a 24 byte
 SMB hash. Return True if the password is correct, False otherwise.
****************************************************************************/

BOOL pass_check_smb(char *user, char *domain, uchar *chal, 
                    uchar *lm_pwd, uchar *nt_pwd, struct passwd *pwd)
{
	SAM_ACCOUNT *sampass = NULL;

	if (!lm_pwd || !nt_pwd)
		return(False);

	/* get the account information */
	pdb_init_sam(&sampass);
	if (!pdb_getsampwnam(sampass, user)) {
		DEBUG(1,("Couldn't find user '%s' in passdb.\n", user));
		pdb_free_sam(sampass);
		return(False);
	}

	/* Quit if the account was disabled. */
	if(pdb_get_acct_ctrl(sampass) & ACB_DISABLED) {
		DEBUG(1,("Account for user '%s' was disabled.\n", user));
		pdb_free_sam(sampass);
		return(False);
	}


	if (pdb_get_acct_ctrl(sampass) & ACB_PWNOTREQ) {
		if (lp_null_passwords()) {
			DEBUG(3,("Account for user '%s' has no password and null passwords are allowed.\n", user));
			pdb_free_sam(sampass);
			return(True);
		} else {
			DEBUG(3,("Account for user '%s' has no password and null passwords are NOT allowed.\n", user));
			pdb_free_sam(sampass);
			return(False);
		}		
	}

	if (smb_password_ok(sampass, chal, lm_pwd, nt_pwd)) {
		pdb_free_sam(sampass);
		return(True);
	}

	DEBUG(2,("pass_check_smb failed - invalid password for user [%s]\n", user));

	pdb_free_sam(sampass);
	return False;
}

/****************************************************************************
 Check if a username/password pair is OK either via the system password
 database or the encrypted SMB password database
 return True if the password is correct, False otherwise.
****************************************************************************/

BOOL password_ok(char *user, char *password, int pwlen, struct passwd *pwd)
{

	BOOL ret;

	if ((pwlen == 0) && !lp_null_passwords()) {
		DEBUG(4,("Null passwords not allowed.\n"));
		return False;
	}

	if (pwlen == 24 || (lp_encrypted_passwords() && (pwlen == 0) && lp_null_passwords())) {
		/* if 24 bytes long assume it is an encrypted password */
		uchar challenge[8];

		if (!last_challenge(challenge)) {
			DEBUG(0,("Error: challenge not done for user=%s\n", user));
			return False;
		}

		ret = pass_check_smb(user, global_myworkgroup,
		                      challenge, (uchar *)password, (uchar *)password, pwd);

		/*
		 * Try with PAM (may not be compiled in - returns True if not. JRA).
		 * FIXME ! Should this be called if we're using winbindd ? What about
		 * non-local accounts ? JRA.
		 */

		if (ret)
		  return (NT_STATUS_V(smb_pam_accountcheck(user)) == NT_STATUS_V(NT_STATUS_OK));

		return ret;
	} 

	return (pass_check(user, password, pwlen, pwd, 
			  lp_update_encrypted() ? 
			  update_smbpassword_file : NULL));
}

/****************************************************************************
 Check if a username is valid
****************************************************************************/

BOOL user_ok(char *user,int snum)
{
	pstring valid, invalid;
	BOOL ret;

	StrnCpy(valid, lp_valid_users(snum), sizeof(pstring)-1);
	StrnCpy(invalid, lp_invalid_users(snum), sizeof(pstring)-1);

	pstring_sub(valid,"%S",lp_servicename(snum));
	pstring_sub(invalid,"%S",lp_servicename(snum));
	
	ret = !user_in_list(user,invalid);
	
	if (ret && valid && *valid)
		ret = user_in_list(user,valid);

	if (ret && lp_onlyuser(snum)) {
		char *user_list = lp_username(snum);
		pstring_sub(user_list,"%S",lp_servicename(snum));
		ret = user_in_list(user,user_list);
	}

	return(ret);
}

/****************************************************************************
 Validate a group username entry. Return the username or NULL.
****************************************************************************/

static char *validate_group(const char *group,char *password,int pwlen,int snum)
{
#ifdef HAVE_NETGROUP
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
  
	{
		struct sys_userlist *user_list = get_users_in_group(group);
		struct sys_userlist *member;

		for (member = user_list; member; member = member->next) {
			static fstring name;
			fstrcpy(name,member->unix_name);
			if (user_ok(name,snum) &&
			    password_ok(name,password,pwlen,NULL)) {
				free_userlist(user_list);
				return(&name[0]);
			}

			DEBUG(10,("validate_group = member = %s\n", member->unix_name));
		}
		free_userlist(user_list);
	}

	return(NULL);
}

/****************************************************************************
 Check for authority to login to a service with a given username/password.
 Note this is *NOT* used when logging on using sessionsetup_and_X.
****************************************************************************/

BOOL authorise_login(int snum,char *user,char *password, int pwlen, 
		     BOOL *guest,BOOL *force,uint16 vuid)
{
	BOOL ok = False;
	user_struct *vuser = get_valid_user_struct(vuid);

#if DEBUG_PASSWORD
	DEBUG(100,("authorise_login: checking authorisation on user=%s pass=%s\n",
			user,password));
#endif

	*guest = False;
  
	if (GUEST_ONLY(snum))
		*force = True;

	if (!GUEST_ONLY(snum) && (lp_security() > SEC_SHARE)) {

		/*
		 * We should just use the given vuid from a sessionsetup_and_X.
		 */

		if (!vuser) {
			DEBUG(1,("authorise_login: refusing user %s with no session setup\n",
					user));
			return False;
		}

		if (!vuser->guest && user_ok(vuser->user.unix_name,snum)) {
			fstrcpy(user,vuser->user.unix_name);
			*guest = False;
			DEBUG(3,("authorise_login: ACCEPTED: validated uid ok as non-guest \
(user=%s)\n", user));
			return True;
		}
	}
 
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

	if (!(GUEST_ONLY(snum) && GUEST_OK(snum))) {
		/* check the given username and password */
		if (!ok && (*user) && user_ok(user,snum)) {
			ok = password_ok(user,password, pwlen, NULL);
			if (ok)
				DEBUG(3,("authorise_login: ACCEPTED: given username (%s) password ok\n",
						user ));
		}

		/* check for a previously registered guest username */
		if (!ok && (vuser != 0) && vuser->guest) {	  
			if (user_ok(vuser->user.unix_name,snum) &&
					password_ok(vuser->user.unix_name, password, pwlen, NULL)) {
				fstrcpy(user, vuser->user.unix_name);
				vuser->guest = False;
				DEBUG(3,("authorise_login: ACCEPTED: given password with registered user %s\n", user));
				ok = True;
			}
		}

		/* now check the list of session users */
		if (!ok) {
			char *auser;
			char *user_list = strdup(session_users);
			if (!user_list)
				return(False);

			for (auser=strtok(user_list,LIST_SEP); !ok && auser;
									auser = strtok(NULL,LIST_SEP)) {
				fstring user2;
				fstrcpy(user2,auser);
				if (!user_ok(user2,snum))
					continue;
		  
				if (password_ok(user2,password, pwlen, NULL)) {
					ok = True;
					fstrcpy(user,user2);
					DEBUG(3,("authorise_login: ACCEPTED: session list username (%s) \
and given password ok\n", user));
				}
			}

			SAFE_FREE(user_list);
		}

		/* check for a previously validated username/password pair */
		if (!ok && (lp_security() > SEC_SHARE) && (vuser != 0) && !vuser->guest &&
							user_ok(vuser->user.unix_name,snum)) {
			fstrcpy(user,vuser->user.unix_name);
			*guest = False;
			DEBUG(3,("authorise_login: ACCEPTED: validated uid (%s) as non-guest\n",
				user));
			ok = True;
		}

		/* check for a rhosts entry */
		if (!ok && user_ok(user,snum) && check_hosts_equiv(user)) {
			ok = True;
			DEBUG(3,("authorise_login: ACCEPTED: hosts equiv or rhosts entry for %s\n",
					user));
		}

		/* check the user= fields and the given password */
		if (!ok && lp_username(snum)) {
			char *auser;
			pstring user_list;
			StrnCpy(user_list,lp_username(snum),sizeof(pstring)-1);

			pstring_sub(user_list,"%S",lp_servicename(snum));
	  
			for (auser=strtok(user_list,LIST_SEP); auser && !ok;
					auser = strtok(NULL,LIST_SEP)) {
				if (*auser == '@') {
					auser = validate_group(auser+1,password,pwlen,snum);
					if (auser) {
						ok = True;
						fstrcpy(user,auser);
						DEBUG(3,("authorise_login: ACCEPTED: group username \
and given password ok (%s)\n", user));
					}
				} else {
					fstring user2;
					fstrcpy(user2,auser);
					if (user_ok(user2,snum) && password_ok(user2,password,pwlen,NULL)) {
						ok = True;
						fstrcpy(user,user2);
						DEBUG(3,("authorise_login: ACCEPTED: user list username \
and given password ok (%s)\n", user));
					}
				}
			}
		}
	} /* not guest only */

	/* check for a normal guest connection */
	if (!ok && GUEST_OK(snum)) {
		fstring guestname;
		StrnCpy(guestname,lp_guestaccount(snum),sizeof(guestname)-1);
		if (Get_Pwnam(guestname,True)) {
			fstrcpy(user,guestname);
			ok = True;
			DEBUG(3,("authorise_login: ACCEPTED: guest account and guest ok (%s)\n",
					user));
		} else {
			DEBUG(0,("authorise_login: Invalid guest account %s??\n",guestname));
		}
		*guest = True;
	}

	if (ok && !user_ok(user,snum)) {
		DEBUG(0,("authorise_login: rejected invalid user %s\n",user));
		ok = False;
	}

	return(ok);
}

/****************************************************************************
 Read the a hosts.equiv or .rhosts file and check if it
 allows this user from this machine.
****************************************************************************/

static BOOL check_user_equiv(char *user, char *remote, char *equiv_file)
{
	int plus_allowed = 1;
	char *file_host;
	char *file_user;
	char **lines = file_lines_load(equiv_file, NULL, False);
	int i;

	DEBUG(5, ("check_user_equiv %s %s %s\n", user, remote, equiv_file));

	if (! lines)
		return False;

	for (i=0; lines[i]; i++) {
		char *buf = lines[i];
		trim_string(buf," "," ");

		if (buf[0] != '#' && buf[0] != '\n') {
			BOOL is_group = False;
			int plus = 1;
			char *bp = buf;
			if (strcmp(buf, "NO_PLUS\n") == 0) {
				DEBUG(6, ("check_user_equiv NO_PLUS\n"));
				plus_allowed = 0;
			} else {
				if (buf[0] == '+') {
					bp++;
					if (*bp == '\n' && plus_allowed) {
						/* a bare plus means everbody allowed */
						DEBUG(6, ("check_user_equiv everybody allowed\n"));
						file_lines_free(lines);
						return True;
					}
				} else if (buf[0] == '-') {
					bp++;
					plus = 0;
				}
				if (*bp == '@') {
					is_group = True;
					bp++;
				}
				file_host = strtok(bp, " \t\n");
				file_user = strtok(NULL, " \t\n");
				DEBUG(7, ("check_user_equiv %s %s\n", file_host ? file_host : "(null)", 
						file_user ? file_user : "(null)" ));
				if (file_host && *file_host) {
					BOOL host_ok = False;

#if defined(HAVE_NETGROUP) && defined(HAVE_YP_GET_DEFAULT_DOMAIN)
					if (is_group) {
						static char *mydomain = NULL;
						if (!mydomain)
							yp_get_default_domain(&mydomain);
						if (mydomain && innetgr(file_host,remote,user,mydomain))
							host_ok = True;
					}
#else
					if (is_group) {
						DEBUG(1,("Netgroups not configured\n"));
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
					if (file_user == 0 || strequal(user, file_user)) {
						DEBUG(5, ("check_user_equiv matched %s%s %s\n",
							(plus ? "+" : "-"), file_host,
							(file_user ? file_user : "")));
						file_lines_free(lines);
						return (plus ? True : False);
					}
				}
			}
		}
	}
	file_lines_free(lines);
	return False;
}

/****************************************************************************
 Check for a possible hosts equiv or rhosts entry for the user.
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
	if (fname && *fname && (pass->pw_uid != 0)) {
		if (check_user_equiv(user,client_name(),fname))
			return(True);
	}
  
	if (lp_use_rhosts()) {
		char *home = get_user_service_home_dir(user);
		if (home) {
			slprintf(rhostsfile, sizeof(rhostsfile)-1, "%s/.rhosts", home);
			if (check_user_equiv(user,client_name(),rhostsfile))
				return(True);
		}
	}

	return(False);
}

/****************************************************************************
 Return the client state structure.
****************************************************************************/

struct cli_state *server_client(void)
{
	static struct cli_state pw_cli;
	return &pw_cli;
}

/****************************************************************************
 Support for server level security.
****************************************************************************/

struct cli_state *server_cryptkey(void)
{
	struct cli_state *cli;
	fstring desthost;
	struct in_addr dest_ip;
	char *pserver;
	const char *p;
	BOOL connected_ok = False;

	cli = server_client();

	if (!cli_initialise(cli))
		return NULL;

	pserver = strdup(lp_passwordserver());
	p = pserver;

	while(next_token( &p, desthost, LIST_SEP, sizeof(desthost))) {
		standard_sub_basic(desthost,sizeof(desthost));
		strupper(desthost);

		if(!resolve_name( desthost, &dest_ip, 0x20)) {
			DEBUG(1,("server_cryptkey: Can't resolve address for %s\n",desthost));
			continue;
		}

		if (ismyip(dest_ip)) {
			DEBUG(1,("Password server loop - disabling password server %s\n",desthost));
			continue;
		}

		if (cli_connect(cli, desthost, &dest_ip)) {
			DEBUG(3,("connected to password server %s\n",desthost));
			connected_ok = True;
			break;
		}
	}

	SAFE_FREE(pserver);

	if (!connected_ok) {
		DEBUG(0,("password server not available\n"));
		cli_shutdown(cli);
		return NULL;
	}

	if (!attempt_netbios_session_request(cli, global_myname, desthost, &dest_ip)) {
		cli_shutdown(cli);
		return NULL;
	}

	DEBUG(3,("got session\n"));

	if (!cli_negprot(cli)) {
		DEBUG(1,("%s rejected the negprot\n",desthost));
		cli_shutdown(cli);
		return NULL;
	}

	if (cli->protocol < PROTOCOL_LANMAN2 ||
	    !(cli->sec_mode & 1)) {
		DEBUG(1,("%s isn't in user level security mode\n",desthost));
		cli_shutdown(cli);
		return NULL;
	}

	DEBUG(3,("password server OK\n"));

	return cli;
}

/****************************************************************************
 Validate a password with the password server.
****************************************************************************/

BOOL server_validate(char *user, char *domain, 
		     char *pass, int passlen,
		     char *ntpass, int ntpasslen)
{
	struct cli_state *cli;
	static unsigned char badpass[24];
	static fstring baduser; 
	static BOOL tested_password_server = False;
	static BOOL bad_password_server = False;

	cli = server_client();

	if (!cli->initialised) {
		DEBUG(1,("password server %s is not connected\n", cli->desthost));
		return(False);
	}  

	if(badpass[0] == 0)
		memset(badpass, 0x1f, sizeof(badpass));

	if((passlen == sizeof(badpass)) && !memcmp(badpass, pass, passlen)) {
		/* 
		 * Very unlikely, our random bad password is the same as the users
		 * password.
		 */
		memset(badpass, badpass[0]+1, sizeof(badpass));
	}

	if(baduser[0] == 0) {
		fstrcpy(baduser, INVALID_USER_PREFIX);
		fstrcat(baduser, global_myname);
	}

	/*
	 * Attempt a session setup with a totally incorrect password.
	 * If this succeeds with the guest bit *NOT* set then the password
	 * server is broken and is not correctly setting the guest bit. We
	 * need to detect this as some versions of NT4.x are broken. JRA.
	 */

	if(!tested_password_server) {
		if (cli_session_setup(cli, baduser, (char *)badpass, sizeof(badpass), 
					(char *)badpass, sizeof(badpass), domain)) {

			/*
			 * We connected to the password server so we
			 * can say we've tested it.
			 */
			tested_password_server = True;

			if ((SVAL(cli->inbuf,smb_vwv2) & 1) == 0) {
				DEBUG(0,("server_validate: password server %s allows users as non-guest \
with a bad password.\n", cli->desthost));
				DEBUG(0,("server_validate: This is broken (and insecure) behaviour. Please do not \
use this machine as the password server.\n"));
				cli_ulogoff(cli);

				/*
				 * Password server has the bug.
				 */
				bad_password_server = True;
				return False;
			}
			cli_ulogoff(cli);
		}
	} else {

		/*
		 * We have already tested the password server.
		 * Fail immediately if it has the bug.
		 */

		if(bad_password_server) {
			DEBUG(0,("server_validate: [1] password server %s allows users as non-guest \
with a bad password.\n", cli->desthost));
			DEBUG(0,("server_validate: [1] This is broken (and insecure) behaviour. Please do not \
use this machine as the password server.\n"));
			return False;
		}
	}

	/*
	 * Now we know the password server will correctly set the guest bit, or is
	 * not guest enabled, we can try with the real password.
	 */

	if (!cli_session_setup(cli, user, pass, passlen, ntpass, ntpasslen, domain)) {
		DEBUG(1,("password server %s rejected the password\n", cli->desthost));
		return False;
	}

	/* if logged in as guest then reject */
	if ((SVAL(cli->inbuf,smb_vwv2) & 1) != 0) {
		DEBUG(1,("password server %s gave us guest only\n", cli->desthost));
		cli_ulogoff(cli);
		return(False);
	}

	cli_ulogoff(cli);

	return(True);
}

static char *mutex_server_name;

static BOOL grab_server_mutex(const char *name)
{
	mutex_server_name = strdup(name);
	if (!mutex_server_name) {
		DEBUG(0,("grab_server_mutex: malloc failed for %s\n", name));
		return False;
	}
	if (!secrets_named_mutex(name, 10)) {
		DEBUG(10,("grab_server_mutex: failed for %s\n", name));
		SAFE_FREE(mutex_server_name);
		return False;
	}

	return True;
}

static void release_server_mutex(void)
{
	if (mutex_server_name) {
		secrets_named_mutex_release(mutex_server_name);
		SAFE_FREE(mutex_server_name);
	}
}

/***********************************************************************
 Connect to a remote machine for domain security authentication
 given a name or IP address.
************************************************************************/

static BOOL connect_to_domain_password_server(struct cli_state **ppcli, 
						char *server, unsigned char *trust_passwd)
{
	struct in_addr dest_ip;
	fstring remote_machine;
	struct cli_state *pcli = NULL;

	*ppcli = NULL;

	if(!(pcli = cli_initialise(NULL))) {
		DEBUG(0,("connect_to_domain_password_server: unable to initialize client connection.\n"));
		return False;
	}

	if (is_ipaddress(server)) {
		struct in_addr to_ip;

		/* we shouldn't have 255.255.255.255 forthe IP address of a password server anyways */
		if ((to_ip.s_addr=inet_addr(server)) == 0xFFFFFFFF) {
			DEBUG (0,("connect_to_domain_password_server: inet_addr(%s) returned 0xFFFFFFFF!\n", server));
			cli_shutdown(pcli);
			return False;
		}

		if (!name_status_find("*", 0, 0x20, to_ip, remote_machine)) {
			DEBUG(1, ("connect_to_domain_password_server: Can't " "resolve name for IP %s\n", server));
			cli_shutdown(pcli);
			return False;
		}
	} else {
		fstrcpy(remote_machine, server);
	}

	standard_sub_basic(remote_machine,sizeof(remote_machine));
	strupper(remote_machine);

	if(!resolve_name( remote_machine, &dest_ip, 0x20)) {
		DEBUG(1,("connect_to_domain_password_server: Can't resolve address for %s\n", remote_machine));
		cli_shutdown(pcli);
		return False;
	}
  
	if (ismyip(dest_ip)) {
		DEBUG(1,("connect_to_domain_password_server: Password server loop - not using password server %s\n",
			remote_machine));
		cli_shutdown(pcli);
		return False;
	}

	/* we use a mutex to prevent two connections at once - when a NT PDC gets
		two connections where one hasn't completed a negprot yet it will send a
		TCP reset to the first connection (tridge) */

	if (!grab_server_mutex(server)) {
		cli_shutdown(pcli);
		return False;
	}

	if (!cli_connect(pcli, remote_machine, &dest_ip)) {
		DEBUG(0,("connect_to_domain_password_server: unable to connect to SMB server on \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}
  
	if (!attempt_netbios_session_request(pcli, global_myname, remote_machine, &dest_ip)) {
		DEBUG(0,("connect_to_password_server: machine %s rejected the NetBIOS \
session request. Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}
  
	pcli->protocol = PROTOCOL_NT1;

	if (!cli_negprot(pcli)) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the negotiate protocol. \
Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}

	if (pcli->protocol != PROTOCOL_NT1) {
		DEBUG(0,("connect_to_domain_password_server: machine %s didn't negotiate NT protocol.\n",
			remote_machine));
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}

	/*
	 * Do an anonymous session setup.
	 */

	if (!cli_session_setup(pcli, "", "", 0, "", 0, "")) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the session setup. \
Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}

	if (!(pcli->sec_mode & 1)) {
		DEBUG(1,("connect_to_domain_password_server: machine %s isn't in user level security mode\n",
			remote_machine));
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}

	if (!cli_send_tconX(pcli, "IPC$", "IPC", "", 1)) {
		DEBUG(0,("connect_to_domain_password_server: machine %s rejected the tconX on the IPC$ share. \
Error was : %s.\n", remote_machine, cli_errstr(pcli) ));
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}

	/*
	 * We now have an anonymous connection to IPC$ on the domain password server.
	 */

	/*
	 * Even if the connect succeeds we need to setup the netlogon
	 * pipe here. We do this as we may just have changed the domain
	 * account password on the PDC and yet we may be talking to
	 * a BDC that doesn't have this replicated yet. In this case
	 * a successful connect to a DC needs to take the netlogon connect
	 * into account also. This patch from "Bjart Kvarme" <bjart.kvarme@usit.uio.no>.
	 */

	if(cli_nt_session_open(pcli, PIPE_NETLOGON) == False) {
		DEBUG(0,("connect_to_domain_password_server: unable to open the domain client session to \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(pcli)));
		cli_nt_session_close(pcli);
		cli_ulogoff(pcli);
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}

	if (!NT_STATUS_IS_OK(cli_nt_setup_creds(pcli, trust_passwd))) {
		DEBUG(0,("connect_to_domain_password_server: unable to setup the PDC credentials to machine \
%s. Error was : %s.\n", remote_machine, cli_errstr(pcli)));
		cli_nt_session_close(pcli);
		cli_ulogoff(pcli);
		cli_shutdown(pcli);
		release_server_mutex();
		return(False);
	}

	*ppcli = pcli;

	/* We exit here with the mutex *locked*. JRA */
	return True;
}

/***********************************************************************
 Utility function to attempt a connection to an IP address of a DC.
************************************************************************/

static BOOL attempt_connect_to_dc(struct cli_state **ppcli, struct in_addr *ip, unsigned char *trust_passwd)
{
	fstring dc_name;

	/*
	 * Ignore addresses we have already tried.
	 */

	if (is_zero_ip(*ip))
		return False;

	if (!lookup_dc_name(global_myname, lp_workgroup(), ip, dc_name))
		return False;

	return connect_to_domain_password_server(ppcli, dc_name, trust_passwd);
}

/***********************************************************************
 We have been asked to dynamcially determine the IP addresses of
 the PDC and BDC's for this DOMAIN, and query them in turn.
************************************************************************/

static BOOL find_connect_pdc(struct cli_state **ppcli, unsigned char *trust_passwd, time_t last_change_time)
{
	struct in_addr *ip_list = NULL;
	int count = 0;
	int i;
	BOOL connected_ok = False;
	time_t time_now = time(NULL);
	BOOL use_pdc_only = False;

	/*
	 * If the time the machine password has changed
	 * was less than an hour ago then we need to contact
	 * the PDC only, as we cannot be sure domain replication
	 * has yet taken place. Bug found by Gerald (way to go
	 * Gerald !). JRA.
	 */

	if (time_now - last_change_time < 3600)
		use_pdc_only = True;

	if (!get_dc_list(use_pdc_only, lp_workgroup(), &ip_list, &count))
		return False;

	/*
	 * Firstly try and contact a PDC/BDC who has the same
	 * network address as any of our interfaces.
	 */
	for(i = 0; i < count; i++) {
		if(!is_local_net(ip_list[i]))
			continue;

		if((connected_ok = attempt_connect_to_dc(ppcli, &ip_list[i], trust_passwd))) 
			break;
		
		zero_ip(&ip_list[i]); /* Tried and failed. */
	}

	/*
	 * Secondly try and contact a random PDC/BDC.
	 */
	if(!connected_ok) {
		i = (sys_random() % count);

		if (!is_zero_ip(ip_list[i])) {
			if (!(connected_ok = attempt_connect_to_dc(ppcli, &ip_list[i], trust_passwd)))
				zero_ip(&ip_list[i]); /* Tried and failed. */
		}
	}

	/*
	 * Finally go through the IP list in turn, ignoring any addresses
	 * we have already tried.
	 */
	if(!connected_ok) {
		/*
		 * Try and connect to any of the other IP addresses in the PDC/BDC list.
		 * Note that from a WINS server the #1 IP address is the PDC.
		 */
		for(i = 0; i < count; i++) {
			if (is_zero_ip(ip_list[i]))
				continue;

			if((connected_ok = attempt_connect_to_dc(ppcli, &ip_list[i], trust_passwd)))
				break;
		}
	}

	SAFE_FREE(ip_list);
	return connected_ok;
}

/***********************************************************************
 Do the same as security=server, but using NT Domain calls and a session
 key from the machine password.
************************************************************************/

BOOL domain_client_validate( char *user, char *domain, 
                             char *smb_apasswd, int smb_apasslen, 
                             char *smb_ntpasswd, int smb_ntpasslen,
                             BOOL *user_exists, NT_USER_TOKEN **pptoken)
{
	unsigned char local_challenge[8];
	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];
	unsigned char trust_passwd[16];
	fstring remote_machine;
	const char *p;
	const char *pserver;
	NET_ID_INFO_CTR ctr;
	NET_USER_INFO_3 info3;
	struct cli_state *pcli = NULL;
	uint32 smb_uid_low;
	BOOL connected_ok = False;
	time_t last_change_time;
	NTSTATUS status;

	if (pptoken)
		*pptoken = NULL;

	if(user_exists != NULL)
		*user_exists = True; /* Only set false on a very specific error. */
 
	/* 
	 * Check that the requested domain is not our own machine name.
	 * If it is, we should never check the PDC here, we use our own local
	 * password file.
	 */

	if(strequal( domain, global_myname)) {
		DEBUG(3,("domain_client_validate: Requested domain was for this machine.\n"));
		return False;
	}

	/*
	 * Next, check that the passwords given were encrypted.
	 */

	if(((smb_apasslen != 24) && (smb_apasslen != 0)) || 
			((smb_ntpasslen != 24) && (smb_ntpasslen != 0))) {

		/*
		 * Not encrypted - do so.
		 */

		DEBUG(3,("domain_client_validate: User passwords not in encrypted format.\n"));
		generate_random_buffer( local_challenge, 8, False);
		SMBencrypt( (uchar *)smb_apasswd, local_challenge, local_lm_response);
		SMBNTencrypt((uchar *)smb_ntpasswd, local_challenge, local_nt_response);
		smb_apasslen = 24;
		smb_ntpasslen = 24;
		smb_apasswd = (char *)local_lm_response;
		smb_ntpasswd = (char *)local_nt_response;
	} else {

		/*
		 * Encrypted - get the challenge we sent for these
		 * responses.
		 */

		if (!last_challenge(local_challenge)) {
			DEBUG(0,("domain_client_validate: no challenge done - password failed\n"));
			return False;
		}
	}

	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(global_myworkgroup, trust_passwd, &last_change_time)) {
		DEBUG(0, ("domain_client_validate: could not fetch trust account password for domain %s\n", global_myworkgroup));
		return False;
	}

	/* Test if machine password is expired and need to be changed */
	if (lp_machine_password_timeout()) {
		if (time(NULL) > last_change_time + lp_machine_password_timeout()) {
			DEBUG(10,("domain_client_validate: machine account password needs changing. \
Last change time = (%u) %s. Machine password timeout = %u seconds\n",
				(unsigned int)last_change_time, http_timestring(last_change_time),
				(unsigned int)lp_machine_password_timeout() ));
			global_machine_password_needs_changing = True;
		}
	}

	/*
	 * At this point, smb_apasswd points to the lanman response to
	 * the challenge in local_challenge, and smb_ntpasswd points to
	 * the NT response to the challenge in local_challenge. Ship
	 * these over the secure channel to a domain controller and
	 * see if they were valid.
	 */

	/*
	 * Treat each name in the 'password server =' line as a potential
	 * PDC/BDC. Contact each in turn and try and authenticate.
	 */

	pserver = lp_passwordserver();
	if (! *pserver)
		pserver = "*";
	p = pserver;

	while (!connected_ok &&
			next_token(&p,remote_machine,LIST_SEP,sizeof(remote_machine))) {
		if(strequal(remote_machine, "*")) {
			connected_ok = find_connect_pdc(&pcli, trust_passwd, last_change_time);
		} else {
			connected_ok = connect_to_domain_password_server(&pcli, remote_machine, trust_passwd);
		}
	}

	if (!connected_ok) {
		DEBUG(0,("domain_client_validate: Domain password server not available.\n"));
		if (pcli)
			cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}

	/* We really don't care what LUID we give the user. */
	generate_random_buffer( (unsigned char *)&smb_uid_low, 4, False);

	ZERO_STRUCT(info3);

	status = cli_nt_login_network(pcli, domain, user, smb_uid_low, (char *)local_challenge,
				((smb_apasslen != 0) ? smb_apasswd : NULL),
				((smb_ntpasslen != 0) ? smb_ntpasswd : NULL),
				&ctr, &info3);

	if (!NT_STATUS_IS_OK(status)) {

		DEBUG(0,("domain_client_validate: unable to validate password for user %s in domain \
%s to Domain controller %s. Error was %s.\n", user, domain, remote_machine, get_nt_error_msg(status) ));
		cli_nt_session_close(pcli);
		cli_ulogoff(pcli);
		cli_shutdown(pcli);
		release_server_mutex();

		if((NT_STATUS_V(status) == NT_STATUS_V(NT_STATUS_NO_SUCH_USER)) && (user_exists != NULL))
			*user_exists = False;

		return False;
	}

	/*
	 * Here, if we really want it, we have lots of info about the user in info3.
	 */

	/* Return group membership as returned by NT.  This contains group
	 membership in nested groups which doesn't seem to be accessible by any
	 other means.  We merge this into the NT_USER_TOKEN associated with the vuid
	 later on. */
 
	if (pptoken && (info3.num_groups2 != 0)) {
		NT_USER_TOKEN *ptok;
		int i;
 
		*pptoken = NULL;
 
		if ((ptok = (NT_USER_TOKEN *)malloc( sizeof(NT_USER_TOKEN) ) ) == NULL) {
			DEBUG(0, ("domain_client_validate: Out of memory allocating NT_USER_TOKEN\n"));
			release_server_mutex();
			return False;
		}
 
		ptok->num_sids = (size_t)info3.num_groups2 + info3.num_other_sids;
		if ((ptok->user_sids = (DOM_SID *)malloc( sizeof(DOM_SID) * ptok->num_sids )) == NULL) {
			DEBUG(0, ("domain_client_validate: Out of memory allocating group SIDS\n"));
			SAFE_FREE(ptok);
			release_server_mutex();
			return False;
		}
 
		/* Group membership (including nested groups) is
		   stored here. */

		for (i = 0; i < info3.num_groups2; i++) {
			sid_copy(&ptok->user_sids[i], &info3.dom_sid.sid);
			sid_append_rid(&ptok->user_sids[i], info3.gids[i].g_rid);
		}

		/* Universal group memberships for other domains are
		   stored in the info3.other_sids field.  We also need to
		   do sid filtering here. */

		for (i = 0; i < info3.num_other_sids; i++)
			sid_copy(&ptok->user_sids[info3.num_groups2 + i], 
				 &info3.other_sids[i].sid);

		*pptoken = ptok;
	}

#if 0
	/* 
	 * We don't actually need to do this - plus it fails currently with
	 * NT_STATUS_INVALID_INFO_CLASS - we need to know *exactly* what to
	 * send here. JRA.
	 */

	if(cli_nt_logoff(pcli, &ctr) == False) {
		DEBUG(0,("domain_client_validate: unable to log off user %s in domain \
%s to Domain controller %s. Error was %s.\n", user, domain, remote_machine, cli_errstr(pcli)));        
		cli_nt_session_close(pcli);
		cli_ulogoff(pcli);
		cli_shutdown(pcli);
		release_server_mutex();
		return False;
	}
#endif /* 0 */

	/* Note - once the cli stream is shutdown the mem_ctx used
	to allocate the other_sids and gids structures has been deleted - so
	these pointers are no longer valid..... */

	cli_nt_session_close(pcli);
	cli_ulogoff(pcli);
	cli_shutdown(pcli);
	release_server_mutex();
	return True;
}
