/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   handle SMBsessionsetup
   Copyright (C) Andrew Tridgell 1998-2001
   Copyright (C) Andrew Bartlett      2001

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

/****************************************************************************
reply to a session setup command
****************************************************************************/
int reply_sesssetup_and_X(connection_struct *conn, char *inbuf,char *outbuf,
			  int length,int bufsize)
{
	int sess_vuid;
	gid_t gid;
	uid_t uid;
	char* full_name;
	int   smb_bufsize;    
	int   smb_apasslen = 0;   
	pstring smb_apasswd;
	int   smb_ntpasslen = 0;   
	pstring smb_ntpasswd;
	pstring user;
	pstring orig_user;
	fstring domain;
	fstring native_os;
	fstring native_lanman;
	BOOL guest=False;
	static BOOL done_sesssetup = False;
	extern BOOL global_encrypted_passwords_negotiated;
	extern uint32 global_client_caps;
	extern int Protocol;
	extern fstring remote_machine;
	extern userdom_struct current_user_info;
	extern int max_send;
	BOOL doencrypt = global_encrypted_passwords_negotiated;
	START_PROFILE(SMBsesssetupX);
	
	*smb_apasswd = *smb_ntpasswd = 0;
	
	smb_bufsize = SVAL(inbuf,smb_vwv2);
	
	if (Protocol < PROTOCOL_NT1) {
		smb_apasslen = SVAL(inbuf,smb_vwv7);
		if (smb_apasslen > MAX_PASS_LEN) {
			return ERROR_DOS(ERRDOS,ERRbuftoosmall);
		}

		memcpy(smb_apasswd,smb_buf(inbuf),smb_apasslen);
		srvstr_pull(inbuf, user, smb_buf(inbuf)+smb_apasslen, sizeof(user), -1, STR_TERMINATE);
		
		if (!doencrypt && (lp_security() != SEC_SERVER)) {
			smb_apasslen = strlen(smb_apasswd);
		}
	} else {
		uint16 passlen1 = SVAL(inbuf,smb_vwv7);
		uint16 passlen2 = SVAL(inbuf,smb_vwv8);
		enum remote_arch_types ra_type = get_remote_arch();
		char *p = smb_buf(inbuf);    
		
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
		
		if (passlen1 != 24 && passlen2 < 24)
			doencrypt = False;
		
		if (passlen1 > MAX_PASS_LEN) {
			return ERROR_DOS(ERRDOS,ERRbuftoosmall);
		}
		
		passlen1 = MIN(passlen1, MAX_PASS_LEN);
		passlen2 = MIN(passlen2, MAX_PASS_LEN);
		
		if (!doencrypt) {
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
			/* there seems to be no reason behind the
			 * differences in MS clients formatting
			 * various info like the domain, NativeOS, and
			 * NativeLanMan fields. Win95 in particular
			 * seems to have an extra null byte between
			 * the username and the domain, or the
			 * password length calculation is wrong, which
			 * throws off the string extraction routines
			 * below.  This makes the value of domain be
			 * the empty string, which fails the restrict
			 * anonymous check further down.  This
			 * compensates for that, and allows browsing
			 * to work in mixed NT and win95 environments
			 * even when restrict anonymous is true. AAB
			 * */
			dump_data(100, p, 0x70);
			DEBUG(9, ("passlen1=%d, passlen2=%d\n", passlen1, passlen2));
			if (ra_type == RA_WIN95 && !passlen1 && !passlen2 && p[0] == 0 && p[1] == 0) {
				DEBUG(0, ("restrict anonymous parameter used in a win95 environment!\n"));
				DEBUG(0, ("client is win95 and broken passlen1 offset -- attempting fix\n"));
				DEBUG(0, ("if win95 cilents are having difficulty browsing, you will be unable to use restrict anonymous\n"));
				passlen1 = 1;
			}
		}

		/* Save the lanman2 password and the NT md4 password. */
		smb_apasslen = passlen1;
		memcpy(smb_apasswd,p,smb_apasslen);

		smb_ntpasslen = passlen2;
		memcpy(smb_ntpasswd,p+passlen1,smb_ntpasslen);

		if (smb_apasslen != 24 || !doencrypt) {
			/* trim the password */
			smb_apasslen = strlen(smb_apasswd);
			
			/* wfwg sometimes uses a space instead of a null */
			if (strequal(smb_apasswd," ")) {
				smb_apasslen = 0;
				*smb_apasswd = 0;
			}
		}
		
		p += passlen1 + passlen2;
		p += srvstr_pull(inbuf, user, p, sizeof(user), -1,
				 STR_TERMINATE);
		p += srvstr_pull(inbuf, domain, p, sizeof(domain), 
				 -1, STR_TERMINATE);
		p += srvstr_pull(inbuf, native_os, p, sizeof(native_os), 
				 -1, STR_TERMINATE);
		p += srvstr_pull(inbuf, native_lanman, p, sizeof(native_lanman),
				 -1, STR_TERMINATE);
		DEBUG(3,("Domain=[%s]  NativeOS=[%s] NativeLanMan=[%s]\n",
			 domain,native_os,native_lanman));
	}
	
	/* don't allow for weird usernames or domains */
	alpha_strcpy(user, user, ". _-$", sizeof(user));
	alpha_strcpy(domain, domain, ". _-", sizeof(domain));
	if (strstr(user, "..") || strstr(domain,"..")) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	if (lp_security() == SEC_SHARE) {
		/* in share level we should ignore any passwords */
		smb_ntpasslen = 0;
		smb_apasslen = 0;
		guest = True;
	}


	DEBUG(3,("sesssetupX:name=[%s]\\[%s]@[%s]\n",user, domain, remote_machine));
	
	if (done_sesssetup && lp_restrict_anonymous()) {
		/* tests show that even if browsing is done over
		 * already validated connections without a username
		 * and password the domain is still provided, which it
		 * wouldn't be if it was a purely anonymous
		 * connection.  So, in order to restrict anonymous, we
		 * only deny connections that have no session
		 * information.  If a domain has been provided, then
		 * it's not a purely anonymous connection. AAB */
		if (!*user && !*smb_apasswd && !*domain) {
			DEBUG(0, ("restrict anonymous is True and anonymous connection attempted. Denying access.\n"));
			END_PROFILE(SMBsesssetupX);
			return ERROR_DOS(ERRDOS,ERRnoaccess);
		}
	}

	/* If no username is sent use the guest account */
	if (!*user) {
		pstrcpy(user,lp_guestaccount(-1));
		guest = True;
	}
	
	pstrcpy(current_user_info.smb_name,user);
	
	reload_services(True);
	
	/*
	 * Save the username before mapping. We will use
	 * the original username sent to us for security=server
	 * and security=domain checking.
	 */
	
	pstrcpy( orig_user, user);
	
	/*
	 * Always try the "DOMAIN\user" lookup first, as this is the most
	 * specific case. If this fails then try the simple "user" lookup.
	 * But don't do this for guests, as this is always a local user.
	 */
	
	if (!guest) {
		pstring dom_user;
		
		/* Work out who's who */
		
		slprintf(dom_user, sizeof(dom_user) - 1,"%s%s%s",
			 domain, lp_winbind_separator(), user);
		
		if (sys_getpwnam(dom_user) != NULL) {
			pstrcpy(user, dom_user);
			DEBUG(3,("Using unix username %s\n", dom_user));
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
	}
	
	add_session_user(user);
	
	if (!guest) {
		NTSTATUS nt_status;
		nt_status = pass_check_smb(orig_user, user, 
					   domain, remote_machine,
					   (unsigned char *)smb_apasswd, 
					   smb_apasslen, 
					   (unsigned char *)smb_ntpasswd,
					   smb_ntpasslen);
	  
		if NT_STATUS_IS_OK(nt_status) {

		} else if NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_SUCH_USER) {
			if ((lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_USER) || 
			    (lp_map_to_guest() ==  MAP_TO_GUEST_ON_BAD_PASSWORD)) {
				DEBUG(3,("No such user %s [%s] - using guest account\n",user, domain));
				pstrcpy(user,lp_guestaccount(-1));
				guest = True;
			} else {
				/* Match WinXP and don't give the game away */
				return ERROR_NT(NT_STATUS_LOGON_FAILURE);
			}
		} else if NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD) {
			if (lp_map_to_guest() ==  MAP_TO_GUEST_ON_BAD_PASSWORD) {
				pstrcpy(user,lp_guestaccount(-1));
				DEBUG(3,("Registered username %s for guest access\n",user));
				guest = True;
			} else {
				/* Match WinXP and don't give the game away */
				return ERROR_NT(NT_STATUS_LOGON_FAILURE);
			}
		} else {
			return ERROR_NT(nt_status);
		}
	}
	
	if (!strequal(user,lp_guestaccount(-1)) &&
	    lp_servicenumber(user) < 0) {
		add_home_service(user,get_user_home_dir(user));
	}


	/* it's ok - setup a reply */
	if (Protocol < PROTOCOL_NT1) {
		set_message(outbuf,3,0,True);
	} else {
		char *p;
		set_message(outbuf,3,0,True);
		p = smb_buf(outbuf);
		p += srvstr_push(outbuf, p, "Unix", -1, STR_TERMINATE);
		p += srvstr_push(outbuf, p, "Samba", -1, STR_TERMINATE);
		p += srvstr_push(outbuf, p, lp_workgroup(), -1, STR_TERMINATE);
		set_message_end(outbuf,p);
		/* perhaps grab OS version here?? */
	}
	
	/* Set the correct uid in the outgoing and incoming packets
	   We will use this on future requests to determine which
	   user we should become.
	*/
	{
		const struct passwd *pw = smb_getpwnam(user,False);
		if (!pw) {
			DEBUG(1,("Username %s is invalid on this system\n",user));
			END_PROFILE(SMBsesssetupX);
			return ERROR_NT(NT_STATUS_LOGON_FAILURE);
		}
		gid = pw->pw_gid;
		uid = pw->pw_uid;
		full_name = pw->pw_gecos;
	}
	
	if (guest)
		SSVAL(outbuf,smb_vwv2,1);
	
	/* register the name and uid as being validated, so further connections
	   to a uid can get through without a password, on the same VC */
	
	sess_vuid = register_vuid(uid,gid,user,orig_user,domain,guest, full_name);
	
	if (sess_vuid == -1) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

 
	SSVAL(outbuf,smb_uid,sess_vuid);
	SSVAL(inbuf,smb_uid,sess_vuid);
	
	if (!done_sesssetup)
		max_send = MIN(max_send,smb_bufsize);
	
	done_sesssetup = True;
	
	END_PROFILE(SMBsesssetupX);
	return chain_reply(inbuf,outbuf,length,bufsize);
}
