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

#if HAVE_KRB5
/****************************************************************************
reply to a session setup spnego negotiate packet for kerberos
****************************************************************************/
static int reply_spnego_kerberos(connection_struct *conn, 
				 char *inbuf, char *outbuf,
				 int length, int bufsize,
				 DATA_BLOB *secblob)
{
	DATA_BLOB ticket;
	krb5_context context;
	krb5_principal server;
	krb5_auth_context auth_context = NULL;
	krb5_keytab keytab = NULL;
	krb5_data packet;
	krb5_ticket *tkt = NULL;
	int ret;
	char *realm, *client, *p;
	fstring service;
	extern pstring global_myname;
	const struct passwd *pw;
	char *user;
	gid_t gid;
	uid_t uid;
	char *full_name;
	int sess_vuid;

	realm = lp_realm();

	if (!spnego_parse_krb5_wrap(*secblob, &ticket)) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	/* the service is the wins name lowercase with $ tacked on */
	fstrcpy(service, global_myname);
	strlower(service);
	fstrcat(service, "$");

	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("krb5_init_context failed (%s)\n", error_message(ret)));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	ret = krb5_build_principal(context, &server, strlen(realm),
				   realm, service, NULL);
	if (ret) {
		DEBUG(1,("krb5_build_principal failed (%s)\n", error_message(ret)));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	packet.length = ticket.length;
	packet.data = (krb5_pointer)ticket.data;

	if ((ret = krb5_rd_req(context, &auth_context, &packet, 
				       server, keytab, NULL, &tkt))) {
		DEBUG(3,("krb5_rd_req failed (%s)\n", 
			 error_message(ret)));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	if ((ret = krb5_unparse_name(context, tkt->enc_part2->client,
				     &client))) {
		DEBUG(3,("krb5_unparse_name failed (%s)\n", 
			 error_message(ret)));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	DEBUG(3,("Ticket name is [%s]\n", client));

	p = strchr_m(client, '@');
	if (!p) {
		DEBUG(3,("Doesn't look like a valid principle\n"));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	*p = 0;
	if (strcasecmp(p+1, realm) != 0) {
		DEBUG(3,("Ticket for incorrect realm %s\n", p+1));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}
	
	user = client;

	/* the password is good - let them in */
	pw = smb_getpwnam(user,False);
	if (!pw) {
		DEBUG(1,("Username %s is invalid on this system\n",user));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}
	gid = pw->pw_gid;
	uid = pw->pw_uid;
	full_name = pw->pw_gecos;
	
	sess_vuid = register_vuid(uid,gid,user,user,realm,False, full_name);

	if (sess_vuid == -1) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	set_message(outbuf,4,0,True);
	SSVAL(outbuf, smb_vwv3, 0);
	p = smb_buf(outbuf);
	p += srvstr_push(outbuf, p, "Unix", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, "Samba", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, lp_workgroup(), -1, STR_TERMINATE);
	set_message_end(outbuf,p);
 
	SSVAL(outbuf,smb_uid,sess_vuid);
	SSVAL(inbuf,smb_uid,sess_vuid);
	
	return chain_reply(inbuf,outbuf,length,bufsize);
}
#endif


/****************************************************************************
send a security blob via a session setup reply
****************************************************************************/
static BOOL reply_sesssetup_blob(connection_struct *conn, char *outbuf,
				 DATA_BLOB blob)
{
	char *p;

	set_message(outbuf,4,0,True);

	/* we set NT_STATUS_MORE_PROCESSING_REQUIRED to tell the other end
	   that we aren't finished yet */

	SIVAL(outbuf, smb_rcls, NT_STATUS_V(NT_STATUS_MORE_PROCESSING_REQUIRED));
	SSVAL(outbuf, smb_vwv0, 0xFF); /* no chaining possible */
	SSVAL(outbuf, smb_vwv3, blob.length);
	p = smb_buf(outbuf);
	memcpy(p, blob.data, blob.length);
	p += blob.length;
	p += srvstr_push(outbuf, p, "Unix", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, "Samba", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, lp_workgroup(), -1, STR_TERMINATE);
	set_message_end(outbuf,p);
	
	return send_smb(smbd_server_fd(),outbuf);
}

/****************************************************************************
reply to a session setup spnego negotiate packet
****************************************************************************/
static int reply_spnego_negotiate(connection_struct *conn, 
				  char *inbuf,
				  char *outbuf,
				  int length, int bufsize,
				  DATA_BLOB blob1)
{
	char *OIDs[ASN1_MAX_OIDS];
	DATA_BLOB secblob;
	int i;
	uint32 ntlmssp_command, neg_flags;
	DATA_BLOB sess_key, chal, spnego_chal;
	uint8 cryptkey[8];
	BOOL got_kerberos = False;

	/* parse out the OIDs and the first sec blob */
	if (!parse_negTokenTarg(blob1, OIDs, &secblob)) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}
	
	for (i=0;OIDs[i];i++) {
		DEBUG(3,("Got OID %s\n", OIDs[i]));
		if (strcmp(OID_KERBEROS5_OLD, OIDs[i]) == 0) {
			got_kerberos = True;
		}
		free(OIDs[i]);
	}
	DEBUG(3,("Got secblob of size %d\n", secblob.length));

#if HAVE_KRB5
	if (got_kerberos) {
		int ret = reply_spnego_kerberos(conn, inbuf, outbuf, 
						length, bufsize, &secblob);
		data_blob_free(&secblob);
		return ret;
	}
#endif

	/* parse the NTLMSSP packet */
#if 0
	file_save("secblob.dat", secblob.data, secblob.length);
#endif

	if (!msrpc_parse(&secblob, "CddB",
			 "NTLMSSP",
			 &ntlmssp_command,
			 &neg_flags,
			 &sess_key)) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	data_blob_free(&secblob);
	data_blob_free(&sess_key);

	if (ntlmssp_command != NTLMSSP_NEGOTIATE) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	DEBUG(3,("Got neg_flags=%08x\n", neg_flags));

	if (!last_challenge(cryptkey)) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	/* Give them the challenge. For now, ignore neg_flags and just
	   return the flags we want. Obviously this is not correct */
	
	neg_flags = NTLMSSP_NEGOTIATE_UNICODE | 
		NTLMSSP_NEGOTIATE_LM_KEY | 
		NTLMSSP_NEGOTIATE_NTLM;

	msrpc_gen(&chal, "Cddddbdddd",
		  "NTLMSSP", 
		  NTLMSSP_CHALLENGE,
		  0,
		  0x30, /* ?? */
		  neg_flags,
		  cryptkey, 8,
		  0, 0, 0,
		  0x3000); /* ?? */

	if (!spnego_gen_challenge(&spnego_chal, &chal, &chal)) {
		DEBUG(3,("Failed to generate challenge\n"));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	/* now tell the client to send the auth packet */
	reply_sesssetup_blob(conn, outbuf, spnego_chal);

	data_blob_free(&chal);
	data_blob_free(&spnego_chal);

	/* and tell smbd that we have already replied to this packet */
	return -1;
}

	
/****************************************************************************
reply to a session setup spnego auth packet
****************************************************************************/
static int reply_spnego_auth(connection_struct *conn, char *inbuf, char *outbuf,
			     int length, int bufsize,
			     DATA_BLOB blob1)
{
	DATA_BLOB auth;
	char *workgroup, *user, *machine;
	DATA_BLOB lmhash, nthash, sess_key;
	uint32 ntlmssp_command, neg_flags;
	NTSTATUS nt_status;
	int sess_vuid;
	gid_t gid;
	uid_t uid;
	char *full_name;
	char *p;
	const struct passwd *pw;

	if (!spnego_parse_auth(blob1, &auth)) {
#if 0
		file_save("auth.dat", blob1.data, blob1.length);
#endif
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	/* now the NTLMSSP encoded auth hashes */
	if (!msrpc_parse(&auth, "CdBBUUUBd", 
			 "NTLMSSP", 
			 &ntlmssp_command, 
			 &lmhash,
			 &nthash,
			 &workgroup, 
			 &user, 
			 &machine,
			 &sess_key,
			 &neg_flags)) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	data_blob_free(&auth);
	data_blob_free(&sess_key);
	
	DEBUG(3,("Got user=[%s] workgroup=[%s] machine=[%s] len1=%d len2=%d\n",
		 user, workgroup, machine, lmhash.length, nthash.length));

#if 0
	file_save("nthash1.dat", nthash.data, nthash.length);
	file_save("lmhash1.dat", lmhash.data, lmhash.length);
#endif

	nt_status = pass_check_smb(user, user, 
				   workgroup, machine,
				   lmhash.data,
				   lmhash.length,
				   nthash.data,
				   nthash.length);

	data_blob_free(&nthash);
	data_blob_free(&lmhash);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return ERROR_NT(nt_status);
	}

	/* the password is good - let them in */
	pw = smb_getpwnam(user,False);
	if (!pw) {
		DEBUG(1,("Username %s is invalid on this system\n",user));
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}
	gid = pw->pw_gid;
	uid = pw->pw_uid;
	full_name = pw->pw_gecos;

	sess_vuid = register_vuid(uid,gid,user,user,workgroup,False, full_name);

	free(user);
	free(workgroup);
	free(machine);
	
	if (sess_vuid == -1) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	set_message(outbuf,4,0,True);
	SSVAL(outbuf, smb_vwv3, 0);
	p = smb_buf(outbuf);
	p += srvstr_push(outbuf, p, "Unix", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, "Samba", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, lp_workgroup(), -1, STR_TERMINATE);
	set_message_end(outbuf,p);
 
	SSVAL(outbuf,smb_uid,sess_vuid);
	SSVAL(inbuf,smb_uid,sess_vuid);
	
	return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
reply to a session setup command
****************************************************************************/
static int reply_sesssetup_and_X_spnego(connection_struct *conn, char *inbuf,char *outbuf,
					int length,int bufsize)
{
	uint8 *p;
	DATA_BLOB blob1;
	extern uint32 global_client_caps;
	int ret;

	if (global_client_caps == 0) {
		global_client_caps = IVAL(inbuf,smb_vwv10);
	}
		
	p = smb_buf(inbuf);

	/* pull the spnego blob */
	blob1 = data_blob(p, SVAL(inbuf, smb_vwv7));
	
#if 0
	chdir("/home/tridge");
	file_save("negotiate.dat", blob1.data, blob1.length);
#endif

	if (blob1.data[0] == ASN1_APPLICATION(0)) {
		/* its a negTokenTarg packet */
		ret = reply_spnego_negotiate(conn, inbuf, outbuf, length, bufsize, blob1);
		data_blob_free(&blob1);
		return ret;
	}

	if (blob1.data[0] == ASN1_CONTEXT(1)) {
		/* its a auth packet */
		ret = reply_spnego_auth(conn, inbuf, outbuf, length, bufsize, blob1);
		data_blob_free(&blob1);
		return ret;
	}

	/* what sort of packet is this? */
	DEBUG(1,("Unknown packet in reply_sesssetup_and_X_spnego\n"));

	data_blob_free(&blob1);

	return ERROR_NT(NT_STATUS_LOGON_FAILURE);
}


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
	
	if (SVAL(inbuf, smb_flg2) & FLAGS2_EXTENDED_SECURITY) {
		/* it's a SPNEGO session setup */
		return reply_sesssetup_and_X_spnego(conn, inbuf, outbuf, length, bufsize);
	}

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
