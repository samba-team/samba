/* 
   Unix SMB/CIFS implementation.
   handle SMBsessionsetup
   Copyright (C) Andrew Tridgell 1998-2001
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jim McDonough        2002

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

uint32 global_client_caps = 0;

static struct auth_ntlmssp_state *global_ntlmssp_state;

/*
  on a logon error possibly map the error to success if "map to guest"
  is set approriately
*/
static NTSTATUS do_map_to_guest(NTSTATUS status, auth_serversupplied_info **server_info,
				const char *user, const char *domain)
{
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		if ((lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_USER) || 
		    (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_PASSWORD)) {
			DEBUG(3,("No such user %s [%s] - using guest account\n",
				 user, domain));
			make_server_info_guest(server_info);
			status = NT_STATUS_OK;
		}
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		if (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_PASSWORD) {
			DEBUG(3,("Registered username %s for guest access\n",user));
			make_server_info_guest(server_info);
			status = NT_STATUS_OK;
		}
	}

	return status;
}


/****************************************************************************
 Add the standard 'Samba' signature to the end of the session setup.
****************************************************************************/
static void add_signature(char *outbuf) 
{
	char *p;
	p = smb_buf(outbuf);
	p += srvstr_push(outbuf, p, "Unix", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, "Samba", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, lp_workgroup(), -1, STR_TERMINATE);
	set_message_end(outbuf,p);
}

/****************************************************************************
send a security blob via a session setup reply
****************************************************************************/
static BOOL reply_sesssetup_blob(connection_struct *conn, char *outbuf,
				 DATA_BLOB blob, NTSTATUS nt_status)
{
	char *p;

	set_message(outbuf,4,0,True);

	/* we set NT_STATUS_MORE_PROCESSING_REQUIRED to tell the other end
	   that we aren't finished yet */

	nt_status = nt_status_squash(nt_status);
	SIVAL(outbuf, smb_rcls, NT_STATUS_V(nt_status));
	SSVAL(outbuf, smb_vwv0, 0xFF); /* no chaining possible */
	SSVAL(outbuf, smb_vwv3, blob.length);
	p = smb_buf(outbuf);

	/* should we cap this? */
	memcpy(p, blob.data, blob.length);
	p += blob.length;

	p += srvstr_push(outbuf, p, "Unix", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, "Samba", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, lp_workgroup(), -1, STR_TERMINATE);
	set_message_end(outbuf,p);

	return send_smb(smbd_server_fd(),outbuf);
}

/****************************************************************************
 Do a 'guest' logon, getting back the 
****************************************************************************/
static NTSTATUS check_guest_password(auth_serversupplied_info **server_info) 
{
	struct auth_context *auth_context;
	auth_usersupplied_info *user_info = NULL;
	
	NTSTATUS nt_status;
	unsigned char chal[8];

	ZERO_STRUCT(chal);

	DEBUG(3,("Got anonymous request\n"));

	if (!NT_STATUS_IS_OK(nt_status = make_auth_context_fixed(&auth_context, chal))) {
		return nt_status;
	}

	if (!make_user_info_guest(&user_info)) {
		(auth_context->free)(&auth_context);
		return NT_STATUS_NO_MEMORY;
	}
	
	nt_status = auth_context->check_ntlm_password(auth_context, user_info, server_info);
	(auth_context->free)(&auth_context);
	free_user_info(&user_info);
	return nt_status;
}


#ifdef HAVE_KRB5
/****************************************************************************
reply to a session setup spnego negotiate packet for kerberos
****************************************************************************/
static int reply_spnego_kerberos(connection_struct *conn, 
				 char *inbuf, char *outbuf,
				 int length, int bufsize,
				 DATA_BLOB *secblob)
{
	DATA_BLOB ticket;
	char *client, *p;
	const struct passwd *pw;
	char *user;
	int sess_vuid;
	NTSTATUS ret;
	DATA_BLOB auth_data;
	auth_serversupplied_info *server_info = NULL;
	ADS_STRUCT *ads;
	BOOL foreign = False;

	if (!spnego_parse_krb5_wrap(*secblob, &ticket)) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	ads = ads_init_simple();

	if (!ads) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	ads->auth.realm = strdup(lp_realm());

	ret = ads_verify_ticket(ads, &ticket, &client, &auth_data);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1,("Failed to verify incoming ticket!\n"));	
		ads_destroy(&ads);
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	data_blob_free(&auth_data);

	DEBUG(3,("Ticket name is [%s]\n", client));

	p = strchr_m(client, '@');
	if (!p) {
		DEBUG(3,("Doesn't look like a valid principal\n"));
		ads_destroy(&ads);
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	*p = 0;
	if (strcasecmp(p+1, ads->auth.realm) != 0) {
		DEBUG(3,("Ticket for foreign realm %s@%s\n", client, p+1));
		if (!lp_allow_trusted_domains()) {
			return ERROR_NT(NT_STATUS_LOGON_FAILURE);
		}
		foreign = True;
	}

	/* this gives a fully qualified user name (ie. with full realm).
	   that leads to very long usernames, but what else can we do? */
	asprintf(&user, "%s%s%s", p+1, lp_winbind_separator(), client);
	
	pw = Get_Pwnam(user);
	if (!pw && !foreign) {
		pw = Get_Pwnam(client);
		SAFE_FREE(user);
		user = smb_xstrdup(client);
	}

	ads_destroy(&ads);

	/* setup the string used by %U */
	sub_set_smb_name(user);

	reload_services(True);

	if (!pw) {
		DEBUG(1,("Username %s is invalid on this system\n",user));
		return ERROR_NT(NT_STATUS_NO_SUCH_USER);
	}

	if (!NT_STATUS_IS_OK(ret = make_server_info_pw(&server_info,pw))) {
		DEBUG(1,("make_server_info_from_pw failed!\n"));
		return ERROR_NT(ret);
	}
	
	/* register_vuid keeps the server info */
	sess_vuid = register_vuid(server_info, user);

	free(user);

	if (sess_vuid == -1) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	set_message(outbuf,4,0,True);
	SSVAL(outbuf, smb_vwv3, 0);
	add_signature(outbuf);
 
	SSVAL(outbuf,smb_uid,sess_vuid);
	SSVAL(inbuf,smb_uid,sess_vuid);
	
	return chain_reply(inbuf,outbuf,length,bufsize);
}
#endif


/****************************************************************************
 send a session setup reply, wrapped in SPNEGO.
 get vuid and check first.
 end the NTLMSSP exchange context if we are OK/complete fail
***************************************************************************/
static BOOL reply_spnego_ntlmssp(connection_struct *conn, char *outbuf,
				 AUTH_NTLMSSP_STATE **auth_ntlmssp_state,
				 DATA_BLOB *ntlmssp_blob, NTSTATUS nt_status) 
{
	BOOL ret;
	DATA_BLOB response;
	struct auth_serversupplied_info *server_info;
	server_info = (*auth_ntlmssp_state)->server_info;

	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = do_map_to_guest(nt_status, 
					    &server_info, 
					    (*auth_ntlmssp_state)->ntlmssp_state->user, 
					    (*auth_ntlmssp_state)->ntlmssp_state->domain);
	}

	if (NT_STATUS_IS_OK(nt_status)) {
		int sess_vuid;
		/* register_vuid keeps the server info */
		sess_vuid = register_vuid(server_info, (*auth_ntlmssp_state)->ntlmssp_state->user);
		(*auth_ntlmssp_state)->server_info = NULL;

		if (sess_vuid == -1) {
			nt_status = NT_STATUS_LOGON_FAILURE;
		} else {
			
			set_message(outbuf,4,0,True);
			SSVAL(outbuf, smb_vwv3, 0);
			
			if (server_info->guest) {
				SSVAL(outbuf,smb_vwv2,1);
			}
			
			SSVAL(outbuf,smb_uid,sess_vuid);
		}
	}

        response = spnego_gen_auth_response(ntlmssp_blob, nt_status);
	ret = reply_sesssetup_blob(conn, outbuf, response, nt_status);
	data_blob_free(&response);

	if (!ret || !NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		auth_ntlmssp_end(auth_ntlmssp_state);
	}

	return ret;
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
	DATA_BLOB chal;
	BOOL got_kerberos = False;
	NTSTATUS nt_status;

	/* parse out the OIDs and the first sec blob */
	if (!parse_negTokenTarg(blob1, OIDs, &secblob)) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}
	
	for (i=0;OIDs[i];i++) {
		DEBUG(3,("Got OID %s\n", OIDs[i]));
		if (strcmp(OID_KERBEROS5, OIDs[i]) == 0 ||
		    strcmp(OID_KERBEROS5_OLD, OIDs[i]) == 0) {
			got_kerberos = True;
		}
		free(OIDs[i]);
	}
	DEBUG(3,("Got secblob of size %d\n", secblob.length));

#ifdef HAVE_KRB5
	if (got_kerberos && (SEC_ADS == lp_security())) {
		int ret = reply_spnego_kerberos(conn, inbuf, outbuf, 
						length, bufsize, &secblob);
		data_blob_free(&secblob);
		return ret;
	}
#endif

	if (global_ntlmssp_state) {
		auth_ntlmssp_end(&global_ntlmssp_state);
	}

	nt_status = auth_ntlmssp_start(&global_ntlmssp_state);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ERROR_NT(nt_status);
	}

	nt_status = auth_ntlmssp_update(global_ntlmssp_state, 
					secblob, &chal);

	data_blob_free(&secblob);

	reply_spnego_ntlmssp(conn, outbuf, &global_ntlmssp_state,
			     &chal, nt_status);
		
	data_blob_free(&chal);

	/* already replied */
	return -1;
}

	
/****************************************************************************
reply to a session setup spnego auth packet
****************************************************************************/
static int reply_spnego_auth(connection_struct *conn, char *inbuf, char *outbuf,
			     int length, int bufsize,
			     DATA_BLOB blob1)
{
	DATA_BLOB auth, auth_reply;
	NTSTATUS nt_status;

	if (!spnego_parse_auth(blob1, &auth)) {
#if 0
		file_save("auth.dat", blob1.data, blob1.length);
#endif
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	nt_status = auth_ntlmssp_update(global_ntlmssp_state, 
					  auth, &auth_reply);

	data_blob_free(&auth);

	reply_spnego_ntlmssp(conn, outbuf, &global_ntlmssp_state,
			     &auth_reply, nt_status);
		
	data_blob_free(&auth_reply);

	/* and tell smbd that we have already replied to this packet */
	return -1;
}


/****************************************************************************
reply to a session setup command
****************************************************************************/
static int reply_sesssetup_and_X_spnego(connection_struct *conn, char *inbuf,
					char *outbuf,
					int length,int bufsize)
{
	uint8 *p;
	DATA_BLOB blob1;
	int ret;
	size_t bufrem;

	DEBUG(3,("Doing spnego session setup\n"));

	if (global_client_caps == 0) {
		global_client_caps = IVAL(inbuf,smb_vwv10);
	}
		
	p = (uint8 *)smb_buf(inbuf);

	if (SVAL(inbuf, smb_vwv7) == 0) {
		/* an invalid request */
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	bufrem = smb_bufrem(inbuf, p);
	/* pull the spnego blob */
	blob1 = data_blob(p, MIN(bufrem, SVAL(inbuf, smb_vwv7)));

#if 0
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
	int   smb_bufsize;    
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
	DATA_BLOB plaintext_password;
	fstring user;
	fstring sub_user; /* Sainitised username for substituion */
	fstring domain;
	fstring native_os;
	fstring native_lanman;
	static BOOL done_sesssetup = False;
	extern BOOL global_encrypted_passwords_negotiated;
	extern BOOL global_spnego_negotiated;
	extern int Protocol;
	extern int max_send;

	auth_usersupplied_info *user_info = NULL;
	extern struct auth_context *negprot_global_auth_context;
	auth_serversupplied_info *server_info = NULL;

	NTSTATUS nt_status;

	BOOL doencrypt = global_encrypted_passwords_negotiated;
	
	START_PROFILE(SMBsesssetupX);

	ZERO_STRUCT(lm_resp);
	ZERO_STRUCT(nt_resp);
	ZERO_STRUCT(plaintext_password);

	DEBUG(3,("wct=%d flg2=0x%x\n", CVAL(inbuf, smb_wct), SVAL(inbuf, smb_flg2)));

	/* a SPNEGO session setup has 12 command words, whereas a normal
	   NT1 session setup has 13. See the cifs spec. */
	if (CVAL(inbuf, smb_wct) == 12 &&
	    (SVAL(inbuf, smb_flg2) & FLAGS2_EXTENDED_SECURITY)) {
		if (!global_spnego_negotiated) {
			DEBUG(0,("reply_sesssetup_and_X:  Rejecting attempt at SPNEGO session setup when it was not negoitiated.\n"));
			return ERROR_NT(NT_STATUS_UNSUCCESSFUL);
		}

		return reply_sesssetup_and_X_spnego(conn, inbuf, outbuf, length, bufsize);
	}

	smb_bufsize = SVAL(inbuf,smb_vwv2);

	if (Protocol < PROTOCOL_NT1) {
		uint16 passlen1 = SVAL(inbuf,smb_vwv7);
		if ((passlen1 > MAX_PASS_LEN) || (passlen1 > smb_bufrem(inbuf, smb_buf(inbuf)))) {
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		if (doencrypt) {
			lm_resp = data_blob(smb_buf(inbuf), passlen1);
		} else {
			plaintext_password = data_blob(smb_buf(inbuf), passlen1+1);
			/* Ensure null termination */
			plaintext_password.data[passlen1] = 0;
		}

		srvstr_pull_buf(inbuf, user, smb_buf(inbuf)+passlen1, sizeof(user), STR_TERMINATE);
		*domain = 0;
  
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
		
		/* check for nasty tricks */
		if (passlen1 > MAX_PASS_LEN || passlen1 > smb_bufrem(inbuf, p)) {
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		if (passlen2 > MAX_PASS_LEN || passlen2 > smb_bufrem(inbuf, p+passlen1)) {
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		/* Save the lanman2 password and the NT md4 password. */
		
		if ((doencrypt) && (passlen1 != 0) && (passlen1 != 24)) {
			doencrypt = False;
		}

		if (doencrypt) {
			lm_resp = data_blob(p, passlen1);
			nt_resp = data_blob(p+passlen1, passlen2);
		} else {
			pstring pass;
			srvstr_pull(inbuf, pass, smb_buf(inbuf), 
				    sizeof(pass),  passlen1, STR_TERMINATE);
			plaintext_password = data_blob(pass, strlen(pass)+1);
		}
		
		p += passlen1 + passlen2;
		p += srvstr_pull_buf(inbuf, user, p, sizeof(user), STR_TERMINATE);
		p += srvstr_pull_buf(inbuf, domain, p, sizeof(domain), STR_TERMINATE);
		p += srvstr_pull_buf(inbuf, native_os, p, sizeof(native_os), STR_TERMINATE);
		p += srvstr_pull_buf(inbuf, native_lanman, p, sizeof(native_lanman), STR_TERMINATE);
		DEBUG(3,("Domain=[%s]  NativeOS=[%s] NativeLanMan=[%s]\n",
			 domain,native_os,native_lanman));

		/* 
		 * we distinguish between 2K and XP by the "Native Lan Manager" string
		 *   WinXP => "Windows 2002 5.1"
		 *   Win2k => "Windows 2000 5.0"
		 *   NT4   => "Windows NT 4.0" 
		 *   Win9x => "Windows 4.0"
		 */
		 
		if ( ra_type == RA_WIN2K ) {
			if ( 0 == strcmp( native_lanman, "Windows 2002 5.1" ) )
				set_remote_arch( RA_WINXP );
		}
		

	}
	
	DEBUG(3,("sesssetupX:name=[%s]\\[%s]@[%s]\n", domain, user, get_remote_machine_name()));

	if (*user) {
		if (global_spnego_negotiated) {
			
			/* This has to be here, becouse this is a perfectly valid behaviour for guest logons :-( */
			
			DEBUG(0,("reply_sesssetup_and_X:  Rejecting attempt at 'normal' session setup after negotiating spnego.\n"));
			return ERROR_NT(NT_STATUS_UNSUCCESSFUL);
		}
		fstrcpy(sub_user, user);

		/* setup the string used by %U */
		sub_set_smb_name(user);
	} else {
		fstrcpy(sub_user, lp_guestaccount());
	}

	sub_set_smb_name(sub_user);

	reload_services(True);
	
	if (lp_security() == SEC_SHARE) {
		/* in share level we should ignore any passwords */

		data_blob_free(&lm_resp);
		data_blob_free(&nt_resp);
		data_blob_clear_free(&plaintext_password);

		map_username(sub_user);
		add_session_user(sub_user);
		/* Then force it to null for the benfit of the code below */
		*user = 0;
	}
	
	if (!*user) {

		nt_status = check_guest_password(&server_info);

	} else if (doencrypt) {
		if (!negprot_global_auth_context) {
			DEBUG(0, ("reply_sesssetup_and_X:  Attempted encrypted session setup without negprot denied!\n"));
			return ERROR_NT(NT_STATUS_LOGON_FAILURE);
		}
		nt_status = make_user_info_for_reply_enc(&user_info, user, domain,
		                                         lm_resp, nt_resp);
		if (NT_STATUS_IS_OK(nt_status)) {
			nt_status = negprot_global_auth_context->check_ntlm_password(negprot_global_auth_context, 
										     user_info, 
										     &server_info);
		}
	} else {
		struct auth_context *plaintext_auth_context = NULL;
		const uint8 *chal;
		if (NT_STATUS_IS_OK(nt_status = make_auth_context_subsystem(&plaintext_auth_context))) {
			chal = plaintext_auth_context->get_ntlm_challenge(plaintext_auth_context);
			
			if (!make_user_info_for_reply(&user_info, 
						      user, domain, chal,
						      plaintext_password)) {
				nt_status = NT_STATUS_NO_MEMORY;
			}
		
			if (NT_STATUS_IS_OK(nt_status)) {
				nt_status = plaintext_auth_context->check_ntlm_password(plaintext_auth_context, 
											user_info, 
											&server_info); 
				
				(plaintext_auth_context->free)(&plaintext_auth_context);
			}
		}
	}

	free_user_info(&user_info);
	
	data_blob_free(&lm_resp);
	data_blob_free(&nt_resp);
	data_blob_clear_free(&plaintext_password);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = do_map_to_guest(nt_status, &server_info, user, domain);
	}
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ERROR_NT(nt_status_squash(nt_status));
	}
	
	/* it's ok - setup a reply */
	set_message(outbuf,3,0,True);
	if (Protocol >= PROTOCOL_NT1) {
		add_signature(outbuf);
		/* perhaps grab OS version here?? */
	}
	
	if (server_info->guest) {
		SSVAL(outbuf,smb_vwv2,1);
	}

	/* register the name and uid as being validated, so further connections
	   to a uid can get through without a password, on the same VC */

	/* register_vuid keeps the server info */
	sess_vuid = register_vuid(server_info, sub_user);
  
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
