/* 
   Unix SMB/CIFS implementation.
   negprot reply code
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

/* initialise the auth_context for this server and return the cryptkey */
static void get_challenge(struct smbsrv_connection *smb_conn, char buff[8]) 
{
	NTSTATUS nt_status;
	const uint8_t *cryptkey;

	/* muliple negprots are not premitted */
	if (smb_conn->negotiate.auth_context) {
		DEBUG(3,("get challenge: is this a secondary negprot?  auth_context is non-NULL!\n"));
		smb_panic("secondary negprot");
	}

	DEBUG(10, ("get challenge: creating negprot_global_auth_context\n"));

	nt_status = make_auth_context_subsystem(&smb_conn->negotiate.auth_context);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("make_auth_context_subsystem returned %s", nt_errstr(nt_status)));
		smb_panic("cannot make_negprot_global_auth_context!\n");
	}

	DEBUG(10, ("get challenge: getting challenge\n"));
	cryptkey = smb_conn->negotiate.auth_context->get_ntlm_challenge(smb_conn->negotiate.auth_context);
	memcpy(buff, cryptkey, 8);
}

/****************************************************************************
 Reply for the core protocol.
****************************************************************************/
static void reply_corep(struct smbsrv_request *req, uint16_t choice)
{
	req_setup_reply(req, 1, 0);

	SSVAL(req->out.vwv, VWV(0), choice);

	req->smb_conn->negotiate.protocol = PROTOCOL_CORE;

	if (req->smb_conn->signing.mandatory_signing) {
		smbsrv_terminate_connection(req->smb_conn, 
					    "CORE does not support SMB signing, and it is mandetory\n");
	}

	req_send_reply(req);
}

/****************************************************************************
 Reply for the coreplus protocol.
this is quite incomplete - we only fill in a small part of the reply, but as nobody uses
this any more it probably doesn't matter
****************************************************************************/
static void reply_coreplus(struct smbsrv_request *req, uint16_t choice)
{
	uint16_t raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);

	req_setup_reply(req, 13, 0);

	/* Reply, SMBlockread, SMBwritelock supported. */
	SCVAL(req->out.hdr,HDR_FLG,
	      CVAL(req->out.hdr, HDR_FLG) | FLAG_SUPPORT_LOCKREAD);

	SSVAL(req->out.vwv, VWV(0), choice);
	SSVAL(req->out.vwv, VWV(1), 0x1); /* user level security, don't encrypt */	

	/* tell redirector we support
	   readbraw and writebraw (possibly) */
	SSVAL(req->out.vwv, VWV(5), raw); 

	req->smb_conn->negotiate.protocol = PROTOCOL_COREPLUS;

	if (req->smb_conn->signing.mandatory_signing) {
		smbsrv_terminate_connection(req->smb_conn, 
					    "COREPLUS does not support SMB signing, and it is mandetory\n");
	}

	req_send_reply(req);
}

/****************************************************************************
 Reply for the lanman 1.0 protocol.
****************************************************************************/
static void reply_lanman1(struct smbsrv_request *req, uint16_t choice)
{
	int raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);
	int secword=0;
	time_t t = req->request_time.tv_sec;

	req->smb_conn->negotiate.encrypted_passwords = lp_encrypted_passwords();

	if (lp_security() != SEC_SHARE)
		secword |= NEGOTIATE_SECURITY_USER_LEVEL;

	if (req->smb_conn->negotiate.encrypted_passwords)
		secword |= NEGOTIATE_SECURITY_CHALLENGE_RESPONSE;

	req->smb_conn->negotiate.protocol = PROTOCOL_LANMAN1;

	req_setup_reply(req, 13, req->smb_conn->negotiate.encrypted_passwords ? 8 : 0);

	/* SMBlockread, SMBwritelock supported. */
	SCVAL(req->out.hdr,HDR_FLG,
	      CVAL(req->out.hdr, HDR_FLG) | FLAG_SUPPORT_LOCKREAD);

	SSVAL(req->out.vwv, VWV(0), choice);
	SSVAL(req->out.vwv, VWV(1), secword); 
	SSVAL(req->out.vwv, VWV(2), req->smb_conn->negotiate.max_recv);
	SSVAL(req->out.vwv, VWV(3), lp_maxmux());
	SSVAL(req->out.vwv, VWV(4), 1);
	SSVAL(req->out.vwv, VWV(5), raw); 
	SIVAL(req->out.vwv, VWV(6), req->smb_conn->pid);
	srv_push_dos_date(req->smb_conn, req->out.vwv, VWV(8), t);
	SSVAL(req->out.vwv, VWV(10), req->smb_conn->negotiate.zone_offset/60);

	/* Create a token value and add it to the outgoing packet. */
	if (req->smb_conn->negotiate.encrypted_passwords) {
		SSVAL(req->out.vwv, VWV(11), 8);
		get_challenge(req->smb_conn, req->out.data);
	}

	if (req->smb_conn->signing.mandatory_signing) {
		smbsrv_terminate_connection(req->smb_conn, 
					    "LANMAN1 does not support SMB signing, and it is mandetory\n");
	}

	req_send_reply(req);	
}

/****************************************************************************
 Reply for the lanman 2.0 protocol.
****************************************************************************/
static void reply_lanman2(struct smbsrv_request *req, uint16_t choice)
{
	int raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);
	int secword=0;
	time_t t = req->request_time.tv_sec;

	req->smb_conn->negotiate.encrypted_passwords = lp_encrypted_passwords();
  
	if (lp_security() != SEC_SHARE)
		secword |= NEGOTIATE_SECURITY_USER_LEVEL;

	if (req->smb_conn->negotiate.encrypted_passwords)
		secword |= NEGOTIATE_SECURITY_CHALLENGE_RESPONSE;

	req->smb_conn->negotiate.protocol = PROTOCOL_LANMAN2;

	req_setup_reply(req, 13, 0);

	SSVAL(req->out.vwv, VWV(0), choice);
	SSVAL(req->out.vwv, VWV(1), secword); 
	SSVAL(req->out.vwv, VWV(2), req->smb_conn->negotiate.max_recv);
	SSVAL(req->out.vwv, VWV(3), lp_maxmux());
	SSVAL(req->out.vwv, VWV(4), 1);
	SSVAL(req->out.vwv, VWV(5), raw); 
	SIVAL(req->out.vwv, VWV(6), req->smb_conn->pid);
	srv_push_dos_date(req->smb_conn, req->out.vwv, VWV(8), t);
	SSVAL(req->out.vwv, VWV(10), req->smb_conn->negotiate.zone_offset/60);

	/* Create a token value and add it to the outgoing packet. */
	if (req->smb_conn->negotiate.encrypted_passwords) {
		SSVAL(req->out.vwv, VWV(11), 8);
		req_grow_data(req, 8);
		get_challenge(req->smb_conn, req->out.data);
	}

	req_push_str(req, NULL, lp_workgroup(), -1, STR_TERMINATE);

	if (req->smb_conn->signing.mandatory_signing) {
		smbsrv_terminate_connection(req->smb_conn, 
					    "LANMAN2 does not support SMB signing, and it is mandetory\n");
	}

	req_send_reply(req);
}

/****************************************************************************
 Reply for the nt protocol.
****************************************************************************/
static void reply_nt1(struct smbsrv_request *req, uint16_t choice)
{
	/* dual names + lock_and_read + nt SMBs + remote API calls */
	int capabilities;
	int secword=0;
	time_t t = req->request_time.tv_sec;
	NTTIME nttime;
	BOOL negotiate_spnego = False;

	unix_to_nt_time(&nttime, t);

	capabilities = 
		CAP_NT_FIND | CAP_LOCK_AND_READ | 
		CAP_LEVEL_II_OPLOCKS | CAP_NT_SMBS | CAP_RPC_REMOTE_APIS;

	req->smb_conn->negotiate.encrypted_passwords = lp_encrypted_passwords();

	/* do spnego in user level security if the client
	   supports it and we can do encrypted passwords */
	
	if (req->smb_conn->negotiate.encrypted_passwords && 
	    (lp_security() != SEC_SHARE) &&
	    lp_use_spnego() &&
	    (req->flags2 & FLAGS2_EXTENDED_SECURITY)) {
		negotiate_spnego = True; 
		capabilities |= CAP_EXTENDED_SECURITY;
	}
	
	if (lp_unix_extensions()) {
		capabilities |= CAP_UNIX;
	}
	
	if (lp_large_readwrite()) {
		capabilities |= CAP_LARGE_READX | CAP_LARGE_WRITEX | CAP_W2K_SMBS;
	}
	
	capabilities |= CAP_LARGE_FILES;

	if (lp_readraw() && lp_writeraw()) {
		capabilities |= CAP_RAW_MODE;
	}
	
	/* allow for disabling unicode */
	if (lp_unicode()) {
		capabilities |= CAP_UNICODE;
	}

	if (lp_nt_status_support()) {
		capabilities |= CAP_STATUS32;
	}
	
	if (lp_host_msdfs()) {
		capabilities |= CAP_DFS;
	}
	
	if (lp_security() != SEC_SHARE) {
		secword |= NEGOTIATE_SECURITY_USER_LEVEL;
	}

	if (req->smb_conn->negotiate.encrypted_passwords) {
		secword |= NEGOTIATE_SECURITY_CHALLENGE_RESPONSE;
	}

	if (req->smb_conn->signing.allow_smb_signing) {
		secword |= NEGOTIATE_SECURITY_SIGNATURES_ENABLED;
	}

	if (req->smb_conn->signing.mandatory_signing) {
		secword |= NEGOTIATE_SECURITY_SIGNATURES_REQUIRED;
	}
	
	req->smb_conn->negotiate.protocol = PROTOCOL_NT1;

	req_setup_reply(req, 17, 0);
	
	SSVAL(req->out.vwv, VWV(0), choice);
	SCVAL(req->out.vwv, VWV(1), secword);

	/* notice the strange +1 on vwv here? That's because
	   this is the one and only SMB packet that is malformed in
	   the specification - all the command words after the secword
	   are offset by 1 byte */
	SSVAL(req->out.vwv+1, VWV(1), lp_maxmux());
	SSVAL(req->out.vwv+1, VWV(2), 1); /* num vcs */
	SIVAL(req->out.vwv+1, VWV(3), req->smb_conn->negotiate.max_recv);
	SIVAL(req->out.vwv+1, VWV(5), 0x10000); /* raw size. full 64k */
	SIVAL(req->out.vwv+1, VWV(7), req->smb_conn->pid); /* session key */
	SIVAL(req->out.vwv+1, VWV(9), capabilities);
	push_nttime(req->out.vwv+1, VWV(11), nttime);
	SSVALS(req->out.vwv+1,VWV(15), req->smb_conn->negotiate.zone_offset/60);
	
	if (!negotiate_spnego) {
		/* Create a token value and add it to the outgoing packet. */
		if (req->smb_conn->negotiate.encrypted_passwords) {
			req_grow_data(req, 8);
			/* note that we do not send a challenge at all if
			   we are using plaintext */
			get_challenge(req->smb_conn, req->out.ptr);
			req->out.ptr += 8;
			SCVAL(req->out.vwv+1, VWV(16), 8);
		}
		req_push_str(req, NULL, lp_workgroup(), -1, STR_UNICODE|STR_TERMINATE|STR_NOALIGN);
		req_push_str(req, NULL, lp_netbios_name(), -1, STR_UNICODE|STR_TERMINATE|STR_NOALIGN);
		DEBUG(3,("not using SPNEGO\n"));
	} else {
		struct gensec_security *gensec_security;
		DATA_BLOB null_data_blob = data_blob(NULL, 0);
		DATA_BLOB blob;
		NTSTATUS nt_status = gensec_server_start(&gensec_security);
		
		if (req->smb_conn->negotiate.auth_context) {
			smbsrv_terminate_connection(req->smb_conn, "reply_nt1: is this a secondary negprot?  auth_context is non-NULL!\n");
			return;
		}

		req->smb_conn->negotiate.auth_context = NULL;
		
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Failed to start GENSEC: %s\n", nt_errstr(nt_status)));
			smbsrv_terminate_connection(req->smb_conn, "Failed to start GENSEC\n");
			return;
		}

		nt_status = gensec_start_mech_by_oid(gensec_security, OID_SPNEGO);
		
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Failed to start SPNEGO: %s\n", nt_errstr(nt_status)));
			smbsrv_terminate_connection(req->smb_conn, "Failed to start SPNEGO\n");
			return;
		}

		nt_status = gensec_update(gensec_security, req, null_data_blob, &blob);

		if (!NT_STATUS_IS_OK(nt_status) && !NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			DEBUG(0, ("Failed to get SPNEGO to give us the first token: %s\n", nt_errstr(nt_status)));
			smbsrv_terminate_connection(req->smb_conn, "Failed to start SPNEGO - no first token\n");
			return;
		}

		req->smb_conn->negotiate.spnego_negotiated = True;
	
		req_grow_data(req, blob.length + 16);
		/* a NOT very random guid */
		memset(req->out.ptr, '\0', 16);
		req->out.ptr += 16;

		memcpy(req->out.ptr, blob.data, blob.length);
		SCVAL(req->out.vwv+1, VWV(16), blob.length + 16);
		req->out.ptr += blob.length;
		DEBUG(3,("using SPNEGO\n"));
	}
	
	req_send_reply_nosign(req);	
}

/* these are the protocol lists used for auto architecture detection:

WinNT 3.51:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [MICROSOFT NETWORKS 1.03]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

Win95:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [MICROSOFT NETWORKS 1.03]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

Win2K:
protocol [PC NETWORK PROGRAM 1.0]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

OS/2:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [LANMAN1.0]
protocol [LM1.2X002]
protocol [LANMAN2.1]
*/

/*
  * Modified to recognize the architecture of the remote machine better.
  *
  * This appears to be the matrix of which protocol is used by which
  * MS product.
       Protocol                       WfWg    Win95   WinNT  Win2K  OS/2
       PC NETWORK PROGRAM 1.0          1       1       1      1      1
       XENIX CORE                                      2             2
       MICROSOFT NETWORKS 3.0          2       2       
       DOS LM1.2X002                   3       3       
       MICROSOFT NETWORKS 1.03                         3
       DOS LANMAN2.1                   4       4       
       LANMAN1.0                                       4      2      3
       Windows for Workgroups 3.1a     5       5       5      3
       LM1.2X002                                       6      4      4
       LANMAN2.1                                       7      5      5
       NT LM 0.12                              6       8      6
  *
  *  tim@fsg.com 09/29/95
  *  Win2K added by matty 17/7/99
  */
  
#define ARCH_WFWG     0x3      /* This is a fudge because WfWg is like Win95 */
#define ARCH_WIN95    0x2
#define ARCH_WINNT    0x4
#define ARCH_WIN2K    0xC      /* Win2K is like NT */
#define ARCH_OS2      0x14     /* Again OS/2 is like NT */
#define ARCH_SAMBA    0x20
 
#define ARCH_ALL      0x3F
 
/* List of supported protocols, most desired first */
static const struct {
	const char *proto_name;
	const char *short_name;
	void (*proto_reply_fn)(struct smbsrv_request *req, uint16_t choice);
	int protocol_level;
} supported_protocols[] = {
	{"NT LANMAN 1.0",           "NT1",      reply_nt1,      PROTOCOL_NT1},
	{"NT LM 0.12",              "NT1",      reply_nt1,      PROTOCOL_NT1},
	{"LM1.2X002",               "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
	{"Samba",                   "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
	{"DOS LM1.2X002",           "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
	{"LANMAN1.0",               "LANMAN1",  reply_lanman1,  PROTOCOL_LANMAN1},
	{"MICROSOFT NETWORKS 3.0",  "LANMAN1",  reply_lanman1,  PROTOCOL_LANMAN1},
	{"MICROSOFT NETWORKS 1.03", "COREPLUS", reply_coreplus, PROTOCOL_COREPLUS},
	{"PC NETWORK PROGRAM 1.0",  "CORE",     reply_corep,    PROTOCOL_CORE}, 
	{NULL,NULL,NULL,0},
};

/****************************************************************************
 Reply to a negprot.
****************************************************************************/

void reply_negprot(struct smbsrv_request *req)
{
	int Index=0;
	int choice = -1;
	int protocol;
	char *p;
	int arch = ARCH_ALL;

	if (req->smb_conn->negotiate.done_negprot) {
		smbsrv_terminate_connection(req->smb_conn, "multiple negprot's are not permitted");
	}
	req->smb_conn->negotiate.done_negprot = True;

	p = req->in.data + 1;

	while (p < req->in.data + req->in.data_size) { 
		Index++;
		DEBUG(3,("Requested protocol [%s]\n",p));
		if (strcmp(p,"Windows for Workgroups 3.1a") == 0)
			arch &= ( ARCH_WFWG | ARCH_WIN95 | ARCH_WINNT | ARCH_WIN2K );
		else if (strcmp(p,"DOS LM1.2X002") == 0)
			arch &= ( ARCH_WFWG | ARCH_WIN95 );
		else if (strcmp(p,"DOS LANMAN2.1") == 0)
			arch &= ( ARCH_WFWG | ARCH_WIN95 );
		else if (strcmp(p,"NT LM 0.12") == 0)
			arch &= ( ARCH_WIN95 | ARCH_WINNT | ARCH_WIN2K );
		else if (strcmp(p,"LANMAN2.1") == 0)
			arch &= ( ARCH_WINNT | ARCH_WIN2K | ARCH_OS2 );
		else if (strcmp(p,"LM1.2X002") == 0)
			arch &= ( ARCH_WINNT | ARCH_WIN2K | ARCH_OS2 );
		else if (strcmp(p,"MICROSOFT NETWORKS 1.03") == 0)
			arch &= ARCH_WINNT;
		else if (strcmp(p,"XENIX CORE") == 0)
			arch &= ( ARCH_WINNT | ARCH_OS2 );
		else if (strcmp(p,"Samba") == 0) {
			arch = ARCH_SAMBA;
			break;
		}
 
		p += strlen(p) + 2;
	}
    
	switch (arch) {
		case ARCH_SAMBA:
			set_remote_arch(req->smb_conn, RA_SAMBA);
			break;
		case ARCH_WFWG:
			set_remote_arch(req->smb_conn, RA_WFWG);
			break;
		case ARCH_WIN95:
			set_remote_arch(req->smb_conn, RA_WIN95);
			break;
		case ARCH_WINNT:
			if (req->flags2==FLAGS2_WIN2K_SIGNATURE)
				set_remote_arch(req->smb_conn, RA_WIN2K);
			else
				set_remote_arch(req->smb_conn, RA_WINNT);
			break;
		case ARCH_WIN2K:
			set_remote_arch(req->smb_conn, RA_WIN2K);
			break;
		case ARCH_OS2:
			set_remote_arch(req->smb_conn, RA_OS2);
			break;
		default:
			set_remote_arch(req->smb_conn, RA_UNKNOWN);
		break;
	}
 
	/* possibly reload - change of architecture */
	reload_services(req->smb_conn, True);      
    
	/* Check for protocols, most desirable first */
	for (protocol = 0; supported_protocols[protocol].proto_name; protocol++) {
		p = req->in.data+1;
		Index = 0;
		if ((supported_protocols[protocol].protocol_level <= lp_maxprotocol()) &&
				(supported_protocols[protocol].protocol_level >= lp_minprotocol()))
			while (p < (req->in.data + req->in.data_size)) { 
				if (strequal(p,supported_protocols[protocol].proto_name))
					choice = Index;
				Index++;
				p += strlen(p) + 2;
			}
		if(choice != -1)
			break;
	}
  
	if(choice != -1) {
		sub_set_remote_proto(supported_protocols[protocol].short_name);
		reload_services(req->smb_conn, True);
		supported_protocols[protocol].proto_reply_fn(req, choice);
		DEBUG(3,("Selected protocol %s\n",supported_protocols[protocol].proto_name));
	} else {
		DEBUG(0,("No protocol supported !\n"));
	}
  
	DEBUG(5,("negprot index=%d\n", choice));
}
