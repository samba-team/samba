/* 
   Unix SMB/CIFS implementation.
   negprot reply code
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Volker Lendecke 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "serverid.h"
#include "auth.h"
#include "messages.h"
#include "smbprofile.h"
#include "auth/gensec/gensec.h"
#include "../libcli/smb/smb_signing.h"

/*
 * MS-CIFS, 2.2.4.52.2 SMB_COM_NEGOTIATE Response:
 * If the server does not support any of the listed dialects, it MUST return a
 * DialectIndex of 0XFFFF
 */
#define NO_PROTOCOL_CHOSEN	0xffff

extern fstring remote_proto;

static void get_challenge(struct smbXsrv_connection *xconn, uint8_t buff[8])
{
	NTSTATUS nt_status;

	/* We might be called more than once, multiple negprots are
	 * permitted */
	if (xconn->smb1.negprot.auth_context) {
		DEBUG(3, ("get challenge: is this a secondary negprot? "
			  "sconn->negprot.auth_context is non-NULL!\n"));
		TALLOC_FREE(xconn->smb1.negprot.auth_context);
	}

	DEBUG(10, ("get challenge: creating negprot_global_auth_context\n"));
	nt_status = make_auth4_context(
		xconn, &xconn->smb1.negprot.auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("make_auth_context_subsystem returned %s",
			  nt_errstr(nt_status)));
		smb_panic("cannot make_negprot_global_auth_context!");
	}
	DEBUG(10, ("get challenge: getting challenge\n"));
	xconn->smb1.negprot.auth_context->get_ntlm_challenge(
		xconn->smb1.negprot.auth_context, buff);
}

/****************************************************************************
 Reply for the lanman 1.0 protocol.
****************************************************************************/

static NTSTATUS reply_lanman1(struct smb_request *req, uint16_t choice)
{
	int secword=0;
	time_t t = time(NULL);
	struct smbXsrv_connection *xconn = req->xconn;
	uint16_t raw;
	NTSTATUS status;

	if (lp_async_smb_echo_handler()) {
		raw = 0;
	} else {
		raw = (lp_read_raw()?1:0) | (lp_write_raw()?2:0);
	}

	xconn->smb1.negprot.encrypted_passwords = lp_encrypt_passwords();

	secword |= NEGOTIATE_SECURITY_USER_LEVEL;
	if (xconn->smb1.negprot.encrypted_passwords) {
		secword |= NEGOTIATE_SECURITY_CHALLENGE_RESPONSE;
	}

	reply_outbuf(req, 13, xconn->smb1.negprot.encrypted_passwords?8:0);

	SSVAL(req->outbuf,smb_vwv0,choice);
	SSVAL(req->outbuf,smb_vwv1,secword);
	/* Create a token value and add it to the outgoing packet. */
	if (xconn->smb1.negprot.encrypted_passwords) {
		get_challenge(xconn, (uint8_t *)smb_buf(req->outbuf));
		SSVAL(req->outbuf,smb_vwv11, 8);
	}

	status = smbXsrv_connection_init_tables(xconn, PROTOCOL_LANMAN1);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return status;
	}

	/* Reply, SMBlockread, SMBwritelock supported. */
	SCVAL(req->outbuf,smb_flg, FLAG_REPLY|FLAG_SUPPORT_LOCKREAD);
	SSVAL(req->outbuf,smb_vwv2, xconn->smb1.negprot.max_recv);
	SSVAL(req->outbuf,smb_vwv3, lp_max_mux()); /* maxmux */
	SSVAL(req->outbuf,smb_vwv4, 1);
	SSVAL(req->outbuf,smb_vwv5, raw); /* tell redirector we support
		readbraw writebraw (possibly) */
	SIVAL(req->outbuf,smb_vwv6, getpid());
	SSVAL(req->outbuf,smb_vwv10, set_server_zone_offset(t)/60);

	srv_put_dos_date((char *)req->outbuf,smb_vwv8,t);

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply for the lanman 2.0 protocol.
****************************************************************************/

static NTSTATUS reply_lanman2(struct smb_request *req, uint16_t choice)
{
	int secword=0;
	time_t t = time(NULL);
	struct smbXsrv_connection *xconn = req->xconn;
	uint16_t raw;
	NTSTATUS status;

	if (lp_async_smb_echo_handler()) {
		raw = 0;
	} else {
		raw = (lp_read_raw()?1:0) | (lp_write_raw()?2:0);
	}

	xconn->smb1.negprot.encrypted_passwords = lp_encrypt_passwords();

	secword |= NEGOTIATE_SECURITY_USER_LEVEL;
	if (xconn->smb1.negprot.encrypted_passwords) {
		secword |= NEGOTIATE_SECURITY_CHALLENGE_RESPONSE;
	}

	reply_outbuf(req, 13, xconn->smb1.negprot.encrypted_passwords?8:0);

	SSVAL(req->outbuf,smb_vwv0, choice);
	SSVAL(req->outbuf,smb_vwv1, secword);
	SIVAL(req->outbuf,smb_vwv6, getpid());

	/* Create a token value and add it to the outgoing packet. */
	if (xconn->smb1.negprot.encrypted_passwords) {
		get_challenge(xconn, (uint8_t *)smb_buf(req->outbuf));
		SSVAL(req->outbuf,smb_vwv11, 8);
	}

	status = smbXsrv_connection_init_tables(xconn, PROTOCOL_LANMAN2);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return status;
	}

	/* Reply, SMBlockread, SMBwritelock supported. */
	SCVAL(req->outbuf,smb_flg,FLAG_REPLY|FLAG_SUPPORT_LOCKREAD);
	SSVAL(req->outbuf,smb_vwv2,xconn->smb1.negprot.max_recv);
	SSVAL(req->outbuf,smb_vwv3,lp_max_mux());
	SSVAL(req->outbuf,smb_vwv4,1);
	SSVAL(req->outbuf,smb_vwv5,raw); /* readbraw and/or writebraw */
	SSVAL(req->outbuf,smb_vwv10, set_server_zone_offset(t)/60);
	srv_put_dos_date((char *)req->outbuf,smb_vwv8,t);
	return NT_STATUS_OK;
}

/****************************************************************************
 Generate the spnego negprot reply blob. Return the number of bytes used.
****************************************************************************/

DATA_BLOB negprot_spnego(TALLOC_CTX *ctx, struct smbXsrv_connection *xconn)
{
	DATA_BLOB blob = data_blob_null;
	DATA_BLOB blob_out = data_blob_null;
	nstring dos_name;
	fstring unix_name;
	NTSTATUS status;
#ifdef DEVELOPER
	size_t slen;
#endif
	struct gensec_security *gensec_security;

	/* See if we can get an SPNEGO blob */
	status = auth_generic_prepare(talloc_tos(),
				      xconn->remote_address,
				      xconn->local_address,
				      "SMB",
				      &gensec_security);

	/*
	 * Despite including it above, there is no need to set a
	 * remote address or similar as we are just interested in the
	 * SPNEGO blob, we never keep this context.
	 */

	if (NT_STATUS_IS_OK(status)) {
		status = gensec_start_mech_by_oid(gensec_security, GENSEC_OID_SPNEGO);
		if (NT_STATUS_IS_OK(status)) {
			status = gensec_update(gensec_security, ctx,
					       data_blob_null, &blob);
			/* If we get the list of OIDs, the 'OK' answer
			 * is NT_STATUS_MORE_PROCESSING_REQUIRED */
			if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
				DEBUG(0, ("Failed to start SPNEGO handler for negprot OID list!\n"));
				blob = data_blob_null;
			}
		}
		TALLOC_FREE(gensec_security);
	}

	xconn->smb1.negprot.spnego = true;

	/* strangely enough, NT does not sent the single OID NTLMSSP when
	   not a ADS member, it sends no OIDs at all

	   OLD COMMENT : "we can't do this until we teach our sesssion setup parser to know
		   about raw NTLMSSP (clients send no ASN.1 wrapping if we do this)"

	   Our sessionsetup code now handles raw NTLMSSP connects, so we can go
	   back to doing what W2K3 does here. This is needed to make PocketPC 2003
	   CIFS connections work with SPNEGO. See bugzilla bugs #1828 and #3133
	   for details. JRA.

	*/

	if (blob.length == 0 || blob.data == NULL) {
		return data_blob_null;
	}

	blob_out = data_blob_talloc(ctx, NULL, 16 + blob.length);
	if (blob_out.data == NULL) {
		data_blob_free(&blob);
		return data_blob_null;
	}

	memset(blob_out.data, '\0', 16);

	checked_strlcpy(unix_name, lp_netbios_name(), sizeof(unix_name));
	(void)strlower_m(unix_name);
	push_ascii_nstring(dos_name, unix_name);
	strlcpy((char *)blob_out.data, dos_name, 17);

#ifdef DEVELOPER
	/* Fix valgrind 'uninitialized bytes' issue. */
	slen = strlen(dos_name);
	if (slen < 16) {
		memset(blob_out.data+slen, '\0', 16 - slen);
	}
#endif

	memcpy(&blob_out.data[16], blob.data, blob.length);

	data_blob_free(&blob);

	return blob_out;
}

/****************************************************************************
 Reply for the nt protocol.
****************************************************************************/

static NTSTATUS reply_nt1(struct smb_request *req, uint16_t choice)
{
	/* dual names + lock_and_read + nt SMBs + remote API calls */
	int capabilities = CAP_NT_FIND|CAP_LOCK_AND_READ|
		CAP_LEVEL_II_OPLOCKS;

	int secword=0;
	bool negotiate_spnego = False;
	struct timespec ts;
	ssize_t ret;
	struct smbXsrv_connection *xconn = req->xconn;
	bool signing_desired = false;
	bool signing_required = false;
	NTSTATUS status;

	xconn->smb1.negprot.encrypted_passwords = lp_encrypt_passwords();

	/* Check the flags field to see if this is Vista.
	   WinXP sets it and Vista does not. But we have to 
	   distinguish from NT which doesn't set it either. */

	if ( (req->flags2 & FLAGS2_EXTENDED_SECURITY) &&
		((req->flags2 & FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED) == 0) )
	{
		if ((get_remote_arch() != RA_SAMBA) &&
				(get_remote_arch() != RA_CIFSFS)) {
			set_remote_arch( RA_VISTA );
		}
	}

	reply_outbuf(req,17,0);

	/* do spnego in user level security if the client
	   supports it and we can do encrypted passwords */

	if (xconn->smb1.negprot.encrypted_passwords &&
	    (req->flags2 & FLAGS2_EXTENDED_SECURITY)) {
		negotiate_spnego = True;
		capabilities |= CAP_EXTENDED_SECURITY;
		add_to_common_flags2(FLAGS2_EXTENDED_SECURITY);
		/* Ensure FLAGS2_EXTENDED_SECURITY gets set in this reply
		   (already partially constructed. */
		SSVAL(req->outbuf, smb_flg2,
		      req->flags2 | FLAGS2_EXTENDED_SECURITY);
	}

	capabilities |= CAP_NT_SMBS|CAP_RPC_REMOTE_APIS;

	if (lp_unicode()) {
		capabilities |= CAP_UNICODE;
	}

	if (lp_unix_extensions()) {
		capabilities |= CAP_UNIX;
	}

	if (lp_large_readwrite())
		capabilities |= CAP_LARGE_READX|CAP_LARGE_WRITEX|CAP_W2K_SMBS;

	capabilities |= CAP_LARGE_FILES;

	if (!lp_async_smb_echo_handler() && lp_read_raw() && lp_write_raw())
		capabilities |= CAP_RAW_MODE;

	if (lp_nt_status_support())
		capabilities |= CAP_STATUS32;

	if (lp_host_msdfs())
		capabilities |= CAP_DFS;

	secword |= NEGOTIATE_SECURITY_USER_LEVEL;
	if (xconn->smb1.negprot.encrypted_passwords) {
		secword |= NEGOTIATE_SECURITY_CHALLENGE_RESPONSE;
	}

	signing_desired = smb_signing_is_desired(xconn->smb1.signing_state);
	signing_required = smb_signing_is_mandatory(xconn->smb1.signing_state);

	if (signing_desired) {
		secword |= NEGOTIATE_SECURITY_SIGNATURES_ENABLED;
		/* No raw mode with smb signing. */
		capabilities &= ~CAP_RAW_MODE;
		if (signing_required) {
			secword |=NEGOTIATE_SECURITY_SIGNATURES_REQUIRED;
		}
	}

	SSVAL(req->outbuf,smb_vwv0,choice);
	SCVAL(req->outbuf,smb_vwv1,secword);

	status = smbXsrv_connection_init_tables(xconn, PROTOCOL_NT1);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return status;
	}

	SSVAL(req->outbuf,smb_vwv1+1, lp_max_mux()); /* maxmpx */
	SSVAL(req->outbuf,smb_vwv2+1, 1); /* num vcs */
	SIVAL(req->outbuf,smb_vwv3+1,
	      xconn->smb1.negprot.max_recv); /* max buffer. LOTS! */
	SIVAL(req->outbuf,smb_vwv5+1, 0x10000); /* raw size. full 64k */
	SIVAL(req->outbuf,smb_vwv7+1, getpid()); /* session key */
	SIVAL(req->outbuf,smb_vwv9+1, capabilities); /* capabilities */
	clock_gettime(CLOCK_REALTIME,&ts);
	put_long_date_full_timespec(TIMESTAMP_SET_NT_OR_BETTER,(char *)req->outbuf+smb_vwv11+1,&ts);
	SSVALS(req->outbuf,smb_vwv15+1,set_server_zone_offset(ts.tv_sec)/60);

	if (!negotiate_spnego) {
		/* Create a token value and add it to the outgoing packet. */
		if (xconn->smb1.negprot.encrypted_passwords) {
			uint8_t chal[8];
			/* note that we do not send a challenge at all if
			   we are using plaintext */
			get_challenge(xconn, chal);
			ret = message_push_blob(
				&req->outbuf, data_blob_const(chal, sizeof(chal)));
			if (ret == -1) {
				DEBUG(0, ("Could not push challenge\n"));
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				return NT_STATUS_NO_MEMORY;
			}
			SCVAL(req->outbuf, smb_vwv16+1, ret);
		}
		ret = message_push_string(&req->outbuf, lp_workgroup(),
					  STR_UNICODE|STR_TERMINATE
					  |STR_NOALIGN);
		if (ret == -1) {
			DEBUG(0, ("Could not push workgroup string\n"));
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			return NT_STATUS_NO_MEMORY;
		}
		ret = message_push_string(&req->outbuf, lp_netbios_name(),
					  STR_UNICODE|STR_TERMINATE
					  |STR_NOALIGN);
		if (ret == -1) {
			DEBUG(0, ("Could not push netbios name string\n"));
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(3,("not using SPNEGO\n"));
	} else {
		DATA_BLOB spnego_blob = negprot_spnego(req, xconn);

		if (spnego_blob.data == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			return NT_STATUS_NO_MEMORY;
		}

		ret = message_push_blob(&req->outbuf, spnego_blob);
		if (ret == -1) {
			DEBUG(0, ("Could not push spnego blob\n"));
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			return NT_STATUS_NO_MEMORY;
		}
		data_blob_free(&spnego_blob);

		SCVAL(req->outbuf,smb_vwv16+1, 0);
		DEBUG(3,("using SPNEGO\n"));
	}

	return NT_STATUS_OK;
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

Vista:
protocol [PC NETWORK PROGRAM 1.0]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]
protocol [SMB 2.001]

OS/2:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [LANMAN1.0]
protocol [LM1.2X002]
protocol [LANMAN2.1]

OSX:
protocol [NT LM 0.12]
protocol [SMB 2.002]
protocol [SMB 2.???]
*/

/*
  * Modified to recognize the architecture of the remote machine better.
  *
  * This appears to be the matrix of which protocol is used by which
  * product.
       Protocol                       WfWg Win95 WinNT Win2K OS/2 Vista OSX
       PC NETWORK PROGRAM 1.0          1     1     1     1     1    1
       XENIX CORE                                  2           2
       MICROSOFT NETWORKS 3.0          2     2
       DOS LM1.2X002                   3     3
       MICROSOFT NETWORKS 1.03                     3
       DOS LANMAN2.1                   4     4
       LANMAN1.0                                   4     2     3    2
       Windows for Workgroups 3.1a     5     5     5     3          3
       LM1.2X002                                   6     4     4    4
       LANMAN2.1                                   7     5     5    5
       NT LM 0.12                            6     8     6     6    6    1
       SMB 2.001                                                    7
       SMB 2.002                                                         2
       SMB 2.???                                                         3
  *
  *  tim@fsg.com 09/29/95
  *  Win2K added by matty 17/7/99
  */

#define PROT_PC_NETWORK_PROGRAM_1_0		0x0001
#define PROT_XENIX_CORE				0x0002
#define PROT_MICROSOFT_NETWORKS_3_0		0x0004
#define PROT_DOS_LM1_2X002			0x0008
#define PROT_MICROSOFT_NETWORKS_1_03		0x0010
#define PROT_DOS_LANMAN2_1			0x0020
#define PROT_LANMAN1_0				0x0040
#define PROT_WFWG				0x0080
#define PROT_LM1_2X002				0x0100
#define PROT_LANMAN2_1				0x0200
#define PROT_NT_LM_0_12				0x0400
#define PROT_SMB_2_001				0x0800
#define PROT_SMB_2_002				0x1000
#define PROT_SMB_2_FF				0x2000
#define PROT_SAMBA				0x4000
#define PROT_POSIX_2				0x8000

#define ARCH_WFWG     ( PROT_PC_NETWORK_PROGRAM_1_0 | PROT_MICROSOFT_NETWORKS_3_0 | \
			PROT_DOS_LM1_2X002 | PROT_DOS_LANMAN2_1 | PROT_WFWG )
#define ARCH_WIN95    ( ARCH_WFWG | PROT_NT_LM_0_12 )
#define ARCH_WINNT    ( PROT_PC_NETWORK_PROGRAM_1_0 | PROT_XENIX_CORE | \
			PROT_MICROSOFT_NETWORKS_1_03 | PROT_LANMAN1_0 | PROT_WFWG | \
			PROT_LM1_2X002 | PROT_LANMAN2_1 | PROT_NT_LM_0_12 )
#define ARCH_WIN2K    ( ARCH_WINNT & ~(PROT_XENIX_CORE | PROT_MICROSOFT_NETWORKS_1_03) )
#define ARCH_OS2      ( ARCH_WINNT & ~(PROT_MICROSOFT_NETWORKS_1_03 | PROT_WFWG) )
#define ARCH_VISTA    ( ARCH_WIN2K | PROT_SMB_2_001 )
#define ARCH_SAMBA    ( PROT_SAMBA )
#define ARCH_CIFSFS   ( PROT_POSIX_2 )
#define ARCH_OSX      ( PROT_NT_LM_0_12 | PROT_SMB_2_002 | PROT_SMB_2_FF )

/* List of supported protocols, most desired first */
static const struct {
	const char *proto_name;
	const char *short_name;
	NTSTATUS (*proto_reply_fn)(struct smb_request *req, uint16_t choice);
	int protocol_level;
} supported_protocols[] = {
	{"SMB 2.???",               "SMB2_FF",  reply_smb20ff,  PROTOCOL_SMB2_10},
	{"SMB 2.002",               "SMB2_02",  reply_smb2002,  PROTOCOL_SMB2_02},
	{"NT LANMAN 1.0",           "NT1",      reply_nt1,      PROTOCOL_NT1},
	{"NT LM 0.12",              "NT1",      reply_nt1,      PROTOCOL_NT1},
	{"POSIX 2",                 "NT1",      reply_nt1,      PROTOCOL_NT1},
	{"LANMAN2.1",               "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
	{"LM1.2X002",               "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
	{"Samba",                   "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
	{"DOS LM1.2X002",           "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
	{"LANMAN1.0",               "LANMAN1",  reply_lanman1,  PROTOCOL_LANMAN1},
	{"MICROSOFT NETWORKS 3.0",  "LANMAN1",  reply_lanman1,  PROTOCOL_LANMAN1},
	{NULL,NULL,NULL,0},
};

/****************************************************************************
 Reply to a negprot.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_negprot(struct smb_request *req)
{
	size_t choice = 0;
	int chosen_level = -1;
	bool choice_set = false;
	int protocol;
	const char *p;
	int protocols = 0;
	int num_cliprotos;
	char **cliprotos;
	size_t i;
	size_t converted_size;
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_server_connection *sconn = req->sconn;
	bool signing_required = true;
	int max_proto;
	int min_proto;
	NTSTATUS status;

	START_PROFILE(SMBnegprot);

	if (xconn->smb1.negprot.done) {
		END_PROFILE(SMBnegprot);
		exit_server_cleanly("multiple negprot's are not permitted");
	}

	if (req->buflen == 0) {
		DEBUG(0, ("negprot got no protocols\n"));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBnegprot);
		return;
	}

	if (req->buf[req->buflen-1] != '\0') {
		DEBUG(0, ("negprot protocols not 0-terminated\n"));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBnegprot);
		return;
	}

	p = (const char *)req->buf + 1;

	num_cliprotos = 0;
	cliprotos = NULL;

	while (smbreq_bufrem(req, p) > 0) {

		char **tmp;

		tmp = talloc_realloc(talloc_tos(), cliprotos, char *,
					   num_cliprotos+1);
		if (tmp == NULL) {
			DEBUG(0, ("talloc failed\n"));
			TALLOC_FREE(cliprotos);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBnegprot);
			return;
		}

		cliprotos = tmp;

		if (!pull_ascii_talloc(cliprotos, &cliprotos[num_cliprotos], p,
				       &converted_size)) {
			DEBUG(0, ("pull_ascii_talloc failed\n"));
			TALLOC_FREE(cliprotos);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBnegprot);
			return;
		}

		DEBUG(3, ("Requested protocol [%s]\n",
			  cliprotos[num_cliprotos]));

		num_cliprotos += 1;
		p += strlen(p) + 2;
	}

	for (i=0; i<num_cliprotos; i++) {
		if (strcsequal(cliprotos[i], "Windows for Workgroups 3.1a")) {
			protocols |= PROT_WFWG;
		} else if (strcsequal(cliprotos[i], "DOS LM1.2X002")) {
			protocols |= PROT_DOS_LM1_2X002;
		} else if (strcsequal(cliprotos[i], "DOS LANMAN2.1")) {
			protocols |= PROT_DOS_LANMAN2_1;
		} else if (strcsequal(cliprotos[i], "LANMAN1.0")) {
			protocols |= PROT_LANMAN1_0;
		} else if (strcsequal(cliprotos[i], "NT LM 0.12")) {
			protocols |= PROT_NT_LM_0_12;
		} else if (strcsequal(cliprotos[i], "SMB 2.001")) {
			protocols |= PROT_SMB_2_001;
		} else if (strcsequal(cliprotos[i], "SMB 2.002")) {
			protocols |= PROT_SMB_2_002;
		} else if (strcsequal(cliprotos[i], "SMB 2.???")) {
			protocols |= PROT_SMB_2_FF;
		} else if (strcsequal(cliprotos[i], "LANMAN2.1")) {
			protocols |= PROT_LANMAN2_1;
		} else if (strcsequal(cliprotos[i], "LM1.2X002")) {
			protocols |= PROT_LM1_2X002;
		} else if (strcsequal(cliprotos[i], "MICROSOFT NETWORKS 1.03")) {
			protocols |= PROT_MICROSOFT_NETWORKS_1_03;
		} else if (strcsequal(cliprotos[i], "MICROSOFT NETWORKS 3.0")) {
			protocols |= PROT_MICROSOFT_NETWORKS_3_0;
		} else if (strcsequal(cliprotos[i], "PC NETWORK PROGRAM 1.0")) {
			protocols |= PROT_PC_NETWORK_PROGRAM_1_0;
		} else if (strcsequal(cliprotos[i], "XENIX CORE")) {
			protocols |= PROT_XENIX_CORE;
		} else if (strcsequal(cliprotos[i], "Samba")) {
			protocols = PROT_SAMBA;
			break;
		} else if (strcsequal(cliprotos[i], "POSIX 2")) {
			protocols = PROT_POSIX_2;
			break;
		}
	}

	switch ( protocols ) {
		/* Old CIFSFS can send one arch only, NT LM 0.12. */
		case PROT_NT_LM_0_12:
		case ARCH_CIFSFS:
			set_remote_arch(RA_CIFSFS);
			break;
		case ARCH_SAMBA:
			set_remote_arch(RA_SAMBA);
			break;
		case ARCH_WFWG:
			set_remote_arch(RA_WFWG);
			break;
		case ARCH_WIN95:
			set_remote_arch(RA_WIN95);
			break;
		case ARCH_WINNT:
			set_remote_arch(RA_WINNT);
			break;
		case ARCH_WIN2K:
			set_remote_arch(RA_WIN2K);
			break;
		case ARCH_VISTA:
			set_remote_arch(RA_VISTA);
			break;
		case ARCH_OS2:
			set_remote_arch(RA_OS2);
			break;
		case ARCH_OSX:
			set_remote_arch(RA_OSX);
			break;
		default:
			set_remote_arch(RA_UNKNOWN);
		break;
	}

	/* possibly reload - change of architecture */
	reload_services(sconn, conn_snum_used, true);

	/*
	 * Anything higher than PROTOCOL_SMB2_10 still
	 * needs to go via "SMB 2.???", which is marked
	 * as PROTOCOL_SMB2_10.
	 *
	 * The real negotiation happens via reply_smb20ff()
	 * using SMB2 Negotiation.
	 */
	max_proto = lp_server_max_protocol();
	if (max_proto > PROTOCOL_SMB2_10) {
		max_proto = PROTOCOL_SMB2_10;
	}
	min_proto = lp_server_min_protocol();
	if (min_proto > PROTOCOL_SMB2_10) {
		min_proto = PROTOCOL_SMB2_10;
	}

	/* Check for protocols, most desirable first */
	for (protocol = 0; supported_protocols[protocol].proto_name; protocol++) {
		i = 0;
		if ((supported_protocols[protocol].protocol_level <= max_proto) &&
		    (supported_protocols[protocol].protocol_level >= min_proto))
			while (i < num_cliprotos) {
				if (strequal(cliprotos[i],supported_protocols[protocol].proto_name)) {
					choice = i;
					chosen_level = supported_protocols[protocol].protocol_level;
					choice_set = true;
				}
				i++;
			}
		if (choice_set) {
			break;
		}
	}

	if (!choice_set) {
		bool ok;

		DBG_NOTICE("No protocol supported !\n");
		reply_outbuf(req, 1, 0);
		SSVAL(req->outbuf, smb_vwv0, NO_PROTOCOL_CHOSEN);

		ok = srv_send_smb(xconn, (char *)req->outbuf,
				  false, 0, false, NULL);
		if (!ok) {
			DBG_NOTICE("srv_send_smb failed\n");
		}
		exit_server_cleanly("no protocol supported\n");
	}

	fstrcpy(remote_proto,supported_protocols[protocol].short_name);
	reload_services(sconn, conn_snum_used, true);
	status = supported_protocols[protocol].proto_reply_fn(req, choice);
	if (!NT_STATUS_IS_OK(status)) {
		exit_server_cleanly("negprot function failed\n");
	}

	DEBUG(3,("Selected protocol %s\n",supported_protocols[protocol].proto_name));

	DBG_INFO("negprot index=%zu\n", choice);

	xconn->smb1.negprot.done = true;

	/* We always have xconn->smb1.signing_state also for >= SMB2_02 */
	signing_required = smb_signing_is_mandatory(xconn->smb1.signing_state);
	if (signing_required && (chosen_level < PROTOCOL_NT1)) {
		exit_server_cleanly("SMB signing is required and "
			"client negotiated a downlevel protocol");
	}

	TALLOC_FREE(cliprotos);

	if (lp_async_smb_echo_handler() && (chosen_level < PROTOCOL_SMB2_02) &&
	    !fork_echo_handler(xconn)) {
		exit_server("Failed to fork echo handler");
	}

	END_PROFILE(SMBnegprot);
	return;
}
