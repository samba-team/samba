/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   
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

/* NTLMSSP mode */
enum NTLMSSP_ROLE
{
	NTLMSSP_SERVER,
	NTLMSSP_CLIENT
};

/* NTLMSSP message types */
enum NTLM_MESSAGE_TYPE
{
	NTLMSSP_NEGOTIATE = 1,
	NTLMSSP_CHALLENGE = 2,
	NTLMSSP_AUTH      = 3,
	NTLMSSP_UNKNOWN   = 4
};

/* NTLMSSP negotiation flags */
#define NTLMSSP_NEGOTIATE_UNICODE          0x00000001
#define NTLMSSP_NEGOTIATE_OEM              0x00000002
#define NTLMSSP_REQUEST_TARGET             0x00000004
#define NTLMSSP_NEGOTIATE_SIGN             0x00000010 /* Message integrity */
#define NTLMSSP_NEGOTIATE_SEAL             0x00000020 /* Message confidentiality */
#define NTLMSSP_NEGOTIATE_DATAGRAM_STYLE   0x00000040
#define NTLMSSP_NEGOTIATE_LM_KEY           0x00000080
#define NTLMSSP_NEGOTIATE_NETWARE          0x00000100
#define NTLMSSP_NEGOTIATE_NTLM             0x00000200
#define NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED  0x00001000
#define NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED 0x00002000
#define NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL  0x00004000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN      0x00008000
#define NTLMSSP_TARGET_TYPE_DOMAIN            0x10000
#define NTLMSSP_TARGET_TYPE_SERVER            0x20000
#define NTLMSSP_CHAL_INIT_RESPONSE         0x00010000

#define NTLMSSP_CHAL_ACCEPT_RESPONSE       0x00020000
#define NTLMSSP_CHAL_NON_NT_SESSION_KEY    0x00040000
#define NTLMSSP_NEGOTIATE_NTLM2            0x00080000
#define NTLMSSP_CHAL_TARGET_INFO           0x00800000
#define NTLMSSP_NEGOTIATE_128              0x20000000 /* 128-bit encryption */
#define NTLMSSP_NEGOTIATE_KEY_EXCH         0x40000000
#define NTLMSSP_NEGOTIATE_080000000        0x80000000

#define NTLMSSP_NAME_TYPE_DOMAIN      0x01
#define NTLMSSP_NAME_TYPE_SERVER      0x02
#define NTLMSSP_NAME_TYPE_DOMAIN_DNS  0x03
#define NTLMSSP_NAME_TYPE_SERVER_DNS  0x04

typedef struct ntlmssp_state 
{
	TALLOC_CTX *mem_ctx;
	enum NTLMSSP_ROLE role;
	BOOL unicode;
	char *user;
	char *domain;
	char *workstation;
 	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
	DATA_BLOB chal;
	void *auth_context;
	const uint8 *(*get_challenge)(struct ntlmssp_state *ntlmssp_state);
	NTSTATUS (*check_password)(struct ntlmssp_state *ntlmssp_state);

	const char *(*get_global_myname)(void);
	const char *(*get_domain)(void);

	int server_role;
	uint32 expected_state;
} NTLMSSP_STATE;

typedef struct ntlmssp_client_state 
{
	TALLOC_CTX *mem_ctx;
	BOOL unicode;
	BOOL use_ntlmv2;
	char *user;
	char *domain;
	char *workstation;
	char *password;

	const char *(*get_global_myname)(void);
	const char *(*get_domain)(void);

	DATA_BLOB session_key;
	
	uint32 neg_flags;

} NTLMSSP_CLIENT_STATE;

