/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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

#ifndef _RPC_NTLMSSP_H /* RPC_NTLMSSP_H */
#define RPC_NTLMSSP_H 

#include "rpc_misc.h" /* this only pulls in STRHDR */

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
#define NTLMSSP_NEGOTIATE_SIGN             0x00000010
#define NTLMSSP_NEGOTIATE_SEAL             0x00000020
#define NTLMSSP_NEGOTIATE_LM_KEY           0x00000080
#define NTLMSSP_NEGOTIATE_00000100         0x00000100
#define NTLMSSP_NEGOTIATE_NTLM             0x00000200
#define NTLMSSP_NEGOTIATE_00000400         0x00000400
#define NTLMSSP_NEGOTIATE_00001000         0x00001000
#define NTLMSSP_NEGOTIATE_00002000         0x00002000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN      0x00008000
#define NTLMSSP_NEGOTIATE_NTLM2            0x00080000
#define NTLMSSP_NEGOTIATE_TARGET_INFO      0x00800000
#define NTLMSSP_NEGOTIATE_128              0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH         0x40000000

/* NTLMSSP signature version */
#define NTLMSSP_SIGN_VERSION 0x01

/* this is TEMPORARILY coded up as a specific structure */
/* this structure comes after the bind request */
/* RPC_AUTH_NTLMSSP_NEG */
typedef struct rpc_auth_ntlmssp_neg_info
{
	uint32  neg_flgs; /* 0x0000 b2b3 */

	STRHDR hdr_myname; /* offset is against START of this structure */
	STRHDR hdr_domain; /* offset is against START of this structure */

	fstring myname; /* calling workstation's name */
	fstring domain; /* calling workstations's domain */

} RPC_AUTH_NTLMSSP_NEG;

/* this is TEMPORARILY coded up as a specific structure */
/* this structure comes after the bind acknowledgement */
/* RPC_AUTH_NTLMSSP_CHAL */
typedef struct rpc_auth_ntlmssp_chal_info
{
	uint32 unknown_1; /* 0x0000 0000 */
	uint32 unknown_2; /* 0x0000 0028 */
	uint32 neg_flags; /* 0x0000 82b1 */

	uint8 challenge[8]; /* ntlm challenge */
	uint8 reserved [8]; /* zeros */

} RPC_AUTH_NTLMSSP_CHAL;


/* RPC_AUTH_NTLMSSP_RESP */
typedef struct rpc_auth_ntlmssp_resp_info
{
	STRHDR hdr_lm_resp; /* LM response (NULL or 24 bytes) */
	STRHDR hdr_nt_resp; /* NT response (NULL, 24 or variable-length) */
	STRHDR hdr_domain;
	STRHDR hdr_usr;
	STRHDR hdr_wks;
	STRHDR hdr_sess_key; /* NULL unless negotiated */
	uint32 neg_flags; /* 0x0000 82b1 */

	fstring sess_key;
	fstring wks;
	fstring user;
	fstring domain;
	fstring nt_resp;
	fstring lm_resp;

} RPC_AUTH_NTLMSSP_RESP;


/* attached to the end of encrypted rpc requests and responses */
/* RPC_AUTH_NTLMSSP_CHK */
typedef struct rpc_auth_ntlmssp_chk_info
{
	uint32 ver; /* 0x0000 0001 */
	uint32 reserved;
	uint32 crc32; /* checksum using 0xEDB8 8320 as a polynomial */
	uint32 seq_num;

} RPC_AUTH_NTLMSSP_CHK;

#endif /* RPC_NTLMSSP_H */

