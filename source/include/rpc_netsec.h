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

#ifndef _RPC_NETSEC_H /* RPC_NETSEC_H */
#define RPC_NETSEC_H 

#include "rpc_misc.h" /* this only pulls in STRHDR */

/* this is TEMPORARILY coded up as a specific structure */
/* this structure comes after the bind request */
/* RPC_AUTH_NETSEC_NEG */
typedef struct rpc_auth_netsec_neg_info
{
	fstring domain; /* calling workstations's domain */
	fstring myname; /* calling workstation's name */

} RPC_AUTH_NETSEC_NEG;


/* RPC_AUTH_NETSEC_RESP */
typedef struct rpc_auth_netsec_resp_info
{
	uint32 flags; /* 0x0500 0000 */

} RPC_AUTH_NETSEC_RESP;

#define NETSEC_SIGNATURE \
(char[8]){ 0x77, 0x00, 0x7a, 0x00, 0xff, 0xff, 0x00, 0x00 }

/* attached to the end of encrypted rpc requests and responses */
/* RPC_AUTH_NETSEC_CHK */
typedef struct rpc_auth_netsec_chk_info
{
	uint8 sig  [8]; /* 77 00 7a 00 ff ff 00 00 */
	uint8 data1[8];
	uint8 data3[8]; /* verifier, seq num */
	uint8 data8[8]; 

} RPC_AUTH_NETSEC_CHK;

#endif /* RPC_NETSEC_H */

