/* 
   Unix SMB/CIFS implementation.

   schannel library code

   Copyright (C) Andrew Tridgell 2004
   
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

struct schannel_state {
	TALLOC_CTX *mem_ctx;
	uint8 session_key[16];
	uint32_t seq_num;
	BOOL initiator;
	DATA_BLOB signature;
};

#define NETSEC_SIGN_SIGNATURE { 0x77, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 }
#define NETSEC_SEAL_SIGNATURE { 0x77, 0x00, 0x7a, 0x00, 0xff, 0xff, 0x00, 0x00 }

