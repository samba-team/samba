/* 
   Unix SMB/CIFS implementation.
   basic raw test suite for change notify
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   
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

BOOL torture_ntlmssp_self_check(int dummy) 
{
	struct ntlmssp_state *ntlmssp_state;
	DATA_BLOB data;
	DATA_BLOB sig, expected_sig;
	NTSTATUS status;

	if (!NT_STATUS_IS_OK(ntlmssp_client_start(&ntlmssp_state))) {
		return False;
	}

	ntlmssp_state->session_key = strhex_to_data_blob("0102030405060708090a0b0c0d0e0f00");
	dump_data_pw("NTLMSSP session key: \n", 
		     ntlmssp_state->session_key.data,  
		     ntlmssp_state->session_key.length);

	ntlmssp_state->server_use_session_keys = True;
	ntlmssp_state->neg_flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_NTLM2;

	if (!NT_STATUS_IS_OK(status = ntlmssp_sign_init(ntlmssp_state))) {
		printf("Failed to sign_init: %s\n", nt_errstr(status));
		return False;
	}

	data = strhex_to_data_blob("6a43494653");
	ntlmssp_sign_packet(ntlmssp_state, ntlmssp_state->mem_ctx, 
			    data.data, data.length, &sig);

	expected_sig = strhex_to_data_blob("01000000e37f97f2544f4d7e00000000");

	dump_data_pw("NTLMSSP sig: ", sig.data, sig.length);
	dump_data_pw("NTLMSSP sig: ", expected_sig.data, expected_sig.length);

	return True;
}
