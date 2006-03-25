/* 
   Unix SMB/CIFS implementation.
   Small self-tests for the NTLMSSP code
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
#include "auth/auth.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "lib/cmdline/popt_common.h"
#include "torture/torture.h"

BOOL torture_ntlmssp_self_check(struct torture_context *torture) 
{
	struct gensec_security *gensec_security;
	struct gensec_ntlmssp_state *gensec_ntlmssp_state;
	DATA_BLOB data;
	DATA_BLOB sig, expected_sig;
	NTSTATUS status;

	status = gensec_client_start(NULL, &gensec_security, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	gensec_set_credentials(gensec_security, cmdline_credentials);

	gensec_want_feature(gensec_security, GENSEC_FEATURE_SIGN);
	gensec_want_feature(gensec_security, GENSEC_FEATURE_SEAL);

	status = gensec_start_mech_by_oid(gensec_security, GENSEC_OID_NTLMSSP);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to start GENSEC for NTLMSSP\n");
		return False;
	}

	gensec_ntlmssp_state = gensec_security->private_data;

	gensec_ntlmssp_state->session_key = strhex_to_data_blob("0102030405060708090a0b0c0d0e0f00");
	dump_data_pw("NTLMSSP session key: \n", 
		     gensec_ntlmssp_state->session_key.data,  
		     gensec_ntlmssp_state->session_key.length);

	gensec_ntlmssp_state->neg_flags = NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_NTLM2;

	if (!NT_STATUS_IS_OK(status = ntlmssp_sign_init(gensec_ntlmssp_state))) {
		printf("Failed to sign_init: %s\n", nt_errstr(status));
		return False;
	}

	data = strhex_to_data_blob("6a43494653");
	gensec_ntlmssp_sign_packet(gensec_security, gensec_security,
				   data.data, data.length, data.data, data.length, &sig);

	expected_sig = strhex_to_data_blob("01000000e37f97f2544f4d7e00000000");

	dump_data_pw("NTLMSSP calc sig:     ", sig.data, sig.length);
	dump_data_pw("NTLMSSP expected sig: ", expected_sig.data, expected_sig.length);

	if (sig.length != expected_sig.length) {
		printf("Wrong sig length: %d != %d\n", 
		       (int)sig.length, (int)expected_sig.length);
		return False;
	}

	if (memcmp(sig.data, expected_sig.data, sig.length)) {
		return False;
	}

	talloc_free(gensec_security);

	status = gensec_client_start(NULL, &gensec_security, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to start GENSEC for NTLMSSP\n");
		return False;
	}

	gensec_set_credentials(gensec_security, cmdline_credentials);

	gensec_want_feature(gensec_security, GENSEC_FEATURE_SIGN);
	gensec_want_feature(gensec_security, GENSEC_FEATURE_SEAL);

	status = gensec_start_mech_by_oid(gensec_security, GENSEC_OID_NTLMSSP);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	gensec_ntlmssp_state = gensec_security->private_data;

	gensec_ntlmssp_state->session_key = strhex_to_data_blob("0102030405e538b0");
	dump_data_pw("NTLMSSP session key: \n", 
		     gensec_ntlmssp_state->session_key.data,  
		     gensec_ntlmssp_state->session_key.length);

	gensec_ntlmssp_state->neg_flags = NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_KEY_EXCH;

	if (!NT_STATUS_IS_OK(status = ntlmssp_sign_init(gensec_ntlmssp_state))) {
		printf("Failed to sign_init: %s\n", nt_errstr(status));
		return False;
	}

	data = strhex_to_data_blob("6a43494653");
	gensec_ntlmssp_sign_packet(gensec_security, gensec_security,
			    data.data, data.length, data.data, data.length, &sig);

	expected_sig = strhex_to_data_blob("0100000078010900397420fe0e5a0f89");

	dump_data_pw("NTLMSSP calc sig:     ", sig.data, sig.length);
	dump_data_pw("NTLMSSP expected sig: ", expected_sig.data, expected_sig.length);

	if (sig.length != expected_sig.length) {
		printf("Wrong sig length: %d != %d\n", 
		       (int)sig.length, (int)expected_sig.length);
		return False;
	}

	if (memcmp(sig.data+8, expected_sig.data+8, sig.length-8)) {
		return False;
	}

	talloc_free(gensec_security);

	return True;
}
