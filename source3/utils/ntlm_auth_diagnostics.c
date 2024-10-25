/*
   Unix SMB/CIFS implementation.

   Winbind status program.

   Copyright (C) Tim Potter      2000-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003-2004
   Copyright (C) Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it> 2000

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
#include "utils/ntlm_auth.h"
#include "../libcli/auth/libcli_auth.h"
#include "nsswitch/winbind_client.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

enum ntlm_break {
	BREAK_NONE,
	BREAK_LM,
	BREAK_NT,
	NO_LM,
	NO_NT
};

/*
   Authenticate a user with a challenge/response, checking session key
   and valid authentication types
*/

/*
 * Test the normal 'LM and NTLM' combination
 */

static bool test_lm_ntlm_broken(enum ntlm_break break_which,
				bool lanman_support_expected)
{
	bool pass = True;
	NTSTATUS nt_status;
	uint32_t flags = 0;
	DATA_BLOB lm_response = data_blob(NULL, 24);
	DATA_BLOB nt_response = data_blob(NULL, 24);
	DATA_BLOB session_key = data_blob(NULL, 16);
	uint8_t authoritative = 1;
	uchar lm_key[8];
	uchar user_session_key[16];
	uchar lm_hash[16];
	uchar nt_hash[16];
	DATA_BLOB chall = get_challenge();
	char *error_string = NULL;

	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(user_session_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_USER_SESSION_KEY;

	SMBencrypt(opt_password,chall.data,lm_response.data);
	E_deshash(opt_password, lm_hash);

	SMBNTencrypt(opt_password,chall.data,nt_response.data);

	E_md4hash(opt_password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, session_key.data);

	switch (break_which) {
	case BREAK_NONE:
		break;
	case BREAK_LM:
		lm_response.data[0]++;
		break;
	case BREAK_NT:
		nt_response.data[0]++;
		break;
	case NO_LM:
		data_blob_free(&lm_response);
		break;
	case NO_NT:
		data_blob_free(&nt_response);
		break;
	}

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain,
					      opt_workstation,
					      &chall,
					      &lm_response,
					      &nt_response,
					      flags, 0,
					      lm_key,
					      user_session_key,
					      &authoritative,
					      &error_string, NULL);
	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n",
			 error_string,
			 NT_STATUS_V(nt_status));

		pass = (break_which == BREAK_NT);
		goto done;
	}

	/* If we are told the DC is Samba4, expect an LM key of zeros */
	if (!lanman_support_expected) {
		if (!all_zero(lm_key,
			      sizeof(lm_key))) {
			DEBUG(1, ("LM Key does not match expectations!\n"));
			DEBUG(1, ("lm_key:\n"));
			dump_data(1, lm_key, 8);
			DEBUG(1, ("expected: all zeros\n"));
			pass = False;
		}
	} else {
		if (memcmp(lm_hash, lm_key,
			   sizeof(lm_key)) != 0) {
			DEBUG(1, ("LM Key does not match expectations!\n"));
			DEBUG(1, ("lm_key:\n"));
			dump_data(1, lm_key, 8);
			DEBUG(1, ("expected:\n"));
			dump_data(1, lm_hash, 8);
			pass = False;
		}
	}

	if (break_which == NO_NT) {
		if (memcmp(lm_hash, user_session_key,
			   8) != 0) {
			DEBUG(1, ("NT Session Key does not match expectations (should be LM hash)!\n"));
			DEBUG(1, ("user_session_key:\n"));
			dump_data(1, user_session_key, sizeof(user_session_key));
			DEBUG(1, ("expected:\n"));
			dump_data(1, lm_hash, sizeof(lm_hash));
			pass = False;
		}
	} else {
		if (memcmp(session_key.data, user_session_key,
			   sizeof(user_session_key)) != 0) {
			DEBUG(1, ("NT Session Key does not match expectations!\n"));
			DEBUG(1, ("user_session_key:\n"));
			dump_data(1, user_session_key, 16);
			DEBUG(1, ("expected:\n"));
			dump_data(1, session_key.data, session_key.length);
			pass = False;
		}
	}

done:
	data_blob_free(&lm_response);
	data_blob_free(&nt_response);
	data_blob_free(&session_key);
	SAFE_FREE(error_string);

        return pass;
}

/*
 * Test LM authentication, no NT response supplied
 */

static bool test_lm(bool lanman_support_expected)
{

	return test_lm_ntlm_broken(NO_NT, lanman_support_expected);
}

/*
 * Test the NTLM response only, no LM.
 */

static bool test_ntlm(bool lanman_support_expected)
{
	return test_lm_ntlm_broken(NO_LM, lanman_support_expected);
}

/*
 * Test the NTLM response only, but in the LM field.
 */

static bool test_ntlm_in_lm(bool lanman_support_expected)
{
	bool pass = True;
	NTSTATUS nt_status;
	uint32_t flags = 0;
	DATA_BLOB nt_response = data_blob(NULL, 24);
	uint8_t authoritative = 1;
	uchar lm_key[8];
	uchar lm_hash[16];
	uchar user_session_key[16];
	DATA_BLOB chall = get_challenge();
	char *error_string = NULL;

	ZERO_STRUCT(user_session_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_USER_SESSION_KEY;

	SMBNTencrypt(opt_password,chall.data,nt_response.data);

	E_deshash(opt_password, lm_hash);

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain,
					      opt_workstation,
					      &chall,
					      &nt_response,
					      NULL,
					      flags, 0,
					      lm_key,
					      user_session_key,
					      &authoritative,
					      &error_string, NULL);

	data_blob_free(&nt_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n",
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return False;
	}
	SAFE_FREE(error_string);

	/* If we are told the DC is Samba4, expect an LM key of zeros */
	if (!lanman_support_expected) {
		if (!all_zero(lm_key,
			      sizeof(lm_key))) {
			DEBUG(1, ("LM Key does not match expectations!\n"));
			DEBUG(1, ("lm_key:\n"));
			dump_data(1, lm_key, 8);
			DEBUG(1, ("expected: all zeros\n"));
			pass = False;
		}
		if (!all_zero(user_session_key,
			      sizeof(user_session_key))) {
			DEBUG(1, ("Session Key (normally first 8 lm hash) does not match expectations!\n"));
			DEBUG(1, ("user_session_key:\n"));
			dump_data(1, user_session_key, 16);
			DEBUG(1, ("expected all zeros:\n"));
			pass = False;
		}
	} else {
		if (memcmp(lm_hash, lm_key,
			   sizeof(lm_key)) != 0) {
			DEBUG(1, ("LM Key does not match expectations!\n"));
			DEBUG(1, ("lm_key:\n"));
			dump_data(1, lm_key, 8);
			DEBUG(1, ("expected:\n"));
			dump_data(1, lm_hash, 8);
			pass = False;
		}
		if (memcmp(lm_hash, user_session_key, 8) != 0) {
			DEBUG(1, ("Session Key (first 8 lm hash) does not match expectations!\n"));
			DEBUG(1, ("user_session_key:\n"));
			dump_data(1, user_session_key, 16);
			DEBUG(1, ("expected:\n"));
			dump_data(1, lm_hash, 8);
			pass = False;
		}
	}
        return pass;
}

/*
 * Test the NTLM response only, but in the both the NT and LM fields.
 */

static bool test_ntlm_in_both(bool lanman_support_expected)
{
	bool pass = True;
	NTSTATUS nt_status;
	uint32_t flags = 0;
	DATA_BLOB nt_response = data_blob(NULL, 24);
	DATA_BLOB session_key = data_blob(NULL, 16);
	uint8_t authoritative = 1;
	uint8_t lm_key[8];
	uint8_t lm_hash[16];
	uint8_t user_session_key[16];
	uint8_t nt_hash[16];
	DATA_BLOB chall = get_challenge();
	char *error_string = NULL;

	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(user_session_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_USER_SESSION_KEY;

	SMBNTencrypt(opt_password,chall.data,nt_response.data);
	E_md4hash(opt_password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, session_key.data);

	E_deshash(opt_password, lm_hash);

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain,
					      opt_workstation,
					      &chall,
					      &nt_response,
					      &nt_response,
					      flags, 0,
					      lm_key,
					      user_session_key,
					      &authoritative,
					      &error_string, NULL);
	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n",
			 error_string,
			 NT_STATUS_V(nt_status));
		pass = false;
		goto done;
	}
	SAFE_FREE(error_string);

	/* If we are told the DC is Samba4, expect an LM key of zeros */
	if (!lanman_support_expected) {
		if (!all_zero(lm_key,
			      sizeof(lm_key))) {
			DEBUG(1, ("LM Key does not match expectations!\n"));
			DEBUG(1, ("lm_key:\n"));
			dump_data(1, lm_key, 8);
			DEBUG(1, ("expected: all zeros\n"));
			pass = False;
		}
	} else {
		if (memcmp(lm_hash, lm_key,
			   sizeof(lm_key)) != 0) {
			DEBUG(1, ("LM Key does not match expectations!\n"));
			DEBUG(1, ("lm_key:\n"));
			dump_data(1, lm_key, 8);
			DEBUG(1, ("expected:\n"));
			dump_data(1, lm_hash, 8);
			pass = False;
		}
	}
	if (memcmp(session_key.data, user_session_key,
		   sizeof(user_session_key)) != 0) {
		DEBUG(1, ("NT Session Key does not match expectations!\n"));
 		DEBUG(1, ("user_session_key:\n"));
		dump_data(1, user_session_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, session_key.data, session_key.length);
		pass = False;
	}


done:
	SAFE_FREE(error_string);
	data_blob_free(&nt_response);
	data_blob_free(&session_key);

        return pass;
}

/*
 * Test the NTLMv2 and LMv2 responses
 */

static bool test_lmv2_ntlmv2_broken(enum ntlm_break break_which)
{
	bool pass = True;
	NTSTATUS nt_status;
	uint32_t flags = 0;
	DATA_BLOB ntlmv2_response = data_blob_null;
	DATA_BLOB lmv2_response = data_blob_null;
	DATA_BLOB ntlmv2_session_key = data_blob_null;
	DATA_BLOB names_blob = NTLMv2_generate_names_blob(NULL, get_winbind_netbios_name(), get_winbind_domain());
	uint8_t authoritative = 1;
	uchar user_session_key[16];
	DATA_BLOB chall = get_challenge();
	char *error_string = NULL;

	ZERO_STRUCT(user_session_key);

	flags |= WBFLAG_PAM_USER_SESSION_KEY;

	if (!SMBNTLMv2encrypt(NULL, opt_username, opt_domain, opt_password, &chall,
			      &names_blob,
			      &lmv2_response, &ntlmv2_response, NULL,
			      &ntlmv2_session_key)) {
		data_blob_free(&names_blob);
		return False;
	}
	data_blob_free(&names_blob);

	switch (break_which) {
	case BREAK_NONE:
		break;
	case BREAK_LM:
		lmv2_response.data[0]++;
		break;
	case BREAK_NT:
		ntlmv2_response.data[0]++;
		break;
	case NO_LM:
		data_blob_free(&lmv2_response);
		break;
	case NO_NT:
		data_blob_free(&ntlmv2_response);
		break;
	}

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain,
					      opt_workstation,
					      &chall,
					      &lmv2_response,
					      &ntlmv2_response,
					      flags, 0,
					      NULL,
					      user_session_key,
					      &authoritative,
					      &error_string, NULL);

	data_blob_free(&lmv2_response);
	data_blob_free(&ntlmv2_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n",
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return break_which == BREAK_NT;
	}

	SAFE_FREE(error_string);

	if (break_which != NO_NT && break_which != BREAK_NT && memcmp(ntlmv2_session_key.data, user_session_key,
		   sizeof(user_session_key)) != 0) {
		DEBUG(1, ("USER (NTLMv2) Session Key does not match expectations!\n"));
 		DEBUG(1, ("user_session_key:\n"));
		dump_data(1, user_session_key, 16);
 		DEBUG(1, ("expected:\n"));
		dump_data(1, ntlmv2_session_key.data, ntlmv2_session_key.length);
		pass = False;
	}

	data_blob_free(&ntlmv2_session_key);
        return pass;
}

/*
 * Test the NTLMv2 and LMv2 responses
 */

static bool test_lmv2_ntlmv2(bool lanman_support_expected)
{
	return test_lmv2_ntlmv2_broken(BREAK_NONE);
}

/*
 * Test the LMv2 response only
 */

static bool test_lmv2(bool lanman_support_expected)
{
	return test_lmv2_ntlmv2_broken(NO_NT);
}

/*
 * Test the NTLMv2 response only
 */

static bool test_ntlmv2(bool lanman_support_expected)
{
	return test_lmv2_ntlmv2_broken(NO_LM);
}

static bool test_lm_ntlm(bool lanman_support_expected)
{
	return test_lm_ntlm_broken(BREAK_NONE, lanman_support_expected);
}

static bool test_ntlm_lm_broken(bool lanman_support_expected)
{
	return test_lm_ntlm_broken(BREAK_LM, lanman_support_expected);
}

static bool test_ntlm_ntlm_broken(bool lanman_support_expected)
{
	return test_lm_ntlm_broken(BREAK_NT, lanman_support_expected);
}

static bool test_ntlmv2_lmv2_broken(bool lanman_support_expected)
{
	return test_lmv2_ntlmv2_broken(BREAK_LM);
}

static bool test_ntlmv2_ntlmv2_broken(bool lanman_support_expected)
{
	return test_lmv2_ntlmv2_broken(BREAK_NT);
}

static bool test_plaintext(enum ntlm_break break_which)
{
	NTSTATUS nt_status;
	uint32_t flags = 0;
	DATA_BLOB nt_response = data_blob_null;
	DATA_BLOB lm_response = data_blob_null;
	char *password;
	smb_ucs2_t *nt_response_ucs2;
	size_t converted_size;
	uint8_t authoritative = 1;
	uchar user_session_key[16];
	uchar lm_key[16];
	static const uchar zeros[8] = { 0, };
	DATA_BLOB chall = data_blob(zeros, sizeof(zeros));
	char *error_string = NULL;

	ZERO_STRUCT(user_session_key);

	flags |= WBFLAG_PAM_LMKEY;
	flags |= WBFLAG_PAM_USER_SESSION_KEY;

	if (!push_ucs2_talloc(talloc_tos(), &nt_response_ucs2, opt_password,
				&converted_size))
	{
		DEBUG(0, ("push_ucs2_talloc failed!\n"));
		exit(1);
	}

	nt_response.data = (unsigned char *)nt_response_ucs2;
	nt_response.length = strlen_w(nt_response_ucs2)*sizeof(smb_ucs2_t);

	if ((password = strupper_talloc(talloc_tos(), opt_password)) == NULL) {
		DEBUG(0, ("strupper_talloc() failed!\n"));
		exit(1);
	}

	if (!convert_string_talloc(talloc_tos(), CH_UNIX,
				   CH_DOS, password,
				   strlen(password)+1,
				   &lm_response.data,
				   &lm_response.length)) {
		DEBUG(0, ("convert_string_talloc failed!\n"));
		exit(1);
	}

	TALLOC_FREE(password);

	switch (break_which) {
	case BREAK_NONE:
		break;
	case BREAK_LM:
		lm_response.data[0]++;
		break;
	case BREAK_NT:
		nt_response.data[0]++;
		break;
	case NO_LM:
		TALLOC_FREE(lm_response.data);
		lm_response.length = 0;
		break;
	case NO_NT:
		TALLOC_FREE(nt_response.data);
		nt_response.length = 0;
		break;
	}

	nt_status = contact_winbind_auth_crap(opt_username, opt_domain,
					      opt_workstation,
					      &chall,
					      &lm_response,
					      &nt_response,
					      flags, MSV1_0_CLEARTEXT_PASSWORD_ALLOWED,
					      lm_key,
					      user_session_key,
					      &authoritative,
					      &error_string, NULL);

	TALLOC_FREE(nt_response.data);
	TALLOC_FREE(lm_response.data);
	data_blob_free(&chall);

	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("%s (0x%x)\n",
			 error_string,
			 NT_STATUS_V(nt_status));
		SAFE_FREE(error_string);
		return break_which == BREAK_NT;
	}
	SAFE_FREE(error_string);

        return break_which != BREAK_NT;
}

static bool test_plaintext_none_broken(bool lanman_support_expected) {
	return test_plaintext(BREAK_NONE);
}

static bool test_plaintext_lm_broken(bool lanman_support_expected) {
	return test_plaintext(BREAK_LM);
}

static bool test_plaintext_nt_broken(bool lanman_support_expected) {
	return test_plaintext(BREAK_NT);
}

static bool test_plaintext_nt_only(bool lanman_support_expected) {
	return test_plaintext(NO_LM);
}

static bool test_plaintext_lm_only(bool lanman_support_expected) {
	return test_plaintext(NO_NT);
}

/*
   Tests:

   - LM only
   - NT and LM
   - NT
   - NT in LM field
   - NT in both fields
   - NTLMv2
   - NTLMv2 and LMv2
   - LMv2
   - plaintext tests (in challenge-response fields)

   check we get the correct session key in each case
   check what values we get for the LM session key

*/

static const struct ntlm_tests {
	bool (*fn)(bool lanman_support_expected);
	const char *name;
	bool lanman;
} test_table[] = {
	{
		.fn = test_lm,
		.name = "LM",
		.lanman = true
	},
	{
		.fn = test_lm_ntlm,
		.name = "LM and NTLM"
	},
	{
		.fn = test_ntlm,
		.name = "NTLM"
	},
	{
		.fn = test_ntlm_in_lm,
		.name = "NTLM in LM"
	},
	{
		.fn = test_ntlm_in_both,
		.name = "NTLM in both"
	},
	{
		.fn = test_ntlmv2,
		.name = "NTLMv2"
	},
	{
		.fn = test_lmv2_ntlmv2,
		.name = "NTLMv2 and LMv2"
	},
	{
		.fn = test_lmv2,
		.name = "LMv2"
	},
	{
		.fn = test_ntlmv2_lmv2_broken,
		.name = "NTLMv2 and LMv2, LMv2 broken"
	},
	{
		.fn = test_ntlmv2_ntlmv2_broken,
		.name = "NTLMv2 and LMv2, NTLMv2 broken"
	},
	{
		.fn = test_ntlm_lm_broken,
		.name = "NTLM and LM, LM broken"
	},
	{
		.fn = test_ntlm_ntlm_broken,
		.name = "NTLM and LM, NTLM broken"
	},
	{
		.fn = test_plaintext_none_broken,
		.name = "Plaintext"
	},
	{
		.fn = test_plaintext_lm_broken,
		.name = "Plaintext LM broken"
	},
	{
		.fn = test_plaintext_nt_broken,
		.name = "Plaintext NT broken"
	},
	{
		.fn = test_plaintext_nt_only,
		.name = "Plaintext NT only"
	},
	{
		.fn = test_plaintext_lm_only,
		.name = "Plaintext LM only",
		.lanman = true
	},
	{
		.fn = NULL
	}
};

bool diagnose_ntlm_auth(bool lanman_support_expected)
{
	unsigned int i;
	bool pass = True;

	for (i=0; test_table[i].fn; i++) {
		bool test_pass = test_table[i].fn(lanman_support_expected);
		if (!lanman_support_expected
		    && test_table[i].lanman) {
			if (test_pass) {
				DBG_ERR("Test %s unexpectedly passed "
					"(server should have rejected LM)!\n",
					test_table[i].name);
				pass = false;
			}
		} else if (!test_pass) {
			DBG_ERR("Test %s failed!\n", test_table[i].name);
			pass = False;
		}
	}

        return pass;
}

