/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../libcli/auth/libcli_auth.h"

/*******************************************************************
 inits a structure.
********************************************************************/

void init_netr_IdentityInfo(struct netr_IdentityInfo *r,
			    const char *domain_name,
			    uint32_t parameter_control,
			    uint32_t logon_id_low,
			    uint32_t logon_id_high,
			    const char *account_name,
			    const char *workstation)
{
	init_lsa_String(&r->domain_name, domain_name);
	r->parameter_control = parameter_control;
	r->logon_id_low = logon_id_low;
	r->logon_id_high = logon_id_high;
	init_lsa_String(&r->account_name, account_name);
	init_lsa_String(&r->workstation, workstation);
}

/*******************************************************************
 inits a structure.
 This is a network logon packet. The log_id parameters
 are what an NT server would generate for LUID once the
 user is logged on. I don't think we care about them.

 Note that this has no access to the NT and LM hashed passwords,
 so it forwards the challenge, and the NT and LM responses (24
 bytes each) over the secure channel to the Domain controller
 for it to say yea or nay. This is the preferred method of
 checking for a logon as it doesn't export the password
 hashes to anyone who has compromised the secure channel. JRA.

********************************************************************/

void init_netr_NetworkInfo(struct netr_NetworkInfo *r,
			   const char *domain_name,
			   uint32_t parameter_control,
			   uint32_t logon_id_low,
			   uint32_t logon_id_high,
			   const char *account_name,
			   const char *workstation,
			   uint8_t challenge[8],
			   struct netr_ChallengeResponse nt,
			   struct netr_ChallengeResponse lm)
{
	init_netr_IdentityInfo(&r->identity_info,
			       domain_name,
			       parameter_control,
			       logon_id_low,
			       logon_id_high,
			       account_name,
			       workstation);
	memcpy(r->challenge, challenge, 8);
	r->nt = nt;
	r->lm = lm;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_netr_PasswordInfo(struct netr_PasswordInfo *r,
			    const char *domain_name,
			    uint32_t parameter_control,
			    uint32_t logon_id_low,
			    uint32_t logon_id_high,
			    const char *account_name,
			    const char *workstation,
			    struct samr_Password lmpassword,
			    struct samr_Password ntpassword)
{
	init_netr_IdentityInfo(&r->identity_info,
			       domain_name,
			       parameter_control,
			       logon_id_low,
			       logon_id_high,
			       account_name,
			       workstation);
	r->lmpassword = lmpassword;
	r->ntpassword = ntpassword;
}

/*************************************************************************
 inits a netr_CryptPassword structure
 *************************************************************************/

void init_netr_CryptPassword(const char *pwd,
			     unsigned char session_key[16],
			     struct netr_CryptPassword *pwd_buf)
{
	struct samr_CryptPassword password_buf;

	encode_pw_buffer(password_buf.data, pwd, STR_UNICODE);

	arcfour_crypt(password_buf.data, session_key, 516);
	memcpy(pwd_buf->data, password_buf.data, 512);
	pwd_buf->length = IVAL(password_buf.data, 512);
}
