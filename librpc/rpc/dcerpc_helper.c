/*
 * Copyright (c) 2020      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "librpc/gen_ndr/security.h"
#include "librpc/gen_ndr/auth.h"
#include "lib/crypto/gnutls_helpers.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/security_token.h"
#include "libcli/smb/smb2_constants.h"

#include "dcerpc_helper.h"

static bool smb3_sid_parse(const struct dom_sid *sid,
			   uint16_t *pdialect,
			   uint16_t *pencrypt,
			   uint16_t *pcipher)
{
	uint16_t dialect;
	uint16_t encrypt;
	uint16_t cipher;

	if (sid->sub_auths[0] != global_sid_Samba_SMB3.sub_auths[0]) {
		return false;
	}

	dialect = sid->sub_auths[1];
	if (dialect > 0x03ff) {
		return false;
	}

	encrypt = sid->sub_auths[2];
	if (encrypt > 0x0002) {
		return false;
	}

	cipher = sid->sub_auths[3];
	if (cipher > SMB2_ENCRYPTION_AES128_GCM) {
		return false;
	}

	if (pdialect != NULL) {
		*pdialect = dialect;
	}

	if (pencrypt != NULL) {
		*pencrypt = encrypt;
	}

	if (pcipher != NULL) {
		*pcipher = cipher;
	}

	return true;
}

bool dcerpc_is_transport_encrypted(struct auth_session_info *session_info)
{
	struct security_token *token = session_info->security_token;
	struct dom_sid smb3_dom_sid = global_sid_Samba_SMB3;
	const struct dom_sid *smb3_sid = NULL;
	uint16_t dialect = 0;
	uint16_t encrypt = 0;
	uint16_t cipher = 0;
	size_t num_smb3_sids;
	bool ok;

	num_smb3_sids = security_token_count_flag_sids(token,
						       &smb3_dom_sid,
						       3,
						       &smb3_sid);
	if (num_smb3_sids > 1) {
		DBG_ERR("ERROR: The SMB3 SID has been detected %zu times\n",
			num_smb3_sids);
		return false;
	}

	if (smb3_sid == NULL) {
		return false;
	}

	ok = smb3_sid_parse(smb3_sid, &dialect, &encrypt, &cipher);
	if (!ok) {
		DBG_ERR("Failed to parse SMB3 SID!\n");
		return false;
	}

	DBG_DEBUG("SMB SID - dialect: %#04x, encrypt: %#04x, cipher: %#04x\n",
		  dialect,
		  encrypt,
		  cipher);

	if (dialect < SMB3_DIALECT_REVISION_300) {
		DBG_DEBUG("Invalid SMB3 dialect!\n");
		return false;
	}

	if (encrypt != DCERPC_SMB_ENCRYPTION_REQUIRED) {
		DBG_DEBUG("Invalid SMB3 encryption!\n");
		return false;
	}

	switch (cipher) {
	case SMB2_ENCRYPTION_AES128_CCM:
	case SMB2_ENCRYPTION_AES128_GCM:
		break;
	default:
		DBG_DEBUG("Invalid SMB3 cipher!\n");
		return false;
	}

	return true;
}
