/*
   Unix SMB/CIFS implementation.
   SMB2 signing

   Copyright (C) Stefan Metzmacher 2009

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
#include "system/filesys.h"
#include "../libcli/smb/smb_common.h"
#include "../lib/crypto/crypto.h"

NTSTATUS smb2_signing_sign_pdu(DATA_BLOB signing_key,
			       enum protocol_types protocol,
			       struct iovec *vector,
			       int count)
{
	uint8_t *hdr;
	uint64_t session_id;
	struct HMACSHA256Context m;
	uint8_t res[SHA256_DIGEST_LENGTH];
	int i;

	if (count < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (vector[0].iov_len != SMB2_HDR_BODY) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	hdr = (uint8_t *)vector[0].iov_base;

	session_id = BVAL(hdr, SMB2_HDR_SESSION_ID);
	if (session_id == 0) {
		/*
		 * do not sign messages with a zero session_id.
		 * See MS-SMB2 3.2.4.1.1
		 */
		return NT_STATUS_OK;
	}

	if (signing_key.length == 0) {
		DEBUG(2,("Wrong session key length %u for SMB2 signing\n",
			 (unsigned)signing_key.length));
		return NT_STATUS_ACCESS_DENIED;
	}

	memset(hdr + SMB2_HDR_SIGNATURE, 0, 16);

	SIVAL(hdr, SMB2_HDR_FLAGS, IVAL(hdr, SMB2_HDR_FLAGS) | SMB2_HDR_FLAG_SIGNED);

	ZERO_STRUCT(m);
	hmac_sha256_init(signing_key.data, MIN(signing_key.length, 16), &m);
	for (i=0; i < count; i++) {
		hmac_sha256_update((const uint8_t *)vector[i].iov_base,
				   vector[i].iov_len, &m);
	}
	hmac_sha256_final(res, &m);
	DEBUG(5,("signed SMB2 message\n"));

	memcpy(hdr + SMB2_HDR_SIGNATURE, res, 16);

	return NT_STATUS_OK;
}

NTSTATUS smb2_signing_check_pdu(DATA_BLOB signing_key,
				enum protocol_types protocol,
				const struct iovec *vector,
				int count)
{
	const uint8_t *hdr;
	const uint8_t *sig;
	uint64_t session_id;
	struct HMACSHA256Context m;
	uint8_t res[SHA256_DIGEST_LENGTH];
	static const uint8_t zero_sig[16] = { 0, };
	int i;

	if (count < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (vector[0].iov_len != SMB2_HDR_BODY) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	hdr = (const uint8_t *)vector[0].iov_base;

	session_id = BVAL(hdr, SMB2_HDR_SESSION_ID);
	if (session_id == 0) {
		/*
		 * do not sign messages with a zero session_id.
		 * See MS-SMB2 3.2.4.1.1
		 */
		return NT_STATUS_OK;
	}

	if (signing_key.length == 0) {
		/* we don't have the session key yet */
		return NT_STATUS_OK;
	}

	sig = hdr+SMB2_HDR_SIGNATURE;

	ZERO_STRUCT(m);
	hmac_sha256_init(signing_key.data, MIN(signing_key.length, 16), &m);
	hmac_sha256_update(hdr, SMB2_HDR_SIGNATURE, &m);
	hmac_sha256_update(zero_sig, 16, &m);
	for (i=1; i < count; i++) {
		hmac_sha256_update((const uint8_t *)vector[i].iov_base,
				   vector[i].iov_len, &m);
	}
	hmac_sha256_final(res, &m);

	if (memcmp(res, sig, 16) != 0) {
		DEBUG(0,("Bad SMB2 signature for message\n"));
		dump_data(0, sig, 16);
		dump_data(0, res, 16);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

void smb2_key_deviration(const uint8_t *KI, size_t KI_len,
			 const uint8_t *Label, size_t Label_len,
			 const uint8_t *Context, size_t Context_len,
			 uint8_t KO[16])
{
	struct HMACSHA256Context ctx;
	uint8_t buf[4];
	static const uint8_t zero = 0;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint32_t i = 1;
	uint32_t L = 128;

	/*
	 * a simplified version of
	 * "NIST Special Publication 800-108" section 5.1
	 * using hmac-sha256.
	 */
	hmac_sha256_init(KI, KI_len, &ctx);

	RSIVAL(buf, 0, i);
	hmac_sha256_update(buf, sizeof(buf), &ctx);
	hmac_sha256_update(Label, Label_len, &ctx);
	hmac_sha256_update(&zero, 1, &ctx);
	hmac_sha256_update(Context, Context_len, &ctx);
	RSIVAL(buf, 0, L);
	hmac_sha256_update(buf, sizeof(buf), &ctx);

	hmac_sha256_final(digest, &ctx);

	memcpy(KO, digest, 16);
}
