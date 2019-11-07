/* 
   Unix SMB/CIFS implementation.
   Helper functions for applying replicated objects
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009
    
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
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "zlib.h"
#include "../libcli/drsuapi/drsuapi.h"
#include "libcli/auth/libcli_auth.h"
#include "dsdb/samdb/samdb.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static WERROR drsuapi_decrypt_attribute_value(TALLOC_CTX *mem_ctx,
					      const DATA_BLOB *gensec_skey,
					      bool rid_crypt,
					      uint32_t rid,
					      const DATA_BLOB *in,
					      DATA_BLOB *out)
{
	DATA_BLOB confounder;
	DATA_BLOB enc_buffer;

	DATA_BLOB dec_buffer;

	uint32_t crc32_given;
	uint32_t crc32_calc;
	DATA_BLOB checked_buffer;

	DATA_BLOB plain_buffer;
	WERROR result;
	int rc;

	/*
	 * users with rid == 0 should not exist
	 */
	if (rid_crypt && rid == 0) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	/* 
	 * the first 16 bytes at the beginning are the confounder
	 * followed by the 4 byte crc32 checksum
	 */
	if (in->length < 20) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}
	confounder = data_blob_const(in->data, 16);
	enc_buffer = data_blob_const(in->data + 16, in->length - 16);

	/* 
	 * decrypt with the encryption key, being md5 over the session
	 * key followed by the confounder.  The parameter order to
	 * samba_gnutls_arcfour_confounded_md5() matters for this!
	 * 
	 * here the gensec session key is used and
	 * not the dcerpc ncacn_ip_tcp "SystemLibraryDTC" key!
	 */

	/*
	 * reference the encrypted buffer part and
	 * decrypt it using the created encryption key using arcfour
	 */
	dec_buffer = data_blob_const(enc_buffer.data, enc_buffer.length);

	rc = samba_gnutls_arcfour_confounded_md5(gensec_skey,
						 &confounder,
						 &dec_buffer,
						 SAMBA_GNUTLS_DECRYPT);
	if (rc < 0) {
		result = gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
		goto out;
	}

	/* 
	 * the first 4 byte are the crc32 checksum
	 * of the remaining bytes
	 */
	crc32_given = IVAL(dec_buffer.data, 0);
	crc32_calc = crc32(0, Z_NULL, 0);
	crc32_calc = crc32(crc32_calc,
			   dec_buffer.data + 4 ,
			   dec_buffer.length - 4);
	checked_buffer = data_blob_const(dec_buffer.data + 4, dec_buffer.length - 4);

	plain_buffer = data_blob_talloc(mem_ctx, checked_buffer.data, checked_buffer.length);
	W_ERROR_HAVE_NO_MEMORY(plain_buffer.data);

	if (crc32_given != crc32_calc) {
		result = W_ERROR(HRES_ERROR_V(HRES_SEC_E_DECRYPT_FAILURE));
		goto out;
	}
	/*
	 * The following rid_crypt obfuscation isn't session specific
	 * and not really needed here, because we allways know the rid of the
	 * user account.
	 *
	 * some attributes with this 'additional encryption' include
	 * dBCSPwd, unicodePwd, ntPwdHistory, lmPwdHistory
	 *
	 * But for the rest of samba it's easier when we remove this static
	 * obfuscation here
	 */
	if (rid_crypt) {
		uint32_t i, num_hashes;

		if ((checked_buffer.length % 16) != 0) {
			result = WERR_DS_DRA_INVALID_PARAMETER;
			goto out;
		}

		num_hashes = plain_buffer.length / 16;
		for (i = 0; i < num_hashes; i++) {
			uint32_t offset = i * 16;
			rc = sam_rid_crypt(rid, checked_buffer.data + offset,
					   plain_buffer.data + offset,
					   SAMBA_GNUTLS_DECRYPT);
			if (rc != 0) {
				result = gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
				goto out;
			}
		}
	}

	*out = plain_buffer;
	result = WERR_OK;
out:
	return result;
}

WERROR drsuapi_decrypt_attribute(TALLOC_CTX *mem_ctx, 
				 const DATA_BLOB *gensec_skey,
				 uint32_t rid,
				 uint32_t dsdb_repl_flags,
				 struct drsuapi_DsReplicaAttribute *attr)
{
	WERROR status;
	DATA_BLOB *enc_data;
	DATA_BLOB plain_data;
	bool rid_crypt = false;

	if (attr->value_ctr.num_values == 0) {
		return WERR_OK;
	}

	switch (attr->attid) {
	case DRSUAPI_ATTID_dBCSPwd:
	case DRSUAPI_ATTID_unicodePwd:
	case DRSUAPI_ATTID_ntPwdHistory:
	case DRSUAPI_ATTID_lmPwdHistory:
		rid_crypt = true;
		break;
	case DRSUAPI_ATTID_supplementalCredentials:
	case DRSUAPI_ATTID_priorValue:
	case DRSUAPI_ATTID_currentValue:
	case DRSUAPI_ATTID_trustAuthOutgoing:
	case DRSUAPI_ATTID_trustAuthIncoming:
	case DRSUAPI_ATTID_initialAuthOutgoing:
	case DRSUAPI_ATTID_initialAuthIncoming:
		break;
	default:
		return WERR_OK;
	}

	if (dsdb_repl_flags & DSDB_REPL_FLAG_EXPECT_NO_SECRETS) {
		return WERR_TOO_MANY_SECRETS;
	}

	if (attr->value_ctr.num_values > 1) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	if (!attr->value_ctr.values[0].blob) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	enc_data	= attr->value_ctr.values[0].blob;

	status = drsuapi_decrypt_attribute_value(mem_ctx,
						 gensec_skey,
						 rid_crypt,
						 rid,
						 enc_data,
						 &plain_data);
	W_ERROR_NOT_OK_RETURN(status);

	talloc_free(attr->value_ctr.values[0].blob->data);
	*attr->value_ctr.values[0].blob = plain_data;

	return WERR_OK;
}

static WERROR drsuapi_encrypt_attribute_value(TALLOC_CTX *mem_ctx,
					      const DATA_BLOB *gensec_skey,
					      bool rid_crypt,
					      uint32_t rid,
					      const DATA_BLOB *in,
					      DATA_BLOB *out)
{
	DATA_BLOB rid_crypt_out = data_blob(NULL, 0);
	DATA_BLOB confounder;

	DATA_BLOB enc_buffer;

	DATA_BLOB to_encrypt;

	uint32_t crc32_calc;
	WERROR result;
	int rc;

	/*
	 * users with rid == 0 should not exist
	 */
	if (rid_crypt && rid == 0) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	/*
	 * The following rid_crypt obfuscation isn't session specific
	 * and not really needed here, because we allways know the rid of the
	 * user account.
	 *
	 * some attributes with this 'additional encryption' include
	 * dBCSPwd, unicodePwd, ntPwdHistory, lmPwdHistory
	 *
	 * But for the rest of samba it's easier when we remove this static
	 * obfuscation here
	 */
	if (rid_crypt) {
		uint32_t i, num_hashes;
		rid_crypt_out = data_blob_talloc(mem_ctx, in->data, in->length);
		W_ERROR_HAVE_NO_MEMORY(rid_crypt_out.data);

		if ((rid_crypt_out.length % 16) != 0) {
			return WERR_DS_DRA_INVALID_PARAMETER;
		}

		num_hashes = rid_crypt_out.length / 16;
		for (i = 0; i < num_hashes; i++) {
			uint32_t offset = i * 16;
			rc = sam_rid_crypt(rid, in->data + offset,
					   rid_crypt_out.data + offset,
					   SAMBA_GNUTLS_ENCRYPT);
			if (rc != 0) {
				result = gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
				goto out;
			}
		}
		in = &rid_crypt_out;
	}

	/* 
	 * the first 16 bytes at the beginning are the confounder
	 * followed by the 4 byte crc32 checksum
	 */

	enc_buffer = data_blob_talloc(mem_ctx, NULL, in->length+20);
	if (!enc_buffer.data) {
		talloc_free(rid_crypt_out.data);
		return WERR_NOT_ENOUGH_MEMORY;
	};
	
	confounder = data_blob_const(enc_buffer.data, 16);
	generate_random_buffer(confounder.data, confounder.length);

	/* 
	 * the first 4 byte are the crc32 checksum
	 * of the remaining bytes
	 */
	crc32_calc = crc32(0, Z_NULL, 0);
	crc32_calc = crc32(crc32_calc, in->data, in->length);
	SIVAL(enc_buffer.data, 16, crc32_calc);

	/*
	 * copy the plain buffer part and 
	 * encrypt it using the created encryption key using arcfour
	 */
	memcpy(enc_buffer.data+20, in->data, in->length); 
	talloc_free(rid_crypt_out.data);

	to_encrypt = data_blob_const(enc_buffer.data+16,
				     enc_buffer.length-16);

	/*
	 * encrypt with the encryption key, being md5 over the session
	 * key followed by the confounder.  The parameter order to
	 * samba_gnutls_arcfour_confounded_md5() matters for this!
	 *
	 * here the gensec session key is used and
	 * not the dcerpc ncacn_ip_tcp "SystemLibraryDTC" key!
	 */

	rc = samba_gnutls_arcfour_confounded_md5(gensec_skey,
						 &confounder,
						 &to_encrypt,
						 SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		result = gnutls_error_to_werror(rc, WERR_INTERNAL_ERROR);
		goto out;
	}

	*out = enc_buffer;
	result =  WERR_OK;
out:
	return result;
}

/*
  encrypt a DRSUAPI attribute ready for sending over the wire
  Only some attribute types are encrypted
 */
WERROR drsuapi_encrypt_attribute(TALLOC_CTX *mem_ctx, 
				 const DATA_BLOB *gensec_skey,
				 uint32_t rid,
				 struct drsuapi_DsReplicaAttribute *attr)
{
	WERROR status;
	DATA_BLOB *plain_data;
	DATA_BLOB enc_data;
	bool rid_crypt = false;

	if (attr->value_ctr.num_values == 0) {
		return WERR_OK;
	}

	switch (attr->attid) {
	case DRSUAPI_ATTID_dBCSPwd:
	case DRSUAPI_ATTID_unicodePwd:
	case DRSUAPI_ATTID_ntPwdHistory:
	case DRSUAPI_ATTID_lmPwdHistory:
		rid_crypt = true;
		break;
	case DRSUAPI_ATTID_supplementalCredentials:
	case DRSUAPI_ATTID_priorValue:
	case DRSUAPI_ATTID_currentValue:
	case DRSUAPI_ATTID_trustAuthOutgoing:
	case DRSUAPI_ATTID_trustAuthIncoming:
	case DRSUAPI_ATTID_initialAuthOutgoing:
	case DRSUAPI_ATTID_initialAuthIncoming:
		break;
	default:
		return WERR_OK;
	}

	if (attr->value_ctr.num_values > 1) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	if (!attr->value_ctr.values[0].blob) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	plain_data	= attr->value_ctr.values[0].blob;

	status = drsuapi_encrypt_attribute_value(mem_ctx,
						 gensec_skey,
						 rid_crypt,
						 rid,
						 plain_data,
						 &enc_data);
	W_ERROR_NOT_OK_RETURN(status);

	talloc_free(attr->value_ctr.values[0].blob->data);
	*attr->value_ctr.values[0].blob = enc_data;

	return WERR_OK;
}

