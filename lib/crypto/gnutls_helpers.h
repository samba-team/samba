/*
 * Copyright (c) 2019      Andreas Schneider <asn@samba.org>
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

#ifndef _GNUTLS_HELPERS_H
#define _GNUTLS_HELPERS_H

#include <gnutls/gnutls.h>

#include "libcli/util/ntstatus.h"
#include "libcli/util/werror.h"
#include "lib/util/data_blob.h"

/* Those macros are only available in GnuTLS >= 3.6.4 */
#ifndef GNUTLS_FIPS140_SET_LAX_MODE
#define GNUTLS_FIPS140_SET_LAX_MODE()
#endif

#ifndef GNUTLS_FIPS140_SET_STRICT_MODE
#define GNUTLS_FIPS140_SET_STRICT_MODE()
#endif

#ifdef DOXYGEN
/**
 * @brief Convert a gnutls error code to a corresponding NTSTATUS.
 *
 * @param[in]  gnutls_rc      The GnuTLS return code.
 *
 * @param[in]  blocked_status The NTSTATUS return code which should be returned
 *                            in case the e.g. the cipher might be blocked due
 *                            to FIPS mode.
 *
 * @return A corresponding NTSTATUS code.
 */
NTSTATUS gnutls_error_to_ntstatus(int gnutls_rc, NTSTATUS blocked_status);
#else
NTSTATUS _gnutls_error_to_ntstatus(int gnutls_rc,
				   NTSTATUS blocked_status,
				   const char *function,
				   const char *location);
#define gnutls_error_to_ntstatus(gnutls_rc, blocked_status) \
	_gnutls_error_to_ntstatus(gnutls_rc,                \
				  blocked_status,           \
				  __FUNCTION__,             \
				  __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Convert a gnutls error code to a corresponding WERROR.
 *
 * @param[in]  gnutls_rc      The GnuTLS return code.
 *
 * @param[in]  blocked_werr   The WERROR code which should be returned if e.g
 *                            the cipher we want to used it not allowed to be
 *                            used because of FIPS mode.
 *
 * @return A corresponding WERROR code.
 */
WERROR gnutls_error_to_werror(int gnutls_rc, WERROR blocked_werr);
#else
WERROR _gnutls_error_to_werror(int gnutls_rc,
			       WERROR blocked_werr,
			       const char *function,
			       const char *location);
#define gnutls_error_to_werror(gnutls_rc, blocked_werr) \
	_gnutls_error_to_werror(gnutls_rc,              \
				blocked_werr,           \
				__FUNCTION__,           \
				__location__)
#endif

enum samba_gnutls_direction { SAMBA_GNUTLS_ENCRYPT, SAMBA_GNUTLS_DECRYPT };

/**
 * @brief Encrypt or decrypt a data blob using RC4 with a key and salt.
 *
 * One of the key input should be a session key and the other a confounder
 * (aka salt). Which one depends on the implementation details of the
 * protocol.
 *
 * @param[in]  key_input1 Either a session_key or a confounder.
 *
 * @param[in]  key_input2 Either a session_key or a confounder.
 *
 * @param[in]  data       The data blob to either encrypt or decrypt. The data
 *                        will be encrypted or decrypted in place.
 *
 * @param[in]  encrypt    The encryption direction.
 *
 * @return A gnutls error code.
 */
int samba_gnutls_arcfour_confounded_md5(const DATA_BLOB *key_input1,
					const DATA_BLOB *key_input2,
					DATA_BLOB *data,
					enum samba_gnutls_direction encrypt);

/**
 * @brief Encrypted a secret plaintext using AEAD_AES_256_CBC_HMAC_SHA512 and
 * the session key.
 *
 * This encrypts a secret plaintext using AEAD_AES_256_CBC_HMAC_SHA512 with a
 * key (can be the session key or PBKDF2 password). This is used in SAMR and
 * LSA.
 *
 * @param mem_ctx       The memory context to allocate the cipher text pointer.
 *
 * @param plaintext     The secret to encrypt
 *
 * @param cek           The content encryption key to encrypt the secret.
 *
 * @param key_salt      The salt used to calculate the encryption key.
 *
 * @param key_salt      The salt used to calculate the mac key.

 * @param iv            The initialization vector used for the encryption.
 *
 * @param pciphertext   A pointer to store the cipher text.
 *
 * @param pauth_tag[64] An array to store the auth tag.
 *
 * @return NT_STATUS_OK on success, an nt status error code otherwise.
 */
NTSTATUS
samba_gnutls_aead_aes_256_cbc_hmac_sha512_encrypt(TALLOC_CTX *mem_ctx,
						  const DATA_BLOB *plaintext,
						  const DATA_BLOB *cek,
						  const DATA_BLOB *key_salt,
						  const DATA_BLOB *mac_salt,
						  const DATA_BLOB *iv,
						  DATA_BLOB *pciphertext,
						  uint8_t pauth_tag[64]);

/**
 * @brief Decypt cipher text using AEAD_AES_256_CBC_HMAC_SHA512 and the session
 * key.
 *
 * This decrypts the cipher text using AEAD_AES_256_CBC_HMAC_SHA512 with the
 * given content decryption key key. The plaintext will be zeroed as soon as the
 * data blob is freed.
 *
 * @param mem_ctx       The memory context to allocate the plaintext on.
 *
 * @param ciphertext    The cipher text to decrypt.
 *
 * @param cdk           The content decryption key.
 *
 * @param key_salt      The salt used to calculate the encryption key.
 *
 * @param key_salt      The salt used to calculate the mac key.

 * @param iv            The initialization vector used for the encryption.
 *
 * @param auth_tag[64]  The authentication blob to be verified.
 *
 * @param pplaintext    A pointer to a DATA_BLOB to store the plaintext.
 *
 * @return NT_STATUS_OK on success, an nt status error code otherwise.
 */
NTSTATUS
samba_gnutls_aead_aes_256_cbc_hmac_sha512_decrypt(TALLOC_CTX *mem_ctx,
						  const DATA_BLOB *ciphertext,
						  const DATA_BLOB *cdk,
						  const DATA_BLOB *key_salt,
						  const DATA_BLOB *mac_salt,
						  const DATA_BLOB *iv,
						  const uint8_t auth_tag[64],
						  DATA_BLOB *pplaintext);

/**
 * @brief Check if weak crypto is allowed.
 *
 * @return true if weak crypo is allowed, false otherwise.
 */
bool samba_gnutls_weak_crypto_allowed(void);

#endif /* _GNUTLS_HELPERS_H */
