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

/**
 * @brief Derive a key using the NIST SP 800‐108 algorithm.
 *
 * The details of the algorithm can be found at
 * https://csrc.nist.gov/pubs/sp/800/108/r1/final.
 *
 * @param KI            The key‐derivation key used as input.
 *
 * @param KI_len        The length of the key‐derivation key.
 *
 * @param FixedData     If non‐NULL, specifies fixed data to be used in place of
 *                      that constructed from the Label and Context parameters.
 *
 * @param FixedData_len The length of the fixed data, if it is present.
 *
 * @param Label         A label that identifies the purpose for the derived key.
 *                      Ignored if FixedData is non‐NULL.
 *
 * @param Label_len     The length of the label.
 *
 * @param Context       Information related to the derived key. Ignored if
 *                      FixedData is non‐NULL.
 *
 * @param Context_len   The length of the context data.
 *
 * @param algorithm     The HMAC algorithm to use.
 *
 * @param KO            A buffer to receive the derived key.
 *
 * @param KO_len        The length of the key to be derived.
 *
 * @return NT_STATUS_OK on success, an NT status error code otherwise.
 */
NTSTATUS samba_gnutls_sp800_108_derive_key(
	const uint8_t *KI,
	size_t KI_len,
	const uint8_t *FixedData,
	size_t FixedData_len,
	const uint8_t *Label,
	size_t Label_len,
	const uint8_t *Context,
	size_t Context_len,
	const gnutls_mac_algorithm_t algorithm,
	uint8_t *KO,
	size_t KO_len);

#ifndef HAVE_GNUTLS_CB_TLS_SERVER_END_POINT
int legacy_gnutls_server_end_point_cb(gnutls_session_t session,
				      bool is_server,
				      gnutls_datum_t * cb);
#endif /* HAVE_GNUTLS_CB_TLS_SERVER_END_POINT */

#endif /* _GNUTLS_HELPERS_H */
