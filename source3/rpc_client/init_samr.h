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

#ifndef _RPC_CLIENT_INIT_SAMR_H_
#define _RPC_CLIENT_INIT_SAMR_H_

/* The following definitions come from rpc_client/init_samr.c  */

NTSTATUS init_samr_CryptPasswordEx(const char *pwd,
				   DATA_BLOB *session_key,
				   struct samr_CryptPasswordEx *pwd_buf);
NTSTATUS init_samr_CryptPassword(const char *pwd,
				 DATA_BLOB *session_key,
				 struct samr_CryptPassword *pwd_buf);

/**
 * @brief Initialize a AES encrypted password structure.
 *
 * This takes a password and a session key and encrypts the password. The
 * encrypted password is then stored in the encrypted passwors structure.
 *
 * @param mem_ctx       The memory context to allocate the password buffer on.
 *
 * @param password      The password to encrypt.
 *
 * @param session_key   The session key used to encrypt the password.
 *
 * @param ppwd_buf      A pointer to the talloc allocated password structure.
 *
 * @return On success NT_STATUS_OK, an error status code otherwise.
 */
NTSTATUS init_samr_CryptPasswordAES(TALLOC_CTX *mem_ctx,
				    const char *password,
				    DATA_BLOB *salt,
				    DATA_BLOB *session_key,
				    struct samr_EncryptedPasswordAES *ppwd_buf);

#endif /* _RPC_CLIENT_INIT_SAMR_H_ */
