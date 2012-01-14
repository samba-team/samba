/*
   Unix SMB/CIFS implementation.
   SMB Transport encryption code.
   Copyright (C) Jeremy Allison 2007.

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

#ifndef _HEADER_SMB_CRYPT_H
#define _HEADER_SMB_CRYPT_H

struct smb_trans_enc_state {
        uint16_t enc_ctx_num;
        bool enc_on;
	struct gensec_security *gensec_security;
};

/* The following definitions come from smb_seal.c  */

NTSTATUS get_enc_ctx_num(const uint8_t *buf, uint16_t *p_enc_ctx_num);
bool common_encryption_on(struct smb_trans_enc_state *es);
NTSTATUS common_encrypt_buffer(struct smb_trans_enc_state *es, char *buffer, char **buf_out);
NTSTATUS common_decrypt_buffer(struct smb_trans_enc_state *es, char *buf);
void common_free_enc_buffer(struct smb_trans_enc_state *es, char *buf);

#endif /* _HEADER_SMB_CRYPT_H */
