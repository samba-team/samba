/* 
   Unix SMB/CIFS implementation.
   Interface header:    HMAC SHA-1 code
   Copyright (C) Stefan Metzmacher
   
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

/*
 taken direct from rfc2202 implementation and modified for suitable use
 */

#include "includes.h"
#include "lib/crypto/crypto.h"

/***********************************************************************
 the rfc 2104/2202 version of hmac_sha1 initialisation.
***********************************************************************/
_PUBLIC_ void hmac_sha1_init(const uint8_t *key, size_t key_len, struct HMACSHA1Context *ctx)
{
        int i;
	uint8_t tk[SHA1HashSize];

        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64)
	{
                struct SHA1Context tctx;

                SHA1Init(&tctx);
                SHA1Update(&tctx, key, key_len);
                SHA1Final(tk, &tctx);

                key = tk;
                key_len = SHA1HashSize;
        }

        /* start out by storing key in pads */
        ZERO_STRUCT(ctx->k_ipad);
        ZERO_STRUCT(ctx->k_opad);
        memcpy( ctx->k_ipad, key, key_len);
        memcpy( ctx->k_opad, key, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++)
	{
                ctx->k_ipad[i] ^= 0x36;
                ctx->k_opad[i] ^= 0x5c;
        }

        SHA1Init(&ctx->ctx);
        SHA1Update(&ctx->ctx, ctx->k_ipad, 64);  
}

/***********************************************************************
 update hmac_sha1 "inner" buffer
***********************************************************************/
_PUBLIC_ void hmac_sha1_update(const uint8_t *data, size_t data_len, struct HMACSHA1Context *ctx)
{
        SHA1Update(&ctx->ctx, data, data_len); /* then text of datagram */
}

/***********************************************************************
 finish off hmac_sha1 "inner" buffer and generate outer one.
***********************************************************************/
_PUBLIC_ void hmac_sha1_final(uint8_t digest[SHA1HashSize], struct HMACSHA1Context *ctx)
{
        struct SHA1Context ctx_o;

        SHA1Final(digest, &ctx->ctx);

        SHA1Init(&ctx_o);
        SHA1Update(&ctx_o, ctx->k_opad, 64);
        SHA1Update(&ctx_o, digest, SHA1HashSize);
        SHA1Final(digest, &ctx_o);
}
