/* 
   Unix SMB/CIFS implementation.
   Interface header:    HMAC SHA1 code
   Copyright (C) Stefan Metzmacher 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _HMAC_SHA1_H

struct HMACSHA1Context {
        struct SHA1Context ctx;
        uint8_t k_ipad[65];    
        uint8_t k_opad[65];

};

void hmac_sha1_init(const uint8_t *key, size_t key_len, struct HMACSHA1Context *ctx);
void hmac_sha1_update(const uint8_t *data, size_t data_len, struct HMACSHA1Context *ctx);
void hmac_sha1_final(uint8_t digest[20], struct HMACSHA1Context *ctx);

#endif /* _HMAC_SHA1_H */
