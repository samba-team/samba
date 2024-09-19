/*
   Unix SMB/CIFS implementation.

   DCERPC client side interface structures

   Copyright (C) 2008 Jelmer Vernooij

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

#ifndef _S3_DCERPC_INTERNAL_H__
#define _S3_DCERPC_INTERNAL_H__

struct pipe_auth_data {
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	uint32_t auth_context_id;
	bool hdr_signing;
	bool verified_bitmask1;

	struct gensec_security *auth_ctx;
};

#endif /* __S3_DCERPC_INTERNAL_H__ */
