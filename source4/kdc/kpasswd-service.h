/*
   Unix SMB/CIFS implementation.

   Samba kpasswd implementation

   Copyright (c) 2016      Andreas Schneider <asn@samba.org>

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

#ifndef _KPASSWD_SERVICE_H
#define _KPASSWD_SERVICE_H

struct gensec_security;

krb5_error_code kpasswd_handle_request(struct kdc_server *kdc,
				       TALLOC_CTX *mem_ctx,
				       struct gensec_security *gensec_security,
				       uint16_t verno,
				       DATA_BLOB *decoded_data,
				       DATA_BLOB *kpasswd_reply,
				       const char **error_string);

kdc_code kpasswd_process(struct kdc_server *kdc,
			 TALLOC_CTX *mem_ctx,
			 DATA_BLOB *request,
			 DATA_BLOB *reply,
			 struct tsocket_address *remote_addr,
			 struct tsocket_address *local_addr,
			 int datagram);

#endif /* _KPASSWD_SERVICE_H */
