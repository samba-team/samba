/*
  Public Interface file for Linux DNS client library implementation

  Copyright (C) 2006 Krishna Ganugapati <krishnag@centeris.com>
  Copyright (C) 2006 Gerald Carter <jerry@samba.org>

     ** NOTE! The following LGPL license applies to the libaddns
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include <talloc.h>
#include "lib/util/talloc_stack.h"
#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "lib/util/charset/charset.h"
#include "libcli/util/ntstatus.h"
#include "auth/gensec/gensec.h"

#include "dns.h"

static DNS_ERROR dns_negotiate_gss_ctx_int(struct dns_connection *conn,
					   const char *keyname,
					   struct gensec_security *gensec,
					   enum dns_ServerType srv_type)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dns_request *req = NULL;
	struct dns_buffer *buf = NULL;
	DATA_BLOB in = { .length = 0, };
	DATA_BLOB out = { .length = 0, };
	NTSTATUS status;
	DNS_ERROR err;

	do {
		status = gensec_update(gensec, frame, in, &out);
		data_blob_free(&in);
		if (GENSEC_UPDATE_IS_NTERROR(status)) {
			err = ERROR_DNS_GSS_ERROR;
			goto error;
		}

		if (out.length != 0) {
			struct dns_rrec *rec;

			time_t t = time(NULL);

			err = dns_create_query(frame, keyname, QTYPE_TKEY,
					       DNS_CLASS_IN, &req);
			if (!ERR_DNS_IS_OK(err)) goto error;

			err = dns_create_tkey_record(
				req, keyname, "gss.microsoft.com", t,
				t + 86400, DNS_TKEY_MODE_GSSAPI, 0,
				out.length, out.data,
				&rec );
			if (!ERR_DNS_IS_OK(err)) goto error;

			/* Windows 2000 DNS is broken and requires the
			   TKEY payload in the Answer section instead
			   of the Additional section like Windows 2003 */

			if ( srv_type == DNS_SRV_WIN2000 ) {
				err = dns_add_rrec(req, rec, &req->num_answers,
						   &req->answers);
			} else {
				err = dns_add_rrec(req, rec, &req->num_additionals,
						   &req->additional);
			}
			
			if (!ERR_DNS_IS_OK(err)) goto error;

			err = dns_marshall_request(frame, req, &buf);
			if (!ERR_DNS_IS_OK(err)) goto error;

			err = dns_send(conn, buf);
			if (!ERR_DNS_IS_OK(err)) goto error;

			TALLOC_FREE(buf);
			TALLOC_FREE(req);

			err = dns_receive(frame, conn, &buf);
			if (!ERR_DNS_IS_OK(err)) goto error;
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			struct dns_request *resp;
			struct dns_tkey_record *tkey;
			struct dns_rrec *tkey_answer = NULL;
			uint16_t i;

			if (buf == NULL) {
				err = ERROR_DNS_BAD_RESPONSE;
				goto error;
			}

			err = dns_unmarshall_request(buf, buf, &resp);
			if (!ERR_DNS_IS_OK(err)) goto error;

			/*
			 * TODO: Compare id and keyname
			 */

			for (i=0; i < resp->num_answers; i++) {
				if (resp->answers[i]->type != QTYPE_TKEY) {
					continue;
				}

				tkey_answer = resp->answers[i];
			}

			if (tkey_answer == NULL) {
				err = ERROR_DNS_INVALID_MESSAGE;
				goto error;
			}

			err = dns_unmarshall_tkey_record(
				frame, resp->answers[0], &tkey);
			if (!ERR_DNS_IS_OK(err)) goto error;

			in = data_blob_const(tkey->key, tkey->key_length);

			TALLOC_FREE(buf);
		}

	} while (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED));

	/* If we arrive here, we have a valid security context */

	err = ERROR_DNS_SUCCESS;

      error:

	TALLOC_FREE(frame);
	return err;
}

DNS_ERROR dns_negotiate_sec_ctx(const char *servername,
				const char *keyname,
				struct gensec_security *gensec,
				enum dns_ServerType srv_type)
{
	TALLOC_CTX *frame = talloc_stackframe();
	DNS_ERROR err;
	struct dns_connection *conn = NULL;

	err = dns_open_connection( servername, DNS_TCP, frame, &conn );
	if (!ERR_DNS_IS_OK(err)) goto error;

	err = dns_negotiate_gss_ctx_int(conn, keyname,
					gensec,
					srv_type);
	if (!ERR_DNS_IS_OK(err)) goto error;

 error:
	TALLOC_FREE(frame);

	return err;
}

DNS_ERROR dns_sign_update(struct dns_update_request *req,
			  struct gensec_security *gensec,
			  const char *keyname,
			  const char *algorithmname,
			  time_t time_signed, uint16_t fudge)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dns_buffer *buf;
	DNS_ERROR err;
	struct dns_domain_name *key, *algorithm;
	struct dns_rrec *rec;
	DATA_BLOB mic = { .length = 0, };
	NTSTATUS status;

	err = dns_marshall_update_request(frame, req, &buf);
	if (!ERR_DNS_IS_OK(err)) return err;

	err = dns_domain_name_from_string(frame, keyname, &key);
	if (!ERR_DNS_IS_OK(err)) goto error;

	err = dns_domain_name_from_string(frame, algorithmname, &algorithm);
	if (!ERR_DNS_IS_OK(err)) goto error;

	dns_marshall_domain_name(buf, key);
	dns_marshall_uint16(buf, DNS_CLASS_ANY);
	dns_marshall_uint32(buf, 0); /* TTL */
	dns_marshall_domain_name(buf, algorithm);
	dns_marshall_uint16(buf, 0); /* Time prefix for 48-bit time_t */
	dns_marshall_uint32(buf, time_signed);
	dns_marshall_uint16(buf, fudge);
	dns_marshall_uint16(buf, 0); /* error */
	dns_marshall_uint16(buf, 0); /* other len */

	err = buf->error;
	if (!ERR_DNS_IS_OK(buf->error)) goto error;

	status = gensec_sign_packet(gensec,
				    frame,
				    buf->data,
				    buf->offset,
				    buf->data,
				    buf->offset,
				    &mic);
	if (!NT_STATUS_IS_OK(status)) {
		err = ERROR_DNS_GSS_ERROR;
		goto error;
	}

	if (mic.length > 0xffff) {
		err = ERROR_DNS_GSS_ERROR;
		goto error;
	}

	err = dns_create_tsig_record(frame, keyname, algorithmname, time_signed,
				     fudge, mic.length, mic.data,
				     req->id, 0, &rec);
	if (!ERR_DNS_IS_OK(err)) goto error;

	err = dns_add_rrec(req, rec, &req->num_additionals, &req->additional);

 error:
	TALLOC_FREE(frame);
	return err;
}
