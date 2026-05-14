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
#include "dnserr.h"
#include "librpc/gen_ndr/dns.h"
#include "dns.h"
#include "libcli/dns/libdns.h"

DNS_ERROR dns_negotiate_sec_ctx(const char *serveraddress,
				const char *keyname,
				struct gensec_security *gensec,
				enum dns_ServerType srv_type)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dns_name_packet *reply = NULL;
	DATA_BLOB in = { .length = 0, };
	DATA_BLOB out = { .length = 0, };
	NTSTATUS status;
	DNS_ERROR err;

	do {
		status = gensec_update(gensec, frame, in, &out);
		TALLOC_FREE(reply);
		if (GENSEC_UPDATE_IS_NTERROR(status)) {
			err = ERROR_DNS_GSS_ERROR;
			goto error;
		}

		if (out.length != 0) {
			int ret;
			time_t t = time(NULL);

			struct dns_res_rec tkey = {
				.name = keyname,
				.rr_type = QTYPE_TKEY,
				.rr_class = DNS_CLASS_ANY,
				.length = 1,
				.rdata.tkey_record
					.algorithm = "gss.microsoft.com",
				.rdata.tkey_record.inception = t,
				.rdata.tkey_record.expiration = t + 86400,
				.rdata.tkey_record.mode = DNS_TKEY_MODE_GSSAPI,
				.rdata.tkey_record.key_size = out.length,
				.rdata.tkey_record.key_data = out.data,
			};
			struct dns_name_question question = {
				.name = keyname,
				.question_class = DNS_CLASS_IN,
				.question_type = QTYPE_TKEY,
			};
			struct dns_name_packet rec = {
				.operation = DNS_OPCODE_QUERY,
				.qdcount = 1,
				.questions = &question,
			};

			/* Windows 2000 DNS is broken and requires the
			   TKEY payload in the Answer section instead
			   of the Additional section like Windows 2003 */

			if ( srv_type == DNS_SRV_WIN2000 ) {
				rec.ancount = 1;
				rec.answers = &tkey;
			} else {
				rec.arcount = 1;
				rec.additional = &tkey;
			}

			ret = dns_cli_request(frame,
					      serveraddress,
					      &rec,
					      &reply);
			if (ret != 0) {
				err = ERROR_DNS_SOCKET_ERROR;
				goto error;
			}
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			struct dns_res_rec *tkey_answer = NULL;
			struct dns_tkey_record *tkey = NULL;

			uint16_t i;

			/*
			 * TODO: Compare id and keyname
			 */

			for (i = 0; i < reply->ancount; i++) {
				tkey_answer = &reply->answers[i];

				if (tkey_answer->rr_type == QTYPE_TKEY) {
					break;
				}
			}

			if (i == reply->ancount) {
				err = ERROR_DNS_INVALID_MESSAGE;
				goto error;
			}

			tkey = &tkey_answer->rdata.tkey_record;

			in = data_blob_const(tkey->key_data, tkey->key_size);
		}

	} while (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED));

	/* If we arrive here, we have a valid security context */

	err = ERROR_DNS_SUCCESS;

      error:

	TALLOC_FREE(frame);
	return err;
}
