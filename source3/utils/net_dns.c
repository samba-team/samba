/* 
   Samba Unix/Linux Dynamic DNS Update
   net ads commands

   Copyright (C) Krishna Ganugapati (krishnag@centeris.com)         2006
   Copyright (C) Gerald Carter                                      2006

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

#include "includes.h"
#include "utils/net.h"
#include "../lib/addns/dns.h"
#include "utils/net_dns.h"
#include "auth/gensec/gensec.h"
#include "auth_generic.h"
#include "libcli/dns/libdns.h"

#if defined(HAVE_KRB5)

static NTSTATUS dns_negotiate_sec_ctx(const char *serveraddress,
				      const char *keyname,
				      struct gensec_security *gensec,
				      enum dns_ServerType srv_type)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dns_name_packet *reply = NULL;
	DATA_BLOB in = { .length = 0, };
	DATA_BLOB out = { .length = 0, };
	NTSTATUS status;

	do {
		status = gensec_update(gensec, frame, in, &out);
		TALLOC_FREE(reply);
		if (GENSEC_UPDATE_IS_NTERROR(status)) {
			goto error;
		}

		if (out.length != 0) {
			int ret;
			time_t t = time(NULL);

			struct dns_res_rec tkey = {
				.name = keyname,
				.rr_type = DNS_QTYPE_TKEY,
				.rr_class = DNS_QCLASS_ANY,
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
				.question_class = DNS_QCLASS_IN,
				.question_type = DNS_QTYPE_TKEY,
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
				status = map_nt_error_from_unix(ret);
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

				if (tkey_answer->rr_type == DNS_QTYPE_TKEY) {
					break;
				}
			}

			if (i == reply->ancount) {
				status = NT_STATUS_INVALID_NETWORK_RESPONSE;
				goto error;
			}

			tkey = &tkey_answer->rdata.tkey_record;

			in = data_blob_const(tkey->key_data, tkey->key_size);
		}

	} while (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED));

	/* If we arrive here, we have a valid security context */

	status = NT_STATUS_OK;

      error:

	TALLOC_FREE(frame);
	return status;
}

/*********************************************************************
*********************************************************************/

static NTSTATUS DoDNSUpdateNegotiateGensec(const char *pszServerAddress,
					   const char *pszServerName,
					   const char *pszDomainName,
					   const char *keyname,
					   enum dns_ServerType srv_type,
					   struct cli_credentials *creds,
					   TALLOC_CTX *mem_ctx,
					   struct gensec_security **_gensec)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct auth_generic_state *ans = NULL;
	NTSTATUS status;

	status = auth_generic_client_prepare(mem_ctx, &ans);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}
	talloc_steal(frame, ans);

	status = auth_generic_set_creds(ans, creds);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	status = gensec_set_target_service(ans->gensec_security,
					   "dns");
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	status = gensec_set_target_hostname(ans->gensec_security,
					    pszServerName);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	gensec_want_feature(ans->gensec_security, GENSEC_FEATURE_SIGN);

	status = auth_generic_client_start(ans, GENSEC_OID_KERBEROS5);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	status = dns_negotiate_sec_ctx(pszServerAddress,
				       keyname,
				       ans->gensec_security,
				       srv_type);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	*_gensec = talloc_move(mem_ctx, &ans->gensec_security);
 error:
	TALLOC_FREE(frame);

	return status;
}

NTSTATUS DoDNSUpdate(const char *pszServerAddress,
		     const char *pszServerName,
		     const char *pszDomainName,
		     const char *pszHostName,
		     struct cli_credentials *creds,
		     const struct sockaddr_storage *_sslist,
		     size_t num_addrs,
		     uint32_t flags,
		     uint32_t ttl,
		     bool remove_host)
{
	TALLOC_CTX *mem_ctx;
	struct samba_sockaddr sslist[num_addrs];
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	size_t i;

	DEBUG(10,("DoDNSUpdate called with flags: 0x%08x\n", flags));

	if (!(flags & DNS_UPDATE_SIGNED) &&
	    !(flags & DNS_UPDATE_UNSIGNED) &&
	    !(flags & DNS_UPDATE_PROBE)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!remove_host && ((num_addrs <= 0) || !_sslist)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!(mem_ctx = talloc_init("DoDNSUpdate"))) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_addrs; i++) {
		sslist[i] = (struct samba_sockaddr){.u.ss = _sslist[i]};
	}

	if (flags & DNS_UPDATE_PROBE) {

		struct dns_name_packet *probe = NULL, *reply = NULL;
		int ret;

		probe = dns_cli_create_probe(mem_ctx,
					     pszDomainName,
					     pszHostName,
					     sslist,
					     num_addrs);
		if (probe == NULL) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		ret = dns_cli_request(mem_ctx,
				      pszServerAddress,
				      probe,
				      &reply);
		if (ret != 0) {
			TALLOC_FREE(mem_ctx);
			return map_nt_error_from_unix(ret);
		}

		if ((flags & DNS_UPDATE_PROBE_SUFFICIENT) &&
		    ((reply->operation & DNS_RCODE) == DNS_RCODE_OK))
		{
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_OK;
		}
	}

	if (flags & DNS_UPDATE_UNSIGNED) {

		struct dns_name_packet *update = NULL, *reply = NULL;
		int ret;

		update = dns_cli_create_update(mem_ctx,
					       pszDomainName,
					       pszHostName,
					       sslist,
					       num_addrs,
					       ttl);
		if (update == NULL) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		ret = dns_cli_request(mem_ctx,
				      pszServerAddress,
				      update,
				      &reply);
		if (ret != 0) {
			TALLOC_FREE(mem_ctx);
			return map_nt_error_from_unix(ret);
		}

		if ((flags & DNS_UPDATE_UNSIGNED_SUFFICIENT) &&
		    ((reply->operation & DNS_RCODE) == DNS_RCODE_OK))
		{
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_OK;
		}
	}

	/*
	 * Okay, we have to try with signing
	 */
	if (flags & DNS_UPDATE_SIGNED) {
		struct gensec_security *gensec = NULL;
		struct GUID key_guid = GUID_random();
		struct GUID_txt_buf guid_buf = {};
		char *keyname = GUID_buf_string(&key_guid, &guid_buf);
		struct dns_name_packet *update = NULL, *reply = NULL;
		int ret;

		update = dns_cli_create_update(mem_ctx,
					       pszDomainName,
					       pszHostName,
					       sslist,
					       num_addrs,
					       ttl);
		if (update == NULL) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		status = DoDNSUpdateNegotiateGensec(pszServerAddress,
						    pszServerName,
						    pszDomainName,
						    keyname,
						    DNS_SRV_ANY,
						    creds,
						    mem_ctx,
						    &gensec);

		/* retry using the Windows 2000 DNS hack */
		if (!NT_STATUS_IS_OK(status)) {
			status = DoDNSUpdateNegotiateGensec(pszServerAddress,
							    pszServerName,
							    pszDomainName,
							    keyname,
							    DNS_SRV_WIN2000,
							    creds,
							    mem_ctx,
							    &gensec);
		}

		if (!NT_STATUS_IS_OK(status)) {
			goto error;
		}

		ret = dns_cli_sign_packet(update,
					  gensec,
					  gensec_sign_packet,
					  keyname,
					  "gss.microsoft.com");
		if (ret != 0) {
			status = map_nt_error_from_unix(ret);
			goto error;
		}

		ret = dns_cli_request(mem_ctx,
				      pszServerAddress,
				      update,
				      &reply);
		if (ret != 0) {
			TALLOC_FREE(mem_ctx);
			return map_nt_error_from_unix(ret);
		}

		status = ((reply->operation & DNS_RCODE) == DNS_RCODE_OK)
				 ? NT_STATUS_OK
				 : NT_STATUS_UNSUCCESSFUL;

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3,("DoDNSUpdate: signed update failed\n"));
		}
	}


error:
	TALLOC_FREE(mem_ctx);
	return status;
}

/*********************************************************************
*********************************************************************/

int get_my_ip_address( struct sockaddr_storage **pp_ss )

{
	int i, n;
	struct sockaddr_storage *list = NULL;
	int count = 0;

	/* Honor the configured list of interfaces to register */

	load_interfaces();
	n = iface_count();

	if (n <= 0) {
		return -1;
	}

	if ( (list = SMB_MALLOC_ARRAY( struct sockaddr_storage, n )) == NULL ) {
		return -1;
	}

	for ( i=0; i<n; i++ ) {
		const struct sockaddr_storage *nic_sa_storage = NULL;

		if ((nic_sa_storage = iface_n_sockaddr_storage(i)) == NULL)
			continue;

		/* Don't register loopback addresses */
		if (is_loopback_addr((const struct sockaddr *)nic_sa_storage)) {
			continue;
		}

		/* Don't register link-local addresses */
		if (is_linklocal_addr(nic_sa_storage)) {
			continue;
		}

		memcpy(&list[count++], nic_sa_storage, sizeof(struct sockaddr_storage));
	}
	*pp_ss = list;

	return count;
}

#endif	/* defined(HAVE_KRB5) */
