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

#if defined(HAVE_KRB5)

/*********************************************************************
*********************************************************************/

static DNS_ERROR DoDNSUpdateNegotiateGensec(const char *pszServerName,
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
	DNS_ERROR err;

	status = auth_generic_client_prepare(mem_ctx, &ans);
	if (!NT_STATUS_IS_OK(status)) {
		err = ERROR_DNS_GSS_ERROR;
		goto error;
	}
	talloc_steal(frame, ans);

	status = auth_generic_set_creds(ans, creds);
	if (!NT_STATUS_IS_OK(status)) {
		err = ERROR_DNS_GSS_ERROR;
		goto error;
	}

	status = gensec_set_target_service(ans->gensec_security,
					   "dns");
	if (!NT_STATUS_IS_OK(status)) {
		err = ERROR_DNS_GSS_ERROR;
		goto error;
	}

	status = gensec_set_target_hostname(ans->gensec_security,
					    pszServerName);
	if (!NT_STATUS_IS_OK(status)) {
		err = ERROR_DNS_GSS_ERROR;
		goto error;
	}

	gensec_want_feature(ans->gensec_security, GENSEC_FEATURE_SIGN);

	status = auth_generic_client_start(ans, GENSEC_OID_KERBEROS5);
	if (!NT_STATUS_IS_OK(status)) {
		err = ERROR_DNS_GSS_ERROR;
		goto error;
	}

	err = dns_negotiate_sec_ctx(pszServerName,
				    keyname,
				    ans->gensec_security,
				    srv_type);
	if (!ERR_DNS_IS_OK(err)) {
		goto error;
	}

	*_gensec = talloc_move(mem_ctx, &ans->gensec_security);
 error:
	TALLOC_FREE(frame);

	return err;
}

DNS_ERROR DoDNSUpdate(char *pszServerName,
		      const char *pszDomainName,
		      const char *pszHostName,
		      struct cli_credentials *creds,
		      const struct sockaddr_storage *sslist,
		      size_t num_addrs,
		      uint32_t flags,
		      uint32_t ttl,
		      bool remove_host)
{
	DNS_ERROR err;
	struct dns_connection *conn;
	TALLOC_CTX *mem_ctx;
	struct dns_update_request *req, *resp;

	DEBUG(10,("DoDNSUpdate called with flags: 0x%08x\n", flags));

	if (!(flags & DNS_UPDATE_SIGNED) &&
	    !(flags & DNS_UPDATE_UNSIGNED) &&
	    !(flags & DNS_UPDATE_PROBE)) {
		return ERROR_DNS_INVALID_PARAMETER;
	}

	if ( !remove_host && ((num_addrs <= 0) || !sslist) ) {
		return ERROR_DNS_INVALID_PARAMETER;
	}

	if (!(mem_ctx = talloc_init("DoDNSUpdate"))) {
		return ERROR_DNS_NO_MEMORY;
	}

	err = dns_open_connection( pszServerName, DNS_TCP, mem_ctx, &conn );
	if (!ERR_DNS_IS_OK(err)) {
		goto error;
	}

	if (flags & DNS_UPDATE_PROBE) {

		/*
		 * Probe if everything's fine
		 */

		err = dns_create_probe(mem_ctx, pszDomainName, pszHostName,
				       num_addrs, sslist, &req);
		if (!ERR_DNS_IS_OK(err)) goto error;

		err = dns_update_transaction(mem_ctx, conn, req, &resp);

		if (!ERR_DNS_IS_OK(err)) {
			DEBUG(3,("DoDNSUpdate: failed to probe DNS\n"));
			goto error;
		}

		if ((dns_response_code(resp->flags) == DNS_NO_ERROR) &&
		    (flags & DNS_UPDATE_PROBE_SUFFICIENT)) {
			TALLOC_FREE(mem_ctx);
			return ERROR_DNS_SUCCESS;
		}
	}

	if (flags & DNS_UPDATE_UNSIGNED) {

		/*
		 * First try without signing
		 */

		err = dns_create_update_request(mem_ctx,
						pszDomainName,
						pszHostName,
						sslist,
						num_addrs,
						ttl,
						&req);
		if (!ERR_DNS_IS_OK(err)) goto error;

		err = dns_update_transaction(mem_ctx, conn, req, &resp);
		if (!ERR_DNS_IS_OK(err)) {
			DEBUG(3,("DoDNSUpdate: unsigned update failed\n"));
			goto error;
		}

		if ((dns_response_code(resp->flags) == DNS_NO_ERROR) &&
		    (flags & DNS_UPDATE_UNSIGNED_SUFFICIENT)) {
			TALLOC_FREE(mem_ctx);
			return ERROR_DNS_SUCCESS;
		}
	}

	/*
	 * Okay, we have to try with signing
	 */
	if (flags & DNS_UPDATE_SIGNED) {
		struct gensec_security *gensec = NULL;
		char *keyname = NULL;

		err = dns_create_update_request(mem_ctx,
						pszDomainName,
						pszHostName,
						sslist,
						num_addrs,
						ttl,
						&req);
		if (!ERR_DNS_IS_OK(err)) goto error;

		if (!(keyname = dns_generate_keyname( mem_ctx ))) {
			err = ERROR_DNS_NO_MEMORY;
			goto error;
		}

		err = DoDNSUpdateNegotiateGensec(pszServerName,
						 pszDomainName,
						 keyname,
						 DNS_SRV_ANY,
						 creds,
						 mem_ctx,
						 &gensec);

		/* retry using the Windows 2000 DNS hack */
		if (!ERR_DNS_IS_OK(err)) {
			err = DoDNSUpdateNegotiateGensec(pszServerName,
							 pszDomainName,
							 keyname,
							 DNS_SRV_WIN2000,
							 creds,
							 mem_ctx,
							 &gensec);
		}

		if (!ERR_DNS_IS_OK(err))
			goto error;

		err = dns_sign_update(req, gensec, keyname,
				      "gss.microsoft.com", time(NULL), 3600);

		if (!ERR_DNS_IS_OK(err)) goto error;

		err = dns_update_transaction(mem_ctx, conn, req, &resp);
		if (!ERR_DNS_IS_OK(err)) goto error;

		err = (dns_response_code(resp->flags) == DNS_NO_ERROR) ?
			ERROR_DNS_SUCCESS : ERROR_DNS_UPDATE_FAILED;

		if (!ERR_DNS_IS_OK(err)) {
			DEBUG(3,("DoDNSUpdate: signed update failed\n"));
		}
	}


error:
	TALLOC_FREE(mem_ctx);
	return err;
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
