/* 
   Samba Unix/Linux SMB client library 
   net ads cldap functions 
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2003 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2008 Guenther Deschner (gd@samba.org)

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

/*
  do a cldap netlogon query
*/
static int send_cldap_netlogon(TALLOC_CTX *mem_ctx, int sock, const char *domain,
			       const char *hostname, unsigned ntversion)
{
	ASN1_DATA *data;
	char ntver[4];
#ifdef CLDAP_USER_QUERY
	char aac[4];

	SIVAL(aac, 0, 0x00000180);
#endif
	SIVAL(ntver, 0, ntversion);

	data = asn1_init(mem_ctx);
	if (data == NULL) {
		return -1;
	}

	asn1_push_tag(data,ASN1_SEQUENCE(0));
	asn1_write_Integer(data, 4);
	asn1_push_tag(data, ASN1_APPLICATION(3));
	asn1_write_OctetString(data, NULL, 0);
	asn1_write_enumerated(data, 0);
	asn1_write_enumerated(data, 0);
	asn1_write_Integer(data, 0);
	asn1_write_Integer(data, 0);
	asn1_write_BOOLEAN(data, False);
	asn1_push_tag(data, ASN1_CONTEXT(0));

	if (domain) {
		asn1_push_tag(data, ASN1_CONTEXT(3));
		asn1_write_OctetString(data, "DnsDomain", 9);
		asn1_write_OctetString(data, domain, strlen(domain));
		asn1_pop_tag(data);
	}

	asn1_push_tag(data, ASN1_CONTEXT(3));
	asn1_write_OctetString(data, "Host", 4);
	asn1_write_OctetString(data, hostname, strlen(hostname));
	asn1_pop_tag(data);

#ifdef CLDAP_USER_QUERY
	asn1_push_tag(data, ASN1_CONTEXT(3));
	asn1_write_OctetString(data, "User", 4);
	asn1_write_OctetString(data, "SAMBA$", 6);
	asn1_pop_tag(data);

	asn1_push_tag(data, ASN1_CONTEXT(3));
	asn1_write_OctetString(data, "AAC", 4);
	asn1_write_OctetString(data, aac, 4);
	asn1_pop_tag(data);
#endif

	asn1_push_tag(data, ASN1_CONTEXT(3));
	asn1_write_OctetString(data, "NtVer", 5);
	asn1_write_OctetString(data, ntver, 4);
	asn1_pop_tag(data);

	asn1_pop_tag(data);

	asn1_push_tag(data,ASN1_SEQUENCE(0));
	asn1_write_OctetString(data, "NetLogon", 8);
	asn1_pop_tag(data);
	asn1_pop_tag(data);
	asn1_pop_tag(data);

	if (data->has_error) {
		DEBUG(2,("Failed to build cldap netlogon at offset %d\n", (int)data->ofs));
		asn1_free(data);
		return -1;
	}

	if (write(sock, data->data, data->length) != (ssize_t)data->length) {
		DEBUG(2,("failed to send cldap query (%s)\n", strerror(errno)));
		asn1_free(data);
		return -1;
	}

	asn1_free(data);

	return 0;
}

/*
  receive a cldap netlogon reply
*/
static int recv_cldap_netlogon(TALLOC_CTX *mem_ctx,
			       int sock,
			       uint32_t nt_version,
			       struct netlogon_samlogon_response **reply)
{
	int ret;
	ASN1_DATA *data;
	DATA_BLOB blob = data_blob_null;
	DATA_BLOB os1 = data_blob_null;
	DATA_BLOB os2 = data_blob_null;
	DATA_BLOB os3 = data_blob_null;
	int i1;
	struct netlogon_samlogon_response *r = NULL;
	NTSTATUS status;

	fd_set r_fds;
	struct timeval timeout;

	blob = data_blob(NULL, 8192);
	if (blob.data == NULL) {
		DEBUG(1, ("data_blob failed\n"));
		errno = ENOMEM;
		return -1;
	}

	FD_ZERO(&r_fds);
	FD_SET(sock, &r_fds);

	/*
	 * half the time of a regular ldap timeout, not less than 3 seconds.
	 */
	timeout.tv_sec = MAX(3,lp_ldap_timeout()/2);
	timeout.tv_usec = 0;

	ret = sys_select(sock+1, &r_fds, NULL, NULL, &timeout);
	if (ret == -1) {
		DEBUG(10, ("select failed: %s\n", strerror(errno)));
		data_blob_free(&blob);
		return -1;
	}

	if (ret == 0) {
		DEBUG(1,("no reply received to cldap netlogon\n"));
		data_blob_free(&blob);
		return -1;
	}

	ret = read(sock, blob.data, blob.length);
	if (ret <= 0) {
		DEBUG(1,("no reply received to cldap netlogon\n"));
		data_blob_free(&blob);
		return -1;
	}
	blob.length = ret;

	data = asn1_init(mem_ctx);
	if (data == NULL) {
		data_blob_free(&blob);
		return -1;
	}

	asn1_load(data, blob);
	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_read_Integer(data, &i1);
	asn1_start_tag(data, ASN1_APPLICATION(4));
	asn1_read_OctetString(data, NULL, &os1);
	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_read_OctetString(data, NULL, &os2);
	asn1_start_tag(data, ASN1_SET);
	asn1_read_OctetString(data, NULL, &os3);
	asn1_end_tag(data);
	asn1_end_tag(data);
	asn1_end_tag(data);
	asn1_end_tag(data);
	asn1_end_tag(data);

	if (data->has_error) {
		data_blob_free(&blob);
		data_blob_free(&os1);
		data_blob_free(&os2);
		data_blob_free(&os3);
		asn1_free(data);
		DEBUG(1,("Failed to parse cldap reply\n"));
		return -1;
	}

	r = TALLOC_ZERO_P(mem_ctx, struct netlogon_samlogon_response);
	if (!r) {
		errno = ENOMEM;
		data_blob_free(&os1);
		data_blob_free(&os2);
		data_blob_free(&os3);
		data_blob_free(&blob);
		asn1_free(data);
		return -1;
	}

	status = pull_netlogon_samlogon_response(&os3, mem_ctx, NULL, r);
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&os1);
		data_blob_free(&os2);
		data_blob_free(&os3);
		data_blob_free(&blob);
		asn1_free(data);
		TALLOC_FREE(r);
		return -1;
	}

	map_netlogon_samlogon_response(r);

	data_blob_free(&os1);
	data_blob_free(&os2);
	data_blob_free(&os3);
	data_blob_free(&blob);

	asn1_free(data);

	if (reply) {
		*reply = r;
	} else {
		TALLOC_FREE(r);
	}

	return 0;
}

/*******************************************************************
  do a cldap netlogon query.  Always 389/udp
*******************************************************************/

bool ads_cldap_netlogon(TALLOC_CTX *mem_ctx,
			const char *server,
			const char *realm,
			uint32_t nt_version,
			struct netlogon_samlogon_response **reply)
{
	int sock;
	int ret;

	sock = open_udp_socket(server, LDAP_PORT );
	if (sock == -1) {
		DEBUG(2,("ads_cldap_netlogon: Failed to open udp socket to %s\n", 
			 server));
		return False;
	}

	ret = send_cldap_netlogon(mem_ctx, sock, realm, global_myname(), nt_version);
	if (ret != 0) {
		close(sock);
		return False;
	}
	ret = recv_cldap_netlogon(mem_ctx, sock, nt_version, reply);
	close(sock);

	if (ret == -1) {
		return False;
	}

	return True;
}

/*******************************************************************
  do a cldap netlogon query.  Always 389/udp
*******************************************************************/

bool ads_cldap_netlogon_5(TALLOC_CTX *mem_ctx,
			  const char *server,
			  const char *realm,
			  struct NETLOGON_SAM_LOGON_RESPONSE_EX *reply5)
{
	uint32_t nt_version = NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX;
	struct netlogon_samlogon_response *reply = NULL;
	bool ret;

	ret = ads_cldap_netlogon(mem_ctx, server, realm, nt_version, &reply);
	if (!ret) {
		return false;
	}

	if (reply->ntver != NETLOGON_NT_VERSION_5EX) {
		DEBUG(0,("ads_cldap_netlogon_5: nt_version mismatch: 0x%08x\n",
			reply->ntver));
		return false;
	}

	*reply5 = reply->data.nt5_ex;

	return true;
}
