/* 
   Samba Unix/Linux SMB client library 
   net ads cldap functions 
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)

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

#include "includes.h"
#include "../utils/net.h"

#ifdef HAVE_ADS

struct cldap_netlogon_reply {
	uint32 version;
	uint32 flags;
	GUID guid;
	char *domain;
	char *server_name;
	char *domain_flatname;
	char *server_flatname;
	char *dns_name;
	uint32 unknown2[2];
};


/*
  pull a length prefixed string from a packet
  return number of bytes consumed
*/
static unsigned pull_len_string(char **ret, const char *p)
{
	unsigned len = *p;
	(*ret) = NULL;
	if (len == 0) return 1;
	(*ret) = smb_xstrndup(p+1, len);
	return len+1;
}

/*
  pull a dotted string from a packet
  return number of bytes consumed
*/
static unsigned pull_dotted_string(char **ret, const char *p)
{
	char *s;
	unsigned len, total_len=0;

	(*ret) = NULL;

	while ((len = pull_len_string(&s, p)) > 1) {
		if (total_len) {
			char *s2;
			asprintf(&s2, "%s.%s", *ret, s);
			SAFE_FREE(*ret);
			(*ret) = s2;
		} else {
			(*ret) = s;
		}
		total_len += len;
		p += len;
	}

	return total_len + 1;
}


/*
  do a cldap netlogon query
*/
static int send_cldap_netlogon(int sock, const char *domain, 
			       const char *hostname, unsigned ntversion)
{
	ASN1_DATA data;
	char ntver[4];

	SIVAL(ntver, 0, ntversion);

	memset(&data, 0, sizeof(data));

	asn1_push_tag(&data,ASN1_SEQUENCE(0));
	asn1_write_Integer(&data, 4);
	asn1_push_tag(&data, ASN1_APPLICATION(3));
	asn1_write_OctetString(&data, NULL, 0);
	asn1_write_enumerated(&data, 0);
	asn1_write_enumerated(&data, 0);
	asn1_write_Integer(&data, 0);
	asn1_write_Integer(&data, 0);
	asn1_write_BOOLEAN2(&data, False);
	asn1_push_tag(&data, ASN1_CONTEXT(0));

	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_write_OctetString(&data, "DnsDomain", 9);
	asn1_write_OctetString(&data, domain, strlen(domain));
	asn1_pop_tag(&data);

	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_write_OctetString(&data, "Host", 4);
	asn1_write_OctetString(&data, hostname, strlen(hostname));
	asn1_pop_tag(&data);

	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_write_OctetString(&data, "NtVer", 5);
	asn1_write_OctetString(&data, ntver, 4);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);

	asn1_push_tag(&data,ASN1_SEQUENCE(0));
	asn1_write_OctetString(&data, "NetLogon", 8);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	if (data.has_error) {
		d_printf("Failed to build cldap netlogon at offset %d\n", (int)data.ofs);
		asn1_free(&data);
		return -1;
	}

	if (write(sock, data.data, data.length) != data.length) {
		d_printf("failed to send cldap query (%s)\n", strerror(errno));
	}

	file_save("cldap_query.dat", data.data, data.length);
	asn1_free(&data);

	return 0;
}


/*
  receive a cldap netlogon reply
*/
static int recv_cldap_netlogon(int sock, struct cldap_netlogon_reply *reply)
{
	int ret;
	ASN1_DATA data;
	DATA_BLOB blob;
	DATA_BLOB os1, os2, os3;
	uint32 i1;
	char *p;

	blob = data_blob(NULL, 8192);

	ret = read(sock, blob.data, blob.length);

	if (ret <= 0) {
		d_printf("no reply received to cldap netlogon\n");
		return -1;
	}
	blob.length = ret;

	file_save("cldap_reply.dat", blob.data, blob.length);

	asn1_load(&data, blob);
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_read_Integer(&data, &i1);
	asn1_start_tag(&data, ASN1_APPLICATION(4));
	asn1_read_OctetString(&data, &os1);
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_start_tag(&data, ASN1_SEQUENCE(0));
	asn1_read_OctetString(&data, &os2);
	asn1_start_tag(&data, ASN1_SET);
	asn1_read_OctetString(&data, &os3);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_end_tag(&data);
	asn1_end_tag(&data);

	if (data.has_error) {
		d_printf("Failed to parse cldap reply\n");
		return -1;
	}

	file_save("cldap_reply_core.dat", os3.data, os3.length);

	p = os3.data;

	reply->version = IVAL(p, 0); p += 4;
	reply->flags = IVAL(p, 0); p += 4;
	memcpy(&reply->guid.info, p, GUID_SIZE);
	p += GUID_SIZE;
	p += pull_dotted_string(&reply->domain, p);
	p += 2; /* 0xc018 - whats this? */
	p += pull_len_string(&reply->server_name, p);
	p += 2; /* 0xc018 - whats this? */
	p += pull_len_string(&reply->domain_flatname, p);
	p += 1;
	p += pull_len_string(&reply->server_flatname, p);
	p += 2;
	p += pull_len_string(&reply->dns_name, p);

	data_blob_free(&os1);
	data_blob_free(&os2);
	data_blob_free(&os3);
	data_blob_free(&blob);
	
	return 0;
}


/*
  free a cldap reply packet
*/
static void cldap_reply_free(struct cldap_netlogon_reply *reply)
{
	SAFE_FREE(reply->domain);
	SAFE_FREE(reply->server_name);
	SAFE_FREE(reply->domain_flatname);
	SAFE_FREE(reply->server_flatname);
	SAFE_FREE(reply->dns_name);
}

/*
  do a cldap netlogon query
*/
int ads_cldap_netlogon(ADS_STRUCT *ads)
{
	int sock;
	int ret;
	struct cldap_netlogon_reply reply;

	sock = open_udp_socket(inet_ntoa(ads->ldap_ip), ads->ldap_port);
	if (sock == -1) {
		d_printf("Failed to open udp socket to %s:%u\n", 
			 inet_ntoa(ads->ldap_ip), 
			 ads->ldap_port);
		return -1;
	}

	ret = send_cldap_netlogon(sock, ads->config.realm, global_myname(), 6);
	if (ret != 0) {
		return ret;
	}

	ret = recv_cldap_netlogon(sock, &reply);
	close(sock);

	if (ret == -1) {
		return -1;
	}

	d_printf("Version: 0x%x\n", reply.version);
	d_printf("GUID: "); 
	print_guid(&reply.guid);
	d_printf("Flags:   0x%x\n", reply.flags);
	d_printf("Domain: %s\n", reply.domain);
	d_printf("Server Name: %s\n", reply.server_name);
	d_printf("Flatname: %s\n", reply.domain_flatname);
	d_printf("Server Name2: %s\n", reply.server_flatname);
	d_printf("DNS Name: %s\n", reply.dns_name);

	cldap_reply_free(&reply);
	
	return ret;
}


#endif
