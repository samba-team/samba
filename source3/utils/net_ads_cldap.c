/* 
   Samba Unix/Linux SMB client library 
   net ads cldap functions 
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2003 Jim McDonough (jmcd@us.ibm.com)

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

#define MAX_DNS_LABEL 255 + 1

struct cldap_netlogon_reply {
	uint32 type;
	uint32 flags;
	UUID_FLAT guid;

	char forest[MAX_DNS_LABEL];
	char domain[MAX_DNS_LABEL];
	char hostname[MAX_DNS_LABEL];

	char netbios_domain[MAX_DNS_LABEL];
	char netbios_hostname[MAX_DNS_LABEL];

	char unk[MAX_DNS_LABEL];
	char user_name[MAX_DNS_LABEL];
	char site_name[MAX_DNS_LABEL];
	char site_name_2[MAX_DNS_LABEL];

	uint32 version;
	uint16 lmnt_token;
	uint16 lm20_token;
};

/*
  These seem to be strings as described in RFC1035 4.1.4 and can be:

   - a sequence of labels ending in a zero octet
   - a pointer
   - a sequence of labels ending with a pointer

  A label is a byte where the first two bits must be zero and the remaining
  bits represent the length of the label followed by the label itself.
  Therefore, the length of a label is at max 64 bytes.  Under RFC1035, a
  sequence of labels cannot exceed 255 bytes.

  A pointer consists of a 14 bit offset from the beginning of the data.

  struct ptr {
    unsigned ident:2; // must be 11
    unsigned offset:14; // from the beginning of data
  };

  This is used as a method to compress the packet by eliminated duplicate
  domain components.  Since a UDP packet should probably be < 512 bytes and a
  DNS name can be up to 255 bytes, this actually makes a lot of sense.
*/
static unsigned pull_netlogon_string(char *ret, const char *ptr,
				     const char *data)
{
	char *pret = ret;
	int followed_ptr = 0;
	unsigned ret_len = 0;

	memset(pret, 0, MAX_DNS_LABEL);
	do {
		if ((*ptr & 0xc0) == 0xc0) {
			uint16 len;

			if (!followed_ptr) {
				ret_len += 2;
				followed_ptr = 1;
			}
			len = ((ptr[0] & 0x3f) << 8) | ptr[1];
			ptr = data + len;
		} else if (*ptr) {
			uint8 len = (uint8)*(ptr++);

			if ((pret - ret + len + 1) >= MAX_DNS_LABEL) {
				d_printf("DC returning too long DNS name\n");
				return 0;
			}

			if (pret != ret) {
				*pret = '.';
				pret++;
			}
			memcpy(pret, ptr, len);
			pret += len;
			ptr += len;

			if (!followed_ptr) {
				ret_len += (len + 1);
			}
		}
	} while (*ptr);

	return followed_ptr ? ret_len : ret_len + 1;
}

/*
  do a cldap netlogon query
*/
static int send_cldap_netlogon(int sock, const char *domain, 
			       const char *hostname, unsigned ntversion)
{
	ASN1_DATA data;
	char ntver[4];
#ifdef CLDAP_USER_QUERY
	char aac[4];

	SIVAL(aac, 0, 0x00000180);
#endif
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

#ifdef CLDAP_USER_QUERY
	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_write_OctetString(&data, "User", 4);
	asn1_write_OctetString(&data, "SAMBA$", 6);
	asn1_pop_tag(&data);

	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_write_OctetString(&data, "AAC", 4);
	asn1_write_OctetString(&data, aac, 4);
	asn1_pop_tag(&data);
#endif

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

	if (write(sock, data.data, data.length) != (ssize_t)data.length) {
		d_printf("failed to send cldap query (%s)\n", strerror(errno));
	}

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

	p = (char *)os3.data;

	reply->type = IVAL(p, 0); p += 4;
	reply->flags = IVAL(p, 0); p += 4;

	memcpy(&reply->guid.info, p, UUID_FLAT_SIZE);
	p += UUID_FLAT_SIZE;

	p += pull_netlogon_string(reply->forest, p, (const char *)os3.data);
	p += pull_netlogon_string(reply->domain, p, (const char *)os3.data);
	p += pull_netlogon_string(reply->hostname, p, (const char *)os3.data);
	p += pull_netlogon_string(reply->netbios_domain, p, (const char *)os3.data);
	p += pull_netlogon_string(reply->netbios_hostname, p, (const char *)os3.data);
	p += pull_netlogon_string(reply->unk, p, (const char *)os3.data);

	if (reply->type == SAMLOGON_AD_R) {
		p += pull_netlogon_string(reply->user_name, p, (const char *)os3.data);
	} else {
		*reply->user_name = 0;
	}

	p += pull_netlogon_string(reply->site_name, p, (const char *)os3.data);
	p += pull_netlogon_string(reply->site_name_2, p, (const char *)os3.data);

	reply->version = IVAL(p, 0);
	reply->lmnt_token = SVAL(p, 4);
	reply->lm20_token = SVAL(p, 6);

	data_blob_free(&os1);
	data_blob_free(&os2);
	data_blob_free(&os3);
	data_blob_free(&blob);
	
	return 0;
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

	d_printf("Information for Domain Controller: %s\n\n", 
		 ads->config.ldap_server_name);

	d_printf("Response Type: ");
	switch (reply.type) {
	case SAMLOGON_AD_UNK_R:
		d_printf("SAMLOGON\n");
		break;
	case SAMLOGON_AD_R:
		d_printf("SAMLOGON_USER\n");
		break;
	default:
		d_printf("0x%x\n", reply.type);
		break;
	}
	d_printf("GUID: %s\n", 
		 smb_uuid_string_static(smb_uuid_unpack_static(reply.guid))); 
	d_printf("Flags:\n"
		 "\tIs a PDC:                                   %s\n"
		 "\tIs a GC of the forest:                      %s\n"
		 "\tIs an LDAP server:                          %s\n"
		 "\tSupports DS:                                %s\n"
		 "\tIs running a KDC:                           %s\n"
		 "\tIs running time services:                   %s\n"
		 "\tIs the closest DC:                          %s\n"
		 "\tIs writable:                                %s\n"
		 "\tHas a hardware clock:                       %s\n"
		 "\tIs a non-domain NC serviced by LDAP server: %s\n",
		 (reply.flags & ADS_PDC) ? "yes" : "no",
		 (reply.flags & ADS_GC) ? "yes" : "no",
		 (reply.flags & ADS_LDAP) ? "yes" : "no",
		 (reply.flags & ADS_DS) ? "yes" : "no",
		 (reply.flags & ADS_KDC) ? "yes" : "no",
		 (reply.flags & ADS_TIMESERV) ? "yes" : "no",
		 (reply.flags & ADS_CLOSEST) ? "yes" : "no",
		 (reply.flags & ADS_WRITABLE) ? "yes" : "no",
		 (reply.flags & ADS_GOOD_TIMESERV) ? "yes" : "no",
		 (reply.flags & ADS_NDNC) ? "yes" : "no");

	printf("Forest:\t\t\t%s\n", reply.forest);
	printf("Domain:\t\t\t%s\n", reply.domain);
	printf("Domain Controller:\t%s\n", reply.hostname);

	printf("Pre-Win2k Domain:\t%s\n", reply.netbios_domain);
	printf("Pre-Win2k Hostname:\t%s\n", reply.netbios_hostname);

	if (*reply.unk) printf("Unk:\t\t\t%s\n", reply.unk);
	if (*reply.user_name) printf("User name:\t%s\n", reply.user_name);

	printf("Site Name:\t\t%s\n", reply.site_name);
	printf("Site Name (2):\t\t%s\n", reply.site_name_2);

	d_printf("NT Version: %d\n", reply.version);
	d_printf("LMNT Token: %.2x\n", reply.lmnt_token);
	d_printf("LM20 Token: %.2x\n", reply.lm20_token);

	return ret;
}


#endif
