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

struct netlogon_string {
	uint32_t comp_len;
	char **component;
	uint8 extra_flag;
};

struct cldap_netlogon_reply {
	uint32_t type;
	uint32_t flags;
	GUID guid;

	struct netlogon_string forest;
	struct netlogon_string domain;
	struct netlogon_string hostname;

	struct netlogon_string netbios_domain;
	struct netlogon_string netbios_hostname;

	struct netlogon_string user_name;
	struct netlogon_string site_name;

	struct netlogon_string unk0;

	uint32_t version;
	uint16 lmnt_token;
	uint16 lm20_token;
};

/*
  These strings are rather interesting... They are composed of a series of
  length encoded strings, terminated by either 1) a zero length string or 2)
  a 0xc0 byte with what appears to be a one byte flags immediately following.
*/
static unsigned pull_netlogon_string(struct netlogon_string *ret,const char *d)
{
	char *p = (char *)d;

	ZERO_STRUCTP(ret);

	do {
		unsigned len = (unsigned char)*p;
		p++;

		if (len > 0 && len != 0xc0) {
			ret->component = realloc(ret->component,
						 ++ret->comp_len *
						 sizeof(char *));

			ret->component[ret->comp_len - 1] = 
				smb_xstrndup(p, len);
			p += len;
		} else {
			if (len == 0xc0) {
				ret->extra_flag = *p;
				p++;
			};
			break;
		}
	} while (1);

	return (p - d);
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
	uint32_t i1;
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

	reply->type = IVAL(p, 0); p += 4;
	reply->flags = IVAL(p, 0); p += 4;

	memcpy(&reply->guid.info, p, GUID_SIZE);
	p += GUID_SIZE;

	p += pull_netlogon_string(&reply->forest, p);
	p += pull_netlogon_string(&reply->domain, p);
	p += pull_netlogon_string(&reply->hostname, p);
	p += pull_netlogon_string(&reply->netbios_domain, p);
	p += pull_netlogon_string(&reply->netbios_hostname, p);
	p += pull_netlogon_string(&reply->user_name, p);
	p += pull_netlogon_string(&reply->site_name, p);

	p += pull_netlogon_string(&reply->unk0, p);

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
  free a netlogon string
*/
static void netlogon_string_free(struct netlogon_string *str)
{
	int i;

	for (i = 0; i < str->comp_len; ++i) {
		SAFE_FREE(str->component[i]);
	}
	SAFE_FREE(str->component);
}

/*
  free a cldap reply packet
*/
static void cldap_reply_free(struct cldap_netlogon_reply *reply)
{
	netlogon_string_free(&reply->forest);
	netlogon_string_free(&reply->domain);
	netlogon_string_free(&reply->hostname);
	netlogon_string_free(&reply->netbios_domain);
	netlogon_string_free(&reply->netbios_hostname);
	netlogon_string_free(&reply->user_name);
	netlogon_string_free(&reply->site_name);
	netlogon_string_free(&reply->unk0);
}

static void d_print_netlogon_string(const char *label, 
				    struct netlogon_string *str)
{
	int i;

	if (str->comp_len) {
		d_printf("%s", label);
		if (str->extra_flag) {
			d_printf("[%d]", str->extra_flag);
		}
		d_printf(": ");
		for (i = 0; i < str->comp_len; ++i) {
			d_printf("%s%s", (i ? "." : ""), str->component[i]);
		}
		d_printf("\n");
	}
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

	ret = send_cldap_netlogon(sock, ads->config.realm, lp_netbios_name(), 6);
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

	d_printf("Response Type: 0x%x\n", reply.type);
	d_printf("GUID: "); 
	print_guid(&reply.guid);
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

	d_print_netlogon_string("Forest", &reply.forest);
	d_print_netlogon_string("Domain", &reply.domain);
	d_print_netlogon_string("Hostname", &reply.hostname);

	d_print_netlogon_string("Pre-Win2k Domain", &reply.netbios_domain);
	d_print_netlogon_string("Pre-Win2k Hostname", &reply.netbios_hostname);

	d_print_netlogon_string("User name", &reply.user_name);
	d_print_netlogon_string("Site Name", &reply.site_name);
	d_print_netlogon_string("Unknown Field", &reply.unk0);

	d_printf("NT Version: %d\n", reply.version);
	d_printf("LMNT Token: %.2x\n", reply.lmnt_token);
	d_printf("LM20 Token: %.2x\n", reply.lm20_token);

	cldap_reply_free(&reply);
	
	return ret;
}


#endif
