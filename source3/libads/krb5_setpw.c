/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   krb5 set password implementation
   Copyright (C) Andrew Tridgell 2001
   
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

#ifdef HAVE_KRB5

#define DEFAULT_KPASSWD_PORT	464
#define KRB5_KPASSWD_VERS_CHANGEPW	1
#define KRB5_KPASSWD_VERS_SETPW		0xff80
#define KRB5_KPASSWD_ACCESSDENIED	5
#define KRB5_KPASSWD_BAD_VERSION	6

/* This implements the Kerb password change protocol as specifed in
 * kerb-chg-password-02.txt
 */
static DATA_BLOB encode_krb5_setpw(const char *hostname, 
				   const char *realm, const char *password)
{
	ASN1_DATA req;
	DATA_BLOB ret;

	memset(&req, 0, sizeof(req));
	
	asn1_push_tag(&req, ASN1_SEQUENCE(0));
	asn1_push_tag(&req, ASN1_CONTEXT(0));
	asn1_write_OctetString(&req, password, strlen(password));
	asn1_pop_tag(&req);

	asn1_push_tag(&req, ASN1_CONTEXT(1));
	asn1_push_tag(&req, ASN1_SEQUENCE(0));

	asn1_push_tag(&req, ASN1_CONTEXT(0));
	asn1_write_Integer(&req, 1);
	asn1_pop_tag(&req);

	asn1_push_tag(&req, ASN1_CONTEXT(1));
	asn1_push_tag(&req, ASN1_SEQUENCE(0));
	asn1_write_GeneralString(&req, "HOST");
	asn1_write_GeneralString(&req, hostname);
	asn1_pop_tag(&req);
	asn1_pop_tag(&req);
	asn1_pop_tag(&req);
	asn1_pop_tag(&req);

	asn1_push_tag(&req, ASN1_CONTEXT(2));
	asn1_write_GeneralString(&req, realm);
	asn1_pop_tag(&req);
	asn1_pop_tag(&req);

	ret = data_blob(req.data, req.length);
	asn1_free(&req);

	return ret;
}	

static krb5_error_code build_setpw_request(krb5_context context,
					   krb5_auth_context auth_context,
					   krb5_data *ap_req,
					   const char *hostname,
					   const char *realm,
					   const char *passwd,
					   krb5_data *packet)
{
	krb5_error_code ret;
	krb5_data cipherpw;
	krb5_data encoded_setpw;
	krb5_replay_data replay;
	char *p;
	DATA_BLOB setpw;

	ret = krb5_auth_con_setflags(context,
				     auth_context,KRB5_AUTH_CONTEXT_DO_SEQUENCE);
	if (ret) {
		DEBUG(1,("krb5_auth_con_setflags failed (%s)\n",
			 error_message(ret)));
		return ret;
	}

	setpw = encode_krb5_setpw(hostname, realm, passwd);

	encoded_setpw.data = setpw.data;
	encoded_setpw.length = setpw.length;

	ret = krb5_mk_priv(context, auth_context,
			   &encoded_setpw, &cipherpw, &replay);
	if (ret) {
		DEBUG(1,("krb5_mk_priv failed (%s)\n", error_message(ret)));
		return ret;
	}

	packet->data = (char *)malloc(ap_req->length + cipherpw.length + 6);

	/* see the RFC for details */
	p = packet->data + 2;
	RSSVAL(p, 0, 0xff80); p += 2;
	RSSVAL(p, 0, ap_req->length); p += 2;
	memcpy(p, ap_req->data, ap_req->length); p += ap_req->length;
	memcpy(p, cipherpw.data, cipherpw.length); p += cipherpw.length;
	packet->length = PTR_DIFF(p,packet->data);
	RSSVAL(packet->data, 0, packet->length);
	
	return 0;
}

static krb5_error_code parse_setpw_reply(krb5_context context, 
					 krb5_auth_context auth_context,
					 krb5_data *packet)
{
	krb5_data ap_rep;
	char *p;
	int vnum, ret, res_code;
	krb5_data cipherresult;
	krb5_data clearresult;
	krb5_ap_rep_enc_part *ap_rep_enc;
	krb5_replay_data replay;
	
	if (packet->length < 4) {
		return KRB5KRB_AP_ERR_MODIFIED;
	}
	
	p = packet->data;
	
	if (packet->data[0] == 0x7e || packet->data[0] == 0x5e) {
		/* it's an error packet. We should parse it ... */
		DEBUG(1,("Got error packet 0x%x from kpasswd server\n",
			 packet->data[0]));
		return KRB5KRB_AP_ERR_MODIFIED;
	}
	
	if (RSVAL(p, 0) != packet->length) {
		DEBUG(1,("Bad packet length (%d/%d) from kpasswd server\n",
			 RSVAL(p, 0), packet->length));
		return KRB5KRB_AP_ERR_MODIFIED;
	}

	p += 2;

	vnum = RSVAL(p, 0); p += 2;
	
	if (vnum != KRB5_KPASSWD_VERS_SETPW && vnum != KRB5_KPASSWD_VERS_CHANGEPW) {
		DEBUG(1,("Bad vnum (%d) from kpasswd server\n", vnum));
		return KRB5KDC_ERR_BAD_PVNO;
	}
	
	ap_rep.length = RSVAL(p, 0); p += 2;
	
	if (p + ap_rep.length >= packet->data + packet->length) {
		DEBUG(1,("ptr beyond end of packet from kpasswd server\n"));
		return KRB5KRB_AP_ERR_MODIFIED;
	}
	
	if (ap_rep.length == 0) {
		DEBUG(1,("got unencrypted setpw result?!\n"));
		return KRB5KRB_AP_ERR_MODIFIED;
	}

	/* verify ap_rep */
	ap_rep.data = p;
	p += ap_rep.length;
	
	ret = krb5_rd_rep(context, auth_context, &ap_rep, &ap_rep_enc);
	if (ret) {
		DEBUG(1,("failed to rd setpw reply (%s)\n", error_message(ret)));
		return KRB5KRB_AP_ERR_MODIFIED;
	}
	
	krb5_free_ap_rep_enc_part(context, ap_rep_enc);
	
	cipherresult.data = p;
	cipherresult.length = (packet->data + packet->length) - p;
		
	ret = krb5_rd_priv(context, auth_context, &cipherresult, &clearresult,
			   &replay);
	if (ret) {
		DEBUG(1,("failed to decrypt setpw reply (%s)\n", error_message(ret)));
		return KRB5KRB_AP_ERR_MODIFIED;
	}

	if (clearresult.length < 2) {
		ret = KRB5KRB_AP_ERR_MODIFIED;
		return KRB5KRB_AP_ERR_MODIFIED;
	}
	
	p = clearresult.data;
	
	res_code = RSVAL(p, 0);
	
	if ((res_code < KRB5_KPASSWD_SUCCESS) || 
	    (res_code > KRB5_KPASSWD_ACCESSDENIED)) {
		return KRB5KRB_AP_ERR_MODIFIED;
	}
	
	return 0;
}

NTSTATUS krb5_set_password(const char *kdc_host, const char *hostname,
			   const char *realm,  const char *newpw)
{
	krb5_context context;
	krb5_auth_context auth_context = NULL;
	krb5_principal principal;
	char *princ_name;
	krb5_creds creds, *credsp;
	krb5_ccache ccache;
	krb5_data ap_req, chpw_req, chpw_rep;
	int ret, sock, addr_len;
	struct sockaddr remote_addr, local_addr;
	krb5_address local_kaddr, remote_kaddr;

	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("Failed to init krb5 context (%s)\n", error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	ret = krb5_cc_default(context, &ccache);
	if (ret) {
		DEBUG(1,("Failed to get default creds (%s)\n", error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCT(creds);
	
	asprintf(&princ_name, "kadmin/changepw@%s", realm);
	ret = krb5_parse_name(context, princ_name, &creds.server);
	if (ret) {
		DEBUG(1,("Failed to parse kadmin/changepw (%s)\n", error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	free(princ_name);

	asprintf(&princ_name, "HOST/%s@%s", hostname, realm);
	ret = krb5_parse_name(context, princ_name, &principal);
	if (ret) {
		DEBUG(1,("Failed to parse %s (%s)\n", princ_name, error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	free(princ_name);

	krb5_princ_set_realm(context, creds.server,
			     krb5_princ_realm(context, principal));
	
	ret = krb5_cc_get_principal(context, ccache, &creds.client);
	if (ret) {
		DEBUG(1,("Failed to get principal from ccache (%s)\n", 
			 error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	ret = krb5_get_credentials(context, 0, ccache, &creds, &credsp);
	if (ret) {
		DEBUG(1,("krb5_get_credentials failed (%s)\n", error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	ret = krb5_mk_req_extended(context, &auth_context, AP_OPTS_USE_SUBKEY,
				   NULL, credsp, &ap_req);
	if (ret) {
		DEBUG(1,("krb5_mk_req_extended failed (%s)\n", error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	sock = open_udp_socket(kdc_host, DEFAULT_KPASSWD_PORT);
	if (sock == -1) {
		DEBUG(1,("failed to open kpasswd socket to %s (%s)\n", 
			 kdc_host, strerror(errno)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	addr_len = sizeof(remote_addr);
	getpeername(sock, &remote_addr, &addr_len);
	addr_len = sizeof(local_addr);
	getsockname(sock, &local_addr, &addr_len);
	
	remote_kaddr.addrtype = ADDRTYPE_INET;
	remote_kaddr.length = sizeof(((struct sockaddr_in *)&remote_addr)->sin_addr);
	remote_kaddr.contents = (char *)&(((struct sockaddr_in *)&remote_addr)->sin_addr);
	local_kaddr.addrtype = ADDRTYPE_INET;
	local_kaddr.length = sizeof(((struct sockaddr_in *)&local_addr)->sin_addr);
	local_kaddr.contents = (char *)&(((struct sockaddr_in *)&local_addr)->sin_addr);

	ret = krb5_auth_con_setaddrs(context, auth_context, &local_kaddr, NULL);
	if (ret) {
		DEBUG(1,("krb5_auth_con_setaddrs failed (%s)\n", error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = build_setpw_request(context, auth_context, &ap_req,
				  hostname, realm, newpw, &chpw_req);
	if (ret) {
		DEBUG(1,("build_setpw_request failed (%s)\n", error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (write(sock, chpw_req.data, chpw_req.length) != chpw_req.length) {
		DEBUG(1,("send of chpw failed (%s)\n", strerror(errno)));
		return NT_STATUS_UNSUCCESSFUL;		
	}

	free(chpw_req.data);

	chpw_rep.length = 1500;
	chpw_rep.data = (char *) malloc(chpw_rep.length);

	ret = read(sock, chpw_rep.data, chpw_rep.length);
	if (ret < 0) {
		DEBUG(1,("recv of chpw reply failed (%s)\n", strerror(errno)));
		return NT_STATUS_UNSUCCESSFUL;		
	}

	close(sock);
	chpw_rep.length = ret;

	ret = krb5_auth_con_setaddrs(context, auth_context, NULL,&remote_kaddr);
	if (ret) {
		DEBUG(1,("krb5_auth_con_setaddrs on reply failed (%s)\n", 
			 error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = parse_setpw_reply(context, auth_context, &chpw_rep);
	free(chpw_rep.data);

	if (ret) {
		DEBUG(1,("parse_setpw_reply failed (%s)\n", 
			 error_message(ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

#endif
