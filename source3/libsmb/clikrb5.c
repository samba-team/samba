/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   simple kerberos5/SPNEGO routines
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

#if HAVE_KRB5
#include <krb5.h>

#define OID_SPNEGO "1 3 6 1 5 5 2"
#define OID_KERBEROS5 "1 2 840 113554 1 2 2"

/*
  we can't use krb5_mk_req because w2k wants the service to be in a particular format
*/
static krb5_error_code krb5_mk_req2(krb5_context context, 
				    krb5_auth_context *auth_context, 
				    const krb5_flags ap_req_options,
				    const char *service, 
				    krb5_data *in_data,
				    krb5_ccache ccache, 
				    krb5_data *outbuf)
{
    krb5_error_code 	  retval;
    krb5_principal	  server;
    krb5_creds 		* credsp;
    krb5_creds 		  creds;
    char *realm;

    /* we should really get the realm from the negTargInit packet,
       but this will do until I've done the asn1 decoder for that */
    if ((retval = krb5_get_default_realm(context, &realm))) {
	    return retval;
    }

    retval = krb5_build_principal(context, &server, strlen(realm),
				  realm, service, NULL);
    if (retval)
      return retval;

    /* obtain ticket & session key */
    memset((char *)&creds, 0, sizeof(creds));
    if ((retval = krb5_copy_principal(context, server, &creds.server)))
	goto cleanup_princ;

    if ((retval = krb5_cc_get_principal(context, ccache, &creds.client)))
	goto cleanup_creds;

    if ((retval = krb5_get_credentials(context, 0,
				       ccache, &creds, &credsp)))
	goto cleanup_creds;

    retval = krb5_mk_req_extended(context, auth_context, ap_req_options, 
				  in_data, credsp, outbuf);

    krb5_free_creds(context, credsp);

cleanup_creds:
    krb5_free_cred_contents(context, &creds);

cleanup_princ:
    krb5_free_principal(context, server);

    return retval;
}

/*
  get a kerberos5 ticket for the given service 
*/
static DATA_BLOB krb5_get_ticket(char *service)
{
	krb5_error_code retval;
	krb5_data packet, inbuf;
	krb5_ccache ccdef;
	krb5_context context;
	krb5_auth_context auth_context = NULL;
	DATA_BLOB ret;

	retval = krb5_init_context(&context);
	if (retval) {
		DEBUG(1,("krb5_init_context failed\n"));
		goto failed;
	}

	inbuf.length = 0;

	if ((retval = krb5_cc_default(context, &ccdef))) {
		DEBUG(1,("krb5_cc_default failed\n"));
		goto failed;
	}

	if ((retval = krb5_mk_req2(context, 
				   &auth_context, 
				   AP_OPTS_MUTUAL_REQUIRED, 
				   service,
				   &inbuf, ccdef, &packet))) {
		DEBUG(1,("krb5_mk_req2 failed\n"));
		goto failed;
	}

	ret = data_blob(packet.data, packet.length);
	krb5_free_data_contents(context, &packet);
	krb5_free_context(context);
	return ret;

failed:
	krb5_free_context(context);
	return data_blob(NULL, 0);
}


/*
  generate a negTokenInit packet given a GUID, a list of supported
  OIDs (the mechanisms) and a principle name string 
*/
ASN1_DATA spnego_gen_negTokenInit(uint8 guid[16], 
				  const char *OIDs[], 
				  const char *principle)
{
	int i;
	ASN1_DATA data;

	memset(&data, 0, sizeof(data));

	asn1_write(&data, guid, 16);
	asn1_push_tag(&data,ASN1_APPLICATION(0));
	asn1_write_OID(&data,OID_SPNEGO);
	asn1_push_tag(&data,ASN1_CONTEXT(0));
	asn1_push_tag(&data,ASN1_SEQUENCE(0));

	asn1_push_tag(&data,ASN1_CONTEXT(0));
	asn1_push_tag(&data,ASN1_SEQUENCE(0));
	for (i=0; OIDs[i]; i++) {
		asn1_write_OID(&data,OIDs[i]);
	}
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_push_tag(&data, ASN1_SEQUENCE(0));
	asn1_push_tag(&data, ASN1_CONTEXT(0));
	asn1_write_GeneralString(&data,principle);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);

	return data;
}


/*
  generate a negTokenTarg packet given a list of OIDs and a security blob
*/
static ASN1_DATA gen_negTokenTarg(const char *OIDs[], ASN1_DATA blob)
{
	int i;
	ASN1_DATA data;

	memset(&data, 0, sizeof(data));

	asn1_push_tag(&data, ASN1_APPLICATION(0));
	asn1_write_OID(&data,OID_SPNEGO);
	asn1_push_tag(&data, ASN1_CONTEXT(0));
	asn1_push_tag(&data, ASN1_SEQUENCE(0));

	asn1_push_tag(&data, ASN1_CONTEXT(0));
	asn1_push_tag(&data, ASN1_SEQUENCE(0));
	for (i=0; OIDs[i]; i++) {
		asn1_write_OID(&data,OIDs[i]);
	}
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_push_tag(&data, ASN1_CONTEXT(2));
	asn1_write_OctetString(&data,blob.data,blob.length);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);

	return data;
}


/*
  generate a krb5 GSS-API wrapper packet given a ticket
*/
static ASN1_DATA spnego_gen_krb5_wrap(DATA_BLOB ticket)
{
	ASN1_DATA data;

	memset(&data, 0, sizeof(data));

	asn1_push_tag(&data, ASN1_APPLICATION(0));
	asn1_write_OID(&data, OID_KERBEROS5);
	asn1_write_BOOLEAN(&data, 0);
	asn1_write(&data, ticket.data, ticket.length);
	asn1_pop_tag(&data);

	return data;
}


/* 
   generate a SPNEGO negTokenTarg packet, ready for a EXTENDED_SECURITY
   kerberos session setup 
*/
DATA_BLOB spnego_gen_negTokenTarg(struct cli_state *cli)
{
	char *p;
	fstring service;
	DATA_BLOB tkt, ret;
	ASN1_DATA tkt_wrapped, targ;
	const char *krb_mechs[] = 
	{"1 2 840 48018 1 2 2", "1 3 6 1 4 1 311 2 2 10", NULL};

	/* the service name is the WINS name of the server in lowercase with
	   a $ on the end */
	fstrcpy(service, cli->desthost);
	p = strchr_m(service, '.');
	if (p) *p = 0;
	fstrcat(service, "$");
	strlower(service);

	/* get a kerberos ticket for the service */
	tkt = krb5_get_ticket(service);

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(tkt);

	/* and wrap that in a shiny SPNEGO wrapper */
	targ = gen_negTokenTarg(krb_mechs, tkt_wrapped);

	ret = data_blob(targ.data, targ.length);

	asn1_free(&tkt_wrapped);
	asn1_free(&targ);
	data_blob_free(tkt);

	return ret;
}

#else /* HAVE_KRB5 */
 void clikrb5_dummy(void) {}
#endif
