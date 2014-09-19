/* 
   Unix SMB/CIFS implementation.
   simple kerberos5/SPNEGO routines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   Copyright (C) Luke Howard     2003
   Copyright (C) Jeremy Allison 2010

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
#include "../libcli/auth/spnego.h"
#include "smb_krb5.h"
#include "../lib/util/asn1.h"

/*
  generate a negTokenInit packet given a list of supported
  OIDs (the mechanisms) a blob, and a principal name string
*/

DATA_BLOB spnego_gen_negTokenInit(TALLOC_CTX *ctx,
				  const char *OIDs[],
				  DATA_BLOB *psecblob,
				  const char *principal)
{
	int i;
	ASN1_DATA *data;
	DATA_BLOB ret = data_blob_null;

	data = asn1_init(talloc_tos());
	if (data == NULL) {
		return data_blob_null;
	}

	if (!asn1_push_tag(data,ASN1_APPLICATION(0))) goto err;
	if (!asn1_write_OID(data,OID_SPNEGO)) goto err;
	if (!asn1_push_tag(data,ASN1_CONTEXT(0))) goto err;
	if (!asn1_push_tag(data,ASN1_SEQUENCE(0))) goto err;

	if (!asn1_push_tag(data,ASN1_CONTEXT(0))) goto err;
	if (!asn1_push_tag(data,ASN1_SEQUENCE(0))) goto err;
	for (i=0; OIDs[i]; i++) {
		if (!asn1_write_OID(data,OIDs[i])) goto err;
	}
	if (!asn1_pop_tag(data)) goto err;
	if (!asn1_pop_tag(data)) goto err;

	if (psecblob && psecblob->length && psecblob->data) {
		if (!asn1_push_tag(data, ASN1_CONTEXT(2))) goto err;
		if (!asn1_write_OctetString(data,psecblob->data,
			psecblob->length)) goto err;
		if (!asn1_pop_tag(data)) goto err;
	}

	if (principal) {
		if (!asn1_push_tag(data, ASN1_CONTEXT(3))) goto err;
		if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
		if (!asn1_push_tag(data, ASN1_CONTEXT(0))) goto err;
		if (!asn1_write_GeneralString(data,principal)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		if (!asn1_pop_tag(data)) goto err;
		if (!asn1_pop_tag(data)) goto err;
	}

	if (!asn1_pop_tag(data)) goto err;
	if (!asn1_pop_tag(data)) goto err;

	if (!asn1_pop_tag(data)) goto err;

	ret = data_blob_talloc(ctx, data->data, data->length);

  err:

	if (data->has_error) {
		DEBUG(1,("Failed to build negTokenInit at offset %d\n", (int)data->ofs));
	}

	asn1_free(data);

	return ret;
}

/*
  parse a negTokenInit packet giving a GUID, a list of supported
  OIDs (the mechanisms) and a principal name string 
*/
bool spnego_parse_negTokenInit(TALLOC_CTX *ctx,
			       DATA_BLOB blob,
			       char *OIDs[ASN1_MAX_OIDS],
			       char **principal,
			       DATA_BLOB *secblob)
{
	int i;
	bool ret = false;
	ASN1_DATA *data;

	for (i = 0; i < ASN1_MAX_OIDS; i++) {
		OIDs[i] = NULL;
	}

	if (principal) {
		*principal = NULL;
	}
	if (secblob) {
		*secblob = data_blob_null;
	}

	data = asn1_init(talloc_tos());
	if (data == NULL) {
		return false;
	}

	if (!asn1_load(data, blob)) goto err;

	if (!asn1_start_tag(data,ASN1_APPLICATION(0))) goto err;

	if (!asn1_check_OID(data,OID_SPNEGO)) goto err;

	/* negTokenInit  [0]  NegTokenInit */
	if (!asn1_start_tag(data,ASN1_CONTEXT(0))) goto err;
	if (!asn1_start_tag(data,ASN1_SEQUENCE(0))) goto err;

	/* mechTypes [0] MechTypeList  OPTIONAL */

	/* Not really optional, we depend on this to decide
	 * what mechanisms we have to work with. */

	if (!asn1_start_tag(data,ASN1_CONTEXT(0))) goto err;
	if (!asn1_start_tag(data,ASN1_SEQUENCE(0))) goto err;
	for (i=0; asn1_tag_remaining(data) > 0 && i < ASN1_MAX_OIDS-1; i++) {
		if (!asn1_read_OID(data,ctx, &OIDs[i])) {
			goto err;
		}
		if (data->has_error) {
			goto err;
		}
	}
	OIDs[i] = NULL;
	if (!asn1_end_tag(data)) goto err;
	if (!asn1_end_tag(data)) goto err;

	/*
	  Win7 + Live Sign-in Assistant attaches a mechToken
	  ASN1_CONTEXT(2) to the negTokenInit packet
	  which breaks our negotiation if we just assume
	  the next tag is ASN1_CONTEXT(3).
	*/

	if (asn1_peek_tag(data, ASN1_CONTEXT(1))) {
		uint8 flags;

		/* reqFlags [1] ContextFlags  OPTIONAL */
		if (!asn1_start_tag(data, ASN1_CONTEXT(1))) goto err;
		if (!asn1_start_tag(data, ASN1_BIT_STRING)) goto err;
		while (asn1_tag_remaining(data) > 0) {
			if (!asn1_read_uint8(data, &flags)) goto err;
		}
		if (!asn1_end_tag(data)) goto err;
		if (!asn1_end_tag(data)) goto err;
	}

	if (asn1_peek_tag(data, ASN1_CONTEXT(2))) {
		DATA_BLOB sblob = data_blob_null;
		/* mechToken [2] OCTET STRING  OPTIONAL */
		if (!asn1_start_tag(data, ASN1_CONTEXT(2))) goto err;
		if (!asn1_read_OctetString(data, ctx, &sblob)) goto err;
		if (!asn1_end_tag(data)) {
			data_blob_free(&sblob);
			goto err;
		}
		if (secblob) {
			*secblob = sblob;
		} else {
			data_blob_free(&sblob);
		}
	}

	if (asn1_peek_tag(data, ASN1_CONTEXT(3))) {
		char *princ = NULL;
		/* mechListMIC [3] OCTET STRING  OPTIONAL */
		if (!asn1_start_tag(data, ASN1_CONTEXT(3))) goto err;
		if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) goto err;
		if (!asn1_start_tag(data, ASN1_CONTEXT(0))) goto err;
		if (!asn1_read_GeneralString(data, ctx, &princ)) goto err;
		if (!asn1_end_tag(data)) goto err;
		if (!asn1_end_tag(data)) goto err;
		if (!asn1_end_tag(data)) goto err;
		if (principal) {
			*principal = princ;
		} else {
			TALLOC_FREE(princ);
		}
	}

	if (!asn1_end_tag(data)) goto err;
	if (!asn1_end_tag(data)) goto err;

	if (!asn1_end_tag(data)) goto err;

	ret = !data->has_error;

  err:

	if (data->has_error) {
		int j;
		if (principal) {
			TALLOC_FREE(*principal);
		}
		if (secblob) {
			data_blob_free(secblob);
		}
		for(j = 0; j < i && j < ASN1_MAX_OIDS-1; j++) {
			TALLOC_FREE(OIDs[j]);
		}
	}

	asn1_free(data);
	return ret;
}

/*
  generate a krb5 GSS-API wrapper packet given a ticket
*/
DATA_BLOB spnego_gen_krb5_wrap(TALLOC_CTX *ctx, const DATA_BLOB ticket, const uint8 tok_id[2])
{
	ASN1_DATA *data;
	DATA_BLOB ret = data_blob_null;

	data = asn1_init(talloc_tos());
	if (data == NULL) {
		return data_blob_null;
	}

	if (!asn1_push_tag(data, ASN1_APPLICATION(0))) goto err;
	if (!asn1_write_OID(data, OID_KERBEROS5)) goto err;

	if (!asn1_write(data, tok_id, 2)) goto err;
	if (!asn1_write(data, ticket.data, ticket.length)) goto err;
	if (!asn1_pop_tag(data)) goto err;

	ret = data_blob_talloc(ctx, data->data, data->length);

  err:

	if (data->has_error) {
		DEBUG(1,("Failed to build krb5 wrapper at offset %d\n", (int)data->ofs));
	}

	asn1_free(data);

	return ret;
}

/* 
   generate a SPNEGO krb5 negTokenInit packet, ready for a EXTENDED_SECURITY
   kerberos session setup
*/
int spnego_gen_krb5_negTokenInit(TALLOC_CTX *ctx,
			    const char *principal, int time_offset,
			    DATA_BLOB *targ,
			    DATA_BLOB *session_key_krb5, uint32 extra_ap_opts,
			    const char *ccname, time_t *expire_time)
{
	int retval;
	DATA_BLOB tkt, tkt_wrapped;
	const char *krb_mechs[] = {OID_KERBEROS5_OLD, OID_KERBEROS5, OID_NTLMSSP, NULL};

	/* get a kerberos ticket for the service and extract the session key */
	retval = cli_krb5_get_ticket(ctx, principal, time_offset,
					  &tkt, session_key_krb5,
					  extra_ap_opts, ccname,
					  expire_time, NULL);
	if (retval) {
		return retval;
	}

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(ctx, tkt, TOK_ID_KRB_AP_REQ);

	/* and wrap that in a shiny SPNEGO wrapper */
	*targ = spnego_gen_negTokenInit(ctx, krb_mechs, &tkt_wrapped, NULL);

	data_blob_free(&tkt_wrapped);
	data_blob_free(&tkt);

	return retval;
}


/*
  parse a spnego NTLMSSP challenge packet giving two security blobs
*/
bool spnego_parse_challenge(TALLOC_CTX *ctx, const DATA_BLOB blob,
			    DATA_BLOB *chal1, DATA_BLOB *chal2)
{
	bool ret = false;
	ASN1_DATA *data;

	ZERO_STRUCTP(chal1);
	ZERO_STRUCTP(chal2);

	data = asn1_init(talloc_tos());
	if (data == NULL) {
		return false;
	}

	if (!asn1_load(data, blob)) goto err;
	if (!asn1_start_tag(data,ASN1_CONTEXT(1))) goto err;
	if (!asn1_start_tag(data,ASN1_SEQUENCE(0))) goto err;

	if (!asn1_start_tag(data,ASN1_CONTEXT(0))) goto err;
	if (!asn1_check_enumerated(data,1)) goto err;
	if (!asn1_end_tag(data)) goto err;

	if (!asn1_start_tag(data,ASN1_CONTEXT(1))) goto err;
	if (!asn1_check_OID(data, OID_NTLMSSP)) goto err;
	if (!asn1_end_tag(data)) goto err;

	if (!asn1_start_tag(data,ASN1_CONTEXT(2))) goto err;
	if (!asn1_read_OctetString(data, ctx, chal1)) goto err;
	if (!asn1_end_tag(data)) goto err;

	/* the second challenge is optional (XP doesn't send it) */
	if (asn1_tag_remaining(data)) {
		if (!asn1_start_tag(data,ASN1_CONTEXT(3))) goto err;
		if (!asn1_read_OctetString(data, ctx, chal2)) goto err;
		if (!asn1_end_tag(data)) goto err;
	}

	if (!asn1_end_tag(data)) goto err;
	if (!asn1_end_tag(data)) goto err;

	ret = !data->has_error;

  err:

	if (data->has_error) {
		data_blob_free(chal1);
		data_blob_free(chal2);
	}

	asn1_free(data);
	return ret;
}


/*
 generate a SPNEGO auth packet. This will contain the encrypted passwords
*/
DATA_BLOB spnego_gen_auth(TALLOC_CTX *ctx, DATA_BLOB blob)
{
	ASN1_DATA *data;
	DATA_BLOB ret = data_blob_null;

	data = asn1_init(talloc_tos());
	if (data == NULL) {
		return data_blob_null;
	}

	if (!asn1_push_tag(data, ASN1_CONTEXT(1))) goto err;
	if (!asn1_push_tag(data, ASN1_SEQUENCE(0))) goto err;
	if (!asn1_push_tag(data, ASN1_CONTEXT(2))) goto err;
	if (!asn1_write_OctetString(data,blob.data,blob.length)) goto err;
	if (!asn1_pop_tag(data)) goto err;
	if (!asn1_pop_tag(data)) goto err;
	if (!asn1_pop_tag(data)) goto err;

	ret = data_blob_talloc(ctx, data->data, data->length);

 err:

	asn1_free(data);

	return ret;
}

/*
 parse a SPNEGO auth packet. This contains the encrypted passwords
*/
bool spnego_parse_auth_response(TALLOC_CTX *ctx,
			        DATA_BLOB blob, NTSTATUS nt_status,
				const char *mechOID,
				DATA_BLOB *auth)
{
	ASN1_DATA *data;
	uint8 negResult;
	bool ret = false;

	if (NT_STATUS_IS_OK(nt_status)) {
		negResult = SPNEGO_ACCEPT_COMPLETED;
	} else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		negResult = SPNEGO_ACCEPT_INCOMPLETE;
	} else {
		negResult = SPNEGO_REJECT;
	}

	data = asn1_init(talloc_tos());
	if (data == NULL) {
		return false;
	}

	*auth = data_blob_null;

	if (!asn1_load(data, blob)) goto err;
	if (!asn1_start_tag(data, ASN1_CONTEXT(1))) goto err;
	if (!asn1_start_tag(data, ASN1_SEQUENCE(0))) goto err;
	if (!asn1_start_tag(data, ASN1_CONTEXT(0))) goto err;
	if (!asn1_check_enumerated(data, negResult)) goto err;
	if (!asn1_end_tag(data)) goto err;

	if (asn1_tag_remaining(data)) {
		if (!asn1_start_tag(data,ASN1_CONTEXT(1))) goto err;
		if (!asn1_check_OID(data, mechOID)) goto err;
		if (!asn1_end_tag(data)) goto err;

		if (asn1_tag_remaining(data)) {
			if (!asn1_start_tag(data,ASN1_CONTEXT(2))) goto err;
			if (!asn1_read_OctetString(data, ctx, auth)) goto err;
			if (!asn1_end_tag(data)) goto err;
		}
	} else if (negResult == SPNEGO_ACCEPT_INCOMPLETE) {
		data->has_error = 1;
		goto err;
	}

	/* Binding against Win2K DC returns a duplicate of the responseToken in
	 * the optional mechListMIC field. This is a bug in Win2K. We ignore
	 * this field if it exists. Win2K8 may return a proper mechListMIC at
	 * which point we need to implement the integrity checking. */
	if (asn1_tag_remaining(data)) {
		DATA_BLOB mechList = data_blob_null;
		if (!asn1_start_tag(data, ASN1_CONTEXT(3))) goto err;
		if (!asn1_read_OctetString(data, ctx, &mechList)) goto err;
		data_blob_free(&mechList);
		if (!asn1_end_tag(data)) goto err;
		DEBUG(5,("spnego_parse_auth_response received mechListMIC, "
		    "ignoring.\n"));
	}

	if (!asn1_end_tag(data)) goto err;
	if (!asn1_end_tag(data)) goto err;

	ret = !data->has_error;

  err:

	if (data->has_error) {
		DEBUG(3,("spnego_parse_auth_response failed at %d\n", (int)data->ofs));
		asn1_free(data);
		data_blob_free(auth);
		return false;
	}

	asn1_free(data);
	return ret;
}
