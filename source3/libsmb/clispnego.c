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

	data = asn1_init(talloc_tos(), ASN1_MAX_TREE_DEPTH);
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
		if (asn1_has_error(data)) {
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
		uint8_t flags;

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

	ret = !asn1_has_error(data);

  err:

	if (asn1_has_error(data)) {
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
DATA_BLOB spnego_gen_krb5_wrap(TALLOC_CTX *ctx, const DATA_BLOB ticket, const uint8_t tok_id[2])
{
	ASN1_DATA *data;
	DATA_BLOB ret = data_blob_null;

	data = asn1_init(talloc_tos(), ASN1_MAX_TREE_DEPTH);
	if (data == NULL) {
		return data_blob_null;
	}

	if (!asn1_push_tag(data, ASN1_APPLICATION(0))) goto err;
	if (!asn1_write_OID(data, OID_KERBEROS5)) goto err;

	if (!asn1_write(data, tok_id, 2)) goto err;
	if (!asn1_write(data, ticket.data, ticket.length)) goto err;
	if (!asn1_pop_tag(data)) goto err;

	if (!asn1_extract_blob(data, ctx, &ret)) {
		goto err;
	}

	asn1_free(data);
	data = NULL;

  err:

	if (data != NULL) {
		if (asn1_has_error(data)) {
			DEBUG(1, ("Failed to build krb5 wrapper at offset %d\n",
				  (int)asn1_current_ofs(data)));
		}

		asn1_free(data);
	}

	return ret;
}
