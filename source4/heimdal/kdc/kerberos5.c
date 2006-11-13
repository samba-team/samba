/*
 * Copyright (c) 1997-2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "kdc_locl.h"

RCSID("$Id: kerberos5.c,v 1.225 2006/11/10 03:36:32 lha Exp $");

#define MAX_TIME ((time_t)((1U << 31) - 1))

void
_kdc_fix_time(time_t **t)
{
    if(*t == NULL){
	ALLOC(*t);
	**t = MAX_TIME;
    }
    if(**t == 0) **t = MAX_TIME; /* fix for old clients */
}

static int
realloc_method_data(METHOD_DATA *md)
{
    PA_DATA *pa;
    pa = realloc(md->val, (md->len + 1) * sizeof(*md->val));
    if(pa == NULL)
	return ENOMEM;
    md->val = pa;
    md->len++;
    return 0;
}

static void
set_salt_padata (METHOD_DATA *md, Salt *salt)
{
    if (salt) {
	realloc_method_data(md);
	md->val[md->len - 1].padata_type = salt->type;
	der_copy_octet_string(&salt->salt,
			      &md->val[md->len - 1].padata_value);
    }
}

PA_DATA*
_kdc_find_padata(KDC_REQ *req, int *start, int type)
{
    while(*start < req->padata->len){
	(*start)++;
	if(req->padata->val[*start - 1].padata_type == type)
	    return &req->padata->val[*start - 1];
    }
    return NULL;
}

/*
 * return the first appropriate key of `princ' in `ret_key'.  Look for
 * all the etypes in (`etypes', `len'), stopping as soon as we find
 * one, but preferring one that has default salt
 */

krb5_error_code
_kdc_find_etype(krb5_context context, const hdb_entry_ex *princ,
		krb5_enctype *etypes, unsigned len, 
		Key **ret_key, krb5_enctype *ret_etype)
{
    int i;
    krb5_error_code ret = KRB5KDC_ERR_ETYPE_NOSUPP;

    for(i = 0; ret != 0 && i < len ; i++) {
	Key *key = NULL;

	if (krb5_enctype_valid(context, etypes[i]) != 0)
	    continue;

	while (hdb_next_enctype2key(context, &princ->entry, etypes[i], &key) == 0) {
	    if (key->key.keyvalue.length == 0) {
		ret = KRB5KDC_ERR_NULL_KEY;
		continue;
	    }
	    *ret_key   = key;
	    *ret_etype = etypes[i];
	    ret = 0;
	    if (key->salt == NULL)
		return ret;
	}
    }
    return ret;
}

krb5_error_code
_kdc_make_anonymous_principalname (PrincipalName *pn)
{
    pn->name_type = KRB5_NT_PRINCIPAL;
    pn->name_string.len = 1;
    pn->name_string.val = malloc(sizeof(*pn->name_string.val));
    if (pn->name_string.val == NULL)
	return ENOMEM;
    pn->name_string.val[0] = strdup("anonymous");
    if (pn->name_string.val[0] == NULL) {
	free(pn->name_string.val);
	pn->name_string.val = NULL;
	return ENOMEM;
    }
    return 0;
}

void
_kdc_log_timestamp(krb5_context context, 
		   krb5_kdc_configuration *config,
		   const char *type,
		   KerberosTime authtime, KerberosTime *starttime, 
		   KerberosTime endtime, KerberosTime *renew_till)
{
    char authtime_str[100], starttime_str[100], 
	endtime_str[100], renewtime_str[100];
    
    krb5_format_time(context, authtime, 
		     authtime_str, sizeof(authtime_str), TRUE); 
    if (starttime)
	krb5_format_time(context, *starttime, 
			 starttime_str, sizeof(starttime_str), TRUE); 
    else
	strlcpy(starttime_str, "unset", sizeof(starttime_str));
    krb5_format_time(context, endtime, 
		     endtime_str, sizeof(endtime_str), TRUE); 
    if (renew_till)
	krb5_format_time(context, *renew_till, 
			 renewtime_str, sizeof(renewtime_str), TRUE); 
    else
	strlcpy(renewtime_str, "unset", sizeof(renewtime_str));
    
    kdc_log(context, config, 5,
	    "%s authtime: %s starttime: %s endtime: %s renew till: %s",
	    type, authtime_str, starttime_str, endtime_str, renewtime_str);
}

static void
log_patypes(krb5_context context, 
	    krb5_kdc_configuration *config,
	    METHOD_DATA *padata)
{
    struct rk_strpool *p = NULL;
    char *str;
    int i;
	    
    for (i = 0; i < padata->len; i++) {
	switch(padata->val[i].padata_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    p = rk_strpoolprintf(p, "PK-INIT(ietf)");
	    break;
	case KRB5_PADATA_PK_AS_REQ_WIN:
	    p = rk_strpoolprintf(p, "PK-INIT(win2k)");
	    break;
	case KRB5_PADATA_PA_PK_OCSP_RESPONSE:
	    p = rk_strpoolprintf(p, "OCSP");
	    break;
	case KRB5_PADATA_ENC_TIMESTAMP:
	    p = rk_strpoolprintf(p, "encrypted-timestamp");
	    break;
	default:
	    p = rk_strpoolprintf(p, "%d", padata->val[i].padata_type);
	    break;
	}
	if (p && i + 1 < padata->len)
	    p = rk_strpoolprintf(p, ", ");
	if (p == NULL) {
	    kdc_log(context, config, 0, "out of memory");
	    return;
	}
    }
    if (p == NULL)
	p = rk_strpoolprintf(p, "none");
	
    str = rk_strpoolcollect(p);
    kdc_log(context, config, 0, "Client sent patypes: %s", str);
    free(str);
}

/*
 *
 */


krb5_error_code
_kdc_encode_reply(krb5_context context,
		  krb5_kdc_configuration *config,
		  KDC_REP *rep, const EncTicketPart *et, EncKDCRepPart *ek, 
		  krb5_enctype etype, 
		  int skvno, const EncryptionKey *skey,
		  int ckvno, const EncryptionKey *ckey,
		  const char **e_text,
		  krb5_data *reply)
{
    unsigned char *buf;
    size_t buf_size;
    size_t len;
    krb5_error_code ret;
    krb5_crypto crypto;

    ASN1_MALLOC_ENCODE(EncTicketPart, buf, buf_size, et, &len, ret);
    if(ret) {
	kdc_log(context, config, 0, "Failed to encode ticket: %s", 
		krb5_get_err_text(context, ret));
	return ret;
    }
    if(buf_size != len) {
	free(buf);
	kdc_log(context, config, 0, "Internal error in ASN.1 encoder");
	*e_text = "KDC internal error";
	return KRB5KRB_ERR_GENERIC;
    }

    ret = krb5_crypto_init(context, skey, etype, &crypto);
    if (ret) {
	free(buf);
	kdc_log(context, config, 0, "krb5_crypto_init failed: %s",
		krb5_get_err_text(context, ret));
	return ret;
    }

    ret = krb5_encrypt_EncryptedData(context, 
				     crypto,
				     KRB5_KU_TICKET,
				     buf,
				     len,
				     skvno,
				     &rep->ticket.enc_part);
    free(buf);
    krb5_crypto_destroy(context, crypto);
    if(ret) {
	kdc_log(context, config, 0, "Failed to encrypt data: %s",
		krb5_get_err_text(context, ret));
	return ret;
    }
    
    if(rep->msg_type == krb_as_rep && !config->encode_as_rep_as_tgs_rep)
	ASN1_MALLOC_ENCODE(EncASRepPart, buf, buf_size, ek, &len, ret);
    else
	ASN1_MALLOC_ENCODE(EncTGSRepPart, buf, buf_size, ek, &len, ret);
    if(ret) {
	kdc_log(context, config, 0, "Failed to encode KDC-REP: %s", 
		krb5_get_err_text(context, ret));
	return ret;
    }
    if(buf_size != len) {
	free(buf);
	kdc_log(context, config, 0, "Internal error in ASN.1 encoder");
	*e_text = "KDC internal error";
	return KRB5KRB_ERR_GENERIC;
    }
    ret = krb5_crypto_init(context, ckey, 0, &crypto);
    if (ret) {
	free(buf);
	kdc_log(context, config, 0, "krb5_crypto_init failed: %s",
		krb5_get_err_text(context, ret));
	return ret;
    }
    if(rep->msg_type == krb_as_rep) {
	krb5_encrypt_EncryptedData(context,
				   crypto,
				   KRB5_KU_AS_REP_ENC_PART,
				   buf,
				   len,
				   ckvno,
				   &rep->enc_part);
	free(buf);
	ASN1_MALLOC_ENCODE(AS_REP, buf, buf_size, rep, &len, ret);
    } else {
	krb5_encrypt_EncryptedData(context,
				   crypto,
				   KRB5_KU_TGS_REP_ENC_PART_SESSION,
				   buf,
				   len,
				   ckvno,
				   &rep->enc_part);
	free(buf);
	ASN1_MALLOC_ENCODE(TGS_REP, buf, buf_size, rep, &len, ret);
    }
    krb5_crypto_destroy(context, crypto);
    if(ret) {
	kdc_log(context, config, 0, "Failed to encode KDC-REP: %s", 
		krb5_get_err_text(context, ret));
	return ret;
    }
    if(buf_size != len) {
	free(buf);
	kdc_log(context, config, 0, "Internal error in ASN.1 encoder");
	*e_text = "KDC internal error";
	return KRB5KRB_ERR_GENERIC;
    }
    reply->data = buf;
    reply->length = buf_size;
    return 0;
}

static krb5_error_code
make_etype_info_entry(krb5_context context, ETYPE_INFO_ENTRY *ent, Key *key)
{
    ent->etype = key->key.keytype;
    if(key->salt){
#if 0
	ALLOC(ent->salttype);

	if(key->salt->type == hdb_pw_salt)
	    *ent->salttype = 0; /* or 1? or NULL? */
	else if(key->salt->type == hdb_afs3_salt)
	    *ent->salttype = 2;
	else {
	    kdc_log(context, config, 0, "unknown salt-type: %d", 
		    key->salt->type);
	    return KRB5KRB_ERR_GENERIC;
	}
	/* according to `the specs', we can't send a salt if
	   we have AFS3 salted key, but that requires that you
	   *know* what cell you are using (e.g by assuming
	   that the cell is the same as the realm in lower
	   case) */
#elif 0
	ALLOC(ent->salttype);
	*ent->salttype = key->salt->type;
#else
	/* 
	 * We shouldn't sent salttype since its incompatible with the
	 * specification and its break windows clients.  The afs
	 * salting problem is solved by using KRB5-PADATA-AFS3-SALT
	 * implemented in Heimdal 0.7 and later.
	 */
	ent->salttype = NULL;
#endif
	krb5_copy_data(context, &key->salt->salt,
		       &ent->salt);
    } else {
	/* we return no salt type at all, as that should indicate
	 * the default salt type and make everybody happy.  some
	 * systems (like w2k) dislike being told the salt type
	 * here. */

	ent->salttype = NULL;
	ent->salt = NULL;
    }
    return 0;
}

static krb5_error_code
get_pa_etype_info(krb5_context context, 
		  krb5_kdc_configuration *config,
		  METHOD_DATA *md, hdb_entry *client, 
		  ENCTYPE *etypes, unsigned int etypes_len)
{
    krb5_error_code ret = 0;
    int i, j;
    unsigned int n = 0;
    ETYPE_INFO pa;
    unsigned char *buf;
    size_t len;
    

    pa.len = client->keys.len;
    if(pa.len > UINT_MAX/sizeof(*pa.val))
	return ERANGE;
    pa.val = malloc(pa.len * sizeof(*pa.val));
    if(pa.val == NULL)
	return ENOMEM;
    memset(pa.val, 0, pa.len * sizeof(*pa.val));

    for(j = 0; j < etypes_len; j++) {
	for (i = 0; i < n; i++)
	    if (pa.val[i].etype == etypes[j])
		goto skip1;
	for(i = 0; i < client->keys.len; i++) {
	    if(client->keys.val[i].key.keytype == etypes[j]) {
 		if (krb5_enctype_valid(context, etypes[j]) != 0)
 		    continue;
		if((ret = make_etype_info_entry(context, 
						&pa.val[n++], 
						&client->keys.val[i])) != 0) {
		    free_ETYPE_INFO(&pa);
		    return ret;
		}
	    }
	}
    skip1:;
    }
    for(i = 0; i < client->keys.len; i++) {
	for(j = 0; j < etypes_len; j++) {
	    if(client->keys.val[i].key.keytype == etypes[j])
		goto skip2;
	}
	if (krb5_enctype_valid(context, client->keys.val[i].key.keytype) != 0)
	    continue;
	if((ret = make_etype_info_entry(context, 
					&pa.val[n++], 
					&client->keys.val[i])) != 0) {
	    free_ETYPE_INFO(&pa);
	    return ret;
	}
    skip2:;
    }
    
    if(n != pa.len) {
	char *name;
	ret = krb5_unparse_name(context, client->principal, &name);
	if (ret)
	    name = "<unparse_name failed>";
	kdc_log(context, config, 0, "internal error in get_pa_etype_info(%s): %d != %d", 
		name, n, pa.len);
	if (ret == 0)
	    free(name);
 	pa.len = n;
    }

    ASN1_MALLOC_ENCODE(ETYPE_INFO, buf, len, &pa, &len, ret);
    free_ETYPE_INFO(&pa);
    if(ret)
	return ret;
    ret = realloc_method_data(md);
    if(ret) {
	free(buf);
	return ret;
    }
    md->val[md->len - 1].padata_type = KRB5_PADATA_ETYPE_INFO;
    md->val[md->len - 1].padata_value.length = len;
    md->val[md->len - 1].padata_value.data = buf;
    return 0;
}

/*
 *
 */

extern int _krb5_AES_string_to_default_iterator;

static krb5_error_code
make_etype_info2_entry(ETYPE_INFO2_ENTRY *ent, Key *key)
{
    ent->etype = key->key.keytype;
    if(key->salt) {
	ALLOC(ent->salt);
	if (ent->salt == NULL)
	    return ENOMEM;
	*ent->salt = malloc(key->salt->salt.length + 1);
	if (*ent->salt == NULL) {
	    free(ent->salt);
	    ent->salt = NULL;
	    return ENOMEM;
	}
	memcpy(*ent->salt, key->salt->salt.data, key->salt->salt.length);
	(*ent->salt)[key->salt->salt.length] = '\0';
    } else
	ent->salt = NULL;

    ent->s2kparams = NULL;

    switch (key->key.keytype) {
    case ETYPE_AES128_CTS_HMAC_SHA1_96:
    case ETYPE_AES256_CTS_HMAC_SHA1_96:
	ALLOC(ent->s2kparams);
	if (ent->s2kparams == NULL)
	    return ENOMEM;
	ent->s2kparams->length = 4;
	ent->s2kparams->data = malloc(ent->s2kparams->length);
	if (ent->s2kparams->data == NULL) {
	    free(ent->s2kparams);
	    ent->s2kparams = NULL;
	    return ENOMEM;
	}
	_krb5_put_int(ent->s2kparams->data, 
		      _krb5_AES_string_to_default_iterator, 
		      ent->s2kparams->length);
	break;
    case ETYPE_DES_CBC_CRC:
    case ETYPE_DES_CBC_MD4:
    case ETYPE_DES_CBC_MD5:
	/* Check if this was a AFS3 salted key */
	if(key->salt && key->salt->type == hdb_afs3_salt){
	    ALLOC(ent->s2kparams);
	    if (ent->s2kparams == NULL)
		return ENOMEM;
	    ent->s2kparams->length = 1;
	    ent->s2kparams->data = malloc(ent->s2kparams->length);
	    if (ent->s2kparams->data == NULL) {
		free(ent->s2kparams);
		ent->s2kparams = NULL;
		return ENOMEM;
	    }
	    _krb5_put_int(ent->s2kparams->data, 
			  1,
			  ent->s2kparams->length);
	}
	break;
    default:
	break;
    }
    return 0;
}

/*
 * Return 1 if the client have only older enctypes, this is for
 * determining if the server should send ETYPE_INFO2 or not.
 */

static int
only_older_enctype_p(const KDC_REQ *req)
{
    int i;

    for(i = 0; i < req->req_body.etype.len; i++) {
	switch (req->req_body.etype.val[i]) {
	case ETYPE_DES_CBC_CRC:
	case ETYPE_DES_CBC_MD4:
	case ETYPE_DES_CBC_MD5:
	case ETYPE_DES3_CBC_SHA1:
	case ETYPE_ARCFOUR_HMAC_MD5:
	case ETYPE_ARCFOUR_HMAC_MD5_56:
	    break;
	default:
	    return 0;
	}
    }
    return 1;
}

/*
 *
 */

static krb5_error_code
get_pa_etype_info2(krb5_context context, 
		   krb5_kdc_configuration *config,
		   METHOD_DATA *md, hdb_entry *client, 
		   ENCTYPE *etypes, unsigned int etypes_len)
{
    krb5_error_code ret = 0;
    int i, j;
    unsigned int n = 0;
    ETYPE_INFO2 pa;
    unsigned char *buf;
    size_t len;

    pa.len = client->keys.len;
    if(pa.len > UINT_MAX/sizeof(*pa.val))
	return ERANGE;
    pa.val = malloc(pa.len * sizeof(*pa.val));
    if(pa.val == NULL)
	return ENOMEM;
    memset(pa.val, 0, pa.len * sizeof(*pa.val));

    for(j = 0; j < etypes_len; j++) {
	for (i = 0; i < n; i++)
	    if (pa.val[i].etype == etypes[j])
		goto skip1;
	for(i = 0; i < client->keys.len; i++) {
	    if(client->keys.val[i].key.keytype == etypes[j]) {
		if (krb5_enctype_valid(context, etypes[j]) != 0)
		    continue;
		if((ret = make_etype_info2_entry(&pa.val[n++], 
						 &client->keys.val[i])) != 0) {
		    free_ETYPE_INFO2(&pa);
		    return ret;
		}
	    }
	}
    skip1:;
    }
    for(i = 0; i < client->keys.len; i++) {
	for(j = 0; j < etypes_len; j++) {
	    if(client->keys.val[i].key.keytype == etypes[j])
		goto skip2;
	}
	if (krb5_enctype_valid(context, client->keys.val[i].key.keytype) != 0)
	    continue;
	if((ret = make_etype_info2_entry(&pa.val[n++],
					 &client->keys.val[i])) != 0) {
	    free_ETYPE_INFO2(&pa);
	    return ret;
	}
      skip2:;
    }
    
    if(n != pa.len) {
	char *name;
	ret = krb5_unparse_name(context, client->principal, &name);
	if (ret)
	    name = "<unparse_name failed>";
	kdc_log(context, config, 0,
		"internal error in get_pa_etype_info2(%s): %d != %d", 
		name, n, pa.len);
	if (ret == 0)
	    free(name);
 	pa.len = n;
    }

    ASN1_MALLOC_ENCODE(ETYPE_INFO2, buf, len, &pa, &len, ret);
    free_ETYPE_INFO2(&pa);
    if(ret)
	return ret;
    ret = realloc_method_data(md);
    if(ret) {
	free(buf);
	return ret;
    }
    md->val[md->len - 1].padata_type = KRB5_PADATA_ETYPE_INFO2;
    md->val[md->len - 1].padata_value.length = len;
    md->val[md->len - 1].padata_value.data = buf;
    return 0;
}

/*
 * verify the flags on `client' and `server', returning 0
 * if they are OK and generating an error messages and returning
 * and error code otherwise.
 */

krb5_error_code
_kdc_check_flags(krb5_context context, 
		 krb5_kdc_configuration *config,
		 hdb_entry_ex *client_ex, const char *client_name,
		 hdb_entry_ex *server_ex, const char *server_name,
		 krb5_boolean is_as_req)
{
    if(client_ex != NULL) {
	hdb_entry *client = &client_ex->entry;

	/* check client */
	if (client->flags.invalid) {
	    kdc_log(context, config, 0, 
		    "Client (%s) has invalid bit set", client_name);
	    return KRB5KDC_ERR_POLICY;
	}
	
	if(!client->flags.client){
	    kdc_log(context, config, 0,
		    "Principal may not act as client -- %s", client_name);
	    return KRB5KDC_ERR_POLICY;
	}
	
	if (client->valid_start && *client->valid_start > kdc_time) {
	    char starttime_str[100];
	    krb5_format_time(context, *client->valid_start, 
			     starttime_str, sizeof(starttime_str), TRUE); 
	    kdc_log(context, config, 0,
		    "Client not yet valid until %s -- %s", 
		    starttime_str, client_name);
	    return KRB5KDC_ERR_CLIENT_NOTYET;
	}
	
	if (client->valid_end && *client->valid_end < kdc_time) {
	    char endtime_str[100];
	    krb5_format_time(context, *client->valid_end, 
			     endtime_str, sizeof(endtime_str), TRUE); 
	    kdc_log(context, config, 0,
		    "Client expired at %s -- %s",
		    endtime_str, client_name);
	    return KRB5KDC_ERR_NAME_EXP;
	}
	
	if (client->pw_end && *client->pw_end < kdc_time 
	    && (server_ex == NULL || !server_ex->entry.flags.change_pw)) {
	    char pwend_str[100];
	    krb5_format_time(context, *client->pw_end, 
			     pwend_str, sizeof(pwend_str), TRUE); 
	    kdc_log(context, config, 0,
		    "Client's key has expired at %s -- %s", 
		    pwend_str, client_name);
	    return KRB5KDC_ERR_KEY_EXPIRED;
	}
    }

    /* check server */
    
    if (server_ex != NULL) {
	hdb_entry *server = &server_ex->entry;

	if (server->flags.invalid) {
	    kdc_log(context, config, 0,
		    "Server has invalid flag set -- %s", server_name);
	    return KRB5KDC_ERR_POLICY;
	}

	if(!server->flags.server){
	    kdc_log(context, config, 0,
		    "Principal may not act as server -- %s", server_name);
	    return KRB5KDC_ERR_POLICY;
	}

	if(!is_as_req && server->flags.initial) {
	    kdc_log(context, config, 0,
		    "AS-REQ is required for server -- %s", server_name);
	    return KRB5KDC_ERR_POLICY;
	}

	if (server->valid_start && *server->valid_start > kdc_time) {
	    char starttime_str[100];
	    krb5_format_time(context, *server->valid_start, 
			     starttime_str, sizeof(starttime_str), TRUE); 
	    kdc_log(context, config, 0,
		    "Server not yet valid until %s -- %s",
		    starttime_str, server_name);
	    return KRB5KDC_ERR_SERVICE_NOTYET;
	}

	if (server->valid_end && *server->valid_end < kdc_time) {
	    char endtime_str[100];
	    krb5_format_time(context, *server->valid_end, 
			     endtime_str, sizeof(endtime_str), TRUE); 
	    kdc_log(context, config, 0,
		    "Server expired at %s -- %s", 
		    endtime_str, server_name);
	    return KRB5KDC_ERR_SERVICE_EXP;
	}

	if (server->pw_end && *server->pw_end < kdc_time) {
	    char pwend_str[100];
	    krb5_format_time(context, *server->pw_end, 
			     pwend_str, sizeof(pwend_str), TRUE); 
	    kdc_log(context, config, 0,
		    "Server's key has expired at -- %s", 
		    pwend_str, server_name);
	    return KRB5KDC_ERR_KEY_EXPIRED;
	}
    }
    return 0;
}

/*
 * Return TRUE if `from' is part of `addresses' taking into consideration
 * the configuration variables that tells us how strict we should be about
 * these checks
 */

krb5_boolean
_kdc_check_addresses(krb5_context context,        
		     krb5_kdc_configuration *config,
		     HostAddresses *addresses, const struct sockaddr *from)
{
    krb5_error_code ret;
    krb5_address addr;
    krb5_boolean result;
    krb5_boolean only_netbios = TRUE;
    int i;
    
    if(config->check_ticket_addresses == 0)
	return TRUE;

    if(addresses == NULL)
	return config->allow_null_ticket_addresses;
    
    for (i = 0; i < addresses->len; ++i) {
	if (addresses->val[i].addr_type != KRB5_ADDRESS_NETBIOS) {
	    only_netbios = FALSE;
	}
    }

    /* Windows sends it's netbios name, which I can only assume is
     * used for the 'allowed workstations' check.  This is painful,
     * but we still want to check IP addresses if they happen to be
     * present.
     */

    if(only_netbios)
	return config->allow_null_ticket_addresses;

    ret = krb5_sockaddr2address (context, from, &addr);
    if(ret)
	return FALSE;

    result = krb5_address_search(context, &addr, addresses);
    krb5_free_address (context, &addr);
    return result;
}

krb5_error_code
_kdc_as_rep(krb5_context context, 
	    krb5_kdc_configuration *config,
	    KDC_REQ *req, 
	    const krb5_data *req_buffer, 
	    krb5_data *reply,
	    const char *from,
	    struct sockaddr *from_addr,
	    int datagram_reply)
{
    KDC_REQ_BODY *b = &req->req_body;
    AS_REP rep;
    KDCOptions f = b->kdc_options;
    hdb_entry_ex *client = NULL, *server = NULL;
    krb5_enctype cetype, setype, sessionetype;
    EncTicketPart et;
    EncKDCRepPart ek;
    krb5_principal client_princ = NULL, server_princ = NULL;
    char *client_name = NULL, *server_name = NULL;
    krb5_error_code ret = 0;
    const char *e_text = NULL;
    krb5_crypto crypto;
    Key *ckey, *skey;
    EncryptionKey *reply_key;
#ifdef PKINIT
    pk_client_params *pkp = NULL;
#endif

    memset(&rep, 0, sizeof(rep));

    if(b->sname == NULL){
	ret = KRB5KRB_ERR_GENERIC;
	e_text = "No server in request";
    } else{
	_krb5_principalname2krb5_principal (context,
					    &server_princ,
					    *(b->sname),
					    b->realm);
	ret = krb5_unparse_name(context, server_princ, &server_name);
    }
    if (ret) {
	kdc_log(context, config, 0, 
		"AS-REQ malformed server name from %s", from);
	goto out;
    }
    
    if(b->cname == NULL){
	ret = KRB5KRB_ERR_GENERIC;
	e_text = "No client in request";
    } else {
	_krb5_principalname2krb5_principal (context,
					    &client_princ,
					    *(b->cname),
					    b->realm);
	ret = krb5_unparse_name(context, client_princ, &client_name);
    }
    if (ret) {
	kdc_log(context, config, 0,
		"AS-REQ malformed client name from %s", from);
	goto out;
    }

    kdc_log(context, config, 0, "AS-REQ %s from %s for %s", 
	    client_name, from, server_name);

    ret = _kdc_db_fetch(context, config, client_princ, 
			HDB_F_GET_CLIENT, NULL, &client);
    if(ret){
	kdc_log(context, config, 0, "UNKNOWN -- %s: %s", client_name,
		krb5_get_err_text(context, ret));
	ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	goto out;
    }

    ret = _kdc_db_fetch(context, config, server_princ,
			HDB_F_GET_SERVER|HDB_F_GET_KRBTGT,
			NULL, &server);
    if(ret){
	kdc_log(context, config, 0, "UNKNOWN -- %s: %s", server_name,
		krb5_get_err_text(context, ret));
	ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto out;
    }

    ret = _kdc_check_flags(context, config, 
			   client, client_name,
			   server, server_name,
			   TRUE);
    if(ret)
	goto out;

    if (client->check_client_access) {
	ret = client->check_client_access(context, client, 
					  b->addresses);
	if(ret)
	    goto out;
    }

    memset(&et, 0, sizeof(et));
    memset(&ek, 0, sizeof(ek));

    if(req->padata){
	int i;
	PA_DATA *pa;
	int found_pa = 0;

	log_patypes(context, config, req->padata);

#ifdef PKINIT
	kdc_log(context, config, 5, 
		"Looking for PKINIT pa-data -- %s", client_name);

	e_text = "No PKINIT PA found";

	i = 0;
	if ((pa = _kdc_find_padata(req, &i, KRB5_PADATA_PK_AS_REQ)))
	    ;
	if (pa == NULL) {
	    i = 0;
	    if((pa = _kdc_find_padata(req, &i, KRB5_PADATA_PK_AS_REQ_WIN)))
		;
	}
	if (pa) {
	    char *client_cert = NULL;

	    ret = _kdc_pk_rd_padata(context, config, req, pa, &pkp);
	    if (ret) {
		ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		kdc_log(context, config, 5, 
			"Failed to decode PKINIT PA-DATA -- %s", 
			client_name);
		goto ts_enc;
	    }
	    if (ret == 0 && pkp == NULL)
		goto ts_enc;

	    ret = _kdc_pk_check_client(context,
				       config,
				       client,
				       pkp,
				       &client_cert);
	    if (ret) {
		e_text = "PKINIT certificate not allowed to "
		    "impersonate principal";
		_kdc_pk_free_client_param(context, pkp);

		kdc_log(context, config, 0, "%s", e_text);
		pkp = NULL;
		goto ts_enc;
	    }
	    found_pa = 1;
	    et.flags.pre_authent = 1;
	    kdc_log(context, config, 0,
		    "PKINIT pre-authentication succeeded -- %s using %s", 
		    client_name, client_cert);
	    free(client_cert);
	    if (pkp)
		goto preauth_done;
	}
    ts_enc:
#endif
	kdc_log(context, config, 5, "Looking for ENC-TS pa-data -- %s", 
		client_name);

	i = 0;
	e_text = "No ENC-TS found";
	while((pa = _kdc_find_padata(req, &i, KRB5_PADATA_ENC_TIMESTAMP))){
	    krb5_data ts_data;
	    PA_ENC_TS_ENC p;
	    size_t len;
	    EncryptedData enc_data;
	    Key *pa_key;
	    char *str;
	    
	    found_pa = 1;
	    
	    ret = decode_EncryptedData(pa->padata_value.data,
				       pa->padata_value.length,
				       &enc_data,
				       &len);
	    if (ret) {
		ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		kdc_log(context, config, 5, "Failed to decode PA-DATA -- %s", 
			client_name);
		goto out;
	    }
	    
	    ret = hdb_enctype2key(context, &client->entry, 
				  enc_data.etype, &pa_key);
	    if(ret){
		char *estr;
		e_text = "No key matches pa-data";
		ret = KRB5KDC_ERR_PREAUTH_FAILED;
		if(krb5_enctype_to_string(context, enc_data.etype, &estr))
		    estr = NULL;
		if(estr == NULL)
		    kdc_log(context, config, 5, 
			    "No client key matching pa-data (%d) -- %s", 
			    enc_data.etype, client_name);
		else
		    kdc_log(context, config, 5,
			    "No client key matching pa-data (%s) -- %s", 
			    estr, client_name);
		free(estr);
		    
		free_EncryptedData(&enc_data);
		continue;
	    }

	try_next_key:
	    ret = krb5_crypto_init(context, &pa_key->key, 0, &crypto);
	    if (ret) {
		kdc_log(context, config, 0, "krb5_crypto_init failed: %s",
			krb5_get_err_text(context, ret));
		free_EncryptedData(&enc_data);
		continue;
	    }

	    ret = krb5_decrypt_EncryptedData (context,
					      crypto,
					      KRB5_KU_PA_ENC_TIMESTAMP,
					      &enc_data,
					      &ts_data);
	    krb5_crypto_destroy(context, crypto);
	    if(ret){
		krb5_error_code ret2;
		ret2 = krb5_enctype_to_string(context, 
					      pa_key->key.keytype, &str);
		if (ret2)
		    str = NULL;
		kdc_log(context, config, 5, 
			"Failed to decrypt PA-DATA -- %s "
			"(enctype %s) error %s",
			client_name,
			str ? str : "unknown enctype", 
			krb5_get_err_text(context, ret));
		free(str);

		if(hdb_next_enctype2key(context, &client->entry, 
					enc_data.etype, &pa_key) == 0)
		    goto try_next_key;
		e_text = "Failed to decrypt PA-DATA";

		free_EncryptedData(&enc_data);
		ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		continue;
	    }
	    free_EncryptedData(&enc_data);
	    ret = decode_PA_ENC_TS_ENC(ts_data.data,
				       ts_data.length,
				       &p,
				       &len);
	    krb5_data_free(&ts_data);
	    if(ret){
		e_text = "Failed to decode PA-ENC-TS-ENC";
		ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		kdc_log(context, config, 
			5, "Failed to decode PA-ENC-TS_ENC -- %s",
			client_name);
		continue;
	    }
	    free_PA_ENC_TS_ENC(&p);
	    if (abs(kdc_time - p.patimestamp) > context->max_skew) {
		char client_time[100];
		
		krb5_format_time(context, p.patimestamp, 
				 client_time, sizeof(client_time), TRUE); 

 		ret = KRB5KRB_AP_ERR_SKEW;
 		kdc_log(context, config, 0,
			"Too large time skew, "
			"client time %s is out by %u > %u seconds -- %s", 
			client_time, 
			(unsigned)abs(kdc_time - p.patimestamp), 
			context->max_skew,
			client_name);
		/* 
		 * the following is needed to make windows clients
		 * to retry using the timestamp in the error message
		 *
		 * this is maybe a bug in windows to not trying when e_text
		 * is present...
		 */
		e_text = NULL;
		goto out;
	    }
	    et.flags.pre_authent = 1;

	    ret = krb5_enctype_to_string(context,pa_key->key.keytype, &str);
	    if (ret)
		str = NULL;

	    kdc_log(context, config, 2,
		    "ENC-TS Pre-authentication succeeded -- %s using %s", 
		    client_name, str ? str : "unknown enctype");
	    free(str);
	    break;
	}
#ifdef PKINIT
    preauth_done:
#endif
	if(found_pa == 0 && config->require_preauth)
	    goto use_pa;
	/* We come here if we found a pa-enc-timestamp, but if there
           was some problem with it, other than too large skew */
	if(found_pa && et.flags.pre_authent == 0){
	    kdc_log(context, config, 0, "%s -- %s", e_text, client_name);
	    e_text = NULL;
	    goto out;
	}
    }else if (config->require_preauth
	      || client->entry.flags.require_preauth
	      || server->entry.flags.require_preauth) {
	METHOD_DATA method_data;
	PA_DATA *pa;
	unsigned char *buf;
	size_t len;
	krb5_data foo_data;

    use_pa: 
	method_data.len = 0;
	method_data.val = NULL;

	ret = realloc_method_data(&method_data);
	pa = &method_data.val[method_data.len-1];
	pa->padata_type		= KRB5_PADATA_ENC_TIMESTAMP;
	pa->padata_value.length	= 0;
	pa->padata_value.data	= NULL;

#ifdef PKINIT
	ret = realloc_method_data(&method_data);
	pa = &method_data.val[method_data.len-1];
	pa->padata_type		= KRB5_PADATA_PK_AS_REQ;
	pa->padata_value.length	= 0;
	pa->padata_value.data	= NULL;
#endif

	/* 
	 * RFC4120 requires: 
	 * - If the client only knows about old enctypes, then send
	 *   both info replies (we send 'info' first in the list).
	 * - If the client is 'modern', because it knows about 'new'
	 *   enctype types, then only send the 'info2' reply.
	 */

	/* XXX check ret */
	if (only_older_enctype_p(req))
	    ret = get_pa_etype_info(context, config,
				    &method_data, &client->entry, 
				    b->etype.val, b->etype.len); 
	/* XXX check ret */
	ret = get_pa_etype_info2(context, config, &method_data, 
				 &client->entry, b->etype.val, b->etype.len);

	
	ASN1_MALLOC_ENCODE(METHOD_DATA, buf, len, &method_data, &len, ret);
	free_METHOD_DATA(&method_data);
	foo_data.data   = buf;
	foo_data.length = len;
	
	ret = KRB5KDC_ERR_PREAUTH_REQUIRED;
	krb5_mk_error(context,
		      ret,
		      "Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ",
		      &foo_data,
		      client_princ,
		      server_princ,
		      NULL,
		      NULL,
		      reply);
	free(buf);
	kdc_log(context, config, 0,
		"No preauth found, returning PREAUTH-REQUIRED -- %s",
		client_name);
	ret = 0;
	goto out2;
    }
    
    /*
     * Find the client key (for preauth ENC-TS verification and reply
     * encryption).  Then the best encryption type for the KDC and
     * last the best session key that shared between the client and
     * KDC runtime enctypes.
     */

    ret = _kdc_find_etype(context, client, b->etype.val, b->etype.len,
			  &ckey, &cetype);
    if (ret) {
	kdc_log(context, config, 0, 
		"Client (%s) has no support for etypes", client_name);
	goto out;
    }
	
    ret = _kdc_get_preferred_key(context, config,
				 server, server_name,
				 &setype, &skey);
    if(ret)
	goto out;

    {
	const krb5_enctype *p;
	int i, j;

	p = krb5_kerberos_enctypes(context);

	sessionetype = ETYPE_NULL;

	for (i = 0; p[i] != ETYPE_NULL && sessionetype == ETYPE_NULL; i++) {
	    if (krb5_enctype_valid(context, p[i]) != 0)
		continue;
	    for (j = 0; j < b->etype.len; j++) {
		if (p[i] == b->etype.val[j]) {
		    sessionetype = p[i];
		    break;
		}
	    }
	}
	if (sessionetype == ETYPE_NULL) {
	    kdc_log(context, config, 0, 
		    "Client (%s) from %s has no common enctypes with KDC"
		    "to use for the session key",
		    client_name, from);
	    goto out;
	}
    }

    {
	struct rk_strpool *p = NULL;
	char *str;
	int i;

	for (i = 0; i < b->etype.len; i++) {
	    ret = krb5_enctype_to_string(context, b->etype.val[i], &str);
	    if (ret == 0) {
		p = rk_strpoolprintf(p, "%s", str);
		free(str);
	    } else
		p = rk_strpoolprintf(p, "%d", b->etype.val[i]);
	    if (p && i + 1 < b->etype.len)
		p = rk_strpoolprintf(p, ", ");
	    if (p == NULL) {
		kdc_log(context, config, 0, "out of memory");
		goto out;
	    }
	}
	if (p == NULL)
	    p = rk_strpoolprintf(p, "no encryption types");

	str = rk_strpoolcollect(p);
	kdc_log(context, config, 0, "Client supported enctypes: %s", str);
	free(str);
    }
    {
	char *cet;
	char *set;

	ret = krb5_enctype_to_string(context, cetype, &cet);
	if(ret == 0) {
	    ret = krb5_enctype_to_string(context, setype, &set);
	    if (ret == 0) {
		kdc_log(context, config, 5, "Using %s/%s", cet, set);
		free(set);
	    }
	    free(cet);
	}
	if (ret != 0)
	    kdc_log(context, config, 5, "Using e-types %d/%d", cetype, setype);
    }
    
    {
	char str[128];
	unparse_flags(KDCOptions2int(f), asn1_KDCOptions_units(), 
		      str, sizeof(str));
	if(*str)
	    kdc_log(context, config, 2, "Requested flags: %s", str);
    }
    

    if(f.renew || f.validate || f.proxy || f.forwarded || f.enc_tkt_in_skey
       || (f.request_anonymous && !config->allow_anonymous)) {
	ret = KRB5KDC_ERR_BADOPTION;
	kdc_log(context, config, 0, "Bad KDC options -- %s", client_name);
	goto out;
    }
    
    rep.pvno = 5;
    rep.msg_type = krb_as_rep;
    copy_Realm(&client->entry.principal->realm, &rep.crealm);
    if (f.request_anonymous)
	_kdc_make_anonymous_principalname (&rep.cname);
    else
	_krb5_principal2principalname(&rep.cname, 
				      client->entry.principal);
    rep.ticket.tkt_vno = 5;
    copy_Realm(&server->entry.principal->realm, &rep.ticket.realm);
    _krb5_principal2principalname(&rep.ticket.sname, 
				  server->entry.principal);

    et.flags.initial = 1;
    if(client->entry.flags.forwardable && server->entry.flags.forwardable)
	et.flags.forwardable = f.forwardable;
    else if (f.forwardable) {
	ret = KRB5KDC_ERR_POLICY;
	kdc_log(context, config, 0,
		"Ticket may not be forwardable -- %s", client_name);
	goto out;
    }
    if(client->entry.flags.proxiable && server->entry.flags.proxiable)
	et.flags.proxiable = f.proxiable;
    else if (f.proxiable) {
	ret = KRB5KDC_ERR_POLICY;
	kdc_log(context, config, 0, 
		"Ticket may not be proxiable -- %s", client_name);
	goto out;
    }
    if(client->entry.flags.postdate && server->entry.flags.postdate)
	et.flags.may_postdate = f.allow_postdate;
    else if (f.allow_postdate){
	ret = KRB5KDC_ERR_POLICY;
	kdc_log(context, config, 0,
		"Ticket may not be postdatable -- %s", client_name);
	goto out;
    }

    /* check for valid set of addresses */
    if(!_kdc_check_addresses(context, config, b->addresses, from_addr)) {
	ret = KRB5KRB_AP_ERR_BADADDR;
	kdc_log(context, config, 0,
		"Bad address list requested -- %s", client_name);
	goto out;
    }

    krb5_generate_random_keyblock(context, sessionetype, &et.key);
    copy_PrincipalName(&rep.cname, &et.cname);
    copy_Realm(&rep.crealm, &et.crealm);
    
    {
	time_t start;
	time_t t;
	
	start = et.authtime = kdc_time;
    
	if(f.postdated && req->req_body.from){
	    ALLOC(et.starttime);
	    start = *et.starttime = *req->req_body.from;
	    et.flags.invalid = 1;
	    et.flags.postdated = 1; /* XXX ??? */
	}
	_kdc_fix_time(&b->till);
	t = *b->till;

	/* be careful not overflowing */

	if(client->entry.max_life)
	    t = start + min(t - start, *client->entry.max_life);
	if(server->entry.max_life)
	    t = start + min(t - start, *server->entry.max_life);
#if 0
	t = min(t, start + realm->max_life);
#endif
	et.endtime = t;
	if(f.renewable_ok && et.endtime < *b->till){
	    f.renewable = 1;
	    if(b->rtime == NULL){
		ALLOC(b->rtime);
		*b->rtime = 0;
	    }
	    if(*b->rtime < *b->till)
		*b->rtime = *b->till;
	}
	if(f.renewable && b->rtime){
	    t = *b->rtime;
	    if(t == 0)
		t = MAX_TIME;
	    if(client->entry.max_renew)
		t = start + min(t - start, *client->entry.max_renew);
	    if(server->entry.max_renew)
		t = start + min(t - start, *server->entry.max_renew);
#if 0
	    t = min(t, start + realm->max_renew);
#endif
	    ALLOC(et.renew_till);
	    *et.renew_till = t;
	    et.flags.renewable = 1;
	}
    }

    if (f.request_anonymous)
	et.flags.anonymous = 1;
    
    if(b->addresses){
	ALLOC(et.caddr);
	copy_HostAddresses(b->addresses, et.caddr);
    }
    
    et.transited.tr_type = DOMAIN_X500_COMPRESS;
    krb5_data_zero(&et.transited.contents); 
     
    copy_EncryptionKey(&et.key, &ek.key);

    /* The MIT ASN.1 library (obviously) doesn't tell lengths encoded
     * as 0 and as 0x80 (meaning indefinite length) apart, and is thus
     * incapable of correctly decoding SEQUENCE OF's of zero length.
     *
     * To fix this, always send at least one no-op last_req
     *
     * If there's a pw_end or valid_end we will use that,
     * otherwise just a dummy lr.
     */
    ek.last_req.val = malloc(2 * sizeof(*ek.last_req.val));
    ek.last_req.len = 0;
    if (client->entry.pw_end
	&& (config->kdc_warn_pwexpire == 0
	    || kdc_time + config->kdc_warn_pwexpire >= *client->entry.pw_end)) {
	ek.last_req.val[ek.last_req.len].lr_type  = LR_PW_EXPTIME;
	ek.last_req.val[ek.last_req.len].lr_value = *client->entry.pw_end;
	++ek.last_req.len;
    }
    if (client->entry.valid_end) {
	ek.last_req.val[ek.last_req.len].lr_type  = LR_ACCT_EXPTIME;
	ek.last_req.val[ek.last_req.len].lr_value = *client->entry.valid_end;
	++ek.last_req.len;
    }
    if (ek.last_req.len == 0) {
	ek.last_req.val[ek.last_req.len].lr_type  = LR_NONE;
	ek.last_req.val[ek.last_req.len].lr_value = 0;
	++ek.last_req.len;
    }
    ek.nonce = b->nonce;
    if (client->entry.valid_end || client->entry.pw_end) {
	ALLOC(ek.key_expiration);
	if (client->entry.valid_end) {
	    if (client->entry.pw_end)
		*ek.key_expiration = min(*client->entry.valid_end, 
					 *client->entry.pw_end);
	    else
		*ek.key_expiration = *client->entry.valid_end;
	} else
	    *ek.key_expiration = *client->entry.pw_end;
    } else
	ek.key_expiration = NULL;
    ek.flags = et.flags;
    ek.authtime = et.authtime;
    if (et.starttime) {
	ALLOC(ek.starttime);
	*ek.starttime = *et.starttime;
    }
    ek.endtime = et.endtime;
    if (et.renew_till) {
	ALLOC(ek.renew_till);
	*ek.renew_till = *et.renew_till;
    }
    copy_Realm(&rep.ticket.realm, &ek.srealm);
    copy_PrincipalName(&rep.ticket.sname, &ek.sname);
    if(et.caddr){
	ALLOC(ek.caddr);
	copy_HostAddresses(et.caddr, ek.caddr);
    }

    ALLOC(rep.padata);
    rep.padata->len = 0;
    rep.padata->val = NULL;

    reply_key = &ckey->key;
#if PKINIT
    if (pkp) {
	ret = _kdc_pk_mk_pa_reply(context, config, pkp, client, 
				  req, req_buffer, 
				  &reply_key, rep.padata);
	if (ret)
	    goto out;
    }
#endif

    set_salt_padata (rep.padata, ckey->salt);

    if (rep.padata->len == 0) {
	free(rep.padata);
	rep.padata = NULL;
    }

    /* Add the PAC, via a HDB abstraction */
    if (client->authz_data_as_req) {
	    ret = client->authz_data_as_req(context, client, 
					    req->padata, 
					    et.authtime,
					    &skey->key,
					    &et.key,
					    &et.authorization_data);
	    if (ret) 
		    goto out;
    }

    _kdc_log_timestamp(context, config, "AS-REQ", et.authtime, et.starttime, 
		       et.endtime, et.renew_till);

    /* do this as the last thing since this signs the EncTicketPart */
    ret = _kdc_add_KRB5SignedPath(context,
				  config,
				  server,
				  setype,
				  NULL,
				  NULL,
				  &et);
    if (ret)
	goto out;

    ret = _kdc_encode_reply(context, config, 
			    &rep, &et, &ek, setype, server->entry.kvno, 
			    &skey->key, client->entry.kvno, 
			    reply_key, &e_text, reply);
    free_EncTicketPart(&et);
    free_EncKDCRepPart(&ek);
    if (ret)
	goto out;

    /* */
    if (datagram_reply && reply->length > config->max_datagram_reply_length) {
	krb5_data_free(reply);
	ret = KRB5KRB_ERR_RESPONSE_TOO_BIG;
	e_text = "Reply packet too large";
    }

out:
    free_AS_REP(&rep);
    if(ret){
	krb5_mk_error(context,
		      ret,
		      e_text,
		      NULL,
		      client_princ,
		      server_princ,
		      NULL,
		      NULL,
		      reply);
	ret = 0;
    }
out2:
#ifdef PKINIT
    if (pkp)
	_kdc_pk_free_client_param(context, pkp);
#endif
    if (client_princ)
	krb5_free_principal(context, client_princ);
    free(client_name);
    if (server_princ)
	krb5_free_principal(context, server_princ);
    free(server_name);
    if(client)
	_kdc_free_ent(context, client);
    if(server)
	_kdc_free_ent(context, server);
    return ret;
}
