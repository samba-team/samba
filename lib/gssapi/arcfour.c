/*
 * Copyright (c) 2003 Kungliga Tekniska Högskolan
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

#include "gssapi_locl.h"

#if 0
static const char arcfour_sk[] = "signaturekey";

static krb5_error_code
get_arcfour_sk(krb5_context context, krb5_keyblock *key,
	       void *sk_key_data, size_t sk_key_size)
{
    Checksum cksum_k4;

    cksum_k4.checksum.data = sk_key_data;
    cksum_k4.checksum.length = sk_key_size;
    return krb5_hmac(context, CKSUMTYPE_RSA_MD5,
		     arcfour_sk, sizeof(arcfour_sk), 13, /* XXX usage */
		     key, &cksum_k4);

}
#endif

static krb5_error_code
arcfour_mic_key(krb5_context context, krb5_keyblock *key,
		const void *header, size_t header_size,
		const void *message, size_t message_size,
		void *cksum_data, size_t cksum_size,
		void *key6_data, size_t key6_size)
{
    krb5_error_code ret;
    
    Checksum cksum_k5;
    krb5_keyblock key5;
    char k5_data[16];
    
    Checksum cksum_k6;
    
    char T[4];

    /* draft: T = 0; */
    memset(T, 0, 4);
    /* draft: HMAC (K, &T, 4, K5); */
    cksum_k5.checksum.data = k5_data;
    cksum_k5.checksum.length = sizeof(k5_data);

    ret = krb5_hmac(context, CKSUMTYPE_RSA_MD5,
		    T, 4, 0, key, &cksum_k5);
    if (ret)
	return ret;

    key5.keytype = KEYTYPE_ARCFOUR;
    key5.keyvalue = cksum_k5.checksum;

    /* HMAC(K5, MIC_checksum, 8, K6); */
    cksum_k6.checksum.data = key6_data;
    cksum_k6.checksum.length = key6_size;

    return krb5_hmac(context, CKSUMTYPE_RSA_MD5,
		     cksum_data, cksum_size, 0, &key5, &cksum_k6);
}

static krb5_error_code
arcfour_mic_cksum(const char *p, size_t p_sz, 
		  const gss_buffer_t message_buffer, 
		  krb5_keyblock *key,
		  u_char *sgn_cksum, size_t sgn_cksum_sz)

{
    Checksum CKSUM;
    u_char *ptr = emalloc(p_sz + message_buffer->length);
    krb5_crypto crypto;
    krb5_error_code ret;
    
    assert(sgn_cksum_sz == 8);

    memcpy(ptr, p, p_sz);
    memcpy(ptr + p_sz, message_buffer->value, message_buffer->length);
    
    ret = krb5_crypto_init(gssapi_krb5_context, key, 0, &crypto);
    if (ret) {
	free(ptr);
	return ret;
    }
    
    ret = krb5_create_checksum(gssapi_krb5_context,
				crypto,
				KRB5_KU_USAGE_SIGN,
				0,
				ptr,
				p_sz + message_buffer->length,
				&CKSUM);
    free(ptr);
    if (ret == 0) {
	memcpy(sgn_cksum, CKSUM.checksum.data, sgn_cksum_sz);
	krb5_free_checksum_contents(gssapi_krb5_context, &CKSUM);
    }
    krb5_crypto_destroy(gssapi_krb5_context, crypto);

    return ret;
}


OM_uint32
_gssapi_get_mic_arcfour
           (OM_uint32 * minor_status,
            const gss_ctx_id_t context_handle,
            gss_qop_t qop_req,
            const gss_buffer_t message_buffer,
            gss_buffer_t message_token,
	    krb5_keyblock *key
           )
{
    gss_arcfour_mic_token *token;
    krb5_error_code kret;
    
    u_char *p;
    
    int32_t seq_number;
    size_t len, total_len;
    
    char k6_data[16];
    
    gssapi_krb5_encap_length (22, &len, &total_len, GSS_KRB5_MECHANISM);
    
    message_token->length = total_len;
    message_token->value  = malloc (total_len);
    if (message_token->value == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    
    p = _gssapi_make_mech_header(message_token->value,
				 len,
				 GSS_KRB5_MECHANISM);
    token = (gss_arcfour_mic_token *)p;
    
    token->TOK_ID[0] = 0x01;
    token->TOK_ID[1] = 0x01;
    token->SGN_ALG[0] = 0x11;
    token->SGN_ALG[1] = 0x00;
    token->Filler[0] = 0xff;
    token->Filler[1] = 0xff;
    token->Filler[2] = 0xff;
    token->Filler[3] = 0xff;

    kret = arcfour_mic_cksum(p, 8, message_buffer, key, token->SGN_CKSUM, 8);
    if (kret) {
	*minor_status = kret;
	gss_release_buffer(minor_status, message_token);
	return GSS_S_FAILURE;
    }
    kret = arcfour_mic_key(gssapi_krb5_context, key,
			   p, 8,
			   message_buffer->value,message_buffer->length,
			   token->SGN_CKSUM, 8,
			   k6_data, sizeof(k6_data));
    if (kret) {
	*minor_status = kret;
	return GSS_S_FAILURE;
    }
    p += 8;
    
    /* draft: copy_seq_num_in_big_endian(seq_num, seq_plus_direction); */
    /* draft: copy_direction_flag (direction_flag, seq_plus_direction + 4); */

    HEIMDAL_MUTEX_lock(&context_handle->ctx_id_mutex);
    krb5_auth_con_getlocalseqnumber (gssapi_krb5_context,
				     context_handle->auth_context,
				     &seq_number);
    
    p[0] = (seq_number >> 24) & 0xFF;
    p[1] = (seq_number >> 16) & 0xFF;
    p[2] = (seq_number >> 8)  & 0xFF;
    p[3] = (seq_number >> 0)  & 0xFF;
    
    krb5_auth_con_setlocalseqnumber (gssapi_krb5_context,
				     context_handle->auth_context,
				     ++seq_number);
    HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);
    
    memset (p + 4,
	    (context_handle->more_flags & LOCAL) ? 0xFF : 0,
	    4);

    /* draft: RC4(K6, seq_plus_direction, 8, MIC_seq); */
    {
	RC4_KEY rc4_key;
	
	RC4_set_key (&rc4_key, sizeof(k6_data), k6_data);
	RC4 (&rc4_key, 8, p, p);
	
	memset(&rc4_key, 0, sizeof(rc4_key));
    }
    
    return GSS_S_COMPLETE;
}


OM_uint32
_gssapi_verify_mic_arcfour
           (OM_uint32 * minor_status,
            const gss_ctx_id_t context_handle,
            const gss_buffer_t message_buffer,
            const gss_buffer_t token_buffer,
            gss_qop_t * qop_state,
	    char *type,
	    krb5_keyblock *key
	    )
{
    krb5_error_code kret;
    int32_t seq_number;
    OM_uint32 ret;
    char cksum_data[8], k6_data[16];
    u_char *p;
    int cmp;
    
    p = token_buffer->value;
    ret = gssapi_krb5_verify_header (&p,
				     token_buffer->length,
				     type,
				     GSS_KRB5_MECHANISM);
    if (ret)
	return ret;
    
    if (memcmp(p, "\x11\x00", 2) != 0) /* SGN_ALG = HMAC MD5 ARCFOUR */
	return GSS_S_BAD_SIG;
    p += 2;
    if (memcmp (p, "\xff\xff\xff\xff", 4) != 0)
	return GSS_S_BAD_MIC;
    p += 4;

    /* draft: memcpy (T_plus_hdr_plus_msg + 04, MIC_hdr, 8); */
    /* draft: memcpy (T_plus_hdr_plus_msg + 12, msg, msg_len); */
  
    kret = arcfour_mic_cksum(p, 8, message_buffer, key,
			     cksum_data, sizeof(cksum_data));
    if (kret) {
	*minor_status = kret;
	return GSS_S_FAILURE;
    }

    kret = arcfour_mic_key(gssapi_krb5_context, key,
			   p - 8, 8,
			   message_buffer->value,
			   message_buffer->length,
			   cksum_data, sizeof(cksum_data),
			   k6_data, sizeof(k6_data));
    if (kret) {
	*minor_status = kret;
	return GSS_S_FAILURE;
    }

    cmp = memcmp(cksum_data, p + 8, 8);
    if (cmp) {
	*minor_status = 0;
	return GSS_S_BAD_MIC;
    }

    /* XXX don't modify p */
    {
	RC4_KEY rc4_key;
	
	RC4_set_key (&rc4_key, sizeof(k6_data), k6_data);
	RC4 (&rc4_key, 8, p, p);
	
	memset(&rc4_key, 0, sizeof(rc4_key));
    }

    gssapi_decode_om_uint32(p, &seq_number);

    if (context_handle->more_flags & LOCAL)
	cmp = memcmp(&p[4], "\xff\xff\xff\xff", 4);
    else
	cmp = memcmp(&p[4], "\x00\x00\x00\x00", 4);
    
    if (cmp != 0) {
	*minor_status = 0;
	return GSS_S_BAD_MIC;
    }
    
    HEIMDAL_MUTEX_lock(&context_handle->ctx_id_mutex);
    ret = gssapi_msg_order_check(context_handle->order, seq_number);
    HEIMDAL_MUTEX_lock(&context_handle->ctx_id_mutex);
    if (ret)
	return ret;

    return 0;
}

OM_uint32
_gssapi_wrap_arcfour
           (OM_uint32 * minor_status,
            const gss_ctx_id_t context_handle,
            int conf_req_flag,
            gss_qop_t qop_req,
            const gss_buffer_t input_message_buffer,
            int * conf_state,
            gss_buffer_t output_message_buffer,
	    krb5_keyblock *key
           )
{
#if 0
    u_char *p;
    OM_uint32 ret;
    int32_t seq_number;
    size_t len, total_len, datalen;
    gss_arcfour_wrap_token *token;

    krb5_keyblock key7;
    char k7_data[16];
    
    Checksum cksum_k8;
    krb5_keyblock key8;
    char k8_data[16];

    Checksum cksum_k9;
    krb5_keyblock key9;
    char k9_data[16];

    krb5_keyblock key10;
    char k10_data[16];

    Checksum cksum_k11;
    char k11_data[16];

    Checksum CKSUM;
    char cksum_data[16];

    datalen = input_message_buffer->length;
    len = datalen + 30;
    gssapi_krb5_encap_length (len, &len, &total_len, GSS_KRB5_MECHANISM);

    output_message_buffer->length = total_len;
    output_message_buffer->value  = malloc (total_len);
    if (output_message_buffer->value == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    
    p = gssapi_krb5_make_header(output_message_buffer->value,
				len,
				"\x02\x01", /* TOK_ID */
				GSS_KRB5_MECHANISM);
    token = (gss_arcfour_wrap_token *)p;

    token->SGN_ALG[0] = 0x11;
    token->SGN_ALG[1] = 0x00;
    if (conf_req_flag) {
	token->SEAL_ALG[0] = 0x00;
	token->SEAL_ALG[1] = 0x00;
    } else {
	token->SEAL_ALG[0] = 0xff;
	token->SEAL_ALG[1] = 0xff;
    }
    token->Filler[0] = 0xff;
    token->Filler[1] = 0xff;

    memset(p + 8, 0, 16); /* XXX SND_SEQ, SGN_CKSUM */
    /* Confounder */
    krb5_generate_random_block(p + 16, 8);
    
    ret = get_arcfour_sk(gssapi_krb5_context, key, k7_data, sizeof(k7_data));
    if (ret) {
	gss_release_buffer(minor_status, output_message_buffer);
	return ret;
    }

    key7.keytype = KEYTYPE_ARCFOUR;
    key7.keyvalue.length = sizeof(k7_data);
    key7.keyvalue.data = k7_data;

    {
	u_char T[4];
	MD5_CTX md5;
	u_char hash[16];

	T[0] = 13;
	T[1] = 0;
	T[2] = 0;
	T[3] = 0;

	MD5_Init(&md5);
	MD5_Update(&md5, T, 4);		/* T */
	MD5_Update(&md5, p - 8, 8);	/* Token.Header */
	MD5_Update(&md5, p + 16, 8);	/* Confounder */
	MD5_Update(&md5, 
		   input_message_buffer->value, input_message_buffer->length);
	MD5_Final(hash, &md5);

	CKSUM.checksum.data = cksum_data;
	CKSUM.checksum.length = sizeof(cksum_data);
	
	/* draft: HMAC (K7, MD5_of_T_hdr_msg, CHKSUM); */
	ret = krb5_hmac(gssapi_krb5_context, CKSUMTYPE_RSA_MD5, 
			hash, sizeof(hash), 
			0 /* XXX */, &key7, &CKSUM);
	if (ret) {
	    gss_release_buffer(minor_status, output_message_buffer);
	    return ret;
	}
    }

    {
	u_char T[4];

	memset(T, 0, sizeof(T));
	cksum_k8.checksum.data = k8_data;
	cksum_k8.checksum.length = sizeof(k8_data);

	ret = krb5_hmac(gssapi_krb5_context, CKSUMTYPE_RSA_MD5, 
			T, sizeof(T), 4 /* XXX */, key, &cksum_k8);
	if (ret) {
	    gss_release_buffer(minor_status, output_message_buffer);
	    return ret;
	}
    }	

    cksum_k9.checksum.data = k9_data;
    cksum_k9.checksum.length = sizeof(k9_data);

    key8.keytype = KEYTYPE_ARCFOUR;
    key8.keyvalue.length = sizeof(k8_data);
    key8.keyvalue.data = k8_data;

    ret = krb5_hmac(gssapi_krb5_context, CKSUMTYPE_RSA_MD5, 
		    cksum_data, sizeof(cksum_data), 
		    8 /* XXX */, &key8, &cksum_k9);
    if (ret) {
	gss_release_buffer(minor_status, output_message_buffer);
	return ret;
    }

    key9.keytype = KEYTYPE_ARCFOUR;
    key9.keyvalue.length = sizeof(k9_data);
    key9.keyvalue.data = k9_data;

    HEIMDAL_MUTEX_lock(&context_handle->ctx_id_mutex);
    krb5_auth_con_getlocalseqnumber (gssapi_krb5_context,
				     context_handle->auth_context,
				     &seq_number);

    p[0] = (seq_number >> 0)  & 0xFF;
    p[1] = (seq_number >> 8)  & 0xFF;
    p[2] = (seq_number >> 16) & 0xFF;
    p[3] = (seq_number >> 24) & 0xFF;
    
    krb5_auth_con_setlocalseqnumber (gssapi_krb5_context,
				     context_handle->auth_context,
				     ++seq_number);
    HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);

    memset (p + 4, (context_handle->more_flags & LOCAL) ? 0 : 0xFF, 4);

    {
	RC4_KEY rc4_key;
	
	RC4_set_key (&rc4_key, sizeof(k9_data), k9_data);
	RC4 (&rc4_key, 8, p, p);
	
	memset(&rc4_key, 0, sizeof(rc4_key));
    }

    p += 8;
    memcpy(p, cksum_data, 8);

    key10.keytype = KEYTYPE_ARCFOUR;
    key10.keyvalue.length = sizeof(k10_data);
    key10.keyvalue.data = k10_data;

    assert(key->keyvalue.length == 16);
    {
	int i;
	memcpy(k10_data, key->keyvalue.data, sizeof(k10_data));
	for (i = 0; i < sizeof(k10_data); i++)
	    k10_data[i] ^= 0xF0;
    }

    {
	u_char T[4];

	memset(T, 0, sizeof(T));
	cksum_k11.checksum.data = k11_data;
	cksum_k11.checksum.length = sizeof(k11_data);

	ret = krb5_hmac(gssapi_krb5_context, CKSUMTYPE_RSA_MD5, 
			T, sizeof(T), 4 /* XXX */, &key10, &cksum_k11);
	if (ret) {
	    gss_release_buffer(minor_status, output_message_buffer);
	    return ret;
	}
    }	

    memcpy(p + 8, input_message_buffer->value,
	   input_message_buffer->length);
    p[8 + input_message_buffer->length] = 1;

    if (conf_req_flag) {
	RC4_KEY rc4_key;
	
	RC4_set_key (&rc4_key, sizeof(k11_data), k11_data);

	RC4 (&rc4_key, 8 + input_message_buffer->length, p, p);
	memset(&rc4_key, 0, sizeof(rc4_key));
    }
    
    *minor_status = 0;
    return GSS_S_COMPLETE;
#else
    *minor_status = (OM_uint32)KRB5_PROG_ETYPE_NOSUPP;
    return GSS_S_FAILURE;
#endif
}

OM_uint32 _gssapi_unwrap_arcfour(OM_uint32 *minor_status,
				 const gss_ctx_id_t context_handle,
				 const gss_buffer_t input_message_buffer,
				 gss_buffer_t output_message_buffer,
				 int *conf_state,
				 gss_qop_t *qop_state,
				 krb5_keyblock *key)
{
    *minor_status = (OM_uint32)KRB5_PROG_ETYPE_NOSUPP;
    return GSS_S_FAILURE;
}
