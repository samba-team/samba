/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

RCSID("$Id$");

struct PAC_INFO_BUFFER {
    uint32_t type;
    uint32_t buffersize;
    uint32_t offset_hi;
    uint32_t offset_lo;
};

struct PACTYPE {
    uint32_t numbuffers;
    uint32_t version;                         
    struct PAC_INFO_BUFFER buffers[1];
};

struct krb5_pac {
    struct PACTYPE *pac;
    krb5_data data;
    struct PAC_INFO_BUFFER *server_checksum;
    struct PAC_INFO_BUFFER *privsvr_checksum;
    struct PAC_INFO_BUFFER *logon_name;
};

#define PAC_ALIGNMENT		8

#define PACTYPE_SIZE		8
#define PAC_INFO_BUFFER_SIZE	16

#define PAC_SERVER_CHECKSUM	6
#define PAC_PRIVSVR_CHECKSUM	7
#define PAC_LOGON_NAME		10

#define VCHECK(r,f,l)						\
	do {							\
		if (((r) = f ) != 0) {				\
			krb5_clear_error_string(context);	\
			goto l;					\
		}						\
	} while(0)

/*
 *
 */

krb5_error_code
_krb5_pac_parse(krb5_context context, const void *ptr, size_t len,
		struct krb5_pac **pac)
{
    krb5_error_code ret;
    struct krb5_pac *p;
    krb5_storage *sp = NULL;
    uint32_t i, tmp, tmp2, header_end;

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
	ret = ENOMEM;
	krb5_set_error_string(context, "out of memory");
	goto out;
    }

    sp = krb5_storage_from_readonly_mem(ptr, len);
    if (sp == NULL) {
	ret = ENOMEM;
	krb5_set_error_string(context, "out of memory");
	goto out;
    }
    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    VCHECK(ret, krb5_ret_uint32(sp, &tmp), out);
    VCHECK(ret, krb5_ret_uint32(sp, &tmp2), out);
    if (tmp < 1) {
	krb5_set_error_string(context, "PAC have too few buffer");
	ret = EINVAL; /* Too few buffers */
	goto out;
    }
    if (tmp2 != 0) {
	krb5_set_error_string(context, "PAC have wrong version");
	ret = EINVAL; /* Wrong version */
	goto out;
    }

    p->pac = calloc(1, 
		    sizeof(*p->pac) + (sizeof(p->pac->buffers[0]) * (tmp - 1)));
    if (p->pac == NULL) {
	krb5_set_error_string(context, "out of memory");
	ret = ENOMEM;
	goto out;
    }

    p->pac->numbuffers = tmp;
    p->pac->version = tmp2;

    header_end = PACTYPE_SIZE + (PAC_INFO_BUFFER_SIZE * p->pac->numbuffers);
    if (header_end > len) {
	ret = EINVAL;
	goto out;
    }

    for (i = 0; i < p->pac->numbuffers; i++) {
	VCHECK(ret, krb5_ret_uint32(sp, &p->pac->buffers[i].type), out);
	VCHECK(ret, krb5_ret_uint32(sp, &p->pac->buffers[i].buffersize), out);
	VCHECK(ret, krb5_ret_uint32(sp, &p->pac->buffers[i].offset_lo), out);
	VCHECK(ret, krb5_ret_uint32(sp, &p->pac->buffers[i].offset_hi), out);

	/* consistency checks */
	if (p->pac->buffers[i].offset_lo & (PAC_ALIGNMENT - 1)) {
	    krb5_set_error_string(context, "PAC out of allignment");
	    ret = EINVAL;
	    goto out;
	}
	if (p->pac->buffers[i].offset_hi) {
	    krb5_set_error_string(context, "PAC high offset set");
	    ret = EINVAL;
	    goto out;
	}
	if (p->pac->buffers[i].offset_lo > len) {
	    krb5_set_error_string(context, "PAC offset off end");
	    ret = EINVAL;
	    goto out;
	}
	if (p->pac->buffers[i].offset_lo < header_end) {
	    krb5_set_error_string(context, "PAC offset inside header");
	    ret = EINVAL;
	    goto out;
	}
	if (p->pac->buffers[i].buffersize > len - p->pac->buffers[i].offset_lo){
	    krb5_set_error_string(context, "PAC length off end");
	    ret = EINVAL;
	    goto out;
	}

	/* let save pointer to data we need later */
	if (p->pac->buffers[i].type == PAC_SERVER_CHECKSUM) {
	    if (p->server_checksum) {
		krb5_set_error_string(context, "PAC have two server checksums");
		ret = EINVAL;
		goto out;
	    }
	    p->server_checksum = &p->pac->buffers[i];
	} else if (p->pac->buffers[i].type == PAC_PRIVSVR_CHECKSUM) {
	    if (p->privsvr_checksum) {
		krb5_set_error_string(context, "PAC have two KDC checksums");
		ret = EINVAL;
		goto out;
	    }
	    p->privsvr_checksum = &p->pac->buffers[i];
	} else if (p->pac->buffers[i].type == PAC_LOGON_NAME) {
	    if (p->logon_name) {
		krb5_set_error_string(context, "PAC have two logon names");
		ret = EINVAL;
		goto out;
	    }
	    p->logon_name = &p->pac->buffers[i];
	}
    }

    ret = krb5_data_copy(&p->data, ptr, len);
    if (ret)
	goto out;

    krb5_storage_free(sp);

    *pac = p;
    return 0;

out:
    if (sp)
	krb5_storage_free(sp);
    if (p) {
	if (p->pac)
	    free(p->pac);
	free(p);
    }
    *pac = NULL;

    return ret;
}

/*
 *
 */

void
_krb5_pac_free(krb5_context context, struct krb5_pac *pac)
{
    krb5_data_free(&pac->data);
    free(pac->pac);
    free(pac);
}

/*
 *
 */

static krb5_error_code
verify_checksum(krb5_context context,
		const struct PAC_INFO_BUFFER *sig,
		krb5_data *data,
		void *ptr, size_t len,
		krb5_keyblock *key)
{
    krb5_crypto crypto = NULL;
    krb5_storage *sp = NULL;
    uint32_t type;
    krb5_error_code ret;
    Checksum cksum;

    sp = krb5_storage_from_mem((char *)data->data + sig->offset_lo,
			       sig->buffersize);
    if (sp == NULL) {
	krb5_set_error_string(context, "out of memory");
	return ENOMEM;
    }
    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    VCHECK(ret, krb5_ret_uint32(sp, &type), out);
    cksum.cksumtype = type;
    cksum.checksum.length = 
	sig->buffersize - krb5_storage_seek(sp, 0, SEEK_CUR);
    cksum.checksum.data = malloc(cksum.checksum.length);
    if (cksum.checksum.data == NULL) {
	krb5_set_error_string(context, "out of memory");
	ret = ENOMEM;
	goto out;
    }
    ret = krb5_storage_read(sp, cksum.checksum.data, cksum.checksum.length);
    if (ret != cksum.checksum.length) {
	krb5_set_error_string(context, "PAC checksum missing checksum");
	ret = EINVAL;
	goto out;
    }

    if (!krb5_checksum_is_keyed(context, cksum.cksumtype)) {
	krb5_set_error_string (context, "Checksum type %d not keyed",
			       cksum.cksumtype);
	ret = EINVAL;
	goto out;
    }

    ret = krb5_crypto_init(context, key, 0, &crypto);
    if (ret)
	goto out;

    ret = krb5_verify_checksum(context, crypto, KRB5_KU_OTHER_CKSUM,
			       ptr, len, &cksum);
    krb5_crypto_destroy(context, crypto);
    krb5_storage_free(sp);

    return ret;

out:
    if (sp)
	krb5_storage_free(sp);
    if (crypto)
	krb5_crypto_destroy(context, crypto);
    return ret;
}

/*
 *
 */

#define NTTIME_EPOCH 0x019DB1DED53E8000LL

static uint64_t
unix2nttime(time_t unix_time)
{
    long long wt;
    wt = unix_time * (uint64_t)10000000 + (uint64_t)NTTIME_EPOCH;
    return wt;
}

static krb5_error_code
verify_logonname(krb5_context context,
		 const struct PAC_INFO_BUFFER *logon_name,
		 krb5_data *data,
		 time_t authtime,
		 krb5_principal principal)
{
    krb5_error_code ret;
    krb5_principal p2;
    uint32_t time1, time2;
    krb5_storage *sp;
    uint16_t len;
    char *s;

    sp = krb5_storage_from_mem((char *)data->data + logon_name->offset_lo,
			       logon_name->buffersize);
    if (sp == NULL) {
	krb5_set_error_string(context, "Out of memory");
	return ENOMEM;
    }

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    VCHECK(ret, krb5_ret_uint32(sp, &time1), out);
    VCHECK(ret, krb5_ret_uint32(sp, &time2), out);

    {
	uint64_t t1, t2;
	t1 = unix2nttime(authtime);
	t2 = ((uint64_t)time2 << 32) | time1;
	if (t1 != t2) {
	    krb5_storage_free(sp);
	    krb5_set_error_string(context, "PAC timestamp mismatch");
	    return EINVAL;
	}
    }
    VCHECK(ret, krb5_ret_uint16(sp, &len), out);
    if (len == 0) {
	krb5_storage_free(sp);
	krb5_set_error_string(context, "PAC logon name length missing");
	return EINVAL;
    }

    s = malloc(len);
    if (s == NULL) {
	krb5_storage_free(sp);
	krb5_set_error_string(context, "Out of memory");
	return ENOMEM;
    }
    ret = krb5_storage_read(sp, s, len);
    if (ret != len) {
	krb5_storage_free(sp);
	krb5_set_error_string(context, "Failed to read pac logon name");
	return EINVAL;
    }
    krb5_storage_free(sp);
#if 1 /* cheat for know */
    {
	size_t i;

	if (len & 1) {
	    krb5_set_error_string(context, "PAC logon name mailformed");
	    return EINVAL;
	}

	for (i = 0; i < len / 2; i++) {
	    if (s[(i * 2) + 1]) {
		krb5_set_error_string(context, "PAC logon name not ASCII");
		return EINVAL;
	    }
	    s[i] = s[i * 2];
	}
	s[i] = '\0';
    }
#else
    {
	uint16_t *ucs2;
	ssize_t ucs2len;
	size_t u8len;

	ucs2 = malloc(sizeof(ucs2[0]) * len / 2);
	if (ucs2)
	    abort();
	ucs2len = wind_ucs2read(s, len / 2, ucs2);
	free(s);
	if (len < 0)
	    return -1;
	ret = wind_ucs2toutf8(ucs2, ucs2len, NULL, &u8len);
	if (ret < 0)
	    abort();
	s = malloc(u8len + 1);
	if (s == NULL)
	    abort();
	wind_ucs2toutf8(ucs2, ucs2len, s, &u8len);
	free(ucs2);
    }
#endif
    ret = krb5_parse_name_flags(context, s, KRB5_PRINCIPAL_PARSE_NO_REALM, &p2);
    free(s);
    if (ret)
	return ret;
    
    if (krb5_principal_compare_any_realm(context, principal, p2) != TRUE) {
	krb5_set_error_string(context, "PAC logon name mismatch");
	ret = EINVAL;
    }
    krb5_free_principal(context, p2);
    return ret;
out:
    return ret;
}

/*
 *
 */

krb5_error_code
_krb5_pac_verify(krb5_context context, 
		 struct krb5_pac *pac,
		 time_t authtime,
		 krb5_principal principal,
		 krb5_keyblock *server,
		 krb5_keyblock *privsvr)
{
    krb5_error_code ret;

    if (pac->server_checksum == NULL) {
	krb5_set_error_string(context, "PAC missing server checksum");
	return EINVAL;
    }
    if (pac->privsvr_checksum == NULL) {
	krb5_set_error_string(context, "PAC missing kdc checksum");
	return EINVAL;
    }
    if (pac->logon_name == NULL) {
	krb5_set_error_string(context, "PAC missing logon name");
	return EINVAL;
    }

    ret = verify_logonname(context, 
			   pac->logon_name,
			   &pac->data,
			   authtime,
			   principal);
    if (ret)
	return ret;

    /* 
     * in the service case, clean out data option of the privsvr and
     * server checksum before checking the checksum.
     */
    {
	krb5_data *copy;

	ret = krb5_copy_data(context, &pac->data, &copy);
	if (ret)
	    return ret;

	if (pac->server_checksum->buffersize < 4)
	    return EINVAL;
	if (pac->privsvr_checksum->buffersize < 4)
	    return EINVAL;

	memset((char *)copy->data + pac->server_checksum->offset_lo + 4,
	       0,
	       pac->server_checksum->buffersize - 4);

	memset((char *)copy->data + pac->privsvr_checksum->offset_lo + 4,
	       0,
	       pac->privsvr_checksum->buffersize - 4);

	ret = verify_checksum(context,
			      pac->server_checksum,
			      &pac->data,
			      copy->data,
			      copy->length,
			      server);
	krb5_free_data(context, copy);
	if (ret)
	    return ret;
    }
    if (privsvr) {
	ret = verify_checksum(context,
			      pac->privsvr_checksum,
			      &pac->data,
			      (char *)pac->data.data
			      + pac->server_checksum->offset_lo + 4,
			      pac->server_checksum->buffersize - 4,
			      privsvr);
	if (ret)
	    return ret;
    }

    return 0;
}

/*
 *
 */

krb5_error_code
_krb5_pac_sign(krb5_context context,
	       struct krb5_pac *pac,
	       time_t authtime,
	       krb5_principal principal,
	       krb5_keyblock *service_key,
	       krb5_keyblock *priv_key,
	       krb5_data *data)
{
    int num = 0;

    if (pac->server_checksum == NULL)
	num++;
    if (pac->privsvr_checksum == NULL)
	num++;
    if (pac->logon_name == NULL)
	num++;
    if (num) {
	void *ptr;

	ptr = realloc(pac->pac, sizeof(*pac->pac) + (sizeof(pac->pac->buffers[0]) * (pac->pac->numbuffers + num - 1)));
	if (ptr == NULL)
	    abort();
	pac->pac = ptr;

	if (pac->server_checksum == NULL) {
	    pac->server_checksum = &pac->pac->buffers[pac->pac->numbuffers++];
	    memset(pac->server_checksum, 0, sizeof(*pac->server_checksum));
	}
	if (pac->privsvr_checksum == NULL) {
	    pac->privsvr_checksum = &pac->pac->buffers[pac->pac->numbuffers++];
	    memset(pac->privsvr_checksum, 0, sizeof(*pac->privsvr_checksum));
	}
	if (pac->logon_name == NULL) {
	    pac->logon_name = &pac->pac->buffers[pac->pac->numbuffers++];
	    memset(pac->logon_name, 0, sizeof(*pac->logon_name));
	}
    }

    return 0;
}
