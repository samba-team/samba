/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
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
#include <wind.h>

/*
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399
 */
struct PAC_INFO_BUFFER {
    uint32_t type;          /* ULONG   ulType       in the original */
    uint32_t buffersize;    /* ULONG   cbBufferSize in the original */
    uint64_t offset;        /* ULONG64 Offset       in the original
                             * this being the offset from the beginning of the
                             * struct PACTYPE to the beginning of the buffer
                             * containing data of type ulType
                             */
};

/*
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6655b92f-ab06-490b-845d-037e6987275f
 */
struct PACTYPE {
    uint32_t numbuffers;    /* named cBuffers of type ULONG in the original */
    uint32_t version;       /* Named Version  of type ULONG in the original */
    struct PAC_INFO_BUFFER buffers[1]; /* an ellipsis (...) in the original */
};

/*
 * A PAC starts with a PACTYPE header structure that is followed by an array of
 * numbuffers PAC_INFO_BUFFER structures, each of which points to a buffer
 * beyond the last PAC_INFO_BUFFER structures.
 */

struct krb5_pac_data {
    struct PACTYPE *pac;
    krb5_data data;
    struct PAC_INFO_BUFFER *server_checksum;
    struct PAC_INFO_BUFFER *privsvr_checksum;
    struct PAC_INFO_BUFFER *logon_name;
    struct PAC_INFO_BUFFER *ticket_checksum;
    krb5_data ticket_sign_data;
};

#define PAC_ALIGNMENT			8

#define PACTYPE_SIZE			8
#define PAC_INFO_BUFFER_SIZE		16

#define PAC_LOGON_INFO			1
#define PAC_SERVER_CHECKSUM		6
#define PAC_PRIVSVR_CHECKSUM		7
#define PAC_LOGON_NAME			10
#define PAC_CONSTRAINED_DELEGATION	11
#define PAC_UPN_DNS_INFO		12
#define PAC_TICKET_CHECKSUM		16

#define CHECK(r,f,l)						\
	do {							\
		if (((r) = f ) != 0) {				\
			krb5_clear_error_message(context);	\
			goto l;					\
		}						\
	} while(0)

static const char zeros[PAC_ALIGNMENT] = { 0 };

/*
 * Returns the size of the PACTYPE header + the PAC_INFO_BUFFER array.  This is
 * also the end of the whole thing, and any offsets to buffers from
 * thePAC_INFO_BUFFER[] entries have to be beyond it.
 */
static krb5_error_code
pac_header_size(krb5_context context, uint32_t num_buffers, uint32_t *result)
{
    krb5_error_code ret;
    uint32_t header_size;

    /* Guard against integer overflow */
    if (num_buffers > UINT32_MAX / PAC_INFO_BUFFER_SIZE) {
	ret = EOVERFLOW;
	krb5_set_error_message(context, ret, "PAC has too many buffers");
	return ret;
    }
    header_size = PAC_INFO_BUFFER_SIZE * num_buffers;

    /* Guard against integer overflow */
    if (header_size > UINT32_MAX - PACTYPE_SIZE) {
	ret = EOVERFLOW;
	krb5_set_error_message(context, ret, "PAC has too many buffers");
	return ret;
    }
    header_size += PACTYPE_SIZE;

    *result = header_size;

    return 0;
}

/* Output `size' + `addend' + padding for alignment if it doesn't overflow */
static krb5_error_code
pac_aligned_size(krb5_context context,
                 uint32_t size,
                 uint32_t addend,
                 uint32_t *aligned_size)
{
    krb5_error_code ret;

    if (size > UINT32_MAX - addend ||
        (size + addend) > UINT32_MAX - (PAC_ALIGNMENT - 1)) {
	ret = EOVERFLOW;
	krb5_set_error_message(context, ret, "integer overrun");
	return ret;
    }
    size += addend;
    size += PAC_ALIGNMENT - 1;
    size &= ~(PAC_ALIGNMENT - 1);
    *aligned_size = size;
    return 0;
}

/*
 * HMAC-MD5 checksum over any key (needed for the PAC routines)
 */

static krb5_error_code
HMAC_MD5_any_checksum(krb5_context context,
		      const krb5_keyblock *key,
		      const void *data,
		      size_t len,
		      unsigned usage,
		      Checksum *result)
{
    struct _krb5_key_data local_key;
    krb5_error_code ret;

    memset(&local_key, 0, sizeof(local_key));

    ret = krb5_copy_keyblock(context, key, &local_key.key);
    if (ret)
	return ret;

    ret = krb5_data_alloc (&result->checksum, 16);
    if (ret) {
	krb5_free_keyblock(context, local_key.key);
	return ret;
    }

    result->cksumtype = CKSUMTYPE_HMAC_MD5;
    ret = _krb5_HMAC_MD5_checksum(context, &local_key, data, len, usage, result);
    if (ret)
	krb5_data_free(&result->checksum);

    krb5_free_keyblock(context, local_key.key);
    return ret;
}


/*
 *
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_parse(krb5_context context, const void *ptr, size_t len,
	       krb5_pac *pac)
{
    krb5_error_code ret = 0;
    krb5_pac p;
    krb5_storage *sp = NULL;
    uint32_t i, num_buffers, version, header_size = 0;
    uint32_t prev_start = 0;
    uint32_t prev_end = 0;

    *pac = NULL;
    p = calloc(1, sizeof(*p));
    if (p)
        sp = krb5_storage_from_readonly_mem(ptr, len);
    if (sp == NULL)
	ret = krb5_enomem(context);
    if (ret == 0) {
        krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);
        ret = krb5_ret_uint32(sp, &num_buffers);
    }
    if (ret == 0)
        ret = krb5_ret_uint32(sp, &version);
    if (ret == 0 && num_buffers < 1)
	krb5_set_error_message(context, ret = EINVAL,
                               N_("PAC has too few buffers", ""));
    if (ret == 0 && num_buffers > 1000)
	krb5_set_error_message(context, ret = EINVAL,
                               N_("PAC has too many buffers", ""));
    if (ret == 0 && version != 0)
	krb5_set_error_message(context, ret = EINVAL,
			       N_("PAC has wrong version %d", ""),
			       (int)version);
    if (ret == 0)
        ret = pac_header_size(context, num_buffers, &header_size);
    if (ret == 0 && header_size > len)
        krb5_set_error_message(context, ret = EOVERFLOW,
                               N_("PAC encoding invalid, would overflow buffers", ""));
    if (ret == 0)
        p->pac = calloc(1, header_size);
    if (ret == 0 && p->pac == NULL)
	ret = krb5_enomem(context);

    if (ret == 0) {
        p->pac->numbuffers = num_buffers;
        p->pac->version = version;
    }

    for (i = 0; ret == 0 && i < p->pac->numbuffers; i++) {
        ret = krb5_ret_uint32(sp, &p->pac->buffers[i].type);
        if (ret == 0)
            ret = krb5_ret_uint32(sp, &p->pac->buffers[i].buffersize);
        if (ret == 0)
            ret = krb5_ret_uint64(sp, &p->pac->buffers[i].offset);
        if (ret)
            break;

	/* Consistency checks (we don't check for wasted space) */
	if (p->pac->buffers[i].offset & (PAC_ALIGNMENT - 1)) {
	    krb5_set_error_message(context, ret = EINVAL,
				   N_("PAC out of alignment", ""));
	    break;
	}
	if (p->pac->buffers[i].offset > len ||
            p->pac->buffers[i].buffersize > len ||
            len - p->pac->buffers[i].offset < p->pac->buffers[i].buffersize) {
	    krb5_set_error_message(context, ret = EOVERFLOW,
				   N_("PAC buffer overflow", ""));
	    break;
	}
	if (p->pac->buffers[i].offset < header_size) {
	    krb5_set_error_message(context, ret = EINVAL,
				   N_("PAC offset inside header: %lu %lu", ""),
				   (unsigned long)p->pac->buffers[i].offset,
				   (unsigned long)header_size);
	    break;
	}

        /*
         * We'd like to check for non-overlapping of buffers, but the buffers
         * need not be in the same order as the PAC_INFO_BUFFER[] entries
         * pointing to them!  To fully check for overlap we'd have to have an
         * O(N^2) loop after we parse all the PAC_INFO_BUFFER[].
         *
         * But we can check that each buffer does not overlap the previous
         * buffer.
         */
        if (prev_start) {
            if (p->pac->buffers[i].offset >= prev_start &&
                p->pac->buffers[i].offset <  prev_end) {
                krb5_set_error_message(context, ret = EINVAL,
                                       N_("PAC overlap", ""));
                break;
            }
            if (p->pac->buffers[i].offset < prev_start &&
                p->pac->buffers[i].offset +
                p->pac->buffers[i].buffersize > prev_start) {
                krb5_set_error_message(context, ret = EINVAL,
                                       N_("PAC overlap", ""));
                break;
            }
        }
        prev_start = p->pac->buffers[i].offset;
        prev_end = p->pac->buffers[i].offset + p->pac->buffers[i].buffersize;

	/* Let's save pointers to buffers we'll need later */
        switch (p->pac->buffers[i].type) {
        case PAC_SERVER_CHECKSUM:
	    if (p->server_checksum)
		krb5_set_error_message(context, ret = EINVAL,
				       N_("PAC has multiple server checksums", ""));
	    else
                p->server_checksum = &p->pac->buffers[i];
            break;
        case PAC_PRIVSVR_CHECKSUM:
	    if (p->privsvr_checksum)
                krb5_set_error_message(context, ret = EINVAL,
                                       N_("PAC has multiple KDC checksums", ""));
            else
                p->privsvr_checksum = &p->pac->buffers[i];
            break;
        case PAC_LOGON_NAME:
	    if (p->logon_name)
		krb5_set_error_message(context, ret = EINVAL,
                                       N_("PAC has multiple logon names", ""));
            else
                p->logon_name = &p->pac->buffers[i];
            break;
        case PAC_TICKET_CHECKSUM:
	    if (p->ticket_checksum)
		krb5_set_error_message(context, ret = EINVAL,
				       N_("PAC has multiple ticket checksums", ""));
            else
                p->ticket_checksum = &p->pac->buffers[i];
            break;
        default: break;
        }
    }

    if (ret == 0)
        ret = krb5_data_copy(&p->data, ptr, len);
    if (ret == 0) {
        *pac = p;
        p = NULL;
    }
    if (sp)
        krb5_storage_free(sp);
    krb5_pac_free(context, p);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_init(krb5_context context, krb5_pac *pac)
{
    krb5_error_code ret;
    krb5_pac p;

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
	return krb5_enomem(context);
    }

    p->pac = calloc(1, sizeof(*p->pac));
    if (p->pac == NULL) {
	free(p);
	return krb5_enomem(context);
    }

    ret = krb5_data_alloc(&p->data, PACTYPE_SIZE);
    if (ret) {
	free (p->pac);
	free(p);
	return krb5_enomem(context);
    }
    memset(p->data.data, 0, p->data.length);

    *pac = p;
    return 0;
}

/**
 * Add a PAC buffer `nd' of type `type' to the pac `p'.
 *
 * @param context
 * @param p
 * @param type
 * @param nd
 *
 * @return 0 on success or a Kerberos or system error.
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_add_buffer(krb5_context context, krb5_pac p,
		    uint32_t type, const krb5_data *nd)
{
    krb5_error_code ret;
    void *ptr;
    size_t old_len = p->data.length;
    uint32_t len, offset, header_size;
    uint32_t i;
    uint32_t num_buffers;

    num_buffers = p->pac->numbuffers;
    ret = pac_header_size(context, num_buffers + 1, &header_size);
    if (ret)
	return ret;

    ptr = realloc(p->pac, header_size);
    if (ptr == NULL)
	return krb5_enomem(context);

    p->pac = ptr;
    p->pac->buffers[num_buffers].type = 0;
    p->pac->buffers[num_buffers].buffersize = 0;
    p->pac->buffers[num_buffers].offset = 0;

    /*
     * Check that we can adjust all the buffer offsets in the existing
     * PAC_INFO_BUFFERs, since changing the size of PAC_INFO_BUFFER[] means
     * changing the offsets of buffers following that array.
     *
     * We don't adjust them until we can't fail.
     */
    for (i = 0; i < num_buffers; i++) {
	if (p->pac->buffers[i].offset > UINT32_MAX - PAC_INFO_BUFFER_SIZE) {
	    krb5_set_error_message(context, ret = EOVERFLOW,
                                   "too many / too large PAC buffers");
	    return ret;
	}
    }

    /*
     * The new buffer's offset must be past the end of the buffers we have
     * (p->data), which is the sum of the header and p->data.length.
     */

    /* Set offset = p->data.length + PAC_INFO_BUFFER_SIZE + alignment */
    ret = pac_aligned_size(context, p->data.length, PAC_INFO_BUFFER_SIZE, &offset);
    if (ret == 0)
        /* Set the new length = offset + nd->length + alignment */
        ret = pac_aligned_size(context, offset, nd->length, &len);
    if (ret) {
	krb5_set_error_message(context, ret, "PAC buffer too large");
        return ret;
    }
    ret = krb5_data_realloc(&p->data, len);
    if (ret) {
	krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
	return ret;
    }

    /* Zero out the new allocation to zero out any padding */
    memset((char *)p->data.data + old_len, 0, len - old_len);

    p->pac->buffers[num_buffers].type = type;
    p->pac->buffers[num_buffers].buffersize = nd->length;
    p->pac->buffers[num_buffers].offset = offset;

    /* Adjust all the buffer offsets in the existing PAC_INFO_BUFFERs now */
    for (i = 0; i < num_buffers; i++)
	p->pac->buffers[i].offset += PAC_INFO_BUFFER_SIZE;

    /*
     * Make place for new PAC INFO BUFFER header
     */
    header_size -= PAC_INFO_BUFFER_SIZE;
    memmove((unsigned char *)p->data.data + header_size + PAC_INFO_BUFFER_SIZE,
	    (unsigned char *)p->data.data + header_size ,
	    old_len - header_size);
    /* Clear the space where we would put the new PAC_INFO_BUFFER[] element */
    memset((unsigned char *)p->data.data + header_size, 0,
           PAC_INFO_BUFFER_SIZE);

    /*
     * Copy in new data part
     */
    memcpy((unsigned char *)p->data.data + offset, nd->data, nd->length);
    p->pac->numbuffers += 1;
    return 0;
}

/**
 * Get the PAC buffer of specific type from the pac.
 *
 * @param context Kerberos 5 context.
 * @param p the pac structure returned by krb5_pac_parse().
 * @param type type of buffer to get
 * @param data return data, free with krb5_data_free().
 *
 * @return Returns 0 to indicate success, ENOENT to indicate that a buffer of
 * the given type was not found, or a Kerberos or system error code.
 *
 * @ingroup krb5_pac
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_get_buffer(krb5_context context, krb5_pac p,
		    uint32_t type, krb5_data *data)
{
    krb5_error_code ret;
    uint32_t i;

    for (i = 0; i < p->pac->numbuffers; i++) {
	size_t len = p->pac->buffers[i].buffersize;
	size_t offset = p->pac->buffers[i].offset;

	if (p->pac->buffers[i].type != type)
	    continue;

	if (!data)
            return 0;

        ret = krb5_data_copy(data, (unsigned char *)p->data.data + offset, len);
        if (ret)
            krb5_set_error_message(context, ret, N_("malloc: out of memory", ""));
	return ret;
    }
    krb5_set_error_message(context, ENOENT, "No PAC buffer of type %lu was found",
			   (unsigned long)type);
    return ENOENT;
}

/*
 *
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_get_types(krb5_context context,
		   krb5_pac p,
		   size_t *len,
		   uint32_t **types)
{
    size_t i;

    *types = calloc(p->pac->numbuffers, sizeof(*types));
    if (*types == NULL) {
	*len = 0;
	return krb5_enomem(context);
    }
    for (i = 0; i < p->pac->numbuffers; i++)
	(*types)[i] = p->pac->buffers[i].type;
    *len = p->pac->numbuffers;

    return 0;
}

/*
 *
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_pac_free(krb5_context context, krb5_pac pac)
{
    if (pac == NULL)
	return;
    krb5_data_free(&pac->data);
    krb5_data_free(&pac->ticket_sign_data);
    free(pac->pac);
    free(pac);
}

/*
 *
 */

static krb5_error_code
verify_checksum(krb5_context context,
		const struct PAC_INFO_BUFFER *sig,
		const krb5_data *data,
		void *ptr, size_t len,
		const krb5_keyblock *key)
{
    krb5_storage *sp = NULL;
    uint32_t type;
    krb5_error_code ret;
    Checksum cksum;
    size_t cksumsize;

    memset(&cksum, 0, sizeof(cksum));

    sp = krb5_storage_from_mem((char *)data->data + sig->offset,
			       sig->buffersize);
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_ret_uint32(sp, &type), out);
    cksum.cksumtype = type;

    ret = krb5_checksumsize(context, type, &cksumsize);
    if (ret)
	goto out;

    /* Allow for RODCIdentifier trailer, see MS-PAC 2.8 */
    if (cksumsize > (sig->buffersize - krb5_storage_seek(sp, 0, SEEK_CUR))) {
	ret = EINVAL;
	goto out;
    }
    cksum.checksum.length = cksumsize;
    cksum.checksum.data = malloc(cksum.checksum.length);
    if (cksum.checksum.data == NULL) {
	ret = krb5_enomem(context);
	goto out;
    }
    ret = krb5_storage_read(sp, cksum.checksum.data, cksum.checksum.length);
    if (ret != (int)cksum.checksum.length) {
	ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
	krb5_set_error_message(context, ret, "PAC checksum missing checksum");
	goto out;
    }

    if (!krb5_checksum_is_keyed(context, cksum.cksumtype)) {
	ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
	krb5_set_error_message(context, ret, "Checksum type %d not keyed",
			       cksum.cksumtype);
	goto out;
    }

    /* If the checksum is HMAC-MD5, the checksum type is not tied to
     * the key type, instead the HMAC-MD5 checksum is applied blindly
     * on whatever key is used for this connection, avoiding issues
     * with unkeyed checksums on des-cbc-md5 and des-cbc-crc.  See
     * http://comments.gmane.org/gmane.comp.encryption.kerberos.devel/8743
     * for the same issue in MIT, and
     * http://blogs.msdn.com/b/openspecification/archive/2010/01/01/verifying-the-server-signature-in-kerberos-privilege-account-certificate.aspx
     * for Microsoft's explaination */

    if (cksum.cksumtype == CKSUMTYPE_HMAC_MD5) {
	Checksum local_checksum;

	memset(&local_checksum, 0, sizeof(local_checksum));

	ret = HMAC_MD5_any_checksum(context, key, ptr, len,
				    KRB5_KU_OTHER_CKSUM, &local_checksum);

	if (ret != 0 || krb5_data_ct_cmp(&local_checksum.checksum, &cksum.checksum) != 0) {
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	    krb5_set_error_message(context, ret,
				   N_("PAC integrity check failed for "
				      "hmac-md5 checksum", ""));
	}
	krb5_data_free(&local_checksum.checksum);

   } else {
	krb5_crypto crypto = NULL;

	ret = krb5_crypto_init(context, key, 0, &crypto);
	if (ret)
		goto out;

	ret = krb5_verify_checksum(context, crypto, KRB5_KU_OTHER_CKSUM,
				   ptr, len, &cksum);
	krb5_crypto_destroy(context, crypto);
    }
    free(cksum.checksum.data);
    krb5_storage_free(sp);

    return ret;

out:
    if (cksum.checksum.data)
	free(cksum.checksum.data);
    if (sp)
	krb5_storage_free(sp);
    return ret;
}

static krb5_error_code
create_checksum(krb5_context context,
		const krb5_keyblock *key,
		uint32_t cksumtype,
		void *data, size_t datalen,
		void *sig, size_t siglen)
{
    krb5_crypto crypto = NULL;
    krb5_error_code ret;
    Checksum cksum;

    /* If the checksum is HMAC-MD5, the checksum type is not tied to
     * the key type, instead the HMAC-MD5 checksum is applied blindly
     * on whatever key is used for this connection, avoiding issues
     * with unkeyed checksums on des-cbc-md5 and des-cbc-crc.  See
     * http://comments.gmane.org/gmane.comp.encryption.kerberos.devel/8743
     * for the same issue in MIT, and
     * http://blogs.msdn.com/b/openspecification/archive/2010/01/01/verifying-the-server-signature-in-kerberos-privilege-account-certificate.aspx
     * for Microsoft's explaination */

    if (cksumtype == (uint32_t)CKSUMTYPE_HMAC_MD5) {
	ret = HMAC_MD5_any_checksum(context, key, data, datalen,
				    KRB5_KU_OTHER_CKSUM, &cksum);
    } else {
	ret = krb5_crypto_init(context, key, 0, &crypto);
	if (ret)
	    return ret;

	ret = krb5_create_checksum(context, crypto, KRB5_KU_OTHER_CKSUM, 0,
				   data, datalen, &cksum);
	krb5_crypto_destroy(context, crypto);
	if (ret)
	    return ret;
    }
    if (cksum.checksum.length != siglen) {
	krb5_set_error_message(context, EINVAL, "pac checksum wrong length");
	free_Checksum(&cksum);
	return EINVAL;
    }

    memcpy(sig, cksum.checksum.data, siglen);
    free_Checksum(&cksum);

    return 0;
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
		 const krb5_data *data,
		 time_t authtime,
		 krb5_const_principal principal)
{
    krb5_error_code ret;
    uint32_t time1, time2;
    krb5_storage *sp;
    uint16_t len;
    char *s = NULL;
    char *principal_string = NULL;
    char *logon_string = NULL;

    sp = krb5_storage_from_readonly_mem((const char *)data->data + logon_name->offset,
					logon_name->buffersize);
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_ret_uint32(sp, &time1), out);
    CHECK(ret, krb5_ret_uint32(sp, &time2), out);

    {
	uint64_t t1, t2;
	t1 = unix2nttime(authtime);
	t2 = ((uint64_t)time2 << 32) | time1;
	if (t1 != t2) {
	    krb5_storage_free(sp);
	    krb5_set_error_message(context, EINVAL, "PAC timestamp mismatch");
	    return EINVAL;
	}
    }
    CHECK(ret, krb5_ret_uint16(sp, &len), out);
    if (len == 0) {
	krb5_storage_free(sp);
	krb5_set_error_message(context, EINVAL, "PAC logon name length missing");
	return EINVAL;
    }

    s = malloc(len);
    if (s == NULL) {
	krb5_storage_free(sp);
	return krb5_enomem(context);
    }
    ret = krb5_storage_read(sp, s, len);
    if (ret != len) {
	krb5_storage_free(sp);
	krb5_set_error_message(context, EINVAL, "Failed to read PAC logon name");
	return EINVAL;
    }
    krb5_storage_free(sp);
    {
	size_t ucs2len = len / 2;
	uint16_t *ucs2;
	size_t u8len;
	unsigned int flags = WIND_RW_LE;

	ucs2 = malloc(sizeof(ucs2[0]) * ucs2len);
	if (ucs2 == NULL)
	    return krb5_enomem(context);

	ret = wind_ucs2read(s, len, &flags, ucs2, &ucs2len);
	free(s);
	if (ret) {
	    free(ucs2);
	    krb5_set_error_message(context, ret, "Failed to convert string to UCS-2");
	    return ret;
	}
	ret = wind_ucs2utf8_length(ucs2, ucs2len, &u8len);
	if (ret) {
	    free(ucs2);
	    krb5_set_error_message(context, ret, "Failed to count length of UCS-2 string");
	    return ret;
	}
	u8len += 1; /* Add space for NUL */
	logon_string = malloc(u8len);
	if (logon_string == NULL) {
	    free(ucs2);
	    return krb5_enomem(context);
	}
	ret = wind_ucs2utf8(ucs2, ucs2len, logon_string, &u8len);
	free(ucs2);
	if (ret) {
	    free(logon_string);
	    krb5_set_error_message(context, ret, "Failed to convert to UTF-8");
	    return ret;
	}
    }
    ret = krb5_unparse_name_flags(context, principal,
				  KRB5_PRINCIPAL_UNPARSE_NO_REALM |
				  KRB5_PRINCIPAL_UNPARSE_DISPLAY,
				  &principal_string);
    if (ret) {
	free(logon_string);
	return ret;
    }

    ret = strcmp(logon_string, principal_string);
    if (ret != 0) {
	ret = EINVAL;
	krb5_set_error_message(context, ret, "PAC logon name [%s] mismatch principal name [%s]",
			       logon_string, principal_string);
    }
    free(logon_string);
    free(principal_string);
    return ret;
out:
    return ret;
}

/*
 *
 */

static krb5_error_code
build_logon_name(krb5_context context,
		 time_t authtime,
		 krb5_const_principal principal,
		 krb5_data *logon)
{
    krb5_error_code ret;
    krb5_storage *sp;
    uint64_t t;
    char *s, *s2;
    size_t s2_len;

    t = unix2nttime(authtime);

    krb5_data_zero(logon);

    sp = krb5_storage_emem();
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    CHECK(ret, krb5_store_uint32(sp, t & 0xffffffff), out);
    CHECK(ret, krb5_store_uint32(sp, t >> 32), out);

    ret = krb5_unparse_name_flags(context, principal,
				  KRB5_PRINCIPAL_UNPARSE_NO_REALM |
				  KRB5_PRINCIPAL_UNPARSE_DISPLAY,
				  &s);
    if (ret)
	goto out;

    {
	size_t ucs2_len;
	uint16_t *ucs2;
	unsigned int flags;

	ret = wind_utf8ucs2_length(s, &ucs2_len);
	if (ret) {
	    free(s);
	    krb5_set_error_message(context, ret, "Failed to count length of UTF-8 string");
	    return ret;
	}

	ucs2 = malloc(sizeof(ucs2[0]) * ucs2_len);
	if (ucs2 == NULL) {
	    free(s);
	    return krb5_enomem(context);
	}

	ret = wind_utf8ucs2(s, ucs2, &ucs2_len);
	free(s);
	if (ret) {
	    free(ucs2);
	    krb5_set_error_message(context, ret, "Failed to convert string to UCS-2");
	    return ret;
	}

	s2_len = (ucs2_len + 1) * 2;
	s2 = malloc(s2_len);
	if (s2 == NULL) {
	    free(ucs2);
	    return krb5_enomem(context);
	}

	flags = WIND_RW_LE;
	ret = wind_ucs2write(ucs2, ucs2_len,
			     &flags, s2, &s2_len);
	free(ucs2);
	if (ret) {
	    free(s2);
	    krb5_set_error_message(context, ret, "Failed to write to UCS-2 buffer");
	    return ret;
	}

	/*
	 * we do not want zero termination
	 */
	s2_len = ucs2_len * 2;
    }

    CHECK(ret, krb5_store_uint16(sp, s2_len), out);

    ret = krb5_storage_write(sp, s2, s2_len);
    free(s2);
    if (ret != (int)s2_len) {
	ret = krb5_enomem(context);
	goto out;
    }
    ret = krb5_storage_to_data(sp, logon);
    if (ret)
	goto out;
    krb5_storage_free(sp);

    return 0;
out:
    krb5_storage_free(sp);
    return ret;
}

/**
 * Verify the PAC.
 *
 * @param context Kerberos 5 context.
 * @param pac the pac structure returned by krb5_pac_parse().
 * @param authtime The time of the ticket the PAC belongs to.
 * @param principal the principal to verify.
 * @param server The service key, most always be given.
 * @param privsvr The KDC key, may be given.

 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5_pac
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_verify(krb5_context context,
		const krb5_pac pac,
		time_t authtime,
		krb5_const_principal principal,
		const krb5_keyblock *server,
		const krb5_keyblock *privsvr)
{
    krb5_error_code ret;

    if (pac->server_checksum == NULL) {
	krb5_set_error_message(context, EINVAL, "PAC missing server checksum");
	return EINVAL;
    }
    if (pac->privsvr_checksum == NULL) {
	krb5_set_error_message(context, EINVAL, "PAC missing kdc checksum");
	return EINVAL;
    }
    if (pac->logon_name == NULL) {
	krb5_set_error_message(context, EINVAL, "PAC missing logon name");
	return EINVAL;
    }

    if (principal != NULL) {
	ret = verify_logonname(context, pac->logon_name, &pac->data, authtime,
			       principal);
	if (ret)
	    return ret;
    }

    if (pac->server_checksum->buffersize < 4 ||
        pac->privsvr_checksum->buffersize < 4)
	return EINVAL;

    /*
     * in the service case, clean out data option of the privsvr and
     * server checksum before checking the checksum.
     */
    if (server != NULL)
    {
	krb5_data *copy;

	ret = krb5_copy_data(context, &pac->data, &copy);
	if (ret)
	    return ret;

	if (pac->server_checksum->buffersize < 4)
	    return EINVAL;
	if (pac->privsvr_checksum->buffersize < 4)
	    return EINVAL;

	memset((char *)copy->data + pac->server_checksum->offset + 4,
	       0,
	       pac->server_checksum->buffersize - 4);

	memset((char *)copy->data + pac->privsvr_checksum->offset + 4,
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
	/* The priv checksum covers the server checksum */
	ret = verify_checksum(context,
			      pac->privsvr_checksum,
			      &pac->data,
			      (char *)pac->data.data
			      + pac->server_checksum->offset + 4,
			      pac->server_checksum->buffersize - 4,
			      privsvr);
	if (ret)
	    return ret;

	if (pac->ticket_sign_data.length != 0) {
	    if (pac->ticket_checksum == NULL) {
		krb5_set_error_message(context, EINVAL,
				       "PAC missing ticket checksum");
		return EINVAL;
	    }

	    ret = verify_checksum(context, pac->ticket_checksum, &pac->data,
				 pac->ticket_sign_data.data,
				 pac->ticket_sign_data.length, privsvr);
	    if (ret)
		return ret;
	}
    }

    return 0;
}

/*
 *
 */

static krb5_error_code
fill_zeros(krb5_context context, krb5_storage *sp, size_t len)
{
    ssize_t sret;
    size_t l;

    while (len) {
	l = len;
	if (l > sizeof(zeros))
	    l = sizeof(zeros);
	sret = krb5_storage_write(sp, zeros, l);
	if (sret <= 0)
	    return krb5_enomem(context);

	len -= sret;
    }
    return 0;
}

static krb5_error_code
pac_checksum(krb5_context context,
	     const krb5_keyblock *key,
	     uint32_t *cksumtype,
	     size_t *cksumsize)
{
    krb5_cksumtype cktype;
    krb5_error_code ret;
    krb5_crypto crypto = NULL;

    ret = krb5_crypto_init(context, key, 0, &crypto);
    if (ret)
	return ret;

    ret = krb5_crypto_get_checksum_type(context, crypto, &cktype);
    krb5_crypto_destroy(context, crypto);
    if (ret)
	return ret;

    if (krb5_checksum_is_keyed(context, cktype) == FALSE) {
	*cksumtype = CKSUMTYPE_HMAC_MD5;
	*cksumsize = 16;
    }

    ret = krb5_checksumsize(context, cktype, cksumsize);
    if (ret)
	return ret;

    *cksumtype = (uint32_t)cktype;

    return 0;
}

krb5_error_code
_krb5_pac_sign(krb5_context context,
	       krb5_pac p,
	       time_t authtime,
	       krb5_principal principal,
	       const krb5_keyblock *server_key,
	       const krb5_keyblock *priv_key,
	       uint16_t rodc_id,
	       krb5_data *data)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL, *spdata = NULL;
    uint32_t end;
    size_t server_size, priv_size;
    uint32_t server_offset = 0, priv_offset = 0, ticket_offset = 0;
    uint32_t server_cksumtype = 0, priv_cksumtype = 0;
    uint32_t num = 0;
    uint32_t i, sz;
    krb5_data logon, d;

    krb5_data_zero(&d);
    krb5_data_zero(&logon);

    /*
     * Set convenience buffer pointers.
     *
     * This could really stand to be moved to krb5_pac_add_buffer() and/or
     * utility function, so that when this function gets called they must
     * already have been set.
     */
    for (i = 0; i < p->pac->numbuffers; i++) {
	if (p->pac->buffers[i].type == PAC_SERVER_CHECKSUM) {
	    if (p->server_checksum == NULL) {
		p->server_checksum = &p->pac->buffers[i];
	    }
	    if (p->server_checksum != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple server checksums", ""));
		goto out;
	    }
	} else if (p->pac->buffers[i].type == PAC_PRIVSVR_CHECKSUM) {
	    if (p->privsvr_checksum == NULL) {
		p->privsvr_checksum = &p->pac->buffers[i];
	    }
	    if (p->privsvr_checksum != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple KDC checksums", ""));
		goto out;
	    }
	} else if (p->pac->buffers[i].type == PAC_LOGON_NAME) {
	    if (p->logon_name == NULL) {
		p->logon_name = &p->pac->buffers[i];
	    }
	    if (p->logon_name != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple logon names", ""));
		goto out;
	    }
	} else if (p->pac->buffers[i].type == PAC_TICKET_CHECKSUM) {
	    if (p->ticket_checksum == NULL) {
		p->ticket_checksum = &p->pac->buffers[i];
	    }
	    if (p->ticket_checksum != &p->pac->buffers[i]) {
		ret = KRB5KDC_ERR_BADOPTION;
		krb5_set_error_message(context, ret,
				       N_("PAC has multiple ticket checksums", ""));
		goto out;
	    }
	}
    }

    /* Count missing-but-necessary buffers */
    if (p->logon_name == NULL)
	num++;
    if (p->server_checksum == NULL)
	num++;
    if (p->privsvr_checksum == NULL)
	num++;
    if (p->ticket_sign_data.length != 0 && p->ticket_checksum == NULL)
	num++;

    /* Allocate any missing-but-necessary buffers */
    if (num) {
	void *ptr;
	uint32_t old_len, len;

	if (p->pac->numbuffers > UINT32_MAX - num) {
	    ret = EINVAL;
	    krb5_set_error_message(context, ret, "integer overrun");
	    goto out;
	}
	ret = pac_header_size(context, p->pac->numbuffers, &old_len);
        if (ret == 0)
            ret = pac_header_size(context, p->pac->numbuffers + num, &len);
	if (ret)
	    goto out;

	ptr = realloc(p->pac, len);
	if (ptr == NULL) {
	    ret = krb5_enomem(context);
            goto out;
        }
        memset((char *)ptr + old_len, 0, len - old_len);
	p->pac = ptr;


	if (p->logon_name == NULL) {
	    p->logon_name = &p->pac->buffers[p->pac->numbuffers++];
	    p->logon_name->type = PAC_LOGON_NAME;
	}
	if (p->server_checksum == NULL) {
	    p->server_checksum = &p->pac->buffers[p->pac->numbuffers++];
	    p->server_checksum->type = PAC_SERVER_CHECKSUM;
	}
	if (p->privsvr_checksum == NULL) {
	    p->privsvr_checksum = &p->pac->buffers[p->pac->numbuffers++];
	    p->privsvr_checksum->type = PAC_PRIVSVR_CHECKSUM;
	}
	if (p->ticket_sign_data.length != 0 && p->ticket_checksum == NULL) {
	    p->ticket_checksum = &p->pac->buffers[p->pac->numbuffers++];
	    p->ticket_checksum->type = PAC_TICKET_CHECKSUM;
	}
    }

    /* Calculate LOGON NAME */
    ret = build_logon_name(context, authtime, principal, &logon);

    /* Set lengths for checksum */
    if (ret == 0)
        ret = pac_checksum(context, server_key, &server_cksumtype, &server_size);

    if (ret == 0)
        ret = pac_checksum(context, priv_key, &priv_cksumtype, &priv_size);

    /* Encode PAC */
    if (ret == 0) {
        sp = krb5_storage_emem();
        if (sp == NULL)
            ret = krb5_enomem(context);
    }

    if (ret == 0) {
        krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);
        spdata = krb5_storage_emem();
        if (spdata == NULL) {
            krb5_storage_free(sp);
            ret = krb5_enomem(context);
        }
    }

    if (ret)
        goto out;

    krb5_storage_set_flags(spdata, KRB5_STORAGE_BYTEORDER_LE);

    /* `sp' has the header, `spdata' has the buffers */
    CHECK(ret, krb5_store_uint32(sp, p->pac->numbuffers), out);
    CHECK(ret, krb5_store_uint32(sp, p->pac->version), out);

    ret = pac_header_size(context, p->pac->numbuffers, &end);
    if (ret)
        goto out;

    /*
     * For each buffer we write its contents to `spdata' and then append the
     * PAC_INFO_BUFFER for that buffer into the header in `sp'.  The logical
     * end of the whole thing is kept in `end', which functions as the offset
     * to write in the buffer's PAC_INFO_BUFFER, then we update it at the
     * bottom so that the next buffer can be written there.
     *
     * TODO?  Maybe rewrite all of this so that:
     *
     *  - we use krb5_pac_add_buffer() to add the buffers we produce
     *  - we use the krb5_data of the concatenated buffers that's maintained by
     *    krb5_pac_add_buffer() so we don't need `spdata' here
     *
     * We do way too much here, and that makes this code hard to read.  Plus we
     * throw away all the work done in krb5_pac_add_buffer().  On the other
     * hand, krb5_pac_add_buffer() has to loop over all the buffers, so if we
     * call krb5_pac_add_buffer() here in a loop, we'll be accidentally
     * quadratic, but we only need to loop over adding the buffers we add,
     * which is very few, so not quite quadratic.  We should also cap the
     * number of buffers we're willing to accept in a PAC we parse to something
     * reasonable, like a few tens.
     */
    for (i = 0; i < p->pac->numbuffers; i++) {
	uint32_t len;
	size_t sret;
	void *ptr = NULL;

	/* store data */

	if (p->pac->buffers[i].type == PAC_SERVER_CHECKSUM) {
	    if (server_size > UINT32_MAX - 4) {
		ret = EINVAL;
		krb5_set_error_message(context, ret, "integer overrun");
		goto out;
	    }
	    len = server_size + 4;
	    if (end > UINT32_MAX - 4) {
		ret = EINVAL;
		krb5_set_error_message(context, ret, "integer overrun");
		goto out;
	    }
	    server_offset = end + 4;
	    CHECK(ret, krb5_store_uint32(spdata, server_cksumtype), out);
	    CHECK(ret, fill_zeros(context, spdata, server_size), out);
	} else if (p->pac->buffers[i].type == PAC_PRIVSVR_CHECKSUM) {
	    if (priv_size > UINT32_MAX - 4) {
		ret = EINVAL;
		krb5_set_error_message(context, ret, "integer overrun");
		goto out;
	    }
	    len = priv_size + 4;
	    if (end > UINT32_MAX - 4) {
		ret = EINVAL;
		krb5_set_error_message(context, ret, "integer overrun");
		goto out;
	    }
	    priv_offset = end + 4;
	    CHECK(ret, krb5_store_uint32(spdata, priv_cksumtype), out);
	    CHECK(ret, fill_zeros(context, spdata, priv_size), out);
	    if (rodc_id != 0) {
		if (len > UINT32_MAX - sizeof(rodc_id)) {
		    ret = EINVAL;
		    krb5_set_error_message(context, ret, "integer overrun");
		    goto out;
		}
		len += sizeof(rodc_id);
		CHECK(ret, fill_zeros(context, spdata, sizeof(rodc_id)), out);
	    }
	} else if (p->ticket_sign_data.length != 0 &&
		   p->pac->buffers[i].type == PAC_TICKET_CHECKSUM) {
	    if (priv_size > UINT32_MAX - 4) {
		ret = EINVAL;
		krb5_set_error_message(context, ret, "integer overrun");
		goto out;
	    }
	    len = priv_size + 4;
	    if (end > UINT32_MAX - 4) {
		ret = EINVAL;
		krb5_set_error_message(context, ret, "integer overrun");
		goto out;
	    }
	    ticket_offset = end + 4;
	    CHECK(ret, krb5_store_uint32(spdata, priv_cksumtype), out);
	    CHECK(ret, fill_zeros(context, spdata, priv_size), out);
	    if (rodc_id != 0) {
		if (len > UINT32_MAX - sizeof(rodc_id)) {
		    ret = EINVAL;
		    krb5_set_error_message(context, ret, "integer overrun");
		    goto out;
		}
		len += sizeof(rodc_id);
		CHECK(ret, krb5_store_uint16(spdata, rodc_id), out);
	    }
	} else if (p->pac->buffers[i].type == PAC_LOGON_NAME) {
	    len = krb5_storage_write(spdata, logon.data, logon.length);
	    if (logon.length != len) {
		ret = KRB5KDC_ERR_BADOPTION;
		goto out;
	    }
	} else {
	    len = p->pac->buffers[i].buffersize;
	    ptr = (char *)p->data.data + p->pac->buffers[i].offset;

	    sret = krb5_storage_write(spdata, ptr, len);
	    if (sret != len) {
		ret = krb5_enomem(context);
		goto out;
	    }

	    if (p->pac->buffers[i].type == PAC_LOGON_INFO
		|| p->pac->buffers[i].type == PAC_UPN_DNS_INFO)
	    {
		uint32_t rounded = (len + PAC_ALIGNMENT - 1) / PAC_ALIGNMENT
		    * PAC_ALIGNMENT;
		uint32_t remaining = rounded - len;
		CHECK(ret, fill_zeros(context, spdata, remaining), out);

		len = rounded;
	    }
	}

	/* write header */
	CHECK(ret, krb5_store_uint32(sp, p->pac->buffers[i].type), out);
	CHECK(ret, krb5_store_uint32(sp, len), out);
	CHECK(ret, krb5_store_uint64(sp, end), out); /* offset */

	/* advance data endpointer and align */
	{
	    uint32_t e;

	    ret = pac_aligned_size(context, end, len, &e);
            if (ret == 0 && end + len != e)
                ret = fill_zeros(context, spdata, e - (end + len));
	    if (ret)
		goto out;
	    end = e;
	}

    }

    /* assert (server_offset != 0 && priv_offset != 0); */

    /* export PAC */
    if (ret == 0)
        ret = krb5_storage_to_data(spdata, &d);
    if (ret == 0) {
        sz = krb5_storage_write(sp, d.data, d.length);
        if (sz != d.length) {
            krb5_data_free(&d);
            ret = krb5_enomem(context);
            goto out;
        }
    }
    krb5_data_free(&d);

    if (ret == 0)
        ret = krb5_storage_to_data(sp, &d);

    /* sign */
    if (ret == 0 && p->ticket_sign_data.length)
	ret = create_checksum(context, priv_key, priv_cksumtype,
			      p->ticket_sign_data.data,
			      p->ticket_sign_data.length,
			      (char *)d.data + ticket_offset, priv_size);
    if (ret == 0)
        ret = create_checksum(context, server_key, server_cksumtype,
                              d.data, d.length,
                              (char *)d.data + server_offset, server_size);
    if (ret == 0)
        ret = create_checksum(context, priv_key, priv_cksumtype,
                              (char *)d.data + server_offset, server_size,
                              (char *)d.data + priv_offset, priv_size);
    if (ret == 0 && rodc_id != 0) {
	krb5_data rd;
	krb5_storage *rs = krb5_storage_emem();
	if (rs == NULL)
	    ret = krb5_enomem(context);
	krb5_storage_set_flags(rs, KRB5_STORAGE_BYTEORDER_LE);
        if (ret == 0)
            ret = krb5_store_uint16(rs, rodc_id);
        if (ret == 0)
            ret = krb5_storage_to_data(rs, &rd);
	krb5_storage_free(rs);
	if (ret)
	    goto out;
	heim_assert(rd.length == sizeof(rodc_id), "invalid length");
	memcpy((char *)d.data + priv_offset + priv_size, rd.data, rd.length);
	krb5_data_free(&rd);
    }

    if (ret)
        goto out;

    /* done */
    *data = d;

    krb5_data_free(&logon);
    krb5_storage_free(sp);
    krb5_storage_free(spdata);

    return 0;
out:
    krb5_data_free(&d);
    krb5_data_free(&logon);
    if (sp)
	krb5_storage_free(sp);
    if (spdata)
	krb5_storage_free(spdata);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_get_kdc_checksum_info(krb5_context context,
			       krb5_pac pac,
			       krb5_cksumtype *cstype,
			       uint16_t *rodc_id)
{
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    const struct PAC_INFO_BUFFER *sig;
    size_t cksumsize, prefix;
    uint32_t type = 0;

    *cstype = 0;
    *rodc_id = 0;

    sig = pac->privsvr_checksum;
    if (sig == NULL) {
	krb5_set_error_message(context, KRB5KDC_ERR_BADOPTION,
			       "PAC missing kdc checksum");
	return KRB5KDC_ERR_BADOPTION;
    }

    sp = krb5_storage_from_mem((char *)pac->data.data + sig->offset,
			       sig->buffersize);
    if (sp == NULL)
	return krb5_enomem(context);

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    ret = krb5_ret_uint32(sp, &type);
    if (ret)
	goto out;

    ret = krb5_checksumsize(context, type, &cksumsize);
    if (ret)
	goto out;

    prefix = krb5_storage_seek(sp, 0, SEEK_CUR);

    if ((sig->buffersize - prefix) >= cksumsize + 2) {
	krb5_storage_seek(sp, cksumsize, SEEK_CUR);
	ret = krb5_ret_uint16(sp, rodc_id);
	if (ret)
	    goto out;
    }

    *cstype = type;

out:
    krb5_storage_free(sp);

    return ret;
}

static unsigned char single_zero = '\0';
static krb5_data single_zero_pac = { 1, &single_zero };

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kdc_pac_ticket_parse(krb5_context context,
			   EncTicketPart *tkt,
			   krb5_boolean *signedticket,
			   krb5_pac *ppac)
{
    AuthorizationData *ad = tkt->authorization_data;
    krb5_pac pac = NULL;
    unsigned i, j;
    size_t len = 0;
    krb5_error_code ret = 0;

    *signedticket = FALSE;
    *ppac = NULL;

    if (ad == NULL || ad->len == 0)
	return 0;

    for (i = 0; i < ad->len; i++) {
	AuthorizationData child;

	if (ad->val[i].ad_type == KRB5_AUTHDATA_WIN2K_PAC) {
	    ret = KRB5KDC_ERR_BADOPTION;
	    goto out;
	}

	if (ad->val[i].ad_type != KRB5_AUTHDATA_IF_RELEVANT)
	    continue;

	ret = decode_AuthorizationData(ad->val[i].ad_data.data,
				       ad->val[i].ad_data.length,
				       &child,
				       NULL);
	if (ret) {
	    krb5_set_error_message(context, ret, "Failed to decode "
				   "AD-IF-RELEVANT with %d", ret);
	    goto out;
	}

	for (j = 0; j < child.len; j++) {
	    krb5_data adifr_data = ad->val[i].ad_data;
	    krb5_data pac_data = child.val[j].ad_data;
	    krb5_data recoded_adifr;

	    if (child.val[j].ad_type != KRB5_AUTHDATA_WIN2K_PAC)
		continue;

	    if (pac != NULL) {
		free_AuthorizationData(&child);
		ret = KRB5KDC_ERR_BADOPTION;
		goto out;
	    }

	    ret = krb5_pac_parse(context,
				 pac_data.data,
				 pac_data.length,
				 &pac);
	    if (ret) {
		free_AuthorizationData(&child);
		goto out;
	    }

	    if (pac->ticket_checksum == NULL)
		continue;

	    /*
	     * Encode the ticket with the PAC replaced with a single zero
	     * byte, to be used as input data to the ticket signature.
	     */

	    child.val[j].ad_data = single_zero_pac;

	    ASN1_MALLOC_ENCODE(AuthorizationData, recoded_adifr.data,
			       recoded_adifr.length, &child, &len, ret);
	    if (recoded_adifr.length != len)
		krb5_abortx(context, "Internal error in ASN.1 encoder");

	    child.val[j].ad_data = pac_data;

	    if (ret) {
		free_AuthorizationData(&child);
		goto out;
	    }

	    ad->val[i].ad_data = recoded_adifr;

	    ASN1_MALLOC_ENCODE(EncTicketPart,
			       pac->ticket_sign_data.data,
			       pac->ticket_sign_data.length, tkt, &len,
			       ret);
	    if (pac->ticket_sign_data.length != len)
		krb5_abortx(context, "Internal error in ASN.1 encoder");

	    ad->val[i].ad_data = adifr_data;
	    krb5_data_free(&recoded_adifr);

	    if (ret) {
		free_AuthorizationData(&child);
		goto out;
	    }

	    *signedticket = TRUE;
	}
	free_AuthorizationData(&child);
    }

out:
    if (ret) {
	krb5_pac_free(context, pac);
	return ret;
    }

    *ppac = pac;

    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kdc_pac_sign_ticket(krb5_context context,
			  const krb5_pac pac,
			  krb5_principal client,
			  const krb5_keyblock *server_key,
			  const krb5_keyblock *kdc_key,
			  uint16_t rodc_id,
			  krb5_boolean add_ticket_sig,
			  EncTicketPart *tkt)
{
    krb5_error_code ret;
    krb5_data tkt_data;
    krb5_data rspac;

    krb5_data_zero(&rspac);
    krb5_data_zero(&tkt_data);

    krb5_data_free(&pac->ticket_sign_data);

    if (add_ticket_sig) {
	size_t len = 0;

	ret = _kdc_tkt_insert_pac(context, tkt, &single_zero_pac);
	if (ret)
	    return ret;

	ASN1_MALLOC_ENCODE(EncTicketPart, tkt_data.data, tkt_data.length,
			   tkt, &len, ret);
	if(tkt_data.length != len)
	    krb5_abortx(context, "Internal error in ASN.1 encoder");
	if (ret)
	    return ret;

	ret = remove_AuthorizationData(tkt->authorization_data, 0);
	if (ret) {
	    krb5_data_free(&tkt_data);
	    return ret;
	}

	pac->ticket_sign_data = tkt_data;
    }

    ret = _krb5_pac_sign(context, pac, tkt->authtime, client, server_key,
			 kdc_key, rodc_id, &rspac);
    if (ret == 0)
        ret = _kdc_tkt_insert_pac(context, tkt, &rspac);
    krb5_data_free(&rspac);
    return ret;
}
