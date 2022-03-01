/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

#define CHECKED_ALLOC(dst) do {                                 \
            if ((ALLOC(dst, 1)) == NULL) {                      \
                ret = krb5_enomem(context);                     \
                goto out;                                       \
            }                                                   \
        } while (0)

#define CHECKED_COPY(cp_func, dst, src) do {                    \
            if (cp_func(src, dst)) {                            \
                ret = krb5_enomem(context);                     \
                goto out;                                       \
            }                                                   \
        } while (0)
#define CHECKED_COPY_PPC2KCI(cp_func, dst, src)                 \
        CHECKED_COPY(cp_func, krb_cred_info->dst, &ppcreds[i]->src)

#define CHECKED_ALLOC_ASSIGN(dst, src) do {                     \
            if ((ALLOC(dst, 1)) == NULL) {                      \
                ret = krb5_enomem(context);                     \
                goto out;                                       \
            } else                                              \
                *dst = src;                                     \
        } while (0)
#define CHECKED_ALLOC_ASSIGN_PPC2KCI(dst, src)                  \
        CHECKED_ALLOC_ASSIGN(krb_cred_info->dst, ppcreds[i]->src)

#define CHECKED_ALLOC_COPY(cp_func, dst, src) do {              \
            if ((ALLOC(dst, 1)) == NULL || cp_func(src, dst)) { \
                ret = krb5_enomem(context);                     \
                goto out;                                       \
            }                                                   \
        } while (0)
#define CHECKED_ALLOC_COPY_PPC2KCI(cp_func, dst, src)           \
        CHECKED_ALLOC_COPY(cp_func, krb_cred_info->dst, &ppcreds[i]->src)

/**
 * Make a KRB-CRED PDU with N credentials.
 *
 * @param context A kerberos 5 context.
 * @param auth_context The auth context with the key to encrypt the out_data.
 * @param ppcreds A null-terminated array of credentials to forward.
 * @param ppdata The output KRB-CRED (to be freed by caller).
 * @param replay_data (unused).
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

/* ARGSUSED */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_ncred(krb5_context context, krb5_auth_context auth_context,
              krb5_creds **ppcreds, krb5_data **ppdata,
              krb5_replay_data *replay_data)
{
    krb5_error_code ret;
    krb5_data out_data;

    ret = _krb5_mk_ncred(context, auth_context, ppcreds, &out_data,
        replay_data);
    if (ret == 0) {
        /*
         * MIT allocates the return structure for no good reason. We do
         * likewise as, in this case, incompatibility is the greater evil.
         */
        *ppdata = calloc(1, sizeof(**ppdata));
        if (*ppdata) {
            **ppdata = out_data;
        } else {
            krb5_data_free(&out_data);
            ret = krb5_enomem(context);
        }
    }

    return ret;
}

/* ARGSUSED */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_mk_ncred(krb5_context context,
               krb5_auth_context auth_context,
               krb5_creds **ppcreds,
               krb5_data *out_data,
               krb5_replay_data *replay_data)
{
    krb5_error_code ret;
    EncKrbCredPart enc_krb_cred_part;
    KrbCredInfo *krb_cred_info;
    krb5_crypto crypto;
    KRB_CRED cred;
    unsigned char *buf = NULL;
    size_t ncreds, i;
    size_t buf_size;
    size_t len;

    /*
     * The ownership of 'buf' is re-assigned to a containing structure
     * multiple times. We enforce an invariant, either buf is non-zero
     * and we own it, or buf is zero and it is freed or some structure
     * owns any storage previously allocated as 'buf'.
     */
#define CHOWN_BUF(x, buf) do { (x) = (buf); (buf) = 0; } while (0)
#define DISOWN_BUF(buf) do { free(buf); (buf) = 0; } while (0)

    for (ncreds = 0; ppcreds[ncreds]; ncreds++)
        ;

    memset (&cred, 0, sizeof(cred));
    memset (&enc_krb_cred_part, 0, sizeof(enc_krb_cred_part));
    cred.pvno = 5;
    cred.msg_type = krb_cred;
    ALLOC_SEQ(&cred.tickets, ncreds);
    if (cred.tickets.val == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }
    ALLOC_SEQ(&enc_krb_cred_part.ticket_info, ncreds);
    if (enc_krb_cred_part.ticket_info.val == NULL) {
        ret = krb5_enomem(context);
        goto out;
    }

    for (i = 0; i < ncreds; i++) {
        ret = decode_Ticket(ppcreds[i]->ticket.data,
                            ppcreds[i]->ticket.length,
                            &cred.tickets.val[i],
                            &len);/* don't care about len */
        if (ret)
           goto out;

        /* fill ticket_info.val[i] */
        krb_cred_info = &enc_krb_cred_part.ticket_info.val[i];

        CHECKED_COPY(copy_EncryptionKey,
                     &krb_cred_info->key, &ppcreds[i]->session);
        CHECKED_ALLOC_COPY_PPC2KCI(copy_Realm, prealm, client->realm);
        CHECKED_ALLOC_COPY_PPC2KCI(copy_PrincipalName, pname, client->name);
        CHECKED_ALLOC_ASSIGN_PPC2KCI(flags, flags.b);
        CHECKED_ALLOC_ASSIGN_PPC2KCI(authtime, times.authtime);
        CHECKED_ALLOC_ASSIGN_PPC2KCI(starttime, times.starttime);
        CHECKED_ALLOC_ASSIGN_PPC2KCI(endtime, times.endtime);
        CHECKED_ALLOC_ASSIGN_PPC2KCI(renew_till, times.renew_till);
        CHECKED_ALLOC_COPY_PPC2KCI(copy_Realm, srealm, server->realm);
        CHECKED_ALLOC_COPY_PPC2KCI(copy_PrincipalName, sname, server->name);
        CHECKED_ALLOC_COPY_PPC2KCI(copy_HostAddresses, caddr, addresses);
    }

    if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME) {
        krb5_timestamp sec;
        int32_t usec;

        krb5_us_timeofday (context, &sec, &usec);

        CHECKED_ALLOC_ASSIGN(enc_krb_cred_part.timestamp, sec);
        CHECKED_ALLOC_ASSIGN(enc_krb_cred_part.usec, usec);
    } else {
        enc_krb_cred_part.timestamp = NULL;
        enc_krb_cred_part.usec = NULL;
        /* XXX Er, shouldn't we set the seq nums?? */
    }

    /* XXX: Is this needed? */
    if (auth_context->local_address && auth_context->local_port) {
        ret = krb5_make_addrport(context,
                                 &enc_krb_cred_part.s_address,
                                 auth_context->local_address,
                                 auth_context->local_port);
        if (ret)
            goto out;
    }

    /* XXX: Is this needed? */
    if (auth_context->remote_address) {
        if (auth_context->remote_port) {
            /*
             * XXX: Should we be checking "no-addresses" for
             * the receiving realm?
             */
            ret = krb5_make_addrport(context,
                                     &enc_krb_cred_part.r_address,
                                     auth_context->remote_address,
                                     auth_context->remote_port);
            if (ret)
                goto out;
        } else {
            /*
             * XXX Ugly, make krb5_make_addrport() handle missing port
             * number (i.e., port == 0), then remove this else.
             */
            CHECKED_ALLOC(enc_krb_cred_part.r_address);
            ret = krb5_copy_address(context, auth_context->remote_address,
                                    enc_krb_cred_part.r_address);
            if (ret)
                goto out;
        }
    }

    /* encode EncKrbCredPart */
    ASN1_MALLOC_ENCODE(EncKrbCredPart, buf, buf_size,
                       &enc_krb_cred_part, &len, ret);
    if (ret)
        goto out;

    /**
     * Some older of the MIT gssapi library used clear-text tickets
     * (warped inside AP-REQ encryption), use the krb5_auth_context
     * flag KRB5_AUTH_CONTEXT_CLEAR_FORWARDED_CRED to support those
     * tickets. The session key is used otherwise to encrypt the
     * forwarded ticket.
     */

    if (auth_context->flags & KRB5_AUTH_CONTEXT_CLEAR_FORWARDED_CRED) {
        cred.enc_part.etype = KRB5_ENCTYPE_NULL;
        cred.enc_part.kvno = NULL;
        CHOWN_BUF(cred.enc_part.cipher.data, buf);
        cred.enc_part.cipher.length = buf_size;
    } else {
        /*
         * Here older versions then 0.7.2 of Heimdal used the local or
         * remote subkey. That is wrong, the session key should be
         * used. Heimdal 0.7.2 and newer have code to try both in the
         * receiving end.
         */

        ret = krb5_crypto_init(context, auth_context->keyblock, 0, &crypto);
        if (ret == 0)
            ret = krb5_encrypt_EncryptedData(context,
                                             crypto,
                                             KRB5_KU_KRB_CRED,
                                             buf,
                                             len,
                                             0,
                                             &cred.enc_part);
        if (ret)
            goto out;
        DISOWN_BUF(buf);
        krb5_crypto_destroy(context, crypto);
    }

    ASN1_MALLOC_ENCODE(KRB_CRED, buf, buf_size, &cred, &len, ret);
    if (ret)
        goto out;

    CHOWN_BUF(out_data->data, buf);
    out_data->length = len;
    ret = 0;

 out:
    free_EncKrbCredPart(&enc_krb_cred_part);
    free_KRB_CRED(&cred);
    free(buf);
    return ret;
}

/**
 * Make a KRB-CRED PDU with 1 credential.
 *
 * @param context A kerberos 5 context.
 * @param auth_context The auth context with the key to encrypt the out_data.
 * @param ppcred A credential to forward.
 * @param ppdata The output KRB-CRED (to be freed by caller).
 * @param replay_data (unused).
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

/* ARGSUSED */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_1cred(krb5_context context, krb5_auth_context auth_context,
              krb5_creds *ppcred, krb5_data **ppdata,
              krb5_replay_data *replay_data)
{
    krb5_creds *ppcreds[2] = { ppcred, NULL };

    return krb5_mk_ncred(context, auth_context, ppcreds, ppdata, replay_data);
}

/* ARGSUSED */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_mk_1cred(krb5_context context, krb5_auth_context auth_context,
               krb5_creds *ppcred, krb5_data *ppdata,
               krb5_replay_data *replay_data)
{
    krb5_creds *ppcreds[2] = { ppcred, NULL };

    return _krb5_mk_ncred(context, auth_context, ppcreds, ppdata, replay_data);
}
