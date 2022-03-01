/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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

/*
 *
 */

#include "krb5_locl.h"

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_principal2principalname(PrincipalName *p,
			      krb5_const_principal from)
{
    return copy_PrincipalName(&from->name, p);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_principalname2krb5_principal (krb5_context context,
				    krb5_principal *principal,
				    const PrincipalName from,
				    const Realm realm)
{
    krb5_error_code ret;
    krb5_principal p;

    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return krb5_enomem(context);
    ret = copy_PrincipalName(&from, &p->name);
    if (ret) {
	free(p);
	return ret;
    }
    p->realm = strdup(realm);
    if (p->realm == NULL) {
	free_PrincipalName(&p->name);
        free(p);
	return krb5_enomem(context);
    }
    *principal = p;
    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_ticket2krb5_principal(krb5_context context,
                            krb5_principal *principal,
                            const EncTicketPart *ticket,
                            const AuthorizationData *authenticator_ad)
{
    krb5_error_code ret;
    krb5_principal p = NULL;

    *principal = NULL;

    ret = _krb5_principalname2krb5_principal(context,
                                             &p,
                                             ticket->cname,
                                             ticket->crealm);
    if (ret == 0 &&
        (p->nameattrs = calloc(1, sizeof(p->nameattrs[0]))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0)
        p->nameattrs->authenticated = 1;
    if (ret == 0 &&
        (p->nameattrs->source =
         calloc(1, sizeof(p->nameattrs->source[0]))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0) {
        p->nameattrs->source->element =
            choice_PrincipalNameAttrSrc_enc_ticket_part;
        ret = copy_EncTicketPart(ticket,
                                 &p->nameattrs->source->u.enc_ticket_part);
        /* NOTE: we don't want to keep a copy of the session key here! */
        if (ret == 0)
            der_free_octet_string(&p->nameattrs->source->u.enc_ticket_part.key.keyvalue);
    }
    if (ret == 0 && authenticator_ad) {
        p->nameattrs->authenticator_ad =
            calloc(1, sizeof(p->nameattrs->authenticator_ad[0]));
        if (p->nameattrs->authenticator_ad == NULL)
            ret = krb5_enomem(context);
        if (ret == 0)
            ret = copy_AuthorizationData(authenticator_ad,
                                         p->nameattrs->authenticator_ad);
    }

    if (ret == 0)
        *principal = p;
    else
        krb5_free_principal(context, p);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kdcrep2krb5_principal(krb5_context context,
                            krb5_principal *principal,
                            const EncKDCRepPart *kdcrep)
{
    krb5_error_code ret;
    krb5_principal p = NULL;

    *principal = NULL;

    ret = _krb5_principalname2krb5_principal(context,
                                             &p,
                                             kdcrep->sname,
                                             kdcrep->srealm);
    if (ret == 0 &&
        (p->nameattrs = calloc(1, sizeof(p->nameattrs[0]))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0)
        p->nameattrs->authenticated = 1;
    if (ret == 0 &&
        (p->nameattrs->source =
         calloc(1, sizeof(p->nameattrs->source[0]))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0) {
        p->nameattrs->source->element =
            choice_PrincipalNameAttrSrc_enc_kdc_rep_part;
        ret = copy_EncKDCRepPart(kdcrep,
                                 &p->nameattrs->source->u.enc_kdc_rep_part);
        /* NOTE: we don't want to keep a copy of the session key here! */
        if (ret == 0)
            der_free_octet_string(&p->nameattrs->source->u.enc_kdc_rep_part.key.keyvalue);
    }

    if (ret == 0)
        *principal = p;
    else
        krb5_free_principal(context, p);
    return ret;
}
