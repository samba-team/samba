/*
 * Copyright (c) 2022, PADL Software Pty Ltd.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef HEIMDAL_KDC_KDC_ACCESSORS_H
#define HEIMDAL_KDC_KDC_ACCESSORS_H 1

/* read-only accessor */
#ifndef _KDC_REQUEST_GET_ACCESSOR
#define _KDC_REQUEST_GET_ACCESSOR(R, T, f)		    \
    KDC_LIB_FUNCTION T KDC_LIB_CALL			    \
    kdc_request_get_ ## f(R);
#endif

#ifndef _KDC_REQUEST_SET_ACCESSOR
#define _KDC_REQUEST_SET_ACCESSOR(R, T, f)		    \
    KDC_LIB_FUNCTION void KDC_LIB_CALL			    \
    kdc_request_set_ ## f(R, T);
#endif

#ifndef KDC_REQUEST_GET_ACCESSOR
#define KDC_REQUEST_GET_ACCESSOR(T, f)			    \
    _KDC_REQUEST_GET_ACCESSOR(kdc_request_t, T, f)
#endif

#ifndef KDC_REQUEST_SET_ACCESSOR
#define KDC_REQUEST_SET_ACCESSOR(T, f)			    \
    _KDC_REQUEST_SET_ACCESSOR(kdc_request_t, T, f)
#endif

#ifndef ASTGS_REQUEST_GET_ACCESSOR
#define ASTGS_REQUEST_GET_ACCESSOR(T, f)		    \
    _KDC_REQUEST_GET_ACCESSOR(astgs_request_t, T, f)
#endif

#ifndef ASTGS_REQUEST_SET_ACCESSOR
#define ASTGS_REQUEST_SET_ACCESSOR(T, f)		    \
    _KDC_REQUEST_SET_ACCESSOR(astgs_request_t, T, f)
#endif

/* get/set accessor for pointer type */
#ifndef _KDC_REQUEST_GET_ACCESSOR_PTR
#define _KDC_REQUEST_GET_ACCESSOR_PTR(R, T, f)		    \
    KDC_LIB_FUNCTION const T KDC_LIB_CALL		    \
    kdc_request_get_ ## f(R);
#endif

#ifndef _KDC_REQUEST_SET_ACCESSOR_PTR
#define _KDC_REQUEST_SET_ACCESSOR_PTR(R, T, t, f)	    \
    KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL	    \
    kdc_request_set_ ## f(R, const T);
#endif

#ifndef KDC_REQUEST_GET_ACCESSOR_PTR
#define KDC_REQUEST_GET_ACCESSOR_PTR(T, f)		    \
    _KDC_REQUEST_GET_ACCESSOR_PTR(kdc_request_t, T, f)
#endif

#ifndef KDC_REQUEST_SET_ACCESSOR_PTR
#define KDC_REQUEST_SET_ACCESSOR_PTR(T, t, f)		    \
    _KDC_REQUEST_SET_ACCESSOR_PTR(kdc_request_t, T, t, f)
#endif

#ifndef ASTGS_REQUEST_GET_ACCESSOR_PTR
#define ASTGS_REQUEST_GET_ACCESSOR_PTR(T, f)		    \
    _KDC_REQUEST_GET_ACCESSOR_PTR(astgs_request_t, T, f)
#endif

#ifndef ASTGS_REQUEST_SET_ACCESSOR_PTR
#define ASTGS_REQUEST_SET_ACCESSOR_PTR(T, t, f)		    \
    _KDC_REQUEST_SET_ACCESSOR_PTR(astgs_request_t, T, t, f)
#endif

/* get/set accessor for struct type */
#ifndef _KDC_REQUEST_GET_ACCESSOR_STRUCT
#define _KDC_REQUEST_GET_ACCESSOR_STRUCT(R, T, f)	    \
    KDC_LIB_FUNCTION const T * KDC_LIB_CALL		    \
    kdc_request_get_ ## f(R);
#endif

#ifndef _KDC_REQUEST_SET_ACCESSOR_STRUCT
#define _KDC_REQUEST_SET_ACCESSOR_STRUCT(R, T, t, f)	    \
    KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL	    \
    kdc_request_set_ ## f(R, const T *);
#endif

#ifndef KDC_REQUEST_GET_ACCESSOR_STRUCT
#define KDC_REQUEST_GET_ACCESSOR_STRUCT(T, f)		    \
    _KDC_REQUEST_GET_ACCESSOR_STRUCT(kdc_request_t, T, f)
#endif

#ifndef KDC_REQUEST_SET_ACCESSOR_STRUCT
#define KDC_REQUEST_SET_ACCESSOR_STRUCT(T, t, f)	    \
    _KDC_REQUEST_SET_ACCESSOR_STRUCT(kdc_request_t, T, t, f)
#endif

#ifndef ASTGS_REQUEST_GET_ACCESSOR_STRUCT
#define ASTGS_REQUEST_GET_ACCESSOR_STRUCT(T, f)		    \
    _KDC_REQUEST_GET_ACCESSOR_STRUCT(astgs_request_t, T, f)
#endif

#ifndef ASTGS_REQUEST_SET_ACCESSOR_STRUCT
#define ASTGS_REQUEST_SET_ACCESSOR_STRUCT(T, t, f)	    \
    _KDC_REQUEST_SET_ACCESSOR_STRUCT(astgs_request_t, T, t, f)
#endif

/*
 * krb5_context
 * kdc_request_get_context(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR(krb5_context, context)

/*
 * krb5_kdc_configuration *
 * kdc_request_get_config(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR(krb5_kdc_configuration *, config)

/*
 * heim_log_facility *
 * kdc_request_get_logf(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR(heim_log_facility *, logf)

/*
 * const char *
 * kdc_request_get_from(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR_PTR(char *, from)

/*
 * const struct sockaddr *
 * kdc_request_get_addr(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR_PTR(struct sockaddr *, addr)

/*
 * krb5_data
 * kdc_request_get_request(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR(krb5_data, request)

/*
 * struct timeval
 * kdc_request_get_tv_start(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR(struct timeval, tv_start)

/*
 * struct timeval
 * kdc_request_get_tv_end(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR(struct timeval, tv_end)

/*
 * krb5_error_code
 * kdc_request_get_error_code(kdc_request_t);
 */
KDC_REQUEST_GET_ACCESSOR(krb5_error_code, error_code)

/*
 * void
 * kdc_request_set_error_code(kdc_request_t, krb5_error_code);
 */
KDC_REQUEST_SET_ACCESSOR(krb5_error_code, error_code)

/*
 * const KDC_REQ *
 * kdc_request_get_req(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_STRUCT(KDC_REQ, req)

/*
 * const KDC_REP *
 * kdc_request_get_rep(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_STRUCT(KDC_REP, rep)

/*
 * krb5_error_code
 * kdc_request_set_rep(astgs_request_t, const KDC_REP *);
 */

ASTGS_REQUEST_SET_ACCESSOR_STRUCT(KDC_REP, KDC_REP, rep)

/*
 * const char *
 * kdc_request_get_cname(kdc_request_t);
 */

KDC_REQUEST_GET_ACCESSOR_PTR(char *, cname)

/*
 * krb5_error_code
 * kdc_request_set_cname(kdc_request_t, const char *);
 */

KDC_REQUEST_SET_ACCESSOR_PTR(char *, string_ptr, cname)

/*
 * const Principal *
 * kdc_request_get_client_princ(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(Principal *, client_princ)

/*
 * krb5_error_code
 * kdc_request_set_client_princ(astgs_request_t, const Principal *);
 */

ASTGS_REQUEST_SET_ACCESSOR_PTR(Principal *, Principal_ptr, client_princ)

/*
 * const Principal *
 * kdc_request_get_canon_client_princ(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(Principal *, canon_client_princ)

/*
 * krb5_error_code
 * kdc_request_set_canon_client_princ(astgs_request_t, const Principal *);
 */

ASTGS_REQUEST_SET_ACCESSOR_PTR(Principal *, Principal_ptr, canon_client_princ)

/*
 * const HDB *
 * kdc_request_get_clientdb(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(HDB *, clientdb)

/*
 * const hdb_entry *
 * kdc_request_get_client(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(hdb_entry *, client)

/*
 * See client accessors
 */

KDC_REQUEST_GET_ACCESSOR_PTR(char *, sname)
KDC_REQUEST_SET_ACCESSOR_PTR(char *, string_ptr, sname)
ASTGS_REQUEST_GET_ACCESSOR_PTR(Principal *, server_princ)
ASTGS_REQUEST_SET_ACCESSOR_PTR(Principal *, Principal_ptr, server_princ)
ASTGS_REQUEST_GET_ACCESSOR_PTR(HDB *, serverdb)
ASTGS_REQUEST_GET_ACCESSOR_PTR(hdb_entry *, server)

/*
 * See client accessors
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(Principal *, krbtgt_princ)
ASTGS_REQUEST_SET_ACCESSOR_PTR(Principal *, Principal_ptr, krbtgt_princ)
ASTGS_REQUEST_GET_ACCESSOR_PTR(HDB *, krbtgtdb)
ASTGS_REQUEST_GET_ACCESSOR_PTR(hdb_entry *, krbtgt)

/*
 * krb5_ticket *
 * kdc_request_get_ticket(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR(krb5_ticket *, ticket)

/*
 * const krb5_keyblock *
 * kdc_request_get_reply_key(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_STRUCT(krb5_keyblock, reply_key)

/*
 * krb5_error_code
 * kdc_request_set_reply_key(astgs_request_t, const krb5_keyblock *);
 */

ASTGS_REQUEST_SET_ACCESSOR_STRUCT(krb5_keyblock, keyblock, reply_key)

/*
 * krb5_const_pac
 * kdc_request_get_pac(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(struct krb5_pac_data *, pac)

/*
 * krb5_error_code
 * kdc_request_set_pac(astgs_request_t, krb5_const_pac);
 */

ASTGS_REQUEST_SET_ACCESSOR_PTR(struct krb5_pac_data *, pac, pac)

/*
 * uint64_t
 * kdc_request_get_pac_attributes(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR(uint64_t, pac_attributes)

/*
 * unsigned int
 * kdc_request_get_pkinit_freshness_used(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR(unsigned int, pkinit_freshness_used)

/*
 * void
 * kdc_request_set_pac_attributes(astgs_request_t, uint64_t);
 */

ASTGS_REQUEST_SET_ACCESSOR(uint64_t, pac_attributes)

KDC_LIB_FUNCTION const HDB * KDC_LIB_CALL
kdc_request_get_explicit_armor_clientdb(astgs_request_t);

KDC_LIB_FUNCTION const hdb_entry * KDC_LIB_CALL
kdc_request_get_explicit_armor_client(astgs_request_t);

KDC_LIB_FUNCTION const Principal * KDC_LIB_CALL
kdc_request_get_explicit_armor_client_principal(astgs_request_t);

KDC_LIB_FUNCTION const hdb_entry * KDC_LIB_CALL
kdc_request_get_explicit_armor_server(astgs_request_t);

KDC_LIB_FUNCTION krb5_const_pac KDC_LIB_CALL
kdc_request_get_explicit_armor_pac(astgs_request_t);

/*
 * const HDB *
 * kdc_request_get_armor_clientdb(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(HDB *, armor_clientdb)

/*
 * const hdb_entry *
 * kdc_request_get_armor_client(astgs_request_t);
 */
ASTGS_REQUEST_GET_ACCESSOR_PTR(hdb_entry *, armor_client);

/*
 * const Principal *
 * kdc_request_get_armor_client_principal(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(Principal *, armor_client_principal)

/*
 * const hdb_entry *
 * kdc_request_get_armor_server(astgs_request_t);
 */
ASTGS_REQUEST_GET_ACCESSOR_PTR(hdb_entry *, armor_server);

/*
 * krb5_const_pac
 * kdc_request_get_armor_pac(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(struct krb5_pac_data *, armor_pac);

/*
 * krb5_boolean
 * kdc_request_get_explicit_armor_present(astgs_request_t);
 */

ASTGS_REQUEST_GET_ACCESSOR_PTR(krb5_boolean, explicit_armor_present);

#endif /* HEIMDAL_KDC_KDC_ACCESSORS_H */
