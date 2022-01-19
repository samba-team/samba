/*
 * Copyright (C) 2011-2019 PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef NEGOEX_LOCL_H
#define NEGOEX_LOCL_H

#include <negoex_err.h>

struct gssspnego_ctx_desc;

#define MESSAGE_SIGNATURE   0x535458454F47454EULL

#define EXTENSION_LENGTH                    12

#define EXTENSION_FLAG_CRITICAL             0x80000000

#define CHECKSUM_SCHEME_RFC3961             1

#define NEGOEX_KEYUSAGE_INITIATOR_CHECKSUM  23
#define NEGOEX_KEYUSAGE_ACCEPTOR_CHECKSUM   25

#define CHECKSUM_HEADER_LENGTH              20

#define GUID_LENGTH                         16

typedef uint8_t auth_scheme[GUID_LENGTH];
typedef uint8_t conversation_id[GUID_LENGTH];
#define GUID_EQ(a, b) (memcmp(a, b, GUID_LENGTH) == 0)

#define NEGO_MESSAGE_HEADER_LENGTH          96
#define EXCHANGE_MESSAGE_HEADER_LENGTH      64
#define VERIFY_MESSAGE_HEADER_LENGTH        80
#define ALERT_MESSAGE_HEADER_LENGTH         72
#define ALERT_LENGTH                        12
#define ALERT_PULSE_LENGTH                  8

#define ALERT_TYPE_PULSE                    1
#define ALERT_VERIFY_NO_KEY                 1

enum message_type {
    INITIATOR_NEGO = 0,         /* NEGO_MESSAGE */
    ACCEPTOR_NEGO,              /* NEGO_MESSAGE */
    INITIATOR_META_DATA,        /* EXCHANGE_MESSAGE */
    ACCEPTOR_META_DATA,         /* EXCHANGE_MESSAGE */
    CHALLENGE,                  /* EXCHANGE_MESSAGE */
    AP_REQUEST,                 /* EXCHANGE_MESSAGE */
    VERIFY,                     /* VERIFY_MESSAGE */
    ALERT,                      /* ALERT */
};

struct nego_message {
    uint8_t random[32];
    const uint8_t *schemes;
    uint16_t nschemes;
};

struct exchange_message {
    auth_scheme scheme;
    gss_buffer_desc token;
};

struct verify_message {
    auth_scheme scheme;
    uint32_t cksum_type;
    const uint8_t *cksum;
    size_t cksum_len;
    size_t offset_in_token;
};

struct alert_message {
    auth_scheme scheme;
    int verify_no_key;
};

struct negoex_message {
    uint32_t type;
    union {
        struct nego_message n;
        struct exchange_message e;
        struct verify_message v;
        struct alert_message a;
    } u;
};

struct negoex_auth_mech {
    HEIM_TAILQ_ENTRY(negoex_auth_mech) links;
    gss_OID oid;
    auth_scheme scheme;
    gss_ctx_id_t mech_context;
    gss_buffer_desc metadata;
    krb5_crypto crypto;
    krb5_crypto verify_crypto;
    int complete;
    int sent_checksum;
    int verified_checksum;
};

#define NEGOEX_LOG_LEVEL		    10

#endif /* NEGOEX_LOCL_H */
