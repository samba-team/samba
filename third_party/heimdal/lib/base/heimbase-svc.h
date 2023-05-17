/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
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

#ifndef HEIMBASE_SVC_H
#define HEIMBASE_SVC_H 1

#include <heimbase.h>

/*
 * This file is meant to be included in services, which can
 *
 *  #define heim_pcontext krb5_context
 *
 * or whatever is appropriate.
 */

#define HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS                   \
    /* Input */                                                 \
    heim_pcontext context;                                      \
    heim_pconfig config;                                        \
    heim_context hcontext;                                      \
    heim_log_facility *logf;                                    \
    const char *from;                                           \
    struct sockaddr *addr;                                      \
    int datagram_reply;                                         \
    heim_octet_string request;                                  \
                                                                \
    /* Output */                                                \
    heim_octet_string *reply;                                   \
    unsigned int use_request_t:1;                               \
                                                                \
    /* Common state, to be freed in process.c */                \
    struct timeval tv_start;                                    \
    struct timeval tv_end;                                      \
    const char *reqtype;                                        \
    char *cname;                                                \
    char *sname;                                                \
    const char *e_text;                                         \
    heim_octet_string *e_data;                                  \
    char *e_text_buf;                                           \
    heim_string_t reason;                                       \
    /* auditing key/value store */                              \
    heim_dict_t kv;                                             \
    heim_dict_t attributes;                                     \
    int32_t error_code

#define HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(CONTEXT_TYPE)        \
    int minor_version;                                          \
    int (HEIM_LIB_CALL *init)(CONTEXT_TYPE, void **);           \
    void (HEIM_LIB_CALL *fini)(void *)

#endif /* HEIMBASE_SVC_H */
