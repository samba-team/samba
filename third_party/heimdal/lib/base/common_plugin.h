/*
 * Copyright (c) 2006 - 2020 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2018 AuriStor, Inc.
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

#ifndef HEIMDAL_BASE_COMMON_PLUGIN_H
#define HEIMDAL_BASE_COMMON_PLUGIN_H

#include <heimbase-svc.h>

#ifdef _WIN32
# ifndef HEIM_CALLCONV
#  define HEIM_CALLCONV __stdcall
# endif
# ifndef HEIM_LIB_CALL
#  define HEIM_LIB_CALL __stdcall
# endif
#else
# ifndef HEIM_CALLCONV
#  define HEIM_CALLCONV
# endif
# ifndef HEIM_LIB_CALL
#  define HEIM_LIB_CALL
# endif
#endif
#ifndef KRB5_CALLCONV
# define KRB5_CALLCONV HEIM_CALLCONV
#endif
#ifndef KRB5_LIB_CALL
# define KRB5_LIB_CALL HEIM_LIB_CALL
#endif

/* For krb5 plugins, this is a krb5_context */
typedef struct heim_pcontext_s *heim_pcontext;

typedef uintptr_t
(HEIM_LIB_CALL *heim_get_instance_func_t)(const char *);
typedef heim_get_instance_func_t krb5_get_instance_t;

/*
 * All plugin function tables extend the following structure.
 */
struct heim_plugin_common_ftable_desc {
    HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(heim_pcontext);
};
typedef struct heim_plugin_common_ftable_desc heim_plugin_common_ftable;
typedef struct heim_plugin_common_ftable_desc *heim_plugin_common_ftable_p;
typedef struct heim_plugin_common_ftable_desc * const heim_plugin_common_ftable_cp;

typedef int
(HEIM_CALLCONV heim_plugin_load_ft)(heim_pcontext context,
                                    heim_get_instance_func_t *func,
                                    size_t *n_ftables,
                                    heim_plugin_common_ftable_cp **ftables);

typedef heim_plugin_load_ft *heim_plugin_load_t;

/* For source backwards-compatibility */
typedef struct heim_plugin_common_ftable_desc krb5_plugin_common_ftable;
typedef struct heim_plugin_common_ftable_desc *krb5_plugin_common_ftable_p;
typedef struct heim_plugin_common_ftable_desc * const krb5_plugin_common_ftable_cp;
typedef heim_plugin_load_ft krb5_plugin_load_ft;
typedef heim_plugin_load_ft *krb5_plugin_load_t;

/*
 * All plugins must export a function named "<type>_plugin_load" with
 * a signature of:
 *
 * int HEIM_CALLCONV
 * <type>_plugin_load(heim_pcontext context,
 *	              heim_get_instance_func_t *func,
 *		      size_t *n_ftables,
 *		      const heim_plugin_common_ftable *const **ftables);
 */
#endif /* HEIMDAL_BASE_COMMON_PLUGIN_H */
