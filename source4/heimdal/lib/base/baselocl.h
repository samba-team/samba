/*
 * Copyright (c) 2010 - 2011 Kungliga Tekniska Högskolan
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

#include "config.h"

#include <roken.h>

#define ISTILDE(x) (x == '~')
#ifdef _WIN32
# define ISPATHSEP(x) (x == '/' || x =='\\')
#else
# define ISPATHSEP(x) (x == '/')
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#define HEIMDAL_TEXTDOMAIN "heimdal_krb5"

#ifdef LIBINTL
#include <libintl.h>
#define N_(x,y) dgettext(HEIMDAL_TEXTDOMAIN, x)
#else
#define N_(x,y) (x)
#define bindtextdomain(package, localedir)
#endif

#include "heimqueue.h"
#include "heim_threads.h"
#include "heimbase.h"
#include "heimbasepriv.h"

#ifdef HAVE_DISPATCH_DISPATCH_H
#include <dispatch/dispatch.h>
#endif

/* tagged strings/object/XXX */
#define heim_base_is_tagged(x) (((uintptr_t)(x)) & 0x3)

#define heim_base_is_tagged_object(x) ((((uintptr_t)(x)) & 0x3) == 1)
#define heim_base_make_tagged_object(x, tid) \
    ((heim_object_t)((((uintptr_t)(x)) << 5) | ((tid) << 2) | 0x1))
#define heim_base_tagged_object_tid(x) ((((uintptr_t)(x)) & 0x1f) >> 2)
#define heim_base_tagged_object_value(x) (((uintptr_t)(x)) >> 5)

/*
 *
 */

#undef HEIMDAL_NORETURN_ATTRIBUTE
#define HEIMDAL_NORETURN_ATTRIBUTE
#undef HEIMDAL_PRINTF_ATTRIBUTE
#define HEIMDAL_PRINTF_ATTRIBUTE(x)

struct heim_context_s {
    heim_log_facility       *log_dest;
    heim_log_facility       *warn_dest;
    heim_log_facility       *debug_dest;
    char                    *time_fmt;
    unsigned int            log_utc:1;
    unsigned int            homedir_access:1;
    struct et_list          *et_list;
    char                    *error_string;
    heim_error_code         error_code;
};
