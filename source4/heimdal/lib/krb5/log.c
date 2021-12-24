/*
 * Copyright (c) 1997-2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
#include <assert.h>
#include <vis.h>

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_initlog(krb5_context context,
	     const char *program,
	     krb5_log_facility **fac)
{
    return heim_initlog(context->hcontext, program, fac);
}

struct krb5_addlog_func_wrapper {
    krb5_context context;
    krb5_log_log_func_t log_func;
    krb5_log_close_func_t close_func;
    void *data;
};

static void HEIM_CALLCONV
krb5_addlog_func_wrapper_log(heim_context hcontext,
			     const char *prefix,
			     const char *msg,
			     void *data)
{
    struct krb5_addlog_func_wrapper *w = data;

    w->log_func(w->context,
                prefix,
                msg,
                w->data);
}

static void HEIM_CALLCONV
krb5_addlog_func_wrapper_close(void *data)
{
    struct krb5_addlog_func_wrapper *w = data;

    w->close_func(w->data);
    free(w);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_addlog_func(krb5_context context,
                 krb5_log_facility *fac,
                 int min,
                 int max,
                 krb5_log_log_func_t log_func,
                 krb5_log_close_func_t close_func,
                 void *data)
{
    struct krb5_addlog_func_wrapper *w = NULL;

    w = calloc(1, sizeof(*w));
    if (w == NULL)
	return krb5_enomem(context);

    w->context = context;
    w->log_func = log_func;
    w->close_func = close_func;
    w->data = data;

    return heim_addlog_func(context->hcontext, fac, min, max,
                            krb5_addlog_func_wrapper_log,
                            krb5_addlog_func_wrapper_close,
                            w);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_addlog_dest(krb5_context context, krb5_log_facility *f, const char *orig)
{
    return heim_addlog_dest(context->hcontext, f, orig);
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_openlog(krb5_context context,
	     const char *program,
	     krb5_log_facility **fac)
{
    krb5_error_code ret;
    char **p;

    p = krb5_config_get_strings(context, NULL, "logging", program, NULL);
    if (p == NULL)
	p = krb5_config_get_strings(context, NULL, "logging", "default", NULL);
    ret = heim_openlog(context->hcontext, program, (const char **)p, fac);
    krb5_config_free_strings(p);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_closelog(krb5_context context,
             krb5_log_facility *fac)
{
    heim_closelog(context->hcontext, fac);
    return 0;
}

#undef __attribute__
#define __attribute__(X)

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vlog_msg(krb5_context context,
	      krb5_log_facility *fac,
	      char **reply,
	      int level,
	      const char *fmt,
	      va_list ap)
     __attribute__ ((__format__ (__printf__, 5, 0)))
{
    return heim_vlog_msg(context->hcontext, fac, reply, level, fmt, ap);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vlog(krb5_context context,
	  krb5_log_facility *fac,
	  int level,
	  const char *fmt,
	  va_list ap)
     __attribute__ ((__format__ (__printf__, 4, 0)))
{
    return heim_vlog_msg(context->hcontext, fac, NULL, level, fmt, ap);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_log_msg(krb5_context context,
	     krb5_log_facility *fac,
	     int level,
	     char **reply,
	     const char *fmt,
	     ...)
     __attribute__ ((__format__ (__printf__, 5, 6)))
{
    va_list ap;
    krb5_error_code ret;

    va_start(ap, fmt);
    ret = heim_vlog_msg(context->hcontext, fac, reply, level, fmt, ap);
    va_end(ap);
    return ret;
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_log(krb5_context context,
	 krb5_log_facility *fac,
	 int level,
	 const char *fmt,
	 ...)
     __attribute__ ((__format__ (__printf__, 4, 5)))
{
    va_list ap;
    krb5_error_code ret;

    va_start(ap, fmt);
    ret = heim_vlog(context->hcontext, fac, level, fmt, ap);
    va_end(ap);
    return ret;
}

void KRB5_LIB_FUNCTION
_krb5_debug(krb5_context context,
	    int level,
	    const char *fmt,
	    ...)
    __attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    if (context && context->hcontext)
        heim_vdebug(context->hcontext, level, fmt, ap);
    va_end(ap);
}

void KRB5_LIB_FUNCTION
krb5_debug(krb5_context context,
	    int level,
	    const char *fmt,
	    ...)
    __attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    if (context && context->hcontext)
        heim_vdebug(context->hcontext, level, fmt, ap);
    va_end(ap);
}

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_have_debug(krb5_context context, int level)
{
    if (context == NULL || context->hcontext == NULL)
	return 0;
    return heim_have_debug(context->hcontext, level);
}

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_have_debug(krb5_context context, int level)
{
    return _krb5_have_debug(context, level);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_debug_dest(krb5_context context, const char *program,
                    const char *log_spec)
{
    return heim_add_debug_dest(context->hcontext, program, log_spec);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_log_dest(krb5_context context, krb5_log_facility *fac)
{
    return heim_set_log_dest(context->hcontext, fac);
}
