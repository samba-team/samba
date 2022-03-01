/*
 * Copyright (c) 2001, 2003, 2005 - 2020 Kungliga Tekniska Högskolan
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

#include "baselocl.h"

#undef __attribute__
#define __attribute__(x)

void
heim_clear_error_message(heim_context context)
{
    if (!context)
        return;
    if (context->error_string)
        free(context->error_string);
    context->error_code = 0;
    context->error_string = NULL;
}

void
heim_set_error_message(heim_context context, heim_error_code ret,
                       const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    if (context)
        heim_vset_error_message(context, ret, fmt, ap);
    va_end(ap);
}

void
heim_vset_error_message(heim_context context, heim_error_code ret,
                        const char *fmt, va_list args)
    __attribute__ ((__format__ (__printf__, 3, 0)))
{
    int r;

    if (context == NULL)
        return;
    if (context->error_string) {
        free(context->error_string);
        context->error_string = NULL;
    }
    context->error_code = ret;
    r = vasprintf(&context->error_string, fmt, args);
    if (r < 0)
        context->error_string = NULL;
    if (context->error_string)
        heim_debug(context, 200, "error message: %s: %d", context->error_string, ret);
}

void
heim_prepend_error_message(heim_context context, heim_error_code ret,
                           const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;

    va_start(ap, fmt);
    heim_vprepend_error_message(context, ret, fmt, ap);
    va_end(ap);
}

void
heim_vprepend_error_message(heim_context context, heim_error_code ret,
                            const char *fmt, va_list args)
    __attribute__ ((__format__ (__printf__, 3, 0)))
{
    char *str = NULL, *str2 = NULL;

    if (context == NULL || context->error_code != ret ||
        vasprintf(&str, fmt, args) < 0 || str == NULL)
        return;
    if (context->error_string) {
        int e;

        e = asprintf(&str2, "%s: %s", str, context->error_string);
        free(context->error_string);
        if (e < 0 || str2 == NULL)
            context->error_string = NULL;
        else
            context->error_string = str2;
        free(str);
    } else
        context->error_string = str;
}

const char *
heim_get_error_message(heim_context context, heim_error_code code)
{
    const char *cstr = NULL;
    char *str = NULL;
    char buf[128];
    int free_context = 0;

    if (code == 0)
        return strdup("Success");

    /*
     * The MIT version of this function ignores the krb5_context
     * and several widely deployed applications call krb5_get_error_message()
     * with a NULL context in order to translate an error code as a
     * replacement for error_message().  Another reason a NULL context
     * might be provided is if the krb5_init_context() call itself
     * failed.
     */
    if (context &&
        context->error_string &&
        (code == context->error_code || context->error_code == 0) &&
        (cstr = strdup(context->error_string)))
        return cstr;

    if (context == NULL && (context = heim_context_init()))
        free_context = 1;
    if (context)
        cstr = com_right_r(context->et_list, code, buf, sizeof(buf));
    if (free_context)
        heim_context_free(&context);

    if (cstr || (cstr = error_message(code)))
        return strdup(cstr);
    if (asprintf(&str, "<unknown error: %d>", (int)code) == -1 || str == NULL)
        return NULL;
    return str;
}

const char *
heim_get_error_string(heim_context context)
{
    if (context && context->error_string)
        return strdup(context->error_string);
    return NULL;
}

int
heim_have_error_string(heim_context context)
{
    return context && context->error_string != NULL;
}

void
heim_free_error_message(heim_context context, const char *msg)
{
    free(rk_UNCONST(msg));
}
