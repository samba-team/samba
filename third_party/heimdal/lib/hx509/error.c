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

#include "hx_locl.h"

/**
 * @page page_error Hx509 error reporting functions
 *
 * See the library functions here: @ref hx509_error
 */

struct hx509_error_data {
    hx509_error next;
    int code;
    char *msg;
};

/**
 * Resets the error strings the hx509 context.
 *
 * @param context A hx509 context.
 *
 * @ingroup hx509_error
 */

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_clear_error_string(hx509_context context)
{
    if (context) {
	heim_release(context->error);
	context->error = NULL;
    }
}

/**
 * Add an error message to the hx509 context.
 *
 * @param context A hx509 context.
 * @param flags
 * - HX509_ERROR_APPEND appends the error string to the old messages
     (code is updated).
 * @param code error code related to error message
 * @param fmt error message format
 * @param ap arguments to error message format
 *
 * @ingroup hx509_error
 */

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_set_error_stringv(hx509_context context, int flags, int code,
			const char *fmt, va_list ap)
{
    heim_error_t msg;

    if (context == NULL)
	return;

    msg = heim_error_createv(code, fmt, ap);
    if (msg) {
	if (flags & HX509_ERROR_APPEND)
	    heim_error_append(msg, context->error);
	heim_release(context->error);
    }
    context->error = msg;
}

/**
 * See hx509_set_error_stringv().
 *
 * @param context A hx509 context.
 * @param flags
 * - HX509_ERROR_APPEND appends the error string to the old messages
     (code is updated).
 * @param code error code related to error message
 * @param fmt error message format
 * @param ... arguments to error message format
 *
 * @ingroup hx509_error
 */

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_set_error_string(hx509_context context, int flags, int code,
		       const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    hx509_set_error_stringv(context, flags, code, fmt, ap);
    va_end(ap);
}

/**
 * Sets ENOMEM as the error on a hx509 context.
 *
 * @param context A hx509 context.
 *
 * @ingroup hx509_error
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_enomem(hx509_context context)
{
    return heim_enomem(context->hcontext);
}

/**
 * Get an error string from context associated with error_code.
 *
 * @param context A hx509 context.
 * @param error_code Get error message for this error code.
 *
 * @return error string, free with hx509_free_error_string().
 *
 * @ingroup hx509_error
 */

HX509_LIB_FUNCTION char * HX509_LIB_CALL
hx509_get_error_string(hx509_context context, int error_code)
{
    heim_string_t s = NULL;
    const char *cstr = NULL;
    char *str;

    if (context) {
        if (context->error &&
            heim_error_get_code(context->error) == error_code &&
            (s = heim_error_copy_string(context->error)))
            cstr = heim_string_get_utf8(s);

        if (cstr == NULL)
            cstr = com_right(context->et_list, error_code);

        if (cstr == NULL && error_code > -1)
            cstr = strerror(error_code);
    } /* else this could be an error in hx509_context_init() */

    if (cstr == NULL)
        cstr = error_message(error_code); /* never returns NULL */

    str = strdup(cstr);
    heim_release(s);
    return str;
}

/**
 * Free error string returned by hx509_get_error_string().
 *
 * @param str error string to free.
 *
 * @ingroup hx509_error
 */

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_free_error_string(char *str)
{
    free(str);
}

/**
 * Print error message and fatally exit from error code
 *
 * @param context A hx509 context.
 * @param exit_code exit() code from process.
 * @param error_code Error code for the reason to exit.
 * @param fmt format string with the exit message.
 * @param ... argument to format string.
 *
 * @ingroup hx509_error
 */

HX509_LIB_NORETURN_FUNCTION
     __attribute__ ((__noreturn__, __format__ (__printf__, 4, 5)))
void HX509_LIB_CALL
hx509_err(hx509_context context, int exit_code,
          int error_code, const char *fmt, ...)
{
    va_list ap;
    const char *msg;
    char *str;
    int ret;

    va_start(ap, fmt);
    ret = vasprintf(&str, fmt, ap);
    va_end(ap);
    msg = hx509_get_error_string(context, error_code);
    if (msg == NULL)
	msg = "no error";

    errx(exit_code, "%s: %s", ret != -1 ? str : "ENOMEM", msg);
}
