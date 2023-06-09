/*
 * Copyright (c) 1997 - 2020 Kungliga Tekniska Högskolan
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

#if defined(_MSC_VER)
# pragma warning(disable: 4646)
# pragma warning(disable: 4716)
#endif

#include "baselocl.h"
#include <err.h>

static heim_error_code _warnerr(heim_context context, int do_errtext,
	 heim_error_code code, int level, const char *fmt, va_list ap)
	__attribute__ ((__format__ (__printf__, 5, 0)));

static heim_error_code
_warnerr(heim_context context, int do_errtext,
	 heim_error_code code, int level, const char *fmt, va_list ap)
{
    char xfmt[7] = "";
    const char *args[2], **arg;
    char *msg = NULL;
    const char *err_str = NULL;
    heim_error_code ret;

    args[0] = args[1] = NULL;
    arg = args;
    if(fmt){
	strlcat(xfmt, "%s", sizeof(xfmt));
	if(do_errtext)
	    strlcat(xfmt, ": ", sizeof(xfmt));
	ret = vasprintf(&msg, fmt, ap);
	if(ret < 0 || msg == NULL)
	    return ENOMEM;
	*arg++ = msg;
    }
    if (do_errtext) {
	strlcat(xfmt, "%s", sizeof(xfmt));

	err_str = heim_get_error_message(context, code);
	if (err_str != NULL) {
	    *arg = err_str;
	} else {
	    *arg= "<unknown error>";
	}
    }

    if (context && heim_get_warn_dest(context))
        heim_log(context, heim_get_warn_dest(context), level, xfmt, args[0],
                 args[1]);
    else
	warnx(xfmt, args[0], args[1]);
    free(msg);
    heim_free_error_message(context, err_str);
    return 0;
}

#define FUNC(ETEXT, CODE, LEVEL)					\
    heim_error_code ret;						\
    va_list ap;								\
    va_start(ap, fmt);							\
    ret = _warnerr(context, ETEXT, CODE, LEVEL, fmt, ap); 		\
    va_end(ap);

#undef __attribute__
#define __attribute__(X)

/**
 * Log a warning to the log, default stderr, include the error from
 * the last failure.
 *
 * @param context A Kerberos 5 context.
 * @param code error code of the last error
 * @param fmt message to print
 * @param ap arguments
 *
 * @ingroup heim_error
 */

heim_error_code
heim_vwarn(heim_context context, heim_error_code code,
	   const char *fmt, va_list ap)
     __attribute__ ((__format__ (__printf__, 3, 0)))
{
    return _warnerr(context, 1, code, 1, fmt, ap);
}

/**
 * Log a warning to the log, default stderr, include the error from
 * the last failure.
 *
 * @param context A Kerberos 5 context.
 * @param code error code of the last error
 * @param fmt message to print
 *
 * @ingroup heim_error
 */

heim_error_code
heim_warn(heim_context context, heim_error_code code, const char *fmt, ...)
     __attribute__ ((__format__ (__printf__, 3, 4)))
{
    FUNC(1, code, 1);
    return ret;
}

/**
 * Log a warning to the log, default stderr.
 *
 * @param context A Kerberos 5 context.
 * @param fmt message to print
 * @param ap arguments
 *
 * @ingroup heim_error
 */

heim_error_code
heim_vwarnx(heim_context context, const char *fmt, va_list ap)
     __attribute__ ((__format__ (__printf__, 2, 0)))
{
    return _warnerr(context, 0, 0, 1, fmt, ap);
}

/**
 * Log a warning to the log, default stderr.
 *
 * @param context A Kerberos 5 context.
 * @param fmt message to print
 *
 * @ingroup heim_error
 */

heim_error_code
heim_warnx(heim_context context, const char *fmt, ...)
     __attribute__ ((__format__ (__printf__, 2, 3)))
{
    FUNC(0, 0, 1);
    return ret;
}
