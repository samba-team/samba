
/***********************************************************************
 * Copyright (c) 2009, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
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
 *
 **********************************************************************/

#include "krb5_locl.h"

#include <stdarg.h>

/**
 * Internal function to expand tokens in paths.
 *
 * Inputs:
 *
 * @context   A krb5_context
 * @path_in   The path to expand tokens from
 * @filepath  True if the value is a filesystem path (converts slashes to
 *            backslashes on Windows)
 * @ppath_out The expanded path
 * 
 * Outputs:
 *
 * @ppath_out Path with expanded tokens (caller must free() this)
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_expand_path_tokens(krb5_context context,
			 const char *path_in,
			 int filepath,
			 char **ppath_out)
{
    return heim_expand_path_tokens(context ? context->hcontext : NULL, path_in,
                                   filepath, ppath_out, NULL);
}

/**
 * Internal function to expand tokens in paths.
 *
 * Inputs:
 *
 * @context   A krb5_context
 * @path_in   The path to expand tokens from
 * @filepath  True if the value is a filesystem path (converts slashes to
 *            backslashes on Windows)
 * @ppath_out The expanded path
 * @...       Variable number of pairs of strings, the first of each
 *            being a token (e.g., "luser") and the second a string to
 *            replace it with.  The list is terminated by a NULL.
 * 
 * Outputs:
 *
 * @ppath_out Path with expanded tokens (caller must free() this)
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_expand_path_tokensv(krb5_context context,
			  const char *path_in,
			  int filepath,
			  char **ppath_out, ...)
{
    krb5_error_code ret;
    va_list ap;

    va_start(ap, ppath_out);
    ret = heim_expand_path_tokensv(context->hcontext, path_in, filepath, ppath_out, ap);
    va_end(ap);

    return ret;
}
