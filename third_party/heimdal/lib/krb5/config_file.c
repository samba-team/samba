/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

#if defined(HAVE_FRAMEWORK_COREFOUNDATION)
#include <CoreFoundation/CoreFoundation.h>
#endif

/**
 * Parse configuration files in the given directory and add the result
 * into res.  Only files whose names consist only of alphanumeric
 * characters, hyphen, and underscore, will be parsed, though files
 * ending in ".conf" will also be parsed.
 *
 * This interface can be used to parse several configuration directories
 * into one resulting krb5_config_section by calling it repeatably.
 *
 * @param context a Kerberos 5 context.
 * @param dname a directory name to a Kerberos configuration file
 * @param res the returned result, must be free with krb5_free_config_files().
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_dir_multi(krb5_context context,
                            const char *dname,
                            krb5_config_section **res)
{
    krb5_error_code ret;
    heim_config_section *section = NULL;

    if (res == NULL)
	return EINVAL;

    *res = NULL;

    ret = heim_config_parse_dir_multi(context->hcontext, dname, &section);
    if (ret == HEIM_ERR_CONFIG_BADFORMAT)
        return KRB5_CONFIG_BADFORMAT;
    if (ret)
	return ret;
    *res = (krb5_config_section *)section;
    return 0;
}

/**
 * Parse a configuration file and add the result into res. This
 * interface can be used to parse several configuration files into one
 * resulting krb5_config_section by calling it repeatably.
 *
 * @param context a Kerberos 5 context.
 * @param fname a file name to a Kerberos configuration file
 * @param res the returned result, must be free with krb5_free_config_files().
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_file_multi(krb5_context context,
			     const char *fname,
			     krb5_config_section **res)
{
    krb5_error_code ret;
    heim_config_section *section = NULL;

    if (res == NULL)
	return EINVAL;

    *res = NULL;

    ret = heim_config_parse_file_multi(context->hcontext, fname, &section);
    if (ret == HEIM_ERR_CONFIG_BADFORMAT)
        return KRB5_CONFIG_BADFORMAT;
    if (ret)
	return ret;
    *res = (krb5_config_section *)section;
    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_file(krb5_context context,
                       const char *fname,
                       krb5_config_section **res)
{
    return krb5_config_parse_file_multi(context, fname, res);
}

/**
 * Free configuration file section, the result of
 * krb5_config_parse_file() and krb5_config_parse_file_multi().
 *
 * @param context A Kerberos 5 context
 * @param s the configuration section to free
 *
 * @return returns 0 on successes, otherwise an error code, see
 *          krb5_get_error_message()
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_file_free(krb5_context context, krb5_config_section *s)
{
    return heim_config_file_free(context->hcontext, (heim_config_section *)s);
}

#ifndef HEIMDAL_SMALLER

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_config_copy(krb5_context context,
		  krb5_config_section *c,
		  krb5_config_section **res)
{
    krb5_error_code ret;
    heim_config_section *section = NULL;

    if (res == NULL)
	return EINVAL;

    *res = NULL;
    ret = heim_config_copy(context->hcontext, (heim_config_section *)c, &section);
    if (ret)
	return ret;
    *res = (krb5_config_section *)section;
    return 0;
}

#endif /* HEIMDAL_SMALLER */

KRB5_LIB_FUNCTION const void * KRB5_LIB_CALL
_krb5_config_get_next(krb5_context context,
		      const krb5_config_section *c,
		      const krb5_config_binding **pointer,
		      int type,
		      ...)
{
    const char *ret;
    va_list args;

    va_start(args, type);
    ret = heim_config_vget_next(context->hcontext,
				(const heim_config_section *)(c ? c : context->cf),
                                (const heim_config_binding **)pointer, type, args);
    va_end(args);
    return ret;
}

KRB5_LIB_FUNCTION const void * KRB5_LIB_CALL
_krb5_config_vget_next(krb5_context context,
                       const krb5_config_section *c,
                       const krb5_config_binding **pointer,
                       int type,
                       va_list args)
{
    return heim_config_vget_next(context->hcontext,
				 (const heim_config_section *)(c ? c : context->cf),
				 (const heim_config_binding **)pointer, type, args);
}

KRB5_LIB_FUNCTION const void * KRB5_LIB_CALL
_krb5_config_get(krb5_context context,
		 const krb5_config_section *c,
		 int type,
		 ...)
{
    const void *ret;
    va_list args;

    va_start(args, type);
    ret = heim_config_vget(context->hcontext,
			   (const heim_config_section *)(c ? c : context->cf),
			   type, args);
    va_end(args);
    return ret;
}


KRB5_LIB_FUNCTION const void * KRB5_LIB_CALL
_krb5_config_vget(krb5_context context,
		  const krb5_config_section *c,
		  int type,
		  va_list args)
{
    return heim_config_vget(context->hcontext,
			    (const heim_config_section *)(c ? c : context->cf),
			    type, args);
}

/**
 * Get a list of configuration binding list for more processing
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return NULL if configuration list is not found, a list otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const krb5_config_binding * KRB5_LIB_CALL
krb5_config_get_list(krb5_context context,
		     const krb5_config_section *c,
		     ...)
{
    const heim_config_binding *ret;
    va_list args;

    va_start(args, c);
    ret = heim_config_vget_list(context->hcontext,
				(const heim_config_section *)(c ? c : context->cf),
				args);
    va_end(args);
    return (const krb5_config_binding *)ret;
}

/**
 * Get a list of configuration binding list for more processing
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return NULL if configuration list is not found, a list otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const krb5_config_binding * KRB5_LIB_CALL
krb5_config_vget_list(krb5_context context,
		      const krb5_config_section *c,
		      va_list args)
{
    const heim_config_binding *ret;

    ret = heim_config_vget_list(context->hcontext,
				(const heim_config_section *)(c ? c : context->cf),
				args);
    return (const krb5_config_binding *)ret;
}

/**
 * Returns a "const char *" to a string in the configuration database.
 * The string may not be valid after a reload of the configuration
 * database so a caller should make a local copy if it needs to keep
 * the string.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return NULL if configuration string not found, a string otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_get_string(krb5_context context,
                       const krb5_config_section *c,
                       ...)
{
    const char *ret;
    va_list args;

    va_start(args, c);
    ret = heim_config_vget_string(context->hcontext,
				  (const heim_config_section *)(c ? c : context->cf),
				  args);
    va_end(args);
    return ret;
}

/**
 * Like krb5_config_get_string(), but uses a va_list instead of ...
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return NULL if configuration string not found, a string otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_vget_string(krb5_context context,
                        const krb5_config_section *c,
                        va_list args)
{
    return heim_config_vget_string(context->hcontext,
				   (const heim_config_section *)(c ? c : context->cf),
				   args);
}

/**
 * Like krb5_config_vget_string(), but instead of returning NULL,
 * instead return a default value.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return a configuration string
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_vget_string_default(krb5_context context,
                                const krb5_config_section *c,
                                const char *def_value,
                                va_list args)
{
    return heim_config_vget_string_default(context->hcontext,
					   (const heim_config_section *)(c ? c : context->cf),
					   def_value, args);
}

/**
 * Like krb5_config_get_string(), but instead of returning NULL,
 * instead return a default value.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return a configuration string
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_get_string_default(krb5_context context,
                               const krb5_config_section *c,
                               const char *def_value,
                               ...)
{
    const char *ret;
    va_list args;

    va_start(args, def_value);
    ret = heim_config_vget_string_default(context->hcontext,
					  (const heim_config_section *)(c ? c : context->cf),
					  def_value, args);
    va_end(args);
    return ret;
}

/**
 * Get a list of configuration strings, free the result with
 * krb5_config_free_strings().
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION char ** KRB5_LIB_CALL
krb5_config_vget_strings(krb5_context context,
			 const krb5_config_section *c,
			 va_list args)
{
    return heim_config_vget_strings(context->hcontext,
				    (const heim_config_section *)(c ? c : context->cf),
				    args);
}

/**
 * Get a list of configuration strings, free the result with
 * krb5_config_free_strings().
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION char** KRB5_LIB_CALL
krb5_config_get_strings(krb5_context context,
			const krb5_config_section *c,
			...)
{
    va_list ap;
    char **ret;
    va_start(ap, c);
    ret = heim_config_vget_strings(context->hcontext,
				   (const heim_config_section *)(c ? c : context->cf),
				   ap);
    va_end(ap);
    return ret;
}

/**
 * Free the resulting strings from krb5_config-get_strings() and
 * krb5_config_vget_strings().
 *
 * @param strings strings to free
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_config_free_strings(char **strings)
{
    heim_config_free_strings(strings);
}

/**
 * Like krb5_config_get_bool_default() but with a va_list list of
 * configuration selection.
 *
 * Configuration value to a boolean value, where yes/true and any
 * non-zero number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_vget_bool_default(krb5_context context,
			      const krb5_config_section *c,
			      krb5_boolean def_value,
			      va_list args)
{
    return heim_config_vget_bool_default(context->hcontext,
					 (const heim_config_section *)(c ? c : context->cf),
					 def_value, args);
}

/**
 * krb5_config_get_bool() will convert the configuration
 * option value to a boolean value, where yes/true and any non-zero
 * number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_vget_bool(krb5_context context,
                      const krb5_config_section *c,
                      va_list args)
{
    return heim_config_vget_bool_default(context->hcontext,
					 (const heim_config_section *)(c ? c : context->cf),
					 FALSE, args);
}

/**
 * krb5_config_get_bool_default() will convert the configuration
 * option value to a boolean value, where yes/true and any non-zero
 * number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_get_bool_default(krb5_context context,
			     const krb5_config_section *c,
			     krb5_boolean def_value,
			     ...)
{
    va_list ap;
    krb5_boolean ret;
    va_start(ap, def_value);
    ret = heim_config_vget_bool_default(context->hcontext,
					(const heim_config_section *)(c ? c : context->cf),
					def_value, ap);
    va_end(ap);
    return ret;
}

/**
 * Like krb5_config_get_bool() but with a va_list list of
 * configuration selection.
 *
 * Configuration value to a boolean value, where yes/true and any
 * non-zero number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_get_bool (krb5_context context,
		      const krb5_config_section *c,
		      ...)
{
    va_list ap;
    krb5_boolean ret;
    va_start(ap, c);
    ret = krb5_config_vget_bool (context, c, ap);
    va_end(ap);
    return ret;
}

/**
 * Get the time from the configuration file using a relative time.
 *
 * Like krb5_config_get_time_default() but with a va_list list of
 * configuration selection.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return parsed the time (or def_value on parse error)
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_time_default(krb5_context context,
			      const krb5_config_section *c,
			      int def_value,
			      va_list args)
{
    return heim_config_vget_time_default(context->hcontext,
					 (const heim_config_section *)(c ? c : context->cf),
					 def_value, args);
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return parsed the time or -1 on error
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_time(krb5_context context,
                      const krb5_config_section *c,
                      va_list args)
{
    return heim_config_vget_time_default(context->hcontext,
					 (const heim_config_section *)(c ? c : context->cf),
					 -1, args);
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return parsed the time (or def_value on parse error)
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_time_default(krb5_context context,
			     const krb5_config_section *c,
			     int def_value,
			     ...)
{
    va_list ap;
    int ret;
    va_start(ap, def_value);
    ret = heim_config_vget_time_default(context->hcontext,
					(const heim_config_section *)(c ? c : context->cf),
					def_value, ap);
    va_end(ap);
    return ret;
}

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return parsed the time or -1 on error
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_time(krb5_context context,
                     const krb5_config_section *c,
                     ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = heim_config_vget_time(context->hcontext,
				(const heim_config_section *)(c ? c : context->cf),
				ap);
    va_end(ap);
    return ret;
}


KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_int_default(krb5_context context,
			     const krb5_config_section *c,
			     int def_value,
			     va_list args)
{
    return heim_config_vget_int_default(context->hcontext,
					(const heim_config_section *)(c ? c : context->cf),
					def_value, args);
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_int(krb5_context context,
		     const krb5_config_section *c,
		     va_list args)
{
    return heim_config_vget_int_default(context->hcontext,
					(const heim_config_section *)(c ? c : context->cf),
					-1, args);
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_int_default(krb5_context context,
			    const krb5_config_section *c,
			    int def_value,
			    ...)
{
    va_list ap;
    int ret;
    va_start(ap, def_value);
    ret = heim_config_vget_int_default(context->hcontext,
				       (const heim_config_section *)(c ? c : context->cf),
				       def_value, ap);
    va_end(ap);
    return ret;
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_int(krb5_context context,
		    const krb5_config_section *c,
		    ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = heim_config_vget_int(context->hcontext,
			       (const heim_config_section *)(c ? c : context->cf),
			       ap);
    va_end(ap);
    return ret;
}


#ifndef HEIMDAL_SMALLER
/**
 * Deprecated: configuration files are not strings
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_string_multi(krb5_context context,
			       const char *string,
			       krb5_config_section **res)
    KRB5_DEPRECATED_FUNCTION("Use X instead")
{
    krb5_error_code ret;
    heim_config_section *section = NULL;

    if (res == NULL)
	return EINVAL;

    *res = NULL;
    ret = heim_config_parse_string_multi(context->hcontext, string, &section);
    if (ret == HEIM_ERR_CONFIG_BADFORMAT)
        return KRB5_CONFIG_BADFORMAT;
    if (ret)
	return ret;
    *res = (krb5_config_section *)section;
    return 0;
}
#endif
