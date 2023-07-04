/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"
#include "common_plugin.h"

/*
 * Definitions:
 *
 *	module	    - a category of plugin module, identified by subsystem
 *		      (typically "krb5")
 *	dso	    - a library for a module containing a map of plugin
 *		      types to plugins (e.g. "service_locator")
 *	plugin	    - a set of callbacks and state that follows the
 *		      common plugin module definition (version, init, fini)
 *
 * Obviously it would have been clearer to use the term "module" rather than
 * "DSO" given there is an internal "DSO", but "module" was already taken...
 *
 *	modules := { module: dsos }
 *	dsos := { path, dsohandle, plugins-by-name }
 *	plugins-by-name := { plugin-name: [plug] }
 *	plug := { ftable, ctx }
 *
 * Some existing plugin consumers outside libkrb5 use the "krb5" module
 * namespace, but going forward the module should match the consumer library
 * name (e.g. libhdb should use the "hdb" module rather than "krb5").
 */

/**
 * Register a plugin symbol name of specific type.
 * @param context a Keberos context
 * @param type type of plugin symbol
 * @param name name of plugin symbol
 * @param symbol a pointer to the named symbol
 * @return In case of error a non zero error com_err error is returned
 * and the Kerberos error string is set.
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_plugin_register(krb5_context context,
		     enum krb5_plugin_type type,
		     const char *name,
		     const void *symbol)
{
    /*
     * It's not clear that PLUGIN_TYPE_FUNC was ever used or supported. It likely
     * would have caused _krb5_plugin_run_f() to crash as the previous implementation
     * assumed PLUGIN_TYPE_DATA.
     */
    if (type != PLUGIN_TYPE_DATA) {
	krb5_warnx(context, "krb5_plugin_register: PLUGIN_TYPE_DATA no longer supported");
	return EINVAL;
    }

    return heim_plugin_register(context->hcontext, (heim_pcontext)context,
                                "krb5", name, symbol);
}

/**
 * Load plugins (new system) for the given module @name (typically
 * "krb5") from the given directory @paths.
 *
 * Inputs:
 *
 * @context A krb5_context
 * @name    Name of plugin module (typically "krb5")
 * @paths   Array of directory paths where to look
 */
KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_load_plugins(krb5_context context, const char *name, const char **paths)
{
    heim_load_plugins(context->hcontext, name, paths);
}

/**
 * Unload plugins (new system)
 */
KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_unload_plugins(krb5_context context, const char *name)
{
    heim_unload_plugins(context->hcontext, name);
}

/**
 * Run plugins for the given @module (e.g., "krb5") and @name (e.g.,
 * "kuserok").  Specifically, the @func is invoked once per-plugin with
 * four arguments: the @context, the plugin symbol value (a pointer to a
 * struct whose first three fields are the same as common_plugin_ftable),
 * a context value produced by the plugin's init method, and @userctx.
 *
 * @func should unpack arguments for a plugin function and invoke it
 * with arguments taken from @userctx.  @func should save plugin
 * outputs, if any, in @userctx.
 *
 * All loaded and registered plugins are invoked via @func until @func
 * returns something other than KRB5_PLUGIN_NO_HANDLE.  Plugins that
 * have nothing to do for the given arguments should return
 * KRB5_PLUGIN_NO_HANDLE.
 *
 * Inputs:
 *
 * @context     A krb5_context
 * @module      Name of module (typically "krb5")
 * @name        Name of pluggable interface (e.g., "kuserok")
 * @min_version Lowest acceptable plugin minor version number
 * @flags       Flags (none defined at this time)
 * @userctx     Callback data for the callback function @func
 * @func        A callback function, invoked once per-plugin
 *
 * Outputs: None, other than the return value and such outputs as are
 *          gathered by @func.
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_plugin_run_f(krb5_context context,
		   const struct heim_plugin_data *caller,
		   int flags,
		   void *userctx,
		   krb5_error_code (KRB5_LIB_CALL *func)(krb5_context, const void *, void *, void *))
{
    int32_t (HEIM_LIB_CALL *func2)(void *, const void *, void *, void *) = (void *)func;
    return heim_plugin_run_f(context->hcontext, (heim_pcontext)context, caller,
                             flags, KRB5_PLUGIN_NO_HANDLE, userctx, func2);
}

/**
 * Return a cookie identifying this instance of a library.
 *
 * Inputs:
 *
 * @context     A krb5_context
 * @module      Our library name or a library we depend on
 *
 * Outputs:	The instance cookie
 *
 * @ingroup	krb5_support
 */

#ifdef WIN32
static uintptr_t
djb2(uintptr_t hash, unsigned char *str)
{
    int c;

    while (c = *str++)
	hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}
#endif

KRB5_LIB_FUNCTION uintptr_t KRB5_LIB_CALL
krb5_get_instance(const char *libname)
{
#ifdef WIN32
    char *version;
    char *name;
    uintptr_t instance;

    if (win32_getLibraryVersion("heimdal", &name, &version))
	return 0;
    instance = djb2(5381, name);
    instance = djb2(instance, version);
    free(name);
    free(version);
    return instance;
#else
    static const char *instance = "libkrb5";

    if (strcmp(libname, "krb5") == 0)
	return (uintptr_t)instance;
    return 0;
#endif
}
