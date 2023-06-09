/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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

/**
 * @page krb5_ccache_intro The credential cache functions
 * @section section_krb5_ccache Kerberos credential caches
 *
 * krb5_ccache structure holds a Kerberos credential cache.
 *
 * Heimdal support the follow types of credential caches:
 *
 * - SCC
 *   Store the credential in a database
 * - FILE
 *   Store the credential in memory
 * - MEMORY
 *   Store the credential in memory
 * - API
 *   A credential cache server based solution for Mac OS X
 * - KCM
 *   A credential cache server based solution for all platforms
 *
 * @subsection Example
 *
 * This is a minimalistic version of klist:
@code
#include <krb5.h>

int
main (int argc, char **argv)
{
    krb5_context context;
    krb5_cc_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;
    krb5_creds creds;

    if (krb5_init_context (&context) != 0)
	errx(1, "krb5_context");

    ret = krb5_cc_default (context, &id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_default");

    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_start_seq_get");

    while((ret = krb5_cc_next_cred(context, id, &cursor, &creds)) == 0){
        char *principal;

	krb5_unparse_name(context, creds.server, &principal);
	printf("principal: %s\\n", principal);
	free(principal);
	krb5_free_cred_contents (context, &creds);
    }
    ret = krb5_cc_end_seq_get(context, id, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_end_seq_get");

    krb5_cc_close(context, id);

    krb5_free_context(context);
    return 0;
}
* @endcode
*/

static const krb5_cc_ops *
cc_get_prefix_ops(krb5_context context,
		  const char *prefix,
		  const char **residual);

/**
 * Add a new ccache type with operations `ops', overwriting any
 * existing one if `override'.
 *
 * @param context a Kerberos context
 * @param ops type of plugin symbol
 * @param override flag to select if the registration is to overide
 * an existing ops with the same name.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_register(krb5_context context,
		 const krb5_cc_ops *ops,
		 krb5_boolean override)
{
    int i;

    for(i = 0; i < context->num_cc_ops && context->cc_ops[i]->prefix; i++) {
	if(strcmp(context->cc_ops[i]->prefix, ops->prefix) == 0) {
	    if(!override) {
		krb5_set_error_message(context,
				       KRB5_CC_TYPE_EXISTS,
				       N_("cache type %s already exists", "type"),
				       ops->prefix);
		return KRB5_CC_TYPE_EXISTS;
	    }
	    break;
	}
    }
    if(i == context->num_cc_ops) {
	const krb5_cc_ops **o = realloc(rk_UNCONST(context->cc_ops),
					(context->num_cc_ops + 1) *
					sizeof(context->cc_ops[0]));
	if(o == NULL) {
	    krb5_set_error_message(context, KRB5_CC_NOMEM,
				   N_("malloc: out of memory", ""));
	    return KRB5_CC_NOMEM;
	}
	context->cc_ops = o;
	context->cc_ops[context->num_cc_ops] = NULL;
	context->num_cc_ops++;
    }
    context->cc_ops[i] = ops;
    return 0;
}

/*
 * Allocate the memory for a `id' and the that function table to
 * `ops'. Returns 0 or and error code.
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_cc_allocate(krb5_context context,
		  const krb5_cc_ops *ops,
		  krb5_ccache *id)
{
    krb5_ccache p;

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM,
			       N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }
    p->ops = ops;
    *id = p;

    return 0;
}

/*
 * Allocate memory for a new ccache in `id' with operations `ops'
 * and name `residual'. Return 0 or an error code.
 */

static krb5_error_code
allocate_ccache(krb5_context context,
                const krb5_cc_ops *ops,
                const char *residual,
                const char *subsidiary,
                krb5_ccache *id)
{
    krb5_error_code ret = 0;
    char *exp_residual = NULL;
    int filepath;

    filepath = (strcmp("FILE", ops->prefix) == 0
		 || strcmp("DIR", ops->prefix) == 0
		 || strcmp("SCC", ops->prefix) == 0);

    if (residual)
        ret = _krb5_expand_path_tokens(context, residual, filepath, &exp_residual);
    if (ret == 0)
        ret = _krb5_cc_allocate(context, ops, id);

    if (ret == 0) {
        if ((*id)->ops->version < KRB5_CC_OPS_VERSION_5
            || (*id)->ops->resolve_2 == NULL) {
            ret = (*id)->ops->resolve(context, id, exp_residual);
        } else {
            ret = (*id)->ops->resolve_2(context, id, exp_residual, subsidiary);
        }
    }
    if (ret) {
	free(*id);
        *id = NULL;
    }
    free(exp_residual);
    return ret;
}


/**
 * Find and allocate a ccache in `id' from the specification in `residual'.
 * If the ccache name doesn't contain any colon, interpret it as a file name.
 *
 * @param context a Kerberos context.
 * @param name string name of a credential cache.
 * @param id return pointer to a found credential cache.
 *
 * @return Return 0 or an error code. In case of an error, id is set
 * to NULL, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_resolve(krb5_context context,
		const char *name,
		krb5_ccache *id)
{
    const krb5_cc_ops *ops;
    const char *residual = NULL;

    *id = NULL;

    ops = cc_get_prefix_ops(context, name, &residual);
    if (ops == NULL)
	ops = &krb5_fcc_ops; /* residual will point to name */

    return allocate_ccache(context, ops, residual, NULL, id);
}

#ifdef _WIN32
static const char *
get_default_cc_type_win32(krb5_context context)
{
    krb5_error_code ret;
    krb5_ccache id;

    /*
     * If the MSLSA ccache type has a principal name,
     * use it as the default.
     */
    ret = krb5_cc_resolve(context, "MSLSA:", &id);
    if (ret == 0) {
        krb5_principal princ;
        ret = krb5_cc_get_principal(context, id, &princ);
        krb5_cc_close(context, id);
        if (ret == 0) {
            krb5_free_principal(context, princ);
	    return "MSLSA";
	}
    }

    /*
     * If the API: ccache can be resolved,
     * use it as the default.
     */
    ret = krb5_cc_resolve(context, "API:", &id);
    if (ret == 0) {
	krb5_cc_close(context, id);
	return "API";
    }

    return NULL;
}
#endif /* _WIN32 */

static const char *
get_default_cc_type(krb5_context context, int simple)
{
    const char *def_ccname;
    const char *def_cctype =
        krb5_config_get_string_default(context, NULL,
                                       secure_getenv("KRB5CCTYPE"),
                                       "libdefaults", "default_cc_type", NULL);
    const char *def_cccol =
        krb5_config_get_string(context, NULL, "libdefaults",
                               "default_cc_collection", NULL);
    const krb5_cc_ops *ops;

    if (!simple && (def_ccname = krb5_cc_default_name(context))) {
	ops = cc_get_prefix_ops(context, def_ccname, NULL);
	if (ops)
	    return ops->prefix;
    }
    if (!def_cctype && def_cccol) {
	ops = cc_get_prefix_ops(context, def_cccol, NULL);
	if (ops)
	    return ops->prefix;
    }
#ifdef _WIN32
    if (def_cctype == NULL)
	def_cctype = get_default_cc_type_win32(context);
#endif
    if (def_cctype == NULL)
	def_cctype = KRB5_DEFAULT_CCTYPE->prefix;
    return def_cctype;
}

/**
 * Find and allocate a ccache in `id' for the subsidiary cache named by
 * `subsidiary' in the collection named by `collection'.
 *
 * @param context a Kerberos context.
 * @param cctype string name of a credential cache collection type.
 * @param collection string name of a credential cache collection.
 * @param subsidiary string name of a credential cache in a collection.
 * @param id return pointer to a found credential cache.
 *
 * @return Return 0 or an error code. In case of an error, id is set
 * to NULL, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_resolve_sub(krb5_context context,
                    const char *cctype,
                    const char *collection,
                    const char *subsidiary,
                    krb5_ccache *id)
{
    const krb5_cc_ops *ops = NULL;

    *id = NULL;

    /* Get the cctype from the collection, maybe */
    if (cctype == NULL && collection)
	ops = cc_get_prefix_ops(context, collection, &collection);

    if (ops == NULL)
	ops = cc_get_prefix_ops(context, get_default_cc_type(context, 0), NULL);

    if (ops == NULL) {
	krb5_set_error_message(context, KRB5_CC_UNKNOWN_TYPE,
			       N_("unknown ccache type %s", ""), cctype);
	return KRB5_CC_UNKNOWN_TYPE;
    }

    return allocate_ccache(context, ops, collection, subsidiary, id);
}


/**
 * Find and allocate a ccache in `id' from the specification in `residual', but
 * specific to the given principal `principal' by using the principal name as
 * the name of a "subsidiary" credentials cache in the collection named by
 * `name'.  If the ccache name doesn't contain any colon, interpret it as a
 * file name.
 *
 * @param context a Kerberos context.
 * @param name string name of a credential cache.
 * @param principal principal name of desired credentials.
 * @param id return pointer to a found credential cache.
 *
 * @return Return 0 or an error code. In case of an error, id is set
 * to NULL, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_resolve_for(krb5_context context,
                    const char *cctype,
		    const char *name,
                    krb5_const_principal principal,
                    krb5_ccache *id)
{
    krb5_error_code ret;
    char *p, *s;

    *id = NULL;

    ret = krb5_unparse_name(context, principal, &p);
    if (ret)
        return ret;
    /*
     * Subsidiary components cannot have various chars in them that are used as
     * separators.  ':' is used for subsidiary separators in all ccache types
     * except FILE, where '+' is used instead because we can't use ':' in file
     * paths on Windows and because ':' is not in the POSIX safe set.
     */
    for (s = p; *s; s++) {
        switch (s[0]) {
        case ':':
        case '+':
        case '/':
        case '\\':
            s[0] = '-';
        default: break;
        }
    }
    ret = krb5_cc_resolve_sub(context, cctype, name, p, id);
    free(p);
    return ret;
}

/**
 * Generates a new unique ccache of `type` in `id'. If `type' is NULL,
 * the library chooses the default credential cache type. The supplied
 * `hint' (that can be NULL) is a string that the credential cache
 * type can use to base the name of the credential on, this is to make
 * it easier for the user to differentiate the credentials.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_new_unique(krb5_context context, const char *type,
		   const char *hint, krb5_ccache *id)
{
    const krb5_cc_ops *ops;
    krb5_error_code ret;

    if (type == NULL)
        type = get_default_cc_type(context, 1);

    ops = krb5_cc_get_prefix_ops(context, type);
    if (ops == NULL) {
	krb5_set_error_message(context, KRB5_CC_UNKNOWN_TYPE,
			      "Credential cache type %s is unknown", type);
	return KRB5_CC_UNKNOWN_TYPE;
    }

    ret = _krb5_cc_allocate(context, ops, id);
    if (ret)
	return ret;
    ret = (*id)->ops->gen_new(context, id);
    if (ret) {
	free(*id);
	*id = NULL;
    }
    return ret;
}

/**
 * Return the name of the ccache `id'
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_cc_get_name(krb5_context context,
		 krb5_ccache id)
{
    const char *name = NULL;

    if (id->ops->version < KRB5_CC_OPS_VERSION_5
	|| id->ops->get_name_2 == NULL)
	return id->ops->get_name(context, id);

    (void) id->ops->get_name_2(context, id, &name, NULL, NULL);
    return name;
}

/**
 * Return the name of the ccache collection associated with `id'
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_cc_get_collection(krb5_context context, krb5_ccache id)
{
    const char *name = NULL;

    if (id->ops->version < KRB5_CC_OPS_VERSION_5
	|| id->ops->get_name_2 == NULL)
	return NULL;

    (void) id->ops->get_name_2(context, id, NULL, &name, NULL);
    return name;
}

/**
 * Return the name of the subsidiary ccache of `id'
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_cc_get_subsidiary(krb5_context context, krb5_ccache id)
{
    const char *name = NULL;

    if (id->ops->version >= KRB5_CC_OPS_VERSION_5
	&& id->ops->get_name_2 != NULL)
        (void) id->ops->get_name_2(context, id, NULL, NULL, &name);
    return name;
}

/**
 * Return the type of the ccache `id'.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_cc_get_type(krb5_context context,
		 krb5_ccache id)
{
    return id->ops->prefix;
}

/**
 * Return the complete resolvable name the cache

 * @param context a Kerberos context
 * @param id return pointer to a found credential cache
 * @param str the returned name of a credential cache, free with krb5_xfree()
 *
 * @return Returns 0 or an error (and then *str is set to NULL).
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_full_name(krb5_context context,
		      krb5_ccache id,
		      char **str)
{
    const char *type, *name;

    *str = NULL;

    type = krb5_cc_get_type(context, id);
    if (type == NULL) {
	krb5_set_error_message(context, KRB5_CC_UNKNOWN_TYPE,
			       "cache have no name of type");
	return KRB5_CC_UNKNOWN_TYPE;
    }

    name = krb5_cc_get_name(context, id);
    if (name == NULL) {
	krb5_set_error_message(context, KRB5_CC_BADNAME,
			       "cache of type %s have no name", type);
	return KRB5_CC_BADNAME;
    }

    if (asprintf(str, "%s:%s", type, name) == -1) {
	*str = NULL;
	return krb5_enomem(context);
    }
    return 0;
}

/**
 * Return krb5_cc_ops of a the ccache `id'.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION const krb5_cc_ops * KRB5_LIB_CALL
krb5_cc_get_ops(krb5_context context, krb5_ccache id)
{
    return id->ops;
}

/*
 * Expand variables in `str' into `res'
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_expand_default_cc_name(krb5_context context, const char *str, char **res)
{
    int filepath;

    filepath = (strncmp("FILE:", str, 5) == 0
		 || strncmp("DIR:", str, 4) == 0
		 || strncmp("SCC:", str, 4) == 0);

    return _krb5_expand_path_tokens(context, str, filepath, res);
}

/*
 * Return non-zero if envirnoment that will determine default krb5cc
 * name has changed.
 */

static int
environment_changed(krb5_context context)
{
    const char *e;

    /* if the cc name was set, don't change it */
    if (context->default_cc_name_set)
	return 0;

    /* XXX performance: always ask KCM/API if default name has changed */
    if (context->default_cc_name &&
	(strncmp(context->default_cc_name, "KCM:", 4) == 0 ||
	 strncmp(context->default_cc_name, "API:", 4) == 0))
	return 1;

    e = secure_getenv("KRB5CCNAME");
    if (e == NULL) {
	if (context->default_cc_name_env) {
	    free(context->default_cc_name_env);
	    context->default_cc_name_env = NULL;
	    return 1;
	}
    } else {
	if (context->default_cc_name_env == NULL)
	    return 1;
	if (strcmp(e, context->default_cc_name_env) != 0)
	    return 1;
    }
    return 0;
}

/**
 * Switch the default default credential cache for a specific
 * credcache type (and name for some implementations).
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_switch(krb5_context context, krb5_ccache id)
{
#ifdef _WIN32
    _krb5_set_default_cc_name_to_registry(context, id);
#endif

    if (id->ops->version == KRB5_CC_OPS_VERSION_0
	|| id->ops->set_default == NULL)
	return 0;

    return (*id->ops->set_default)(context, id);
}

/**
 * Return true if the default credential cache support switch
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_cc_support_switch(krb5_context context, const char *type)
{
    const krb5_cc_ops *ops;

    ops = krb5_cc_get_prefix_ops(context, type);
    if (ops && ops->version > KRB5_CC_OPS_VERSION_0 && ops->set_default)
	return 1;
    return FALSE;
}

/**
 * Set the default cc name for `context' to `name'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_default_name(krb5_context context, const char *name)
{
    krb5_error_code ret = 0;
    char *p = NULL;

    if (name == NULL) {
	const char *e;

        if ((e = secure_getenv("KRB5CCNAME"))) {
            if ((p = strdup(e)) == NULL)
                return krb5_enomem(context);

            free(context->default_cc_name_env);
            context->default_cc_name_env = p;

            if ((p = strdup(e)) == NULL)
                return krb5_enomem(context);

            /*
             * We're resetting the default ccache name.  Recall that we got
             * this from the environment, which might change.
             */
            context->default_cc_name_set = 0;
        } else if ((e = krb5_cc_configured_default_name(context))) {
            if ((p = strdup(e)) == NULL)
                return krb5_enomem(context);

            /*
             * Since $KRB5CCNAME was not set, and since we got the default
             * ccache name from configuration, we'll not want
             * environment_changed() to return true to avoid re-doing the
             * krb5_cc_configured_default_name() call unnecessarily.
             *
             * XXX Perhaps if we got the ccache name from the registry then
             *     we'd want to recheck it?  If so we might need an indication
             *     from krb5_cc_configured_default_name() about that!
             */
            context->default_cc_name_set = 1;
        }
    } else {
        int filepath = (strncmp("FILE:", name, 5) == 0 ||
                        strncmp("DIR:",  name, 4) == 0 ||
                        strncmp("SCC:",  name, 4) == 0);

        ret = _krb5_expand_path_tokens(context, name, filepath, &p);
        if (ret)
            return ret;

        /*
         * Since the default ccache name was set explicitly, we won't want
         * environment_changed() to return true until the default ccache name
         * is reset.
         */
	context->default_cc_name_set = 1;
    }

    free(context->default_cc_name);
    context->default_cc_name = p;
    return 0;
}

/**
 * Return a pointer to a context static string containing the default
 * ccache name.
 *
 * @return String to the default credential cache name.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_cc_default_name(krb5_context context)
{
    if (context->default_cc_name == NULL || environment_changed(context))
	krb5_cc_set_default_name(context, NULL);

    return context->default_cc_name;
}

KRB5_LIB_FUNCTION const char * KRB5_LIB_CALL
krb5_cc_configured_default_name(krb5_context context)
{
    krb5_error_code ret = 0;
#ifdef _WIN32
    krb5_ccache id;
#endif
    const char *cfg;
    char *expanded;
    const krb5_cc_ops *ops;

    if (context->configured_default_cc_name)
        return context->configured_default_cc_name;

#ifdef _WIN32
    if ((expanded = _krb5_get_default_cc_name_from_registry(context)))
        return context->configured_default_cc_name = expanded;
#endif

    /* If there's a configured default, expand the tokens and use it */
    cfg = krb5_config_get_string(context, NULL, "libdefaults",
                                 "default_cc_name", NULL);
    if (cfg == NULL)
        cfg = krb5_config_get_string(context, NULL, "libdefaults",
                                     "default_ccache_name", NULL);
    if (cfg) {
        ret = _krb5_expand_default_cc_name(context, cfg, &expanded);
        if (ret) {
            krb5_set_error_message(context, ret,
                                   "token expansion failed for %s", cfg);
            return NULL;
        }
        return context->configured_default_cc_name = expanded;
    }

    /* Else try a configured default ccache type's default */
    cfg = get_default_cc_type(context, 1);
    if ((ops = krb5_cc_get_prefix_ops(context, cfg)) == NULL) {
	krb5_set_error_message(context, KRB5_CC_UNKNOWN_TYPE,
                               "unknown configured credential cache "
                               "type %s", cfg);
	return NULL;
    }

    /* The get_default_name() method expands any tokens */
    ret = (*ops->get_default_name)(context, &expanded);
    if (ret) {
	krb5_set_error_message(context, ret, "failed to find a default "
			       "ccache for default ccache type %s", cfg);
	return NULL;
    }
    return context->configured_default_cc_name = expanded;
}

KRB5_LIB_FUNCTION char * KRB5_LIB_CALL
krb5_cccol_get_default_ccname(krb5_context context)
{
    const char *cfg = get_default_cc_type(context, 1);
    char *cccol_default_ccname;
    const krb5_cc_ops *ops = krb5_cc_get_prefix_ops(context, cfg);

    (void) (*ops->get_default_name)(context, &cccol_default_ccname);
    return cccol_default_ccname;
}

/**
 * Open the default ccache in `id'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_default(krb5_context context,
		krb5_ccache *id)
{
    const char *p = krb5_cc_default_name(context);

    *id = NULL;
    if (p == NULL)
	return krb5_enomem(context);
    return krb5_cc_resolve(context, p, id);
}

/**
 * Open the named subsidiary cache from the default ccache collection in `id'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_default_sub(krb5_context context,
                    const char *subsidiary,
		    krb5_ccache *id)
{
    return krb5_cc_resolve_sub(context, get_default_cc_type(context, 0), NULL,
                               subsidiary, id);
}

/**
 * Open the default ccache in `id' that corresponds to the given principal.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_default_for(krb5_context context,
                    krb5_const_principal principal,
                    krb5_ccache *id)
{
    return krb5_cc_resolve_for(context, get_default_cc_type(context, 0), NULL,
                               principal, id);
}

/**
 * Create a new ccache in `id' for `primary_principal'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_initialize(krb5_context context,
		   krb5_ccache id,
		   krb5_principal primary_principal)
{
    krb5_error_code ret;

    ret = (*id->ops->init)(context, id, primary_principal);
    if (ret == 0) {
        id->cc_kx509_done = 0;
        id->cc_initialized = 1;
        id->cc_need_start_realm = 1;
        id->cc_start_tgt_stored = 0;
    }
    return ret;
}


/**
 * Remove the ccache `id'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_destroy(krb5_context context,
		krb5_ccache id)
{
    krb5_error_code ret2 = 0;
    krb5_error_code ret;
    krb5_data d;

    /*
     * Destroy associated hx509 PKIX credential store created by krb5_kx509*().
     */
    if (krb5_cc_get_config(context, id, NULL, "kx509store", &d) == 0) {
        char *name;

        if ((name = strndup(d.data, d.length)) == NULL) {
            ret2 = krb5_enomem(context);
        } else {
            hx509_certs certs;
            ret = hx509_certs_init(context->hx509ctx, name, 0, NULL, &certs);
            if (ret == 0)
                ret2 = hx509_certs_destroy(context->hx509ctx, &certs);
            else
                hx509_certs_free(&certs);
            free(name);
        }
    }

    ret = (*id->ops->destroy)(context, id);
    (void) krb5_cc_close(context, id);
    return ret ? ret : ret2;
}

/**
 * Stop using the ccache `id' and free the related resources.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_close(krb5_context context,
	      krb5_ccache id)
{
    krb5_error_code ret;

    if (!id)
	return 0;

    /*
     * We want to automatically acquire a PKIX credential using kx509.
     *
     * This can be slow if we're generating an RSA key.  Plus it means talking
     * to the KDC.
     *
     * We only want to do this when:
     *
     *  - krb5_cc_initialize() was called on this ccache handle,
     *  - a start TGT was stored (actually, a cross-realm TGT would do),
     *
     * and
     *
     *  - we aren't creating a gss_cred_id_t for a delegated credential.
     *
     * We only have a heuristic for the last condition: that `id' is not a
     * MEMORY ccache, which is what's used for delegated credentials.
     *
     * We really only want to do this when storing a credential in a user's
     * default ccache, but we leave it to krb5_kx509() to do that check.
     *
     * XXX Perhaps we should do what krb5_kx509() does here, and just call
     *     krb5_kx509_ext() (renamed to krb5_kx509()).  Then we wouldn't need
     *     the delegated cred handle heuristic.
     */
    if (id->cc_initialized && id->cc_start_tgt_stored && !id->cc_kx509_done &&
        strcmp("MEMORY", krb5_cc_get_type(context, id)) != 0) {
        krb5_boolean enabled;

        krb5_appdefault_boolean(context, NULL, NULL, "enable_kx509", FALSE,
                                &enabled);
        if (enabled) {
            _krb5_debug(context, 2, "attempting to fetch a certificate using "
                        "kx509");
            ret = krb5_kx509(context, id, NULL);
            if (ret)
                _krb5_debug(context, 2, "failed to fetch a certificate");
            else
                _krb5_debug(context, 2, "fetched a certificate");
        }
    }

    ret = (*id->ops->close)(context, id);
    free(id);
    return ret;
}

/**
 * Store `creds' in the ccache `id'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_store_cred(krb5_context context,
		   krb5_ccache id,
		   krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_data realm;
    const char *cfg = "";

    /* Automatic cc_config-setting and other actions */
    if (krb5_principal_get_num_comp(context, creds->server) > 1 &&
        krb5_is_config_principal(context, creds->server))
        cfg = krb5_principal_get_comp_string(context, creds->server, 1);

    if (id->cc_initialized && !id->cc_need_start_realm &&
        strcmp(cfg, "start_realm") == 0)
        return 0;

    ret = (*id->ops->store)(context, id, creds);
    if (ret)
        return ret;

    if (id->cc_initialized && !id->cc_start_tgt_stored &&
        id->cc_need_start_realm &&
        krb5_principal_is_root_krbtgt(context, creds->server)) {
        /* Mark the first root TGT's realm as the start realm */
        id->cc_start_tgt_stored = 1;
        realm.length = strlen(creds->server->realm);
        realm.data = creds->server->realm;
        (void) krb5_cc_set_config(context, id, NULL, "start_realm", &realm);
        id->cc_need_start_realm = 0;
    } else if (id->cc_initialized && id->cc_start_tgt_stored &&
               !id->cc_kx509_done && strcmp(cfg, "kx509cert") == 0) {
        /*
         * Do not attempt kx509 at cc close time -- we're copying a ccache and
         * we've already got a cert (and private key).
         */
        id->cc_kx509_done = 1;
    } else if (id->cc_initialized && id->cc_start_tgt_stored &&
               !id->cc_kx509_done && strcmp(cfg, "kx509_service_status") == 0) {
        /*
         * Do not attempt kx509 at cc close time -- we're copying a ccache and
         * we know the kx509 service is not available.
         */
        id->cc_kx509_done = 1;
    } else if (id->cc_initialized && strcmp(cfg, "start_realm") == 0) {
        /*
         * If the caller is storing a start_realm ccconfig, then stop looking
         * for root TGTs to mark as the start_realm.
         *
         * By honoring any start_realm cc config stored, we interop both, with
         * ccache implementations that don't preserve insertion order, and
         * Kerberos implementations that store this cc config before the TGT.
         */
        id->cc_need_start_realm = 0;
    }
    return ret;
}

/**
 * Retrieve the credential identified by `mcreds' (and `whichfields')
 * from `id' in `creds'. 'creds' must be free by the caller using
 * krb5_free_cred_contents.
 *
 * @param context A Kerberos 5 context
 * @param id a Kerberos 5 credential cache
 * @param whichfields what fields to use for matching credentials, same
 *        flags as whichfields in krb5_compare_creds()
 * @param mcreds template credential to use for comparing
 * @param creds returned credential, free with krb5_free_cred_contents()
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_retrieve_cred(krb5_context context,
		      krb5_ccache id,
		      krb5_flags whichfields,
		      const krb5_creds *mcreds,
		      krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_cc_cursor cursor;

    if (id->ops->retrieve != NULL) {
	return (*id->ops->retrieve)(context, id, whichfields,
				    mcreds, creds);
    }

    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret)
	return ret;
    while((ret = krb5_cc_next_cred(context, id, &cursor, creds)) == 0){
	if(krb5_compare_creds(context, whichfields, mcreds, creds)){
	    ret = 0;
	    break;
	}
	krb5_free_cred_contents (context, creds);
    }
    krb5_cc_end_seq_get(context, id, &cursor);
    return ret;
}

/**
 * Return the principal of `id' in `principal'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_principal(krb5_context context,
		      krb5_ccache id,
		      krb5_principal *principal)
{
    return (*id->ops->get_princ)(context, id, principal);
}

/**
 * Start iterating over `id', `cursor' is initialized to the
 * beginning.  Caller must free the cursor with krb5_cc_end_seq_get().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_start_seq_get (krb5_context context,
		       const krb5_ccache id,
		       krb5_cc_cursor *cursor)
{
    return (*id->ops->get_first)(context, id, cursor);
}

/**
 * Retrieve the next cred pointed to by (`id', `cursor') in `creds'
 * and advance `cursor'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_next_cred (krb5_context context,
		   const krb5_ccache id,
		   krb5_cc_cursor *cursor,
		   krb5_creds *creds)
{
    return (*id->ops->get_next)(context, id, cursor, creds);
}

/**
 * Destroy the cursor `cursor'.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_end_seq_get (krb5_context context,
		     const krb5_ccache id,
		     krb5_cc_cursor *cursor)
{
    return (*id->ops->end_get)(context, id, cursor);
}

/**
 * Remove the credential identified by `cred', `which' from `id'.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_remove_cred(krb5_context context,
		    krb5_ccache id,
		    krb5_flags which,
		    krb5_creds *cred)
{
    if(id->ops->remove_cred == NULL) {
	krb5_set_error_message(context,
			       EACCES,
			       "ccache %s does not support remove_cred",
			       id->ops->prefix);
	return EACCES; /* XXX */
    }
    return (*id->ops->remove_cred)(context, id, which, cred);
}

/**
 * Set the flags of `id' to `flags'.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_flags(krb5_context context,
		  krb5_ccache id,
		  krb5_flags flags)
{
    return (*id->ops->set_flags)(context, id, flags);
}

/**
 * Get the flags of `id', store them in `flags'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_flags(krb5_context context,
		  krb5_ccache id,
		  krb5_flags *flags)
{
    *flags = 0;
    return 0;
}

/**
 * Copy the contents of `from' to `to' if the given match function
 * return true.
 *
 * @param context A Kerberos 5 context.
 * @param from the cache to copy data from.
 * @param to the cache to copy data to.
 * @param match a match function that should return TRUE if cred argument should be copied, if NULL, all credentials are copied.
 * @param matchctx context passed to match function.
 * @param matched set to true if there was a credential that matched, may be NULL.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_copy_match_f(krb5_context context,
		     const krb5_ccache from,
		     krb5_ccache to,
		     krb5_boolean (*match)(krb5_context, void *, const krb5_creds *),
		     void *matchctx,
		     unsigned int *matched)
{
    krb5_error_code ret;
    krb5_cc_cursor cursor;
    krb5_creds cred;
    krb5_principal princ;

    if (matched)
	*matched = 0;

    ret = krb5_cc_get_principal(context, from, &princ);
    if (ret)
	return ret;
    ret = krb5_cc_initialize(context, to, princ);
    if (ret) {
	krb5_free_principal(context, princ);
	return ret;
    }
    ret = krb5_cc_start_seq_get(context, from, &cursor);
    if (ret) {
	krb5_free_principal(context, princ);
	return ret;
    }

    while ((ret = krb5_cc_next_cred(context, from, &cursor, &cred)) == 0) {
	   if (match == NULL || (*match)(context, matchctx, &cred)) {
	       if (matched)
		   (*matched)++;
	       ret = krb5_cc_store_cred(context, to, &cred);
	       if (ret)
		   break;
	   }
	   krb5_free_cred_contents(context, &cred);
    }
    krb5_cc_end_seq_get(context, from, &cursor);
    krb5_free_principal(context, princ);
    if (ret == KRB5_CC_END)
	ret = 0;
    return ret;
}

/**
 * Just like krb5_cc_copy_match_f(), but copy everything.
 *
 * @ingroup @krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_copy_cache(krb5_context context,
		   const krb5_ccache from,
		   krb5_ccache to)
{
    return krb5_cc_copy_match_f(context, from, to, NULL, NULL, NULL);
}

/**
 * Return the version of `id'.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_version(krb5_context context,
		    const krb5_ccache id)
{
    if(id->ops->get_version)
	return (*id->ops->get_version)(context, id);
    else
	return 0;
}

/**
 * Clear `mcreds' so it can be used with krb5_cc_retrieve_cred
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_cc_clear_mcred(krb5_creds *mcred)
{
    memset(mcred, 0, sizeof(*mcred));
}

/**
 * Get the cc ops that is registered in `context' to handle the
 * prefix. prefix can be a complete credential cache name or a
 * prefix, the function will only use part up to the first colon (:)
 * if there is one. If prefix the argument is NULL, the default ccache
 * implemtation is returned.
 *
 * @return Returns NULL if ops not found.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION const krb5_cc_ops * KRB5_LIB_CALL
krb5_cc_get_prefix_ops(krb5_context context, const char *prefix)
{
    return cc_get_prefix_ops(context, prefix, NULL);
}

/**
 * Get the cc ops that is registered in `context' to handle the
 * prefix. prefix can be a complete credential cache name or a
 * prefix, the function will only use part up to the first colon (:)
 * if there is one. If prefix the argument is NULL, the default ccache
 * implementation is returned.
 *
 * If residual is non-NULL, it is set to the residual component of
 * prefix (if present) or the prefix itself.
 *
 * @return Returns NULL if ops not found.
 *
 * @ingroup krb5_ccache
 */


static const krb5_cc_ops *
cc_get_prefix_ops(krb5_context context,
		  const char *prefix,
		  const char **residual)
{
    int i;

    if (residual)
	*residual = prefix;

    if (prefix == NULL)
	return KRB5_DEFAULT_CCTYPE;

    /* Is absolute path? Or UNC path? */
    if (ISPATHSEP(prefix[0]))
	return &krb5_fcc_ops;

#ifdef _WIN32
    /* Is drive letter? */
    if (isalpha((unsigned char)prefix[0]) && prefix[1] == ':')
	return &krb5_fcc_ops;
#endif

    for(i = 0; i < context->num_cc_ops && context->cc_ops[i]->prefix; i++) {
	size_t prefix_len = strlen(context->cc_ops[i]->prefix);

	if (strncmp(context->cc_ops[i]->prefix, prefix, prefix_len) == 0 &&
	    (prefix[prefix_len] == ':' || prefix[prefix_len] == '\0')) {
	    if (residual) {
		if (prefix[prefix_len] == ':' && prefix[prefix_len + 1] != '\0')
		    *residual = &prefix[prefix_len + 1];
		else
		    *residual = NULL;
	    }

	    return context->cc_ops[i];
	}
    }

    return NULL;
}

struct krb5_cc_cache_cursor_data {
    const krb5_cc_ops *ops;
    krb5_cc_cursor cursor;
};

/**
 * Start iterating over all caches of specified type. See also
 * krb5_cccol_cursor_new().

 * @param context A Kerberos 5 context
 * @param type optional type to iterate over, if NULL, the default cache is used.
 * @param cursor cursor should be freed with krb5_cc_cache_end_seq_get().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_cache_get_first (krb5_context context,
			 const char *type,
			 krb5_cc_cache_cursor *cursor)
{
    const krb5_cc_ops *ops;
    krb5_error_code ret;

    if (type == NULL)
	type = krb5_cc_default_name(context);

    ops = krb5_cc_get_prefix_ops(context, type);
    if (ops == NULL) {
	krb5_set_error_message(context, KRB5_CC_UNKNOWN_TYPE,
			       "Unknown type \"%s\" when iterating "
			       "trying to iterate the credential caches", type);
	return KRB5_CC_UNKNOWN_TYPE;
    }

    if (ops->get_cache_first == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOSUPP,
			       N_("Credential cache type %s doesn't support "
				 "iterations over caches", "type"),
			       ops->prefix);
	return KRB5_CC_NOSUPP;
    }

    *cursor = calloc(1, sizeof(**cursor));
    if (*cursor == NULL)
	return krb5_enomem(context);

    (*cursor)->ops = ops;

    ret = ops->get_cache_first(context, &(*cursor)->cursor);
    if (ret) {
	free(*cursor);
	*cursor = NULL;
    }
    return ret;
}

/**
 * Retrieve the next cache pointed to by (`cursor') in `id'
 * and advance `cursor'.
 *
 * @param context A Kerberos 5 context
 * @param cursor the iterator cursor, returned by krb5_cc_cache_get_first()
 * @param id next ccache
 *
 * @return Return 0 or an error code. Returns KRB5_CC_END when the end
 *         of caches is reached, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_cache_next (krb5_context context,
		   krb5_cc_cache_cursor cursor,
		   krb5_ccache *id)
{
    return cursor->ops->get_cache_next(context, cursor->cursor, id);
}

/**
 * Destroy the cursor `cursor'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_cache_end_seq_get (krb5_context context,
			   krb5_cc_cache_cursor cursor)
{
    krb5_error_code ret;
    ret = cursor->ops->end_cache_get(context, cursor->cursor);
    cursor->ops = NULL;
    free(cursor);
    return ret;
}

/**
 * Search for a matching credential cache that have the
 * `principal' as the default principal. On success, `id' needs to be
 * freed with krb5_cc_close() or krb5_cc_destroy().
 *
 * @param context A Kerberos 5 context
 * @param client The principal to search for
 * @param id the returned credential cache
 *
 * @return On failure, error code is returned and `id' is set to NULL.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_cache_match (krb5_context context,
		     krb5_principal client,
		     krb5_ccache *id)
{
    krb5_cccol_cursor cursor;
    krb5_error_code ret;
    krb5_ccache cache = NULL;
    krb5_ccache expired_match = NULL;

    *id = NULL;

    ret = krb5_cccol_cursor_new (context, &cursor);
    if (ret)
	return ret;

    while (krb5_cccol_cursor_next(context, cursor, &cache) == 0 && cache != NULL) {
	krb5_principal principal;
	krb5_boolean match;
	time_t lifetime;

	ret = krb5_cc_get_principal(context, cache, &principal);
	if (ret)
	    goto next;

	if (client->name.name_string.len == 0)
	    match = (strcmp(client->realm, principal->realm) == 0);
	else
	    match = krb5_principal_compare(context, principal, client);
	krb5_free_principal(context, principal);

	if (!match)
	    goto next;

	if (expired_match == NULL &&
	    (krb5_cc_get_lifetime(context, cache, &lifetime) != 0 || lifetime == 0)) {
	    expired_match = cache;
	    cache = NULL;
	    goto next;
	}
	break;

    next:
        if (cache)
	    krb5_cc_close(context, cache);
	cache = NULL;
    }

    krb5_cccol_cursor_free(context, &cursor);

    if (cache == NULL && expired_match) {
	cache = expired_match;
	expired_match = NULL;
    } else if (expired_match) {
	krb5_cc_close(context, expired_match);
    } else if (cache == NULL) {
	char *str;

	(void) krb5_unparse_name(context, client, &str);
	krb5_set_error_message(context, KRB5_CC_NOTFOUND,
			       N_("Principal %s not found in any "
				  "credential cache", ""),
			       str ? str : "<out of memory>");
	if (str)
	    free(str);
	return KRB5_CC_NOTFOUND;
    }

    *id = cache;

    return 0;
}

/**
 * Move the content from one credential cache to another. The
 * operation is an atomic switch.
 *
 * @param context a Kerberos context
 * @param from the credential cache to move the content from
 * @param to the credential cache to move the content to

 * @return On sucess, from is destroyed and closed. On failure, error code is
 *         returned and from and to are both still allocated; see
 *         krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_error_code ret = ENOTSUP;
    krb5_principal princ = NULL;

    if (to->ops->move &&
        strcmp(from->ops->prefix, to->ops->prefix) == 0) {
        /*
         * NOTE: to->ops->move() is expected to call
         *       krb5_cc_destroy(context, from) on success.
         */
        ret = (*to->ops->move)(context, from, to);
        if (ret == 0)
            return 0;
        if (ret != EXDEV && ret != ENOTSUP && ret != KRB5_CC_NOSUPP &&
            ret != KRB5_FCC_INTERNAL)
            return ret;
        /* Fallback to high-level copy */
    }   /* Else        high-level copy */

    /*
     * Initialize destination, copy the source's contents to the destination,
     * then destroy the source on success.
     *
     * It'd be nice if we could destroy any half-built destination if the copy
     * fails, but the interface is not documented as doing so.
     */
    ret = krb5_cc_get_principal(context, from, &princ);
    if (ret == 0)
        ret = krb5_cc_initialize(context, to, princ);
    krb5_free_principal(context, princ);
    if (ret == 0)
        ret = krb5_cc_copy_cache(context, from, to);
    if (ret == 0)
        krb5_cc_destroy(context, from);
    return ret;
}

#define KRB5_CONF_NAME "krb5_ccache_conf_data"
#define KRB5_REALM_NAME "X-CACHECONF:"

static krb5_error_code
build_conf_principals(krb5_context context, krb5_ccache id,
		      krb5_const_principal principal,
		      const char *name, krb5_creds *cred)
{
    krb5_principal client;
    krb5_error_code ret;
    char *pname = NULL;

    memset(cred, 0, sizeof(*cred));

    ret = krb5_cc_get_principal(context, id, &client);
    if (ret)
	return ret;

    if (principal) {
	ret = krb5_unparse_name(context, principal, &pname);
	if (ret)
	    return ret;
    }

    ret = krb5_make_principal(context, &cred->server,
			      KRB5_REALM_NAME,
			      KRB5_CONF_NAME, name, pname, NULL);
    free(pname);
    if (ret) {
	krb5_free_principal(context, client);
	return ret;
    }
    ret = krb5_copy_principal(context, client, &cred->client);
    krb5_free_principal(context, client);
    return ret;
}

/**
 * Return TRUE (non zero) if the principal is a configuration
 * principal (generated part of krb5_cc_set_config()). Returns FALSE
 * (zero) if not a configuration principal.
 *
 * @param context a Kerberos context
 * @param principal principal to check if it a configuration principal
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_is_config_principal(krb5_context context,
			 krb5_const_principal principal)
{
    if (strcmp(principal->realm, KRB5_REALM_NAME) != 0)
	return FALSE;

    if (principal->name.name_string.len == 0 ||
	strcmp(principal->name.name_string.val[0], KRB5_CONF_NAME) != 0)
	return FALSE;

    return TRUE;
}

/**
 * Store some configuration for the credential cache in the cache.
 * Existing configuration under the same name is over-written.
 *
 * @param context a Kerberos context
 * @param id the credential cache to store the data for
 * @param principal configuration for a specific principal, if
 * NULL, global for the whole cache.
 * @param name name under which the configuraion is stored.
 * @param data data to store, if NULL, configure is removed.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_config(krb5_context context, krb5_ccache id,
		   krb5_const_principal principal,
		   const char *name, krb5_data *data)
{
    krb5_error_code ret;
    krb5_creds cred;

    ret = build_conf_principals(context, id, principal, name, &cred);
    if (ret)
	goto out;

    /* Remove old configuration */
    ret = krb5_cc_remove_cred(context, id, 0, &cred);
    if (ret && ret != KRB5_CC_NOTFOUND && ret != KRB5_CC_NOSUPP &&
        ret != KRB5_FCC_INTERNAL)
        goto out;

    if (data) {
	/* not that anyone care when this expire */
	cred.times.authtime = time(NULL);
	cred.times.endtime = cred.times.authtime + 3600 * 24 * 30;

	ret = krb5_data_copy(&cred.ticket, data->data, data->length);
	if (ret)
	    goto out;

	ret = krb5_cc_store_cred(context, id, &cred);
    }

out:
    krb5_free_cred_contents (context, &cred);
    return ret;
}

/**
 * Get some configuration for the credential cache in the cache.
 *
 * @param context a Kerberos context
 * @param id the credential cache to store the data for
 * @param principal configuration for a specific principal, if
 * NULL, global for the whole cache.
 * @param name name under which the configuraion is stored.
 * @param data data to fetched, free with krb5_data_free()
 * @return 0 on success, KRB5_CC_NOTFOUND or KRB5_CC_END if not found,
 *           or other system error.
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_config(krb5_context context, krb5_ccache id,
		   krb5_const_principal principal,
		   const char *name, krb5_data *data)
{
    krb5_creds mcred, cred;
    krb5_error_code ret;

    memset(&cred, 0, sizeof(cred));
    krb5_data_zero(data);

    ret = build_conf_principals(context, id, principal, name, &mcred);
    if (ret)
	goto out;

    ret = krb5_cc_retrieve_cred(context, id, 0, &mcred, &cred);
    if (ret)
	goto out;

    ret = krb5_data_copy(data, cred.ticket.data, cred.ticket.length);

out:
    krb5_free_cred_contents (context, &cred);
    krb5_free_cred_contents (context, &mcred);
    return ret;
}

/*
 *
 */

struct krb5_cccol_cursor_data {
    int idx;
    krb5_cc_cache_cursor cursor;
};

/**
 * Get a new cache interation cursor that will interate over all
 * credentials caches independent of type.
 *
 * @param context a Kerberos context
 * @param cursor passed into krb5_cccol_cursor_next() and free with krb5_cccol_cursor_free().
 *
 * @return Returns 0 or and error code, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cccol_cursor_new(krb5_context context, krb5_cccol_cursor *cursor)
{
    *cursor = calloc(1, sizeof(**cursor));
    if (*cursor == NULL)
	return krb5_enomem(context);
    (*cursor)->idx = 0;
    (*cursor)->cursor = NULL;

    return 0;
}

/**
 * Get next credential cache from the iteration.
 *
 * @param context A Kerberos 5 context
 * @param cursor the iteration cursor
 * @param cache the returned cursor, pointer is set to NULL on failure
 *        and a cache on success. The returned cache needs to be freed
 *        with krb5_cc_close() or destroyed with krb5_cc_destroy().
 *        MIT Kerberos behavies slightly diffrent and sets cache to NULL
 *        when all caches are iterated over and return 0.
 *
 * @return Return 0 or and error, KRB5_CC_END is returned at the end
 *        of iteration. See krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cccol_cursor_next(krb5_context context, krb5_cccol_cursor cursor,
		       krb5_ccache *cache)
{
    krb5_error_code ret = 0;

    *cache = NULL;

    while (cursor->idx < context->num_cc_ops) {

	if (cursor->cursor == NULL) {
	    ret = krb5_cc_cache_get_first (context,
					   context->cc_ops[cursor->idx]->prefix,
					   &cursor->cursor);
	    if (ret) {
		cursor->idx++;
		continue;
	    }
	}
	ret = krb5_cc_cache_next(context, cursor->cursor, cache);
	if (ret == 0)
	    break;

	krb5_cc_cache_end_seq_get(context, cursor->cursor);
	cursor->cursor = NULL;
	if (ret != KRB5_CC_END)
	    break;

	cursor->idx++;
    }
    if (cursor->idx >= context->num_cc_ops) {
	krb5_set_error_message(context, KRB5_CC_END,
			       N_("Reached end of credential caches", ""));
	return KRB5_CC_END;
    }

    return ret;
}

/**
 * End an iteration and free all resources, can be done before end is reached.
 *
 * @param context A Kerberos 5 context
 * @param cursor the iteration cursor to be freed.
 *
 * @return Return 0 or and error, KRB5_CC_END is returned at the end
 *        of iteration. See krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cccol_cursor_free(krb5_context context, krb5_cccol_cursor *cursor)
{
    krb5_cccol_cursor c = *cursor;

    *cursor = NULL;
    if (c) {
	if (c->cursor)
	    krb5_cc_cache_end_seq_get(context, c->cursor);
	free(c);
    }
    return 0;
}

/**
 * Return the last time the credential cache was modified.
 *
 * @param context A Kerberos 5 context
 * @param id The credential cache to probe
 * @param mtime the last modification time, set to 0 on error.

 * @return Return 0 or and error. See krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_last_change_time(krb5_context context,
			 krb5_ccache id,
			 krb5_timestamp *mtime)
{
    *mtime = 0;

    if (id->ops->version < KRB5_CC_OPS_VERSION_2
	 || id->ops->lastchange == NULL)
	return KRB5_CC_NOSUPP;

    return (*id->ops->lastchange)(context, id, mtime);
}

/**
 * Return the last modfication time for a cache collection. The query
 * can be limited to a specific cache type. If the function return 0
 * and mtime is 0, there was no credentials in the caches.
 *
 * @param context A Kerberos 5 context
 * @param type The credential cache to probe, if NULL, all type are traversed.
 * @param mtime the last modification time, set to 0 on error.

 * @return Return 0 or and error. See krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cccol_last_change_time(krb5_context context,
			    const char *type,
			    krb5_timestamp *mtime)
{
    krb5_cccol_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;
    krb5_timestamp t = 0;

    *mtime = 0;

    ret = krb5_cccol_cursor_new (context, &cursor);
    if (ret)
	return ret;

    while (krb5_cccol_cursor_next(context, cursor, &id) == 0 && id != NULL) {

	if (type && strcmp(krb5_cc_get_type(context, id), type) != 0)
	    continue;

	ret = krb5_cc_last_change_time(context, id, &t);
	krb5_cc_close(context, id);
	if (ret)
	    continue;
	if (t > *mtime)
	    *mtime = t;
    }

    krb5_cccol_cursor_free(context, &cursor);

    return 0;
}
/**
 * Return a friendly name on credential cache. Free the result with krb5_xfree().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_friendly_name(krb5_context context,
			  krb5_ccache id,
			  char **name)
{
    krb5_error_code ret;
    krb5_data data;

    ret = krb5_cc_get_config(context, id, NULL, "FriendlyName", &data);
    if (ret) {
	krb5_principal principal;
	ret = krb5_cc_get_principal(context, id, &principal);
	if (ret)
	    return ret;
	ret = krb5_unparse_name(context, principal, name);
	krb5_free_principal(context, principal);
    } else {
	ret = asprintf(name, "%.*s", (int)data.length, (char *)data.data);
	krb5_data_free(&data);
	if (ret <= 0)
	    ret = krb5_enomem(context);
	else
	    ret = 0;
    }

    return ret;
}

/**
 * Set the friendly name on credential cache.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_friendly_name(krb5_context context,
			  krb5_ccache id,
			  const char *name)
{
    krb5_data data;

    data.data = rk_UNCONST(name);
    data.length = strlen(name);

    return krb5_cc_set_config(context, id, NULL, "FriendlyName", &data);
}

/**
 * Get the lifetime of the initial ticket in the cache
 *
 * Get the lifetime of the initial ticket in the cache, if the initial
 * ticket was not found, the error code KRB5_CC_END is returned.
 *
 * @param context A Kerberos 5 context.
 * @param id a credential cache
 * @param t the relative lifetime of the initial ticket
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_lifetime(krb5_context context, krb5_ccache id, time_t *t)
{
    krb5_data config_start_realm;
    char *start_realm;
    krb5_cc_cursor cursor;
    krb5_error_code ret;
    krb5_creds cred;
    time_t now, endtime = 0;

    *t = 0;
    krb5_timeofday(context, &now);

    ret = krb5_cc_get_config(context, id, NULL, "start_realm", &config_start_realm);
    if (ret == 0) {
	start_realm = strndup(config_start_realm.data, config_start_realm.length);
	krb5_data_free(&config_start_realm);
    } else {
	krb5_principal client;

	ret = krb5_cc_get_principal(context, id, &client);
	if (ret)
	    return ret;
	start_realm = strdup(krb5_principal_get_realm(context, client));
	krb5_free_principal(context, client);
    }
    if (start_realm == NULL)
	return krb5_enomem(context);

    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret) {
        free(start_realm);
	return ret;
    }

    while ((ret = krb5_cc_next_cred(context, id, &cursor, &cred)) == 0) {
	/**
	 * If we find the start krbtgt in the cache, use that as the lifespan.
	 */
	if (krb5_principal_is_root_krbtgt(context, cred.server) &&
	    strcmp(cred.server->realm, start_realm) == 0) {
	    if (now < cred.times.endtime)
		endtime = cred.times.endtime;
	    krb5_free_cred_contents(context, &cred);
	    break;
	}
	/*
	 * Skip config entries
	 */
	if (krb5_is_config_principal(context, cred.server)) {
	    krb5_free_cred_contents(context, &cred);
	    continue;
	}
	/**
	 * If there was no krbtgt, use the shortest lifetime of
	 * service tickets that have yet to expire.  If all
	 * credentials are expired, krb5_cc_get_lifetime() will fail.
	 */
	if ((endtime == 0 || cred.times.endtime < endtime) && now < cred.times.endtime)
	    endtime = cred.times.endtime;
	krb5_free_cred_contents(context, &cred);
    }
    free(start_realm);

    /* if we found an endtime use that */
    if (endtime) {
	*t = endtime - now;
	ret = 0;
    }

    krb5_cc_end_seq_get(context, id, &cursor);

    return ret;
}

/**
 * Set the time offset betwen the client and the KDC
 *
 * If the backend doesn't support KDC offset, use the context global setting.
 *
 * @param context A Kerberos 5 context.
 * @param id a credential cache
 * @param offset the offset in seconds
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat offset)
{
    if (id->ops->version < KRB5_CC_OPS_VERSION_3
	|| id->ops->set_kdc_offset == NULL) {
	context->kdc_sec_offset = offset;
	context->kdc_usec_offset = 0;
	return 0;
    }
    return (*id->ops->set_kdc_offset)(context, id, offset);
}

/**
 * Get the time offset betwen the client and the KDC
 *
 * If the backend doesn't support KDC offset, use the context global setting.
 *
 * @param context A Kerberos 5 context.
 * @param id a credential cache
 * @param offset the offset in seconds
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat *offset)
{
    if (id->ops->version < KRB5_CC_OPS_VERSION_3
	|| id->ops->get_kdc_offset == NULL) {
	*offset = context->kdc_sec_offset;
	return 0;
    }
    return (*id->ops->get_kdc_offset)(context, id, offset);
}

#ifdef _WIN32
#define REGPATH_MIT_KRB5 "SOFTWARE\\MIT\\Kerberos5"

static char *
_get_default_cc_name_from_registry(krb5_context context, HKEY hkBase)
{
    HKEY hk_k5 = 0;
    LONG code;
    char *ccname = NULL;

    code = RegOpenKeyEx(hkBase,
                        REGPATH_MIT_KRB5,
                        0, KEY_READ, &hk_k5);

    if (code != ERROR_SUCCESS)
        return NULL;

    ccname = heim_parse_reg_value_as_string(context->hcontext, hk_k5, "ccname",
                                            REG_NONE, 0);

    RegCloseKey(hk_k5);

    return ccname;
}

KRB5_LIB_FUNCTION char * KRB5_LIB_CALL
_krb5_get_default_cc_name_from_registry(krb5_context context)
{
    char *ccname;

    ccname = _get_default_cc_name_from_registry(context, HKEY_CURRENT_USER);
    if (ccname == NULL)
	ccname = _get_default_cc_name_from_registry(context,
						    HKEY_LOCAL_MACHINE);

    return ccname;
}

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_set_default_cc_name_to_registry(krb5_context context, krb5_ccache id)
{
    HKEY hk_k5 = 0;
    LONG code;
    int ret = -1;
    char * ccname = NULL;

    code = RegOpenKeyEx(HKEY_CURRENT_USER,
                        REGPATH_MIT_KRB5,
                        0, KEY_READ|KEY_WRITE, &hk_k5);

    if (code != ERROR_SUCCESS)
        return -1;

    ret = asprintf(&ccname, "%s:%s", krb5_cc_get_type(context, id), krb5_cc_get_name(context, id));
    if (ret < 0)
        goto cleanup;

    ret = heim_store_string_to_reg_value(context->hcontext, hk_k5, "ccname",
                                         REG_SZ, ccname, -1, 0);

  cleanup:

    if (ccname)
        free(ccname);

    RegCloseKey(hk_k5);

    return ret;
}
#endif
