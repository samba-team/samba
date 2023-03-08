/*
 * Copyright (c) 2020 Kungliga Tekniska Högskolan
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
#define __attribute__(X)

heim_context
heim_context_init(void)
{
    heim_context context;

    if ((context = calloc(1, sizeof(*context))) == NULL)
        return NULL;

    context->homedir_access = !issuid();
    context->log_utc = 1;
    context->error_string = NULL;
    context->debug_dest = NULL;
    context->warn_dest = NULL;
    context->log_dest = NULL;
    context->time_fmt = NULL;
    context->et_list = NULL;
    return context;
}

void
heim_context_free(heim_context *contextp)
{
    heim_context context = *contextp;

    *contextp = NULL;
    if (!context)
        return;
    heim_closelog(context, context->debug_dest);
    heim_closelog(context, context->warn_dest);
    heim_closelog(context, context->log_dest);
    free_error_table(context->et_list);
    free(context->time_fmt);
    free(context->error_string);
    free(context);
}

heim_error_code
heim_add_et_list(heim_context context, void (*func)(struct et_list **))
{
    (*func)(&context->et_list);
    return 0;
}

heim_error_code
heim_context_set_time_fmt(heim_context context, const char *fmt)
{
    char *s;

    if (fmt == NULL) {
        free(context->time_fmt);
        return 0;
    }
    if ((s = strdup(fmt)) == NULL)
        return heim_enomem(context);
    free(context->time_fmt);
    context->time_fmt = s;
    return 0;
}

const char *
heim_context_get_time_fmt(heim_context context)
{
    return context->time_fmt ? context->time_fmt : "%Y-%m-%dT%H:%M:%S";
}

unsigned int
heim_context_set_log_utc(heim_context context, unsigned int log_utc)
{
    unsigned int old = context->log_utc;

    context->log_utc = log_utc ? 1 : 0;
    return old;
}

int
heim_context_get_log_utc(heim_context context)
{
    return context->log_utc;
}

unsigned int
heim_context_set_homedir_access(heim_context context, unsigned int homedir_access)
{
    unsigned int old = context->homedir_access;

    context->homedir_access = homedir_access ? 1 : 0;
    return old;
}

unsigned int
heim_context_get_homedir_access(heim_context context)
{
    return context->homedir_access;
}

heim_error_code
heim_enomem(heim_context context)
{
    heim_set_error_message(context, ENOMEM, "malloc: out of memory");
    return ENOMEM;
}

heim_log_facility *
heim_get_log_dest(heim_context context)
{
    return context->log_dest;
}

heim_log_facility *
heim_get_warn_dest(heim_context context)
{
    return context->warn_dest;
}

heim_log_facility *
heim_get_debug_dest(heim_context context)
{
    return context->debug_dest;
}

heim_error_code
heim_set_log_dest(heim_context context, heim_log_facility *fac)
{
    context->log_dest = heim_log_ref(fac);
    return 0;
}

heim_error_code
heim_set_warn_dest(heim_context context, heim_log_facility *fac)
{
    context->warn_dest = fac;
    return 0;
}

heim_error_code
heim_set_debug_dest(heim_context context, heim_log_facility *fac)
{
    context->debug_dest = fac;
    return 0;
}

#ifndef PATH_SEP
# define PATH_SEP ":"
#endif

static heim_error_code
add_file(char ***pfilenames, int *len, char *file)
{
    char **pp = *pfilenames;
    int i;

    for(i = 0; i < *len; i++) {
        if(strcmp(pp[i], file) == 0) {
            free(file);
            return 0;
        }
    }

    pp = realloc(*pfilenames, (*len + 2) * sizeof(*pp));
    if (pp == NULL) {
        free(file);
        return ENOMEM;
    }

    pp[*len] = file;
    pp[*len + 1] = NULL;
    *pfilenames = pp;
    *len += 1;
    return 0;
}

#ifdef WIN32
static char *
get_default_config_config_files_from_registry(const char *envvar)
{
    static const char *KeyName = "Software\\Heimdal"; /* XXX #define this */
    const char *ValueName;
    char *config_file = NULL;
    LONG rcode;
    HKEY key;

    if (stricmp(envvar, "KRB5_CONFIG") == 0)
	ValueName = "config";
    else
	ValueName = envvar;

    rcode = RegOpenKeyEx(HKEY_CURRENT_USER, KeyName, 0, KEY_READ, &key);
    if (rcode == ERROR_SUCCESS) {
	config_file = heim_parse_reg_value_as_multi_string(NULL, key, ValueName,
                                                           REG_NONE, 0, PATH_SEP);
        RegCloseKey(key);
    }

    if (config_file)
        return config_file;

    rcode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &key);
    if (rcode == ERROR_SUCCESS) {
	config_file = heim_parse_reg_value_as_multi_string(NULL, key, ValueName,
                                                           REG_NONE, 0, PATH_SEP);
        RegCloseKey(key);
    }

    return config_file;
}
#endif

heim_error_code
heim_prepend_config_files(const char *filelist,
                          char **pq,
                          char ***ret_pp)
{
    heim_error_code ret;
    const char *p, *q;
    char **pp;
    int len;
    char *fn;

    pp = NULL;

    len = 0;
    p = filelist;
    while(1) {
        ssize_t l;
        q = p;
        l = strsep_copy(&q, PATH_SEP, NULL, 0);
        if(l == -1)
            break;
        fn = malloc(l + 1);
        if(fn == NULL) {
            heim_free_config_files(pp);
            return ENOMEM;
        }
        (void) strsep_copy(&p, PATH_SEP, fn, l + 1);
        ret = add_file(&pp, &len, fn);
        if (ret) {
            heim_free_config_files(pp);
            return ret;
        }
    }

    if (pq != NULL) {
        int i;

        for (i = 0; pq[i] != NULL; i++) {
            fn = strdup(pq[i]);
            if (fn == NULL) {
                heim_free_config_files(pp);
                return ENOMEM;
            }
            ret = add_file(&pp, &len, fn);
            if (ret) {
                heim_free_config_files(pp);
                return ret;
            }
        }
    }

    *ret_pp = pp;
    return 0;
}

heim_error_code
heim_prepend_config_files_default(const char *prepend,
                                  const char *def,
                                  const char *envvar,
                                  char ***pfilenames)
{
    heim_error_code ret;
    char **defpp, **pp = NULL;

    ret = heim_get_default_config_files(def, envvar, &defpp);
    if (ret)
        return ret;

    ret = heim_prepend_config_files(prepend, defpp, &pp);
    heim_free_config_files(defpp);
    if (ret) {
        return ret;
    }
    *pfilenames = pp;
    return 0;
}

heim_error_code
heim_get_default_config_files(const char *def,
                              const char *envvar,
                              char ***pfilenames)
{
    const char *files = NULL;

    files = secure_getenv(envvar);

#ifdef _WIN32
    if (files == NULL) {
        char * reg_files;
	reg_files = get_default_config_config_files_from_registry(envvar);
        if (reg_files != NULL) {
            heim_error_code code;

            code = heim_prepend_config_files(reg_files, NULL, pfilenames);
            free(reg_files);

            return code;
        }
    }
#endif

    if (files == NULL)
        files = def;
    return heim_prepend_config_files(files, NULL, pfilenames);
}

#ifdef _WIN32
#define REGPATH_KERBEROS "SOFTWARE\\Kerberos"
#define REGPATH_HEIMDAL  "SOFTWARE\\Heimdal"
#endif

heim_error_code
heim_set_config_files(heim_context context, char **filenames,
                      heim_config_binding **res)
{
    heim_error_code ret = 0;

    *res = NULL;
    while (filenames != NULL && *filenames != NULL && **filenames != '\0') {
        ret = heim_config_parse_file_multi(context, *filenames, res);
        if (ret != 0 && ret != ENOENT && ret != EACCES && ret != EPERM
            && ret != HEIM_ERR_CONFIG_BADFORMAT) {
            heim_config_file_free(context, *res);
            *res = NULL;
            return ret;
        }
        filenames++;
    }

#ifdef _WIN32
    /*
     * We always ignored errors from loading from the registry, so we still do.
     */
    heim_load_config_from_registry(context, REGPATH_KERBEROS,
                                   REGPATH_HEIMDAL, res);

#endif
    return 0;
}

void
heim_free_config_files(char **filenames)
{
    char **p;

    for (p = filenames; p && *p != NULL; p++)
        free(*p);
    free(filenames);
}
