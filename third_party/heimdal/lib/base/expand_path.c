
/***********************************************************************
 * Copyright (c) 2009-2020, Secure Endpoints Inc.
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

#include "baselocl.h"

#include <stdarg.h>

typedef int PTYPE;

#ifdef _WIN32
#include <shlobj.h>
#include <sddl.h>

/*
 * Expand a %{TEMP} token
 *
 * The %{TEMP} token expands to the temporary path for the current
 * user as returned by GetTempPath().
 *
 * @note: Since the GetTempPath() function relies on the TMP or TEMP
 * environment variables, this function will failover to the system
 * temporary directory until the user profile is loaded.  In addition,
 * the returned path may or may not exist.
 */
static heim_error_code
expand_temp_folder(heim_context context, PTYPE param, const char *postfix,
                   const char *arg, char **ret)
{
    TCHAR tpath[MAX_PATH];
    size_t len;

    if (!GetTempPath(sizeof(tpath)/sizeof(tpath[0]), tpath)) {
        heim_set_error_message(context, EINVAL,
                               "Failed to get temporary path (GLE=%d)",
                               GetLastError());
        return EINVAL;
    }

    len = strlen(tpath);

    if (len > 0 && tpath[len - 1] == '\\')
        tpath[len - 1] = '\0';

    *ret = strdup(tpath);

    if (*ret == NULL)
        return heim_enomem(context);

    return 0;
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

/*
 * Expand a %{BINDIR} token
 *
 * This is also used to expand a few other tokens on Windows, since
 * most of the executable binaries end up in the same directory.  The
 * "bin" directory is considered to be the directory in which the
 * containing DLL is located.
 */
static heim_error_code
expand_bin_dir(heim_context context, PTYPE param, const char *postfix,
               const char *arg, char **ret)
{
    TCHAR path[MAX_PATH];
    TCHAR *lastSlash;
    DWORD nc;

    nc = GetModuleFileName((HINSTANCE)&__ImageBase, path,
                           sizeof(path)/sizeof(path[0]));
    if (nc == 0 ||
        nc == sizeof(path)/sizeof(path[0])) {
        return EINVAL;
    }

    lastSlash = strrchr(path, '\\');
    if (lastSlash != NULL) {
        TCHAR *fslash = strrchr(lastSlash, '/');

        if (fslash != NULL)
            lastSlash = fslash;

        *lastSlash = '\0';
    }

    if (postfix) {
        if (strlcat(path, postfix, sizeof(path)/sizeof(path[0])) >= sizeof(path)/sizeof(path[0]))
            return EINVAL;
    }

    *ret = strdup(path);
    if (*ret == NULL)
        return heim_enomem(context);

    return 0;
}

/*
 *  Expand a %{USERID} token
 *
 *  The %{USERID} token expands to the string representation of the
 *  user's SID.  The user account that will be used is the account
 *  corresponding to the current thread's security token.  This means
 *  that:
 *
 *  - If the current thread token has the anonymous impersonation
 *    level, the call will fail.
 *
 *  - If the current thread is impersonating a token at
 *    SecurityIdentification level the call will fail.
 *
 */
static heim_error_code
expand_userid(heim_context context, PTYPE param, const char *postfix,
              const char *arg, char **ret)
{
    int rv = EINVAL;
    HANDLE hThread = NULL;
    HANDLE hToken = NULL;
    PTOKEN_OWNER pOwner = NULL;
    DWORD len = 0;
    LPTSTR strSid = NULL;

    hThread = GetCurrentThread();

    if (!OpenThreadToken(hThread, TOKEN_QUERY,
                         FALSE, /* Open the thread token as the
                                   current thread user. */
                         &hToken)) {

        DWORD le = GetLastError();

        if (le == ERROR_NO_TOKEN) {
            HANDLE hProcess = GetCurrentProcess();

            le = 0;
            if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
                le = GetLastError();
        }

        if (le != 0) {
            heim_set_error_message(context, rv,
                                   "Can't open thread token (GLE=%d)", le);
            goto _exit;
        }
    }

    if (!GetTokenInformation(hToken, TokenOwner, NULL, 0, &len)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            heim_set_error_message(context, rv,
                                   "Unexpected error reading token information (GLE=%d)",
                                   GetLastError());
            goto _exit;
        }

        if (len == 0) {
            heim_set_error_message(context, rv,
                                   "GetTokenInformation() returned truncated buffer");
            goto _exit;
        }

        pOwner = malloc(len);
        if (pOwner == NULL) {
            heim_set_error_message(context, rv, "Out of memory");
            goto _exit;
        }
    } else {
        heim_set_error_message(context, rv, "GetTokenInformation() returned truncated buffer");
        goto _exit;
    }

    if (!GetTokenInformation(hToken, TokenOwner, pOwner, len, &len)) {
        heim_set_error_message(context, rv,
                               "GetTokenInformation() failed. GLE=%d",
                               GetLastError());
        goto _exit;
    }

    if (!ConvertSidToStringSid(pOwner->Owner, &strSid)) {
        heim_set_error_message(context, rv,
                               "Can't convert SID to string. GLE=%d",
                               GetLastError());
        goto _exit;
    }

    *ret = strdup(strSid);
    if (*ret == NULL)
        heim_set_error_message(context, rv, "Out of memory");

    rv = 0;

 _exit:
    if (hToken != NULL)
        CloseHandle(hToken);

    if (pOwner != NULL)
        free (pOwner);

    if (strSid != NULL)
        LocalFree(strSid);

    return rv;
}

/*
 * Expand a folder identified by a CSIDL
 */

static heim_error_code
expand_csidl(heim_context context, PTYPE folder, const char *postfix,
             const char *arg, char **ret)
{
    TCHAR path[MAX_PATH];
    size_t len;

    if (SHGetFolderPath(NULL, folder, NULL, SHGFP_TYPE_CURRENT, path) != S_OK) {
        heim_set_error_message(context, EINVAL, "Unable to determine folder path");
        return EINVAL;
    }

    len = strlen(path);

    if (len > 0 && path[len - 1] == '\\')
        path[len - 1] = '\0';

    if (postfix &&
        strlcat(path, postfix, sizeof(path)/sizeof(path[0])) >= sizeof(path)/sizeof(path[0]))
        return heim_enomem(context);

    *ret = strdup(path);
    if (*ret == NULL)
        return heim_enomem(context);
    return 0;
}

#else

static heim_error_code
expand_path(heim_context context, PTYPE param, const char *postfix,
            const char *arg, char **ret)
{
    *ret = strdup(postfix);
    if (*ret == NULL)
        return heim_enomem(context);
    return 0;
}

static heim_error_code
expand_temp_folder(heim_context context, PTYPE param, const char *postfix,
                   const char *arg, char **ret)
{
    const char *p = NULL;

    p = secure_getenv("TEMP");

    if (p)
        *ret = strdup(p);
    else
        *ret = strdup("/tmp");
    if (*ret == NULL)
        return heim_enomem(context);
    return 0;
}

static heim_error_code
expand_userid(heim_context context, PTYPE param, const char *postfix,
              const char *arg, char **str)
{
    int ret = asprintf(str, "%ld", (unsigned long)getuid());
    if (ret < 0 || *str == NULL)
        return heim_enomem(context);
    return 0;
}

static heim_error_code
expand_euid(heim_context context, PTYPE param, const char *postfix,
            const char *arg, char **str)
{
    int ret = asprintf(str, "%ld", (unsigned long)geteuid());
    if (ret < 0 || *str == NULL)
        return heim_enomem(context);
    return 0;
}
#endif /* _WIN32 */

static heim_error_code
expand_home(heim_context context, PTYPE param, const char *postfix,
            const char *arg, char **str)
{
    char homedir[MAX_PATH];
    int ret;

    if (roken_get_homedir(homedir, sizeof(homedir)))
        ret = asprintf(str, "%s", homedir);
    else
        ret = asprintf(str, "/unknown");
    if (ret < 0 || *str == NULL)
        return heim_enomem(context);
    return 0;
}

static heim_error_code
expand_username(heim_context context, PTYPE param, const char *postfix,
                const char *arg, char **str)
{
    char user[128];
    const char *username = roken_get_username(user, sizeof(user));

    if (username == NULL) {
        heim_set_error_message(context, ENOTTY,
                               N_("unable to figure out current principal",
                               ""));
        return ENOTTY; /* XXX */
    }

    *str = strdup(username);
    if (*str == NULL)
        return heim_enomem(context);

    return 0;
}

static heim_error_code
expand_loginname(heim_context context, PTYPE param, const char *postfix,
                 const char *arg, char **str)
{
    char user[128];
    const char *username = roken_get_loginname(user, sizeof(user));

    if (username == NULL) {
        heim_set_error_message(context, ENOTTY,
                               N_("unable to figure out current principal",
                               ""));
        return ENOTTY; /* XXX */
    }

    *str = strdup(username);
    if (*str == NULL)
        return heim_enomem(context);

    return 0;
}

static heim_error_code
expand_strftime(heim_context context, PTYPE param, const char *postfix,
                const char *arg, char **ret)
{
    size_t len;
    time_t t;
    char buf[1024];

    t = time(NULL);
    len = strftime(buf, sizeof(buf), arg, localtime(&t));
    if (len == 0 || len >= sizeof(buf))
        return heim_enomem(context);
    *ret = strdup(buf);
    return 0;
}

/**
 * Expand an extra token
 */

static heim_error_code
expand_extra_token(heim_context context, const char *value, char **ret)
{
    *ret = strdup(value);
    if (*ret == NULL)
        return heim_enomem(context);
    return 0;
}

/**
 * Expand a %{null} token
 *
 * The expansion of a %{null} token is always the empty string.
 */

static heim_error_code
expand_null(heim_context context, PTYPE param, const char *postfix,
            const char *arg, char **ret)
{
    *ret = strdup("");
    if (*ret == NULL)
        return heim_enomem(context);
    return 0;
}


static const struct {
    const char * tok;
    int ftype;
#define FTYPE_CSIDL 0
#define FTYPE_SPECIAL 1

    PTYPE param;
    const char * postfix;

    int (*exp_func)(heim_context, PTYPE, const char *, const char *, char **);

#define SPECIALP(f, P) FTYPE_SPECIAL, 0, P, f
#define SPECIAL(f) SPECIALP(f, NULL)

} tokens[] = {
#ifdef _WIN32
#define CSIDLP(C,P) FTYPE_CSIDL, C, P, expand_csidl
#define CSIDL(C) CSIDLP(C, NULL)

    {"APPDATA", CSIDL(CSIDL_APPDATA)}, /* Roaming application data (for current user) */
    {"COMMON_APPDATA", CSIDL(CSIDL_COMMON_APPDATA)}, /* Application data (all users) */
    {"LOCAL_APPDATA", CSIDL(CSIDL_LOCAL_APPDATA)}, /* Local application data (for current user) */
    {"SYSTEM", CSIDL(CSIDL_SYSTEM)}, /* Windows System folder (e.g. %WINDIR%\System32) */
    {"WINDOWS", CSIDL(CSIDL_WINDOWS)}, /* Windows folder */
    {"USERCONFIG", CSIDLP(CSIDL_APPDATA, "\\" PACKAGE)}, /* Per user Heimdal configuration file path */
    {"COMMONCONFIG", CSIDLP(CSIDL_COMMON_APPDATA, "\\" PACKAGE)}, /* Common Heimdal configuration file path */
    {"LIBDIR", SPECIAL(expand_bin_dir)},
    {"BINDIR", SPECIAL(expand_bin_dir)},
    {"LIBEXEC", SPECIAL(expand_bin_dir)},
    {"SBINDIR", SPECIAL(expand_bin_dir)},
#else
    {"LOCALSTATEDIR", FTYPE_SPECIAL, 0, LOCALSTATEDIR, expand_path},
    {"LIBDIR", FTYPE_SPECIAL, 0, LIBDIR, expand_path},
    {"BINDIR", FTYPE_SPECIAL, 0, BINDIR, expand_path},
    {"LIBEXEC", FTYPE_SPECIAL, 0, LIBEXECDIR, expand_path},
    {"SBINDIR", FTYPE_SPECIAL, 0, SBINDIR, expand_path},
    {"USERCONFIG", SPECIAL(expand_home)}, /* same as %{HOME} on not-Windows */
    {"euid", SPECIAL(expand_euid)},
    {"ruid", SPECIAL(expand_userid)},
    {"loginname", SPECIAL(expand_loginname)},
#endif
    {"username", SPECIAL(expand_username)},
    {"TEMP", SPECIAL(expand_temp_folder)},
    {"USERID", SPECIAL(expand_userid)},
    {"uid", SPECIAL(expand_userid)},
    {"null", SPECIAL(expand_null)},
    {"strftime", SPECIAL(expand_strftime)},
    {"HOME", SPECIAL(expand_home)},
};

static heim_error_code
expand_token(heim_context context,
             const char *token,
             const char *token_end,
             char **extra_tokens,
             char **ret)
{
    heim_error_code errcode;
    size_t i;
    char **p;
    const char *colon;

    *ret = NULL;

    if (token[0] != '%' || token[1] != '{' || token_end[0] != '}' ||
        token_end - token <= 2) {
        heim_set_error_message(context, EINVAL,"Invalid token.");
        return EINVAL;
    }

    for (p = extra_tokens; p && p[0]; p += 2) {
        if (strncmp(token+2, p[0], (token_end - token) - 2) == 0)
            return expand_extra_token(context, p[1], ret);
    }

    for (colon=token+2; colon < token_end; colon++)
        if (*colon == ':')
            break;

    for (i = 0; i < sizeof(tokens)/sizeof(tokens[0]); i++)
        if (!strncmp(token+2, tokens[i].tok, (colon - token) - 2)) {
            char *arg = NULL;

            errcode = 0;
            if (*colon == ':') {
                int asprintf_ret = asprintf(&arg, "%.*s",
                                            (int)(token_end - colon - 1),
                                            colon + 1);
                if (asprintf_ret < 0 || !arg)
                    errcode = ENOMEM;
            }
            if (!errcode)
                errcode = tokens[i].exp_func(context, tokens[i].param,
                                             tokens[i].postfix, arg, ret);
            free(arg);
            return errcode;
        }

    heim_set_error_message(context, EINVAL, "Invalid token.");
    return EINVAL;
}

/**
 * Internal function to expand tokens in paths.
 *
 * Params:
 *
 * @context   A heim_context
 * @path_in   The path to expand tokens from
 * @filepath  True if this is a filesystem path (converts slashes to
 *            backslashes on Windows)
 * @ppath_out The expanded path
 * @...       Variable number of pairs of strings, the first of each
 *            being a token (e.g., "luser") and the second a string to
 *            replace it with.  The list is terminated by a NULL.
 */
heim_error_code
heim_expand_path_tokens(heim_context context,
                        const char *path_in,
                        int filepath,
                        char **ppath_out,
                        ...)
{
    heim_error_code ret;
    va_list ap;

    va_start(ap, ppath_out);
    ret = heim_expand_path_tokensv(context, path_in, filepath, ppath_out, ap);
    va_end(ap);

    return ret;
}

static void
free_extra_tokens(char **extra_tokens)
{
    char **p;

    for (p = extra_tokens; p && *p; p++)
        free(*p);
    free(extra_tokens);
}

/**
 * Internal function to expand tokens in paths.
 *
 * Inputs:
 *
 * @context   A heim_context
 * @path_in   The path to expand tokens from
 * @filepath  True if this is a filesystem path (converts slashes to
 *            backslashes on Windows)
 * @ppath_out The expanded path
 * @ap        A NULL-terminated va_list of pairs of strings, the first of each
 *            being a token (e.g., "luser") and the second a string to replace
 *            it with.
 * 
 * Outputs:
 *
 * @ppath_out Path with expanded tokens (caller must free() this)
 */
heim_error_code
heim_expand_path_tokensv(heim_context context,
                         const char *path_in,
                         int filepath,
                         char **ppath_out, va_list ap)
{
    char *tok_begin, *tok_end, *append;
    char **extra_tokens = NULL;
    const char *path_left;
    size_t nargs = 0;
    size_t len = 0;
    va_list ap2;

    if (path_in == NULL || *path_in == '\0') {
        *ppath_out = strdup("");
        return 0;
    }

    *ppath_out = NULL;

#if defined(_MSC_VER)
    ap2 = ap;           /* Come on! See SO #558223 */
#else
    va_copy(ap2, ap);
#endif
    while (va_arg(ap2, const char *)) {
        nargs++;
        va_arg(ap2, const char *);
    }
    va_end(ap2);
    nargs *= 2;

    /* Get extra tokens */
    if (nargs) {
        size_t i;

        extra_tokens = calloc(nargs + 1, sizeof (*extra_tokens));
        if (extra_tokens == NULL)
            return heim_enomem(context);
        for (i = 0; i < nargs; i++) {
            const char *s = va_arg(ap, const char *); /* token key */
            if (s == NULL)
                break;
            extra_tokens[i] = strdup(s);
            if (extra_tokens[i++] == NULL) {
                free_extra_tokens(extra_tokens);
                return heim_enomem(context);
            }
            s = va_arg(ap, const char *); /* token value */
            if (s == NULL)
                s = "";
            extra_tokens[i] = strdup(s);
            if (extra_tokens[i] == NULL) {
                free_extra_tokens(extra_tokens);
                return heim_enomem(context);
            }
        }
    }

    for (path_left = path_in; path_left && *path_left; ) {

        tok_begin = strstr(path_left, "%{");

        if (tok_begin && tok_begin != path_left) {

            append = malloc((tok_begin - path_left) + 1);
            if (append) {
                memcpy(append, path_left, tok_begin - path_left);
                append[tok_begin - path_left] = '\0';
            }
            path_left = tok_begin;

        } else if (tok_begin) {

            tok_end = strchr(tok_begin, '}');
            if (tok_end == NULL) {
                free_extra_tokens(extra_tokens);
                if (*ppath_out)
                    free(*ppath_out);
                *ppath_out = NULL;
                heim_set_error_message(context, EINVAL, "variable missing }");
                return EINVAL;
            }

            if (expand_token(context, tok_begin, tok_end, extra_tokens,
                             &append)) {
                free_extra_tokens(extra_tokens);
                if (*ppath_out)
                    free(*ppath_out);
                *ppath_out = NULL;
                return EINVAL;
            }

            path_left = tok_end + 1;
        } else {

            append = strdup(path_left);
            path_left = NULL;

        }

        if (append == NULL) {

            free_extra_tokens(extra_tokens);
            if (*ppath_out)
                free(*ppath_out);
            *ppath_out = NULL;
            return heim_enomem(context);

        }

        {
            size_t append_len = strlen(append);
            char * new_str = realloc(*ppath_out, len + append_len + 1);

            if (new_str == NULL) {
                free_extra_tokens(extra_tokens);
                free(append);
                if (*ppath_out)
                    free(*ppath_out);
                *ppath_out = NULL;
                return heim_enomem(context);
            }

            *ppath_out = new_str;
            memcpy(*ppath_out + len, append, append_len + 1);
            len = len + append_len;
            free(append);
        }
    }

#ifdef _WIN32
    /* Also deal with slashes */
    if (filepath && *ppath_out) {
        char * c;

        for (c = *ppath_out; *c; c++)
            if (*c == '/')
                *c = '\\';
    }
#endif

    free_extra_tokens(extra_tokens);
    return 0;
}
