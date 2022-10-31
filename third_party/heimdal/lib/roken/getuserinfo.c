/*
 * Copyright (c) 2017 Kungliga Tekniska Högskolan
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

#include <config.h>
#include "roken.h"

#ifdef WIN32
#include <Shlobj.h>  // need to include definitions of constants
#define SECURITY_WIN32
#include <security.h>
#else
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#endif

/**
 * Returns the user's SHELL.
 */
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
roken_get_shell(char *shell, size_t shellsz)
{
    char *p;

#ifndef WIN32
#ifdef HAVE_GETPWNAM_R
    size_t buflen = 2048;

    if (sysconf(_SC_GETPW_R_SIZE_MAX) > 0)
        buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
#endif

    if (issuid())
        return "/bin/sh";

    p = secure_getenv("SHELL");
    if (p != NULL && p[0] != '\0') {
        if (strlcpy(shell, p, shellsz) < shellsz)
            return shell;
        errno = ERANGE;
        return NULL;
    }

#ifdef HAVE_GETPWNAM_R
    {
        struct passwd pwd;
        struct passwd *pwdp;
        char buf[buflen];
        char user[128];
        const char *username = roken_get_username(user, sizeof(user));

        if (username &&
            getpwnam_r(username, &pwd, buf, buflen, &pwdp) == 0 &&
            pwdp != NULL && pwdp->pw_shell != NULL) {
            if (strlcpy(shell, pwdp->pw_shell, shellsz) < shellsz)
                return shell;
            errno = ERANGE;
            return NULL;
        }
    }
#endif
    errno = 0;
    return "/bin/sh";
#else
    /* Windows */
    p = getenv("SHELL");
    if (p != NULL && p[0] != '\0') {
        if (strlcpy(shell, p, shellsz) < shellsz)
            return shell;
        errno = ERANGE;
        return NULL;
    }
    errno = 0;
    return NULL;
#endif
}

/**
 * Returns the home directory.
 */
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
roken_get_homedir(char *home, size_t homesz)
{
    char *p;

#ifdef WIN32
    if (homesz < MAX_PATH) {
        errno = ERANGE;
        return NULL;
    }

    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_PROFILE, NULL,
                                  SHGFP_TYPE_CURRENT, home)))
        return home;

    if ((p = getenv("HOMEDRIVE")) != NULL && p[0] != '\0') {
        if (strlcpy(home, p, homesz) >= homesz) {
            errno = ERANGE;
            return NULL;
        }
        if ((p = getenv("HOMEPATH")) != NULL) {
            if (strlcat(home, p, homesz) < homesz)
                return home;
            errno = ERANGE;
            return NULL;
        }
        return home;
    }
    HEIM_FALLTHROUGH;
#else
#ifdef HAVE_GETPWNAM_R
    size_t buflen = 2048;

    if (sysconf(_SC_GETPW_R_SIZE_MAX) > 0)
        buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
#endif

    if (issuid()) {
        errno = 0;
        return NULL;
    }

    p = secure_getenv("HOME");
    if (p != NULL && p[0] != '\0') {
        if (strlcpy(home, p, homesz) < homesz)
            return home;
        errno = ERANGE;
        return NULL;
    }

#ifdef HAVE_GETPWNAM_R
    {
        char user[128];
        const char *username = roken_get_username(user, sizeof(user));
        struct passwd pwd;
        struct passwd *pwdp;
        char buf[buflen];

        if (username &&
            getpwnam_r(username, &pwd, buf, buflen, &pwdp) == 0 &&
            pwdp != NULL && pwdp->pw_dir != NULL) {
            if (strlcpy(home, pwdp->pw_dir, homesz) < homesz)
                return home;
            errno = ERANGE;
            return NULL;
        }
    }
#endif
#endif
    errno = 0;
    return NULL;
}

/**
 * Returns the home directory on Unix, or the AppData directory on
 * Windows.
 */
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
roken_get_appdatadir(char *appdata, size_t appdatasz)
{
#ifdef WIN32
    char *p;
#endif

#ifndef WIN32
    return roken_get_homedir(appdata, appdatasz);
#else
    if (appdatasz < MAX_PATH) {
        errno = ERANGE;
        return NULL;
    }

    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL,
                                  SHGFP_TYPE_CURRENT, appdata)))
        return appdata;

    if ((p = getenv("APPDATA")) != NULL && p[0] != '\0') {
        if (strlcpy(appdata, p, appdatasz) < appdatasz)
            return appdata;
        errno = ERANGE;
        return NULL;
    }

    errno = 0;
    return NULL;
#endif
}

/**
 * Return a bare username.  This is used for, e.g., constructing default
 * principal names.
 *
 * On POSIX systems, if the caller is not set-uid-like, then this will return
 * the value of the USER or LOGNAME environment variables (in that order of
 * preference), else the username found by looking up the effective UID.
 */
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
roken_get_username(char *user, size_t usersz)
{
    char *p;

#ifdef WIN32
    ULONG sz = usersz;

    if (GetUserNameEx(NameSamCompatible, user, &sz)) {
        /*
         * There's no EXTENDED_NAME_FORMAT for "bare username".  We we
         * have to parse one.
         */
        p = strchr(user, '\\');
        if (p != NULL) {
            p++;
            memmove(user, p, strlen(p) + 1);
        }
        return user;
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_MORE_DATA) {
            errno = ERANGE;
            return NULL;
        }
        /* %USERNAME% is generally bare */
        p = getenv("USERNAME");
        if (p != NULL && p[0] != '\0') {
            if (strchr(p, '\\') != NULL)
                p = strchr(p, '\\') + 1;
            if (strlcpy(user, p, usersz) < usersz)
                return user;
            errno = ERANGE;
            return NULL;
        }
    }
#else
#ifdef HAVE_GETPWUID_R
    size_t buflen = 2048;

    if (sysconf(_SC_GETPW_R_SIZE_MAX) > 0)
        buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
#endif

    p = secure_getenv("USER");
    if (p == NULL || p[0] == '\0')
        p = secure_getenv("LOGNAME");
    if (p != NULL && p[0] != '\0') {
        if (strlcpy(user, p, usersz) < usersz)
            return user;
        errno = ERANGE;
        return NULL;
    }

#ifdef HAVE_GETPWUID_R
    {
        struct passwd pwd;
        struct passwd *pwdp;
        char buf[buflen];

        if (getpwuid_r(getuid(), &pwd, buf, buflen, &pwdp) == 0 &&
            pwdp != NULL && pwdp->pw_name != NULL) {
            if (strlcpy(user, pwdp->pw_name, usersz) < usersz)
                return user;
            errno = ERANGE;
            return NULL;
        }
    }
#endif
#endif
    errno = 0;
    return NULL;
}

/**
 * Return a bare username.  This is used for, e.g., constructing default
 * principal names.
 *
 * On POSIX systems this returns the name recorded in the system as currently
 * logged in on the current terminal.
 */
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
roken_get_loginname(char *user, size_t usersz)
{
#ifdef WIN32
    return roken_get_username(user, usersz);
#else
#ifdef HAVE_GETLOGIN_R
    if ((errno = getlogin_r(user, usersz)) == 0)
        return user;
    if (errno != ENOENT)
        return NULL;
#else
#ifdef HAVE_GETLOGIN
    if ((p = getlogin()) != NULL && p[0] != '\0') {
        if (strlcpy(user, p, usersz) < usersz)
            return user;
        errno = ERANGE;
        return NULL;
    }
    if (errno != ENOENT)
        return NULL;
#endif
#endif
    errno = 0;
    return NULL;
#endif
}
