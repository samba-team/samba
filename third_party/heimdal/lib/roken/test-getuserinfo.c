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

#ifndef WIN32
#include <err.h>
#endif
#include "roken.h"

static void
print1(const char *name, const char *tabs, const char *s2)
{
    (void) printf("%s:%s%s\n", name, tabs, s2 ? s2 : "<NULL>");
}

int
main(void)
{
    char buf[MAX_PATH * 2];
#ifndef WIN32
    char buf2[MAX_PATH * 2];
    int ret = 0;
    if (!issuid() && getuid() != 0) {
        const char *s = NULL;
        const char *s2 = NULL;

        if (getenv("USER") != NULL && strlen(getenv("USER")) != 0 &&
            (s = roken_get_username(buf, sizeof(buf))) == NULL) {
            warnx("roken_get_username() returned NULL but $USER is set");
            ret++;
        }
        if (getenv("USER") != NULL && strlen(getenv("USER")) != 0 && s &&
            strcmp(getenv("USER"), s) != 0) {
            warnx("roken_get_username() != getenv(\"USER\")");
            ret++;
        }

        if (getenv("HOME") != NULL && strlen(getenv("HOME")) != 0 &&
            (s = roken_get_homedir(buf, sizeof(buf))) == NULL) {
            warnx("roken_get_homedir() returned NULL but $HOME is set");
            ret++;
        }
        if (getenv("HOME") != NULL && strlen(getenv("HOME")) != 0 && s &&
            strcmp(getenv("HOME"), s) != 0) {
            warnx("roken_get_homedir() != getenv(\"HOME\")");
            ret++;
        }

        if (getenv("HOME") != NULL && strlen(getenv("HOME")) != 0 && s &&
            (s2 = roken_get_appdatadir(buf, sizeof(buf))) == NULL) {
            warnx("roken_get_appdatadir() returned NULL but $HOME is set "
                  "and roken_get_homedir() returned not-NULL");
            ret++;
        }
        if (getenv("HOME") != NULL && strlen(getenv("HOME")) != 0 &&
            s && s2 && strcmp(s, s2) != 0) {
            warnx("roken_get_homedir() != roken_get_appdatadir()");
            ret++;
        }
        if (getenv("SHELL") != NULL && strlen(getenv("SHELL")) != 0 &&
            strcmp(getenv("SHELL"), roken_get_shell(buf, sizeof(buf))) != 0) {
            warnx("roken_get_shell() != getenv(\"SHELL\")");
            ret++;
        }
    }
#endif

    print1("Username",      "\t",   roken_get_username(buf, sizeof(buf)));
    print1("Loginname",     "\t",   roken_get_loginname(buf, sizeof(buf)));
    print1("Home",          "\t\t", roken_get_homedir(buf, sizeof(buf)));
    print1("Appdatadir",    "\t",   roken_get_appdatadir(buf, sizeof(buf)));
    print1("Shell",         "\t\t", roken_get_shell(buf, sizeof(buf)));

#ifndef WIN32
    if (!issuid() && getuid() != 0) {
        const char *s, *s2;

        putenv("USER=h5lfoouser");
        putenv("HOME=/no/such/dir/h5lfoouser");
        putenv("SHELL=/no/such/shell");
        if ((s = roken_get_username(buf, sizeof(buf))) == NULL ||
            strcmp("h5lfoouser", s) != 0) {
            warnx("roken_get_username() (%s) did not honor $USER", s);
            ret++;
        }
        if ((s = roken_get_homedir(buf, sizeof(buf))) == NULL ||
            strcmp("/no/such/dir/h5lfoouser", s) != 0) {
            warnx("roken_get_homedir() (%s) did not honor $HOME", s);
            ret++;
        }
        s = roken_get_homedir(buf, sizeof(buf));
        s2 = roken_get_appdatadir(buf2, sizeof(buf2));
        if (strcmp(s, s2) != 0) {
            warnx("roken_get_homedir() != roken_get_appdatadir() (%s)",
                  roken_get_appdatadir(buf, sizeof(buf)));
            ret++;
        }
        if ((s = roken_get_shell(buf, sizeof(buf))) == NULL ||
            strcmp("/no/such/shell", s) != 0) {
            warnx("roken_get_shell() (%s) did not honor $SHELL", s);
            ret++;
        }
    }
    return ret;
#endif
    return 0;
}
