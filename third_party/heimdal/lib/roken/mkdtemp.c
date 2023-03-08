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

#include <config.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#include <roken.h>

#ifndef O_APPEND
#define O_APPEND 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_SYNC
#define O_SYNC 0
#endif

#ifndef HAVE_MKDTEMP
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
mkdtemp(char *template)
{
    size_t len = strlen(template) - 1;
    size_t start, i;
    pid_t val = getpid();

    for (i = 0; i < len && i < 7 && template[len - i] == 'X'; i++) {
	template[len - i] = '0' + val % 10;
	val /= 10;
        if (!val)
            val = getpid();
    }

    if (i < 6) {
        errno = EINVAL;
        return NULL;
    }

    start = len - i;
    do {
        if (mkdir(template, 0700) == 0)
            return template;
	for (i = start + 1; i < len; i++) {
	    if (++(template[i]) == '9' + 1)
		template[i] = 'a';
	    if (template[i] <= 'z')
		break;
	    template[i] = 'a';
	}
    } while(1);
}
#endif
