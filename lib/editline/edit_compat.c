/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Kungliga Tekniska
 *      Högskolan and its contributors.
 * 
 * 4. Neither the name of the Institute nor the names of its contributors
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
#include <stdio.h>
#include <string.h>
#include <histedit.h>

RCSID("$Id$");

void
rl_reset_terminal(char *p)
{
}

void
rl_initialize()
{
}

static const char *pr;
static const char* ret_prompt(EditLine *e)
{
    return pr;
}

static History *h;

char *
readline(const char* prompt)
{
    static EditLine *e;
#ifdef H_SETMAXSIZE
    HistEvent ev;
#endif
    int count;
    char *ret;
    if(e == NULL){
	e = el_init("", stdin, stdout);
	el_set(e, EL_PROMPT, ret_prompt);
	h = history_init();
#ifdef H_SETMAXSIZE
	history(h, &ev, H_SETMAXSIZE, 25);
#else
	history(h, H_EVENT, 25);
#endif
	el_set(e, EL_HIST, history, h);
	el_set(e, EL_EDITOR, "emacs"); /* XXX? */
    }
    pr = prompt ? prompt : "";
    ret = (char*)el_gets(e, &count);
    if (ret) {
	if (ret[strlen(ret) - 1] == '\n')
	    ret[strlen(ret) - 1] = '\0';
	return strdup(ret);
    } else
	return ret;
}

void
add_history(char *p)
{
#ifdef H_SETMAXSIZE
    HistEvent ev;
    history(h, &ev, H_ENTER, p);
#else
    history(h, H_ENTER, p);
#endif
}
