/*
 * Copyright (c) 1995, 1996, 1997, 1998 Kungliga Tekniska Högskolan
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

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if 0 /* Where were those needed? /confused */
#ifdef HAVE_SYS_PROC_H
#include <sys/proc.h>
#endif

#ifdef HAVE_SYS_TTY_H
#include <sys/tty.h>
#endif
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#include <roken.h>

int
get_window_size(int fd, struct winsize *wp)
{
    char *s;
    struct winsize tmp;
    int ret = -1;
    
    memset(wp, 0, sizeof(*wp));
    memset(&tmp, 0, sizeof(tmp));
    if((s = getenv("COLUMNS")))
	wp->ws_col = atoi(s);
    if((s = getenv("LINES")))
	wp->ws_row = atoi(s);
    if(wp->ws_col > 0 && wp->ws_row > 0)
	return 0;
    
#if defined(TIOCGWINSZ)
    ret = ioctl(fd, TIOCGWINSZ, &tmp);
#elif defined(TIOCGSIZE)
    {
	struct ttysize ts;
	
	ret = ioctl(fd, TIOCGSIZE, &ts);
	if(ret == 0) {
	    tmp.ws_row = ts.ts_lines;
	    tmp.ws_col = ts.ts_cols;
	    tmp.ws_xpixel = 0;
	    tmp.ws_ypixel = 0;
	}
    }
#elif defined(HAVE__SCRSIZE)
    {
	int dst[2];
	
	_scrsize(dst);
	tmp.ws_row = dst[1];
	tmp.ws_col = dst[0];
	tmp.ws_xpixel = 0;
	tmp.ws_ypixel = 0;
	ret = 0;
    }
#endif
    if(ret == 0) {
	if(wp->ws_col == 0) {
	    wp->ws_col = tmp.ws_col;
	    wp->ws_xpixel = tmp.ws_xpixel;
	}
	if(wp->ws_row == 0) {
	    wp->ws_row = tmp.ws_row;
	    wp->ws_ypixel = tmp.ws_ypixel;
	}
    }
    return ret;
}
