/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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
 *      This product includes software developed by Kungliga Tekniska 
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

#include "admin_locl.h"
#if defined (HAVE_SYS_TIMEB_H)
#include <sys/timeb.h>
#else

/* get_date uses the obsolete `struct timeb' in its interface!  FIXME.
   Since some systems don't have it, we define it here;
   callers must do likewise.  */
struct timeb
  {
    time_t		time;		/* Seconds since the epoch	*/
    unsigned short	millitm;	/* Field not used		*/
    short		timezone;	/* Minutes west of GMT		*/
    short		dstflag;	/* Field not used		*/
};
#endif /* defined (HAVE_SYS_TIMEB_H) */

time_t 
gettime(const char *prompt, const char *def, int relative)
{
    char buf[1024];
    time_t t;
    struct timeb now, *tp = NULL;
    if(relative){
	memset(&now, 0, sizeof(now));
	tp = &now;
    }
    while(1){
	printf("%s", prompt);
	if(def)
	    printf(" [%s]", def);
	printf(": ");
	if(fgets(buf, sizeof(buf), stdin) == NULL)
	    return -1;
	buf[strlen(buf) - 1] = 0;
	if(def && buf[0] == 0) strcpy(buf, def);
	if(strcmp(buf, "infinite") == 0 || strcmp(buf, "unlimited") == 0)
	    return 0;
	t = get_date(buf, tp);
	if(t != -1)
	    return t;
	printf("Unrecognised time.\n");
    }
}
