/*
 * Copyright (c) 2000 Kungliga Tekniska Högskolan
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

#include "hprop.h"

RCSID("$Id$");

static time_t
time_parse(const char *cp)
{
    char wbuf[5];
    struct tm tp;
    int local;

    memset(&tp, 0, sizeof(tp));	/* clear out the struct */
    
    /* new format is YYYYMMDDHHMM UTC,
       old format is YYMMDDHHMM local time */
    if (strlen(cp) > 10) {		/* new format */
	strlcpy(wbuf, cp, sizeof(wbuf));
	tp.tm_year = atoi(wbuf) - 1900;
	cp += 4;
	local = 0;
    } else {
	wbuf[0] = *cp++;
	wbuf[1] = *cp++;
	wbuf[2] = '\0';
	tp.tm_year = atoi(wbuf);
	if(tp.tm_year < 38)
	    tp.tm_year += 100;
	local = 1;
    }

    wbuf[0] = *cp++;
    wbuf[1] = *cp++;
    wbuf[2] = 0;
    tp.tm_mon = atoi(wbuf) - 1;

    wbuf[0] = *cp++;
    wbuf[1] = *cp++;
    tp.tm_mday = atoi(wbuf);
    
    wbuf[0] = *cp++;
    wbuf[1] = *cp++;
    tp.tm_hour = atoi(wbuf);
    
    wbuf[0] = *cp++;
    wbuf[1] = *cp++;
    tp.tm_min = atoi(wbuf);
    
    return(tm2time(tp, local));
}

int
v4_prop_dump(void *arg, const char *file)
{
    char buf [1024];
    FILE *f;
    int lineno = 0;

    f = fopen(file, "r");
    if(f == NULL)
	return errno;
    
    while(fgets(buf, sizeof(buf), f)) {
	int ret;
	unsigned long key[2]; /* yes, long */
	int life, kkvno, kvno;
	char exp_date[64], mod_date[64];
	Principal pr;
    
	memset(&pr, 0, sizeof(pr));
	errno = 0;
	lineno++;
	ret = sscanf(buf, "%s %s %d %d %d %hd %lx %lx %s %s %s %s",
		     pr.name, pr.instance,
		     &life, &kkvno, &kvno,
		     &pr.attributes,
		     &key[0], &key[1],
		     exp_date, mod_date,
		     pr.mod_name, pr.mod_instance);
	if(ret != 12){
	    warnx("Line %d malformed (ignored)", lineno);
	    continue;
	}
	pr.key_low = ntohl (key[0]);
	pr.key_high = ntohl (key[1]);
	pr.max_life = life;
	pr.kdc_key_ver = kkvno;
	pr.key_version = kvno;
	pr.exp_date = time_parse(exp_date);
	pr.mod_date = time_parse(mod_date);
	if (pr.instance[0] == '*')
	    pr.instance[0] = '\0';
	if (pr.mod_name[0] == '*')
	    pr.mod_name[0] = '\0';
	if (pr.mod_instance[0] == '*')
	    pr.mod_instance[0] = '\0';
	v4_prop(arg, &pr);
	memset(&pr, 0, sizeof(pr));
    }
    return 0;
}
