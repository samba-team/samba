/*
 * Copyright (c) 1995, 1996 Kungliga Tekniska Högskolan (Royal Institute
 * of Technology, Stockholm, Sweden).
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
#endif

RCSID("$Id$");

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#ifdef HAVE_SYS_TIME_H 
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <roken.h>

#include <des.h>
#include <krb.h>
#include <kafs.h>

#include "extern.h"
#include "krb4.h"
#include "auth.h"
#include "base64.h"

static KTEXT_ST cip;
static unsigned int lifetime;
static time_t local_time;

static char name[ANAME_SZ], inst[INST_SZ], realm[REALM_SZ];

static int
save_tkt(char *user, char *instance, char *realm, void *arg, 
	 int (*key_proc)(char*, char*, char*, void*, des_cblock*), KTEXT *cipp)
{
    local_time = time(0);
    memmove(&cip, *cipp, sizeof(cip));
    return -1;
}

static int
store_ticket(KTEXT cip)
{
    char *ptr;
    des_cblock session;
    char sname[SNAME_SZ];
    char sinst[INST_SZ];
    char srealm[REALM_SZ];
    unsigned char kvno;
    KTEXT_ST tkt;
    int left = cip->length;

    int kerror;
    
    time_t kdc_time;

    ptr = (char *) cip->dat;

    /* extract session key */
    memmove(session, ptr, 8);
    ptr += 8;
    left -= 8;

    if (strnlen(ptr, left) == left)
	return(INTK_BADPW);
    
    /* extract server's name */
    strcpy(sname,ptr);
    ptr += strlen(sname) + 1;
    left -= strlen(sname) + 1;

    if (strnlen(ptr, left) == left)
	return(INTK_BADPW);

    /* extract server's instance */
    strcpy(sinst, ptr);
    ptr += strlen(sinst) + 1;
    left -= strlen(sinst) + 1;

    if (strnlen(ptr, left) == left)
	return(INTK_BADPW);

    /* extract server's realm */
    strcpy(srealm,ptr);
    ptr += strlen(srealm) + 1;
    left -= strlen(srealm) + 1;

    if(left < 3)
	return INTK_BADPW;
    /* extract ticket lifetime, server key version, ticket length */
    /* be sure to avoid sign extension on lifetime! */
    lifetime = (unsigned char) ptr[0];
    kvno = (unsigned char) ptr[1];
    tkt.length = (unsigned char) ptr[2];
    ptr += 3;
    left -= 3;
    
    if (tkt.length > left)
	return(INTK_BADPW);

    /* extract ticket itself */
    memmove(tkt.dat, ptr, tkt.length);
    ptr += tkt.length;
    left -= tkt.length;

    /* Here is where the time should be verified against the KDC.
     * Unfortunately everything is sent in host byte order (receiver
     * makes wrong) , and at this stage there is no way for us to know
     * which byteorder the KDC has. So we simply ignore the time,
     * there are no security risks with this, the only thing that can
     * happen is that we might receive a replayed ticket, which could
     * at most be useless.
     */
    
#if 0
    /* check KDC time stamp */
    memmove(&kdc_time, ptr, sizeof(kdc_time));
    if (swap_bytes) swap_u_long(kdc_time);

    ptr += 4;
    
    if (abs((int)(local_time - kdc_time)) > CLOCK_SKEW) {
        return(RD_AP_TIME);		/* XXX should probably be better
					   code */
    }
#endif

    /* initialize ticket cache */

    if (tf_create(TKT_FILE) != KSUCCESS)
	return(INTK_ERR);

    if (tf_put_pname(name) != KSUCCESS ||
	tf_put_pinst(inst) != KSUCCESS) {
	tf_close();
	return(INTK_ERR);
    }

    
    kerror = tf_save_cred(sname, sinst, srealm, session, lifetime, kvno,
			  &tkt, local_time);
    tf_close();

    return(kerror);
}

void kauth(char *principal, char *ticket)
{
    char *p;
    int ret;
  
    ret = kname_parse(name, inst, realm, principal);
    if(ret){
	reply(500, "Bad principal: %s.", krb_get_err_text(ret));
	return;
    }
    if(realm[0] == 0)
	krb_get_lrealm(realm, 1);

    if(ticket){
	cip.length = base64_decode(ticket, &cip.dat);
	if(cip.length == -1){
	    reply(500, "Failed to decode data.");
	    return;
	}
	ret = store_ticket(&cip);
	if(ret){
	    reply(500, "Kerberos error: %s.", krb_get_err_text(ret));
	    memset(&cip, 0, sizeof(cip));
	    return;
	}
	if(k_hasafs())
	    k_afsklog(0, 0);
	reply(200, "Tickets will be destroyed on exit.");
	return;
    }
    
    ret = krb_get_in_tkt (name, inst, realm, "krbtgt", realm, 12,
			  NULL, save_tkt, NULL);
    if(ret != INTK_BADPW){
	reply(500, "Kerberos error: %s.", krb_get_err_text(ret));
	return;
    }
    base64_encode(cip.dat, cip.length, &p);
    reply(300, "P=%s%s%s@%s T=%s", name, *inst?".":"", inst, realm, p);
    free(p);
    memset(&cip, 0, sizeof(cip));
}


static char *
short_date(int32_t dp)
{
    char *cp;
    time_t t = (time_t)dp;

    if (t == (time_t)(-1L)) return "***  Never  *** ";
    cp = ctime(&t) + 4;
    cp[15] = '\0';
    return (cp);
}

void klist(void)
{
    int err;

    char *file = tkt_string();

    char name[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];

    char buf1[128], buf2[128];
    int header = 1;
    CREDENTIALS c;

    

    err = tf_init(file, R_TKT_FIL);
    if(err != KSUCCESS){
	reply(500, "%s", krb_get_err_text(err));
	return;
    }
    tf_close();

    /* 
     * We must find the realm of the ticket file here before calling
     * tf_init because since the realm of the ticket file is not
     * really stored in the principal section of the file, the
     * routine we use must itself call tf_init and tf_close.
     */
    err = krb_get_tf_realm(file, realm);
    if(err != KSUCCESS){
	reply(500, "%s", krb_get_err_text(err));
	return;
    }

    err = tf_init(file, R_TKT_FIL);
    if(err != KSUCCESS){
	reply(500, "%s", krb_get_err_text(err));
	return;
    }

    err = tf_get_pname(name);
    if(err != KSUCCESS){
	reply(500, "%s", krb_get_err_text(err));
	return;
    }
    err = tf_get_pinst(inst);
    if(err != KSUCCESS){
	reply(500, "%s", krb_get_err_text(err));
	return;
    }

    /* 
     * You may think that this is the obvious place to get the
     * realm of the ticket file, but it can't be done here as the
     * routine to do this must open the ticket file.  This is why 
     * it was done before tf_init.
     */
       
    if(inst[0])
	lreply(200, "Principal: %s.%s@%s", name, inst, realm);
    else
	lreply(200, "Principal: %s@%s", name, realm);
    while ((err = tf_get_cred(&c)) == KSUCCESS) {
	if (header) {
	    lreply(200, "%-15s  %-15s  %s",
		   "  Issued", "  Expires", "  Principal (kvno)");
	    header = 0;
	}
	strcpy(buf1, short_date(c.issue_date));
	c.issue_date = krb_life_to_time(c.issue_date, c.lifetime);
	if (time(0) < (unsigned long) c.issue_date)
	    strcpy(buf2, short_date(c.issue_date));
	else
	    strcpy(buf2, ">>> Expired <<< ");
	lreply(200, "%s  %s  %s%s%s%s%s (%d)", buf1, buf2,
	       c.service, (c.instance[0] ? "." : ""), c.instance,
	       (c.realm[0] ? "@" : ""), c.realm, c.kvno); 
    }
    if (header && err == EOF) {
	lreply(200, "No tickets in file.");
    }
    reply(200, "");
}
