/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include <config.h>

RCSID("$Id$");

#ifdef	KRB5
#include <arpa/telnet.h>
#include <stdio.h>
#define Authenticator k5_Authenticator
#include <krb5.h>
#undef Authenticator
#include <des.h>
#if 0
#include <krb5/asn1.h>
#include <krb5/crc-32.h>
#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>
#endif
#if 0
#include <com_err.h>
#endif
#include <netdb.h>
#include <ctype.h>
#ifdef SOCKS
#include <socks.h>
#endif

/* kerberos 5 include files (ext-proto.h) will get an appropriate stdlib.h
   and string.h/strings.h */

#include "encrypt.h"
#include "auth.h"
#include "misc.h"

extern auth_debug_mode;

#ifdef	FORWARD
int forward_flags = 0;  /* Flags get set in telnet/main.c on -f and -F */

/* These values need to be the same as those defined in telnet/main.c. */
/* Either define them in both places, or put in some common header file. */
#define OPTS_FORWARD_CREDS	0x00000002
#define OPTS_FORWARDABLE_CREDS	0x00000001

void kerberos5_forward();

#endif	/* FORWARD */

static unsigned char str_data[1024] = { IAC, SB, TELOPT_AUTHENTICATION, 0,
			  		AUTHTYPE_KERBEROS_V5, };
/*static unsigned char str_name[1024] = { IAC, SB, TELOPT_AUTHENTICATION,
					TELQUAL_NAME, };*/

#define	KRB_AUTH		0	/* Authentication data follows */
#define	KRB_REJECT		1	/* Rejected (reason might follow) */
#define	KRB_ACCEPT		2	/* Accepted */
#define	KRB_RESPONSE		3	/* Response for mutual auth. */

#ifdef	FORWARD
#define KRB_FORWARD     	4       /* Forwarded credentials follow */
#define KRB_FORWARD_ACCEPT     	5       /* Forwarded credentials accepted */
#define KRB_FORWARD_REJECT     	6       /* Forwarded credentials rejected */
#endif	/* FORWARD */

static	krb5_data auth;
/* telnetd gets session key from here */
static	/*krb5_tkt_authent*/ void *authdat = NULL;
/* telnet matches the AP_REQ and AP_REP with this */
static	krb5_authenticator authenticator;
static  krb5_ticket *ticket;

static krb5_context context;
static krb5_auth_context auth_context;

/* some compilers can't hack void *, so we use the Kerberos krb5_pointer,
   which is either void * or char *, depending on the compiler. */

des_cblock	session_key;

static int
Data(Authenticator *ap, int type, void *d, int c)
{
    unsigned char *p = str_data + 4;
    unsigned char *cd = (unsigned char *)d;

    if (c == -1)
	c = strlen(cd);

    if (auth_debug_mode) {
	printf("%s:%d: [%d] (%d)",
	       str_data[3] == TELQUAL_IS ? ">>>IS" : ">>>REPLY",
	       str_data[3],
	       type, c);
	printd(d, c);
	printf("\r\n");
    }
    *p++ = ap->type;
    *p++ = ap->way;
    *p++ = type;
    while (c-- > 0) {
	if ((*p++ = *cd++) == IAC)
	    *p++ = IAC;
    }
    *p++ = IAC;
    *p++ = SE;
    if (str_data[3] == TELQUAL_IS)
	printsub('>', &str_data[2], p - &str_data[2]);
    return(net_write(str_data, p - str_data));
}

int
kerberos5_init(Authenticator *ap, int server)
{
    if (server)
	str_data[3] = TELQUAL_REPLY;
    else
	str_data[3] = TELQUAL_IS;
    krb5_init_context(&context);
    return(1);
}

static int
kerberos5_send(char *name, Authenticator *ap)
{
    krb5_error_code r;
    krb5_ccache ccache;
    int ap_opts;
    krb5_data cksum_data;
    char foo[2];
    
    printf("[ Trying %s ... ]\r\n", name);
    if (!UserNameRequested) {
	if (auth_debug_mode) {
	    printf("Kerberos V5: no user name supplied\r\n");
	}
	return(0);
    }
    
    if (r = krb5_cc_default(context, &ccache)) {
	if (auth_debug_mode) {
	    printf("Kerberos V5: could not get default ccache\r\n");
	}
	return(0);
    }
	
    if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
	ap_opts = AP_OPTS_MUTUAL_REQUIRED;
    else
	ap_opts = 0;
    
    auth_context = NULL;

    foo[0] = ap->type;
    foo[1] = ap->way;

    cksum_data.length = sizeof(foo);
    cksum_data.data   = foo;
    r = krb5_mk_req(context, &auth_context, ap_opts, 
		    "host", RemoteHostName, 
		    &cksum_data, ccache, &auth);

    if (r) {
	if (auth_debug_mode) {
	    printf("Kerberos V5: mk_req failed (%s)\r\n",
		   krb5_get_err_text(context, r));
	}
	return(0);
    }

    if (!auth_sendname(UserNameRequested, strlen(UserNameRequested))) {
	if (auth_debug_mode)
	    printf("Not enough room for user name\r\n");
	return(0);
    }
    if (!Data(ap, KRB_AUTH, auth.data, auth.length)) {
	if (auth_debug_mode)
	    printf("Not enough room for authentication data\r\n");
	return(0);
    }
    if (auth_debug_mode) {
	printf("Sent Kerberos V5 credentials to server\r\n");
    }
    return(1);
}

int
kerberos5_send_mutual(Authenticator *ap)
{
    return kerberos5_send("mutual KERBEROS5", ap);
}

int
kerberos5_send_oneway(Authenticator *ap)
{
    return kerberos5_send("KERBEROS5", ap);
}

void
kerberos5_is(Authenticator *ap, unsigned char *data, int cnt)
{
    int r;
    krb5_data outbuf;
    krb5_keyblock *key_block;
    char *name;

    if (cnt-- < 1)
	return;
    switch (*data++) {
    case KRB_AUTH:
	auth.data = (char *)data;
	auth.length = cnt;

	auth_context = NULL;

	r = krb5_rd_req(context, &auth_context, &auth, 
			NULL, NULL, NULL, &ticket);

	if (r) {
	    char *errbuf;
	errout:

	    authdat = 0;
	    asprintf(&errbuf,
		     "Read req failed: %s",
		     krb5_get_err_text(context, r));
	    Data(ap, KRB_REJECT, errbuf, -1);
	    if (auth_debug_mode)
		printf("%s\r\n", errbuf);
	    free (errbuf);
	    return;
	}
	{
	    krb5_authenticator authenticator;

	    r = krb5_auth_getauthenticator (context,
					    auth_context,
					    &authenticator);
	    if (r)
		abort ();
	    if (authenticator->cksum) {
		char foo[2];

		foo[0] = ap->type;
		foo[1] = ap->way;

		r = krb5_verify_checksum (context,
					  foo,
					  sizeof(foo),
					  NULL,
					  authenticator->cksum);
		if (r) {
		    Data(ap, KRB_REJECT, "No checksum", -1);
		    if (auth_debug_mode)
			printf ("No checksum\r\n");
		    krb5_free_authenticator (context,
					     &authenticator);

		    return;
		}
	    }
	    krb5_free_authenticator (context,
				     &authenticator);
	}

	if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
	    r = krb5_mk_rep(context, &auth_context, &outbuf);
	    if(r){
	      abort ();
	    }
	    Data(ap, KRB_RESPONSE, outbuf.data, outbuf.length);
	}
	if (krb5_unparse_name(context, ticket->client, &name))
	    name = 0;
	Data(ap, KRB_ACCEPT, name, name ? -1 : 0);
	if (auth_debug_mode) {
	    printf("Kerberos5 identifies him as ``%s''\r\n",
		   name ? name : "");
	}
	auth_finished(ap, AUTH_USER);

	r = krb5_auth_con_getremotesubkey (context,
					   auth_context,
					   &key_block);

	if (r)
	    r = krb5_auth_con_getkey(context, auth_context, &key_block);

	if(r){
	  abort ();
	}
	
	if(key_block->keytype == KEYTYPE_DES){
	  Session_Key skey;

	  skey.type = SK_DES;
	  skey.length = 8;
	  skey.data = key_block->keyvalue.data;
	  encrypt_session_key(&skey, 0);
#if 0
	    memcpy(&session_key, key_block->contents.data,
		   sizeof(session_key));
#endif
	}

	krb5_free_keyblock(context, key_block);
	
	break;
#ifdef	FORWARD
    case KRB_FORWARD:
	inbuf.data = (char *)data;
	inbuf.length = cnt;
	if (r = rd_and_store_for_creds(&inbuf, authdat->ticket,
				       UserNameRequested)) {
	    char *errbuf;


	    asprintf(&errbuf,
		     "Read forwarded creds failed: %s",
		     krb5_get_err_text (context, r));
	    Data(ap, KRB_FORWARD_REJECT, errbuf, -1);
	    if (auth_debug_mode)
		printf("Could not read forwarded credentials: %s\r\n",
		       errbuf);
	    free (errbuf);
	}
	else
	    Data(ap, KRB_FORWARD_ACCEPT, 0, 0);
	if (auth_debug_mode)
	    printf("Forwarded credentials obtained\r\n");
	break;
#endif	/* FORWARD */
    default:
	if (auth_debug_mode)
	    printf("Unknown Kerberos option %d\r\n", data[-1]);
	Data(ap, KRB_REJECT, 0, 0);
	break;
    }
}

void
kerberos5_reply(Authenticator *ap, unsigned char *data, int cnt)
{
    Session_Key skey;
    static int mutual_complete = 0;

    if (cnt-- < 1)
	return;
    switch (*data++) {
    case KRB_REJECT:
	if (cnt > 0) {
	    printf("[ Kerberos V5 refuses authentication because %.*s ]\r\n",
		   cnt, data);
	} else
	    printf("[ Kerberos V5 refuses authentication ]\r\n");
	auth_send_retry();
	return;
    case KRB_ACCEPT:
	if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL &&
	    !mutual_complete) {
	    printf("[ Kerberos V5 accepted you, but didn't provide mutual authentication! ]\r\n");
	    auth_send_retry();
	    return;
	}
	if (cnt)
	    printf("[ Kerberos V5 accepts you as ``%.*s'' ]\r\n", cnt, data);
	else
	    printf("[ Kerberos V5 accepts you ]\r\n");
	auth_finished(ap, AUTH_USER);
#ifdef	FORWARD
	if (forward_flags & OPTS_FORWARD_CREDS)
	    kerberos5_forward(ap);
#endif	/* FORWARD */
	break;
    case KRB_RESPONSE:
	if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
	    /* the rest of the reply should contain a krb_ap_rep */
#if 0
	  /*krb5_ap_rep_enc_part*/ void *reply;
#endif
	  EncAPRepPart *reply;
	    krb5_data inbuf;
	    krb5_error_code r;
	    
	    inbuf.length = cnt;
	    inbuf.data = (char *)data;

	    if (r = krb5_rd_rep(context, auth_context, &inbuf, &reply)) {
		printf("[ Mutual authentication failed: %s ]\r\n",
		       krb5_get_err_text (context, r));
		auth_send_retry();
		return;
	    }
#if 0
	    if (reply->ctime != authenticator.ctime ||
		reply->cusec != authenticator.cusec) {
		printf("[ Mutual authentication failed (mismatched KRB_AP_REP) ]\r\n");
		auth_send_retry();
		return;
	    }
#endif
	    krb5_free_ap_rep_enc_part(context, reply);
	    {
	      Session_Key skey;
	      krb5_keyblock *keyblock;
	      
	      r = krb5_auth_con_getlocalsubkey (context,
						auth_context,
						&keyblock);
	      if (r)
		  r = krb5_auth_con_getkey (context,
					    auth_context,
					    &keyblock);
	      if (r) {
		abort ();
	      }
	      
	      skey.type = SK_DES;
	      skey.length = 8;
	      skey.data = keyblock->keyvalue.data;
	      encrypt_session_key(&skey, 0);
	      krb5_free_keyblock (context, keyblock);
	    }
	    mutual_complete = 1;
	}
	return;
#ifdef	FORWARD
    case KRB_FORWARD_ACCEPT:
	printf("[ Kerberos V5 accepted forwarded credentials ]\r\n");
	return;
    case KRB_FORWARD_REJECT:
	printf("[ Kerberos V5 refuses forwarded credentials because %.*s ]\r\n",
	       cnt, data);
	return;
#endif	/* FORWARD */
    default:
	if (auth_debug_mode)
	    printf("Unknown Kerberos option %d\r\n", data[-1]);
	return;
    }
}

int
kerberos5_status(Authenticator *ap, char *name, int level)
{
    if (level < AUTH_USER)
	return(level);

    if (UserNameRequested &&
	krb5_kuserok(context,
		     ticket->client,
		     UserNameRequested))
	{
	    strcpy(name, UserNameRequested);
	    return(AUTH_VALID);
	} else
	    return(AUTH_USER);
}

#define	BUMP(buf, len)		while (*(buf)) {++(buf), --(len);}
#define	ADDC(buf, len, c)	if ((len) > 0) {*(buf)++ = (c); --(len);}

void
kerberos5_printsub(unsigned char *data, int cnt, unsigned char *buf, int buflen)
{
    char lbuf[32];
    int i;

    buf[buflen-1] = '\0';		/* make sure its NULL terminated */
    buflen -= 1;

    switch(data[3]) {
    case KRB_REJECT:		/* Rejected (reason might follow) */
	strncpy((char *)buf, " REJECT ", buflen);
	goto common;

    case KRB_ACCEPT:		/* Accepted (name might follow) */
	strncpy((char *)buf, " ACCEPT ", buflen);
    common:
	BUMP(buf, buflen);
	if (cnt <= 4)
	    break;
	ADDC(buf, buflen, '"');
	for (i = 4; i < cnt; i++)
	    ADDC(buf, buflen, data[i]);
	ADDC(buf, buflen, '"');
	ADDC(buf, buflen, '\0');
	break;


    case KRB_AUTH:			/* Authentication data follows */
	strncpy((char *)buf, " AUTH", buflen);
	goto common2;

    case KRB_RESPONSE:
	strncpy((char *)buf, " RESPONSE", buflen);
	goto common2;

#ifdef	FORWARD
    case KRB_FORWARD:		/* Forwarded credentials follow */
	strncpy((char *)buf, " FORWARD", buflen);
	goto common2;

    case KRB_FORWARD_ACCEPT:	/* Forwarded credentials accepted */
	strncpy((char *)buf, " FORWARD_ACCEPT", buflen);
	goto common2;

    case KRB_FORWARD_REJECT:	/* Forwarded credentials rejected */
	/* (reason might follow) */
	strncpy((char *)buf, " FORWARD_REJECT", buflen);
	goto common2;
#endif	/* FORWARD */

    default:
	snprintf(lbuf, sizeof(lbuf), " %d (unknown)", data[3]);
	strncpy((char *)buf, lbuf, buflen);
    common2:
	BUMP(buf, buflen);
	for (i = 4; i < cnt; i++) {
	    snprintf(lbuf, sizeof(lbuf), " %d", data[i]);
	    strncpy((char *)buf, lbuf, buflen);
	    BUMP(buf, buflen);
	}
	break;
    }
}

#ifdef	FORWARD
void
kerberos5_forward(Authenticator *ap)
{
    struct hostent *hp;
    krb5_creds *local_creds;
    krb5_error_code r;
    krb5_data forw_creds;
    extern krb5_cksumtype krb5_kdc_req_sumtype;
    krb5_ccache ccache;
    int i;

    if (!(local_creds = (krb5_creds *)
	  calloc(1, sizeof(*local_creds)))) {
	if (auth_debug_mode)
	    printf("Kerberos V5: could not allocate memory for credentials\r\n");
	return;
    }

    if (r = krb5_sname_to_principal(context, RemoteHostName, "host", 1,
				    &local_creds->server)) {
	if (auth_debug_mode)
	    printf("Kerberos V5: could not build server name - %s\r\n",
		   krb5_get_err_text(context, r));
	krb5_free_creds(local_creds);
	return;
    }

    if (r = krb5_cc_default(&ccache)) {
	if (auth_debug_mode)
	    printf("Kerberos V5: could not get default ccache - %s\r\n",
		   krb5_get_err_text(context, r));
	krb5_free_creds(local_creds);
	return;
    }

    if (r = krb5_cc_get_principal(ccache, &local_creds->client)) {
	if (auth_debug_mode)
	    printf("Kerberos V5: could not get default principal - %s\r\n",
		   krb5_get_err_text(context, r));
	krb5_free_creds(local_creds);
	return;
    }

    /* Get ticket from credentials cache */
    if (r = krb5_get_credentials(KRB5_GC_CACHED, ccache, local_creds)) {
	if (auth_debug_mode)
	    printf("Kerberos V5: could not obtain credentials - %s\r\n",
		   krb5_get_err_text(context, r));
	krb5_free_creds(local_creds);
	return;
    }

    if (r = get_for_creds(ETYPE_DES_CBC_CRC,
			  krb5_kdc_req_sumtype,
			  RemoteHostName,
			  local_creds->client,
			  &local_creds->keyblock,
			  forward_flags & OPTS_FORWARDABLE_CREDS,
			  &forw_creds)) {
	if (auth_debug_mode)
	    printf("Kerberos V5: error getting forwarded creds - %s\r\n",
		   krb5_get_err_text(context, r));
	krb5_free_creds(local_creds);
	return;
    }

    /* Send forwarded credentials */
    if (!Data(ap, KRB_FORWARD, forw_creds.data, forw_creds.length)) {
	if (auth_debug_mode)
	    printf("Not enough room for authentication data\r\n");
    }
    else {
	if (auth_debug_mode)
	    printf("Forwarded local Kerberos V5 credentials to server\r\n");
    }

    krb5_free_creds(local_creds);
}
#endif	/* FORWARD */

#endif /* KRB5 */
